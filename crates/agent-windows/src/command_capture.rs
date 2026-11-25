use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
    GENERIC_WRITE, HANDLE, WAIT_EVENT, WAIT_OBJECT_0,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Pipes::{CreateNamedPipeW, NAMED_PIPE_MODE};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForMultipleObjects};

use super::{keep_count, wide};

const PIPE_ACCESS_INBOUND: u32 = 1;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const DRAIN_BUDGET: Duration = Duration::from_secs(2);
const BUFFER_SIZE: usize = 8192;

pub(super) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub(super) fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub(super) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Ready,
    Pending,
    Eof,
    Failed,
}

// The slice-taking windows-rs wrapper would pass a Rust borrow into an
// operation that can outlive the call. Submit the read through the raw ABI.
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "ReadFile"]
    fn read_file(
        file: HANDLE,
        buffer: *mut std::ffi::c_void,
        count: u32,
        read: *mut u32,
        overlapped: *mut OVERLAPPED,
    ) -> BOOL;
}

struct IoSlot {
    overlapped: OVERLAPPED,
    buffer: [u8; BUFFER_SIZE],
}

struct Stream {
    pipe: OwnedHandle,
    event: OwnedHandle,
    io: *mut IoSlot,
    kept: Vec<u8>,
    truncated: bool,
    state: ReadState,
}

impl Stream {
    fn new(attrs: &SECURITY_ATTRIBUTES) -> windows::core::Result<(Box<Self>, OwnedHandle)> {
        // One local instance, with a unique name. Only the ordinary client write end is inheritable.
        let name = wide(&format!(r"\\.\pipe\DeskRally-command-{}", uuid::Uuid::new_v4()));
        let name = PCWSTR(name.as_ptr());
        // CreateNamedPipeW returns a raw HANDLE (INVALID_HANDLE_VALUE on failure) in this windows-rs version.
        let raw = unsafe {
            CreateNamedPipeW(
                name,
                FILE_FLAGS_AND_ATTRIBUTES(
                    PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED.0 | FILE_FLAG_FIRST_PIPE_INSTANCE,
                ),
                NAMED_PIPE_MODE(PIPE_REJECT_REMOTE_CLIENTS),
                1,
                0,
                BUFFER_SIZE as u32,
                0,
                None,
            )
        };
        if raw.is_invalid() {
            return Err(windows::core::Error::from_win32());
        }
        let pipe = OwnedHandle::new(raw);
        let writer = OwnedHandle::new(unsafe {
            CreateFileW(
                name,
                GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                Some(attrs),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )
        }?);
        let event = OwnedHandle::new(unsafe { CreateEventW(None, true, false, PCWSTR::null()) }?);
        Ok((
            Box::new(Self {
                pipe,
                event,
                io: Box::into_raw(Box::new(IoSlot {
                    overlapped: OVERLAPPED::default(),
                    buffer: [0; BUFFER_SIZE],
                })),
                kept: Vec::new(),
                truncated: false,
                state: ReadState::Ready,
            }),
            writer,
        ))
    }

    fn overlapped(&self) -> *mut OVERLAPPED {
        unsafe { std::ptr::addr_of_mut!((*self.io).overlapped) }
    }

    fn buffer(&self) -> *mut u8 {
        unsafe { std::ptr::addr_of_mut!((*self.io).buffer).cast() }
    }

    fn complete(&mut self, wait: bool) -> Option<windows::core::Result<u32>> {
        let mut count = 0;
        let result = unsafe {
            GetOverlappedResult(self.pipe.raw(), self.overlapped(), &mut count, wait)
        };
        match result {
            Ok(()) => Some(Ok(count)),
            Err(e) if e.code() == HRESULT::from_win32(ERROR_IO_INCOMPLETE.0)
                || e.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => None,
            Err(e) => Some(Err(e)),
        }
    }

    fn end_read(&mut self, result: windows::core::Result<u32>, cap: usize) {
        match result {
            Ok(count) => {
                let (take, truncated) = keep_count(self.kept.len(), count as usize, cap);
                // GetOverlappedResult confirmed this read completed before we access its bytes.
                let bytes = unsafe { std::slice::from_raw_parts(self.buffer(), take) };
                self.kept.extend_from_slice(bytes);
                self.truncated |= truncated;
                self.state = ReadState::Ready;
            }
            Err(e) if e.code() == HRESULT::from_win32(ERROR_BROKEN_PIPE.0)
                || e.code() == HRESULT::from_win32(ERROR_HANDLE_EOF.0) =>
            {
                self.state = ReadState::Eof;
            }
            Err(_) => self.state = ReadState::Failed,
        }
    }

    fn collect(&mut self, cap: usize) {
        if self.state == ReadState::Pending {
            if let Some(result) = self.complete(false) {
                self.end_read(result, cap);
            }
        }
    }

    fn pump(&mut self, cap: usize, deadline: Instant) -> bool {
        self.collect(cap);
        if self.state != ReadState::Ready || Instant::now() >= deadline {
            return false;
        }
        if unsafe { ResetEvent(self.event.raw()) }.is_err() {
            self.state = ReadState::Failed;
            return false;
        }
        // Ready means the previous read has completed. The separate I/O allocation
        // stays live through completion, including after ownership moves to the reaper.
        let result = unsafe {
            let overlapped = self.overlapped();
            overlapped.write(OVERLAPPED { hEvent: self.event.raw(), ..Default::default() });
            read_file(
                self.pipe.raw(),
                self.buffer().cast(),
                BUFFER_SIZE as u32,
                std::ptr::null_mut(),
                overlapped,
            )
            .ok()
        };
        match result {
            Ok(()) => {
                self.state = ReadState::Pending;
                true
            }
            Err(e) if e.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                self.state = ReadState::Pending;
                false
            }
            Err(e) => {
                self.end_read(Err(e), cap);
                false
            }
        }
    }

    fn cancel(&self) {
        if self.state == ReadState::Pending {
            // A completion can win the race and make CancelIoEx report ERROR_NOT_FOUND.
            // Either way the reaper still observes completion before releasing this stream.
            let _ = unsafe { CancelIoEx(self.pipe.raw(), Some(self.overlapped())) };
        }
    }

    fn reap(&mut self, mut complete: impl FnMut(&mut Self) -> Option<windows::core::Result<u32>>) {
        if self.state == ReadState::Pending {
            while complete(self).is_none() {
                std::thread::yield_now();
            }
            self.state = ReadState::Failed;
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Capture transfers pending streams to the reaper, leaking them if handoff fails.
        // The reaper drops them only after observing completion.
        debug_assert!(self.state != ReadState::Pending);
        unsafe { drop(Box::from_raw(self.io)) };
    }
}

pub(super) struct Capture {
    streams: [Option<Box<Stream>>; 2],
    cap: usize,
    reaper: Option<mpsc::Sender<Capture>>,
}

// The Win32 pointers refer to each stream's separately allocated I/O slot. A single Rust owner
// drives each capture, then transfers it exclusively to the reaper once no more reads can be issued.
unsafe impl Send for Capture {}

impl Capture {
    pub(super) fn new(
        cap: usize,
        attrs: &SECURITY_ATTRIBUTES,
    ) -> Result<(Self, OwnedHandle, OwnedHandle), super::CommandError> {
        let setup = |error: windows::core::Error| super::CommandError::Setup(error.to_string());
        let (stdout, out_writer) = Stream::new(attrs).map_err(setup)?;
        let (stderr, err_writer) = Stream::new(attrs).map_err(setup)?;
        let (reaper, pending) = mpsc::channel::<Self>();
        // Reserve the reaper before issuing any I/O, so thread creation failure is a setup error.
        std::thread::Builder::new().name("command-capture-reaper".into())
            .spawn(move || {
                if let Ok(capture) = pending.recv() {
                    capture.reap_with(|stream| stream.complete(true));
                }
            })
            .map_err(|error| super::CommandError::Setup(error.to_string()))?;
        let capture = Self {
            streams: [Some(stdout), Some(stderr)],
            cap,
            reaper: Some(reaper),
        };
        Ok((capture, out_writer, err_writer))
    }

    pub(super) fn pump(&mut self, deadline: Instant) -> bool {
        let mut progress = false;
        for stream in self.streams.iter_mut().flatten() {
            progress |= stream.pump(self.cap, deadline);
        }
        progress
    }

    pub(super) fn wait(
        &self,
        process: Option<HANDLE>,
        deadline: Instant,
        immediate: bool,
    ) -> WAIT_EVENT {
        let mut handles = [HANDLE::default(); 3];
        let mut count = 0;
        if let Some(process) = process {
            handles[count] = process;
            count += 1;
        }
        for stream in self.streams.iter().flatten().filter(|s| s.state == ReadState::Pending) {
            handles[count] = stream.event.raw();
            count += 1;
        }
        if count == 0 {
            return WAIT_OBJECT_0;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = if immediate || remaining.is_zero() {
            0
        } else {
            remaining.as_millis().saturating_add(1).min(u128::from(u32::MAX - 1)) as u32
        };
        // The process, when present, has index zero and wins ties against capture activity.
        unsafe { WaitForMultipleObjects(&handles[..count], false, millis) }
    }

    pub(super) fn finish(mut self, limit: Option<Instant>) -> (String, String, bool) {
        let deadline = Instant::now() + DRAIN_BUDGET;
        let deadline = limit.map_or(deadline, |limit| deadline.min(limit));
        while Instant::now() < deadline {
            let progress = self.pump(deadline);
            if self.streams.iter().flatten().all(|s| {
                matches!(s.state, ReadState::Eof | ReadState::Failed)
            }) {
                break;
            }
            if self.wait(None, deadline, progress) == windows::Win32::Foundation::WAIT_FAILED {
                break;
            }
        }
        // Harvest any completions already available at the deadline without issuing another read.
        for stream in self.streams.iter_mut().flatten() {
            stream.collect(self.cap);
        }
        let mut truncated = false;
        let [stdout, stderr] = self.streams.each_mut().map(|slot| {
            let stream = slot.as_mut().expect("capture owns both streams");
            truncated |= stream.truncated || stream.state != ReadState::Eof;
            String::from_utf8_lossy(&std::mem::take(&mut stream.kept)).into_owned()
        });
        self.cancel_and_reap();
        (stdout, stderr, truncated)
    }

    fn cancel_and_reap(mut self) {
        if self.has_pending_reads() {
            for stream in self.streams.iter().flatten() {
                stream.cancel();
            }
            let sender = self.reaper.take().expect("capture has a reserved reaper");
            if let Err(error) = sender.send(self) {
                tracing::error!("command capture reaper exited before accepting pending reads");
                drop(error);
            }
        }
    }

    fn has_pending_reads(&self) -> bool {
        self.streams.iter().flatten().any(|s| s.state == ReadState::Pending)
    }

    fn reap_with(
        mut self,
        mut complete: impl FnMut(&mut Stream) -> Option<windows::core::Result<u32>>,
    ) {
        for stream in self.streams.iter_mut().flatten() {
            stream.reap(&mut complete);
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if !self.has_pending_reads() {
            return;
        }
        if let Some(sender) = self.reaper.take() {
            // Also transfer ownership on unwind if a read was already issued.
            let capture = Self {
                streams: std::mem::take(&mut self.streams),
                cap: self.cap,
                reaper: Some(sender),
            };
            capture.cancel_and_reap();
            return;
        }
        for slot in &mut self.streams {
            if slot.as_ref().is_some_and(|stream| stream.state == ReadState::Pending) {
                // If the reserved reaper has failed, leaking pending storage is
                // safer than closing a handle or freeing memory while the kernel can still use it.
                let stream = slot.take().expect("pending stream");
                stream.cancel();
                let _ = Box::leak(stream);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{GetHandleInformation, ERROR_OPERATION_ABORTED};

    #[test]
    fn reaper_observes_both_cancelled_completions_before_closing_handles() {
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        let (mut capture, _out_writer, _err_writer) = Capture::new(64, &attrs).unwrap();
        capture.pump(Instant::now() + Duration::from_secs(1));
        let handles: Vec<_> = capture.streams.iter().flatten()
            .flat_map(|stream| [stream.pipe.raw(), stream.event.raw()])
            .collect();

        for stream in capture.streams.iter_mut().flatten() {
            assert!(stream.state == ReadState::Pending);
            assert!(stream.complete(false).is_none(), "writer is open and has produced no bytes");
            stream.cancel();
        }

        let mut attempts = 0;
        let mut completed = 0;
        capture.reap_with(|stream| {
            // Exercise the reaper's completion step while checking the lifetime of both reads,
            // including the first stream while processing the second one's cancellation.
            for &handle in &handles {
                let mut flags = 0;
                unsafe { GetHandleInformation(handle, &mut flags) }
                    .expect("capture closed a handle before both cancellations completed");
            }
            attempts += 1;
            if attempts % 2 == 1 {
                // Inject a completion that is still pending. The reaper must check it again.
                return None;
            }
            let result = stream.complete(true).expect("cancelled read completed");
            let error = result.as_ref().unwrap_err();
            assert_eq!(error.code(), HRESULT::from_win32(ERROR_OPERATION_ABORTED.0));
            completed += 1;
            Some(result)
        });
        assert_eq!(attempts, 4);
        assert_eq!(completed, 2);
    }

    #[test]
    fn finish_hands_pending_reads_to_the_reaper_which_closes_them_within_the_bound() {
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        // The writers stay open for the whole test: neither stream can reach EOF, so `finish` must
        // stop at the drain budget, report truncation and hand both pending reads to the reaper.
        let (mut capture, _out_writer, _err_writer) = Capture::new(64, &attrs).unwrap();
        capture.pump(Instant::now() + Duration::from_secs(1));
        let handles: Vec<_> = capture.streams.iter().flatten()
            .flat_map(|stream| [stream.pipe.raw(), stream.event.raw()])
            .collect();

        use windows::Win32::Foundation::{CloseHandle, CompareObjectHandles, DuplicateHandle, DUPLICATE_SAME_ACCESS};
        use windows::Win32::System::Threading::GetCurrentProcess;
        let witnesses: Vec<HANDLE> = handles
            .iter()
            .map(|&h| {
                let mut dup = HANDLE::default();
                unsafe { DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut dup, 0, false, DUPLICATE_SAME_ACCESS) }
                    .expect("duplicate a capture handle as its identity witness");
                dup
            })
            .collect();
        let started = Instant::now();
        let (_, _, truncated) = capture.finish(None);
        let drained = started.elapsed();
        assert!(truncated, "a stream short of EOF is truncated");
        assert!(drained >= DRAIN_BUDGET - Duration::from_millis(50), "drained for {drained:?}");
        assert!(drained < DRAIN_BUDGET + Duration::from_millis(750), "finish overran the bound: {drained:?}");

        // The production reaper (not `reap_with` called by hand) completes the cancelled reads and
        // only then closes every handle.
        //
        // "Closed" is judged by IDENTITY, not by the handle number: Windows reuses handle values, and a handle another
        // test opens meanwhile can take a closed one's value and look "still open" (an intermittent failure under the
        // parallel suite). A duplicate keeps each original object alive; an original handle is open only while its
        // value is valid AND still names that same object.
        let closed_by = Instant::now() + Duration::from_secs(2);
        loop {
            let open = handles.iter().zip(&witnesses).filter(|(&handle, &witness)| {
                let mut flags = 0;
                unsafe { GetHandleInformation(handle, &mut flags) }.is_ok()
                    && unsafe { CompareObjectHandles(handle, witness) }.as_bool()
            }).count();
            if open == 0 {
                break;
            }
            assert!(Instant::now() < closed_by, "{open} capture handles still open: the reaper never ran");
            std::thread::sleep(Duration::from_millis(10));
        }
        for w in witnesses {
            let _ = unsafe { CloseHandle(w) };
        }
    }
}
