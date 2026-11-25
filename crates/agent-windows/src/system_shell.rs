//! Under the Hood SYSTEM terminal, phase 1 (docs/76 section 4): one PowerShell child under a pseudoconsole, in a
//! kill-on-close job from its first instruction, with no inherited handles.
//!
//! Why not the `conpty` crate (agent/src/backstage/shell.rs): its child attaches to the HOST's console, so it cannot
//! run from the console-less service. This spawns directly (CreatePseudoConsole + CreateProcessW with a two-entry
//! attribute list: PSEUDOCONSOLE and JOB_LIST), the shape proven as SYSTEM in Session 0 by
//! agent/examples/conpty_service_spike.rs. The child is in the job before it runs, so nothing it starts can be
//! created outside the job; killing the shell terminates the job (the whole tree). What the shell created OUTSIDE
//! its process tree (services, scheduled tasks, WMI-spawned processes) is not undone, and docs/76 says so.
//!
//! The agent is a byte relay: ConPTY emits VT on output and consumes VT on input; the console renders it.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, WaitForSingleObject, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

// ProcThreadAttributeValue(attribute, thread=false, input=true, additive=false) for the two attributes used here.
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;
const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;
const STILL_ACTIVE: u32 = 259;

/// The largest terminal the console may ask for; anything bigger is clamped (a hostile resize cannot make ConPTY
/// allocate an absurd buffer).
pub(crate) const MAX_COLS: u16 = 500;
pub(crate) const MAX_ROWS: u16 = 300;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ShellError {
    #[error("{api} failed: {source}")]
    Api { api: &'static str, source: windows::core::Error },
}

fn api(api: &'static str) -> impl FnOnce(windows::core::Error) -> ShellError {
    move |source| ShellError::Api { api, source }
}

fn clamp_size(cols: u16, rows: u16) -> COORD {
    COORD { X: cols.clamp(1, MAX_COLS) as i16, Y: rows.clamp(1, MAX_ROWS) as i16 }
}

/// Reads the terminal's VT output. Blocking; run it on its own thread. EOF (`Ok(0)`) once the shell is gone.
pub(crate) struct ShellReader(OwnedHandle);

impl io::Read for ShellReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut got = 0u32;
        match unsafe { ReadFile(HANDLE(self.0.as_raw_handle()), Some(buf), Some(&mut got), None) } {
            Ok(()) => Ok(got as usize),
            // A broken pipe is the normal end: the pseudoconsole closed its side.
            Err(e) if e.code().0 as u32 == 0x8007_006D => Ok(0),
            Err(e) => Err(io::Error::other(e)),
        }
    }
}

/// One live SYSTEM shell. Dropping it kills the whole process tree.
pub(crate) struct SystemShell {
    hpc: Option<HPCON>,
    input: Option<OwnedHandle>,
    reader: Option<ShellReader>,
    process: OwnedHandle,
    job: OwnedHandle,
    pid: u32,
}

// HPCON is a plain handle value; the shell is moved between threads but used from one at a time.
unsafe impl Send for SystemShell {}

impl SystemShell {
    /// Start `powershell.exe -NoProfile -NoLogo` (by absolute path) under a `cols` x `rows` pseudoconsole.
    pub(crate) fn spawn(cols: u16, rows: u16) -> Result<Self, ShellError> {
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null()).map_err(api("CreateJobObjectW"))?;
            let job = OwnedHandle::from_raw_handle(job.0);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // Kill on close, and no breakaway flag: a child cannot leave the job.
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                HANDLE(job.as_raw_handle()),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(api("SetInformationJobObject"))?;

            let (mut in_r, mut in_w, mut out_r, mut out_w) =
                (HANDLE::default(), HANDLE::default(), HANDLE::default(), HANDLE::default());
            CreatePipe(&mut in_r, &mut in_w, None, 0).map_err(api("CreatePipe"))?;
            let (in_r, in_w) = (OwnedHandle::from_raw_handle(in_r.0), OwnedHandle::from_raw_handle(in_w.0));
            CreatePipe(&mut out_r, &mut out_w, None, 0).map_err(api("CreatePipe"))?;
            let (out_r, out_w) = (OwnedHandle::from_raw_handle(out_r.0), OwnedHandle::from_raw_handle(out_w.0));
            let hpc = CreatePseudoConsole(
                clamp_size(cols, rows),
                HANDLE(in_r.as_raw_handle()),
                HANDLE(out_w.as_raw_handle()),
                0,
            )
            .map_err(api("CreatePseudoConsole"))?;
            // The pseudoconsole holds its own duplicates of the child-side ends.
            drop(in_r);
            drop(out_w);

            let mut size = 0usize;
            let _ = InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST::default(), 2, 0, &mut size);
            let mut attr_buf = vec![0u8; size];
            let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr().cast());
            let spawned = (|| -> Result<PROCESS_INFORMATION, ShellError> {
                InitializeProcThreadAttributeList(attrs, 2, 0, &mut size).map_err(api("InitializeProcThreadAttributeList"))?;
                UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, Some(hpc.0 as *const _),
                    std::mem::size_of::<HPCON>(), None, None)
                    .map_err(api("UpdateProcThreadAttribute(PSEUDOCONSOLE)"))?;
                let job_list = [HANDLE(job.as_raw_handle())];
                UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, Some(job_list.as_ptr().cast()),
                    std::mem::size_of_val(&job_list), None, None)
                    .map_err(api("UpdateProcThreadAttribute(JOB_LIST)"))?;

                let mut si = STARTUPINFOEXW::default();
                si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
                si.lpAttributeList = attrs;
                // STARTF_USESTDHANDLES with NULL handles: without it a parent whose standard handles are redirected
                // (a test harness, a service host with log pipes) hands them to the child, which then writes around
                // the pseudoconsole (seen 2026-11-24: the prompt appeared in the parent's own output).
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                let mut cmd: Vec<u16> = powershell_command_line().encode_utf16().chain(Some(0)).collect();
                let cwd: Vec<u16> = system_directory().encode_utf16().chain(Some(0)).collect();
                let mut pi = PROCESS_INFORMATION::default();
                // bInheritHandles = FALSE and null std handles: the child's only I/O is the pseudoconsole.
                CreateProcessW(PCWSTR::null(), PWSTR(cmd.as_mut_ptr()), None, None, false, EXTENDED_STARTUPINFO_PRESENT,
                    None, PCWSTR(cwd.as_ptr()), &si.StartupInfo, &mut pi)
                    .map_err(api("CreateProcessW"))?;
                Ok(pi)
            })();
            DeleteProcThreadAttributeList(attrs);
            let pi = match spawned {
                Ok(pi) => pi,
                Err(e) => {
                    ClosePseudoConsole(hpc);
                    return Err(e);
                }
            };
            drop(OwnedHandle::from_raw_handle(pi.hThread.0));
            Ok(Self {
                hpc: Some(hpc),
                input: Some(in_w),
                reader: Some(ShellReader(out_r)),
                process: OwnedHandle::from_raw_handle(pi.hProcess.0),
                job,
                pid: pi.dwProcessId,
            })
        }
    }

    /// The output side, taken once by the pump that relays it.
    pub(crate) fn take_reader(&mut self) -> Option<ShellReader> {
        self.reader.take()
    }

    /// Send keystrokes / pasted text (VT input) to the shell.
    pub(crate) fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let input = self.input.as_ref().ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        write_all(input, bytes)
    }

    /// A duplicate of the input pipe for a writer thread (WriteFile can block; it must not run on the async runtime).
    /// Writes fail once the shell is killed.
    pub(crate) fn input_handle(&self) -> Option<OwnedHandle> {
        self.input.as_ref().and_then(|h| h.try_clone().ok())
    }

    pub(crate) fn resize(&self, cols: u16, rows: u16) {
        if let Some(hpc) = self.hpc {
            let _ = unsafe { ResizePseudoConsole(hpc, clamp_size(cols, rows)) };
        }
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// `Some(code)` once the shell process has exited.
    pub(crate) fn exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(HANDLE(self.process.as_raw_handle()), &mut code) }.ok()?;
        (code != STILL_ACTIVE).then_some(code)
    }

    /// Kill the whole tree and release the pseudoconsole. Idempotent.
    pub(crate) fn kill(&mut self) {
        unsafe {
            let _ = TerminateJobObject(HANDLE(self.job.as_raw_handle()), 1);
            let _ = WaitForSingleObject(HANDLE(self.process.as_raw_handle()), 5_000) == WAIT_OBJECT_0;
        }
        self.input = None;
        if let Some(hpc) = self.hpc.take() {
            // ClosePseudoConsole can block on older Windows until its output has been drained, and the reader may
            // already be gone; close it off-thread so a kill never hangs the session loop.
            let raw = hpc.0;
            std::thread::spawn(move || unsafe { ClosePseudoConsole(HPCON(raw)) });
        }
    }
}

impl Drop for SystemShell {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Write every byte to a pipe handle.
pub(crate) fn write_all(input: &OwnedHandle, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut wrote = 0u32;
        unsafe { WriteFile(HANDLE(input.as_raw_handle()), Some(rest), Some(&mut wrote), None) }.map_err(io::Error::other)?;
        rest = &rest[wrote as usize..];
    }
    Ok(())
}

fn system_directory() -> String {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n >= buf.len() {
        return r"C:\Windows\System32".to_owned();
    }
    String::from_utf16_lossy(&buf[..n])
}

/// The absolute path, so neither the working directory nor PATH can substitute another `powershell.exe`.
fn powershell_command_line() -> String {
    format!(r#""{}\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NoLogo"#, system_directory())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Relay the reader to a channel and collect text until `pred` holds or the deadline passes.
    fn pump(shell: &mut SystemShell) -> mpsc::Receiver<String> {
        let mut reader = shell.take_reader().expect("reader");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(String::from_utf8_lossy(&buf[..n]).into_owned()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        rx
    }

    fn wait_for(shell: &SystemShell, rx: &mpsc::Receiver<String>, send: &str, pred: impl Fn(&str) -> bool) -> String {
        let mut seen = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut next = Instant::now();
        while Instant::now() < deadline {
            if Instant::now() >= next {
                shell.write(send.as_bytes()).unwrap();
                next = Instant::now() + Duration::from_secs(3);
            }
            if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(100)) {
                seen.push_str(&chunk);
                if pred(&seen) {
                    return seen;
                }
            }
        }
        panic!("condition not met within 30 s; output tail: {}", &seen[seen.len().saturating_sub(800)..]);
    }

    /// Output that only the command's RESULT produces (the echo of the typed line contains the parts in quotes).
    /// Found anywhere in a line, not only at its start: the terminal may put cursor-control sequences in front of
    /// it (a gate run saw `child_pid=105044` arrive that way and the old starts-with test missed it). The echo of
    /// the typed command has a quote right after the marker; real output never does.
    fn result_line(seen: &str, marker: &str) -> Option<String> {
        seen.lines().find_map(|l| {
            l.match_indices(marker).find_map(|(i, _)| {
                let rest = &l[i..];
                (!rest[marker.len()..].starts_with('\'')).then(|| rest.trim_end().to_owned())
            })
        })
    }

    /// The first `marker` IMMEDIATELY followed by digits, as a number. The echo of the typed command never has digits
    /// there (a quote, or a cursor sequence where the line wrapped at the terminal width); the result always does.
    fn number_after(seen: &str, marker: &str) -> Option<u32> {
        seen.match_indices(marker).find_map(|(i, _)| {
            let digits: String = seen[i + marker.len()..].chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
    }

    #[test]
    fn a_command_round_trips_through_the_pseudoconsole() {
        let mut shell = SystemShell::spawn(100, 30).expect("spawn");
        let rx = pump(&mut shell);
        let seen = wait_for(&shell, &rx, "Write-Output ('rt' + '_ok_' + (6*7))\r", |s| result_line(s, "rt_ok_42").is_some());
        assert!(result_line(&seen, "rt_ok_42").is_some());
        shell.resize(140, 40); // resizing a live shell must not fail or hang
        assert_eq!(shell.exit_code(), None, "the shell is still running");
    }

    #[test]
    fn kill_reaps_the_shell_and_every_process_it_started() {
        let mut shell = SystemShell::spawn(100, 30).expect("spawn");
        let rx = pump(&mut shell);
        // A grandchild that would outlive its parent if it were outside the job.
        let seen = wait_for(
            &shell,
            &rx,
            "Write-Output ('child_pid=' + (Start-Process ping.exe -ArgumentList '-n','300','127.0.0.1' -WindowStyle Hidden -PassThru).Id)\r",
            |s| number_after(s, "child_pid=").is_some(),
        );
        let child = number_after(&seen, "child_pid=").expect("pid");
        shell.kill();
        assert!(shell.exit_code().is_some(), "the shell exited");
        // The grandchild is gone too: it cannot be opened, or it has exited.
        let alive = unsafe {
            windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION, false, child)
        }
        .ok()
        .map(|h| {
            let h = unsafe { OwnedHandle::from_raw_handle(h.0) };
            let mut code = 0u32;
            unsafe { GetExitCodeProcess(HANDLE(h.as_raw_handle()), &mut code) }.is_ok() && code == STILL_ACTIVE
        })
        .unwrap_or(false);
        assert!(!alive, "process {child} started by the shell survived the kill");
    }

    #[test]
    fn sizes_are_clamped() {
        let c = clamp_size(0, 60_000);
        assert_eq!((c.X, c.Y), (1, MAX_ROWS as i16));
        assert!(powershell_command_line().contains(r#"\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NoLogo"#));
    }
}
