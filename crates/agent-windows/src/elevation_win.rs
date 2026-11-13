//! The Win32 half of docs/53 (attended "Request admin rights"): the guest's token, the private pipe,
//! the UAC launch of `agent_host elevated-input`, and that helper's own entry point.
//!
//! The protocol and its tests live in [`crate::elevated_input`] (helper) and
//! [`crate::elevated_link`] (session); this module only connects them to Windows. What it proves on
//! its own is unit-tested here (token queries, the pipe's identity checks, identification-only
//! connections); the UAC launch itself is proven only in the VM (docs/53 §6).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevationType,
    TokenElevationTypeLimited, TokenIntegrityLevel, TokenUser, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, NAMED_PIPE_MODE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

/// How long a request may wait for the guest, from BEFORE the launch (docs/53 §3.1 step 6).
pub(crate) const REQUEST_DEADLINE: Duration = Duration::from_secs(120);
/// The helper's own deadline to connect, from its start (§3.2).
const HELPER_CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// The handshake's deadline (§3.1 step 9).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(1);
const MAX_HELLO: usize = 1024;
/// Pipe buffer size each way; frames are far smaller, so writes do not block in normal operation.
const PIPE_BUFFER: u32 = 64 * 1024;

const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
/// Read/write data and attributes, read-control, synchronize; NOT FILE_CREATE_PIPE_INSTANCE (the
/// same exact-rights constant the recording broker's client uses).
const CLIENT_ACCESS: u32 = 0x0012_019b;
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
const WAIT_TIMEOUT: u32 = 0x0000_0102;
const ERROR_PIPE_CONNECTED: i32 = 535;
const ERROR_CANCELLED: u32 = 1223;

fn win(e: windows::core::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// RAII for a raw handle this module owns.
struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: owned and closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}
// SAFETY: a kernel handle value may be used from any thread.
unsafe impl Send for Owned {}
unsafe impl Sync for Owned {}

// ---------------------------------------------------------------------------------------------
// Tokens

fn process_token(process: HANDLE) -> io::Result<Owned> {
    let mut token = HANDLE::default();
    // SAFETY: out-param handle, owned below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(win)?;
    Ok(Owned(token))
}

fn token_info(token: HANDLE, class: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: the size query; failure with a size is expected.
    unsafe {
        let _ = GetTokenInformation(token, class, None, 0, &mut needed);
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: buffer sized and aligned for the class's struct.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), (buf.len() * 8) as u32, &mut needed) }
        .map_err(win)?;
    Ok(buf)
}

/// Whether this process runs as a split-token administrator with UAC on (`TokenElevationTypeLimited`):
/// the only guest docs/53 v1 serves (§2.1).
pub(crate) fn is_split_token_admin() -> io::Result<bool> {
    // SAFETY: pseudo-handle for this process.
    let token = process_token(unsafe { GetCurrentProcess() })?;
    let mut kind = TOKEN_ELEVATION_TYPE::default();
    let mut got = 0u32;
    // SAFETY: out-param of the right size.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            Some((&mut kind as *mut TOKEN_ELEVATION_TYPE).cast()),
            std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut got,
        )
    }
    .map_err(win)?;
    Ok(kind == TokenElevationTypeLimited)
}

/// This process's mandatory integrity RID (0x2000 medium, 0x3000 high, 0x4000 system).
pub(crate) fn integrity_rid() -> io::Result<u32> {
    // SAFETY: pseudo-handle for this process.
    let token = process_token(unsafe { GetCurrentProcess() })?;
    let buf = token_info(token.0, TokenIntegrityLevel)?;
    // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID points inside it.
    unsafe {
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let count = *GetSidSubAuthorityCount(sid) as u32;
        Ok(*GetSidSubAuthority(sid, count - 1))
    }
}

/// This process's user SID, as a string (`S-1-5-21-…`).
pub(crate) fn user_sid() -> io::Result<String> {
    // SAFETY: pseudo-handle for this process.
    let token = process_token(unsafe { GetCurrentProcess() })?;
    let buf = token_info(token.0, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER whose SID points inside it; the string is LocalFree'd.
    unsafe {
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).map_err(win)?;
        let out = s.to_string().map_err(|e| io::Error::other(e.to_string()));
        let _ = LocalFree(HLOCAL(s.0.cast()));
        out
    }
}

// ---------------------------------------------------------------------------------------------
// The handshake

/// What the helper says about itself first, read from its own token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Hello {
    pub integrity_rid: u32,
    pub user_sid: String,
}

fn write_hello(w: &mut impl Write, h: &Hello) -> io::Result<()> {
    let body = serde_json::to_vec(h).map_err(io::Error::other)?;
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

fn read_hello(r: &mut impl Read) -> io::Result<Hello> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > MAX_HELLO {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hello length out of range"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad hello"))
}

/// The session's acceptance rule for a helper's hello (§3.1 step 9).
pub(crate) fn hello_acceptable(h: &Hello, guest_sid: &str) -> Result<(), String> {
    if h.integrity_rid < SECURITY_MANDATORY_HIGH_RID {
        return Err("the helper is not elevated".into());
    }
    if h.user_sid != guest_sid {
        return Err("the helper runs as a different account".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The pipe (session side)

/// A server pipe instance only `user_sid` can open, reachable locally only, one instance, created
/// first or not at all.
fn create_pipe(name: &str, user_sid: &str) -> io::Result<Owned> {
    let sddl = HSTRING::from(format!("D:P(A;;GA;;;{user_sid})"));
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: SDDL in, LocalAlloc'd descriptor out, freed below.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &mut sd, None) }
        .map_err(win)?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: BOOL(0),
    };
    // SAFETY: valid name and attributes for the call's duration.
    let handle = unsafe {
        CreateNamedPipeW(
            &HSTRING::from(name),
            FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE),
            NAMED_PIPE_MODE(PIPE_REJECT_REMOTE_CLIENTS),
            1,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            Some(&attrs),
        )
    };
    // SAFETY: freed once, after the call.
    unsafe {
        let _ = LocalFree(HLOCAL(sd.0));
    }
    if handle.is_invalid() {
        return Err(io::Error::last_os_error());
    }
    Ok(Owned(handle))
}

/// Open `name` as a client with identification-only impersonation (§3.2): the server may learn who
/// connected, never act as them.
fn open_pipe_identification_only(name: &str) -> io::Result<File> {
    // SAFETY: plain CreateFileW; the handle moves into a File.
    let h = unsafe {
        CreateFileW(
            &HSTRING::from(name),
            CLIENT_ACCESS,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION),
            None,
        )
    }
    .map_err(win)?;
    // SAFETY: we own h.
    Ok(unsafe { File::from_raw_handle(h.0) })
}

/// The pipe of a granted helper, for [`crate::elevated_link::ElevatedSink::attach`].
pub(crate) struct GrantedPipe {
    pub writer: File,
    pub acks: File,
    /// Force-close: disconnects the instance, which fails both directions' pending I/O here and
    /// ends the helper's reader (a revocation it cannot miss).
    pub close: Box<dyn Fn() + Send + Sync>,
}

/// How a request ended.
pub(crate) enum Outcome {
    Granted(GrantedPipe),
    Declined,
    Unavailable(String),
}

/// Ask the guest for admin rights: verify ourselves, create the pipe, raise UAC for
/// `elevated-input`, and accept only the process we launched, elevated, as the guest. `retired` is
/// set by the session to abandon the request (session ended, technician cancelled); the deadline
/// starts here, before the launch.
pub(crate) fn request(retired: Arc<AtomicBool>) -> Outcome {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    match request_inner(&retired, deadline) {
        Ok(o) => o,
        Err(e) => Outcome::Unavailable(e),
    }
}

enum Event {
    Launched(io::Result<Option<Owned>>),
    Connected(io::Result<()>),
}

/// VM self-test (docs/53 §6), `test-harness` only: drive the REAL request → attach → detach path in
/// a medium-integrity interactive process, so the one thing unit tests cannot touch — the UAC launch
/// of the elevated helper and its pipe handshake — runs for real. Meant to run under
/// `ConsentPromptBehaviorAdmin = 0` (silent auto-elevate for admins), the only way to reach Granted
/// without a human at the secure desktop. Prints `SELFTEST ...` lines and returns 0 only on success.
#[cfg(feature = "test-harness")]
pub(crate) fn run_selftest(_args: &[String]) -> i32 {
    use rmt_agent_core::{InputButton, InputEvent, InputSink};
    use std::sync::atomic::AtomicU64;

    let _ = crate::set_process_dpi_awareness();
    println!("SELFTEST integrity_rid=0x{:X}", integrity_rid().unwrap_or(0));
    match is_split_token_admin() {
        Ok(true) => println!("SELFTEST split_token_admin=true"),
        Ok(false) => {
            println!("SELFTEST FAIL split_token_admin=false (the lab user must be a UAC admin)");
            return 2;
        }
        Err(e) => {
            println!("SELFTEST FAIL token={e}");
            return 2;
        }
    }

    let retire = Arc::new(AtomicBool::new(false));
    let pipe = match request(Arc::clone(&retire)) {
        Outcome::Granted(p) => {
            println!("SELFTEST granted=true");
            p
        }
        Outcome::Declined => {
            println!("SELFTEST FAIL declined (is ConsentPromptBehaviorAdmin=0 set?)");
            return 3;
        }
        Outcome::Unavailable(why) => {
            println!("SELFTEST FAIL unavailable={why}");
            return 3;
        }
    };

    let ended = Arc::new(AtomicU64::new(0));
    let e = Arc::clone(&ended);
    let sink = Arc::new(crate::elevated_link::ElevatedSink::new(
        Arc::new(crate::input::SendInputSink::new()),
        Arc::new(tick_ms),
        Arc::new(move |_| {
            e.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }),
    ));
    sink.attach(pipe.writer, pipe.acks, pipe.close);
    std::thread::sleep(Duration::from_millis(400));
    if !sink.is_attached() {
        println!("SELFTEST FAIL not_attached (helper did not stay connected)");
        return 4;
    }
    println!("SELFTEST attached=true");

    // Forward a harmless press/release pair; the helper injects it (into no particular window).
    let _ = sink.inject(InputEvent::MouseButton { button: InputButton::Left, down: true });
    let _ = sink.inject(InputEvent::MouseButton { button: InputButton::Left, down: false });
    std::thread::sleep(Duration::from_millis(200));

    // End the grant: the helper must exit and Ended must fire within a bound.
    sink.detach();
    let deadline = Instant::now() + Duration::from_secs(5);
    while ended.load(std::sync::atomic::Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    let ended_n = ended.load(std::sync::atomic::Ordering::SeqCst);
    let attached = sink.is_attached();
    println!("SELFTEST after_detach ended={ended_n} attached={attached}");
    if ended_n == 0 || attached {
        println!("SELFTEST FAIL helper_did_not_end");
        return 5;
    }
    println!("SELFTEST ended=true");
    println!("SELFTEST PASS");
    0
}

fn request_inner(retired: &Arc<AtomicBool>, deadline: Instant) -> Result<Outcome, String> {
    if !is_split_token_admin().map_err(|e| format!("could not read the guest's token: {e}"))? {
        return Ok(Outcome::Unavailable("the signed-in user is not an administrator".into()));
    }
    let guest_sid = user_sid().map_err(|e| format!("could not read the guest's account: {e}"))?;

    // §3.1 step 3: hold our own image against writers and renames, and verify it, before asking.
    let exe = std::env::current_exe().map_err(|e| format!("could not locate this program: {e}"))?;
    let _image_lock = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001) // FILE_SHARE_READ only: no writers, no delete/rename
            .open(&exe)
            .map_err(|e| format!("could not lock this program's file: {e}"))?
    };
    crate::update_download::verify_authenticode(&exe).map_err(|e| format!("this program's signature did not verify: {e}"))?;

    let name = format!(r"\\.\pipe\deskrally-elev-{}", uuid::Uuid::new_v4().simple());
    let pipe = Arc::new(create_pipe(&name, &guest_sid).map_err(|e| format!("could not create the helper's pipe: {e}"))?);

    let (tx, rx) = mpsc::channel::<Event>();
    // The launch, which blocks for as long as the UAC prompt is up.
    {
        let tx = tx.clone();
        let exe = exe.clone();
        let args = format!("elevated-input --pipe {name} --parent {}", std::process::id());
        std::thread::spawn(move || {
            let _ = tx.send(Event::Launched(launch_elevated(&exe, &args)));
        });
    }
    // The connection, which blocks until a client connects (or our own dummy client unblocks it).
    {
        let tx = tx.clone();
        let pipe = Arc::clone(&pipe);
        std::thread::spawn(move || {
            // SAFETY: a valid server handle kept alive by the Arc.
            let r = unsafe { ConnectNamedPipe(pipe.0, None) };
            let r = match r {
                Ok(()) => Ok(()),
                Err(e) if e.code().0 == (0x8007_0000u32 as i32 | ERROR_PIPE_CONNECTED) => Ok(()),
                Err(e) => Err(win(e)),
            };
            let _ = tx.send(Event::Connected(r));
        });
    }
    drop(tx);

    // Wake the blocked ConnectNamedPipe on every non-success path, so its thread ends.
    let unblock = |name: &str| {
        let _ = open_pipe_identification_only(name);
    };

    let mut helper: Option<Owned> = None;
    let mut connected = false;
    let outcome = loop {
        if retired.load(Ordering::SeqCst) {
            break Outcome::Unavailable("the request was cancelled".into());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break Outcome::Unavailable("expired".into());
        }
        match rx.recv_timeout(left.min(Duration::from_millis(100))) {
            Ok(Event::Launched(Ok(Some(h)))) => {
                helper = Some(h);
                if connected {
                    break verify_and_handshake(&pipe, helper.as_ref().unwrap(), &guest_sid, deadline, retired);
                }
            }
            Ok(Event::Launched(Ok(None))) => break Outcome::Declined,
            Ok(Event::Launched(Err(e))) => break Outcome::Unavailable(format!("could not start the helper: {e}")),
            Ok(Event::Connected(Ok(()))) => {
                connected = true;
                if let Some(h) = &helper {
                    break verify_and_handshake(&pipe, h, &guest_sid, deadline, retired);
                }
            }
            Ok(Event::Connected(Err(e))) => break Outcome::Unavailable(format!("the helper's pipe failed: {e}")),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break Outcome::Unavailable("the request ended".into()),
        }
    };

    match outcome {
        Outcome::Granted(g) => Ok(Outcome::Granted(g)),
        other => {
            // Retire: disconnect (a connected helper's reader ends; it exits), and wake a still
            // blocked ConnectNamedPipe. A launch worker still blocked in ShellExecuteEx returns
            // later into a dropped channel and publishes nothing; a helper it starts then finds no
            // pipe and exits within its own deadline.
            // SAFETY: valid handle.
            unsafe {
                let _ = DisconnectNamedPipe(pipe.0);
            }
            if !connected {
                unblock(&name);
            }
            Ok(other)
        }
    }
}

/// §3.1 step 8 and 9: the connected client is the process we launched, still alive, and its hello
/// says elevated and the guest's own account. `deadline`/`retired` bound the handshake and are
/// rechecked before `Granted` is returned (Codex impl-B): a connection accepted just before expiry,
/// or after the request was cancelled, must not yield a live grant.
fn verify_and_handshake(pipe: &Arc<Owned>, helper: &Owned, guest_sid: &str, deadline: Instant, retired: &Arc<AtomicBool>) -> Outcome {
    let mut client_pid = 0u32;
    // SAFETY: valid handles; out-param.
    let same = unsafe {
        GetNamedPipeClientProcessId(pipe.0, &mut client_pid).is_ok()
            && client_pid == GetProcessId(helper.0)
            && WaitForSingleObject(helper.0, 0).0 == WAIT_TIMEOUT
    };
    if !same {
        return Outcome::Unavailable("helper did not connect".into());
    }
    // Duplicate the server handle into owned Files for the two directions and the closer.
    // SAFETY: the Arc keeps the original alive while we duplicate it.
    let base = unsafe { File::from_raw_handle(pipe.0 .0) };
    let dup = |f: &File| f.try_clone();
    let (writer, acks, closer) = match (dup(&base), dup(&base), dup(&base)) {
        (Ok(w), Ok(a), Ok(c)) => (w, a, c),
        _ => {
            std::mem::forget(base);
            return Outcome::Unavailable("could not duplicate the pipe".into());
        }
    };
    // `base` aliases the Arc's handle; never close it through the File.
    std::mem::forget(base);

    // Hello within its deadline, read on a thread so a silent helper cannot hold us.
    let (htx, hrx) = mpsc::channel();
    let mut reader = match acks.try_clone() {
        Ok(r) => r,
        Err(_) => return Outcome::Unavailable("could not duplicate the pipe".into()),
    };
    std::thread::spawn(move || {
        let _ = htx.send(read_hello(&mut reader));
    });
    // Bound the handshake by the smaller of its own deadline and the request's remaining time.
    let wait = HANDSHAKE_DEADLINE.min(deadline.saturating_duration_since(Instant::now()));
    let hello = match hrx.recv_timeout(wait) {
        Ok(Ok(h)) => h,
        _ => return Outcome::Unavailable("the helper did not complete its handshake".into()),
    };
    if let Err(why) = hello_acceptable(&hello, guest_sid) {
        return Outcome::Unavailable(why);
    }
    // Recheck the request is still live: a helper that connected and handshook just as the request
    // expired or was cancelled must NOT become a grant. Disconnect so that late helper exits.
    if retired.load(Ordering::SeqCst) || Instant::now() >= deadline {
        // SAFETY: valid server handle kept alive by the Arc.
        unsafe {
            let _ = DisconnectNamedPipe(pipe.0);
        }
        return Outcome::Unavailable("expired".into());
    }
    let raw = closer.as_raw_handle() as isize;
    Outcome::Granted(GrantedPipe {
        writer,
        acks,
        close: Box::new(move || {
            let _keep = &closer;
            // SAFETY: `closer` owns a duplicate of the pipe handle for the closure's lifetime.
            unsafe {
                let _ = DisconnectNamedPipe(HANDLE(raw as *mut _));
            }
        }),
    })
}

/// `ShellExecuteExW("runas")`: `Ok(Some(process))` when it started, `Ok(None)` when the guest said
/// no at the UAC prompt.
fn launch_elevated(exe: &std::path::Path, args: &str) -> io::Result<Option<Owned>> {
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from(args);
    // SAFETY: zeroed C struct, pointers valid for the call.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = PCWSTR(verb.as_ptr());
        info.lpFile = PCWSTR(file.as_ptr());
        info.lpParameters = PCWSTR(params.as_ptr());
        info.nShow = 0; // SW_HIDE: the helper has no window
        match ShellExecuteExW(&mut info) {
            Ok(()) if !info.hProcess.is_invalid() => Ok(Some(Owned(info.hProcess))),
            Ok(()) => Err(io::Error::other("no process handle")),
            Err(e) if e.code().0 as u32 == (0x8007_0000 | ERROR_CANCELLED) => Ok(None),
            Err(e) => Err(win(e)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The helper (`agent_host elevated-input --pipe <name> --parent <pid>`)

/// The helper's entry point. Exit codes: 0 served and ended; 2 bad arguments; 3 DLL search could not
/// be locked; 4 parent or pipe failed verification; 5 could not connect in time.
pub(crate) fn run_helper(args: &[String]) -> i32 {
    // §3.1 step 4: before anything else can load a DLL by search, search System32 only. Fail closed.
    // SAFETY: process-wide setting, no pointers.
    if unsafe {
        windows::Win32::System::LibraryLoader::SetDefaultDllDirectories(
            windows::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .is_err()
    {
        return 3;
    }
    let (Some(name), Some(parent)) = (
        crate::host::parse_str_arg(args, "--pipe"),
        crate::host::parse_str_arg(args, "--parent").and_then(|p| p.parse::<u32>().ok()),
    ) else {
        return 2;
    };
    if !name.starts_with(r"\\.\pipe\deskrally-elev-") {
        return 2;
    }
    let _ = crate::set_process_dpi_awareness();

    // The parent, by handle: identity and liveness from one process object.
    // SAFETY: plain OpenProcess.
    let parent_handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, parent) } {
        Ok(h) => Owned(h),
        Err(_) => return 4,
    };

    let start = Instant::now();
    let pipe = loop {
        match open_pipe_identification_only(&name) {
            Ok(f) => break f,
            Err(_) if start.elapsed() < HELPER_CONNECT_DEADLINE => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return 5,
        }
    };
    if !server_is_parent(&pipe, &parent_handle, parent) {
        return 4;
    }

    let hello = match (integrity_rid(), user_sid()) {
        (Ok(integrity_rid), Ok(user_sid)) => Hello { integrity_rid, user_sid },
        _ => return 4,
    };
    let mut writer = match pipe.try_clone() {
        Ok(w) => w,
        Err(_) => return 4,
    };
    if write_hello(&mut writer, &hello).is_err() {
        return 4;
    }

    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(tick_ms);
    let state = Arc::new(crate::elevated_input::HelperState::new(clock));
    let permit_state = Arc::clone(&state);
    let sink: Arc<dyn rmt_agent_core::InputSink> =
        Arc::new(crate::input::SendInputSink::with_press_permit(Arc::new(move || permit_state.press_permit())));

    // Parent death ends everything: close the gate, stop typing, lift what is held, exit.
    {
        let state = Arc::clone(&state);
        let sink = Arc::clone(&sink);
        let parent = parent_handle;
        std::thread::spawn(move || {
            let parent = parent; // move the owner in whole (not just its raw handle field)
            // SAFETY: valid handle owned by this thread.
            unsafe {
                let _ = WaitForSingleObject(parent.0, u32::MAX);
            }
            state.close();
            sink.cancel_typing(false);
            let _ = sink.release_held();
            std::process::exit(0);
        });
    }

    let _ = crate::elevated_input::serve(pipe, writer, sink, state);
    0
}

/// The connected server is the `--parent` process, still alive, running this same program.
fn server_is_parent(pipe: &File, parent: &Owned, parent_pid: u32) -> bool {
    let mut server_pid = 0u32;
    // SAFETY: valid handles; out-params; buffer sized.
    unsafe {
        if GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut server_pid).is_err() || server_pid != parent_pid {
            return false;
        }
        if WaitForSingleObject(parent.0, 0).0 != WAIT_TIMEOUT {
            return false;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        if QueryFullProcessImageNameW(parent.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_err() {
            return false;
        }
        let parent_image = String::from_utf16_lossy(&buf[..len as usize]);
        match std::env::current_exe() {
            Ok(me) => parent_image.eq_ignore_ascii_case(&me.to_string_lossy()),
            Err(_) => false,
        }
    }
}

/// The shared clock (docs/53 §3.3), in milliseconds: the system-wide interrupt time, identical in
/// every process on the machine and monotonic (it excludes nothing a process could adjust).
pub(crate) fn tick_ms() -> u64 {
    let mut t = 0u64;
    // SAFETY: out-param.
    unsafe {
        let _ = windows::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime(&mut t);
    }
    t / 10_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{
        RevertToSelf, SecurityIdentification, SecurityImpersonation, TokenImpersonationLevel,
        SECURITY_IMPERSONATION_LEVEL,
    };
    use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    fn pipe_name() -> String {
        format!(r"\\.\pipe\deskrally-elev-test-{}", uuid::Uuid::new_v4().simple())
    }

    #[test]
    fn token_queries_return_this_process_s_identity() {
        let rid = integrity_rid().unwrap();
        assert!((0x1000..=0x4000).contains(&rid), "a mandatory-label RID: {rid:#x}");
        assert!(user_sid().unwrap().starts_with("S-1-5-"));
        is_split_token_admin().unwrap();
    }

    #[test]
    fn the_hello_must_be_elevated_and_the_guest() {
        let me = "S-1-5-21-1-2-3-1001";
        assert!(hello_acceptable(&Hello { integrity_rid: 0x3000, user_sid: me.into() }, me).is_ok());
        assert!(hello_acceptable(&Hello { integrity_rid: 0x2000, user_sid: me.into() }, me).is_err(), "medium is refused");
        assert!(hello_acceptable(&Hello { integrity_rid: 0x3000, user_sid: "S-1-5-21-9-9-9-500".into() }, me).is_err(), "another account is refused");
        let mut buf = Vec::new();
        let h = Hello { integrity_rid: 0x3000, user_sid: me.into() };
        write_hello(&mut buf, &h).unwrap();
        assert_eq!(read_hello(&mut io::Cursor::new(buf)).unwrap(), h);
        assert!(read_hello(&mut io::Cursor::new(((MAX_HELLO + 1) as u32).to_le_bytes().to_vec())).is_err());
    }

    #[test]
    fn a_pipe_name_is_created_first_or_not_at_all() {
        let name = pipe_name();
        let sid = user_sid().unwrap();
        let _first = create_pipe(&name, &sid).unwrap();
        assert!(create_pipe(&name, &sid).is_err(), "FIRST_PIPE_INSTANCE: a second instance is refused");
    }

    /// Connect a client opened by `open`, have it write one byte, and return the impersonation level
    /// the server obtains (read before impersonating; always revert).
    fn impersonation_level(open: fn(&str) -> io::Result<File>) -> SECURITY_IMPERSONATION_LEVEL {
        let name = pipe_name();
        let server = create_pipe(&name, &user_sid().unwrap()).unwrap();
        let n2 = name.clone();
        let client = std::thread::spawn(move || {
            let mut c = open(&n2).unwrap();
            c.write_all(&[7]).unwrap();
            let mut b = [0u8; 1];
            let _ = c.read(&mut b); // hold the connection until the server is done
        });
        // SAFETY: valid server handle.
        let _ = unsafe { ConnectNamedPipe(server.0, None) };
        let mut srv = unsafe { File::from_raw_handle(server.0 .0) };
        let mut b = [0u8; 1];
        srv.read_exact(&mut b).unwrap();
        let level = unsafe {
            ImpersonateNamedPipeClient(server.0).unwrap();
            let mut token = HANDLE::default();
            let got = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token);
            let mut level = SECURITY_IMPERSONATION_LEVEL::default();
            let mut n = 0u32;
            if got.is_ok() {
                GetTokenInformation(token, TokenImpersonationLevel, Some((&mut level as *mut SECURITY_IMPERSONATION_LEVEL).cast()), 4, &mut n).unwrap();
                let _ = CloseHandle(token);
            }
            if RevertToSelf().is_err() {
                std::process::abort();
            }
            level
        };
        srv.write_all(&[0]).unwrap();
        std::mem::forget(srv); // `server` owns the handle
        client.join().unwrap();
        level
    }

    fn open_full_impersonation(name: &str) -> io::Result<File> {
        // SAFETY: plain CreateFileW without SQOS flags (the default is SecurityImpersonation).
        let h = unsafe { CreateFileW(&HSTRING::from(name), CLIENT_ACCESS, FILE_SHARE_MODE(0), None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None) }.map_err(win)?;
        Ok(unsafe { File::from_raw_handle(h.0) })
    }

    /// docs/53 §3.2: the helper's connection lets the server IDENTIFY it only. The positive control
    /// (a client without the flags) yields full impersonation, so this cannot pass by accident.
    #[test]
    fn the_helper_s_connection_is_identification_only() {
        assert_eq!(impersonation_level(open_pipe_identification_only), SecurityIdentification);
        assert_eq!(impersonation_level(open_full_impersonation), SecurityImpersonation, "positive control");
    }

    /// §3.1 step 8: the connected client must be the process we launched. Here WE are the client;
    /// claiming a different launched process is refused, and claiming ourselves passes the PID
    /// check (it then fails the handshake, which is not under test here).
    #[test]
    fn only_the_launched_process_is_accepted() {
        let check = |launched: &Owned| {
            let name = pipe_name();
            let server = Arc::new(create_pipe(&name, &user_sid().unwrap()).unwrap());
            let n2 = name.clone();
            let client = std::thread::spawn(move || {
                let c = open_pipe_identification_only(&n2).unwrap();
                std::thread::sleep(Duration::from_millis(1500));
                drop(c);
            });
            // SAFETY: valid handle.
            let _ = unsafe { ConnectNamedPipe(server.0, None) };
            let live = Instant::now() + Duration::from_secs(30);
            let retired = Arc::new(AtomicBool::new(false));
            let out = match verify_and_handshake(&server, launched, &user_sid().unwrap(), live, &retired) {
                Outcome::Unavailable(why) => why,
                Outcome::Granted(_) => "granted".into(),
                Outcome::Declined => "declined".into(),
            };
            client.join().unwrap();
            out
        };
        let mut other = std::process::Command::new("cmd.exe").args(["/c", "ping", "-n", "4", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn().unwrap();
        let other_handle = Owned(HANDLE(other.as_raw_handle()));
        assert_eq!(check(&other_handle), "helper did not connect", "a client that is not the launched process");
        std::mem::forget(other_handle); // `other` owns it
        let _ = other.kill();
        let _ = other.wait();
        // SAFETY: the pseudo-handle for this process; never closed.
        let me = std::mem::ManuallyDrop::new(Owned(unsafe { GetCurrentProcess() }));
        assert_eq!(check(&me), "the helper did not complete its handshake", "positive control: the PID check passed");
    }
}