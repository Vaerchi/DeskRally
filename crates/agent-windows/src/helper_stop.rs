//! Graceful helper stop: the service asks its helpers to stop before it terminates them.
//!
//! Before this, the service's STOP went straight to `TerminateProcess`, so the helper's docs/49
//! shutdown drain (tear every session down, queue its `service_stop` end report, deliver for up to
//! 5 s) never ran on a service stop. A session open during a reboot, an `sc stop` or an MSI that stops
//! the service left its row open exactly as before docs/49 (docs/49, "Implementation limit").
//!
//! The channel is a **named manual-reset event**, one per service start:
//! - The service creates it before the first helper spawn with a SYSTEM-only DACL. Any process may
//!   create an event in `Global\`, so the squatting defence is the name's random 128-bit nonce plus
//!   refusing a name that already exists (the same rule as [`crate::sas::run_sas_responder`]). The
//!   name reaches each helper as `--stop-event <name>`.
//! - On STOP or PRESHUTDOWN the service sets it. Manual reset, so every helper sees it, including one
//!   that opens it late.
//! - The helper's watcher thread only records the request ([`requested`]); the existing stop paths
//!   (the stop-file watcher, the proof loop) read it and flip the same `stop` flag the stop file does,
//!   so the drain that runs is the one already tested.
//!
//! Not the shared stop file: a file outlives a crash, and a stale one would stop every later helper.
//! Signaling the event is never required for correctness. A helper that does not exit in time is
//! still terminated, exactly as before.

use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// The helper's command-line flag carrying the event name.
pub const STOP_EVENT_ARG: &str = "--stop-event";

/// Every stop event's name starts with this. The helper refuses any other name, so `--stop-event`
/// cannot be pointed at some unrelated object.
const NAME_PREFIX: &str = r"Global\DeskRallyHelperStop-";

/// SYSTEM only, EVENT_ALL_ACCESS. Both the service (the setter) and the helper (the waiter) run as
/// LocalSystem, and nothing else has a reason to touch this object.
const EVENT_SDDL: &str = "D:P(A;;0x1F0003;;;SY)";

/// Set once the service has asked this helper process to stop.
static REQUESTED: AtomicBool = AtomicBool::new(false);

/// Whether the service has asked this helper to stop. Read by the stop paths that already exist.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// A fresh event name: the fixed prefix plus a random 128-bit nonce in lowercase hex.
pub fn new_event_name() -> String {
    format!("{NAME_PREFIX}{}", uuid::Uuid::new_v4().simple())
}

/// True for a name [`new_event_name`] could have produced, and nothing else.
pub fn is_valid_event_name(name: &str) -> bool {
    name.strip_prefix(NAME_PREFIX).is_some_and(|nonce| {
        nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The `--stop-event <name>` value, if present and well-formed. A malformed value reads as absent:
/// the helper then runs without a graceful stop, which is the pre-existing behaviour.
pub fn parse_stop_event_arg(args: &[String]) -> Option<String> {
    let i = args.iter().position(|a| a == STOP_EVENT_ARG)?;
    args.get(i + 1).filter(|n| is_valid_event_name(n)).cloned()
}

/// The service's side: the event it owns for its lifetime.
pub struct StopEvent {
    handle: usize,
    name: String,
}

// SAFETY: an event handle is a kernel object reference usable from any thread; the raw value is
// stored as `usize` and closed exactly once in `Drop`.
unsafe impl Send for StopEvent {}

impl StopEvent {
    /// Create the event under a fresh name. `None` (logged) when the ACL cannot be built, the create
    /// fails, or the name already existed. The service then spawns helpers without the flag and stops
    /// them by termination alone, as it did before.
    pub fn create() -> Option<StopEvent> {
        Self::create_with(EVENT_SDDL)
    }

    /// [`StopEvent::create`] under an explicit DACL, so a test running as an administrator (not
    /// SYSTEM) can open the event it created.
    fn create_with(sddl: &str) -> Option<StopEvent> {
        use std::mem::size_of;
        use windows::Win32::Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS, FALSE, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows::Win32::System::Threading::CreateEventW;

        let name = new_event_name();
        let sddl = wide(sddl);
        let mut psd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is NUL-terminated UTF-16 outliving the call; on success `psd` is a
        // LocalAlloc'd descriptor freed once below, after CreateEventW has copied it.
        if let Err(e) = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut psd, None)
        } {
            tracing::warn!(error = %e, "helper-stop: could not build the event ACL; helpers will be terminated without a graceful stop");
            return None;
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: FALSE,
        };
        let name_w = wide(&name);
        // Manual reset, initially unset.
        // SAFETY: `sa`/`psd` outlive the call; `name_w` is NUL-terminated UTF-16.
        let created = unsafe { CreateEventW(Some(&sa), true, false, PCWSTR(name_w.as_ptr())) };
        // Read the last error BEFORE any other call: LocalFree below may overwrite it.
        // SAFETY: no arguments.
        let already_existed = created.is_ok() && unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        // SAFETY: `psd.0` came from ConvertStringSecurityDescriptorToSecurityDescriptorW; freed once.
        unsafe {
            let _ = LocalFree(HLOCAL(psd.0));
        }
        match created {
            Ok(h) => {
                // A pre-existing object is not ours: its DACL and reset type were chosen by whoever
                // created it. Refuse it (see `crate::sas::run_sas_responder`).
                if already_existed {
                    // SAFETY: our handle, closed once.
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                    tracing::warn!(event = %name, "helper-stop: event already existed (unexpected); helpers will be terminated without a graceful stop");
                    return None;
                }
                tracing::info!(event = %name, "helper-stop: event ready");
                Some(StopEvent { handle: h.0 as usize, name })
            }
            Err(e) => {
                tracing::warn!(error = %e, "helper-stop: could not create the event; helpers will be terminated without a graceful stop");
                None
            }
        }
    }

    /// The name passed to each helper as `--stop-event`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ask every helper to stop. True if the event was set.
    pub fn signal(&self) -> bool {
        use windows::Win32::System::Threading::SetEvent;
        // SAFETY: our live event handle.
        unsafe { SetEvent(HANDLE(self.handle as *mut _)).is_ok() }
    }
}

impl Drop for StopEvent {
    fn drop(&mut self) {
        // SAFETY: our handle, closed exactly once.
        unsafe {
            let _ = CloseHandle(HANDLE(self.handle as *mut _));
        }
    }
}

/// The helper's side: open `name` and start a thread that records the service's stop request.
/// Returns false (and the helper keeps running without a graceful stop) when the event cannot be
/// opened.
pub fn spawn_watcher(name: &str) -> bool {
    spawn_watcher_into(name, &REQUESTED)
}

/// [`spawn_watcher`] recording into `flag`, so a test does not set the process-wide request that
/// every stop path in the test binary reads.
fn spawn_watcher_into(name: &str, flag: &'static AtomicBool) -> bool {
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::{OpenEventW, WaitForSingleObject, INFINITE, SYNCHRONIZATION_SYNCHRONIZE};

    if !is_valid_event_name(name) {
        return false;
    }
    let name_w = wide(name);
    // SAFETY: `name_w` is NUL-terminated UTF-16 outliving the call.
    let opened = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, PCWSTR(name_w.as_ptr())) };
    let event = match opened {
        Ok(h) => h.0 as usize,
        Err(e) => {
            tracing::warn!(error = %e, event = name, "helper-stop: could not open the service's stop event; a service stop will terminate this helper");
            return false;
        }
    };
    let name = name.to_owned();
    std::thread::spawn(move || {
        // SAFETY: our handle, owned by this thread for the process lifetime.
        let rc = unsafe { WaitForSingleObject(HANDLE(event as *mut _), INFINITE) };
        if rc == WAIT_OBJECT_0 {
            tracing::info!(event = %name, "helper-stop: the service asked this helper to stop");
            flag.store(true, Ordering::SeqCst);
        } else {
            tracing::warn!(code = rc.0, event = %name, "helper-stop: wait on the stop event failed; a service stop will terminate this helper");
        }
        // SAFETY: closed exactly once.
        unsafe {
            let _ = CloseHandle(HANDLE(event as *mut _));
        }
    });
    true
}

// ---------------------------------------------------------------------------------------------
// The helper's OWN session ending (logoff, or the logoff a reboot starts with)
// ---------------------------------------------------------------------------------------------
//
// The service's stop event does not cover a reboot. Measured on the acceptance VM (2026-10-20,
// phase C): the user session's logoff killed the session-1
// helper about 0.6 s into the restart, and the SCM's PRESHUTDOWN arrived 20 s later, by which time
// the service had nothing left to drain. Only the helper hears its session ending in time, so it
// reacts itself: it requests the same stop, then holds the notification until the drain finishes or
// SESSION_END_DRAIN_WAIT passes.
//
// The channel is WM_QUERYENDSESSION / WM_ENDSESSION to a hidden TOP-LEVEL window (the tray's window
// is message-only, and message-only windows receive no broadcasts). Measured on the VM: a reboot
// delivers flags 0x40000000 and a sign-out 0xC0000000, and the drain then finishes in 0.13-0.5 s.
// Window messages are scoped to this session's desktop, so another user's sign-out never reaches
// this helper. Console control events are deliberately NOT used: CTRL_LOGOFF_EVENT has a history
// of reaching SYSTEM console processes when ANY user signs out, which would stop the console
// helper on someone else's RDP sign-out.

/// Set after the helper's streaming loop has stopped (its docs/49 drain done) or its proof loop exited.
static DRAINED: AtomicBool = AtomicBool::new(false);
/// Set once a session-end notification has requested the stop, so a second channel only waits.
static SESSION_ENDING: AtomicBool = AtomicBool::new(false);

/// How long a session-end notification is held while the drain runs. Windows terminates a process
/// that holds an end-session notification too long (a few seconds), and an idle or ordinary drain
/// takes well under one second (VM phase B: 0.23 s); this bound keeps us inside that.
const SESSION_END_DRAIN_WAIT: std::time::Duration = std::time::Duration::from_secs(4);

/// The helper calls this once its stop has fully run: the streaming loop's drain or the proof loop's
/// exit. Releases any session-end notification being held.
pub fn mark_drained() {
    DRAINED.store(true, Ordering::SeqCst);
}

/// Request the stop and hold the caller until the drain finishes or `wait` passes. Returns whether
/// the drain finished.
fn stop_and_wait_for_drain(source: &str, wait: std::time::Duration) -> bool {
    stop_and_wait_with(source, wait, &REQUESTED, &DRAINED, &SESSION_ENDING)
}

/// [`stop_and_wait_for_drain`] over explicit flags, so a test never sets the process-wide request.
fn stop_and_wait_with(
    source: &str,
    wait: std::time::Duration,
    requested: &AtomicBool,
    drained: &AtomicBool,
    ending: &AtomicBool,
) -> bool {
    if !ending.swap(true, Ordering::SeqCst) {
        tracing::info!(source, "helper-stop: this helper's session is ending; stopping sessions");
    }
    requested.store(true, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + wait;
    while !drained.load(Ordering::SeqCst) {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(source, "helper-stop: session ending before the drain finished");
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    tracing::info!(source, "helper-stop: drained before the session ended");
    true
}

/// The helper's shutdown level: the lowest application priority (0x100-0x1FF is the "last" range).
/// Windows asks the helper after every process at a higher level. The order among processes that
/// share 0x100 is unspecified.
///
/// Windows sends WM_QUERYENDSESSION, then WM_ENDSESSION, process by process from the highest level
/// down (applications default to 0x280). Measured on a Windows 11 lab VM, 2026-11-12, agent 1.3.27 at the
/// default level: a user-started restart with an app that vetoes it queried the helper and sent it
/// WM_ENDSESSION 12 ms later, so the helper stopped and the operator's session ended. In the same
/// instant the input desktop switched to Winlogon, where LogonUI draws "These apps are preventing
/// restart / Restart anyway". So the operator never saw the screen they needed to clear the
/// restart. Chrome Remote Desktop kept streaming it.
///
/// At 0x100 a blocking app (0x280) is asked first. Windows stops on its blocked-apps screen before
/// ever querying the helper, so the helper keeps streaming. The capturer already follows the
/// Winlogon desktop. Once the operator clicks "Restart anyway", or the apps close, the helper is
/// queried and drains as before. The drain stays best effort:
/// - after a FORCED "Restart anyway", Windows terminated the helper 0.4 s into its drain and its end
///   report was lost; the control plane still closed the session row when the agent dropped (VM, 2026-11-12);
/// - an ordinary unblocked restart drained and was acknowledged in 0.21 s, as at the default level.
///
/// 0x000-0x0FF and 0x400-0x4FF are reserved for the system.
pub const HELPER_SHUTDOWN_LEVEL: u32 = 0x100;

/// Arm the session-end window. Called once by the installed helper; a failure is logged and leaves
/// the helper exactly as before (killed with its session).
pub fn arm_session_end() {
    // SAFETY: plain Win32 call on this process; no pointers.
    match unsafe { windows::Win32::System::Threading::SetProcessShutdownParameters(HELPER_SHUTDOWN_LEVEL, 0) } {
        Ok(()) => tracing::info!(level = HELPER_SHUTDOWN_LEVEL, "helper-stop: shutdown level set; this helper is asked last"),
        Err(e) => tracing::warn!(error = %e, "helper-stop: shutdown level not set; a blocked restart may end the session"),
    }
    if let Err(e) = std::thread::Builder::new().name("deskrally-session-end".into()).spawn(session_end_window_thread) {
        tracing::warn!(error = %e, "helper-stop: session-end window thread not started");
    }
}

fn session_end_window_thread() {
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassExW, HMENU, MSG,
        WINDOW_EX_STYLE, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSEXW, WS_OVERLAPPED,
    };
    const CLASS: PCWSTR = windows::core::w!("DeskRallyHelperSessionEnd");

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_QUERYENDSESSION => {
                tracing::info!(flags = lp.0 as u64, "helper-stop: WM_QUERYENDSESSION");
                LRESULT(1) // never veto: allow the logoff/shutdown
            }
            WM_ENDSESSION => {
                // TRUE: the session is ending, or Restart Manager is closing this application
                // (ENDSESSION_CLOSEAPP); stopping is right for both. FALSE: a cancelled shutdown.
                // Logged on entry so a "the restart screen never showed" report can tell a cancelled
                // query from a committed shutdown or a Restart Manager close. lParam bits:
                // 0x1 CLOSEAPP, 0x40000000 CRITICAL, 0x80000000 LOGOFF.
                tracing::info!(ending = wp.0 != 0, flags = lp.0 as u64, "helper-stop: WM_ENDSESSION");
                if wp.0 != 0 {
                    stop_and_wait_for_drain("WM_ENDSESSION", SESSION_END_DRAIN_WAIT);
                }
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }

    // SAFETY: every call is on this dedicated thread; the window lives until the process exits.
    unsafe {
        let Ok(module) = GetModuleHandleW(None) else { return };
        let hinstance = HINSTANCE(module.0);
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: CLASS,
            ..Default::default()
        };
        let _ = RegisterClassExW(&wc);
        // A hidden top-level window: never shown, but on the desktop's top-level list, which is
        // where end-session messages are delivered.
        let created = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            CLASS,
            windows::core::w!("DeskRally helper"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            HMENU(std::ptr::null_mut()),
            hinstance,
            None,
        );
        if let Err(e) = created {
            tracing::warn!(error = %e, "helper-stop: session-end window not created");
            return;
        }
        tracing::info!("helper-stop: session-end window armed");
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            let _ = DispatchMessageW(&msg);
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_end_requests_the_stop_and_waits_for_the_drain_only_as_long_as_bounded() {
        use std::time::{Duration, Instant};
        // Drain finishes after ~150 ms: the notification is held exactly that long, not the bound.
        let (req, drained, ending) = (AtomicBool::new(false), std::sync::Arc::new(AtomicBool::new(false)), AtomicBool::new(false));
        let d = drained.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            d.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        assert!(stop_and_wait_with("test", Duration::from_secs(5), &req, &drained, &ending));
        t.join().unwrap();
        assert!(req.load(Ordering::SeqCst), "the session end requests the stop");
        assert!(start.elapsed() < Duration::from_secs(2), "released by the drain, not the bound: {:?}", start.elapsed());

        // Never drained: released at the bound, reporting failure.
        let (req, drained, ending) = (AtomicBool::new(false), AtomicBool::new(false), AtomicBool::new(false));
        let start = Instant::now();
        assert!(!stop_and_wait_with("test", Duration::from_millis(300), &req, &drained, &ending));
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert!(req.load(Ordering::SeqCst));
        assert!(!requested(), "the process-wide request is untouched by this test");
    }

    #[test]
    fn names_are_fresh_and_round_trip_through_the_argument() {
        let a = new_event_name();
        let b = new_event_name();
        assert_ne!(a, b, "every service start gets its own nonce");
        assert!(is_valid_event_name(&a));
        let args: Vec<String> = ["agent_host.exe", "--helper", "--session", "1", STOP_EVENT_ARG, &a]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(parse_stop_event_arg(&args).as_deref(), Some(a.as_str()));
    }

    #[test]
    fn a_name_outside_the_prefix_or_alphabet_is_refused() {
        let ok = format!("{NAME_PREFIX}{}", "0123456789abcdef0123456789abcdef");
        assert!(is_valid_event_name(&ok));
        for bad in [
            r"Global\RmtAgentSasEvent".to_string(),
            format!("{NAME_PREFIX}{}", "0123456789ABCDEF0123456789ABCDEF"),
            format!("{NAME_PREFIX}{}", "0123456789abcdef"),
            format!("{NAME_PREFIX}{}x", "0123456789abcdef0123456789abcdef"),
            format!(r"Local\DeskRallyHelperStop-{}", "0123456789abcdef0123456789abcdef"),
            String::new(),
        ] {
            assert!(!is_valid_event_name(&bad), "{bad:?} must be refused");
            let args = vec!["--helper".to_string(), STOP_EVENT_ARG.to_string(), bad.clone()];
            assert_eq!(parse_stop_event_arg(&args), None, "{bad:?} must read as absent");
        }
        assert_eq!(parse_stop_event_arg(&["--helper".into(), STOP_EVENT_ARG.into()]), None, "a missing value");
    }

    /// The production DACL admits SYSTEM only: this test process (an administrator, never SYSTEM in
    /// the gate) creates the event but cannot open it as the helper would.
    #[test]
    fn a_non_system_process_cannot_open_the_production_event() {
        static SEEN: AtomicBool = AtomicBool::new(false);
        let user = std::env::var("USERNAME").unwrap_or_default();
        assert!(!user.ends_with('$'), "this test's premise is a non-SYSTEM caller; it ran as {user:?}");
        let ev = StopEvent::create().expect("StopEvent::create");
        assert!(!spawn_watcher_into(ev.name(), &SEEN), "the SYSTEM-only DACL must refuse this caller");
    }

    /// The real kernel path, end to end in one process: create, open as the helper does, signal,
    /// observe. Records into its own flag, never the process-wide one. The DACL also admits
    /// Administrators, because this process is not SYSTEM.
    #[test]
    fn a_signal_reaches_the_watcher() {
        static SEEN: AtomicBool = AtomicBool::new(false);
        let seen = || SEEN.load(Ordering::SeqCst);
        let Some(ev) = StopEvent::create_with("D:P(A;;0x1F0003;;;SY)(A;;0x1F0003;;;BA)") else {
            panic!("StopEvent::create_with failed");
        };
        assert!(spawn_watcher_into(ev.name(), &SEEN), "the helper side opens the service's event");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!seen(), "an unset event must not read as a stop request");
        assert!(ev.signal());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !seen() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(seen(), "the watcher records the service's request");
        assert!(!requested(), "the process-wide request is untouched by this test");
    }
}
