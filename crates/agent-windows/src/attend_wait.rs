//! The attended guest's wait for its technician (docs/27, the 2026-11-13 production incident).
//!
//! `WebRtcTransport::connect_with_ice` waits IDLE for a controller for at most 20 s
//! (`CONNECT_TIMEOUT`) and then returns `CONNECT_TIMED_OUT`. For the installed helper that is the
//! ordinary idle outcome and its reconnect loop simply goes round again. The support client used to
//! treat the same error as fatal: a guest who consented and a technician who clicked Connect a few
//! seconds after that 20 s found a process that had already exited (exit 1, nothing logged — stderr is
//! NUL in the GUI exe), and the technician saw "target unavailable".
//!
//! [`wait_for_technician`] is that loop for the attended path. It keeps asking the transport for a
//! technician until one arrives, and stops only for a reason that is NAMED to the caller:
//!
//! * `stop` is set — the status poller saw the control plane end the attended session, or the guest
//!   pressed Cancel on the waiting notice ([`WaitNotice`]);
//! * the attended session's server-side lifetime has elapsed ([`ATTEND_WAIT_CAP`]);
//! * the transport failed for a reason that is NOT "nobody asked yet".
//!
//! Each round is a fresh signaling connection and a fresh agent registration (the idle timeout drops
//! the socket), re-authenticated with the same ephemeral identity. There is therefore a window of a few
//! milliseconds between rounds in which the device is not registered; a Connect landing exactly there is
//! refused once, and the technician's next click succeeds.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the guest keeps waiting for a technician: the attended session's server-side lifetime
/// (`AttendedSessionTTL` in control-plane/attended.go, 30 minutes from redeem). After it the control
/// plane refuses this ephemeral machine's signaling authentication, so waiting longer could not end in
/// a session. The invitation CODE's 10 minute `AttendedCodeTTL` only bounds redemption, which has
/// already happened by the time this runs.
pub const ATTEND_WAIT_CAP: Duration = Duration::from_secs(30 * 60);

/// How often a connect attempt in flight checks `stop` and the deadline.
const POLL: Duration = Duration::from_millis(250);

/// Why the wait ended without a technician.
#[derive(Debug, PartialEq, Eq)]
pub enum WaitEnd {
    /// `stop` was set (session ended/expired on the control plane, or the guest cancelled).
    Stopped,
    /// [`ATTEND_WAIT_CAP`] elapsed with no technician.
    CapReached,
    /// The transport failed for a reason other than "no technician yet".
    Failed(String),
}

/// Whether a status poll's `state` means the attended session is over for good.
pub fn status_ends_session(state: &str) -> bool {
    matches!(state, "ended" | "expired")
}

/// Whether a failed connect means "nobody has asked for this machine (yet)" rather than a fault: the
/// idle timeout, or a brokered peer that did not finish negotiating (the peer is gone; staying
/// registered is what keeps the machine reachable for the next click).
fn is_wait_again(err: &str) -> bool {
    err == rmt_transport_webrtc::CONNECT_TIMED_OUT || err == rmt_transport_webrtc::NEGOTIATE_TIMED_OUT
}

/// Keep calling `connect` until it yields a technician (`Ok`), or a [`WaitEnd`] reason applies.
/// `on_wait` is told each time a round ended with nobody (round number, the transport's message).
pub async fn wait_for_technician<T, F, Fut>(
    mut connect: F,
    stop: &AtomicBool,
    deadline: Instant,
    mut on_wait: impl FnMut(u32, &str),
) -> Result<T, WaitEnd>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut rounds = 0u32;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(WaitEnd::Stopped);
        }
        if Instant::now() >= deadline {
            return Err(WaitEnd::CapReached);
        }
        let fut = connect();
        tokio::pin!(fut);
        let outcome = loop {
            tokio::select! {
                r = &mut fut => break Ok(r),
                _ = tokio::time::sleep(POLL) => {
                    if stop.load(Ordering::Relaxed) { break Err(WaitEnd::Stopped); }
                    if Instant::now() >= deadline { break Err(WaitEnd::CapReached); }
                }
            }
        };
        match outcome {
            Err(end) => return Err(end), // `fut` is dropped here, which closes its signaling socket
            Ok(Ok(t)) => return Ok(t),
            Ok(Err(e)) if is_wait_again(&e) => {
                rounds += 1;
                on_wait(rounds, &e);
            }
            Ok(Err(e)) => return Err(WaitEnd::Failed(e)),
        }
    }
}

/// What the notice's thread and its closer share: one flag, and nothing that names a thread or a window.
///
/// There is deliberately no thread id or window handle here. Windows reuses thread ids, and the notice
/// thread can exit long before the wait does (the guest clicks OK), so any id a closer held could by
/// then belong to an unrelated thread whose windows a `WM_CLOSE` would hit. The only code that ever
/// touches the notice's window is the notice thread itself.
struct NoticeShared {
    /// A close was requested. Read by the thread before it shows anything, and by its own timer while
    /// the box is up.
    closing: AtomicBool,
}

/// A small notice that tells the guest the truth while the client waits: the session is approved,
/// nothing is shared yet, and Cancel ends it. Before this existed the guest saw NOTHING at all
/// between the consent box and the technician's arrival (the session window only opens once a
/// technician is connected), with no way to stop the program short of Task Manager.
///
/// It is a message box on its own thread, so it never blocks the wait. Cancel sets `stop`; OK just
/// dismisses it (the wait carries on).
///
/// **Closing never blocks and never touches another thread.** [`WaitNotice::close`] only sets a flag.
/// The notice thread closes ITS OWN window: a close that arrives before the window exists makes the
/// thread skip showing it, and while the box is up a 100 ms timer inside the box's own message loop
/// sees the flag and posts `WM_CLOSE` to the windows of the thread it is running on. So a technician
/// who has just connected is never made to wait for a notice to go away, a wedged notice thread cannot
/// stall serving, cancelling or the expiry, and once the thread has exited (the guest clicked OK)
/// `close()` and `Drop` are inert by construction: there is nothing left for them to reach.
pub struct WaitNotice {
    shared: Arc<NoticeShared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WaitNotice {
    /// Show the notice. `cancelled` is set (and `stop` with it) when the guest presses Cancel.
    pub fn show(stop: Arc<AtomicBool>, cancelled: Arc<AtomicBool>) -> Self {
        Self::spawn(move |shared| show_message_box(&shared, &stop, &cancelled))
    }

    /// The lifecycle, with the body of the thread supplied so a test can drive it without putting a
    /// window on a real desktop.
    fn spawn(body: impl FnOnce(Arc<NoticeShared>) + Send + 'static) -> Self {
        let shared = Arc::new(NoticeShared { closing: AtomicBool::new(false) });
        let shared_t = shared.clone();
        let thread = std::thread::Builder::new().name("attend-wait-notice".into()).spawn(move || body(shared_t));
        Self { shared, thread: thread.ok() }
    }

    /// Remove the notice. Returns immediately; the thread finishes on its own (within about 100 ms if
    /// the window is up). Idempotent. It only sets a flag: no enumeration, no message to any thread.
    pub fn close(&mut self) {
        self.shared.closing.store(true, Ordering::SeqCst);
        // Detach: dropping a JoinHandle does not stop or wait for the thread.
        self.thread.take();
    }
}

impl Drop for WaitNotice {
    fn drop(&mut self) {
        self.close();
    }
}

const NOTICE_TITLE: &str = "DeskRally \u{2014} waiting for your technician";

/// Test seam: how many times anything posted a close to a thread's windows.
#[cfg(test)]
static POST_CLOSE_CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Post `WM_CLOSE` to every top-level window owned by thread `tid`. ONLY the notice thread calls this,
/// and only with its own id (from its timer), so `tid` is always a live thread of this notice.
fn post_close(tid: u32) {
    #[cfg(test)]
    POST_CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{EnumThreadWindows, PostMessageW, WM_CLOSE};
    if tid == 0 {
        return;
    }
    unsafe extern "system" fn each(hwnd: HWND, _l: LPARAM) -> BOOL {
        // SAFETY: PostMessageW with a window handle handed to us by the enumeration.
        let _ = unsafe { PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)) };
        BOOL(1)
    }
    // SAFETY: the callback is a plain function; no pointer crosses the call.
    let _ = unsafe { EnumThreadWindows(tid, Some(each), LPARAM(0)) };
}

thread_local! {
    /// The notice thread's own view of its shared state, for the timer callback (which gets no argument).
    static NOTICE_TLS: std::cell::RefCell<Option<Arc<NoticeShared>>> = const { std::cell::RefCell::new(None) };
}

unsafe extern "system" fn notice_timer(_hwnd: windows::Win32::Foundation::HWND, _msg: u32, _id: usize, _time: u32) {
    // Runs on the notice thread, inside the message box's own loop: if a close was requested, close
    // THIS thread's windows (the box). The thread id is read here, on the thread, never stored.
    let closing = NOTICE_TLS.with(|c| c.borrow().as_ref().is_some_and(|s| s.closing.load(Ordering::SeqCst)));
    if closing {
        // SAFETY: no arguments.
        post_close(unsafe { windows::Win32::System::Threading::GetCurrentThreadId() });
    }
}

fn show_message_box(shared: &Arc<NoticeShared>, stop: &AtomicBool, cancelled: &AtomicBool) {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        KillTimer, MessageBoxW, SetTimer, IDCANCEL, MB_ICONINFORMATION, MB_OKCANCEL, MB_SETFOREGROUND,
    };
    // A close that arrived before there was a window: never show one. (A close that arrives after this
    // check is caught by the timer below, within 100 ms of the box existing.)
    if shared.closing.load(Ordering::SeqCst) {
        return; // closed before the window existed: never show it
    }
    NOTICE_TLS.with(|c| *c.borrow_mut() = Some(shared.clone()));
    // SAFETY: a thread timer with no window; `notice_timer` is a plain function.
    let timer = unsafe { SetTimer(HWND::default(), 0, 100, Some(notice_timer)) };
    let title = HSTRING::from(NOTICE_TITLE);
    let text = HSTRING::from(
        "You approved this support session. Your technician has not connected yet, so \
         nothing on your screen is being shared.\n\n\
         You can leave this running; this window closes when your technician connects.\n\n\
         Click Cancel to end the session. OK only hides this message and the session keeps \
         waiting.",
    );
    // SAFETY: owned HSTRING buffers; a NULL owner is fine for a standalone notice.
    let ret = unsafe { MessageBoxW(None, &text, &title, MB_OKCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND) };
    if timer != 0 {
        // SAFETY: the timer id SetTimer returned for this thread.
        let _ = unsafe { KillTimer(HWND::default(), timer) };
    }
    NOTICE_TLS.with(|c| *c.borrow_mut() = None);
    if ret == IDCANCEL && !shared.closing.load(Ordering::SeqCst) {
        tracing::info!("attend: the guest pressed Cancel on the waiting notice");
        cancelled.store(true, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_transport_webrtc::{CONNECT_TIMED_OUT, NEGOTIATE_TIMED_OUT};
    use std::sync::atomic::AtomicU32;

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(600)
    }

    /// The incident: nobody connects within the idle window (several of them), then a technician does.
    /// The wait must go round again, not give up, and hand the technician's transport back.
    #[tokio::test]
    async fn no_technician_for_several_idle_windows_then_one_connects() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let stop = AtomicBool::new(false);
        let mut waits = Vec::new();
        let t0 = Instant::now();
        let got = wait_for_technician(
            move || {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    tokio::time::sleep(Duration::from_millis(60)).await; // the "idle window"
                    if n < 4 { Err(CONNECT_TIMED_OUT.to_string()) } else { Ok(n) }
                }
            },
            &stop,
            far(),
            |round, why| waits.push((round, why.to_string())),
        )
        .await;
        assert_eq!(got, Ok(4), "the 4th round's technician must be served");
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(waits.len(), 3, "three idle windows were reported");
        assert!(t0.elapsed() >= Duration::from_millis(180), "it really waited out the idle windows");
    }

    #[tokio::test]
    async fn a_peer_that_failed_to_negotiate_also_waits_again() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let stop = AtomicBool::new(false);
        let got = wait_for_technician(
            move || {
                let n = c.fetch_add(1, Ordering::SeqCst);
                async move { if n == 0 { Err(NEGOTIATE_TIMED_OUT.to_string()) } else { Ok(()) } }
            },
            &stop,
            far(),
            |_, _| {},
        )
        .await;
        assert_eq!(got, Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The control plane reporting the session ended (the poller sets `stop`) ends the wait, even in
    /// the middle of an idle window.
    #[tokio::test]
    async fn the_session_ended_status_stops_the_wait() {
        assert!(status_ends_session("ended") && status_ends_session("expired"));
        assert!(!status_ends_session("consented") && !status_ends_session("active") && !status_ends_session("pending"));
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            s2.store(true, Ordering::Relaxed);
        });
        let t0 = Instant::now();
        let got: Result<(), WaitEnd> = wait_for_technician(
            || async {
                tokio::time::sleep(Duration::from_secs(30)).await; // an idle window far longer than the test
                Err(CONNECT_TIMED_OUT.to_string())
            },
            &stop,
            far(),
            |_, _| {},
        )
        .await;
        assert_eq!(got, Err(WaitEnd::Stopped));
        assert!(t0.elapsed() < Duration::from_secs(5), "the stop was not noticed inside the idle window");
    }

    #[tokio::test]
    async fn the_overall_cap_ends_the_wait() {
        let stop = AtomicBool::new(false);
        let got: Result<(), WaitEnd> = wait_for_technician(
            || async {
                tokio::time::sleep(Duration::from_millis(40)).await;
                Err(CONNECT_TIMED_OUT.to_string())
            },
            &stop,
            Instant::now() + Duration::from_millis(500),
            |_, _| {},
        )
        .await;
        assert_eq!(got, Err(WaitEnd::CapReached));
        // The shipped cap is the attended session's lifetime, not something shorter.
        assert_eq!(ATTEND_WAIT_CAP, Duration::from_secs(30 * 60));
    }

    #[tokio::test]
    async fn a_real_transport_failure_is_not_waited_out() {
        let stop = AtomicBool::new(false);
        let calls = AtomicU32::new(0);
        let got: Result<(), WaitEnd> = wait_for_technician(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err("signaling closed before broker".to_string()) }
            },
            &stop,
            far(),
            |_, _| {},
        )
        .await;
        assert_eq!(got, Err(WaitEnd::Failed("signaling closed before broker".into())));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ---- the notice's lifecycle (driven with fake thread bodies: no window on a real desktop) ----

    /// A fake notice body that "creates its window" after `create_after`, honours `closing` the way
    /// the real one does, and records what happened.
    fn fake_body(
        create_after: Duration,
        honours_close: bool,
        events: Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) -> impl FnOnce(Arc<NoticeShared>) + Send + 'static {
        move |sh| {
            std::thread::sleep(create_after);
            if sh.closing.load(Ordering::SeqCst) {
                events.lock().unwrap().push("skipped");
                return;
            }
            events.lock().unwrap().push("shown");
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(5) {
                if honours_close && sh.closing.load(Ordering::SeqCst) {
                    events.lock().unwrap().push("closed");
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            events.lock().unwrap().push("timed out");
        }
    }

    fn wait_for(events: &Arc<std::sync::Mutex<Vec<&'static str>>>, n: usize) {
        let t0 = Instant::now();
        while events.lock().unwrap().len() < n && t0.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn closing_before_the_window_exists_means_it_is_never_shown() {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut n = WaitNotice::spawn(fake_body(Duration::from_millis(200), true, ev.clone()));
        let t0 = Instant::now();
        n.close(); // the thread has not "created" anything yet
        assert!(t0.elapsed() < Duration::from_millis(100), "close() blocked");
        wait_for(&ev, 1);
        assert_eq!(*ev.lock().unwrap(), vec!["skipped"]);
    }

    #[test]
    fn closing_after_the_window_exists_closes_it() {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut n = WaitNotice::spawn(fake_body(Duration::ZERO, true, ev.clone()));
        wait_for(&ev, 1);
        let t0 = Instant::now();
        n.close();
        assert!(t0.elapsed() < Duration::from_millis(100), "close() blocked");
        wait_for(&ev, 2);
        assert_eq!(*ev.lock().unwrap(), vec!["shown", "closed"]);
    }

    /// close() is a flag and nothing else: it must make no window call of its own, on any thread (a
    /// stale thread id could name an unrelated program's windows). The only code that posts a close is
    /// the notice thread's own timer, which these fake bodies do not run.
    #[test]
    fn close_makes_no_cross_thread_window_call() {
        let before = POST_CLOSE_CALLS.load(Ordering::SeqCst);
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        // Case 1: the thread is still running. Case 2: it has already exited (the guest clicked OK).
        let mut running = WaitNotice::spawn(fake_body(Duration::ZERO, true, ev.clone()));
        wait_for(&ev, 1);
        running.close();
        wait_for(&ev, 2);
        let mut exited = WaitNotice::spawn(|_sh| {});
        std::thread::sleep(Duration::from_millis(100)); // let it finish
        exited.close();
        exited.close();
        drop(exited);
        drop(running);
        assert_eq!(POST_CLOSE_CALLS.load(Ordering::SeqCst), before, "close()/Drop posted a close to a thread's windows");
    }

    #[test]
    fn closing_twice_is_harmless() {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut n = WaitNotice::spawn(fake_body(Duration::ZERO, true, ev.clone()));
        wait_for(&ev, 1);
        n.close();
        n.close();
        drop(n); // Drop closes a third time
        wait_for(&ev, 2);
        assert_eq!(*ev.lock().unwrap(), vec!["shown", "closed"]);
    }

    /// The point of the fix: a notice thread that never notices the close (a wedged message loop, a
    /// window that appears late) must not be able to hold the caller. Serving the technician comes first.
    #[test]
    fn close_returns_within_a_bound_even_if_the_notice_never_goes_away() {
        let ev = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut n = WaitNotice::spawn(fake_body(Duration::ZERO, false, ev.clone()));
        wait_for(&ev, 1);
        let t0 = Instant::now();
        n.close();
        assert!(t0.elapsed() < Duration::from_millis(250), "close() waited for a stuck notice thread: {:?}", t0.elapsed());
    }
}
