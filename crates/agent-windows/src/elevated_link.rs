//! The session side of the elevated input helper (docs/53 §3.3): [`ElevatedSink`].
//!
//! It sits at the bottom of an attended session's input chain, where `SendInputSink` sat. With no
//! helper attached it is a pass-through to the local sink. With a helper attached, input goes to the
//! helper over its pipe, and this side owns the helper's authority:
//!
//! * **Admission** ([`Admission`]) under one mutex; a renewal thread stamps a renewal every
//!   [`RENEW_EVERY_MS`] while admitted, so the helper's lease lapses on its own if renewals stop.
//! * **A priority lane.** Gate frames and typing cancels go ahead of queued input; the writer always
//!   drains it first. Revocation needs neither the transition lock nor any ack to be queued there.
//! * **Acks drained continuously** on their own thread, so the helper never blocks writing them.
//! * **The revoke watchdog.** If a revocation is not acknowledged within [`REVOKE_ACK`], the link is
//!   closed (`close`, in production `CancelIoEx` + `CloseHandle`); the helper treats that as a
//!   revocation. That is clean-up, not the bound: the lease is the bound.
//! * **Transitions under one lock.** Attaching releases what the local sink holds first; a dead
//!   helper falls back to the local sink and reports [`LinkEvent::Ended`].
//!
//! Platform-free: the link is built over any byte streams, so tests run it against the real
//! [`crate::elevated_input::serve`] through OS anonymous pipes.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rmt_agent_core::elevation_gate::{Admission, RENEW_EVERY_MS};
use rmt_agent_core::platform::PlatformResult;
use rmt_agent_core::{InputEvent, InputSink};

use crate::elevated_input::{write_frame, HelperFrame};

/// How long [`ElevatedSink::detach`] waits for the helper to acknowledge teardown before it
/// force-closes the pipe. This is only the CLEANUP bound: input-stop is already guaranteed by the
/// admission lease ([`rmt_agent_core::elevation_gate::LEASE_MS`]), independent of any ack. Set above
/// real named-pipe round-trip latency so a healthy teardown drains cleanly and the force-close is a
/// true backstop, not the normal path.
pub(crate) const REVOKE_ACK: Duration = Duration::from_millis(500);

/// What the link reports to the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkEvent {
    /// The helper is gone (pipe closed or broken, or closed by the watchdog). Input is local again.
    Ended,
}

/// A queued frame. `seq`, when present, is set by the writer to the frame's sequence number (1-based,
/// in write order) once it is written, so the revoke watchdog knows exactly which ack covers it.
type Queued = (HelperFrame, Option<Arc<AtomicU64>>);

#[derive(Default)]
struct Queues {
    priority: VecDeque<Queued>,
    normal: VecDeque<Queued>,
    closed: bool,
}

/// One attached helper.
struct Link {
    queues: Mutex<Queues>,
    ready: Condvar,
    alive: AtomicBool,
    /// Frames written, and frames the helper acknowledged (acks arrive in order).
    written: AtomicU64,
    acked: AtomicU64,
    close: Box<dyn Fn() + Send + Sync>,
    /// Fired exactly once, from [`Link::kill`], whoever ends the link (the writer, the ack reader,
    /// the detach watchdog, or a helper crash). Reporting `Ended` here means it never depends on a
    /// blocking pipe read unblocking or on a `Weak<ElevatedSink>` upgrade.
    events: Arc<dyn Fn(LinkEvent) + Send + Sync>,
    /// `true` once [`Link::kill`] has begun. Held across the whole kill sequence so exactly one
    /// caller runs it (Ended strictly before close) and the others return without closing again.
    killed: Mutex<bool>,
}

impl Link {
    fn push(&self, frame: HelperFrame, priority: bool) {
        self.push_tracked(frame, priority, None);
    }

    fn push_tracked(&self, frame: HelperFrame, priority: bool, seq: Option<Arc<AtomicU64>>) {
        let mut q = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        if q.closed {
            return;
        }
        if priority { q.priority.push_back((frame, seq)) } else { q.normal.push_back((frame, seq)) }
        self.ready.notify_one();
    }

    /// Stop accepting frames; the writer drains what is queued, then ends.
    fn finish(&self) {
        self.queues.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.ready.notify_all();
    }

    /// End this link: stop the renew loop (via `alive`), report `Ended` once, then close the pipe.
    ///
    /// The whole sequence runs under `killed`, so one caller owns it (the writer, the ack reader, the
    /// detach watchdog, or a helper crash — whoever gets there first) and later callers return at
    /// once without closing again. `Ended` fires BEFORE the close: a real named-pipe close
    /// (DisconnectNamedPipe, which waits for the elevated helper to notice and exit) can take a
    /// moment, and the viewer's "admin rights ended" must not wait on it — nor be lost if this
    /// background thread is torn down during close.
    fn kill(&self) {
        // `alive = false` immediately (outside the guard) so the renew loop stops even while another
        // caller owns the kill sequence.
        self.alive.store(false, Ordering::SeqCst);
        self.finish();
        let mut killed = self.killed.lock().unwrap_or_else(|e| e.into_inner());
        if *killed {
            return;
        }
        *killed = true;
        (self.events)(LinkEvent::Ended);
        (self.close)();
    }
}

/// The session-side state that must change atomically together (Codex impl-A high): the session's
/// admission flag, the epoch/lease admission, and the attached link. A single mutex over all three
/// closes the attach-vs-revoke and concurrent-set_admitted races — a revocation and an attach can no
/// longer interleave into "admitted with a live link" after a revoke.
struct Core {
    /// The session's admission, as last set through [`InputSink::set_admitted`]. An attach that runs
    /// while this is false must NOT admit the helper.
    admitted: bool,
    admission: Admission,
    link: Option<Arc<Link>>,
}

/// See the module docs.
pub(crate) struct ElevatedSink {
    local: Arc<dyn InputSink>,
    core: Arc<Mutex<Core>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    events: Arc<dyn Fn(LinkEvent) + Send + Sync>,
}

impl ElevatedSink {
    pub(crate) fn new(
        local: Arc<dyn InputSink>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        events: Arc<dyn Fn(LinkEvent) + Send + Sync>,
    ) -> Self {
        Self {
            local,
            core: Arc::new(Mutex::new(Core { admitted: true, admission: Admission::new(), link: None })),
            clock,
            events,
        }
    }

    fn current(&self) -> Option<Arc<Link>> {
        self.core.lock().unwrap_or_else(|e| e.into_inner()).link.clone().filter(|l| l.alive.load(Ordering::SeqCst))
    }

    pub(crate) fn is_attached(&self) -> bool {
        self.current().is_some()
    }

    /// Attach a helper that passed its handshake. `writer` / `acks` are the pipe's two directions;
    /// `close` force-closes it (it must unblock both). Local held input is released first, so no
    /// release is ever routed to the wrong side.
    pub(crate) fn attach(
        self: &Arc<Self>,
        writer: impl Write + Send + 'static,
        acks: impl Read + Send + 'static,
        close: Box<dyn Fn() + Send + Sync>,
    ) {
        self.local.cancel_typing(true);
        let _ = self.local.release_keys();
        let _ = self.local.release_held();

        let link = Arc::new(Link {
            queues: Mutex::new(Queues::default()),
            ready: Condvar::new(),
            alive: AtomicBool::new(true),
            written: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            close,
            events: Arc::clone(&self.events),
            killed: Mutex::new(false),
        });
        // Publish the link AND decide its initial admission under the one core lock, so a concurrent
        // set_admitted(false) cannot slip between "decided admitted" and "published" (Codex impl-A).
        {
            let mut c = self.core.lock().unwrap_or_else(|e| e.into_inner());
            if c.admitted {
                link.push(HelperFrame::Gate(c.admission.admit()), true);
                if let Some(r) = c.admission.renew((self.clock)()) {
                    link.push(HelperFrame::Gate(r), true);
                }
            }
            c.link = Some(Arc::clone(&link));
        }

        // Writer: priority first, then normal, until finished and drained.
        let w_link = Arc::clone(&link);
        let mut writer = writer;
        std::thread::spawn(move || {
            loop {
                let frame = {
                    let mut q = w_link.queues.lock().unwrap_or_else(|e| e.into_inner());
                    loop {
                        if let Some(f) = q.priority.pop_front().or_else(|| q.normal.pop_front()) {
                            break Some(f);
                        }
                        if q.closed {
                            break None;
                        }
                        q = w_link.ready.wait(q).unwrap_or_else(|e| e.into_inner());
                    }
                };
                let Some((frame, seq)) = frame else { break };
                if write_frame(&mut writer, &frame).is_err() {
                    break;
                }
                let n = w_link.written.fetch_add(1, Ordering::SeqCst) + 1;
                if let Some(seq) = seq {
                    seq.store(n, Ordering::SeqCst);
                }
            }
            drop(writer);
            w_link.kill();
        });

        // Acks: one status byte per frame, drained so the helper never blocks writing them.
        let a_link = Arc::clone(&link);
        let mut acks = acks;
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                match acks.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        a_link.acked.fetch_add(n as u64, Ordering::SeqCst);
                    }
                }
            }
            a_link.kill();
        });

        // Renewals while admitted: under the core lock, and only while THIS link is still the current
        // one, so a stale thread from a replaced link can never renew (Codex impl-A).
        let r_link = Arc::clone(&link);
        let core = Arc::clone(&self.core);
        let clock = Arc::clone(&self.clock);
        std::thread::spawn(move || {
            while r_link.alive.load(Ordering::SeqCst) {
                let renewal = {
                    let mut c = core.lock().unwrap_or_else(|e| e.into_inner());
                    if c.admitted && c.link.as_ref().is_some_and(|l| Arc::ptr_eq(l, &r_link)) {
                        c.admission.renew(clock())
                    } else {
                        None
                    }
                };
                if let Some(r) = renewal {
                    r_link.push(HelperFrame::Gate(r), true);
                }
                std::thread::sleep(Duration::from_millis(RENEW_EVERY_MS));
            }
        });
    }

    /// End the grant (session teardown, or the technician giving it up): revoke, cancel typing,
    /// release held input, finish. A watchdog force-closes the pipe — and so reports `Ended` — if the
    /// helper has not acknowledged the revoke within [`REVOKE_ACK`], so teardown never waits on a
    /// stalled helper. (Input-stop is already bounded by the lease; this is only the cleanup bound.)
    pub(crate) fn detach(&self) {
        // Take the link out of `core` and revoke admission atomically, so nothing re-admits it.
        let (link, frame) = {
            let mut c = self.core.lock().unwrap_or_else(|e| e.into_inner());
            c.admitted = false;
            let frame = c.admission.revoke();
            (c.link.take(), frame)
        };
        let Some(link) = link.filter(|l| l.alive.load(Ordering::SeqCst)) else { return };
        let seq = Arc::new(AtomicU64::new(0));
        link.push_tracked(HelperFrame::Gate(frame), true, Some(Arc::clone(&seq)));
        link.push(HelperFrame::CancelTyping, true);
        link.push(HelperFrame::ReleaseHeld, false);
        link.finish();
        let w = Arc::clone(&link);
        std::thread::spawn(move || {
            std::thread::sleep(REVOKE_ACK);
            let s = seq.load(Ordering::SeqCst);
            if w.alive.load(Ordering::SeqCst) && (s == 0 || w.acked.load(Ordering::SeqCst) < s) {
                tracing::debug!("elevated input: teardown not acknowledged within the backstop; force-closing the helper's pipe");
            }
            // Either way, end the link now; kill() reports Ended exactly once.
            w.kill();
        });
    }
}

impl InputSink for ElevatedSink {
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        match self.current() {
            Some(link) => {
                link.push(HelperFrame::Inject(event), false);
                Ok(())
            }
            None => self.local.inject(event),
        }
    }

    fn release_held(&self) -> PlatformResult<()> {
        if let Some(link) = self.current() {
            link.push(HelperFrame::ReleaseHeld, false);
        }
        self.local.release_held()
    }

    fn cancel_typing(&self, wait: bool) {
        if let Some(link) = self.current() {
            link.push(HelperFrame::CancelTyping, true);
        }
        self.local.cancel_typing(wait);
    }

    fn set_admitted(&self, admitted: bool) {
        // The flag, the admission epoch mutation, and the frame to the current link all move under the
        // one core lock, so concurrent set_admitted calls (and a racing attach) linearize and the
        // final flag always matches the last epoch the helper is told about (Codex impl-A).
        {
            let mut c = self.core.lock().unwrap_or_else(|e| e.into_inner());
            c.admitted = admitted;
            if let Some(link) = c.link.clone().filter(|l| l.alive.load(Ordering::SeqCst)) {
                if admitted {
                    link.push(HelperFrame::Gate(c.admission.admit()), true);
                    if let Some(r) = c.admission.renew((self.clock)()) {
                        link.push(HelperFrame::Gate(r), true);
                    }
                } else {
                    let frame = c.admission.revoke();
                    link.push(HelperFrame::Gate(frame), true);
                }
            }
        }
        self.local.set_admitted(admitted);
    }

    fn release_keys(&self) -> PlatformResult<()> {
        if let Some(link) = self.current() {
            link.push(HelperFrame::ReleaseKeys, false);
        }
        self.local.release_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elevated_input::{serve, HelperState};
    use rmt_agent_core::InputButton;
    use std::time::Instant;

    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);
    impl Log {
        fn take(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
        fn has(&self, s: &str) -> bool {
            self.take().iter().any(|o| o == s)
        }
    }
    impl InputSink for Log {
        fn inject(&self, e: InputEvent) -> PlatformResult<()> {
            self.0.lock().unwrap().push(format!("{e:?}"));
            Ok(())
        }
        fn release_held(&self) -> PlatformResult<()> {
            self.0.lock().unwrap().push("release_held".into());
            Ok(())
        }
        fn cancel_typing(&self, _wait: bool) {
            self.0.lock().unwrap().push("cancel_typing".into());
        }
        fn release_keys(&self) -> PlatformResult<()> {
            self.0.lock().unwrap().push("release_keys".into());
            Ok(())
        }
    }

    fn clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
        let t0 = Instant::now();
        Arc::new(move || t0.elapsed().as_millis() as u64 + 1_000)
    }

    fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ok() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    struct Rig {
        sink: Arc<ElevatedSink>,
        local: Arc<Log>,
        helper: Arc<Log>,
        state: Arc<HelperState>,
        ended: Arc<AtomicU64>,
        server: Option<std::thread::JoinHandle<std::io::Result<()>>>,
        kill_helper: Arc<Mutex<Option<std::io::PipeWriter>>>,
    }

    /// A session sink attached to a real `serve` over two anonymous pipes. `ack` false makes a helper
    /// that reads frames but never acknowledges them (and never applies them).
    fn rig(ack: bool) -> Rig {
        let clock = clock();
        let local = Arc::new(Log::default());
        let helper = Arc::new(Log::default());
        let ended = Arc::new(AtomicU64::new(0));
        let e = ended.clone();
        let sink = Arc::new(ElevatedSink::new(local.clone(), clock.clone(), Arc::new(move |_| {
            e.fetch_add(1, Ordering::SeqCst);
        })));
        let (to_helper_r, to_helper_w) = std::io::pipe().unwrap();
        let (acks_r, acks_w) = std::io::pipe().unwrap();
        let state = Arc::new(HelperState::new(clock));
        let kill_helper = Arc::new(Mutex::new(None));
        let server = if ack {
            let (h, s) = (helper.clone(), state.clone());
            Some(std::thread::spawn(move || serve(to_helper_r, acks_w, h, s)))
        } else {
            *kill_helper.lock().unwrap() = Some(acks_w);
            std::thread::spawn(move || {
                let mut r = to_helper_r;
                let mut buf = [0u8; 4096];
                while matches!(r.read(&mut buf), Ok(n) if n > 0) {}
            });
            None
        };
        let k = kill_helper.clone();
        sink.attach(to_helper_w, acks_r, Box::new(move || {
            k.lock().unwrap().take();
        }));
        Rig { sink, local, helper, state, ended, server, kill_helper }
    }

    #[test]
    fn unattached_it_is_the_local_sink() {
        let local = Arc::new(Log::default());
        let s = ElevatedSink::new(local.clone(), clock(), Arc::new(|_| {}));
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        assert!(local.has(&format!("{:?}", InputEvent::Key { code: 65, down: true })));
        assert!(!s.is_attached());
    }

    #[test]
    fn attached_input_goes_to_the_helper_after_local_input_is_released() {
        let r = rig(true);
        assert!(r.local.has("release_held") && r.local.has("release_keys"), "attach releases local input first");
        wait_for("the helper's gate to open", || r.state.may_press());
        let click = InputEvent::MouseButton { button: InputButton::Left, down: true };
        r.sink.inject(click.clone()).unwrap();
        wait_for("the click at the helper", || r.helper.has(&format!("{click:?}")));
        assert!(!r.local.has(&format!("{click:?}")), "attached input never goes local");
        // Renewals keep the gate open well past one lease.
        std::thread::sleep(Duration::from_millis(3 * rmt_agent_core::elevation_gate::LEASE_MS));
        assert!(r.state.may_press(), "renewals keep the lease alive");
        r.sink.detach();
        r.server.map(|s| s.join().unwrap().unwrap());
    }

    #[test]
    fn a_revocation_closes_the_helper_gate_and_cleans_up() {
        let r = rig(true);
        wait_for("the gate to open", || r.state.may_press());
        r.sink.set_admitted(false);
        wait_for("the gate to close", || !r.state.may_press());
        wait_for("the helper's clean-up", || r.helper.has("release_held"));
        assert_eq!(r.ended.load(Ordering::SeqCst), 0, "an acknowledged revocation keeps the link");
        // Re-admission opens a new epoch on the same helper.
        r.sink.set_admitted(true);
        wait_for("the gate to reopen", || r.state.may_press());
        r.sink.detach();
        r.server.map(|s| s.join().unwrap().unwrap());
    }

    #[test]
    fn detach_ends_the_helper_and_input_goes_local_again() {
        let r = rig(true);
        wait_for("the gate to open", || r.state.may_press());
        r.sink.detach();
        r.server.map(|s| s.join().unwrap().unwrap());
        wait_for("Ended", || r.ended.load(Ordering::SeqCst) == 1);
        assert!(!r.sink.is_attached());
        assert!(r.helper.has("cancel_typing") && r.helper.has("release_held"), "detach cleaned up at the helper");
        let k = InputEvent::Key { code: 66, down: true };
        r.sink.inject(k.clone()).unwrap();
        assert!(r.local.has(&format!("{k:?}")), "after the grant, input is local");
    }

    /// Codex impl-A high: a revoke that lands BEFORE the helper is attached must leave the attached
    /// helper un-admitted — attach must not re-open a gate a prior set_admitted(false) closed. Both
    /// run under the one core lock, so this is deterministic: set_admitted(false), then attach.
    #[test]
    fn attach_after_a_revoke_does_not_admit_the_helper() {
        let clock = clock();
        let helper = Arc::new(Log::default());
        let sink = Arc::new(ElevatedSink::new(Arc::new(Nothing), clock.clone(), Arc::new(|_| {})));
        sink.set_admitted(false); // revoke lands with no link yet
        let (to_r, to_w) = std::io::pipe().unwrap();
        let (ack_r, ack_w) = std::io::pipe().unwrap();
        let state = Arc::new(HelperState::new(clock));
        let (h, s) = (helper.clone(), state.clone());
        let server = std::thread::spawn(move || serve(to_r, ack_w, h, s));
        sink.attach(to_w, ack_r, Box::new(|| {}));
        // The gate must never open, over several renew intervals.
        std::thread::sleep(Duration::from_millis(4 * RENEW_EVERY_MS));
        assert!(!state.may_press(), "attach after a revoke must not admit the helper");
        // And re-admitting now does open it.
        sink.set_admitted(true);
        wait_for("the gate to open after re-admit", || state.may_press());
        sink.detach();
        server.join().unwrap().unwrap();
    }

    struct Nothing;
    impl InputSink for Nothing {
        fn inject(&self, _: InputEvent) -> PlatformResult<()> {
            Ok(())
        }
    }

    /// A view-only toggle (set_admitted(false)) must NOT end the grant even if the helper never acks:
    /// the lease stops input on its own, and the link stays attached so re-admitting resumes it.
    #[test]
    fn set_admitted_false_does_not_tear_down_the_grant() {
        let r = rig(false);
        r.sink.set_admitted(false);
        std::thread::sleep(REVOKE_ACK + Duration::from_millis(150));
        assert_eq!(r.ended.load(Ordering::SeqCst), 0, "a view-only revoke never ends the grant");
        assert!(r.sink.is_attached(), "the helper stays attached");
        r.kill_helper.lock().unwrap().take(); // end the helper so the ack reader thread can exit
    }

    /// detach() ends the grant — Ended fires, the pipe is closed, the link detaches — even when the
    /// helper never acknowledges the teardown (whether the writer drains or the watchdog force-closes).
    #[test]
    fn detach_closes_the_link_even_when_the_helper_never_acks() {
        let r = rig(false);
        r.sink.detach();
        wait_for("the link to end", || r.ended.load(Ordering::SeqCst) == 1);
        assert!(r.kill_helper.lock().unwrap().is_none(), "close() was called");
        assert!(!r.sink.is_attached());
    }

    #[test]
    fn a_helper_that_dies_reports_ended_once_and_falls_back() {
        let r = rig(false);
        r.kill_helper.lock().unwrap().take();
        wait_for("Ended", || r.ended.load(Ordering::SeqCst) >= 1);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(r.ended.load(Ordering::SeqCst), 1, "Ended is reported exactly once");
        let k = InputEvent::Key { code: 67, down: true };
        r.sink.inject(k.clone()).unwrap();
        assert!(r.local.has(&format!("{k:?}")));
    }
}