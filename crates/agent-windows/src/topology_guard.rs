//! Runtime **display-topology guard** — the small, hardware-free pieces the Windows session
//! host uses to end a session cleanly when the display layout changes underneath it, plus the
//! stopped-state input gate every drain site routes through.
//!
//! This module deliberately contains no OS calls. The host constructs a [`TopologyGuard`] from
//! (1) an initial baseline snapshot (or `None` for the unguarded startup policy), (2) a shared
//! [`InputGate`] flag, and (3) the one-shot terminal notifier for the async loop. Every drain
//! and capture site then calls [`TopologyGuard::check`] with a closure that produces a fresh
//! observation (calling the capturer's `topology_snapshot`). The check performs these steps on the capture thread: observe, compare, and — on real change — stop the gate + send the
//! terminal notification once. On no-baseline, `check` returns false without invoking `observe`
//! and never adopts a new baseline.
//!
//! # Scope and limits (deliberately not overstated)
//!
//! There is a genuine cross-thread check/use race: the gate is a plain `AtomicBool`, and an event
//! that passes the pre-check can still land on the sink after another thread flips the flag —
//! any weakening of that would require a mutex per submit and is out of scope. The guard reduces
//! the *window* in which a change goes unobserved; it does not eliminate it.
//!
//! An observation call that fails at the API boundary yields `None` (unavailable) and is *not*
//! treated as change, so the guard cannot prove a live layout is still current — only that a
//! *change we can see* has not been ignored. Same-slot replacement whose logical output name is
//! unchanged is undetectable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rmt_agent_core::platform::PlatformResult;
use rmt_agent_core::{InputEvent, InputSink, TopologySnapshot};

/// Decide whether `fresh` describes a **changed** topology compared with `baseline`.
///
/// `None` (unavailable) is *not* change — the caller preserves the baseline. Order is
/// significant: [`TopologySnapshot`] carries the enumeration's own ordering, so a re-ordering
/// under a positional id space is a change even when the *set* of monitors is the same.
pub fn topology_changed(baseline: &TopologySnapshot, fresh: Option<&TopologySnapshot>) -> bool {
    match fresh {
        None => false,
        Some(s) => s != baseline,
    }
}

/// A shared stopped-state flag and the single gate every input drain routes through.
///
/// Cloneable, `Arc`-shared. Once [`Self::stop`] is called (by the topology observer or by any
/// other terminal path — the same flag the host uses as `session_stop`), every subsequent
/// [`Self::try_inject`] short-circuits without calling the underlying sink, and [`drain_events`]
/// discards its queue instead of injecting.
#[derive(Clone)]
pub struct InputGate {
    stopped: Arc<AtomicBool>,
}

impl InputGate {
    /// Build a gate wrapping an existing shared stop flag. Passing in the caller's flag rather
    /// than making a new one is deliberate: the same flag also controls the capture thread's
    /// outer loop and any other worker, so a single `stop()` ends every producer at once. That
    /// flag is the **session** flag — never the caller/agent lifetime flag.
    pub fn from_shared(stopped: Arc<AtomicBool>) -> Self {
        Self { stopped }
    }

    /// Whether the gate has been stopped.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Mark the gate stopped. Idempotent.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    /// Attempt to inject `ev`. Returns `Ok(true)` if the injector ran (success), `Ok(false)` if
    /// the gate was stopped, or the injector's error otherwise. The stopped check happens BEFORE
    /// the call, which shrinks (but does not eliminate — see the module docs) the window in
    /// which a racing event can land after teardown.
    pub fn try_inject<F>(&self, ev: InputEvent, inject: F) -> PlatformResult<bool>
    where
        F: FnOnce(InputEvent) -> PlatformResult<()>,
    {
        if self.is_stopped() {
            return Ok(false);
        }
        inject(ev).map(|()| true)
    }
}

/// Drain up to `cap` events from `iter`, feeding each through `gate.try_inject(inject)`. If
/// `discard_only` is true — the final teardown drain — events are pulled and dropped without
/// injection regardless of gate state.
///
/// Returns the number of events pulled. Injection errors are swallowed (logging is the caller's
/// concern; this helper is called from hot paths). The gate is the ONLY gate layer — callers
/// must not layer a second `try_inject` inside `inject`.
pub fn drain_events<I, F>(iter: I, cap: usize, gate: &InputGate, mut inject: F, discard_only: bool) -> usize
where
    I: IntoIterator<Item = InputEvent>,
    F: FnMut(InputEvent) -> PlatformResult<()>,
{
    let mut n = 0usize;
    for ev in iter.into_iter().take(cap) {
        n += 1;
        if discard_only {
            continue;
        }
        let _ = gate.try_inject(ev, |e| inject(e));
    }
    n
}

/// The observer that owns the frozen baseline snapshot, the shared gate, and the async-loop
/// terminal notifier. One `TopologyGuard` per session; the capture thread calls [`Self::check`]
/// at every drain and capture site.
pub struct TopologyGuard {
    baseline: Option<TopologySnapshot>,
    gate: InputGate,
    /// One-shot sender wrapped in a Mutex<Option<..>> so the guard can be `Sync` and any thread
    /// can consume the sender exactly once (on the first observed change).
    notifier: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl TopologyGuard {
    /// Build a guard. `baseline == None` selects the **unguarded startup policy**: [`Self::check`]
    /// returns false and never invokes the observer, so the guard never adopts a later baseline
    /// silently.
    pub fn new(
        baseline: Option<TopologySnapshot>,
        gate: InputGate,
        notifier: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            baseline,
            gate,
            notifier: Mutex::new(Some(notifier)),
        }
    }

    /// Whether this guard has a baseline (i.e. is active). Useful for logging.
    pub fn has_baseline(&self) -> bool {
        self.baseline.is_some()
    }

    /// Observe fresh topology, compare, and on real change stop the gate and fire the terminal
    /// notification exactly once. Returns `true` when a change was observed (the caller then
    /// stops what it is doing).
    ///
    /// * No baseline ⇒ returns `false`, does NOT invoke `observe`, does NOT adopt a baseline.
    /// * `observe()` returns `None` (unavailable) ⇒ returns `false`; baseline is preserved.
    /// * Fresh equals baseline ⇒ returns `false`.
    /// * Fresh differs ⇒ stops the gate, sends the notifier (if not already), returns `true`.
    pub fn check<F>(&self, observe: F) -> bool
    where
        F: FnOnce() -> Option<TopologySnapshot>,
    {
        let baseline = match self.baseline.as_ref() {
            Some(b) => b,
            None => return false,
        };
        let fresh = observe();
        if !topology_changed(baseline, fresh.as_ref()) {
            return false;
        }
        self.gate.stop();
        if let Some(tx) = self.notifier.lock().unwrap().take() {
            let _ = tx.send(());
        }
        true
    }

    /// Access the shared gate (for wiring into drain sites and teardown).
    pub fn gate(&self) -> &InputGate {
        &self.gate
    }
}

/// Session teardown for the capture thread: stop the gate, discard any remaining queued events,
/// then release everything the sink still tracks as held. Ordering matters — the gate stop
/// prevents new events from being injected between the discard and the release.
///
/// `drain` should perform a [`drain_events`] with `discard_only = true`; keeping it as a closure
/// avoids threading the `iter`'s concrete type through this helper's signature.
pub fn teardown_capture(
    gate: &InputGate,
    drain: impl FnOnce(),
    sink: &dyn InputSink,
) -> PlatformResult<()> {
    gate.stop();
    drain();
    sink.release_held()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_agent_core::platform::{MonitorInfo, PlatformError, PlatformResult};
    use std::sync::atomic::AtomicUsize;

    fn mon(id: u32, left: i32, top: i32, w: u32, h: u32, dpi: f32) -> MonitorInfo {
        MonitorInfo { id, width: w, height: h, dpi_scale: dpi, left, top }
    }
    fn snap(mons: Vec<MonitorInfo>, names: Vec<&str>) -> TopologySnapshot {
        TopologySnapshot { monitors: mons, names: names.into_iter().map(String::from).collect() }
    }
    fn baseline() -> TopologySnapshot {
        snap(
            vec![mon(0, 0, 0, 1920, 1080, 1.0), mon(1, 1920, 0, 2560, 1440, 1.5)],
            vec![r"\\.\DISPLAY1", r"\\.\DISPLAY2"],
        )
    }

    // ---- topology_changed ---------------------------------------------------------------------

    #[test]
    fn identical_snapshot_is_not_change() {
        let b = baseline();
        assert!(!topology_changed(&b, Some(&b.clone())));
    }
    #[test]
    fn unavailable_is_not_change() {
        assert!(!topology_changed(&baseline(), None));
    }
    #[test]
    fn removal_is_change() {
        let b = baseline();
        let fresh = snap(vec![b.monitors[0]], vec![r"\\.\DISPLAY1"]);
        assert!(topology_changed(&b, Some(&fresh)));
    }
    #[test]
    fn addition_is_change() {
        let b = baseline();
        let mut m = b.monitors.clone();
        m.push(mon(2, 4480, 0, 1920, 1080, 1.0));
        assert!(topology_changed(&b, Some(&snap(m, vec![r"\\.\DISPLAY1", r"\\.\DISPLAY2", r"\\.\DISPLAY3"]))));
    }
    #[test]
    fn move_is_change() {
        let b = baseline();
        let mut m = b.monitors.clone();
        m[1].left = -2560;
        assert!(topology_changed(&b, Some(&snap(m, vec![r"\\.\DISPLAY1", r"\\.\DISPLAY2"]))));
    }
    #[test]
    fn resize_is_change() {
        let b = baseline();
        let mut m = b.monitors.clone();
        m[0].width = 2560;
        assert!(topology_changed(&b, Some(&snap(m, vec![r"\\.\DISPLAY1", r"\\.\DISPLAY2"]))));
    }
    #[test]
    fn name_reassignment_at_same_rect_is_change() {
        let b = baseline();
        assert!(topology_changed(&b, Some(&snap(b.monitors.clone(), vec![r"\\.\DISPLAY1", r"\\.\DISPLAY9"]))));
    }
    #[test]
    fn dpi_change_is_change() {
        let b = baseline();
        let mut m = b.monitors.clone();
        m[0].dpi_scale = 1.25;
        assert!(topology_changed(&b, Some(&snap(m, vec![r"\\.\DISPLAY1", r"\\.\DISPLAY2"]))));
    }
    #[test]
    fn unavailable_then_changed_is_change() {
        let b = baseline();
        assert!(!topology_changed(&b, None));
        let fresh = snap(vec![b.monitors[0]], vec![r"\\.\DISPLAY1"]);
        assert!(topology_changed(&b, Some(&fresh)));
    }
    #[test]
    fn unavailable_then_same_is_not_change() {
        let b = baseline();
        assert!(!topology_changed(&b, None));
        assert!(!topology_changed(&b, Some(&b.clone())));
    }

    // ---- InputGate ----------------------------------------------------------------------------

    #[test]
    fn gate_lets_events_through_until_stopped() {
        let gate = InputGate::from_shared(Arc::new(AtomicBool::new(false)));
        let seen = Mutex::new(Vec::<InputEvent>::new());
        let ev = InputEvent::Key { code: 65, down: true };
        assert!(gate.try_inject(ev.clone(), |e| { seen.lock().unwrap().push(e); Ok(()) }).unwrap());
        gate.stop();
        assert!(!gate.try_inject(ev, |e| { seen.lock().unwrap().push(e); Ok(()) }).unwrap());
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
    #[test]
    fn drain_discards_when_told_regardless_of_gate() {
        let gate = InputGate::from_shared(Arc::new(AtomicBool::new(false)));
        let seen = Mutex::new(Vec::<InputEvent>::new());
        let events = vec![InputEvent::Key { code: 1, down: true }, InputEvent::Key { code: 2, down: true }];
        let n = drain_events(events, 16, &gate, |e| { seen.lock().unwrap().push(e); Ok(()) }, true);
        assert_eq!(n, 2);
        assert!(seen.lock().unwrap().is_empty());
    }
    #[test]
    fn drain_stopped_gate_rejects_queued_events() {
        let gate = InputGate::from_shared(Arc::new(AtomicBool::new(false)));
        gate.stop();
        let seen = Mutex::new(Vec::<InputEvent>::new());
        let events = vec![InputEvent::Text("blocked".into())];
        let n = drain_events(events, 16, &gate, |e| { seen.lock().unwrap().push(e); Ok(()) }, false);
        assert_eq!(n, 1);
        assert!(seen.lock().unwrap().is_empty());
    }
    #[test]
    fn stop_is_idempotent_and_shared_across_clones() {
        let flag = Arc::new(AtomicBool::new(false));
        let a = InputGate::from_shared(flag.clone());
        let b = a.clone();
        a.stop(); a.stop();
        assert!(b.is_stopped());
        assert!(flag.load(Ordering::Relaxed));
    }

    // ---- TopologyGuard (the shared production helper) -----------------------------------------

    fn guard(baseline: Option<TopologySnapshot>) -> (Arc<TopologyGuard>, InputGate, tokio::sync::oneshot::Receiver<()>) {
        let flag = Arc::new(AtomicBool::new(false));
        let gate = InputGate::from_shared(flag);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let g = Arc::new(TopologyGuard::new(baseline, gate.clone(), tx));
        (g, gate, rx)
    }

    #[test]
    fn no_baseline_never_calls_observer_or_adopts_baseline() {
        let (g, gate, mut rx) = guard(None);
        let calls = AtomicUsize::new(0);
        let changed = g.check(|| { calls.fetch_add(1, Ordering::Relaxed); Some(baseline()) });
        assert!(!changed);
        assert_eq!(calls.load(Ordering::Relaxed), 0, "observer must not run when no baseline");
        assert!(!g.has_baseline());
        assert!(!gate.is_stopped(), "gate stays open");
        assert!(rx.try_recv().is_err(), "no terminal notification");
    }

    #[test]
    fn unavailable_observation_is_not_change() {
        let (g, gate, mut rx) = guard(Some(baseline()));
        let changed = g.check(|| None);
        assert!(!changed);
        assert!(!gate.is_stopped());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn same_observation_is_not_change() {
        let (g, gate, mut rx) = guard(Some(baseline()));
        let changed = g.check(|| Some(baseline()));
        assert!(!changed);
        assert!(!gate.is_stopped());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn changed_stops_gate_and_sends_oneshot_and_blocks_injection() {
        let (g, gate, mut rx) = guard(Some(baseline()));
        let fresh = snap(vec![baseline().monitors[0]], vec![r"\\.\DISPLAY1"]);
        let changed = g.check(|| Some(fresh));
        assert!(changed);
        assert!(gate.is_stopped(), "gate flipped on real change");
        assert!(matches!(rx.try_recv(), Ok(())), "terminal oneshot fired");
        // Post-change injection is blocked.
        let seen = Mutex::new(0u32);
        let ok = gate.try_inject(InputEvent::Key { code: 65, down: true }, |_| { *seen.lock().unwrap() += 1; Ok(()) }).unwrap();
        assert!(!ok);
        assert_eq!(*seen.lock().unwrap(), 0);
    }

    #[test]
    fn changed_fires_notifier_only_once() {
        let (g, _gate, mut rx) = guard(Some(baseline()));
        let fresh = snap(vec![baseline().monitors[0]], vec![r"\\.\DISPLAY1"]);
        assert!(g.check(|| Some(fresh.clone())));
        assert!(g.check(|| Some(fresh)), "still returns true because change persists");
        assert!(matches!(rx.try_recv(), Ok(())));
        // Nothing else queued on the oneshot.
        assert!(rx.try_recv().is_err());
    }

    // ---- teardown_capture ---------------------------------------------------------------------

    #[derive(Default)]
    struct RecordingSink {
        release_calls: AtomicUsize,
        fail_release: AtomicBool,
    }
    impl InputSink for RecordingSink {
        fn inject(&self, _e: InputEvent) -> PlatformResult<()> { Ok(()) }
        fn release_held(&self) -> PlatformResult<()> {
            self.release_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_release.load(Ordering::Relaxed) {
                Err(PlatformError::InputRefused("test".into()))
            } else { Ok(()) }
        }
    }

    #[test]
    fn teardown_stops_gate_drains_and_releases_sink() {
        let flag = Arc::new(AtomicBool::new(false));
        let gate = InputGate::from_shared(flag);
        let sink = RecordingSink::default();
        let drained = Arc::new(AtomicUsize::new(0));
        let d = drained.clone();
        teardown_capture(&gate, || {
            assert!(gate.is_stopped(), "stop must precede draining");
            d.store(1, Ordering::Relaxed);
        }, &sink).unwrap();
        assert!(gate.is_stopped(), "gate stopped before drain");
        assert_eq!(drained.load(Ordering::Relaxed), 1, "drain ran");
        assert_eq!(sink.release_calls.load(Ordering::Relaxed), 1, "release_held actually called");
    }

    #[test]
    fn teardown_propagates_release_error_but_still_ran_drain_and_stop() {
        let flag = Arc::new(AtomicBool::new(false));
        let gate = InputGate::from_shared(flag);
        let sink = RecordingSink::default();
        sink.fail_release.store(true, Ordering::Relaxed);
        let drained = Arc::new(AtomicBool::new(false));
        let d = drained.clone();
        let res = teardown_capture(&gate, || { d.store(true, Ordering::Relaxed); }, &sink);
        assert!(res.is_err());
        assert!(gate.is_stopped());
        assert!(drained.load(Ordering::Relaxed));
        assert_eq!(sink.release_calls.load(Ordering::Relaxed), 1);
    }
}
