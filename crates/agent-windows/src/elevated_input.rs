//! The elevated input helper's pipe protocol and serving loop (docs/53 §3.2-§3.3).
//!
//! An attended session can forward its input to an elevated copy of this executable, run as
//! `agent_host elevated-input`, so the technician's input reaches elevated windows. The helper holds
//! no network connection and no credential: it reads frames from one named pipe and injects them.
//! This module is the platform-free core, generic over the byte streams, so it is unit-tested
//! without a pipe; the Win32 pipe, launch and handshake live with their callers.
//!
//! Frames are `[u32 LE length][u8 kind][payload]`, the length covering kind + payload and bounded by
//! [`MAX_FRAME`]. The helper answers each frame with one status byte on RECEIPT (never after the
//! injection completes), so no acknowledgement waits behind typing.
//!
//! Authority comes from the admission gate ([`rmt_agent_core::elevation_gate`]), checked at the OS
//! boundary for every press (the press permit in [`crate::input`]); this loop only feeds it. The
//! reader never injects and never takes the injection lock: injections go to a worker thread, and
//! the clean-up a revocation needs (cancel typing, release what is held) goes to a separate clean-up
//! thread, so a stalled `SendInput` delays neither the next gate frame nor the clean-up.
//!
//! Two more guarantees (1.3.16 release review): a lease that LAPSES with no revocation (a stalled
//! reader or session) runs the same clean-up, from a watchdog thread; and every injection is bound to
//! the epoch it arrived under, so input queued before a revoke never runs under a later
//! re-admission, and no press runs until the previous admission's clean-up has finished.

use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use rmt_agent_core::elevation_gate::{GateFrame, HelperGate};
use rmt_agent_core::{input_codec, InputEvent, InputSink};

/// Largest frame body (kind + payload): one input event at the codec's own limit, plus slack.
pub(crate) const MAX_FRAME: usize = input_codec::MAX_INPUT_WIRE_LEN + 64;

const KIND_GATE: u8 = 1;
const KIND_INJECT: u8 = 2;
const KIND_CANCEL_TYPING: u8 = 3;
const KIND_RELEASE_HELD: u8 = 4;
const KIND_RELEASE_KEYS: u8 = 5;

/// Status byte the helper answers each frame with.
pub(crate) const STATUS_OK: u8 = 0;

/// One session → helper frame.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum HelperFrame {
    Gate(GateFrame),
    Inject(InputEvent),
    CancelTyping,
    ReleaseHeld,
    ReleaseKeys,
}

pub(crate) fn write_frame(w: &mut impl Write, frame: &HelperFrame) -> io::Result<()> {
    let mut body = Vec::with_capacity(16);
    match frame {
        HelperFrame::Gate(g) => {
            body.push(KIND_GATE);
            body.extend(serde_json::to_vec(g).map_err(io::Error::other)?);
        }
        HelperFrame::Inject(e) => {
            body.push(KIND_INJECT);
            body.extend(input_codec::encode(e));
        }
        HelperFrame::CancelTyping => body.push(KIND_CANCEL_TYPING),
        HelperFrame::ReleaseHeld => body.push(KIND_RELEASE_HELD),
        HelperFrame::ReleaseKeys => body.push(KIND_RELEASE_KEYS),
    }
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame over the limit"));
    }
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one frame. `Ok(None)` is a clean end of stream at a frame boundary; a truncated or malformed
/// frame is an error (the helper never acts on an incomplete frame).
pub(crate) fn read_frame(r: &mut impl Read) -> io::Result<Option<HelperFrame>> {
    // Only a stream that ends BEFORE a frame's first byte ends cleanly; one cut inside the length
    // prefix is as truncated as one cut inside the body.
    let mut len = [0u8; 4];
    loop {
        match r.read(&mut len[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    r.read_exact(&mut len[1..])?;
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length out of range"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
    let payload = &body[1..];
    let frame = match body[0] {
        KIND_GATE => HelperFrame::Gate(serde_json::from_slice(payload).map_err(|_| bad("bad gate frame"))?),
        KIND_INJECT => HelperFrame::Inject(input_codec::decode(payload).map_err(|_| bad("bad input event"))?),
        KIND_CANCEL_TYPING if payload.is_empty() => HelperFrame::CancelTyping,
        KIND_RELEASE_HELD if payload.is_empty() => HelperFrame::ReleaseHeld,
        KIND_RELEASE_KEYS if payload.is_empty() => HelperFrame::ReleaseKeys,
        _ => return Err(bad("unknown frame kind")),
    };
    Ok(Some(frame))
}

/// Everything the press permit decides on, under ONE mutex so a check sees a coherent snapshot.
#[derive(Default)]
struct Core {
    gate: HelperGate,
    /// Clean-ups (cancel typing + release held) asked for and finished. While one is outstanding no
    /// press may run: a revocation's or lapse's clean-up must complete (invalidating older typing
    /// jobs and lifting what they held) before any later admission can press.
    cleanups_requested: u64,
    cleanups_done: u64,
    /// The current lease already lapsed and its clean-up was asked for; a renewal re-arms it.
    lapse_handled: bool,
    /// The epoch of the input the worker is executing (bound at dequeue). Typing that input starts
    /// presses later on the typist thread, so the binding is state, not a per-call argument.
    bound_epoch: u64,
}

/// The helper's admission state, shared by the reader (which applies gate frames), the worker
/// (which binds each injection to the epoch it arrived under), the lease watchdog, and the press
/// permit (which reads it at every press, at the OS boundary).
pub(crate) struct HelperState {
    core: Mutex<Core>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl HelperState {
    pub(crate) fn new(clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self { core: Mutex::new(Core::default()), clock }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the GATE admits a press right now (admitted, lease valid). Not the permit: see
    /// [`HelperState::press_permit`].
    pub(crate) fn may_press(&self) -> bool {
        let now = (self.clock)();
        self.lock().gate.may_press(now)
    }

    /// The press permit, checked at the OS boundary for every press: the gate admits it, no
    /// clean-up is outstanding, and the input being executed belongs to the CURRENT epoch (a
    /// backlog from before a revoke never runs under a later re-admission).
    pub(crate) fn press_permit(&self) -> bool {
        let now = (self.clock)();
        let c = self.lock();
        c.gate.may_press(now) && c.cleanups_done == c.cleanups_requested && c.bound_epoch == c.gate.epoch()
    }

    /// The epoch input arriving now belongs to.
    fn epoch(&self) -> u64 {
        self.lock().gate.epoch()
    }

    /// Whether the worker is already bound to `epoch`.
    fn is_bound(&self, epoch: u64) -> bool {
        self.lock().bound_epoch == epoch
    }

    /// Bind the worker to `epoch` before executing input that arrived under it. `false` (and no
    /// binding) when that epoch is no longer current: the input is stale and must be dropped.
    fn bind(&self, epoch: u64) -> bool {
        let mut c = self.lock();
        if c.gate.epoch() != epoch {
            return false;
        }
        c.bound_epoch = epoch;
        true
    }

    /// Apply a gate frame. Returns the clean-up to run when it ended an open admission (closed it,
    /// or moved it to a new epoch): whatever older input holds must be lifted.
    fn apply(&self, frame: GateFrame) -> Option<u64> {
        let mut c = self.lock();
        let (was_open, epoch, lease) = (c.gate.is_open(), c.gate.epoch(), c.gate.lease_until());
        c.gate.apply(frame);
        if c.gate.lease_until() > lease {
            c.lapse_handled = false;
        }
        if was_open && (!c.gate.is_open() || c.gate.epoch() != epoch) {
            c.cleanups_requested += 1;
            return Some(c.cleanups_requested);
        }
        None
    }

    /// The lease ran out with no renewal and no revocation: ask for the clean-up once per lapse.
    fn check_lapse(&self) -> Option<u64> {
        let now = (self.clock)();
        let mut c = self.lock();
        if c.lapse_handled || !c.gate.lease_lapsed(now) {
            return None;
        }
        c.lapse_handled = true;
        c.cleanups_requested += 1;
        Some(c.cleanups_requested)
    }

    fn cleanup_done(&self, seq: u64) {
        let mut c = self.lock();
        c.cleanups_done = c.cleanups_done.max(seq);
    }

    pub(crate) fn close(&self) {
        self.lock().gate.close();
    }

    #[cfg(test)]
    pub(crate) fn apply_for_tests(&self, frame: GateFrame) {
        let _ = self.apply(frame);
    }
}

/// What the worker and clean-up threads are asked to do.
enum Op {
    /// An input event and the epoch it arrived under.
    Inject(InputEvent, u64),
    CancelTyping,
    ReleaseHeld,
    ReleaseKeys,
    /// The clean-up with this sequence number has finished (queued behind its own operations).
    CleanupDone(u64),
}

fn run(sink: &dyn InputSink, state: &HelperState, op: Op) {
    let result = match op {
        Op::Inject(e, epoch) => {
            // Input from an ended admission is dropped. (Should the admission end between this check
            // and the injection, the press permit refuses its presses at the OS boundary, and any
            // typing it registers is cancelled by the next admission's first input, below.)
            if state.epoch() != epoch {
                tracing::debug!(epoch, "elevated input: dropped input from an ended admission");
                return;
            }
            if !state.is_bound(epoch) {
                // The first input of a newer admission. Typing an OLDER admission's input queued may
                // still be live: it can even have been registered after that admission's own
                // clean-up (bound, then paused before inject while the revoke ran). Invalidate it
                // here, before binding, so it can never press under this admission; nothing of this
                // admission is typing yet, since this thread submits all of its input.
                sink.cancel_typing(false);
                if !state.bind(epoch) {
                    tracing::debug!(epoch, "elevated input: dropped input from an ended admission");
                    return;
                }
            }
            sink.inject(e)
        }
        Op::CancelTyping => {
            sink.cancel_typing(false);
            Ok(())
        }
        Op::ReleaseHeld => sink.release_held(),
        Op::ReleaseKeys => sink.release_keys(),
        Op::CleanupDone(seq) => {
            state.cleanup_done(seq);
            Ok(())
        }
    };
    if let Err(e) = result {
        tracing::debug!(error = %e, "elevated input: an operation was refused");
    }
}

/// How often the lease watchdog looks for a lapsed lease: a fraction of the lease, so held input is
/// lifted soon after the lease ends even when no revocation arrives.
const LAPSE_CHECK: std::time::Duration = std::time::Duration::from_millis(rmt_agent_core::elevation_gate::LEASE_MS / 5);

/// Serve one session over `reader` / `writer` until the stream ends, breaks or carries a malformed
/// frame. Every exit closes the gate, then cancels typing and releases held input on the clean-up
/// thread, and waits for both threads before returning (so the process never exits holding a key).
pub(crate) fn serve(
    mut reader: impl Read,
    mut writer: impl Write,
    sink: Arc<dyn InputSink>,
    state: Arc<HelperState>,
) -> io::Result<()> {
    let (work_tx, work_rx) = mpsc::channel::<Op>();
    let (clean_tx, clean_rx) = mpsc::channel::<Op>();
    let worker = {
        let (sink, state) = (Arc::clone(&sink), Arc::clone(&state));
        std::thread::Builder::new()
            .name("elevated-input-worker".into())
            .spawn(move || {
                for op in work_rx {
                    run(sink.as_ref(), &state, op);
                }
            })?
    };
    let cleaner = {
        let (sink, state) = (Arc::clone(&sink), Arc::clone(&state));
        std::thread::Builder::new()
            .name("elevated-input-cleanup".into())
            .spawn(move || {
                for op in clean_rx {
                    run(sink.as_ref(), &state, op);
                }
            })?
    };
    // `seq` marks the clean-up finished once its operations ran; until then no press is permitted.
    let clean_up = |tx: &mpsc::Sender<Op>, seq: Option<u64>| {
        let _ = tx.send(Op::CancelTyping);
        let _ = tx.send(Op::ReleaseHeld);
        if let Some(seq) = seq {
            let _ = tx.send(Op::CleanupDone(seq));
        }
    };
    // The lease watchdog: a lapsed lease lifts held input without waiting for a revocation, which a
    // stalled reader or session may never deliver. Stopped by dropping `stop_tx`.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let watchdog = {
        let (state, tx) = (Arc::clone(&state), clean_tx.clone());
        std::thread::Builder::new()
            .name("elevated-input-lease".into())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) = stop_rx.recv_timeout(LAPSE_CHECK) {
                    if let Some(seq) = state.check_lapse() {
                        tracing::info!("elevated input: the lease lapsed with no renewal; lifting held input");
                        clean_up(&tx, Some(seq));
                    }
                }
            })?
    };

    let outcome = loop {
        let frame = match read_frame(&mut reader) {
            Ok(Some(f)) => f,
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        };
        match frame {
            HelperFrame::Gate(g) => {
                if let Some(seq) = state.apply(g) {
                    clean_up(&clean_tx, Some(seq));
                }
            }
            HelperFrame::Inject(e) => {
                let _ = work_tx.send(Op::Inject(e, state.epoch()));
            }
            // Ordered behind earlier input while the gate is open (a release must not overtake the
            // press it lifts); a revocation's own clean-up runs separately, above.
            HelperFrame::CancelTyping => {
                let _ = work_tx.send(Op::CancelTyping);
            }
            HelperFrame::ReleaseHeld => {
                let _ = work_tx.send(Op::ReleaseHeld);
            }
            HelperFrame::ReleaseKeys => {
                let _ = work_tx.send(Op::ReleaseKeys);
            }
        }
        if let Err(e) = writer.write_all(&[STATUS_OK]).and_then(|()| writer.flush()) {
            break Err(e);
        }
    };

    state.close();
    drop(stop_tx);
    let _ = watchdog.join();
    clean_up(&clean_tx, None);
    drop(work_tx);
    drop(clean_tx);
    let _ = worker.join();
    let _ = cleaner.join();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_agent_core::elevation_gate::Admission;
    use rmt_agent_core::platform::PlatformResult;
    use rmt_agent_core::InputButton;
    use std::io::Cursor;

    fn bytes_of(frames: &[HelperFrame]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            write_frame(&mut out, f).unwrap();
        }
        out
    }

    #[test]
    fn every_frame_kind_round_trips() {
        let frames = vec![
            HelperFrame::Gate(GateFrame::SetAdmitted { admitted: true, epoch: 1 }),
            HelperFrame::Gate(GateFrame::Renew { epoch: 1, valid_until: 250 }),
            HelperFrame::Inject(InputEvent::Key { code: 65, down: true }),
            HelperFrame::Inject(InputEvent::Text("héllo".into())),
            HelperFrame::CancelTyping,
            HelperFrame::ReleaseHeld,
            HelperFrame::ReleaseKeys,
        ];
        let mut r = Cursor::new(bytes_of(&frames));
        for f in &frames {
            assert_eq!(read_frame(&mut r).unwrap().as_ref(), Some(f));
        }
        assert_eq!(read_frame(&mut r).unwrap(), None, "a clean end at a frame boundary");
    }

    #[test]
    fn malformed_frames_are_errors_never_actions() {
        let whole = bytes_of(&[HelperFrame::Inject(InputEvent::Key { code: 65, down: true })]);
        // Truncated body.
        assert!(read_frame(&mut Cursor::new(whole[..whole.len() - 1].to_vec())).is_err());
        // Truncated length prefix: an error, not a clean end.
        assert!(read_frame(&mut Cursor::new(vec![3u8, 0])).is_err());
        // Zero and over-limit lengths.
        assert!(read_frame(&mut Cursor::new(0u32.to_le_bytes().to_vec())).is_err());
        assert!(read_frame(&mut Cursor::new(((MAX_FRAME + 1) as u32).to_le_bytes().to_vec())).is_err());
        // Unknown kind, and a payload on a bare kind.
        assert!(read_frame(&mut Cursor::new([1u32.to_le_bytes().to_vec(), vec![99]].concat())).is_err());
        assert!(read_frame(&mut Cursor::new([2u32.to_le_bytes().to_vec(), vec![KIND_RELEASE_HELD, 0]].concat())).is_err());
    }

    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);
    impl Log {
        fn take(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
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

    fn state_at(now: u64) -> Arc<HelperState> {
        Arc::new(HelperState::new(Arc::new(move || now)))
    }

    #[test]
    fn serve_injects_in_order_acks_each_frame_and_cleans_up_at_the_end() {
        let mut s = Admission::new();
        let frames = vec![
            HelperFrame::Gate(s.admit()),
            HelperFrame::Gate(s.renew(0).unwrap()),
            HelperFrame::Inject(InputEvent::Key { code: 65, down: true }),
            HelperFrame::Inject(InputEvent::Key { code: 65, down: false }),
        ];
        let log = Arc::new(Log::default());
        let state = state_at(10);
        let mut acks = Vec::new();
        serve(Cursor::new(bytes_of(&frames)), &mut acks, log.clone(), state.clone()).unwrap();
        assert_eq!(acks, vec![STATUS_OK; frames.len()], "one status byte per frame");
        let ops = log.take();
        let k = |d: bool| format!("{:?}", InputEvent::Key { code: 65, down: d });
        let (down, up) = (ops.iter().position(|o| *o == k(true)).unwrap(), ops.iter().position(|o| *o == k(false)).unwrap());
        assert!(down < up, "input keeps its order: {ops:?}");
        assert!(ops.contains(&"cancel_typing".to_string()) && ops.contains(&"release_held".to_string()), "the end of the stream cleans up: {ops:?}");
        assert!(!state.may_press(), "the gate is closed once the stream ends");
    }

    #[test]
    fn a_revocation_cleans_up_while_the_stream_continues() {
        let mut s = Admission::new();
        let frames = vec![
            HelperFrame::Gate(s.admit()),
            HelperFrame::Gate(s.renew(0).unwrap()),
            HelperFrame::Inject(InputEvent::MouseButton { button: InputButton::Left, down: true }),
            HelperFrame::Gate(s.revoke()),
        ];
        let state = state_at(10);
        // Feed the frames, then hold the stream open: the revocation's clean-up must not wait for
        // the stream to end. A reader that blocks after the frames models a live pipe.
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        tx.send(bytes_of(&frames)).unwrap();
        struct Live(mpsc::Receiver<Vec<u8>>, Vec<u8>);
        impl Read for Live {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                while self.1.is_empty() {
                    match self.0.recv() {
                        Ok(b) => self.1 = b,
                        Err(_) => return Ok(0),
                    }
                }
                let n = buf.len().min(self.1.len());
                buf[..n].copy_from_slice(&self.1[..n]);
                self.1.drain(..n);
                Ok(n)
            }
        }
        let log = Arc::new(Log::default());
        let (l2, s2) = (log.clone(), state.clone());
        let server = std::thread::spawn(move || serve(Live(rx, Vec::new()), io::sink(), l2, s2));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !log.take().contains(&"release_held".to_string()) {
            assert!(std::time::Instant::now() < deadline, "the revocation never cleaned up: {:?}", log.take());
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!state.may_press(), "the revocation closed the gate with the stream still open");
        drop(tx);
        server.join().unwrap().unwrap();
    }

    /// A reader that delivers what it is sent and then blocks, like a live pipe.
    struct Live(mpsc::Receiver<Vec<u8>>, Vec<u8>);
    impl Read for Live {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            while self.1.is_empty() {
                match self.0.recv() {
                    Ok(b) => self.1 = b,
                    Err(_) => return Ok(0),
                }
            }
            let n = buf.len().min(self.1.len());
            buf[..n].copy_from_slice(&self.1[..n]);
            self.1.drain(..n);
            Ok(n)
        }
    }

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn the_permit_binds_input_to_its_epoch_and_waits_for_clean_up() {
        let mut s = Admission::new();
        let state = state_at(10);
        state.apply_for_tests(s.admit());
        state.apply_for_tests(s.renew(10).unwrap());
        assert!(state.may_press());
        assert!(!state.press_permit(), "nothing is bound to this epoch yet");
        let first = state.epoch();
        assert!(state.bind(first));
        assert!(state.press_permit());

        // Revoke, then re-admit: the revoke asks for a clean-up; until it finishes, and while the
        // worker is still bound to the ended epoch, nothing presses.
        let seq = state.apply(s.revoke()).expect("ending an open admission asks for a clean-up");
        assert!(state.apply(s.admit()).is_none(), "admitting a closed gate has nothing to lift");
        state.apply_for_tests(s.renew(10).unwrap());
        assert!(state.may_press(), "the gate itself is open again");
        assert!(!state.press_permit(), "the clean-up is outstanding");
        state.cleanup_done(seq);
        assert!(!state.press_permit(), "the worker is still bound to the ended epoch");
        assert!(!state.bind(first), "input from the ended epoch is stale");
        assert!(state.bind(state.epoch()));
        assert!(state.press_permit());

        // Moving an OPEN admission straight to a new epoch also ends the old one.
        assert!(state.apply(s.admit()).is_some(), "a new epoch over an open one lifts the old input");
    }

    #[test]
    fn a_lapsed_lease_lifts_held_input_without_a_revocation() {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(10));
        let n = Arc::clone(&now);
        let state = Arc::new(HelperState::new(Arc::new(move || n.load(std::sync::atomic::Ordering::SeqCst))));
        let mut s = Admission::new();
        let key = InputEvent::Key { code: 17, down: true };
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        tx.send(bytes_of(&[HelperFrame::Gate(s.admit()), HelperFrame::Gate(s.renew(10).unwrap()), HelperFrame::Inject(key.clone())]))
            .unwrap();
        let log = Arc::new(Log::default());
        let (l2, s2) = (log.clone(), state.clone());
        let server = std::thread::spawn(move || serve(Live(rx, Vec::new()), io::sink(), l2, s2));
        wait_until("the key to go down", || log.take().contains(&format!("{key:?}")));
        assert!(!log.take().contains(&"release_held".to_string()), "nothing is lifted while the lease is valid");

        // The session stops renewing and no revocation ever arrives (the stream stays open).
        now.store(10 + rmt_agent_core::elevation_gate::LEASE_MS + 1, std::sync::atomic::Ordering::SeqCst);
        wait_until("the lapse to lift held input", || log.take().contains(&"release_held".to_string()));
        assert!(!state.press_permit());
        std::thread::sleep(LAPSE_CHECK * 4);
        let lifts = log.take().iter().filter(|o| *o == "release_held").count();
        assert_eq!(lifts, 1, "one clean-up per lapse, not one per check");
        drop(tx);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn input_from_before_a_revoke_never_runs_under_a_re_admission() {
        // The worker is stuck in an injection while the backlog behind it outlives a revoke and a
        // re-admission (the reader never waits for the worker).
        struct Stuck {
            log: Log,
            gate: Mutex<mpsc::Receiver<()>>,
            entered: Mutex<mpsc::Sender<()>>,
        }
        impl InputSink for Stuck {
            fn inject(&self, e: InputEvent) -> PlatformResult<()> {
                if e == (InputEvent::Key { code: 65, down: true }) {
                    let _ = self.entered.lock().unwrap().send(());
                    let _ = self.gate.lock().unwrap().recv();
                }
                self.log.inject(e)
            }
            fn release_held(&self) -> PlatformResult<()> {
                self.log.release_held()
            }
            fn cancel_typing(&self, wait: bool) {
                self.log.cancel_typing(wait)
            }
            fn release_keys(&self) -> PlatformResult<()> {
                self.log.release_keys()
            }
        }
        let (go, gate) = mpsc::channel::<()>();
        let (entered_tx, entered) = mpsc::channel::<()>();
        let sink = Arc::new(Stuck { log: Log::default(), gate: Mutex::new(gate), entered: Mutex::new(entered_tx) });
        let state = state_at(10);
        let mut s = Admission::new();
        let stale = InputEvent::Key { code: 66, down: true };
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        tx.send(bytes_of(&[
            HelperFrame::Gate(s.admit()),
            HelperFrame::Gate(s.renew(10).unwrap()),
            HelperFrame::Inject(InputEvent::Key { code: 65, down: true }),
            HelperFrame::Inject(stale.clone()),
        ]))
        .unwrap();
        let (k2, s2) = (sink.clone(), state.clone());
        let server = std::thread::spawn(move || serve(Live(rx, Vec::new()), io::sink(), k2, s2));
        // The worker is inside the first injection, the stale event queued behind it, BEFORE the
        // revoke and re-admission arrive.
        entered.recv_timeout(std::time::Duration::from_secs(5)).expect("the worker never started injecting");
        tx.send(bytes_of(&[HelperFrame::Gate(s.revoke()), HelperFrame::Gate(s.admit()), HelperFrame::Gate(s.renew(10).unwrap())]))
            .unwrap();
        let readmitted = s.epoch();
        wait_until("the re-admission to reach the helper", || state.epoch() == readmitted && state.may_press());
        go.send(()).unwrap();
        // Fresh input under the new admission still runs, behind the stale backlog.
        let fresh = InputEvent::Key { code: 67, down: true };
        tx.send(bytes_of(&[HelperFrame::Inject(fresh.clone())])).unwrap();
        wait_until("fresh input to run", || sink.log.take().contains(&format!("{fresh:?}")));
        assert!(!sink.log.take().contains(&format!("{stale:?}")), "stale input ran: {:?}", sink.log.take());
        drop(tx);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn typing_registered_after_a_revoke_never_presses_under_a_re_admission() {
        // A typist like the real one: a job keeps the generation it was registered under, a cancel
        // moves the generation, and a press needs its job's generation AND the press permit.
        struct Typist {
            log: Log,
            generation: std::sync::atomic::AtomicU64,
            jobs: Mutex<Vec<(String, u64)>>,
            pause_old: Mutex<mpsc::Receiver<()>>,
            entered: Mutex<mpsc::Sender<()>>,
        }
        impl InputSink for Typist {
            fn inject(&self, e: InputEvent) -> PlatformResult<()> {
                if let InputEvent::Text(t) = &e {
                    if t == "old" {
                        // Paused between bind() and the job's registration.
                        let _ = self.entered.lock().unwrap().send(());
                        let _ = self.pause_old.lock().unwrap().recv();
                    }
                    let generation = self.generation.load(std::sync::atomic::Ordering::SeqCst);
                    self.jobs.lock().unwrap().push((t.clone(), generation));
                }
                self.log.inject(e)
            }
            fn release_held(&self) -> PlatformResult<()> {
                self.log.release_held()
            }
            fn cancel_typing(&self, wait: bool) {
                self.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.log.cancel_typing(wait)
            }
            fn release_keys(&self) -> PlatformResult<()> {
                self.log.release_keys()
            }
        }
        let (resume, pause_old) = mpsc::channel::<()>();
        let (entered_tx, entered) = mpsc::channel::<()>();
        let sink = Arc::new(Typist {
            log: Log::default(),
            generation: Default::default(),
            jobs: Mutex::new(Vec::new()),
            pause_old: Mutex::new(pause_old),
            entered: Mutex::new(entered_tx),
        });
        let state = state_at(10);
        let mut s = Admission::new();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        tx.send(bytes_of(&[
            HelperFrame::Gate(s.admit()),
            HelperFrame::Gate(s.renew(10).unwrap()),
            HelperFrame::Inject(InputEvent::Text("old".into())),
        ]))
        .unwrap();
        let (k2, s2) = (sink.clone(), state.clone());
        let server = std::thread::spawn(move || serve(Live(rx, Vec::new()), io::sink(), k2, s2));
        // The worker bound "old" to the first admission and is paused before registering it; only
        // now do the revoke and the re-admission arrive.
        entered.recv_timeout(std::time::Duration::from_secs(5)).expect("the worker never reached the old text");
        tx.send(bytes_of(&[HelperFrame::Gate(s.revoke()), HelperFrame::Gate(s.admit()), HelperFrame::Gate(s.renew(10).unwrap())]))
            .unwrap();
        let readmitted = s.epoch();
        // The revoke's clean-up has run and the re-admission is in, while "old" is still paused.
        wait_until("the revoke's clean-up and the re-admission", || {
            state.epoch() == readmitted && state.may_press() && sink.log.take().contains(&"release_held".to_string())
        });
        resume.send(()).unwrap();
        wait_until("the old job to register", || sink.jobs.lock().unwrap().iter().any(|(t, _)| t == "old"));
        tx.send(bytes_of(&[HelperFrame::Inject(InputEvent::Text("new".into()))])).unwrap();
        wait_until("the new job to register", || sink.jobs.lock().unwrap().iter().any(|(t, _)| t == "new"));

        let current = sink.generation.load(std::sync::atomic::Ordering::SeqCst);
        let may_type = |name: &str| {
            let jobs = sink.jobs.lock().unwrap();
            let (_, generation) = jobs.iter().find(|(t, _)| t == name).unwrap().clone();
            generation == current && state.press_permit()
        };
        assert!(may_type("new"), "the re-admission's own typing presses");
        assert!(!may_type("old"), "typing registered after the revoke pressed under the re-admission");
        drop(tx);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn a_malformed_frame_ends_the_session_closed() {
        let mut s = Admission::new();
        let mut bytes = bytes_of(&[HelperFrame::Gate(s.admit()), HelperFrame::Gate(s.renew(0).unwrap())]);
        bytes.extend([1u32.to_le_bytes().to_vec(), vec![99]].concat());
        let log = Arc::new(Log::default());
        let state = state_at(10);
        assert!(serve(Cursor::new(bytes), io::sink(), log.clone(), state.clone()).is_err());
        assert!(!state.may_press());
        assert!(log.take().contains(&"release_held".to_string()));
    }
}