//! Machine-wide directory of the sessions taking part in input arbitration (docs/61 stage 3).
//!
//! The viewer names a hand-off target by its **signaling session id** (a uuid string, from the
//! `session_participants` list); the input arbiter ([`crate::input_arbiter`], wired into
//! [`crate::shared_capture`]) speaks in opaque `u64` session handles. This directory is the bridge,
//! and it is also the fan-out list for the authoritative `InputControlChanged` snapshot:
//!
//! * the control handler resolves `HandInputControl { to_session }` to the target's handle
//!   ([`SessionDirectory::handle_of`]) — the arbiter then re-validates liveness/eligibility itself;
//! * every registered session holds an outbound channel its own select loop drains, so a snapshot
//!   can reach EVERY participant (design D2/D7), not just the two parties to a hand.
//!
//! It lives on the arbiter hub, so it shares the `SharedCapture` lifetime: one per helper, spanning
//! signaling reconnects (sessions outlive a connection). Snapshots are computed and sent while this
//! directory's lock is held, by callers that serialize on the hub lock — so each session's channel
//! only ever receives newer-or-equal states, in order (see `InputArbiterHub::publish`).

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::sync::Mutex;

use rmt_agent::backstage::audit::AuditAction;
use rmt_agent_core::control::{ControlMessage, InputControlMode};

use crate::input_arbiter::Mode;

/// Who is behind a session handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionIdentity {
    /// The input-arbiter handle (`SessionInputSender::handle`) this session injects under.
    pub handle: u64,
    /// The control-plane session, when signaling vouched for one (the audit chain's own session id).
    pub control_plane_session: Option<uuid::Uuid>,
    /// The technician's control-plane id, when signaling vouched for one.
    pub technician_id: Option<uuid::Uuid>,
}

/// What another party can ask a session's own task to do (docs/61). Both go through that session's
/// channel because only its task owns its transport and its audit chain.
#[derive(Debug)]
pub(crate) enum HandoffOutbound {
    /// Send this control message to the session's controller.
    Control(ControlMessage),
    /// Seal this action into the session's OWN audit chain and send the sealed event on its OWN
    /// transport, as one act — sealing anywhere else would leave a seq hole the control plane can
    /// never get past (stage 3c).
    SealAudit(AuditAction),
    /// The session's outbound queue overflowed because its loop stopped draining (an audit message could not be queued, and audit is never
    /// dropped): end this session. Delivered after everything that WAS queued, in order. The text is the logged reason.
    Disconnect(&'static str),
}


// ---------------------------------------------------------------------------------------------------
// The bounded per-session outbound channel (release review 1.3.19 E2)
// ---------------------------------------------------------------------------------------------------

/// The most NON-snapshot messages (audit seals, hand refusals) one session may have waiting. Two technicians can hand control back and
/// forth as fast as the arbiter lets them while a participant's session loop is stalled on its transport; an unbounded queue would
/// grow without limit and take the helper (and every live session) down with it.
pub(crate) const MAX_PENDING_OUTBOUND: usize = 64;

struct ChannelState {
    /// The newest `InputControlChanged` not yet delivered. Snapshots are authoritative and complete, so the latest replaces any
    /// older one still waiting (latest wins, per participant): a stalled session catches up in ONE message instead of N.
    snapshot: Option<ControlMessage>,
    /// Everything else, in order, bounded by [`MAX_PENDING_OUTBOUND`].
    queue: std::collections::VecDeque<HandoffOutbound>,
    /// Non-audit messages refused because the queue was full (counted, and logged: first and every 64th).
    dropped: u64,
    /// An AUDIT message did not fit: this participant is being disconnected. Nothing more is accepted for it.
    overflowed: bool,
    /// The `Disconnect` was handed to the receiver.
    disconnect_sent: bool,
    senders: usize,
    receiver_alive: bool,
}

struct ChannelShared {
    state: Mutex<ChannelState>,
    notify: tokio::sync::Notify,
}

/// A session's outbound channel: coalescing and bounded. `send` NEVER blocks (the callers hold the machine-wide arbiter and
/// directory locks, so waiting on a slow participant would stall everyone).
pub(crate) struct HandoffTx(std::sync::Arc<ChannelShared>);

/// The receiving end, drained by the session's own select loop.
pub(crate) struct HandoffRx(std::sync::Arc<ChannelShared>);

pub(crate) fn handoff_channel() -> (HandoffTx, HandoffRx) {
    let shared = std::sync::Arc::new(ChannelShared {
        state: Mutex::new(ChannelState {
            snapshot: None,
            queue: std::collections::VecDeque::new(),
            dropped: 0,
            overflowed: false,
            disconnect_sent: false,
            senders: 1,
            receiver_alive: true,
        }),
        notify: tokio::sync::Notify::new(),
    });
    (HandoffTx(shared.clone()), HandoffRx(shared))
}

fn lock_state(s: &ChannelShared) -> std::sync::MutexGuard<'_, ChannelState> {
    s.state.lock().unwrap_or_else(|e| e.into_inner())
}

impl Clone for HandoffTx {
    fn clone(&self) -> Self {
        lock_state(&self.0).senders += 1;
        Self(self.0.clone())
    }
}

impl Drop for HandoffTx {
    fn drop(&mut self) {
        let last = {
            let mut s = lock_state(&self.0);
            s.senders -= 1;
            s.senders == 0
        };
        if last {
            self.0.notify.notify_one();
        }
    }
}

impl Drop for HandoffRx {
    fn drop(&mut self) {
        let mut s = lock_state(&self.0);
        s.receiver_alive = false;
        s.snapshot = None;
        s.queue.clear();
    }
}

/// The message was NOT queued: the receiving session is gone, or is being disconnected because it stopped draining. Never "success".
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HandoffClosed;

impl HandoffTx {
    /// Queue `msg`. `Err` when the message was not queued: the receiver is gone, or is being disconnected. An `InputControlChanged`
    /// replaces any older undelivered snapshot (latest wins). An AUDIT action is never dropped: if it does not fit within
    /// [`MAX_PENDING_OUTBOUND`] the participant is DISCONNECTED (its receiver gets `Disconnect` after what was queued) and this returns
    /// `Err`, so no caller reports success for an undelivered seal. Other messages (hand refusals) that do not fit are dropped with a
    /// count and a logged reason.
    pub fn send(&self, msg: HandoffOutbound) -> Result<(), HandoffClosed> {
        let mut s = lock_state(&self.0);
        if !s.receiver_alive || s.overflowed {
            return Err(HandoffClosed);
        }
        match msg {
            HandoffOutbound::Control(c @ ControlMessage::InputControlChanged { .. }) => s.snapshot = Some(c),
            HandoffOutbound::SealAudit(a) if s.queue.len() >= MAX_PENDING_OUTBOUND => {
                s.overflowed = true;
                tracing::error!(
                    pending = s.queue.len(),
                    "input hand-off: a session stopped draining its outbound queue; an audit record could not be queued, so the session is disconnected (audit is never dropped)"
                );
                drop(s);
                drop(a);
                self.0.notify.notify_one();
                return Err(HandoffClosed);
            }
            other => {
                if s.queue.len() >= MAX_PENDING_OUTBOUND {
                    s.dropped += 1;
                    if s.dropped == 1 || s.dropped % 64 == 0 {
                        tracing::warn!(
                            dropped = s.dropped,
                            pending = s.queue.len(),
                            "input hand-off: a session's outbound queue is full (its loop is not draining); message dropped"
                        );
                    }
                    return Ok(());
                }
                s.queue.push_back(other);
            }
        }
        drop(s);
        self.0.notify.notify_one();
        Ok(())
    }
}

impl HandoffRx {
    fn take(&self) -> Result<HandoffOutbound, tokio::sync::mpsc::error::TryRecvError> {
        use tokio::sync::mpsc::error::TryRecvError;
        let mut s = lock_state(&self.0);
        if let Some(c) = s.snapshot.take() {
            return Ok(HandoffOutbound::Control(c));
        }
        if let Some(m) = s.queue.pop_front() {
            return Ok(m);
        }
        if s.overflowed && !s.disconnect_sent {
            s.disconnect_sent = true;
            return Ok(HandoffOutbound::Disconnect("its outbound queue overflowed (the session stopped draining hand-off audit records)"));
        }
        if s.senders == 0 {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    pub fn try_recv(&mut self) -> Result<HandoffOutbound, tokio::sync::mpsc::error::TryRecvError> {
        self.take()
    }

    /// The next message; `None` once every sender is gone and nothing is left.
    pub async fn recv(&mut self) -> Option<HandoffOutbound> {
        use tokio::sync::mpsc::error::TryRecvError;
        loop {
            match self.take() {
                Ok(m) => return Some(m),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => self.0.notify.notified().await,
            }
        }
    }

    /// How many messages were dropped for lack of room (tests, diagnostics).
    #[cfg(test)]
    pub fn dropped(&self) -> u64 {
        lock_state(&self.0).dropped
    }
}

struct Entry {
    identity: SessionIdentity,
    /// Drained by the session's own select loop.
    outbound: HandoffTx,
}

/// signaling-session-id → entry. Small (one entry per concurrent session), so the reverse lookup
/// (handle → signaling id) iterates rather than keeping a second map.
#[derive(Default)]
pub(crate) struct SessionDirectory {
    entries: Mutex<HashMap<String, Entry>>,
}

/// Reverse lookup over a locked map: the signaling id whose entry holds `handle`.
fn signaling_id_of(map: &HashMap<String, Entry>, handle: u64) -> Option<String> {
    map.iter().find(|(_, e)| e.identity.handle == handle).map(|(id, _)| id.clone())
}

impl SessionDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) `signaling_id`, then — under the same lock — compute this session's
    /// join greeting with `greet` and queue it on ITS channel only. Holding the lock across the insert
    /// and the greeting is what keeps the greeting from being overtaken by an older broadcast.
    pub fn insert_with_greeting(
        &self,
        signaling_id: impl Into<String>,
        identity: SessionIdentity,
        outbound: HandoffTx,
        greet: impl FnOnce(&dyn Fn(u64) -> Option<String>) -> Option<ControlMessage>,
    ) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(signaling_id.into(), Entry { identity, outbound: outbound.clone() });
        let sid_of = |h: u64| signaling_id_of(&map, h);
        if let Some(msg) = greet(&sid_of) {
            let _ = outbound.send(HandoffOutbound::Control(msg));
        }
    }

    /// Drop `signaling_id`'s entry, but only if it still belongs to `handle`: a stale session's
    /// teardown must never remove the entry a newer session registered under the same id.
    pub fn remove_if_handle(&self, signaling_id: &str, handle: u64) -> bool {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(signaling_id).is_some_and(|e| e.identity.handle == handle) {
            map.remove(signaling_id);
            true
        } else {
            false
        }
    }

    /// Resolve a signaling id to its identity. `None` if unknown or departed.
    pub fn resolve(&self, signaling_id: &str) -> Option<SessionIdentity> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(signaling_id)
            .map(|e| e.identity.clone())
    }

    /// Resolve a signaling id straight to its arbiter handle (the hand-target path).
    pub fn handle_of(&self, signaling_id: &str) -> Option<u64> {
        self.resolve(signaling_id).map(|i| i.handle)
    }

    /// Compute one message under the lock (with a handle → signaling-id resolver over the locked map)
    /// and queue it on EVERY registered session's channel. A closed channel (a session already
    /// ending) is skipped; its own teardown removes the entry.
    pub fn broadcast_with(&self, compute: impl FnOnce(&dyn Fn(u64) -> Option<String>) -> Option<ControlMessage>) {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let sid_of = |h: u64| signaling_id_of(&map, h);
        if let Some(msg) = compute(&sid_of) {
            for entry in map.values() {
                let _ = entry.outbound.send(HandoffOutbound::Control(msg.clone()));
            }
        }
    }

    /// The identity registered under arbiter `handle`, if a live session holds it.
    pub fn identity_of_handle(&self, handle: u64) -> Option<SessionIdentity> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|e| e.identity.handle == handle)
            .map(|e| e.identity.clone())
    }

    /// Both parties' identities read under ONE lock, so the record of a hand describes a single
    /// instant rather than two lookups that can straddle a departure (Codex 3c review).
    pub fn identities_of(&self, a: u64, b: u64) -> (Option<SessionIdentity>, Option<SessionIdentity>) {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let find = |h: u64| map.values().find(|e| e.identity.handle == h).map(|e| e.identity.clone());
        (find(a), find(b))
    }

    /// Queue `msg` on the channel of the session holding arbiter `handle`. `false` if none does (it
    /// left) or its channel is closed (it is ending).
    pub fn send_to_handle(&self, handle: u64, msg: HandoffOutbound) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|e| e.identity.handle == handle)
            .is_some_and(|e| e.outbound.send(msg).is_ok())
    }

    /// How many sessions are registered (tests / diagnostics).
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether any session is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The authoritative `InputControlChanged` for an arbitration `mode`, or `None` when there is nothing
/// to announce:
///
/// * `Unowned` — compatibility mode; the viewer's default is already "shared", so nothing is sent
///   (arbitration never returns to `Unowned` once armed, design D2);
/// * `Transitioning` — transient; the commit that follows announces the result;
/// * `Owned` whose owner no longer resolves — the owner is departing; the `Blocked` its teardown
///   publishes is what gets announced.
///
/// `owner_name` is `None` in v1: signaling carries no technician display names (the viewer renders
/// "you" / "another technician" from `owner_session`).
pub(crate) fn input_control_snapshot(mode: &Mode, sid_of: &dyn Fn(u64) -> Option<String>) -> Option<ControlMessage> {
    match mode {
        Mode::Unowned | Mode::Transitioning { .. } => None,
        Mode::Owned { who } => sid_of(who.handle).map(|sid| ControlMessage::InputControlChanged {
            owner_session: Some(sid),
            owner_name: None,
            mode: InputControlMode::Owned,
        }),
        Mode::Blocked => Some(ControlMessage::InputControlChanged {
            owner_session: None,
            owner_name: None,
            mode: InputControlMode::Blocked,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input_arbiter::Member;
    use super::handoff_channel as unbounded_channel;

    fn ident(handle: u64) -> SessionIdentity {
        SessionIdentity {
            handle,
            control_plane_session: Some(uuid::Uuid::from_u128(handle as u128)),
            technician_id: Some(uuid::Uuid::from_u128(1000 + handle as u128)),
        }
    }

    /// The control messages queued on a channel (a SealAudit here would be a bug in these tests).
    fn drain(rx: &mut HandoffRx) -> Vec<ControlMessage> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            match m {
                HandoffOutbound::Control(c) => out.push(c),
                other => panic!("unexpected {other:?}"),
            }
        }
        out
    }

    fn owned(sid: &str) -> ControlMessage {
        ControlMessage::InputControlChanged { owner_session: Some(sid.into()), owner_name: None, mode: InputControlMode::Owned }
    }

    fn blocked() -> ControlMessage {
        ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Blocked }
    }

    #[test]
    fn insert_resolve_remove_round_trips() {
        let d = SessionDirectory::new();
        let (tx, _rx) = unbounded_channel();
        assert!(d.is_empty());
        d.insert_with_greeting("sig-a", ident(10), tx.clone(), |_| None);
        d.insert_with_greeting("sig-b", ident(20), tx, |_| None);
        assert_eq!(d.len(), 2);
        assert_eq!(d.resolve("sig-a"), Some(ident(10)));
        assert_eq!(d.handle_of("sig-b"), Some(20));
        assert_eq!(d.handle_of("sig-missing"), None);
        assert!(d.remove_if_handle("sig-a", 10));
        assert_eq!(d.handle_of("sig-a"), None);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn a_stale_teardown_never_removes_a_newer_entry() {
        // A reconnect re-registered the same signaling id under a NEW handle; the old session's
        // late teardown must leave the new entry in place.
        let d = SessionDirectory::new();
        let (tx, _rx) = unbounded_channel();
        d.insert_with_greeting("sig", ident(1), tx.clone(), |_| None);
        d.insert_with_greeting("sig", ident(2), tx, |_| None);
        assert!(!d.remove_if_handle("sig", 1), "stale teardown removed the newer entry");
        assert_eq!(d.handle_of("sig"), Some(2));
        assert!(d.remove_if_handle("sig", 2));
        assert!(d.is_empty());
    }

    #[test]
    fn broadcast_reaches_every_session_and_resolves_the_owner() {
        let d = SessionDirectory::new();
        let (tx_a, mut rx_a) = unbounded_channel();
        let (tx_b, mut rx_b) = unbounded_channel();
        d.insert_with_greeting("sig-a", ident(10), tx_a, |_| None);
        d.insert_with_greeting("sig-b", ident(20), tx_b, |_| None);
        let mode = Mode::Owned { who: Member { handle: 20, incarnation: 1 } };
        d.broadcast_with(|sid_of| input_control_snapshot(&mode, sid_of));
        assert_eq!(drain(&mut rx_a), vec![owned("sig-b")]);
        assert_eq!(drain(&mut rx_b), vec![owned("sig-b")]);
    }

    #[test]
    fn the_join_greeting_goes_only_to_the_joiner() {
        let d = SessionDirectory::new();
        let (tx_a, mut rx_a) = unbounded_channel();
        let (tx_b, mut rx_b) = unbounded_channel();
        d.insert_with_greeting("sig-a", ident(10), tx_a, |_| None);
        let mode = Mode::Owned { who: Member { handle: 10, incarnation: 1 } };
        // B joins while A owns input: B (only) is greeted with the current snapshot naming A.
        d.insert_with_greeting("sig-b", ident(20), tx_b, |sid_of| input_control_snapshot(&mode, sid_of));
        assert_eq!(drain(&mut rx_b), vec![owned("sig-a")]);
        assert!(drain(&mut rx_a).is_empty(), "an existing session was re-greeted");
    }

    #[test]
    fn a_closed_channel_does_not_stop_the_fanout() {
        let d = SessionDirectory::new();
        let (tx_a, rx_a) = unbounded_channel();
        let (tx_b, mut rx_b) = unbounded_channel();
        d.insert_with_greeting("sig-a", ident(10), tx_a, |_| None);
        d.insert_with_greeting("sig-b", ident(20), tx_b, |_| None);
        drop(rx_a); // A's session is ending
        d.broadcast_with(|sid_of| input_control_snapshot(&Mode::Blocked, sid_of));
        assert_eq!(drain(&mut rx_b), vec![blocked()]);
    }

    #[test]
    fn snapshot_announces_only_settled_states() {
        let none = |_: u64| None::<String>;
        let some = |h: u64| (h == 7).then(|| "sig-7".to_string());
        assert_eq!(input_control_snapshot(&Mode::Unowned, &some), None);
        assert_eq!(
            input_control_snapshot(&Mode::Transitioning { id: 1, to: Member { handle: 7, incarnation: 1 } }, &some),
            None
        );
        let owner = Mode::Owned { who: Member { handle: 7, incarnation: 1 } };
        assert_eq!(input_control_snapshot(&owner, &some), Some(owned("sig-7")));
        // An owner that no longer resolves (departing) is not announced; its Blocked will be.
        assert_eq!(input_control_snapshot(&owner, &none), None);
        assert_eq!(input_control_snapshot(&Mode::Blocked, &none), Some(blocked()));
    }

    #[test]
    fn send_to_handle_reaches_only_that_session() {
        let d = SessionDirectory::new();
        let (tx_a, mut rx_a) = unbounded_channel();
        let (tx_b, mut rx_b) = unbounded_channel();
        d.insert_with_greeting("sig-a", ident(10), tx_a, |_| None);
        d.insert_with_greeting("sig-b", ident(20), tx_b, |_| None);
        assert_eq!(d.identity_of_handle(20), Some(ident(20)));
        assert!(d.send_to_handle(20, HandoffOutbound::Control(blocked())));
        assert_eq!(drain(&mut rx_b), vec![blocked()]);
        assert!(drain(&mut rx_a).is_empty());
        // A handle no session holds is reported, not silently dropped.
        assert!(!d.send_to_handle(99, HandoffOutbound::Control(blocked())));
        assert_eq!(d.identity_of_handle(99), None);
    }

    // ---- release review 1.3.19 E2: the per-session channel is bounded and coalescing ----------------------------------

    fn seal(epoch: u64) -> HandoffOutbound {
        let nil = uuid::Uuid::nil();
        HandoffOutbound::SealAudit(AuditAction::InputControlHanded { from_session: nil, from_technician: nil, to_session: nil, to_technician: nil, epoch })
    }

    #[test]
    fn undelivered_snapshots_coalesce_latest_wins_per_participant() {
        let (tx, mut rx) = handoff_channel();
        for i in 0..10_000 {
            let sid = format!("sig-{i}");
            tx.send(HandoffOutbound::Control(owned(&sid))).unwrap();
        }
        assert_eq!(drain(&mut rx), vec![owned("sig-9999")], "a stalled session catches up in ONE authoritative message");
        assert_eq!(rx.dropped(), 0);
    }

    #[test]
    fn audit_actions_are_never_dropped_an_overflow_disconnects_and_never_reports_success() {
        let (tx, mut rx) = handoff_channel();
        for e in 0..MAX_PENDING_OUTBOUND as u64 {
            tx.send(seal(e)).unwrap();
        }
        // The next seal does not fit: NOT success, the participant is disconnected, and nothing more is accepted for it.
        assert_eq!(tx.send(seal(999)), Err(HandoffClosed));
        assert_eq!(tx.send(seal(1000)), Err(HandoffClosed));
        assert_eq!(tx.send(HandoffOutbound::Control(blocked())), Err(HandoffClosed));
        let mut epochs = Vec::new();
        let mut disconnected = 0;
        while let Ok(m) = rx.try_recv() {
            match m {
                HandoffOutbound::SealAudit(AuditAction::InputControlHanded { epoch, .. }) => {
                    assert_eq!(disconnected, 0, "the disconnect comes after everything that was queued");
                    epochs.push(epoch)
                }
                HandoffOutbound::Disconnect(_) => disconnected += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(epochs, (0..MAX_PENDING_OUTBOUND as u64).collect::<Vec<_>>(), "what was queued is delivered, in order");
        assert_eq!(disconnected, 1, "exactly one disconnect");
        assert_eq!(rx.dropped(), 0, "an audit record is never counted-and-dropped");
    }

    #[test]
    fn a_stalled_participant_is_disconnected_while_the_others_audit_sequence_stays_complete_and_ordered() {
        let d = SessionDirectory::new();
        let (tx_stalled, mut rx_stalled) = handoff_channel();
        let (tx_ok, mut rx_ok) = handoff_channel();
        d.insert_with_greeting("sig-stalled", ident(10), tx_stalled, |_| None);
        d.insert_with_greeting("sig-ok", ident(20), tx_ok, |_| None);
        // Repeated hand-offs between them: each seals into both parties. The healthy one drains every round; the stalled one never does.
        let mut ok_epochs = Vec::new();
        let mut stalled_ok = 0;
        let mut stalled_refused = 0;
        let rounds = MAX_PENDING_OUTBOUND as u64 * 3;
        for e in 0..rounds {
            if d.send_to_handle(10, seal(e)) { stalled_ok += 1 } else { stalled_refused += 1 }
            assert!(d.send_to_handle(20, seal(e)), "the healthy participant is never refused");
            while let Ok(m) = rx_ok.try_recv() {
                match m {
                    HandoffOutbound::SealAudit(AuditAction::InputControlHanded { epoch, .. }) => ok_epochs.push(epoch),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(ok_epochs, (0..rounds).collect::<Vec<_>>(), "the others' audit sequence is complete and ordered");
        assert_eq!(stalled_ok, MAX_PENDING_OUTBOUND, "the stalled one accepted exactly its bound");
        assert_eq!(stalled_refused as u64, rounds - MAX_PENDING_OUTBOUND as u64, "every later seal for it reported FAILURE, not success");
        let mut got = Vec::new();
        while let Ok(m) = rx_stalled.try_recv() {
            got.push(m);
        }
        assert!(matches!(got.last(), Some(HandoffOutbound::Disconnect(_))), "the stalled participant's session is told to end");
        assert_eq!(got.len(), MAX_PENDING_OUTBOUND + 1);
    }

    #[test]
    fn a_snapshot_is_never_starved_by_a_full_audit_queue() {
        let (tx, mut rx) = handoff_channel();
        for e in 0..MAX_PENDING_OUTBOUND as u64 {
            tx.send(seal(e)).unwrap();
        }
        tx.send(HandoffOutbound::Control(blocked())).unwrap();
        assert!(matches!(rx.try_recv(), Ok(HandoffOutbound::Control(m)) if m == blocked()));
    }

    #[test]
    fn a_dropped_receiver_closes_the_channel_and_a_queue_does_not_outlive_it() {
        let (tx, rx) = handoff_channel();
        tx.send(seal(1)).unwrap();
        drop(rx);
        assert_eq!(tx.send(seal(2)), Err(HandoffClosed));
        let (tx, mut rx) = handoff_channel();
        let tx2 = tx.clone();
        tx.send(seal(1)).unwrap();
        drop(tx);
        drop(tx2);
        assert!(rx.try_recv().is_ok(), "what was queued is still delivered");
        assert!(matches!(rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)));
    }

    #[tokio::test]
    async fn recv_wakes_on_a_send_and_ends_when_every_sender_is_gone() {
        let (tx, mut rx) = handoff_channel();
        let t = tokio::spawn(async move {
            let first = rx.recv().await;
            let end = rx.recv().await;
            (first, end.is_none())
        });
        tokio::task::yield_now().await;
        tx.send(HandoffOutbound::Control(blocked())).unwrap();
        drop(tx);
        let (first, ended) = t.await.unwrap();
        assert!(matches!(first, Some(HandoffOutbound::Control(m)) if m == blocked()));
        assert!(ended);
    }
}
