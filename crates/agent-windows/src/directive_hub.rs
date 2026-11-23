//! The glue between the signaling connection and the directive engine (docs/65 F4).
//!
//! One [`DirectiveHub`] lives for the helper's lifetime (across signaling reconnects). The mux hands it every relayed
//! `Directive` and every `DirectiveAckResult`; a single pump task drives the engine (resume, reinstall polling, the removal
//! launch) and puts owed acknowledgements on whichever connection is currently attached, one at a time and in order, retrying a
//! step that goes unanswered. All engine work is blocking file I/O, so it only ever runs on the blocking pool.
//!
//! # Correlating answers (Codex B1, B2)
//!
//! * Every answer carries the acknowledgement it answers (`from`, `to`, `ts_ms`: the timestamp is strictly increasing, so it is a
//!   unique request id). The engine settles a step only when the answer names a send of exactly that step it persisted; nothing is
//!   inferred from arrival order. An answer WITHOUT the echo is unattributable and is ignored.
//! * Answers are queued in arrival order and consumed by ONE consumer (the pump), so two callbacks can never be applied out of order.
//! * Each attachment has a GENERATION. Every answer is tagged with the generation of the connection it arrived on; the queue and the
//!   current generation live under one lock, so an answer from a previous connection (or one delayed across a re-attach) is rejected
//!   atomically and can never settle anything on the new one.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rmt_protocol::directive::{DirectiveKind, SignedAck};
use tokio::sync::Notify;

use crate::directive::{AckKey, Engine, SubmitOutcome, ACK_RETRY_MS};

/// Where acknowledgements go: the live signaling connection (or a test double).
pub trait AckSink: Send + Sync {
    /// Queue `ack` for the control plane; `false` if the connection is gone.
    fn send(&self, ack: &SignedAck) -> bool;
}

/// How often the pump wakes by itself (resume, reinstall polling, ack retry), in addition to being woken by events.
const PUMP_INTERVAL: Duration = Duration::from_secs(5);

/// The most relayed directives that may wait for the pump. The engine admits one operation at a time and a legitimate control plane
/// sends one directive per device at a time, so a small bound loses nothing real; the control plane renotifies a directive it has not
/// seen acknowledged, so a dropped one is redelivered.
pub const MAX_PENDING_DIRECTIVES: usize = 8;
/// The most a relayed artifact may weigh (a signed directive is well under 1 KiB; the record that stores it is capped at 32 KiB).
pub const MAX_ARTIFACT_BYTES: usize = 16 * 1024;
/// The most unapplied answers kept (at most one is ever legitimately outstanding: the ack on the wire).
const MAX_PENDING_RESULTS: usize = 8;

/// One `DirectiveAckResult` as it arrived, tagged with the generation of the connection it arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckResult {
    pub directive_id: String,
    pub outcome: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub ts_ms: Option<i64>,
}

impl AckResult {
    /// The exact send this answers, if the server echoed it. `None` ⇒ unattributable.
    fn key(&self) -> Option<AckKey> {
        Some(AckKey {
            directive_id: self.directive_id.clone(),
            from: self.from.clone()?,
            to: self.to.clone()?,
            ts_ms: self.ts_ms?,
        })
    }
}

/// Everything that must change together: the attachment, its generation, what is on the wire, and the answers waiting to be applied.
struct Inner {
    /// Incremented by every attach and detach. A send and an answer both carry the generation they belong to.
    generation: u64,
    sink: Option<Arc<dyn AckSink>>,
    /// The ack on the wire (its exact key, the generation it was sent on, when).
    inflight: Option<(AckKey, u64, Instant)>,
    /// Answers in ARRIVAL order, each tagged with its connection's generation; drained by the one consumer (the pump).
    results: VecDeque<(u64, AckResult)>,
    /// Relayed directives waiting for the pump to verify them (BOUNDED: [`MAX_PENDING_DIRECTIVES`]).
    directives: VecDeque<(String, String)>,
    /// Directives dropped at admission since the last log line (counted, so a flood is one log line, not one per message).
    dropped_directives: u64,
}

pub struct DirectiveHub {
    engine: Mutex<Engine>,
    /// Lock order: `inner` before `engine`, always.
    inner: Mutex<Inner>,
    wake: Notify,
}

static GLOBAL: OnceLock<Arc<DirectiveHub>> = OnceLock::new();

/// The process-wide hub, if directives are enabled (a directive key is pinned). The in-session `EndSession` path reads it.
pub fn global() -> Option<Arc<DirectiveHub>> {
    GLOBAL.get().cloned()
}

/// Install the process-wide hub (once).
pub fn set_global(hub: Arc<DirectiveHub>) -> bool {
    GLOBAL.set(hub).is_ok()
}

impl DirectiveHub {
    pub fn new(engine: Engine) -> Arc<Self> {
        Arc::new(Self {
            engine: Mutex::new(engine),
            inner: Mutex::new(Inner { generation: 0, sink: None, inflight: None, results: VecDeque::new(), directives: VecDeque::new(), dropped_directives: 0 }),
            wake: Notify::new(),
        })
    }

    fn engine(&self) -> std::sync::MutexGuard<'_, Engine> {
        // A poisoned engine lock means a panic mid-transition; the record store is the truth, so keep going.
        self.engine.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A (re)registered connection is now live: acknowledgements flow to `sink`. Returns the connection's GENERATION, which the
    /// caller must tag every answer from this connection with. Anything queued or in flight from the previous connection is dropped.
    pub fn attach(&self, sink: Arc<dyn AckSink>) -> u64 {
        let mut i = self.inner();
        i.generation += 1;
        i.sink = Some(sink);
        i.inflight = None;
        i.results.clear();
        let g = i.generation;
        drop(i);
        self.wake.notify_one();
        g
    }

    pub fn detach(&self) {
        let mut i = self.inner();
        i.generation += 1;
        i.sink = None;
        i.inflight = None;
        i.results.clear();
    }

    /// The current attachment generation (tests, diagnostics).
    pub fn generation(&self) -> u64 {
        self.inner().generation
    }

    /// A relayed directive. Never spawns work: it is cheaply screened (size, duplicate, queue bound) and queued for the pump, which
    /// verifies and persists it on its single blocking task. A directive that does not fit is dropped with a counted, logged reason
    /// (the control plane renotifies one it has not seen acknowledged). A refused directive changes nothing and earns no ack.
    pub fn on_directive(&self, directive_id: String, artifact: String) {
        // The id comes off the wire unverified and is queued and logged: only a canonical UUID (36 bytes) is admitted, so no queued
        // entry (or log line) can be larger than the artifact cap plus 36 bytes.
        let canonical = directive_id.len() == 36 && uuid::Uuid::parse_str(&directive_id).is_ok_and(|u| u.hyphenated().to_string() == directive_id);
        if !canonical {
            self.inner().dropped_directives += 1;
            return;
        }
        let mut i = self.inner();
        if artifact.len() > MAX_ARTIFACT_BYTES
            || i.directives.len() >= MAX_PENDING_DIRECTIVES
            || i.directives.iter().any(|(id, a)| *id == directive_id && *a == artifact)
        {
            i.dropped_directives += 1;
            return;
        }
        i.directives.push_back((directive_id, artifact));
        drop(i);
        self.wake.notify_one();
    }

    /// The control plane's answer to an ack, received on the connection of generation `generation`. Queued in arrival order for the
    /// pump (the single consumer); an answer from any other generation is rejected here, under the same lock that guards the queue.
    pub fn on_ack_result(&self, generation: u64, result: AckResult) {
        let mut i = self.inner();
        if i.generation != generation {
            return; // a previous connection, or one delayed across a re-attach
        }
        // Admit only the answer to the ack that is on the wire (same directive, step) and coalesce duplicates: the queue is bounded by
        // construction, and nothing a peer sends can grow it past MAX_PENDING_RESULTS.
        let admissible = i.inflight.as_ref().is_some_and(|(k, g, _)| {
            *g == generation && result.directive_id == k.directive_id && result.from.as_deref() == Some(k.from.as_str()) && result.to.as_deref() == Some(k.to.as_str())
        });
        if !admissible || i.results.iter().any(|(_, r)| *r == result) || i.results.len() >= MAX_PENDING_RESULTS {
            return;
        }
        i.results.push_back((generation, result));
        drop(i);
        self.wake.notify_one();
    }

    /// The in-session path (D-C2): an `EndSession { uninstall: true }` honours the removal ONLY when it carries a valid signed
    /// UNINSTALL directive for this device, which then runs through the very same engine as a relayed one. Blocking.
    pub fn submit_session_uninstall(&self, artifact: &str) -> SubmitOutcome {
        let outcome = self.engine().submit(artifact, Some(DirectiveKind::Uninstall));
        if let SubmitOutcome::Accepted { directive_id, .. } = &outcome {
            log_submit(directive_id, &outcome);
            self.wake.notify_one();
        }
        outcome
    }

    /// One pump pass (blocking): apply queued answers (this is the ONLY place answers are applied), resume/advance the active
    /// directive, then put the next owed ack on the wire.
    pub fn pump(&self) {
        let mut i = self.inner();
        // 0. Relayed directives, verified and persisted here, on the pump's ONE blocking task (never one task per message).
        let dropped = std::mem::take(&mut i.dropped_directives);
        if dropped > 0 {
            tracing::warn!(dropped, "directive: relayed directives were dropped at admission (queue full, oversized or duplicate)");
        }
        while let Some((directive_id, artifact)) = i.directives.pop_front() {
            let outcome = self.engine().submit(&artifact, None);
            log_submit(&directive_id, &outcome);
        }
        // 1. Answers, in arrival order, under the lock that also fixes the generation.
        while let Some((generation, result)) = i.results.pop_front() {
            if generation != i.generation {
                continue;
            }
            let Some(key) = result.key() else {
                tracing::warn!(directive = %result.directive_id, "directive: an answer without the echoed ack is unattributable; ignored");
                continue;
            };
            self.engine().on_ack_result(&key, &result.outcome);
            if i.inflight.as_ref().is_some_and(|(k, g, _)| *k == key && *g == generation) && result.outcome != "unavailable" {
                i.inflight = None;
            }
        }
        // 2. The engine (resume, polling, launch).
        for line in self.engine().drive() {
            tracing::info!("{line}");
        }
        // 3. The next owed ack, if the wire is clear.
        let Some(sink) = i.sink.clone() else { return };
        if i.inflight.as_ref().is_some_and(|(_, _, at)| at.elapsed() < Duration::from_millis(ACK_RETRY_MS as u64)) {
            return; // still waiting for the answer to the step on the wire
        }
        let Some(ack) = self.engine().next_ack() else { return };
        if sink.send(&ack) {
            tracing::info!(directive = %ack.directive_id, from = %ack.from, to = %ack.to, "directive: acknowledgement sent");
            let generation = i.generation;
            i.inflight = Some((AckKey::of(&ack), generation, Instant::now()));
        }
    }

    /// The pump task: run once at startup (this is the resume after a crash), then on events and every few seconds. Never
    /// returns.
    pub async fn run(self: Arc<Self>) {
        loop {
            let hub = self.clone();
            let _ = tokio::task::spawn_blocking(move || hub.pump()).await;
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(PUMP_INTERVAL) => {}
            }
        }
    }
}

/// D-C2 for an `EndSession { uninstall: true, directive }`: whether the removal is AUTHORIZED. Only a valid signed uninstall
/// directive for this device (accepted into the engine, which then runs it like any relayed directive) authorizes it; no hub
/// (no pinned key), no directive, or any refusal (including a replay of an already-accepted directive) means the session ends and
/// NOTHING is removed. The engine's file I/O runs on the blocking pool.
pub async fn authorize_session_uninstall(hub: Option<Arc<DirectiveHub>>, directive: Option<String>) -> bool {
    let Some(hub) = hub else {
        tracing::info!("uninstall request ignored: directives are not enabled on this agent (no pinned directive key)");
        return false;
    };
    let Some(artifact) = directive else {
        tracing::warn!("uninstall request ignored: a bare uninstall flag carries no signed directive (docs/65 D-C2)");
        return false;
    };
    let outcome = tokio::task::spawn_blocking(move || hub.submit_session_uninstall(&artifact)).await;
    match outcome {
        Ok(SubmitOutcome::Accepted { .. }) => true,
        Ok(other) => {
            tracing::warn!(outcome = ?other, "uninstall request ignored: the carried directive did not authorize a removal");
            false
        }
        Err(_) => false,
    }
}

fn log_submit(directive_id: &str, outcome: &SubmitOutcome) {
    match outcome {
        SubmitOutcome::Accepted { kind, .. } => tracing::info!(directive = %directive_id, kind = kind.as_str(), "directive accepted"),
        SubmitOutcome::Refused(r) => tracing::warn!(directive = %directive_id, reason = r.code(), "directive refused"),
        SubmitOutcome::WrongKind => tracing::warn!(directive = %directive_id, "directive refused: not an uninstall"),
        SubmitOutcome::Busy => tracing::info!(directive = %directive_id, "directive deferred: another directive is active"),
        SubmitOutcome::StoreFailed(e) => tracing::error!(directive = %directive_id, error = %e, "directive not accepted: record store failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive::testkit::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Sink {
        sent: Mutex<Vec<SignedAck>>,
        up: AtomicBool,
    }
    impl AckSink for Sink {
        fn send(&self, ack: &SignedAck) -> bool {
            if !self.up.load(Ordering::SeqCst) {
                return false;
            }
            self.sent.lock().unwrap().push(ack.clone());
            true
        }
    }

    fn hub_with(rig: Rig) -> (Arc<DirectiveHub>, MemStore, FakeActuator) {
        let (store, act) = (rig.store.clone(), rig.act.clone());
        (DirectiveHub::new(rig.engine), store, act)
    }

    fn sink() -> Arc<Sink> {
        Arc::new(Sink { sent: Mutex::new(vec![]), up: AtomicBool::new(true) })
    }

    /// The answer the server would send for `ack`, echoing it.
    fn answer(ack: &SignedAck, outcome: &str) -> AckResult {
        AckResult {
            directive_id: ack.directive_id.clone(),
            outcome: outcome.into(),
            from: Some(ack.from.clone()),
            to: Some(ack.to.clone()),
            ts_ms: Some(ack.ts_ms),
        }
    }

    fn accepted_hub(kind: &str) -> (Arc<DirectiveHub>, MemStore) {
        let mut r = rig();
        assert!(matches!(r.engine.submit(&mint(kind, DIRECTIVE_ID), None), SubmitOutcome::Accepted { .. }));
        let (hub, store, _) = hub_with(r);
        (hub, store)
    }

    fn steps(store: &MemStore) -> Vec<(bool, bool)> {
        store.get(DIRECTIVE_ID).unwrap().acks.iter().map(|a| (a.delivered, a.refused)).collect()
    }

    #[test]
    fn the_pump_sends_one_ack_at_a_time_and_only_the_next_after_its_answer() {
        let (hub, store) = accepted_hub("reinstall");
        let s = sink();
        let g = hub.attach(s.clone());
        hub.pump(); // drives accepted->executing, sends issued->accepted
        hub.pump();
        hub.pump();
        let sent = s.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!((sent[0].from.as_str(), sent[0].to.as_str()), ("issued", "accepted"));
        hub.on_ack_result(g, answer(&sent[0], "applied"));
        hub.pump();
        let sent = s.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        assert_eq!((sent[1].from.as_str(), sent[1].to.as_str()), ("accepted", "executing"));
        assert_eq!(steps(&store)[0], (true, false));
    }

    #[test]
    fn a_reconnect_resends_the_step_that_was_on_the_old_connection() {
        let (hub, _) = accepted_hub("reinstall");
        let first = sink();
        hub.attach(first.clone());
        hub.pump();
        assert_eq!(first.sent.lock().unwrap().len(), 1);
        hub.detach();
        let second = sink();
        hub.attach(second.clone());
        hub.pump();
        assert_eq!(second.sent.lock().unwrap().len(), 1, "unanswered step is sent again on the new connection");
        assert_eq!(second.sent.lock().unwrap()[0].from, "issued");
    }

    #[test]
    fn nothing_is_sent_without_a_connection_and_a_dead_connection_is_not_marked_in_flight() {
        let (hub, _) = accepted_hub("reinstall");
        hub.pump(); // no sink at all
        let s = sink();
        s.up.store(false, Ordering::SeqCst);
        hub.attach(s.clone());
        hub.pump();
        assert!(hub.inner().inflight.is_none(), "a send that failed is not waiting for an answer");
        s.up.store(true, Ordering::SeqCst);
        hub.pump();
        assert_eq!(s.sent.lock().unwrap().len(), 1);
    }

    // ---- B1: answers are correlated by the echoed (id, from, to, ts_ms), never inferred -------------------------

    #[test]
    fn after_accepted_is_confirmed_and_executing_is_sent_a_duplicate_accepted_answer_changes_nothing() {
        let (hub, store) = accepted_hub("reinstall");
        let s = sink();
        let g = hub.attach(s.clone());
        hub.pump();
        let accepted = s.sent.lock().unwrap()[0].clone();
        hub.on_ack_result(g, answer(&accepted, "applied"));
        hub.pump(); // sends accepted->executing
        let executing = s.sent.lock().unwrap()[1].clone();
        assert_eq!(executing.to, "executing");
        // The delayed DUPLICATE answer for the first step (and a duplicate refusal of it).
        hub.on_ack_result(g, answer(&accepted, "replay"));
        hub.on_ack_result(g, answer(&accepted, "refused"));
        hub.pump();
        assert_eq!(steps(&store), vec![(true, false), (false, false)], "executing is still owed: nothing answered IT");
        // Only its own answer settles it.
        hub.on_ack_result(g, answer(&executing, "applied"));
        hub.pump();
        assert_eq!(steps(&store)[1], (true, false));
    }

    #[test]
    fn answers_are_applied_in_arrival_order_and_never_inferred_from_it() {
        let (hub, store) = accepted_hub("reinstall");
        let s = sink();
        let g = hub.attach(s.clone());
        hub.pump();
        let first = s.sent.lock().unwrap()[0].clone();
        hub.on_ack_result(g, answer(&first, "applied"));
        hub.pump();
        let second = s.sent.lock().unwrap()[1].clone();
        // Out of order: the second step's answer arrives BEFORE a (late) duplicate of the first, then nothing else. The second settles
        // by its own echo; the duplicate changes nothing.
        hub.on_ack_result(g, answer(&second, "applied"));
        hub.on_ack_result(g, answer(&first, "applied"));
        hub.pump();
        assert_eq!(steps(&store), vec![(true, false), (true, false)]);
    }

    #[test]
    fn an_answer_without_the_echo_or_with_a_timestamp_never_sent_is_ignored() {
        let (hub, store) = accepted_hub("reinstall");
        let s = sink();
        let g = hub.attach(s.clone());
        hub.pump();
        let first = s.sent.lock().unwrap()[0].clone();
        let bare = AckResult { directive_id: DIRECTIVE_ID.into(), outcome: "applied".into(), from: None, to: None, ts_ms: None };
        hub.on_ack_result(g, bare);
        let mut forged = answer(&first, "applied");
        forged.ts_ms = Some(first.ts_ms + 1_000_000);
        hub.on_ack_result(g, forged);
        let mut wrong_step = answer(&first, "applied");
        wrong_step.to = Some("executing".into());
        hub.on_ack_result(g, wrong_step);
        hub.pump();
        assert_eq!(steps(&store), vec![(false, false), (false, false)], "nothing settles on an unattributable answer");
        hub.on_ack_result(g, answer(&first, "applied"));
        hub.pump();
        assert_eq!(steps(&store)[0], (true, false));
    }

    // ---- B2: generations ------------------------------------------------------------------------------------------

    #[test]
    fn an_old_connections_answer_after_a_new_send_settles_nothing() {
        let (hub, store) = accepted_hub("reinstall");
        let first = sink();
        let g1 = hub.attach(first.clone());
        hub.pump();
        let old_send = first.sent.lock().unwrap()[0].clone();
        // Reconnect: the step is sent again on the new connection (a NEW timestamp).
        let second = sink();
        let g2 = hub.attach(second.clone());
        assert!(g2 > g1);
        hub.pump();
        assert_eq!(second.sent.lock().unwrap().len(), 1);
        // The OLD connection's answer (which does echo a real, persisted send of this very step) arrives now: rejected by generation.
        hub.on_ack_result(g1, answer(&old_send, "applied"));
        hub.pump();
        assert_eq!(steps(&store)[0], (false, false), "a previous connection's answer must not settle the step");
        // The new connection's own answer does.
        let new_send = second.sent.lock().unwrap()[0].clone();
        hub.on_ack_result(g2, answer(&new_send, "applied"));
        hub.pump();
        assert_eq!(steps(&store)[0], (true, false));
    }

    #[test]
    fn a_callback_queued_before_a_reattach_is_dropped_with_the_old_generation() {
        let (hub, store) = accepted_hub("reinstall");
        let first = sink();
        let g1 = hub.attach(first.clone());
        hub.pump();
        let sent = first.sent.lock().unwrap()[0].clone();
        hub.on_ack_result(g1, answer(&sent, "applied")); // queued, not yet consumed
        let g2 = hub.attach(sink()); // the connection is replaced before the pump runs
        assert!(g2 > g1);
        hub.pump();
        assert_eq!(steps(&store)[0], (false, false), "the queued answer belonged to the old generation");
        // And a callback that was DELAYED past the attach is rejected on arrival.
        hub.on_ack_result(g1, answer(&sent, "applied"));
        hub.pump();
        assert_eq!(steps(&store)[0], (false, false));
        assert_eq!(hub.generation(), g2);
    }

    #[test]
    fn detach_also_closes_the_generation() {
        let (hub, store) = accepted_hub("reinstall");
        let s = sink();
        let g = hub.attach(s.clone());
        hub.pump();
        let sent = s.sent.lock().unwrap()[0].clone();
        hub.detach();
        hub.on_ack_result(g, answer(&sent, "applied"));
        hub.attach(sink());
        hub.pump();
        assert_eq!(steps(&store)[0], (false, false));
    }

    #[test]
    fn the_session_path_accepts_only_a_signed_uninstall() {
        let r = rig();
        let (hub, store, act) = hub_with(r);
        assert_eq!(hub.submit_session_uninstall(&mint("reinstall", DIRECTIVE_ID)), SubmitOutcome::WrongKind);
        assert_eq!(hub.submit_session_uninstall("garbage"), SubmitOutcome::Refused(rmt_protocol::directive::Refusal::Malformed));
        assert!(store.records.lock().unwrap().is_empty());
        assert!(matches!(hub.submit_session_uninstall(&mint("uninstall", OTHER_ID)), SubmitOutcome::Accepted { .. }));
        assert!(store.get(OTHER_ID).is_some());
        assert_eq!(act.calls("start_"), 0, "accepting never actuates by itself");
    }
}

#[cfg(test)]
mod session_path_tests {
    use super::*;
    use crate::directive::testkit::*;

    fn hub() -> (Arc<DirectiveHub>, MemStore, FakeActuator) {
        let r = rig();
        let (store, act) = (r.store.clone(), r.act.clone());
        (DirectiveHub::new(r.engine), store, act)
    }

    #[tokio::test]
    async fn a_bare_uninstall_flag_removes_nothing() {
        let (h, store, act) = hub();
        assert!(!authorize_session_uninstall(Some(h.clone()), None).await, "D-C2: no directive, no removal");
        assert!(!authorize_session_uninstall(None, Some(mint("uninstall", DIRECTIVE_ID))).await, "no pinned key / no hub");
        assert!(store.records.lock().unwrap().is_empty());
        assert_eq!(act.calls("start_"), 0);
    }

    #[tokio::test]
    async fn only_a_valid_signed_uninstall_for_this_device_authorizes_and_it_is_single_use() {
        let (h, store, act) = hub();
        for bad in [
            "garbage".to_string(),
            mint("reinstall", DIRECTIVE_ID),
            sign_with(&rmt_crypto::Identity::from_seed(&[0x55; 32]), claims("uninstall", DIRECTIVE_ID, NOW - 1000, NOW + 600_000)),
            sign_with(&directive_key(), claims("uninstall", DIRECTIVE_ID, NOW - 7_200_000, NOW - 3_600_000)),
        ] {
            assert!(!authorize_session_uninstall(Some(h.clone()), Some(bad)).await);
            assert!(store.records.lock().unwrap().is_empty());
        }
        let good = mint("uninstall", OTHER_ID);
        assert!(authorize_session_uninstall(Some(h.clone()), Some(good.clone())).await);
        assert!(store.get(OTHER_ID).is_some(), "accepted through the engine, persisted");
        assert!(!authorize_session_uninstall(Some(h), Some(good)).await, "single use: the same directive cannot authorize twice");
        assert_eq!(act.calls("start_"), 0, "authorizing accepts; the engine's pump performs it");
    }
}

#[cfg(test)]
mod bounded_ingress_tests {
    use super::*;
    use crate::directive::testkit::*;
    use std::sync::atomic::AtomicBool;

    struct Sink(Mutex<Vec<SignedAck>>, AtomicBool);
    impl AckSink for Sink {
        fn send(&self, ack: &SignedAck) -> bool {
            self.0.lock().unwrap().push(ack.clone());
            true
        }
    }

    fn hub() -> (Arc<DirectiveHub>, MemStore) {
        let r = rig();
        let store = r.store.clone();
        (DirectiveHub::new(r.engine), store)
    }

    #[test]
    fn a_flood_of_relayed_directives_is_bounded_and_spawns_no_work() {
        // No tokio runtime exists here: any spawn_blocking from on_directive would panic.
        let (h, store) = hub();
        for n in 0..10_000 {
            h.on_directive(uuid::Uuid::from_u128(n as u128 + 1).to_string(), format!("garbage-{n}"));
        }
        assert_eq!(h.inner().directives.len(), MAX_PENDING_DIRECTIVES, "the ingress queue is bounded");
        assert!(h.inner().dropped_directives >= 10_000 - MAX_PENDING_DIRECTIVES as u64, "excess is dropped with a count");
        h.pump();
        assert!(h.inner().directives.is_empty(), "the pump drains the queue on its own task");
        assert_eq!(h.inner().dropped_directives, 0, "the count is reported once and reset");
        assert!(store.records.lock().unwrap().is_empty(), "garbage persists nothing");
    }

    #[test]
    fn a_directive_id_that_is_not_a_canonical_uuid_is_dropped_before_queueing() {
        let (h, _) = hub();
        let art = mint("reinstall", DIRECTIVE_ID);
        for bad in [String::new(), "x".repeat(1_000_000), DIRECTIVE_ID.to_uppercase(), format!("{{{DIRECTIVE_ID}}}"), DIRECTIVE_ID.replace('-', ""), format!("{DIRECTIVE_ID} ")] {
            h.on_directive(bad, art.clone());
        }
        assert!(h.inner().directives.is_empty());
        assert_eq!(h.inner().dropped_directives, 6);
        h.on_directive(DIRECTIVE_ID.into(), art);
        assert_eq!(h.inner().directives.len(), 1, "the canonical id is admitted");
    }

    #[test]
    fn an_oversized_artifact_is_dropped_before_anything_else() {
        let (h, _) = hub();
        h.on_directive(DIRECTIVE_ID.into(), "x".repeat(MAX_ARTIFACT_BYTES + 1));
        assert!(h.inner().directives.is_empty());
    }

    #[test]
    fn a_queued_valid_directive_is_accepted_by_the_pump_and_a_duplicate_is_coalesced() {
        let (h, store) = hub();
        let art = mint("reinstall", DIRECTIVE_ID);
        h.on_directive(DIRECTIVE_ID.into(), art.clone());
        h.on_directive(DIRECTIVE_ID.into(), art);
        assert_eq!(h.inner().directives.len(), 1);
        h.pump();
        assert!(store.get(DIRECTIVE_ID).is_some());
    }

    #[test]
    fn unsolicited_ack_results_are_not_queued_and_the_queue_never_grows() {
        let (h, _) = hub();
        let s = Arc::new(Sink(Mutex::new(vec![]), AtomicBool::new(true)));
        let g = h.attach(s.clone());
        // Nothing is on the wire: every answer is unsolicited.
        for n in 0..10_000 {
            h.on_ack_result(g, AckResult { directive_id: DIRECTIVE_ID.into(), outcome: "applied".into(), from: Some("issued".into()), to: Some("accepted".into()), ts_ms: Some(n) });
        }
        assert!(h.inner().results.is_empty());
        // With one on the wire, only its own step is admitted, and distinct forgeries of that step are capped.
        h.on_directive(DIRECTIVE_ID.into(), mint("reinstall", DIRECTIVE_ID));
        h.pump();
        let sent = s.0.lock().unwrap()[0].clone();
        for n in 0..10_000 {
            h.on_ack_result(g, AckResult { directive_id: DIRECTIVE_ID.into(), outcome: "applied".into(), from: Some(sent.from.clone()), to: Some(sent.to.clone()), ts_ms: Some(n) });
        }
        assert!(h.inner().results.len() <= MAX_PENDING_RESULTS);
        h.on_ack_result(g, AckResult { directive_id: DIRECTIVE_ID.into(), outcome: "applied".into(), from: Some("accepted".into()), to: Some("executing".into()), ts_ms: Some(1) });
        assert!(h.inner().results.len() <= MAX_PENDING_RESULTS, "another step's answer is not admitted");
    }
}
