//! docs/73 2.2.8 (b): the request state machine and its fence integration, driven through the hub API
//! with an injected clock (`base + seconds`): deterministic, no sleeps for positive assertions, no
//! sockets. The registry, the directory and the arbiter are the real ones; only the host (HandSlot,
//! permit, transport) is absent, and its verdict arrives as [`AcceptGate`].

use super::*;
use crate::input_request::{AuditRecord, RequesterMsg};
use crate::session_directory::{handoff_channel, HandoffRx};
use rmt_agent_core::control::ControlMessage;
use std::time::Duration;

/// An OS sink that refuses every Ctrl-less key-up of `S` (0x53) while `failing`.
struct RefusesKeyUp {
    failing: Arc<AtomicBool>,
}
impl InputSink for RefusesKeyUp {
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        if self.failing.load(Ordering::SeqCst) && matches!(event, InputEvent::Key { code: 0x53, down: false }) {
            return Err(PlatformError::InputRefused("refused".into()));
        }
        Ok(())
    }
}

struct Rig {
    hub: Arc<InputArbiterHub>,
    base: Instant,
    regs: Vec<(u64, DirectoryRegistration)>,
    rxs: Vec<(u64, HandoffRx)>,
    /// Every directive routed so far that a test has not yet taken (the hub's global routing order).
    history: std::cell::RefCell<Vec<Directive>>,
}

impl Rig {
    /// Sessions 1..=n: registered, eligible, request-capable, directory-joined.
    fn new(n: u64) -> Self {
        let mut r = Self { hub: Arc::new(InputArbiterHub::new()), base: Instant::now(), regs: vec![], rxs: vec![], history: Default::default() };
        for h in 1..=n {
            r.add(h, true);
        }
        r
    }

    fn add(&mut self, h: u64, capable: bool) {
        self.add_with_tech(h, capable, 1000 + h as u128);
    }

    fn add_with_tech(&mut self, h: u64, capable: bool, tech: u128) {
        self.hub.register(h);
        self.hub.set_control_eligible(h, true);
        if capable {
            self.hub.set_request_capable(h);
        }
        let (tx, rx) = handoff_channel();
        let id = SessionIdentity {
            handle: h,
            control_plane_session: Some(Uuid::from_u128(h as u128)),
            technician_id: Some(Uuid::from_u128(tech)),
        };
        let reg = self.hub.join_directory(format!("sig-{h}"), id, tx);
        self.regs.push((h, reg));
        self.rxs.push((h, rx));
    }

    fn t(&self, secs: u64) -> Instant {
        self.base + Duration::from_secs(secs)
    }

    /// `owner` owns input (a plain hand from `other`, committed).
    fn own(&self, owner: u64, other: u64) {
        let t = self.hub.begin_by_handle(other, owner).unwrap();
        assert!(matches!(self.hub.commit_at(t.id, self.t(0)), CommitOutcome::Owned { .. }));
    }

    fn sync(&self) {
        self.history.borrow_mut().extend(self.hub.take_log());
    }

    /// Everything routed since the last `take`, in routing order.
    fn take(&self) -> Vec<Directive> {
        self.sync();
        std::mem::take(&mut *self.history.borrow_mut())
    }

    /// Run `f`, then return the reply it queued to `b` for `cid` (the LAST such directive), or `Dropped`
    /// when nothing was queued: the directive is the only reply channel.
    fn reply_after(&self, b: u64, cid: u128, f: impl FnOnce()) -> RequestReply {
        self.sync();
        f();
        let new = self.hub.take_log();
        self.history.borrow_mut().extend(new.iter().cloned());
        let want = Uuid::from_u128(cid);
        new.iter()
            .rev()
            .find_map(|d| match d {
                Directive::ToRequester { to, msg: RequesterMsg::Pending { client_request_id, request_id, state } }
                    if *to == b && *client_request_id == want =>
                {
                    Some(RequestReply::Pending { client_request_id: want, request_id: *request_id, state: *state })
                }
                Directive::ToRequester { to, msg: RequesterMsg::Result { client_request_id, request_id, outcome } }
                    if *to == b && *client_request_id == want =>
                {
                    Some(RequestReply::Result { client_request_id: want, request_id: *request_id, outcome: *outcome })
                }
                _ => None,
            })
            .unwrap_or(RequestReply::Dropped)
    }

    fn request(&self, b: u64, cid: u128, retry: bool, secs: u64) -> RequestReply {
        self.reply_after(b, cid, || self.hub.request_input(b, Uuid::from_u128(cid), retry, self.t(secs)))
    }

    fn req(&self, b: u64, cid: u128, secs: u64) -> RequestReply {
        self.request(b, cid, false, secs)
    }

    fn retry(&self, b: u64, cid: u128, secs: u64) -> RequestReply {
        self.request(b, cid, true, secs)
    }

    fn withdraw(&self, b: u64, cid: u128, secs: u64) -> RequestReply {
        self.reply_after(b, cid, || self.hub.withdraw_request(b, Uuid::from_u128(cid), self.t(secs)))
    }

    /// Drain session `h`'s handoff queue.
    fn drain(&mut self, h: u64) -> Vec<HandoffOutbound> {
        let rx = &mut self.rxs.iter_mut().find(|(x, _)| *x == h).expect("joined").1;
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    fn admit(&self, b: u64, cid: u128, secs: u64) -> Uuid {
        match self.req(b, cid, secs) {
            RequestReply::Pending { request_id, state: ReqState::PendingDelivery, .. } => request_id,
            o => panic!("expected an admitted request, got {o:?}"),
        }
    }

    fn state_of(&self, b: u64, cid: u128, secs: u64) -> RequestReply {
        self.retry(b, cid, secs)
    }

    /// Hand session `h`'s directory registration back (the session leaves the directory).
    fn leave_directory(&mut self, h: u64) {
        let i = self.regs.iter().position(|(x, _)| *x == h).expect("joined");
        drop(self.regs.remove(i));
    }

    /// Accept as `holder` with both admissions held, then begin the hand (the job's begin).
    fn accept_and_begin(&self, holder: u64, id: Uuid, secs: u64) -> Transition {
        match self.hub.answer_request(holder, id, true, AcceptGate::Held, self.t(secs)) {
            AnswerResult::Consumed { .. } => {}
            o => panic!("expected Consumed, got {o:?}"),
        }
        self.hub.begin_request_by_handle(id, self.t(secs)).expect("begin")
    }

    fn mode(&self) -> Mode {
        self.hub.mode()
    }
}

fn nil() -> Uuid {
    Uuid::nil()
}

/// `closed` audit records queued, as (requester handle, request id, outcome), in queue order.
fn closed(ds: &[Directive]) -> Vec<(u64, Uuid, Outcome)> {
    ds.iter()
        .filter_map(|d| match d {
            Directive::Audit { to, record: AuditRecord::Closed { request_id, outcome, .. } } => Some((*to, *request_id, *outcome)),
            _ => None,
        })
        .collect()
}

fn requested(ds: &[Directive]) -> Vec<Uuid> {
    ds.iter()
        .filter_map(|d| match d {
            Directive::Audit { record: AuditRecord::Requested { request_id, .. }, .. } => Some(*request_id),
            _ => None,
        })
        .collect()
}

/// Results queued for `to`, as (request id, outcome).
fn results_to(ds: &[Directive], to: u64) -> Vec<(Option<Uuid>, Resolved)> {
    ds.iter()
        .filter_map(|d| match d {
            Directive::ToRequester { to: t, msg: RequesterMsg::Result { request_id, outcome, .. } } if *t == to => {
                Some((*request_id, *outcome))
            }
            _ => None,
        })
        .collect()
}

fn withdrawn_to(ds: &[Directive], to: u64) -> Vec<(Uuid, WithdrawReason)> {
    ds.iter()
        .filter_map(|d| match d {
            Directive::ToHolder { to: t, msg: HolderMsg::Withdrawn { request_id, reason } } if *t == to => {
                Some((*request_id, *reason))
            }
            _ => None,
        })
        .collect()
}

fn result_of(reply: RequestReply) -> Resolved {
    match reply {
        RequestReply::Result { outcome, .. } => outcome,
        o => panic!("expected a Result, got {o:?}"),
    }
}

fn is_outcome(reply: RequestReply, want: Outcome) -> bool {
    matches!(reply, RequestReply::Result { outcome: Resolved::Outcome(o), .. } if o == want)
}

// ── admission ─────────────────────────────────────────────────────────────────────────────────────

/// Admission queues, in this order: `requested` (requester's chain), `Pending` to the requester, the
/// prompt to the holder. The record binds the Owned epoch and the trusted ids.
#[test]
fn admission_queues_requested_then_pending_then_the_prompt() {
    let r = Rig::new(3);
    r.own(1, 2);
    let epoch = r.hub.lock_core().arbiter.epoch();
    let id = r.admit(3, 1, 1);
    let ds = r.take();
    assert_eq!(ds.len(), 3);
    assert!(matches!(ds[0], Directive::Audit { to: 3, record: AuditRecord::Requested { request_id, epoch: e, ids }, .. }
        if request_id == id && e == epoch && ids.requester_session == Uuid::from_u128(3) && ids.holder_technician == Uuid::from_u128(1001)));
    assert!(matches!(ds[1], Directive::ToRequester { to: 3, msg: RequesterMsg::Pending { request_id, state: ReqState::PendingDelivery, .. } } if request_id == id));
    assert!(matches!(ds[2], Directive::ToHolder { to: 1, msg: HolderMsg::Requested { request_id, from: 3, expires_in_ms: 60_000 } } if request_id == id));
}

/// The fixed refusal order, each refusal cached and replayed, none audited.
#[test]
fn refusals_follow_the_fixed_order_are_cached_and_never_audited() {
    let mut r = Rig::new(4);
    r.add(5, false); // 5 never announces holder capability
    let ineligible = |reply| matches!(reply, RequestReply::Result { outcome: Resolved::Refusal(Refusal::Ineligible), .. });
    let refused = |reply, why: Refusal| matches!(reply, RequestReply::Result { outcome: Resolved::Refusal(w), request_id: None, .. } if w == why);

    // Unowned: no holder. But a demoted/observer session is `ineligible` first, whatever the mode.
    assert!(refused(r.req(2, 10, 0), Refusal::NoHolder));
    r.hub.set_control_eligible(3, false);
    assert!(ineligible(r.req(3, 11, 0)));
    r.hub.set_control_eligible(3, true);
    assert!(matches!(r.req(99, 12, 0), RequestReply::Dropped), "not registered: no reply at all");
    r.hub.register(6);
    r.hub.set_control_eligible(6, true);
    r.hub.set_request_capable(6);
    assert!(ineligible(r.req(6, 13, 0)), "registered but not directory-joined");

    // Blocked: `no_holder` precedes the owed-releases `busy`.
    r.own(1, 2);
    r.hub.teardown_by_handle(1);
    assert_eq!(r.mode(), Mode::Blocked);
    r.hub.releases_owed.store(true, Ordering::SeqCst);
    assert!(refused(r.req(3, 14, 0), Refusal::NoHolder));

    // Owned by 1 again: the holder itself is `ineligible`; owed releases (flag) => busy.
    r.add(1, true);
    let t = r.hub.begin_by_handle(1, 1).unwrap();
    assert!(matches!(r.hub.commit_at(t.id, r.t(0)), CommitOutcome::Owned { .. }));
    assert!(ineligible(r.req(1, 15, 0)), "the holder cannot request from itself");
    assert!(refused(r.req(3, 16, 0), Refusal::Busy), "releases still owed");
    r.hub.releases_owed.store(false, Ordering::SeqCst);

    // Transitioning => busy, checked from the mode (the flag lags a supersede).
    let plain = r.hub.begin_by_handle(1, 2).unwrap();
    assert!(refused(r.req(3, 17, 0), Refusal::Busy), "a transition is in flight");
    assert!(matches!(r.hub.commit_at(plain.id, r.t(0)), CommitOutcome::Owned { .. }));

    // Owner 5 never announced holder capability.
    let t = r.hub.begin_by_handle(2, 5).unwrap();
    assert!(matches!(r.hub.commit_at(t.id, r.t(0)), CommitOutcome::Owned { .. }));
    assert!(refused(r.req(3, 18, 0), Refusal::UnsupportedHolder));

    // Replay: same id, any `retry`, returns the cached refusal; no refusal was ever audited.
    assert!(refused(r.req(3, 18, 1), Refusal::UnsupportedHolder));
    assert!(refused(r.retry(3, 18, 1), Refusal::UnsupportedHolder));
    let ds = r.take();
    assert!(ds.iter().all(|d| !matches!(d, Directive::Audit { .. })), "refusals are never audited");
}

/// Rate limit 10 s per session; a new request after it replaces the prior pending one (its close
/// queued before the new `requested`). Per-holder cap 4. Technician budget survives session churn.
#[test]
fn bounds_rate_limit_replace_holder_cap_and_technician_budget() {
    let mut r = Rig::new(7);
    r.own(1, 2);
    let first = r.admit(3, 1, 0);
    r.hub.prompt_shown(1, first, r.t(1)); // shown: otherwise it would already be undelivered at 10 s
    assert!(matches!(r.req(3, 2, 5), RequestReply::Result { outcome: Resolved::Refusal(Refusal::RateLimited), .. }));
    r.take();
    let second = r.admit(3, 3, 10);
    let ds = r.take();
    assert_eq!(closed(&ds), vec![(3, first, Outcome::Replaced)]);
    assert!(is_outcome(r.state_of(3, 1, 10), Outcome::Replaced));
    let close_at = ds.iter().position(|d| matches!(d, Directive::Audit { record: AuditRecord::Closed { .. }, .. })).unwrap();
    let req_at = ds.iter().position(|d| matches!(d, Directive::Audit { record: AuditRecord::Requested { .. }, .. })).unwrap();
    assert!(close_at < req_at, "closed{{replaced}} precedes the new requested");
    assert_eq!(withdrawn_to(&ds, 1), vec![(first, WithdrawReason::Outcome(Outcome::Replaced))]);
    assert_eq!(requested(&ds), vec![second]);

    // 3 holds one live request; 4, 5, 6 make four live on holder 1; the fifth requester is refused.
    r.admit(4, 10, 11);
    r.admit(5, 11, 11);
    r.admit(6, 12, 11);
    assert!(matches!(r.req(7, 13, 11), RequestReply::Result { outcome: Resolved::Refusal(Refusal::Capacity), .. }));

    // Technician-keyed budget: the same technician on a fresh session handle is still limited.
    r.hub.teardown_by_handle(4);
    r.leave_directory(4);
    r.hub.register(8);
    r.hub.set_control_eligible(8, true);
    r.hub.set_request_capable(8);
    let (tx, rx) = handoff_channel();
    let same_tech = SessionIdentity {
        handle: 8,
        control_plane_session: Some(Uuid::from_u128(8)),
        technician_id: Some(Uuid::from_u128(1004)), // session 4's technician
    };
    let reg = r.hub.join_directory("sig-8".into(), same_tech, tx);
    r.regs.push((8, reg));
    r.rxs.push((8, rx));
    assert!(
        matches!(r.req(8, 14, 12), RequestReply::Result { outcome: Resolved::Refusal(Refusal::RateLimited), .. }),
        "the budget follows the technician id across sessions"
    );
}

// ── the outcome table ─────────────────────────────────────────────────────────────────────────────

/// Timers: undelivered at 10 s unless shown, expired at 60 s, a valid answer establishes `shown`.
#[test]
fn timers_undelivered_expired_and_a_lost_prompt_shown_is_recovered_by_the_answer() {
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    // 10 s without PromptShown => undelivered.
    r.hub.sweep_requests(r.t(9));
    assert!(matches!(r.state_of(3, 1, 9), RequestReply::Pending { state: ReqState::PendingDelivery, .. }));
    r.hub.sweep_requests(r.t(10));
    assert!(is_outcome(r.state_of(3, 1, 10), Outcome::Undelivered));
    r.take();

    // PromptShown at 5 s => shown; 60 s after admission => expired.
    let b = r.admit(4, 2, 20);
    r.hub.prompt_shown(1, b, r.t(25));
    r.hub.sweep_requests(r.t(79));
    assert!(matches!(r.state_of(4, 2, 79), RequestReply::Pending { state: ReqState::Shown, .. }));
    r.hub.sweep_requests(r.t(80));
    assert!(is_outcome(r.state_of(4, 2, 80), Outcome::Expired));
    let ds = r.take();
    assert_eq!(closed(&ds), vec![(4, b, Outcome::Expired)]);
    assert_eq!(withdrawn_to(&ds, 1), vec![(b, WithdrawReason::Outcome(Outcome::Expired))]);

    // The PromptShown was lost but a valid answer (here an ignored accept) establishes `shown`.
    let _ = a;
    r.hub.set_control_eligible(4, true);
    let c = r.admit(4, 3, 100);
    let plain = r.hub.begin_by_handle(1, 4).unwrap();
    assert_eq!(r.hub.answer_request(1, c, true, AcceptGate::Unavailable, r.t(101)), AnswerResult::Ignored);
    r.hub.sweep_requests(r.t(115));
    assert!(matches!(r.state_of(4, 3, 115), RequestReply::Pending { state: ReqState::Shown, .. }), "not undelivered");
    let _ = plain;
}

#[test]
fn declined_and_cancelled_and_withdraw_after_consumption_changes_nothing() {
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    assert_eq!(r.hub.answer_request(1, a, false, AcceptGate::Held, r.t(1)), AnswerResult::Declined);
    assert!(is_outcome(r.state_of(3, 1, 1), Outcome::Declined));

    let b = r.admit(4, 2, 2);
    let reply = r.withdraw(4, 2, 3);
    assert!(is_outcome(reply, Outcome::Cancelled));
    let ds = r.take();
    assert_eq!(closed(&ds).iter().map(|c| c.2).collect::<Vec<_>>(), vec![Outcome::Declined, Outcome::Cancelled]);
    // Withdraw again / for an unknown id: the recorded result, or unknown; nothing changes.
    assert!(is_outcome(r.withdraw(4, 2, 4), Outcome::Cancelled));
    assert!(matches!(r.withdraw(4, 99, 4), RequestReply::Result { outcome: Resolved::Unknown, .. }));
    let _ = b;

    // After consumption a withdraw returns the CURRENT state and settles nothing; so do a second
    // answer and the 60 s expiry sweep (only the job's outcome, or B leaving, ends it).
    let c = r.admit(3, 3, 20);
    assert!(matches!(r.hub.answer_request(1, c, true, AcceptGate::Held, r.t(21)), AnswerResult::Consumed { .. }));
    assert!(matches!(
        r.withdraw(3, 3, 22),
        RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }
    ));
    assert_eq!(r.hub.answer_request(1, c, false, AcceptGate::Held, r.t(22)), AnswerResult::NoEffect);
    assert_eq!(r.hub.answer_request(1, c, true, AcceptGate::Held, r.t(22)), AnswerResult::NoEffect);
    assert!(matches!(r.state_of(3, 3, 22), RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }));
}

/// Accept consumes under `core` with no transition id; begin records the id; commit -> granted with
/// NOTHING sent until `complete_grant`, which queues `handed` (on both chains) and only then `closed`.
#[test]
fn grant_orders_requested_then_handed_then_closed_on_the_requesters_single_queue() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    assert_eq!(r.hub.lock_core().arbiter.guard().map(|g| g.id), Some(t.id));
    r.take();

    let (who, epoch) = match r.hub.commit_at(t.id, r.t(2)) {
        CommitOutcome::Owned { who, epoch } => (who, epoch),
        o => panic!("expected Owned, got {o:?}"),
    };
    assert_eq!(who.handle, 3);
    assert!(r.take().is_empty(), "settle(granted) sends nothing: the hand's own audit comes first");
    assert!(matches!(r.state_of(3, 1, 2), RequestReply::Result { outcome: Resolved::Outcome(Outcome::Granted), .. }), "recorded at commit");
    r.take();

    r.hub.complete_grant(Some(id), 1, 3, epoch);

    // ONE queue, B's: `requested` (queued at admission), then the hand's `handed`, then `closed{granted}`.
    let q = r.drain(3);
    let kinds: Vec<&str> = q
        .iter()
        .filter_map(|m| match m {
            HandoffOutbound::Request(Directive::Audit { record: AuditRecord::Requested { .. }, .. }) => Some("requested"),
            HandoffOutbound::SealAudit(_) => Some("handed"),
            HandoffOutbound::Request(Directive::Audit { record: AuditRecord::Closed { outcome: Outcome::Granted, .. }, .. }) => {
                Some("closed")
            }
            _ => None,
        })
        .collect();
    assert_eq!(kinds, vec!["requested", "handed", "closed"], "queue: {q:?}");
    // The Result follows `closed` on the same queue, and A hears Withdrawn{granted}.
    let ds = r.take();
    assert_eq!(closed(&ds), vec![(3, id, Outcome::Granted)]);
    assert_eq!(results_to(&ds, 3), vec![(Some(id), Resolved::Outcome(Outcome::Granted))]);
    assert_eq!(withdrawn_to(&ds, 1), vec![(id, WithdrawReason::Outcome(Outcome::Granted))]);
    // Finishing twice queues nothing more.
    r.hub.complete_grant(Some(id), 1, 3, epoch);
    assert!(r.take().is_empty());
}

#[test]
fn begin_refusals_and_a_busy_slot_settle_failed_exactly_once() {
    let mut r = Rig::new(5);
    r.own(1, 2);

    // Slot or permit unavailable (not A's plain hand to B): consumed, then `failed` at once.
    let a = r.admit(3, 1, 0);
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Unavailable, r.t(1)), AnswerResult::FailedBusy);
    assert!(is_outcome(r.state_of(3, 1, 1), Outcome::Failed));

    // A tears down after consumption but before the job's begin: surfaces as the begin refusal.
    let b = r.admit(4, 2, 2);
    assert!(matches!(r.hub.answer_request(1, b, true, AcceptGate::Held, r.t(3)), AnswerResult::Consumed { .. }));
    r.hub.teardown_by_handle(1);
    assert!(matches!(r.state_of(4, 2, 3), RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }), "A's teardown cannot settle a consumed request");
    assert_eq!(
        r.hub.begin_request_by_handle(b, r.t(3)),
        Err(RequestBeginError::Refused(HandRefusal::SenderNotLive))
    );
    assert!(is_outcome(r.state_of(4, 2, 3), Outcome::Failed));
    let ds = r.take();
    assert_eq!(closed(&ds).iter().filter(|c| c.1 == b).count(), 1, "closed exactly once");

    // B demoted after consumption: the begin refuses TargetNotEligible -> failed.
    r.add(1, true);
    r.own(1, 2);
    let c = r.admit(5, 3, 30);
    assert!(matches!(r.hub.answer_request(1, c, true, AcceptGate::Held, r.t(31)), AnswerResult::Consumed { .. }));
    r.hub.set_control_eligible(5, false);
    assert!(matches!(r.state_of(5, 3, 31), RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }));
    assert_eq!(
        r.hub.begin_request_by_handle(c, r.t(31)),
        Err(RequestBeginError::Refused(HandRefusal::TargetNotEligible))
    );
    assert!(is_outcome(r.state_of(5, 3, 31), Outcome::Failed));
    assert_eq!(r.hub.begin_request_by_handle(c, r.t(31)), Err(RequestBeginError::Discarded), "already settled");
}

/// The gate cannot be taken before the deadline: nothing began, the mode is untouched, `failed`.
#[test]
fn gate_timeout_begins_nothing_and_fails_the_request() {
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    // Consumed 9.95 s ago on the real clock: the 10 s deadline is ~50 ms away.
    let accepted = Instant::now() - Duration::from_millis(9_950);
    assert!(matches!(
        r.hub.answer_request(1, id, true, AcceptGate::Held, accepted),
        AnswerResult::Consumed { .. }
    ));
    let before = r.mode();
    let gate = r.hub.dispatch_gate.read().unwrap(); // a dispatch that never finishes
    let res = r.hub.begin_request_by_handle(id, accepted);
    drop(gate);
    assert_eq!(res, Err(RequestBeginError::GateTimeout));
    assert_eq!(r.mode(), before, "nothing began");
    assert!(r.hub.lock_core().arbiter.guard().is_none());
    assert!(is_outcome(r.state_of(3, 1, 0), Outcome::Failed));
}

/// Worker lost before begin (no transition id) -> failed; lost job past the deadline -> failed by the
/// sweep; B leaving after consumption discards it and the job ends without beginning.
#[test]
fn lost_worker_lost_job_and_requester_leaving_after_consumption() {
    let mut r = Rig::new(5);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(1));
    assert_eq!(r.hub.abort_request(a, r.t(2)), Some(AbortOutcome::Aborted));
    assert!(is_outcome(r.state_of(3, 1, 2), Outcome::Failed));

    let b = r.admit(4, 2, 20);
    r.hub.answer_request(1, b, true, AcceptGate::Held, r.t(21));
    r.hub.sweep_requests(r.t(30));
    assert!(matches!(r.state_of(4, 2, 30), RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }), "not yet: the deadline is 31 s");
    r.hub.sweep_requests(r.t(31));
    assert!(is_outcome(r.state_of(4, 2, 31), Outcome::Failed), "the lost job is settled by the sweep");

    let c = r.admit(5, 3, 50);
    r.hub.answer_request(1, c, true, AcceptGate::Held, r.t(51));
    r.take();
    r.leave_directory(5);
    r.hub.teardown_by_handle(5);
    assert_eq!(r.hub.begin_request_by_handle(c, r.t(51)), Err(RequestBeginError::Discarded));
    let ds = r.take();
    assert_eq!(withdrawn_to(&ds, 1), vec![(c, WithdrawReason::RequesterLeft)]);
    assert!(closed(&ds).is_empty() && results_to(&ds, 5).is_empty(), "no result, no close for a leaver");
    assert_eq!(r.mode(), Mode::Owned { who: Member { handle: 1, incarnation: r.hub.lock_core().registry.entries[&1].incarnation } });
}

/// Events before the accept: a transition to someone else, A's departure and a Blocked mode end a
/// pending request `holder_changed`; B's demotion ends it `ineligible`; B's session end discards it.
#[test]
fn events_before_the_accept() {
    let mut r = Rig::new(6);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    let b = r.admit(4, 2, 0);
    // A plain hand to someone else (5): every pending request ends holder_changed.
    let plain = r.hub.begin_by_handle(1, 5).unwrap();
    assert!(is_outcome(r.state_of(3, 1, 1), Outcome::HolderChanged));
    assert!(is_outcome(r.state_of(4, 2, 1), Outcome::HolderChanged));
    r.hub.commit_at(plain.id, r.t(1));
    let ds = r.take();
    assert_eq!(closed(&ds).iter().filter(|c| c.2 == Outcome::HolderChanged).count(), 2);
    let _ = (a, b);

    // Owner 5 tears down => Blocked => pending requests holder_changed.
    let c = r.admit(3, 3, 20); // owner is 5 after the plain hand
    r.hub.teardown_by_handle(5);
    assert!(is_outcome(r.state_of(3, 3, 21), Outcome::HolderChanged));
    let _ = c;

    // B demoted while pending => ineligible.
    r.own(1, 2);
    let d = r.admit(4, 4, 40);
    r.hub.set_control_eligible(4, false);
    assert!(is_outcome(r.state_of(4, 4, 41), Outcome::Ineligible));
    let _ = d;

    // B's session ends: discarded, A hears requester_left, nothing sealed, retry on a new incarnation
    // finds nothing (unknown).
    r.hub.set_control_eligible(4, true);
    let e = r.admit(6, 5, 60);
    r.take();
    r.leave_directory(6);
    r.hub.teardown_by_handle(6);
    let ds = r.take();
    assert_eq!(withdrawn_to(&ds, 1), vec![(e, WithdrawReason::RequesterLeft)]);
    assert!(closed(&ds).is_empty());
    r.add(6, true);
    assert_eq!(result_of(r.retry(6, 5, 61)), Resolved::Unknown, "a different incarnation holds no record");
}

/// A plain hand A -> B in flight while B's request is pending: the accept is IGNORED, its commit ends
/// the request `already_satisfied`, its abort ends it `holder_changed`.
#[test]
fn a_plain_hand_to_the_requester_decides_the_request() {
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    let plain = r.hub.begin_by_handle(1, 3).unwrap();
    assert!(matches!(r.state_of(3, 1, 1), RequestReply::Pending { .. }), "nothing yet");
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Unavailable, r.t(2)), AnswerResult::Ignored);
    assert!(matches!(r.state_of(3, 1, 2), RequestReply::Pending { .. }), "no consumption, no settle");
    assert!(matches!(r.hub.commit_at(plain.id, r.t(3)), CommitOutcome::Owned { .. }));
    assert!(is_outcome(r.state_of(3, 1, 3), Outcome::AlreadySatisfied));

    // The abort variant: the plain hand to the requester aborts (target gone from the arbiter's view).
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    let plain = r.hub.begin_by_handle(1, 3).unwrap();
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Unavailable, r.t(2)), AnswerResult::Ignored);
    {
        let mut c = r.hub.lock_core();
        assert!(c.arbiter.abort_transition(plain.id)); // test-only: an abort of a plain hand
        r.hub.publish(&c);
        r.hub.finish_locked(&mut c, r.t(3));
    }
    assert!(is_outcome(r.state_of(3, 1, 3), Outcome::HolderChanged));
}

// ── races: both orders, exactly one terminal outcome ──────────────────────────────────────────────

#[test]
fn accept_versus_expiry_and_withdraw_and_demotion_and_departure_one_terminal_each() {
    // accept first (inside 60 s): consumed; the later expiry sweep cannot settle it.
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.hub.prompt_shown(1, a, r.t(1));
    assert!(matches!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(59)), AnswerResult::Consumed { .. }));
    r.hub.sweep_requests(r.t(65));
    assert!(matches!(r.state_of(3, 1, 65), RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }), "the 60 s expiry cannot settle a consumed request");

    // expiry first: the late accept finds the request terminal and only gets Withdrawn.
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.hub.prompt_shown(1, a, r.t(1));
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(60)), AnswerResult::Withdrawn);
    assert!(is_outcome(r.state_of(3, 1, 60), Outcome::Expired));
    let ds = r.take();
    assert_eq!(withdrawn_to(&ds, 1).last(), Some(&(a, WithdrawReason::Outcome(Outcome::Expired))));
    assert_eq!(closed(&ds).len(), 1, "closed exactly once");

    // withdraw first, then accept => Withdrawn{cancelled}; accept first, then withdraw => state returned.
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.withdraw(3, 1, 1);
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(2)), AnswerResult::Withdrawn);
    let ds = r.take();
    assert_eq!(withdrawn_to(&ds, 1).last(), Some(&(a, WithdrawReason::Outcome(Outcome::Cancelled))));

    // B demoted first => ineligible; accept later is Withdrawn. Accept first => begin refuses -> failed.
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.hub.set_control_eligible(3, false);
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(1)), AnswerResult::Withdrawn);
    assert_eq!(closed(&r.take()).len(), 1);

    // A tears down first => holder_changed; accept from the (gone) holder has no effect.
    let r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.hub.teardown_by_handle(1);
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(1)), AnswerResult::NoEffect);
    assert!(is_outcome(r.state_of(3, 1, 1), Outcome::HolderChanged));
}

#[test]
fn answers_from_the_wrong_holder_or_a_stale_incarnation_or_for_an_unknown_id_do_nothing() {
    let mut r = Rig::new(4);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    // Another session answers for A's request: unknown for it, nothing consumed.
    assert_eq!(r.hub.answer_request(2, a, true, AcceptGate::Held, r.t(1)), AnswerResult::Withdrawn);
    assert_eq!(
        withdrawn_to(&r.take(), 2),
        vec![(a, WithdrawReason::Unknown)]
    );
    assert!(matches!(r.state_of(3, 1, 1), RequestReply::Pending { state: ReqState::PendingDelivery, .. }));
    // An id nobody holds.
    let ghost = Uuid::from_u128(0xdead);
    assert_eq!(r.hub.answer_request(1, ghost, true, AcceptGate::Held, r.t(1)), AnswerResult::Withdrawn);
    assert_eq!(withdrawn_to(&r.take(), 1), vec![(ghost, WithdrawReason::Unknown)]);
    // A stale holder incarnation: session 1 leaves and its handle is re-registered; the old request
    // is already holder_changed and the new incarnation does not hold it.
    r.leave_directory(1);
    r.hub.teardown_by_handle(1);
    r.add(1, true);
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(2)), AnswerResult::Withdrawn);
    assert_eq!(
        withdrawn_to(&r.take(), 1).last(),
        Some(&(a, WithdrawReason::Unknown)),
        "a different incarnation never held it"
    );
}

// ── replay and recovery ───────────────────────────────────────────────────────────────────────────

#[test]
fn replay_returns_the_same_request_and_current_state_and_unknown_outside_the_window() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    // Lost Pending: same key, either `retry` value, same request, CURRENT state, one request only.
    for retry in [false, true] {
        let again = r.request(3, 1, retry, 1);
        assert!(matches!(again, RequestReply::Pending { request_id, .. } if request_id == id));
    }
    assert_eq!(r.hub.live_requests(), 1);
    r.hub.prompt_shown(1, id, r.t(2));
    assert!(matches!(r.state_of(3, 1, 2), RequestReply::Pending { state: ReqState::Shown, .. }));
    r.hub.answer_request(1, id, true, AcceptGate::Held, r.t(3));
    assert!(matches!(r.state_of(3, 1, 3), RequestReply::Pending { state: ReqState::AcceptedInFlight, .. }), "never a stale shown");

    // Never seen: unknown.
    assert_eq!(result_of(r.retry(3, 777, 3)), Resolved::Unknown);

    // Retention: 5 minutes from the terminal state.
    r.hub.abort_request(id, r.t(4));
    assert!(is_outcome(r.state_of(3, 1, 4 + 299), Outcome::Failed), "still recorded at 4m59s");
    assert_eq!(result_of(r.retry(3, 1, 4 + 300)), Resolved::Unknown, "outside the window");

    // A different incarnation (the session reconnected): unknown, never a statement about a grant.
    let k = r.admit(3, 2, 400);
    let _ = k;
    r.leave_directory(3);
    r.hub.teardown_by_handle(3);
    r.add(3, true);
    assert_eq!(result_of(r.retry(3, 2, 401)), Resolved::Unknown);
}

/// 32 cache entries per incarnation, oldest terminal first; the evicted id answers unknown.
#[test]
fn cache_is_bounded_per_incarnation_and_evicts_the_oldest_terminal() {
    let r = Rig::new(3); // Unowned: every request is a cached `no_holder` refusal
    for i in 0..40u64 {
        assert!(matches!(r.req(2, 100 + i as u128, i), RequestReply::Result { outcome: Resolved::Refusal(Refusal::NoHolder), .. }));
    }
    assert_eq!(result_of(r.retry(2, 100, 41)), Resolved::Unknown, "the oldest was evicted");
    assert_eq!(result_of(r.retry(2, 107, 41)), Resolved::Unknown, "40 - 32 = 8 evicted");
    assert!(matches!(r.retry(2, 108, 41), RequestReply::Result { outcome: Resolved::Refusal(Refusal::NoHolder), .. }));
    assert!(matches!(r.retry(2, 139, 41), RequestReply::Result { outcome: Resolved::Refusal(Refusal::NoHolder), .. }));
    assert_eq!(r.hub.lock_core().requests.cache_len(), 32);
}

// ── the arbiter integration: deadline, abort, commit ──────────────────────────────────────────────

/// The deadline abort comes from the sweep: epoch advanced, `Blocked` published, request `failed`,
/// the late commit stale; the aborted fence becomes step (a)'s owed set, so requests refuse `busy`
/// while it exists and a retried release finally clears it.
#[test]
fn deadline_abort_blocks_fails_the_request_and_leaves_the_owed_set() {
    let r = Rig::new(3);
    r.own(1, 2);
    let epoch0 = r.hub.lock_core().arbiter.epoch();
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1); // consumed at t=1: deadline t=11
    let epoch1 = r.hub.lock_core().arbiter.epoch();
    assert!(epoch1 > epoch0);
    r.hub.sweep_requests(r.t(10));
    assert!(matches!(r.mode(), Mode::Transitioning { .. }), "not yet");
    r.hub.sweep_requests(r.t(11));
    assert_eq!(r.mode(), Mode::Blocked);
    assert!(r.hub.lock_core().arbiter.epoch() > epoch1, "the epoch advanced");
    assert!(is_outcome(r.state_of(3, 1, 11), Outcome::Failed));
    assert_eq!(r.hub.commit_at(t.id, r.t(12)), CommitOutcome::StaleTransition, "a late commit is stale");
    assert_eq!(r.hub.last_committed(), 1, "never committed (only the setup commit)");

    // The aborted fence is superseded: step (a) turns it into the release-only owed set while the
    // OS refuses the key-up, and the set clears once the OS accepts.
    let failing = Arc::new(AtomicBool::new(true));
    let coord = InputCoordinator::with_injector(Box::new(RefusesKeyUp { failing: Arc::clone(&failing) }));
    coord.inject(1, InputEvent::Key { code: 0x53, down: true }).unwrap();
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut st = ArbFenceState { fences: vec![DeferredFence { id: t.id, members: vec![1], done: Some(tx) }], owed: None };
    run_arb_fences(&mut st, &r.hub, &coord);
    assert!(st.fences.is_empty(), "no longer in flight, never commits");
    assert!(st.owed.is_some() && r.hub.releases_owed(), "the refused key-up is owed");
    assert_eq!(r.hub.last_committed(), 1);
    failing.store(false, Ordering::SeqCst);
    run_arb_fences(&mut st, &r.hub, &coord);
    assert!(st.owed.is_none() && !r.hub.releases_owed());
}

/// With the flag the capture thread publishes for an owed set, an Owned machine refuses `busy`.
#[test]
fn an_owed_set_makes_requests_busy_through_the_published_flag() {
    let r = Rig::new(4);
    r.own(1, 2);
    let hub = &r.hub;
    // Build a real owed set: a superseded fence naming 1 whose release is refused.
    let failing = Arc::new(AtomicBool::new(true));
    let coord = Arc::new(InputCoordinator::with_injector(Box::new(RefusesKeyUp { failing: Arc::clone(&failing) })));
    coord.inject(1, InputEvent::Key { code: 0x53, down: true }).unwrap();
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut st = ArbFenceState { fences: vec![DeferredFence { id: t.id, members: vec![1], done: Some(tx) }], owed: None };
    hub.sweep_requests(r.t(11)); // deadline abort -> Blocked
    run_arb_fences(&mut st, hub, &coord);
    assert!(hub.releases_owed() && st.owed.is_some(), "the refused key-up is owed");
    // Blocked: no_holder wins over busy.
    assert!(matches!(r.req(4, 5, 20), RequestReply::Result { outcome: Resolved::Refusal(Refusal::NoHolder), .. }));
    // A claim re-arms ownership but a lagging flag still reads busy until the capture pass clears it.
    let claim = hub.begin_by_handle(2, 2).unwrap();
    assert!(matches!(hub.commit_at(claim.id, r.t(21)), CommitOutcome::Owned { .. }));
    assert!(hub.releases_owed(), "the flag lags until the next capture pass");
    assert!(matches!(r.req(4, 6, 30), RequestReply::Result { outcome: Resolved::Refusal(Refusal::Busy), .. }));
    run_arb_fences(&mut st, hub, &coord);
    assert!(!hub.releases_owed(), "the commit dropped the owed set");
}

/// A fence that finishes after the deadline cannot commit: the commit takes the abort path.
#[test]
fn commit_after_the_deadline_aborts_instead_of_committing() {
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    assert_eq!(r.hub.commit_at(t.id, r.t(11)), CommitOutcome::StaleTransition, "at the deadline it is already aborted");
    assert_eq!(r.mode(), Mode::Blocked);
    assert!(is_outcome(r.state_of(3, 1, 12), Outcome::Failed));
    assert_eq!(r.hub.last_committed(), 1);
}

/// `abort_transition`: Aborted before the commit; AlreadyCommitted (even after B left, so
/// `seal_handoff` still runs on A's chain); Stale for any other id or a plain hand.
#[test]
fn abort_transition_aborted_already_committed_and_stale() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    assert_eq!(r.hub.abort_transition(t.id + 100, AbortReason::CaptureUnavailable, r.t(2)), AbortOutcome::Stale);
    assert_eq!(r.mode(), Mode::Transitioning { id: t.id, to: r.hub.lock_core().arbiter.guard().unwrap().to });
    assert_eq!(r.hub.abort_transition(t.id, AbortReason::CaptureUnavailable, r.t(2)), AbortOutcome::Aborted);
    assert_eq!(r.mode(), Mode::Blocked);
    assert!(is_outcome(r.state_of(3, 1, 2), Outcome::Failed));
    assert_eq!(r.hub.abort_transition(t.id, AbortReason::CaptureUnavailable, r.t(2)), AbortOutcome::Stale, "already resolved");

    // Commit wins, then B leaves before the job asks: AlreadyCommitted, seal_handoff still runs for A.
    let r2 = Rig::new(3);
    r2.own(1, 2);
    let id = r2.admit(3, 1, 0);
    let t = r2.accept_and_begin(1, id, 1);
    let (who, epoch) = match r2.hub.commit_at(t.id, r2.t(2)) {
        CommitOutcome::Owned { who, epoch } => (who, epoch),
        o => panic!("{o:?}"),
    };
    let mut r2 = r2;
    r2.leave_directory(3);
    r2.hub.teardown_by_handle(3);
    assert_eq!(
        r2.hub.abort_transition(t.id, AbortReason::Deadline, r2.t(3)),
        AbortOutcome::AlreadyCommitted { who, epoch }
    );
    let rx1 = &mut r2.rxs.iter_mut().find(|(h, _)| *h == 1).unwrap().1;
    while rx1.try_recv().is_ok() {}
    r2.hub.complete_grant(Some(id), 1, 3, epoch);
    let rx1 = &mut r2.rxs.iter_mut().find(|(h, _)| *h == 1).unwrap().1;
    assert!(
        matches!(rx1.try_recv(), Ok(HandoffOutbound::SealAudit(_))),
        "the hand's audit is still sealed on A's chain although B already left"
    );

    // A plain hand is never aborted by this path.
    let r3 = Rig::new(3);
    r3.own(1, 2);
    let plain = r3.hub.begin_by_handle(1, 3).unwrap();
    assert_eq!(r3.hub.abort_transition(plain.id, AbortReason::Deadline, r3.t(100)), AbortOutcome::Stale);
    assert!(matches!(r3.mode(), Mode::Transitioning { .. }), "no deadline, no abort");
    r3.hub.sweep_requests(r3.t(1000));
    assert!(matches!(r3.mode(), Mode::Transitioning { .. }));
}

/// The job's helper: done first, then the hub, then done once more after `Stale`.
#[test]
fn resolve_after_wait_never_reports_failed_for_a_commit_that_won() {
    let r = Rig::new(3);
    r.own(1, 2);
    let epoch = r.hub.lock_core().arbiter.epoch();
    let owned = CommitOutcome::Owned { who: Member { handle: 3, incarnation: 1 }, epoch };

    // 1. done already has the commit.
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(owned.clone()).unwrap();
    assert_eq!(resolve_after_wait(&r.hub, 99, &rx, AbortReason::Deadline, r.t(0)), FenceResolution::Committed { who: Member { handle: 3, incarnation: 1 }, epoch });

    // 2. nothing arrived and the transition is in flight: aborted -> failed.
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    let (_tx, rx) = std::sync::mpsc::channel::<CommitOutcome>();
    assert_eq!(resolve_after_wait(&r.hub, t.id, &rx, AbortReason::Deadline, r.t(2)), FenceResolution::Failed);
    assert_eq!(r.mode(), Mode::Blocked);

    // 3. the commit landed before the job asked: AlreadyCommitted takes the Owned path.
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    let out = r.hub.commit_at(t.id, r.t(2));
    let (_tx, rx) = std::sync::mpsc::channel::<CommitOutcome>();
    match (out, resolve_after_wait(&r.hub, t.id, &rx, AbortReason::Deadline, r.t(3))) {
        (CommitOutcome::Owned { who, epoch }, FenceResolution::Committed { who: w2, epoch: e2 }) => assert_eq!((who, epoch), (w2, e2)),
        o => panic!("{o:?}"),
    }

    // 4. the hub says Stale (the sweep already aborted this id) and nothing arrived: failed. (The
    // second `try_recv` after Stale is the same call as case 1; interleaving it with a concurrent
    // send is covered by the real capture thread in the host-wiring step.)
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    r.hub.sweep_requests(r.t(11));
    let (_tx, rx) = std::sync::mpsc::channel::<CommitOutcome>();
    assert_eq!(resolve_after_wait(&r.hub, t.id, &rx, AbortReason::Deadline, r.t(12)), FenceResolution::Failed);
}

/// Either party leaving or losing eligibility before the commit aborts a REQUEST-DRIVEN hand; a plain
/// hand keeps today's behaviour (it still commits after its sender leaves).
#[test]
fn party_departure_aborts_request_driven_hands_only() {
    for leaver in [1u64, 3u64] {
        let mut r = Rig::new(3);
        r.own(1, 2);
        let id = r.admit(3, 1, 0);
        let t = r.accept_and_begin(1, id, 1);
        r.take();
        r.leave_directory(leaver); // member_left, before the ordered teardown
        assert_eq!(r.mode(), Mode::Blocked, "aborted on the directory departure alone");
        r.hub.teardown_by_handle(leaver); // idempotent
        assert_eq!(r.hub.commit_at(t.id, r.t(2)), CommitOutcome::StaleTransition);
        let ds = r.take();
        if leaver == 3 {
            assert!(closed(&ds).is_empty(), "B gone: discarded, no close");
            assert_eq!(withdrawn_to(&ds, 1), vec![(id, WithdrawReason::RequesterLeft)]);
        } else {
            assert_eq!(closed(&ds), vec![(3, id, Outcome::Failed)]);
        }
    }
    // Demotion of either party before the commit.
    for demoted in [1u64, 3u64] {
        let r = Rig::new(3);
        r.own(1, 2);
        let id = r.admit(3, 1, 0);
        let t = r.accept_and_begin(1, id, 1);
        r.hub.set_control_eligible(demoted, false);
        assert_eq!(r.mode(), Mode::Blocked);
        assert!(is_outcome(r.state_of(3, 1, 2), Outcome::Failed));
        assert_eq!(r.hub.commit_at(t.id, r.t(2)), CommitOutcome::StaleTransition);
    }
    // Plain hand: the sender leaves, the hand still commits.
    let r = Rig::new(3);
    r.own(1, 2);
    let plain = r.hub.begin_by_handle(1, 3).unwrap();
    r.hub.teardown_by_handle(1);
    assert!(matches!(r.mode(), Mode::Transitioning { .. }));
    assert!(matches!(r.hub.commit_at(plain.id, r.t(1)), CommitOutcome::Owned { .. }));
}

/// A holder's directory entry vanishes before its Release sentinel: the request settles once.
#[test]
fn holder_departure_between_directory_removal_and_the_sentinel_settles_once() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    r.leave_directory(1);
    let first = r.take();
    assert_eq!(closed(&first), vec![(3, id, Outcome::HolderChanged)], "settled by the directory departure alone");
    assert_eq!(results_to(&first, 3).len(), 1);
    r.hub.teardown_by_handle(1); // the ordered sentinel arrives later: nothing more to settle
    let ds = r.take();
    assert!(closed(&ds).is_empty() && results_to(&ds, 3).is_empty(), "settled once");
    assert!(is_outcome(r.state_of(3, 1, 1), Outcome::HolderChanged));
}

// ── the capture thread's trigger ──────────────────────────────────────────────────────────────────

#[test]
fn the_next_deadline_mirror_drives_a_cheap_capture_side_sweep() {
    let r = Rig::new(3);
    r.own(1, 2);
    assert_eq!(r.hub.next_deadline_ns.load(Ordering::SeqCst), u64::MAX, "nothing pending");
    let id = r.admit(3, 1, 0);
    let due = r.hub.next_deadline_ns.load(Ordering::SeqCst);
    assert_eq!(due, r.hub.deadline_ns(r.t(10)), "undelivered at 10 s");
    r.hub.sweep_if_due(r.t(9));
    assert!(matches!(r.state_of(3, 1, 9), RequestReply::Pending { .. }));
    r.hub.sweep_if_due(r.t(10));
    assert!(is_outcome(r.state_of(3, 1, 10), Outcome::Undelivered));
    let _ = id;
    assert_eq!(r.hub.next_deadline_ns.load(Ordering::SeqCst), u64::MAX);
}

/// Admission, answer, abort, sweep and member_left from several threads at once: no deadlock, and
/// every request is closed at most once.
#[test]
fn concurrent_entry_points_and_a_real_party_leaving_do_not_deadlock_and_settle_each_request_once() {
    let mut r = Rig::new(6);
    r.own(1, 2);
    let hub = Arc::clone(&r.hub);
    let base = r.base;
    let sink: Arc<Mutex<Vec<Directive>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let mut workers = Vec::new();
    // Nobody else drains the sessions' queues, so a drainer keeps every one below its cap (an audit
    // that did not fit would disconnect the session and abandon the request).
    let mut rxs = std::mem::take(&mut r.rxs);
    let drainer = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for (_, rx) in rxs.iter_mut() {
                    while rx.try_recv().is_ok() {}
                }
                std::thread::yield_now();
            }
        })
    };
    let pending_of = |sink: &Mutex<Vec<Directive>>, hub: &InputArbiterHub, cid: Uuid| -> Option<Uuid> {
        let mut s = sink.lock().unwrap();
        s.extend(hub.take_log());
        s.iter().rev().find_map(|d| match d {
            Directive::ToRequester { msg: RequesterMsg::Pending { client_request_id, request_id, .. }, .. }
                if *client_request_id == cid =>
            {
                Some(*request_id)
            }
            _ => None,
        })
    };
    for w in 0..3u64 {
        let hub = Arc::clone(&hub);
        let sink = Arc::clone(&sink);
        let done = done_tx.clone();
        workers.push(std::thread::spawn(move || {
            for i in 0..150u64 {
                let now = base + Duration::from_millis(i * 400);
                let b = 3 + (i + w) % 4;
                let cid = Uuid::from_u128(((w as u128) << 32) | i as u128);
                hub.request_input(b, cid, false, now);
                if let Some(request_id) = pending_of(&sink, &hub, cid) {
                    match (i + w) % 3 {
                        0 => {
                            let _ = hub.answer_request(1, request_id, true, AcceptGate::Held, now);
                            if let Ok(t) = hub.begin_request_by_handle(request_id, now) {
                                let _ = hub.abort_transition(t.id, AbortReason::Deadline, now);
                            }
                        }
                        1 => hub.withdraw_request(b, cid, now),
                        _ => {
                            let _ = hub.answer_request(1, request_id, false, AcceptGate::Held, now);
                        }
                    }
                }
                hub.sweep_requests(now);
                if i % 20 == 0 {
                    // Re-arm a hand so the abort paths keep having something to abort.
                    if let Ok(t) = hub.begin_by_handle(2, 1) {
                        let _ = hub.commit_at(t.id, now);
                    }
                }
            }
            let _ = done.send(());
        }));
    }
    // A real party leaves and REJOINS (registry and directory), over and over, while the others work.
    {
        let hub = Arc::clone(&hub);
        let done = done_tx.clone();
        workers.push(std::thread::spawn(move || {
            let mut kept = Vec::new(); // registrations and receivers stay alive until the end
            for k in 0..60u64 {
                let h = 5 + k % 2;
                hub.member_left(h);
                hub.teardown_by_handle(h);
                hub.register(h);
                hub.set_control_eligible(h, true);
                hub.set_request_capable(h);
                let (tx, mut rx) = handoff_channel();
                let id = SessionIdentity {
                    handle: h,
                    control_plane_session: Some(Uuid::from_u128(h as u128)),
                    technician_id: Some(Uuid::from_u128(1000 + h as u128)),
                };
                let reg = hub.join_directory(format!("rejoin-{h}"), id, tx);
                while rx.try_recv().is_ok() {}
                kept.push((reg, rx));
                if kept.len() > 4 {
                    // Keep the newest few; dropping an older one is another real departure.
                    let (old_reg, mut old_rx) = kept.remove(0);
                    while old_rx.try_recv().is_ok() {}
                    drop(old_reg);
                }
                for (_, rx) in kept.iter_mut() {
                    while rx.try_recv().is_ok() {}
                }
            }
            let _ = done.send(());
        }));
    }
    drop(done_tx);
    for _ in 0..4 {
        done_rx.recv_timeout(Duration::from_secs(60)).expect("a worker deadlocked");
    }
    for w in workers {
        w.join().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    drainer.join().unwrap();
    // Settle whatever is still live (timers, lost jobs, deadline aborts).
    hub.sweep_requests(base + Duration::from_secs(3600));
    sink.lock().unwrap().extend(hub.take_log());
    let ds = sink.lock().unwrap().clone();

    let mut admitted: std::collections::HashMap<Uuid, u64> = Default::default();
    for d in &ds {
        if let Directive::ToRequester { to, msg: RequesterMsg::Pending { request_id, .. } } = d {
            admitted.entry(*request_id).or_insert(*to);
        }
    }
    assert!(admitted.len() >= 6, "the run admitted requests ({}): the 10 s rate limit bounds it", admitted.len());
    let mut closed_n: std::collections::HashMap<Uuid, usize> = Default::default();
    for (_, id, _) in closed(&ds) {
        *closed_n.entry(id).or_default() += 1;
    }
    let mut results_n: std::collections::HashMap<Uuid, usize> = Default::default();
    for d in &ds {
        if let Directive::ToRequester { msg: RequesterMsg::Result { request_id: Some(id), outcome: Resolved::Outcome(_), .. }, .. } = d {
            *results_n.entry(*id).or_default() += 1;
        }
    }
    for (id, b) in &admitted {
        let results = results_n.get(id).copied().unwrap_or(0);
        let closes = closed_n.get(id).copied().unwrap_or(0);
        assert!(results <= 1 && closes <= 1, "request {id}: {results} results, {closes} closes");
        if *b == 3 || *b == 4 {
            // These requesters never left: the request MUST have ended exactly once, closed and answered.
            assert_eq!((results, closes), (1, 1), "request {id} of the session that stayed");
        }
    }
    assert!(closed_n.keys().all(|id| admitted.contains_key(id)), "no close for a request that was never admitted");
}
// ── review changes (e50367d1) ─────────────────────────────────────────────────────────────────────

/// L1: a gate obtained only at or past the deadline begins nothing: the mode is untouched.
#[test]
fn a_begin_whose_gate_arrives_after_the_deadline_begins_nothing() {
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let accepted = Instant::now() - Duration::from_secs(11); // the 10 s deadline passed a second ago
    assert!(matches!(r.hub.answer_request(1, id, true, AcceptGate::Held, accepted), AnswerResult::Consumed { .. }));
    let before = r.mode();
    assert_eq!(r.hub.begin_request_by_handle(id, accepted), Err(RequestBeginError::GateTimeout));
    assert_eq!(r.mode(), before, "nothing began");
    assert!(r.hub.lock_core().arbiter.guard().is_none());
    assert!(is_outcome(r.state_of(3, 1, 0), Outcome::Failed));
}

/// L2: when the sweep in the same call aborts the id, the answer is `Aborted`, not `Stale`.
#[test]
fn abort_transition_reports_aborted_when_its_own_sweep_aborted_the_id() {
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1); // deadline t=11
    assert_eq!(r.hub.abort_transition(t.id, AbortReason::Deadline, r.t(11)), AbortOutcome::Aborted);
    assert_eq!(r.mode(), Mode::Blocked);
    assert_eq!(r.hub.abort_transition(t.id, AbortReason::Deadline, r.t(11)), AbortOutcome::Stale, "a second ask is stale");
}

/// L3: five sessions of one technician hold at most one live request between them.
#[test]
fn one_live_request_per_technician_across_five_sessions() {
    let mut r = Rig::new(2);
    r.own(1, 2);
    for h in 3..=7 {
        r.add_with_tech(h, true, 5000);
    }
    let first = r.admit(3, 1, 0);
    r.hub.prompt_shown(1, first, r.t(1)); // shown, so it stays live past 10 s
    for (i, h) in (4..=7u64).enumerate() {
        assert!(
            matches!(r.req(h, 10 + i as u128, 20), RequestReply::Result { outcome: Resolved::Refusal(Refusal::Capacity), .. }),
            "session {h}"
        );
    }
    // Once the first request ends, another session of that technician may ask.
    assert_eq!(r.hub.answer_request(1, first, false, AcceptGate::Held, r.t(21)), AnswerResult::Declined);
    r.admit(4, 20, 22);
}

/// L4: a departed session's cache entries (refusals included) are gone, by either departure signal.
#[test]
fn a_departed_requester_leaves_no_cache_entries() {
    let mut r = Rig::new(4); // Unowned: every request is a cached no_holder refusal
    for i in 0..10u128 {
        r.req(2, 100 + i, 0);
        r.req(3, 200 + i, 0);
    }
    assert_eq!(r.hub.lock_core().requests.cache_len(), 20);
    r.hub.teardown_by_handle(2);
    assert_eq!(r.hub.lock_core().requests.cache_len(), 10, "teardown drops the departed session's entries");
    r.leave_directory(3);
    assert_eq!(r.hub.lock_core().requests.cache_len(), 0, "so does the directory departure");
}

/// L5: a session that is not registered or never announced `InputRequestCapable` gets NO reply, no
/// cache entry and no rate-limit charge; an answer from one is `NoEffect` with no `Withdrawn`.
#[test]
fn unannounced_and_unregistered_sessions_get_no_reply_at_all() {
    let mut r = Rig::new(3);
    r.add(7, false);
    r.add(8, false);
    r.own(1, 2);
    assert!(matches!(r.req(7, 1, 0), RequestReply::Dropped));
    assert!(matches!(r.req(99, 2, 0), RequestReply::Dropped));
    assert!(matches!(r.retry(7, 1, 0), RequestReply::Dropped));
    assert!(matches!(r.withdraw(7, 1, 0), RequestReply::Dropped));
    assert!(r.take().is_empty(), "nothing queued to anyone");
    assert_eq!(r.hub.lock_core().requests.cache_len(), 0);
    // No charge: once it announces, its first request is admitted at once.
    r.hub.set_request_capable(7);
    r.admit(7, 3, 1);
    // An answer from a session that never announced is a silent no-op.
    let id = r.admit(3, 4, 1);
    r.take();
    assert_eq!(r.hub.answer_request(8, id, true, AcceptGate::Held, r.t(2)), AnswerResult::NoEffect);
    assert!(withdrawn_to(&r.take(), 8).is_empty());
}

/// L6: an owner that has left (directory gone, teardown not yet run) is no holder.
#[test]
fn a_departed_owner_is_no_holder() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    r.leave_directory(1);
    assert!(matches!(r.mode(), Mode::Owned { .. }), "premise: the arbiter has not heard yet");
    assert!(matches!(r.req(3, 1, 0), RequestReply::Result { outcome: Resolved::Refusal(Refusal::NoHolder), .. }));
}

/// A plain hand's sender leaving the directory does not stop its commit (today's behaviour).
#[test]
fn a_plain_hands_sender_leaving_the_directory_still_commits() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    let plain = r.hub.begin_by_handle(1, 3).unwrap();
    r.leave_directory(1); // member_left on the sender
    assert!(matches!(r.mode(), Mode::Transitioning { .. }), "no deadline, no party-left abort");
    assert!(matches!(r.hub.commit_at(plain.id, r.t(1)), CommitOutcome::Owned { .. }));
}

/// Replace versus answer, both orders: a replaced request's late accept is only `Withdrawn{replaced}`;
/// an accept that wins makes the next request `busy`.
#[test]
fn replace_versus_answer_both_orders() {
    let r = Rig::new(3);
    r.own(1, 2);
    let a = r.admit(3, 1, 0);
    r.hub.prompt_shown(1, a, r.t(1));
    let b = r.admit(3, 2, 10); // replaces a
    assert!(is_outcome(r.state_of(3, 1, 10), Outcome::Replaced));
    r.take();
    assert_eq!(r.hub.answer_request(1, a, true, AcceptGate::Held, r.t(11)), AnswerResult::Withdrawn);
    assert_eq!(
        withdrawn_to(&r.take(), 1),
        vec![(a, WithdrawReason::Outcome(Outcome::Replaced))]
    );
    assert!(matches!(r.state_of(3, 2, 11), RequestReply::Pending { request_id, .. } if request_id == b), "b untouched");
    // The accept wins: b is consumed, so a further request from the same session is refused busy.
    assert!(matches!(r.hub.answer_request(1, b, true, AcceptGate::Held, r.t(12)), AnswerResult::Consumed { .. }));
    assert!(matches!(r.req(3, 3, 13), RequestReply::Result { outcome: Resolved::Refusal(Refusal::Busy), .. }));
}

/// The final `try_recv` after `Stale`: the fence's `done` can arrive in the instant after the hub
/// answered, so the job looks once more before concluding anything.
#[test]
fn the_second_try_recv_after_stale_sees_a_done_that_arrived_in_between() {
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    r.hub.sweep_requests(r.t(11)); // aborted by the deadline: the hub will answer Stale
    let owned = CommitOutcome::Owned { who: Member { handle: 3, incarnation: 3 }, epoch: 9 };
    let (tx, rx) = std::sync::mpsc::channel();
    let got = resolve_after_wait_with(&r.hub, t.id, &rx, AbortReason::Deadline, r.t(12), || tx.send(owned.clone()).unwrap());
    assert_eq!(got, FenceResolution::Committed { who: Member { handle: 3, incarnation: 3 }, epoch: 9 });
    // Without the late send the same situation is a failure.
    let r = Rig::new(3);
    r.own(1, 2);
    let id = r.admit(3, 1, 0);
    let t = r.accept_and_begin(1, id, 1);
    r.hub.sweep_requests(r.t(11));
    let (_tx, rx) = std::sync::mpsc::channel::<CommitOutcome>();
    assert_eq!(
        resolve_after_wait_with(&r.hub, t.id, &rx, AbortReason::Deadline, r.t(12), || {}),
        FenceResolution::Failed
    );
}

/// L1: an already-invalid accepted hand is refused by the job's pre-check BEFORE it cancels anyone's typing.
#[test]
fn a_refused_precheck_fails_the_request_without_cancelling_typing() {
    struct CancelCounter(Arc<std::sync::atomic::AtomicUsize>);
    impl InputSink for CancelCounter {
        fn inject(&self, _event: InputEvent) -> PlatformResult<()> {
            Ok(())
        }
        fn cancel_typing(&self, _wait: bool) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let cancels = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let coordinator = Arc::new(InputCoordinator::with_injector(Box::new(CancelCounter(Arc::clone(&cancels)))));
    let stop = Arc::new(AtomicBool::new(false));
    let (cap, thread) = SharedCapture::spawn_inner(
        super::tests::SyntheticCapturer::with_frames(0),
        60,
        Arc::clone(&stop),
        coordinator,
        false,
    );
    let (a, b) = (cap.new_session_input(), cap.new_session_input());
    let mut keep = Vec::new();
    for (n, s) in [(1u128, &a), (2u128, &b)] {
        cap.arb.set_control_eligible(s.handle(), true);
        cap.arb.set_request_capable(s.handle());
        let (tx, rx) = handoff_channel();
        let id = SessionIdentity { handle: s.handle(), control_plane_session: None, technician_id: None };
        keep.push((cap.arb.join_directory(format!("sig-{n}"), id, tx), rx));
    }
    cap.hand_input_control(b.handle(), a.handle()).unwrap(); // a owns input
    let t0 = Instant::now();
    cap.arb.request_input(b.handle(), Uuid::from_u128(1), false, t0);
    let id = cap.arb.lock_core().requests.live[0].request_id;
    assert!(matches!(
        cap.arb.answer_request(a.handle(), id, true, AcceptGate::Held, t0),
        AnswerResult::Consumed { .. }
    ));
    cap.arb.set_control_eligible(b.handle(), false); // the hand is now invalid
    cancels.store(0, Ordering::SeqCst);
    let out = cap.hand_input_control_for_request(a.handle(), id, t0 + Duration::from_secs(10));
    assert_eq!(out, RequestHandOutcome::Failed);
    assert_eq!(cancels.load(Ordering::SeqCst), 0, "typing was not cancelled for a refused hand");
    assert_eq!(cap.arb.live_requests(), 0, "the request settled failed");
    stop.store(true, Ordering::SeqCst);
    thread.join().unwrap();
}

/// N1 (a): a requester whose handoff queue is at its cap cannot take the `requested` audit seal: the
/// request is NOT admitted (no prompt to the holder, no cache entry, no reply) and the session is
/// told to disconnect. Audit is never dropped.
#[test]
fn a_requester_queue_at_its_cap_means_not_admitted_and_a_disconnect() {
    let mut r = Rig::new(3);
    r.own(1, 2);
    for i in 0..crate::session_directory::MAX_PENDING_OUTBOUND {
        let fill = HandoffOutbound::Control(ControlMessage::Error { message: format!("fill {i}") });
        assert!(r.hub.directory.send_to_handle(3, fill));
    }
    assert!(matches!(r.req(3, 1, 0), RequestReply::Dropped), "no reply is possible");
    assert_eq!(r.hub.live_requests(), 0, "not admitted");
    assert_eq!(r.hub.lock_core().requests.cache_len(), 0, "no cache entry either");
    let holder_q = r.drain(1);
    assert!(
        !holder_q.iter().any(|m| matches!(m, HandoffOutbound::Request(Directive::ToHolder { .. }))),
        "the holder never saw a prompt: {holder_q:?}"
    );
    let q = r.drain(3);
    assert!(matches!(q.last(), Some(HandoffOutbound::Disconnect(_))), "the requester is told to end: {:?}", q.last());
    assert!(
        !q.iter().any(|m| matches!(m, HandoffOutbound::Request(_))),
        "nothing of the abandoned request reached the requester"
    );
}

