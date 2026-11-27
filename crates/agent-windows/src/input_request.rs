//! The request-for-input-control book (docs/73 2.2.3, build step b): request records, the replay
//! cache, the bounds, the single `settle` and the directives it emits, as plain data.
//!
//! This module knows nothing about the arbiter, the registry or the directory. The hub
//! (`shared_capture::InputArbiterHub`) holds one [`RequestBook`] under its `core` lock, decides every
//! event there, and calls the book to record the decision. Nothing here sends anything: every effect
//! is a [`Directive`] pushed on the book's outbox in the order the decisions were made, for the host
//! wiring (build step c) to route onto the sessions' handoff queues.

#![cfg_attr(not(windows), allow(dead_code))]
// Unused outside tests until the host wiring (docs/73 build step c).
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::input_arbiter::Member;

/// A request-driven hand's deadline, from the moment the holder's accept is received.
pub(crate) const REQUEST_HAND_DEADLINE: Duration = Duration::from_secs(10);
/// A prompt nobody confirmed shown within this long is `undelivered`.
pub(crate) const UNDELIVERED_AFTER: Duration = Duration::from_secs(10);
/// A shown prompt nobody answered within this long is `expired`.
pub(crate) const EXPIRES_AFTER: Duration = Duration::from_secs(60);
/// Minimum spacing between two admitted requests of one session (or technician).
pub(crate) const RATE_LIMIT: Duration = Duration::from_secs(10);
pub(crate) const MAX_LIVE_PER_HOLDER: usize = 4;
pub(crate) const MAX_LIVE_PER_MACHINE: usize = 8;
/// How long a terminal result stays replayable.
pub(crate) const REPLAY_RETENTION: Duration = Duration::from_secs(300);
pub(crate) const MAX_CACHE_PER_INCARNATION: usize = 32;
pub(crate) const MAX_CACHE_PER_MACHINE: usize = 256;

/// Terminal outcomes of an ADMITTED request (the closed set; also the audit enum).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Outcome {
    Granted,
    Declined,
    Expired,
    Undelivered,
    Cancelled,
    Replaced,
    HolderChanged,
    AlreadySatisfied,
    Failed,
    /// The requester lost eligibility after admission.
    Ineligible,
}

impl Outcome {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Outcome::Granted => "granted",
            Outcome::Declined => "declined",
            Outcome::Expired => "expired",
            Outcome::Undelivered => "undelivered",
            Outcome::Cancelled => "cancelled",
            Outcome::Replaced => "replaced",
            Outcome::HolderChanged => "holder_changed",
            Outcome::AlreadySatisfied => "already_satisfied",
            Outcome::Failed => "failed",
            Outcome::Ineligible => "ineligible",
        }
    }
}

/// Immediate refusals: no request id, cached for retry, never audited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Refusal {
    Ineligible,
    NoHolder,
    Busy,
    RateLimited,
    Capacity,
    UnsupportedHolder,
}

/// What a reply to the requester says happened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Resolved {
    Outcome(Outcome),
    Refusal(Refusal),
    /// Reply-only: the agent holds no record (window passed, evicted, or another incarnation).
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ReqState {
    PendingDelivery,
    Shown,
    AcceptedInFlight,
}

/// The reply to the requester's `RequestInputControl` / `Withdraw`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RequestReply {
    Pending { client_request_id: Uuid, request_id: Uuid, state: ReqState },
    Result { client_request_id: Uuid, request_id: Option<Uuid>, outcome: Resolved },
    /// The session never announced `InputRequestCapable`: dropped silently, no reply, no state.
    Dropped,
}

/// Trusted ids captured at admission (nil where signaling vouched for none).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct TrustedIds {
    pub requester_session: Uuid,
    pub requester_technician: Uuid,
    pub holder_session: Uuid,
    pub holder_technician: Uuid,
}

/// A live (non-terminal) request.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub request_id: Uuid,
    pub client_request_id: Uuid,
    pub requester: Member,
    pub holder: Member,
    /// The Owned epoch the request was bound to at admission.
    pub epoch: u64,
    pub ids: TrustedIds,
    pub state: ReqState,
    pub admitted_at: Instant,
    /// Set at consumption (the accept): `consumed + REQUEST_HAND_DEADLINE`.
    pub deadline: Option<Instant>,
    /// The transition id, recorded by the job's begin.
    pub transition: Option<u64>,
    /// A PLAIN hand of the holder to this requester was seen in flight under this id.
    pub plain_to_requester: Option<u64>,
}

impl RequestReply {
    /// The message that carries this reply onto the requester's queue (`Dropped` carries none).
    pub(crate) fn as_msg(&self) -> Option<RequesterMsg> {
        match *self {
            RequestReply::Pending { client_request_id, request_id, state } => {
                Some(RequesterMsg::Pending { client_request_id, request_id, state })
            }
            RequestReply::Result { client_request_id, request_id, outcome } => {
                Some(RequesterMsg::Result { client_request_id, request_id, outcome })
            }
            RequestReply::Dropped => None,
        }
    }
}

impl Directive {
    /// The arbiter handle whose handoff queue this directive belongs on.
    pub(crate) fn target(&self) -> u64 {
        match self {
            Directive::ToRequester { to, .. } | Directive::ToHolder { to, .. } | Directive::Audit { to, .. } => *to,
        }
    }

    /// The request it concerns, when it names one.
    pub(crate) fn request_id(&self) -> Option<Uuid> {
        match self {
            Directive::ToRequester { msg: RequesterMsg::Pending { request_id, .. }, .. } => Some(*request_id),
            Directive::ToRequester { msg: RequesterMsg::Result { request_id, .. }, .. } => *request_id,
            Directive::ToHolder { msg: HolderMsg::Requested { request_id, .. } | HolderMsg::Withdrawn { request_id, .. }, .. } => {
                Some(*request_id)
            }
            Directive::Audit { record: AuditRecord::Requested { request_id, .. } | AuditRecord::Closed { request_id, .. }, .. } => {
                Some(*request_id)
            }
        }
    }
}

/// Who gets what, as data. The host routes these onto the sessions' queues (step c).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Directive {
    /// A reply to the requester (always queued, never sent directly).
    ToRequester { to: u64, msg: RequesterMsg },
    /// A message to the holder.
    ToHolder { to: u64, msg: HolderMsg },
    /// An audit record for the REQUESTER's chain only (never A's).
    Audit { to: u64, record: AuditRecord },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequesterMsg {
    Pending { client_request_id: Uuid, request_id: Uuid, state: ReqState },
    Result { client_request_id: Uuid, request_id: Option<Uuid>, outcome: Resolved },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HolderMsg {
    /// The prompt. `from` is the requester's arbiter handle (the host maps it to a signaling id).
    Requested { request_id: Uuid, from: u64, expires_in_ms: u64 },
    Withdrawn { request_id: Uuid, reason: WithdrawReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WithdrawReason {
    Outcome(Outcome),
    RequesterLeft,
    /// An id the agent does not hold for this holder.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditRecord {
    Requested { request_id: Uuid, ids: TrustedIds, epoch: u64 },
    Closed { request_id: Uuid, ids: TrustedIds, epoch: u64, outcome: Outcome },
}

/// One replay-cache entry: every admitted request and every immediate refusal.
#[derive(Clone, Debug)]
struct CacheEntry {
    requester: Member,
    client_request_id: Uuid,
    request_id: Option<Uuid>,
    holder: Option<Member>,
    /// `None` while the request is live.
    result: Option<Resolved>,
    terminal_at: Option<Instant>,
}

/// A request settled `granted`, whose `closed`/`Result`/`Withdrawn` are sent by `finish_granted`,
/// after the hand's own audit directives (docs/73 2.2.5).
#[derive(Clone, Copy, Debug)]
struct Unfinished {
    client_request_id: Uuid,
    requester: u64,
    holder: u64,
    ids: TrustedIds,
    epoch: u64,
    /// Decided in `settle`: the requester's registry entry was live at that instant.
    route_requester: bool,
    holder_live: bool,
    /// Pruned after this: the job that owes `finish_granted` died (the chain then ends at `handed`).
    prune_at: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum RateKey {
    Technician(Uuid),
    Session(Member),
}

#[derive(Default)]
pub(crate) struct RequestBook {
    pub(crate) live: Vec<Request>,
    cache: Vec<CacheEntry>,
    unfinished: HashMap<Uuid, Unfinished>,
    last_admit: HashMap<RateKey, Instant>,
    outbox: Vec<Directive>,
}

impl RequestBook {
    pub(crate) fn take_outbox(&mut self) -> Vec<Directive> {
        std::mem::take(&mut self.outbox)
    }

    pub(crate) fn push(&mut self, d: Directive) {
        self.outbox.push(d);
    }

    pub(crate) fn find(&self, request_id: Uuid) -> Option<&Request> {
        self.live.iter().find(|r| r.request_id == request_id)
    }

    pub(crate) fn find_mut(&mut self, request_id: Uuid) -> Option<&mut Request> {
        self.live.iter_mut().find(|r| r.request_id == request_id)
    }

    pub(crate) fn live_of_requester(&self, m: Member) -> Option<&Request> {
        self.live.iter().find(|r| r.requester == m)
    }

    /// Drop retention-expired terminal cache entries and stale rate-limit marks.
    pub(crate) fn prune(&mut self, now: Instant) {
        self.unfinished.retain(|_, u| now < u.prune_at);
        self.cache.retain(|e| e.terminal_at.is_none_or(|t| now.saturating_duration_since(t) < REPLAY_RETENTION));
        self.last_admit.retain(|_, t| now.saturating_duration_since(*t) < RATE_LIMIT);
    }

    /// The reply for a cached key, CURRENT state for a live request, the recorded result otherwise.
    pub(crate) fn reply_for_key(&self, requester: Member, client_request_id: Uuid) -> Option<RequestReply> {
        let e = self.cache.iter().find(|e| e.requester == requester && e.client_request_id == client_request_id)?;
        Some(self.reply_for_entry(e))
    }

    fn reply_for_entry(&self, e: &CacheEntry) -> RequestReply {
        match (e.result, e.request_id) {
            (None, Some(rid)) => match self.find(rid) {
                Some(r) => RequestReply::Pending { client_request_id: e.client_request_id, request_id: rid, state: r.state },
                // Cannot happen (live and cached move together); never invent a state.
                None => RequestReply::Result {
                    client_request_id: e.client_request_id,
                    request_id: None,
                    outcome: Resolved::Unknown,
                },
            },
            (Some(outcome), rid) => {
                RequestReply::Result { client_request_id: e.client_request_id, request_id: rid, outcome }
            }
            (None, None) => RequestReply::Result {
                client_request_id: e.client_request_id,
                request_id: None,
                outcome: Resolved::Unknown,
            },
        }
    }

    /// The recorded terminal result of `request_id` for `holder` (an answer after terminal).
    pub(crate) fn recorded_for_holder(&self, request_id: Uuid, holder: Member) -> Option<Outcome> {
        self.cache.iter().find_map(|e| match (e.request_id, e.holder, e.result) {
            (Some(r), Some(h), Some(Resolved::Outcome(o))) if r == request_id && h == holder => Some(o),
            _ => None,
        })
    }

    fn charge_key(ids: &TrustedIds, requester: Member) -> RateKey {
        if ids.requester_technician.is_nil() {
            RateKey::Session(requester)
        } else {
            RateKey::Technician(ids.requester_technician)
        }
    }

    /// Bounds check in the fixed order `rate_limited` -> `capacity`. `replacing` is the requester's own
    /// live pending/shown request, which this admission would replace (it frees its slot).
    pub(crate) fn bound_refusal(
        &self,
        requester: Member,
        holder: Member,
        ids: &TrustedIds,
        now: Instant,
    ) -> Option<Refusal> {
        let key = Self::charge_key(ids, requester);
        if self.last_admit.get(&key).is_some_and(|t| now.saturating_duration_since(*t) < RATE_LIMIT) {
            return Some(Refusal::RateLimited);
        }
        // One live request per charge key (technician id when present, else session): a technician
        // with several sessions cannot hold several requests.
        if self.live.iter().any(|r| r.requester != requester && Self::charge_key(&r.ids, r.requester) == key) {
            return Some(Refusal::Capacity);
        }
        let own = self.live_of_requester(requester).map(|r| r.request_id);
        let per_holder = self.live.iter().filter(|r| r.holder == holder && Some(r.request_id) != own).count();
        let machine = self.live.len() - own.is_some() as usize;
        if per_holder >= MAX_LIVE_PER_HOLDER || machine >= MAX_LIVE_PER_MACHINE {
            return Some(Refusal::Capacity);
        }
        None
    }

    /// Record and cache an immediate refusal, and queue the reply to the requester.
    pub(crate) fn refuse(&mut self, requester: Member, client_request_id: Uuid, why: Refusal, now: Instant) -> RequestReply {
        let outcome = Resolved::Refusal(why);
        self.insert_cache(CacheEntry {
            requester,
            client_request_id,
            request_id: None,
            holder: None,
            result: Some(outcome),
            terminal_at: Some(now),
        });
        let reply = RequestReply::Result { client_request_id, request_id: None, outcome };
        self.outbox.push(Directive::ToRequester {
            to: requester.handle,
            msg: RequesterMsg::Result { client_request_id, request_id: None, outcome },
        });
        reply
    }

    /// Admit: record the request and queue, in this order, `requested` (audit, requester's chain),
    /// `Pending` to the requester, the prompt to the holder. The caller has already replaced any prior
    /// request of the requester (so its `closed{replaced}` precedes this `requested`).
    pub(crate) fn admit(&mut self, req: Request, now: Instant) -> RequestReply {
        let key = Self::charge_key(&req.ids, req.requester);
        self.last_admit.insert(key, now);
        self.insert_cache(CacheEntry {
            requester: req.requester,
            client_request_id: req.client_request_id,
            request_id: Some(req.request_id),
            holder: Some(req.holder),
            result: None,
            terminal_at: None,
        });
        let reply = RequestReply::Pending {
            client_request_id: req.client_request_id,
            request_id: req.request_id,
            state: ReqState::PendingDelivery,
        };
        self.outbox.push(Directive::Audit {
            to: req.requester.handle,
            record: AuditRecord::Requested { request_id: req.request_id, ids: req.ids, epoch: req.epoch },
        });
        self.outbox.push(Directive::ToRequester {
            to: req.requester.handle,
            msg: RequesterMsg::Pending {
                client_request_id: req.client_request_id,
                request_id: req.request_id,
                state: ReqState::PendingDelivery,
            },
        });
        self.outbox.push(Directive::ToHolder {
            to: req.holder.handle,
            msg: HolderMsg::Requested {
                request_id: req.request_id,
                from: req.requester.handle,
                expires_in_ms: EXPIRES_AFTER.as_millis() as u64,
            },
        });
        self.live.push(req);
        reply
    }

    /// THE ONLY way a request becomes terminal. Removes it from the live set, records the result in
    /// the replay cache and queues the effects: `closed` + `Result` to the requester when it is still
    /// the route (`requester_live`), `Withdrawn` to the holder when it is live. A `granted` request
    /// records its result and route here but sends nothing: `finish_granted` does, after the hand's
    /// own audit directives. Returns false when the request was already terminal (event ignored).
    pub(crate) fn settle(
        &mut self,
        request_id: Uuid,
        outcome: Outcome,
        now: Instant,
        requester_live: bool,
        holder_live: bool,
    ) -> bool {
        let Some(pos) = self.live.iter().position(|r| r.request_id == request_id) else { return false };
        let r = self.live.remove(pos);
        if let Some(e) = self.cache.iter_mut().find(|e| e.request_id == Some(request_id)) {
            e.result = Some(Resolved::Outcome(outcome));
            e.terminal_at = Some(now);
        }
        if outcome == Outcome::Granted {
            self.unfinished.insert(
                request_id,
                Unfinished {
                    client_request_id: r.client_request_id,
                    requester: r.requester.handle,
                    holder: r.holder.handle,
                    ids: r.ids,
                    epoch: r.epoch,
                    route_requester: requester_live,
                    holder_live,
                    // Commit is refused past the deadline, so the job finishes well inside this.
                    prune_at: r.deadline.unwrap_or(now) + REQUEST_HAND_DEADLINE,
                },
            );
            return true;
        }
        self.emit_terminal(&r.ids, r.epoch, request_id, r.client_request_id, r.requester.handle, r.holder.handle, outcome, requester_live, holder_live);
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_terminal(
        &mut self,
        ids: &TrustedIds,
        epoch: u64,
        request_id: Uuid,
        client_request_id: Uuid,
        requester: u64,
        holder: u64,
        outcome: Outcome,
        requester_live: bool,
        holder_live: bool,
    ) {
        if requester_live {
            self.outbox.push(Directive::Audit {
                to: requester,
                record: AuditRecord::Closed { request_id, ids: *ids, epoch, outcome },
            });
            self.outbox.push(Directive::ToRequester {
                to: requester,
                msg: RequesterMsg::Result {
                    client_request_id,
                    request_id: Some(request_id),
                    outcome: Resolved::Outcome(outcome),
                },
            });
        }
        if holder_live {
            self.outbox.push(Directive::ToHolder {
                to: holder,
                msg: HolderMsg::Withdrawn { request_id, reason: WithdrawReason::Outcome(outcome) },
            });
        }
    }

    /// Queue what a `granted` settle deferred: `closed{granted}` to the requester's chain, then its
    /// `Result`, then `Withdrawn{granted}` to the holder. Call it only AFTER the hand's own audit
    /// directives were queued. False when nothing was owed (unknown or already finished).
    pub(crate) fn finish_granted(&mut self, request_id: Uuid) -> bool {
        let Some(u) = self.unfinished.remove(&request_id) else { return false };
        self.emit_terminal(
            &u.ids,
            u.epoch,
            request_id,
            u.client_request_id,
            u.requester,
            u.holder,
            Outcome::Granted,
            u.route_requester,
            u.holder_live,
        );
        true
    }

    /// The requester's session ended: its records and cache entries are DISCARDED (no result, no
    /// close); each live request's holder is told `Withdrawn{requester_left}` when it is live.
    pub(crate) fn discard_requester(&mut self, requester: Member, holder_live: impl Fn(Member) -> bool) {
        let mut gone = Vec::new();
        self.live.retain(|r| {
            if r.requester == requester {
                gone.push(r.clone());
                false
            } else {
                true
            }
        });
        for r in gone {
            if holder_live(r.holder) {
                self.outbox.push(Directive::ToHolder {
                    to: r.holder.handle,
                    msg: HolderMsg::Withdrawn { request_id: r.request_id, reason: WithdrawReason::RequesterLeft },
                });
            }
        }
        self.cache.retain(|e| e.requester != requester);
    }

    /// A departed session leaves no cache entries behind (refusals included), however it left.
    pub(crate) fn drop_cache_of_handle(&mut self, handle: u64) {
        self.cache.retain(|e| e.requester.handle != handle);
    }

    /// Remove a just-admitted request silently (its `requested` seal could not be queued: not admitted).
    pub(crate) fn abandon(&mut self, request_id: Uuid) -> bool {
        let before = self.live.len();
        self.live.retain(|r| r.request_id != request_id);
        self.cache.retain(|e| e.request_id != Some(request_id));
        self.unfinished.remove(&request_id);
        before != self.live.len()
    }

    fn insert_cache(&mut self, e: CacheEntry) {
        let who = e.requester;
        self.cache.push(e);
        // Evict terminal entries only, oldest first: per incarnation, then per machine.
        while self.cache.iter().filter(|c| c.requester == who).count() > MAX_CACHE_PER_INCARNATION {
            if !self.evict_oldest_terminal(Some(who)) {
                break;
            }
        }
        while self.cache.len() > MAX_CACHE_PER_MACHINE {
            if !self.evict_oldest_terminal(None) {
                break;
            }
        }
    }

    fn evict_oldest_terminal(&mut self, only: Option<Member>) -> bool {
        let idx = self
            .cache
            .iter()
            .enumerate()
            .filter(|(_, c)| c.terminal_at.is_some() && only.is_none_or(|m| c.requester == m))
            .min_by_key(|(_, c)| c.terminal_at)
            .map(|(i, _)| i);
        match idx {
            Some(i) => {
                self.cache.remove(i);
                true
            }
            None => false,
        }
    }

    /// Earliest time at which `sweep` has something to do, from the records alone.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.live
            .iter()
            .filter_map(|r| match r.state {
                ReqState::PendingDelivery => Some(r.admitted_at + UNDELIVERED_AFTER),
                ReqState::Shown => Some(r.admitted_at + EXPIRES_AFTER),
                ReqState::AcceptedInFlight => if r.transition.is_none() { r.deadline } else { None },
            })
            .min()
    }

    #[cfg(test)]
    pub(crate) fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(h: u64) -> Member {
        Member { handle: h, incarnation: h * 10 }
    }

    fn req(n: u128, requester: u64, holder: u64, at: Instant) -> Request {
        Request {
            request_id: Uuid::from_u128(n),
            client_request_id: Uuid::from_u128(1000 + n),
            requester: m(requester),
            holder: m(holder),
            epoch: 5,
            ids: TrustedIds::default(),
            state: ReqState::PendingDelivery,
            admitted_at: at,
            deadline: None,
            transition: None,
            plain_to_requester: None,
        }
    }

    /// The machine cap is 8 live requests across holders (a per-holder cap of 4 binds first on one
    /// holder, so this needs two); a requester replacing its own request frees its slot.
    #[test]
    fn machine_cap_is_eight_and_replacing_frees_a_slot() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        for i in 0..4 {
            b.admit(req(i as u128, 10 + i, 1, now), now);
        }
        for i in 4..8 {
            b.admit(req(i as u128, 10 + i, 2, now), now);
        }
        let ids = TrustedIds::default();
        assert_eq!(b.bound_refusal(m(30), m(1), &ids, now), Some(Refusal::Capacity), "holder 1 already has 4");
        assert_eq!(b.bound_refusal(m(30), m(3), &ids, now), Some(Refusal::Capacity), "8 live on the machine");
        // Requester 10 already has a live request on holder 1: replacing it is within both caps.
        assert_eq!(b.bound_refusal(m(10), m(1), &ids, now + RATE_LIMIT), None);
    }

    /// `settle` is the only terminal path: the second settle of the same request is ignored, and a
    /// granted one stays silent until `finish_granted`, which then runs exactly once.
    #[test]
    fn settle_is_once_and_granted_waits_for_finish() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        b.admit(req(1, 10, 1, now), now);
        b.admit(req(2, 11, 1, now), now);
        b.take_outbox();
        assert!(b.settle(Uuid::from_u128(1), Outcome::Declined, now, true, true));
        assert!(!b.settle(Uuid::from_u128(1), Outcome::Expired, now, true, true), "already terminal");
        let out = b.take_outbox();
        assert_eq!(out.len(), 3, "closed + Result to the requester, Withdrawn to the holder");
        assert!(matches!(out[0], Directive::Audit { record: AuditRecord::Closed { outcome: Outcome::Declined, .. }, .. }));

        assert!(b.settle(Uuid::from_u128(2), Outcome::Granted, now, true, true));
        assert!(b.take_outbox().is_empty(), "granted sends nothing at settle");
        assert!(b.finish_granted(Uuid::from_u128(2)));
        assert_eq!(b.take_outbox().len(), 3);
        assert!(!b.finish_granted(Uuid::from_u128(2)), "once");
    }

    /// B gone at the decision: no close, no result to B, and A still hears the outcome.
    #[test]
    fn a_requester_that_is_gone_gets_no_close() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        b.admit(req(1, 10, 1, now), now);
        b.take_outbox();
        b.settle(Uuid::from_u128(1), Outcome::Failed, now, false, true);
        let out = b.take_outbox();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Directive::ToHolder { to: 1, .. }));
    }

    /// 256 entries per machine: the oldest TERMINAL one goes; live ones are never evicted.
    #[test]
    fn machine_cache_cap_evicts_terminal_only() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        b.admit(req(1, 10, 1, now), now); // live, oldest: must survive
        for i in 0..40u64 {
            for k in 0..8u64 {
                let who = m(100 + i);
                b.refuse(who, Uuid::from_u128(((i as u128) << 16) | k as u128), Refusal::NoHolder, now + Duration::from_millis(i * 10 + k));
            }
        }
        assert_eq!(b.cache_len(), MAX_CACHE_PER_MACHINE);
        assert!(b.reply_for_key(m(10), Uuid::from_u128(1001)).is_some_and(|r| matches!(r, RequestReply::Pending { .. })));
    }

    /// A discard names the requester by Member (handle AND incarnation), never by handle alone.
    #[test]
    fn discard_requester_matches_the_incarnation() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        let old = Member { handle: 10, incarnation: 100 };
        let new = Member { handle: 10, incarnation: 200 };
        let mut r1 = req(1, 10, 1, now);
        r1.requester = old;
        let mut r2 = req(2, 10, 1, now);
        r2.requester = new;
        b.admit(r1, now);
        b.admit(r2, now);
        b.discard_requester(old, |_| true);
        assert_eq!(b.live.len(), 1);
        assert_eq!(b.live[0].requester, new);
        assert!(b.reply_for_key(new, Uuid::from_u128(1002)).is_some(), "the new incarnation's cache entry stays");
        assert!(b.reply_for_key(old, Uuid::from_u128(1001)).is_none());
    }

    /// A granted request whose job never finished is pruned after its deadline plus one deadline.
    #[test]
    fn unfinished_grants_are_pruned_past_their_deadline() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        let mut r = req(1, 10, 1, now);
        r.deadline = Some(now + REQUEST_HAND_DEADLINE);
        b.admit(r, now);
        b.settle(Uuid::from_u128(1), Outcome::Granted, now, true, true);
        b.prune(now + REQUEST_HAND_DEADLINE * 2 - Duration::from_millis(1));
        assert!(b.unfinished.contains_key(&Uuid::from_u128(1)));
        b.prune(now + REQUEST_HAND_DEADLINE * 2);
        assert!(!b.finish_granted(Uuid::from_u128(1)), "pruned: nothing is owed any more");
    }

    /// One live request per charge key: a technician's second session is refused while the first lives.
    #[test]
    fn one_live_request_per_technician() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        let tech = Uuid::from_u128(77);
        let mut r1 = req(1, 10, 1, now);
        r1.ids.requester_technician = tech;
        b.admit(r1, now);
        let ids = TrustedIds { requester_technician: tech, ..TrustedIds::default() };
        let later = now + RATE_LIMIT * 2;
        assert_eq!(b.bound_refusal(m(11), m(1), &ids, later), Some(Refusal::Capacity));
        assert_eq!(b.bound_refusal(m(10), m(1), &ids, later), None, "its own request may be replaced");
    }

    /// Retention is 5 minutes from the terminal state.
    #[test]
    fn retention_is_five_minutes_from_terminal() {
        let now = Instant::now();
        let mut b = RequestBook::default();
        b.refuse(m(10), Uuid::from_u128(1), Refusal::Busy, now);
        b.prune(now + REPLAY_RETENTION - Duration::from_secs(1));
        assert!(b.reply_for_key(m(10), Uuid::from_u128(1)).is_some());
        b.prune(now + REPLAY_RETENTION);
        assert!(b.reply_for_key(m(10), Uuid::from_u128(1)).is_none());
    }
}

