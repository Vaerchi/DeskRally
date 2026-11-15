//! Retains session-end reports until signaling acknowledges a terminal control-plane result.
//!
//! Originally guest-end only; since docs/49 every end of a signaling-vouched session is reported
//! with its [`SessionEndReason`]. A connection whose `Registered` advertised
//! [`rmt_protocol::signaling::SESSION_ENDED_FEATURE`] sends any reason as `SessionEnded`; an older
//! connection can carry only `guest_ended` (as `GuestEndedSession`), so other reasons wait for a
//! capable connection rather than being dropped.
//!
//! Time is supplied by callers so retries can be tested without a runtime or platform APIs.
//! Entries never expire: a delayed acknowledgement must not silently restore automatic recovery.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_protocol::signaling::{GuestEndOutcome, SessionEndReason};
use uuid::Uuid;

/// Bound memory without replacing an existing unacknowledged report.
pub const CAPACITY: usize = 64;
/// Slots non-guest reasons may hold. On an older connection they cannot be delivered and wait;
/// the remainder stays reserved so a guest End is still reported there as it was before docs/49.
pub const NON_GUEST_CAPACITY: usize = 48;
/// A successful socket send is retried if no acknowledgement arrives within this interval.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// The ended-ids fence (docs/49 v3): the last this-many control-plane ids that ended here...
pub const FENCE_CAPACITY: usize = 1024;
/// ...each remembered this long, far beyond any session ticket's two-minute life.
pub const FENCE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

struct Entry {
    reason: SessionEndReason,
    queued_at: Instant,
    next_attempt: Instant,
    attempts: u32,
}

/// One report claimed for sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueReport {
    /// The control-plane session id.
    pub id: Uuid,
    /// Why the session ended.
    pub reason: SessionEndReason,
    /// How long the report has waited since it was queued (docs/49 §4: the audit's queue age).
    pub queue_age: Duration,
}

/// Reports retained across registration connections for one helper lifetime.
pub struct PendingGuestEnds {
    entries: HashMap<Uuid, Entry>,
    cap: usize,
    non_guest_cap: usize,
}

/// Whether the caller's report is retained for acknowledged delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddResult {
    /// A new report is immediately due.
    Queued,
    /// The existing report retains its current reason and retry schedule.
    AlreadyPending,
    /// No existing report was replaced; the caller must log the unqueued report.
    Full,
}

impl Default for PendingGuestEnds {
    fn default() -> Self {
        Self { entries: HashMap::new(), cap: CAPACITY, non_guest_cap: NON_GUEST_CAPACITY }
    }
}

fn backoff(attempts: u32) -> Duration {
    Duration::from_secs((2_u64 << attempts.saturating_sub(1).min(5)).min(60))
}

/// Whether a connection can carry this reason. Only `guest_ended` has a pre-docs/49 message.
fn sendable(reason: SessionEndReason, session_ended_capable: bool) -> bool {
    session_ended_capable || reason == SessionEndReason::GuestEnded
}

impl PendingGuestEnds {
    /// Queue without resetting a duplicate's deadline or reason, or evicting another report.
    pub fn add(&mut self, id: Uuid, reason: SessionEndReason, now: Instant) -> AddResult {
        if self.entries.contains_key(&id) {
            return AddResult::AlreadyPending;
        }
        if self.entries.len() >= self.cap {
            return AddResult::Full;
        }
        if reason != SessionEndReason::GuestEnded
            && self.entries.values().filter(|e| e.reason != SessionEndReason::GuestEnded).count() >= self.non_guest_cap
        {
            return AddResult::Full;
        }
        self.entries.insert(id, Entry { reason, queued_at: now, next_attempt: now, attempts: 0 });
        AddResult::Queued
    }

    /// Claim the due reports this connection can carry before sending, so concurrent callers
    /// cannot send the same attempt. Reports it cannot carry are left untouched, still due.
    pub fn due(&mut self, now: Instant, session_ended_capable: bool) -> Vec<DueReport> {
        self.entries.iter_mut().filter_map(|(id, entry)| {
            if entry.next_attempt > now || !sendable(entry.reason, session_ended_capable) {
                return None;
            }
            entry.next_attempt = now + ACK_TIMEOUT;
            entry.attempts = entry.attempts.saturating_add(1);
            Some(DueReport {
                id: *id,
                reason: entry.reason,
                queue_age: now.saturating_duration_since(entry.queued_at),
            })
        }).collect()
    }

    /// Forget only terminal results; temporary failures retain the report with bounded backoff.
    pub fn on_result(&mut self, id: Uuid, outcome: GuestEndOutcome, now: Instant) {
        match outcome {
            GuestEndOutcome::Ended | GuestEndOutcome::AlreadyEnded | GuestEndOutcome::Refused => {
                self.entries.remove(&id);
            }
            GuestEndOutcome::Unavailable => {
                if let Some(entry) = self.entries.get_mut(&id) {
                    entry.next_attempt = now + backoff(entry.attempts);
                }
            }
        }
    }

    /// Older signaling cannot acknowledge reports; retain them at the maximum retry delay.
    pub fn on_rejected_unsupported(&mut self, now: Instant) {
        for entry in self.entries.values_mut() {
            entry.next_attempt = now + MAX_BACKOFF;
        }
    }

    /// A newly authenticated connection gets another attempt regardless of an old deadline.
    pub fn on_reregistered(&mut self, now: Instant) {
        for entry in self.entries.values_mut() {
            entry.next_attempt = now;
        }
    }

    /// Reports this connection could still deliver (the shutdown drain waits for these only).
    pub fn sendable_len(&self, session_ended_capable: bool) -> usize {
        self.entries.values().filter(|e| sendable(e.reason, session_ended_capable)).count()
    }

    /// Number of reports still awaiting a terminal acknowledgement.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether all retained reports have been acknowledged.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Control-plane session ids that already ended in this process (docs/49 v3 fence). A `Brokered`
/// naming one is refused, so an end report can never close a second lifetime of the same id. The
/// control plane never re-issues a ticket for an id (the v4 invariant); this is defence in depth.
#[derive(Default)]
pub struct EndedFence {
    order: VecDeque<(Uuid, Instant)>,
    ids: HashSet<Uuid>,
}

impl EndedFence {
    fn prune(&mut self, now: Instant) {
        while let Some(&(id, at)) = self.order.front() {
            if now.saturating_duration_since(at) < FENCE_TTL {
                break;
            }
            self.order.pop_front();
            self.ids.remove(&id);
        }
    }

    /// Remember that `id` ended at `now`. A repeat keeps the first time; the oldest entry is
    /// evicted at capacity.
    pub fn insert(&mut self, id: Uuid, now: Instant) {
        self.prune(now);
        if !self.ids.insert(id) {
            return;
        }
        if self.order.len() >= FENCE_CAPACITY {
            if let Some((old, _)) = self.order.pop_front() {
                self.ids.remove(&old);
            }
        }
        self.order.push_back((id, now));
    }

    /// Whether `id` ended here within the fence's window.
    pub fn contains(&mut self, id: Uuid, now: Instant) -> bool {
        self.prune(now);
        self.ids.contains(&id)
    }

    /// Ids currently remembered.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no id is remembered.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Shared ownership lets sessions enqueue while successive mux connections deliver reports.
pub type GuestEndReports = Arc<GuestEndShared>;

/// The lock protects only synchronous state transitions; notification wakes the connection sender.
pub struct GuestEndShared {
    /// Reports survive connection teardown while the helper retains this handle.
    pub pending: Mutex<PendingGuestEnds>,
    /// Ids that ended in this process; consulted by the mux before admitting a `Brokered`.
    pub ended: Mutex<EndedFence>,
    /// Wake the sender immediately after adding a report.
    pub notify: tokio::sync::Notify,
}

impl GuestEndShared {
    /// Create the single handle retained for the helper lifetime.
    pub fn new() -> GuestEndReports {
        Arc::new(Self {
            pending: Mutex::new(PendingGuestEnds::default()),
            ended: Mutex::new(EndedFence::default()),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Record that `id` ended for `reason`: fence it, queue the report, wake the sender. The fence
    /// is written even when the queue is full, so a refused re-attach never depends on capacity.
    pub fn report_end(&self, id: Uuid, reason: SessionEndReason, now: Instant) -> AddResult {
        self.ended.lock().unwrap().insert(id, now);
        let added = self.pending.lock().unwrap().add(id, reason, now);
        self.notify.notify_one();
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: SessionEndReason = SessionEndReason::GuestEnded;

    fn ids(due: Vec<DueReport>) -> Vec<Uuid> {
        due.into_iter().map(|d| d.id).collect()
    }

    #[test]
    fn add_deduplicates_and_enforces_capacity_without_eviction() {
        let now = Instant::now();
        let mut pending = PendingGuestEnds::default();
        let all: Vec<_> = (0..CAPACITY).map(|_| Uuid::new_v4()).collect();
        for id in &all {
            assert_eq!(pending.add(*id, G, now), AddResult::Queued);
        }
        assert_eq!(pending.add(all[0], G, now), AddResult::AlreadyPending);
        assert_eq!(pending.add(Uuid::new_v4(), G, now), AddResult::Full);
        assert_eq!(pending.len(), CAPACITY);
        let due = ids(pending.due(now, false));
        assert_eq!(due.len(), CAPACITY);
        for id in all {
            assert!(due.contains(&id));
        }
    }

    #[test]
    fn lost_ack_is_resent_at_timeout_and_duplicate_does_not_reset_it() {
        let now = Instant::now();
        let id = Uuid::new_v4();
        let mut pending = PendingGuestEnds::default();
        pending.add(id, G, now);
        assert_eq!(ids(pending.due(now, false)), vec![id]);
        assert_eq!(pending.entries[&id].attempts, 1);
        assert_eq!(pending.add(id, SessionEndReason::ViewerLeft, now), AddResult::AlreadyPending);
        assert_eq!(pending.entries[&id].reason, G, "a duplicate must not replace the first reason");
        assert!(pending.due(now + ACK_TIMEOUT - Duration::from_nanos(1), false).is_empty());
        assert_eq!(ids(pending.due(now + ACK_TIMEOUT, false)), vec![id]);
        assert_eq!(pending.entries[&id].attempts, 2);
    }

    #[test]
    fn each_terminal_outcome_removes_and_frees_capacity() {
        let now = Instant::now();
        for outcome in [GuestEndOutcome::Ended, GuestEndOutcome::AlreadyEnded, GuestEndOutcome::Refused] {
            let mut pending = PendingGuestEnds { entries: HashMap::new(), cap: 1, non_guest_cap: 1 };
            let id = Uuid::new_v4();
            pending.add(id, G, now);
            pending.due(now, true);
            pending.on_result(id, outcome, now);
            assert!(pending.is_empty());
            pending.on_result(id, outcome, now);
            assert_eq!(pending.add(Uuid::new_v4(), G, now), AddResult::Queued);
        }
    }

    #[test]
    fn unavailable_backoff_grows_and_stays_capped() {
        let mut now = Instant::now();
        let id = Uuid::new_v4();
        let mut pending = PendingGuestEnds::default();
        pending.add(id, G, now);
        for seconds in [2, 4, 8, 16, 32, 60, 60, 60] {
            assert_eq!(ids(pending.due(now, false)), vec![id]);
            pending.on_result(id, GuestEndOutcome::Unavailable, now);
            let deadline = now + Duration::from_secs(seconds);
            assert_eq!(pending.entries[&id].next_attempt, deadline);
            assert!(pending.due(deadline - Duration::from_nanos(1), false).is_empty());
            now = deadline;
        }
        assert_eq!(backoff(0), Duration::from_secs(2));
        assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn unknown_results_do_not_create_reports() {
        let mut pending = PendingGuestEnds::default();
        pending.on_result(Uuid::new_v4(), GuestEndOutcome::Unavailable, Instant::now());
        assert!(pending.is_empty());
    }

    #[test]
    fn unsupported_retains_every_entry_and_reregistration_makes_them_due() {
        let now = Instant::now();
        let mut pending = PendingGuestEnds::default();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        pending.add(first, G, now);
        pending.due(now, false);
        pending.add(second, G, now);
        pending.on_rejected_unsupported(now);
        assert_eq!(pending.len(), 2);
        assert!(pending.due(now + MAX_BACKOFF - Duration::from_nanos(1), false).is_empty());
        assert_eq!(pending.due(now + MAX_BACKOFF, false).len(), 2);
        pending.on_reregistered(now + MAX_BACKOFF);
        assert_eq!(pending.due(now + MAX_BACKOFF, false).len(), 2);
        // Even a very old report is retained and becomes eligible again.
        assert_eq!(pending.due(now + Duration::from_secs(86_400), false).len(), 2);
    }

    // docs/49: an older connection carries only guest_ended; every other reason stays queued,
    // unclaimed, until a capable connection, and is then sent with its age.
    #[test]
    fn non_guest_reasons_wait_for_a_capable_connection() {
        let now = Instant::now();
        let mut pending = PendingGuestEnds::default();
        let guest = Uuid::new_v4();
        let lapsed = Uuid::new_v4();
        pending.add(guest, G, now);
        pending.add(lapsed, SessionEndReason::LeaseLapsed, now);
        assert_eq!(pending.sendable_len(false), 1);
        assert_eq!(pending.sendable_len(true), 2);
        assert_eq!(ids(pending.due(now, false)), vec![guest]);
        assert_eq!(pending.entries[&lapsed].attempts, 0, "an unsendable report must not be claimed");
        let later = now + Duration::from_millis(1500);
        let due = pending.due(later, true);
        assert_eq!(due, vec![DueReport { id: lapsed, reason: SessionEndReason::LeaseLapsed, queue_age: Duration::from_millis(1500) }]);
    }

    // Codex agent-slice review: on an older connection, non-guest reports cannot drain; they must
    // never take the slots a guest End needs to be reported as it was before docs/49.
    #[test]
    fn undeliverable_non_guest_reports_cannot_starve_guest_reports() {
        let now = Instant::now();
        let mut pending = PendingGuestEnds::default();
        for _ in 0..NON_GUEST_CAPACITY {
            assert_eq!(pending.add(Uuid::new_v4(), SessionEndReason::ViewerLeft, now), AddResult::Queued);
        }
        assert_eq!(pending.add(Uuid::new_v4(), SessionEndReason::Idle, now), AddResult::Full);
        let guests: Vec<_> = (0..CAPACITY - NON_GUEST_CAPACITY).map(|_| Uuid::new_v4()).collect();
        for id in &guests {
            assert_eq!(pending.add(*id, G, now), AddResult::Queued);
        }
        let due = ids(pending.due(now, false));
        assert_eq!(due.len(), guests.len(), "only the guest reports go out on an older connection");
        assert!(guests.iter().all(|g| due.contains(g)));
        assert_eq!(pending.add(Uuid::new_v4(), G, now), AddResult::Full, "the total bound still holds");
    }

    #[test]
    fn fence_remembers_ids_for_its_ttl_and_evicts_the_oldest_at_capacity() {
        let now = Instant::now();
        let mut fence = EndedFence::default();
        let first = Uuid::new_v4();
        fence.insert(first, now);
        assert!(fence.contains(first, now + FENCE_TTL - Duration::from_secs(1)));
        // A repeat does not refresh the first end's time.
        fence.insert(first, now + Duration::from_secs(10));
        assert!(!fence.contains(first, now + FENCE_TTL));
        assert!(fence.is_empty());
        let ids: Vec<_> = (0..=FENCE_CAPACITY).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            fence.insert(*id, now);
        }
        assert_eq!(fence.len(), FENCE_CAPACITY);
        assert!(!fence.contains(ids[0], now), "the oldest id is evicted at capacity");
        assert!(fence.contains(ids[FENCE_CAPACITY], now));
    }

    #[test]
    fn report_end_fences_even_when_the_queue_is_full() {
        let reports = GuestEndShared::new();
        let now = Instant::now();
        reports.pending.lock().unwrap().cap = 0;
        let id = Uuid::new_v4();
        assert_eq!(reports.report_end(id, SessionEndReason::Idle, now), AddResult::Full);
        assert!(reports.ended.lock().unwrap().contains(id, now));
    }

    #[test]
    fn shared_constructor_starts_empty() {
        let reports = GuestEndShared::new();
        assert!(reports.pending.lock().unwrap().is_empty());
        assert!(reports.ended.lock().unwrap().is_empty());
    }
}
