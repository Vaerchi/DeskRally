package controlplane

// Session records — the control-plane data plane for remote-support sessions (the
// `session_record` table in migrations/0001_core.sql). NOT the login session (user_session /
// session.go): a SessionRecord is one technician↔machine remote-support session — who connected
// to what, when, carrying which backstage capabilities.
//
// Follows the repo's interface-plus-fakes pattern (MachineStore, UserStore, …): a
// SessionRecordStore interface, an in-memory fake for tests + DEV mode, and a pgx
// implementation (PgSessionRecordStore, pgstore_dataplane.go) for production.

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrSessionRecordNotFound is returned when a session id does not resolve within the tenant.
var ErrSessionRecordNotFound = errors.New("session record not found")

// ErrConcurrentSessionLimit is returned by StartSessionWithinLimit when the tenant already holds its
// maximum number of OPEN sessions. The handler answers it 409 (a capacity conflict, not a server error).
var ErrConcurrentSessionLimit = errors.New("concurrent session limit reached")

// ErrGroupConcurrentSessionLimit is returned by StartSessionWithinLimit when the target machine's GROUP is
// already at its own per-group cap (docs/01 §5, migrations/0034), independently of the tenant-wide cap. Also
// answered 409, with a message that names the group axis so the operator knows which limit blocked them.
var ErrGroupConcurrentSessionLimit = errors.New("group concurrent session limit reached")

// Observers consume a separate encoder on the guest, even when tenant/group seats are unlimited.
var ErrObserverSessionLimit = errors.New("observer session limit reached for this machine")

// SessionStartLimits are the concurrency caps StartSessionWithinLimit enforces atomically at session start.
// Tenant is the tenant-wide OPEN-session cap (loop 56); Group is the cap for GroupID, the group the session
// is admitted against (loop 78). A cap <= 0 on either axis is unlimited on that axis; both zero is the old
// unconditional insert. Group is only consulted when Group > 0 (GroupID may be empty for a group-less
// session — such a session is simply uncapped by group).
//
// Nested groups (docs/62 R7): GroupCaps lists EVERY ancestor-or-self of the admitted group that has a seat
// cap, and each one is enforced against the live count of ITS OWN SUBTREE (the admitted-group snapshot of
// every open session, mapped through the current ancestry), inside the same per-tenant admission lock — so
// two sibling admissions under a shared capped ancestor cannot both slip under it. A move that puts a
// subtree over a cap ends nothing; new admissions are simply refused until the count is back under. Tree is
// the structure the in-memory store counts through (the pg store reads the live tree itself, in SQL); a nil
// Tree counts exact-group only.
type SessionStartLimits struct {
	Tenant  int
	GroupID string
	Group   int
	// GroupCaps are the per-ancestor caps (nearest first). When empty, a positive Group with a GroupID is
	// treated as the single cap {GroupID, Group}, so a direct caller of the store keeps its old meaning.
	GroupCaps []GroupSeatCap
	Tree      GroupTree
	// Applies only to view_only records, in the SAME atomic admission as seat caps.
	MaxObserversPerMachine int
}

// seatCaps is the set of seat caps this admission must satisfy (see GroupCaps).
func (l SessionStartLimits) seatCaps() []GroupSeatCap {
	if len(l.GroupCaps) > 0 {
		return l.GroupCaps
	}
	if l.Group > 0 && l.GroupID != "" {
		return []GroupSeatCap{{GroupID: l.GroupID, Cap: l.Group}}
	}
	return nil
}

// admissionGroups are the groups a store resolves capped ancestors for: the admitted group the record is
// persisted under (rec.MachineGroupID — what every count reads) and limits.GroupID when it names another.
func admissionGroups(rec *SessionRecord, limits SessionStartLimits) []string {
	var out []string
	if rec != nil && rec.MachineGroupID != "" {
		out = append(out, rec.MachineGroupID)
	}
	if limits.GroupID != "" && (len(out) == 0 || out[0] != limits.GroupID) {
		out = append(out, limits.GroupID)
	}
	return out
}

// mergeSeatCaps unions two cap lists by group id, the smaller cap winning a duplicate; order is a's, then
// b's new entries.
func mergeSeatCaps(a, b []GroupSeatCap) []GroupSeatCap {
	out := make([]GroupSeatCap, 0, len(a)+len(b))
	idx := make(map[string]int, len(a)+len(b))
	for _, list := range [][]GroupSeatCap{a, b} {
		for _, c := range list {
			if c.Cap <= 0 {
				continue
			}
			if i, ok := idx[c.GroupID]; ok {
				if c.Cap < out[i].Cap {
					out[i].Cap = c.Cap
				}
				continue
			}
			idx[c.GroupID] = len(out)
			out = append(out, c)
		}
	}
	return out
}

// SessionRecord is one remote-support session. MachineID is the machine's DATABASE PRIMARY KEY
// (session_record.machine_id foreign-keys machine.id) — the handler resolves the caller-supplied
// device id to the machine row first. The Machine* companion fields are denormalized from the
// machine row (joined on read; populated at insert for the in-memory fake) so the console can
// render a session list without N+1 lookups, and so handlers can group-scope visibility.
type SessionRecord struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	MachineID    string `json:"machine_id"` // machine PRIMARY KEY (machine.id)
	TechnicianID string `json:"technician_id"`
	// SourceIP is the technician's trusted client address when they started the session
	// (session_record.source_ip; sourceip.go). Write-only here: set by handleStartSession from the
	// request, "" (NULL) for sessions not started through an HTTP request. Never read back.
	SourceIP string `json:"-"`
	// Immutable admission mode. A later group-policy change can tighten control, but
	// clearing that mandate must never upgrade a session admitted as an observer.
	Access string `json:"access"`

	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	ConsentPolicy string   `json:"consent_policy"`
	GrantedCaps   []string `json:"granted_caps"` // backstage capabilities the session carried

	// Denormalized machine fields (see type doc). MachineGroupID is what RBAC group-scoping
	// keys off; MachineDeviceID is the stable agent identity the viewer connects to.
	//
	// CAREFUL — MachineGroupID means two different things depending on direction, and the pg store
	// reads and writes DIFFERENT columns for it:
	//
	//   on WRITE (StartSession/StartSessionWithinLimit): the group the session is being ADMITTED
	//     against. It is persisted to session_record.group_id (migration 0034) and is what the
	//     per-group seat count reads. Frozen for the life of the session.
	//   on READ (GetSession/ListSessions/the reports): the machine's LIVE group, resolved by JOINing
	//     `machine` — deliberately, because RBAC scoping and the reports must follow a machine that
	//     has been moved.
	//
	// So for a session whose machine was reassigned mid-session the two DIFFER, and reading this
	// field back after a Get does NOT tell you which group holds the seat. If you need the admitted
	// group, read session_record.group_id directly (see
	// TestPgGroupSeatCountUsesTheAdmittedGroupSnapshotNotTheLiveGroup). The in-memory fake has only
	// one field and so cannot show this divergence — another reason not to reason about seat
	// accounting from the fake alone.
	MachineGroupID  string `json:"machine_group_id"`
	MachineDeviceID string `json:"machine_device_id"`
	MachineName     string `json:"machine_name"`
	// MachineAlias is the tenant-chosen friendly name for the machine (machine.alias, migration
	// 0032). Empty string means no alias has been set; the console falls back to MachineName.
	// Like MachineGroupID, this is JOIN-read from the live machine row by the pg store but is
	// absent from the in-memory fake (which has no machine lookup seam). Fake-based tests that
	// assert alias behaviour will always see "" — use the pg store tests for alias coverage.
	MachineAlias string `json:"machine_alias"`

	// Note is a free-text operator annotation on the session (docs/01 §7) — a handoff/audit note
	// set after the fact via PATCH /sessions/{id}/note. Empty by default (migration 0031 defaults it
	// to ''); persisted on the session_record row itself, not denormalized from anywhere.
	Note string `json:"note"`

	// TransferredFrom is the session this one was handed over from (docs/51; session_record.transferred_from);
	// empty for an ordinary start. EndReason is "transferred" for a session closed by a transfer (empty =
	// ended as before). AgentEndedAt is when the AGENT's authenticated end report (docs/49) first said the
	// session no longer exists on the machine; the first report wins and it never moves.
	TransferredFrom string     `json:"transferred_from,omitempty"`
	EndReason       string     `json:"end_reason,omitempty"`
	AgentEndedAt    *time.Time `json:"agent_ended_at,omitempty"`
}

// MachineSessionCount is one row of the §5 "sessions by machine" activity report: a machine and how
// many remote-support sessions it has had. MachineGroupID is carried so the handler can narrow the
// report to the groups the caller's memberships cover (the same scoping GET /sessions applies).
type MachineSessionCount struct {
	MachineID      string `json:"machine_id"`
	MachineName    string `json:"machine_name"`
	MachineGroupID string `json:"machine_group_id"`
	Count          int64  `json:"count"`
	// TotalSeconds is the machine's total COMPLETED session time, in whole seconds — the sum of
	// (ended_at - started_at) over its ENDED sessions (open sessions contribute nothing). Each session's
	// duration is FLOORED to whole seconds and CLAMPED to >= 0 (a non-positive duration from clock skew
	// contributes 0) BEFORE summing, so the fake and the pg SUM agree exactly regardless of sub-second or
	// skewed timestamps (the "fake and pg must agree" invariant).
	TotalSeconds int64 `json:"total_seconds"`
}

// TechnicianSessionCount is one row of the §5 "sessions by technician" activity report — a technician and
// how many remote-support sessions they ran, plus their total completed session time. This is what the
// HANDLER returns (already narrowed to the caller's viewable groups and aggregated per technician). The
// technician is identified by id; the console resolves it to an email for display (the store cannot, since
// session_record denormalizes no user name — a technician label is a display concern, like a group name).
type TechnicianSessionCount struct {
	TechnicianID string `json:"technician_id"`
	Count        int64  `json:"count"`
	TotalSeconds int64  `json:"total_seconds"`
}

// TechnicianGroupSessionCount is the STORE's finer aggregation for the by-technician report: sessions
// grouped by BOTH technician and the session's machine group. The extra group dimension exists so the
// handler can drop the groups the caller cannot view BEFORE summing per technician — a technician's
// sessions span multiple machine groups, so (unlike the by-machine report, where each row is one group)
// narrowing MUST precede aggregation or a scoped viewer would see cross-group totals. TotalSeconds carries
// the same completed-time semantics as MachineSessionCount (floored, clamped >= 0, for fake/pg agreement).
type TechnicianGroupSessionCount struct {
	TechnicianID   string `json:"technician_id"`
	MachineGroupID string `json:"machine_group_id"`
	Count          int64  `json:"count"`
	TotalSeconds   int64  `json:"total_seconds"`
}

// SessionSummaryFilter narrows a §5 session activity report to a CLOSED [Since, Until] window on the
// session's START time (started_at). A zero Since/Until means "no bound" (so a zero-value filter matches
// EVERY session — the all-time report); an inverted range simply matches nothing. Mirrors AuditFilter's
// since/until so the session and audit reports share the ?since=/?until= parse (parseSinceUntil).
type SessionSummaryFilter struct {
	Since time.Time
	Until time.Time
}

// matches reports whether a session that started at startedAt falls within the filter's [Since, Until]
// window; a zero bound is open on that side.
func (f SessionSummaryFilter) matches(startedAt time.Time) bool {
	if !f.Since.IsZero() && startedAt.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && startedAt.After(f.Until) {
		return false
	}
	return true
}

// SessionRecordStore is the persistence seam for session records. Every method is tenant-scoped
// by the caller-supplied tenantID (and, in pgx, additionally by RLS).
type SessionRecordStore interface {
	// StartSession persists a new session record. The store assigns ID and StartedAt (read
	// back into rec); the caller supplies the machine/technician identities and granted caps.
	StartSession(ctx context.Context, tenantID string, rec *SessionRecord) error
	// StartSessionWithinLimit persists a new session record ONLY if BOTH caps in `limits` have room: the
	// tenant currently holds fewer than limits.Tenant OPEN (ended_at IS NULL) sessions, AND the session's
	// group (limits.GroupID) holds fewer than limits.Group OPEN sessions. A cap <= 0 on an axis is unlimited
	// on that axis. The counts and the insert are ONE atomic step (the pg impl serializes per-tenant with a
	// pg_advisory_xact_lock) so a burst of concurrent starts cannot each observe "under the limit" and all
	// succeed. Returns ErrConcurrentSessionLimit (tenant axis) or ErrGroupConcurrentSessionLimit (group
	// axis) when already at capacity; the tenant axis is checked first.
	StartSessionWithinLimit(ctx context.Context, tenantID string, rec *SessionRecord, limits SessionStartLimits) error
	// ReapExpiredSessions ends (stamps ended_at) every OPEN session in the tenant older than maxAge,
	// returning how many it ended. This is the seat-metering cleanup for abandoned sessions: the agent's
	// own max_session_secs tears down the live stream but never ends the control-plane record, so without
	// this a crashed/closed session would pin a seat against the concurrency cap forever. Tenant-scoped
	// (RLS-pinned in pg); idempotent (an already-ended session is untouched). maxAge <= 0 is a no-op.
	ReapExpiredSessions(ctx context.Context, tenantID string, maxAge time.Duration) (int, error)
	// ReapExpiredGroupSessions ends OPEN sessions for a specific group (by MachineGroupID) that are
	// older than maxAge. This is the group-scoped variant of ReapExpiredSessions used when a group has
	// its own max_session_duration_seconds: only sessions belonging to groupID are affected — sessions
	// in other groups with longer (or no) duration limits are left untouched. maxAge <= 0 is a no-op.
	ReapExpiredGroupSessions(ctx context.Context, tenantID, groupID string, maxAge time.Duration) (int, error)
	// EndSessionsForMachine ends (stamps ended_at) every OPEN session for machineID in the tenant,
	// returning how many it ended. Called immediately after a machine is quarantined or retired so that
	// a live session cannot persist on a machine the operator has taken out of service.
	EndSessionsForMachine(ctx context.Context, tenantID, machineID string) (int, error)
	// GetSession resolves one session by id, or ErrSessionRecordNotFound.
	GetSession(ctx context.Context, tenantID, id string) (*SessionRecord, error)
	// EndSession stamps ended_at on an active session (idempotent: an already-ended session
	// keeps its original end time). Returns the updated record, or ErrSessionRecordNotFound.
	EndSession(ctx context.Context, tenantID, id string, at time.Time) (*SessionRecord, error)
	// SetSessionNote overwrites the session's free-text note (docs/01 §7) and returns the updated
	// record, or ErrSessionRecordNotFound. The caller validates/normalizes the note first.
	SetSessionNote(ctx context.Context, tenantID, id, note string) (*SessionRecord, error)
	// ListSessions returns the tenant's sessions, most recently started first (callers further narrow
	// by group scope). filter narrows to sessions that STARTED within its window (a zero-value filter is
	// all-time), reusing the SessionSummaryFilter the reports use.
	ListSessions(ctx context.Context, tenantID string, filter SessionSummaryFilter) ([]SessionRecord, error)
	// SummarizeByMachine groups the tenant's session records BY MACHINE, returning one row per
	// machine (id + denormalized name + group) with its total session count, ordered most sessions
	// first. This is the §5 "sessions by machine" usage report; the handler further narrows the rows
	// to the groups the caller's memberships cover (like ListSessions). filter narrows to sessions that
	// STARTED within its window (a zero-value filter is all-time). Every matching session counts —
	// open and ended alike.
	SummarizeByMachine(ctx context.Context, tenantID string, filter SessionSummaryFilter) ([]MachineSessionCount, error)
	// SummarizeByTechnician groups the tenant's session records BY (technician, machine group), returning
	// one row per (technician, group) pair with its session count + total completed time. The handler
	// narrows these to the groups the caller can view and then aggregates per technician (narrowing before
	// the sum, because a technician's sessions span groups). filter narrows by session START time (a
	// zero-value filter is all-time). Every matching session counts — open and ended alike.
	SummarizeByTechnician(ctx context.Context, tenantID string, filter SessionSummaryFilter) ([]TechnicianGroupSessionCount, error)
}

// -------------------------------------------------------------------------------------
// InMemorySessionRecordStore — concurrency-safe fake for tests and DEV mode.
// -------------------------------------------------------------------------------------

type InMemorySessionRecordStore struct {
	mu      sync.Mutex
	records map[string]*SessionRecord // key: tenantID + "\x00" + id
	// tree and policies make admission AUTHORITATIVE about seat caps (docs/62 R7, LinkGroupPolicyStores): the
	// capped ancestor-or-self set is resolved from the linked group and policy stores, never from a
	// caller-supplied Tree. Written once at wiring time, before the store is shared. Lock order: the group
	// store's lock FIRST (withTree), then s.mu, then the policy store's lock.
	tree     groupTreeSource
	policies *InMemoryGroupSessionPolicyStore
}

// admitWithCurrentTree runs fn with s.mu held. When linked to a group store, the group lock is taken FIRST
// and held across fn, and fn gets the CURRENT tree; unlinked, tree is nil and fn gets the caller's limits as
// they are.
func (s *InMemorySessionRecordStore) admitWithCurrentTree(tenantID string, fn func(tree GroupTree) error) error {
	if s.tree == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		return fn(nil)
	}
	return s.tree.withTree(tenantID, func(tree GroupTree, _ int64) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return fn(tree)
	})
}

// authoritativeLimits returns limits whose seat caps and tree come from the linked stores' CURRENT state:
// every positive-cap ancestor-or-self of the admitted group (the caller's caps are unioned in, the stricter
// duplicate winning) counted through the current tree. tree == nil (unlinked) returns limits unchanged.
// Caller holds s.mu and the group lock.
func (s *InMemorySessionRecordStore) authoritativeLimits(tenantID string, rec *SessionRecord, limits SessionStartLimits, tree GroupTree) SessionStartLimits {
	if tree == nil {
		return limits
	}
	caps := limits.seatCaps()
	if s.policies != nil {
		var current []GroupSeatCap
		for _, p := range s.policies.snapshot(tenantID) {
			if p.MaxConcurrentSessions <= 0 {
				continue
			}
			for _, g := range admissionGroups(rec, limits) {
				covered := false
				for _, a := range ancestorsOf(tree, g) {
					if a == p.GroupID {
						covered = true
					}
				}
				if covered {
					current = append(current, GroupSeatCap{GroupID: p.GroupID, Cap: p.MaxConcurrentSessions})
					break
				}
			}
		}
		caps = mergeSeatCaps(caps, current)
	}
	limits.GroupCaps = caps
	limits.Tree = tree
	return limits
}

// LinkGroupPolicyStores wires the in-memory session-admission and policy stores to the group store: the
// policy store's SetIfTree checks the tree version under the group lock, and admission resolves capped
// ancestors from the CURRENT tree and policies (the fake's twin of the pg store doing it in SQL under the
// shared tree lock). Either of policies and sessions may be nil.
func LinkGroupPolicyStores(groups *InMemoryMachineGroupStore, policies *InMemoryGroupSessionPolicyStore, sessions *InMemorySessionRecordStore) {
	if policies != nil {
		policies.tree = groups
	}
	if sessions != nil {
		sessions.tree = groups
		sessions.policies = policies
	}
}

// NewInMemorySessionRecordStore constructs an empty in-memory session record store.
func NewInMemorySessionRecordStore() *InMemorySessionRecordStore {
	return &InMemorySessionRecordStore{records: make(map[string]*SessionRecord)}
}

var _ SessionRecordStore = (*InMemorySessionRecordStore)(nil)

func sessionRecordKey(tenantID, id string) string { return tenantID + "\x00" + id }

// StartSession implements SessionRecordStore.
func (s *InMemorySessionRecordStore) StartSession(ctx context.Context, tenantID string, rec *SessionRecord) error {
	// Keep direct store writers subject to the observer resource limit too.
	return s.StartSessionWithinLimit(ctx, tenantID, rec, SessionStartLimits{})
}

// StartSessionWithinLimit implements SessionRecordStore: count-open-and-insert under ONE lock so the
// checks and the insert are atomic (mirrors the pg advisory-locked path). A cap <= 0 on an axis is
// unlimited on that axis. The tenant axis is checked first (matching pg), then the group axis, which counts
// OPEN sessions whose admitted group (rec.MachineGroupID, the snapshot persisted at start) matches
// limits.GroupID — the same start-time-snapshot semantics the pg store counts on session_record.group_id.
func (s *InMemorySessionRecordStore) StartSessionWithinLimit(_ context.Context, tenantID string, rec *SessionRecord, limits SessionStartLimits) error {
	if err := normalizeSessionRecordAccess(rec); err != nil {
		return err
	}
	// Two is a hard resource ceiling; a caller may request a stricter cap, never bypass it.
	if rec.Access == "view_only" && (limits.MaxObserversPerMachine <= 0 || limits.MaxObserversPerMachine > 2) {
		limits.MaxObserversPerMachine = 2
	}
	return s.admitWithCurrentTree(tenantID, func(tree GroupTree) error {
		return s.admitLocked(tenantID, rec, s.authoritativeLimits(tenantID, rec, limits, tree))
	})
}

// admitLocked is the count-and-insert body of StartSessionWithinLimit (the in-memory twin of the pg
// store's admitSessionTx): both POST /sessions and a transfer's finalize admit through it. The caller
// MUST hold s.mu.
func (s *InMemorySessionRecordStore) admitLocked(tenantID string, rec *SessionRecord, limits SessionStartLimits) error {
	if limits.Tenant > 0 {
		active := 0
		for _, r := range s.records {
			if r.TenantID == tenantID && r.EndedAt == nil {
				active++
			}
		}
		if active >= limits.Tenant {
			return ErrConcurrentSessionLimit
		}
	}
	for _, c := range limits.seatCaps() {
		// The cap group's subtree, through the tree the caller handed over; the root itself always counts
		// (a group missing from the tree is the exact-group case).
		members := subtreeOf(limits.Tree, []string{c.GroupID})
		members[c.GroupID] = struct{}{}
		active := 0
		for _, r := range s.records {
			if r.TenantID != tenantID || r.EndedAt != nil {
				continue
			}
			if _, in := members[r.MachineGroupID]; in {
				active++
			}
		}
		if active >= c.Cap {
			return ErrGroupConcurrentSessionLimit
		}
	}
	if rec.Access == "view_only" {
		active := 0
		for _, r := range s.records {
			if r.TenantID == tenantID && r.MachineID == rec.MachineID && r.EndedAt == nil && r.Access == "view_only" {
				active++
			}
		}
		if active >= limits.MaxObserversPerMachine {
			return ErrObserverSessionLimit
		}
	}
	s.insertLocked(tenantID, rec)
	return nil
}

// ReapExpiredSessions implements SessionRecordStore.
func (s *InMemorySessionRecordStore) ReapExpiredSessions(_ context.Context, tenantID string, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-maxAge)
	n := 0
	for _, r := range s.records {
		if r.TenantID == tenantID && r.EndedAt == nil && r.StartedAt.Before(cutoff) {
			end := now
			r.EndedAt = &end
			n++
		}
	}
	return n, nil
}

// ReapExpiredGroupSessions implements SessionRecordStore.
func (s *InMemorySessionRecordStore) ReapExpiredGroupSessions(_ context.Context, tenantID, groupID string, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-maxAge)
	n := 0
	for _, r := range s.records {
		if r.TenantID == tenantID && r.MachineGroupID == groupID && r.EndedAt == nil && r.StartedAt.Before(cutoff) {
			end := now
			r.EndedAt = &end
			n++
		}
	}
	return n, nil
}

// EndSessionsForMachine implements SessionRecordStore.
func (s *InMemorySessionRecordStore) EndSessionsForMachine(_ context.Context, tenantID, machineID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, r := range s.records {
		if r.TenantID == tenantID && r.MachineID == machineID && r.EndedAt == nil {
			end := now
			r.EndedAt = &end
			n++
		}
	}
	return n, nil
}

// insertLocked assigns id/started_at and stores the record. The caller MUST hold s.mu — this is the
// shared body of StartSession and StartSessionWithinLimit so the count and the insert can be atomic.
func (s *InMemorySessionRecordStore) insertLocked(tenantID string, rec *SessionRecord) {
	cp := *rec
	cp.TenantID = tenantID
	cp.SourceIP = validIPText(rec.SourceIP) // the same never-store-a-non-IP rule the inet column enforces
	if cp.ID == "" {
		cp.ID = newUUID()
	}
	if cp.StartedAt.IsZero() {
		cp.StartedAt = time.Now()
	}
	s.records[sessionRecordKey(tenantID, cp.ID)] = &cp
	rec.ID = cp.ID
	rec.TenantID = cp.TenantID
	rec.StartedAt = cp.StartedAt
}

// GetSession implements SessionRecordStore.
func (s *InMemorySessionRecordStore) GetSession(_ context.Context, tenantID, id string) (*SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.records[sessionRecordKey(tenantID, id)]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, ErrSessionRecordNotFound
}

// EndSession implements SessionRecordStore.
func (s *InMemorySessionRecordStore) EndSession(_ context.Context, tenantID, id string, at time.Time) (*SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[sessionRecordKey(tenantID, id)]
	if !ok {
		return nil, ErrSessionRecordNotFound
	}
	if r.EndedAt == nil {
		end := at
		r.EndedAt = &end
	}
	cp := *r
	return &cp, nil
}

// SetSessionNote implements SessionRecordStore.
func (s *InMemorySessionRecordStore) SetSessionNote(_ context.Context, tenantID, id, note string) (*SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[sessionRecordKey(tenantID, id)]
	if !ok {
		return nil, ErrSessionRecordNotFound
	}
	r.Note = note
	cp := *r
	return &cp, nil
}

// ListSessions implements SessionRecordStore: the tenant's sessions within filter, most recent first.
func (s *InMemorySessionRecordStore) ListSessions(_ context.Context, tenantID string, filter SessionSummaryFilter) ([]SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SessionRecord
	for _, r := range s.records {
		if r.TenantID == tenantID && filter.matches(r.StartedAt) {
			if err := appendListRow(&out, *r); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// SummarizeByMachine implements SessionRecordStore: count the tenant's sessions per machine, within filter.
func (s *InMemorySessionRecordStore) SummarizeByMachine(_ context.Context, tenantID string, filter SessionSummaryFilter) ([]MachineSessionCount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byMachine := make(map[string]*MachineSessionCount)
	for _, r := range s.records {
		if r.TenantID != tenantID || !filter.matches(r.StartedAt) {
			continue
		}
		c, ok := byMachine[r.MachineID]
		if !ok {
			c = &MachineSessionCount{MachineID: r.MachineID, MachineName: r.MachineName, MachineGroupID: r.MachineGroupID}
			byMachine[r.MachineID] = c
		}
		c.Count++
		// Completed session time only: an open session (EndedAt nil) contributes nothing, and a
		// NON-POSITIVE duration (ended_at <= started_at — e.g. app/DB clock skew) is CLAMPED to 0. The
		// clamp is load-bearing for fake/pg agreement: Go integer division truncates TOWARD ZERO while pg
		// FLOOR rounds toward -inf, so a negative sub-second duration would otherwise disagree by 1s;
		// clamping both to 0 (and it is nonsense for a session to use negative time) keeps them equal.
		if r.EndedAt != nil {
			if d := r.EndedAt.Sub(r.StartedAt); d > 0 {
				c.TotalSeconds += int64(d / time.Second)
			}
		}
	}
	out := make([]MachineSessionCount, 0, len(byMachine))
	for _, c := range byMachine {
		out = append(out, *c)
	}
	// Most sessions first; ties broken by machine name then id for a stable order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].MachineName != out[j].MachineName {
			return out[i].MachineName < out[j].MachineName
		}
		return out[i].MachineID < out[j].MachineID
	})
	return out, nil
}

// SummarizeByTechnician implements SessionRecordStore: count the tenant's sessions per (technician, group)
// within filter.
func (s *InMemorySessionRecordStore) SummarizeByTechnician(_ context.Context, tenantID string, filter SessionSummaryFilter) ([]TechnicianGroupSessionCount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type key struct{ tech, group string }
	byKey := make(map[key]*TechnicianGroupSessionCount)
	for _, r := range s.records {
		if r.TenantID != tenantID || !filter.matches(r.StartedAt) {
			continue
		}
		k := key{r.TechnicianID, r.MachineGroupID}
		c, ok := byKey[k]
		if !ok {
			c = &TechnicianGroupSessionCount{TechnicianID: r.TechnicianID, MachineGroupID: r.MachineGroupID}
			byKey[k] = c
		}
		c.Count++
		// Same completed-time semantics as SummarizeByMachine: open sessions contribute nothing, and a
		// non-positive (clock-skew) duration is CLAMPED to 0 so Go's truncate-toward-zero matches pg FLOOR.
		if r.EndedAt != nil {
			if d := r.EndedAt.Sub(r.StartedAt); d > 0 {
				c.TotalSeconds += int64(d / time.Second)
			}
		}
	}
	out := make([]TechnicianGroupSessionCount, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, *c)
	}
	// Byte-order (technician, group) so the SET is stable for a direct fake-vs-pg comparison; the handler
	// re-aggregates per technician and re-sorts, so this order is not otherwise load-bearing.
	sort.Slice(out, func(i, j int) bool {
		if out[i].TechnicianID != out[j].TechnicianID {
			return out[i].TechnicianID < out[j].TechnicianID
		}
		return out[i].MachineGroupID < out[j].MachineGroupID
	})
	return out, nil
}

// discardSession deletes one session record outright. Only the help-request FAKE uses it, to roll back an
// admission whose transition failed part-way (a Postgres transaction would simply not have committed it).
func (s *InMemorySessionRecordStore) discardSession(tenantID, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, sessionRecordKey(tenantID, id))
}
