package controlplane

// Per-machine-group session policy (docs/01 §5 seat metering) — the concurrency cap an admin sets on a
// single machine GROUP, enforced at the session-start path ALONGSIDE the tenant-wide cap (loop 56). A group
// with no row (or a 0 cap) is unlimited by group, exactly like an unset tenant policy. Same shape as the
// other tenant-scoped settings stores (TenantSessionPolicyStore, TenantBrandingStore): an interface, an
// in-memory fake for tests + DEV, and a pgx impl (PgGroupSessionPolicyStore) over `group_session_policy`
// (migrations/0034). Normalization lives in NormalizeGroupSessionCap so the fake and pg agree on which
// inputs are accepted (reusing the tenant cap's 0..MaxSessionLimit bound).

import (
	"context"
	"sort"
	"sync"
)

// GroupSessionPolicy is what an admin has decided about one machine GROUP. Two independent settings that
// share a row:
//
//   - MaxConcurrentSessions — the seat cap (0 = unlimited by group; the tenant-wide cap still applies).
//   - EnforceViewOnly — every session on a machine in this group is VIEW-ONLY, enforced by the AGENT via a
//     control-plane-signed session policy the technician cannot decline (loops 79/80, docs/01 §5). Distinct
//     from the technician's own view-only toggle, which they may simply switch off again.
//
// SCOPE OF EnforceViewOnly, because the name promises more than the AGENT alone delivers. At the agent it
// covers exactly what `AccessLevel::ViewOnly` is defined to cover (agent/src/session_policy.rs): injected
// input is dropped and reboot / tool-launch / command-run / lock / log-off / shut-down are refused. It does
// **not** reach BACKSTAGE — the remote shell and the other backstage tools ride a SEPARATE trust axis, a
// control-plane-signed grant gated on CapBackstageShell / CapManageMachines, and nothing on the agent's
// backstage path consults the session's access level.
//
// The two axes exist on purpose and REMAIN separate. An access LEVEL bounds what a live, interactive session
// may do to a desktop somebody may be sitting at; a backstage GRANT is a separately signed, separately
// audited, short-TTL authorization to run tooling, and it confers nothing its holder did not already hold.
// Collapsing them into one flag would also make "watch only, but our unattended patch window still runs"
// inexpressible, which is a real fleet's real requirement.
//
// What was WRONG was the label. An admin ticking "Force view-only" will not infer "except the remote shell",
// so the console said watch-only while a technician holding backstage capability could still run commands as
// SYSTEM on that machine. That is closed at the ISSUING end rather than by merging the axes: handleMintGrant
// (control-plane/http.go) now REFUSES to mint a backstage grant for a machine whose group enforces
// view-only, which is exactly what handleMintElevation (http_elevation.go) already did for an elevation
// grant. Before this the two privilege-issuing endpoints disagreed about the same mandate; now they answer
// the same 409. AllowBackstageUnderViewOnly below is the deliberate, per-group, explicitly-chosen way back
// to the combination — the label is honest BY DEFAULT, and the exception has to be asked for.
//
// Named GroupSessionPolicy, not GroupSessionCap, since loop 80: it is no longer only a cap. (The package
// already has an unrelated SessionPolicy — tenant seat metering — and a SignedSessionPolicy — the signed
// artifact shipped to the agent. See session_policy_mint.go's naming header.)
type GroupSessionPolicy struct {
	GroupID               string `json:"group_id"`
	MaxConcurrentSessions int    `json:"max_concurrent_sessions"`
	EnforceViewOnly       bool   `json:"enforce_view_only"`
	// AllowBackstageUnderViewOnly re-opens backstage on a group that enforces view-only. FALSE — the zero
	// value — means PROTECTED: handleMintGrant refuses to mint a backstage grant for machines in the group,
	// so the console's "view only" label is honest by default. True is the explicit opt-out for deliberate
	// unattended maintenance.
	//
	// WHY THE NAME IS INVERTED, and why this must never be "improved" into a positively-named
	// `RefuseBackstageUnderViewOnly` defaulting to true. Three facts about this type compose into a
	// fleet-wide off switch the moment the safe state is not the zero value:
	//
	//  1. Go's zero value for a bool is false.
	//  2. PUT /machine-groups/{id}/session-policy is a FULL OVERWRITE (see groupSessionPolicyRequest in
	//     http_group_session_policy.go): an omitted field decodes to its zero value and is WRITTEN as such.
	//  3. IsDefault drives row DELETION.
	//
	// With a positively-named, default-true field, every older console build, every operator script and
	// every hand-rolled curl that predates the field would send a body omitting it and thereby DISABLE the
	// protection on whichever group it touched — a security control switched off by a client that never
	// mentioned it, leaving an audit entry that looks like a routine cap edit. With the inverted name that
	// same stale caller writes false, which IS the protected state. Fail-closed by construction rather than
	// by every caller staying current (docs/14 §0.1; docs/25 keeps finding this default-flip family).
	//
	// It has meaning only while EnforceViewOnly is true. Stored true on a group that is not view-only it is
	// simply dormant, and is deliberately preserved rather than normalized away — see
	// NormalizeGroupSessionPolicy for why.
	AllowBackstageUnderViewOnly bool `json:"allow_backstage_under_view_only"`
	// ProhibitRecording bans technicians from starting a session recording on machines in this group. FALSE —
	// the zero value — means recording is NOT prohibited, preserving the current behaviour. TRUE is an admin's
	// explicit decision to bar recordings for this group.
	//
	// WHY THE NAME IS `Prohibit…` AND NOT `Allow…`, by the same reasoning as AllowBackstageUnderViewOnly:
	// the zero value (false) must be the backward-compatible, permissive state. A stale console build or
	// hand-rolled curl that PUTs a body omitting this field writes false, which correctly means "not banned".
	// If the field were named `AllowRecording` and the PUT had to contain `true` to permit recording, then
	// every pre-0043 caller would ban recording on every group it touched — an invisible, audit-silent data
	// loss of capability. Named ProhibitRecording, the zero value is "nothing prohibited"; the restriction is
	// the opt-in. The same three-fact argument as 0040's header applies; see migration 0043.
	//
	// The SIGNED session policy carries the inverse (`allow_recording = !ProhibitRecording`) because the
	// field in the agent's enforced artifact means what it says from the AGENT's perspective: can it start
	// a recording? The minting code handles the flip; this field is the admin's setting, not the wire value.
	ProhibitRecording bool `json:"prohibit_recording"`
	// RequireRecording mandates that every session on a machine in this group is recorded automatically from
	// the first frame, and the technician CANNOT stop the recording mid-session. FALSE — the zero value —
	// means recording is not required (the current default). TRUE is an admin's explicit decision to enforce
	// continuous session recording, e.g. for compliance auditing.
	//
	// WHY THE NAME IS `Require…` AND NOT `Forbid…`: the zero value (false) must be the permissive,
	// backward-compatible state — a stale console or hand-rolled curl that omits this field writes false,
	// meaning "not required", which is the correct safe default. The same three-fact argument applies as
	// AllowBackstageUnderViewOnly and ProhibitRecording (see their comments and migration 0040/0043).
	//
	// CONFLICT: ProhibitRecording = true AND RequireRecording = true is a contradiction — one bans recording,
	// the other mandates it. NormalizeGroupSessionPolicy rejects this combination at PUT time (400). The
	// schema carries no CHECK constraint because the check is cross-field; the application layer is the
	// right place.
	//
	// ENFORCEMENT: when RequireRecording is true the control plane mints `require_recording = true` into the
	// SIGNED session policy. The agent verifies it, auto-starts a recording on policy install, and refuses
	// StopRecording messages for the session's lifetime. The VIEWER detects require_recording in the
	// SessionPolicyInstalled ack and hides the "Stop recording" affordance.
	RequireRecording bool `json:"require_recording"`
	// MaxSessionDurationSeconds caps how long a session on a machine in this group may run. ZERO — the zero
	// value — means unlimited, preserving the current behaviour. A positive value is the maximum session
	// lifetime in SECONDS from the moment the agent begins serving the connection; the agent ends the session
	// when the wall-clock limit expires.
	//
	// WHY ZERO = UNLIMITED: the zero value must be the backward-compatible, permissive state — a stale console
	// build or hand-rolled curl that omits this field writes 0, meaning "no limit", which is the safe default.
	// The same three-fact argument as AllowBackstageUnderViewOnly applies (see that field's comment).
	//
	// SIGNED PREIMAGE: max_session_duration_seconds is in the SIGNED session policy preimage (appended as
	// u32be after require_recording) so the viewer cannot tamper it after signing. The agent reads and
	// enforces it from the verified policy body.
	//
	// APPLICATION-LAYER VALIDATION: NormalizeGroupSessionPolicy clamps to 0..MaxSessionDurationSeconds (0 =
	// unlimited, max = 86400 s = 24 h). The schema carries no CHECK constraint — the upper bound is a product
	// decision that will move, and the application layer is the right place for it.
	MaxSessionDurationSeconds int `json:"max_session_duration_seconds"`
	// MaxIdleSeconds is the maximum number of seconds a session may run without the controller sending any
	// keyboard or mouse input before the agent ends it automatically. ZERO — the zero value — means no idle
	// timeout, preserving the current behaviour. A positive value causes the agent to end the session once
	// no Input channel frames have been received for this many consecutive seconds.
	//
	// WHY ZERO = UNLIMITED: same three-fact argument as AllowBackstageUnderViewOnly — the zero value must be
	// the backward-compatible, permissive state so a stale console or hand-rolled curl that omits this field
	// writes 0, meaning "no idle timeout", which is the safe default.
	//
	// SIGNED PREIMAGE: max_idle_seconds is in the SIGNED session policy preimage (appended as u32be after
	// max_session_duration_seconds) so the viewer cannot tamper it after signing. The agent tracks the last
	// input timestamp and enforces the limit at each lease tick.
	//
	// APPLICATION-LAYER VALIDATION: NormalizeGroupSessionPolicy clamps to 0..MaxGroupIdleSeconds (0 =
	// unlimited, max = 3600 s = 1 h). The schema carries no CHECK constraint — the upper bound is a product
	// decision that may change without a migration.
	MaxIdleSeconds int `json:"max_idle_seconds"`
}

// IsDefault reports whether this policy says nothing at all — no cap, no view-only mandate, and no backstage
// opt-out. Such a row carries no information, so Set DELETES it rather than storing it; List then means "the
// groups an admin has actually decided something about".
//
// This replaced a plain `cap == 0` delete test in loop 80, and the distinction is load-bearing: under the old
// rule, clearing a group's CAP would also have silently dropped its VIEW-ONLY mandate, quietly handing
// control of those machines back to every technician. A row must survive while ANY setting is non-default.
//
// EVERY setting added to the struct must be added HERE too — migration 0035 wrote that warning down and 0040
// repeats it, because this is the second time the list has had to grow. Omitting AllowBackstageUnderViewOnly
// would mean a group whose only stored decision is the backstage opt-out gets its row deleted on write and
// reads back as the default, so the console's checkbox would silently untick itself after a save. That
// direction happens to fail SAFE (the group ends up protected again), which is exactly what makes it
// insidious: a settings-loss bug that sets off nobody's alarm, and the NEXT setting added under the same
// omission may not fail safe at all.
func (p GroupSessionPolicy) IsDefault() bool {
	return p.MaxConcurrentSessions == 0 && !p.EnforceViewOnly && !p.AllowBackstageUnderViewOnly && !p.ProhibitRecording && !p.RequireRecording && p.MaxSessionDurationSeconds == 0 && p.MaxIdleSeconds == 0
}

// AllowRecording returns the inverse of ProhibitRecording — the value the signed session policy carries
// in its `allow_recording` field. This is the single inversion point: the DB stores the admin's restriction
// (zero=safe default), the agent wire carries the affirmative (what the session may do). Callers that need
// the wire value use this instead of spelling out `!p.ProhibitRecording` at each of the three mint sites,
// so a future rename or logic change has one place to update.
func (p GroupSessionPolicy) AllowRecording() bool { return !p.ProhibitRecording }

// MaxGroupSessionDurationSeconds is the upper bound on MaxSessionDurationSeconds: 86400 s = 24 hours.
// Zero remains "unlimited". Values above this cap are rejected by NormalizeGroupSessionPolicy.
const MaxGroupSessionDurationSeconds = 86400

// MaxGroupIdleSeconds is the upper bound on MaxIdleSeconds: 3600 s = 1 hour.
// Zero remains "no idle timeout". Values above this cap are rejected by NormalizeGroupSessionPolicy.
const MaxGroupIdleSeconds = 3600

// NormalizeGroupSessionCap clamps a requested per-group cap into the accepted range and reports whether the
// INPUT was already valid — identical semantics to NormalizeSessionPolicy's MaxConcurrentSessions branch
// (0 = unlimited; a negative or absurd value is a client bug, rejected rather than silently accepted). The
// clamped value is returned regardless so a caller that ignores ok still gets a safe value.
func NormalizeGroupSessionCap(cap int) (int, bool) {
	switch {
	case cap < 0:
		return 0, false
	case cap > MaxSessionLimit:
		return MaxSessionLimit, false
	default:
		return cap, true
	}
}

// NormalizeGroupSessionDuration clamps a requested per-group duration limit and reports whether the INPUT
// was already valid (0 = unlimited; negative = client bug rejected; above 86400 s = rejected). The clamped
// value is returned regardless so a caller that ignores ok still gets a safe value.
func NormalizeGroupSessionDuration(dur int) (int, bool) {
	switch {
	case dur < 0:
		return 0, false
	case dur > MaxGroupSessionDurationSeconds:
		return MaxGroupSessionDurationSeconds, false
	default:
		return dur, true
	}
}

// NormalizeGroupIdleSeconds clamps a requested per-group idle timeout and reports whether the INPUT was
// already valid (0 = unlimited; negative = client bug rejected; above 3600 s = rejected). The clamped
// value is returned regardless so a caller that ignores ok still gets a safe value.
func NormalizeGroupIdleSeconds(idle int) (int, bool) {
	switch {
	case idle < 0:
		return 0, false
	case idle > MaxGroupIdleSeconds:
		return MaxGroupIdleSeconds, false
	default:
		return idle, true
	}
}

// NormalizeGroupSessionPolicy clamps a requested policy and reports whether the INPUT was already valid.
// Only the cap has a range to police; the boolean fields cannot be out of range individually. The conflict
// check — ProhibitRecording && RequireRecording — is the one cross-field invariant and is detected here.
// Wrapping them in ONE function means a new setting has exactly one place to be validated, and a caller
// cannot validate the cap while forgetting the rest. This comment used to promise that for "a future third
// setting"; AllowBackstageUnderViewOnly was that setting, and RequireRecording is the next.
//
// It deliberately does NOT clear AllowBackstageUnderViewOnly when EnforceViewOnly is false, even though the
// pair is inert in that state. Two reasons. Storing what the admin actually ticked keeps the console honest —
// a checkbox that unticks itself on save is the same class of lie as rendering an unread value as a safe one.
// And an admin composing a policy in the order "opt-out first, mandate second" would otherwise lose half
// their edit to click order. The inert combination is safe by definition: nothing reads
// AllowBackstageUnderViewOnly except the refusal in handleMintGrant, and that read happens only inside the
// EnforceViewOnly branch.
//
// Similarly, RequireRecording is stored regardless of ProhibitRecording's value — but that particular
// combination IS an error and is reported as invalid rather than silently coerced.
//
// Cross-field invariant (mirroring the tenant-level SessionPolicy): when MaxConcurrentSessions > 0 (a seat
// cap is active), MaxSessionDurationSeconds must also be > 0. The reaper that reclaims leaked seats at session
// start uses this field as its threshold — leaked rows older than the group's duration limit are safely
// reaped (the agent should have ended them). Without a stated duration, leaked seats cannot be reclaimed
// automatically and the cap will be starved indefinitely. The tenant-level API enforces the equivalent
// constraint (handleSetSessionPolicy rejects {max_concurrent > 0, max_session_seconds: 0}); this function
// now matches it for the group level.
func NormalizeGroupSessionPolicy(p GroupSessionPolicy) (GroupSessionPolicy, bool) {
	cap, ok := NormalizeGroupSessionCap(p.MaxConcurrentSessions)
	p.MaxConcurrentSessions = cap
	dur, durOK := NormalizeGroupSessionDuration(p.MaxSessionDurationSeconds)
	p.MaxSessionDurationSeconds = dur
	if !durOK {
		ok = false
	}
	idle, idleOK := NormalizeGroupIdleSeconds(p.MaxIdleSeconds)
	p.MaxIdleSeconds = idle
	if !idleOK {
		ok = false
	}
	if p.ProhibitRecording && p.RequireRecording {
		// Contradictory: one bans recording, the other mandates it.
		return p, false
	}
	if p.MaxConcurrentSessions > 0 && p.MaxSessionDurationSeconds <= 0 {
		// Seat cap without a duration: leaked rows would accumulate against the cap indefinitely.
		return p, false
	}
	return p, ok
}

// GroupSessionPolicyStore is the persistence seam for per-group session caps. Production wires
// PgGroupSessionPolicyStore (RLS-scoped via withTenant); tests + DEV wire the in-memory fake.
type GroupSessionPolicyStore interface {
	// Get returns the group's policy, or the zero policy (unlimited, not view-only) when no row is set.
	Get(ctx context.Context, tenantID, groupID string) (GroupSessionPolicy, error)
	// Set upserts the group's policy (one row per (tenant, group)). A policy that IsDefault DELETES the row.
	// The caller normalizes/validates first.
	Set(ctx context.Context, tenantID, groupID string, policy GroupSessionPolicy) error
	// SetIfTree is Set conditional on the tenant's group tree still being at expectTree (docs/62 R2): who may
	// edit a group's policy depends on the tree, so a reparent between the grant read and this write refuses
	// it with ErrGroupTreeChanged instead of letting a former manager write. The pg store holds the shared
	// tree lock to the end of its transaction; the fake holds the group lock across check and write.
	SetIfTree(ctx context.Context, tenantID, groupID string, policy GroupSessionPolicy, expectTree int64) error
	// List returns every group in the tenant that has a policy row, ordered by group id, for the console.
	// Groups with no row (an all-default policy) are simply absent.
	List(ctx context.Context, tenantID string) ([]GroupSessionPolicy, error)
	// DeleteForGroup removes any cap row for a group that is being DELETED. Deleting a group that is
	// absent or uncapped is not an error.
	//
	// This exists to keep the fake and pg on ONE contract. Postgres drops the row by itself via the
	// composite FK's ON DELETE CASCADE (migration 0034); the in-memory store has no such mechanism, so
	// without an explicit call it would keep the cap of a group that no longer exists and List would
	// return an orphan the pg store never returns. A test written against the fake would then "prove"
	// behaviour pg does not have -- this package's most-repeated defect. The handler calls this AFTER a
	// successful group delete, so a refused delete (409: the group still has machines) leaves the cap
	// intact.
	DeleteForGroup(ctx context.Context, tenantID, groupID string) error
}

// -------------------------------------------------------------------------------------
// InMemoryGroupSessionPolicyStore — concurrency-safe fake. A (tenantID, groupID) -> cap map; an absent
// entry is 0 (unlimited by group), exactly what the pg store returns for no row.
// -------------------------------------------------------------------------------------

type InMemoryGroupSessionPolicyStore struct {
	mu   sync.Mutex
	caps map[string]map[string]GroupSessionPolicy // tenantID -> groupID -> policy
	// tree lets SetIfTree know the group tree version (LinkGroupPolicyStores). Written once at wiring time,
	// before the store is shared; nil = SetIfTree writes unconditionally.
	tree groupTreeSource
}

// NewInMemoryGroupSessionPolicyStore constructs an empty in-memory group-session-policy store.
func NewInMemoryGroupSessionPolicyStore() *InMemoryGroupSessionPolicyStore {
	return &InMemoryGroupSessionPolicyStore{caps: make(map[string]map[string]GroupSessionPolicy)}
}

var _ GroupSessionPolicyStore = (*InMemoryGroupSessionPolicyStore)(nil)

// Get implements GroupSessionPolicyStore: the stored policy, or the zero policy when unset. GroupID is
// filled in either way, so a caller can pass the result straight back to a handler response.
func (s *InMemoryGroupSessionPolicyStore) Get(_ context.Context, tenantID, groupID string) (GroupSessionPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.caps[tenantID][groupID]
	p.GroupID = groupID
	return p, nil
}

// Set implements GroupSessionPolicyStore: overwrite the group's policy. An all-default policy DELETES the
// row so List reflects only decided groups (matching the pg store).
func (s *InMemoryGroupSessionPolicyStore) Set(_ context.Context, tenantID, groupID string, policy GroupSessionPolicy) error {
	return s.set(tenantID, groupID, policy)
}

// SetIfTree implements GroupSessionPolicyStore: with a linked group store the group lock is held across the
// version check and the write (group before policy), exactly the pg shared-lock protocol.
func (s *InMemoryGroupSessionPolicyStore) SetIfTree(_ context.Context, tenantID, groupID string, policy GroupSessionPolicy, expectTree int64) error {
	if s.tree == nil {
		return s.set(tenantID, groupID, policy)
	}
	return s.tree.withTree(tenantID, func(_ GroupTree, version int64) error {
		if version != expectTree {
			return ErrGroupTreeChanged
		}
		return s.set(tenantID, groupID, policy)
	})
}

func (s *InMemoryGroupSessionPolicyStore) set(tenantID, groupID string, policy GroupSessionPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy.IsDefault() {
		if m := s.caps[tenantID]; m != nil {
			delete(m, groupID)
		}
		return nil
	}
	m := s.caps[tenantID]
	if m == nil {
		m = make(map[string]GroupSessionPolicy)
		s.caps[tenantID] = m
	}
	policy.GroupID = groupID
	m[groupID] = policy
	return nil
}

// snapshot returns a copy of the tenant's policy rows (for in-process readers that must not call back
// through the interface while holding another store's lock).
func (s *InMemoryGroupSessionPolicyStore) snapshot(tenantID string) []GroupSessionPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]GroupSessionPolicy, 0, len(s.caps[tenantID]))
	for gid, p := range s.caps[tenantID] {
		p.GroupID = gid
		out = append(out, p)
	}
	return out
}

// List implements GroupSessionPolicyStore: every capped group in the tenant, ordered by group id.
func (s *InMemoryGroupSessionPolicyStore) List(_ context.Context, tenantID string) ([]GroupSessionPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]GroupSessionPolicy, 0, len(s.caps[tenantID]))
	for gid, p := range s.caps[tenantID] {
		p.GroupID = gid
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GroupID < out[j].GroupID })
	return out, nil
}

// DeleteForGroup implements GroupSessionPolicyStore: drop the group's cap row, mirroring the pg store's
// ON DELETE CASCADE. Absent tenant or group is a no-op, matching a cascade that finds nothing to drop.
func (s *InMemoryGroupSessionPolicyStore) DeleteForGroup(_ context.Context, tenantID, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.caps[tenantID]; m != nil {
		delete(m, groupID)
	}
	return nil
}
