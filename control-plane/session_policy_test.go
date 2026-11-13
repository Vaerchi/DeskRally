package controlplane

// Proofs for §5 seat metering (per-tenant concurrent-session limits): normalization, the in-memory
// policy store, the fake's atomic StartSessionWithinLimit, and the HTTP surface — enforcement at
// POST /sessions plus GET/PUT /tenant/session-policy (CapManageTenant).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeSessionPolicy(t *testing.T) {
	for _, tc := range []struct {
		in       int
		wantOK   bool
		wantNorm int
	}{
		{0, true, 0},                             // unlimited
		{1, true, 1},                             // the smallest real cap
		{MaxSessionLimit, true, MaxSessionLimit}, // the ceiling is accepted
		{-1, false, 0},                           // negative is a client bug, not "unlimited"
		{MaxSessionLimit + 1, false, MaxSessionLimit}, // above the ceiling is rejected, clamped
	} {
		got, ok := NormalizeSessionPolicy(SessionPolicy{MaxConcurrentSessions: tc.in})
		if ok != tc.wantOK || got.MaxConcurrentSessions != tc.wantNorm {
			t.Fatalf("Normalize(concurrency=%d) = (%+v, %v), want (%d, %v)", tc.in, got, ok, tc.wantNorm, tc.wantOK)
		}
	}
	// max_session_seconds: 0 (no maximum) and [MinSessionSeconds, MaxSessionSecondsCeiling] are valid;
	// a negative, a too-short (0 < s < 60), or a too-large value is rejected.
	for _, tc := range []struct {
		in       int
		wantOK   bool
		wantNorm int
	}{
		{0, true, 0},
		{MinSessionSeconds, true, MinSessionSeconds},
		{MaxSessionSecondsCeiling, true, MaxSessionSecondsCeiling},
		{-1, false, 0},
		{MinSessionSeconds - 1, false, 0}, // too short → rejected, not clamped up
		{MaxSessionSecondsCeiling + 1, false, MaxSessionSecondsCeiling},
	} {
		got, ok := NormalizeSessionPolicy(SessionPolicy{MaxSessionSeconds: tc.in})
		if ok != tc.wantOK || got.MaxSessionSeconds != tc.wantNorm {
			t.Fatalf("Normalize(maxAge=%d) = (%+v, %v), want (%d, %v)", tc.in, got, ok, tc.wantNorm, tc.wantOK)
		}
	}
}

func TestReapExpiredSessionsFake(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	// One OLD open session, one RECENT open session, one already-ENDED old session — all in t1.
	oldOpen := &SessionRecord{MachineID: "m-old", TechnicianID: "u1", StartedAt: time.Now().Add(-2 * time.Hour)}
	recent := &SessionRecord{MachineID: "m-new", TechnicianID: "u1"}
	endedOld := &SessionRecord{MachineID: "m-done", TechnicianID: "u1", StartedAt: time.Now().Add(-3 * time.Hour)}
	for _, r := range []*SessionRecord{oldOpen, recent, endedOld} {
		if err := s.StartSession(ctx, "t1", r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if _, err := s.EndSession(ctx, "t1", endedOld.ID, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("pre-end: %v", err)
	}
	// Another tenant's OLD open session must NOT be reaped by t1's call.
	other := &SessionRecord{MachineID: "m-other", StartedAt: time.Now().Add(-5 * time.Hour)}
	if err := s.StartSession(ctx, "t2", other); err != nil {
		t.Fatalf("seed t2: %v", err)
	}

	// maxAge <= 0 is a no-op.
	if n, _ := s.ReapExpiredSessions(ctx, "t1", 0); n != 0 {
		t.Fatalf("reap(0) = %d, want 0 (no-op)", n)
	}
	// 1h max age: only oldOpen (2h) is reaped — recent is young, endedOld already ended.
	n, err := s.ReapExpiredSessions(ctx, "t1", time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("reap(1h) = (%d, %v), want 1", n, err)
	}
	if got, _ := s.GetSession(ctx, "t1", oldOpen.ID); got.EndedAt == nil {
		t.Fatalf("old open session was not ended")
	}
	if got, _ := s.GetSession(ctx, "t1", recent.ID); got.EndedAt != nil {
		t.Fatalf("recent session was wrongly reaped")
	}
	// Idempotent: a second reap ends nothing (oldOpen is already ended).
	if n2, _ := s.ReapExpiredSessions(ctx, "t1", time.Hour); n2 != 0 {
		t.Fatalf("second reap = %d, want 0 (idempotent)", n2)
	}
	// Tenant isolation: t2's old session is untouched by t1's reap.
	if got, _ := s.GetSession(ctx, "t2", other.ID); got.EndedAt != nil {
		t.Fatalf("another tenant's session was reaped")
	}
}

func TestHandleStartSessionReapsBeforeLimit(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	ctx := context.Background()
	start := func(srv *Server) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"machine_id":"dev-1"}`)))
		return rec
	}

	// With a max age set, an OLD open session that filled the only seat is reaped first → the new start
	// succeeds, and the old session is now ended.
	srv, _ := newTestServer(owner)
	old := &SessionRecord{MachineID: "m-old", TechnicianID: "u1", StartedAt: time.Now().Add(-2 * time.Hour)}
	if err := srv.SessionRecords.StartSession(ctx, "tenant-123", old); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if err := srv.SessionPolicies.Set(ctx, "tenant-123", SessionPolicy{MaxConcurrentSessions: 1, MaxSessionSeconds: 3600}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	if rec := start(srv); rec.Code != http.StatusCreated {
		t.Fatalf("start with reap = %d, want 201 (the 2h-old session should be reaped): %s", rec.Code, rec.Body.String())
	}
	if got, _ := srv.SessionRecords.GetSession(ctx, "tenant-123", old.ID); got.EndedAt == nil {
		t.Fatalf("the expired session was not reaped")
	}

	// CONTROL: same old session, cap 1, but NO max age → it is NOT reaped and still holds the seat → 409.
	srv2, _ := newTestServer(owner)
	old2 := &SessionRecord{MachineID: "m-old", TechnicianID: "u1", StartedAt: time.Now().Add(-2 * time.Hour)}
	if err := srv2.SessionRecords.StartSession(ctx, "tenant-123", old2); err != nil {
		t.Fatalf("seed old2: %v", err)
	}
	if err := srv2.SessionPolicies.Set(ctx, "tenant-123", SessionPolicy{MaxConcurrentSessions: 1, MaxSessionSeconds: 0}); err != nil {
		t.Fatalf("set policy 2: %v", err)
	}
	if rec := start(srv2); rec.Code != http.StatusConflict {
		t.Fatalf("start without max age = %d, want 409 (no reap, seat still held)", rec.Code)
	}
}

func TestInMemoryTenantSessionPolicy(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryTenantSessionPolicyStore()
	// Unset → the zero policy (unlimited).
	if p, err := s.Get(ctx, "t1"); err != nil || p.MaxConcurrentSessions != 0 {
		t.Fatalf("unset = (%+v, %v), want 0", p, err)
	}
	if err := s.Set(ctx, "t1", SessionPolicy{MaxConcurrentSessions: 3}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if p, _ := s.Get(ctx, "t1"); p.MaxConcurrentSessions != 3 {
		t.Fatalf("after set = %+v, want 3", p)
	}
	// Another tenant is unaffected (the fake mirrors the pg row-per-tenant isolation).
	if p, _ := s.Get(ctx, "t2"); p.MaxConcurrentSessions != 0 {
		t.Fatalf("t2 = %+v, want 0", p)
	}
}

func TestStartSessionWithinLimitFake(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	start := func(limit int) error {
		return s.StartSessionWithinLimit(ctx, "t1", &SessionRecord{MachineID: "m1", TechnicianID: "u1"}, SessionStartLimits{Tenant: limit})
	}
	// limit 2: two open sessions are allowed, the third is refused.
	if err := start(2); err != nil {
		t.Fatalf("1st (limit 2): %v", err)
	}
	if err := start(2); err != nil {
		t.Fatalf("2nd (limit 2): %v", err)
	}
	if err := start(2); err != ErrConcurrentSessionLimit {
		t.Fatalf("3rd (limit 2) = %v, want ErrConcurrentSessionLimit", err)
	}
	// Only OPEN sessions count: end one and a start is allowed again.
	list, _ := s.ListSessions(ctx, "t1", SessionSummaryFilter{})
	if _, err := s.EndSession(ctx, "t1", list[0].ID, list[0].StartedAt); err != nil {
		t.Fatalf("end: %v", err)
	}
	if err := start(2); err != nil {
		t.Fatalf("after ending one (limit 2): %v", err)
	}
	// limit 0 = unlimited: a start always succeeds even with three already open.
	if err := start(0); err != nil {
		t.Fatalf("limit 0 (unlimited): %v", err)
	}
	// Another tenant's open sessions do NOT count against t1's cap (and vice versa).
	if err := s.StartSessionWithinLimit(ctx, "t2", &SessionRecord{MachineID: "m9"}, SessionStartLimits{Tenant: 1}); err != nil {
		t.Fatalf("t2 first (limit 1): %v", err)
	}
}

func TestHandleStartSessionEnforcesLimit(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	if err := srv.SessionPolicies.Set(ctx, "tenant-123", SessionPolicy{MaxConcurrentSessions: 1}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	h := srv.Handler()
	start := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"machine_id":"dev-1"}`)))
		return rec
	}
	// First session: allowed.
	first := start()
	if first.Code != http.StatusCreated {
		t.Fatalf("1st start = %d, want 201: %s", first.Code, first.Body.String())
	}
	var started struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Second concurrent session: at capacity → 409.
	if rec := start(); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "concurrent session limit") {
		t.Fatalf("2nd start = %d body %q, want 409 concurrent session limit", rec.Code, rec.Body.String())
	}
	// End the first, and a new session is allowed again — the cap is on OPEN sessions, not lifetime.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions/"+started.Session.ID+"/end", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("end = %d: %s", rec.Code, rec.Body.String())
	}
	if again := start(); again.Code != http.StatusCreated {
		t.Fatalf("start after end = %d, want 201: %s", again.Code, again.Body.String())
	}
}

// mustEnrollMachine enrolls "dev-1" (no restrictions) in srv.
// Pass4 note: the old mustEnrollDurationPolicyMachine enrolled with RequireSessionPolicy=true
// to pass the Pass3 gate. Pass4 gates unconditionally, so sessions into groups with new
// restrictions cannot start. Reaper tests now call the store function directly.
func mustEnrollMachine(t *testing.T, ctx context.Context, srv *Server) {
	t.Helper()
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", &Machine{
		DeviceID: "dev-1",
		Name:     "test-machine",
		GroupID:  DevDefaultMachineGroupID,
		Status:   MachineStatusActive,
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
}

// TestGroupDurationReaperStoreLevel proves the group-cap reaper correctly clears sessions older
// than the group's max_session_duration_seconds while leaving younger sessions intact.
//
// Pass4 note: the old test went through POST /sessions (HTTP) but the unconditional gate now refuses
// sessions in groups with max_session_duration_seconds > 0. The reaper is tested at the STORE level
// directly: the same InMemorySessionRecordStore.ReapExpiredGroupSessions logic the HTTP handler calls.
// The HTTP path is no longer testable while the gate is active; it will be re-enabled when agent
// capability negotiation ships.
func TestGroupDurationReaperStoreLevel(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySessionRecordStore()
	const groupDuration = time.Hour

	// MAIN: session 90 min old (> 1h) must be reaped.
	leaked := &SessionRecord{
		MachineID:      "dev-1",
		MachineGroupID: DevDefaultMachineGroupID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(groupDuration + 30*time.Minute)),
	}
	if err := store.StartSession(ctx, "tenant-123", leaked); err != nil {
		t.Fatalf("seed leaked: %v", err)
	}
	reaped, err := store.ReapExpiredGroupSessions(ctx, "tenant-123", DevDefaultMachineGroupID, groupDuration)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("expected 1 reaped (90-min session with 1h limit), got %d", reaped)
	}
	if got, _ := store.GetSession(ctx, "tenant-123", leaked.ID); got.EndedAt == nil {
		t.Fatalf("leaked session was not stamped ended by the reaper")
	}

	// CONTROL M1 (duration boundary): session 30 min old (< 1h) must NOT be reaped.
	// Mutation: removing the age comparison would reap this session incorrectly.
	store2 := NewInMemorySessionRecordStore()
	young := &SessionRecord{
		MachineID:      "dev-1",
		MachineGroupID: DevDefaultMachineGroupID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(groupDuration / 2)), // 30 min ago
	}
	if err := store2.StartSession(ctx, "tenant-123", young); err != nil {
		t.Fatalf("seed young: %v", err)
	}
	reaped2, err := store2.ReapExpiredGroupSessions(ctx, "tenant-123", DevDefaultMachineGroupID, groupDuration)
	if err != nil {
		t.Fatalf("reap2: %v", err)
	}
	if reaped2 != 0 {
		t.Fatalf("expected 0 reaped (30-min session within 1h limit), got %d", reaped2)
	}
	if got, _ := store2.GetSession(ctx, "tenant-123", young.ID); got.EndedAt != nil {
		t.Fatalf("young session was wrongly reaped (it is within the stated duration)")
	}

	// CONTROL M2 (group scoping): a session in a DIFFERENT group is never reaped by a different
	// group's reaper call. Mutation: replacing ReapExpiredGroupSessions with a tenant-wide call
	// would reap this session from another group.
	store3 := NewInMemorySessionRecordStore()
	const otherGroup = "other-group-id"
	otherSession := &SessionRecord{
		MachineID:      "dev-2",
		MachineGroupID: otherGroup,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(groupDuration + 30*time.Minute)), // 90 min — old enough
	}
	if err := store3.StartSession(ctx, "tenant-123", otherSession); err != nil {
		t.Fatalf("seed other: %v", err)
	}
	reaped3, err := store3.ReapExpiredGroupSessions(ctx, "tenant-123", DevDefaultMachineGroupID, groupDuration)
	if err != nil {
		t.Fatalf("reap3: %v", err)
	}
	if reaped3 != 0 {
		t.Fatalf("expected 0 reaped (session in different group), got %d — cross-group scope violation", reaped3)
	}
	if got, _ := store3.GetSession(ctx, "tenant-123", otherSession.ID); got.EndedAt != nil {
		t.Fatalf("session in other group was wrongly reaped by a different group's reaper call")
	}
}

// TestHandleStartSessionGroupCapReapsByDuration verifies that the HTTP session start handler
// integrates the group-duration reaper correctly for cases that DO NOT use max_session_duration_seconds
// as a restriction — specifically, the cap-guard (limits.Group == 0) check and the legacy
// (cap>0, duration=0) no-fallback-reap invariant.
//
// Pass4: cases requiring max_session_duration_seconds > 0 in the group policy are tested at the
// store level (TestGroupDurationReaperStoreLevel) because the unconditional admission gate refuses
// sessions in those groups. This test covers the two remaining HTTP-testable invariants.
func TestHandleStartSessionGroupCapReapsByDuration(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	ctx := context.Background()
	start := func(srv *Server) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
			strings.NewReader(`{"machine_id":"dev-1"}`)))
		return rec
	}
	const groupDuration = time.Hour

	// CONTROL M2 (cap-guard removed): cap=0 (unlimited), session 90 min old.
	// The reaper must NOT fire when no group cap is armed.
	// If the group-duration guard is removed (limits.Group > 0 check), the reaper fires and
	// ends a valid old session in an uncapped group — the test catches that by asserting the
	// old session remains open after the new start.
	srv3, _ := newTestServer(owner)
	mustEnrollMachine(t, ctx, srv3)
	uncapped := &SessionRecord{
		MachineID:      "dev-1",
		MachineGroupID: DevDefaultMachineGroupID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(groupDuration + 30*time.Minute)),
	}
	if err := srv3.SessionRecords.StartSession(ctx, "tenant-123", uncapped); err != nil {
		t.Fatalf("seed uncapped: %v", err)
	}
	// No group policy set → cap=0, duration=0, group reaper does not fire.
	if rec := start(srv3); rec.Code != http.StatusCreated {
		t.Fatalf("unlimited start = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if got, _ := srv3.SessionRecords.GetSession(ctx, "tenant-123", uncapped.ID); got.EndedAt != nil {
		t.Fatalf("an old session was wrongly reaped when no group cap was armed")
	}

	// CONTROL (tenant-cap axis): tenant cap=1 via direct store write, no group cap.
	// The tenant-level API rejects {cap>0, max_session_seconds=0} — this simulates a legacy row.
	// The group-duration reaper must NOT fire on the tenant axis (limits.Group == 0).
	srv4, _ := newTestServer(owner)
	mustEnrollMachine(t, ctx, srv4)
	tenantLeaked := &SessionRecord{
		MachineID:    "dev-1",
		TechnicianID: "u1",
		StartedAt:    time.Now().Add(-(groupDuration + 30*time.Minute)),
	}
	if err := srv4.SessionRecords.StartSession(ctx, "tenant-123", tenantLeaked); err != nil {
		t.Fatalf("seed tenant-leaked: %v", err)
	}
	if err := srv4.SessionPolicies.Set(ctx, "tenant-123",
		SessionPolicy{MaxConcurrentSessions: 1, MaxSessionSeconds: 0}); err != nil {
		t.Fatalf("set tenant policy: %v", err)
	}
	if rec := start(srv4); rec.Code != http.StatusConflict {
		t.Fatalf("tenant-cap-only start = %d, want 409 (group reaper must not fire on tenant axis): %s",
			rec.Code, rec.Body.String())
	}
	if got, _ := srv4.SessionRecords.GetSession(ctx, "tenant-123", tenantLeaked.ID); got.EndedAt != nil {
		t.Fatalf("an old session was wrongly reaped by the tenant-cap-only path (group reaper must not apply)")
	}

	// CONTROL (legacy group — cap>0, duration=0, bypassed API):
	// A group written with cap>0 but duration=0 (before validation was added, or via direct store write)
	// must NOT trigger an arbitrary fallback reap. The warning is logged, no sessions are ended.
	srv5, _ := newTestServer(owner)
	mustEnrollMachine(t, ctx, srv5)
	legacySession := &SessionRecord{
		MachineID:      "dev-1",
		MachineGroupID: DevDefaultMachineGroupID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(groupDuration + 30*time.Minute)),
	}
	if err := srv5.SessionRecords.StartSession(ctx, "tenant-123", legacySession); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	// Bypass API: write cap=1, duration=0 directly to the store (API would now reject this).
	if err := srv5.GroupSessionPolicies.Set(ctx, "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{MaxConcurrentSessions: 1, MaxSessionDurationSeconds: 0}); err != nil {
		t.Fatalf("set legacy group policy: %v", err)
	}
	// The legacy session holds the seat → start conflicts (409), not bypassed by any fallback reap.
	if rec := start(srv5); rec.Code != http.StatusConflict {
		t.Fatalf("legacy group start = %d, want 409 (no fallback reap without duration): %s",
			rec.Code, rec.Body.String())
	}
	if got, _ := srv5.SessionRecords.GetSession(ctx, "tenant-123", legacySession.ID); got.EndedAt != nil {
		t.Fatalf("legacy session was wrongly reaped — no arbitrary fallback reap must exist")
	}
}

// TestHandleStartSessionGroupReaperDoesNotCrossGroups proves that the group-duration reaper is scoped
// to the group whose policy drove the reap — sessions belonging to other groups with longer (or absent)
// duration limits are never reaped.
//
// Pass4: this test now calls ReapExpiredGroupSessions directly rather than going through the HTTP
// handler, because the unconditional gate refuses sessions in groups with max_session_duration_seconds > 0.
//
// Cross-group mutation: if ReapExpiredGroupSessions were replaced with ReapExpiredSessions (tenant-wide
// reap using the group duration), the Group B session (90min, duration=4h) would be wrongly ended when
// someone reaps Group A (duration=1h) — the 90min session would exceed Group A's 1h threshold in a
// tenant-wide query, even though Group B allows 4 hours.
func TestHandleStartSessionGroupReaperDoesNotCrossGroups(t *testing.T) {
	ctx := context.Background()
	const groupBID = "bbbbbbbb-0000-0000-0000-000000000000"
	const groupADuration = time.Hour     // Group A: 1h
	const groupBDuration = 4 * time.Hour // Group B: 4h

	// Seed a session in Group B that is 90 min old — within Group B's 4h policy but OLDER than
	// Group A's 1h policy. The tenant-wide reaper (old behaviour) would end it; the group-scoped
	// reaper (fix) must leave it open.
	store := NewInMemorySessionRecordStore()
	groupBSession := &SessionRecord{
		MachineID:      "machine-b",
		MachineGroupID: groupBID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(groupADuration + 30*time.Minute)), // 90 min — beyond A's 1h
	}
	if err := store.StartSession(ctx, "tenant-123", groupBSession); err != nil {
		t.Fatalf("seed groupB session: %v", err)
	}

	// Reap Group A with its 1h threshold. Group B's session must survive.
	reaped, err := store.ReapExpiredGroupSessions(ctx, "tenant-123", DevDefaultMachineGroupID, groupADuration)
	if err != nil {
		t.Fatalf("reap group A: %v", err)
	}
	if reaped != 0 {
		t.Fatalf("group A reap reaped %d sessions — expected 0 (no Group A sessions seeded)", reaped)
	}

	// CRITICAL: Group B's 90-min session is still OPEN — the Group A reap did NOT touch it.
	// Mutation: replacing ReapExpiredGroupSessions with ReapExpiredSessions would end this session.
	got, err := store.GetSession(ctx, "tenant-123", groupBSession.ID)
	if err != nil {
		t.Fatalf("get groupB session: %v", err)
	}
	if got.EndedAt != nil {
		t.Fatalf("Group B session (90min, within 4h policy) was wrongly reaped by Group A's reaper — cross-group scope violation")
	}

	// COMPLEMENT: reaping Group B with its own 4h threshold must also leave the 90-min session intact.
	reaped2, err := store.ReapExpiredGroupSessions(ctx, "tenant-123", groupBID, groupBDuration)
	if err != nil {
		t.Fatalf("reap group B: %v", err)
	}
	if reaped2 != 0 {
		t.Fatalf("group B reap (4h) reaped %d sessions — 90-min session is within 4h, expected 0", reaped2)
	}
	if got2, _ := store.GetSession(ctx, "tenant-123", groupBSession.ID); got2.EndedAt != nil {
		t.Fatalf("Group B session was wrongly reaped by its own reaper (still within the 4h limit)")
	}

}

// TestReaperUsesLesserDuration proves that when both tenant and group reap thresholds are active,
// each axis uses its own threshold independently. Tested at the store level because the unconditional
// Pass4 gate refuses sessions in groups with max_session_duration_seconds > 0.
//
// Mutation guards:
//   M1: group reap ignores session age → group-expired session not reaped.
//   M2: tenant reap ignores session age → tenant-expired session not reaped.
func TestReaperUsesLesserDuration(t *testing.T) {
	ctx := context.Background()
	const oneHour, threeHours = time.Hour, 3 * time.Hour

	// MAIN M1: group duration 1h, session 90min → group reaper reaped it.
	store := NewInMemorySessionRecordStore()
	leaked := &SessionRecord{
		MachineID:      "dev-1",
		MachineGroupID: DevDefaultMachineGroupID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(oneHour + 30*time.Minute)), // 90 min ago
	}
	if err := store.StartSession(ctx, "tenant-123", leaked); err != nil {
		t.Fatalf("seed leaked: %v", err)
	}
	reaped, err := store.ReapExpiredGroupSessions(ctx, "tenant-123", DevDefaultMachineGroupID, oneHour)
	if err != nil {
		t.Fatalf("group reap: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("group reap (1h threshold, 90min session): expected 1 reaped, got %d", reaped)
	}
	if got, _ := store.GetSession(ctx, "tenant-123", leaked.ID); got.EndedAt == nil {
		t.Fatalf("the 90-min session was not stamped ended by the group reaper (1h threshold)")
	}

	// MAIN M2: tenant duration 1h, session 90min → tenant reaper reaped it.
	store2 := NewInMemorySessionRecordStore()
	expired := &SessionRecord{
		MachineID:    "dev-1",
		TechnicianID: "u1",
		StartedAt:    time.Now().Add(-(oneHour + 30*time.Minute)),
	}
	if err := store2.StartSession(ctx, "tenant-123", expired); err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	reaped2, err := store2.ReapExpiredSessions(ctx, "tenant-123", oneHour)
	if err != nil {
		t.Fatalf("tenant reap: %v", err)
	}
	if reaped2 != 1 {
		t.Fatalf("tenant reap (1h threshold, 90min session): expected 1 reaped, got %d", reaped2)
	}
	if got, _ := store2.GetSession(ctx, "tenant-123", expired.ID); got.EndedAt == nil {
		t.Fatalf("the 90-min session was not stamped ended by the tenant reaper (1h threshold)")
	}

	// CONTROL: group reap with 3h threshold must NOT reap a 90-min session.
	store3 := NewInMemorySessionRecordStore()
	young := &SessionRecord{
		MachineID:      "dev-1",
		MachineGroupID: DevDefaultMachineGroupID,
		TechnicianID:   "u1",
		StartedAt:      time.Now().Add(-(oneHour + 30*time.Minute)), // 90 min — within 3h
	}
	if err := store3.StartSession(ctx, "tenant-123", young); err != nil {
		t.Fatalf("seed young: %v", err)
	}
	reaped3, err := store3.ReapExpiredGroupSessions(ctx, "tenant-123", DevDefaultMachineGroupID, threeHours)
	if err != nil {
		t.Fatalf("group reap3: %v", err)
	}
	if reaped3 != 0 {
		t.Fatalf("group reap (3h threshold, 90min session): expected 0 reaped, got %d — session is within limit", reaped3)
	}
	_ = threeHours
}

func TestHandleSessionPolicy(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	h := srv.Handler()
	do := func(hh http.Handler, method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		var b *strings.Reader
		if body != "" {
			b = strings.NewReader(body)
		} else {
			b = strings.NewReader("")
		}
		hh.ServeHTTP(rec, httptest.NewRequest(method, "/tenant/session-policy", b))
		return rec
	}

	// GET default → 0 (unlimited).
	rec := do(h, "GET", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var pol SessionPolicy
	if err := json.Unmarshal(rec.Body.Bytes(), &pol); err != nil || pol.MaxConcurrentSessions != 0 {
		t.Fatalf("GET default = (%+v, %v), want 0", pol, err)
	}
	// PUT 5 → 200, echoes the stored value; GET reflects it.
	if rec := do(h, "PUT", `{"max_concurrent_sessions":5,"max_session_seconds":3600}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT 5 = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, "GET", ""); !strings.Contains(rec.Body.String(), `"max_concurrent_sessions":5`) {
		t.Fatalf("GET after PUT = %s, want 5", rec.Body.String())
	}
	// A negative value is a clean 400 (not silently stored).
	if rec := do(h, "PUT", `{"max_concurrent_sessions":-1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT -1 = %d, want 400", rec.Code)
	}

	// A technician (no CapManageTenant) is refused the PUT.
	tech := &Principal{UserID: "u2", TenantID: "tenant-123",
		Grant: NewGrant("u2", "tenant-123", NewMembership(RoleTechnician, AllGroups()))}
	techSrv, _ := newTestServer(tech)
	if rec := do(techSrv.Handler(), "PUT", `{"max_concurrent_sessions":9}`); rec.Code != http.StatusForbidden {
		t.Fatalf("technician PUT = %d, want 403", rec.Code)
	}
}
