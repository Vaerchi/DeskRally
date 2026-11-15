package controlplane

// Proofs for §5 per-machine-group seat metering (loop 78): normalization, the in-memory group-policy store,
// the fake's atomic per-group StartSessionWithinLimit, and the HTTP surface — GET/PUT
// /machine-groups/{id}/session-policy (CapManageGroups + group scope) plus enforcement at POST /sessions.
// The pg store's RLS + cross-tenant + atomicity live in group_session_policy_pgstore_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeGroupSessionCap(t *testing.T) {
	for _, tc := range []struct {
		in       int
		wantOK   bool
		wantNorm int
	}{
		{0, true, 0},                                  // unlimited by group
		{1, true, 1},                                  // the smallest real cap
		{MaxSessionLimit, true, MaxSessionLimit},      // the ceiling is accepted
		{-1, false, 0},                                // negative is a client bug, not "unlimited"
		{MaxSessionLimit + 1, false, MaxSessionLimit}, // above the ceiling is rejected, clamped
	} {
		got, ok := NormalizeGroupSessionCap(tc.in)
		if ok != tc.wantOK || got != tc.wantNorm {
			t.Fatalf("NormalizeGroupSessionCap(%d) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.wantNorm, tc.wantOK)
		}
	}
}

// TestGroupSessionPolicyCapRequiresDuration proves NormalizeGroupSessionPolicy rejects a seat cap
// without an explicit max_session_duration_seconds. The reaper at POST /sessions uses that field as
// its threshold — without it, leaked rows accumulate forever against the group cap.
// Mirrors the tenant-level constraint tested by TestSecurityConcurrencyLimitRequiresExpiry.
func TestGroupSessionPolicyCapRequiresDuration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cap     int
		dur     int
		wantOK  bool
	}{
		{"no cap, no dur — unlimited", 0, 0, true},
		{"cap=1, dur=3600 — valid", 1, 3600, true},
		{"cap=1, dur=0 — invalid: cap requires dur", 1, 0, false},
		{"cap=100, dur=1 — valid (minimum dur)", 100, 1, true},
		{"cap=0, dur=3600 — valid: no cap, dur is fine", 0, 3600, true},
	} {
		p := GroupSessionPolicy{MaxConcurrentSessions: tc.cap, MaxSessionDurationSeconds: tc.dur}
		_, ok := NormalizeGroupSessionPolicy(p)
		if ok != tc.wantOK {
			t.Errorf("%s: NormalizeGroupSessionPolicy = %v, want %v", tc.name, ok, tc.wantOK)
		}
	}
	// M1: removing the cap>0&&dur==0 guard in NormalizeGroupSessionPolicy → case "cap=1,dur=0" returns
	// ok=true → TestGroupSessionPolicyCapRequiresDuration FAILS at the "invalid: cap requires dur" case.
}

func TestInMemoryGroupSessionPolicy(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryGroupSessionPolicyStore()
	// Unset → the default policy (unlimited by group, not view-only).
	if got, err := s.Get(ctx, "t1", "g1"); err != nil || !got.IsDefault() {
		t.Fatalf("unset = (%+v, %v), want the default policy", got, err)
	}
	if err := s.Set(ctx, "t1", "g1", GroupSessionPolicy{MaxConcurrentSessions: 3}); err != nil {
		t.Fatalf("set g1: %v", err)
	}
	if err := s.Set(ctx, "t1", "g2", GroupSessionPolicy{MaxConcurrentSessions: 7}); err != nil {
		t.Fatalf("set g2: %v", err)
	}
	if got, _ := s.Get(ctx, "t1", "g1"); got.MaxConcurrentSessions != 3 {
		t.Fatalf("g1 after set = %d, want 3", got.MaxConcurrentSessions)
	}
	// List is ordered by group id and holds only the groups with a policy.
	list, _ := s.List(ctx, "t1")
	if len(list) != 2 || list[0].GroupID != "g1" || list[0].MaxConcurrentSessions != 3 || list[1].GroupID != "g2" {
		t.Fatalf("List = %+v, want [g1:3 g2:7] ordered", list)
	}
	// An all-default policy clears the row so List drops it (matching the pg DELETE), and Get reads back
	// the default.
	if err := s.Set(ctx, "t1", "g1", GroupSessionPolicy{}); err != nil {
		t.Fatalf("clear g1: %v", err)
	}
	if got, _ := s.Get(ctx, "t1", "g1"); !got.IsDefault() {
		t.Fatalf("g1 after clear = %+v, want the default policy", got)
	}
	if list, _ := s.List(ctx, "t1"); len(list) != 1 || list[0].GroupID != "g2" {
		t.Fatalf("List after clear = %+v, want [g2] only", list)
	}
	// Another tenant is unaffected (row-per-(tenant,group) isolation, mirroring pg RLS).
	if got, _ := s.Get(ctx, "t2", "g2"); !got.IsDefault() {
		t.Fatalf("t2/g2 = %+v, want the default policy (isolated)", got)
	}

	// THE LOOP-80 RULE: a row survives while EITHER setting is non-default. Clearing the CAP of a group
	// that is view-only must NOT delete its row — under the old cap==0 delete test it did, silently
	// dropping the view-only mandate and handing control of those machines back to every technician.
	viewOnly := GroupSessionPolicy{MaxConcurrentSessions: 4, EnforceViewOnly: true}
	if err := s.Set(ctx, "t1", "g3", viewOnly); err != nil {
		t.Fatalf("set g3: %v", err)
	}
	if err := s.Set(ctx, "t1", "g3", GroupSessionPolicy{MaxConcurrentSessions: 0, EnforceViewOnly: true}); err != nil {
		t.Fatalf("clear g3 cap: %v", err)
	}
	got, _ := s.Get(ctx, "t1", "g3")
	if !got.EnforceViewOnly {
		t.Fatalf("g3 after clearing only its CAP = %+v, want enforce_view_only still true", got)
	}
	if got.MaxConcurrentSessions != 0 {
		t.Fatalf("g3 cap after clear = %d, want 0", got.MaxConcurrentSessions)
	}
	if list, _ := s.List(ctx, "t1"); len(list) != 2 {
		t.Fatalf("List = %+v, want g2 and g3 (g3 kept for its view-only mandate)", list)
	}
	// …and clearing BOTH does delete it.
	if err := s.Set(ctx, "t1", "g3", GroupSessionPolicy{}); err != nil {
		t.Fatalf("clear g3 entirely: %v", err)
	}
	if list, _ := s.List(ctx, "t1"); len(list) != 1 || list[0].GroupID != "g2" {
		t.Fatalf("List after clearing g3 entirely = %+v, want [g2] only", list)
	}

	// THE SAME RULE FOR THE THIRD SETTING (migration 0040's backstage opt-out). A row must survive while
	// ANY setting is non-default, and IsDefault() has to test THIS one too. If it does not, a group whose
	// only stored decision is `allow_backstage_under_view_only` is DELETED on write and reads back as the
	// default — the console's checkbox silently unticking itself after a save. This is deliberately
	// asserted with the opt-out ALONE, no cap and no mandate: with any other field set the row would
	// survive for that field's sake and an IsDefault() that ignored the opt-out would still pass.
	optOutOnly := GroupSessionPolicy{AllowBackstageUnderViewOnly: true}
	if optOutOnly.IsDefault() {
		t.Fatal("a policy whose only decision is the backstage opt-out reports IsDefault — its row would be deleted")
	}
	if err := s.Set(ctx, "t1", "g4", optOutOnly); err != nil {
		t.Fatalf("set g4: %v", err)
	}
	if got, _ := s.Get(ctx, "t1", "g4"); !got.AllowBackstageUnderViewOnly {
		t.Fatalf("g4 = %+v, want the backstage opt-out to have survived the write", got)
	}
	if list, _ := s.List(ctx, "t1"); len(list) != 2 {
		t.Fatalf("List = %+v, want g2 and g4 (g4 kept for its backstage opt-out)", list)
	}
	// And it round-trips ALONGSIDE the mandate, which is the combination that actually does anything: a
	// view-only group whose admin deliberately re-opened backstage for unattended maintenance.
	both := GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: true}
	if err := s.Set(ctx, "t1", "g4", both); err != nil {
		t.Fatalf("set g4 both: %v", err)
	}
	got4, _ := s.Get(ctx, "t1", "g4")
	if !got4.EnforceViewOnly || !got4.AllowBackstageUnderViewOnly {
		t.Fatalf("g4 = %+v, want BOTH the mandate and the opt-out (each is stored independently)", got4)
	}
	// Revoking only the opt-out leaves the mandate — and the row — intact.
	if err := s.Set(ctx, "t1", "g4", GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
		t.Fatalf("revoke g4 opt-out: %v", err)
	}
	got4, _ = s.Get(ctx, "t1", "g4")
	if !got4.EnforceViewOnly || got4.AllowBackstageUnderViewOnly {
		t.Fatalf("g4 after revoking the opt-out = %+v, want {viewOnly:true allowBackstage:false}", got4)
	}
	// Clearing everything deletes it, as for any other combination.
	if err := s.Set(ctx, "t1", "g4", GroupSessionPolicy{}); err != nil {
		t.Fatalf("clear g4: %v", err)
	}
	if list, _ := s.List(ctx, "t1"); len(list) != 1 || list[0].GroupID != "g2" {
		t.Fatalf("List after clearing g4 = %+v, want [g2] only", list)
	}
}

// IsDefault is the row-DELETION test, so every field of GroupSessionPolicy has to appear in it. This pins the
// rule field-by-field rather than through a store, because the store round-trip can only ever catch the
// fields the test happens to set — and the failure mode being guarded is a field NOBODY remembered.
//
// Migration 0035 wrote this warning down after the first time it bit (clearing a cap silently dropped a
// group's view-only mandate); 0040 repeats it for the backstage opt-out. If a fourth setting is added and
// this test is not updated, that is the same bug for the third time.
func TestGroupSessionPolicyIsDefaultCoversEverySetting(t *testing.T) {
	if !(GroupSessionPolicy{GroupID: "g1"}).IsDefault() {
		t.Fatal("a policy with nothing decided is not IsDefault — every group would keep a pointless row")
	}
	// GroupID alone must NOT make a policy non-default: it is the row's identity, not a decision, and Get
	// fills it in even for a group that has no row at all.
	for _, tc := range []struct {
		name string
		p    GroupSessionPolicy
	}{
		{"a cap", GroupSessionPolicy{GroupID: "g1", MaxConcurrentSessions: 1}},
		{"the view-only mandate", GroupSessionPolicy{GroupID: "g1", EnforceViewOnly: true}},
		{"the backstage opt-out", GroupSessionPolicy{GroupID: "g1", AllowBackstageUnderViewOnly: true}},
		{"a recording ban", GroupSessionPolicy{GroupID: "g1", ProhibitRecording: true}},
		{"mandatory recording", GroupSessionPolicy{GroupID: "g1", RequireRecording: true}},
		{"a max session duration", GroupSessionPolicy{GroupID: "g1", MaxSessionDurationSeconds: 3600}},
		{"a max idle timeout", GroupSessionPolicy{GroupID: "g1", MaxIdleSeconds: 300}},
	} {
		if tc.p.IsDefault() {
			t.Errorf("%s alone reports IsDefault — Set would DELETE the row and the setting would be lost", tc.name)
		}
	}
}

// TestStartSessionWithinGroupLimitFake proves the fake enforces the GROUP axis independently of the tenant
// axis, counts only OPEN sessions in the SAME group, and leaves a group-less session uncapped.
func TestStartSessionWithinGroupLimitFake(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	startIn := func(group string, limits SessionStartLimits) error {
		return s.StartSessionWithinLimit(ctx, "t1",
			&SessionRecord{MachineID: "m", TechnicianID: "u", MachineGroupID: group}, limits)
	}

	// Group cap 2 on g1 (tenant unlimited): two open in g1 allowed, the third refused on the GROUP axis.
	if err := startIn("g1", SessionStartLimits{GroupID: "g1", Group: 2}); err != nil {
		t.Fatalf("g1 #1: %v", err)
	}
	if err := startIn("g1", SessionStartLimits{GroupID: "g1", Group: 2}); err != nil {
		t.Fatalf("g1 #2: %v", err)
	}
	if err := startIn("g1", SessionStartLimits{GroupID: "g1", Group: 2}); err != ErrGroupConcurrentSessionLimit {
		t.Fatalf("g1 #3 = %v, want ErrGroupConcurrentSessionLimit", err)
	}
	// A DIFFERENT group is counted separately — g2 has room even though g1 is full.
	if err := startIn("g2", SessionStartLimits{GroupID: "g2", Group: 2}); err != nil {
		t.Fatalf("g2 #1 (separate group): %v", err)
	}
	// Only OPEN sessions count: end one g1 session and a g1 start is allowed again.
	list, _ := s.ListSessions(ctx, "t1", SessionSummaryFilter{})
	var g1id string
	for _, r := range list {
		if r.MachineGroupID == "g1" {
			g1id = r.ID
			break
		}
	}
	if _, err := s.EndSession(ctx, "t1", g1id, list[0].StartedAt); err != nil {
		t.Fatalf("end a g1 session: %v", err)
	}
	if err := startIn("g1", SessionStartLimits{GroupID: "g1", Group: 2}); err != nil {
		t.Fatalf("g1 after ending one: %v", err)
	}
	// A group-less session (empty GroupID) is uncapped by group even with a positive Group cap.
	if err := startIn("", SessionStartLimits{GroupID: "", Group: 1}); err != nil {
		t.Fatalf("group-less start should be uncapped by group: %v", err)
	}
}

// TestStartSessionWithinLimitTenantAndGroup proves both caps compose: the tenant axis is checked first, and
// a group cap can block even when the tenant axis has room (and vice versa).
func TestStartSessionWithinLimitTenantAndGroup(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	// Tenant cap 5, group g1 cap 1. First g1 start ok; the second is blocked by the GROUP axis (tenant
	// still has room), returning the group error, not the tenant error.
	if err := s.StartSessionWithinLimit(ctx, "t1",
		&SessionRecord{MachineID: "m", MachineGroupID: "g1"}, SessionStartLimits{Tenant: 5, GroupID: "g1", Group: 1}); err != nil {
		t.Fatalf("g1 #1: %v", err)
	}
	if err := s.StartSessionWithinLimit(ctx, "t1",
		&SessionRecord{MachineID: "m", MachineGroupID: "g1"}, SessionStartLimits{Tenant: 5, GroupID: "g1", Group: 1}); err != ErrGroupConcurrentSessionLimit {
		t.Fatalf("g1 #2 = %v, want group error (tenant still has room)", err)
	}
	// Now fill the tenant axis (cap 2) with a g2 session; the next start hits the TENANT error first.
	if err := s.StartSessionWithinLimit(ctx, "t1",
		&SessionRecord{MachineID: "m", MachineGroupID: "g2"}, SessionStartLimits{Tenant: 2, GroupID: "g2", Group: 9}); err != nil {
		t.Fatalf("g2 #1: %v", err)
	}
	if err := s.StartSessionWithinLimit(ctx, "t1",
		&SessionRecord{MachineID: "m", MachineGroupID: "g2"}, SessionStartLimits{Tenant: 2, GroupID: "g2", Group: 9}); err != ErrConcurrentSessionLimit {
		t.Fatalf("tenant-full start = %v, want ErrConcurrentSessionLimit (checked before the group axis)", err)
	}
}

func TestHandleGroupSessionPolicy(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	// A real group to target (the permissive machine store's DevDefaultMachineGroupID is not a group ROW).
	g := &MachineGroup{Name: "Sales"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	h := srv.Handler()
	do := func(hh http.Handler, method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	path := "/machine-groups/" + g.ID + "/session-policy"

	// GET default → 200, cap 0.
	rec := do(h, "GET", path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var cap GroupSessionPolicy
	if err := json.Unmarshal(rec.Body.Bytes(), &cap); err != nil || cap.MaxConcurrentSessions != 0 || cap.GroupID != g.ID {
		t.Fatalf("GET default = (%+v, %v), want {%s 0}", cap, err, g.ID)
	}
	// PUT cap=4 with required max_session_duration_seconds → 200 echo; GET reflects it.
	if rec := do(h, "PUT", path, `{"max_concurrent_sessions":4,"max_session_duration_seconds":3600}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"max_concurrent_sessions":4`) {
		t.Fatalf("PUT 4 = %d body %q, want 200 echo 4", rec.Code, rec.Body.String())
	}
	if rec := do(h, "GET", path, ""); !strings.Contains(rec.Body.String(), `"max_concurrent_sessions":4`) {
		t.Fatalf("GET after PUT = %s, want 4", rec.Body.String())
	}
	// A negative value is a clean 400 (not stored).
	if rec := do(h, "PUT", path, `{"max_concurrent_sessions":-1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT -1 = %d, want 400", rec.Code)
	}
	// cap>0 without max_session_duration_seconds is a 400 — reaper requires a stated duration.
	if rec := do(h, "PUT", path, `{"max_concurrent_sessions":2}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "max_session_duration_seconds is required") {
		t.Fatalf("PUT cap-only = %d body %q, want 400 with duration error", rec.Code, rec.Body.String())
	}
	// An unknown group id 404s on both GET and PUT (existence checked before the store).
	unknown := "/machine-groups/00000000-0000-0000-0000-000000000000/session-policy"
	if rec := do(h, "GET", unknown, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET unknown = %d, want 404", rec.Code)
	}
	if rec := do(h, "PUT", unknown, `{"max_concurrent_sessions":2,"max_session_duration_seconds":3600}`); rec.Code != http.StatusNotFound {
		t.Fatalf("PUT unknown = %d, want 404", rec.Code)
	}
	// The set was audited.
	events, err := srv.MgmtAudit.ListEvents(ctx, "tenant-123", 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == "machine_group.session_policy.set" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a machine_group.session_policy.set audit event, got %+v", events)
	}
	// The list endpoint reflects the capped group in one call.
	if rec := do(h, "GET", "/machine-groups/session-policies", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), g.ID) || !strings.Contains(rec.Body.String(), `"max_concurrent_sessions":4`) {
		t.Fatalf("list session-policies = %d body %q, want the capped group", rec.Code, rec.Body.String())
	}

	// A technician (no CapManageGroups) is refused BOTH the PUT and the GET.
	tech := &Principal{UserID: "u2", TenantID: "tenant-123",
		Grant: NewGrant("u2", "tenant-123", NewMembership(RoleTechnician, AllGroups()))}
	techSrv, _ := newTestServer(tech)
	tg := &MachineGroup{Name: "Ops"}
	if err := techSrv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", tg); err != nil {
		t.Fatalf("create group (tech srv): %v", err)
	}
	tpath := "/machine-groups/" + tg.ID + "/session-policy"
	if rec := do(techSrv.Handler(), "PUT", tpath, `{"max_concurrent_sessions":9}`); rec.Code != http.StatusForbidden {
		t.Fatalf("technician PUT = %d, want 403", rec.Code)
	}
	if rec := do(techSrv.Handler(), "GET", tpath, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("technician GET = %d, want 403", rec.Code)
	}
}

// TestHandleStartSessionEnforcesGroupLimit proves the per-group cap is enforced at POST /sessions, on the
// GROUP axis, independently of the tenant cap (which is left unlimited here).
func TestHandleStartSessionEnforcesGroupLimit(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	// Every machine in the permissive store resolves to DevDefaultMachineGroupID; cap THAT group at 1.
	// Set directly on the store (the group is not a machine_group ROW, so the handler would 404 a PUT — the
	// point here is enforcement, not the admin surface, which TestHandleGroupSessionPolicy covers).
	if err := srv.GroupSessionPolicies.Set(ctx, "tenant-123", DevDefaultMachineGroupID, GroupSessionPolicy{MaxConcurrentSessions: 1}); err != nil {
		t.Fatalf("set group cap: %v", err)
	}
	h := srv.Handler()
	start := func(machine string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"machine_id":"`+machine+`"}`)))
		return rec
	}
	// First session in the group: allowed (tenant cap is unlimited).
	first := start("dev-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("1st start = %d, want 201: %s", first.Code, first.Body.String())
	}
	var started struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Second session (a different machine, SAME group) → 409 naming the machine group.
	if rec := start("dev-2"); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "machine group") {
		t.Fatalf("2nd start = %d body %q, want 409 machine-group limit", rec.Code, rec.Body.String())
	}
	// End the first and a new session is allowed again — the cap is on OPEN sessions in the group.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/sessions/"+started.Session.ID+"/end", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("end = %d: %s", rec.Code, rec.Body.String())
	}
	if again := start("dev-3"); again.Code != http.StatusCreated {
		t.Fatalf("start after end = %d, want 201: %s", again.Code, again.Body.String())
	}
}
