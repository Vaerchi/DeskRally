package controlplane

// Proofs for the §5 "sessions by technician" activity report (SessionRecordStore.SummarizeByTechnician):
// the store returns per-(technician, group) sub-counts (fake + pg under RLS, with the completed-time SUM),
// and the HTTP surface (GET /reports/sessions-by-technician) gates CapViewSessions and NARROWS BY GROUP
// BEFORE aggregating per technician — the property that keeps a scoped viewer from seeing a technician's
// totals from groups outside their scope.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInMemorySessionSummaryByTechnician(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	open := func(tid, tech, group string) {
		if err := s.StartSession(ctx, tid, &SessionRecord{MachineID: "m", MachineGroupID: group, TechnicianID: tech}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	ended := func(tid, tech, group string, dur time.Duration) {
		en := base.Add(dur)
		if err := s.StartSession(ctx, tid, &SessionRecord{
			MachineID: "m", MachineGroupID: group, TechnicianID: tech, StartedAt: base, EndedAt: &en,
		}); err != nil {
			t.Fatalf("start ended: %v", err)
		}
	}
	// Tenant t1: tech u1 works across TWO groups (g1: one open + one 30s ended; g2: one open); tech u2 works
	// in g1 (one 45.9s ended → floors to 45, plus one skewed -3.5s ended → clamped to 0). Three sub-rows.
	open("t1", "u1", "g1")
	ended("t1", "u1", "g1", 30*time.Second)
	open("t1", "u1", "g2")
	ended("t1", "u2", "g1", 45*time.Second+900*time.Millisecond)
	ended("t1", "u2", "g1", -3*time.Second-500*time.Millisecond)
	// Tenant t2 must NOT bleed into t1.
	open("t2", "u1", "g1")

	sub, err := s.SummarizeByTechnician(ctx, "t1", SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	got := map[string]TechnicianGroupSessionCount{}
	for _, c := range sub {
		got[c.TechnicianID+"/"+c.MachineGroupID] = c
	}
	if len(sub) != 3 {
		t.Fatalf("sub-count rows = %d, want 3 (u1/g1, u1/g2, u2/g1): %+v", len(sub), sub)
	}
	if r := got["u1/g1"]; r.Count != 2 || r.TotalSeconds != 30 {
		t.Fatalf("u1/g1 = %+v, want count 2 total 30 (open contributes 0)", r)
	}
	if r := got["u1/g2"]; r.Count != 1 || r.TotalSeconds != 0 {
		t.Fatalf("u1/g2 = %+v, want count 1 total 0", r)
	}
	if r := got["u2/g1"]; r.Count != 2 || r.TotalSeconds != 45 {
		t.Fatalf("u2/g1 = %+v, want count 2 total 45 (45.9 floored, -3.5 clamped to 0)", r)
	}
	if e, err := s.SummarizeByTechnician(ctx, "t-none", SessionSummaryFilter{}); err != nil || len(e) != 0 {
		t.Fatalf("empty-tenant summary = %+v, %v; want empty, nil", e, err)
	}
}

func TestSessionsByTechnicianHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed := func(tech, group string, n int) {
		for i := 0; i < n; i++ {
			if err := srv.SessionRecords.StartSession(ctx, tid, &SessionRecord{
				MachineID: "m", MachineGroupID: group, TechnicianID: tech,
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	// Tech u1's sessions SPAN two groups: 2 in group-a, 3 in group-b. Tech u2: 1 in group-a.
	seed("u1", "group-a", 2)
	seed("u1", "group-b", 3)
	seed("u2", "group-a", 1)

	get := func(hh http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	type resp struct {
		Rows []TechnicianSessionCount `json:"sessions_by_technician"`
	}
	const path = "/reports/sessions-by-technician"

	// Owner (AllGroups): u1 aggregated ACROSS both groups = 5, u2 = 1. Sorted most-sessions-first.
	rec := get(srv.Handler(), path)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var r resp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode owner: %v", err)
	}
	if len(r.Rows) != 2 || r.Rows[0].TechnicianID != "u1" || r.Rows[0].Count != 5 || r.Rows[1].TechnicianID != "u2" || r.Rows[1].Count != 1 {
		t.Fatalf("owner rows = %+v, want u1:5 then u2:1", r.Rows)
	}

	// A viewer scoped to group-a ONLY, over the SAME seeded store. THE KEY ASSERTION: narrowing happens
	// BEFORE aggregation, so u1's THREE group-b sessions are dropped and u1 shows count 2 (its group-a
	// portion) — NOT 5. If narrowing came after the per-technician sum (or not at all), u1 would read 5.
	viewer := &Principal{UserID: "u9", TenantID: tid,
		Grant: NewGrant("u9", tid, NewMembership(RoleReadOnly, Groups("group-a")))}
	vsrv, _ := newTestServer(viewer)
	vsrv.SessionRecords = srv.SessionRecords // share the seeded data across principals
	vrec := get(vsrv.Handler(), path)
	if vrec.Code != http.StatusOK {
		t.Fatalf("viewer = %d, want 200: %s", vrec.Code, vrec.Body.String())
	}
	var vr resp
	if err := json.Unmarshal(vrec.Body.Bytes(), &vr); err != nil {
		t.Fatalf("decode viewer: %v", err)
	}
	if len(vr.Rows) != 2 || vr.Rows[0].TechnicianID != "u1" || vr.Rows[0].Count != 2 || vr.Rows[1].TechnicianID != "u2" || vr.Rows[1].Count != 1 {
		t.Fatalf("group-a viewer rows = %+v, want u1:2 (group-b narrowed out, NOT 5) then u2:1", vr.Rows)
	}

	// GATE: a principal holding no CapViewSessions → 403.
	nocap := &Principal{UserID: "u3", TenantID: tid, Grant: NewGrant("u3", tid)}
	nsrv, _ := newTestServer(nocap)
	if nrec := get(nsrv.Handler(), path); nrec.Code != http.StatusForbidden {
		t.Fatalf("no-cap = %d, want 403", nrec.Code)
	}
}

// TestPgSessionSummaryByTechnicianUnderRLS drives PgSessionRecordStore.SummarizeByTechnician as rmt_app:
// sessions on TWO machines in the SAME group lump into ONE (technician, group) row (proving GROUP BY the
// technician + the machine's joined group, not the machine), the completed-time SUM floors + clamps, and
// RLS keeps another tenant's sessions out.
func TestPgSessionSummaryByTechnicianUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	tidA, uidA := provisionUser(t, suPool, "tsum-a", "a@tsum-a.test", "password-1234")
	tidB, uidB := provisionUser(t, suPool, "tsum-b", "b@tsum-b.test", "password-1234")
	gidA, midA1 := seedGroupMachine(t, suPool, tidA, "dev-ta1")
	midA2 := seedNamedMachine(t, suPool, tidA, gidA, "dev-ta2", "HOST2") // same group gidA
	_, midB1 := seedGroupMachine(t, suPool, tidB, "dev-tb1")

	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)

	endWith := func(mid string, dur time.Duration) {
		rec := &SessionRecord{MachineID: mid, TechnicianID: uidA}
		if err := store.StartSession(ctx, tidA, rec); err != nil {
			t.Fatalf("start: %v", err)
		}
		got, err := store.GetSession(ctx, tidA, rec.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if _, err := store.EndSession(ctx, tidA, rec.ID, got.StartedAt.Add(dur)); err != nil {
			t.Fatalf("end: %v", err)
		}
	}
	// uidA: on A1 → 30s + 60s ended + one -3.5s skewed (clamped) + one open; on A2 → one open. All group gidA.
	endWith(midA1, 30*time.Second)
	endWith(midA1, 60*time.Second)
	endWith(midA1, -3500*time.Millisecond)
	if err := store.StartSession(ctx, tidA, &SessionRecord{MachineID: midA1, TechnicianID: uidA}); err != nil {
		t.Fatalf("open A1: %v", err)
	}
	if err := store.StartSession(ctx, tidA, &SessionRecord{MachineID: midA2, TechnicianID: uidA}); err != nil {
		t.Fatalf("open A2: %v", err)
	}
	// Tenant B: 5 sessions — RLS must keep them out of A's summary.
	for i := 0; i < 5; i++ {
		if err := store.StartSession(ctx, tidB, &SessionRecord{MachineID: midB1, TechnicianID: uidB}); err != nil {
			t.Fatalf("start B: %v", err)
		}
	}

	sum, err := store.SummarizeByTechnician(ctx, tidA, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize A: %v", err)
	}
	// ONE row: (uidA, gidA) — A1 and A2 lump by technician+group; count 5 (2 ended + 1 skewed + 2 open),
	// total 90s (skewed and open each contribute 0). B's 5 sessions are excluded by RLS (never a 10).
	if len(sum) != 1 {
		t.Fatalf("A summary = %+v, want ONE (technician, group) row", sum)
	}
	if sum[0].TechnicianID != uidA || sum[0].MachineGroupID != gidA || sum[0].Count != 5 || sum[0].TotalSeconds != 90 {
		t.Fatalf("A row = %+v, want uidA/gidA count 5 total 90", sum[0])
	}
}
