package controlplane

// Proofs for the §5 "sessions by machine" activity report (SessionRecordStore.SummarizeByMachine):
// the store (fake + pg under RLS) and the HTTP surface (GET /reports/sessions-by-machine —
// CapViewSessions + the per-group narrowing GET /sessions applies + the JSON shape).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInMemorySessionSummaryByMachine(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	start := func(tid, machineID, name, group string) {
		if err := s.StartSession(ctx, tid, &SessionRecord{
			MachineID: machineID, MachineName: name, MachineGroupID: group, TechnicianID: "u1",
		}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	// Tenant t1: m-b has 3 sessions, m-a and m-c have 1 each (a count tie). Tenant t2: m-a has 5 —
	// must NOT bleed into t1's counts.
	start("t1", "m-a", "alpha", "g1")
	start("t1", "m-b", "bravo", "g1")
	start("t1", "m-b", "bravo", "g1")
	start("t1", "m-b", "bravo", "g1")
	start("t1", "m-c", "aardvark", "g2")
	for i := 0; i < 5; i++ {
		start("t2", "m-a", "alpha", "g9")
	}

	sum, err := s.SummarizeByMachine(ctx, "t1", SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	// count DESC, then name ASC on the tie: m-b(3), then aardvark(m-c) before alpha(m-a). t2 excluded.
	if len(sum) != 3 || sum[0].MachineID != "m-b" || sum[0].Count != 3 || sum[0].MachineName != "bravo" {
		t.Fatalf("t1 summary = %+v, want m-b:3 first", sum)
	}
	if sum[1].MachineID != "m-c" || sum[1].Count != 1 || sum[2].MachineID != "m-a" || sum[2].Count != 1 {
		t.Fatalf("t1 tie-break = %+v, want aardvark(m-c) before alpha(m-a) (name ASC)", sum)
	}
	if sum[0].MachineGroupID != "g1" {
		t.Fatalf("group id not carried through the summary: %+v", sum[0])
	}
	// An empty tenant summarizes to nothing without erroring.
	if e, err := s.SummarizeByMachine(ctx, "t-none", SessionSummaryFilter{}); err != nil || len(e) != 0 {
		t.Fatalf("empty-tenant summary = %+v, %v; want empty, nil", e, err)
	}
}

func TestSessionsByMachineHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed := func(machineID, name, group string, n int) {
		for i := 0; i < n; i++ {
			if err := srv.SessionRecords.StartSession(ctx, tid, &SessionRecord{
				MachineID: machineID, MachineName: name, MachineGroupID: group, TechnicianID: "u1",
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	seed("m-a", "alpha", "group-a", 2)
	seed("m-b", "bravo", "group-b", 1)

	get := func(hh http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	type resp struct {
		Rows []MachineSessionCount `json:"sessions_by_machine"`
	}

	// Owner (AllGroups): both machines, m-a(2) before m-b(1).
	rec := get(srv.Handler(), "/reports/sessions-by-machine")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var r resp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode owner: %v", err)
	}
	if len(r.Rows) != 2 || r.Rows[0].MachineID != "m-a" || r.Rows[0].Count != 2 || r.Rows[1].MachineID != "m-b" {
		t.Fatalf("owner rows = %+v, want m-a:2 then m-b:1", r.Rows)
	}

	// A viewer scoped to ONLY group-a, over the SAME seeded store: m-b (group-b) is narrowed OUT.
	// Without the handler's AllowsInGroup filter this would leak the count for a machine the caller
	// cannot see in the session list.
	viewer := &Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleReadOnly, Groups("group-a")))}
	vsrv, _ := newTestServer(viewer)
	vsrv.SessionRecords = srv.SessionRecords // share the seeded data across principals
	vrec := get(vsrv.Handler(), "/reports/sessions-by-machine")
	if vrec.Code != http.StatusOK {
		t.Fatalf("viewer = %d, want 200: %s", vrec.Code, vrec.Body.String())
	}
	var vr resp
	if err := json.Unmarshal(vrec.Body.Bytes(), &vr); err != nil {
		t.Fatalf("decode viewer: %v", err)
	}
	if len(vr.Rows) != 1 || vr.Rows[0].MachineID != "m-a" || vr.Rows[0].Count != 2 {
		t.Fatalf("group-a viewer rows = %+v, want ONLY m-a:2 (group-b narrowed out)", vr.Rows)
	}

	// GATE: a principal holding no CapViewSessions → 403.
	nocap := &Principal{UserID: "u3", TenantID: tid, Grant: NewGrant("u3", tid)}
	nsrv, _ := newTestServer(nocap)
	if nrec := get(nsrv.Handler(), "/reports/sessions-by-machine"); nrec.Code != http.StatusForbidden {
		t.Fatalf("no-cap = %d, want 403", nrec.Code)
	}
}

// TestPgSessionSummaryByMachineUnderRLS drives PgSessionRecordStore.SummarizeByMachine as rmt_app:
// grouped counts joined to the machine name, ordered count DESC, and RLS-scoped (another tenant's
// sessions do not bleed into the total).
func TestPgSessionSummaryByMachineUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	tidA, uidA := provisionUser(t, suPool, "sum-a", "a@sum-a.test", "password-1234")
	tidB, uidB := provisionUser(t, suPool, "sum-b", "b@sum-b.test", "password-1234")
	_, midA1 := seedGroupMachine(t, suPool, tidA, "dev-a1")
	_, midA2 := seedGroupMachine(t, suPool, tidA, "dev-a2")
	_, midB1 := seedGroupMachine(t, suPool, tidB, "dev-b1")

	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)

	startN := func(tid, mid, uid string, n int) {
		for i := 0; i < n; i++ {
			if err := store.StartSession(ctx, tid, &SessionRecord{MachineID: mid, TechnicianID: uid}); err != nil {
				t.Fatalf("start: %v", err)
			}
		}
	}
	// Tenant A: machine A1 x3, A2 x1. Tenant B: B1 x5 — RLS must keep B out of A's summary.
	startN(tidA, midA1, uidA, 3)
	startN(tidA, midA2, uidA, 1)
	startN(tidB, midB1, uidB, 5)

	sum, err := store.SummarizeByMachine(ctx, tidA, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize A: %v", err)
	}
	// count DESC: A1(3) before A2(1). B1's 5 sessions are excluded (RLS) — not an 8 anywhere.
	if len(sum) != 2 || sum[0].MachineID != midA1 || sum[0].Count != 3 || sum[1].MachineID != midA2 || sum[1].Count != 1 {
		t.Fatalf("A summary = %+v, want A1:3 then A2:1 (RLS: B excluded)", sum)
	}
	// The machine name is joined from the machine row (seedGroupMachine names them all 'HOST').
	if sum[0].MachineName != "HOST" {
		t.Fatalf("machine name not joined from machine row: %+v", sum[0])
	}
}

// TestInMemorySessionSummaryDuration pins the per-machine TOTAL COMPLETED session time (the usage-hours
// metric): only ENDED sessions count, each session's duration is FLOORED to whole seconds, and an open
// session contributes zero.
func TestInMemorySessionSummaryDuration(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	endedSession := func(machineID, name string, startOffset int, dur time.Duration) {
		st := base.Add(time.Duration(startOffset) * time.Second)
		en := st.Add(dur)
		if err := s.StartSession(ctx, "t1", &SessionRecord{
			MachineID: machineID, MachineName: name, MachineGroupID: "g1", StartedAt: st, EndedAt: &en,
		}); err != nil {
			t.Fatalf("seed ended: %v", err)
		}
	}
	// Machine A: 30s + 60s ended = 90s, plus one OPEN session (contributes 0 to time, +1 to count).
	endedSession("m-a", "alpha", 0, 30*time.Second)
	endedSession("m-a", "alpha", 100, 60*time.Second)
	if err := s.StartSession(ctx, "t1", &SessionRecord{MachineID: "m-a", MachineName: "alpha", MachineGroupID: "g1"}); err != nil {
		t.Fatalf("seed open: %v", err)
	}
	// Machine B: one session of 45.9s → floors to 45 (proves per-session flooring, not rounding).
	endedSession("m-b", "bravo", 0, 45*time.Second+900*time.Millisecond)
	// Machine C: ended_at 3.5s BEFORE started_at (clock skew) → CLAMPED to 0, not a negative -3s (which a
	// bare Go truncation would give and which pg FLOOR would round to -4 — the review-caught divergence).
	endedSession("m-c", "charlie", 200, -3*time.Second-500*time.Millisecond)

	sum, err := s.SummarizeByMachine(ctx, "t1", SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	byID := map[string]MachineSessionCount{}
	for _, c := range sum {
		byID[c.MachineID] = c
	}
	if a := byID["m-a"]; a.Count != 3 || a.TotalSeconds != 90 {
		t.Fatalf("m-a = count %d, total %ds; want count 3, total 90s (open contributes 0)", a.Count, a.TotalSeconds)
	}
	if b := byID["m-b"]; b.Count != 1 || b.TotalSeconds != 45 {
		t.Fatalf("m-b = count %d, total %ds; want count 1, total 45s (45.9s floored)", b.Count, b.TotalSeconds)
	}
	if c := byID["m-c"]; c.Count != 1 || c.TotalSeconds != 0 {
		t.Fatalf("m-c = count %d, total %ds; want count 1, total 0 (negative duration clamped)", c.Count, c.TotalSeconds)
	}
}

// TestPgSessionSummaryDurationUnderRLS drives the SUM(FLOOR(EXTRACT(EPOCH ...))) total-time column on
// PgSessionRecordStore: two ended sessions (30s + 60s) sum to 90s, and an open session adds to the count
// but not the time — matching the fake exactly.
func TestPgSessionSummaryDurationUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	tid, uid := provisionUser(t, suPool, "dur", "d@dur.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tid, "dev-dur")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)

	endWith := func(dur time.Duration) {
		rec := &SessionRecord{MachineID: mid, TechnicianID: uid}
		if err := store.StartSession(ctx, tid, rec); err != nil {
			t.Fatalf("start: %v", err)
		}
		got, err := store.GetSession(ctx, tid, rec.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if _, err := store.EndSession(ctx, tid, rec.ID, got.StartedAt.Add(dur)); err != nil {
			t.Fatalf("end: %v", err)
		}
	}
	endWith(30 * time.Second)
	endWith(60 * time.Second)
	// A session ended 3.5s BEFORE it started (clock skew) → GREATEST(0, FLOOR(-3.5)) = 0, matching the
	// fake's clamp; without the GREATEST it would subtract 4s and the total would be 86, not 90.
	endWith(-3500 * time.Millisecond)
	if err := store.StartSession(ctx, tid, &SessionRecord{MachineID: mid, TechnicianID: uid}); err != nil {
		t.Fatalf("open: %v", err)
	}

	sum, err := store.SummarizeByMachine(ctx, tid, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	// count = 4 (two 30/60 + one skewed + one open); total = 90 (skewed and open each contribute 0).
	if len(sum) != 1 || sum[0].Count != 4 || sum[0].TotalSeconds != 90 {
		t.Fatalf("summary = %+v, want count 4, total 90s (negative + open both contribute 0)", sum)
	}
}

// TestPgSessionSummaryByMachineTieBreak pins the count-TIE order: two machines in one tenant with the
// SAME session count must come back in Go byte-wise name order (the fake's contract), which the pg query
// forces with COLLATE "C". 'Zebra' (Z=0x5A) sorts before 'apple' (a=0x61) by BYTE value — the opposite
// of a dictionary/locale collation — so this locks the byte-order tie-break and matches the fake. (On a
// cluster whose default collation already equals byte-order, like this dev box, the assertion also holds
// without the COLLATE; on a dictionary-locale cluster only the COLLATE keeps fake and pg in step — the
// `know-what-the-vm-cannot-prove` limitation, cross-validated by the byte-order fake test above.)
func TestPgSessionSummaryByMachineTieBreak(t *testing.T) {
	suPool := newTestPool(t)
	tid, uid := provisionUser(t, suPool, "tie", "t@tie.test", "password-1234")
	gid, _ := seedGroupMachine(t, suPool, tid, "dev-tie-seed") // reuse its group; its 'HOST' machine has 0 sessions
	midZ := seedNamedMachine(t, suPool, tid, gid, "dev-tie-z", "Zebra")
	midA := seedNamedMachine(t, suPool, tid, gid, "dev-tie-a", "apple")

	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)
	for _, mid := range []string{midZ, midA} {
		for i := 0; i < 2; i++ {
			if err := store.StartSession(ctx, tid, &SessionRecord{MachineID: mid, TechnicianID: uid}); err != nil {
				t.Fatalf("start: %v", err)
			}
		}
	}

	sum, err := store.SummarizeByMachine(ctx, tid, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	// Both have count 2 (a tie); the seedGroupMachine 'HOST' machine has 0 sessions so it does not appear.
	// Byte order: 'Zebra' before 'apple'.
	if len(sum) != 2 || sum[0].MachineName != "Zebra" || sum[0].Count != 2 ||
		sum[1].MachineName != "apple" || sum[1].Count != 2 {
		t.Fatalf("tie-break order = %+v, want Zebra(2) before apple(2) — byte order Z<a", sum)
	}
}
