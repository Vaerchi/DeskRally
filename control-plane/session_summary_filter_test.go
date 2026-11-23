package controlplane

// Proofs for the §5 session-report DATE-RANGE filter (SessionSummaryFilter on SummarizeByMachine /
// SummarizeByTechnician + GET /reports/sessions-by-{machine,technician}?since=&until=): a CLOSED [since,
// until] window on the session START time narrows BOTH reports (fake + pg under RLS), a zero-value filter is
// all-time, and a malformed timestamp is a clean 400. Mirrors the loop-45 audit ?since=/?until= (shared
// parseSinceUntil).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func day(d int) time.Time { return time.Date(2026, 8, d, 0, 0, 0, 0, time.UTC) }

func TestSessionSummaryDateFilter(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	start := func(at time.Time) {
		if err := s.StartSession(ctx, "t1", &SessionRecord{
			MachineID: "m", MachineName: "m", MachineGroupID: "g", TechnicianID: "u", StartedAt: at,
		}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	start(day(1))
	start(day(2))
	start(day(3))

	// Zero filter → all 3 (all-time).
	if all, _ := s.SummarizeByMachine(ctx, "t1", SessionSummaryFilter{}); len(all) != 1 || all[0].Count != 3 {
		t.Fatalf("all-time by-machine = %+v, want count 3", all)
	}
	// [day2, day2+23h] → ONLY the day-2 session (day 1 is before Since, day 3 is after Until).
	win := SessionSummaryFilter{Since: day(2), Until: day(2).Add(23 * time.Hour)}
	if m2, _ := s.SummarizeByMachine(ctx, "t1", win); len(m2) != 1 || m2[0].Count != 1 {
		t.Fatalf("windowed by-machine = %+v, want count 1 (only day 2)", m2)
	}
	// The SAME window narrows the by-TECHNICIAN report too (proving that method also filters).
	techTotal := int64(0)
	sub, _ := s.SummarizeByTechnician(ctx, "t1", win)
	for _, c := range sub {
		techTotal += c.Count
	}
	if techTotal != 1 {
		t.Fatalf("windowed by-technician total = %d, want 1 (only day 2)", techTotal)
	}
	// A window entirely BEFORE the sessions → nothing (an upper bound that excludes all rows).
	if none, _ := s.SummarizeByMachine(ctx, "t1", SessionSummaryFilter{Until: day(1).Add(-time.Hour)}); len(none) != 0 {
		t.Fatalf("pre-window by-machine = %+v, want empty", none)
	}
}

func TestSessionReportDateFilterHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	start := func(at time.Time) {
		if err := srv.SessionRecords.StartSession(ctx, tid, &SessionRecord{
			MachineID: "m", MachineGroupID: "g", TechnicianID: "u", StartedAt: at,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	start(day(1))
	start(day(2))
	start(day(3))

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	countMachine := func(rec *httptest.ResponseRecorder) int64 {
		var r struct {
			Rows []MachineSessionCount `json:"sessions_by_machine"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatalf("decode by-machine: %v", err)
		}
		var n int64
		for _, c := range r.Rows {
			n += c.Count
		}
		return n
	}

	sinceQ := url.QueryEscape(day(2).Format(time.RFC3339))
	untilQ := url.QueryEscape(day(2).Add(23 * time.Hour).Format(time.RFC3339))

	// No filter → 3.
	if got := countMachine(get("/reports/sessions-by-machine")); got != 3 {
		t.Fatalf("unfiltered by-machine total = %d, want 3", got)
	}
	// ?since&until spanning only day 2 → 1.
	if got := countMachine(get("/reports/sessions-by-machine?since=" + sinceQ + "&until=" + untilQ)); got != 1 {
		t.Fatalf("windowed by-machine total = %d, want 1", got)
	}
	// A malformed since → 400 AND no report body. Asserting the body carries no "sessions_by_machine" (not
	// just the status) is load-bearing: writeError already set 400, so a handler that WRONGLY proceeded to
	// produce the report would still read 400 (the superfluous later WriteHeader is ignored) — only the body
	// betrays it (the loop-54 "400-then-double-write" trap).
	badRec := get("/reports/sessions-by-machine?since=notatimestamp")
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad since = %d, want 400", badRec.Code)
	}
	if strings.Contains(badRec.Body.String(), "sessions_by_machine") {
		t.Fatalf("bad-since response produced a report body: %s", badRec.Body.String())
	}

	// The by-TECHNICIAN report honors ?since too: from day 2 onward → 2 sessions (day 2 + day 3).
	var tr struct {
		Rows []TechnicianSessionCount `json:"sessions_by_technician"`
	}
	if err := json.Unmarshal(get("/reports/sessions-by-technician?since="+sinceQ).Body.Bytes(), &tr); err != nil {
		t.Fatalf("decode by-technician: %v", err)
	}
	var techTotal int64
	for _, c := range tr.Rows {
		techTotal += c.Count
	}
	if techTotal != 2 {
		t.Fatalf("since-day2 by-technician total = %d, want 2 (day 2 + day 3)", techTotal)
	}
}

// TestPgSessionSummaryDateFilterUnderRLS drives the pg WHERE ($1 IS NULL OR started_at >= $1) AND ($2 IS
// NULL OR started_at <= $2) on BOTH summary queries: a zero filter is all-time, an Until in the past excludes
// every ~now session, and a wide [past, future] window includes them all.
func TestPgSessionSummaryDateFilterUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	tid, uid := provisionUser(t, suPool, "sdf", "s@sdf.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tid, "dev-sdf")
	ctx := context.Background()
	store := NewPgSessionRecordStore(newAppRolePool(t, ctx))
	for i := 0; i < 3; i++ {
		if err := store.StartSession(ctx, tid, &SessionRecord{MachineID: mid, TechnicianID: uid}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	machineCount := func(f SessionSummaryFilter) int64 {
		rows, err := store.SummarizeByMachine(ctx, tid, f)
		if err != nil {
			t.Fatalf("by-machine: %v", err)
		}
		var n int64
		for _, c := range rows {
			n += c.Count
		}
		return n
	}
	techCount := func(f SessionSummaryFilter) int64 {
		rows, err := store.SummarizeByTechnician(ctx, tid, f)
		if err != nil {
			t.Fatalf("by-technician: %v", err)
		}
		var n int64
		for _, c := range rows {
			n += c.Count
		}
		return n
	}

	if got := machineCount(SessionSummaryFilter{}); got != 3 {
		t.Fatalf("all-time by-machine = %d, want 3", got)
	}
	if got := machineCount(SessionSummaryFilter{Until: past}); got != 0 {
		t.Fatalf("until-past by-machine = %d, want 0 (all ~now sessions excluded)", got)
	}
	if got := machineCount(SessionSummaryFilter{Since: past, Until: future}); got != 3 {
		t.Fatalf("wide-window by-machine = %d, want 3", got)
	}
	// The same WHERE governs the by-technician query.
	if got := techCount(SessionSummaryFilter{Since: past, Until: future}); got != 3 {
		t.Fatalf("wide-window by-technician = %d, want 3", got)
	}
	if got := techCount(SessionSummaryFilter{Until: past}); got != 0 {
		t.Fatalf("until-past by-technician = %d, want 0", got)
	}
}
