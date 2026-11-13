package controlplane

// Proofs for the §5/§7 Sessions-LIST date filter (ListSessions gains a SessionSummaryFilter + GET
// /sessions?since=&until=): a CLOSED [since, until] window on the session START narrows the list (fake + pg
// under RLS), a zero-value filter is all-time, and a malformed timestamp is a 400 that produces NO list body.
// Reuses the loop-74 SessionSummaryFilter / parseSinceUntil / nullableTimes so the list and the reports share
// one range syntax. (`day(d)` helper lives in session_summary_filter_test.go, same package.)

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

func TestInMemoryListSessionsDateFilter(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionRecordStore()
	start := func(at time.Time) {
		if err := s.StartSession(ctx, "t1", &SessionRecord{
			MachineID: "m", MachineGroupID: "g", TechnicianID: "u", StartedAt: at,
		}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	start(day(1))
	start(day(2))
	start(day(3))

	// Zero filter → all 3, most recent (day 3) first.
	all, _ := s.ListSessions(ctx, "t1", SessionSummaryFilter{})
	if len(all) != 3 || !all[0].StartedAt.Equal(day(3)) {
		t.Fatalf("all-time list = %d rows (first=%v), want 3 with day-3 first", len(all), all)
	}
	// [day2, day2+23h] → ONLY the day-2 session (day 1 before Since, day 3 after Until).
	win := SessionSummaryFilter{Since: day(2), Until: day(2).Add(23 * time.Hour)}
	m2, _ := s.ListSessions(ctx, "t1", win)
	if len(m2) != 1 || !m2[0].StartedAt.Equal(day(2)) {
		t.Fatalf("windowed list = %+v, want only day 2", m2)
	}
	// A window entirely BEFORE the sessions → nothing.
	if none, _ := s.ListSessions(ctx, "t1", SessionSummaryFilter{Until: day(1).Add(-time.Hour)}); len(none) != 0 {
		t.Fatalf("pre-window list = %+v, want empty", none)
	}
}

func TestListSessionsDateFilterHandler(t *testing.T) {
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
	count := func(rec *httptest.ResponseRecorder) int {
		var r struct {
			Sessions []SessionRecord `json:"sessions"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return len(r.Sessions)
	}

	if n := count(get("/sessions")); n != 3 {
		t.Fatalf("unfiltered list = %d, want 3", n)
	}
	sinceQ := url.QueryEscape(day(2).Format(time.RFC3339))
	untilQ := url.QueryEscape(day(2).Add(23 * time.Hour).Format(time.RFC3339))
	if n := count(get("/sessions?since=" + sinceQ + "&until=" + untilQ)); n != 1 {
		t.Fatalf("windowed list = %d, want 1", n)
	}

	// A malformed since → 400 AND no session-list body (writeError already set 400, so a handler that WRONGLY
	// proceeded to list would still read 400 — only the absence of "sessions" in the body betrays it; the
	// loop-54 writeError-then-writeJSON trap).
	badRec := get("/sessions?since=notatimestamp")
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad since = %d, want 400", badRec.Code)
	}
	if strings.Contains(badRec.Body.String(), "sessions") {
		t.Fatalf("bad-since response produced a session list: %s", badRec.Body.String())
	}
}

// TestPgListSessionsDateFilterUnderRLS drives the pg WHERE on ListSessions: zero filter = all-time, an Until in
// the past excludes every ~now session, a wide [past, future] includes them all.
func TestPgListSessionsDateFilterUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	tid, uid := provisionUser(t, suPool, "slf", "s@slf.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tid, "dev-slf")
	ctx := context.Background()
	store := NewPgSessionRecordStore(newAppRolePool(t, ctx))
	for i := 0; i < 3; i++ {
		if err := store.StartSession(ctx, tid, &SessionRecord{MachineID: mid, TechnicianID: uid}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	n := func(f SessionSummaryFilter) int {
		list, err := store.ListSessions(ctx, tid, f)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		return len(list)
	}
	if got := n(SessionSummaryFilter{}); got != 3 {
		t.Fatalf("all-time = %d, want 3", got)
	}
	if got := n(SessionSummaryFilter{Until: past}); got != 0 {
		t.Fatalf("until-past = %d, want 0 (all ~now sessions excluded)", got)
	}
	if got := n(SessionSummaryFilter{Since: past, Until: future}); got != 3 {
		t.Fatalf("wide-window = %d, want 3", got)
	}
}
