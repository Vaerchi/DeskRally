package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestInMemoryMgmtAuditFilter pins the fake's audit-search behaviour to the pg store's
// (TestPgMgmtAuditFilter): exact-match action/target_kind, applied BEFORE the limit so a newer
// non-matching event never consumes a limit slot.
func TestInMemoryMgmtAuditFilter(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMgmtAuditStore()
	const tid = "tenant-1"
	for _, e := range []MgmtAuditEvent{
		{Action: "machine.enroll", TargetKind: "machine"},
		{Action: "session.start", TargetKind: "session"},
		{Action: "machine.enroll", TargetKind: "machine"},
		{Action: "tenant.update", TargetKind: "tenant"}, // newest, non-machine on purpose
	} {
		ev := e
		if err := s.RecordEvent(ctx, tid, &ev); err != nil {
			t.Fatalf("record %s: %v", e.Action, err)
		}
	}
	n := func(f AuditFilter, limit int) int {
		got, err := s.ListEventsFiltered(ctx, tid, limit, f)
		if err != nil {
			t.Fatalf("filtered %+v: %v", f, err)
		}
		return len(got)
	}
	if n(AuditFilter{}, 0) != 4 {
		t.Fatal("no filter must list all 4")
	}
	if n(AuditFilter{Action: "machine.enroll"}, 0) != 2 {
		t.Fatal("action=machine.enroll must be 2")
	}
	if n(AuditFilter{TargetKind: "machine"}, 0) != 2 {
		t.Fatal("target_kind=machine must be 2")
	}
	if n(AuditFilter{Action: "session.start", TargetKind: "machine"}, 0) != 0 {
		t.Fatal("mismatched action+kind must be 0")
	}
	// The newest event is tenant.update; a session filter with limit 1 must still return the older
	// session event (limit applies after the filter, not before).
	if n(AuditFilter{TargetKind: "session"}, 1) != 1 {
		t.Fatal("limit must apply AFTER the filter")
	}
}

// TestInMemoryMgmtAuditFilterActorAndTime pins the fake's actor + time-range filtering to the pg
// store's (TestPgMgmtAuditFilterActorAndTime): exact actor match and a CLOSED [Since, Until] range,
// with inclusive boundaries, applied before the limit.
func TestInMemoryMgmtAuditFilterActorAndTime(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMgmtAuditStore()
	const tid = "tenant-1"
	t0 := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	seed := func(actor string, at time.Time) {
		ev := MgmtAuditEvent{Action: "x", TargetKind: "machine", ActorUserID: actor, OccurredAt: at}
		if err := s.RecordEvent(ctx, tid, &ev); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	seed("alice", t0)                  // oldest
	seed("bob", t0.Add(1*time.Hour))   // middle
	seed("alice", t0.Add(2*time.Hour)) // newest
	n := func(f AuditFilter) int {
		got, err := s.ListEventsFiltered(ctx, tid, 0, f)
		if err != nil {
			t.Fatalf("filtered %+v: %v", f, err)
		}
		return len(got)
	}
	if n(AuditFilter{Actor: "alice"}) != 2 {
		t.Fatal("actor=alice must be 2")
	}
	if n(AuditFilter{Actor: "carol"}) != 0 {
		t.Fatal("unknown actor must be 0")
	}
	// Since is INCLUSIVE: at or after t0+1h → bob + newest alice = 2.
	if n(AuditFilter{Since: t0.Add(1 * time.Hour)}) != 2 {
		t.Fatal("since (inclusive) must be 2")
	}
	// Until is INCLUSIVE: at or before t0+1h → oldest alice + bob = 2.
	if n(AuditFilter{Until: t0.Add(1 * time.Hour)}) != 2 {
		t.Fatal("until (inclusive) must be 2")
	}
	// A closed range collapsed to one instant returns exactly the event at that instant (bob).
	if n(AuditFilter{Since: t0.Add(1 * time.Hour), Until: t0.Add(1 * time.Hour)}) != 1 {
		t.Fatal("closed single-instant range must be 1 (both bounds inclusive)")
	}
	// Actor AND time compose: alice at or after t0+2h → the newest alice only.
	if n(AuditFilter{Actor: "alice", Since: t0.Add(2 * time.Hour)}) != 1 {
		t.Fatal("actor+since must be 1")
	}
	// An inverted range (since after until) matches nothing.
	if n(AuditFilter{Since: t0.Add(2 * time.Hour), Until: t0}) != 0 {
		t.Fatal("inverted range must be 0")
	}
}

// TestHandleListAuditActorAndTimeFilter drives GET /audit?actor=&since=&until= through the real HTTP
// chain: the actor and RFC3339 time bounds narrow the trail, and a malformed timestamp is a 400 (not
// a silent unbounded listing).
func TestHandleListAuditActorAndTimeFilter(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	t0 := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	rec := func(actor string, at time.Time) {
		if err := srv.MgmtAudit.RecordEvent(ctx, "tenant-123",
			&MgmtAuditEvent{Action: "x", TargetKind: "machine", ActorUserID: actor, OccurredAt: at}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	rec("alice", t0)
	rec("bob", t0.Add(1*time.Hour))
	rec("alice", t0.Add(2*time.Hour))

	body := func(query string) (int, string) {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/audit"+query, nil))
		return w.Code, w.Body.String()
	}
	ok := func(query string) string {
		code, b := body(query)
		if code != http.StatusOK {
			t.Fatalf("GET /audit%s = %d (%s)", query, code, b)
		}
		return b
	}

	// ?actor=alice → the 2 alice events, none by bob.
	if b := ok("?actor=alice"); strings.Count(b, `"alice"`) != 2 || strings.Contains(b, `"bob"`) {
		t.Fatalf("?actor=alice = %s", b)
	}
	// ?since= (RFC3339), inclusive: at or after t0+1h → 2 events.
	if b := ok("?since=" + t0.Add(1*time.Hour).Format(time.RFC3339)); strings.Count(b, `"actor_user_id"`) != 2 {
		t.Fatalf("?since = %s", b)
	}
	// ?until=, inclusive: at or before t0+1h → 2 events.
	if b := ok("?until=" + t0.Add(1*time.Hour).Format(time.RFC3339)); strings.Count(b, `"actor_user_id"`) != 2 {
		t.Fatalf("?until = %s", b)
	}
	// Actor AND range compose: alice at or after t0+2h → 1.
	if b := ok("?actor=alice&since=" + t0.Add(2*time.Hour).Format(time.RFC3339)); strings.Count(b, `"actor_user_id"`) != 1 {
		t.Fatalf("?actor+since = %s", b)
	}
	// A malformed since/until is a 400, never a silently-unbounded listing.
	for _, q := range []string{"?since=not-a-time", "?until=2026-13-40T99:99:99Z"} {
		if code, b := body(q); code != http.StatusBadRequest {
			t.Fatalf("GET /audit%s = %d, want 400 (%s)", q, code, b)
		}
	}
}

// TestHandleListAuditFilter drives GET /audit?action=…&target_kind=… through the real HTTP chain and
// asserts the response narrows to the matching events.
func TestHandleListAuditFilter(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	rec := func(action, kind string) {
		if err := srv.MgmtAudit.RecordEvent(ctx, "tenant-123", &MgmtAuditEvent{Action: action, TargetKind: kind}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	rec("machine.enroll", "machine")
	rec("session.start", "session")
	rec("machine.enroll", "machine")

	body := func(query string) string {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/audit"+query, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /audit%s = %d (%s)", query, w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	// Unfiltered: both actions present, 2 enroll events.
	if b := body(""); !strings.Contains(b, "session.start") || strings.Count(b, `"machine.enroll"`) != 2 {
		t.Fatalf("unfiltered = %s", b)
	}
	// ?action=machine.enroll: 2 enroll events, NO session.start.
	if b := body("?action=machine.enroll"); strings.Contains(b, "session.start") || strings.Count(b, `"machine.enroll"`) != 2 {
		t.Fatalf("?action=machine.enroll = %s", b)
	}
	// ?target_kind=session: only the session event, NO machine.enroll.
	if b := body("?target_kind=session"); !strings.Contains(b, "session.start") || strings.Contains(b, "machine.enroll") {
		t.Fatalf("?target_kind=session = %s", b)
	}
	// A value nobody has → an empty events array.
	if b := body("?action=nope.never"); !strings.Contains(b, `"events":[]`) {
		t.Fatalf("absent action should give empty events: %s", b)
	}
}
