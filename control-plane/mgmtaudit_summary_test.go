package controlplane

// Proofs for the §5 Reports audit summary (SummarizeByAction): the store (fake + pg under RLS) and the
// HTTP surface (GET /audit/summary — CapViewAudit + the shared filter parsing + grouped counts).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInMemoryMgmtAuditSummary(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMgmtAuditStore()
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	rec := func(tid, actor, action string, at time.Time) {
		if err := s.RecordEvent(ctx, tid, &MgmtAuditEvent{ActorUserID: actor, Action: action, OccurredAt: at}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	rec("t1", "u1", "machine.enroll", base)
	rec("t1", "u1", "session.start", base.Add(time.Hour))
	rec("t1", "u2", "machine.enroll", base.Add(2*time.Hour))
	rec("t1", "u1", "machine.enroll", base.Add(3*time.Hour))
	rec("t2", "u9", "machine.enroll", base) // another tenant — must not leak into t1's counts

	// Whole tenant: machine.enroll (3) before session.start (1) — count DESC.
	sum, err := s.SummarizeByAction(ctx, "t1", AuditFilter{})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if len(sum) != 2 || sum[0].Action != "machine.enroll" || sum[0].Count != 3 || sum[1].Action != "session.start" || sum[1].Count != 1 {
		t.Fatalf("summary = %+v, want machine.enroll:3, session.start:1", sum)
	}

	// Actor filter: only u1 (2x machine.enroll + 1x session.start).
	if u1, _ := s.SummarizeByAction(ctx, "t1", AuditFilter{Actor: "u1"}); len(u1) != 2 || u1[0].Action != "machine.enroll" || u1[0].Count != 2 {
		t.Fatalf("actor=u1 summary = %+v, want machine.enroll:2, session.start:1", u1)
	}

	// Closed time range [base+1h, base+2h] (inclusive): session.start (base+1h) + machine.enroll (base+2h),
	// 1 each → count-tie broken by action ASC.
	rng, _ := s.SummarizeByAction(ctx, "t1", AuditFilter{Since: base.Add(time.Hour), Until: base.Add(2 * time.Hour)})
	if len(rng) != 2 || rng[0].Action != "machine.enroll" || rng[0].Count != 1 || rng[1].Action != "session.start" {
		t.Fatalf("time-range summary = %+v, want machine.enroll:1, session.start:1 (action ASC tie-break)", rng)
	}
}

func TestAuditSummaryHandler(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	for _, a := range []string{"machine.enroll", "machine.enroll", "session.start"} {
		if err := srv.MgmtAudit.RecordEvent(ctx, "tenant-123", &MgmtAuditEvent{ActorUserID: "u1", Action: a}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	h := srv.Handler()
	get := func(hh http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	rec := get(h, "/audit/summary")
	if rec.Code != http.StatusOK {
		t.Fatalf("summary = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var sr struct {
		Summary []AuditActionCount `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sr.Summary) != 2 || sr.Summary[0].Action != "machine.enroll" || sr.Summary[0].Count != 2 {
		t.Fatalf("summary = %+v, want machine.enroll:2 first", sr.Summary)
	}

	// A malformed timestamp → a CLEAN 400 (the shared parseAuditFilter): the handler must STOP, not
	// write the error and then ALSO proceed to a summary body (a double-write). Asserting the body
	// carries no "summary" catches a parse guard that 400s but forgets to return.
	if rec := get(h, "/audit/summary?since=notatime"); rec.Code != http.StatusBadRequest ||
		strings.Contains(rec.Body.String(), "summary") {
		t.Fatalf("bad since = %d body %q, want a clean 400 with no summary body", rec.Code, rec.Body.String())
	}
	// GATE: a Technician holds no CapViewAudit → 403.
	techSrv, _ := newTestServer(&Principal{UserID: "u2", TenantID: "tenant-123",
		Grant: NewGrant("u2", "tenant-123", NewMembership(RoleTechnician, AllGroups()))})
	if rec := get(techSrv.Handler(), "/audit/summary"); rec.Code != http.StatusForbidden {
		t.Fatalf("technician summary = %d, want 403", rec.Code)
	}
}

// TestPgMgmtAuditSummaryUnderRLS drives PgMgmtAuditStore.SummarizeByAction as rmt_app: grouped counts,
// ordered count DESC, RLS-scoped (another tenant's events do not bleed in), and a non-uuid actor matches
// nothing without erroring.
func TestPgMgmtAuditSummaryUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyMgmtAuditChainMigration(t, suPool)
	applyAppRoleMigration(t, suPool)
	tidA, uidA := provisionUser(t, suPool, "as-a", "a@as-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "as-b", "b@as-b.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgMgmtAuditStore(appPool)

	// Tenant A: machine.enroll x3, session.start x1, tenant.update x1.
	for _, a := range []string{"machine.enroll", "session.start", "machine.enroll", "tenant.update", "machine.enroll"} {
		if err := store.RecordEvent(ctx, tidA, &MgmtAuditEvent{ActorUserID: uidA, Action: a}); err != nil {
			t.Fatalf("record A %s: %v", a, err)
		}
	}
	// Tenant B: machine.enroll x5 — must NOT bleed into A's counts (RLS).
	for i := 0; i < 5; i++ {
		if err := store.RecordEvent(ctx, tidB, &MgmtAuditEvent{Action: "machine.enroll"}); err != nil {
			t.Fatalf("record B: %v", err)
		}
	}

	sum, err := store.SummarizeByAction(ctx, tidA, AuditFilter{})
	if err != nil {
		t.Fatalf("summarize A: %v", err)
	}
	// count DESC, then action ASC. machine.enroll is 3 (NOT 8 — B's 5 excluded).
	if len(sum) != 3 || sum[0].Action != "machine.enroll" || sum[0].Count != 3 {
		t.Fatalf("A summary = %+v, want machine.enroll:3 first (RLS: not 8)", sum)
	}
	if sum[1].Action != "session.start" || sum[1].Count != 1 || sum[2].Action != "tenant.update" || sum[2].Count != 1 {
		t.Fatalf("A tie-break = %+v, want session.start then tenant.update", sum)
	}

	// A non-uuid actor matches nothing (no cast error).
	if s, err := store.SummarizeByAction(ctx, tidA, AuditFilter{Actor: "nobody"}); err != nil || len(s) != 0 {
		t.Fatalf("unknown actor summary = %+v, %v; want empty", s, err)
	}
}
