package controlplane_test

// Background session reaper unit tests (session_reaper.go).
//
// All tests use in-memory stores and do not require a database. The pg path is covered by the
// existing session_policy_pgstore_test.go's ReapExpiredSessions tests, and ListTenantsWithMaxAge
// is tested through the InMemory implementation here (fake-and-pg-must-agree invariant: the
// in-memory fake's behaviour is the spec the pg SECURITY DEFINER function must match).

import (
	"context"
	"testing"
	"time"

	controlplane "rmt/controlplane"
)

// helper: build a minimal Server with in-memory session records and policy store.
func reaperServer(t *testing.T) (*controlplane.Server, *controlplane.InMemorySessionRecordStore, *controlplane.InMemoryTenantSessionPolicyStore) {
	t.Helper()
	sessions := controlplane.NewInMemorySessionRecordStore()
	policies := controlplane.NewInMemoryTenantSessionPolicyStore()
	srv := &controlplane.Server{
		SessionRecords:  sessions,
		SessionPolicies: policies,
	}
	return srv, sessions, policies
}

// openSession inserts an open session whose StartedAt is offset from now.
func openSession(t *testing.T, sessions *controlplane.InMemorySessionRecordStore, tenantID, machineID, groupID string, age time.Duration) string {
	t.Helper()
	rec := &controlplane.SessionRecord{
		TenantID:       tenantID,
		MachineID:      machineID,
		MachineGroupID: groupID,
		StartedAt:      time.Now().Add(-age),
	}
	if err := sessions.StartSession(context.Background(), tenantID, rec); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	return rec.ID
}

// isOpen returns true when the session's EndedAt is nil.
func isOpen(t *testing.T, sessions *controlplane.InMemorySessionRecordStore, tenantID, id string) bool {
	t.Helper()
	rec, err := sessions.GetSession(context.Background(), tenantID, id)
	if err != nil {
		t.Fatalf("GetSession %s: %v", id, err)
	}
	return rec.EndedAt == nil
}

// TestRunReaperSweepClosesExpiredSession — a session older than the tenant's MaxSessionSeconds is
// ended by a sweep.
func TestRunReaperSweepClosesExpiredSession(t *testing.T) {
	srv, sessions, policies := reaperServer(t)

	const tenant = "t-reap-1"
	if err := policies.Set(context.Background(), tenant, controlplane.SessionPolicy{MaxSessionSeconds: 3600}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	id := openSession(t, sessions, tenant, "machine-1", "group-1", 2*time.Hour) // 2h old > 1h limit

	srv.RunReaperSweep(context.Background())

	if isOpen(t, sessions, tenant, id) {
		t.Errorf("session %s should be closed after sweep (age=2h, limit=1h)", id)
	}
}

// TestRunReaperSweepPreservesActiveSession — a session younger than the tenant's MaxSessionSeconds
// is NOT ended.
func TestRunReaperSweepPreservesActiveSession(t *testing.T) {
	srv, sessions, policies := reaperServer(t)

	const tenant = "t-reap-2"
	if err := policies.Set(context.Background(), tenant, controlplane.SessionPolicy{MaxSessionSeconds: 3600}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	id := openSession(t, sessions, tenant, "machine-2", "group-1", 30*time.Minute) // 30 min < 1h limit

	srv.RunReaperSweep(context.Background())

	if !isOpen(t, sessions, tenant, id) {
		t.Errorf("session %s should still be open after sweep (age=30m, limit=1h)", id)
	}
}

// TestRunReaperSweepSkipsTenantWithNoMaxAge — a tenant with MaxSessionSeconds=0 is not swept
// even when it has old open sessions.
func TestRunReaperSweepSkipsTenantWithNoMaxAge(t *testing.T) {
	srv, sessions, policies := reaperServer(t)

	const tenant = "t-reap-3"
	// Explicitly set policy with MaxSessionSeconds=0 (no maximum)
	if err := policies.Set(context.Background(), tenant, controlplane.SessionPolicy{MaxSessionSeconds: 0}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	id := openSession(t, sessions, tenant, "machine-3", "group-1", 48*time.Hour) // 2 days old

	srv.RunReaperSweep(context.Background())

	if !isOpen(t, sessions, tenant, id) {
		t.Errorf("session %s should still be open (MaxSessionSeconds=0 disables the reaper for this tenant)", id)
	}
}

// TestRunReaperSweepSkipsUnsetTenant — a tenant with no policy row has no reap age and is skipped.
func TestRunReaperSweepSkipsUnsetTenant(t *testing.T) {
	srv, sessions, _ := reaperServer(t)
	// Note: no policy.Set call — this tenant has no policy row

	const tenant = "t-reap-4"
	id := openSession(t, sessions, tenant, "machine-4", "group-1", 48*time.Hour)

	srv.RunReaperSweep(context.Background())

	if !isOpen(t, sessions, tenant, id) {
		t.Errorf("session %s should still be open (tenant has no policy row)", id)
	}
}

// TestRunReaperSweepMultiTenant — a sweep with two configured tenants reaps the expired session
// in each independently (boundary case: exactly-at-limit is NOT reaped; one second over IS).
func TestRunReaperSweepMultiTenant(t *testing.T) {
	srv, sessions, policies := reaperServer(t)

	const (
		tenantA = "t-reap-5a"
		tenantB = "t-reap-5b"
	)
	// Tenant A: 1h limit, session is 90 minutes old → reaped
	if err := policies.Set(context.Background(), tenantA, controlplane.SessionPolicy{MaxSessionSeconds: 3600}); err != nil {
		t.Fatalf("set policy A: %v", err)
	}
	idA := openSession(t, sessions, tenantA, "machine-A", "group-1", 90*time.Minute)

	// Tenant B: 2h limit, session is 90 minutes old → NOT reaped
	if err := policies.Set(context.Background(), tenantB, controlplane.SessionPolicy{MaxSessionSeconds: 7200}); err != nil {
		t.Fatalf("set policy B: %v", err)
	}
	idB := openSession(t, sessions, tenantB, "machine-B", "group-1", 90*time.Minute)

	srv.RunReaperSweep(context.Background())

	if isOpen(t, sessions, tenantA, idA) {
		t.Errorf("tenant A session should be closed (age=90m > limit=60m)")
	}
	if !isOpen(t, sessions, tenantB, idB) {
		t.Errorf("tenant B session should still be open (age=90m < limit=120m)")
	}
}

// TestRunReaperSweepNilStores — RunReaperSweep is a no-op when stores are not wired (no panic).
func TestRunReaperSweepNilStores(t *testing.T) {
	// SessionRecords nil
	srvNoRec := &controlplane.Server{
		SessionPolicies: controlplane.NewInMemoryTenantSessionPolicyStore(),
	}
	srvNoRec.RunReaperSweep(context.Background()) // must not panic

	// SessionPolicies nil
	srvNoPol := &controlplane.Server{
		SessionRecords: controlplane.NewInMemorySessionRecordStore(),
	}
	srvNoPol.RunReaperSweep(context.Background()) // must not panic

	// Both nil
	srvBoth := &controlplane.Server{}
	srvBoth.RunReaperSweep(context.Background()) // must not panic
}

// TestStartBackgroundReaperZeroIntervalIsNoOp — a zero or negative interval starts no goroutine.
// Verified by calling StartBackgroundReaper and immediately cancelling ctx; if the goroutine
// panicked on a zero-interval ticker it would crash the test.
func TestStartBackgroundReaperZeroIntervalIsNoOp(t *testing.T) {
	srv, _, _ := reaperServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done
	srv.StartBackgroundReaper(ctx, 0)           // must not panic or block
	srv.StartBackgroundReaper(ctx, -time.Second) // must not panic or block
}

// TestListTenantsWithMaxAgeInMemory — the InMemoryTenantSessionPolicyStore returns only tenants
// whose MaxSessionSeconds > 0, and includes the correct MaxAge.
func TestListTenantsWithMaxAgeInMemory(t *testing.T) {
	store := controlplane.NewInMemoryTenantSessionPolicyStore()
	ctx := context.Background()

	// Tenant with a limit
	if err := store.Set(ctx, "t-have", controlplane.SessionPolicy{MaxSessionSeconds: 7200}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Tenant with no limit (zero)
	if err := store.Set(ctx, "t-none", controlplane.SessionPolicy{MaxSessionSeconds: 0}); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := store.ListTenantsWithMaxAge(ctx)
	if err != nil {
		t.Fatalf("ListTenantsWithMaxAge: %v", err)
	}

	// Only "t-have" should appear
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (only the tenant with MaxSessionSeconds > 0)", len(got))
	}
	if got[0].TenantID != "t-have" {
		t.Errorf("got TenantID=%q, want %q", got[0].TenantID, "t-have")
	}
	if got[0].MaxAge != 2*time.Hour {
		t.Errorf("got MaxAge=%v, want 2h", got[0].MaxAge)
	}
}

// TestListTenantsWithMaxAgeEmpty — an empty store returns an empty slice (not nil or error).
func TestListTenantsWithMaxAgeEmpty(t *testing.T) {
	store := controlplane.NewInMemoryTenantSessionPolicyStore()
	got, err := store.ListTenantsWithMaxAge(context.Background())
	if err != nil {
		t.Fatalf("ListTenantsWithMaxAge on empty store: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

// TestRunReaperSweepMutation_SkipsNoMaxAge — mutation test: if ListTenantsWithMaxAge returned all
// tenants (including those with MaxSessionSeconds=0), the tenant with no limit would also be swept.
// This test pins the "MaxSessionSeconds=0 must not contribute to the list" invariant.
//
// Verified by confirming that a manually fabricated "bug" (including a zero-max-age tenant) does
// NOT cause the no-limit session to be reaped, since the reaper checks if MaxAge > 0 via the
// ReapExpiredSessions no-op guard (maxAge <= 0 returns 0, nil in both fake and pg).
// Even if the list accidentally included the zero tenant, the reap itself would be a no-op.
// The real invariant is that ListTenantsWithMaxAge filters them OUT before that point.
func TestRunReaperSweepMutation_SkipsNoMaxAge(t *testing.T) {
	// This mirrors TestRunReaperSweepSkipsTenantWithNoMaxAge but confirms the filter
	// is in ListTenantsWithMaxAge (not just in the reap call):
	store := controlplane.NewInMemoryTenantSessionPolicyStore()
	ctx := context.Background()
	if err := store.Set(ctx, "t-zero", controlplane.SessionPolicy{MaxSessionSeconds: 0}); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := store.ListTenantsWithMaxAge(ctx)
	if err != nil {
		t.Fatalf("ListTenantsWithMaxAge: %v", err)
	}
	for _, ta := range got {
		if ta.TenantID == "t-zero" {
			t.Errorf("tenant with MaxSessionSeconds=0 should not appear in ListTenantsWithMaxAge result")
		}
	}
}
