package controlplane

// DB-gated proofs for §5 seat metering, driven as the least-privilege rmt_app role RLS is enforced
// against: the per-tenant policy store (Get/Set upsert, cross-tenant isolation) and — the crux — that
// PgSessionRecordStore.StartSessionWithinLimit enforces the cap ATOMICALLY under concurrency, so a burst
// of parallel starts cannot each read "under the limit" and all win. Needs TEST_DATABASE_URL;
// scripts/verify-all.ps1 sets it and treats a skip as a failure.

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyTenantSessionPolicyMigration lays 0029 on top of the schema newTestPool applied; resetSchema
// DROPs tenant_session_policy, so this is re-runnable.
func applyTenantSessionPolicyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, f := range []string{
		"migrations/0029_tenant_session_policy.sql",
		"migrations/0030_tenant_session_max_age.sql", // ALTER: adds max_session_seconds
		"migrations/0083_tenant_session_binding.sql", // ALTER: adds session_binding (docs/69 step 4)
		"migrations/0086_tenant_default_idle.sql",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		execScript(t, pool, string(b))
	}
}

func TestPgTenantSessionPolicyUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantSessionPolicyMigration(t, suPool)
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "sp-a", "a@sp-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "sp-b", "b@sp-b.test", "password-1234")

	appPool := newAppRolePool(t, ctx)
	store := NewPgTenantSessionPolicyStore(appPool)

	// Unset → the zero policy (unlimited), no row.
	if p, err := store.Get(ctx, tidA); err != nil || p.MaxConcurrentSessions != 0 {
		t.Fatalf("unset A = (%+v, %v), want 0", p, err)
	}
	// Upsert insert, then update. An omitted idle timeout preserves the stored setting.
	idle := 900
	if err := store.Set(ctx, tidA, SessionPolicy{MaxConcurrentSessions: 5, MaxSessionSeconds: 3600, DefaultMaxIdleSeconds: &idle}); err != nil {
		t.Fatalf("Set A insert: %v", err)
	}
	if p, _ := store.Get(ctx, tidA); p.MaxConcurrentSessions != 5 || p.MaxSessionSeconds != 3600 || p.DefaultMaxIdleSeconds == nil || *p.DefaultMaxIdleSeconds != 900 {
		t.Fatalf("A after insert = %+v, want limit 5, duration 3600, idle 900", p)
	}
	if err := store.Set(ctx, tidA, SessionPolicy{MaxConcurrentSessions: 2}); err != nil {
		t.Fatalf("Set A update: %v", err)
	}
	if p, err := store.Get(ctx, tidA); err != nil || p.MaxConcurrentSessions != 2 || p.DefaultMaxIdleSeconds == nil || *p.DefaultMaxIdleSeconds != 900 {
		t.Fatalf("A after update = (%+v, %v), want limit 2 and idle 900", p, err)
	}
	invalid := MaxGroupIdleSeconds + 1
	if err := store.Set(ctx, tidA, SessionPolicy{DefaultMaxIdleSeconds: &invalid}); err == nil {
		t.Fatal("database accepted out-of-range idle timeout")
	}
	zero := 0
	if err := store.Set(ctx, tidA, SessionPolicy{MaxConcurrentSessions: 2, DefaultMaxIdleSeconds: &zero}); err != nil {
		t.Fatalf("clear idle: %v", err)
	}
	if p, err := store.Get(ctx, tidA); err != nil || p.DefaultMaxIdleSeconds == nil || *p.DefaultMaxIdleSeconds != 0 {
		t.Fatalf("A after clear = (%+v, %v), want idle 0", p, err)
	}
	// An insert that leaves the column to PostgreSQL gets the migration's default.
	if err := withTenant(ctx, appPool, tidB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO tenant_session_policy (tenant_id) VALUES ($1)", tidB)
		return err
	}); err != nil {
		t.Fatalf("insert B with column defaults: %v", err)
	}
	if p, err := store.Get(ctx, tidB); err != nil || p.MaxConcurrentSessions != 0 || p.DefaultMaxIdleSeconds == nil || *p.DefaultMaxIdleSeconds != 0 {
		t.Fatalf("B = (%+v, %v), want limit 0 and idle 0", p, err)
	}
	if err := store.Set(ctx, tidB, SessionPolicy{MaxConcurrentSessions: 9}); err != nil {
		t.Fatalf("Set B: %v", err)
	}
	if p, _ := store.Get(ctx, tidA); p.MaxConcurrentSessions != 2 {
		t.Fatalf("A after B's write = %+v, want 2 (isolation)", p)
	}
}

// TestPgStartSessionWithinLimitAtomic is the atomicity proof: with a cap of K, firing N > K parallel
// StartSessionWithinLimit calls must leave EXACTLY K open sessions — the pg_advisory_xact_lock is what
// serializes the count-then-insert so the others get ErrConcurrentSessionLimit instead of overshooting.
func TestPgStartSessionWithinLimitAtomic(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: machine projection the session join needs
	tid, uid := provisionUser(t, suPool, "sp-atomic", "t@sp-atomic.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tid, "atomic-dev")
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)

	const N, K = 8, 3
	var wg sync.WaitGroup
	results := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := &SessionRecord{MachineID: mid, TechnicianID: uid}
			results[i] = store.StartSessionWithinLimit(ctx, tid, rec, SessionStartLimits{Tenant: K})
		}(i)
	}
	wg.Wait()

	ok, limited, other := 0, 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case err == ErrConcurrentSessionLimit:
			limited++
		default:
			other++
		}
	}
	if other != 0 {
		t.Fatalf("%d starts failed with an unexpected error: %v", other, results)
	}
	if ok != K || limited != N-K {
		t.Fatalf("concurrent starts: %d succeeded, %d limited; want %d succeeded, %d limited "+
			"(a non-atomic count+insert would let more than %d through)", ok, limited, K, N-K, K)
	}
	// And the database agrees: exactly K open sessions exist.
	list, err := store.ListSessions(ctx, tid, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	open := 0
	for _, s := range list {
		if s.EndedAt == nil {
			open++
		}
	}
	if open != K {
		t.Fatalf("open sessions in DB = %d, want %d", open, K)
	}
}

// TestPgReapExpiredSessions drives PgSessionRecordStore.ReapExpiredSessions as rmt_app: an OPEN session
// older than maxAge is ended, a recent one is left, the count is right, it is idempotent and RLS-scoped.
func TestPgReapExpiredSessions(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: machine projection the session join needs
	tid, uid := provisionUser(t, suPool, "reap", "t@reap.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tid, "reap-dev")
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)

	oldRec := &SessionRecord{MachineID: mid, TechnicianID: uid}
	recentRec := &SessionRecord{MachineID: mid, TechnicianID: uid}
	if err := store.StartSession(ctx, tid, oldRec); err != nil {
		t.Fatalf("start old: %v", err)
	}
	if err := store.StartSession(ctx, tid, recentRec); err != nil {
		t.Fatalf("start recent: %v", err)
	}
	// Backdate the "old" one 2h (the pg StartSession always stamps started_at = now()).
	if err := withTenant(ctx, appPool, tid, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE session_record SET started_at = now() - interval '2 hours' WHERE id = $1`, oldRec.ID)
		return e
	}); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// maxAge <= 0 is a no-op.
	if n, _ := store.ReapExpiredSessions(ctx, tid, 0); n != 0 {
		t.Fatalf("reap(0) = %d, want 0", n)
	}
	// 1h: only the 2h-old open session is ended.
	n, err := store.ReapExpiredSessions(ctx, tid, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("reap(1h) = (%d, %v), want 1", n, err)
	}
	if got, _ := store.GetSession(ctx, tid, oldRec.ID); got.EndedAt == nil {
		t.Fatalf("old session not ended")
	}
	if got, _ := store.GetSession(ctx, tid, recentRec.ID); got.EndedAt != nil {
		t.Fatalf("recent session wrongly reaped")
	}
	// Idempotent: nothing left to reap.
	if n2, _ := store.ReapExpiredSessions(ctx, tid, time.Hour); n2 != 0 {
		t.Fatalf("second reap = %d, want 0", n2)
	}
}

// docs/69 step 4: the binding mode round-trips, an unset tenant reads as warn, and the CHECK refuses anything else.
func TestPgTenantSessionBindingMode(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantSessionPolicyMigration(t, suPool)
	ctx := context.Background()
	tidA, _ := provisionUser(t, suPool, "sb-a", "a@sb-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "sb-b", "b@sb-b.test", "password-1234")
	store := NewPgTenantSessionPolicyStore(newAppRolePool(t, ctx))

	if p, err := store.Get(ctx, tidA); err != nil || p.SessionBinding != "" {
		t.Fatalf("unset A = (%+v, %v), want no binding value (reads as warn)", p, err)
	}
	if err := store.Set(ctx, tidA, SessionPolicy{SessionBinding: "require"}); err != nil {
		t.Fatalf("Set require: %v", err)
	}
	if p, _ := store.Get(ctx, tidA); p.SessionBinding != "require" {
		t.Fatalf("A = %+v, want require", p)
	}
	// An empty mode is stored as warn (bindingOrWarn), never as an empty string the CHECK would refuse.
	if err := store.Set(ctx, tidB, SessionPolicy{MaxConcurrentSessions: 0}); err != nil {
		t.Fatalf("Set B with no mode: %v", err)
	}
	if p, _ := store.Get(ctx, tidB); p.SessionBinding != "warn" {
		t.Fatalf("B = %+v, want warn", p)
	}
	if p, _ := store.Get(ctx, tidA); p.SessionBinding != "require" {
		t.Fatalf("A after B's write = %+v, want require (isolation)", p)
	}
	// An omitted mode KEEPS the stored one, atomically in the upsert (Codex bindmode r1).
	if err := store.Set(ctx, tidA, SessionPolicy{MaxConcurrentSessions: 3, MaxSessionSeconds: 600}); err != nil {
		t.Fatalf("Set A limits only: %v", err)
	}
	if p, _ := store.Get(ctx, tidA); p.SessionBinding != "require" || p.MaxConcurrentSessions != 3 {
		t.Fatalf("A after a limits-only write = %+v, want require kept and limit 3", p)
	}
	if err := store.Set(ctx, tidA, SessionPolicy{SessionBinding: "maybe"}); err == nil {
		t.Fatal("an unknown mode must be refused by the column CHECK")
	}
}
