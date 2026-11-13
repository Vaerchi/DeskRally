package controlplane

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyTenantIPAllowlistMigration lays 0025 (the tenant_ip_allowlist table + RLS + grant) on top of the
// schema newTestPool built. It GRANTs to rmt_app, so applyAppRoleMigration (0005) MUST run first.
// resetSchema drops tenant_ip_allowlist with the rest, so this re-applies cleanly on a re-run.
func applyTenantIPAllowlistMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0025_tenant_ip_allowlist.sql")
	if err != nil {
		t.Fatalf("read 0025: %v", err)
	}
	execScript(t, pool, string(b))
}

// seedBareTenant inserts a single tenant row (no group/machine — this table only references tenant),
// seeded as the SUPERUSER pool with the tenant pinned so the WITH CHECK is satisfied.
func seedBareTenant(t *testing.T, pool *pgxpool.Pool, tid, slug string) {
	t.Helper()
	if err := withTenant(context.Background(), pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,$2,$2,'self_hosted')`,
			tid, slug)
		return err
	}); err != nil {
		t.Fatalf("seed tenant %s: %v", slug, err)
	}
}

// TestPgTenantIPAllowlistRLSIsolation is the golden proof, run as the RLS-SUBJECT rmt_app role (a
// superuser pool would BYPASS RLS and pass against broken code): a second tenant's pin sees NONE of the
// first's CIDRs, CANNOT insert a row tagged to the first (RLS WITH CHECK), and CANNOT delete the first's
// rows. Positive controls confirm a tenant fully manages its own list.
func TestPgTenantIPAllowlistRLSIsolation(t *testing.T) {
	suPool := newTestPool(t)                 // skips w/o TEST_DATABASE_URL; superuser; 0001-0003 + always-on
	applyAppRoleMigration(t, suPool)         // 0005: creates rmt_app + grants
	applyTenantIPAllowlistMigration(t, suPool) // 0025: the new table + RLS + grant
	ctx := context.Background()

	var tenantA, tenantB string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("gen tenant uuids: %v", err)
	}
	seedBareTenant(t, suPool, tenantA, "ipa-a")
	seedBareTenant(t, suPool, tenantB, "ipa-b")

	appPool := newAppRolePool(t, ctx) // the RLS-subject connection
	store := NewPgTenantIPAllowlistStore(appPool)

	// Tenant A adds two CIDRs; a re-add is idempotent (ON CONFLICT DO NOTHING → still 2, sorted).
	for _, c := range []string{"192.0.2.0/24", "10.0.0.0/8", "192.0.2.0/24"} {
		if err := store.AddCIDR(ctx, tenantA, c); err != nil {
			t.Fatalf("A add %q: %v", c, err)
		}
	}
	if got, err := store.ListCIDRs(ctx, tenantA); err != nil ||
		len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.0.2.0/24" {
		t.Fatalf("A list = %v, %v; want [10.0.0.0/8 192.0.2.0/24] (deduped, sorted)", got, err)
	}

	// (1) READ ISOLATION — tenant B's pin sees NONE of A's CIDRs.
	if got, err := store.ListCIDRs(ctx, tenantB); err != nil || len(got) != 0 {
		t.Fatalf("B list = %v, %v; want 0 rows (RLS must hide tenant A)", got, err)
	}

	// (2) WRITE ISOLATION — a connection pinned to B cannot INSERT a row tagged to tenant A: the RLS
	//     WITH CHECK (tenant_id = current_setting('app.current_tenant')) rejects the mismatched row.
	//     (The store API always pins == inserts the same tenant, so this cross-tenant write is only
	//     reachable by a raw statement, which is exactly what a compromised query would attempt.)
	err := withTenant(ctx, appPool, tenantB, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO tenant_ip_allowlist (tenant_id, cidr) VALUES ($1, $2)`, tenantA, "9.9.9.9/32")
		return e
	})
	if err == nil {
		t.Fatal("pinned-to-B insert tagged to tenant A must be rejected by RLS WITH CHECK")
	}
	if got, _ := store.ListCIDRs(ctx, tenantA); len(got) != 2 {
		t.Fatalf("tenant A now has %d CIDRs, want 2 (B's cross-tenant write must not have landed)", len(got))
	}

	// (3) DELETE ISOLATION — tenant B deleting a CIDR A has (by value) removes NOTHING: RLS hides A's
	//     row from B's pin, so the DELETE matches 0 rows (ErrTenantIPAllowlistEntryNotFound), and A's
	//     row survives.
	if err := store.RemoveCIDR(ctx, tenantB, "10.0.0.0/8"); !errors.Is(err, ErrTenantIPAllowlistEntryNotFound) {
		t.Fatalf("B delete of A's CIDR = %v, want ErrTenantIPAllowlistEntryNotFound", err)
	}
	if got, _ := store.ListCIDRs(ctx, tenantA); len(got) != 2 {
		t.Fatalf("tenant A lost a CIDR to tenant B's delete: %v", got)
	}

	// (4) POSITIVE CONTROLS — A manages its own: B adds its own CIDR (visible only to B); A removes one
	//     of its own (1 remains); re-removing a gone entry is not-found.
	if err := store.AddCIDR(ctx, tenantB, "172.16.0.0/12"); err != nil {
		t.Fatalf("B add own: %v", err)
	}
	if got, _ := store.ListCIDRs(ctx, tenantB); len(got) != 1 || got[0] != "172.16.0.0/12" {
		t.Fatalf("B own list = %v, want [172.16.0.0/12]", got)
	}
	if err := store.RemoveCIDR(ctx, tenantA, "10.0.0.0/8"); err != nil {
		t.Fatalf("A remove own: %v", err)
	}
	if got, _ := store.ListCIDRs(ctx, tenantA); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("A after self-remove = %v, want [192.0.2.0/24]", got)
	}
	if err := store.RemoveCIDR(ctx, tenantA, "10.0.0.0/8"); !errors.Is(err, ErrTenantIPAllowlistEntryNotFound) {
		t.Fatalf("re-remove of a gone CIDR = %v, want ErrTenantIPAllowlistEntryNotFound", err)
	}

	// Tidy up so re-runs against a persistent DB stay independent.
	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tenantA, tenantB); err != nil {
		t.Fatalf("cleanup tenants: %v", err)
	}
}

// TestPgTenantIPAllowlistConcurrentDeleteNoLockout is the regression for the anti-lockout TOCTOU: two
// concurrent deletes of OVERLAPPING-coverage entries must NEVER jointly strand the caller. The list
// {192.0.2.0/24, 192.0.2.1/32, 10.0.0.0/8} covers caller 192.0.2.1 via BOTH the /24 and the /32; the
// non-covering 10.0.0.0/8 remains. Fired concurrently, a naive handler-side check would let BOTH deletes
// pass (each validating against the stale 3-entry snapshot where the OTHER covering entry still exists),
// leaving {10.0.0.0/8} — the caller locked out. The store's advisory-locked read-check-write SERIALIZES
// them, so the second delete sees the first's removal and is refused (ErrWouldLockOut). We hammer the
// race many times; the invariant is that the caller is ALWAYS still covered afterward.
func TestPgTenantIPAllowlistConcurrentDeleteNoLockout(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantIPAllowlistMigration(t, suPool)
	ctx := context.Background()

	var tenant string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&tenant); err != nil {
		t.Fatalf("gen tenant uuid: %v", err)
	}
	seedBareTenant(t, suPool, tenant, "ipa-race")

	appPool := newAppRolePool(t, ctx)
	store := NewPgTenantIPAllowlistStore(appPool)

	caller := net.ParseIP("192.0.2.1")
	// safe: an empty list is open; otherwise some remaining CIDR must cover the caller.
	safe := func(resulting []string) bool {
		if len(resulting) == 0 {
			return true
		}
		for _, c := range resulting {
			if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(caller) {
				return true
			}
		}
		return false
	}
	covering := []string{"192.0.2.0/24", "192.0.2.1/32"}

	for i := 0; i < 25; i++ {
		// Reset to the full three-entry list before each round.
		if _, err := suPool.Exec(ctx, "DELETE FROM tenant_ip_allowlist WHERE tenant_id = $1", tenant); err != nil {
			t.Fatalf("reset: %v", err)
		}
		for _, c := range []string{"192.0.2.0/24", "192.0.2.1/32", "10.0.0.0/8"} {
			if err := store.AddCIDR(ctx, tenant, c); err != nil {
				t.Fatalf("seed %q: %v", c, err)
			}
		}

		// Two goroutines, released together, each removing ONE covering entry.
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for g := 0; g < 2; g++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				errs[idx] = store.RemoveCIDRGuarded(ctx, tenant, covering[idx], safe)
			}(g)
		}
		close(start) // fire both
		wg.Wait()

		final, err := store.ListCIDRs(ctx, tenant)
		if err != nil {
			t.Fatalf("round %d: list: %v", i, err)
		}
		if !safe(final) {
			t.Fatalf("round %d: caller LOCKED OUT — both covering deletes landed; final=%v errs=%v", i, final, errs)
		}
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tenant); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
