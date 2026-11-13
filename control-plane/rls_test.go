package controlplane

// Row-Level Security isolation test — the concrete proof that the multi-tenant guarantee in
// 0001_core.sql actually HOLDS when the app connects as the least-privilege role from
// 0005_app_role.sql, and that it is SILENTLY BYPASSED when connecting as the superuser.
//
// Like the other pgx tests this needs a live PostgreSQL and SKIPS (green) without
// TEST_DATABASE_URL, so the default `go test ./...` never touches a database. Run with:
//
//	TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5433/rmt_test?sslmode=disable go test ./... -run TestRLS -v
//
// TEST_DATABASE_URL is expected to be the SUPERUSER/owner DSN (matches every other pgx test —
// it applies migrations and bypasses RLS). This test derives a SECOND pool for the RLS-subject
// application role `rmt_app` by swapping only the username (trust auth locally, no password),
// then contrasts what each role can see.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newAppRolePool derives an rmt_app-authenticated pool from the superuser TEST_DATABASE_URL by
// swapping only the connection user (and clearing any password — local trust auth needs none).
// This is the connection the production app SHOULD use: a non-superuser, non-owner role that is
// genuinely subject to RLS.
func newAppRolePool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatalf("parse app-role config: %v", err)
	}
	cfg.ConnConfig.User = "rmt_app"
	cfg.ConnConfig.Password = ""
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as rmt_app: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// applyAppRoleMigration lays down 0005_app_role.sql on top of the schema newTestPool applied
// (0001–0003). Because resetSchema DROPs + recreates the tables — dropping their per-object
// grants with them — the grants must be (re)applied here for the freshly built schema.
func applyAppRoleMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0005_app_role.sql")
	if err != nil {
		t.Fatalf("read 0005: %v", err)
	}
	execScript(t, pool, string(b))
}

// seedTenantWithMachine inserts a tenant + one machine_group + one machine, all carrying the
// given tenant id. Seeded as the SUPERUSER pool (RLS-bypassing) with the tenant pinned so the
// inserts are explicit and self-contained. Returns the machine's primary-key id.
func seedTenantWithMachine(t *testing.T, pool *pgxpool.Pool, tid, slug string) (machineID string) {
	t.Helper()
	ctx := context.Background()
	var gid, mid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&gid, &mid); err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,$2,$2,'self_hosted')`,
			tid, slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G')`, gid, tid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO machine (id, tenant_id, device_id, group_id, pubkey)
			 VALUES ($1,$2,$3,$4,'\x00')`, mid, tid, "dev-"+slug, gid)
		return err
	}); err != nil {
		t.Fatalf("seed tenant %s: %v", slug, err)
	}
	return mid
}

// TestRLSTenantIsolationAsAppRole is the load-bearing proof: connecting as rmt_app, RLS confines
// every read/write to the pinned tenant; connecting as the superuser, the SAME query bypasses RLS
// and sees both tenants — so provisioning + using rmt_app is what makes tenant isolation real.
func TestRLSTenantIsolationAsAppRole(t *testing.T) {
	suPool := newTestPool(t) // skips without TEST_DATABASE_URL; superuser; applies 0001–0003
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	// Two tenants, each with its own group + machine.
	var tenantA, tenantB string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("gen tenant uuids: %v", err)
	}
	machineA := seedTenantWithMachine(t, suPool, tenantA, "rls-a")
	machineB := seedTenantWithMachine(t, suPool, tenantB, "rls-b")

	appPool := newAppRolePool(t, ctx)

	// Sanity: rmt_app really is neither superuser nor bypassing RLS.
	var isSuper, bypass bool
	if err := appPool.QueryRow(ctx,
		"SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&isSuper, &bypass); err != nil {
		t.Fatalf("introspect rmt_app: %v", err)
	}
	if isSuper || bypass {
		t.Fatalf("rmt_app must be non-superuser and non-bypassrls; got super=%v bypass=%v", isSuper, bypass)
	}

	// (1) rmt_app pinned to tenant A sees ONLY tenant A's machine (count == 1), and tenant B's
	//     machine is invisible even by explicit primary key (0 rows).
	if err := withTenant(ctx, appPool, tenantA, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM machine").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("rmt_app pinned to A: count(machine) = %d, want 1 (RLS must hide tenant B)", n)
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM machine WHERE id = $1", machineB).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("rmt_app pinned to A: sees tenant B's machine by id (%d rows), want 0 (RLS must hide it)", n)
		}
		// UPDATE of tenant B's row while pinned to A affects 0 rows: the USING clause makes the
		// row invisible to the UPDATE, so a mis-scoped write silently touches nothing rather than
		// mutating another tenant.
		ct, err := tx.Exec(ctx, "UPDATE machine SET hostname = 'hijacked' WHERE id = $1", machineB)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 0 {
			t.Fatalf("rmt_app pinned to A: UPDATE of tenant B's machine affected %d rows, want 0", ct.RowsAffected())
		}
		return nil
	}); err != nil {
		t.Fatalf("rmt_app tenant-A tx: %v", err)
	}

	// (2) rmt_app pinned to A attempting to INSERT a row INTO tenant B is blocked by WITH CHECK.
	//     Its own tx so the earlier work is untouched.
	err := withTenant(ctx, appPool, tenantA, func(tx pgx.Tx) error {
		var gidB string
		// Even reading B's group id would be hidden by RLS while pinned to A, so pass a fresh id;
		// the WITH CHECK on tenant_id fires regardless of the group.
		if err := tx.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&gidB); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO machine (tenant_id, device_id, group_id, pubkey) VALUES ($1,'evil',$2,'\x00')`,
			tenantB, gidB)
		return err
	})
	if err == nil {
		t.Fatal("rmt_app pinned to A was allowed to INSERT a machine into tenant B; WITH CHECK must block it")
	}
	if !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("cross-tenant INSERT blocked, but not by RLS: %v", err)
	}

	// (3) rmt_app with NO app.current_tenant set RAISES rather than leaking every tenant: the
	//     policy's current_setting('app.current_tenant') has no default, so the query errors. This
	//     is the guarantee that a request which skips the tenant middleware fails loudly.
	//
	//     Use a FRESH pool whose physical connection never ran SET LOCAL app.current_tenant, so the
	//     GUC is genuinely UNSET and we see the canonical raise:
	//         ERROR: unrecognized configuration parameter "app.current_tenant"
	//     (A pooled connection that previously served a tenant-pinned tx reverts the SET LOCAL to
	//     an EMPTY STRING at tx end rather than "unset", so there the same query raises
	//         ERROR: invalid input syntax for type uuid: ""
	//     instead — still a loud failure, never a silent leak. We accept either.)
	freshPool := newAppRolePool(t, ctx)
	var n int
	err = freshPool.QueryRow(ctx, "SELECT count(*) FROM machine").Scan(&n)
	if err == nil {
		t.Fatalf("rmt_app with no tenant set returned %d rows instead of raising", n)
	}
	if !strings.Contains(err.Error(), "app.current_tenant") &&
		!strings.Contains(err.Error(), "invalid input syntax for type uuid") {
		t.Fatalf("no-tenant query raised, but not on the unset tenant GUC: %v", err)
	}

	// (4) CONTRAST — the SAME cross-tenant SELECT as the SUPERUSER sees BOTH machines (2): RLS is
	//     bypassed for a superuser even with FORCE, proving connecting the app as postgres/owner
	//     is unsafe and that this test is meaningful.
	if err := suPool.QueryRow(ctx,
		"SELECT count(*) FROM machine WHERE id IN ($1,$2)", machineA, machineB).Scan(&n); err != nil {
		t.Fatalf("superuser cross-tenant count: %v", err)
	}
	if n != 2 {
		t.Fatalf("superuser sees %d of the 2 seeded machines, want 2 (RLS should be BYPASSED for a superuser)", n)
	}

	// Clean up the two tenants so re-runs against a persistent DB stay independent (resetSchema
	// also drops everything on the next newTestPool, but be tidy).
	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tenantA, tenantB); err != nil {
		t.Fatalf("cleanup tenants: %v", err)
	}
}
