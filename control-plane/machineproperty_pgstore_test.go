package controlplane

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// applyMachinePropertyMigration lays 0024 (the machine_property table + RLS + the
// UNIQUE(tenant_id, id) the composite FK needs) on top of the schema newTestPool built. It GRANTs to
// rmt_app, so applyAppRoleMigration (0005) MUST run first. resetSchema drops machine_property with
// the rest (and drops+recreates machine, so the ALTER ... ADD CONSTRAINT re-applies cleanly).
func applyMachinePropertyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0024_machine_property.sql")
	if err != nil {
		t.Fatalf("read 0024: %v", err)
	}
	execScript(t, pool, string(b))
}

// TestPgMachinePropertyRLSIsolation is the golden proof, run as the RLS-SUBJECT rmt_app role (a
// superuser pool would BYPASS RLS and pass against broken code, proving nothing): a second tenant's
// pin sees NONE of the first's properties, CANNOT write onto the first's machine (the composite FK
// rejects a cross-tenant machine even by its real PK), and CANNOT delete the first's rows. The
// positive controls confirm a tenant can fully manage its own.
func TestPgMachinePropertyRLSIsolation(t *testing.T) {
	suPool := newTestPool(t)                 // skips w/o TEST_DATABASE_URL; superuser; 0001-0003 + always-on
	applyAppRoleMigration(t, suPool)         // 0005: creates rmt_app + grants
	applyMachinePropertyMigration(t, suPool) // 0024: the new table + RLS + composite FK + grant
	ctx := context.Background()

	// Two tenants, each with a group + one enrolled machine. Seeded privileged (RLS-bypassing) so the
	// setup is explicit; the property store below runs as rmt_app, which is the whole point.
	var tenantA, tenantB string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("gen tenant uuids: %v", err)
	}
	machineA := seedTenantWithMachine(t, suPool, tenantA, "mp-a")
	machineB := seedTenantWithMachine(t, suPool, tenantB, "mp-b")

	appPool := newAppRolePool(t, ctx) // the RLS-subject connection
	store := NewPgMachinePropertyStore(appPool)

	// Tenant A sets two properties, then upserts one — proving ON CONFLICT updates in place (2 rows).
	if err := store.SetProperty(ctx, tenantA, machineA, "site", "HQ"); err != nil {
		t.Fatalf("set A/site: %v", err)
	}
	if err := store.SetProperty(ctx, tenantA, machineA, "rack", "R7"); err != nil {
		t.Fatalf("set A/rack: %v", err)
	}
	if err := store.SetProperty(ctx, tenantA, machineA, "site", "DR"); err != nil {
		t.Fatalf("upsert A/site: %v", err)
	}
	propsA, err := store.ListProperties(ctx, tenantA, machineA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(propsA) != 2 || propsA[0].Key != "rack" || propsA[1].Key != "site" || propsA[1].Value != "DR" {
		t.Fatalf("list A = %+v, want [rack=R7, site=DR] (upsert updates in place, ORDER BY key)", propsA)
	}

	// (1) READ ISOLATION — tenant B's pin sees NONE of A's properties, even naming A's machine PK.
	if got, err := store.ListProperties(ctx, tenantB, machineA); err != nil || len(got) != 0 {
		t.Fatalf("tenant B listing A's machine = %+v, %v; want 0 rows (RLS must hide tenant A)", got, err)
	}
	if got, _ := store.ListProperties(ctx, tenantB, machineB); len(got) != 0 {
		t.Fatalf("tenant B's own machine has %d properties, want 0", len(got))
	}

	// (2) WRITE ISOLATION — tenant B cannot annotate A's machine. No (tenantB, machineA) row exists
	//     for the composite FK, so the INSERT RAISES 23503 -> ErrMachineNotFound rather than creating
	//     an orphan property tagged to B but pointing at A's machine PK (the hole a plain FK leaves).
	if err := store.SetProperty(ctx, tenantB, machineA, "pwn", "1"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("tenant B set a property on tenant A's machine: err = %v, want ErrMachineNotFound", err)
	}
	if got, _ := store.ListProperties(ctx, tenantA, machineA); len(got) != 2 {
		t.Fatalf("tenant A now has %d properties, want 2 (B's cross-tenant write must not have landed)", len(got))
	}

	// (3) DELETE ISOLATION — tenant B deleting by A's machine id + a real key of A's removes NOTHING:
	//     the row is invisible to B's pin so the DELETE matches 0 rows (ErrMachinePropertyNotFound),
	//     and A's row survives.
	if err := store.DeleteProperty(ctx, tenantB, machineA, "site"); !errors.Is(err, ErrMachinePropertyNotFound) {
		t.Fatalf("tenant B delete of A's property = %v, want ErrMachinePropertyNotFound", err)
	}
	if got, _ := store.ListProperties(ctx, tenantA, machineA); len(got) != 2 {
		t.Fatalf("tenant A lost a property to tenant B's delete: %+v", got)
	}

	// (4) POSITIVE CONTROLS — A manages its own: delete succeeds (1 remains), re-delete is not-found.
	if err := store.DeleteProperty(ctx, tenantA, machineA, "site"); err != nil {
		t.Fatalf("tenant A delete of its own property: %v, want nil", err)
	}
	if got, _ := store.ListProperties(ctx, tenantA, machineA); len(got) != 1 || got[0].Key != "rack" {
		t.Fatalf("after self-delete, list A = %+v, want [rack=R7]", got)
	}
	if err := store.DeleteProperty(ctx, tenantA, machineA, "site"); !errors.Is(err, ErrMachinePropertyNotFound) {
		t.Fatalf("re-delete of a gone key = %v, want ErrMachinePropertyNotFound", err)
	}

	// Tidy up so re-runs against a persistent DB stay independent (resetSchema also drops everything).
	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tenantA, tenantB); err != nil {
		t.Fatalf("cleanup tenants: %v", err)
	}
}

// TestPgMachineIDsWithPropertyIsolation proves the fleet search/filter query (docs/01 §4) as the
// RLS-subject rmt_app role: it returns the tenant's OWN matching machine ids (key-only = any value,
// key+value = exact), and a second tenant with the SAME key/value on its own machine sees ONLY its
// own id — never tenant A's, which is the isolation the search must not break.
func TestPgMachineIDsWithPropertyIsolation(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyMachinePropertyMigration(t, suPool)
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "ids-a", "a@ids.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "ids-b", "b@ids.test", "password-1234")
	_, a1 := seedGroupMachine(t, suPool, tidA, "dev-ids-a1")
	_, a2 := seedGroupMachine(t, suPool, tidA, "dev-ids-a2")
	_, a3 := seedGroupMachine(t, suPool, tidA, "dev-ids-a3") // has NO site property
	_, b1 := seedGroupMachine(t, suPool, tidB, "dev-ids-b1")

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachinePropertyStore(appPool)

	// a1: site=HQ ; a2: site=DR ; b1: site=HQ (same key+value as a1, but ANOTHER tenant).
	for _, sp := range []struct{ tid, mid, v string }{{tidA, a1, "HQ"}, {tidA, a2, "DR"}, {tidB, b1, "HQ"}} {
		if err := store.SetProperty(ctx, sp.tid, sp.mid, "site", sp.v); err != nil {
			t.Fatalf("set site on %s: %v", sp.mid, err)
		}
	}

	want := func(name string, got map[string]struct{}, ids ...string) {
		t.Helper()
		if len(got) != len(ids) {
			t.Fatalf("%s = %v, want exactly %v", name, keysOf(got), ids)
		}
		for _, id := range ids {
			if _, ok := got[id]; !ok {
				t.Fatalf("%s = %v, missing %s", name, keysOf(got), id)
			}
		}
	}

	// key-only (any value) for tenant A → both a1 and a2 (NOT a3 which lacks the key, NOT b1's).
	got, err := store.MachineIDsWithProperty(ctx, tidA, "site", "")
	if err != nil {
		t.Fatalf("ids A site/any: %v", err)
	}
	want("A site=*", got, a1, a2)
	if _, leaked := got[b1]; leaked {
		t.Fatalf("tenant A's search returned tenant B's machine %s", b1)
	}
	if _, has := got[a3]; has {
		t.Fatalf("a3 has no site property but was returned")
	}

	// key+value for tenant A → only a1 (site=HQ), not a2 (site=DR).
	got, _ = store.MachineIDsWithProperty(ctx, tidA, "site", "HQ")
	want("A site=HQ", got, a1)

	// ISOLATION: tenant B pinned, site=HQ → only b1, NEVER a1 even though a1 also has site=HQ.
	got, _ = store.MachineIDsWithProperty(ctx, tidB, "site", "HQ")
	want("B site=HQ", got, b1)
	if _, leaked := got[a1]; leaked {
		t.Fatalf("tenant B's search returned tenant A's machine %s (RLS must hide it)", a1)
	}

	// No match (value nobody has) and unknown key → empty.
	if got, _ = store.MachineIDsWithProperty(ctx, tidA, "site", "NOWHERE"); len(got) != 0 {
		t.Fatalf("A site=NOWHERE = %v, want empty", keysOf(got))
	}
	if got, _ = store.MachineIDsWithProperty(ctx, tidA, "nosuchkey", ""); len(got) != 0 {
		t.Fatalf("A nosuchkey = %v, want empty", keysOf(got))
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup tenants: %v", err)
	}
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
