package controlplane

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// applyDynamicGroupMigration lays 0026 (the dynamic_group table + RLS + grant) on top of the schema
// newTestPool built. It GRANTs to rmt_app, so applyAppRoleMigration (0005) MUST run first. resetSchema
// drops dynamic_group with the rest, so this re-applies cleanly on a re-run.
func applyDynamicGroupMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0026_dynamic_group.sql")
	if err != nil {
		t.Fatalf("read 0026: %v", err)
	}
	execScript(t, pool, string(b))
}

// TestPgDynamicGroupRLSIsolation is the golden proof, run as the RLS-SUBJECT rmt_app role: a second
// tenant's pin sees NONE of the first's dynamic groups, CANNOT get/delete them by id, and a name that
// is "taken" in tenant A is free in tenant B. Positive controls confirm a tenant manages its own.
func TestPgDynamicGroupRLSIsolation(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyDynamicGroupMigration(t, suPool)
	ctx := context.Background()

	var tenantA, tenantB string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("gen tenant uuids: %v", err)
	}
	seedBareTenant(t, suPool, tenantA, "dg-a")
	seedBareTenant(t, suPool, tenantB, "dg-b")

	appPool := newAppRolePool(t, ctx)
	store := NewPgDynamicGroupStore(appPool)

	// Tenant A creates a group (DB assigns the id).
	gA := &DynamicGroup{Name: "HQ", PropertyKey: "site", PropertyValue: "HQ"}
	if err := store.CreateDynamicGroup(ctx, tenantA, gA); err != nil || gA.ID == "" {
		t.Fatalf("A create = %v, id=%q", err, gA.ID)
	}
	// A duplicate name in the SAME tenant is rejected CASE-INSENSITIVELY ("hq" collides with "HQ"),
	// proving the functional unique index on lower(name) — the contract the fake also enforces, so dev
	// and prod agree (this exercises the case gap a same-case duplicate would miss).
	if err := store.CreateDynamicGroup(ctx, tenantA, &DynamicGroup{Name: "hq", PropertyKey: "x"}); !errors.Is(err, ErrDynamicGroupNameTaken) {
		t.Fatalf("A case-differing duplicate name = %v, want ErrDynamicGroupNameTaken", err)
	}

	// (1) READ ISOLATION — tenant B sees NONE of A's groups, and get-by-id (A's id) is not-found for B.
	if got, err := store.ListDynamicGroups(ctx, tenantB); err != nil || len(got) != 0 {
		t.Fatalf("B list = %v, %v; want 0 rows (RLS must hide tenant A)", got, err)
	}
	if _, err := store.GetDynamicGroup(ctx, tenantB, gA.ID); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("B get A's group = %v, want ErrDynamicGroupNotFound (RLS-hidden)", err)
	}

	// (2) NAME REUSE ACROSS TENANTS — the name "HQ" is taken in A but FREE in B (isolation, not a global unique).
	gB := &DynamicGroup{Name: "HQ", PropertyKey: "env", PropertyValue: "prod"}
	if err := store.CreateDynamicGroup(ctx, tenantB, gB); err != nil {
		t.Fatalf("B create same-name group = %v, want ok (names are per-tenant)", err)
	}

	// (3) DELETE ISOLATION — tenant B deleting A's group id removes NOTHING (RLS-hidden → 0 rows → not-found);
	//     A's group survives.
	if err := store.DeleteDynamicGroup(ctx, tenantB, gA.ID); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("B delete A's group = %v, want ErrDynamicGroupNotFound", err)
	}
	if got, err := store.GetDynamicGroup(ctx, tenantA, gA.ID); err != nil || got.Name != "HQ" {
		t.Fatalf("A's group lost to B's delete: %+v, %v", got, err)
	}

	// (4) POSITIVE CONTROLS — A lists exactly its own, deletes its own, re-delete is not-found.
	if got, _ := store.ListDynamicGroups(ctx, tenantA); len(got) != 1 || got[0].Name != "HQ" {
		t.Fatalf("A list = %+v, want [HQ]", got)
	}
	if err := store.DeleteDynamicGroup(ctx, tenantA, gA.ID); err != nil {
		t.Fatalf("A delete own: %v", err)
	}
	if err := store.DeleteDynamicGroup(ctx, tenantA, gA.ID); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("A re-delete = %v, want ErrDynamicGroupNotFound", err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tenantA, tenantB); err != nil {
		t.Fatalf("cleanup tenants: %v", err)
	}
}
