package controlplane

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestPgDynamicGroupRLSIsolation is the golden proof, run as the RLS-SUBJECT rmt_app role: a second
// tenant's pin sees NONE of the first's dynamic groups, CANNOT get/delete them by id, and a name that
// is "taken" in tenant A is free in tenant B. Positive controls confirm a tenant manages its own.
func TestPgDynamicGroupRLSIsolation(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyMigrationFile(t, suPool, "migrations/0026_dynamic_group.sql")
	ctx := context.Background()

	var tenantA, tenantB string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tenantA, &tenantB); err != nil {
		t.Fatalf("gen tenant uuids: %v", err)
	}
	seedBareTenant(t, suPool, tenantA, "dg-a")
	seedBareTenant(t, suPool, tenantB, "dg-b")

	var legacyID string
	if err := suPool.QueryRow(ctx, `
		INSERT INTO dynamic_group (tenant_id, name, property_key, property_value)
		VALUES ($1, 'Old group', 'site', 'HQ') RETURNING id::text
	`, tenantB).Scan(&legacyID); err != nil {
		t.Fatalf("insert pre-migration group: %v", err)
	}
	applyMigrationFile(t, suPool, "migrations/0085_dynamic_group_conditions.sql")

	appPool := newAppRolePool(t, ctx)
	store := NewPgDynamicGroupStore(appPool)

	// Tenant A creates a group (DB assigns the id).
	gA := &DynamicGroup{Name: "HQ", Match: "any", Conditions: []Condition{
		{Field: "property:site", Op: "equals", Value: "HQ"},
		{Field: "os", Op: "contains", Value: "11"},
	}}
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
	if got, err := store.ListDynamicGroups(ctx, tenantB); err != nil || len(got) != 1 ||
		got[0].ID != legacyID || got[0].Match != "all" || got[0].Conditions != nil ||
		got[0].PropertyKey != "site" || got[0].PropertyValue != "HQ" {
		t.Fatalf("B list = %v, %v; want only the unchanged pre-migration group", got, err)
	}
	if _, err := store.GetDynamicGroup(ctx, tenantB, gA.ID); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("B get A's group = %v, want ErrDynamicGroupNotFound (RLS-hidden)", err)
	}

	// (2) NAME REUSE ACROSS TENANTS — the name "HQ" is taken in A but FREE in B (isolation, not a global unique).
	gB := &DynamicGroup{Name: "HQ", PropertyKey: "env", PropertyValue: "prod"}
	if err := store.CreateDynamicGroup(ctx, tenantB, gB); err != nil {
		t.Fatalf("B create same-name group = %v, want ok (names are per-tenant)", err)
	}
	if got, err := store.GetDynamicGroup(ctx, tenantB, gB.ID); err != nil ||
		got.Match != "all" || got.Conditions != nil || got.PropertyKey != "env" || got.PropertyValue != "prod" {
		t.Fatalf("B legacy group = %+v, %v", got, err)
	}

	// (3) DELETE ISOLATION — tenant B deleting A's group id removes NOTHING (RLS-hidden → 0 rows → not-found);
	//     A's group survives.
	if err := store.DeleteDynamicGroup(ctx, tenantB, gA.ID); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("B delete A's group = %v, want ErrDynamicGroupNotFound", err)
	}
	if got, err := store.GetDynamicGroup(ctx, tenantA, gA.ID); err != nil ||
		got.Name != "HQ" || got.Match != "any" || !slices.Equal(got.Conditions, gA.Conditions) {
		t.Fatalf("A get = %+v, %v; want %+v", got, err, gA)
	}

	// (4) POSITIVE CONTROLS — A lists exactly its own, deletes its own, re-delete is not-found.
	if got, err := store.ListDynamicGroups(ctx, tenantA); err != nil || len(got) != 1 ||
		got[0].ID != gA.ID || got[0].Match != "any" || !slices.Equal(got[0].Conditions, gA.Conditions) {
		t.Fatalf("A list = %+v, %v; want [%+v]", got, err, gA)
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
