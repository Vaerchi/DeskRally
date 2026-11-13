package controlplane

// DB-gated proof for per-tenant branding (docs/01 §9), driven as the least-privilege rmt_app role
// RLS is enforced against: Get returns the zero Branding for no row, Set upserts a SINGLE per-tenant
// row (insert then update), and one tenant never sees another's branding. Needs TEST_DATABASE_URL;
// scripts/verify-all.ps1 sets it and treats a skip as a failure.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// applyTenantBrandingMigration lays 0028 on top of the schema newTestPool applied; resetSchema DROPs
// tenant_branding, so this is re-runnable.
func applyTenantBrandingMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, f := range []string{"migrations/0028_tenant_branding.sql", "migrations/0064_tenant_branding_logo.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		execScript(t, pool, string(b))
	}
}

func TestPgTenantBrandingUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantBrandingMigration(t, suPool)
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "brand-a", "a@brand-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "brand-b", "b@brand-b.test", "password-1234")

	appPool := newAppRolePool(t, ctx)
	store := NewPgTenantBrandingStore(appPool)

	// Unset → the zero Branding (no row).
	if b, err := store.Get(ctx, tidA); err != nil || b != (Branding{}) {
		t.Fatalf("unset A = (%+v, %v), want zero", b, err)
	}
	// Upsert path 1 (insert), then read back.
	if err := store.Set(ctx, tidA, Branding{ProductName: "Acme A", AccentColor: "#ff0000"}); err != nil {
		t.Fatalf("Set A: %v", err)
	}
	if b, _ := store.Get(ctx, tidA); b.ProductName != "Acme A" || b.AccentColor != "#ff0000" {
		t.Fatalf("get A = %+v", b)
	}
	// RLS isolation: B is untouched.
	if b, _ := store.Get(ctx, tidB); b != (Branding{}) {
		t.Fatalf("B leaked A's branding: %+v", b)
	}
	// A logo round-trips through the new column (and B still sees nothing).
	if err := store.Set(ctx, tidA, Branding{ProductName: "Acme A", LogoDataURI: validPNG}); err != nil {
		t.Fatalf("Set A logo: %v", err)
	}
	if b, _ := store.Get(ctx, tidA); b.LogoDataURI != validPNG {
		t.Fatalf("logo did not round-trip: %.48q", b.LogoDataURI)
	}
	if b, _ := store.Get(ctx, tidB); b.LogoDataURI != "" {
		t.Fatalf("B leaked A's logo: %.48q", b.LogoDataURI)
	}
	// Upsert path 2 (update A to a new value, clearing the accent AND the logo).
	if err := store.Set(ctx, tidA, Branding{ProductName: "Acme A2", AccentColor: ""}); err != nil {
		t.Fatalf("re-Set A: %v", err)
	}
	if b, _ := store.Get(ctx, tidA); b.ProductName != "Acme A2" || b.AccentColor != "" || b.LogoDataURI != "" {
		t.Fatalf("get A after update = %+v", b)
	}
	// The upsert kept a SINGLE row for A (not a second insert).
	var n int
	if err := suPool.QueryRow(ctx, `SELECT count(*) FROM tenant_branding WHERE tenant_id = $1::uuid`, tidA).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("tenant A rows = %d, want 1 (upsert, not duplicate insert)", n)
	}
}
