package controlplane

// DB-gated proof for the API-token path (docs/01 §8). apitoken_test.go pins the store CONTRACT
// against the in-memory fake and the handler; only a real database, driven as the least-privilege
// rmt_app role RLS is actually enforced against, can pin the SQL properties:
//
//   - MINT lands in the caller's tenant and stores only the hash (never the plaintext).
//   - LIST is RLS-scoped — one tenant never sees another's tokens.
//   - RESOLVE goes through the SECURITY DEFINER cp_api_token_resolve on the POOL (no tenant pinned),
//     the auth-time path, and honours revoke + expiry + tenant suspension.
//   - a tenant-pinned REVOKE cannot reach across the tenant boundary.
//
// Needs TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a skip as a failure.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyAPITokenMigration lays 0027 (api_token + cp_api_token_resolve) on top of the schema
// newTestPool applied. resetSchema DROPs both the table and the function, so this is re-runnable.
func applyAPITokenMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0027_api_token.sql")
	if err != nil {
		t.Fatalf("read 0027: %v", err)
	}
	execScript(t, pool, string(b))
}

func TestPgAPITokenUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAPITokenMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "api-a", "dana@api-a.test", "Original-Passw0rd!")
	tidB, _ := provisionUser(t, suPool, "api-b", "eve@api-b.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	store := NewPgAPITokenStore(appPool)

	// --- MINT lands in the caller's tenant; the row stores the HASH, not the plaintext.
	plaintext, tok, err := store.Mint(ctx, tidA, "ci-bot", []Capability{CapViewMachines, CapViewAudit}, uidA, nil)
	if err != nil {
		t.Fatalf("Mint as rmt_app: %v", err)
	}
	if tok.TenantID != tidA {
		t.Fatalf("minted token tenant = %s, want %s", tok.TenantID, tidA)
	}
	var storedHash []byte
	var storedTenant string
	if err := suPool.QueryRow(ctx,
		`SELECT token_hash, tenant_id::text FROM api_token WHERE id = $1::uuid`, tok.ID).
		Scan(&storedHash, &storedTenant); err != nil {
		t.Fatalf("read minted row: %v", err)
	}
	if storedTenant != tidA {
		t.Fatalf("stored tenant = %s, want %s", storedTenant, tidA)
	}
	if string(storedHash) == plaintext {
		t.Fatalf("the PLAINTEXT was stored — only its hash may be")
	}
	if string(storedHash) != string(HashToken(plaintext)) {
		t.Fatalf("stored hash is not SHA-256(plaintext)")
	}

	// --- RESOLVE (pre-tenant, on the pool) returns the right tenant + caps.
	got, err := store.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.TenantID != tidA {
		t.Fatalf("resolved tenant = %s, want %s", got.TenantID, tidA)
	}
	if len(got.Capabilities) != 2 || got.Capabilities[0] != CapViewMachines || got.Capabilities[1] != CapViewAudit {
		t.Fatalf("resolved caps = %v, want [view_machines view_audit]", got.Capabilities)
	}

	// --- LIST is RLS-scoped: tenant B's listing must not include tenant A's token.
	bList, err := store.List(ctx, tidB)
	if err != nil {
		t.Fatalf("List(B): %v", err)
	}
	for _, tk := range bList {
		if tk.ID == tok.ID {
			t.Fatalf("tenant B's listing leaked tenant A's token %s", tok.ID)
		}
	}
	aList, err := store.List(ctx, tidA)
	if err != nil {
		t.Fatalf("List(A): %v", err)
	}
	if len(aList) != 1 || aList[0].ID != tok.ID {
		t.Fatalf("List(A) = %+v, want the one token %s", aList, tok.ID)
	}

	// --- A tenant-pinned REVOKE cannot reach across the boundary: pinned to B, A's id is invisible.
	if err := store.Revoke(ctx, tidB, tok.ID); err != ErrAPITokenNotFound {
		t.Fatalf("cross-tenant Revoke err = %v, want ErrAPITokenNotFound", err)
	}
	// And after that failed attempt the token is still live.
	if _, err := store.Resolve(ctx, plaintext); err != nil {
		t.Fatalf("token should still resolve after a cross-tenant revoke attempt: %v", err)
	}
	// The owning tenant's revoke works, and then it no longer resolves.
	if err := store.Revoke(ctx, tidA, tok.ID); err != nil {
		t.Fatalf("Revoke(A): %v", err)
	}
	if _, err := store.Resolve(ctx, plaintext); err != ErrAPITokenNotFound {
		t.Fatalf("Resolve after revoke err = %v, want ErrAPITokenNotFound", err)
	}
}

func TestPgAPITokenResolveHonoursExpiryAndSuspension(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAPITokenMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "api-exp", "dana@api-exp.test", "Original-Passw0rd!")
	tidS, uidS := provisionUser(t, suPool, "api-susp", "eve@api-susp.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	store := NewPgAPITokenStore(appPool)

	// --- EXPIRY: a token whose expires_at is already past does not resolve.
	past := time.Now().Add(-time.Hour)
	expiredPlain, _, err := store.Mint(ctx, tidA, "expired", []Capability{CapViewMachines}, uidA, &past)
	if err != nil {
		t.Fatalf("Mint expired: %v", err)
	}
	if _, err := store.Resolve(ctx, expiredPlain); err != ErrAPITokenNotFound {
		t.Fatalf("expired token resolved: %v", err)
	}
	// A future expiry DOES resolve.
	future := time.Now().Add(time.Hour)
	livePlain, _, err := store.Mint(ctx, tidA, "live", []Capability{CapViewMachines}, uidA, &future)
	if err != nil {
		t.Fatalf("Mint live: %v", err)
	}
	if _, err := store.Resolve(ctx, livePlain); err != nil {
		t.Fatalf("future-expiry token should resolve: %v", err)
	}

	// --- SUSPENSION: a token in a tenant that is later suspended stops resolving. This is the
	// pg-only property the in-memory fake cannot express (it has no tenant registry).
	suspPlain, _, err := store.Mint(ctx, tidS, "in-suspended", []Capability{CapViewMachines}, uidS, nil)
	if err != nil {
		t.Fatalf("Mint in-suspended: %v", err)
	}
	if _, err := store.Resolve(ctx, suspPlain); err != nil {
		t.Fatalf("token should resolve before suspension: %v", err)
	}
	if err := withTenant(ctx, suPool, tidS, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1::uuid`, tidS)
		return err
	}); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}
	if _, err := store.Resolve(ctx, suspPlain); err != ErrAPITokenNotFound {
		t.Fatalf("token in a suspended tenant resolved: %v", err)
	}
}
