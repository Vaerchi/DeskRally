package controlplane

// DB-gated proofs for the email-change path. All tests run as the least-privilege rmt_app role
// (via newAppRolePool) against real Postgres so that RLS and the unique constraint are actually
// enforced. See password_pgstore_test.go for the test-pool helpers and provisionUser.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPgSetEmailUnderRLS: UPDATE path, cross-tenant isolation, duplicate email, disabled user,
// and stale expected epoch — all driven as rmt_app.
func TestPgSetEmailUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "em-a", "dana@em-a.test", "Original-Passw0rd!")
	tidB, uidB := provisionUser(t, suPool, "em-b", "eve@em-b.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	// Read the initial epoch so we can pass it to SetEmail.
	uA, err := store.FindUserByEmail(ctx, tidA, "dana@em-a.test")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if uA.CredentialUpdatedAt.IsZero() {
		t.Fatal("CredentialUpdatedAt is zero — pg store did not carry the epoch")
	}
	initialEpoch := uA.CredentialUpdatedAt

	// --- UPDATE path: email changes, old address gone, new address resolves the same user.
	newEpoch, err := store.SetEmail(ctx, tidA, uidA, "dana.new@em-a.test", initialEpoch)
	if err != nil {
		t.Fatalf("SetEmail as rmt_app: %v", err)
	}
	if !newEpoch.After(initialEpoch) {
		t.Fatalf("new epoch %v not after initial %v — epoch must advance", newEpoch, initialEpoch)
	}
	// Old address is gone.
	if _, err := store.FindUserByEmail(ctx, tidA, "dana@em-a.test"); err != ErrNoUser {
		t.Fatalf("old email still findable: err=%v", err)
	}
	// New address resolves the same user and password hash is unchanged.
	uAfter, err := store.FindUserByEmail(ctx, tidA, "dana.new@em-a.test")
	if err != nil {
		t.Fatalf("FindUserByEmail(new): %v", err)
	}
	if uAfter.ID != uidA {
		t.Fatalf("userID changed: got %s, want %s", uAfter.ID, uidA)
	}
	if ok, err := VerifyPassword(uAfter.PasswordHash, "Original-Passw0rd!"); err != nil || !ok {
		t.Fatalf("password hash altered by SetEmail (ok=%v err=%v)", ok, err)
	}
	// Epoch advanced in the database.
	var dbEpoch time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT updated_at FROM user_credential WHERE user_id = $1::uuid`, uidA).Scan(&dbEpoch); err != nil {
		t.Fatalf("read credential epoch: %v", err)
	}
	if !dbEpoch.UTC().Equal(newEpoch) {
		t.Fatalf("SetEmail returned %v but DB holds %v", newEpoch, dbEpoch.UTC())
	}

	// --- CROSS-TENANT: tenant A pinned, tenant B's user id → ErrNoUser, B's email untouched.
	var bEmailBefore string
	if err := suPool.QueryRow(ctx,
		`SELECT email FROM app_user WHERE id = $1::uuid`, uidB).Scan(&bEmailBefore); err != nil {
		t.Fatalf("read tenant B email: %v", err)
	}
	if _, err := store.SetEmail(ctx, tidA, uidB, "hacked@em-b.test", uA.CredentialUpdatedAt); err != ErrNoUser {
		t.Fatalf("cross-tenant SetEmail = %v, want ErrNoUser", err)
	}
	var bEmailAfter string
	if err := suPool.QueryRow(ctx,
		`SELECT email FROM app_user WHERE id = $1::uuid`, uidB).Scan(&bEmailAfter); err != nil {
		t.Fatalf("re-read tenant B email: %v", err)
	}
	if bEmailAfter != bEmailBefore {
		t.Fatalf("tenant-A SetEmail modified tenant B's email: %s → %s", bEmailBefore, bEmailAfter)
	}

	// --- DUPLICATE EMAIL in the same tenant → ErrEmailExists, entire tx rolled back.
	// Insert a bare user into tidA holding the target address (no second tenant needed).
	var uidTaken string
	if err := suPool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&uidTaken); err != nil {
		t.Fatalf("gen uuid for taken user: %v", err)
	}
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
			uidTaken, tidA, "taken@em-a.test")
		return err
	}); err != nil {
		t.Fatalf("insert taken user into tidA: %v", err)
	}
	// Get current epoch after the previous SetEmail advanced it.
	uCurrent, err := store.FindUserByEmail(ctx, tidA, "dana.new@em-a.test")
	if err != nil {
		t.Fatalf("FindUserByEmail before dup test: %v", err)
	}
	if _, err := store.SetEmail(ctx, tidA, uidA, "taken@em-a.test", uCurrent.CredentialUpdatedAt); err != ErrEmailExists {
		t.Fatalf("duplicate SetEmail = %v, want ErrEmailExists", err)
	}
	// Email must still be dana.new@em-a.test (atomically rolled back).
	if _, err := store.FindUserByEmail(ctx, tidA, "dana.new@em-a.test"); err != nil {
		t.Fatalf("email changed despite duplicate error — rollback failed: %v", err)
	}

	// --- STALE EPOCH: expectedEpoch doesn't match → ErrStaleCredential, email rolled back.
	staleEpoch := uCurrent.CredentialUpdatedAt.Add(-time.Second)
	if _, err := store.SetEmail(ctx, tidA, uidA, "stale@em-a.test", staleEpoch); err != ErrStaleCredential {
		t.Fatalf("stale epoch SetEmail = %v, want ErrStaleCredential", err)
	}
	if _, err := store.FindUserByEmail(ctx, tidA, "stale@em-a.test"); err != ErrNoUser {
		t.Fatalf("stale-epoch write was not rolled back")
	}

	// --- DISABLED USER → ErrNoUser.
	if _, err := suPool.Exec(ctx,
		`UPDATE app_user SET disabled_at = now() WHERE id = $1::uuid`, uidA); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if _, err := store.SetEmail(ctx, tidA, uidA, "disabled@em-a.test", uCurrent.CredentialUpdatedAt); err != ErrNoUser {
		t.Fatalf("disabled user SetEmail = %v, want ErrNoUser", err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgEmailChangeAsAppRole is the end-to-end DB proof of the full HTTP chain
// (csrf → auth → PgBinder → HandleChangeEmail → pgx stores) against real Postgres as rmt_app.
func TestPgEmailChangeAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "emchg", "dana@emchg.test", "Original-Passw0rd!")
	appPool := newAppRolePool(t, ctx)

	users := newPgUserStoreT(appPool)
	sessions := NewSessionManager(NewPgSessionStore(appPool))
	audit := NewInMemoryMgmtAuditStore()
	authSvc := &AuthService{
		Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(appPool),
		Issuer: "RMT", MgmtAudit: audit,
	}
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(appPool))
	srv.AuthAPI = authSvc
	srv.MgmtAudit = audit
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	h := srv.Handler()

	oldCreds := loginRequest{Tenant: "emchg", Email: "dana@emchg.test", Password: "Original-Passw0rd!"}

	// Two sessions: the one the change is made from, and another device's.
	first := doJSON(t, h, "POST", "/auth/login", oldCreds, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", first.Code, first.Body.String())
	}
	cookie := sessionCookieFrom(first)
	csrfCookie, csrfToken := csrfFrom(t, first)

	second := doJSON(t, h, "POST", "/auth/login", oldCreds, nil)
	if second.Code != http.StatusOK {
		t.Fatalf("second login = %d", second.Code)
	}
	otherCookie := sessionCookieFrom(second)

	// Snapshot credential row before the change.
	var hashBefore string
	var epochBefore time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash, updated_at FROM user_credential WHERE user_id = $1::uuid`,
		uid).Scan(&hashBefore, &epochBefore); err != nil {
		t.Fatalf("read credential before: %v", err)
	}

	// Wrong current password is refused; credential row is untouched.
	if rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: "wrong-password", NewEmail: "dana.new@emchg.test",
	}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong password = %d, want 403", rec.Code)
	}
	var hashStill string
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash FROM user_credential WHERE user_id = $1::uuid`, uid).Scan(&hashStill); err != nil {
		t.Fatalf("re-read hash: %v", err)
	}
	if hashStill != hashBefore {
		t.Fatal("rejected change still wrote the credential row")
	}

	// The real change.
	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: "Original-Passw0rd!", NewEmail: "dana.new@emchg.test",
	}, csrfToken, cookie, csrfCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Changed bool   `json:"changed"`
		Email   string `json:"email"`
		Revoked int    `json:"sessions_revoked"`
		CSRF    string `json:"csrf_token"`
		Expires string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Changed || body.Email != "dana.new@emchg.test" {
		t.Fatalf("response = %+v, want changed with new email", body)
	}
	if body.Revoked != 2 {
		t.Fatalf("sessions_revoked = %d, want 2", body.Revoked)
	}
	rotatedCookie := sessionCookieFrom(rec)
	if rotatedCookie == nil || rotatedCookie.Value == cookie.Value {
		t.Fatal("response did not issue a distinct replacement session cookie")
	}

	// DB: email updated, password hash unchanged, epoch advanced.
	var emailAfter, hashAfter string
	var epochAfter time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT u.email, c.password_hash, c.updated_at
		   FROM app_user u JOIN user_credential c ON c.user_id = u.id
		  WHERE u.id = $1::uuid`, uid).Scan(&emailAfter, &hashAfter, &epochAfter); err != nil {
		t.Fatalf("read after change: %v", err)
	}
	if emailAfter != "dana.new@emchg.test" {
		t.Fatalf("email in DB = %s, want dana.new@emchg.test", emailAfter)
	}
	if hashAfter != hashBefore {
		t.Fatal("password_hash changed after email change — must be preserved")
	}
	if !epochAfter.After(epochBefore) {
		t.Fatalf("credential epoch did not advance: before=%s after=%s", epochBefore, epochAfter)
	}

	// Sessions: both pre-change sessions are revoked; exactly one live session remains.
	var revokedCount, liveCount int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE revoked_at IS NOT NULL), count(*) FILTER (WHERE revoked_at IS NULL)
		   FROM user_session WHERE tenant_id=$1::uuid AND user_id=$2::uuid`,
		tid, uid).Scan(&revokedCount, &liveCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if revokedCount != 2 || liveCount != 1 {
		t.Fatalf("sessions: revoked=%d live=%d, want revoked=2 live=1", revokedCount, liveCount)
	}

	// Old sessions are dead.
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("original session post-change = %d, want 401", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, otherCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session post-change = %d, want 401", rec.Code)
	}
	// Rotated session works.
	if rec := doJSON(t, h, "GET", "/machines", nil, rotatedCookie); rec.Code != http.StatusOK {
		t.Fatalf("rotated session post-change = %d, want 200", rec.Code)
	}

	// Login boundary: old email refused, new email works.
	if rec := doJSON(t, h, "POST", "/auth/login", oldCreds, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old-email login = %d, want 401", rec.Code)
	}
	newCreds := loginRequest{Tenant: "emchg", Email: "dana.new@emchg.test", Password: "Original-Passw0rd!"}
	if rec := doJSON(t, h, "POST", "/auth/login", newCreds, nil); rec.Code != http.StatusOK {
		t.Fatalf("new-email login = %d: %s", rec.Code, rec.Body.String())
	}

	// Audit trail.
	events, err := audit.ListEvents(ctx, tid, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var sawChanged, sawFailed bool
	for _, e := range events {
		switch e.Action {
		case "auth.email_changed":
			sawChanged = true
			if !strings.Contains(string(e.Metadata), "dana@emchg.test") {
				t.Errorf("old_email missing from audit metadata: %s", e.Metadata)
			}
			if !strings.Contains(string(e.Metadata), "dana.new@emchg.test") {
				t.Errorf("new_email missing from audit metadata: %s", e.Metadata)
			}
			if strings.Contains(string(e.Metadata), "Passw0rd") {
				t.Errorf("password leaked into audit metadata: %s", e.Metadata)
			}
		case "auth.email_change_failed":
			sawFailed = true
		}
	}
	if !sawChanged || !sawFailed {
		t.Fatalf("audit actions missing (changed=%v failed=%v): %+v", sawChanged, sawFailed, events)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgSetEmailAtomicRollbackOnDuplicate: a duplicate email in the same transaction must roll
// back the email write entirely — the user's email must be unchanged after ErrEmailExists.
func TestPgSetEmailAtomicRollbackOnDuplicate(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "em-dup", "dana@em-dup.test", "Passw0rd-A!")

	// Insert a second user in the SAME tenant holding the target address (withTenant so
	// the RLS WITH CHECK is satisfied; suPool bypasses RLS as the owner role).
	var uidTaken string
	if err := suPool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&uidTaken); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
			uidTaken, tidA, "taken@em-dup.test")
		return err
	}); err != nil {
		t.Fatalf("insert taken user: %v", err)
	}

	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	uA, err := store.FindUserByEmail(ctx, tidA, "dana@em-dup.test")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	_, err = store.SetEmail(ctx, tidA, uidA, "taken@em-dup.test", uA.CredentialUpdatedAt)
	if err != ErrEmailExists {
		t.Fatalf("duplicate SetEmail = %v, want ErrEmailExists", err)
	}
	// email column must be unchanged in the DB.
	var emailInDB string
	if err := suPool.QueryRow(ctx,
		`SELECT email FROM app_user WHERE id = $1::uuid`, uidA).Scan(&emailInDB); err != nil {
		t.Fatalf("read email: %v", err)
	}
	if emailInDB != "dana@em-dup.test" {
		t.Fatalf("email changed to %s despite ErrEmailExists — rollback failed", emailInDB)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tidA); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
