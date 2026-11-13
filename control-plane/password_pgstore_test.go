package controlplane

// DB-gated proof for the password-change path (docs/01-feature-parity.md §10 P0). Everything here
// runs as the LEAST-PRIVILEGE `rmt_app` role — the role Row-Level Security is actually enforced
// against — because the interesting question is not "does the UPDATE run" but "can it reach a
// credential row outside the pinned tenant". Running these as the superuser/owner would bypass RLS
// and prove nothing (see the note at the top of 0005_app_role.sql).
//
// Like every pgx test these need TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a
// skip as a failure.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPgSetPasswordUnderRLS drives PgUserStore.SetPassword as rmt_app: the INSERT path (a user
// with no credential yet), the UPDATE path, and — the load-bearing case — a user id from ANOTHER
// tenant, which must write nothing at all.
func TestPgSetPasswordUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "pw-a", "dana@pw-a.test", "Original-Passw0rd!")
	tidB, uidB := provisionUser(t, suPool, "pw-b", "eve@pw-b.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	// --- UPDATE path: the user already has a credential (provisionUser inserted one).
	newHash, err := HashPassword("Replacement-Passw0rd!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := store.SetPassword(ctx, tidA, uidA, newHash); err != nil {
		t.Fatalf("SetPassword (update) as rmt_app: %v", err)
	}
	u, err := store.FindUserByEmail(ctx, tidA, "dana@pw-a.test")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if ok, err := VerifyPassword(u.PasswordHash, "Replacement-Passw0rd!"); err != nil || !ok {
		t.Fatalf("stored hash does not verify the new password (ok=%v err=%v)", ok, err)
	}
	if ok, _ := VerifyPassword(u.PasswordHash, "Original-Passw0rd!"); ok {
		t.Fatal("the OLD password still verifies against the stored hash")
	}

	// --- CROSS-TENANT: tenant A pinned, tenant B's user id. RLS confines the app_user subquery
	// the tenant is derived from, so this matches no row → ErrNoUser, and tenant B's credential
	// must be byte-for-byte untouched.
	var bHashBefore string
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash FROM user_credential WHERE user_id = $1::uuid`, uidB).Scan(&bHashBefore); err != nil {
		t.Fatalf("read tenant B credential: %v", err)
	}
	attacker, err := HashPassword("Attacker-Chosen-Passw0rd!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := store.SetPassword(ctx, tidA, uidB, attacker); err != ErrNoUser {
		t.Fatalf("cross-tenant SetPassword err = %v, want ErrNoUser", err)
	}
	var bHashAfter string
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash FROM user_credential WHERE user_id = $1::uuid`, uidB).Scan(&bHashAfter); err != nil {
		t.Fatalf("re-read tenant B credential: %v", err)
	}
	if bHashAfter != bHashBefore {
		t.Fatal("a tenant-A-pinned SetPassword modified tenant B's credential")
	}
	// And tenant B's own password still works, i.e. nothing was silently rewritten.
	if ok, err := VerifyPassword(bHashAfter, "Other-Passw0rd!"); err != nil || !ok {
		t.Fatalf("tenant B credential no longer verifies (ok=%v err=%v)", ok, err)
	}

	// --- INSERT path: a user with NO credential row yet (the OIDC-only shape).
	var uidC string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&uidC); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
			uidC, tidA, "nocred@pw-a.test")
		return err
	}); err != nil {
		t.Fatalf("seed credential-less user: %v", err)
	}
	freshHash, err := HashPassword("Provisioned-Passw0rd!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := store.SetPassword(ctx, tidA, uidC, freshHash); err != nil {
		t.Fatalf("SetPassword (insert) as rmt_app: %v", err)
	}
	// The tenant_id was derived from the USER'S row, not from the parameter — check the DB agrees.
	var storedTenant string
	if err := suPool.QueryRow(ctx,
		`SELECT tenant_id::text FROM user_credential WHERE user_id = $1::uuid`, uidC).Scan(&storedTenant); err != nil {
		t.Fatalf("read inserted credential: %v", err)
	}
	if storedTenant != tidA {
		t.Fatalf("inserted credential tenant = %s, want %s", storedTenant, tidA)
	}

	// --- An unknown user id is ErrNoUser, not a silent success.
	var ghost string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&ghost); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if _, err := store.SetPassword(ctx, tidA, ghost, freshHash); err != ErrNoUser {
		t.Fatalf("SetPassword for an unknown user = %v, want ErrNoUser", err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgRevokeAllForUserUnderRLS proves the mass-revocation primitive is tenant-scoped and honours
// the keep-token, as rmt_app.
func TestPgRevokeAllForUserUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "rev-a", "dana@rev-a.test", "Original-Passw0rd!")
	tidB, uidB := provisionUser(t, suPool, "rev-b", "eve@rev-b.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	sessions := NewSessionManager(NewPgSessionStore(appPool))

	keepToken, _, err := sessions.Issue(ctx, tidA, uidA, time.Time{})
	if err != nil {
		t.Fatalf("issue keep session: %v", err)
	}
	for range 3 {
		if _, _, err := sessions.Issue(ctx, tidA, uidA, time.Time{}); err != nil {
			t.Fatalf("issue extra session: %v", err)
		}
	}
	bToken, _, err := sessions.Issue(ctx, tidB, uidB, time.Time{})
	if err != nil {
		t.Fatalf("issue tenant-B session: %v", err)
	}

	n, err := sessions.RevokeOtherSessions(ctx, tidA, uidA, keepToken)
	if err != nil {
		t.Fatalf("RevokeOtherSessions as rmt_app: %v", err)
	}
	if n != 3 {
		t.Fatalf("revoked %d sessions, want 3", n)
	}
	// The kept session still validates; the others do not.
	if _, err := sessions.Validate(ctx, keepToken); err != nil {
		t.Fatalf("kept session no longer validates: %v", err)
	}
	// Tenant B's session is untouched — the UPDATE ran RLS-pinned to A.
	if _, err := sessions.Validate(ctx, bToken); err != nil {
		t.Fatalf("tenant B session was revoked by a tenant-A revocation: %v", err)
	}
	var liveA, liveB int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_session WHERE tenant_id=$1::uuid AND revoked_at IS NULL`, tidA).Scan(&liveA); err != nil {
		t.Fatalf("count tenant A: %v", err)
	}
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_session WHERE tenant_id=$1::uuid AND revoked_at IS NULL`, tidB).Scan(&liveB); err != nil {
		t.Fatalf("count tenant B: %v", err)
	}
	if liveA != 1 || liveB != 1 {
		t.Fatalf("live sessions: tenantA=%d (want 1), tenantB=%d (want 1)", liveA, liveB)
	}

	// Re-running is idempotent and reports 0 — already-revoked rows are not re-stamped.
	if n, err := sessions.RevokeOtherSessions(ctx, tidA, uidA, keepToken); err != nil || n != 0 {
		t.Fatalf("second revocation = (%d, %v), want (0, nil)", n, err)
	}
	// An EMPTY keep token revokes everything, including the caller's own.
	if n, err := sessions.RevokeOtherSessions(ctx, tidA, uidA, ""); err != nil || n != 1 {
		t.Fatalf("revoke-all = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := sessions.Validate(ctx, keepToken); err == nil {
		t.Fatal("revoke-all left the previously kept session alive")
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgPasswordChangeAsAppRole is the end-to-end DB proof: the full HTTP chain
// (csrf → auth → PgBinder → handler → pgx stores) against real Postgres AS rmt_app. It proves the
// property that actually matters to a user — after the change, the old password no longer logs in,
// the new one does, and the other device's session is dead in the database.
func TestPgPasswordChangeAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "pwchg", "dana@pwchg.test", "Original-Passw0rd!")
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

	oldCreds := loginRequest{Tenant: "pwchg", Email: "dana@pwchg.test", Password: "Original-Passw0rd!"}

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
	if rec := doJSON(t, h, "GET", "/machines", nil, otherCookie); rec.Code != http.StatusOK {
		t.Fatalf("other session pre-change = %d, want 200", rec.Code)
	}

	// A wrong current password is refused, and the credential row is untouched.
	var hashBefore string
	var updatedBefore time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash, updated_at FROM user_credential WHERE user_id = $1::uuid`,
		uid).Scan(&hashBefore, &updatedBefore); err != nil {
		t.Fatalf("read credential: %v", err)
	}
	if rec := doJSONWith(t, h, "POST", "/me/password", changePasswordRequest{
		CurrentPassword: "wrong-password", NewPassword: "Replacement-Passw0rd!",
	}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong current password = %d, want 403", rec.Code)
	}
	var hashStill string
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash FROM user_credential WHERE user_id = $1::uuid`, uid).Scan(&hashStill); err != nil {
		t.Fatalf("re-read credential: %v", err)
	}
	if hashStill != hashBefore {
		t.Fatal("a rejected change still wrote the credential")
	}

	// A policy-violating new password is refused with machine-readable reasons.
	weak := doJSONWith(t, h, "POST", "/me/password", changePasswordRequest{
		CurrentPassword: "Original-Passw0rd!", NewPassword: "dana-dana-dana",
	}, csrfToken, cookie, csrfCookie)
	if weak.Code != http.StatusBadRequest {
		t.Fatalf("weak new password = %d, want 400: %s", weak.Code, weak.Body.String())
	}

	// The real change.
	rec := doJSONWith(t, h, "POST", "/me/password", changePasswordRequest{
		CurrentPassword: "Original-Passw0rd!", NewPassword: "Replacement-Passw0rd!",
	}, csrfToken, cookie, csrfCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Changed bool `json:"changed"`
		Revoked int  `json:"sessions_revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// BOTH live sessions are revoked — the other device's and the caller's own, which is rotated.
	if !body.Changed || body.Revoked != 2 {
		t.Fatalf("response = %+v, want changed with 2 revoked", body)
	}
	rotatedCookie := sessionCookieFrom(rec)
	if rotatedCookie == nil || rotatedCookie.Value == cookie.Value {
		t.Fatal("the change did not issue a replacement session cookie")
	}

	// The DATABASE agrees: a new argon2id hash, verifying the new password and not the old, with
	// updated_at moved forward — and no plaintext anywhere in the row.
	var hashAfter string
	var updatedAfter time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash, updated_at FROM user_credential WHERE user_id = $1::uuid`,
		uid).Scan(&hashAfter, &updatedAfter); err != nil {
		t.Fatalf("read changed credential: %v", err)
	}
	if hashAfter == hashBefore {
		t.Fatal("credential hash unchanged after a successful change")
	}
	if !updatedAfter.After(updatedBefore) {
		t.Fatalf("updated_at did not advance: before=%s after=%s", updatedBefore, updatedAfter)
	}
	if !strings.HasPrefix(hashAfter, "$argon2id$") {
		t.Fatalf("stored credential is not an argon2id PHC string: %q", hashAfter)
	}
	if strings.Contains(hashAfter, "Replacement-Passw0rd!") {
		t.Fatal("stored credential contains the plaintext password")
	}
	if ok, err := VerifyPassword(hashAfter, "Replacement-Passw0rd!"); err != nil || !ok {
		t.Fatalf("stored hash does not verify the new password (ok=%v err=%v)", ok, err)
	}
	if ok, _ := VerifyPassword(hashAfter, "Original-Passw0rd!"); ok {
		t.Fatal("stored hash still verifies the OLD password")
	}

	// Every pre-change session is revoked IN THE DATABASE (both of them), and exactly one live
	// session remains: the replacement this response issued.
	var revokedCount, liveCount int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE revoked_at IS NOT NULL), count(*) FILTER (WHERE revoked_at IS NULL)
		   FROM user_session WHERE tenant_id=$1::uuid AND user_id=$2::uuid`,
		tid, uid).Scan(&revokedCount, &liveCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if revokedCount != 2 || liveCount != 1 {
		t.Fatalf("sessions: revoked=%d live=%d, want revoked=2 live=1 (the rotated replacement)",
			revokedCount, liveCount)
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, otherCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session post-change = %d, want 401", rec.Code)
	}
	// The token the caller PRESENTED is dead; the rotated one works.
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the presented session survived the change (%d); it must be rotated", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, rotatedCookie); rec.Code != http.StatusOK {
		t.Fatalf("rotated session post-change = %d, want 200", rec.Code)
	}

	// The login boundary is the real proof.
	if rec := doJSON(t, h, "POST", "/auth/login", oldCreds, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with the OLD password = %d, want 401", rec.Code)
	}
	newCreds := oldCreds
	newCreds.Password = "Replacement-Passw0rd!"
	if rec := doJSON(t, h, "POST", "/auth/login", newCreds, nil); rec.Code != http.StatusOK {
		t.Fatalf("login with the NEW password = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Audited: one failure, one success.
	events, err := audit.ListEvents(ctx, tid, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var sawChanged, sawFailed bool
	for _, e := range events {
		switch e.Action {
		case "auth.password_changed":
			sawChanged = true
		case "auth.password_change_failed":
			sawFailed = true
		}
		if strings.Contains(string(e.Metadata), "Passw0rd") {
			t.Fatalf("audit metadata leaked a password: %s", e.Metadata)
		}
	}
	if !sawChanged || !sawFailed {
		t.Fatalf("audit actions missing (changed=%v failed=%v): %+v", sawChanged, sawFailed, events)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgCredentialEpochUnderRLS is the DB-gated proof of the password-change TOCTOU fix
// (migrations/0018), driven against real Postgres as the least-privilege rmt_app role.
//
// It matters that this exists separately from the in-memory test. Three things here are properties
// of STORAGE, not of the Go code, and each has already been the shape of a real bug in this repo:
//
//   - the epoch is Postgres's own now(), taken inside SetPassword's transaction, so the Go process's
//     clock never defines a credential version;
//   - it survives the timestamptz round trip into user_session.credential_epoch and back out through
//     cp_session_by_token (which is `RETURNS SETOF user_session`, so the new column rides along);
//   - a NULL epoch — the pre-0018 row shape — is read back as the zero time and therefore fails
//     CLOSED, rather than being read as "no constraint".
//
// The race is driven in the order that produces the vulnerable session: read the credential, THEN
// change the password (revoking everything), THEN insert the racing session.
func TestPgCredentialEpochUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "epoch", "dana@epoch.test", "Original-Passw0rd!")
	appPool := newAppRolePool(t, ctx)
	users := newPgUserStoreT(appPool)
	sessions := NewSessionManager(NewPgSessionStore(appPool))
	sa := &SessionAuthenticator{Sessions: sessions, Users: users}

	// (1) The racing login's credential read: the epoch that accompanied the hash it verified.
	racer, err := users.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if racer.CredentialUpdatedAt.IsZero() {
		t.Fatal("the pg store did not carry user_credential.updated_at onto AuthUser — the epoch " +
			"must come from the same read as the hash")
	}

	// (2) The password change. The epoch it returns is the DB's, and must be strictly newer.
	newHash, err := HashPassword("Replacement-Passw0rd!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	epoch, err := users.SetPassword(ctx, tid, uid, newHash)
	if err != nil {
		t.Fatalf("SetPassword as rmt_app: %v", err)
	}
	if !epoch.After(racer.CredentialUpdatedAt) {
		t.Fatalf("SetPassword returned epoch %v, not after the previous %v — RETURNING updated_at "+
			"must advance the version", epoch, racer.CredentialUpdatedAt)
	}
	var dbEpoch time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT updated_at FROM user_credential WHERE user_id = $1::uuid`, uid).Scan(&dbEpoch); err != nil {
		t.Fatalf("read credential epoch: %v", err)
	}
	if !dbEpoch.UTC().Equal(epoch) {
		t.Fatalf("SetPassword returned %v but the row holds %v — the epoch must be the STORED value",
			epoch, dbEpoch.UTC())
	}
	// Every session is revoked by the change, exactly as HandleChangePassword does.
	if _, err := sessions.RevokeOtherSessions(ctx, tid, uid, ""); err != nil {
		t.Fatalf("RevokeOtherSessions: %v", err)
	}

	// (3) The racing login inserts its session AFTER the revocation, carrying the OLD epoch.
	raced, racedSess, err := sessions.Issue(ctx, tid, uid, racer.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue (racing login): %v", err)
	}
	var revokedAt *time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT revoked_at FROM user_session WHERE id = $1::uuid`, racedSess.ID).Scan(&revokedAt); err != nil {
		t.Fatalf("read raced session: %v", err)
	}
	if revokedAt != nil {
		t.Fatal("test premise: the raced session must be UNREVOKED in the database — otherwise " +
			"revocation, not the epoch, is what this test measures")
	}
	// It validates as a session (unrevoked, unexpired) and is still refused by the authenticator.
	if _, err := sessions.Validate(ctx, raced); err != nil {
		t.Fatalf("the raced session is not even a live session (%v); the test would prove nothing", err)
	}
	if _, err := sa.Authenticate(bearerRequest(raced)); err != ErrSessionCredentialStale {
		t.Fatalf("Authenticate(raced session) = %v, want ErrSessionCredentialStale — a session "+
			"authorized by the RETIRED password must not authenticate", err)
	}

	// A session on the CURRENT epoch works, so the check is not simply refusing everything.
	fresh, _, err := sessions.Issue(ctx, tid, uid, epoch)
	if err != nil {
		t.Fatalf("Issue (post-change): %v", err)
	}
	if _, err := sa.Authenticate(bearerRequest(fresh)); err != nil {
		t.Fatalf("Authenticate(current-epoch session) = %v, want success", err)
	}
	// …and the value really made the round trip, rather than being remembered in process.
	stored, err := sessions.Store.GetByTokenHash(ctx, HashToken(fresh))
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if !stored.CredentialEpoch.Equal(epoch) {
		t.Fatalf("credential_epoch round-tripped as %v, want %v", stored.CredentialEpoch, epoch)
	}

	// THE PRE-0018 ROW SHAPE: credential_epoch NULL. It must read back as the zero time and be
	// refused for a user who has a credential — "unknown version" is not "any version".
	if _, err := suPool.Exec(ctx,
		`UPDATE user_session SET credential_epoch = NULL WHERE id = $1::uuid`, stored.ID); err != nil {
		t.Fatalf("null out credential_epoch: %v", err)
	}
	nulled, err := sessions.Store.GetByTokenHash(ctx, HashToken(fresh))
	if err != nil {
		t.Fatalf("GetByTokenHash after NULL: %v", err)
	}
	if !nulled.CredentialEpoch.IsZero() {
		t.Fatalf("a NULL credential_epoch read back as %v, want the zero time", nulled.CredentialEpoch)
	}
	if _, err := sa.Authenticate(bearerRequest(fresh)); err != ErrSessionCredentialStale {
		t.Fatalf("Authenticate(NULL-epoch session) = %v, want ErrSessionCredentialStale — an "+
			"unbackfilled pre-0018 row must fail CLOSED", err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// 0018 DELIBERATELY DOES NOT BACKFILL, executed as the shipped migration file rather than as a
// paraphrase of it. This test exists because the first draft DID backfill, and the closing review
// confirmed that as the loop's one real defect.
//
// The draft set every live session's epoch to the credential's CURRENT updated_at, arguing that a
// password change revokes every session so a live session must postdate the last change. Two
// reachable states falsify it, and both are exactly the states the epoch was written to refuse:
//
//   - a FAILED-REVOCATION ORPHAN. HandleChangePassword writes the credential and revokes in
//     separate transactions and returns 500 when the revocation fails AFTER the password changed,
//     leaving a live unrevoked session on the retired password.
//   - a PRE-0018 RACED SESSION, which is what the whole migration is for.
//
// A tighter predicate was considered and REJECTED: `AND s.created_at > c.updated_at` excludes the
// orphan (issued before the change) but NOT the raced session, which by construction is inserted
// AFTER the credential write. It fixes the lesser case and misses the primary one.
//
// So nothing is written for a pre-0018 row: its credential version is genuinely unknown, and NULL
// says so and fails closed. The cost is one forced re-login at upgrade, which is the correct price.
func TestPgCredentialEpochMigrationDoesNotLaunderPreexistingSessions(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "backfill", "dana@backfill.test", "Original-Passw0rd!")
	appPool := newAppRolePool(t, ctx)
	users := newPgUserStoreT(appPool)
	sessions := NewSessionManager(NewPgSessionStore(appPool))

	u, err := users.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	// An ORPHAN: live, unrevoked, unexpired, and authorized by a credential that has since been
	// replaced — the shape a failed revocation leaves behind.
	orphan, orphanSess, err := sessions.Issue(ctx, tid, uid, u.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue orphan: %v", err)
	}
	newHash, err := HashPassword("Replacement-Passw0rd!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := users.SetPassword(ctx, tid, uid, newHash); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	// Rewind to the pre-0018 shape: no epoch recorded at all, revocation never happened.
	if _, err := suPool.Exec(ctx,
		`UPDATE user_session SET credential_epoch = NULL WHERE tenant_id = $1::uuid`, tid); err != nil {
		t.Fatalf("rewind epochs: %v", err)
	}

	// Re-run the SHIPPED migration (idempotent: ADD COLUMN IF NOT EXISTS), so what is under test is
	// the file an operator will actually apply.
	b, err := os.ReadFile("migrations/0018_credential_epoch.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	execScript(t, suPool, string(b))

	var epoch *time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT credential_epoch FROM user_session WHERE id = $1::uuid`, orphanSess.ID).Scan(&epoch); err != nil {
		t.Fatalf("read epoch: %v", err)
	}
	if epoch != nil {
		t.Fatalf("the migration stamped %v onto a pre-0018 session; a version we do not know must "+
			"not be invented — it launders exactly the sessions the epoch exists to refuse", epoch.UTC())
	}
	// …and the consequence that matters: it does not authenticate.
	sa := &SessionAuthenticator{Sessions: sessions, Users: users}
	if _, err := sa.Authenticate(bearerRequest(orphan)); err != ErrSessionCredentialStale {
		t.Fatalf("Authenticate(pre-0018 orphan) = %v, want ErrSessionCredentialStale", err)
	}
	// A session issued by the NEW binary is unaffected — the forced logout is one-time, not permanent.
	after, err := users.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	fresh, _, err := sessions.Issue(ctx, tid, uid, after.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue fresh: %v", err)
	}
	if _, err := sa.Authenticate(bearerRequest(fresh)); err != nil {
		t.Fatalf("Authenticate(post-migration session) = %v, want success", err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
