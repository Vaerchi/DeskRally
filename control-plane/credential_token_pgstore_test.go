package controlplane

// DB-gated proof for the credential-token path (first-password provisioning / admin reset).
//
// WHAT THIS FILE CARRIES THAT credential_token_test.go CANNOT. Those tests run against
// InMemoryCredentialTokenStore, so they pin the HANDLER: status codes, the capability and
// hierarchy checks, what a redemption touches. They would stay green if the SQL wrote the wrong
// tenant_id, let a consumed token be consumed twice, or ignored a suspended tenant — because the
// fake decides all of that in Go. Only a real database can pin those, and only as the LEAST-
// PRIVILEGE `rmt_app` role, the role Row-Level Security is actually enforced against; running as
// the superuser/owner would bypass RLS and prove nothing (see the note at the top of
// 0005_app_role.sql).
//
// Like every pgx test these need TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a
// skip as a failure.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyCredentialTokenMigration lays 0020 (user_credential_token + the two SECURITY DEFINER
// helpers) on top of the schema newTestPool applied. resetSchema DROPs both the table and the
// functions, so this is re-runnable.
func applyCredentialTokenMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0020_credential_token.sql")
	if err != nil {
		t.Fatalf("read 0020: %v", err)
	}
	execScript(t, pool, string(b))
}

// seedCredentiallessUser inserts an app_user with NO user_credential row — the account shape that
// POST /me/password answers 409 for and that this whole feature exists to serve.
func seedCredentiallessUser(t *testing.T, pool *pgxpool.Pool, tenantID, email string) string {
	t.Helper()
	ctx := context.Background()
	var uid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&uid); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if err := withTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
			uid, tenantID, email)
		return err
	}); err != nil {
		t.Fatalf("seed credential-less user: %v", err)
	}
	return uid
}

// grantRole attaches a preset role membership (tenant-wide) to a user.
func grantRole(t *testing.T, pool *pgxpool.Pool, tenantID, userID string, role Role) {
	t.Helper()
	ctx := context.Background()
	if err := withTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		var roleID string
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key=$1 AND tenant_id IS NULL`, string(role)).Scan(&roleID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids) VALUES ($1,$2,$3,'{}')`,
			tenantID, userID, roleID)
		return err
	}); err != nil {
		t.Fatalf("grant %s: %v", role, err)
	}
}

// TestPgCredentialTokenUnderRLS drives PgCredentialTokenStore as rmt_app. Everything here is a
// property of the SQL, not of the handler: which tenant the row lands in, whether a consumed token
// can be consumed again, whether a suspended tenant or disabled user still admits a redemption,
// and whether a tenant-pinned revoke can reach across the boundary.
func TestPgCredentialTokenUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyCredentialTokenMigration(t, suPool)
	// 0005 ran before the table existed in the reset schema, so its ALTER DEFAULT PRIVILEGES is
	// what grants rmt_app DML here. Re-applying it after the table exists would ALSO work via the
	// blanket GRANT — applying it only once, first, is the harder case and the one production has.
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "ct-a", "dana@ct-a.test", "Original-Passw0rd!")
	tidB, uidB := provisionUser(t, suPool, "ct-b", "eve@ct-b.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	store := NewPgCredentialTokenStore(appPool)

	// --- MINT lands in the user's own tenant, and the PLAINTEXT is not in the row.
	plaintext, tok, err := store.Mint(ctx, tidA, uidA, uidA, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Mint as rmt_app: %v", err)
	}
	if tok.TenantID != tidA || tok.UserID != uidA {
		t.Fatalf("minted token = tenant %s user %s, want %s / %s", tok.TenantID, tok.UserID, tidA, uidA)
	}
	var storedHash []byte
	var storedTenant string
	if err := suPool.QueryRow(ctx,
		`SELECT token_hash, tenant_id::text FROM user_credential_token WHERE id = $1::uuid`,
		tok.ID).Scan(&storedHash, &storedTenant); err != nil {
		t.Fatalf("read minted row: %v", err)
	}
	if storedTenant != tidA {
		t.Fatalf("stored tenant = %s, want %s (it must come from the USER'S row)", storedTenant, tidA)
	}
	if string(storedHash) != string(HashToken(plaintext)) {
		t.Fatal("the stored token_hash is not the SHA-256 of the returned secret")
	}
	var plaintextRows int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_credential_token WHERE encode(token_hash,'escape') = $1`,
		plaintext).Scan(&plaintextRows); err != nil {
		t.Fatalf("scan for a stored plaintext: %v", err)
	}
	if plaintextRows != 0 {
		t.Fatal("the plaintext secret is stored in the table")
	}

	// --- CROSS-TENANT MINT: tenant A pinned, tenant B's user id. The INSERT derives tenant_id
	// from a SELECT on app_user, which RLS confines to the pinned tenant, so it matches no row.
	if _, _, err := store.Mint(ctx, tidA, uidB, uidA, time.Now().Add(time.Hour)); err != ErrNoUser {
		t.Fatalf("cross-tenant Mint err = %v, want ErrNoUser", err)
	}
	var forB int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_credential_token WHERE user_id = $1::uuid`, uidB).Scan(&forB); err != nil {
		t.Fatalf("count tenant B tokens: %v", err)
	}
	if forB != 0 {
		t.Fatalf("a tenant-A-pinned mint created %d token(s) for tenant B's user", forB)
	}

	// --- PEEK does not consume; CONSUME does, exactly once.
	if _, err := store.Peek(ctx, plaintext); err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if _, err := store.Peek(ctx, plaintext); err != nil {
		t.Fatalf("second Peek (it must not have consumed anything): %v", err)
	}
	if _, err := store.Consume(ctx, plaintext); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, err := store.Consume(ctx, plaintext); err != ErrCredentialTokenInvalid {
		t.Fatalf("second Consume = %v, want ErrCredentialTokenInvalid — the token is single-use", err)
	}
	if _, err := store.Peek(ctx, plaintext); err != ErrCredentialTokenInvalid {
		t.Fatalf("Peek after Consume = %v, want ErrCredentialTokenInvalid", err)
	}

	// --- SUPERSEDE: minting revokes the user's outstanding tokens, in the same transaction.
	firstTok, _, err := store.Mint(ctx, tidA, uidA, uidA, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Mint (first): %v", err)
	}
	secondTok, _, err := store.Mint(ctx, tidA, uidA, uidA, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Mint (second): %v", err)
	}
	if _, err := store.Peek(ctx, firstTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("superseded token Peek = %v, want ErrCredentialTokenInvalid", err)
	}
	if _, err := store.Peek(ctx, secondTok); err != nil {
		t.Fatalf("newest token Peek: %v", err)
	}

	// --- EXPIRY is enforced by the FUNCTION, not by Go. Backdate the row and re-peek.
	if _, err := suPool.Exec(ctx,
		`UPDATE user_credential_token SET expires_at = now() - interval '1 second'
		  WHERE user_id = $1::uuid AND consumed_at IS NULL AND revoked_at IS NULL`, uidA); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	if _, err := store.Peek(ctx, secondTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("expired token Peek = %v, want ErrCredentialTokenInvalid", err)
	}
	// CONSUME enforces it too. Asserting only through Peek would leave the whole predicate
	// deletable from cp_credential_token_consume with the suite still green — and consume is the
	// gate that actually authorizes the write, so it is the one that must hold.
	if _, err := store.Consume(ctx, secondTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("expired token Consume = %v, want ErrCredentialTokenInvalid", err)
	}

	// --- A DISABLED USER's outstanding link is dead. Without this, disabling an account would
	// leave a working back door into it.
	disabledTok, _, err := store.Mint(ctx, tidA, uidA, uidA, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Mint (disabled-user case): %v", err)
	}
	if _, err := suPool.Exec(ctx, `UPDATE app_user SET disabled_at = now() WHERE id = $1::uuid`, uidA); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if _, err := store.Peek(ctx, disabledTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("disabled user's token Peek = %v, want ErrCredentialTokenInvalid", err)
	}
	if _, err := store.Consume(ctx, disabledTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("disabled user's token Consume = %v, want ErrCredentialTokenInvalid", err)
	}
	if _, err := suPool.Exec(ctx, `UPDATE app_user SET disabled_at = NULL WHERE id = $1::uuid`, uidA); err != nil {
		t.Fatalf("re-enable user: %v", err)
	}
	// Re-enabling brings the SAME token back — proving the refusal above was the disabled flag and
	// not the token having been quietly consumed by the attempt.
	if _, err := store.Peek(ctx, disabledTok); err != nil {
		t.Fatalf("token Peek after re-enabling the user: %v", err)
	}

	// --- A SUSPENDED TENANT's links are dead too (the lesson of 0011: suspension has to mean the
	// same thing on every path that admits a new principal).
	if _, err := suPool.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1::uuid`, tidA); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}
	if _, err := store.Peek(ctx, disabledTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("suspended tenant's token Peek = %v, want ErrCredentialTokenInvalid", err)
	}
	if _, err := store.Consume(ctx, disabledTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("suspended tenant's token Consume = %v, want ErrCredentialTokenInvalid", err)
	}
	if _, err := suPool.Exec(ctx, `UPDATE tenant SET disabled_at = NULL WHERE id = $1::uuid`, tidA); err != nil {
		t.Fatalf("unsuspend tenant: %v", err)
	}

	// --- REVOKE is tenant-pinned: pinned to A, B's user id revokes nothing and leaves B's token
	// alive. (Seed B a token through the store, pinned to B.)
	bTok, _, err := store.Mint(ctx, tidB, uidB, uidB, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Mint for tenant B: %v", err)
	}
	n, err := store.RevokeForUser(ctx, tidA, uidB)
	if err != nil {
		t.Fatalf("cross-tenant RevokeForUser: %v", err)
	}
	if n != 0 {
		t.Fatalf("a tenant-A-pinned revoke reached %d of tenant B's tokens", n)
	}
	if _, err := store.Peek(ctx, bTok); err != nil {
		t.Fatalf("tenant B's token was revoked across the tenant boundary: %v", err)
	}
	// In its own tenant it works.
	if n, err := store.RevokeForUser(ctx, tidB, uidB); err != nil || n != 1 {
		t.Fatalf("RevokeForUser in-tenant = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := store.Peek(ctx, bTok); err != ErrCredentialTokenInvalid {
		t.Fatalf("revoked token Peek = %v, want ErrCredentialTokenInvalid", err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgCredentialTokenConcurrentMintsLeaveOneLiveLink drives the race the first version of Mint
// lost: two mints for the SAME user at the same time.
//
// One transaction is not enough on its own. withTenant pins READ COMMITTED, under which the
// supersede UPDATE cannot see a row a concurrent transaction has inserted but not committed, and
// has nothing to block on — so both mints used to commit and leave TWO live account-takeover links
// while the administrator who double-clicked believed there was one, with the older shown as
// superseded. A per-user advisory lock serializes them; the partial unique index is the backstop.
//
// This is DB-only by nature: the in-memory fake takes a mutex around the same pair, so it never
// exhibited the bug and its passing said nothing about production.
func TestPgCredentialTokenConcurrentMintsLeaveOneLiveLink(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyCredentialTokenMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "ct-race", "dana@ct-race.test", "Original-Passw0rd!")
	appPool := newAppRolePool(t, ctx)
	store := NewPgCredentialTokenStore(appPool)

	const racers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, racers)
	toks := make([]string, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release them together, so the transactions genuinely overlap
			plaintext, _, err := store.Mint(ctx, tid, uid, uid, time.Now().Add(time.Hour))
			toks[i], errs[i] = plaintext, err
		}(i)
	}
	close(start)
	wg.Wait()

	minted := 0
	for i, err := range errs {
		if err != nil {
			// A unique-violation here would mean the advisory lock failed to order the writers and
			// the index caught it — still safe, but it is not the behaviour being claimed.
			t.Fatalf("concurrent Mint %d failed: %v", i, err)
		}
		minted++
	}
	if minted != racers {
		t.Fatalf("only %d of %d mints succeeded", minted, racers)
	}

	// EXACTLY ONE live link survives, per the database's own count.
	var live int
	if err := suPool.QueryRow(ctx, `
		SELECT count(*) FROM user_credential_token
		 WHERE user_id = $1::uuid AND consumed_at IS NULL AND revoked_at IS NULL`, uid).Scan(&live); err != nil {
		t.Fatalf("count live tokens: %v", err)
	}
	if live != 1 {
		t.Fatalf("%d live credential tokens after %d concurrent mints, want exactly 1 — "+
			"each one is an account-takeover primitive", live, racers)
	}
	// And it is redeemable: the survivor is a real link, not a wedged row.
	redeemable := 0
	for _, tk := range toks {
		if _, err := store.Peek(ctx, tk); err == nil {
			redeemable++
		}
	}
	if redeemable != 1 {
		t.Fatalf("%d of the %d minted secrets still redeem, want exactly 1", redeemable, racers)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgCredentialTokenRLSHidesOtherTenants proves the table's own RLS policy, independently of
// the store's queries: pinned to tenant A, tenant B's token rows are not visible at all. The
// store's tenant-scoped statements are one layer; this is the layer underneath them, the one that
// still holds when a future query forgets its WHERE clause.
func TestPgCredentialTokenRLSHidesOtherTenants(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyCredentialTokenMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "ctrls-a", "dana@ctrls-a.test", "Original-Passw0rd!")
	tidB, uidB := provisionUser(t, suPool, "ctrls-b", "eve@ctrls-b.test", "Other-Passw0rd!")

	appPool := newAppRolePool(t, ctx)
	store := NewPgCredentialTokenStore(appPool)
	if _, _, err := store.Mint(ctx, tidA, uidA, uidA, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Mint A: %v", err)
	}
	if _, _, err := store.Mint(ctx, tidB, uidB, uidB, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Mint B: %v", err)
	}

	// An UNFILTERED select, pinned to A: RLS must return only A's row.
	var seenTenants []string
	if err := withTenant(ctx, appPool, tidA, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text FROM user_credential_token`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			seenTenants = append(seenTenants, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("unfiltered select pinned to A: %v", err)
	}
	if len(seenTenants) != 1 || seenTenants[0] != tidA {
		t.Fatalf("pinned to tenant A, an unfiltered SELECT saw %v; want exactly [%s]", seenTenants, tidA)
	}
	// The superuser sees both, so the assertion above is RLS filtering rather than an empty table.
	var total int
	if err := suPool.QueryRow(ctx, `SELECT count(*) FROM user_credential_token`).Scan(&total); err != nil {
		t.Fatalf("count all: %v", err)
	}
	if total != 2 {
		t.Fatalf("table holds %d rows, want 2 — the RLS assertion above was vacuous", total)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgPasswordResetChainAsAppRole is the end-to-end DB proof: the full HTTP chain
// (csrf → auth → PgBinder → handler → pgx stores) against real Postgres AS rmt_app, for an account
// that has NO credential at all. It proves the property a user cares about — an account that could
// not log in before can log in after — and it proves it at the login boundary, where a broken write
// would show up, rather than by reading back the row the handler just wrote.
func TestPgPasswordResetChainAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyCredentialTokenMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool)
	ctx := context.Background()

	// The admin has a password (they log in); the target has NONE.
	tid, adminID := provisionUser(t, suPool, "pwreset", "admin@pwreset.test", "Admin-Passw0rd!")
	grantRole(t, suPool, tid, adminID, RoleAdmin)
	targetID := seedCredentiallessUser(t, suPool, tid, "dana@pwreset.test")
	grantRole(t, suPool, tid, targetID, RoleTechnician)

	appPool := newAppRolePool(t, ctx)
	users := newPgUserStoreT(appPool)
	sessions := NewSessionManager(NewPgSessionStore(appPool))
	mgmtAudit := NewPgMgmtAuditStore(appPool)
	authSvc := &AuthService{
		Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(appPool),
		Issuer: "RMT", MgmtAudit: mgmtAudit,
		CredentialTokens: NewPgCredentialTokenStore(appPool),
	}
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(appPool))
	srv.AuthAPI = authSvc
	srv.MgmtAudit = mgmtAudit
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	h := srv.Handler()

	targetCreds := loginRequest{Tenant: "pwreset", Email: "dana@pwreset.test", Password: "Provisioned-Passw0rd!"}
	// Before: the account genuinely cannot log in.
	if rec := doJSON(t, h, "POST", "/auth/login", targetCreds, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login before provisioning = %d, want 401", rec.Code)
	}

	// The admin logs in and mints.
	adminLogin := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "pwreset", Email: "admin@pwreset.test", Password: "Admin-Passw0rd!"}, nil)
	if adminLogin.Code != http.StatusOK {
		t.Fatalf("admin login = %d: %s", adminLogin.Code, adminLogin.Body.String())
	}
	adminCookie := sessionCookieFrom(adminLogin)
	csrfCookie, csrfToken := csrfFrom(t, adminLogin)

	// The mint carries the ADMIN'S OWN password: minting a takeover link is a step-up operation,
	// not something a live session alone authorizes (HandleIssuePasswordReset).
	mintBody := map[string]any{"password": "Admin-Passw0rd!"}
	mint := doJSONWith(t, h, "POST", "/users/"+targetID+"/password-reset", mintBody, csrfToken, adminCookie, csrfCookie)
	if mint.Code != http.StatusCreated {
		t.Fatalf("mint = %d: %s", mint.Code, mint.Body.String())
	}
	var minted struct {
		Token           string `json:"token"`
		FirstProvision  bool   `json:"first_provision"`
		CredentialToken struct {
			ID string `json:"id"`
		} `json:"credential_token"`
	}
	if err := json.Unmarshal(mint.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode mint: %v", err)
	}
	if minted.Token == "" || !minted.FirstProvision {
		t.Fatalf("mint payload = %s, want a token with first_provision:true", mint.Body.String())
	}

	// The redemption is UNAUTHENTICATED — no session, no CSRF header — which is the whole point.
	redeem := doJSON(t, h, "POST", "/auth/password/redeem", map[string]string{
		"token": minted.Token, "new_password": "Provisioned-Passw0rd!",
	}, nil)
	if redeem.Code != http.StatusOK {
		t.Fatalf("redeem = %d: %s", redeem.Code, redeem.Body.String())
	}
	if c := sessionCookieFrom(redeem); c != nil {
		t.Fatal("redemption issued a session cookie; possession of a link must not be access")
	}

	// THE POINT: the account can now log in.
	after := doJSON(t, h, "POST", "/auth/login", targetCreds, nil)
	if after.Code != http.StatusOK {
		t.Fatalf("login after provisioning = %d: %s", after.Code, after.Body.String())
	}

	// The DATABASE agrees: an argon2id PHC hash for the target, the token marked consumed, and no
	// plaintext anywhere in either row.
	var storedHash string
	if err := suPool.QueryRow(ctx,
		`SELECT password_hash FROM user_credential WHERE user_id = $1::uuid`, targetID).Scan(&storedHash); err != nil {
		t.Fatalf("read provisioned credential: %v", err)
	}
	if ok, err := VerifyPassword(storedHash, "Provisioned-Passw0rd!"); err != nil || !ok {
		t.Fatalf("stored hash does not verify the provisioned password (ok=%v err=%v)", ok, err)
	}
	if storedHash == "Provisioned-Passw0rd!" {
		t.Fatal("the plaintext password is in user_credential")
	}
	var consumedAt *time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT consumed_at FROM user_credential_token WHERE id = $1::uuid`,
		minted.CredentialToken.ID).Scan(&consumedAt); err != nil {
		t.Fatalf("read token row: %v", err)
	}
	if consumedAt == nil {
		t.Fatal("the redeemed token is not marked consumed in the database")
	}

	// A second redemption of the same link is refused BY THE DATABASE (the atomic consume), and
	// changes nothing.
	if again := doJSON(t, h, "POST", "/auth/password/redeem", map[string]string{
		"token": minted.Token, "new_password": "Second-Passw0rd!",
	}, nil); again.Code != http.StatusForbidden {
		t.Fatalf("second redemption = %d, want 403", again.Code)
	}
	if rec := doJSON(t, h, "POST", "/auth/login", targetCreds, nil); rec.Code != http.StatusOK {
		t.Fatalf("login after the refused second redemption = %d, want 200 (nothing should have "+
			"changed)", rec.Code)
	}

	// Both halves are on the REAL management-plane trail, hash-chained, with the target named.
	events, err := mgmtAudit.ListEvents(ctx, tid, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var issued, redeemed *MgmtAuditEvent
	for i := range events {
		switch events[i].Action {
		case "auth.password_reset_issued":
			issued = &events[i]
		case "auth.password_reset_redeemed":
			redeemed = &events[i]
		}
	}
	if issued == nil || redeemed == nil {
		t.Fatalf("audit trail is missing one of the two events: %+v", events)
	}
	if issued.ActorUserID != adminID || issued.TargetID != targetID {
		t.Fatalf("issued event actor=%s target=%s, want %s / %s",
			issued.ActorUserID, issued.TargetID, adminID, targetID)
	}
	if redeemed.TargetID != targetID {
		t.Fatalf("redeemed event target=%s, want %s", redeemed.TargetID, targetID)
	}

	// SECOND ROUND — the one that exercises session revocation on the PUBLIC path against the real
	// database. Round one provisioned an account that had never logged in, so RevokeAllForUser ran
	// but had nothing to revoke and could have been broken without anything noticing.
	targetLogin := doJSON(t, h, "POST", "/auth/login", targetCreds, nil)
	if targetLogin.Code != http.StatusOK {
		t.Fatalf("target login = %d: %s", targetLogin.Code, targetLogin.Body.String())
	}
	targetCookie := sessionCookieFrom(targetLogin)
	if rec := doJSON(t, h, "GET", "/machines", nil, targetCookie); rec.Code != http.StatusOK {
		t.Fatalf("target session should work before the reset, got %d", rec.Code)
	}
	var liveBefore int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_session WHERE user_id = $1::uuid AND revoked_at IS NULL`,
		targetID).Scan(&liveBefore); err != nil {
		t.Fatalf("count live sessions before the reset: %v", err)
	}
	mint2 := doJSONWith(t, h, "POST", "/users/"+targetID+"/password-reset", mintBody, csrfToken, adminCookie, csrfCookie)
	if mint2.Code != http.StatusCreated {
		t.Fatalf("second mint = %d: %s", mint2.Code, mint2.Body.String())
	}
	var minted2 struct {
		Token          string `json:"token"`
		FirstProvision bool   `json:"first_provision"`
	}
	if err := json.Unmarshal(mint2.Body.Bytes(), &minted2); err != nil {
		t.Fatalf("decode second mint: %v", err)
	}
	if minted2.FirstProvision {
		t.Fatal("first_provision is true on the second round, but the account now HAS a credential")
	}
	redeem2 := doJSON(t, h, "POST", "/auth/password/redeem", map[string]string{
		"token": minted2.Token, "new_password": "Second-Provisioned-Passw0rd!",
	}, nil)
	if redeem2.Code != http.StatusOK {
		t.Fatalf("second redeem = %d: %s", redeem2.Code, redeem2.Body.String())
	}
	var redeemBody struct {
		Revoked int `json:"sessions_revoked"`
	}
	if err := json.Unmarshal(redeem2.Body.Bytes(), &redeemBody); err != nil {
		t.Fatalf("decode second redeem: %v", err)
	}
	// Compared against what the DATABASE said was live just before the redeem, rather than a
	// hardcoded 1: earlier rounds of this test logged the target in more than once, and a literal
	// would be asserting the arithmetic of this test rather than the behaviour of the handler.
	if redeemBody.Revoked != liveBefore {
		t.Fatalf("sessions_revoked = %d, want %d (every live session at the moment of the reset) — "+
			"the unauthenticated redeem path must revoke them IN THE DATABASE",
			redeemBody.Revoked, liveBefore)
	}
	if liveBefore == 0 {
		t.Fatal("the target had no live session, so this leg proves nothing about revocation")
	}
	// The database agrees, and the old cookie is dead against the real middleware chain.
	var liveSessions int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_session WHERE user_id = $1::uuid AND revoked_at IS NULL`,
		targetID).Scan(&liveSessions); err != nil {
		t.Fatalf("count live sessions: %v", err)
	}
	if liveSessions != 0 {
		t.Fatalf("%d live session rows survive the reset, want 0", liveSessions)
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, targetCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pre-reset session still works after the reset: %d, want 401", rec.Code)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
