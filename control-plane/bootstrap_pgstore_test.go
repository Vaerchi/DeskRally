package controlplane

// Bootstrap against a REAL Postgres, because every interesting thing about it is a database
// property: the tenant comes from a SECURITY DEFINER function, the user and credential writes go
// through RLS-pinned transactions, and the "already bootstrapped" guard is a count that RLS decides
// the visibility of. An in-memory fake would testify to none of that.
//
// The end-to-end assertion that matters is the LAST one: the created credential actually verifies
// against the printed password. Everything else could be right while the account still cannot log
// in, which is the exact failure this command exists to prevent.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// bootstrapTestPool is `newTestPool` under a name that says why: Bootstrap needs the REAL schema —
// cp_create_tenant and cp_resolve_tenant_by_slug are SECURITY DEFINER functions, the role presets
// come from 0001, and the user/credential writes go through RLS policies.
//
// A first draft applied the migrations into a per-test schema for isolation. That does not work and
// the reason is worth recording: 0003's functions are declared `SET search_path = public,
// pg_catalog`, so a function created in schema `bs_ok` returns `public.user_session` while being
// declared to return `bs_ok.user_session` — Postgres rejects it with a return-type mismatch. The
// migrations assume `public`. `newTestPool` resets that schema per test, which gives the isolation
// anyway since these tests do not run in parallel.
func bootstrapTestPool(t *testing.T, _ string) *pgxpool.Pool {
	t.Helper()
	pool := newTestPool(t) // skips without TEST_DATABASE_URL; resets the schema
	// 0006 defines cp_create_tenant and is opt-in rather than part of the core reset, so a test that
	// provisions a tenant has to ask for it.
	applyTenantProvisionMigration(t, pool)
	return pool
}

func TestPgBootstrapCreatesATenantAndAnOwnerWhoCanActuallyLogIn(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_ok")
	ctx := context.Background()

	res, err := Bootstrap(ctx, pool, BootstrapOptions{
		TenantSlug: "acme",
		Email:      "owner@acme.test",
		SelfHosted: true,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if !res.TenantCreated {
		t.Error("the tenant did not exist, so it should have been reported as created")
	}
	if !res.GeneratedPassword || res.Password == "" {
		t.Fatal("no password was generated, so the operator has no way to log in")
	}
	if len(res.Password) < 24 {
		t.Errorf("generated password is only %d chars; too short to lean on", len(res.Password))
	}

	// THE assertion. A user row and a credential row can both exist and still not authenticate —
	// wrong hash format, wrong tenant, a credential written for a different user. Verify the way
	// login does.
	u, err := newPgUserStoreT(pool).FindUserByEmail(ctx, res.TenantID, "owner@acme.test")
	if err != nil {
		t.Fatalf("the bootstrapped owner cannot be found by email: %v", err)
	}
	if u.ID != res.UserID {
		t.Errorf("FindUserByEmail returned %s, want the created %s", u.ID, res.UserID)
	}
	ok, err := VerifyPassword(u.PasswordHash, res.Password)
	if err != nil {
		t.Fatalf("stored credential does not decode: %v", err)
	}
	if !ok {
		t.Fatal("the stored credential does NOT verify against the printed password — the account " +
			"exists and cannot be logged into, which is the whole failure this command prevents")
	}

	// Negative control: a different password must NOT verify. Without this, a VerifyPassword that
	// returned true unconditionally would pass the assertion above.
	if bad, _ := VerifyPassword(u.PasswordHash, res.Password+"x"); bad {
		t.Fatal("a wrong password verified against the stored credential")
	}

	// The slug is what the login form takes, so it must resolve.
	if id, rerr := NewPgTenantResolver(pool).ResolveTenant(ctx, "acme"); rerr != nil || id != res.TenantID {
		t.Fatalf("ResolveTenant(acme) = %q, %v; want %s", id, rerr, res.TenantID)
	}
}

// The owner must really be an OWNER. A bootstrap that created a user with no membership, or a
// lesser role, would log in and then be unable to do anything — including create other users, which
// would leave the deployment just as stuck.
func TestPgBootstrapOwnerHoldsTheOwnerRole(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_role")
	ctx := context.Background()

	res, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "o@acme.test"})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	var roleKey string
	if err := withTenant(ctx, pool, res.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT r.key FROM membership m JOIN role r ON r.id = m.role_id
			 WHERE m.user_id = $1`, res.UserID).Scan(&roleKey)
	}); err != nil {
		t.Fatalf("read the owner's membership: %v", err)
	}
	if roleKey != string(RoleOwner) {
		t.Fatalf("bootstrapped user holds role %q, want %q", roleKey, RoleOwner)
	}
}

// Re-running against a tenant that already has users must REFUSE. A deploy pipeline that runs
// bootstrap unconditionally would otherwise mint an extra owner on every deploy — invisible until
// somebody audits the user list.
func TestPgBootstrapRefusesATenantThatAlreadyHasUsers(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_twice")
	ctx := context.Background()

	first, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "one@acme.test"})
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	_, err = Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "two@acme.test"})
	if !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second Bootstrap = %v, want ErrAlreadyBootstrapped", err)
	}

	// And it must have created NOTHING — a refusal that half-ran is worse than either outcome.
	n, cerr := countUsers(ctx, pool, first.TenantID)
	if cerr != nil {
		t.Fatalf("count users: %v", cerr)
	}
	if n != 1 {
		t.Fatalf("tenant has %d users after a refused bootstrap, want 1", n)
	}
}

// A tenant that exists but has NO users must still be bootstrappable. This is the half-finished
// state: the tenant insert committed and the user insert failed. Refusing here would leave the
// operator with a deployment they can neither use nor repair without hand-written SQL.
func TestPgBootstrapCompletesATenantThatHasNoUsers(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_resume")
	ctx := context.Background()

	// Stage the half-finished state the way the code itself would produce it.
	var tenantID string
	if err := pool.QueryRow(ctx,
		`SELECT (cp_create_tenant($1, $2, $3)).id::text`, "acme", "Acme", "self_hosted",
	).Scan(&tenantID); err != nil {
		t.Fatalf("stage the tenant: %v", err)
	}

	res, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "o@acme.test"})
	if err != nil {
		t.Fatalf("Bootstrap over a user-less tenant: %v", err)
	}
	if res.TenantCreated {
		t.Error("the tenant already existed; TenantCreated must be false so the operator is told")
	}
	if res.TenantID != tenantID {
		t.Errorf("Bootstrap made a SECOND tenant (%s) instead of reusing %s", res.TenantID, tenantID)
	}
}

// Two tenants must not see each other's users, or the "already bootstrapped" count would refuse a
// legitimate second tenant. This is an RLS property, which is why it is asserted against pg.
func TestPgBootstrapASecondTenantIsUnaffectedByTheFirst(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_two_tenants")
	ctx := context.Background()

	if _, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "one", Email: "a@one.test"}); err != nil {
		t.Fatalf("first tenant: %v", err)
	}
	second, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "two", Email: "b@two.test"})
	if err != nil {
		t.Fatalf("a SECOND tenant must bootstrap independently, got: %v", err)
	}
	if n, _ := countUsers(ctx, pool, second.TenantID); n != 1 {
		t.Fatalf("second tenant sees %d users, want exactly its own 1", n)
	}
}

// A caller-supplied password must be used verbatim, and must NOT be echoed back — echoing it would
// put a value the operator already holds into logs for no reason.
func TestPgBootstrapHonoursASuppliedPassword(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_supplied")
	ctx := context.Background()

	const pw = "a-supplied-password-that-is-long-enough"
	res, err := Bootstrap(ctx, pool, BootstrapOptions{
		TenantSlug: "acme", Email: "o@acme.test", Password: pw,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if res.GeneratedPassword {
		t.Error("a password was supplied, so none should have been generated")
	}
	if res.Password != "" {
		t.Error("a supplied password must not be echoed back in the result")
	}

	u, err := newPgUserStoreT(pool).FindUserByEmail(ctx, res.TenantID, "o@acme.test")
	if err != nil {
		t.Fatalf("find owner: %v", err)
	}
	if ok, _ := VerifyPassword(u.PasswordHash, pw); !ok {
		t.Fatal("the supplied password does not verify against the stored credential")
	}
}

func TestBootstrapRejectsIncompleteInput(t *testing.T) {
	// No database needed: these fail before any query, which is itself the property — a typo must
	// not create a tenant and then fail.
	for _, tc := range []struct {
		name string
		opts BootstrapOptions
		want string
	}{
		{"no slug", BootstrapOptions{Email: "o@acme.test"}, "tenant slug is required"},
		{"blank slug", BootstrapOptions{TenantSlug: "   ", Email: "o@acme.test"}, "tenant slug is required"},
		{"slug is not a hostname label", BootstrapOptions{TenantSlug: "Acme Corp", Email: "o@acme.test"}, "is not usable"},
		{"slug is reserved", BootstrapOptions{TenantSlug: "www", Email: "o@acme.test"}, "is not usable"},
		{"no email", BootstrapOptions{TenantSlug: "acme"}, "owner email is required"},
		{"email is not an email", BootstrapOptions{TenantSlug: "acme", Email: "owner"}, "does not look like an email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Bootstrap(context.Background(), nil, tc.opts)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not explain the problem (want %q)", err, tc.want)
			}
		})
	}
}

// --- reset-password -----------------------------------------------------------------------------

// The recovery path. `bootstrap` prints a password once and refuses to run again, every in-product
// reset needs an authenticated admin, and there is no mail path — so without this a lost password
// meant hand-writing an argon2id digest into Postgres.
//
// The assertion that matters is the pair: the NEW password verifies AND the old one no longer does.
// Either alone passes against a no-op.
func TestPgResetOwnerPasswordReplacesTheCredential(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_reset")
	ctx := context.Background()

	first, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "o@acme.test"})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	res, err := ResetOwnerPassword(ctx, pool, nil, "acme", "o@acme.test")
	if err != nil {
		t.Fatalf("ResetOwnerPassword: %v", err)
	}
	if res.Password == "" || res.Password == first.Password {
		t.Fatal("the reset must mint a NEW password, not reprint or blank the old one")
	}
	if res.UserID != first.UserID {
		t.Errorf("reset targeted %s, want the bootstrapped owner %s", res.UserID, first.UserID)
	}

	u, err := newPgUserStoreT(pool).FindUserByEmail(ctx, first.TenantID, "o@acme.test")
	if err != nil {
		t.Fatalf("find owner: %v", err)
	}
	if ok, _ := VerifyPassword(u.PasswordHash, res.Password); !ok {
		t.Fatal("the NEW password does not verify — the operator still cannot log in")
	}
	if ok, _ := VerifyPassword(u.PasswordHash, first.Password); ok {
		t.Fatal("the OLD password still verifies — the credential was not actually replaced")
	}
}

// Wrong tenant and wrong email must each fail by NAME, not by silently doing nothing. An operator
// locked out is already guessing; "no user X in tenant Y" tells them which half is wrong.
func TestPgResetOwnerPasswordRefusesUnknownTargets(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_reset_unknown")
	ctx := context.Background()

	if _, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "o@acme.test"}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	for _, tc := range []struct{ name, tenant, email, want string }{
		{"unknown tenant", "nope", "o@acme.test", "no tenant with slug"},
		{"unknown email", "acme", "ghost@acme.test", "no user"},
		{"blank tenant", "", "o@acme.test", "required"},
		{"blank email", "acme", "", "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResetOwnerPassword(ctx, pool, nil, tc.tenant, tc.email)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not say which half is wrong (want %q)", err, tc.want)
			}
		})
	}
}

// A refused reset must leave the existing credential untouched — an operator recovering from a
// typo'd email must not find the original password has stopped working too.
func TestPgResetOwnerPasswordLeavesTheCredentialAloneWhenItRefuses(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_reset_intact")
	ctx := context.Background()

	first, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "o@acme.test"})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := ResetOwnerPassword(ctx, pool, nil, "acme", "typo@acme.test"); err == nil {
		t.Fatal("premise: the typo'd email must be refused")
	}

	u, err := newPgUserStoreT(pool).FindUserByEmail(ctx, first.TenantID, "o@acme.test")
	if err != nil {
		t.Fatalf("find owner: %v", err)
	}
	if ok, _ := VerifyPassword(u.PasswordHash, first.Password); !ok {
		t.Fatal("a REFUSED reset changed the existing credential")
	}
}

// A DISABLED account must be refused by name.
//
// Without the explicit guard this fails misleadingly rather than loudly: SetPassword's INSERT
// carries `WHERE u.disabled_at IS NULL`, so on a disabled account it writes nothing and reports
// "no such user" — sending an operator who is already locked out to look for a typo in an email
// that is perfectly correct.
func TestPgResetOwnerPasswordRefusesADisabledAccount(t *testing.T) {
	pool := bootstrapTestPool(t, "bs_reset_disabled")
	ctx := context.Background()

	first, err := Bootstrap(ctx, pool, BootstrapOptions{TenantSlug: "acme", Email: "o@acme.test"})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	users := newPgUserStoreT(pool)
	// Disable the tenant's ONLY Owner. The console can no longer do this (docs/56: SetUserDisabled
	// refuses to leave a tenant without an active Owner, ErrLastOwner), but the state still arises from
	// pre-0062 data or a direct database edit, and the recovery CLI must handle it, so set it in SQL.
	if _, err := pool.Exec(ctx, `UPDATE app_user SET disabled_at = now() WHERE id = $1`, first.UserID); err != nil {
		t.Fatalf("disable the account: %v", err)
	}

	_, err = ResetOwnerPassword(ctx, pool, nil, "acme", "o@acme.test")
	if err == nil {
		t.Fatal("a disabled account must be refused, not silently no-op'd")
	}
	if !strings.Contains(err.Error(), "DISABLED") {
		t.Fatalf("the refusal must say the account is disabled, got %q — anything vaguer sends the "+
			"operator hunting for a typo in a correct email", err)
	}

	// And the old credential must be intact: a refused reset changes nothing.
	u, ferr := users.FindUserByEmail(ctx, first.TenantID, "o@acme.test")
	if ferr == nil {
		if ok, _ := VerifyPassword(u.PasswordHash, first.Password); !ok {
			t.Error("the refused reset altered the credential of a disabled account")
		}
	}
}
