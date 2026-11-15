package controlplane

// Tenant suspension against a REAL database — the half tenant_suspension_test.go cannot carry.
//
// The fake's flag is set by a method; here it is `UPDATE tenant SET disabled_at = now()`, the
// column an operator (or a billing job) actually writes, read back through PgUserStore's projection
// on the ordinary authenticated-request path. Deleting the tenant JOIN from `selectUser` leaves
// every in-memory test green and fails here.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// suspendTenant flips `tenant.disabled_at`, as the SaaS control surface would. It runs on the
// SUPERUSER test pool: suspending a tenant is a privileged act, not something the app role does
// through RLS.
func suspendTenant(t *testing.T, pool *pgxpool.Pool, tenantID string, suspended bool) {
	t.Helper()
	sql := `UPDATE tenant SET disabled_at = now() WHERE id = $1::uuid`
	if !suspended {
		sql = `UPDATE tenant SET disabled_at = NULL WHERE id = $1::uuid`
	}
	ct, err := pool.Exec(context.Background(), sql, tenantID)
	if err != nil {
		t.Fatalf("set disabled_at=%v on %s: %v", suspended, tenantID, err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("set disabled_at=%v on %s updated %d rows, want 1", suspended, tenantID, ct.RowsAffected())
	}
}

// A live console session is refused the moment its tenant is suspended — with ErrTenantSuspended,
// and only for that tenant.
//
// WHY THE LOGIN PATH IS NOT WHAT THIS TESTS. `cp_resolve_tenant_by_slug` (0003) already filters
// `disabled_at IS NULL`, so a suspended tenant cannot LOG IN and never could. That second mechanism
// is asserted below precisely so it is not mistaken for the fix: the defect was always about the
// technician who was already signed in, whose session outlived the suspension by up to the 12-hour
// absolute TTL.
func TestPgSuspendedTenantEvictsALiveConsoleSession(t *testing.T) {
	pool := newTestPool(t) // skips without TEST_DATABASE_URL
	ctx := context.Background()

	tidA, uidA := provisionUser(t, pool, "suspend-a", "tech@suspend-a.test", "password-1234")
	tidB, uidB := provisionUser(t, pool, "suspend-b", "tech@suspend-b.test", "password-1234")

	users := newPgUserStoreT(pool)
	sessions := NewSessionManager(NewPgSessionStore(pool))
	sa := &SessionAuthenticator{Sessions: sessions, Users: users}

	issue := func(tid, uid string) string {
		t.Helper()
		u, err := users.FindUserByID(ctx, tid, uid)
		if err != nil {
			t.Fatalf("FindUserByID(%s): %v", uid, err)
		}
		token, _, err := sessions.Issue(ctx, tid, uid, u.CredentialUpdatedAt)
		if err != nil {
			t.Fatalf("Issue(%s): %v", uid, err)
		}
		return token
	}
	tokenA := issue(tidA, uidA)
	tokenB := issue(tidB, uidB)

	// Baseline — both consoles work. A denial assertion means nothing without it.
	if _, err := authenticateWithToken(sa, tokenA); err != nil {
		t.Fatalf("baseline Authenticate (tenant A): %v", err)
	}
	if _, err := authenticateWithToken(sa, tokenB); err != nil {
		t.Fatalf("baseline Authenticate (tenant B): %v", err)
	}

	suspendTenant(t, pool, tidA, true)

	// The SAME credential that worked a moment ago is now refused, and refused BY NAME.
	_, err := authenticateWithToken(sa, tokenA)
	if !errors.Is(err, ErrTenantSuspended) {
		t.Fatalf("suspended tenant's live session: Authenticate = %v, want ErrTenantSuspended", err)
	}
	// The session itself is still valid — suspension denies the REQUEST, it does not (and must not
	// silently) revoke the row. If this ever fails, the assertion above has started passing for a
	// different reason.
	if _, err := sessions.Validate(ctx, tokenA); err != nil {
		t.Fatalf("session validation = %v; suspension must deny at the tenant check, not by revoking", err)
	}

	// NEGATIVE CONTROL: tenant B, untouched, still authenticates. Without this, "deny everything"
	// would pass.
	if _, err := authenticateWithToken(sa, tokenB); err != nil {
		t.Fatalf("unsuspended tenant B was denied too (%v) — the check is not tenant-specific", err)
	}

	// The pre-existing SECOND mechanism, stated so it is never mistaken for this fix: login was
	// already closed at the SQL admission function.
	if _, err := NewPgTenantResolver(pool).ResolveTenant(ctx, "suspend-a"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("ResolveTenant on a suspended tenant = %v, want ErrNoTenant", err)
	}

	// Lifting the suspension restores the ORIGINAL session: the flag is re-read per request, and the
	// denial above was not a revocation or a credential-epoch bump in disguise.
	suspendTenant(t, pool, tidA, false)
	if _, err := authenticateWithToken(sa, tokenA); err != nil {
		t.Fatalf("after un-suspending: Authenticate = %v, want the original session to work again", err)
	}
}

// The same fact at the HTTP surface, through the production chain (SessionAuthenticator → PgBinder
// → RLS): a suspended tenant's console gets 403 "tenant suspended", not the generic 401 that every
// other authentication failure collapses into, while another tenant's console keeps working.
func TestPgSuspendedTenantAnswers403OnTheProtectedChain(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)  // 0013 GRANTs to rmt_app, so the role must exist first
	applyAttendedMigration(t, pool) // 0013: PgMachineStore's projection reads its columns
	ctx := context.Background()

	tidA, uidA := provisionUser(t, pool, "suspend-http-a", "tech@suspend-http-a.test", "password-1234")
	tidB, uidB := provisionUser(t, pool, "suspend-http-b", "tech@suspend-http-b.test", "password-1234")

	users := newPgUserStoreT(pool)
	sessions := NewSessionManager(NewPgSessionStore(pool))
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(pool))
	srv.Machines = NewPgMachineStore(pool)
	h := srv.Handler()

	cookieFor := func(tid, uid string) *http.Cookie {
		t.Helper()
		u, err := users.FindUserByID(ctx, tid, uid)
		if err != nil {
			t.Fatalf("FindUserByID: %v", err)
		}
		token, _, err := sessions.Issue(ctx, tid, uid, u.CredentialUpdatedAt)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		return &http.Cookie{Name: DefaultSessionCookie, Value: token}
	}
	ckA, ckB := cookieFor(tidA, uidA), cookieFor(tidB, uidB)

	if rec := doJSON(t, h, "GET", "/machines", nil, ckA); rec.Code != http.StatusOK {
		t.Fatalf("baseline GET /machines = %d (body %s), want 200", rec.Code, rec.Body.String())
	}

	suspendTenant(t, pool, tidA, true)

	rec := doJSON(t, h, "GET", "/machines", nil, ckA)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("suspended tenant GET /machines = %d (body %s), want 403", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), ErrTenantSuspended.Error()) {
		t.Fatalf("403 body = %s, want it to name %q", rec.Body.String(), ErrTenantSuspended.Error())
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, ckB); rec.Code != http.StatusOK {
		t.Fatalf("unsuspended tenant GET /machines = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
}
