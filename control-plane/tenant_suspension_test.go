package controlplane

// Tenant suspension on a LIVE console session — the handler/authenticator half, over the in-memory
// fakes. TestPgSuspendedTenantEvictsALiveConsoleSession (tenant_suspension_pgstore_test.go) carries
// the persistence half: that `tenant.disabled_at` is what the flag is actually read from.
//
// WHAT WAS BROKEN. `tenant.disabled_at` was honoured only by the SQL ADMISSION paths — login's
// cp_resolve_tenant_by_slug, enrollment redemption (0011), attended redemption (0021) — and by the
// per-USER `app_user.disabled_at`. Nothing re-examined a technician who was already inside, so
// suspending a tenant stopped everyone getting in while everyone already in kept a live console
// (and a live backstage shell) for up to the 12-hour absolute session TTL.
//
// The tests below assert WHICH error denies the request, not merely that one did — a denial
// asserted as "not nil" is satisfied by ErrInvalidCredentials, ErrUserDisabled, a revoked session,
// or a store outage, none of which is the mechanism under test.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authenticateWithToken runs one request through the real SessionAuthenticator, exactly as
// authMiddleware does.
func authenticateWithToken(a *SessionAuthenticator, token string) (*Principal, error) {
	req := httptest.NewRequest("GET", "/machines", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return a.Authenticate(req)
}

// A session issued BEFORE the suspension must stop working the moment the tenant is suspended, and
// must fail with ErrTenantSuspended specifically.
func TestSuspendedTenantRefusesALiveSessionWithItsOwnError(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-live", "u1", "tech@live.test", "password-1234", RoleTechnician)
	f.addUser(t, "tenant-other", "u2", "tech@other.test", "password-1234", RoleTechnician)

	u1, err := f.users.FindUserByID(t.Context(), "tenant-live", "u1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	u2, _ := f.users.FindUserByID(t.Context(), "tenant-other", "u2")
	tok1, _, err := f.sessions.Issue(t.Context(), "tenant-live", "u1", u1.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tok2, _, err := f.sessions.Issue(t.Context(), "tenant-other", "u2", u2.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue (other): %v", err)
	}
	sa := &SessionAuthenticator{Sessions: f.sessions, Users: f.users}

	// Baseline: both sessions are good. Without this the test could not tell "suspension denied it"
	// from "it never worked".
	if _, err := authenticateWithToken(sa, tok1); err != nil {
		t.Fatalf("baseline Authenticate: %v", err)
	}

	f.users.SetTenantSuspended("tenant-live", true)

	_, err = authenticateWithToken(sa, tok1)
	if !errors.Is(err, ErrTenantSuspended) {
		t.Fatalf("suspended-tenant Authenticate = %v, want ErrTenantSuspended", err)
	}
	// The specific error matters as much as the denial: the console tells the operator their tenancy
	// is suspended, which is not something a login retry can fix.
	if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserDisabled) || errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("suspension was reported as some other failure (%v); the console cannot distinguish it", err)
	}

	// NEGATIVE CONTROL. Without this, an authenticator that denied EVERYTHING would pass the
	// assertion above.
	if _, err := authenticateWithToken(sa, tok2); err != nil {
		t.Fatalf("a different tenant's session was denied too (%v) — the check is not tenant-specific", err)
	}

	// Suspension is a STATE re-read on every request, not a one-off eviction: lifting it restores the
	// SAME session. This also refutes the alternative explanation for the denial above (that the
	// session was revoked or the credential epoch moved), which lifting a flag could not undo.
	f.users.SetTenantSuspended("tenant-live", false)
	if _, err := authenticateWithToken(sa, tok1); err != nil {
		t.Fatalf("un-suspended tenant: Authenticate = %v, want the original session to work again", err)
	}
}

// Through the middleware: the suspension is surfaced as 403 + a named reason, not the generic 401
// every other authentication failure collapses into.
func TestSuspendedTenantIsNamedAtTheHTTPSurface(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-live", "u1", "tech@live.test", "password-1234", RoleTechnician)
	f.addUser(t, "tenant-other", "u2", "tech@other.test", "password-1234", RoleTechnician)
	h := f.srv.Handler()

	login := func(tenant, email string) *http.Cookie {
		t.Helper()
		rec := doJSON(t, h, "POST", "/auth/login",
			loginRequest{Tenant: tenant, Email: email, Password: "password-1234"}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("login %s = %d (body %s)", email, rec.Code, rec.Body.String())
		}
		c := sessionCookieFrom(rec)
		if c == nil {
			t.Fatalf("login %s set no session cookie", email)
		}
		return c
	}
	live := login("tenant-live", "tech@live.test")
	other := login("tenant-other", "tech@other.test")

	if rec := doJSON(t, h, "GET", "/machines", nil, live); rec.Code != http.StatusOK {
		t.Fatalf("baseline GET /machines = %d (body %s), want 200", rec.Code, rec.Body.String())
	}

	f.users.SetTenantSuspended("tenant-live", true)

	rec := doJSON(t, h, "GET", "/machines", nil, live)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("suspended-tenant GET /machines = %d (body %s), want 403", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, ErrTenantSuspended.Error()) {
		t.Fatalf("403 body = %s, want it to name %q so the console can explain the denial",
			body, ErrTenantSuspended.Error())
	}
	// NEGATIVE CONTROL: another tenant's console is untouched.
	if rec := doJSON(t, h, "GET", "/machines", nil, other); rec.Code != http.StatusOK {
		t.Fatalf("unsuspended tenant GET /machines = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
}
