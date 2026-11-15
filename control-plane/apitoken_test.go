package controlplane

// In-memory / unit proofs for the API-token feature (docs/01 §8): the store's mint→resolve
// contract and liveness predicate, the capability-validation gate, the authenticator front's
// routing, and the explicit-capability Grant. The DB-gated properties (RLS isolation, the
// SECURITY DEFINER resolver, tenant suspension) live in apitoken_pgstore_test.go.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInMemoryAPITokenMintResolve(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryAPITokenStore()

	plaintext, tok, err := store.Mint(ctx, "tenant-a", "ci-bot", []Capability{CapViewMachines, CapViewAudit}, "owner-1", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(plaintext, APITokenPrefix) {
		t.Fatalf("plaintext %q lacks the %q prefix", plaintext, APITokenPrefix)
	}
	if tok.ID == "" || tok.TenantID != "tenant-a" || tok.Name != "ci-bot" {
		t.Fatalf("minted token metadata wrong: %+v", tok)
	}
	if tok.CreatedBy != "owner-1" {
		t.Fatalf("created_by = %q, want owner-1", tok.CreatedBy)
	}

	got, err := store.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ID != tok.ID || got.TenantID != "tenant-a" {
		t.Fatalf("resolved token = %+v, want id %s tenant-a", got, tok.ID)
	}
	if len(got.Capabilities) != 2 || got.Capabilities[0] != CapViewMachines || got.Capabilities[1] != CapViewAudit {
		t.Fatalf("resolved caps = %v, want [view_machines view_audit]", got.Capabilities)
	}

	// A different secret does not resolve.
	if _, err := store.Resolve(ctx, APITokenPrefix+"not-a-real-secret"); err != ErrAPITokenNotFound {
		t.Fatalf("Resolve(bogus) err = %v, want ErrAPITokenNotFound", err)
	}
}

func TestAPITokenResolveRejectsRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryAPITokenStore()
	plaintext, tok, err := store.Mint(ctx, "tenant-a", "bot", []Capability{CapViewMachines}, "owner-1", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Live before revoke.
	if _, err := store.Resolve(ctx, plaintext); err != nil {
		t.Fatalf("Resolve before revoke: %v", err)
	}
	if err := store.Revoke(ctx, "tenant-a", tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.Resolve(ctx, plaintext); err != ErrAPITokenNotFound {
		t.Fatalf("Resolve after revoke err = %v, want ErrAPITokenNotFound", err)
	}
	// Revoke is idempotent, and a cross-tenant revoke is a not-found (never touches another tenant).
	if err := store.Revoke(ctx, "tenant-a", tok.ID); err != nil {
		t.Fatalf("re-Revoke: %v", err)
	}
	if err := store.Revoke(ctx, "tenant-b", tok.ID); err != ErrAPITokenNotFound {
		t.Fatalf("cross-tenant Revoke err = %v, want ErrAPITokenNotFound", err)
	}
}

func TestAPITokenResolveRejectsExpired(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAPITokenStore()
	store.Now = func() time.Time { return base }

	// Expires one hour after mint.
	exp := base.Add(time.Hour)
	plaintext, _, err := store.Mint(ctx, "tenant-a", "bot", []Capability{CapViewMachines}, "owner-1", &exp)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Still live 30 minutes in.
	store.Now = func() time.Time { return base.Add(30 * time.Minute) }
	if _, err := store.Resolve(ctx, plaintext); err != nil {
		t.Fatalf("Resolve before expiry: %v", err)
	}
	// Exactly at expiry is NOT before it → expired.
	store.Now = func() time.Time { return exp }
	if _, err := store.Resolve(ctx, plaintext); err != ErrAPITokenNotFound {
		t.Fatalf("Resolve at expiry err = %v, want ErrAPITokenNotFound", err)
	}
	// And past it.
	store.Now = func() time.Time { return exp.Add(time.Second) }
	if _, err := store.Resolve(ctx, plaintext); err != ErrAPITokenNotFound {
		t.Fatalf("Resolve past expiry err = %v, want ErrAPITokenNotFound", err)
	}
}

func TestAPITokenListTenantScopedNewestFirst(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAPITokenStore()

	store.Now = func() time.Time { return base }
	_, older, _ := store.Mint(ctx, "tenant-a", "older", []Capability{CapViewMachines}, "o", nil)
	store.Now = func() time.Time { return base.Add(time.Minute) }
	_, newer, _ := store.Mint(ctx, "tenant-a", "newer", []Capability{CapViewMachines}, "o", nil)
	// A token in another tenant must never appear in tenant-a's listing.
	store.Now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, _, err := store.Mint(ctx, "tenant-b", "other", []Capability{CapViewMachines}, "o", nil); err != nil {
		t.Fatalf("Mint tenant-b: %v", err)
	}

	list, err := store.List(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List(tenant-a) len = %d, want 2 (tenant-b leaked?)", len(list))
	}
	if list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Fatalf("List order = [%s %s], want newest-first [%s %s]", list[0].ID, list[1].ID, newer.ID, older.ID)
	}
}

func TestParseAPITokenCapabilities(t *testing.T) {
	// Empty is rejected.
	if _, err := parseAPITokenCapabilities(nil); err == nil {
		t.Fatalf("empty caps: want error, got nil")
	}
	// An unknown capability string is rejected.
	if _, err := parseAPITokenCapabilities([]string{"teleport"}); err == nil {
		t.Fatalf("unknown cap: want error, got nil")
	}
	// A KNOWN-but-not-grantable capability is rejected — this is the security boundary.
	for _, c := range []Capability{CapManageTenant, CapStartSession, CapManageUsers, CapManageEnrollment, CapBackstageShell} {
		if _, err := parseAPITokenCapabilities([]string{string(c)}); err == nil {
			t.Fatalf("non-grantable cap %q: want error, got nil", c)
		}
	}
	// The grantable set parses, de-duplicates, and preserves first-seen order.
	got, err := parseAPITokenCapabilities([]string{"view_machines", "manage_groups", "view_machines"})
	if err != nil {
		t.Fatalf("grantable caps: %v", err)
	}
	if len(got) != 2 || got[0] != CapViewMachines || got[1] != CapManageGroups {
		t.Fatalf("parsed caps = %v, want [view_machines manage_groups] (deduped, ordered)", got)
	}
}

func TestAPITokenGrantableSetExcludesUserFKPaths(t *testing.T) {
	// The allow-list must be exactly the fleet/reporting five. If someone widens it to a cap whose
	// handler keys on a real user (session start, user management, enrollment) or that would let a
	// token mint tokens (manage_tenant), this test fails and forces them to confront the FK/lookup
	// consequence documented in 0027 and apitoken.go.
	want := map[Capability]bool{
		CapViewMachines: true, CapManageMachines: true, CapManageGroups: true,
		CapViewSessions: true, CapViewAudit: true,
	}
	for _, c := range AllCapabilities {
		if IsAPITokenGrantableCapability(c) != want[c] {
			t.Fatalf("IsAPITokenGrantableCapability(%q) = %v, want %v", c, IsAPITokenGrantableCapability(c), want[c])
		}
	}
}

func TestNewCapabilityMembershipGrant(t *testing.T) {
	g := NewGrant("tok-1", "tenant-a", NewCapabilityMembership([]Capability{CapViewMachines}, AllGroups()))
	if !g.Allows(CapViewMachines) {
		t.Fatalf("grant should Allow view_machines")
	}
	// Tenant-wide scope covers any group.
	if !g.AllowsInGroup(CapViewMachines, "group-anything") {
		t.Fatalf("AllGroups scope should cover any group")
	}
	// A capability NOT in the set is denied — the token carries exactly what it was minted with.
	if g.Allows(CapManageTenant) {
		t.Fatalf("grant must not Allow a capability outside its set")
	}
	if g.Allows(CapStartSession) {
		t.Fatalf("grant must not Allow start_session")
	}
}

// stubNext is an Authenticator that records whether it was reached, returning a sentinel principal.
type stubNext struct {
	called    bool
	principal *Principal
}

func (s *stubNext) Authenticate(*http.Request) (*Principal, error) {
	s.called = true
	return s.principal, nil
}

func newAPITokenAuthTest(t *testing.T) (*InMemoryAPITokenStore, *stubNext, *APITokenAuthenticator, *Principal) {
	t.Helper()
	store := NewInMemoryAPITokenStore()
	sentinel := &Principal{UserID: "session-user", TenantID: "tenant-session"}
	next := &stubNext{principal: sentinel}
	auth := &APITokenAuthenticator{Tokens: store, Next: next}
	return store, next, auth, sentinel
}

func TestAPITokenAuthenticatorResolvesScopedPrincipal(t *testing.T) {
	ctx := context.Background()
	store, next, auth, _ := newAPITokenAuthTest(t)
	plaintext, tok, err := store.Mint(ctx, "tenant-a", "bot", []Capability{CapViewMachines}, "owner-1", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	req := httptest.NewRequest("GET", "/machines", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	p, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if next.called {
		t.Fatalf("a valid API token must NOT fall through to Next")
	}
	if p.UserID != tok.ID || p.TenantID != "tenant-a" {
		t.Fatalf("principal = {%s,%s}, want {%s,tenant-a}", p.UserID, p.TenantID, tok.ID)
	}
	if p.SessionID != "" {
		t.Fatalf("token principal should carry no session, got SessionID %q", p.SessionID)
	}
	// The principal is capability-SCOPED to exactly the token's caps.
	if !p.Grant.Allows(CapViewMachines) {
		t.Fatalf("token principal should allow view_machines")
	}
	if p.Grant.Allows(CapManageTenant) || p.Grant.Allows(CapManageMachines) {
		t.Fatalf("token principal must be scoped to its minted caps only")
	}
}

func TestAPITokenAuthenticatorRejectsInvalidTokenWithoutFallthrough(t *testing.T) {
	_, next, auth, _ := newAPITokenAuthTest(t)
	req := httptest.NewRequest("GET", "/machines", nil)
	req.Header.Set("Authorization", "Bearer "+APITokenPrefix+"bogus-unminted-secret")
	p, err := auth.Authenticate(req)
	if err != ErrInvalidCredentials {
		t.Fatalf("invalid API token err = %v, want ErrInvalidCredentials", err)
	}
	if p != nil {
		t.Fatalf("invalid API token principal = %+v, want nil", p)
	}
	// Critically, a prefixed-but-invalid token is NOT re-interpreted as a session.
	if next.called {
		t.Fatalf("a prefixed-but-invalid token must be rejected, not passed to Next")
	}
}

func TestAPITokenAuthenticatorFallsThroughForNonAPICredentials(t *testing.T) {
	ctx := context.Background()
	store, next, auth, sentinel := newAPITokenAuthTest(t)
	// Mint a real token so its plaintext exists — we will present it via a COOKIE, which must be
	// ignored (headerBearerToken reads the Authorization header only).
	plaintext, _, err := store.Mint(ctx, "tenant-a", "bot", []Capability{CapViewMachines}, "owner-1", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cases := []struct {
		name  string
		setup func(*http.Request)
	}{
		{"no credential", func(*http.Request) {}},
		{"a non-API bearer (session token)", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer some-opaque-session-token")
		}},
		{"an API secret smuggled in a cookie is NOT an API token", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: DefaultSessionCookie, Value: plaintext})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next.called = false
			req := httptest.NewRequest("GET", "/machines", nil)
			tc.setup(req)
			p, err := auth.Authenticate(req)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if !next.called {
				t.Fatalf("%s must fall through to Next", tc.name)
			}
			if p != sentinel {
				t.Fatalf("%s: principal = %+v, want the Next sentinel", tc.name, p)
			}
		})
	}
}
