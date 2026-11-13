package controlplane

// PG end to end for the OIDC callback's registration of the session it mints with the credential guard
// (credential_guard.go). The OIDC store is concrete (*PgOIDCStore), so this needs the full fixture; it skips
// without TEST_DATABASE_URL like every pgx test here, and verify-all treats a skip as a failure.

import (
	"net/http"
	"testing"
	"time"
)

// An SSO sign-in is a login: its session must be registered, or its holder is refused by the failure budget an
// attacker sharing the source address ran down just before.
func TestCredentialGuard_Pg_OIDCCallbackRegistersTheSessionItMints(t *testing.T) {
	f := b2bFixture(t)
	cookieName := f.server.AuthAPI.sessionCookie("", time.Now()).Name
	guard := NewCredentialGuard(CredentialGuardConfig{MaxFailures: 2})
	f.server.Auth = &GuardedAuthenticator{
		Guard: guard, CookieName: cookieName,
		Next: &SessionAuthenticator{Sessions: f.server.AuthAPI.Sessions, Users: f.server.AuthAPI.Users, CookieName: cookieName},
	}
	f.server.AuthAPI.Guard = guard

	f.link()
	a := f.start("/console/devices")
	f.mint(a, nil)

	// The attacker runs the shared source (the fixture's default address) out of budget.
	probe := func(tok string) int {
		return f.request("GET", "/auth/session", "", &http.Cookie{Name: cookieName, Value: tok}).Code
	}
	for i := 0; i < 2; i++ {
		if got := probe(garbage(i)); got != 401 {
			t.Fatalf("attacker %d = %d, want 401", i, got)
		}
	}
	if got := probe(garbage(9)); got != 429 {
		t.Fatalf("attacker over budget = %d, want 429", got)
	}

	w := f.callback(a, "code=callback-code", a.cookie)
	b2bStatus(t, w, 302)
	session := f.session(w)
	if session == nil {
		t.Fatal("the callback issued no session")
	}
	if got := probe(session.Value); got != 204 {
		t.Fatalf("the session the SSO callback just minted, from an over-budget source = %d, want 204 (it was never registered)", got)
	}
	if got := probe(garbage(10)); got != 429 {
		t.Fatalf("garbage after the sign-in = %d, want 429", got)
	}
}
