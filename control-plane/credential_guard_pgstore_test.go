package controlplane

// PG end to end for credential_guard.go: the guard in front of the REAL session store (cp_session_by_token,
// SECURITY DEFINER, RLS-pinned binder). Skips without TEST_DATABASE_URL like every pgx test here; verify-all
// treats a skip as a failure.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCredentialGuard_Pg_ValidSessionWorksEndToEndWhileGarbageIsBounded(t *testing.T) {
	f := newPass13PgFixture(t)
	// Re-front the fixture's real session authenticator with a guard. The handler resolves s.Auth per request,
	// so swapping it here changes the live chain; the stores underneath are the fixture's pgx ones.
	guard := NewCredentialGuard(CredentialGuardConfig{MaxFailures: 3})
	f.srv.Auth = &GuardedAuthenticator{
		Guard: guard,
		Next:  &SessionAuthenticator{Sessions: f.srv.AuthAPI.Sessions, Users: f.srv.AuthAPI.Users},
	}
	f.srv.AuthAPI.Guard = guard

	// Real logins (argon2, real tenant resolution): the tokens are registered by login.
	alice, _, _ := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bob, _, _ := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)

	send := func(method, path, tok, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "198.51.100.60:9"
		if tok != "" {
			r.AddCookie(&http.Cookie{Name: DefaultSessionCookie, Value: tok})
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		return w
	}

	if got := f.listSessions(t, alice); got != http.StatusOK {
		t.Fatalf("alice before the flood = %d, want 200", got)
	}
	// Valid-shaped garbage against the real store: three real lookups answer 401, then the source is refused.
	for i := 0; i < 3; i++ {
		if w := send("GET", "/sessions", garbage(i), ""); w.Code != 401 {
			t.Fatalf("garbage %d = %d, want 401", i, w.Code)
		}
	}
	if w := send("GET", "/sessions", garbage(7), ""); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("garbage over budget = %d, want 429 with Retry-After", w.Code)
	}
	// Valid sessions keep working end to end through the PG store, by cookie and by bearer.
	if got := f.listSessions(t, alice); got != http.StatusOK {
		t.Fatalf("alice while the source is over budget = %d, want 200", got)
	}
	if w := send("GET", "/sessions", "", bob.Value); w.Code != http.StatusOK {
		t.Fatalf("bob by bearer while over budget = %d, want 200", w.Code)
	}
	// Logout by Authorization header (no cookie, so no CSRF) revokes in the real store...
	if w := send("POST", "/auth/logout", "", bob.Value); w.Code != http.StatusNoContent {
		t.Fatalf("bob logout = %d, want 204", w.Code)
	}
	// ... a plausible-but-unknown token from the over-budget source is refused without a lookup ...
	if w := send("POST", "/auth/logout", "", garbage(8)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("garbage logout over budget = %d, want 429", w.Code)
	}
	// ... and the revoked session is refused by the REAL store, from a source with budget to spare (so the
	// answer is the store's 401, not the guard's 429), and no longer exempt from an over-budget one.
	r := httptest.NewRequest("GET", "/sessions", nil)
	r.RemoteAddr = "203.0.113.61:9"
	r.Header.Set("Authorization", "Bearer "+bob.Value)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bob after logout, fresh source = %d, want 401", w.Code)
	}
	if w := send("GET", "/sessions", "", bob.Value); w.Code != http.StatusTooManyRequests {
		t.Fatalf("bob after logout, over-budget source = %d, want 429 (no longer exempt)", w.Code)
	}
}
