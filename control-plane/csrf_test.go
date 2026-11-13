package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doBearerJSON issues a request authenticated by Authorization: Bearer, carrying a JSON body,
// optionally also carrying a session cookie (to prove the cookie-wins precedence), never a CSRF
// header.
func doBearerJSON(t *testing.T, h http.Handler, method, path, token string, body any, sessionCookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rdr)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	if sessionCookie != nil {
		r.AddCookie(sessionCookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// The full csrfMiddleware matrix over the real login flow: only MUTATING requests
// authenticated VIA THE SESSION COOKIE must double-submit; Bearer requests, safe methods, and
// the public endpoints pass untouched.
func TestCSRFMiddlewareMatrix(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	f.srv.EnrollmentTokens = NewInMemoryEnrollmentTokenStore() // mounts the exempt /enroll/redeem
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login = %d (body %s)", login.Code, login.Body.String())
	}
	sess := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	// Cookie-auth mutation without the header → 403 with the fixed message.
	rec := doJSONWith(t, h, "POST", "/auth/totp/enroll", nil, "", sess, csrfCookie)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "csrf token missing or invalid") {
		t.Fatalf("cookie POST without header = %d body %s, want 403 csrf", rec.Code, rec.Body.String())
	}
	// Wrong header value → 403.
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll", nil, "deadbeef", sess, csrfCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("cookie POST with wrong header = %d, want 403", rec.Code)
	}
	// Header present but the csrf COOKIE missing → 403 (nothing to match against).
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll", nil, csrfToken, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("cookie POST without csrf cookie = %d, want 403", rec.Code)
	}
	// Matching pair → the request reaches the handler.
	// The body carries the first-enrollment step-up (HandleEnrollTOTP); this test is about the
	// CSRF layer in front of it, so the request has to be one the handler itself accepts.
	enrollBody := enrollTOTPRequest{Password: "password-1234"}
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollBody, csrfToken, sess, csrfCookie); rec.Code != http.StatusOK {
		t.Fatalf("cookie POST with matching pair = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// Safe method with the cookie and no header → untouched.
	if rec := doJSON(t, h, "GET", "/machines", nil, sess); rec.Code != http.StatusOK {
		t.Fatalf("cookie GET without header = %d, want 200", rec.Code)
	}

	// Bearer-auth mutation (no cookies) → exempt: the Authorization header is not ambient
	// authority, a cross-site page cannot attach it.
	token := issueSessionFor(t, context.Background(), f.users, f.sessions, "tenant-1", "u1")
	recB := doBearerJSON(t, h, "POST", "/auth/totp/enroll", token, enrollBody, nil)
	if recB.Code != http.StatusOK {
		t.Fatalf("bearer POST without csrf header = %d (body %s), want 200", recB.Code, recB.Body.String())
	}

	// A request carrying BOTH the session cookie and a Bearer header is cookie-authenticated
	// (cookie wins in bearerToken) — so the CSRF check applies.
	recBoth := doBearerJSON(t, h, "POST", "/auth/totp/enroll", token, enrollBody, sess)
	if recBoth.Code != http.StatusForbidden {
		t.Fatalf("cookie+bearer POST without header = %d, want 403 (cookie precedence)", recBoth.Code)
	}

	// PUBLIC exemptions: /auth/login works with a stale session cookie attached and no header…
	if rec := doJSONWith(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, "", sess); rec.Code != http.StatusOK {
		t.Fatalf("login with ambient cookie, no csrf header = %d, want 200 (exempt)", rec.Code)
	}
	// …and so does /enroll/redeem (the token in the body is the authorization).
	plaintext, err := f.srv.EnrollmentTokens.MintToken(context.Background(), "tenant-1",
		&EnrollmentToken{GroupID: DevDefaultMachineGroupID, CreatedBy: "u1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	pub := hex.EncodeToString(make([]byte, 32))
	rec = doJSONWith(t, h, "POST", "/enroll/redeem",
		map[string]any{"token": plaintext, "pubkey": pub}, "", sess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem with ambient cookie, no csrf header = %d (body %s), want 201 (exempt)", rec.Code, rec.Body.String())
	}
}

// The CSRF token is BOUND to the session it was issued with, so a pair borrowed from another
// session is refused even though its two halves match each other. Without the binding the
// middleware could only check "cookie equals header", which any self-consistent pair satisfies —
// including one an attacker planted alongside a session cookie they did not issue.
func TestCSRFTokenIsBoundToTheSession(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	f.addUser(t, "tenant-1", "u2", "other@example.com", "password-1234", RoleTechnician)
	h := f.srv.Handler()

	loginA := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	sessA := sessionCookieFrom(loginA)
	csrfCookieA, csrfTokenA := csrfFrom(t, loginA)

	loginB := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "other@example.com", Password: "password-1234"}, nil)
	csrfCookieB, csrfTokenB := csrfFrom(t, loginB)

	if csrfTokenA == csrfTokenB {
		t.Fatal("two sessions received the same csrf token")
	}
	// Session A's cookie with session B's self-consistent CSRF pair → refused.
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll", nil, csrfTokenB, sessA, csrfCookieB); rec.Code != http.StatusForbidden {
		t.Fatalf("transplanted csrf pair = %d, want 403", rec.Code)
	}
	// A cookie from one session and a header from the other (the cookie-injection shape) → refused.
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll", nil, csrfTokenA, sessA, csrfCookieB); rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched csrf cookie = %d, want 403", rec.Code)
	}
	// The session's own pair still works.
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfTokenA, sessA, csrfCookieA); rec.Code != http.StatusOK {
		t.Fatalf("own csrf pair = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// The derivation is one-way: the csrf value must not be (or reveal) the session token.
	if csrfTokenA == sessA.Value {
		t.Fatal("csrf token equals the session token; it is readable by page scripts and must not be")
	}
}

// LOGIN CSRF. /auth/login cannot double-submit (no session exists yet) and the cookies it sets are
// SameSite=Lax, which a top-level cross-site form POST is allowed to trigger. Unguarded, an
// attacker's auto-submitting form logs the victim's browser into the ATTACKER's account and every
// subsequent action the victim takes lands in the attacker's tenant. The browser's own signals are
// the gate.
func TestLoginRejectsCrossSiteRequests(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	h := f.srv.Handler()
	creds := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}

	login := func(headers map[string]string) *httptest.ResponseRecorder {
		buf, _ := json.Marshal(creds)
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(buf)))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	// Refused, and — the part that matters — no session cookie is planted in the browser.
	for name, headers := range map[string]map[string]string{
		"sec-fetch-site cross-site": {"Sec-Fetch-Site": "cross-site"},
		"attacker origin":           {"Origin": "https://evil.example"},
		"same-site without origin":  {"Sec-Fetch-Site": "same-site"},
		"sibling origin":            {"Sec-Fetch-Site": "same-site", "Origin": "https://console.example.com"},
		"opaque origin":             {"Origin": "null"},
	} {
		rec := login(headers)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s login = %d (body %s), want 403", name, rec.Code, rec.Body.String())
		}
		if sessionCookieFrom(rec) != nil {
			t.Fatalf("%s login planted a session cookie", name)
		}
	}

	// The console's own requests keep working, in every shape a browser sends them.
	for name, headers := range map[string]map[string]string{
		"same-origin":             {"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"},
		"same-site matching host": {"Sec-Fetch-Site": "same-site", "Origin": "http://example.com"},
		"typed url / bookmark":    {"Sec-Fetch-Site": "none"},
		"origin matching host":    {"Origin": "http://example.com"},
		"non-browser (no hints)":  {},
	} {
		rec := login(headers)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s login = %d (body %s), want 200", name, rec.Code, rec.Body.String())
		}
	}
}

// Requests with NO credentials at all still pass the CSRF layer and die in auth (401, not 403
// csrf) — the middleware only ever gates cookie-carrying mutations.
func TestCSRFUncredentialedPassesThrough(t *testing.T) {
	f := newAuthFixture(t)
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/totp/enroll", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("credential-less POST = %d, want 401 from auth (csrf must not trip)", rec.Code)
	}
}
