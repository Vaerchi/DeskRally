package controlplane

// Tests for the credential-endpoint throttle: the backoff curve itself, plus the three HTTP
// surfaces that meter with it (login, TOTP confirmation, public enrollment redemption). These are
// the tests that fail if brute-force protection is ever removed.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestThrottleBackoffAndReset(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	th := NewThrottle(ThrottleConfig{FreeAttempts: 3, BaseDelay: time.Second, MaxDelay: 8 * time.Second, Reset: time.Minute})
	th.Now = func() time.Time { return now }

	// The free allowance (3 failures) passes untouched…
	for i := 0; i < 3; i++ {
		if _, ok := th.Allow("k"); !ok {
			t.Fatalf("attempt %d locked out inside the free allowance", i+1)
		}
		th.Fail("k")
	}
	if _, ok := th.Allow("k"); !ok {
		t.Fatal("the attempt right after the free allowance must still be served")
	}
	th.Fail("k") // …and the first failure beyond it starts the backoff.

	// The lockout then doubles per failure, capped at MaxDelay.
	for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second} {
		retry, ok := th.Allow("k")
		if ok {
			t.Fatalf("expected a lockout of %s, got none", want)
		}
		if retry != want {
			t.Fatalf("retry-after = %s, want %s", retry, want)
		}
		now = now.Add(want) // wait it out, then fail once more
		if _, ok := th.Allow("k"); !ok {
			t.Fatal("lockout did not expire after its window")
		}
		th.Fail("k")
	}

	// A success clears the key outright.
	th.Reset("k")
	if retry, ok := th.Allow("k"); !ok {
		t.Fatalf("Reset left the key locked for %s", retry)
	}

	// Independent keys do not share a budget, and ANY locked key blocks a multi-key check.
	th.Fail("a", "a", "a", "a", "a")
	if _, ok := th.Allow("b"); !ok {
		t.Fatal("a lockout on key a must not affect key b")
	}
	if _, ok := th.Allow("b", "a"); ok {
		t.Fatal("a request must be blocked when ANY of its keys is locked out")
	}

	// An idle key decays, so the map cannot grow without bound.
	now = now.Add(2 * time.Minute)
	if _, ok := th.Allow("a"); !ok {
		t.Fatal("an idle key should have decayed")
	}
	th.mu.Lock()
	n := len(th.entries)
	th.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d entries survived the idle window, want 0", n)
	}
}

// A nil Throttle is the "metering disabled" case and must never panic.
func TestNilThrottleAllowsEverything(t *testing.T) {
	var th *Throttle
	th.Fail("k")
	th.Reset("k")
	if retry, ok := th.Allow("k"); !ok || retry != 0 {
		t.Fatalf("nil throttle = (%s, %v), want (0, true)", retry, ok)
	}
}

// Password/TOTP guessing on /auth/login runs into a lockout, the response carries Retry-After, and
// the failures are on the audit trail. This is the online brute-force guard for the second factor.
func TestLoginThrottledAfterRepeatedFailures(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "the-real-password", RoleTechnician)
	f.srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	f.auth.MgmtAudit = f.srv.MgmtAudit
	f.auth.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 2, BaseDelay: 2 * time.Second, MaxDelay: time.Minute, Reset: time.Minute})
	h := f.srv.Handler()

	// Two free failures, then the third starts the backoff — the fourth request is refused
	// outright without the credentials even being checked.
	bad := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "guess"}
	for i := 0; i < 3; i++ {
		if rec := doJSON(t, h, "POST", "/auth/login", bad, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, rec.Code)
		}
	}
	rec := doJSON(t, h, "POST", "/auth/login", bad, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 4 = %d, want 429", rec.Code)
	}
	if secs, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q (%v), want a positive integer", rec.Header().Get("Retry-After"), err)
	}
	if !strings.Contains(rec.Body.String(), ErrTooManyAttempts.Error()) {
		t.Fatalf("throttled body = %s", rec.Body.String())
	}

	// The CORRECT password is refused too while the lockout stands — otherwise the limit would
	// only slow down the attacker's wrong guesses.
	good := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "the-real-password"}
	if rec := doJSON(t, h, "POST", "/auth/login", good, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password during lockout = %d, want 429", rec.Code)
	}

	// Failures are auditable — with no actor attributed (the caller never authenticated).
	events, err := f.srv.MgmtAudit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("audited %d login failures, want 3", len(events))
	}
	for _, e := range events {
		if e.Action != "auth.login_failed" || e.ActorUserID != "" {
			t.Fatalf("audit event = %+v, want an actor-less auth.login_failed", e)
		}
	}
}

// A successful login must not erase failures charged to the shared source-IP budget.
func TestSuccessfulLoginPreservesSourceThrottle(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "the-real-password", RoleTechnician)
	f.auth.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 2, BaseDelay: time.Minute, MaxDelay: time.Minute, Reset: time.Hour})
	h := f.srv.Handler()

	bad := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "guess"}
	good := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "the-real-password"}
	for i := 0; i < 2; i++ {
		doJSON(t, h, "POST", "/auth/login", bad, nil)
	}
	if rec := doJSON(t, h, "POST", "/auth/login", good, nil); rec.Code != http.StatusOK {
		t.Fatalf("login inside the free allowance = %d, want 200", rec.Code)
	}
	// The source budget survives a successful login: one more failure exhausts it.
	if rec := doJSON(t, h, "POST", "/auth/login", bad, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure = %d, want 401", rec.Code)
	}
	if rec := doJSON(t, h, "POST", "/auth/login", bad, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("shared source budget = %d, want 429", rec.Code)
	}
}

// TOTP confirmation is metered on the same curve — it verifies a 6-digit code just like login.
func TestTOTPConfirmThrottled(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	f.auth.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 1, BaseDelay: time.Minute, MaxDelay: time.Minute, Reset: time.Hour})
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusOK {
		t.Fatalf("enroll = %d (body %s)", rec.Code, rec.Body.String())
	}
	for i := 0; i < 2; i++ {
		if rec := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: "000000"}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusForbidden {
			t.Fatalf("guess %d = %d, want 403", i+1, rec.Code)
		}
	}
	if rec := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: "000000"}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("guess 3 = %d, want 429", rec.Code)
	}
}

// The UNAUTHENTICATED enrollment-redemption endpoint is metered per source so tokens cannot be
// guessed at line rate. Malformed requests cost no budget — only real token checks do.
func TestRedeemEnrollmentThrottled(t *testing.T) {
	srv, _ := newTestServer(nil)
	srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 1, BaseDelay: time.Minute, MaxDelay: time.Minute, Reset: time.Hour})
	pubHex := testPubkeyHex(t)

	body := `{"token":"never-minted","pubkey":"` + pubHex + `"}`
	for i := 0; i < 2; i++ {
		if code := apiJSON(t, srv, "POST", "/enroll/redeem", body, nil); code != http.StatusForbidden {
			t.Fatalf("guess %d = %d, want 403", i+1, code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/enroll/redeem", strings.NewReader(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("guess 3 = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("throttled redemption carries no Retry-After")
	}
}
