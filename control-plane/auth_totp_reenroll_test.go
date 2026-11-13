package controlplane

// The TOTP step-up on POST /auth/totp/enroll must SPEND the code it accepts, exactly as login does.
//
// Re-enrolling is the operation that decides what an account's second factor will be, and
// HandleEnrollTOTP demands a current code precisely so that someone riding a stolen session (or an
// XSS foothold) cannot convert that session into a permanent authentication downgrade. That
// argument only holds if the code is proof the rider does not have. Verifying without consuming
// left the ±1-step skew window keeping every code usable for ~90 seconds, so ANY observed code — a
// shoulder-surf, a proxy log, or, worst, the code the victim just spent logging in — was still
// good enough to arm the attacker's own authenticator.
//
// The replay machinery already existed and was already applied at login (ConsumeTOTPStep, RFC 6238
// §5.2); this endpoint simply did not use it. So these tests are less about a new mechanism than
// about an existing defence that one caller skipped.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// totpFixture: a user with a CONFIRMED TOTP enrollment, logged in, with throttling off so every
// rejection below is provably the replay check and not a lockout.
type totpFixture struct {
	*authFixture
	handler    http.Handler
	secret     string
	now        time.Time
	cookie     *http.Cookie
	csrfCookie *http.Cookie
	csrfToken  string
}

// newTOTPFixture logs the user in WITHOUT spending a code (the login below uses the code at `now`,
// which the caller must account for) — see loginAt.
func newTOTPFixture(t *testing.T) *totpFixture {
	t.Helper()
	f := newAuthFixture(t)
	f.auth.DisableThrottle = true
	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	fx := &totpFixture{authFixture: f, secret: secret, now: time.Unix(1_700_000_000, 0)}
	f.auth.Now = func() time.Time { return fx.now }
	fx.handler = f.srv.Handler()
	return fx
}

// login authenticates at the fixture's current clock, spending that instant's code, and stores the
// resulting session + CSRF material.
func (f *totpFixture) login(t *testing.T) {
	t.Helper()
	code, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)
	rec := doJSON(t, f.handler, "POST", "/auth/login", loginRequest{
		Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	f.cookie = sessionCookieFrom(rec)
	f.csrfCookie, f.csrfToken = csrfFrom(t, rec)
}

// enroll posts a re-enrollment step-up carrying code.
func (f *totpFixture) enroll(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/auth/totp/enroll",
		map[string]any{"code": code}, f.csrfToken, f.cookie, f.csrfCookie)
}

// TestReenrollTOTPCodeIsSingleUse is the same-endpoint replay: one observed code must arm at most
// one new authenticator.
func TestReenrollTOTPCodeIsSingleUse(t *testing.T) {
	f := newTOTPFixture(t)
	f.login(t) // spends the code at f.now

	// Move to a fresh step so the re-enroll below is not refused merely because login spent this
	// one — this test is about the SECOND presentation of a code, not the first.
	f.now = f.now.Add(61 * time.Second)
	code, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)

	if rec := f.enroll(t, code); rec.Code != http.StatusOK {
		t.Fatalf("premise not met: first re-enroll with a fresh code = %d (%s), want 200",
			rec.Code, rec.Body.String())
	}
	// The replay. Opaque message on purpose: "already used" would confirm to an attacker that the
	// code they replayed was genuine.
	replay := f.enroll(t, code)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replayed code re-enrolled again = %d (%s), want 403 — a code that has already "+
			"authorized a re-enrollment must not authorize another",
			replay.Code, replay.Body.String())
	}
	if strings.Contains(strings.ToLower(replay.Body.String()), "already") {
		t.Errorf("replay rejection names the reason (%s); it must be indistinguishable from a wrong code",
			replay.Body.String())
	}
	// Still refused later inside the same code's skew window — the window is exactly what made this
	// exploitable.
	f.now = f.now.Add(29 * time.Second)
	if rec := f.enroll(t, code); rec.Code != http.StatusForbidden {
		t.Fatalf("replay inside the skew window = %d, want 403", rec.Code)
	}
	// A code from a LATER step still works: replay protection must not lock the owner out of
	// re-enrolling.
	f.now = f.now.Add(61 * time.Second)
	next, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)
	if next == code {
		t.Fatal("test setup: expected a different code after advancing the clock")
	}
	if rec := f.enroll(t, next); rec.Code != http.StatusOK {
		t.Fatalf("fresh code after a replay = %d (%s), want 200", rec.Code, rec.Body.String())
	}
}

// TestReenrollRejectsACodeAlreadySpentAtLogin is the sharper case, and the one that makes this a
// security fix rather than a consistency fix: the two endpoints must share ONE replay ledger.
//
// The attack it closes: an attacker who observes the victim's login code (proxy log, shoulder-surf,
// phishing relay) and holds a session can present that ALREADY-SPENT code to /auth/totp/enroll.
// Before, login's ConsumeTOTPStep was the only reader of the ledger, so the enroll step-up happily
// re-accepted a code the system had itself recorded as spent — and the attacker walks away with a
// pending secret for an authenticator the real owner does not hold.
func TestReenrollRejectsACodeAlreadySpentAtLogin(t *testing.T) {
	f := newTOTPFixture(t)
	code, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)
	f.login(t) // consumes exactly this code's step

	if rec := f.enroll(t, code); rec.Code != http.StatusForbidden {
		t.Fatalf("re-enroll with the code login already spent = %d (%s), want 403 — login and "+
			"re-enrollment must share one replay ledger",
			rec.Code, rec.Body.String())
	}
}

// TestReenrollSpendingACodeBlocksItAtLogin is the same invariant in the other direction: a code
// spent on the enroll step-up must not still log someone in. Both directions matter because the
// ledger is only a defence if EVERY consumer both reads and writes it.
func TestReenrollSpendingACodeBlocksItAtLogin(t *testing.T) {
	f := newTOTPFixture(t)
	f.login(t)

	f.now = f.now.Add(61 * time.Second)
	code, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)
	if rec := f.enroll(t, code); rec.Code != http.StatusOK {
		t.Fatalf("premise not met: re-enroll = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	// The same code must no longer authenticate a login.
	relogin := doJSON(t, f.handler, "POST", "/auth/login", loginRequest{
		Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code,
	}, nil)
	if relogin.Code != http.StatusUnauthorized {
		t.Fatalf("login with a code the re-enroll spent = %d (%s), want 401",
			relogin.Code, relogin.Body.String())
	}
	if sessionCookieFrom(relogin) != nil {
		t.Fatal("a code spent by re-enrollment must not establish a session")
	}
}
