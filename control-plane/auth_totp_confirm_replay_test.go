package controlplane

// POST /auth/totp/confirm must SPEND the code it accepts, exactly as login and the re-enroll
// step-up already do.
//
// Confirmation is the moment a pending secret becomes the account's enforced second factor, and the
// code presented here is a genuine, currently-valid code for that secret. Verifying it without
// recording it on the replay ledger left it alive for the rest of its ±1-step skew window — roughly
// 90 seconds — during which the SAME code still completed a LOGIN against the secret it had just
// activated. So anyone who observed the confirmation code (a shoulder-surf, a proxy log, a phishing
// relay, a screenshot of the setup screen) held a working first login on the account.
//
// This is the third consumer of one ledger. `ConsumeTOTPStep` (RFC 6238 §5.2, migrations/0012) was
// already built, already read by login, and already read by the enroll step-up — confirm simply did
// not use it. The pattern worth naming is that the gap was not a missing defence but an UNAPPLIED
// one, which is invisible to any review that only asks "does this mechanism exist?".
//
// Note what the ledger is keyed on: (user, step), not (user, secret, step). Consuming here therefore
// also refuses a confirmation whose time step some OTHER endpoint spent in the same 30 seconds — see
// TestConfirmTOTPSharesOneLedgerWithLoginAndEnroll for that deliberate cost.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// confirm posts a confirmation carrying code, on the fixture's session.
func (f *totpFixture) confirm(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/auth/totp/confirm",
		confirmTOTPRequest{Code: code}, f.csrfToken, f.cookie, f.csrfCookie)
}

// pendingSecretFrom reads the secret an enroll response handed back for the client's QR code.
func pendingSecretFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Secret == "" {
		t.Fatalf("bad enroll payload (err %v): %s", err, rec.Body.String())
	}
	return body.Secret
}

// TestConfirmedTOTPCodeCannotAlsoLogIn is the FIRST-enrollment case, and the one with no accidental
// protection at all: that enroll step-up is proven with the PASSWORD, so it spends no step, and the
// confirmation code reached the ledger completely unrecorded.
//
// The sequence an attacker gets for free is exactly the one below — read the code off the victim's
// setup screen, then use it to log in.
func TestConfirmedTOTPCodeCannotAlsoLogIn(t *testing.T) {
	f := newAuthFixture(t)
	// Throttling off so every rejection below is provably the replay check and not a lockout.
	f.auth.DisableThrottle = true
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }
	h := f.srv.Handler()

	creds := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}
	login := doJSON(t, h, "POST", "/auth/login", creds, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("premise not met: password-only login before enrollment = %d (%s), want 200",
			login.Code, login.Body.String())
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	enroll := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfToken, cookie, csrfCookie)
	if enroll.Code != http.StatusOK {
		t.Fatalf("premise not met: first enrollment = %d (%s), want 200", enroll.Code, enroll.Body.String())
	}
	secret := pendingSecretFrom(t, enroll)

	code, err := TOTPCode(secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	confirm := doJSONWith(t, h, "POST", "/auth/totp/confirm",
		confirmTOTPRequest{Code: code}, csrfToken, cookie, csrfCookie)
	if confirm.Code != http.StatusOK {
		t.Fatalf("premise not met: confirm with a fresh code = %d (%s), want 200",
			confirm.Code, confirm.Body.String())
	}

	// THE DEFECT. The clock has not moved, so this is the same code inside its own skew window.
	replay := creds
	replay.TOTPCode = code
	relogin := doJSON(t, h, "POST", "/auth/login", replay, nil)
	if relogin.Code != http.StatusUnauthorized {
		t.Fatalf("login with the code that confirmed the enrollment = %d (%s), want 401 — a code "+
			"accepted by /auth/totp/confirm is spent and must not also authenticate",
			relogin.Code, relogin.Body.String())
	}
	if sessionCookieFrom(relogin) != nil {
		t.Fatal("a code spent by confirmation must not establish a session")
	}

	// Still dead later inside the same code's skew window — the window is what made this exploitable.
	now = now.Add(29 * time.Second)
	if rec := doJSON(t, h, "POST", "/auth/login", replay, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay inside the skew window = %d, want 401", rec.Code)
	}

	// And the owner is not locked out: a code from a LATER step logs in normally. Without this leg a
	// confirm handler that simply rejected every login afterwards would satisfy the assertions above.
	now = now.Add(61 * time.Second)
	fresh, err := TOTPCode(secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (later step): %v", err)
	}
	if fresh == code {
		t.Fatal("test setup: expected a different code after advancing the clock")
	}
	freshCreds := creds
	freshCreds.TOTPCode = fresh
	if rec := doJSON(t, h, "POST", "/auth/login", freshCreds, nil); rec.Code != http.StatusOK {
		t.Fatalf("login with a fresh code after confirmation = %d (%s), want 200 — replay protection "+
			"must not lock the owner out of the factor they just enrolled", rec.Code, rec.Body.String())
	}
}

// TestConfirmedReEnrollmentCodeCannotAlsoLogIn is the same property on the RE-enrollment path, where
// the account already had 2FA. It matters separately because the enforced secret changes at the
// moment of confirmation: the code being spent belongs to the NEW authenticator, and the login it
// must not authorize is the first login against that new authenticator.
func TestConfirmedReEnrollmentCodeCannotAlsoLogIn(t *testing.T) {
	f := newTOTPFixture(t)
	f.login(t) // spends the step at f.now

	f.now = f.now.Add(61 * time.Second)
	oldCode, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)
	enroll := f.enroll(t, oldCode)
	if enroll.Code != http.StatusOK {
		t.Fatalf("premise not met: re-enroll = %d (%s), want 200", enroll.Code, enroll.Body.String())
	}
	pending := pendingSecretFrom(t, enroll)
	if pending == f.secret {
		t.Fatal("test setup: re-enrollment returned the existing secret")
	}

	// A fresh step, because the re-enroll step-up above spent this user's current one.
	f.now = f.now.Add(61 * time.Second)
	newCode, _ := TOTPCode(pending, f.now, DefaultTOTPConfig)
	if rec := f.confirm(t, newCode); rec.Code != http.StatusOK {
		t.Fatalf("premise not met: confirm = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	// THE DEFECT: the confirmation code still logs in against the secret it just activated.
	relogin := doJSON(t, f.handler, "POST", "/auth/login", loginRequest{
		Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: newCode,
	}, nil)
	if relogin.Code != http.StatusUnauthorized {
		t.Fatalf("login with the code that confirmed the re-enrollment = %d (%s), want 401",
			relogin.Code, relogin.Body.String())
	}
	if sessionCookieFrom(relogin) != nil {
		t.Fatal("a code spent by confirmation must not establish a session")
	}

	// The switched-to authenticator does work, from a later step.
	f.now = f.now.Add(61 * time.Second)
	next, _ := TOTPCode(pending, f.now, DefaultTOTPConfig)
	if rec := doJSON(t, f.handler, "POST", "/auth/login", loginRequest{
		Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: next,
	}, nil); rec.Code != http.StatusOK {
		t.Fatalf("login with the re-enrolled authenticator = %d (%s), want 200", rec.Code, rec.Body.String())
	}
}

// TestConfirmTOTPSharesOneLedgerWithLoginAndEnroll pins the OTHER direction — confirm reads the same
// ledger it writes — and with it the deliberate cost of doing so.
//
// The ledger is keyed on (user, step), not (user, secret, step), because a monotonic per-user
// counter is what makes a compare-and-set UPDATE atomic and what stops a re-enrollment rewinding the
// replay window (migrations/0012). The consequence is that a confirmation lands in the same 30-second
// step as the re-enroll step-up that produced the pending secret is REFUSED, even though the two
// codes come from different secrets and neither is a replay of the other.
//
// That cost is accepted rather than worked around, for two reasons. It is the cost this tree already
// took one endpoint over — login and the enroll step-up have refused each other inside a shared step
// since the ledger's second consumer landed — and the alternative, a write-only bump that never
// reads, would be a SECOND single-use mechanism sitting beside the existing one. The user's
// remediation is to enter the next code; the engineering remediation, should this ever be worth the
// schema change, is to key the ledger per-secret.
func TestConfirmTOTPSharesOneLedgerWithLoginAndEnroll(t *testing.T) {
	f := newTOTPFixture(t)
	f.login(t)

	f.now = f.now.Add(61 * time.Second)
	oldCode, _ := TOTPCode(f.secret, f.now, DefaultTOTPConfig)
	enroll := f.enroll(t, oldCode) // spends this step
	if enroll.Code != http.StatusOK {
		t.Fatalf("premise not met: re-enroll = %d (%s), want 200", enroll.Code, enroll.Body.String())
	}
	pending := pendingSecretFrom(t, enroll)

	// Same step as the step-up. A different code from a different secret — and still refused, because
	// the step is spent.
	sameStep, _ := TOTPCode(pending, f.now, DefaultTOTPConfig)
	rec := f.confirm(t, sameStep)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("confirm inside the step the enroll step-up spent = %d (%s), want 403 — confirm "+
			"reads the same replay ledger it writes", rec.Code, rec.Body.String())
	}
	// Opaque, exactly as at login and enroll: "already used" would confirm the code was genuine.
	if strings.Contains(strings.ToLower(rec.Body.String()), "already") {
		t.Errorf("rejection names the reason (%s); it must be indistinguishable from a wrong code",
			rec.Body.String())
	}
	// Nothing was promoted — the pending enrollment survives for the retry below.
	if rec := f.confirm(t, "000000"); rec.Code != http.StatusForbidden {
		t.Fatalf("a refused confirmation must leave the enrollment pending; wrong-code confirm = %d (%s), want 403",
			rec.Code, rec.Body.String())
	}

	// The next code confirms, which is the whole of the user-visible remediation.
	f.now = f.now.Add(61 * time.Second)
	nextStep, _ := TOTPCode(pending, f.now, DefaultTOTPConfig)
	if rec := f.confirm(t, nextStep); rec.Code != http.StatusOK {
		t.Fatalf("confirm at the next step = %d (%s), want 200", rec.Code, rec.Body.String())
	}
}
