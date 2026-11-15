package controlplane

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// "Remember this app for 30 days" for Microsoft sign-in (migrations/0080). Ed, 2026-11-09: in the Hello-unlocked desktop
// app the box did nothing for "Sign in with Microsoft", so Hello asked him to sign in again every 12 hours.

const helloDesktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/130.0 DeskRallyDesktop/0.8.4 DeskRallyHello/1 DeskRallySSO/1"

func (f *b2bHTTP) startQuery(query string) b2bAttempt {
	f.t.Helper()
	w := f.request("GET", "/auth/oidc/start?"+query, "")
	b2bStatus(f.t, w, 302)
	return f.parseStart(w, w.Header().Get("Location"))
}

func (f *b2bHTTP) attemptRemember(a b2bAttempt) bool {
	f.t.Helper()
	var remember bool
	if err := f.su.QueryRow(f.ctx, `SELECT remember FROM oidc_login_attempt WHERE tenant_id=$1 AND state_hash=$2`,
		f.tenant, oidcHash(a.authorize.Query().Get("state"))).Scan(&remember); err != nil {
		f.t.Fatal(err)
	}
	return remember
}

// sessionLife reads the issued session row: its remembered flag and its absolute lifetime.
func (f *b2bHTTP) sessionLife(w *httptest.ResponseRecorder) (bool, time.Duration) {
	f.t.Helper()
	c := f.session(w)
	if c == nil {
		f.t.Fatal("missing session cookie")
	}
	var remembered bool
	var created, expires time.Time
	if err := f.su.QueryRow(f.ctx, `SELECT remembered,created_at,expires_at FROM user_session WHERE token_hash=$1`, HashToken(c.Value)).
		Scan(&remembered, &created, &expires); err != nil {
		f.t.Fatal(err)
	}
	// The cookie lives exactly as long as the session it carries.
	if d := c.Expires.Sub(expires); d > time.Second || d < -time.Second {
		f.t.Fatalf("cookie expires %v, session %v", c.Expires, expires)
	}
	return remembered, expires.Sub(created)
}

func TestOIDCRememberHelloDesktopIssuesRememberedSession(t *testing.T) {
	f := b2bFixture(t)
	f.userAgent = helloDesktopUA
	f.link()
	a := f.startQuery("return=" + url.QueryEscape("/console") + "&remember=1")
	if !f.attemptRemember(a) {
		t.Fatal("the attempt did not keep the remember choice")
	}
	f.mint(a, nil)
	w := f.callback(a, "code=callback-code", a.cookie)
	b2bStatus(t, w, 302)
	f.authenticated(w)
	remembered, life := f.sessionLife(w)
	if !remembered || life != RememberedSessionTTL {
		t.Fatalf("remembered=%v life=%v, want true and %v", remembered, life, RememberedSessionTTL)
	}
	var meta string
	if err := f.su.QueryRow(f.ctx, `SELECT metadata::text FROM audit_event WHERE tenant_id=$1 AND action='auth.login' ORDER BY occurred_at DESC LIMIT 1`, f.tenant).Scan(&meta); err != nil {
		t.Fatal(err)
	}
	if !containsAll(meta, `"remembered": true`, `"method": "oidc"`) {
		t.Fatalf("login audit does not record the remembered sign-in: %s", meta)
	}
}

func TestOIDCRememberOrdinaryUnlessAsked(t *testing.T) {
	for _, tc := range []struct{ name, ua, query string }{
		// The box unticked in the Hello app: an ordinary session, as before.
		{"hello app without remember", helloDesktopUA, ""},
		// A crafted start link opened in an ordinary browser (a shared machine): the choice is dropped, not honoured.
		{"ordinary browser asking to remember", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0", "&remember=1"},
		// The desktop app before its Hello check: no marker, no remembered session (the form shows no box there).
		{"desktop app without Hello", "Mozilla/5.0 Edg/130.0 DeskRallyDesktop/0.8.4 DeskRallySSO/1", "&remember=1"},
		// A marker that only CONTAINS the token is not the token.
		{"look-alike marker", "Mozilla/5.0 XDeskRallyHello/1", "&remember=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := b2bFixture(t)
			f.userAgent = tc.ua
			f.link()
			a := f.startQuery("return=" + url.QueryEscape("/console") + tc.query)
			if f.attemptRemember(a) {
				t.Fatal("the attempt asked to remember")
			}
			f.mint(a, nil)
			w := f.callback(a, "code=callback-code", a.cookie)
			b2bStatus(t, w, 302)
			remembered, life := f.sessionLife(w)
			if remembered || life != DefaultSessionTTL {
				t.Fatalf("remembered=%v life=%v, want false and %v", remembered, life, DefaultSessionTTL)
			}
		})
	}
}

// The DeskRally code step after Microsoft (tenant 2FA, or an enrolled authenticator) issues the session later, from
// POST /auth/oidc/totp. It reads the choice from the same consumed attempt.
func TestOIDCRememberSurvivesTheTOTPStep(t *testing.T) {
	f := b2bFixture(t)
	f.userAgent = helloDesktopUA
	f.link()
	secret := f.enroll()
	a := f.startQuery("return=" + url.QueryEscape("/console/devices") + "&remember=1")
	f.mint(a, nil)
	w := f.callback(a, "code=callback-code", a.cookie)
	b2bStatus(t, w, 302)
	if f.session(w) != nil {
		t.Fatal("MFA challenge issued session prematurely")
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Path != "/console/sso-totp" {
		t.Fatalf("MFA redirect: %v %v", u, err)
	}
	w = f.totp(u.Query().Get("p"), b2bCode(t, secret, f.server.AuthAPI.now()))
	b2bStatus(t, w, 200)
	f.authenticated(w)
	f.mfaMarked(w)
	remembered, life := f.sessionLife(w)
	if !remembered || life != RememberedSessionTTL {
		t.Fatalf("remembered=%v life=%v, want true and %v", remembered, life, RememberedSessionTTL)
	}
}

func TestOIDCRememberMalformedStartIsRefused(t *testing.T) {
	for _, query := range []string{"remember=yes", "remember=1&remember=1", "remember=true", "remember=0"} {
		t.Run(query, func(t *testing.T) {
			f := b2bFixture(t)
			f.userAgent = helloDesktopUA
			before := f.auditCount("auth.login_failed")
			f.refusal(f.request("GET", "/auth/oidc/start?"+query, ""), before, "invalid_start", "")
		})
	}
}

// Only a sign-in may ask: the store refuses a link or test attempt that does, and so does the table (0080's CHECK).
func TestOIDCRememberIsLoginOnly(t *testing.T) {
	f := b2bFixture(t)
	var constraint string
	if err := f.su.QueryRow(f.ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='oidc_attempt_remember_login_only'`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if !containsAll(constraint, "remember", "login") {
		t.Fatalf("constraint: %s", constraint)
	}
	user, session := f.user, "00000000-0000-0000-0000-000000000001"
	err := f.store.CreateAttempt(f.ctx, &OIDCAttempt{TenantID: f.tenant, KeyHash: make([]byte, 32), StateHash: make([]byte, 32),
		Nonce: "n", CodeVerifier: "v", Mode: "link", UserID: &user, SessionID: &session, ConnectionVersion: 1, Profile: "entra",
		RedirectURI: "https://acme.deskrally.test/cp/auth/oidc/callback", ReturnPath: "/console", Remember: true})
	if err != ErrOIDCInvalid {
		t.Fatalf("a link attempt asking to remember: %v, want ErrOIDCInvalid", err)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
