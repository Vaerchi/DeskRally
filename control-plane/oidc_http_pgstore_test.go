package controlplane

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Reuse the store fixture's disposable database, migrations, rmt_app connection,
// and TEST_DATABASE_URL skip/fail policy. Do not run these tests in parallel:
// the sibling fixtures share database provisioning conventions.
type b2bHTTP struct {
	*oidcFixture
	t       *testing.T
	server  *Server
	handler http.Handler
	idp     *b1IdP
	client  *EntraClient
	// remoteAddr overrides the client address for the next requests (default 192.0.2.20).
	remoteAddr string
	// forwardedFor / userAgent, when set, are sent as X-Forwarded-For / User-Agent on every request.
	forwardedFor, userAgent string
}

type b2bAttempt struct {
	cookie    *http.Cookie
	authorize *url.URL
}

func b2bFixture(t *testing.T) *b2bHTTP {
	t.Helper()
	f := newOIDCFixture(t)
	// The handlers audit through the chained management audit (migration 0014+), and the SSO settings
	// need an OWNER; provisionUser makes a technician.
	applyMgmtAuditChainMigration(t, f.su)
	mustExec(t, f.su, `UPDATE membership SET role_id=(SELECT id FROM role WHERE key='owner' AND tenant_id IS NULL) WHERE user_id=$1`, f.user)
	p, c := b1Fake(t)
	// b1Fake's endpoint router uses b1Config identifiers.
	cfg := b1Config()
	f.write.EntraTenantID, f.write.ClientID = cfg.TenantID, cfg.ClientID
	connection, err := f.store.PutConnection(f.ctx, f.tenant, f.write)
	if err != nil {
		t.Fatal(err)
	}
	f.a.ConnectionVersion = connection.Version
	f.a.Issuer = c.issuer
	f.a.Subject = "subject"
	s, handler := newPgAuthTestServer(t, f.app, f.cipher)
	s.OIDC = f.store
	s.TenantHostSuffix = ".deskrally.test"
	s.newEntraClient = func(cfg EntraConfig) (*EntraClient, error) {
		return newEntraClientWithBase(cfg, p.server.URL, p.server.Client())
	}
	// The handler must retain the real password, session, CSRF, authorization,
	// tenant-binding, origin, and audit middleware from the auth fixture.
	return &b2bHTTP{oidcFixture: f, t: t, server: s, handler: handler, idp: p, client: c}
}

func (f *b2bHTTP) request(method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, "https://acme.deskrally.test"+path, strings.NewReader(body))
	r.Host = "acme.deskrally.test"
	r.RemoteAddr = "192.0.2.20:12345"
	if f.remoteAddr != "" {
		r.RemoteAddr = f.remoteAddr
	}
	r.Header.Set("Origin", "https://acme.deskrally.test")
	if f.forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", f.forwardedFor)
	}
	if f.userAgent != "" {
		r.Header.Set("User-Agent", f.userAgent)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	csrfName := f.server.AuthAPI.csrfCookie("", time.Now()).Name
	for _, c := range cookies {
		r.AddCookie(c)
		if c.Name == csrfName {
			r.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func b2bStatus(t *testing.T, w *httptest.ResponseRecorder, allowed ...int) {
	t.Helper()
	for _, status := range allowed {
		if w.Code == status {
			return
		}
	}
	t.Fatalf("status %d, want %v; body=%s", w.Code, allowed, w.Body.String())
}

func b2bJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func b2bCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func (f *b2bHTTP) session(w *httptest.ResponseRecorder) *http.Cookie {
	return b2bCookie(w, f.server.AuthAPI.sessionCookie("", time.Now()).Name)
}

func (f *b2bHTTP) headers(w *httptest.ResponseRecorder) {
	f.t.Helper()
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		f.t.Fatalf("missing OIDC privacy headers: %v", w.Header())
	}
}

func (f *b2bHTTP) link() {
	f.t.Helper()
	mustExec(f.t, f.su, `UPDATE app_user SET oidc_issuer=$2,oidc_subject=$3 WHERE id=$1`, f.user, f.a.Issuer, f.a.Subject)
}

func (f *b2bHTTP) start(returnPath string) b2bAttempt {
	f.t.Helper()
	w := f.request("GET", "/auth/oidc/start?return="+url.QueryEscape(returnPath), "")
	b2bStatus(f.t, w, 302)
	return f.parseStart(w, w.Header().Get("Location"))
}

func (f *b2bHTTP) parseStart(w *httptest.ResponseRecorder, location string) b2bAttempt {
	f.t.Helper()
	f.headers(w)
	u, err := url.Parse(location)
	if err != nil {
		f.t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != f.idp.server.URL+"/"+b1Config().TenantID+"/oauth2/v2.0/authorize" {
		f.t.Fatalf("authorize URL: %s", u)
	}
	q := u.Query()
	for _, key := range []string{"state", "nonce", "code_challenge"} {
		raw, err := base64.RawURLEncoding.DecodeString(q.Get(key))
		if err != nil || len(raw) != 32 || len(q[key]) != 1 {
			f.t.Fatalf("invalid %s", key)
		}
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != "https://acme.deskrally.test/cp/auth/oidc/callback" {
		f.t.Fatalf("authorization parameters: %v", q)
	}
	c := b2bCookie(w, oidcAttemptCookie)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 600 {
		f.t.Fatalf("attempt cookie: %+v", c)
	}
	// Verify the actual persisted verifier, rather than only the challenge's shape.
	var sealed []byte
	if err := f.su.QueryRow(f.ctx, `SELECT code_verifier_enc FROM oidc_login_attempt WHERE tenant_id=$1 AND state_hash=$2`, f.tenant, oidcHash(q.Get("state"))).Scan(&sealed); err != nil {
		f.t.Fatal(err)
	}
	verifier, encrypted, err := f.cipher.Open(sealed)
	if err != nil || !encrypted {
		f.t.Fatalf("verifier encryption: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		f.t.Fatal("incorrect PKCE challenge")
	}
	return b2bAttempt{c, u}
}

func (f *b2bHTTP) mint(a b2bAttempt, mutate func(map[string]any)) string {
	f.t.Helper()
	claims := b1Claims(f.client, time.Now())
	claims["nonce"] = a.authorize.Query().Get("nonce")
	delete(claims, "amr")
	if mutate != nil {
		mutate(claims)
	}
	raw := b1Sign(f.t, f.idp.key, jose.RS256, "initial", claims)
	f.idp.mu.Lock()
	f.idp.raw = raw
	f.idp.mu.Unlock()
	return raw
}

func (f *b2bHTTP) callback(a b2bAttempt, extra string, cookie *http.Cookie) *httptest.ResponseRecorder {
	path := "/auth/oidc/callback?state=" + url.QueryEscape(a.authorize.Query().Get("state")) + "&" + extra
	if cookie == nil {
		return f.request("GET", path, "")
	}
	return f.request("GET", path, "", cookie)
}

func (f *b2bHTTP) auditCount(action string) int {
	f.t.Helper()
	var n int
	if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM audit_event WHERE tenant_id=$1 AND action=$2`, f.tenant, action).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *b2bHTTP) audit(action, reason string, forbidden ...string) {
	f.t.Helper()
	var rowsJSON []byte
	if err := f.su.QueryRow(f.ctx, `SELECT coalesce(jsonb_agg(metadata),'[]'::jsonb) FROM audit_event WHERE tenant_id=$1 AND action=$2`, f.tenant, action).Scan(&rowsJSON); err != nil {
		f.t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rowsJSON, &rows); err != nil {
		f.t.Fatal(err)
	}
	matched := false
	for _, row := range rows {
		if row["method"] == "oidc" && (reason == "" || row["reason"] == reason) {
			matched = true
		}
		b, err := json.Marshal(row)
		if err != nil {
			f.t.Fatal(err)
		}
		for _, secret := range forbidden {
			if secret != "" && bytes.Contains(b, []byte(secret)) {
				f.t.Fatal("secret leaked in audit metadata")
			}
		}
		for key := range row {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "token") || lower == "code" || lower == "client_secret" || lower == "code_verifier" {
				f.t.Fatalf("sensitive audit field: %s", key)
			}
		}
	}
	if !matched {
		f.t.Fatalf("missing %s audit, reason=%q: %s", action, reason, rowsJSON)
	}
}

func (f *b2bHTTP) refusal(w *httptest.ResponseRecorder, before int, reason, raw string) {
	f.t.Helper()
	b2bStatus(f.t, w, 401, 403)
	f.headers(w)
	if f.session(w) != nil {
		f.t.Fatal("refusal issued a session")
	}
	if f.auditCount("auth.login_failed") != before+1 {
		f.t.Fatal("refusal did not produce exactly one failure audit")
	}
	f.audit("auth.login_failed", reason, raw, "callback-code", *f.write.ClientSecret)
}

func (f *b2bHTTP) password() []*http.Cookie {
	f.t.Helper()
	body := `{"tenant":"acme","email":"owner@acme.test","password":"password-1234"}`
	w := f.request("POST", "/auth/login", body)
	b2bStatus(f.t, w, 200)
	if f.session(w) == nil {
		f.t.Fatal("password login fixture did not issue session")
	}
	return w.Result().Cookies()
}

func (f *b2bHTTP) fresh(cookies []*http.Cookie, age time.Duration) {
	f.t.Helper()
	name := f.server.AuthAPI.sessionCookie("", time.Now()).Name
	var token string
	for _, c := range cookies {
		if c.Name == name {
			token = c.Value
		}
	}
	if token == "" {
		f.t.Fatal("missing origin session")
	}
	mustExec(f.t, f.su, `UPDATE user_session SET mfa_verified_at=clock_timestamp()-($2::double precision*interval '1 second'),mfa_generation=42 WHERE token_hash=$1`, HashToken(token), age.Seconds())
}

func (f *b2bHTTP) authenticated(w *httptest.ResponseRecorder) {
	f.t.Helper()
	c := f.session(w)
	if c == nil {
		f.t.Fatal("missing session cookie")
	}
	// /auth/session runs the full protected chain and answers 204; WHO it authenticated is read from
	// the session row the cookie's token hashes to.
	me := f.request("GET", "/auth/session", "", c)
	b2bStatus(f.t, me, 204)
	var uid string
	if err := f.su.QueryRow(f.ctx, `SELECT user_id::text FROM user_session WHERE token_hash=$1`, HashToken(c.Value)).Scan(&uid); err != nil || uid != f.user {
		f.t.Fatalf("session authenticated user %q (%v), want %q", uid, err, f.user)
	}
}

func (f *b2bHTTP) mfaMarked(w *httptest.ResponseRecorder) {
	f.t.Helper()
	c := f.session(w)
	if c == nil {
		f.t.Fatal("missing MFA session")
	}
	var valid bool
	if err := f.su.QueryRow(f.ctx, `SELECT mfa_verified_at IS NOT NULL AND mfa_generation=42 AND login_method='oidc' FROM user_session WHERE token_hash=$1`, HashToken(c.Value)).Scan(&valid); err != nil {
		f.t.Fatal(err)
	}
	if !valid {
		f.t.Fatal("session lacks generation-bound MFA stamp")
	}
}

func TestB2bHTTPInfoAndHost(t *testing.T) {
	f := b2bFixture(t)
	mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=false WHERE tenant_id=$1`, f.tenant)
	w := f.request("GET", "/auth/sso-info?tenant=acme", "")
	b2bStatus(t, w, 200)
	if got := b2bJSON(t, w)["providers"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("disabled providers: %#v", got)
	}
	f.headers(w)
	mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=true WHERE tenant_id=$1`, f.tenant)
	w = f.request("GET", "/auth/sso-info?tenant=acme", "")
	b2bStatus(t, w, 200)
	want := []any{map[string]any{"id": "entra", "label": "Microsoft"}}
	if !reflect.DeepEqual(b2bJSON(t, w)["providers"], want) {
		t.Fatal(w.Body.String())
	}
	t.Run("tenant query cannot override host", func(t *testing.T) {
		b2bStatus(t, f.request("GET", "/auth/sso-info?tenant=other", ""), 400, 403)
	})
	for _, host := range []string{"acme", "evil.test", "acme.deskrally.test.evil.test", "x.acme.deskrally.test", "acme.deskrally.test:444"} {
		t.Run(host, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://"+host+"/auth/oidc/start", nil)
			r.Host = host
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			b2bStatus(t, w, 400, 401, 403)
			if w.Header().Get("Location") != "" || b2bCookie(w, oidcAttemptCookie) != nil {
				t.Fatal("unbound host started login")
			}
		})
	}
}

func TestB2bHTTPLogin(t *testing.T) {
	f := b2bFixture(t)
	passwordCookies := f.password()
	f.link()
	a := f.start("/console/devices?tab=online")
	raw := f.mint(a, nil)
	w := f.callback(a, "code=callback-code", a.cookie)
	b2bStatus(t, w, 302)
	if w.Header().Get("Location") != "/console/devices?tab=online" {
		t.Fatal(w.Header())
	}
	f.headers(w)
	f.authenticated(w)
	f.audit("auth.login", "", raw, "callback-code", *f.write.ClientSecret)
	// Compare all cookie policy attributes against real password login. Values
	// and expiration timestamps necessarily differ between the two logins.
	for _, name := range []string{f.server.AuthAPI.sessionCookie("", time.Now()).Name, f.server.AuthAPI.csrfCookie("", time.Now()).Name} {
		got := b2bCookie(w, name)
		var want *http.Cookie
		for _, c := range passwordCookies {
			if c.Name == name {
				copy := *c
				want = &copy
			}
		}
		if got == nil || want == nil {
			t.Fatalf("missing auth cookie %s", name)
		}
		if got.Expires.IsZero() || want.Expires.IsZero() {
			t.Fatal("missing cookie expiration")
		}
		g, p := *got, *want
		g.Value, p.Value = "", ""
		g.Expires, p.Expires = time.Time{}, time.Time{}
		g.Raw, p.Raw = "", ""
		if !reflect.DeepEqual(g, p) {
			t.Fatalf("OIDC/password cookie policy differs: %+v / %+v", g, p)
		}
	}
	session := f.session(w)
	csrf := b2bCookie(w, f.server.AuthAPI.csrfCookie("", time.Now()).Name)
	if csrf.Value != csrfTokenFor(session.Value) {
		t.Fatal("CSRF cookie does not bind issued session")
	}
	f.idp.mu.Lock()
	form := f.idp.form
	f.idp.mu.Unlock()
	if form.Get("redirect_uri") != "https://acme.deskrally.test/cp/auth/oidc/callback" || form.Get("code") != "callback-code" {
		t.Fatalf("exchange form: %v", form)
	}
	sum := sha256.Sum256([]byte(form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != a.authorize.Query().Get("code_challenge") {
		t.Fatal("exchange did not use attempt verifier")
	}
}

func TestB2bHTTPInvalidReturnFallsBack(t *testing.T) {
	for _, path := range []string{"//evil", "https://evil"} {
		t.Run(path, func(t *testing.T) {
			f := b2bFixture(t)
			f.link()
			a := f.start(path)
			f.mint(a, nil)
			w := f.callback(a, "code=callback-code", a.cookie)
			b2bStatus(t, w, 302)
			if w.Header().Get("Location") != "/console" {
				t.Fatal("unsafe return did not fall back to /console")
			}
		})
	}
}

func TestB2bHTTPCallbackRefusals(t *testing.T) {
	cases := []struct{ name, reason string }{
		{"unlinked", "not_linked"}, {"missing-cookie", "attempt_not_found"},
		{"wrong-cookie", "attempt_not_found"}, {"replay", "attempt_used"},
		{"duplicate-code", "invalid_callback"}, {"idp-error", "idp_error"},
		{"nonce", "token_nonce"}, {"disabled", "disabled"}, {"version", "version_changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := b2bFixture(t)
			if tc.name != "unlinked" {
				f.link()
			}
			a := f.start("/console")
			raw := f.mint(a, func(m map[string]any) {
				if tc.name == "nonce" {
					m["nonce"] = "different-nonce"
				}
			})
			cookie, extra := a.cookie, "code=callback-code"
			switch tc.name {
			case "missing-cookie":
				cookie = nil
			case "wrong-cookie":
				key, err := NewOIDCState()
				if err != nil {
					t.Fatal(err)
				}
				copy := *a.cookie
				copy.Value = key
				cookie = &copy
			case "duplicate-code":
				extra += "&code=second-code"
			case "idp-error":
				extra = "error=access_denied&error_description=secret-provider-text"
			case "disabled":
				mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=false WHERE tenant_id=$1`, f.tenant)
			case "version":
				mustExec(t, f.su, `UPDATE tenant_oidc SET version=version+1 WHERE tenant_id=$1`, f.tenant)
			case "replay":
				first := f.callback(a, extra, cookie)
				b2bStatus(t, first, 302)
				f.authenticated(first)
			}
			before := f.auditCount("auth.login_failed")
			f.refusal(f.callback(a, extra, cookie), before, tc.reason, raw)
			f.audit("auth.login_failed", tc.reason, "secret-provider-text", "second-code")
		})
	}
}

// Generate a real six-digit RFC 6238 code without an extra test dependency.
func b2bCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func (f *b2bHTTP) enroll() string {
	f.t.Helper()
	secret := "JBSWY3DPEHPK3PXP"
	// Use the sibling auth fixture's encryption-aware enrollment helper.
	setPgTestTOTP(f.t, f.su, f.cipher, f.tenant, f.user, secret)
	return secret
}

func (f *b2bHTTP) pending() string {
	f.t.Helper()
	a := f.start("/console/devices")
	f.mint(a, nil)
	w := f.callback(a, "code=callback-code", a.cookie)
	b2bStatus(f.t, w, 302)
	if f.session(w) != nil {
		f.t.Fatal("MFA challenge issued session prematurely")
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Path != "/console/sso-totp" || !isUUID(u.Query().Get("p")) {
		f.t.Fatalf("MFA redirect: %v %v", u, err)
	}
	return u.Query().Get("p")
}

func (f *b2bHTTP) totp(id, code string) *httptest.ResponseRecorder {
	body, err := json.Marshal(map[string]string{"pending_id": id, "totp_code": code})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.request("POST", "/auth/oidc/totp", string(body))
}

func TestB2bHTTPMFA(t *testing.T) {
	t.Run("local TOTP and pending replay", func(t *testing.T) {
		f := b2bFixture(t)
		f.link()
		secret := f.enroll()
		mustExec(t, f.su, `UPDATE tenant SET require_2fa=true WHERE id=$1`, f.tenant)
		id := f.pending()
		code := b2bCode(t, secret, f.server.AuthAPI.now())
		w := f.totp(id, code)
		b2bStatus(t, w, 200)
		if b2bJSON(t, w)["return_path"] != "/console/devices" {
			t.Fatal(w.Body.String())
		}
		f.authenticated(w)
		f.mfaMarked(w)
		before := f.auditCount("auth.login_failed")
		f.refusal(f.totp(id, code), before, "attempt_used", "")
	})
	// One MFA policy for local and SSO login (design v2): a user who ENROLLED TOTP must use it even when
	// the tenant does not require 2FA — password login already demands it, so SSO must not skip it.
	t.Run("enrolled TOTP is required without a tenant 2FA policy", func(t *testing.T) {
		f := b2bFixture(t)
		f.link()
		f.enroll()
		id := f.pending() // pending() fatals unless the callback redirected to the TOTP step
		if id == "" {
			t.Fatal("no pending MFA challenge")
		}
	})
	t.Run("wrong code is charged and eventually throttled", func(t *testing.T) {
		f := b2bFixture(t)
		f.link()
		f.enroll()
		mustExec(t, f.su, `UPDATE tenant SET require_2fa=true WHERE id=$1`, f.tenant)
		// Malformed numeric length cannot accidentally match a live TOTP. Each
		// failure uses a fresh pending id because consumption is one-shot.
		throttled := false
		// Collect the pending challenges FIRST: a successful start charges nothing, while every refused
		// TOTP also charges the public per-IP limiter, which would otherwise refuse the next START
		// before the account's TOTP throttle is consulted. This way the 429 must come from the TOTP
		// endpoint itself.
		ids := make([]string, 0, 8)
		for i := 0; i < 8; i++ {
			ids = append(ids, f.pending())
		}
		for i, id := range ids {
			// A different client address per attempt keeps the public per-IP limiter out of the way, so
			// only the ACCOUNT's TOTP throttle can produce the 429 this test is about.
			f.remoteAddr = fmt.Sprintf("198.51.100.%d:443", i+1)
			before := f.auditCount("auth.login_failed")
			w := f.totp(id, "0000000")
			if w.Code == 429 {
				if f.session(w) != nil || w.Header().Get("Retry-After") == "" {
					t.Fatal("invalid throttle response")
				}
				f.audit("auth.login_failed", "totp_throttled")
				throttled = true
				break
			}
			f.refusal(w, before, "totp_invalid", "")
		}
		if !throttled {
			t.Fatal("wrong TOTP attempts never throttled")
		}
	})
	t.Run("trusted Entra MFA", func(t *testing.T) {
		f := b2bFixture(t)
		f.link()
		mustExec(t, f.su, `UPDATE tenant SET require_2fa=true WHERE id=$1`, f.tenant)
		mustExec(t, f.su, `UPDATE tenant_oidc SET trust_entra_mfa=true WHERE tenant_id=$1`, f.tenant)
		a := f.start("/console")
		f.mint(a, func(m map[string]any) { m["amr"] = []string{"pwd", "mfa"} })
		w := f.callback(a, "code=callback-code", a.cookie)
		b2bStatus(t, w, 302)
		if w.Header().Get("Location") != "/console" {
			t.Fatal(w.Header())
		}
		f.authenticated(w)
		f.mfaMarked(w)
	})
	t.Run("required MFA without enrollment", func(t *testing.T) {
		f := b2bFixture(t)
		f.link()
		mustExec(t, f.su, `UPDATE tenant SET require_2fa=true WHERE id=$1`, f.tenant)
		a := f.start("/console")
		raw := f.mint(a, nil)
		before := f.auditCount("auth.login_failed")
		f.refusal(f.callback(a, "code=callback-code", a.cookie), before, "totp_not_enrolled", raw)
	})
}
