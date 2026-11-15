package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestB2bHTTPLink(t *testing.T) {
	for _, name := range []string{"success", "stale", "identity-conflict"} {
		t.Run(name, func(t *testing.T) {
			f := b2bFixture(t)
			cookies := f.password()
			f.enroll()
			f.fresh(cookies, time.Minute)
			if name == "stale" {
				f.fresh(cookies, 6*time.Minute)
			}
			var other string
			if name == "identity-conflict" {
				if err := f.su.QueryRow(f.ctx, `INSERT INTO app_user (tenant_id,email,oidc_issuer,oidc_subject) VALUES ($1,'other@acme.test',$2,$3) RETURNING id::text`, f.tenant, f.a.Issuer, f.a.Subject).Scan(&other); err != nil {
					t.Fatal(err)
				}
			}
			beforeAttempts, err := f.store.CountLiveAttempts(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			w := f.request("POST", "/auth/oidc/link/start", "{}", cookies...)
			if name == "stale" {
				b2bStatus(t, w, http.StatusPreconditionRequired)
				if f.session(w) != nil {
					t.Fatal("stale start issued session")
				}
				f.audit("user.sso_link_failed", "step_up_stale")
				after, err := f.store.CountLiveAttempts(f.ctx, f.tenant)
				if err != nil || after != beforeAttempts {
					t.Fatal("stale start created an attempt")
				}
				return
			}
			b2bStatus(t, w, 200)
			location, ok := b2bJSON(t, w)["url"].(string)
			if !ok {
				t.Fatal("link start did not return url")
			}
			a := f.parseStart(w, location)
			raw := f.mint(a, nil)
			before := f.auditCount("user.sso_link_failed")
			result := f.callback(a, "code=callback-code", a.cookie)
			f.headers(result)
			if f.session(result) != nil {
				t.Fatal("link callback issued a login session")
			}
			if name == "identity-conflict" {
				b2bStatus(t, result, 401, 403, 409)
				if f.auditCount("user.sso_link_failed") != before+1 {
					t.Fatal("missing conflict audit")
				}
				f.audit("user.sso_link_failed", "link_conflict", raw, "callback-code")
				linked, err := f.store.FindLinkedUserID(f.ctx, f.tenant, f.a.Issuer, f.a.Subject)
				if err != nil || linked != other {
					t.Fatalf("conflict changed existing link: %s %v", linked, err)
				}
				var unlinked bool
				if err := f.su.QueryRow(f.ctx, `SELECT oidc_issuer IS NULL AND oidc_subject IS NULL FROM app_user WHERE id=$1`, f.user).Scan(&unlinked); err != nil {
					t.Fatal(err)
				}
				if !unlinked {
					t.Fatal("conflict linked the initiating user")
				}
				return
			}
			b2bStatus(t, result, 302)
			if result.Header().Get("Location") != "/console/account?sso=linked" {
				t.Fatal(result.Header())
			}
			linked, err := f.store.FindLinkedUserID(f.ctx, f.tenant, f.a.Issuer, f.a.Subject)
			if err != nil || linked != f.user {
				t.Fatalf("link result: %s %v", linked, err)
			}
			f.audit("user.sso_link", "", raw, "callback-code", *f.write.ClientSecret)
		})
	}
}

func TestB2bHTTPLinkRequiresAuthenticationAndCSRF(t *testing.T) {
	f := b2bFixture(t)
	w := f.request("POST", "/auth/oidc/link/start", "{}")
	b2bStatus(t, w, 401, 403)
	cookies := f.password()
	f.enroll()
	f.fresh(cookies, time.Minute)
	// Omit the double-submit cookie/header while retaining authentication.
	var sessionCookies []*http.Cookie
	sessionName := f.server.AuthAPI.sessionCookie("", time.Now()).Name
	for _, c := range cookies {
		if c.Name == sessionName {
			sessionCookies = append(sessionCookies, c)
		}
	}
	before, err := f.store.CountLiveAttempts(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	b2bStatus(t, f.request("POST", "/auth/oidc/link/start", "{}", sessionCookies...), 403)
	after, err := f.store.CountLiveAttempts(f.ctx, f.tenant)
	if err != nil || before != after {
		t.Fatal("CSRF refusal created an attempt")
	}
}

func (f *b2bHTTP) settingsBody(client string) string {
	return `{"entra_tenant_id":"` + f.write.EntraTenantID + `","client_id":"` + client + `","enabled":true,"trust_entra_mfa":false}`
}

func TestB2bHTTPSettings(t *testing.T) {
	t.Run("read omits secret and update fences existing authority", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		f.link()
		// Issue through the HTTP callback so revocation is tested against an actual
		// browser session, not merely an inspected store row.
		a := f.start("/console")
		f.mint(a, nil)
		login := f.callback(a, "code=callback-code", a.cookie)
		b2bStatus(t, login, 302)
		f.authenticated(login)
		oidcCookie := f.session(login)
		f.enroll()
		f.fresh(cookies, time.Minute)
		get := f.request("GET", "/tenant/sso", "", cookies...)
		b2bStatus(t, get, 200)
		f.headers(get)
		data := b2bJSON(t, get)
		if data["has_secret"] != true {
			t.Fatal("settings lost secret-presence flag")
		}
		if _, exists := data["client_secret"]; exists {
			t.Fatal("settings expose client_secret field")
		}
		if _, exists := data["client_secret_enc"]; exists {
			t.Fatal("settings expose ciphertext field")
		}
		assertB2bNoSecret(t, get.Body.String(), *f.write.ClientSecret)
		oldVersion := data["version"].(float64)
		if data["redirect_uri"] != "https://acme.deskrally.test/cp/auth/oidc/callback" {
			t.Fatal(data)
		}
		// Keep the client ID unchanged first: settings still bump the version.
		same := f.request("PUT", "/tenant/sso", f.settingsBody(f.write.ClientID), cookies...)
		b2bStatus(t, same, 200)
		if b2bJSON(t, same)["version"].(float64) != oldVersion+1 {
			t.Fatal("update did not bump version")
		}
		linked, err := f.store.FindLinkedUserID(f.ctx, f.tenant, f.a.Issuer, f.a.Subject)
		if err != nil || linked != f.user {
			t.Fatal("unchanged client ID cleared identity link")
		}
		// Version updates revoke existing OIDC sessions even without ID changes.
		b2bStatus(t, f.request("GET", "/auth/session", "", oidcCookie), 401)
		changed := f.request("PUT", "/tenant/sso", f.settingsBody("33333333-3333-4333-8333-333333333333"), cookies...)
		b2bStatus(t, changed, 200)
		f.headers(changed)
		updated := b2bJSON(t, changed)
		if updated["version"].(float64) != oldVersion+2 {
			t.Fatal("client change did not bump version")
		}
		assertB2bNoSecret(t, changed.Body.String(), *f.write.ClientSecret)
		var links, live int
		if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM app_user WHERE tenant_id=$1 AND (oidc_issuer IS NOT NULL OR oidc_subject IS NOT NULL)`, f.tenant).Scan(&links); err != nil {
			t.Fatal(err)
		}
		if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session WHERE tenant_id=$1 AND login_method='oidc' AND revoked_at IS NULL`, f.tenant).Scan(&live); err != nil {
			t.Fatal(err)
		}
		if links != 0 || live != 0 {
			t.Fatalf("client change left links=%d live OIDC sessions=%d", links, live)
		}
		// The originating password session survives both updates.
		b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 200)
	})
	t.Run("fresh step-up required", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		f.enroll()
		f.fresh(cookies, 6*time.Minute)
		before, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		w := f.request("PUT", "/tenant/sso", f.settingsBody(f.write.ClientID), cookies...)
		b2bStatus(t, w, http.StatusPreconditionRequired)
		after, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil || after.Version != before.Version {
			t.Fatal("stale step-up changed settings")
		}
	})
	t.Run("technician cannot read or write settings", func(t *testing.T) {
		f := b2bFixture(t)
		// Change the role before login so the real authenticator resolves the grant.
		mustExec(t, f.su, `UPDATE membership SET role_id=(SELECT id FROM role WHERE key='technician' AND tenant_id IS NULL) WHERE tenant_id=$1 AND user_id=$2`, f.tenant, f.user)
		cookies := f.password()
		f.enroll()
		f.fresh(cookies, time.Minute)
		before, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 403)
		b2bStatus(t, f.request("PUT", "/tenant/sso", f.settingsBody(f.write.ClientID), cookies...), 403)
		after, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil || after.Version != before.Version {
			t.Fatal("technician changed settings")
		}
	})
}

func assertB2bNoSecret(t *testing.T, body, secret string) {
	t.Helper()
	// Decode as well as scan so escaping cannot conceal the configured secret.
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case string:
			if strings.Contains(v, secret) {
				t.Fatal("settings disclose configured secret")
			}
		case map[string]any:
			for key, child := range v {
				if key == "client_secret" || key == "client_secret_enc" {
					t.Fatal("settings disclose secret field")
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	var value any
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		t.Fatal(err)
	}
	walk(value)
}

func TestB2bHTTPSelfUnlink(t *testing.T) {
	f := b2bFixture(t)
	cookies := f.password()
	f.link()
	var sessions []*http.Cookie
	for i := 0; i < 2; i++ {
		a := f.start("/console")
		f.mint(a, nil)
		w := f.callback(a, "code=callback-code", a.cookie)
		b2bStatus(t, w, 302)
		f.authenticated(w)
		sessions = append(sessions, f.session(w))
	}
	f.enroll()
	f.fresh(cookies, time.Minute)
	w := f.request("POST", "/auth/oidc/unlink", "{}", cookies...)
	b2bStatus(t, w, 204)
	f.headers(w)
	var unlinked bool
	if err := f.su.QueryRow(f.ctx, `SELECT oidc_issuer IS NULL AND oidc_subject IS NULL FROM app_user WHERE id=$1`, f.user).Scan(&unlinked); err != nil {
		t.Fatal(err)
	}
	if !unlinked {
		t.Fatal("self unlink retained identity")
	}
	for _, c := range sessions {
		b2bStatus(t, f.request("GET", "/auth/session", "", c), 401)
	}
	var live int
	if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session WHERE tenant_id=$1 AND user_id=$2 AND login_method='oidc' AND revoked_at IS NULL`, f.tenant, f.user).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatal("unlink retained OIDC sessions")
	}
	b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 200)
	f.audit("user.sso_unlink", "")
}

// A signed-in SSO request that fails must never answer 401: the console treats every 401 as "session
// ended" and signs the user out (production 2026-10-17: a refused settings save logged the owner out and
// hid the reason). Each failure below must keep the session, carry a JSON error, and change nothing.
func TestB2bHTTPSignedInSSOFailuresKeepTheSession(t *testing.T) {
	assertJSONError := func(t *testing.T, w *httptest.ResponseRecorder, status int) {
		t.Helper()
		b2bStatus(t, w, status)
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("failure is not JSON: %q %s", w.Header().Get("Content-Type"), w.Body.String())
		}
		if msg, _ := b2bJSON(t, w)["error"].(string); msg == "" {
			t.Fatal("failure carries no error message")
		}
	}
	t.Run("invalid settings are 400 and keep the session", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		f.enroll()
		f.fresh(cookies, time.Minute)
		before, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{
			"not a guid":   `{"entra_tenant_id":"contoso.onmicrosoft.com","client_id":"` + f.write.ClientID + `","enabled":true}`,
			"blank secret": `{"entra_tenant_id":"` + f.write.EntraTenantID + `","client_id":"` + f.write.ClientID + `","client_secret":"   ","enabled":true}`,
			"bad json":     `{`,
		} {
			w := f.request("PUT", "/tenant/sso", body, cookies...)
			assertJSONError(t, w, http.StatusBadRequest)
			if name == "not a guid" && !strings.Contains(b2bJSON(t, w)["error"].(string), "GUID") {
				t.Fatalf("%s: error does not say what is wrong: %s", name, w.Body.String())
			}
		}
		f.audit("auth.login_failed", "invalid_connection")
		b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 200)
		after, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil || after.Version != before.Version {
			t.Fatal("refused settings changed the connection")
		}
	})
	t.Run("pasted GUIDs are trimmed and lowercased", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		f.enroll()
		f.fresh(cookies, time.Minute)
		client := "33333333-3333-4333-8333-33333333abcd"
		body := `{"entra_tenant_id":" ` + strings.ToUpper(f.write.EntraTenantID) + `\n","client_id":"` + strings.ToUpper(client) + ` ","enabled":true,"trust_entra_mfa":false}`
		w := f.request("PUT", "/tenant/sso", body, cookies...)
		b2bStatus(t, w, 200)
		data := b2bJSON(t, w)
		if data["entra_tenant_id"] != f.write.EntraTenantID || data["client_id"] != client {
			t.Fatalf("not normalised: %v", data)
		}
		stored, err := f.store.GetConnection(f.ctx, f.tenant)
		if err != nil || stored.EntraTenantID != f.write.EntraTenantID || stored.ClientID != client {
			t.Fatalf("stored form not canonical: %+v %v", stored, err)
		}
	})
	// 428, not 403: the console hides the SSO section on 403 but a stale step-up is recoverable.
	t.Run("stale step-up is 428 on every signed-in SSO route", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		f.link()
		f.enroll()
		f.fresh(cookies, 6*time.Minute)
		for _, route := range []struct{ method, path, body string }{
			{"PUT", "/tenant/sso", f.settingsBody(f.write.ClientID)},
			{"POST", "/auth/oidc/link/start", "{}"},
			{"POST", "/auth/oidc/test/start", "{}"},
			{"POST", "/auth/oidc/unlink", "{}"},
		} {
			assertJSONError(t, f.request(route.method, route.path, route.body, cookies...), http.StatusPreconditionRequired)
		}
		b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 200)
	})
	t.Run("test start on a disabled connection is 409", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		f.enroll()
		f.fresh(cookies, time.Minute)
		disabled := `{"entra_tenant_id":"` + f.write.EntraTenantID + `","client_id":"` + f.write.ClientID + `","enabled":false}`
		b2bStatus(t, f.request("PUT", "/tenant/sso", disabled, cookies...), 200)
		f.fresh(cookies, time.Minute)
		assertJSONError(t, f.request("POST", "/auth/oidc/test/start", "{}", cookies...), http.StatusConflict)
		b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 200)
	})
	// Security audit 2026-10-18: admin unlink applies the per-user admin hierarchy. An Admin may unlink
	// a technician (positive control) but not the Owner.
	t.Run("admin unlink respects the admin hierarchy", func(t *testing.T) {
		f := b2bFixture(t)
		other := func(role string) string {
			var id string
			if err := f.su.QueryRow(f.ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			mustExec(t, f.su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`, id, f.tenant, role+"-"+id[:8]+"@acme.test")
			mustExec(t, f.su, `INSERT INTO membership (tenant_id, user_id, role_id) VALUES ($1,$2,(SELECT id FROM role WHERE key=$3 AND tenant_id IS NULL))`, f.tenant, id, role)
			mustExec(t, f.su, `UPDATE app_user SET oidc_issuer=$2,oidc_subject=$3 WHERE id=$1`, id, f.a.Issuer, "subject-"+id)
			return id
		}
		owner, technician := other("owner"), other("technician")
		mustExec(t, f.su, `UPDATE membership SET role_id=(SELECT id FROM role WHERE key='admin' AND tenant_id IS NULL) WHERE user_id=$1`, f.user)
		cookies := f.password()
		assertJSONError(t, f.request("POST", "/users/"+owner+"/sso-unlink", "{}", cookies...), http.StatusForbidden)
		b2bStatus(t, f.request("POST", "/users/"+technician+"/sso-unlink", "{}", cookies...), 204)
		var linked bool
		if err := f.su.QueryRow(f.ctx, `SELECT oidc_subject IS NOT NULL FROM app_user WHERE id=$1`, owner).Scan(&linked); err != nil {
			t.Fatal(err)
		}
		if !linked {
			t.Fatal("refused unlink still removed the owner's Microsoft identity")
		}
	})
	t.Run("admin unlink of an unknown user is 404", func(t *testing.T) {
		f := b2bFixture(t)
		cookies := f.password()
		assertJSONError(t, f.request("POST", "/users/00000000-0000-4000-8000-000000000000/sso-unlink", "{}", cookies...), http.StatusNotFound)
		assertJSONError(t, f.request("POST", "/users/not-a-uuid/sso-unlink", "{}", cookies...), http.StatusBadRequest)
		b2bStatus(t, f.request("GET", "/tenant/sso", "", cookies...), 200)
	})
}

// The DeskRally code page says WHY it is still needed, and the audit records what Entra reported, so
// an owner can tell "trust is off" from "Entra sent no MFA evidence" (production 2026-10-17: a guest
// MSA's token carried no amr and nothing showed it).
func TestB2bHTTPSSOTOTPReasonIsShownAndAudited(t *testing.T) {
	for _, c := range []struct {
		name  string
		trust bool
		amr   []string
		why   string
	}{
		{"trust off", false, []string{"pwd", "mfa"}, "trust_off"},
		{"no amr", true, nil, "no_amr"},
		{"amr without mfa", true, []string{"pwd"}, "no_mfa"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := b2bFixture(t)
			f.link()
			f.enroll()
			mustExec(t, f.su, `UPDATE tenant_oidc SET trust_entra_mfa=$2 WHERE tenant_id=$1`, f.tenant, c.trust)
			a := f.start("/console")
			f.mint(a, func(m map[string]any) {
				delete(m, "amr")
				if c.amr != nil {
					m["amr"] = c.amr
				}
			})
			w := f.callback(a, "code=callback-code", a.cookie)
			b2bStatus(t, w, 302)
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil || u.Path != "/console/sso-totp" || u.Query().Get("why") != c.why {
				t.Fatalf("redirect %v, want why=%s", u, c.why)
			}
			f.audit("auth.sso_totp_required", c.why)
		})
	}
}

func TestB2bHTTPStepUpStatusAndMe(t *testing.T) {
	f := b2bFixture(t)
	cookies := f.password()
	f.enroll()
	status := func() bool {
		t.Helper()
		w := f.request("GET", "/auth/oidc/step-up-status", "", cookies...)
		b2bStatus(t, w, 200)
		fresh, ok := b2bJSON(t, w)["fresh"].(bool)
		if !ok {
			t.Fatal("no fresh flag")
		}
		return fresh
	}
	f.fresh(cookies, 6*time.Minute)
	if status() {
		t.Fatal("a 6-minute-old step-up reported fresh")
	}
	f.fresh(cookies, time.Minute)
	if !status() {
		t.Fatal("a 1-minute-old step-up reported stale")
	}
	w := f.request("GET", "/me", "", cookies...)
	b2bStatus(t, w, 200)
	var email string
	if err := f.su.QueryRow(f.ctx, `SELECT email FROM app_user WHERE id=$1`, f.user).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if got := b2bJSON(t, w)["email"]; got != email {
		t.Fatalf("/me email %v, want %s", got, email)
	}
	b2bStatus(t, f.request("GET", "/me", ""), 401)
}
