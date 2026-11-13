package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrOIDCCap = errors.New("OIDC attempt capacity reached")
var oidcSlug = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

const oidcAttemptCookie = "__Host-cp_oidc"

type oidcCachedClient struct {
	version int64
	client  *EntraClient
}

func (s *Server) mountOIDCPublic(m *http.ServeMux) {
	m.Handle("GET /auth/sso-info", s.oidcPublic(http.HandlerFunc(s.handleSSOInfo)))
	m.Handle("GET /auth/oidc/start", s.oidcPublic(http.HandlerFunc(s.handleOIDCLoginStart)))
	m.Handle("GET /auth/oidc/callback", s.oidcPublic(http.HandlerFunc(s.handleOIDCCallback)))
	m.Handle("POST /auth/oidc/totp", s.oidcPublic(s.originMiddleware(http.HandlerFunc(s.handleOIDCTOTP))))
}

func (s *Server) mountOIDCProtected(m *http.ServeMux) {
	m.Handle("GET /tenant/sso", oidcHeaders(http.HandlerFunc(s.handleGetSSO)))
	m.Handle("PUT /tenant/sso", oidcHeaders(http.HandlerFunc(s.handlePutSSO)))
	m.Handle("POST /auth/oidc/link/start", oidcHeaders(s.oidcOrigin(http.HandlerFunc(s.handleOIDCLinkStart))))
	m.Handle("POST /auth/oidc/test/start", oidcHeaders(s.oidcOrigin(http.HandlerFunc(s.handleOIDCTestStart))))
	m.Handle("POST /auth/oidc/unlink", oidcHeaders(http.HandlerFunc(s.handleOIDCUnlink)))
	m.Handle("POST /users/{id}/sso-unlink", oidcHeaders(http.HandlerFunc(s.handleOIDCAdminUnlink)))
	m.Handle("GET /auth/oidc/step-up-status", oidcHeaders(http.HandlerFunc(s.handleOIDCStepUpStatus)))
}

// handleOIDCStepUpStatus tells the console whether this session's step-up is still fresh enough for
// the SSO actions (the same check they make), so it can skip asking for a code the user just gave.
// Read-only and unaudited: it grants nothing, and every action still re-checks freshness itself.
func (s *Server) handleOIDCStepUpStatus(w http.ResponseWriter, r *http.Request) {
	_, p, ok := s.oidcProtectedTenant(w, r, "", false)
	if !ok {
		return
	}
	_, err := s.oidcFreshUser(r, p)
	writeJSON(w, http.StatusOK, map[string]bool{"fresh": err == nil})
}

func oidcHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Origins are also checked for protected starts: these endpoints create browser-bound authority.
func (s *Server) oidcOrigin(next http.Handler) http.Handler { return s.originMiddleware(next) }

func (s *Server) oidcPublic(next http.Handler) http.Handler {
	return oidcHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.AuthAPI == nil || s.AuthAPI.Tenants == nil || s.AuthAPI.Users == nil || s.AuthAPI.Sessions == nil {
			s.oidcFailure(w, r, "", "login", "", "unavailable")
			return
		}
		if retry, ok := s.throttle().Allow(ipKey("oidc", clientIP(r))); !ok {
			// A throttled request is cheap, anonymous and unbounded in number, so it must cost the
			// server nothing durable: no tenant lookup and NO audit row (each row takes the tenant's
			// chain advisory lock, so a flood of throttled requests could stall every audited
			// mutation of the victim tenant). The failures that tripped the throttle were already
			// audited one by one (bounded by the throttle's own failure budget). This matches
			// HandleLogin's throttled branch, which does not audit either.
			writeThrottled(w, retry)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// The public host is an authority boundary. Never use a query parameter to select a tenant.
func (s *Server) tenantFromHost(r *http.Request) (slug, tenantID string, err error) {
	suffix := s.TenantHostSuffix
	if suffix != strings.ToLower(suffix) || !strings.HasPrefix(suffix, ".") || strings.ContainsAny(suffix, "/\\:@?# \t\r\n") || suffix == "." {
		return "", "", ErrOIDCInvalid
	}
	host := strings.ToLower(r.Host)
	if strings.Contains(host, ":") {
		var port string
		host, port, err = net.SplitHostPort(host)
		if err != nil || port != "443" {
			return "", "", ErrOIDCInvalid
		}
	}
	if !strings.HasSuffix(host, suffix) {
		return "", "", ErrOIDCInvalid
	}
	slug = strings.TrimSuffix(host, suffix)
	if !oidcSlug.MatchString(slug) || s.AuthAPI == nil || s.AuthAPI.Tenants == nil {
		return "", "", ErrOIDCInvalid
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", "", ErrOIDCInvalid
	}
	if tenants, present := q["tenant"]; present && (len(tenants) != 1 || tenants[0] != slug) {
		return "", "", ErrOIDCInvalid
	}
	tenantID, err = s.AuthAPI.Tenants.ResolveTenant(r.Context(), slug)
	return slug, tenantID, err
}

func (s *Server) redirectURI(slug string) string {
	// ServeMux sees /auth; /cp belongs to the public reverse-proxy URL.
	return "https://" + slug + s.TenantHostSuffix + "/cp/auth/oidc/callback"
}

func oidcReturnPath(path string) (string, error) {
	if path == "" {
		return "/console", nil
	}
	u, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n\x00") || u.IsAbs() || u.Host != "" {
		return "", ErrOIDCInvalid
	}
	// Browsers normalize escaped slashes and backslashes differently; refuse ambiguous destinations.
	decoded, err := url.PathUnescape(u.EscapedPath())
	if err != nil || strings.HasPrefix(decoded, "//") || strings.ContainsAny(decoded, "\\\r\n\x00") {
		return "", ErrOIDCInvalid
	}
	return path, nil
}

func oidcHash(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func oidcKeys(r *http.Request) []string {
	var keys []string
	// Multiple cookies with the same name are ambiguous; fail closed.
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == oidcAttemptCookie {
			count++
			value = c.Value
		}
	}
	if count != 1 || len(value) > 132 {
		return nil
	}
	for _, key := range strings.Split(value, ".") {
		b, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(b) != 32 {
			return nil
		}
		for _, existing := range keys {
			if key == existing {
				return nil
			}
		}
		keys = append(keys, key)
	}
	if len(keys) > 3 {
		return nil
	}
	return keys
}

func setOIDCKeys(w http.ResponseWriter, keys []string) {
	age := 600
	if len(keys) == 0 {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: oidcAttemptCookie, Value: strings.Join(keys, "."), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}

func (s *Server) oidcAuditFailure(r *http.Request, tenant, mode, user, reason string) {
	if s.AuthAPI == nil {
		return
	}
	action := "auth.login_failed"
	actor := ""
	if mode == "link" {
		action = "user.sso_link_failed"
		actor = user
	}
	_ = s.AuthAPI.recordAuthEvent(r.Context(), tenant, actor, action, map[string]any{"method": "oidc", "reason": reason, "ip": clientIP(r)})
}

func (s *Server) oidcFailure(w http.ResponseWriter, r *http.Request, tenant, mode, user, reason string) {
	s.oidcAuditFailure(r, tenant, mode, user, reason)
	s.throttle().Fail(ipKey("oidc", clientIP(r)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	message := "Microsoft sign-in could not be completed. Please start again."
	if reason == "not_linked" {
		message = "This Microsoft account is not linked to a DeskRally user. Sign in with your password and link it under My Account."
	} else if reason == "totp_not_enrolled" {
		message = "Sign in with your password and enroll an authenticator first."
	}
	// All page text is fixed; neither callback parameters nor provider errors are reflected.
	_, _ = io.WriteString(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in unsuccessful</title></head><body><p>"+message+"</p><a href=\"/console\">Return to sign-in</a></body></html>")
}

// oidcAPIFailure answers a failed SIGNED-IN SSO request: settings, link/test start and unlink. These are
// console fetches, where every 401 means "your session ended" and signs the user out, so they must never
// use oidcFailure's 401 sign-in page. The status and message say what failed; the audit is unchanged.
func (s *Server) oidcAPIFailure(w http.ResponseWriter, r *http.Request, tenant, mode, user, reason string) {
	s.oidcAuditFailure(r, tenant, mode, user, reason)
	status, message := oidcAPIStatus(reason)
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, status, message)
}

const oidcStepUpMessage = "Your verification expired; enter a fresh authenticator code and try again"

func oidcAPIStatus(reason string) (int, string) {
	switch reason {
	case "invalid_json":
		return http.StatusBadRequest, "invalid request body"
	case "invalid_connection":
		return http.StatusBadRequest, "Directory (tenant) ID and Application (client) ID must each be a GUID like 00000000-0000-0000-0000-000000000000, and the client secret cannot be blank"
	case "invalid_user_id":
		return http.StatusBadRequest, "invalid user id"
	case "user_not_found":
		return http.StatusNotFound, "user not found"
	case "step_up_stale", "origin_session_invalid", "epoch_changed":
		// 428, not 403: the console hides the SSO section on 403 (permission denied), but a stale step-up
		// is recoverable with a fresh code.
		return http.StatusPreconditionRequired, oidcStepUpMessage
	case "permission_denied", "host_mismatch", "user_ineligible", "user_disabled", "tenant_disabled", "totp_not_enrolled":
		return http.StatusForbidden, "not permitted"
	case "version_changed", "link_conflict":
		return http.StatusConflict, "Microsoft sign-in settings changed; reload and try again"
	case "disabled":
		return http.StatusConflict, "Microsoft sign-in is not configured and enabled for this tenant; save the settings with Enabled checked first"
	}
	return http.StatusServiceUnavailable, "Microsoft sign-in is temporarily unavailable; try again"
}

func oidcReason(err error) string {
	var invalid *EntraValidationError
	if errors.As(err, &invalid) {
		return "token_" + invalid.Rule
	}
	switch {
	case errors.Is(err, ErrOIDCDisabled):
		return "disabled"
	case errors.Is(err, ErrOIDCVersion):
		return "version_changed"
	case errors.Is(err, ErrOIDCNotLinked):
		return "not_linked"
	case errors.Is(err, ErrOIDCUserDisabled):
		return "user_disabled"
	case errors.Is(err, ErrOIDCEpoch):
		return "epoch_changed"
	case errors.Is(err, ErrOIDCLinkConflict):
		return "link_conflict"
	case errors.Is(err, ErrOIDCSessionInvalid):
		return "origin_session_invalid"
	case errors.Is(err, ErrOIDCStepUpStale):
		return "step_up_stale"
	case errors.Is(err, ErrOIDCAttemptUsed):
		return "attempt_used"
	case errors.Is(err, ErrOIDCAttemptExpired):
		return "attempt_expired"
	case errors.Is(err, ErrOIDCAttemptNotFound):
		return "attempt_not_found"
	case errors.Is(err, ErrOIDCTenantDisabled):
		return "tenant_disabled"
	case errors.Is(err, ErrOIDCCap):
		return "attempt_capacity"
	case errors.Is(err, ErrOIDCInvalid):
		return "invalid_request"
	default:
		return "storage_or_provider_failure"
	}
}

func (s *Server) oidcClient(ctx context.Context, tenant string, version int64) (*OIDCConnection, *EntraClient, error) {
	connection, err := s.OIDC.GetConnection(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	if !connection.Enabled {
		return nil, nil, ErrOIDCDisabled
	}
	if version != 0 && connection.Version != version {
		return nil, nil, ErrOIDCVersion
	}
	s.oidcClientsMu.Lock()
	defer s.oidcClientsMu.Unlock()
	if cached, ok := s.oidcClients[tenant]; ok && cached.version == connection.Version {
		return connection, cached.client, nil
	}
	cfg, err := s.OIDC.entraConfig(ctx, tenant, connection.Version)
	if err != nil {
		return nil, nil, err
	}
	factory := s.newEntraClient
	if factory == nil {
		factory = NewEntraClient
	}
	client, err := factory(cfg)
	if err != nil {
		return nil, nil, err
	}
	if s.oidcClients == nil {
		s.oidcClients = make(map[string]oidcCachedClient)
	}
	s.oidcClients[tenant] = oidcCachedClient{connection.Version, client}
	return connection, client, nil
}

func (s *PgOIDCStore) entraConfig(ctx context.Context, tenant string, version int64) (EntraConfig, error) {
	var cfg EntraConfig
	var sealed []byte
	err := withTenant(ctx, s.Pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT entra_tenant_id::text,client_id::text,client_secret_enc FROM tenant_oidc WHERE tenant_id=$1 AND enabled AND version=$2`, tenant, version).Scan(&cfg.TenantID, &cfg.ClientID, &sealed)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return cfg, ErrOIDCVersion
	}
	if err != nil {
		return cfg, err
	}
	if s.Cipher == nil {
		return cfg, ErrOIDCInvalid
	}
	var encrypted bool
	cfg.ClientSecret, encrypted, err = s.Cipher.Open(sealed)
	if err != nil {
		return EntraConfig{}, err
	}
	if !encrypted {
		return EntraConfig{}, ErrOIDCInvalid
	}
	return cfg, nil
}

func (s *PgOIDCStore) FindLinkedUserID(ctx context.Context, tenant, issuer, subject string) (string, error) {
	var id string
	err := withTenant(ctx, s.Pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM app_user WHERE tenant_id=$1 AND oidc_issuer=$2 AND oidc_subject=$3`, tenant, issuer, subject).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrOIDCNotLinked
	}
	return id, err
}

func (s *Server) handleSSOInfo(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Resolve the tenant from the HOST alone (tenantFromHost would also refuse a disagreeing parameter,
	// folding two different errors into one), then compare the parameter explicitly below.
	bare := r.Clone(r.Context())
	bareQuery := bare.URL.Query()
	bareQuery.Del("tenant")
	bare.URL.RawQuery = bareQuery.Encode()
	slug, tenant, err := s.tenantFromHost(bare)
	// A JSON probe the login page makes on every load: answer in JSON, without the HTML failure page or
	// an audit row. An unbound host is unknown (404); a tenant parameter that disagrees with the host is
	// a malformed request (400) — the host, never the parameter, picks the tenant.
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown tenant")
		return
	}
	if len(q["tenant"]) != 1 || q.Get("tenant") != slug {
		writeError(w, http.StatusBadRequest, "tenant does not match this host")
		return
	}
	providers := []map[string]string{}
	connection, err := s.OIDC.GetConnection(r.Context(), tenant)
	if err != nil && !errors.Is(err, ErrOIDCDisabled) {
		s.oidcFailure(w, r, tenant, "login", "", "connection_read")
		return
	}
	if err == nil && connection.Enabled {
		providers = append(providers, map[string]string{"id": "entra", "label": "Microsoft"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

// Charge every start, not just failed starts. The shared Bump is atomic across replicas.
// Bucket keys bound the allowance to twenty requests in each ten-minute window.
func (s *Server) oidcStartBudget(tenant string, r *http.Request) bool {
	th := s.throttle()
	if th == nil {
		return true
	}
	now := time.Now()
	key := accountKey("oidc-start", tenant, clientIP(r)) + ":" + strconv.FormatInt(now.Unix()/600, 10)
	if th.store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), storeThrottleOpTimeout)
		defer cancel()
		n, err := th.store.Bump(ctx, key, now, now.Add(-10*time.Minute))
		return err == nil && n <= 20
	}
	th.mu.Lock()
	defer th.mu.Unlock()
	if th.entries == nil {
		th.entries = make(map[string]*throttleEntry)
	}
	for k, entry := range th.entries {
		if strings.HasPrefix(k, "acct:oidc-start:") && entry.lastFailure.Before(now.Add(-20*time.Minute)) {
			delete(th.entries, k)
		}
	}
	entry := th.entries[key]
	if entry == nil {
		entry = &throttleEntry{}
		th.entries[key] = entry
	}
	entry.failures++
	entry.lastFailure = now
	return entry.failures <= 20
}

func (s *Server) handleOIDCLoginStart(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["mode"]) > 1 || (q.Get("mode") != "" && q.Get("mode") != "login") || len(q["return"]) > 1 ||
		len(q["remember"]) > 1 || (q.Get("remember") != "" && q.Get("remember") != "1") {
		_, tenant, _ := s.tenantFromHost(r)
		s.oidcFailure(w, r, tenant, "login", "", "invalid_start")
		return
	}
	s.oidcStart(w, r, "login", q.Get("return"), q.Get("remember") == "1" && oidcRememberAllowed(r.UserAgent()))
}

// oidcRememberAllowed: a Microsoft sign-in is remembered only in the desktop app after its startup Windows Hello
// check, which is what the "Remember this app" box on the sign-in form already requires (LoginForm.tsx shows it
// only for this marker; clients/windows/client.cpp adds it only after Hello verified). Unlike the password form's
// POST, the start is a plain GET link, so the server checks the marker too: a crafted
// /auth/oidc/start?remember=1 opened in an ordinary browser (a shared or kiosk machine) gets an ordinary session.
// The marker is a user agent, so this is a guard against accidents and lures, not an authentication factor; the
// session is still bound to this browser's cookie and still needs the Microsoft sign-in (and MFA policy) to issue.
func oidcRememberAllowed(userAgent string) bool {
	for _, token := range strings.Fields(userAgent) {
		if token == "DeskRallyHello/1" {
			return true
		}
	}
	return false
}

func (s *Server) handleOIDCLinkStart(w http.ResponseWriter, r *http.Request) {
	s.oidcStart(w, r, "link", "/console/account?sso=linked", false)
}
func (s *Server) handleOIDCTestStart(w http.ResponseWriter, r *http.Request) {
	s.oidcStart(w, r, "test", "/console/security?sso=test-ok", false)
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request, mode, returnPath string, remember bool) {
	slug, tenant, err := s.tenantFromHost(r)
	userID := ""
	fail := func(reason string) {
		if mode == "login" {
			s.oidcFailure(w, r, tenant, mode, userID, reason)
			return
		}
		// Link and test start are console fetches: never the 401 sign-in page.
		s.oidcAPIFailure(w, r, tenant, mode, userID, reason)
	}
	if err != nil {
		fail("host_mismatch")
		return
	}
	// An unsafe or malformed return path falls back to the console (design: default /console) rather
	// than failing sign-in; oidcReturnPath has already refused everything that could leave the origin.
	path, err := oidcReturnPath(returnPath)
	if err != nil {
		path = "/console"
	}
	var user *AuthUser
	var principal *Principal
	if mode != "login" {
		principal = principalFrom(r.Context())
		if principal == nil || principal.TenantID != tenant || principal.SessionID == "" {
			fail("origin_session_invalid")
			return
		}
		userID = principal.UserID
		if mode == "test" {
			if err := principal.Grant.Require(CapManageTenant); err != nil {
				fail("permission_denied")
				return
			}
		}
		user, err = s.oidcFreshUser(r, principal)
		if err != nil {
			fail(oidcReason(err))
			return
		}
	}
	if !s.oidcStartBudget(tenant, r) {
		s.oidcAuditFailure(r, tenant, mode, userID, "start_budget")
		writeThrottled(w, 10*time.Minute)
		return
	}
	// No live-attempt cap check here: the store makes room by retiring the oldest attempts under its
	// admission lock (CreateAttempt), so a full table never refuses a sign-in.
	connection, client, err := s.oidcClient(r.Context(), tenant, 0)
	if err != nil {
		fail(oidcReason(err))
		return
	}
	state, err := NewOIDCState()
	if err != nil {
		fail("random_generation")
		return
	}
	key, err := NewOIDCState()
	if err != nil {
		fail("random_generation")
		return
	}
	nonce, err := NewOIDCNonce()
	if err != nil {
		fail("random_generation")
		return
	}
	verifier, challenge, err := NewPKCE()
	if err != nil {
		fail("random_generation")
		return
	}
	a := &OIDCAttempt{TenantID: tenant, KeyHash: oidcHash(key), StateHash: oidcHash(state), Nonce: nonce, CodeVerifier: verifier, Mode: mode, ConnectionVersion: connection.Version, Profile: "entra", RedirectURI: s.redirectURI(slug), ReturnPath: path, Remember: remember && mode == "login"}
	if principal != nil {
		a.UserID, a.SessionID, a.EpochBaseline = &principal.UserID, &principal.SessionID, user.CredentialUpdatedAt
	}
	if err := s.OIDC.CreateAttempt(r.Context(), a); err != nil {
		fail(oidcReason(err))
		return
	}
	keys := append(oidcKeys(r), key)
	if len(keys) > 3 {
		keys = keys[len(keys)-3:]
	}
	setOIDCKeys(w, keys)
	authorize := client.AuthURL(a.RedirectURI, state, nonce, challenge)
	if mode == "login" {
		http.Redirect(w, r, authorize, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": authorize})
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	slug, tenant, err := s.tenantFromHost(r)
	mode, userID := "login", ""
	fail := func(reason string) { s.oidcFailure(w, r, tenant, mode, userID, reason) }
	if err != nil {
		fail("host_mismatch")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["state"]) != 1 || q.Get("state") == "" || len(q["code"]) > 1 || len(q["error"]) > 1 {
		fail("invalid_callback")
		return
	}
	keys := oidcKeys(r)
	var attempt *OIDCAttempt
	for i, key := range keys {
		attempt, err = s.OIDC.ConsumeAttempt(r.Context(), tenant, oidcHash(q.Get("state")), oidcHash(key))
		if errors.Is(err, ErrOIDCAttemptNotFound) {
			continue
		}
		// Expired and replayed matching attempts retire their browser key too.
		remaining := append(append([]string{}, keys[:i]...), keys[i+1:]...)
		setOIDCKeys(w, remaining)
		if err != nil {
			fail(oidcReason(err))
			return
		}
		break
	}
	if attempt == nil {
		fail("attempt_not_found")
		return
	}
	mode = attempt.Mode
	if attempt.UserID != nil {
		userID = *attempt.UserID
	}
	if attempt.Profile != "entra" || attempt.RedirectURI != s.redirectURI(slug) {
		fail("attempt_binding")
		return
	}
	if _, present := q["error"]; present {
		fail("idp_error")
		return
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		fail("missing_code")
		return
	}
	connection, client, err := s.oidcClient(r.Context(), tenant, attempt.ConnectionVersion)
	if err != nil {
		fail(oidcReason(err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	raw, err := client.Exchange(ctx, q.Get("code"), attempt.CodeVerifier, attempt.RedirectURI)
	if err != nil {
		fail("exchange_failed")
		return
	}
	identity, err := client.Verify(ctx, raw, attempt.Nonce, s.AuthAPI.now())
	if err != nil {
		fail(oidcReason(err))
		return
	}
	authority := OIDCIdentityAuthority{TenantID: tenant, Issuer: identity.Issuer, Subject: identity.Subject, ConnectionVersion: attempt.ConnectionVersion, EpochBaseline: attempt.EpochBaseline}
	switch mode {
	case "link", "test":
		if attempt.UserID == nil || attempt.SessionID == nil {
			fail("origin_session_invalid")
			return
		}
		authority.UserID = *attempt.UserID
		if mode == "link" {
			err = s.OIDC.LinkIdentity(r.Context(), authority, *attempt.SessionID)
		} else {
			err = s.OIDC.RecordTest(r.Context(), authority, *attempt.SessionID)
		}
		if err != nil {
			fail(oidcReason(err))
			return
		}
		if mode == "link" {
			if err := s.AuthAPI.recordAuthEvent(r.Context(), tenant, userID, "user.sso_link", map[string]any{"method": "oidc", "issuer": identity.Issuer, "subject": identity.Subject, "oid": identity.OID, "tid": identity.TenantID, "preferred_username": identity.PreferredUsername}); err != nil {
				fail("audit_failed")
				return
			}
			http.Redirect(w, r, "/console/account?sso=linked", http.StatusFound)
		} else {
			linked, lookupErr := s.OIDC.FindLinkedUserID(r.Context(), tenant, identity.Issuer, identity.Subject)
			if lookupErr != nil && !errors.Is(lookupErr, ErrOIDCNotLinked) {
				fail("identity_lookup")
				return
			}
			http.Redirect(w, r, "/console/security?sso=test-ok&amr_present="+strconv.FormatBool(len(identity.AMR) > 0)+"&linked="+strconv.FormatBool(linked == userID), http.StatusFound)
		}
	case "login":
		id, err := s.OIDC.FindLinkedUserID(r.Context(), tenant, identity.Issuer, identity.Subject)
		if err != nil {
			fail(oidcReason(err))
			return
		}
		user, err := s.AuthAPI.Users.FindUserByID(r.Context(), tenant, id)
		if err != nil || user == nil || user.TenantID != tenant || user.Disabled || user.TenantSuspended {
			fail("user_ineligible")
			return
		}
		authority.UserID, authority.EpochBaseline = user.ID, user.CredentialUpdatedAt
		authority.Remember = attempt.Remember // from the consumed attempt only (migrations/0080)
		amrMFA := false
		for _, amr := range identity.AMR {
			if amr == "mfa" {
				amrMFA = true
			}
		}
		trustedMFA := amrMFA && connection.TrustEntraMFA
		if mfaRequired(user) && !trustedMFA {
			if !user.TOTPConfirmed || user.TOTPSecret == "" {
				fail("totp_not_enrolled")
				return
			}
			pending := &OIDCPendingMFA{TenantID: tenant, UserID: user.ID, AttemptID: attempt.ID, Issuer: identity.Issuer, Subject: identity.Subject, EpochBaseline: authority.EpochBaseline, ConnectionVersion: authority.ConnectionVersion}
			if err := s.OIDC.CreatePendingMFA(r.Context(), pending); err != nil {
				fail(oidcReason(err))
				return
			}
			// Say WHY the DeskRally code is still needed (a fixed enum, never token content), both to the
			// user and in the audit: an owner otherwise cannot tell "trust is off" from "Entra did not
			// report MFA" (production 2026-10-17, a Duo-protected tenant).
			why := oidcTOTPReason(connection.TrustEntraMFA, len(identity.AMR) > 0, amrMFA)
			_ = s.AuthAPI.recordAuthEvent(r.Context(), tenant, user.ID, "auth.sso_totp_required", map[string]any{"method": "oidc", "reason": why, "amr_present": len(identity.AMR) > 0, "amr_mfa": amrMFA, "trust_entra_mfa": connection.TrustEntraMFA, "ip": clientIP(r)})
			http.Redirect(w, r, "/console/sso-totp?p="+url.QueryEscape(pending.ID)+"&why="+why, http.StatusFound)
			return
		}
		if err := s.oidcIssue(w, r, authority, user, trustedMFA, attempt.ReturnPath, false); err != nil {
			fail(oidcReason(err))
			return
		}
	default:
		fail("invalid_mode")
	}
}

func mfaRequired(user *AuthUser) bool { return user.Require2FA || user.TOTPConfirmed }

// oidcTOTPReason names why a Microsoft sign-in still needs the DeskRally code: the owner has not
// trusted Entra MFA, Entra sent no amr claim, or the amr claim did not include "mfa".
func oidcTOTPReason(trust, amrPresent, amrMFA bool) string {
	switch {
	case !trust:
		return "trust_off"
	case !amrPresent:
		return "no_amr"
	case !amrMFA:
		return "no_mfa"
	}
	return "required"
}

// IssueOIDCSession owns the final B checks. HTTP never substitutes Sessions.Issue for it.
func (s *Server) oidcIssue(w http.ResponseWriter, r *http.Request, authority OIDCIdentityAuthority, user *AuthUser, mfa bool, path string, jsonResponse bool) error {
	path, err := oidcReturnPath(path)
	if err != nil {
		return err
	}
	token, session, err := s.OIDC.IssueOIDCSession(r.Context(), authority)
	if err != nil {
		return err
	}
	s.AuthAPI.Guard.NoteValid(token)
	if mfa {
		ok, err := s.AuthAPI.Sessions.Store.MarkMFAVerified(r.Context(), authority.TenantID, authority.UserID, session.ID, user.MFAGeneration)
		if err != nil || !ok {
			// Do not leave an issued, usable session behind when the required MFA stamp fails.
			ctx, cancel := compensationContext(r)
			_ = s.AuthAPI.Sessions.Revoke(ctx, token)
			cancel()
			return ErrOIDCSessionInvalid
		}
	}
	_ = s.AuthAPI.recordAuthEvent(r.Context(), authority.TenantID, authority.UserID, "auth.login", map[string]any{"method": "oidc", "issuer": authority.Issuer, "subject": authority.Subject, "first": false, "mfa": mfa, "remembered": authority.Remember, "ip": clientIP(r), "expires_at": session.ExpiresAt.UTC().Format(time.RFC3339)})
	csrf := csrfTokenFor(token)
	http.SetCookie(w, s.AuthAPI.sessionCookie(token, session.ExpiresAt))
	http.SetCookie(w, s.AuthAPI.csrfCookie(csrf, session.ExpiresAt))
	if jsonResponse {
		writeJSON(w, http.StatusOK, map[string]any{"user_id": authority.UserID, "tenant_id": authority.TenantID, "expires_at": session.ExpiresAt.UTC().Format(time.RFC3339), "csrf_token": csrf, "return_path": path})
	} else {
		http.Redirect(w, r, path, http.StatusFound)
	}
	return nil
}

func (s *Server) handleOIDCTOTP(w http.ResponseWriter, r *http.Request) {
	_, tenant, err := s.tenantFromHost(r)
	fail := func(reason string) { s.oidcFailure(w, r, tenant, "login", "", reason) }
	if err != nil {
		fail("host_mismatch")
		return
	}
	var req struct {
		PendingID string `json:"pending_id"`
		Code      string `json:"totp_code"`
	}
	if err := oidcDecode(r, &req); err != nil {
		fail("invalid_json")
		return
	}
	if !isUUID(req.PendingID) {
		fail("invalid_pending_id")
		return
	}
	pending, err := s.OIDC.ConsumePendingMFA(r.Context(), tenant, req.PendingID)
	if err != nil {
		fail(oidcReason(err))
		return
	}
	user, err := s.AuthAPI.Users.FindUserByID(r.Context(), tenant, pending.UserID)
	if err != nil || user == nil || user.TenantID != tenant || user.Disabled || user.TenantSuspended || !user.TOTPConfirmed || user.TOTPSecret == "" {
		fail("user_ineligible")
		return
	}
	key := accountKey("login-totp", tenant, user.ID)
	th := s.AuthAPI.throttle()
	if retry, allowed := th.Allow(key); !allowed {
		s.oidcAuditFailure(r, tenant, "login", "", "totp_throttled")
		writeThrottled(w, retry)
		return
	}
	step, valid, err := VerifyTOTPStep(user.TOTPSecret, req.Code, s.AuthAPI.now(), s.AuthAPI.totpCfg())
	if err != nil || !valid {
		th.Fail(key)
		fail("totp_invalid")
		return
	}
	fresh, err := s.AuthAPI.Users.ConsumeTOTPStep(r.Context(), tenant, user.ID, step)
	if err != nil || !fresh {
		th.Fail(key)
		fail("totp_invalid")
		return
	}
	th.Reset(key)
	var path string
	var remember bool
	err = withTenant(r.Context(), s.OIDC.Pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT return_path,remember FROM oidc_login_attempt WHERE tenant_id=$1 AND id=$2 AND mode='login' AND used_at IS NOT NULL`, tenant, pending.AttemptID).Scan(&path, &remember)
	})
	if err != nil {
		fail("attempt_not_found")
		return
	}
	authority := OIDCIdentityAuthority{TenantID: tenant, UserID: pending.UserID, Issuer: pending.Issuer, Subject: pending.Subject, ConnectionVersion: pending.ConnectionVersion, EpochBaseline: pending.EpochBaseline, Remember: remember}
	if err := s.oidcIssue(w, r, authority, user, true, path, true); err != nil {
		fail(oidcReason(err))
	}
}

// Strict top-level objects reject duplicate and unknown fields, trailing input, and text
// encoding/json would silently replace. No decoder errors containing input reach the response.
func oidcDecode(r *http.Request, dst any) error {
	if r.Body == nil {
		return ErrOIDCInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSmallJSONBodyBytes+1))
	if err != nil || len(raw) > maxSmallJSONBodyBytes || !jsonTextIsStrict(raw) {
		return ErrOIDCInvalid
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	token, err := check.Token()
	if err != nil || token != json.Delim('{') {
		return ErrOIDCInvalid
	}
	seen := map[string]bool{}
	for check.More() {
		token, err := check.Token()
		if err != nil {
			return ErrOIDCInvalid
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return ErrOIDCInvalid
		}
		seen[key] = true
		var value json.RawMessage
		if err := check.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrOIDCInvalid
		}
	}
	if _, err := check.Token(); err != nil {
		return ErrOIDCInvalid
	}
	var extra any
	if err := check.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrOIDCInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return ErrOIDCInvalid
	}
	return nil
}

// Use the existing generation-bound session freshness predicate, including its database
// clock after lock waits. Start's CreateAttempt repeats this check inside its own fence.
func (s *Server) oidcFreshUser(r *http.Request, p *Principal) (*AuthUser, error) {
	if s.AuthAPI == nil || p == nil || p.SessionID == "" {
		return nil, ErrOIDCSessionInvalid
	}
	user, err := s.AuthAPI.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || user == nil || user.TenantID != p.TenantID || user.Disabled || user.TenantSuspended {
		return nil, ErrOIDCUserDisabled
	}
	a := OIDCIdentityAuthority{TenantID: p.TenantID, UserID: p.UserID, EpochBaseline: user.CredentialUpdatedAt}
	err = withTenant(r.Context(), s.OIDC.Pool, p.TenantID, func(tx pgx.Tx) error {
		_, _, generation, err := oidcLockUser(r.Context(), tx, a, false)
		if err != nil {
			return err
		}
		if err := oidcCheckEpoch(r.Context(), tx, a.UserID, a.EpochBaseline); err != nil {
			return err
		}
		return oidcCheckOrigin(r.Context(), tx, a, p.SessionID, generation, 5*time.Minute)
	})
	return user, err
}

func (s *Server) oidcProtectedTenant(w http.ResponseWriter, r *http.Request, cap Capability, fresh bool) (string, *Principal, bool) {
	p := principalFrom(r.Context())
	slug, tenant, err := s.tenantFromHost(r)
	if err != nil || p == nil || p.TenantID != tenant {
		s.oidcAPIFailure(w, r, tenant, "login", "", "host_mismatch")
		return "", nil, false
	}
	if cap != "" {
		if err := p.Grant.Require(cap); err != nil {
			s.oidcAuditFailure(r, tenant, "login", "", "permission_denied")
			writeDenied(w, err)
			return "", nil, false
		}
	}
	if fresh {
		if _, err := s.oidcFreshUser(r, p); err != nil {
			s.oidcAuditFailure(r, tenant, "login", "", oidcReason(err))
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, http.StatusPreconditionRequired, oidcStepUpMessage)
			return "", nil, false
		}
	}
	return slug, p, true
}

func oidcConnectionResponse(c *OIDCConnection, redirect string) map[string]any {
	out := map[string]any{"profile": "entra", "entra_tenant_id": "", "client_id": "", "enabled": false, "trust_entra_mfa": false, "has_secret": false, "version": int64(0), "last_test": nil, "redirect_uri": redirect}
	if c == nil {
		return out
	}
	out["entra_tenant_id"], out["client_id"] = c.EntraTenantID, c.ClientID
	out["enabled"], out["trust_entra_mfa"], out["has_secret"], out["version"] = c.Enabled, c.TrustEntraMFA, c.HasSecret, c.Version
	if c.LastTestVersion != nil && c.LastTestAt != nil {
		out["last_test"] = map[string]any{"version": *c.LastTestVersion, "at": c.LastTestAt.UTC().Format(time.RFC3339)}
	}
	return out
}

func (s *Server) handleGetSSO(w http.ResponseWriter, r *http.Request) {
	slug, p, ok := s.oidcProtectedTenant(w, r, CapManageTenant, false)
	if !ok {
		return
	}
	connection, err := s.OIDC.GetConnection(r.Context(), p.TenantID)
	if errors.Is(err, ErrOIDCDisabled) {
		connection, err = nil, nil
	}
	if err != nil {
		s.oidcAPIFailure(w, r, p.TenantID, "login", "", "connection_read")
		return
	}
	writeJSON(w, http.StatusOK, oidcConnectionResponse(connection, s.redirectURI(slug)))
}

func (s *Server) handlePutSSO(w http.ResponseWriter, r *http.Request) {
	slug, p, ok := s.oidcProtectedTenant(w, r, CapManageTenant, true)
	if !ok {
		return
	}
	var req struct {
		TenantID string  `json:"entra_tenant_id"`
		ClientID string  `json:"client_id"`
		Secret   *string `json:"client_secret"`
		Enabled  bool    `json:"enabled"`
		Trust    bool    `json:"trust_entra_mfa"`
	}
	if err := oidcDecode(r, &req); err != nil {
		s.oidcAPIFailure(w, r, p.TenantID, "login", "", "invalid_json")
		return
	}
	// Values pasted from the Entra portal often carry surrounding whitespace or uppercase; normalise to the
	// canonical lowercase UUID before validating, so the stored form stays case-independent.
	req.TenantID = strings.ToLower(strings.TrimSpace(req.TenantID))
	req.ClientID = strings.ToLower(strings.TrimSpace(req.ClientID))
	if req.Secret != nil {
		trimmed := strings.TrimSpace(*req.Secret)
		req.Secret = &trimmed
	}
	// Canonical UUIDs match the provider client's validation and avoid case-dependent versions.
	if !entraGUID.MatchString(req.TenantID) || !entraGUID.MatchString(req.ClientID) || (req.Secret != nil && *req.Secret == "") {
		s.oidcAPIFailure(w, r, p.TenantID, "login", "", "invalid_connection")
		return
	}
	// The step-up passed at entry; the store re-checks it under its locks at commit time.
	actor, err := s.AuthAPI.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || actor == nil {
		s.oidcAPIFailure(w, r, p.TenantID, "login", "", "user_ineligible")
		return
	}
	connection, err := s.OIDC.PutConnection(r.Context(), p.TenantID, OIDCConnectionWrite{Profile: "entra", EntraTenantID: req.TenantID, ClientID: req.ClientID, ClientSecret: req.Secret, Enabled: req.Enabled, TrustEntraMFA: req.Trust, UpdatedBy: &p.UserID,
		Authority: &OIDCSettingsAuthority{UserID: p.UserID, SessionID: p.SessionID, EpochBaseline: actor.CredentialUpdatedAt}})
	if err != nil {
		s.oidcAPIFailure(w, r, p.TenantID, "login", "", oidcReason(err))
		return
	}
	s.oidcClientsMu.Lock()
	delete(s.oidcClients, p.TenantID)
	s.oidcClientsMu.Unlock()
	if err := s.recordMgmtAudit(r, "tenant.sso_update", "tenant", p.TenantID, map[string]any{"profile": "entra", "entra_tenant_id": req.TenantID, "client_id": req.ClientID, "enabled": req.Enabled, "trust_entra_mfa": req.Trust, "secret_changed": req.Secret != nil, "version": connection.Version}); err != nil {
		writeError(w, http.StatusInternalServerError, "settings saved but audit could not be recorded")
		return
	}
	writeJSON(w, http.StatusOK, oidcConnectionResponse(connection, s.redirectURI(slug)))
}

func (s *Server) handleOIDCUnlink(w http.ResponseWriter, r *http.Request) {
	_, p, ok := s.oidcProtectedTenant(w, r, "", true)
	if !ok {
		return
	}
	s.oidcUnlink(w, r, p, p.UserID)
}

func (s *Server) handleOIDCAdminUnlink(w http.ResponseWriter, r *http.Request) {
	_, p, ok := s.oidcProtectedTenant(w, r, CapManageUsers, false)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !isUUID(id) {
		s.oidcAPIFailure(w, r, p.TenantID, "link", p.UserID, "invalid_user_id")
		return
	}
	// Resolve inside the actor's tenant before calling the mutation, even with RLS enabled.
	user, err := s.AuthAPI.Users.FindUserByID(r.Context(), p.TenantID, id)
	if err != nil || user == nil || user.TenantID != p.TenantID {
		s.oidcAPIFailure(w, r, p.TenantID, "link", p.UserID, "user_not_found")
		return
	}
	// The same hierarchy every other per-user admin action applies (disable, sign-out, role, reset
	// link): CapManageUsers alone let an Admin strip the OWNER's Microsoft identity and revoke the
	// Owner's SSO sessions — and an SSO-only Owner then has no local password and nobody below
	// them may mint one a reset link (security audit 2026-10-18).
	targetGrant, err := s.AuthAPI.Users.StoredGrantFor(r.Context(), p.TenantID, id)
	if err != nil {
		s.oidcAPIFailure(w, r, p.TenantID, "link", p.UserID, "store_unavailable")
		return
	}
	if canAdministerExistingUser(p.Grant, targetGrant) != nil {
		s.oidcAPIFailure(w, r, p.TenantID, "link", p.UserID, "permission_denied")
		return
	}
	s.oidcUnlink(w, r, p, id)
}

func (s *Server) oidcUnlink(w http.ResponseWriter, r *http.Request, p *Principal, target string) {
	if err := s.OIDC.UnlinkIdentity(r.Context(), p.TenantID, target); err != nil {
		s.oidcAPIFailure(w, r, p.TenantID, "link", p.UserID, oidcReason(err))
		return
	}
	if err := s.AuthAPI.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, target, "user.sso_unlink", map[string]any{"method": "oidc", "ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "identity unlinked but audit could not be recorded")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
