package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func b1Config() EntraConfig {
	return EntraConfig{TenantID: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", ClientSecret: "a-test-client-secret-with-at-least-32-bytes"}
}

type b1IdP struct {
	server  *httptest.Server
	key     *rsa.PrivateKey
	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetches int
	raw     string
	form    url.Values
}

func b1Fake(t *testing.T) (*b1IdP, *EntraClient) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &b1IdP{key: key}
	p.keys = []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "initial", Algorithm: "RS256", Use: "sig"}}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/" + b1Config().TenantID + "/discovery/v2.0/keys":
			p.fetches++
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: p.keys})
		case "/" + b1Config().TenantID + "/oauth2/v2.0/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "form", 400)
				return
			}
			p.form = r.PostForm
			response := map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600}
			if p.raw != "" {
				response["id_token"] = p.raw
			}
			_ = json.NewEncoder(w).Encode(response)
		default:
			// Any discovery request makes tests fail rather than silently succeeding.
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	c, err := newEntraClientWithBase(b1Config(), p.server.URL, p.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return p, c
}
func b1Claims(c *EntraClient, now time.Time) map[string]any {
	return map[string]any{
		"iss": c.issuer, "aud": c.cfg.ClientID, "nonce": "nonce", "exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(), "nbf": now.Unix(), "tid": c.cfg.TenantID, "ver": "2.0", "sub": "subject",
		"oid": "object", "email": "user@example.com", "preferred_username": "preferred@example.com", "amr": []string{"pwd", "mfa"},
	}
}
func b1Sign(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func b1Rule(t *testing.T, err error, want string) {
	t.Helper()
	var validation *EntraValidationError
	if !errors.As(err, &validation) || validation.Rule != want {
		t.Fatalf("error = %v; want rule %s", err, want)
	}
}

func TestB1EntraClaims(t *testing.T) {
	p, c := b1Fake(t)
	now := time.Now().Truncate(time.Second)
	raw := b1Sign(t, p.key, jose.RS256, "initial", b1Claims(c, now))
	id, err := c.Verify(context.Background(), raw, "nonce", now)
	if err != nil {
		t.Fatal(err)
	}
	if id.Issuer != c.issuer || id.Subject != "subject" || id.OID != "object" || id.TenantID != c.cfg.TenantID || id.Email != "user@example.com" || id.PreferredUsername != "preferred@example.com" || len(id.AMR) != 2 || id.AMR[1] != "mfa" {
		t.Fatalf("identity = %+v", id)
	}
	// Each negative changes exactly one rule, so bypassing any check is observable.
	cases := []struct {
		name, rule string
		change     func(map[string]any)
	}{
		{"issuer", "iss", func(m map[string]any) { m["iss"] = "https://evil.example/v2.0" }},
		{"audience", "aud", func(m map[string]any) { m["aud"] = "other" }},
		{"azp", "azp", func(m map[string]any) { m["aud"] = []string{c.cfg.ClientID, "other"}; m["azp"] = "other" }},
		{"missing azp", "azp", func(m map[string]any) { m["aud"] = []string{c.cfg.ClientID, "other"} }},
		{"single audience foreign azp", "azp", func(m map[string]any) { m["azp"] = "other-client" }},
		{"nonce", "nonce", func(m map[string]any) { m["nonce"] = "wrong" }},
		{"expired", "exp", func(m map[string]any) { m["exp"] = now.Add(-3 * time.Minute).Unix() }},
		{"missing expiry", "exp", func(m map[string]any) { delete(m, "exp") }},
		{"future nbf", "nbf", func(m map[string]any) { m["nbf"] = now.Add(3 * time.Minute).Unix() }},
		{"future iat", "iat", func(m map[string]any) { m["iat"] = now.Add(3 * time.Minute).Unix() }},
		{"missing iat", "iat", func(m map[string]any) { delete(m, "iat") }},
		{"tenant", "tid", func(m map[string]any) { m["tid"] = "33333333-3333-3333-3333-333333333333" }},
		{"version", "ver", func(m map[string]any) { m["ver"] = "1.0" }},
		{"subject", "sub", func(m map[string]any) { m["sub"] = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := b1Claims(c, now)
			tc.change(claims)
			_, err := c.Verify(context.Background(), b1Sign(t, p.key, jose.RS256, "initial", claims), "nonce", now)
			b1Rule(t, err, tc.rule)
		})
	}
	t.Run("skew and multiple audiences accepted", func(t *testing.T) {
		claims := b1Claims(c, now)
		claims["exp"] = now.Add(-time.Minute).Unix()
		claims["iat"] = now.Add(time.Minute).Unix()
		claims["nbf"] = now.Add(time.Minute).Unix()
		claims["aud"] = []string{"other", c.cfg.ClientID}
		claims["azp"] = c.cfg.ClientID
		if _, err := c.Verify(context.Background(), b1Sign(t, p.key, jose.RS256, "initial", claims), "nonce", now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("HS256 cannot use client secret as signing authority", func(t *testing.T) {
		raw := b1Sign(t, []byte(c.cfg.ClientSecret), jose.HS256, "initial", b1Claims(c, now))
		_, err := c.Verify(context.Background(), raw, "nonce", now)
		b1Rule(t, err, "alg")
	})
	t.Run("none", func(t *testing.T) {
		payload, err := json.Marshal(b1Claims(c, now))
		if err != nil {
			t.Fatal(err)
		}
		raw := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
		_, err = c.Verify(context.Background(), raw, "nonce", now)
		b1Rule(t, err, "alg")
	})
	t.Run("invalid signature", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Verify(context.Background(), b1Sign(t, other, jose.RS256, "initial", b1Claims(c, now)), "nonce", now)
		b1Rule(t, err, "signature")
	})
}

func TestB1EntraUnknownKidRefresh(t *testing.T) {
	p, c := b1Fake(t)
	now := time.Now()
	verify := func(kid string) error {
		_, err := c.Verify(context.Background(), b1Sign(t, p.key, jose.RS256, kid, b1Claims(c, now)), "nonce", now)
		return err
	}
	if err := verify("initial"); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	before := p.fetches
	// Publish a rotation only after the initial key cache was populated.
	p.keys = append(p.keys, jose.JSONWebKey{Key: &p.key.PublicKey, KeyID: "rotated", Algorithm: "RS256", Use: "sig"})
	p.mu.Unlock()
	if err := verify("rotated"); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	after := p.fetches
	p.mu.Unlock()
	if before != 1 || after != before+1 {
		t.Fatalf("fetches %d -> %d", before, after)
	}
	b1Rule(t, verify("unknown-again"), "signature")
	p.mu.Lock()
	final := p.fetches
	p.mu.Unlock()
	if final != after {
		t.Fatalf("second unknown key fetched again: %d -> %d", after, final)
	}
	if err := verify("rotated"); err != nil {
		t.Fatalf("cooldown broke cached key: %v", err)
	}
}

func TestB1EntraOAuth(t *testing.T) {
	p, c := b1Fake(t)
	redirect := "https://tenant.deskrally.com/cp/auth/oidc/callback"
	u, err := url.Parse(c.AuthURL(redirect, "state", "nonce", "challenge"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != p.server.URL+"/"+c.cfg.TenantID+"/oauth2/v2.0/authorize" {
		t.Fatal(u)
	}
	expected := map[string]string{"response_type": "code", "scope": "openid email profile", "response_mode": "query", "prompt": "select_account", "code_challenge_method": "S256", "code_challenge": "challenge", "nonce": "nonce", "state": "state", "redirect_uri": redirect, "client_id": c.cfg.ClientID}
	for key, value := range expected {
		if u.Query().Get(key) != value {
			t.Fatalf("%s = %q", key, u.Query().Get(key))
		}
	}
	p.mu.Lock()
	p.raw = "id-token"
	p.mu.Unlock()
	raw, err := c.Exchange(context.Background(), "code", "verifier", redirect)
	if err != nil || raw != "id-token" {
		t.Fatalf("exchange: %q, %v", raw, err)
	}
	p.mu.Lock()
	form := p.form
	p.raw = ""
	p.mu.Unlock()
	for key, value := range map[string]string{"grant_type": "authorization_code", "code": "code", "code_verifier": "verifier", "redirect_uri": redirect, "client_id": c.cfg.ClientID, "client_secret": c.cfg.ClientSecret} {
		if form.Get(key) != value {
			t.Fatalf("form %s = %q", key, form.Get(key))
		}
	}
	if _, err := c.Exchange(context.Background(), "code", "verifier", redirect); err == nil {
		t.Fatal("accepted missing id_token")
	}
}

type b1RoundTripFunc func(*http.Request) (*http.Response, error)

func (f b1RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestB1EntraPinning(t *testing.T) {
	// A rejected URL must never reach the underlying transport, even once.
	transport := &entraPinnedTransport{base: b1RoundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("dialed refused URL"); return nil, nil })}
	for _, raw := range []string{"http://login.microsoftonline.com/", "https://evil.example/", "https://login.microsoftonline.com.evil.example/", "https://login.microsoftonline.com:444/", "https://user@login.microsoftonline.com/", "https://LOGIN.microsoftonline.com/"} {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"https://login.microsoftonline.com/", "https://login.microsoftonline.com:443/path"} {
		u, err := url.Parse(raw)
		if err != nil || !entraAllowedURL(u) {
			t.Fatalf("refused %s", raw)
		}
	}
	// Route the pinned hostname to a local TLS server while retaining certificate
	// verification; this exercises the real body wrapper and redirect policy.
	var mu sync.Mutex
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://login.microsoftonline.com/followed", http.StatusFound)
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("x", int(entraResponseLimit)+1))
		case "/exact":
			_, _ = io.WriteString(w, strings.Repeat("x", int(entraResponseLimit)))
		default:
			t.Error("redirect was followed")
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	local := server.Client().Transport.(*http.Transport).Clone()
	// The test server certificate is for example.com. Verify that certificate
	// using its trusted test roots while the HTTP URL remains pinned to Microsoft.
	local.TLSClientConfig = local.TLSClientConfig.Clone()
	local.TLSClientConfig.MinVersion = tls.VersionTLS12
	local.TLSClientConfig.ServerName = "example.com"
	dialer := &net.Dialer{Timeout: time.Second}
	local.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	defer local.CloseIdleConnections()
	client := newEntraHTTPClient()
	if client.Timeout != 10*time.Second {
		t.Fatal("missing total timeout")
	}
	client.Transport = &entraPinnedTransport{base: local}
	response, err := client.Get("https://login.microsoftonline.com/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", response.StatusCode)
	}
	mu.Lock()
	count := requests
	mu.Unlock()
	if count != 1 {
		t.Fatalf("redirect made %d requests", count)
	}
	for _, tc := range []struct {
		path      string
		oversized bool
	}{{"/large", true}, {"/exact", false}} {
		response, err := client.Get("https://login.microsoftonline.com" + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if (readErr != nil) != tc.oversized || int64(len(data)) != entraResponseLimit {
			t.Fatalf("%s: bytes=%d err=%v", tc.path, len(data), readErr)
		}
	}
}

func TestB1EntraConfigurationAndRandom(t *testing.T) {
	for _, field := range []string{"tenant", "client"} {
		for _, invalid := range []string{"common", "organizations", "consumers", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", "11111111111111111111111111111111", "../tenant", "11111111-1111-1111-1111-111111111111/"} {
			cfg := b1Config()
			if field == "tenant" {
				cfg.TenantID = invalid
			} else {
				cfg.ClientID = invalid
			}
			if _, err := NewEntraClient(cfg); err == nil {
				t.Fatalf("accepted %s %q", field, invalid)
			}
		}
	}
	c, err := NewEntraClient(b1Config())
	if err != nil {
		t.Fatal(err)
	}
	root := "https://login.microsoftonline.com/" + c.cfg.TenantID
	if c.issuer != root+"/v2.0" || c.oauth.Endpoint.AuthURL != root+"/oauth2/v2.0/authorize" || c.oauth.Endpoint.TokenURL != root+"/oauth2/v2.0/token" {
		t.Fatal("incorrect fixed endpoints")
	}
	verifier, challenge, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("verifier: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("wrong S256 challenge")
	}
	state, err := NewOIDCState()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewOIDCNonce()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{state, nonce} {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatal("invalid random value")
		}
	}
	if state == nonce || state == verifier || nonce == verifier {
		t.Fatal("reused random value")
	}
}
