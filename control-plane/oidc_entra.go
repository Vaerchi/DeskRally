package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const entraResponseLimit int64 = 256 << 10
const entraSkew = 2 * time.Minute

// EntraConfig accepts identifiers, never tenant-controlled endpoint URLs.
type EntraConfig struct{ TenantID, ClientID, ClientSecret string }

type EntraIdentity struct {
	Issuer, Subject, OID, TenantID, Email, PreferredUsername string
	AMR                                                      []string
}

// EntraValidationError identifies the failed rule without exposing token contents.
// Rule is one of signature, alg, claims, iss, aud, azp, nonce, exp, iat,
// nbf, tid, ver, or sub. errors.As can distinguish validation from transport errors.
type EntraValidationError struct{ Rule string }

func (e *EntraValidationError) Error() string { return "entra: invalid " + e.Rule }
func entraInvalid(rule string) error          { return &EntraValidationError{Rule: rule} }

var entraGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateEntraConfig(cfg EntraConfig) error {
	if !entraGUID.MatchString(cfg.TenantID) {
		return errors.New("entra: tenant ID must be a lowercase canonical UUID")
	}
	if !entraGUID.MatchString(cfg.ClientID) {
		return errors.New("entra: client ID must be a lowercase canonical UUID")
	}
	if cfg.ClientSecret == "" {
		return errors.New("entra: client secret is required")
	}
	return nil
}

// Validate before dialing, including requests issued by OAuth or JWKS libraries.
func entraAllowedURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil &&
		u.Hostname() == "login.microsoftonline.com" &&
		(u.Host == "login.microsoftonline.com" || u.Host == "login.microsoftonline.com:443")
}

type entraPinnedTransport struct{ base http.RoundTripper }

func (t *entraPinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !entraAllowedURL(req.URL) {
		return nil, errors.New("entra: outbound URL refused")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		resp.Body = &entraLimitedBody{body: resp.Body, remaining: entraResponseLimit}
	}
	return resp, nil
}

// Read one byte beyond the limit so an oversized response cannot look like a
// successfully truncated JSON document. Closing still closes the real body.
type entraLimitedBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *entraLimitedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n != 0 {
			return 0, errors.New("entra: response exceeds 256 KiB")
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:int(b.remaining)]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	return n, err
}
func (b *entraLimitedBody) Close() error { return b.body.Close() }

func newEntraHTTPClient() *http.Client {
	return &http.Client{
		Transport:     &entraPinnedTransport{base: http.DefaultTransport.(*http.Transport).Clone()},
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// RemoteKeySet already caches keys and coalesces concurrent fetches. Gate its
// network fetches as well: cached signatures remain usable during the cooldown.
// The initial load is separate from the unknown-key refresh allowance. Failed
// refreshes consume that allowance too, preventing attacker-driven retry storms.
type entraRefreshTransport struct {
	base        http.RoundTripper
	mu          sync.Mutex
	initialized bool
	lastRefresh time.Time
}

func (t *entraRefreshTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	now := time.Now()
	if t.initialized {
		if !t.lastRefresh.IsZero() && now.Sub(t.lastRefresh) < time.Minute {
			t.mu.Unlock()
			return nil, errors.New("entra: JWKS refresh rate limited")
		}
		t.lastRefresh = now
	} else {
		t.initialized = true
	}
	t.mu.Unlock()
	return t.base.RoundTrip(r)
}

type entraKeySet struct{ remote *oidc.RemoteKeySet }

func (k *entraKeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	return k.remote.VerifySignature(ctx, token)
}

type EntraClient struct {
	cfg    EntraConfig
	issuer string
	oauth  oauth2.Config
	http   *http.Client
	keys   oidc.KeySet
}

func NewEntraClient(cfg EntraConfig) (*EntraClient, error) {
	return newEntraClientWithBase(cfg, "https://login.microsoftonline.com", newEntraHTTPClient())
}

// Only tests may replace the endpoint origin and HTTP client. Production always
// enters through NewEntraClient and never performs OIDC discovery.
func newEntraClientWithBase(cfg EntraConfig, baseURL string, client *http.Client) (*EntraClient, error) {
	if err := validateEntraConfig(cfg); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("entra: HTTP client is required")
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("entra: invalid test endpoint origin")
	}
	root := strings.TrimSuffix(baseURL, "/") + "/" + cfg.TenantID
	c := &EntraClient{cfg: cfg, issuer: root + "/v2.0", http: client}
	c.oauth = oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		Scopes:   []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{AuthURL: root + "/oauth2/v2.0/authorize", TokenURL: root + "/oauth2/v2.0/token", AuthStyle: oauth2.AuthStyleInParams},
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	jwksClient := *client
	jwksClient.Transport = &entraRefreshTransport{base: transport}
	// A long-lived context is required: a request cancellation must not poison the
	// shared key cache. RemoteKeySet still honors each verification's context.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &jwksClient)
	c.keys = &entraKeySet{remote: oidc.NewRemoteKeySet(ctx, root+"/discovery/v2.0/keys")}
	return c, nil
}

func (c *EntraClient) AuthURL(redirectURI, state, nonce, codeChallengeS256 string) string {
	cfg := c.oauth
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("response_mode", "query"),
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("code_challenge", codeChallengeS256),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}

func (c *EntraClient) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (string, error) {
	cfg := c.oauth
	cfg.RedirectURL = redirectURI
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)
	token, err := cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return "", errors.New("entra: code exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("entra: token response has no id_token")
	}
	return raw, nil
}

type entraAudience []string

func (a *entraAudience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type entraClaims struct {
	Issuer            string        `json:"iss"`
	Audience          entraAudience `json:"aud"`
	AZP               string        `json:"azp"`
	Nonce             string        `json:"nonce"`
	Exp               *int64        `json:"exp"`
	IAT               *int64        `json:"iat"`
	NBF               *int64        `json:"nbf"`
	TenantID          string        `json:"tid"`
	Version           string        `json:"ver"`
	Subject           string        `json:"sub"`
	OID               string        `json:"oid"`
	Email             string        `json:"email"`
	PreferredUsername string        `json:"preferred_username"`
	AMR               []string      `json:"amr"`
}

func (c *EntraClient) Verify(ctx context.Context, rawIDToken, expectedNonce string, now time.Time) (*EntraIdentity, error) {
	// This untrusted header is used only to reject algorithms early. The verifier
	// authenticates the entire token before any claims can authorize an identity.
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return nil, entraInvalid("signature")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
	}
	if err != nil || json.Unmarshal(headerBytes, &header) != nil {
		return nil, entraInvalid("signature")
	}
	if header.Alg != "RS256" {
		return nil, entraInvalid("alg")
	}
	verifier := oidc.NewVerifier(c.issuer, c.keys, &oidc.Config{
		ClientID: c.cfg.ClientID, SupportedSigningAlgs: []string{"RS256"},
		// App checks below provide stable rule-specific errors and our explicit skew.
		SkipIssuerCheck: true, SkipClientIDCheck: true, SkipExpiryCheck: true,
		Now: func() time.Time { return now },
	})
	token, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, entraInvalid("signature")
	}
	var claims entraClaims
	if err := token.Claims(&claims); err != nil {
		return nil, entraInvalid("claims")
	}
	if claims.Issuer != c.issuer {
		return nil, entraInvalid("iss")
	}
	found := false
	for _, aud := range claims.Audience {
		if aud == c.cfg.ClientID {
			found = true
		}
	}
	if !found {
		return nil, entraInvalid("aud")
	}
	// azp names the party the token was issued TO: if present it must be this client, whatever the
	// audience; with several audiences it is mandatory (OIDC Core 3.1.3.7).
	if (claims.AZP != "" || len(claims.Audience) > 1) && claims.AZP != c.cfg.ClientID {
		return nil, entraInvalid("azp")
	}
	if expectedNonce == "" || claims.Nonce != expectedNonce {
		return nil, entraInvalid("nonce")
	}
	if claims.Exp == nil || !now.Before(time.Unix(*claims.Exp, 0).Add(entraSkew)) {
		return nil, entraInvalid("exp")
	}
	if claims.IAT == nil || time.Unix(*claims.IAT, 0).After(now.Add(entraSkew)) {
		return nil, entraInvalid("iat")
	}
	if claims.NBF != nil && time.Unix(*claims.NBF, 0).After(now.Add(entraSkew)) {
		return nil, entraInvalid("nbf")
	}
	if claims.TenantID != c.cfg.TenantID {
		return nil, entraInvalid("tid")
	}
	if claims.Version != "2.0" {
		return nil, entraInvalid("ver")
	}
	if claims.Subject == "" {
		return nil, entraInvalid("sub")
	}
	return &EntraIdentity{
		Issuer: claims.Issuer, Subject: claims.Subject, OID: claims.OID,
		TenantID: claims.TenantID, Email: claims.Email,
		PreferredUsername: claims.PreferredUsername, AMR: claims.AMR,
	}, nil
}

func entraRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("entra: random generation: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func NewOIDCState() (string, error) { return entraRandom() }
func NewOIDCNonce() (string, error) { return entraRandom() }
func NewPKCE() (verifier, challengeS256 string, err error) {
	verifier, err = entraRandom()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
