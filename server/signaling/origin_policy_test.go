package main

// Tests for the Origin admission policy (origin_policy.go, docs/25 F09 residual).
//
// Unit tests cover ParseOriginPolicy and originPolicy.allow. Integration tests drive the real
// handleWS endpoint over a loopback httptest server so the policy-check → admission-counter
// interaction is verified end-to-end, not just in isolation.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ---------------------------------------------------------------------------
// ParseOriginPolicy unit tests
// ---------------------------------------------------------------------------

func TestParseOriginPolicyEmpty(t *testing.T) {
	t.Parallel()
	p, err := ParseOriginPolicy("")
	if err != nil {
		t.Fatalf("ParseOriginPolicy(%q): unexpected error: %v", "", err)
	}
	if p.enforcing() {
		t.Fatal("empty input must yield warn-only policy (not enforcing)")
	}
}

func TestParseOriginPolicyWhitespaceOnly(t *testing.T) {
	t.Parallel()
	p, err := ParseOriginPolicy("   ")
	if err != nil {
		t.Fatalf("ParseOriginPolicy(whitespace): unexpected error: %v", err)
	}
	if p.enforcing() {
		t.Fatal("whitespace-only input must yield warn-only policy")
	}
}

func TestParseOriginPolicyCommaOnly(t *testing.T) {
	t.Parallel()
	p, err := ParseOriginPolicy(",,,")
	if err != nil {
		t.Fatalf("ParseOriginPolicy(commas-only): unexpected error: %v", err)
	}
	if p.enforcing() {
		t.Fatal("comma-only input (no valid entries) must yield warn-only policy")
	}
}

func TestParseOriginPolicyValidHTTPS(t *testing.T) {
	t.Parallel()
	p, err := ParseOriginPolicy("https://console.deskrally.com")
	if err != nil {
		t.Fatalf("ParseOriginPolicy(https): %v", err)
	}
	if !p.enforcing() {
		t.Fatal("non-empty https origin must yield enforcing policy")
	}
	if len(p.allowed) != 1 || p.allowed[0] != "https://console.deskrally.com" {
		t.Fatalf("allowed = %v, want [https://console.deskrally.com]", p.allowed)
	}
}

func TestParseOriginPolicyMultiple(t *testing.T) {
	t.Parallel()
	p, err := ParseOriginPolicy("https://a.example.com , https://b.example.com")
	if err != nil {
		t.Fatalf("ParseOriginPolicy(multiple): %v", err)
	}
	if !p.enforcing() {
		t.Fatal("multiple valid origins must yield enforcing policy")
	}
	if len(p.allowed) != 2 {
		t.Fatalf("allowed count = %d, want 2; got %v", len(p.allowed), p.allowed)
	}
}

func TestParseOriginPolicyValidHTTP(t *testing.T) {
	t.Parallel()
	p, err := ParseOriginPolicy("http://localhost:3000")
	if err != nil {
		t.Fatalf("ParseOriginPolicy(http): %v", err)
	}
	if !p.enforcing() {
		t.Fatal("http origin must yield enforcing policy")
	}
}

func TestParseOriginPolicyMissingScheme(t *testing.T) {
	t.Parallel()
	_, err := ParseOriginPolicy("console.deskrally.com")
	if err == nil {
		t.Fatal("origin without scheme must be rejected with an error")
	}
}

func TestParseOriginPolicyMixedValidAndInvalid(t *testing.T) {
	t.Parallel()
	_, err := ParseOriginPolicy("https://good.example.com,badentry,https://also-good.example.com")
	if err == nil {
		t.Fatal("any invalid entry in a list must cause an error")
	}
}

// ---------------------------------------------------------------------------
// originPolicy.allow unit tests (no network)
// ---------------------------------------------------------------------------

func allowPolicy(t *testing.T, raw string) *originPolicy {
	t.Helper()
	p, err := ParseOriginPolicy(raw)
	if err != nil {
		t.Fatalf("ParseOriginPolicy(%q): %v", raw, err)
	}
	return p
}

func makeRequest(origin string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

// Warn-only: no Origin (native client) → allowed.
func TestAllowWarnOnlyNoOrigin(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "")
	if !p.allow(makeRequest("")) {
		t.Fatal("warn-only policy must allow native client (no Origin)")
	}
}

// Warn-only: any browser Origin → allowed.
func TestAllowWarnOnlyAnyOrigin(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "")
	if !p.allow(makeRequest("https://evil.attacker.com")) {
		t.Fatal("warn-only policy must allow any browser Origin")
	}
}

// Enforcing: no Origin (native client) → always allowed regardless of allowlist.
//
// MUTATION TARGET: remove the `if origin == "" { return true }` branch and this test fails,
// because the empty origin will fall through to the allowlist check and be refused.
func TestAllowEnforcingNoOriginNativeClient(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "https://allowed.example.com")
	if !p.allow(makeRequest("")) {
		t.Fatal("enforcing policy must allow native client with no Origin header")
	}
}

// Enforcing: listed Origin → allowed.
func TestAllowEnforcingListedOrigin(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "https://allowed.example.com")
	if !p.allow(makeRequest("https://allowed.example.com")) {
		t.Fatal("enforcing policy must allow a listed Origin")
	}
}

// Enforcing: second of two listed Origins → allowed.
func TestAllowEnforcingSecondListedOrigin(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "https://first.example.com,https://second.example.com")
	if !p.allow(makeRequest("https://second.example.com")) {
		t.Fatal("enforcing policy must allow any listed Origin, not just the first")
	}
}

// Enforcing: unlisted Origin → blocked.
//
// MUTATION TARGET: replace the allowlist loop with `return true` and this test fails.
func TestAllowEnforcingUnlistedOrigin(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "https://allowed.example.com")
	if p.allow(makeRequest("https://evil.attacker.com")) {
		t.Fatal("enforcing policy must block an unlisted Origin")
	}
}

// Enforcing: case-sensitive match (Origin is a verbatim string, not a hostname compare).
func TestAllowEnforcingCaseSensitive(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "https://Allowed.Example.Com")
	// lowercase variant must NOT match the uppercase-stored origin
	if p.allow(makeRequest("https://allowed.example.com")) {
		t.Fatal("origin comparison must be case-sensitive; lowercase should not match uppercase allowlist entry")
	}
}

// Enforcing: browsers loaded from file:// or sandboxed iframes send `Origin: null` (the literal
// string "null"). That is not a valid origin scheme, so it must not match any normal allowlist
// entry and must be blocked.
func TestAllowEnforcingNullOriginBlocked(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "https://allowed.example.com")
	if p.allow(makeRequest("null")) {
		t.Fatal("enforcing policy must block the literal Origin value 'null' (sandboxed iframes, file:// docs)")
	}
}

// Warn-only: literal "null" Origin is allowed (non-enforcing, no allowlist).
func TestAllowWarnOnlyNullOriginAllowed(t *testing.T) {
	t.Parallel()
	p := allowPolicy(t, "")
	if !p.allow(makeRequest("null")) {
		t.Fatal("warn-only policy must allow all Origins including the literal 'null'")
	}
}

// Enforcing: https://host and https://host:443 are DIFFERENT byte sequences. Browsers typically
// omit the default port; an allowlist entry without the port does NOT match one with port 443.
// This is an operator foot-gun — the comment in ParseOriginPolicy's godoc calls it out.
func TestAllowEnforcingDefaultPortMismatch(t *testing.T) {
	t.Parallel()
	// Allowlist carries the normal form (no explicit default port).
	p := allowPolicy(t, "https://console.example.com")
	// Browser that (unusually) sends the explicit port must NOT match.
	if p.allow(makeRequest("https://console.example.com:443")) {
		t.Fatal("https://host and https://host:443 are distinct origins; explicit-port form must not match implicit-port allowlist entry")
	}
}

// ---------------------------------------------------------------------------
// Integration tests: policy enforced in handleWS over a real loopback
// ---------------------------------------------------------------------------

// dialWSWithOrigin opens a WebSocket to the given URL with an optional Origin header.
// The returned Conn is registered for cleanup; the raw response is always returned so
// the caller can check status codes on rejection.
func dialWSWithOrigin(t *testing.T, wsURL, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	dialer := &websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	var header http.Header
	if origin != "" {
		header = http.Header{"Origin": {origin}}
	}
	conn, resp, err := dialer.Dial(wsURL, header)
	if err != nil && resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if conn != nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	return conn, resp, err
}

// defaultLimits for integration tests: large enough that admission is not the bottleneck.
var integrationLimits = admissionLimits{
	maxTotal:       64,
	maxPending:     32,
	preAuthTimeout: 10 * time.Second,
}

// Warn-only: a browser with any Origin can upgrade — the slot IS consumed (the upgrade was
// permitted, so tryAcquire ran successfully).
func TestOriginWarnOnlyAllowsBrowser(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, integrationLimits)
	// default warn-only policy — no SetOriginPolicy call needed

	conn, _, err := dialWSWithOrigin(t, ts.wsURL, "https://any-origin.example.com")
	if err != nil {
		t.Fatalf("warn-only: browser with any origin must connect; got: %v", err)
	}
	_ = conn

	if err := ts.waitCounters(1, 1, time.Second); err != nil {
		t.Fatalf("warn-only allowed connection did not consume a slot: %v", err)
	}
}

// Enforcing: a native client (no Origin) always passes, even when the allowlist is non-empty.
//
// MUTATION TARGET: remove the `if origin == "" { return true }` branch in allow() → native
// client has no Origin, falls through to the allowlist, is not found → 403 → test fails.
func TestOriginEnforcingAllowsNativeClient(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, integrationLimits)
	p, err := ParseOriginPolicy("https://allowed.example.com")
	if err != nil {
		t.Fatalf("ParseOriginPolicy: %v", err)
	}
	ts.srv.SetOriginPolicy(p)

	// Native client: no Origin header.
	conn, _, err := dialWSWithOrigin(t, ts.wsURL, "")
	if err != nil {
		t.Fatalf("enforcing: native client (no Origin) must connect; got: %v", err)
	}
	_ = conn
}

// Enforcing: a browser with a listed Origin is allowed through.
func TestOriginEnforcingAllowsListedBrowser(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, integrationLimits)
	p, err := ParseOriginPolicy("https://allowed.example.com")
	if err != nil {
		t.Fatalf("ParseOriginPolicy: %v", err)
	}
	ts.srv.SetOriginPolicy(p)

	conn, _, err := dialWSWithOrigin(t, ts.wsURL, "https://allowed.example.com")
	if err != nil {
		t.Fatalf("enforcing: browser with listed Origin must connect; got: %v", err)
	}
	_ = conn
}

// Enforcing: a browser with an unlisted Origin is rejected 403 BEFORE the WebSocket upgrade
// (no Upgrade header in the response) and without consuming an admission slot.
//
// MUTATION TARGET: remove `if !s.originPolicy.allow(r) { ... }` from handleWS → banned browser
// reaches tryAcquire, upgrade succeeds, conn is non-nil → the "err == nil" check fails.
// Also: remove the slot check → admission counter might move, revealing that tryAcquire ran.
func TestOriginEnforcingBlocksUnlistedBrowser(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, integrationLimits)
	p, err := ParseOriginPolicy("https://allowed.example.com")
	if err != nil {
		t.Fatalf("ParseOriginPolicy: %v", err)
	}
	ts.srv.SetOriginPolicy(p)

	_, resp, err := dialWSWithOrigin(t, ts.wsURL, "https://evil.attacker.com")
	if err == nil {
		t.Fatal("enforcing: browser with unlisted Origin must be rejected; got a live connection")
	}
	if resp == nil {
		t.Fatalf("enforcing: expected HTTP response with status code on rejection, got nil (err=%v)", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("enforcing: response status = %d, want 403", resp.StatusCode)
	}
	// The upgrade must not have happened — a successful upgrade would carry Upgrade: websocket.
	if resp.Header.Get("Upgrade") != "" {
		t.Fatal("enforcing: 403 response must not advertise Upgrade (origin check must run BEFORE the upgrade)")
	}
	// The admission slot must NOT have been consumed: origin check runs before tryAcquire.
	if err := ts.waitCounters(0, 0, 500*time.Millisecond); err != nil {
		t.Fatalf("enforcing: banned-origin rejection must not consume an admission slot: %v", err)
	}
}
