package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The refusal matrix of docs/66 2b.6, at the control plane's own layer (Caddy's half is a deployment test).
func TestNormalizeAuthorityMatrix(t *testing.T) {
	accepted := map[string]string{
		"main.deskrally.com":       "main.deskrally.com",
		"MAIN.Deskrally.com":       "main.deskrally.com", // any case
		"main.deskrally.com.":      "main.deskrally.com", // one trailing dot
		"main.deskrally.com:443":   "main.deskrally.com", // :443 normalised away
		"Main.DeskRally.COM.:443":  "main.deskrally.com",
		"a-b.c1.deskrally.com":     "a-b.c1.deskrally.com",
		"x.deskrally.com":          "x.deskrally.com",
		"deskrally.com":            "deskrally.com",
		"main.deskrally.com:443.":  "", // placeholder: refused below (port then dot)
		"main.deskrally.com.:8443": "",
	}
	for in, want := range accepted {
		got, ok := NormalizeAuthority(in)
		if want == "" {
			if ok {
				t.Errorf("NormalizeAuthority(%q) accepted as %q, want refused", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("NormalizeAuthority(%q) = %q,%v, want %q", in, got, ok, want)
		}
	}
	refused := []string{
		"", " ", "main.deskrally.com:8443", "main.deskrally.com:80", "main.deskrally.com:", "main.deskrally.com:0443",
		"main.deskrally.com:443:443", " main.deskrally.com", "main.deskrally.com ", "main.deskrally.com\t",
		"user@main.deskrally.com", "main.deskrally.com/x", "main.deskrally.com\\x", "main.deskrally.com..",
		"main.deskrally.com..:443", "127.0.0.1", "127.0.0.1:443", "[::1]", "[::1]:443", "::1", "10.0.0.1.",
		"0x7f.1", "1.2.3", "localhost", "controlplane", "controlplane:8081", ".deskrally.com", "-a.deskrally.com",
		"a-.deskrally.com", "a..deskrally.com", "münchen.deskrally.com", "main.deskrally.com\x00",
		"main.deskrally.com\r\n", "main.deskrally.com?x=1", "main.deskrally.com#f", "main.%64eskrally.com",
		strings.Repeat("a", 64) + ".deskrally.com", strings.Repeat("a.", 130) + "com",
	}
	for _, in := range refused {
		if got, ok := NormalizeAuthority(in); ok {
			t.Errorf("NormalizeAuthority(%q) accepted as %q, want refused", in, got)
		}
	}
}

func testPolicy(t *testing.T, secret string) *HostPolicy {
	t.Helper()
	p, err := NewHostPolicy(HostPolicyConfig{
		DefaultHosts:        []string{"main.deskrally.com"},
		LegacyUnscopedHosts: []string{"loam.deskrally.com", "vc.deskrally.com"},
		PublicAuthorities:   []string{"main.deskrally.com", "loam.deskrally.com", "vc.deskrally.com", "acme.deskrally.com"},
		EdgeSecret:          secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHostPolicyClassifyNeverDefaultsAnUnknownAuthority(t *testing.T) {
	p := testPolicy(t, "")
	cases := []struct {
		in    string
		host  string
		class HostClass
	}{
		{"main.deskrally.com", "main.deskrally.com", HostDefault},
		{"MAIN.deskrally.com.:443", "main.deskrally.com", HostDefault},
		{"loam.deskrally.com", "loam.deskrally.com", HostLegacy},
		{"vc.deskrally.com", "vc.deskrally.com", HostLegacy},
		{"acme.deskrally.com", "acme.deskrally.com", HostTenant},
		{"unknown.deskrally.com", "unknown.deskrally.com", HostTenant}, // the SQL, not Go, decides: never Default
		{"evil.example.com", "evil.example.com", HostTenant},
		{"main.deskrally.com:8443", "", HostRefused},
		{"", "", HostRefused},
		{"127.0.0.1", "", HostRefused},
	}
	for _, c := range cases {
		h, class := p.Classify(c.in)
		if h != c.host || class != c.class {
			t.Errorf("Classify(%q) = %q,%v want %q,%v", c.in, h, class, c.host, c.class)
		}
		sc := p.ScopeFor(c.in)
		wantUnscoped := c.class == HostDefault || c.class == HostLegacy
		if sc.Unscoped != wantUnscoped {
			t.Errorf("ScopeFor(%q).Unscoped = %v, want %v", c.in, sc.Unscoped, wantUnscoped)
		}
		if c.class == HostRefused && (sc.Unscoped || sc.Host != "") {
			t.Errorf("a refused authority must scope to nothing, got %+v", sc)
		}
	}
	if sc := (*HostPolicy)(nil).ScopeFor("anything"); !sc.Unscoped {
		t.Error("a nil policy is the pre-theming behaviour: unscoped")
	}
}

func TestHostPolicyConfigRefusals(t *testing.T) {
	if _, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"a.example.com"}, LegacyUnscopedHosts: []string{"A.example.com."}}); err == nil {
		t.Error("a host in both lists must be a startup error")
	}
	if _, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"a.example.com:8443"}}); err == nil {
		t.Error("a port in a host list must be refused")
	}
	if _, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"a.example.com"}, EdgeSecret: "short"}); err == nil {
		t.Error("a short edge secret must be refused")
	}
}

const gateSecret = "0123456789abcdef0123456789abcdef"

// gateProbe is the next handler: it counts how often the gate let a request through.
func gateProbe(hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
}

func gateDo(h http.Handler, host, path string, hdr map[string][]string) int {
	req := httptest.NewRequest("GET", path, nil)
	req.Host = host
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestEdgeGateAppliesOnlyToMarkedPublicIngress(t *testing.T) {
	p := testPolicy(t, gateSecret)
	var hits atomic.Int32
	h := p.EdgeAuthorityGate(gateProbe(&hits))
	marked := map[string][]string{EdgeMarkerHeader: {gateSecret}}

	// Marked + on the allowlist (after normalisation): accepted.
	for _, host := range []string{"main.deskrally.com", "MAIN.DESKRALLY.COM", "main.deskrally.com.", "main.deskrally.com:443", "acme.deskrally.com"} {
		if got := gateDo(h, host, "/auth/session", marked); got != http.StatusNoContent {
			t.Errorf("marked %q: %d, want 204", host, got)
		}
	}
	// Marked + refused authority: 421, and the handler is never reached.
	before := hits.Load()
	for _, host := range []string{"main.deskrally.com:8443", "evil.example.com", "unlisted.deskrally.com", "127.0.0.1", "main.deskrally.com..", "controlplane:8081"} {
		if got := gateDo(h, host, "/auth/session", marked); got != http.StatusMisdirectedRequest {
			t.Errorf("marked %q: %d, want 421", host, got)
		}
	}
	// A forged / wrong / repeated marker is untrusted: 421 even for a good host.
	for name, hdr := range map[string]map[string][]string{
		"wrong":    {EdgeMarkerHeader: {"nope-nope-nope-nope-nope-nope-nope-nope"}},
		"prefix":   {EdgeMarkerHeader: {gateSecret[:20]}},
		"repeated": {EdgeMarkerHeader: {gateSecret, gateSecret}},
		"empty":    {EdgeMarkerHeader: {""}},
	} {
		if got := gateDo(h, "main.deskrally.com", "/auth/session", hdr); got != http.StatusMisdirectedRequest {
			t.Errorf("%s marker: %d, want 421", name, got)
		}
	}
	// Duplicate Host header values: refused.
	if got := gateDo(h, "main.deskrally.com", "/auth/session", map[string][]string{
		EdgeMarkerHeader: {gateSecret}, "Host": {"main.deskrally.com", "main.deskrally.com"}}); got != http.StatusMisdirectedRequest {
		t.Errorf("duplicate Host: %d, want 421", got)
	}
	if hits.Load() != before {
		t.Errorf("a refused request reached the handler (%d -> %d): refusal must precede every handler", before, hits.Load())
	}

	// INTERNAL callers: no marker, service-name Host, no allowlist membership needed. Unaffected.
	hits.Store(0)
	for _, c := range []struct{ host, path string }{
		{"controlplane:8081", "/internal/session-tickets/redeem"},
		{"controlplane:8081", "/internal/devices/x/identity"},
		{"controlplane", "/healthz"},
		{"controlplane:8081", "/readyz"},
		{"controlplane:8081", "/attended-sessions/redeem"},
		{"127.0.0.1:8081", "/auth/login"},
	} {
		if got := gateDo(h, c.host, c.path, nil); got != http.StatusNoContent {
			t.Errorf("internal %s %s: %d, want 204", c.host, c.path, got)
		}
	}
	// A marked request to an exempt route is not authority-gated either (the routes have their own auth).
	if got := gateDo(h, "controlplane:8081", "/healthz", marked); got != http.StatusNoContent {
		t.Errorf("marked /healthz: %d, want 204", got)
	}
	// X-Forwarded-Host is never consulted: a good Host with a hostile forwarded header is judged on Host.
	if got := gateDo(h, "main.deskrally.com", "/auth/session", map[string][]string{
		EdgeMarkerHeader: {gateSecret}, "X-Forwarded-Host": {"evil.example.com"}, "Forwarded": {"host=evil.example.com"}}); got != http.StatusNoContent {
		t.Errorf("X-Forwarded-Host must not matter: %d", got)
	}
	if got := gateDo(h, "evil.example.com", "/auth/session", map[string][]string{
		EdgeMarkerHeader: {gateSecret}, "X-Forwarded-Host": {"main.deskrally.com"}}); got != http.StatusMisdirectedRequest {
		t.Errorf("a forwarded host must not rescue a bad Host: %d", got)
	}
}

func TestEdgeGateNotInstalledWithoutASecret(t *testing.T) {
	p := testPolicy(t, "")
	var hits atomic.Int32
	h := p.EdgeAuthorityGate(gateProbe(&hits))
	if got := gateDo(h, "evil.example.com", "/auth/session", map[string][]string{EdgeMarkerHeader: {"whatever"}}); got != http.StatusNoContent {
		t.Errorf("no secret configured: the gate must not exist, got %d", got)
	}
	if got := (*HostPolicy)(nil).EdgeAuthorityGate(gateProbe(&hits)); got == nil {
		t.Error("nil policy must return the next handler")
	}
}

// Through the real Handler(): a marked, bad-authority request never reaches a store (no DB query) and the
// internal routes still work with no marker.
func TestEdgeGateInFrontOfTheRealHandlerMakesNoStoreCall(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.HostPolicy = testPolicy(t, gateSecret)
	counting := &countingAttended{AttendedStore: srv.Attended}
	srv.Attended = counting
	h := srv.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/attended-sessions/redeem", strings.NewReader(`{"code":"X","pubkey":"`+attendTestPubkey+`"}`))
	req.Host = "evil.example.com"
	req.Header.Set(EdgeMarkerHeader, gateSecret)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("forged Host with a valid marker: %d, want 421", rec.Code)
	}
	if counting.calls.Load() != 0 {
		t.Fatalf("the store was called %d times behind a refused authority", counting.calls.Load())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/healthz", nil)
	req.Host = "controlplane:8081"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health probe with a service-name Host: %d", rec.Code)
	}
}

type countingAttended struct {
	AttendedStore
	calls atomic.Int32
}

func (c *countingAttended) RedeemScoped(ctx context.Context, code, pub, name string, scope RedeemScope) (*AttendedRedeem, error) {
	c.calls.Add(1)
	return c.AttendedStore.RedeemScoped(ctx, code, pub, name, scope)
}

func (c *countingAttended) Redeem(ctx context.Context, code, pub, name string) (*AttendedRedeem, error) {
	c.calls.Add(1)
	return c.AttendedStore.Redeem(ctx, code, pub, name)
}
