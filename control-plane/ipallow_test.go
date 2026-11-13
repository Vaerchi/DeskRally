package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseIPAllowlist(t *testing.T) {
	// Empty / whitespace → nil (open).
	for _, spec := range []string{"", "   ", "\t, ;\n"} {
		a, err := ParseIPAllowlist(spec, false)
		if err != nil || a != nil {
			t.Fatalf("ParseIPAllowlist(%q) = %v, %v; want nil, nil (open)", spec, a, err)
		}
	}

	// Mixed separators, CIDRs + bare IPs (v4 → /32, v6 → /128).
	a, err := ParseIPAllowlist("10.0.0.0/8, 192.168.1.5 ;  2001:db8::/32\t203.0.113.7", false)
	if err != nil {
		t.Fatalf("parse valid: %v", err)
	}
	if len(a.nets) != 4 {
		t.Fatalf("parsed %d nets, want 4", len(a.nets))
	}

	// A bare IP is a host route: it must match itself and NOT its neighbour.
	if !a.Allows(reqFrom("192.168.1.5:9", "")) {
		t.Fatal("bare IP 192.168.1.5 should allow itself")
	}
	if a.Allows(reqFrom("192.168.1.6:9", "")) {
		t.Fatal("bare IP 192.168.1.5/32 must NOT allow .6")
	}

	// Malformed entries are hard errors — never silently dropped.
	for _, bad := range []string{"not-an-ip", "10.0.0.0/999", "10.0.0.0/33", "banana"} {
		if _, err := ParseIPAllowlist(bad, false); err == nil {
			t.Fatalf("ParseIPAllowlist(%q) should error", bad)
		}
	}
}

func TestIPAllowlistAllows(t *testing.T) {
	// A nil allowlist (unconfigured) allows everything, including a nil receiver.
	var open *IPAllowlist
	if !open.Allows(reqFrom("8.8.8.8:1", "")) {
		t.Fatal("nil allowlist must be open")
	}

	a, err := ParseIPAllowlist("10.0.0.0/8, 2001:db8::/32", false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cases := []struct {
		remote string
		want   bool
	}{
		{"10.1.2.3:5000", true},          // inside 10/8
		{"10.255.255.255:1", true},       // edge of 10/8
		{"11.0.0.1:1", false},            // outside
		{"8.8.8.8:53", false},            // outside
		{"[2001:db8::1]:443", true},      // inside v6 range
		{"[2001:dead::1]:443", false},    // outside v6 range
		{"10.1.2.3", true},               // RemoteAddr with no port still parses
		{"garbage", false},               // unparseable source → deny (cannot be shown on the list)
	}
	for _, c := range cases {
		if got := a.Allows(reqFrom(c.remote, "")); got != c.want {
			t.Fatalf("Allows(remote=%q) = %v, want %v", c.remote, got, c.want)
		}
	}
}

func TestIPAllowlistTrustProxy(t *testing.T) {
	a, _ := ParseIPAllowlist("10.0.0.0/8", true)          // trustProxy ON
	direct, _ := ParseIPAllowlist("10.0.0.0/8", false)    // trustProxy OFF

	// Behind a trusted proxy: the RemoteAddr is the proxy (172.16.0.9, NOT allowed), but the client
	// the proxy reports (rightmost XFF) IS allowed — so trustProxy=true admits it, false does not.
	r := reqFrom("172.16.0.9:443", "203.0.113.1, 10.1.2.3")
	if !a.Allows(r) {
		t.Fatal("trustProxy: rightmost XFF 10.1.2.3 is in 10/8 and must be allowed")
	}
	if direct.Allows(reqFrom("172.16.0.9:443", "10.1.2.3")) {
		t.Fatal("trustProxy OFF must ignore XFF and judge the (disallowed) RemoteAddr 172.16.0.9")
	}

	// A spoofed XFF whose rightmost hop is outside the range is still refused under trustProxy.
	if a.Allows(reqFrom("10.1.2.3:443", "10.1.2.3, 8.8.8.8")) {
		t.Fatal("trustProxy uses the rightmost XFF hop (8.8.8.8, disallowed), not RemoteAddr")
	}
}

// TestIPAllowMiddleware proves the edge middleware refuses a disallowed source with 403 BEFORE auth,
// and lets an allowed source reach the handler — driven through the real Handler() chain.
func TestIPAllowMiddleware(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	allow, _ := ParseIPAllowlist("10.0.0.0/8", false)
	srv.IPAllowlist = allow

	do := func(remote string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/machines", nil)
		req.RemoteAddr = remote
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Denied source → 403 at the edge, with the network message (not a generic auth 401/403).
	if rec := do("8.8.8.8:1234"); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "access from this network is not allowed") {
		t.Fatalf("disallowed IP: got %d %s, want 403 network-refused", rec.Code, rec.Body.String())
	}
	// Allowed source → reaches the handler (200 listing, not the edge 403).
	if rec := do("10.1.2.3:1234"); rec.Code != http.StatusOK {
		t.Fatalf("allowed IP: got %d %s, want 200 (reaches the handler)", rec.Code, rec.Body.String())
	}
	// With no allowlist configured, every source reaches the handler (backward-compatible default).
	srv.IPAllowlist = nil
	if rec := do("8.8.8.8:1234"); rec.Code != http.StatusOK {
		t.Fatalf("unconfigured allowlist must be open: got %d %s", rec.Code, rec.Body.String())
	}
}

// --- helpers ---------------------------------------------------------------

func reqFrom(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest("GET", "/machines", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}
