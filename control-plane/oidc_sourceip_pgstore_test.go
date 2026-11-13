package controlplane

// An OIDC login persists the TRUSTED-derived source address and user agent (sourceip.go) on its
// user_session row and its auth.login audit event, exactly as a password login does. The OIDC store
// is Postgres-only (there is no in-memory OIDC store), so this is a pg test; the password-login
// fake/pg scenario lives in sourceip_test.go.

import (
	"net"
	"testing"
)

func TestB2bHTTPLoginPersistsTheTrustedSourceAddress(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux) OIDCSourceIP/1.0"
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	cases := []struct {
		name         string
		trustProxies bool
		remote, xff  string
		want         string
	}{
		{"no proxy trust, spoofed XFF is ignored", false, "198.51.100.7:5555", "6.6.6.6", "198.51.100.7"},
		{"untrusted ipv6 peer, spoofed XFF", false, "[2001:db8:ffff::9]:1234", "6.6.6.6", "2001:db8:ffff::9"},
		{"trust configured, untrusted peer's XFF is ignored", true, "203.0.113.9:1234", "6.6.6.6", "203.0.113.9"},
		{"trusted proxy: the rightmost hop", true, "10.1.2.3:9999", "6.6.6.6, 2001:db8::1", "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := b2bFixture(t)
			t.Cleanup(func() { SetTrustedProxyNets(nil); SetTrustProxyForClientIP(false) })
			if c.trustProxies {
				f.server.SetTrustedProxies([]*net.IPNet{trusted})
			}
			f.remoteAddr, f.forwardedFor, f.userAgent = c.remote, c.xff, ua
			f.link()
			a := f.start("/console/devices")
			f.mint(a, nil)
			w := f.callback(a, "code=callback-code", a.cookie)
			b2bStatus(t, w, 302)
			cookie := f.session(w)
			if cookie == nil {
				t.Fatal("missing session cookie")
			}
			var ip, gotUA, method string
			if err := f.su.QueryRow(f.ctx, `SELECT COALESCE(host(source_ip),''), COALESCE(user_agent,''), login_method
				FROM user_session WHERE token_hash=$1`, HashToken(cookie.Value)).Scan(&ip, &gotUA, &method); err != nil {
				t.Fatal(err)
			}
			if method != "oidc" || ip != c.want || gotUA != ua {
				t.Fatalf("user_session = method %q ip %q ua %q, want oidc %q %q", method, ip, gotUA, c.want, ua)
			}
			var evIP string
			if err := f.su.QueryRow(f.ctx, `SELECT COALESCE(host(source_ip),'') FROM audit_event
				WHERE tenant_id=$1 AND action='auth.login' ORDER BY occurred_at DESC, id DESC LIMIT 1`, f.tenant).Scan(&evIP); err != nil {
				t.Fatal(err)
			}
			if evIP != c.want {
				t.Fatalf("auth.login audit source_ip = %q, want %q", evIP, c.want)
			}
		})
	}
}
