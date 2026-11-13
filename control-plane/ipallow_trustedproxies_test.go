package controlplane

// Tests for the F14 fix: trusted-proxy peer gating of X-Forwarded-For.
//
// Without this fix, any TCP peer that reaches the control plane directly — including a sibling
// container on the same Docker network — can set X-Forwarded-For to an arbitrary IP and bypass
// the IP allow-list or spoof its per-source throttle identity.
//
// With the fix, XFF is only honoured when the TCP peer's address is in the configured
// CP_TRUSTED_PROXIES list. All other peers are judged on their RemoteAddr.
//
// Every positive below is paired with a negative control. The negative is what closes the
// mutation gap: a fix that always ignores XFF would satisfy the "untrusted peer" assertion but
// would break normal proxy traffic, while a fix that always trusts XFF would pass the "trusted
// peer" assertion but leave the spoofing path open.

import (
	"net"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	// Empty / whitespace → nil (no proxies trusted).
	for _, spec := range []string{"", "   ", "\t, ;\n"} {
		nets, err := ParseTrustedProxies(spec)
		if err != nil || nets != nil {
			t.Fatalf("ParseTrustedProxies(%q) = %v, %v; want nil, nil", spec, nets, err)
		}
	}

	// Mixed separators, CIDRs + bare IPs.
	nets, err := ParseTrustedProxies("172.20.0.0/16, 10.0.0.1 ;  ::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies valid: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("parsed %d nets, want 3", len(nets))
	}

	// Bare IPv4 becomes /32: must match exactly that IP and not its neighbour.
	check := func(host string, want bool) {
		t.Helper()
		ip := net.ParseIP(host)
		if got := netContains(nets, ip); got != want {
			t.Fatalf("netContains(%q) = %v, want %v", host, got, want)
		}
	}
	check("10.0.0.1", true)
	check("10.0.0.2", false)
	check("172.20.1.1", true)
	check("172.21.0.1", false)
	check("::1", true)
	check("::2", false)

	// Malformed entries are hard errors.
	for _, bad := range []string{"not-an-ip", "10.0.0.0/999", "banana"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Fatalf("ParseTrustedProxies(%q) should error", bad)
		}
	}
}

// TestResolveClientIPTrustedNetsGatesXFFToPeer is the core F14 regression.
//
// Peer from the trusted subnet → XFF honoured.
// Peer outside the trusted subnet → XFF ignored regardless of trustProxy=true.
//
// The negative (untrusted-peer) case is the mutation target: removing the peer check, the
// netContains call, or the trusted-nets branch all cause it to accept the spoofed XFF and FAIL.
func TestResolveClientIPTrustedNetsGatesXFFToPeer(t *testing.T) {
	nets, _ := ParseTrustedProxies("172.20.0.0/24")

	// Trusted peer (172.20.0.5 ∈ 172.20.0.0/24): XFF should be used.
	r := reqFrom("172.20.0.5:443", "10.1.2.3")
	got := resolveClientIP(r, true, nets)
	if got == nil || got.String() != "10.1.2.3" {
		t.Fatalf("trusted peer: want XFF 10.1.2.3, got %v", got)
	}

	// Negative control: untrusted peer (8.8.8.8 ∉ 172.20.0.0/24): XFF must be ignored.
	// Without F14, this would return the spoofed 10.1.2.3.
	r2 := reqFrom("8.8.8.8:443", "10.1.2.3")
	got2 := resolveClientIP(r2, true, nets)
	if got2 == nil || got2.String() != "8.8.8.8" {
		t.Fatalf("untrusted peer: want RemoteAddr 8.8.8.8, got %v (XFF must be ignored)", got2)
	}
}

func TestResolveClientIPTrustedNetsFallsBackToRemoteAddrForNoXFF(t *testing.T) {
	nets, _ := ParseTrustedProxies("172.20.0.0/24")

	// Trusted peer with no XFF header: RemoteAddr should be returned.
	r := reqFrom("172.20.0.5:443", "")
	got := resolveClientIP(r, true, nets)
	if got == nil || got.String() != "172.20.0.5" {
		t.Fatalf("trusted peer, no XFF: want 172.20.0.5, got %v", got)
	}
}

func TestResolveClientIPLegacyPathUnchangedWhenNoTrustedNets(t *testing.T) {
	// Legacy path (nil trustedNets): trustProxy=true still honours XFF from any peer.
	r := reqFrom("8.8.8.8:443", "10.1.2.3")
	got := resolveClientIP(r, true, nil)
	if got == nil || got.String() != "10.1.2.3" {
		t.Fatalf("legacy path: want XFF 10.1.2.3, got %v", got)
	}

	// Legacy path: trustProxy=false ignores XFF.
	got2 := resolveClientIP(r, false, nil)
	if got2 == nil || got2.String() != "8.8.8.8" {
		t.Fatalf("legacy path no-trust: want RemoteAddr 8.8.8.8, got %v", got2)
	}
}

// TestIPAllowlistTrustedProxyGatesXFFToPeer proves the F14 fix end-to-end: a peer outside the
// trusted proxy list cannot bypass the IP allow-list by spoofing XFF.
//
// Without F14 (trustProxy=true, no nets), the untrusted peer at 8.8.8.8 sends XFF=10.1.2.3
// and the allow-list sees 10.1.2.3 (in 10/8) → allowed. With F14, XFF is ignored and the
// allow-list sees 8.8.8.8 (not in 10/8) → denied.
func TestIPAllowlistTrustedProxyGatesXFFToPeer(t *testing.T) {
	nets, _ := ParseTrustedProxies("172.20.0.0/24")

	a, _ := ParseIPAllowlist("10.0.0.0/8", false)
	a.trustedProxyNets = nets

	// Peer in trusted subnet (172.20.0.5) → XFF honoured → client 10.1.2.3 in 10/8 → allowed.
	if !a.Allows(reqFrom("172.20.0.5:443", "10.1.2.3")) {
		t.Fatal("trusted peer: XFF 10.1.2.3 in allowlist must be allowed")
	}

	// Untrusted peer (8.8.8.8) → XFF ignored → RemoteAddr 8.8.8.8 not in 10/8 → denied.
	// This is the spoofing attack: mutating the peer check here causes the test to fail.
	if a.Allows(reqFrom("8.8.8.8:443", "10.1.2.3")) {
		t.Fatal("untrusted peer: XFF must be ignored; RemoteAddr 8.8.8.8 not in allowlist → must deny")
	}

	// Negative control: a peer that IS in 10/8 (and therefore directly allowed) should still pass
	// without going through any proxy at all.
	if !a.Allows(reqFrom("10.5.6.7:443", "")) {
		t.Fatal("direct client 10.5.6.7 in allowlist must be allowed")
	}
}
