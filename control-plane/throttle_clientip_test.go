package controlplane

// Tests for clientIP — the throttling identity of a request's source.
//
// This file exists because clientIP had NO test at all, and the gap hid a real defect: the function
// read RemoteAddr unconditionally, so behind the reverse proxy that docs/18 puts in front of the
// whole stack, every request arrived with the proxy's container address. Every per-IP bucket
// collapsed into ONE — meaning `/auth/login` metered all users together, one attacker could lock out
// the entire deployment, and per-source brute-force protection was silently gone in exactly the
// deployment shape the product ships.
//
// Each positive below is paired with a NEGATIVE control, because a test that only asserts the
// trusting mode passes just as happily against a function that trusts the header unconditionally —
// which would be a worse bug than the one being fixed (an attacker could then mint unlimited throttle
// identities by varying a header).

import (
	"net"
	"testing"
)

// withTrustedProxy sets the process-wide trust flag for one test and restores it afterwards.
//
// The flag is package-level state (see SetTrustProxyForClientIP for why), so a test that leaves it
// set would silently change the meaning of every later test in the package. Restoring the PREVIOUS
// value rather than hardcoding false keeps that true regardless of nesting.
func withTrustedProxy(t *testing.T, trust bool) {
	t.Helper()
	prev := trustProxyForClientIP.Load()
	SetTrustProxyForClientIP(trust)
	t.Cleanup(func() { SetTrustProxyForClientIP(prev) })
}

// The default: X-Forwarded-For is attacker-settable, so an untrusting deployment must ignore it
// entirely. Without this control, a fix that always trusted the header would look correct.
func TestClientIPIgnoresForwardedForWhenNoProxyIsTrusted(t *testing.T) {
	withTrustedProxy(t, false)

	got := clientIP(reqFrom("203.0.113.9:44321", "198.51.100.7"))
	if got != "203.0.113.9" {
		t.Fatalf("with no trusted proxy clientIP must be the RemoteAddr host; got %q", got)
	}
}

func TestClientIPBehindATrustedProxyIsTheForwardedClient(t *testing.T) {
	withTrustedProxy(t, true)

	// RemoteAddr is the proxy (a Docker bridge address, as it is under docs/18's compose stack).
	got := clientIP(reqFrom("172.18.0.4:51000", "198.51.100.7"))
	if got != "198.51.100.7" {
		t.Fatalf("behind a trusted proxy clientIP must be the forwarded client; got %q", got)
	}
}

// The header is only safe to read because the RIGHTMOST hop is taken — the one the trusted proxy
// itself appended. Anything an attacker sets arrives to its left.
func TestClientIPTakesTheRightmostHopSoAnInjectedOneCannotWin(t *testing.T) {
	withTrustedProxy(t, true)

	// The client sent "X-Forwarded-For: 10.9.9.9" hoping to be metered as that address; Caddy
	// appended the address it actually saw.
	got := clientIP(reqFrom("172.18.0.4:51000", "10.9.9.9, 198.51.100.7"))
	if got != "198.51.100.7" {
		t.Fatalf("clientIP must take the rightmost (proxy-appended) hop, not an injected one; got %q", got)
	}
}

// A garbage header must not become a throttle identity of its own: falling back to RemoteAddr keeps
// one source from minting unlimited buckets by sending unparseable values.
func TestClientIPFallsBackToRemoteAddrWhenTheForwardedHopIsUnparseable(t *testing.T) {
	withTrustedProxy(t, true)

	for _, xff := range []string{"not-an-ip", "198.51.100.7, banana", ""} {
		if got := clientIP(reqFrom("172.18.0.4:51000", xff)); got != "172.18.0.4" {
			t.Fatalf("XFF %q: unparseable forwarded hop must fall back to RemoteAddr; got %q", xff, got)
		}
	}

	// And when RemoteAddr is not an IP literal either, the raw RemoteAddr is the identity.
	//
	// This case is what makes the nil check load-bearing, and a first draft of this test missed it:
	// with a parseable RemoteAddr, dropping the check is EQUIVALENT (resolveClientIP re-parses
	// RemoteAddr itself and succeeds), so the mutation survived. It only diverges here, where
	// resolveClientIP returns nil and `nil.String()` is the string "<nil>" — collapsing every such
	// request into ONE shared throttle bucket, silently and without an error.
	if got := clientIP(reqFrom("@unix-socket", "banana")); got != "@unix-socket" {
		t.Fatalf("a RemoteAddr that is not an IP literal must be its own identity, not a shared "+
			"placeholder; got %q", got)
	}
}

// withTrustedProxyNets sets the F14-secure nets for one test and restores both atomics afterwards.
// It also arms trustProxyForClientIP (SetTrustedProxyNets does this when nets is non-empty), and
// restores it to its prior value so tests remain independent.
func withTrustedProxyNets(t *testing.T, nets []*net.IPNet) {
	t.Helper()
	prevBool := trustProxyForClientIP.Load()
	prevNetsPtr := trustedProxyNetsForClientIP.Load()
	SetTrustedProxyNets(nets)
	t.Cleanup(func() {
		trustProxyForClientIP.Store(prevBool)
		trustedProxyNetsForClientIP.Store(prevNetsPtr)
	})
}

// TestClientIPTrustedNetsGatesXFFToPeer is the F14 regression for the throttle path.
//
// A peer NOT in the trusted subnet must be judged on RemoteAddr — its XFF header is attacker-set
// and must not change the throttle bucket. The negative control (legacy path, trust=true) shows
// what the OLD code would return, closing the mutation gap.
func TestClientIPTrustedNetsGatesXFFToPeer(t *testing.T) {
	nets, _ := ParseTrustedProxies("172.18.0.0/24")
	withTrustedProxyNets(t, nets)

	// Untrusted peer (192.168.99.1 ∉ 172.18.0.0/24): XFF must be ignored.
	// The attacker sends XFF=10.1.2.3 hoping to steal the victim's throttle identity.
	got := clientIP(reqFrom("192.168.99.1:12345", "10.1.2.3"))
	if got != "192.168.99.1" {
		t.Fatalf("untrusted peer: want RemoteAddr 192.168.99.1, got %q (XFF must not be honoured)", got)
	}

	// Negative control: same peer with the legacy bool path (no nets) would honour XFF.
	// If this half also returns the RemoteAddr, the positive above proves nothing.
	withTrustedProxy(t, true)
	trustedProxyNetsForClientIP.Store(nil) // force legacy path for this sub-check
	gotLegacy := clientIP(reqFrom("192.168.99.1:12345", "10.1.2.3"))
	if gotLegacy != "10.1.2.3" {
		t.Fatalf("negative control: legacy path should honour XFF from any peer; got %q", gotLegacy)
	}
}

// TestClientIPTrustedPeerHonorsXFFWithNets is the positive path of the F14 throttle fix.
// A peer in the trusted subnet is allowed to set XFF; the client behind the proxy is the bucket key.
func TestClientIPTrustedPeerHonorsXFFWithNets(t *testing.T) {
	nets, _ := ParseTrustedProxies("172.18.0.0/24")
	withTrustedProxyNets(t, nets)

	// Trusted peer (172.18.0.4 ∈ 172.18.0.0/24): XFF should be used.
	got := clientIP(reqFrom("172.18.0.4:51000", "10.1.2.3"))
	if got != "10.1.2.3" {
		t.Fatalf("trusted peer: want XFF 10.1.2.3, got %q", got)
	}

	// Negative control: trusted peer with no XFF falls back to its own address.
	got2 := clientIP(reqFrom("172.18.0.4:51000", ""))
	if got2 != "172.18.0.4" {
		t.Fatalf("trusted peer, no XFF: want 172.18.0.4, got %q", got2)
	}
}

// SetTrustProxy must arm BOTH readers of the setting. Asserting the allow-list half alone is what
// let the two drift apart in the first place.
func TestSetTrustProxyArmsTheAllowlistAndTheThrottleTogether(t *testing.T) {
	withTrustedProxy(t, false)
	srv := &Server{}

	srv.SetTrustProxy(true)
	if !srv.trustProxyIP {
		t.Error("SetTrustProxy(true) did not arm the allow-list's copy")
	}
	if got := clientIP(reqFrom("172.18.0.4:51000", "198.51.100.7")); got != "198.51.100.7" {
		t.Errorf("SetTrustProxy(true) did not arm the throttle's copy: clientIP = %q", got)
	}

	srv.SetTrustProxy(false)
	if srv.trustProxyIP {
		t.Error("SetTrustProxy(false) did not disarm the allow-list's copy")
	}
	if got := clientIP(reqFrom("172.18.0.4:51000", "198.51.100.7")); got != "172.18.0.4" {
		t.Errorf("SetTrustProxy(false) did not disarm the throttle's copy: clientIP = %q", got)
	}
}

// TestSetTrustedProxiesArmsAllowlistAndThrottleTogether proves that SetTrustedProxies keeps the
// allow-list and throttle in sync — the same defect SetTrustProxy fixed, now for the nets variant.
func TestSetTrustedProxiesArmsAllowlistAndThrottleTogether(t *testing.T) {
	nets, _ := ParseTrustedProxies("172.18.0.0/24")

	// Restore atomics after test.
	prevBool := trustProxyForClientIP.Load()
	prevNetsPtr := trustedProxyNetsForClientIP.Load()
	t.Cleanup(func() {
		trustProxyForClientIP.Store(prevBool)
		trustedProxyNetsForClientIP.Store(prevNetsPtr)
	})

	allow, _ := ParseIPAllowlist("10.0.0.0/8", false)
	srv := &Server{IPAllowlist: allow}
	srv.SetTrustedProxies(nets)

	// Allow-list must have the nets and be in F14 mode.
	if srv.IPAllowlist.trustedProxyNets == nil {
		t.Error("SetTrustedProxies did not propagate nets to IPAllowlist")
	}
	if !srv.IPAllowlist.trustProxy {
		t.Error("SetTrustedProxies did not arm trustProxy on IPAllowlist")
	}

	// Throttle path: untrusted peer (8.8.8.8 ∉ 172.18.0.0/24) must not use XFF.
	if got := clientIP(reqFrom("8.8.8.8:1234", "10.1.2.3")); got != "8.8.8.8" {
		t.Errorf("throttle: untrusted peer XFF must be ignored; got %q", got)
	}
	// Throttle path: trusted peer (172.18.0.4 ∈ 172.18.0.0/24) must use XFF.
	if got := clientIP(reqFrom("172.18.0.4:51000", "10.1.2.3")); got != "10.1.2.3" {
		t.Errorf("throttle: trusted peer XFF must be honoured; got %q", got)
	}

	// Allow-list end-to-end: 10/8 allowlist + trusted proxy nets.
	// Untrusted peer 8.8.8.8 sends XFF=10.1.2.3 (spoofing attack): must be denied.
	if allow.Allows(reqFrom("8.8.8.8:1234", "10.1.2.3")) {
		t.Error("allow-list: untrusted peer with spoofed XFF must be denied")
	}
	// Trusted peer 172.18.0.4 sends XFF=10.1.2.3: must be allowed (10.1.2.3 ∈ 10/8).
	if !allow.Allows(reqFrom("172.18.0.4:51000", "10.1.2.3")) {
		t.Error("allow-list: trusted peer with valid XFF must be allowed")
	}
}

// THE PROPERTY THE FINDING WAS ABOUT, asserted end to end against a real Throttle rather than on
// clientIP's return value alone: two distinct clients arriving through ONE proxy must land in
// SEPARATE per-IP buckets, so exhausting one does not lock out the other.
//
// The negative control in the same test is what gives it teeth — it reproduces the original defect
// (both clients in one bucket) by flipping only the trust flag. A test asserting just the trusting
// half would pass against a build where the throttle keyed on something unique-per-request, which
// would be no throttle at all.
func TestPerIPThrottleKeepsSeparateBucketsBehindATrustedProxy(t *testing.T) {
	const proxy = "172.18.0.4:51000"
	attacker, bystander := "198.51.100.7", "198.51.100.8"

	// Exhaust the attacker's free attempts, then ask whether the bystander is still allowed.
	bystanderAllowed := func() bool {
		th := NewThrottle(ThrottleConfig{FreeAttempts: 2})
		for i := 0; i < 6; i++ {
			th.Fail(ipKey("login", clientIP(reqFrom(proxy, attacker))))
		}
		_, ok := th.Allow(ipKey("login", clientIP(reqFrom(proxy, bystander))))
		return ok
	}

	withTrustedProxy(t, true)
	if !bystanderAllowed() {
		t.Fatal("behind a trusted proxy one client's failures locked out a DIFFERENT client: " +
			"the per-IP buckets have collapsed into one")
	}

	// Negative control: the same traffic with the flag off must reproduce the collapse. If this
	// half passes too, the test above proves nothing — the buckets were separating for some other
	// reason and the trust flag is not what is being measured.
	withTrustedProxy(t, false)
	if bystanderAllowed() {
		t.Fatal("negative control failed: with no trusted proxy both clients present as the proxy's " +
			"address, so the bystander MUST be caught by the attacker's lockout. It was not, so this " +
			"test is not measuring the trust flag")
	}
}
