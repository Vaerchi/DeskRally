package main

// Tests for source_quota.go — per-source connection quota and trusted-proxy IP resolution.
//
// Unit tests cover: parser, IP resolver, quota state machine (acquire/release/disabled/empty-IP).
// Integration tests exercise the REAL handleWS over an httptest loopback (same pattern as
// websocket_limits_test.go), because a fake conn cannot catch the interaction of the quota
// guard, the admission counters, and the cleanup defer.
//
// Three mutations are proven:
//   (M1) Remove s.sourceQuota.tryAcquire from handleWS → over-quota client passes (integration)
//   (M2) sourceQuota.enabled() always false → same result as M1 (integration)
//   (M3) Remove s.sourceQuota.release from cleanup → closed slot never returns (integration)

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --------------------------------------------------------------------------------------------
// ParseSignalingTrustedProxies
// --------------------------------------------------------------------------------------------

func TestParseSignalingTrustedProxiesEmpty(t *testing.T) {
	nets, err := ParseSignalingTrustedProxies("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nets != nil {
		t.Fatalf("want nil for empty spec, got %v", nets)
	}
}

func TestParseSignalingTrustedProxiesWhitespaceOnly(t *testing.T) {
	nets, err := ParseSignalingTrustedProxies("   ,  ;  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nets != nil {
		t.Fatalf("want nil for whitespace-only spec, got %v", nets)
	}
}

func TestParseSignalingTrustedProxiesValid(t *testing.T) {
	cases := []struct {
		spec    string
		wantLen int
		wantIP  string // check that the first net contains this IP
	}{
		{"192.168.1.0/24", 1, "192.168.1.100"},
		{"172.20.0.0/16,10.0.0.1", 2, "172.20.5.5"},
		{"::1/128", 1, "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			nets, err := ParseSignalingTrustedProxies(tc.spec)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if len(nets) != tc.wantLen {
				t.Fatalf("want %d networks, got %d", tc.wantLen, len(nets))
			}
			if tc.wantIP != "" {
				ip := net.ParseIP(tc.wantIP)
				if !signalingNetContains(nets, ip) {
					t.Fatalf("expected net to contain %s", tc.wantIP)
				}
			}
		})
	}
}

func TestParseSignalingTrustedProxiesInvalid(t *testing.T) {
	cases := []string{
		"not-an-ip",
		"999.999.999.999",
		"192.168.1.0/33",
		"::1/129",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseSignalingTrustedProxies(tc)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc)
			}
		})
	}
}

// --------------------------------------------------------------------------------------------
// signalingClientIP
// --------------------------------------------------------------------------------------------

func makeSourceRequest(t *testing.T, remoteAddr, xff string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestSignalingClientIPDirect(t *testing.T) {
	r := makeSourceRequest(t, "10.0.0.1:12345", "")
	got := signalingClientIP(r, nil)
	if got != "10.0.0.1" {
		t.Fatalf("want 10.0.0.1, got %q", got)
	}
}

func TestSignalingClientIPXFFIgnoredWithoutTrustedNets(t *testing.T) {
	r := makeSourceRequest(t, "10.0.0.1:12345", "1.2.3.4")
	got := signalingClientIP(r, nil)
	// XFF must be ignored when no trusted nets configured.
	if got != "10.0.0.1" {
		t.Fatalf("want RemoteAddr 10.0.0.1 (XFF ignored), got %q", got)
	}
}

func TestSignalingClientIPXFFHonouredFromTrustedPeer(t *testing.T) {
	nets, _ := ParseSignalingTrustedProxies("10.0.0.0/8")
	r := makeSourceRequest(t, "10.0.0.5:12345", "203.0.113.42")
	got := signalingClientIP(r, nets)
	if got != "203.0.113.42" {
		t.Fatalf("want XFF 203.0.113.42 from trusted peer, got %q", got)
	}
}

func TestSignalingClientIPXFFIgnoredFromUntrustedPeer(t *testing.T) {
	nets, _ := ParseSignalingTrustedProxies("10.0.0.0/8")
	// Peer is 172.x, outside the trusted range.
	r := makeSourceRequest(t, "172.16.0.1:12345", "203.0.113.42")
	got := signalingClientIP(r, nets)
	if got != "172.16.0.1" {
		t.Fatalf("want RemoteAddr 172.16.0.1 (XFF ignored for untrusted peer), got %q", got)
	}
}

func TestSignalingClientIPXFFRightmostHopUsed(t *testing.T) {
	// XFF chains: leftmost is client-added, rightmost is what the trusted proxy saw.
	nets, _ := ParseSignalingTrustedProxies("10.0.0.0/8")
	r := makeSourceRequest(t, "10.0.0.2:9999", "5.5.5.5, 6.6.6.6, 7.7.7.7")
	got := signalingClientIP(r, nets)
	if got != "7.7.7.7" {
		t.Fatalf("want rightmost XFF hop 7.7.7.7, got %q", got)
	}
}

func TestSignalingClientIPTrustedPeerBadXFF(t *testing.T) {
	// Trusted peer but XFF is garbage — fall back to RemoteAddr.
	nets, _ := ParseSignalingTrustedProxies("10.0.0.0/8")
	r := makeSourceRequest(t, "10.0.0.1:9999", "not-an-ip")
	got := signalingClientIP(r, nets)
	if got != "10.0.0.1" {
		t.Fatalf("want RemoteAddr fallback 10.0.0.1, got %q", got)
	}
}

func TestSignalingClientIPUnparseable(t *testing.T) {
	r := makeSourceRequest(t, "INVALID", "")
	got := signalingClientIP(r, nil)
	if got != "" {
		t.Fatalf("want empty string for unparseable RemoteAddr, got %q", got)
	}
}

// TestSignalingClientIPIPv4MappedNormalization verifies that "1.2.3.4" and "::ffff:1.2.3.4"
// resolve to the SAME map key. Without normalization an attacker could use the mapped form in
// XFF to obtain a separate quota bucket and double their per-source slot allocation (SEC-001).
func TestSignalingClientIPIPv4MappedNormalization(t *testing.T) {
	nets, _ := ParseSignalingTrustedProxies("10.0.0.0/8")

	// Standard IPv4 XFF.
	r1 := makeSourceRequest(t, "10.0.0.1:9999", "1.2.3.4")
	dotted := signalingClientIP(r1, nets)

	// IPv4-mapped IPv6 XFF for the same address.
	r2 := makeSourceRequest(t, "10.0.0.1:9999", "::ffff:1.2.3.4")
	mapped := signalingClientIP(r2, nets)

	if dotted != mapped {
		t.Fatalf("normalization failed: %q != %q — an attacker can get two buckets for one IP", dotted, mapped)
	}
}

// TestSourceQuotaIPv4MappedSameBucket verifies the normalization at the quota level: a source
// that fills its bucket as "1.2.3.4" cannot then connect again as "::ffff:1.2.3.4".
func TestSourceQuotaIPv4MappedSameBucket(t *testing.T) {
	nets, _ := ParseSignalingTrustedProxies("10.0.0.0/8")
	sq := newSourceQuota(1)

	r1 := makeSourceRequest(t, "10.0.0.1:9999", "1.2.3.4")
	ip1 := signalingClientIP(r1, nets)
	if !sq.tryAcquire(ip1) {
		t.Fatal("first acquire should succeed")
	}

	r2 := makeSourceRequest(t, "10.0.0.1:9999", "::ffff:1.2.3.4")
	ip2 := signalingClientIP(r2, nets)
	if sq.tryAcquire(ip2) {
		t.Fatal("mapped form should share the same bucket and be rejected at cap=1")
	}
}

// --------------------------------------------------------------------------------------------
// sourceQuota unit tests
// --------------------------------------------------------------------------------------------

func TestSourceQuotaDisabledByDefault(t *testing.T) {
	sq := newSourceQuota(0)
	if sq.enabled() {
		t.Fatal("want disabled (maxPerIP=0)")
	}
	// All acquires must succeed regardless of how many we attempt.
	for i := 0; i < 1000; i++ {
		if !sq.tryAcquire("1.2.3.4") {
			t.Fatalf("disabled quota refused acquire at i=%d", i)
		}
	}
}

func TestSourceQuotaAllowsUpToMax(t *testing.T) {
	sq := newSourceQuota(3)
	for i := 0; i < 3; i++ {
		if !sq.tryAcquire("1.2.3.4") {
			t.Fatalf("expected allow on attempt %d", i+1)
		}
	}
}

func TestSourceQuotaRejectsOverMax(t *testing.T) {
	sq := newSourceQuota(2)
	sq.tryAcquire("1.2.3.4")
	sq.tryAcquire("1.2.3.4")
	if sq.tryAcquire("1.2.3.4") {
		t.Fatal("expected rejection on 3rd acquire beyond maxPerIP=2")
	}
}

func TestSourceQuotaReleaseFreeSlot(t *testing.T) {
	sq := newSourceQuota(1)
	if !sq.tryAcquire("1.2.3.4") {
		t.Fatal("first acquire should succeed")
	}
	if sq.tryAcquire("1.2.3.4") {
		t.Fatal("second acquire should fail (at cap)")
	}
	sq.release("1.2.3.4")
	if !sq.tryAcquire("1.2.3.4") {
		t.Fatal("acquire after release should succeed")
	}
}

func TestSourceQuotaReleaseIdempotent(t *testing.T) {
	sq := newSourceQuota(2)
	sq.tryAcquire("1.2.3.4")
	// Release more times than acquired — must not underflow.
	for i := 0; i < 5; i++ {
		sq.release("1.2.3.4")
	}
	// Should be back to zero; a new acquire succeeds.
	if !sq.tryAcquire("1.2.3.4") {
		t.Fatal("acquire after over-release should succeed (idempotent underflow guard)")
	}
}

func TestSourceQuotaEmptyIPPassesThrough(t *testing.T) {
	// An empty IP (unparseable address) must always pass; no slot is incremented so no slot
	// must ever be released. Release("") is a no-op.
	sq := newSourceQuota(1)
	for i := 0; i < 5; i++ {
		if !sq.tryAcquire("") {
			t.Fatalf("empty IP must always be allowed, failed at i=%d", i)
		}
	}
	// Releasing "" must not panic or corrupt state.
	for i := 0; i < 3; i++ {
		sq.release("")
	}
}

func TestSourceQuotaPerIPNotGlobal(t *testing.T) {
	// maxPerIP=1 means 1 per distinct IP, not 1 total.
	sq := newSourceQuota(1)
	if !sq.tryAcquire("10.0.0.1") {
		t.Fatal("first IP should be allowed")
	}
	if !sq.tryAcquire("10.0.0.2") {
		t.Fatal("second IP should also be allowed (different source)")
	}
	if sq.tryAcquire("10.0.0.1") {
		t.Fatal("first IP should be at cap now")
	}
}

func TestSourceQuotaMapCleanupOnRelease(t *testing.T) {
	sq := newSourceQuota(2)
	sq.tryAcquire("1.2.3.4")
	sq.release("1.2.3.4")
	// Map entry should have been deleted (zero count) to prevent unbounded growth.
	sq.mu.Lock()
	_, exists := sq.byIP["1.2.3.4"]
	sq.mu.Unlock()
	if exists {
		t.Fatal("map entry should be cleaned up when count reaches zero")
	}
}

// --------------------------------------------------------------------------------------------
// Integration tests: per-source quota enforced in real handleWS
// --------------------------------------------------------------------------------------------

// newTestSignalingWithSourceQuota extends the existing testSignaling harness to also configure
// a per-source quota and optional trusted proxy nets on the server.
func newTestSignalingWithSourceQuota(t *testing.T, maxPerIP int, trustedNets []*net.IPNet) *testSignaling {
	t.Helper()
	limits := admissionLimits{
		maxTotal:       64,
		maxPending:     32,
		preAuthTimeout: 10 * time.Second,
	}
	ts := newTestSignaling(t, 30*time.Second, nil, nil, limits)
	ts.srv.SetSourceQuota(maxPerIP)
	ts.srv.SetTrustedProxyNets(trustedNets)
	return ts
}

// dialWS attempts one WebSocket dial and returns (conn, httpStatusCode, error).
// A 5xx rejection from the server before upgrade comes back as a non-nil error with a nil conn.
func dialWS(wsURL string) (*websocket.Conn, int, error) {
	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, resp, err := dialer.Dial(wsURL, nil)
	if resp != nil {
		return conn, resp.StatusCode, err
	}
	return conn, 0, err
}

// TestPerSourceQuotaEnforcedInHandleWS: connections from the same source IP (127.0.0.1 in
// httptest) are capped at maxPerIP; the (maxPerIP+1)th attempt gets 503.
//
// MUTATION M1 target: remove s.sourceQuota.tryAcquire(clientIP) from handleWS.
// MUTATION M2 target: sourceQuota.enabled() always returns false.
// Both mutations let the third connection through, so this test FAILS on either.
func TestPerSourceQuotaEnforcedInHandleWS(t *testing.T) {
	const maxPerIP = 2
	ts := newTestSignalingWithSourceQuota(t, maxPerIP, nil)

	var conns []*websocket.Conn
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	// Open maxPerIP connections — all must succeed.
	for i := 0; i < maxPerIP; i++ {
		conn, code, err := dialWS(ts.wsURL)
		if err != nil {
			t.Fatalf("connection %d: want success, got %v (HTTP %d)", i+1, err, code)
		}
		conns = append(conns, conn)
	}

	// (maxPerIP+1)th connection from the same IP must be rejected.
	conn, code, err := dialWS(ts.wsURL)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("expected 503, got a successful WebSocket connection")
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("want HTTP 503, got %d (err: %v)", code, err)
	}
}

// TestPerSourceQuotaSlotReturnedOnClose: closing one of the maxPerIP connections frees its slot
// so a new connection from the same IP can succeed.
//
// MUTATION M3 target: remove s.sourceQuota.release(self.clientIP) from cleanup.
// Without the release the slot stays permanently consumed and the new connection fails.
func TestPerSourceQuotaSlotReturnedOnClose(t *testing.T) {
	const maxPerIP = 1
	ts := newTestSignalingWithSourceQuota(t, maxPerIP, nil)

	conn, code, err := dialWS(ts.wsURL)
	if err != nil {
		t.Fatalf("first connection: want success, got %v (HTTP %d)", err, code)
	}

	// At cap: a second attempt should fail.
	conn2, code2, err2 := dialWS(ts.wsURL)
	if conn2 != nil {
		_ = conn2.Close()
		t.Fatal("at cap: expected rejection, got connection")
	}
	if code2 != http.StatusServiceUnavailable {
		t.Fatalf("at cap: want 503, got %d (err: %v)", code2, err2)
	}

	// Close the first connection to free the slot. Wait for cleanup to run.
	_ = conn.Close()
	// Poll until the slot is freed: the cleanup defer runs in handleWS's goroutine, which
	// may not have woken from ReadMessage yet. A 200 ms poll with a 2 s deadline is ample.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn3, code3, err3 := dialWS(ts.wsURL)
		if err3 == nil {
			_ = conn3.Close()
			return // slot freed, new connection succeeded
		}
		if code3 != http.StatusServiceUnavailable {
			t.Fatalf("unexpected status %d (err: %v) while polling for slot release", code3, err3)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("slot was never returned after closing the first connection (cleanup did not release quota)")
}

// TestPerSourceQuotaDoesNotAffectOtherIPs: the per-source ceiling is per-IP, not global.
// In an httptest environment all clients come from 127.0.0.1. To test isolation we set a high
// maxPerIP and verify the global admission cap is still the binding constraint.
func TestPerSourceQuotaDoesNotAffectOtherIPs(t *testing.T) {
	// Set maxPerIP high enough that it does not bind; the global total (3) is the real cap.
	limits := admissionLimits{maxTotal: 3, maxPending: 3, preAuthTimeout: 10 * time.Second}
	ts := newTestSignaling(t, 30*time.Second, nil, nil, limits)
	ts.srv.SetSourceQuota(100) // per-IP cap >> global cap

	var conns []*websocket.Conn
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	for i := 0; i < 3; i++ {
		conn, code, err := dialWS(ts.wsURL)
		if err != nil {
			t.Fatalf("connection %d: want success, got %v (HTTP %d)", i+1, err, code)
		}
		conns = append(conns, conn)
	}

	// Global cap reached — 4th must fail even though per-IP cap (100) is far from hit.
	_, code, _ := dialWS(ts.wsURL)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 from global cap, got %d", code)
	}
}

// TestPerSourceQuotaDisabledAllowsMany: maxPerIP=0 must not block any connections.
func TestPerSourceQuotaDisabledAllowsMany(t *testing.T) {
	// A tight global cap so the test finishes quickly, but no per-source limit.
	limits := admissionLimits{maxTotal: 10, maxPending: 10, preAuthTimeout: 5 * time.Second}
	ts := newTestSignaling(t, 30*time.Second, nil, nil, limits)
	// Zero = disabled.
	ts.srv.SetSourceQuota(0)

	var conns []*websocket.Conn
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	// Connect up to the global cap — all must succeed (per-source limit is off).
	var mu sync.Mutex
	var wg sync.WaitGroup
	failures := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _, err := dialWS(ts.wsURL)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
			} else {
				conns = append(conns, conn)
			}
		}()
	}
	wg.Wait()
	if failures > 0 {
		t.Fatalf("%d connection(s) failed with per-source quota disabled", failures)
	}
}
