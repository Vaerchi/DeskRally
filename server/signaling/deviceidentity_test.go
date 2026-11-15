package main

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testIdentityToken = "0123456789abcdef0123456789abcdef" // 32 chars, the configured minimum

// identityStub is a stand-in control plane. It counts requests so the tests can prove what was and
// was not cached, and records the last Authorization header and path.
type identityStub struct {
	status   int
	body     string
	delay    time.Duration
	requests int
	lastAuth string
	lastPath string
}

func (s *identityStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests++
	s.lastAuth = r.Header.Get("Authorization")
	s.lastPath = r.URL.EscapedPath()
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	w.WriteHeader(s.status)
	_, _ = w.Write([]byte(s.body))
}

func okBody(device, tenant, pubkey string) string {
	return fmt.Sprintf(`{"device_id":%q,"tenant_id":%q,"pubkey":%q}`, device, tenant, pubkey)
}

// testResolver wires a resolver at a stub control plane with an injectable clock.
func testResolver(t *testing.T, stub *identityStub) (*httpIdentityResolver, *time.Time) {
	t.Helper()
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	r, err := newHTTPIdentityResolver(srv.URL, testIdentityToken)
	if err != nil {
		t.Fatalf("newHTTPIdentityResolver: %v", err)
	}
	clock := time.Now()
	r.now = func() time.Time { return clock }
	return r, &clock
}

func TestIdentityResolverFetchesAndValidates(t *testing.T) {
	stub := &identityStub{
		status: http.StatusOK,
		body:   okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, strings.ToUpper(agentAuthGoldenPubkeyHex)),
	}
	r, _ := testResolver(t, stub)

	got, err := r.Resolve(context.Background(), agentAuthGoldenDevice)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.TenantID != agentAuthGoldenTenant {
		t.Fatalf("tenant = %q, want %q", got.TenantID, agentAuthGoldenTenant)
	}
	// The pinned key is canonicalized to lowercase hex, which is what Peer.Pubkey pins.
	if got.Pubkey != agentAuthGoldenPubkeyHex {
		t.Fatalf("pubkey = %q, want lowercase %q", got.Pubkey, agentAuthGoldenPubkeyHex)
	}
	if stub.lastAuth != "Bearer "+testIdentityToken {
		t.Fatalf("Authorization = %q, want the bearer service token", stub.lastAuth)
	}
	if want := "/internal/devices/" + agentAuthGoldenDevice + "/identity"; stub.lastPath != want {
		t.Fatalf("path = %q, want %q", stub.lastPath, want)
	}
}

// A device id with URL-significant characters must not be able to reshape the request path.
func TestIdentityResolverEscapesDeviceID(t *testing.T) {
	stub := &identityStub{status: http.StatusNotFound, body: `{"error":"unknown device"}`}
	r, _ := testResolver(t, stub)

	_, _ = r.Resolve(context.Background(), "../../admin?x=1")
	// The escaped path still has exactly the three literal segments — the device id cannot climb
	// out of its own segment or start a query string.
	if want := "/internal/devices/..%2F..%2Fadmin%3Fx=1/identity"; stub.lastPath != want {
		t.Fatalf("device id was not escaped into the path:\n got  %q\n want %q", stub.lastPath, want)
	}
}

func TestIdentityResolverPositiveCacheAndExpiry(t *testing.T) {
	stub := &identityStub{
		status: http.StatusOK,
		body:   okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, agentAuthGoldenPubkeyHex),
	}
	r, clock := testResolver(t, stub)

	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if stub.requests != 1 {
		t.Fatalf("%d control-plane requests, want 1 (cached)", stub.requests)
	}

	// Just inside the TTL: still cached. Past it: re-fetched, never served stale.
	*clock = clock.Add(deviceIdentityPositiveTTL - time.Second)
	if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if stub.requests != 1 {
		t.Fatalf("%d requests before TTL expiry, want 1", stub.requests)
	}
	*clock = clock.Add(2 * time.Second)
	if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if stub.requests != 2 {
		t.Fatalf("%d requests after TTL expiry, want 2", stub.requests)
	}
}

// A 404 is cached only briefly, so a machine that re-enrols is authenticatable within seconds
// rather than being locked out for a full positive TTL.
func TestIdentityResolverNegativeCacheIsShortLived(t *testing.T) {
	stub := &identityStub{status: http.StatusNotFound, body: `{"error":"unknown device"}`}
	r, clock := testResolver(t, stub)

	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); !errors.Is(err, ErrDeviceUnknown) {
			t.Fatalf("Resolve = %v, want ErrDeviceUnknown", err)
		}
	}
	if stub.requests != 1 {
		t.Fatalf("%d requests, want 1 (negative cached)", stub.requests)
	}
	if deviceIdentityNegativeTTL >= deviceIdentityPositiveTTL {
		t.Fatal("the negative TTL must be shorter than the positive one")
	}

	// After the negative TTL the device is looked up again — and a fresh enrollment resolves.
	*clock = clock.Add(deviceIdentityNegativeTTL + time.Second)
	stub.status = http.StatusOK
	stub.body = okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, agentAuthGoldenPubkeyHex)
	got, err := r.Resolve(context.Background(), agentAuthGoldenDevice)
	if err != nil {
		t.Fatalf("re-enrolled device: %v", err)
	}
	if got.Pubkey != agentAuthGoldenPubkeyHex {
		t.Fatalf("pubkey = %q after re-enrollment", got.Pubkey)
	}
}

// Transport/config failures fail CLOSED and are never cached: the very next registration retries.
func TestIdentityResolverFailuresAreNotCached(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, `{"error":"could not resolve device identity"}`},
		{"unauthorized", http.StatusUnauthorized, `{"error":"unauthorized"}`},
		{"malformed body", http.StatusOK, `not json`},
		{"pubkey not hex", http.StatusOK, okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, "nothex")},
		{"pubkey wrong length", http.StatusOK, okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, "aabb")},
		{"no tenant", http.StatusOK, okBody(agentAuthGoldenDevice, "", agentAuthGoldenPubkeyHex)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &identityStub{status: tt.status, body: tt.body}
			r, _ := testResolver(t, stub)

			for i := 0; i < 2; i++ {
				_, err := r.Resolve(context.Background(), agentAuthGoldenDevice)
				if err == nil {
					t.Fatal("expected a failure")
				}
				if errors.Is(err, ErrDeviceUnknown) {
					t.Fatalf("a transport failure must not be reported as ErrDeviceUnknown: %v", err)
				}
			}
			if stub.requests != 2 {
				t.Fatalf("%d requests, want 2 — failures must never be cached", stub.requests)
			}
		})
	}
}

func TestIdentityResolverTimesOut(t *testing.T) {
	stub := &identityStub{
		status: http.StatusOK,
		body:   okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, agentAuthGoldenPubkeyHex),
		delay:  300 * time.Millisecond,
	}
	r, _ := testResolver(t, stub)
	r.client.Timeout = 30 * time.Millisecond

	if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); err == nil {
		t.Fatal("a hung control plane must fail the lookup, not hang the registration")
	}
	// A hung lookup must not poison the cache either.
	if _, _, ok := r.cached(agentAuthGoldenDevice); ok {
		t.Fatal("a timed-out lookup must not be cached")
	}
}

func TestIdentityResolverCacheCap(t *testing.T) {
	stub := &identityStub{status: http.StatusNotFound}
	r, _ := testResolver(t, stub)
	for i := 0; i < deviceIdentityCacheEntries+2; i++ {
		r.store(fmt.Sprintf("dev-%d", i), nil, deviceIdentityNegativeTTL)
	}
	if len(r.cache) > deviceIdentityCacheEntries {
		t.Fatalf("cache grew to %d entries, cap is %d", len(r.cache), deviceIdentityCacheEntries)
	}
}

func TestNewHTTPIdentityResolverValidatesConfig(t *testing.T) {
	if _, err := newHTTPIdentityResolver("https://cp.example:8443", "short"); err == nil {
		t.Fatal("a token shorter than the minimum must be refused at wiring time")
	}
	for _, bad := range []string{"", "cp.example:8443", "ftp://cp.example", "://nope"} {
		if _, err := newHTTPIdentityResolver(bad, testIdentityToken); err == nil {
			t.Fatalf("base URL %q was accepted", bad)
		}
	}
	r, err := newHTTPIdentityResolver("https://cp.example:8443/", testIdentityToken)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if r.baseURL != "https://cp.example:8443" {
		t.Fatalf("baseURL = %q, want the trailing slash trimmed", r.baseURL)
	}
}

func TestIdentityResolverFromEnv(t *testing.T) {
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", "")
	// Unset is reported as (nil, nil); main() is what turns that into a fatal startup error unless
	// -insecure-no-agent-auth was passed.
	if r, err := identityResolverFromEnv(); r != nil || err != nil {
		t.Fatalf("unset = (%v, %v), want (nil, nil)", r, err)
	}

	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "https://cp.example:8443")
	if r, err := identityResolverFromEnv(); r != nil || err != nil {
		t.Fatalf("url without token = (%v, %v), want (nil, nil)", r, err)
	}

	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", "too-short")
	if _, err := identityResolverFromEnv(); err == nil {
		t.Fatal("a short token must be a startup error, not a silent downgrade")
	}

	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", "  "+testIdentityToken+"  ")
	r, err := identityResolverFromEnv()
	if err != nil || r == nil {
		t.Fatalf("valid env = (%v, %v), want a resolver", r, err)
	}
}

// TestEvictionNegativeOverflowPreservesPositive confirms that flooding the cache with negative
// entries does not evict a still-valid positive, and that the positive is served from cache
// without any upstream HTTP request.
func TestEvictionNegativeOverflowPreservesPositive(t *testing.T) {
	stub := &identityStub{status: http.StatusOK,
		body: okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, agentAuthGoldenPubkeyHex)}
	r, _ := testResolver(t, stub)
	if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); err != nil {
		t.Fatal(err)
	}
	// An evicted positive now fails, rather than being silently re-fetched.
	stub.status = http.StatusNotFound

	// Repeatedly overflow while one fetched identity remains valid.
	for i := 0; i < deviceIdentityCacheEntries*2+10; i++ {
		r.store(fmt.Sprintf("neg-%d", i), nil, deviceIdentityNegativeTTL)
	}

	reqsBefore := stub.requests
	got, err := r.Resolve(context.Background(), agentAuthGoldenDevice)
	if err != nil || got == nil || got.Pubkey != agentAuthGoldenPubkeyHex {
		t.Fatalf("positive lost under overflow: got=%v err=%v", got, err)
	}
	if stub.requests != reqsBefore {
		t.Fatal("cache hit triggered an upstream HTTP request")
	}

	r.mu.Lock()
	n := len(r.cache)
	r.mu.Unlock()
	if n > deviceIdentityCacheEntries {
		t.Fatalf("cache size %d exceeds cap %d", n, deviceIdentityCacheEntries)
	}
}

// TestEvictionPositiveAdmittedAtNegativeCapacity confirms that a positive entry is admitted into
// a full negative cache by evicting the oldest negative.
func TestEvictionPositiveAdmittedAtNegativeCapacity(t *testing.T) {
	stub := &identityStub{status: http.StatusNotFound}
	r, _ := testResolver(t, stub)

	for i := 0; i < deviceIdentityCacheEntries; i++ {
		r.store(fmt.Sprintf("neg-%d", i), nil, deviceIdentityNegativeTTL)
	}

	r.store("known", &DeviceIdentity{DeviceID: "known", TenantID: agentAuthGoldenTenant, Pubkey: agentAuthGoldenPubkeyHex}, deviceIdentityPositiveTTL)

	got, err, ok := r.cached("known")
	if !ok || err != nil || got == nil {
		t.Fatal("positive entry was not admitted into a full negative cache")
	}

	if _, _, ok := r.cached("neg-0"); ok {
		t.Fatal("oldest negative not evicted")
	}
	if _, err, ok := r.cached("neg-1"); !ok || !errors.Is(err, ErrDeviceUnknown) {
		t.Fatal("positive admission flushed unrelated negatives")
	}

	r.mu.Lock()
	n := len(r.cache)
	r.mu.Unlock()
	if n > deviceIdentityCacheEntries {
		t.Fatalf("cache size %d exceeds cap %d after positive admission", n, deviceIdentityCacheEntries)
	}
}

// TestEvictionPositiveOnlyFullRefusesNegativeAdmitsPositive verifies the asymmetric policy: a
// full positive-only cache declines a new negative but admits a new positive (by evicting the
// oldest positive).
func TestEvictionPositiveOnlyFullRefusesNegativeAdmitsPositive(t *testing.T) {
	stub := &identityStub{status: http.StatusNotFound}
	r, _ := testResolver(t, stub)

	first := "pos-0"
	for i := 0; i < deviceIdentityCacheEntries; i++ {
		id := fmt.Sprintf("pos-%d", i)
		r.store(id, &DeviceIdentity{DeviceID: id, TenantID: agentAuthGoldenTenant, Pubkey: agentAuthGoldenPubkeyHex}, deviceIdentityPositiveTTL)
	}

	// A new negative must be declined silently.
	r.store("neg-new", nil, deviceIdentityNegativeTTL)
	if _, _, ok := r.cached("neg-new"); ok {
		t.Fatal("negative entry was admitted into a full positive-only cache")
	}

	// A new positive must evict the oldest positive.
	r.store("pos-new", &DeviceIdentity{DeviceID: "pos-new", TenantID: agentAuthGoldenTenant, Pubkey: agentAuthGoldenPubkeyHex}, deviceIdentityPositiveTTL)
	if _, err, ok := r.cached("pos-new"); !ok || err != nil {
		t.Fatal("new positive was not admitted into a full positive-only cache")
	}
	if _, _, ok := r.cached(first); ok {
		t.Fatalf("oldest positive %q was not evicted to make room for the new positive", first)
	}

	r.mu.Lock()
	n := len(r.cache)
	r.mu.Unlock()
	if n > deviceIdentityCacheEntries {
		t.Fatalf("cache size %d exceeds cap %d", n, deviceIdentityCacheEntries)
	}
}

// TestEvictionUpdateAtCapacityPreservesNeighbors verifies that refreshing an existing entry at
// capacity does not disturb neighbours and leaves the queue and map lengths in sync (no orphan nodes).
func TestEvictionUpdateAtCapacityPreservesNeighbors(t *testing.T) {
	stub := &identityStub{status: http.StatusNotFound}
	r, _ := testResolver(t, stub)

	for i := 0; i < deviceIdentityCacheEntries; i++ {
		id := fmt.Sprintf("pos-%d", i)
		r.store(id, &DeviceIdentity{DeviceID: id, TenantID: "t1", Pubkey: agentAuthGoldenPubkeyHex}, deviceIdentityPositiveTTL)
	}

	const target = "pos-100"
	const neighbor = "pos-101"

	// Refresh the target with a new tenant.
	r.store(target, &DeviceIdentity{DeviceID: target, TenantID: "t2", Pubkey: agentAuthGoldenPubkeyHex}, deviceIdentityPositiveTTL)

	got, err, ok := r.cached(target)
	if !ok || err != nil || got == nil || got.TenantID != "t2" {
		t.Fatalf("refreshed entry not found or stale: ok=%v err=%v got=%v", ok, err, got)
	}
	if _, err, ok := r.cached(neighbor); !ok || err != nil {
		t.Fatalf("neighbor %q was unexpectedly evicted during refresh", neighbor)
	}

	r.mu.Lock()
	mapLen := len(r.cache)
	qLen := r.positiveQ.Len() + r.negativeQ.Len()
	r.mu.Unlock()
	if mapLen != qLen {
		t.Fatalf("queue length %d != map length %d (orphan or missing nodes)", qLen, mapLen)
	}
}

// TestEvictionExactTTLExpiry confirms that a cache entry is evicted on expiry and that its queue
// node is cleaned up, leaving queue and map lengths equal.
func TestEvictionExactTTLExpiry(t *testing.T) {
	stub := &identityStub{
		status: http.StatusOK,
		body:   okBody(agentAuthGoldenDevice, agentAuthGoldenTenant, agentAuthGoldenPubkeyHex),
	}
	r, clock := testResolver(t, stub)

	r.store(agentAuthGoldenDevice, &DeviceIdentity{
		DeviceID: agentAuthGoldenDevice,
		TenantID: agentAuthGoldenTenant,
		Pubkey:   agentAuthGoldenPubkeyHex,
	}, deviceIdentityPositiveTTL)

	// Just inside TTL: still cached.
	*clock = clock.Add(deviceIdentityPositiveTTL - time.Millisecond)
	if _, err, ok := r.cached(agentAuthGoldenDevice); !ok || err != nil {
		t.Fatal("entry expired before its TTL")
	}

	// Exactly at TTL: expired despite the immediately preceding cache hit.
	*clock = clock.Add(time.Millisecond)
	if _, _, ok := r.cached(agentAuthGoldenDevice); ok {
		t.Fatal("entry was served past its TTL")
	}

	r.mu.Lock()
	mapLen := len(r.cache)
	qLen := r.positiveQ.Len() + r.negativeQ.Len()
	r.mu.Unlock()
	if mapLen != 0 || qLen != 0 {
		t.Fatalf("after expiry: map=%d queue=%d (expected both 0)", mapLen, qLen)
	}
	if _, err := r.Resolve(context.Background(), agentAuthGoldenDevice); err != nil {
		t.Fatal(err)
	}
	if stub.requests != 1 {
		t.Fatalf("requests=%d, want one fresh lookup at expiry", stub.requests)
	}

}

// TestEvictionConcurrentBounded verifies that concurrent stores and reads never exceed the cap
// and leave the queue and map in a consistent state. Uses a dedicated resolver with direct cache
// methods to avoid data races on the shared identityStub.
func TestEvictionConcurrentBounded(t *testing.T) {
	r := &httpIdentityResolver{
		cache:     make(map[string]identityCacheEntry),
		positiveQ: list.New(),
		negativeQ: list.New(),
		now:       time.Now,
	}

	const goroutines = 8
	const opsEach = 1000

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < opsEach; i++ {
				devID := fmt.Sprintf("dev-%d-%d", base, i)
				if i%3 == 0 {
					r.store(devID, &DeviceIdentity{DeviceID: devID, TenantID: "t1", Pubkey: agentAuthGoldenPubkeyHex}, deviceIdentityPositiveTTL)
				} else {
					r.store(devID, nil, deviceIdentityNegativeTTL)
				}
				r.cached(devID)
			}
		}(g * opsEach)
	}
	wg.Wait()

	r.mu.Lock()
	mapLen := len(r.cache)
	qLen := r.positiveQ.Len() + r.negativeQ.Len()
	r.mu.Unlock()
	if mapLen > deviceIdentityCacheEntries {
		t.Fatalf("cache size %d exceeds cap %d after concurrent load", mapLen, deviceIdentityCacheEntries)
	}
	if mapLen != qLen {
		t.Fatalf("queue length %d != map length %d (inconsistent state after concurrent load)", qLen, mapLen)
	}
}

// Refresh can change result class; stale FIFO nodes must not evict its replacement later.
func TestEvictionResultClassTransitions(t *testing.T) {
	r, clock := testResolver(t, &identityStub{status: http.StatusNotFound})
	for i := 0; i < 100; i++ {
		r.store("flip", nil, deviceIdentityNegativeTTL)
		r.store("flip", &DeviceIdentity{DeviceID: "flip"}, deviceIdentityPositiveTTL)
	}
	if r.positiveQ.Len() != 1 || r.negativeQ.Len() != 0 || len(r.cache) != 1 {
		t.Fatal("negative-to-positive refresh retained stale nodes")
	}
	r.store("flip", nil, deviceIdentityNegativeTTL)
	if r.positiveQ.Len() != 0 || r.negativeQ.Len() != 1 || len(r.cache) != 1 {
		t.Fatal("positive-to-negative refresh retained stale nodes")
	}
	*clock = clock.Add(deviceIdentityNegativeTTL)
	if _, _, ok := r.cached("flip"); ok {
		t.Fatal("negative survived exact expiry")
	}
	if r.positiveQ.Len()+r.negativeQ.Len() != 0 || len(r.cache) != 0 {
		t.Fatal("expired negative retained a queue node")
	}
}

func TestSecurityIdentityRejectsOversizeBeforeLookup(t *testing.T) {
	// No client: an attempted network lookup would panic, rather than pass unnoticed.
	resolver := &httpIdentityResolver{cache: make(map[string]identityCacheEntry)}
	for _, id := range []string{"", strings.Repeat("x", 129), strings.Repeat("x", 64000)} {
		if _, err := resolver.Resolve(context.Background(), id); !errors.Is(err, ErrDeviceUnknown) {
			t.Fatalf("oversize identity = %v", err)
		}
	}
	if len(resolver.cache) != 0 {
		t.Fatal("oversize identity entered cache")
	}
}
