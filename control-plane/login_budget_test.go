package controlplane

// Security review 2026-11-01 #3 (login online-guessing budgets) and #12 (tenant-slug timing
// oracle). The tests are deterministic: time is injected into the Throttle, and the #12 oracle is
// asserted by COUNTING argon2 verifications per branch through loginVerifyHook, never by wall clock.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type slugResolver map[string]string

func (r slugResolver) ResolveTenant(_ context.Context, slug string) (string, error) {
	if id, ok := r[slug]; ok {
		return id, nil
	}
	return "", errors.New("unknown tenant")
}

func loginFrom(t *testing.T, h http.Handler, remote string, req loginRequest) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func countingLoginFixture(t *testing.T, clock *time.Time) (*authFixture, http.Handler, *atomic.Int64) {
	t.Helper()
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "victim@example.com", "the-real-password", RoleTechnician)
	th := NewThrottle(DefaultThrottleConfig)
	th.Now = func() time.Time { return *clock }
	f.auth.Throttle = th
	var verifies atomic.Int64
	f.auth.loginVerifyHook = func(path string) {
		if path == "user" {
			verifies.Add(1)
		}
	}
	return f, f.srv.Handler(), &verifies
}

// (a) A parallel burst from one source cannot all pass the check before any failure lands.
func TestLoginParallelBurstIsBounded(t *testing.T) {
	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	_, h, verifies := countingLoginFixture(t, &clock)

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loginFrom(t, h, "198.51.100.7:4000", loginRequest{Tenant: "tenant-1", Email: "victim@example.com", Password: "guess"})
		}()
	}
	wg.Wait()
	if got, max := verifies.Load(), int64(DefaultThrottleConfig.FreeAttempts+1); got > max {
		t.Fatalf("%d of 40 parallel guesses reached argon2, want <= %d", got, max)
	}
	if verifies.Load() == 0 {
		t.Fatal("no attempt was verified at all; the test is vacuous")
	}
}

// (b) Many sources against ONE account: bounded by the account-wide delay, not by source count.
// And the legitimate owner is delayed (bounded), never locked out.
func TestLoginSprayingOneAccountFromManySourcesIsBounded(t *testing.T) {
	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	_, h, verifies := countingLoginFixture(t, &clock)
	bad := loginRequest{Tenant: "tenant-1", Email: "victim@example.com", Password: "guess"}

	for i := 0; i < 60; i++ {
		loginFrom(t, h, "203.0.113."+itoa(i+1)+":4000", bad)
	}
	if got, max := verifies.Load(), int64(loginAccountFree+1); got > max {
		t.Fatalf("60 sources got %d verifications of one account, want <= %d", got, max)
	}
	// Half a minute later exactly one more guess per 30 s slot is admitted, no matter the source.
	before := verifies.Load()
	clock = clock.Add(loginAccountDelay + time.Second)
	for i := 0; i < 20; i++ {
		loginFrom(t, h, "203.0.113."+itoa(100+i)+":4000", bad)
	}
	if got := verifies.Load() - before; got != 1 {
		t.Fatalf("one 30s slot admitted %d guesses, want 1", got)
	}

	// The owner, from a clean source, is told to wait (bounded Retry-After) and then succeeds.
	good := loginRequest{Tenant: "tenant-1", Email: "victim@example.com", Password: "the-real-password"}
	rec := loginFrom(t, h, "192.0.2.99:5000", good)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("owner during an attack = %d, want 429 (bounded delay)", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After = %q", ra)
	}
	clock = clock.Add(loginAccountDelay + time.Second)
	if rec := loginFrom(t, h, "192.0.2.99:5000", good); rec.Code != http.StatusOK {
		t.Fatalf("owner after the bounded delay = %d, want 200 (no lockout)", rec.Code)
	}
}

// The owner's own successful logins never consume the account-wide budget.
func TestLoginSuccessesDoNotConsumeAccountBudget(t *testing.T) {
	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	_, h, _ := countingLoginFixture(t, &clock)
	good := loginRequest{Tenant: "tenant-1", Email: "victim@example.com", Password: "the-real-password"}
	for i := 0; i < 15; i++ {
		if rec := loginFrom(t, h, "192.0.2.50:5000", good); rec.Code != http.StatusOK {
			t.Fatalf("login %d = %d, want 200", i, rec.Code)
		}
	}
}

// (c) IPv6 sources are throttled per /64, IPv4 per address.
func TestLoginThrottleKeysIPv6ByPrefix64(t *testing.T) {
	for _, tc := range []struct{ a, b string; same bool }{
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff", true},
		{"2001:db8:1:2::1", "2001:db8:1:3::1", false},
		{"192.0.2.1", "192.0.2.2", false},
		{"192.0.2.1", "::ffff:192.0.2.1", true},
		{"fe80::1%eth0", "fe80::2", true},
	} {
		if got := ipKey("login", tc.a) == ipKey("login", tc.b); got != tc.same {
			t.Fatalf("ipKey(%q)==ipKey(%q) is %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}

	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	_, h, verifies := countingLoginFixture(t, &clock)
	// Rotating the interface id inside one /64 AND the target account: only the /64 key links them.
	for i := 0; i < 30; i++ {
		loginFrom(t, h, "[2001:db8:1:2::"+itoa(i+1)+"]:4000",
			loginRequest{Tenant: "tenant-1", Email: "user" + itoa(i) + "@example.com", Password: "guess"})
	}
	_ = verifies // unknown users hash too, but they are labelled "unknown_user"
	rec := loginFrom(t, h, "[2001:db8:1:2::ffff]:4000", loginRequest{Tenant: "tenant-1", Email: "other@example.com", Password: "x"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a fresh address in the attacker's /64 = %d, want 429", rec.Code)
	}
	rec = loginFrom(t, h, "[2001:db8:1:9::1]:4000", loginRequest{Tenant: "tenant-1", Email: "other@example.com", Password: "x"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unrelated /64 = %d, want 401", rec.Code)
	}
}

// (#12) Every branch of the login path performs exactly one argon2 verification.
func TestLoginUnknownTenantBurnsTheSameVerification(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "victim@example.com", "the-real-password", RoleTechnician)
	f.auth.Tenants = slugResolver{"acme": "tenant-1"}
	var mu sync.Mutex
	paths := map[string]int{}
	f.auth.loginVerifyHook = func(p string) { mu.Lock(); paths[p]++; mu.Unlock() }
	h := f.srv.Handler()

	for _, tc := range []struct {
		name, tenant, email, want string
		code                      int
	}{
		{"unknown tenant", "no-such-slug", "victim@example.com", "unknown_tenant", http.StatusUnauthorized},
		{"unknown user", "acme", "nobody@example.com", "unknown_user", http.StatusUnauthorized},
		{"real user, bad password", "acme", "victim@example.com", "user", http.StatusUnauthorized},
	} {
		mu.Lock()
		paths = map[string]int{}
		mu.Unlock()
		rec := loginFrom(t, h, "192.0.2.1:1", loginRequest{Tenant: tc.tenant, Email: tc.email, Password: "wrong"})
		if rec.Code != tc.code {
			t.Fatalf("%s: status %d", tc.name, rec.Code)
		}
		mu.Lock()
		total := 0
		for _, n := range paths {
			total += n
		}
		got := paths[tc.want]
		mu.Unlock()
		if got != 1 || total != 1 {
			t.Fatalf("%s: verifications = %v, want exactly one on %q", tc.name, paths, tc.want)
		}
	}
}
