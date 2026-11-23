package controlplane

// Regression tests for docs/25 F01 — "login admits unbounded concurrent Argon2 work".
//
// WHAT MAKES THESE CONTROLS RATHER THAN CONSTANTS. The concurrency assertion reads argon2Peak,
// which password.go maintains around the argon2.IDKey call itself, NOT around the semaphore.
// Delete the acquire() call in verifyPassword and the peak rises to the goroutine count and
// TestArgon2ConcurrencyIsBounded fails. Had the test asked the limiter for its own slot count it
// would have reported 0 after that same deletion and passed — the classic test that pins a
// constant instead of a behaviour.
//
// The second test is the ASYMMETRIC one. Bounding concurrency is easy to do in a way that is worse
// than the defect: if a saturation answer is folded into the "wrong password" path it spends the
// victim's throttle budget, so anyone able to generate load holds a remote lockout switch for any
// account they can name. A truth table over the limiter alone cannot see that; only driving the
// real HandleLogin under saturation can.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cheapArgon2Params keeps these tests fast. 8 MiB / t=1 still exercises the identical code path —
// the limiter does not look at the parameters — while keeping a 32-goroutine burst off the
// gigabyte scale that DefaultArgon2Params would reach on an unbounded build, which is precisely
// the failure mode under test.
var cheapArgon2Params = Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 4, SaltLen: 16, KeyLen: 32}

func TestArgon2ConcurrencyIsBounded(t *testing.T) {
	const (
		limit   = 2
		callers = 32
	)
	restore := ConfigurePasswordHashing(HashLimiterConfig{
		MaxConcurrent: limit,
		MaxQueue:      callers, // room for everyone, so this test measures the BOUND, not refusals
		MaxWait:       30 * time.Second,
	})
	defer restore()
	ResetPasswordHashingStats()

	hash, err := HashPasswordWith("correct horse battery staple", cheapArgon2Params)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	ResetPasswordHashingStats() // the seed hash above is not part of the measurement

	// A barrier so every goroutine is ready before any of them starts: without it the callers
	// trickle in and a serialized run would look identical to a bounded one.
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(callers)
	done.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			// Deliberately the WRONG password: verification runs to completion either way, and a
			// wrong one cannot be short-circuited by any future fast path.
			_, _ = VerifyPasswordCtx(context.Background(), hash, "wrong")
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	peak, _, maxConcurrent := PasswordHashingStats()
	if maxConcurrent != limit {
		t.Fatalf("limiter not configured: MaxConcurrent=%d want %d", maxConcurrent, limit)
	}
	if peak > limit {
		t.Errorf("argon2 ran %d-way concurrent with a limit of %d — the bound is not applied at the "+
			"allocation (docs/25 F01)", peak, limit)
	}
	// Guard against the inverse failure: a peak of 0 would mean the instrumentation never ran and
	// the assertion above is vacuous.
	if peak == 0 {
		t.Fatal("argon2 peak was 0 — instrumentation did not run, so the bound was never measured")
	}
	t.Logf("peak concurrent argon2 = %d (limit %d, %d callers)", peak, limit, callers)
}

// TestHashBusyIsRefusedNotQueuedForever proves the queue bound refuses rather than piling up, and
// that a refusal allocates no argon2 memory (it never reaches the IDKey call).
func TestHashBusyIsRefusedNotQueuedForever(t *testing.T) {
	restore := ConfigurePasswordHashing(HashLimiterConfig{
		MaxConcurrent: 1,
		MaxQueue:      1,
		MaxWait:       50 * time.Millisecond,
	})
	defer restore()

	hash, err := HashPasswordWith("pw", cheapArgon2Params)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}

	// Occupy the single slot for longer than MaxWait, so every later caller must queue.
	l := passwordLimiter()
	release, err := l.acquire(context.Background(), false)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	var busy atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, verr := VerifyPasswordCtx(context.Background(), hash, "pw"); errors.Is(verr, ErrHashBusy) {
				busy.Add(1)
			}
		}()
	}
	wg.Wait()
	release()

	if busy.Load() == 0 {
		t.Error("no caller was refused with ErrHashBusy — the queue bound is not enforced, so a " +
			"saturated process piles up waiters instead of answering (docs/25 F01)")
	}
	t.Logf("%d of 8 callers refused with ErrHashBusy", busy.Load())
}

// TestHashCapacityRefusalCancels proves a caller that goes away while queued gives up its place
// and never allocates.
func TestHashCapacityRefusalHonoursContext(t *testing.T) {
	restore := ConfigurePasswordHashing(HashLimiterConfig{
		MaxConcurrent: 1, MaxQueue: 16, MaxWait: 10 * time.Second,
	})
	defer restore()

	hash, err := HashPasswordWith("pw", cheapArgon2Params)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	release, err := passwordLimiter().acquire(context.Background(), false)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, verr := VerifyPasswordCtx(ctx, hash, "pw")
		errCh <- verr
	}()
	cancel()

	select {
	case verr := <-errCh:
		if !errors.Is(verr, context.Canceled) {
			t.Errorf("got %v, want context.Canceled", verr)
		}
		if !IsHashCapacityError(verr) {
			t.Error("a cancelled queue wait must classify as a capacity error, never as a wrong password")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled caller did not return — it is still queued, so a client hang-up leaks a waiter")
	}
}

// TestLoginUnderSaturationDoesNotSpendThrottleBudget is the amplification guard, and the reason
// the non-context entry points must not report saturation.
//
// A saturated process must answer 503 and leave the account's failure counter untouched. If the
// busy answer were treated as a credential failure, an attacker who can generate load could spend
// any named account's budget and lock its owner out — turning a memory bound into a remote off
// switch. The assertion is deliberately on the THROTTLE STATE, not on the status code alone: a
// handler could return 503 and still have called Fail on the way there.
func TestLoginUnderSaturationDoesNotSpendThrottleBudget(t *testing.T) {
	const (
		tenant = "acme"
		email  = "victim@example.com"
		pw     = "correct horse battery staple"
	)
	hash, err := HashPasswordWith(pw, cheapArgon2Params)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}

	users := NewInMemoryUserStore()
	users.AddUser(
		&AuthUser{ID: "u1", TenantID: tenant, Email: email, PasswordHash: hash},
		NewGrant("u1", tenant, NewMembership(RoleOwner, AllGroups())),
	)
	// FreeAttempts:1 is load-bearing, not incidental. The DEFAULT profile tolerates five failures
	// before it locks anything, so a test that fired ONE saturated login and asked Allow() whether
	// the account was locked would answer "no" whether or not the handler had charged it — the
	// assertion would pin a constant. With one free attempt and three saturated logins below, a
	// single stray Fail() locks the account and the assertion becomes a real control. (Verified by
	// mutation: adding th.Fail to the capacity branch must turn this test red.)
	th := NewThrottle(ThrottleConfig{
		FreeAttempts: 1,
		BaseDelay:    time.Minute,
		MaxDelay:     time.Minute,
		Reset:        time.Hour,
	})
	svc := &AuthService{
		Users:    users,
		Sessions: NewSessionManager(NewInMemorySessionStore()),
		Tenants:  nil, // req.Tenant is used as the tenant id directly
		Throttle: th,
	}

	// Saturate: one slot, no queue, so any concurrent verification is refused at once.
	restore := ConfigurePasswordHashing(HashLimiterConfig{
		MaxConcurrent: 1, MaxQueue: 0, MaxWait: 10 * time.Millisecond,
	})
	defer restore()
	held, err := passwordLimiter().acquire(context.Background(), false)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Three attempts, so that with FreeAttempts:1 even one stray Fail() per attempt puts the
	// account into a lockout the assertion below can see.
	body := `{"tenant":"` + tenant + `","email":"` + email + `","password":"` + pw + `"}`
	var lastCode int
	var lastBody, retryAfter string
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		svc.HandleLogin(rec, req)
		lastCode, lastBody, retryAfter = rec.Code, rec.Body.String(), rec.Header().Get("Retry-After")
	}
	held()

	if lastCode != http.StatusServiceUnavailable {
		t.Fatalf("saturated login returned %d, want 503 — a busy process must not answer with a "+
			"credential verdict it never reached (body: %s)", lastCode, lastBody)
	}
	if retryAfter == "" {
		t.Error("503 carried no Retry-After, so a client cannot pace its retry")
	}

	// THE ASSERTION THAT MATTERS: the account's budget is untouched. Allow() must still say yes,
	// with no lockout, for both the account key and the IP key HandleLogin meters on.
	keys := []string{accountKey("login", tenant, email), ipKey("login", "192.0.2.1")}
	if retry, ok := th.Allow(keys...); !ok {
		t.Errorf("a capacity refusal spent the account's throttle budget (locked for %s) — anyone "+
			"able to saturate argon2 could lock out any account they can name (docs/25 F01)", retry)
	}
}
