package controlplane

// DB-gated tests for the Postgres-backed throttle (migration 0015): the shared multi-replica
// budget. Run as rmt_app (the production posture — the table has no RLS, direct pool DML).
// Like every pgx test these SKIP without TEST_DATABASE_URL.

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// applyThrottleMigration lays 0015 (throttle_counter) on top of the schema newTestPool applied.
// resetSchema DROPs the table.
func applyThrottleMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0015_throttle.sql")
	if err != nil {
		t.Fatalf("read 0015: %v", err)
	}
	execScript(t, pool, string(b))
}

func TestPgThrottleBackoffResetAndDecayAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool) // 0005: the rmt_app role the grant in 0015 targets
	applyThrottleMigration(t, suPool)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)

	th := NewStoreThrottle(ThrottleConfig{
		FreeAttempts: 2,
		BaseDelay:    time.Second,
		MaxDelay:     4 * time.Second,
		Reset:        time.Minute,
	}, NewPgThrottleStore(appPool))
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	th.Now = func() time.Time { return now }

	// Free attempts stay free.
	th.Fail("k1")
	th.Fail("k1")
	if wait, ok := th.Allow("k1"); !ok {
		t.Fatalf("still within free attempts, blocked for %v", wait)
	}
	// Third failure locks for BaseDelay; the fourth doubles; the cap holds (1s, 2s, 4s, 4s).
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		th.Fail("k1")
		wait, ok := th.Allow("k1")
		if ok || wait != want {
			t.Fatalf("failure %d: Allow = (%v, %v), want (%v, false)", i+3, wait, ok, want)
		}
	}

	// ANY locked key blocks the request; an unknown second key does not unlock it.
	if _, ok := th.Allow("k1", "other"); ok {
		t.Fatal("locked k1 must block a multi-key Allow")
	}
	if _, ok := th.Allow("other"); !ok {
		t.Fatal("an untouched key must not be blocked")
	}

	// The lock expires with time (shared clock: the injectable Now feeds the SQL predicates).
	now = now.Add(5 * time.Second)
	if wait, ok := th.Allow("k1"); !ok {
		t.Fatalf("lock should have expired, blocked for %v", wait)
	}

	// Reset forgets the key outright.
	th.Fail("k2")
	th.Fail("k2")
	th.Fail("k2")
	if _, ok := th.Allow("k2"); ok {
		t.Fatal("k2 should be locked before Reset")
	}
	th.Reset("k2")
	if _, ok := th.Allow("k2"); !ok {
		t.Fatal("Reset must clear the lockout")
	}

	// Idle decay: after Reset(cfg) of idle time, the next failure restarts the count at 1 —
	// within the free allowance again.
	now = now.Add(2 * time.Minute) // > cfg.Reset since k1's last failure
	th.Fail("k1")
	if _, ok := th.Allow("k1"); !ok {
		t.Fatal("an idle-decayed key's first new failure must be within the free allowance")
	}

	// The decayed-and-refailed row restarted at failures=1 (not 8).
	var failures int
	if err := appPool.QueryRow(ctx,
		`SELECT failures FROM throttle_counter WHERE key = 'k1'`).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("decayed k1 failures = %d (%v), want 1", failures, err)
	}
}

// TestPgThrottleConcurrentBumps is the reason the store exists: N concurrent writers (think N
// replicas) must never lose an increment — the single-statement upsert serializes on the row.
func TestPgThrottleConcurrentBumps(t *testing.T) {
	suPool := newTestPool(t)
	applyThrottleMigration(t, suPool)
	ctx := context.Background()
	store := NewPgThrottleStore(suPool)

	const writers = 12
	now := time.Now().UTC()
	stale := now.Add(-time.Hour)
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Bump(ctx, "conc", now, stale)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Bump: %v", err)
		}
	}
	var failures int
	if err := suPool.QueryRow(ctx,
		`SELECT failures FROM throttle_counter WHERE key = 'conc'`).Scan(&failures); err != nil || failures != writers {
		t.Fatalf("failures = %d (%v), want %d — increments were lost", failures, err, writers)
	}
}

func TestPgThrottleLongKeysDigestedAndCleanup(t *testing.T) {
	suPool := newTestPool(t)
	applyThrottleMigration(t, suPool)
	ctx := context.Background()
	store := NewPgThrottleStore(suPool)
	now := time.Now().UTC()
	stale := now.Add(-time.Hour)

	// An attacker-length key is stored in digest form but keeps per-key semantics.
	long := "login:acct:tenant\x00" + strings.Repeat("a", 5000)
	if _, err := store.Bump(ctx, long, now, stale); err != nil {
		t.Fatalf("Bump(long): %v", err)
	}
	if n, err := store.Bump(ctx, long, now, stale); err != nil || n != 2 {
		t.Fatalf("Bump(long) again = %d (%v), want 2", n, err)
	}
	var storedKey string
	if err := suPool.QueryRow(ctx,
		`SELECT key FROM throttle_counter LIMIT 1`).Scan(&storedKey); err != nil {
		t.Fatalf("read stored key: %v", err)
	}
	if !strings.HasPrefix(storedKey, "sha256:") || len(storedKey) != len("sha256:")+64 {
		t.Fatalf("long key stored as %q, want a sha256: digest form", storedKey)
	}
	if err := store.SetLock(ctx, long, now.Add(time.Minute)); err != nil {
		t.Fatalf("SetLock(long): %v", err)
	}
	until, err := store.MaxLockedUntil(ctx, []string{long}, now)
	if err != nil || until.IsZero() {
		t.Fatalf("MaxLockedUntil(long) = %v (%v), want the lock", until, err)
	}

	// Cleanup drops idle unlocked entries but keeps live-locked ones.
	if _, err := store.Bump(ctx, "idle", now.Add(-2*time.Hour), now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("Bump(idle): %v", err)
	}
	if err := store.Cleanup(ctx, now.Add(-time.Hour), now); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	var n int
	if err := suPool.QueryRow(ctx, `SELECT count(*) FROM throttle_counter`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows after cleanup = %d (%v), want 1 (the live-locked digest row)", n, err)
	}
}

// TestPgThrottleRealKeysSurvivePostgres is the regression for a CRITICAL defect the adversarial
// review found: `accountKey` embedded U+0000 as its tenant/account separator, and PostgreSQL `text`
// cannot represent a NUL. Every per-account Bump therefore failed with
// `invalid byte sequence for encoding "UTF8": 0x00` (SQLSTATE 22021) against the PG-backed store —
// the PRODUCTION posture — and because the throttle fails CLOSED that meant a permanent 429 on the
// credential endpoints. The in-memory map used by most tests stores NUL happily, which is exactly
// why nothing caught it.
//
// So this test does not assert on the separator: it drives the REAL key builders the handlers use
// through a REAL Postgres round trip, which is the only thing that can prove storability.
func TestPgThrottleRealKeysSurvivePostgres(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyThrottleMigration(t, suPool)
	ctx := context.Background()
	store := NewPgThrottleStore(newAppRolePool(t, ctx))

	now := time.Now()
	stale := now.Add(-time.Hour)

	// Every key shape the handlers actually build.
	keys := map[string]string{
		"login account":    accountKey("login", "11111111-1111-1111-1111-111111111111", "Dana@Acme.Test"),
		"totp account":     accountKey("totp", "11111111-1111-1111-1111-111111111111", "user-id-1"),
		"password account": accountKey("password", "11111111-1111-1111-1111-111111111111", "user-1\x1fsess-1"),
		"login ip":         ipKey("login", "203.0.113.7"),
		"redeem ip":        ipKey("redeem", "2001:db8::1"),
	}
	for name, key := range keys {
		n, err := store.Bump(ctx, key, now, stale)
		if err != nil {
			t.Fatalf("%s key %q could not be stored in Postgres: %v", name, key, err)
		}
		if n != 1 {
			t.Fatalf("%s: first Bump = %d, want 1", name, n)
		}
		// And a SECOND failure increments rather than starting over — a key that cannot round-trip
		// is a key whose budget silently resets, which is the same as no throttle at all.
		again, err := store.Bump(ctx, key, now, stale)
		if err != nil {
			t.Fatalf("%s: second Bump: %v", name, err)
		}
		if again != 2 {
			t.Fatalf("%s: second Bump = %d, want 2 (the key must round-trip)", name, again)
		}
	}

	// Distinct accounts in the SAME tenant must stay distinct budgets (the separator's actual job).
	a := accountKey("login", "t1", "alice@x.test")
	b := accountKey("login", "t1", "bob@x.test")
	if _, err := store.Bump(ctx, a, now, stale); err != nil {
		t.Fatalf("bump a: %v", err)
	}
	nb, err := store.Bump(ctx, b, now, stale)
	if err != nil {
		t.Fatalf("bump b: %v", err)
	}
	if nb != 1 {
		t.Fatalf("second account's first failure = %d, want 1 (budgets must not be shared)", nb)
	}
	// Two sessions of the SAME user get SEPARATE budgets — the property that stops a stolen session
	// from locking its owner out of /me/password. The session lives in the KIND, so the account
	// component never carries the separator (accountKey's contract).
	s1 := passwordThrottleKey(&Principal{TenantID: "t1", UserID: "u1", SessionID: "sess-A"})
	s2 := passwordThrottleKey(&Principal{TenantID: "t1", UserID: "u1", SessionID: "sess-B"})
	if s1 == s2 {
		t.Fatal("two sessions of one user share a throttle budget")
	}
	for _, k := range []string{s1, s2} {
		if strings.Count(k, accountSeparator) != 1 {
			t.Fatalf("key %q must contain exactly one separator, or it is ambiguous", k)
		}
	}
	if _, err := store.Bump(ctx, s1, now, stale); err != nil {
		t.Fatalf("bump session A: %v", err)
	}
	n2, err := store.Bump(ctx, s2, now, stale)
	if err != nil {
		t.Fatalf("bump session B: %v", err)
	}
	if n2 != 1 {
		t.Fatalf("session B's first failure = %d, want 1 (budgets must not be shared)", n2)
	}

	// storeKey is the boundary guard: anything unstorable is digested rather than sent raw.
	if k := storeKey("login:acct:t\x00a"); strings.Contains(k, "\x00") {
		t.Fatalf("storeKey passed a NUL through: %q", k)
	}
	if _, err := store.Bump(ctx, "probe:acct:t\x00a", now, stale); err != nil {
		t.Fatalf("a NUL-bearing key must be normalized, not rejected: %v", err)
	}
}

// Reserve is atomic across concurrent callers (the login burst fix) and Release refunds exactly
// one charge. Same fake-and-pg-must-agree contract: the in-memory Throttle is run through the same
// assertions.
func TestPgThrottleReserveIsAtomicAndReleasable(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyThrottleMigration(t, suPool)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)

	cfg := ThrottleConfig{FreeAttempts: 5, BaseDelay: 2 * time.Second, MaxDelay: time.Minute, Reset: time.Hour}
	for name, th := range map[string]*Throttle{
		"pg":  NewStoreThrottle(cfg, NewPgThrottleStore(appPool)),
		"mem": NewThrottle(cfg),
	} {
		now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
		th.Now = func() time.Time { return now }
		spec := throttleSpec{Key: "reserve:burst:" + name}

		var admitted atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, ok := th.Reserve(spec); ok {
					admitted.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := admitted.Load(); got != int64(cfg.FreeAttempts+1) {
			t.Fatalf("%s: %d of 40 parallel Reserve calls admitted, want exactly %d", name, got, cfg.FreeAttempts+1)
		}

		// A fixed-delay policy (account-wide shape): free 2, then one admission per 30 s.
		acct := throttleSpec{Key: "reserve:acct:" + name, Free: 2, Base: 30 * time.Second, Max: 30 * time.Second}
		for i := 0; i < 3; i++ {
			if _, ok := th.Reserve(acct); !ok {
				t.Fatalf("%s: reserve %d refused", name, i+1)
			}
		}
		wait, ok := th.Reserve(acct)
		if ok || wait <= 0 || wait > 30*time.Second {
			t.Fatalf("%s: 4th reserve = (%v,%v), want refused with a wait <= 30s", name, wait, ok)
		}
		now = now.Add(31 * time.Second)
		if _, ok := th.Reserve(acct); !ok {
			t.Fatalf("%s: slot after 31s refused", name)
		}
		if _, ok := th.Reserve(acct); ok {
			t.Fatalf("%s: fixed delay must not grow into a second admission", name)
		}

		// Release refunds one charge and lifts a lock the count no longer justifies.
		rel := throttleSpec{Key: "reserve:rel:" + name}
		for i := 0; i < 6; i++ {
			if _, ok := th.Reserve(rel); !ok {
				t.Fatalf("%s: reserve %d refused", name, i+1)
			}
		}
		if _, ok := th.Reserve(rel); ok {
			t.Fatalf("%s: 7th reserve admitted", name)
		}
		th.Release(rel)
		if _, ok := th.Reserve(rel); !ok {
			t.Fatalf("%s: refund did not lift the lock", name)
		}

		// All-or-nothing: a refused second key charges nothing to the first.
		a, b := throttleSpec{Key: "reserve:a:" + name}, throttleSpec{Key: "reserve:b:" + name}
		for i := 0; i < 6; i++ {
			th.Reserve(b)
		}
		if _, ok := th.Reserve(a, b); ok {
			t.Fatalf("%s: locked b must refuse the pair", name)
		}
		for i := 0; i < 6; i++ {
			if _, ok := th.Reserve(a); !ok {
				t.Fatalf("%s: a was charged by the refused pair (reserve %d)", name, i+1)
			}
		}
	}
}

// A very long attack must keep behaving as promised: the backoff exponent is capped BEFORE
// power() so Postgres never overflows (it used to error after ~1035 failures and, failing closed,
// turned the 30 s account-wide delay into a lockout), and memory and pg agree.
func TestThrottleReserveSurvivesHugeFailureCounts(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyThrottleMigration(t, suPool)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)

	cfg := ThrottleConfig{FreeAttempts: 5, BaseDelay: 2 * time.Second, MaxDelay: 15 * time.Minute, Reset: 1000 * time.Hour}
	for name, th := range map[string]*Throttle{
		"pg":  NewStoreThrottle(cfg, NewPgThrottleStore(appPool)),
		"mem": NewThrottle(cfg),
	} {
		now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
		th.Now = func() time.Time { return now }
		for label, spec := range map[string]throttleSpec{
			"default-curve": {Key: "huge:default:" + name},
			"base-eq-max":   {Key: "huge:acct:" + name, Free: 10, Base: 30 * time.Second, Max: 30 * time.Second},
		} {
			wantMax := 15 * time.Minute
			if spec.Max > 0 {
				wantMax = spec.Max
			}
			for i := 1; i <= 5000; i++ {
				wait, ok := th.Reserve(spec)
				if !ok {
					t.Fatalf("%s/%s: reserve %d refused (wait %v): a long attack must not fail closed", name, label, i, wait)
				}
				now = now.Add(wantMax + time.Second) // let the lock lapse; the count keeps growing
			}
			// After 5000 failures the lock is exactly the cap, not an error and not a lockout.
			if _, ok := th.Reserve(spec); !ok {
				t.Fatalf("%s/%s: 5001st reserve refused", name, label)
			}
			wait, ok := th.Reserve(spec)
			if ok || wait <= 0 || wait > wantMax {
				t.Fatalf("%s/%s: at 5000+ failures the lock = (%v,%v), want a wait in (0,%v]", name, label, wait, ok, wantMax)
			}
		}
	}
}
