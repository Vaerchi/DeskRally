package controlplane

// Write-amplification accounting for a REJECTED attended redemption (docs/66 2o/2p). A rejection is
// Allow (one read) then Fail; the test counts the SQL statements the Postgres throttle store really
// sends (a pgx tracer on the pool, not a wrapper), so a regression back to Bump+SetLock+Cleanup per
// rejection fails here.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sqlCounter struct {
	mu    sync.Mutex
	stmts []string
}

func (c *sqlCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	c.stmts = append(c.stmts, d.SQL)
	c.mu.Unlock()
	return ctx
}
func (c *sqlCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *sqlCounter) reset() { c.mu.Lock(); c.stmts = nil; c.mu.Unlock() }

// counts returns (total statements, writes).
func (c *sqlCounter) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := 0
	for _, s := range c.stmts {
		s = strings.ToUpper(strings.TrimSpace(s))
		if strings.HasPrefix(s, "INSERT") || strings.HasPrefix(s, "UPDATE") || strings.HasPrefix(s, "DELETE") {
			w++
		}
	}
	return len(c.stmts), w
}

func newCountingPool(t *testing.T, ctx context.Context, c *sqlCounter) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Tracer = c
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPgThrottleRejectionWriteCount(t *testing.T) {
	su := newTestPool(t)
	applyThrottleMigration(t, su)
	ctx := context.Background()
	c := &sqlCounter{}
	th := NewStoreThrottle(DefaultThrottleConfig, NewPgThrottleStore(newCountingPool(t, ctx, c)))
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	th.Now = func() time.Time { return now }

	// Warm the pool so connection setup queries are not counted, and let the first-Fail cleanup happen.
	th.Fail("warm")

	const n = 200
	c.reset()
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("attend-redeem:ip:10.0.%d.%d", i/250, i%250)
		if _, ok := th.Allow(key); !ok {
			t.Fatal("unexpected lock")
		}
		th.Fail(key)
	}
	total, writes := c.counts()
	t.Logf("REJECTED REDEMPTION over %d distinct addresses: %d statements (%.2f/rejection), %d writes (%.2f/rejection)",
		n, total, float64(total)/n, writes, float64(writes)/n)
	if writes > n+1 {
		t.Fatalf("writes per rejection = %.2f, want 1 (one upsert; cleanup is off the request path)", float64(writes)/n)
	}
	if total > 2*n+1 {
		t.Fatalf("round trips per rejection = %.2f, want 2 (Allow read + one upsert)", float64(total)/n)
	}

	// A multi-key Fail is still one statement.
	c.reset()
	th.Fail("m1", "m2", "m3")
	if total, _ := c.counts(); total != 1 {
		t.Fatalf("3-key Fail = %d statements, want 1", total)
	}
}

// Two concurrent Fails on the same key must both count, and the lock must reflect the final count.
func TestPgThrottleConcurrentFailsAllCountAndLock(t *testing.T) {
	su := newTestPool(t)
	applyThrottleMigration(t, su)
	ctx := context.Background()
	th := NewStoreThrottle(ThrottleConfig{FreeAttempts: 5, BaseDelay: 2 * time.Second, MaxDelay: time.Hour, Reset: time.Hour}, NewPgThrottleStore(su))
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	th.Now = func() time.Time { return now }

	const workers, each = 16, 5
	var wg sync.WaitGroup
	var started atomic.Int32
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Add(1)
			for started.Load() < workers {
			}
			for i := 0; i < each; i++ {
				th.Fail("hot", "hot2")
			}
		}()
	}
	wg.Wait()
	const total = workers * each
	for _, k := range []string{"hot", "hot2"} {
		var failures int
		var locked *time.Time
		if err := su.QueryRow(ctx, `SELECT failures, locked_until FROM throttle_counter WHERE key=$1`, k).Scan(&failures, &locked); err != nil {
			t.Fatal(err)
		}
		if failures != total {
			t.Fatalf("%s failures = %d, want %d: concurrent increments were lost", k, failures, total)
		}
		want := now.Add(th.delayFor(total - 5))
		if locked == nil || !locked.Equal(want) {
			t.Fatalf("%s locked_until = %v, want %v (lock must follow the final count)", k, locked, want)
		}
	}
	// Duplicate keys in one Fail count twice, as they did when each was bumped separately.
	th.Fail("dup", "dup", "dup")
	var f int
	if err := su.QueryRow(ctx, `SELECT failures FROM throttle_counter WHERE key='dup'`).Scan(&f); err != nil || f != 3 {
		t.Fatalf("dup failures = %d (%v), want 3", f, err)
	}
}
