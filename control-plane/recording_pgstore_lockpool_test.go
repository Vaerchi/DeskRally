package controlplane

// Review r3, finding 1: the per-recording advisory lock must not draw its connections from the pool the
// locked operations use. Needs TEST_DATABASE_URL (skips without, like the other pg tests).

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// smallQueryStore is a PgRecordingStore whose QUERY pool has a single connection.
func smallQueryStore(t *testing.T, h *pgRecHarness, lockMax int, wait time.Duration) *PgRecordingStore {
	t.Helper()
	cfg := h.app.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	st := &PgRecordingStore{Pool: pool, LockPoolMax: lockMax, LockWait: wait}
	t.Cleanup(func() { st.Close(); pool.Close() })
	return st
}

func TestRecordingPgLockWorksWithAOneConnectionQueryPool(t *testing.T) {
	h := newPgRecHarness(t)
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	r, _ := env.create(t, h.tenantA, h.machineA)
	st := smallQueryStore(t, h, 2, 2*time.Second)

	unlock, err := st.LockRecording(context.Background(), h.tenantA, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	// A locked operation needs a QUERY-pool connection: with the lock on that pool this would wait forever.
	qctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := st.GetRecording(qctx, h.tenantA, r.ID); err != nil {
		t.Fatalf("a locked operation could not get a query connection (lock and query pools are shared): %v", err)
	}
	if _, _, err := st.ApplyRetention(qctx, h.tenantA, r.ID); err != nil && !errors.Is(err, ErrRecordingState) {
		t.Fatalf("second locked operation: %v", err)
	}
}

func TestRecordingPgLockWaitersSaturatingTheLockPoolFailFastAndNeverDeadlock(t *testing.T) {
	h := newPgRecHarness(t)
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	r, _ := env.create(t, h.tenantA, h.machineA)
	const wait = 600 * time.Millisecond
	st := smallQueryStore(t, h, 2, wait) // one query connection, two lock connections

	unlock, err := st.LockRecording(context.Background(), h.tenantA, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Five waiters on the SAME recording: one sits in pg_advisory_lock on the second lock connection, the
	// rest cannot get a connection at all. Every one must end within the bound with ErrRecordingLockBusy.
	var wg sync.WaitGroup
	errs := make([]error, 5)
	took := make([]time.Duration, 5)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			u, e := st.LockRecording(context.Background(), h.tenantA, r.ID)
			took[i], errs[i] = time.Since(start), e
			if e == nil {
				u()
			}
		}()
	}
	// The HOLDER still makes progress on the single query connection while the lock pool is saturated.
	time.Sleep(150 * time.Millisecond)
	qctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if _, err := st.GetRecording(qctx, h.tenantA, r.ID); err != nil {
		cancel()
		t.Fatalf("the holder stalled while waiters saturated the lock pool: %v", err)
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("waiters did not give up: a saturated lock pool queues without bound")
	}
	for i, e := range errs {
		if !errors.Is(e, ErrRecordingLockBusy) {
			t.Errorf("waiter %d: %v, want ErrRecordingLockBusy", i, e)
		}
		if took[i] > 5*time.Second {
			t.Errorf("waiter %d took %s", i, took[i])
		}
	}
	// A DIFFERENT recording's lock is also refused fast while the pool is full of waiters on this one? The
	// waiters are gone now, so it must be available again, and so must this recording after release.
	unlock()
	for _, id := range []string{r.ID} {
		u, err := st.LockRecording(context.Background(), h.tenantA, id)
		if err != nil {
			t.Fatalf("the lock pool did not recover after the waiters gave up: %v", err)
		}
		u()
	}
}
