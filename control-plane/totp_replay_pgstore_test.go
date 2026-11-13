package controlplane

// DB-gated proof for the TOTP replay ledger (migrations/0012), run as the least-privilege `rmt_app`
// role so RLS is genuinely in force.
//
// This closes a gap rather than covering new code: `ConsumeTOTPStep` is the single-use enforcement
// behind BOTH login and — since the re-enroll step-up started spending its code —
// POST /auth/totp/enroll, and until now it was pinned only by InMemoryUserStore. That fake keeps a
// map under a mutex, so it can demonstrate the CONTRACT but not the mechanism the contract rests
// on: the enforcement here is a compare-and-set `UPDATE … WHERE last_step < $2`, and whether that
// statement actually refuses a replayed step is a fact about PostgreSQL. A fake pins a caller; only
// the database pins persistence.

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// No apply*Migration for 0012 here: resetSchema applies it with the core, because last_step is
// written by every TOTP login and PgUserStore hard-depends on the column.

// seedConfirmedTOTP gives a user a confirmed enrollment (and therefore a user_totp row for the
// compare-and-set to act on).
func seedConfirmedTOTP(t *testing.T, pool *pgxpool.Pool, tenantID, userID string) {
	t.Helper()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := newPgUserStoreT(pool).SetTOTP(context.Background(), tenantID, userID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
}

// TestPgConsumeTOTPStepUnderRLS pins every branch of the ledger against a live server as rmt_app.
func TestPgConsumeTOTPStepUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tidA, uidA := provisionUser(t, suPool, "totp-a", "dana@totp-a.test", "Original-Passw0rd!")
	tidB, uidB := provisionUser(t, suPool, "totp-b", "eve@totp-b.test", "Other-Passw0rd!")
	seedConfirmedTOTP(t, suPool, tidA, uidA)
	seedConfirmedTOTP(t, suPool, tidB, uidB)

	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	const step = uint64(56_666_666)

	// First presentation wins.
	if fresh, err := store.ConsumeTOTPStep(ctx, tidA, uidA, step); err != nil || !fresh {
		t.Fatalf("first ConsumeTOTPStep = (%v, %v), want (true, nil)", fresh, err)
	}
	// The same step again is a replay — the WHERE clause matches no row.
	if fresh, err := store.ConsumeTOTPStep(ctx, tidA, uidA, step); err != nil || fresh {
		t.Fatalf("replayed step = (%v, %v), want (false, nil)", fresh, err)
	}
	// An EARLIER step is refused too, which is what makes a clock rewind unexploitable.
	if fresh, err := store.ConsumeTOTPStep(ctx, tidA, uidA, step-1); err != nil || fresh {
		t.Fatalf("earlier step = (%v, %v), want (false, nil)", fresh, err)
	}
	// A later step still works: replay protection must not lock the account out.
	if fresh, err := store.ConsumeTOTPStep(ctx, tidA, uidA, step+1); err != nil || !fresh {
		t.Fatalf("later step = (%v, %v), want (true, nil)", fresh, err)
	}

	// PER USER: tenant B's user shares the step value and must be unaffected by A spending it.
	// (Codes and clocks legitimately line up across accounts; one user must never lock out another.)
	if fresh, err := store.ConsumeTOTPStep(ctx, tidB, uidB, step); err != nil || !fresh {
		t.Fatalf("other tenant's user at the same step = (%v, %v), want (true, nil) — the ledger "+
			"is per user, not global", fresh, err)
	}

	// CROSS-TENANT: pinned to tenant A, spending against tenant B's user id must write nothing.
	// RLS is the enforcement; the false return is what a caller sees, and B's own ledger below
	// proves no row moved.
	if fresh, err := store.ConsumeTOTPStep(ctx, tidA, uidB, step+5); err != nil || fresh {
		t.Fatalf("cross-tenant consume = (%v, %v), want (false, nil) — RLS must confine it", fresh, err)
	}
	var lastB *int64
	if err := suPool.QueryRow(ctx,
		`SELECT last_step FROM user_totp WHERE user_id = $1::uuid`, uidB).Scan(&lastB); err != nil {
		t.Fatalf("read B's last_step: %v", err)
	}
	if lastB == nil || *lastB != int64(step) {
		t.Fatalf("tenant B's last_step = %v, want %d — a tenant-A-pinned consume moved it",
			lastB, step)
	}

	// A user with NO user_totp row fails CLOSED (reaching here means a confirmed enrollment was
	// believed to exist, so a missing row is an inconsistency, not a free pass).
	uidC := seedCredentiallessUser(t, suPool, tidA, "carol@totp-a.test")
	if fresh, err := store.ConsumeTOTPStep(ctx, tidA, uidC, step); err != nil || fresh {
		t.Fatalf("consume with no user_totp row = (%v, %v), want (false, nil)", fresh, err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgConsumeTOTPStepIsAtomicUnderConcurrency is the property the in-memory fake cannot testify
// to: N callers presenting the SAME code at once must produce exactly ONE winner. The fake
// serializes on a Go mutex in one process; production runs several replicas against one database,
// where the only thing standing between two simultaneous logins and two accepted uses of one code
// is the row lock this single UPDATE takes.
func TestPgConsumeTOTPStepIsAtomicUnderConcurrency(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "totp-race", "dana@totp-race.test", "Original-Passw0rd!")
	seedConfirmedTOTP(t, suPool, tid, uid)

	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	const (
		step    = uint64(56_777_777)
		callers = 8
	)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together so they genuinely contend
			fresh, err := store.ConsumeTOTPStep(ctx, tid, uid, step)
			if err != nil {
				t.Errorf("ConsumeTOTPStep: %v", err)
				return
			}
			if fresh {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Fatalf("%d of %d concurrent callers consumed the same step, want exactly 1 — the "+
			"compare-and-set is not atomic", winners, callers)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
