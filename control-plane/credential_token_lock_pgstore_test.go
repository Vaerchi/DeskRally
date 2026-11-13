package controlplane

// The per-user mint lock must key on the CANONICAL user id, so two spellings of one uuid cannot take
// two different locks.
//
// PREMISE, declared locally: `TestPgCredentialTokenConcurrentMintsLeaveOneLiveLink` already proves
// that concurrent mints for one user leave exactly ONE live account-takeover link, and that the
// advisory lock is what orders them ("one transaction is not atomicity" — under READ COMMITTED the
// supersede UPDATE cannot see a concurrent uncommitted INSERT, so without the lock both commit).
//
// That lock hashes a STRING: `hashtextextended($1, 0)` over the caller's `userID`. Every other
// predicate in this store compares a `uuid` column and is therefore spelling-insensitive for free —
// but a hash is not. `mgmtaudit`'s lock site carries a comment saying exactly this and canonicalizes
// its key for exactly this reason; this one did not. So a caller alternating `ABC…` and `abc…` for
// the same user takes two different locks, both mints read the same state, and the serialization
// silently does not happen.
//
// This test uses the SAME user id in two spellings. It is not about a malicious caller — Postgres
// accepts both spellings for a `uuid` parameter, so any client that upper-cases an id anywhere in
// its stack gets this for free. The partial unique index remains the backstop, which is why the
// assertion below accepts "one mint failed loudly" as well as "the lock ordered them": what must
// NOT happen is two live links.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPgCredentialTokenLockIgnoresUUIDSpelling(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyCredentialTokenMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "ct-spell", "dana@ct-spell.test", "Original-Passw0rd!")
	appPool := newAppRolePool(t, ctx)
	store := NewPgCredentialTokenStore(appPool)

	upper := strings.ToUpper(uid)
	if upper == uid {
		t.Fatalf("premise not met: %q has no lower-case hex digits to flip, so this test cannot "+
			"produce two spellings of one id", uid)
	}

	const racers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := uid
			if i%2 == 1 {
				id = upper // same user, different spelling — must take the SAME lock
			}
			<-start
			_, _, errs[i] = store.Mint(ctx, tid, id, id, time.Now().Add(time.Hour))
		}(i)
	}
	close(start)
	wg.Wait()

	// FIRST, the security invariant — at most ONE live (unconsumed, unrevoked) link, whichever
	// spelling minted it. MEASURED: this already holds without the fix, because the partial unique
	// index is the backstop. Asserted anyway as the negative control: it is what must never regress,
	// and a "fix" that broke it would be far worse than the defect.
	var live int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM user_credential_token
		  WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL`, uid).Scan(&live); err != nil {
		t.Fatalf("count live links: %v", err)
	}
	if live > 1 {
		t.Fatalf("SECURITY: %d LIVE account-takeover links exist for one user — the unique index "+
			"backstop failed, not just the lock", live)
	}

	// THEN the actual defect. The lock exists so concurrent mints SERIALIZE and all succeed; the
	// index is only the backstop for when they do not. With the lock keyed on the raw spelling, the
	// two spellings take two different locks, the mints do not serialize, and the ones that lose the
	// race die on the unique index — surfacing to an administrator as a 500 on a button they are
	// entitled to press. `TestPgCredentialTokenConcurrentMintsLeaveOneLiveLink` asserts exactly this
	// (all 8 succeed) for the single-spelling case; the canonical key extends that guarantee to a
	// caller whose id spelling varies, which Postgres accepts everywhere else.
	failed := 0
	for _, e := range errs {
		if e != nil {
			failed++
		}
	}
	if failed != 0 {
		t.Fatalf("%d of %d mints failed: two spellings of one uuid took two different advisory locks, "+
			"so the mints raced to the unique index instead of serializing on the lock (errs: %v)",
			failed, racers, errs)
	}
}
