package controlplane

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

// --- A1: the active assignment is locked and revalidated INSIDE the redemption ---------------------------

// Order 1: a release is in flight (uncommitted) when the redeem starts; it commits while the redeem waits. The
// redeem must see the release (it re-evaluates the locked row) and refuse, leaving the code unspent.
func TestPgScopedRedeemBlockedByReleaseThatCommitsFirstIsRefused(t *testing.T) {
	l := newLockFx(t)
	ctx := context.Background()
	tx, err := l.fx.pf.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_hostname_assignment SET state = 'released', released_by = 'x',
		quarantined_until = now() + interval '31 days' WHERE host = $1 AND state = 'active'`, l.host); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := l.redeemTimed(t); done <- err }()
	time.Sleep(15 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("a redeem that waited on a committing release: %v, want the generic rejection", err)
	}
	if _, err := l.fx.store.RedeemScoped(ctx, l.code, randPubkeyHex(t), "G", RedeemScope{Unscoped: true}); err != nil {
		t.Fatalf("the refused code must be unspent: %v", err)
	}
}

// Order 2: the redeem holds the assignment (share lock) and waits on the code row; a release started meanwhile
// must WAIT for the redemption to finish, never commit in between. The redeem succeeds; the release lands after.
func TestPgScopedRedeemHoldsTheAssignmentUntilTheCodeIsConsumed(t *testing.T) {
	l := newLockFx(t)
	ctx := context.Background()
	// Warm the pools: a cold connection would let the release win the race to the assignment row.
	_, _ = l.fx.store.RedeemScoped(ctx, "WARMUPWARMUP", randPubkeyHex(t), "G", l.scope)
	all, err := l.fx.hosts.List(ctx, l.fx.caller, l.A)
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %v %v", all, err)
	}
	holder := l.holdRowTx(t, nil) // someone else briefly holds the CODE row
	type res struct {
		err error
		at  time.Time
	}
	redeemDone, releaseDone := make(chan res, 1), make(chan res, 1)
	go func() { _, err := l.redeemTimed(t); redeemDone <- res{err, time.Now()} }()
	time.Sleep(10 * time.Millisecond) // the redeem now holds the assignment share lock and waits on the code row
	go func() {
		_, err := l.fx.hosts.Release(ctx, l.fx.caller, all[0].ID, 30, nil)
		releaseDone <- res{err, time.Now()}
	}()
	time.Sleep(10 * time.Millisecond)
	holder(false) // rolls back inside the 50 ms bound: the redeem proceeds
	rd, rl := <-redeemDone, <-releaseDone
	if rd.err != nil {
		t.Fatalf("redeem that held the assignment first: %v, want success", rd.err)
	}
	if rl.err != nil {
		t.Fatalf("release: %v", rl.err)
	}
	if rl.at.Before(rd.at.Add(-2 * time.Millisecond)) {
		t.Fatalf("the release finished (%v) before the redemption it was concurrent with (%v)", rl.at, rd.at)
	}
	code2, _ := l.fx.newCode(l.A)
	if _, err := l.fx.store.RedeemScoped(ctx, code2, randPubkeyHex(t), "G", l.scope); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("after the release: %v, want the generic rejection", err)
	}
}

// --- A2: release transitions are stamped IN the trigger -----------------------------------------------

func TestPgReleaseIsStampedByTheTriggerOnEveryWritePath(t *testing.T) {
	fx := newPgHostFx(t)
	su := fx.pf.su
	ctx := context.Background()
	A, B := fx.tenant("ra"), fx.tenant("rb")
	exec := func(sql string, args ...any) error { _, err := su.Exec(ctx, sql, args...); return err }

	// Direct INSERT of an already-released row, backdated or with a short quarantine: refused.
	for name, cols := range map[string]string{
		"backdated quarantine": `now() - interval '60 days', 'x', now() - interval '30 days'`,
		"short quarantine":     `now(), 'x', now() + interval '10 days'`,
		"719 hours":            `now(), 'x', now() + interval '719 hours'`,
	} {
		err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, released_at, released_by, quarantined_until)
			VALUES ('bd.example.test', $1, 'released', 'x', `+cols+`)`, A)
		if hostPgCode(err) != "23514" {
			t.Errorf("%s: %v, want the trigger/CHECK refusal", name, err)
		}
	}
	// A backdated released_at with a long quarantine is accepted but the release time is the DATABASE clock.
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, released_at, released_by, quarantined_until)
		VALUES ('stamp.example.test', $1, 'released', 'x', now() - interval '400 days', 'x', now() + interval '800 hours')`, A); err != nil {
		t.Fatal(err)
	}
	var ageSecs, qHours float64
	if err := su.QueryRow(ctx, `SELECT extract(epoch FROM now() - released_at), extract(epoch FROM quarantined_until - now()) / 3600
		FROM tenant_hostname_assignment WHERE host = 'stamp.example.test'`).Scan(&ageSecs, &qHours); err != nil {
		t.Fatal(err)
	}
	if ageSecs > 60 || qHours < 719 {
		t.Fatalf("released_at was not stamped now() (age %.0fs) or the quarantine shrank (%.0f h)", ageSecs, qHours)
	}
	// A NULL quarantine is defaulted to 720 hours.
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, released_by) VALUES ('null.example.test', $1, 'released', 'x', 'x')`, B); err != nil {
		t.Fatalf("null quarantine insert: %v", err)
	}
	// Direct UPDATE release of a live row: backdating is refused; a valid one is stamped.
	C := fx.tenant("rc")
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('up.example.test', $1, 'pending', 'x')`, C); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE tenant_hostname_assignment SET state = 'released', released_at = now() - interval '90 days', released_by = 'x',
		quarantined_until = now() - interval '60 days' WHERE host = 'up.example.test'`); hostPgCode(err) != "23514" {
		t.Fatalf("backdated direct release: %v, want refusal", err)
	}
	if err := exec(`UPDATE tenant_hostname_assignment SET state = 'released', released_at = now() - interval '90 days', released_by = 'x',
		quarantined_until = now() + interval '725 hours' WHERE host = 'up.example.test'`); err != nil {
		t.Fatal(err)
	}
	if err := su.QueryRow(ctx, `SELECT extract(epoch FROM now() - released_at) FROM tenant_hostname_assignment WHERE host = 'up.example.test'`).Scan(&ageSecs); err != nil || ageSecs > 60 {
		t.Fatalf("direct UPDATE release kept the caller's released_at (age %.0fs, %v)", ageSecs, err)
	}
}

// Concurrent release and assign serialize on the host lock even for direct SQL: the assign waits for the
// release to commit and then sees the quarantine.
func TestPgConcurrentDirectReleaseAndAssignSerialize(t *testing.T) {
	fx := newPgHostFx(t)
	su := fx.pf.su
	ctx := context.Background()
	A, B := fx.tenant("ca"), fx.tenant("cb")
	if _, err := su.Exec(ctx, `INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, activated_at) VALUES ('cc.example.test', $1, 'active', 'x', now())`, A); err != nil {
		t.Fatal(err)
	}
	tx, err := su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_hostname_assignment SET state = 'released', released_by = 'x' WHERE host = 'cc.example.test'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := su.Exec(ctx, `INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('cc.example.test', $1, 'pending', 'x')`, B)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the assign did not wait for the in-flight release: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; hostPgCode(err) != "HQ001" {
		t.Fatalf("assign after the release committed: %v, want the quarantine refusal", err)
	}
}

// now() is the TRANSACTION start: a release made late in a long transaction must still be stamped with the
// moment of the transition and get a full 720 hours from THEN (not from the transaction start).
func TestPgReleaseFromALongTransactionIsStampedAtTheTransition(t *testing.T) {
	fx := newPgHostFx(t)
	su := fx.pf.su
	ctx := context.Background()
	check := func(name string, tx pgx.Tx, release func()) {
		t.Helper()
		var txStart time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&txStart); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_sleep(1.5)`); err != nil {
			t.Fatal(err)
		}
		release()
		var rel, until, clock time.Time
		if err := tx.QueryRow(ctx, `SELECT released_at, quarantined_until, clock_timestamp() FROM tenant_hostname_assignment WHERE host = $1`, name).Scan(&rel, &until, &clock); err != nil {
			t.Fatal(err)
		}
		if rel.Sub(txStart) < 1400*time.Millisecond || clock.Sub(rel) > 500*time.Millisecond {
			t.Errorf("%s: released_at %v is not the transition time (tx start %v, clock %v)", name, rel, txStart, clock)
		}
		if until.Sub(rel) < 720*time.Hour {
			t.Errorf("%s: quarantine %v after the release, want >= 720 h from THEN", name, until.Sub(rel))
		}
		if until.Before(clock.Add(720*time.Hour - time.Second)) {
			t.Errorf("%s: quarantine ends %v, shorter than 720 h from now (%v)", name, until, clock)
		}
	}

	// Direct SQL path.
	A := fx.tenant("lt")
	if _, err := su.Exec(ctx, `INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, activated_at) VALUES ('long1.example.test', $1, 'active', 'x', now())`, A); err != nil {
		t.Fatal(err)
	}
	tx, err := su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("long1.example.test", tx, func() {
		if _, err := tx.Exec(ctx, `UPDATE tenant_hostname_assignment SET state = 'released', released_by = 'x' WHERE host = 'long1.example.test'`); err != nil {
			t.Fatal(err)
		}
	})
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The operator function path (default 30 days and a longer request).
	for i, days := range []int{30, 45} {
		B := fx.tenant("lf")
		host := []string{"long2.example.test", "long3.example.test"}[i]
		a := fx.mustAssign(t, B, host)
		if _, err := fx.hosts.Activate(ctx, fx.caller, a.ID, nil); err != nil {
			t.Fatal(err)
		}
		tx, err := su.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		check(host, tx, func() {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant', $1, true)`, fx.pf.platform); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT * FROM cp_platform_hostname_release($1, $2, $3, 'x', $4)`, fx.pf.op, fx.pf.opSession, a.ID, days); err != nil {
				t.Fatal(err)
			}
		})
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
