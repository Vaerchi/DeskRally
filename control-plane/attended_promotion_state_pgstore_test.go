package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPgPromotionStateAdmissionAndRowLock(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "promotion", "tech@promotion.test", "synthetic-password")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)
	var lastID string
	for _, state := range []string{AttendedPending, AttendedRedeemed, AttendedDeclined, AttendedEnded, AttendedExpired, AttendedConsented, AttendedActive} {
		t.Run(state, func(t *testing.T) {
			session := &AttendedSession{GroupID: gid, TechnicianID: uid}
			if _, err := store.Create(ctx, tid, session); err != nil {
				t.Fatal(err)
			}
			lastID = session.ID
			// Administrative fixture seeding; the candidate write itself uses the RLS-subject role.
			if _, err := pool.Exec(ctx, `UPDATE attended_session SET state=$2,promote_token='old' WHERE id=$1`, session.ID, state); err != nil {
				t.Fatal(err)
			}
			err := store.SetPromoteToken(ctx, tid, session.ID, "new")
			allowed := state == AttendedConsented || state == AttendedActive
			if allowed && err != nil {
				t.Fatal(err)
			}
			if !allowed && !errors.Is(err, ErrAttendedNotPromotable) {
				t.Fatalf("ineligible stash: %v", err)
			}
			got, err := store.Get(ctx, tid, session.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := "old"
			if allowed {
				want = "new"
			}
			if got.PromoteToken != want || got.State != state {
				t.Fatalf("stash/state changed unexpectedly: %#v", got)
			}
			if err := store.SetPromoteToken(ctx, tid, session.ID, ""); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			got, err = store.Get(ctx, tid, session.ID)
			if err != nil || got.PromoteToken != "" {
				t.Fatalf("cleanup result: %#v %v", got, err)
			}
		})
	}
	if err := store.SetPromoteToken(ctx, newUUID(), lastID, "foreign"); !errors.Is(err, ErrAttendedNotFound) {
		t.Fatalf("foreign tenant: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, "bad-id", "new"); !errors.Is(err, ErrAttendedNotFound) {
		t.Fatalf("invalid id: %v", err)
	}

	t.Run("end_wins_row_lock", func(t *testing.T) {
		session := &AttendedSession{GroupID: gid, TechnicianID: uid}
		if _, err := store.Create(ctx, tid, session); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE attended_session SET state='consented' WHERE id=$1`, session.ID); err != nil {
			t.Fatal(err)
		}
		config := appPool.Config()
		config.MaxConns = 1
		config.ConnConfig.RuntimeParams["application_name"] = "promotion-state-row-lock"
		racePool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer racePool.Close()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `UPDATE attended_session SET state='ended',promote_token='' WHERE id=$1`, session.ID); err != nil {
			t.Fatal(err)
		}
		workCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		result := make(chan error, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			result <- NewPgAttendedStore(racePool).SetPromoteToken(workCtx, tid, session.ID, "late")
		}()
		defer func() {
			_ = tx.Rollback(ctx)
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("owned stash worker did not finish")
			}
		}()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		// Prove the candidate UPDATE is actually waiting on our row lock before committing End.
		for {
			var waiting bool
			if err := pool.QueryRow(workCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='promotion-state-row-lock' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case <-ticker.C:
			case <-workCtx.Done():
				t.Fatal("stash did not reach the held row lock")
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrAttendedNotPromotable) {
			t.Fatalf("late stash after End: %v", err)
		}
		got, err := store.Get(ctx, tid, session.ID)
		if err != nil || got.State != AttendedEnded || got.PromoteToken != "" {
			t.Fatalf("late stash resurrected promotion: %#v %v", got, err)
		}
	})
}
