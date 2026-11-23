package controlplane

// The PG half of the loop-83 floor flag (migration 0036), plus the fake↔pg CONTRACT it has to satisfy.
//
// Why a whole file for one boolean. This repo's standing lesson is that a fake and its Pg*Store share
// ONE contract, and a test written against the fake says nothing about the pg store's divergent
// semantics. There are two divergences available here and both are exercised below:
//
//   1. THE PROJECTION. `attendedColumns` and `scanAttended` are positional pairs with no compile-time
//      coupling, and every read path funnels through them. (Deliberately no COUNT here: the first draft
//      of this comment said "14" on the day the column made it 15, and the production comment states the
//      same invariant without a number for exactly that reason.) A column added to one list and
//      not the other is a runtime scan error; a column added in the WRONG POSITION typechecks, because
//      the neighbours share types. So the flag is asserted through EVERY read, with the neighbouring
//      string and time fields checked at the same time.
//   2. CREATE. The fake copies whatever the caller pre-set on the struct; the pg INSERT names a fixed
//      column list and never re-reads the row. A caller-set flag therefore persists in the fake and
//      vanishes in production unless the fake explicitly overwrites it. Asserted on BOTH stores, from
//      one table, so neither can drift alone.

import (
	"context"
	"errors"
	"testing"
)

// TestPgAttendedRequireSessionPolicy drives the flag through the pg store's whole read surface.
func TestPgAttendedRequireSessionPolicy(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)             // 0005 — 0013 GRANTs to rmt_app, so the role must exist
	applyMachineDeviceUniqueMigration(t, suPool) // 0008
	applyDeviceIdentityMigration(t, suPool)      // 0010
	applyAttendedMigration(t, suPool)            // 0013 + 0036
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	otherTid, _ := provisionUser(t, suPool, "beta", "tech@beta.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	// The store runs as the LEAST-PRIVILEGE rmt_app role, which is the only way the cross-tenant leg
	// below proves anything: newTestPool connects as the superuser, and a superuser BYPASSES RLS
	// entirely, so the same assertion against it would pass on a store with no tenant pinning at all.
	// (This test was written against the superuser pool first, and that is exactly what it showed —
	// a cross-tenant write "succeeding" that in production RLS refuses.)
	store := NewPgAttendedStore(newAppRolePool(t, ctx))

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "printer"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// A brand-new session has NOT been told to floor. 0036's DEFAULT false is what makes every row
	// that predates the column correct rather than merely non-null.
	if sess.RequireSessionPolicy {
		t.Fatal("a freshly created attended session already carries the floor flag")
	}
	if got, err := store.Get(ctx, tid, sess.ID); err != nil || got.RequireSessionPolicy {
		t.Fatalf("Get on a fresh session: flag=%v err=%v, want false", got.RequireSessionPolicy, err)
	}

	res, err := store.Redeem(ctx, code, attendTestPubkey, "USER-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	// The write, exactly where the handler does it: after redemption, before consent.
	if err := store.SetRequireSessionPolicy(ctx, tid, sess.ID); err != nil {
		t.Fatalf("SetRequireSessionPolicy: %v", err)
	}

	// READ 1 — Get (the technician's projection).
	got, err := store.Get(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.RequireSessionPolicy {
		t.Fatal("the floor flag did not survive a round trip through Get")
	}
	// The neighbours, in the same read. A column inserted at the wrong offset in `attendedColumns`
	// typechecks (reason/consent_user/promote_token are all strings), so the only thing that catches it
	// is asserting that VALUE-DISTINCT fields still land in the right places.
	if got.Reason != "printer" {
		t.Fatalf("reason = %q, want %q — the projection's positional pairs have drifted, which silently "+
			"lands one column's value in another's field", got.Reason, "printer")
	}
	if got.GroupID != gid || got.TechnicianID != uid {
		t.Fatalf("group/technician = %q/%q, want %q/%q (projection drift)",
			got.GroupID, got.TechnicianID, gid, uid)
	}
	if got.RedeemedAt == nil {
		t.Fatal("redeemed_at is nil after a successful redeem (projection drift among the *time.Time run)")
	}

	// READ 2 — ByToken (the GUEST's projection, a different query).
	byTok, err := store.ByToken(ctx, res.AttendToken)
	if err != nil {
		t.Fatalf("ByToken: %v", err)
	}
	if !byTok.RequireSessionPolicy {
		t.Fatal("the floor flag is invisible through ByToken")
	}

	// READ 3 — Consent (the guest's transition), then READ 4 — MarkActive (what CONNECT actually reads).
	// MarkActive is the one that matters most: the fix reads `active.RequireSessionPolicy` off exactly
	// this row, so a projection that dropped the column here would make the whole feature inert while
	// every other read still looked right.
	consented, err := store.Consent(ctx, res.AttendToken, true, "alice")
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	if !consented.RequireSessionPolicy {
		t.Fatal("the floor flag is invisible through Consent")
	}
	// The THREE *time.Time columns at the tail of the projection are the easiest place for a positional
	// swap to hide: they are the same type, all nullable, and until an adversarial review reproduced it,
	// swapping `consented_at` and `ended_at` passed every attended test in the tree. It is not internal
	// bookkeeping either — both fields are on the JSON of GET /attended-sessions/{id}, so the swap ships
	// a live session whose "consented at" is its end time. Pin them by their DISTINGUISHING property:
	// right now consent has happened and the session has not ended.
	if consented.ConsentedAt == nil {
		t.Fatal("consented_at is nil straight after a successful Consent (projection drift)")
	}
	if consented.EndedAt != nil {
		t.Fatalf("ended_at is set on a session that has NOT ended (%v) — consented_at and ended_at are "+
			"swapped in the projection, which ships a session whose consent time is its end time",
			consented.EndedAt)
	}
	active, err := store.MarkActive(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if !active.RequireSessionPolicy {
		t.Fatal("the floor flag is invisible through MarkActive — this is the read handleConnectAttended " +
			"uses, so the mint decision would silently fall back to group-only and the guest would be " +
			"stranded exactly as before the fix")
	}

	// READ 5 — End. The flag is a HISTORICAL record of what the guest was told, not live state, so
	// unlike promote_token it must NOT be cleared on teardown.
	ended, err := store.End(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("End: %v", err)
	}
	if !ended.RequireSessionPolicy {
		t.Fatal("End cleared the floor flag — it records what the guest was TOLD, which does not stop " +
			"being true when the session finishes")
	}
	// The other half of the swap check: after End, BOTH timestamps must be set. Asserting only this one
	// would be satisfied by a swap (End writes ended_at, so a swapped read finds a value either way) —
	// it is the pair of assertions, before and after End, that makes the columns distinguishable.
	if ended.EndedAt == nil {
		t.Fatal("ended_at is nil after End (projection drift among the *time.Time run)")
	}
	if ended.ConsentedAt == nil {
		t.Fatal("consented_at was lost by End — the two tail timestamps are swapped or misread")
	}

	// Misses, on the same shapes Get uses: an unknown uuid and a string no uuid column could hold must
	// both be ErrAttendedNotFound, never a 500-shaped driver error.
	if err := store.SetRequireSessionPolicy(ctx, tid, "11111111-1111-1111-1111-111111111111"); !errors.Is(err, ErrAttendedNotFound) {
		t.Fatalf("SetRequireSessionPolicy on an unknown id: err=%v, want ErrAttendedNotFound", err)
	}
	if err := store.SetRequireSessionPolicy(ctx, tid, "not-a-uuid"); !errors.Is(err, ErrAttendedNotFound) {
		t.Fatalf("SetRequireSessionPolicy on a non-uuid id: err=%v, want ErrAttendedNotFound", err)
	}
	// Cross-tenant: RLS must make another tenant's session unreachable, not merely unreadable.
	if err := store.SetRequireSessionPolicy(ctx, otherTid, sess.ID); !errors.Is(err, ErrAttendedNotFound) {
		t.Fatalf("SetRequireSessionPolicy across tenants: err=%v, want ErrAttendedNotFound", err)
	}
	if got, err := store.Get(ctx, tid, sess.ID); err != nil || !got.RequireSessionPolicy {
		t.Fatalf("a cross-tenant write changed or hid the row: flag=%v err=%v", got.RequireSessionPolicy, err)
	}

	// Cleanup through the pool we already hold. Calling newTestPool again would not just give another
	// connection — it RESETS THE SCHEMA, dropping the table this cleanup is about to delete from.
	for _, cleanup := range []string{tid, otherTid} {
		if _, err := suPool.Exec(ctx, "DELETE FROM attended_session WHERE tenant_id = $1", cleanup); err != nil {
			t.Fatalf("cleanup attended %s: %v", cleanup, err)
		}
		if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", cleanup); err != nil {
			t.Fatalf("cleanup tenant %s: %v", cleanup, err)
		}
	}
}

// TestAttendedCreateNeverAcceptsACallerSetFloor pins the fake↔pg contract for Create on BOTH stores from
// one table. The floor is decided at REDEEM; Create must ignore it. The fake would otherwise happily
// keep it (it copies the caller's struct) while pg drops it (fixed INSERT column list), and the next
// field added to this struct would inherit the divergence silently.
func TestAttendedCreateNeverAcceptsACallerSetFloor(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	// Superuser pool is fine here: this test is about what Create RETURNS and PERSISTS, not about
	// tenant isolation, and it needs the same pool for setup, the store and the cleanup.

	machines := NewInMemoryMachineStore()
	for _, tc := range []struct {
		name  string
		store AttendedStore
		tid   string
	}{
		{"fake", NewInMemoryAttendedStore(machines), "00000000-0000-0000-0000-0000000000bb"},
		{"pg", NewPgAttendedStore(pool), tid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := &AttendedSession{
				GroupID:      gid,
				TechnicianID: uid,
				Reason:       "printer",
				// The caller lies. Both stores must ignore it.
				RequireSessionPolicy: true,
			}
			if _, err := tc.store.Create(ctx, tc.tid, sess); err != nil {
				t.Fatalf("create: %v", err)
			}
			if sess.RequireSessionPolicy {
				t.Fatal("Create honoured a caller-set floor flag in its returned struct — the two stores " +
					"disagree about what a created session looks like, and the fake is the one every " +
					"handler test uses")
			}
			got, err := tc.store.Get(ctx, tc.tid, sess.ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.RequireSessionPolicy {
				t.Fatal("a caller-set floor flag was PERSISTED by Create")
			}
		})
	}

	if _, err := pool.Exec(ctx, "DELETE FROM attended_session WHERE tenant_id = $1", tid); err != nil {
		t.Fatalf("cleanup attended: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
