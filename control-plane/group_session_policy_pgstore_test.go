package controlplane

// DB-gated proofs for §5 per-group seat metering (loop 78), driven as the least-privilege rmt_app role RLS
// is enforced against: the per-group policy store (Get/Set upsert + delete-on-zero, cross-tenant isolation,
// the composite-FK block on a cross-tenant write) and — the crux — that StartSessionWithinLimit enforces the
// GROUP cap ATOMICALLY under concurrency, so a burst of parallel starts in one group cannot each read "under
// the cap" and all win. Needs TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a skip as failure.
//
// group_session_policy + session_record.group_id come from migration 0034, applied by resetSchema (in the
// always-on list), so no per-test apply helper is needed — 0005's blanket GRANT ON ALL TABLES (run by
// applyAppRoleMigration after resetSchema) covers the new table for rmt_app.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPgGroupSessionPolicyUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: the machine projection seedGroupMachine/session join need
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "gsp-a", "a@gsp-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "gsp-b", "b@gsp-b.test", "password-1234")
	gidA, _ := seedGroupMachine(t, suPool, tidA, "gsp-a-dev")
	gidB, _ := seedGroupMachine(t, suPool, tidB, "gsp-b-dev")

	appPool := newAppRolePool(t, ctx)
	store := NewPgGroupSessionPolicyStore(appPool)

	// Unset → 0 (unlimited by group), no row.
	if got, err := store.Get(ctx, tidA, gidA); err != nil || !got.IsDefault() {
		t.Fatalf("unset A/gidA = (%+v, %v), want the default policy", got, err)
	}
	// Upsert insert then update; each read-back reflects the last write.
	if err := store.Set(ctx, tidA, gidA, GroupSessionPolicy{MaxConcurrentSessions: 5}); err != nil {
		t.Fatalf("Set insert: %v", err)
	}
	if got, _ := store.Get(ctx, tidA, gidA); got.MaxConcurrentSessions != 5 {
		t.Fatalf("after insert = %d, want 5", got.MaxConcurrentSessions)
	}
	if err := store.Set(ctx, tidA, gidA, GroupSessionPolicy{MaxConcurrentSessions: 2}); err != nil {
		t.Fatalf("Set update: %v", err)
	}
	if got, _ := store.Get(ctx, tidA, gidA); got.MaxConcurrentSessions != 2 {
		t.Fatalf("after update = %d, want 2", got.MaxConcurrentSessions)
	}
	if list, _ := store.List(ctx, tidA); len(list) != 1 || list[0].GroupID != gidA || list[0].MaxConcurrentSessions != 2 {
		t.Fatalf("List A = %+v, want [gidA:2]", list)
	}
	// Set(0) DELETEs the row → Get reads unlimited, List drops it.
	if err := store.Set(ctx, tidA, gidA, GroupSessionPolicy{}); err != nil {
		t.Fatalf("Set clear: %v", err)
	}
	if got, _ := store.Get(ctx, tidA, gidA); !got.IsDefault() {
		t.Fatalf("after clear = %+v, want the default policy", got)
	}
	if list, _ := store.List(ctx, tidA); len(list) != 0 {
		t.Fatalf("List after clear = %+v, want empty", list)
	}

	// EVERY SETTING ON THE ROW MUST SURVIVE THE PG ROUND TRIP, not just the cap — a column can be added to
	// the struct, the fake and two of the pg store's THREE SQL sites (Get's SELECT, Set's INSERT + ON
	// CONFLICT, List's SELECT) and still compile, reading back false from whichever site was missed. The
	// fake's own version of these assertions is in group_session_policy_test.go; a test against the fake
	// says nothing about pg's semantics, which is this package's most-repeated defect.
	//
	// The state under test is the one migration 0040 exists for: view-only WITH the deliberate backstage
	// opt-out. Both bools true and the cap 0, so a Set that dropped either boolean would also have to be
	// caught here rather than by a cap that happens to be non-zero.
	both := GroupSessionPolicy{MaxConcurrentSessions: 0, EnforceViewOnly: true, AllowBackstageUnderViewOnly: true}
	if err := store.Set(ctx, tidA, gidA, both); err != nil {
		t.Fatalf("Set both bools: %v", err)
	}
	got, err := store.Get(ctx, tidA, gidA)
	if err != nil {
		t.Fatalf("Get both bools: %v", err)
	}
	if !got.EnforceViewOnly || !got.AllowBackstageUnderViewOnly || got.MaxConcurrentSessions != 0 {
		t.Fatalf("Get after Set(view-only + backstage opt-out) = %+v, want both flags true and cap 0", got)
	}
	// LIST is a SEPARATE query with its own projection and its own Scan, so it is asserted separately —
	// a column present in Get's SELECT but missing from List's would show as false only here.
	if list, lerr := store.List(ctx, tidA); lerr != nil || len(list) != 1 ||
		!list[0].EnforceViewOnly || !list[0].AllowBackstageUnderViewOnly {
		t.Fatalf("List = (%+v, %v), want one row carrying BOTH flags", list, lerr)
	}
	// The UPSERT path (ON CONFLICT DO UPDATE) is distinct from the INSERT path above and has its own
	// column list. Revoking ONLY the opt-out must leave the mandate standing — and must actually revoke.
	if err := store.Set(ctx, tidA, gidA, GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
		t.Fatalf("Set revoke opt-out: %v", err)
	}
	if got, _ := store.Get(ctx, tidA, gidA); !got.EnforceViewOnly || got.AllowBackstageUnderViewOnly {
		t.Fatalf("after revoking only the opt-out = %+v, want {viewOnly:true allowBackstage:false}", got)
	}
	// THE ROW-DELETION RULE FOR THE THIRD SETTING, in pg as in the fake: a policy whose ONLY non-default
	// field is the backstage opt-out is NOT default, so Set must UPSERT it rather than DELETE it. Asserted
	// with the opt-out alone — with any other field set the row would survive for that field's sake and an
	// IsDefault() that ignored the opt-out would still pass (migration 0035's warning, second occurrence).
	if err := store.Set(ctx, tidA, gidA, GroupSessionPolicy{AllowBackstageUnderViewOnly: true}); err != nil {
		t.Fatalf("Set opt-out alone: %v", err)
	}
	if got, _ := store.Get(ctx, tidA, gidA); !got.AllowBackstageUnderViewOnly {
		t.Fatalf("opt-out alone = %+v, want it to have survived (the row must not be deleted)", got)
	}
	if list, _ := store.List(ctx, tidA); len(list) != 1 || !list[0].AllowBackstageUnderViewOnly {
		t.Fatalf("List with only the opt-out set = %+v, want one row carrying it", list)
	}
	// …and clearing everything still deletes, so the new field did not turn the delete path off.
	if err := store.Set(ctx, tidA, gidA, GroupSessionPolicy{}); err != nil {
		t.Fatalf("Set clear all: %v", err)
	}
	if list, _ := store.List(ctx, tidA); len(list) != 0 {
		t.Fatalf("List after clearing every setting = %+v, want empty", list)
	}

	// Cross-tenant WRITE is impossible: pinned to A, a cap for B's GROUP fails the composite FK (the
	// (A, gidB) pair is not a machine_group row — RLS makes B's group invisible, so its pair is absent).
	if err := store.Set(ctx, tidA, gidB, GroupSessionPolicy{MaxConcurrentSessions: 3}); err == nil {
		t.Fatalf("Set(A, gidB) succeeded, want a foreign-key violation (cross-tenant write must be blocked)")
	}

	// RLS isolation: B's own cap is invisible to A's List and vice versa.
	if err := store.Set(ctx, tidB, gidB, GroupSessionPolicy{MaxConcurrentSessions: 9}); err != nil {
		t.Fatalf("Set B: %v", err)
	}
	if list, _ := store.List(ctx, tidA); len(list) != 0 {
		t.Fatalf("A List sees B's cap = %+v, want empty (RLS)", list)
	}
	if list, _ := store.List(ctx, tidB); len(list) != 1 || list[0].GroupID != gidB {
		t.Fatalf("B List = %+v, want [gidB:9]", list)
	}
}

// TestPgStartSessionWithinGroupLimitAtomic is the per-group atomicity proof: with a group cap of K, firing
// N > K parallel starts in that group must leave EXACTLY K open — the same per-tenant advisory lock that
// serializes the tenant count also serializes the group count, so no two starts in the group both win.
func TestPgStartSessionWithinGroupLimitAtomic(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: machine projection the session join needs
	tid, uid := provisionUser(t, suPool, "gsp-atomic", "t@gsp-atomic.test", "password-1234")
	gid, mid := seedGroupMachine(t, suPool, tid, "gsp-atomic-dev")
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)

	const N, K = 8, 3
	var wg sync.WaitGroup
	results := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Tenant axis unlimited (0); only the GROUP cap is under test. MachineGroupID is the admitted
			// group snapshot the pg store persists + counts, exactly as the handler sets it.
			rec := &SessionRecord{MachineID: mid, TechnicianID: uid, MachineGroupID: gid}
			results[i] = store.StartSessionWithinLimit(ctx, tid, rec, SessionStartLimits{GroupID: gid, Group: K})
		}(i)
	}
	wg.Wait()

	ok, limited, other := 0, 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case err == ErrGroupConcurrentSessionLimit:
			limited++
		default:
			other++
		}
	}
	if other != 0 {
		t.Fatalf("%d starts failed with an unexpected error: %v", other, results)
	}
	if ok != K || limited != N-K {
		t.Fatalf("concurrent group starts: %d succeeded, %d group-limited; want %d/%d "+
			"(a non-atomic group count+insert would let more than %d through)", ok, limited, K, N-K, K)
	}
	// The database agrees: exactly K open sessions.
	list, err := store.ListSessions(ctx, tid, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	open := 0
	for _, s := range list {
		if s.EndedAt == nil {
			open++
		}
	}
	if open != K {
		t.Fatalf("open sessions in DB = %d, want %d", open, K)
	}
}

// The per-group seat count reads session_record.group_id — the group the session was ADMITTED against,
// snapshotted at start — NOT the machine's LIVE group resolved by joining `machine`. That is loop 78's
// central design claim and, until this test, nothing pinned it: every existing case starts and counts
// sessions for machines that never move, and a live-JOIN implementation passes all of them identically.
//
// The discriminator is a machine that MOVES mid-session, plus a SECOND machine left behind:
//
//	group A (cap 1) holds machines M and N.
//	S1 starts for M                     → admitted against A; A is now full (1/1).
//	M is reassigned to group B.
//	S2 is attempted for N (still in A)  → SNAPSHOT: S1 still counts against A → refused.
//	                                      LIVE JOIN: S1 now counts against B → A reads 0/1 → ALLOWED.
//
// So a live-JOIN count fails exactly here and nowhere else. The complement (end S1, retry S2, expect
// success) is what stops the refusal being credited to some unrelated failure — without it, a store that
// refused every start would pass.
func TestPgGroupSeatCountUsesTheAdmittedGroupSnapshotNotTheLiveGroup(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "gsp-snap", "a@gsp-snap.test", "password-1234")
	gidA, midM := seedGroupMachine(t, suPool, tid, "gsp-snap-m")
	midN := seedNamedMachine(t, suPool, tid, gidA, "gsp-snap-n", "HOST-N")
	gidB, _ := seedGroupMachine(t, suPool, tid, "gsp-snap-other")

	appPool := newAppRolePool(t, ctx)
	store := NewPgSessionRecordStore(appPool)
	limitsA := SessionStartLimits{GroupID: gidA, Group: 1}

	// S1 fills group A's single seat.
	s1 := &SessionRecord{MachineID: midM, TechnicianID: uid, MachineGroupID: gidA}
	if err := store.StartSessionWithinLimit(ctx, tid, s1, limitsA); err != nil {
		t.Fatalf("first start in group A: %v", err)
	}

	// M moves to group B. Its OPEN session must not move with it.
	if err := withTenant(ctx, suPool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE machine SET group_id = $1 WHERE id = $2`, gidB, midM)
		return err
	}); err != nil {
		t.Fatalf("reassign machine M to group B: %v", err)
	}

	// N is still in A, and A's seat is still held by S1's SNAPSHOT.
	s2 := &SessionRecord{MachineID: midN, TechnicianID: uid, MachineGroupID: gidA}
	err := store.StartSessionWithinLimit(ctx, tid, s2, limitsA)
	if err != ErrGroupConcurrentSessionLimit {
		t.Fatalf("start in group A after its only open session's machine moved away = %v, "+
			"want ErrGroupConcurrentSessionLimit — the seat must stay in the group the session was "+
			"ADMITTED against (a live machine→group JOIN would have freed it and allowed this start)", err)
	}

	// Complement: free the seat properly and the SAME start now succeeds, so the refusal above was the
	// group cap and not an unrelated error.
	if _, err := store.EndSession(ctx, tid, s1.ID, time.Now().UTC()); err != nil {
		t.Fatalf("end S1: %v", err)
	}
	if err := store.StartSessionWithinLimit(ctx, tid, s2, limitsA); err != nil {
		t.Fatalf("start in group A after the seat was genuinely released: %v", err)
	}

	// And the snapshot really is persisted: S1's session_record.group_id is still group A even though
	// its machine now lives in B.
	//
	// Asserted with SQL against the COLUMN, deliberately, NOT via GetSession. SessionRecord.
	// MachineGroupID is asymmetric — the admitted group on write, but the machine's LIVE group
	// (JOIN-derived) on read, so a Get here returns gidB and would make this assertion test the
	// opposite of what it claims. That asymmetry is by design (RBAC scoping must follow a moved
	// machine) but it means the snapshot has no read-model accessor; see the field's doc comment.
	var snapshot string
	if err := withTenant(ctx, suPool, tid, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT group_id::text FROM session_record WHERE id = $1`, s1.ID).Scan(&snapshot)
	}); err != nil {
		t.Fatalf("read S1 group snapshot: %v", err)
	}
	if snapshot != gidA {
		t.Fatalf("session_record.group_id for S1 = %q, want the ADMITTED group %q "+
			"(the machine has since moved to %q, which must not follow the open seat)",
			snapshot, gidA, gidB)
	}
}
