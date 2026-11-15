package controlplane

// `attended_session` must sit at the same tenant-isolation posture as every other tenant-scoped
// table (migration 0022).
//
// PREMISE, declared locally: 0013 created this table with three divergences from its siblings, and
// each was MEASURED against the live schema before 0022 was written:
//
//	1. no composite (tenant_id, group_id) FK — `machine` and `enrollment_token` both carry one, and
//	   0001's own comment says it closes "a cross-tenant group-assignment hole RLS alone would not
//	   catch on writes";
//	2. the ONLY tenant policy in the migration set passing `missing_ok => true`, so an unpinned read
//	   returned an empty result where `machine` and `enrollment_token` raised;
//	3. the only one of the four without FORCE ROW LEVEL SECURITY (pg_class.relforcerowsecurity=f).
//
// The third leg here is the one that matters most for confidence: it proves the tightened policy did
// NOT break the public guest paths. Those are pre-tenant by design (the guest holds a code, not a
// principal) and reach the table only through SECURITY DEFINER functions owned by a BYPASSRLS role,
// so they never evaluate the policy at all. That is why `missing_ok` was safe to remove — and this
// test is what stops that reasoning from being merely an argument.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func applyAttendedParityMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0022_attended_session_parity.sql")
	if err != nil {
		t.Fatalf("read 0022: %v", err)
	}
	execScript(t, pool, string(b))
}

func TestPgAttendedSessionMatchesItsSiblingsIsolationPosture(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)             // 0005 — rmt_app must exist
	applyMachineDeviceUniqueMigration(t, suPool) // 0008
	applyDeviceIdentityMigration(t, suPool)      // 0010
	applyAttendedMigration(t, suPool)            // 0013
	applyAttendedTenantActiveMigration(t, suPool)
	applyAttendedParityMigration(t, suPool) // 0022 — under test

	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	// --- 1. The composite FK rejects a group from ANOTHER tenant -----------------------------------
	otherTid, _ := provisionUser(t, suPool, "other", "tech@other.test", "password-1234")
	foreignGid := seedGroup(t, suPool, otherTid)

	// Negative control FIRST: a group in the SAME tenant inserts fine. Without this leg a constraint
	// that rejected every insert would satisfy the assertion below.
	if _, err := suPool.Exec(ctx,
		`INSERT INTO attended_session (tenant_id, group_id, technician_id, code_hash, state, expires_at)
		 VALUES ($1,$2,$3,$4,'pending', now() + interval '10 minutes')`,
		tid, gid, uid, []byte("own-tenant-group")); err != nil {
		t.Fatalf("premise not met: a same-tenant group was rejected: %v", err)
	}

	_, err := suPool.Exec(ctx,
		`INSERT INTO attended_session (tenant_id, group_id, technician_id, code_hash, state, expires_at)
		 VALUES ($1,$2,$3,$4,'pending', now() + interval '10 minutes')`,
		tid, foreignGid, uid, []byte("cross-tenant-group"))
	if err == nil {
		t.Fatal("SECURITY: an attended_session was written naming a group that belongs to a DIFFERENT " +
			"tenant — the composite FK its two siblings carry is not enforced")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("cross-tenant group was rejected, but not by the FK: %v", err)
	}

	// --- 2. An UNPINNED read RAISES, exactly as the siblings do -------------------------------------
	appPool := newAppRolePool(t, ctx)
	var n int
	sibErr := appPool.QueryRow(ctx, `SELECT count(*) FROM machine`).Scan(&n)
	if sibErr == nil {
		t.Fatal("premise not met: an unpinned read of `machine` did not raise, so this database is " +
			"not in the posture this test compares against")
	}
	attErr := appPool.QueryRow(ctx, `SELECT count(*) FROM attended_session`).Scan(&n)
	if attErr == nil {
		t.Fatal("an unpinned read of attended_session returned rows instead of raising: a missing " +
			"tenant pin is a bug and must be loud here as it is on every sibling table")
	}

	// --- 3. FORCE ROW LEVEL SECURITY matches the siblings -------------------------------------------
	var forced bool
	if err := suPool.QueryRow(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'attended_session'`).Scan(&forced); err != nil {
		t.Fatalf("read relforcerowsecurity: %v", err)
	}
	if !forced {
		t.Fatal("attended_session still lacks FORCE ROW LEVEL SECURITY, which machine, " +
			"enrollment_token and audit_event all carry")
	}

	// --- 4. The PUBLIC GUEST PATH still works — the point of the whole exercise ---------------------
	// Redeem is pre-tenant: nothing is pinned, and it reaches the table only through a SECURITY
	// DEFINER function owned by a BYPASSRLS role. If tightening the policy had broken the guest, it
	// would break here.
	store := NewPgAttendedStore(appPool)
	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "parity"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create (tenant-pinned) after 0022: %v", err)
	}
	if _, err := store.Redeem(ctx, code, attendTestPubkey, "USER-PC"); err != nil {
		t.Fatalf("REGRESSION: the PUBLIC guest redeem path broke under the tightened RLS policy: %v", err)
	}
}
