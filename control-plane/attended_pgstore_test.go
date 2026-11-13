package controlplane

// DB-gated integration tests for the attended-session store (docs/12): the SECURITY DEFINER
// cp_attended_redeem / cp_attended_consent redemption + consent chain, the consent gate
// (MarkActive refuses until consented), and the ephemeral-machine expiry that
// cp_machine_identity_by_device_id (as replaced by 0013) enforces so signaling won't authenticate a
// lapsed guest. Like every pgx test these SKIP without TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// applyAttendedMigration lays 0013 on top of the schema. It CREATE-OR-REPLACEs
// cp_machine_identity_by_device_id, so apply applyDeviceIdentityMigration (0010) first (which itself
// needs 0008) — applying 0010 AFTER this would silently revert the expired-guest refusal;
// resetSchema DROPs the attended table + cp_attended_* functions.
//
// NOT only for attended tests: 0013 adds machine.ephemeral/expires_at, and PgMachineStore's
// projection (and ListMachines' `WHERE NOT m.ephemeral` fleet-listing contract) reads them — so
// EVERY test that exercises PgMachineStore must apply this or every machine read fails 42703.
// It also GRANTs to rmt_app, so applyAppRoleMigration (0005) must have run first.
func applyAttendedMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// 0013 redefines the identity function with its OLD return type; 0068 changed that type, so the older
	// definition is applied over a clean slate and this helper ends on the LATEST definition (below).
	execScript(t, pool, `DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);`)
	// 0013 then 0036, in that order, from ONE helper: `attended_session` does not exist until 0013
	// (it is opt-in, not part of resetSchema's always-on list), and 0036 ALTERs it. Every attended
	// test goes through here, so a new column on that table needs no per-test edit — and must not
	// get one, because a test that forgot it fails with a bare 42703 from whichever projection ran
	// first, which reads like a broken query rather than a missing migration.
	for _, m := range []string{
		"migrations/0013_attended_sessions.sql",
		"migrations/0036_attended_require_session_policy.sql",
		"migrations/0042_attended_audit_key.sql",
		"migrations/0052_attended_promote_result.sql",
		"migrations/0059_attended_consent_tenant_active.sql",
	} {
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("read %s: %v", m, err)
		}
		execScript(t, pool, string(b))
	}
	applyLatestIdentityFunction(t, pool)
}

func TestPgAttendedConsentGateAndRedeem(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool) // 0008
	applyDeviceIdentityMigration(t, pool)      // 0010
	applyAttendedMigration(t, pool)            // 0013
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()

	store := NewPgAttendedStore(pool)
	machines := NewPgMachineStore(pool)

	// Create (tenant-pinned) → pending.
	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "printer"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.State != AttendedPending || sess.ID == "" {
		t.Fatalf("bad created session: %+v", sess)
	}

	// Consent gate BEFORE redemption: MarkActive must refuse.
	if _, err := store.MarkActive(ctx, tid, sess.ID); !errors.Is(err, ErrAttendedNotConsented) {
		t.Fatalf("MarkActive on pending: err=%v, want ErrAttendedNotConsented", err)
	}

	// Redeem (PRE-TENANT) → ephemeral machine minted, pubkey pinned, attend token issued.
	res, err := store.Redeem(ctx, code, attendTestPubkey, "USER-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if res.DeviceID == "" || res.AttendToken == "" || res.TenantID != tid {
		t.Fatalf("bad redeem result: %+v", res)
	}

	// The ephemeral guest's identity resolves (so signaling can authenticate it).
	id, err := machines.LookupDeviceIdentity(ctx, res.DeviceID)
	if err != nil || id.Pubkey != attendTestPubkey || id.TenantID != tid {
		t.Fatalf("ephemeral identity not resolvable: id=%+v err=%v", id, err)
	}

	// Consent gate AFTER redemption but BEFORE consent: still refused.
	if _, err := store.MarkActive(ctx, tid, sess.ID); !errors.Is(err, ErrAttendedNotConsented) {
		t.Fatalf("MarkActive on redeemed: err=%v, want ErrAttendedNotConsented", err)
	}

	// Consent (by attend token) → consented; now MarkActive works.
	s2, err := store.Consent(ctx, res.AttendToken, true, "alice")
	if err != nil || s2.State != AttendedConsented || s2.ConsentUser != "alice" {
		t.Fatalf("consent: state=%v user=%q err=%v", s2.State, s2.ConsentUser, err)
	}
	s3, err := store.MarkActive(ctx, tid, sess.ID)
	if err != nil || s3.State != AttendedActive {
		t.Fatalf("MarkActive after consent: state=%+v err=%v", s3, err)
	}
	// The handoff write reports the technician it replaced, read under the row lock, and persists.
	var peer string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&peer); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,'peer@att.test')`, peer, tid)
	if prev, err := store.ReassignTechnician(ctx, tid, sess.ID, peer); err != nil || prev != uid {
		t.Fatalf("ReassignTechnician: prev=%q err=%v, want prev=%q", prev, err, uid)
	}
	if got, err := store.Get(ctx, tid, sess.ID); err != nil || got.TechnicianID != peer {
		t.Fatalf("after reassign: %+v err=%v", got, err)
	}
	if prev, err := store.ReassignTechnician(ctx, tid, sess.ID, uid); err != nil || prev != peer {
		t.Fatalf("reassign back: prev=%q err=%v", prev, err)
	}

	// Generic errors: a bad code and a bad attend token are both undifferentiated.
	if _, err := store.Redeem(ctx, "ZZZZZZZZZZZZ", attendTestPubkey, ""); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("bad code: err=%v, want ErrAttendedInvalid", err)
	}
	if _, err := store.ByToken(ctx, "not-a-real-token"); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("bad token: err=%v, want ErrAttendedInvalid", err)
	}

	// End reaps the ephemeral machine and identity resolution then misses it.
	if _, err := store.End(ctx, tid, sess.ID); err != nil {
		t.Fatalf("end: %v", err)
	}
	if _, err := machines.LookupDeviceIdentity(ctx, res.DeviceID); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("identity after end: err=%v, want ErrMachineNotFound", err)
	}
}

// TestPgAttendedEphemeralExpiryRefused proves cp_machine_identity_by_device_id (as replaced by 0013)
// refuses an ephemeral machine past its expiry, so signaling cannot authenticate a lapsed guest.
func TestPgAttendedEphemeralExpiryRefused(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()

	store := NewPgAttendedStore(pool)
	machines := NewPgMachineStore(pool)
	sess := &AttendedSession{GroupID: gid, TechnicianID: uid}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "USER-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	// Live → resolvable.
	if _, err := machines.LookupDeviceIdentity(ctx, res.DeviceID); err != nil {
		t.Fatalf("live identity: %v", err)
	}
	// Backdate the machine's expiry (superuser test pool bypasses RLS) → resolution must refuse it.
	if _, err := pool.Exec(ctx, `UPDATE machine SET expires_at = now() - interval '1 hour' WHERE device_id = $1`, res.DeviceID); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	if _, err := machines.LookupDeviceIdentity(ctx, res.DeviceID); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("expired identity: err=%v, want ErrMachineNotFound", err)
	}
}

// TestPgAttendedGuestHiddenFromFleetListing is the regression for a HIGH-severity divergence the
// adversarial review found: the fleet-listing contract ("ephemeral rows are hidden", stated in
// migrations/0013 and docs/12 §10.1) was implemented ONLY in InMemoryMachineStore. Every test that
// asserted it ran against that fake, so PgMachineStore — production — returned attended guests in
// GET /machines, where the console rendered them as connectable fleet machines.
//
// It runs as rmt_app so RLS is genuinely in force, and it drives the REAL redeem path rather than
// hand-inserting a row, so it also proves cp_attended_redeem still marks the guest ephemeral.
func TestPgAttendedGuestHiddenFromFleetListing(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "att-fleet", "tech@att.test", "Original-Passw0rd!")
	gid, _ := seedGroupMachine(t, suPool, tid, "managed-dev")

	appPool := newAppRolePool(t, ctx)
	machines := NewPgMachineStore(appPool)
	attended := NewPgAttendedStore(appPool)

	// A real attended session, redeemed by a guest → an ephemeral machine row.
	sess := &AttendedSession{TenantID: tid, GroupID: gid, TechnicianID: uid, Reason: "fleet-listing test"}
	code, err := attended.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("Create attended: %v", err)
	}
	redeemed, err := attended.Redeem(ctx, code, attendTestPubkey, "GUEST-PC")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if redeemed.DeviceID == "" {
		t.Fatal("redeem produced no guest device id")
	}

	// Cross-check with the superuser that the row really is there and really is ephemeral —
	// otherwise the assertion below could pass for the wrong reason.
	var ephemeral bool
	if err := suPool.QueryRow(ctx,
		`SELECT ephemeral FROM machine WHERE device_id = $1`, redeemed.DeviceID).Scan(&ephemeral); err != nil {
		t.Fatalf("read guest machine row: %v", err)
	}
	if !ephemeral {
		t.Fatal("test premise: the redeemed guest machine is not marked ephemeral")
	}

	// THE ASSERTION: the fleet listing must not contain it, while the managed machine still does.
	list, err := machines.ListMachines(ctx, tid)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	var sawManaged bool
	for _, m := range list {
		if m.DeviceID == redeemed.DeviceID {
			t.Fatalf("attended guest %s leaked into the fleet listing: %+v", m.DeviceID, m)
		}
		if m.DeviceID == "managed-dev" {
			sawManaged = true
			if m.Ephemeral {
				t.Fatal("a managed machine was reported as ephemeral")
			}
		}
	}
	if !sawManaged {
		t.Fatalf("the managed machine vanished from the listing: %+v", list)
	}

	// And Machine.Ephemeral must now be TRUTHFUL on a direct lookup — it used to be permanently
	// false because the projection omitted the column, so no caller could tell the two apart.
	guest, err := machines.GetMachine(ctx, tid, redeemed.DeviceID)
	if err != nil {
		t.Fatalf("GetMachine(guest): %v", err)
	}
	if !guest.Ephemeral {
		t.Fatal("GetMachine reported an attended guest as a permanent machine")
	}
	if guest.ExpiresAt == nil {
		t.Fatal("an ephemeral machine has no expiry")
	}
	managed, err := machines.GetMachine(ctx, tid, "managed-dev")
	if err != nil {
		t.Fatalf("GetMachine(managed): %v", err)
	}
	if managed.Ephemeral || managed.ExpiresAt != nil {
		t.Fatalf("a managed machine looks ephemeral: %+v", managed)
	}

	// attended_session FKs the tenant, so it goes first.
	if _, err := suPool.Exec(ctx, "DELETE FROM attended_session WHERE tenant_id = $1", tid); err != nil {
		t.Fatalf("cleanup attended: %v", err)
	}
	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
