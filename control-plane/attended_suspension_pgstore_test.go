package controlplane

// A SUSPENDED tenant must not be able to admit a new principal through attended redemption.
//
// PREMISE, declared locally: redeeming an attended code is not a read. It INSERTs a `machine` row
// with a caller-supplied pubkey pinned to it and returns a device id — after which the signaling
// server will authenticate that device (RMTAGENTAUTHv1) and a technician can be brokered to it. That
// is admitting a principal, and migration 0011 already settled what suspension means for those:
//
//	"Suspension has to mean the same thing on every path that admits a new principal."
//
// 0011 applied that to unattended enrollment; 0020 cites it as settled law. 0013's
// `cp_attended_redeem` — written after 0011 — never got it, so a code minted before a suspension
// kept minting live guests after it. Migration 0021 closes it.
//
// This must be a pg test and cannot be an in-memory one: the rule lives in a SECURITY DEFINER
// plpgsql function, so only the real database can show it. That is the same reason 0011's own
// behaviour is pinned in pg.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func applyAttendedTenantActiveMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0021_attended_redeem_tenant_active.sql")
	if err != nil {
		t.Fatalf("read 0021: %v", err)
	}
	execScript(t, pool, string(b))
}

func TestPgAttendedRedeemRefusedForSuspendedTenant(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool) // 0008
	applyDeviceIdentityMigration(t, pool)      // 0010
	applyAttendedMigration(t, pool)            // 0013
	applyAttendedTenantActiveMigration(t, pool) // 0021 — the rule under test

	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	store := NewPgAttendedStore(pool)

	// Two codes minted while the tenant is healthy — one to spend as the negative control, one to
	// still be outstanding when the suspension lands (the real-world shape: the code predates it).
	control := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "before"}
	controlCode, err := store.Create(ctx, tid, control)
	if err != nil {
		t.Fatalf("create control: %v", err)
	}
	outstanding := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "spans the suspension"}
	outstandingCode, err := store.Create(ctx, tid, outstanding)
	if err != nil {
		t.Fatalf("create outstanding: %v", err)
	}

	// Negative control FIRST: while the tenant is ACTIVE the code redeems. Without this leg a
	// function that refused every redemption would satisfy the assertion below.
	if _, err := store.Redeem(ctx, controlCode, attendTestPubkey, "USER-PC"); err != nil {
		t.Fatalf("premise not met: redeem against an ACTIVE tenant failed: %v", err)
	}

	// Suspend the tenant — the same act that already locks its humans out of the console.
	if _, err := pool.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1`, tid); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}

	// The measurement: the outstanding code must now be refused, and refused the SAME generic way as
	// a bad code, so a guest cannot distinguish "wrong code" from "right code, suspended tenant".
	res, err := store.Redeem(ctx, outstandingCode, attendTestPubkey, "USER-PC")
	if err == nil {
		t.Fatalf("SECURITY: attended redemption succeeded for a SUSPENDED tenant: %+v", res)
	}
	if !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("suspended-tenant redeem err = %v, want the generic invalid-code error "+
			"(a distinct error would tell a guest the code was real)", err)
	}

	// And no ephemeral machine may have been minted. A refusal that still created the row would be
	// the worse bug: the device would be authenticatable while the tenant is suspended.
	var machines int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM machine WHERE tenant_id = $1 AND ephemeral`, tid).Scan(&machines); err != nil {
		t.Fatalf("count ephemeral machines: %v", err)
	}
	if machines != 1 {
		t.Fatalf("ephemeral machine count = %d, want 1 (only the control redemption); a refused "+
			"redeem must not mint a device", machines)
	}
}

// docs/37 D3 (migration 0059): a token redeemed BEFORE the suspension can no longer be ACCEPTED
// after it — but the guest can still DECLINE, and status still reports the session. Each leg has a
// control: the same accept works while the tenant is active.
func TestPgAttendedConsentRefusedAfterSuspensionButDeclineAndStatusWork(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool) // 0008
	applyDeviceIdentityMigration(t, pool)      // 0010
	applyAttendedMigration(t, pool)            // 0013 … 0059 — the rule under test is the last
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	store := NewPgAttendedStore(pool)
	redeemed := func(reason string) string {
		code, err := store.Create(ctx, tid, &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: reason})
		if err != nil {
			t.Fatal(err)
		}
		res, err := store.Redeem(ctx, code, attendTestPubkey, "USER-PC")
		if err != nil {
			t.Fatal(err)
		}
		return res.AttendToken
	}
	control, refused, declining := redeemed("control"), redeemed("accept after"), redeemed("decline after")
	if _, err := store.Consent(ctx, control, true, "guest"); err != nil {
		t.Fatalf("premise: accept on an ACTIVE tenant failed: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1`, tid); err != nil {
		t.Fatal(err)
	}

	if s, err := store.Consent(ctx, refused, true, "guest"); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("accept after suspension = %+v, %v; want ErrAttendedInvalid", s, err)
	}
	if s, err := store.Consent(ctx, declining, false, "guest"); err != nil || s.State != AttendedDeclined {
		t.Fatalf("decline after suspension = %+v, %v; declining must always work", s, err)
	}
	if s, err := store.ByToken(ctx, refused); err != nil || s.State != AttendedRedeemed {
		t.Fatalf("status after suspension = %+v, %v; the guest must still see the session", s, err)
	}
}
