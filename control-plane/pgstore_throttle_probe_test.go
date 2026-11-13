package controlplane

import (
	"context"
	"strings"
	"testing"
)

// The startup probe must distinguish "the table is EMPTY" from "I cannot READ the table".
//
// This turns a live recovery incident from a three-hypothesis log hunt into a boot message. A
// restore from `pg_dump --no-privileges` strips every GRANT, and `migrate` will not put them back —
// the ledger reports the schema current, so `applied=0 skipped=39` and 0005_app_role.sql never
// re-runs; it only resets rmt_app's password. What comes up starts cleanly, logs "production mode",
// derives the correct grant_issuer_pubkey, and then answers EVERY login with:
//
//	HTTP 429 {"error":"too many attempts"}
//
// Nobody is being rate-limited. The throttle cannot SELECT its own table, so it fails closed — which
// is correct, and indistinguishable from the thing it is not. The real cause shows up only in
// container logs as `permission denied for table throttle_counter` (SQLSTATE 42501). The engineer
// who hit it had full log access and still spent three wrong hypotheses on it.
//
// Driven against `rmt_app`, the ACTUAL production role, and by revoking the ACTUAL grant 0015
// issues — so this reproduces the incident rather than approximating it with a synthetic role.
func TestThrottleReadabilityProbeDistinguishesEmptyFromUnreadable(t *testing.T) {
	ctx := context.Background()
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)  // 0005: creates rmt_app
	applyThrottleMigration(t, suPool) // 0015: creates throttle_counter and GRANTs to rmt_app

	// ---- POSITIVE: an EMPTY table is readable, and must not read as broken ----------------------
	// This is exactly why the probe COUNTS rather than doing `SELECT ... LIMIT 1`: that returns no
	// rows on an empty table AND on a permission failure, so it cannot tell health from outage.
	if _, err := suPool.Exec(ctx, `DELETE FROM throttle_counter`); err != nil {
		t.Fatalf("clear table: %v", err)
	}
	appPool := newAppRolePool(t, ctx)
	if err := NewPgThrottleStore(appPool).VerifyReadable(ctx); err != nil {
		t.Fatalf("an empty throttle_counter must read as HEALTHY, got: %v", err)
	}

	// ---- NEGATIVE: revoke the grant, exactly as --no-privileges does ----------------------------
	// Without this half the assertion above is nearly free — a probe hardcoded to `return nil`
	// passes it.
	t.Cleanup(func() {
		_, _ = suPool.Exec(context.Background(),
			`GRANT SELECT, INSERT, UPDATE, DELETE ON throttle_counter TO rmt_app`)
	})
	if _, err := suPool.Exec(ctx, `REVOKE ALL ON throttle_counter FROM rmt_app`); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A FRESH pool: the existing one holds established connections, and the point is what a control
	// plane starting against this database would find.
	revokedPool := newAppRolePool(t, ctx)
	err := NewPgThrottleStore(revokedPool).VerifyReadable(ctx)
	if err == nil {
		t.Fatal("rmt_app with no SELECT on throttle_counter PASSED the probe — the control plane " +
			"would start, report production mode, and then 429 every login with the cause visible " +
			"only in container logs")
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("the probe's error must name what is wrong, got: %v", err)
	}
	// And it must carry the underlying cause, which is the sentence an operator needs.
	if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("the probe must surface the permission error itself, got: %v", err)
	}
}
