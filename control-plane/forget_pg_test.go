package controlplane

// Postgres-only tests for migration 0073 (the 'forgotten' directive state) and for what the database itself enforces
// around a forget.

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// 0073 changes exactly two constraints. It must REPLACE the earlier definitions (not sit beside them: the old state
// list would still refuse 'forgotten'), keep every rule they carried, and be safe to apply twice.
func TestPgForgottenStateConstraints(t *testing.T) {
	h := newPgDirHarness(t)
	ctx := context.Background()
	now := time.Now()
	insert := func(state string, withArtifact bool) error {
		return withTenant(ctx, h.app, h.tenant, func(tx pgx.Tx) error {
			machine := h.addMachineFn(h.group, MachineStatusRetired) // one machine per row: one ACTIVE directive per machine
			var issued, expires, nonce, artifact any
			if withArtifact {
				issued, expires, nonce, artifact = now, now.Add(time.Hour), make([]byte, 16), "artifact"
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO agent_directive (tenant_id, machine_id, device_id, key_fp, group_id, kind, state, requested_by,
				    requested_at, not_before, request_expires_at, issued_at, expires_at, nonce, artifact)
				VALUES ($1, $2, 'dev', $3, $4, 'uninstall', $5, $6, $7, $7, $7, $8, $9, $10, $11)`,
				h.tenant, machine.ID, hex.EncodeToString(make([]byte, 32)), h.group, state, h.owner, now, issued, expires, nonce, artifact)
			return err
		})
	}
	// 'forgotten' is accepted whatever the row had: never issued (closed from `requested`) or issued.
	if err := insert("forgotten", false); err != nil {
		t.Fatalf("a forgotten directive that was never issued: %v", err)
	}
	if err := insert("forgotten", true); err != nil {
		t.Fatalf("a forgotten directive that was issued: %v", err)
	}
	// The earlier rules are intact: an unknown state, and an 'issued' row with no artifact, are still refused.
	if c := pgErrorCode(insert("forgotton", false)); c != "23514" {
		t.Fatalf("a misspelled state = %q, want 23514", c)
	}
	if c := pgErrorCode(insert("issued", false)); c != "23514" {
		t.Fatalf("issued without an artifact = %q, want 23514", c)
	}
	if err := insert("failed", false); err != nil {
		t.Fatalf("failed (no artifact needed): %v", err)
	}
	// Exactly the constraints that list the states now mention 'forgotten': none of the old ones survived beside it.
	rows, err := h.su.Query(ctx, `SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'agent_directive'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%removal_unconfirmed%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatal(err)
		}
		n++
		if !strings.Contains(def, "forgotten") {
			t.Fatalf("constraint %s still lists the states without 'forgotten': %s", name, def)
		}
	}
	rows.Close()
	if n != 2 {
		t.Fatalf("%d constraints list the directive states, want 2 (state_check and state_fields)", n)
	}
	// Idempotent: a second application changes nothing and does not fail.
	applyMigrationFile(t, h.su, "migrations/0073_directive_forgotten.sql")
	if err := insert("forgotten", false); err != nil {
		t.Fatalf("after re-applying the migration: %v", err)
	}
}

// The database, not the handler, is what makes the order of a forget matter: the tombstone UPDATE is refused
// while ANY directive is still active on the machine (DR001), and once removed the status never moves again
// (DR002). ForgetMachine closes the directive first for exactly this reason.
func TestPgTheTombstoneNeedsTheDirectiveClosedFirst(t *testing.T) {
	h := newPgDirHarness(t)
	ctx := context.Background()
	id := h.mustRequestUninstall(h.owner, h.m)
	tombstone := func() error {
		return withTenant(ctx, h.app, h.tenant, func(tx pgx.Tx) error { return tombstoneMachineTx(ctx, tx, h.m.ID) })
	}
	if err := tombstone(); err != ErrMachineHasActiveDirective {
		t.Fatalf("tombstone with an active directive = %v, want ErrMachineHasActiveDirective", err)
	}
	if got := h.machine(h.m.ID).Status; got != MachineStatusRetired {
		t.Fatalf("machine %s", got)
	}
	// Close the directive the way ForgetMachine does, then the same statement goes through.
	h.rawSQL(`UPDATE agent_directive SET state = 'forgotten', state_detail = 'x' WHERE id = $1`, id)
	if err := tombstone(); err != nil {
		t.Fatalf("tombstone after the directive was closed: %v", err)
	}
	if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
		t.Fatalf("machine %s", got)
	}
	if err := tombstone(); err != nil { // idempotent at the SQL level: removed -> removed is no status change
		t.Fatalf("second tombstone: %v", err)
	}
}
