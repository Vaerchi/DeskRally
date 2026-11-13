package controlplane

// Postgres-only tests for migration 0068 itself: the identity function's predicates (every one the older
// definitions carried plus the new status handling), the machine guard trigger, the one-active-per-machine
// index, the composite foreign keys, RLS and the app role's grants.

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPgIdentityFunctionKeepsEveryPredicate(t *testing.T) {
	h := newPgDirHarness(t)
	ctx := context.Background()
	store := NewPgMachineStore(h.app)
	lookup := func(dev string) (*DeviceIdentity, error) { return store.LookupDeviceIdentity(ctx, dev) }

	active := h.addMachineFn(h.group, MachineStatusActive)
	if id, err := lookup(active.Device); err != nil || id.Status != "active" {
		t.Fatalf("active: %+v %v", id, err)
	}
	// Retired resolves (the Go layer decides who may see it); quarantined too.
	if id, err := lookup(h.m.Device); err != nil || id.Status != "retired" {
		t.Fatalf("retired: %+v %v", id, err)
	}
	// Removed never resolves.
	h.bypassGuard(func() { h.rawSQL(`UPDATE machine SET status = 'removed' WHERE id = $1`, active.ID) })
	if _, err := lookup(active.Device); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("removed resolved: %v", err)
	}
	// No pinned key: unknown.
	nokey := h.addMachineFn(h.group, MachineStatusActive)
	h.rawSQL(`UPDATE machine SET pubkey = ''::bytea WHERE id = $1`, nokey.ID)
	if _, err := lookup(nokey.Device); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("keyless machine resolved: %v", err)
	}
	// Ephemeral + expired: refused (0013); ephemeral + live: fine.
	eph := h.addMachineFn(h.group, MachineStatusActive)
	h.rawSQL(`UPDATE machine SET ephemeral = true, expires_at = now() - interval '1 minute' WHERE id = $1`, eph.ID)
	if _, err := lookup(eph.Device); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("expired ephemeral resolved: %v", err)
	}
	h.rawSQL(`UPDATE machine SET expires_at = now() + interval '1 hour' WHERE id = $1`, eph.ID)
	if _, err := lookup(eph.Device); err != nil {
		t.Fatalf("live ephemeral refused: %v", err)
	}
	// Suspended tenant: refused (0055).
	live := h.addMachineFn(h.group, MachineStatusActive)
	h.setSuspended(true)
	if _, err := lookup(live.Device); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("suspended tenant's machine resolved: %v", err)
	}
	h.setSuspended(false)
	if _, err := lookup(live.Device); err != nil {
		t.Fatalf("after resume: %v", err)
	}
}

func TestPgMachineGuardTrigger(t *testing.T) {
	h := newPgDirHarness(t)
	ctx := context.Background()
	id := h.mustRequestUninstall(h.owner, h.m)
	exec := func(sql string, args ...any) error {
		return withTenant(ctx, h.app, h.tenant, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
	}
	pgCode := func(err error) string { return pgErrorCode(err) }
	// DR001 for status and group, straight in SQL (no handler to hide behind).
	if c := pgCode(exec(`UPDATE machine SET status = 'active' WHERE id = $1`, h.m.ID)); c != "DR001" {
		t.Fatalf("status change during a directive: %q, want DR001", c)
	}
	if c := pgCode(exec(`UPDATE machine SET group_id = $2 WHERE id = $1`, h.m.ID, h.otherGroup)); c != "DR001" {
		t.Fatalf("group change during a directive: %q, want DR001", c)
	}
	// Unrelated columns are not blocked.
	if err := exec(`UPDATE machine SET alias = 'x' WHERE id = $1`, h.m.ID); err != nil {
		t.Fatalf("alias change blocked: %v", err)
	}
	// After cancellation it is free again.
	if code, _ := h.do(h.owner, "POST", "/directives/"+id+"/cancel", ""); code != 200 {
		t.Fatal("cancel failed")
	}
	if err := exec(`UPDATE machine SET status = 'active' WHERE id = $1`, h.m.ID); err != nil {
		t.Fatalf("status change after cancel: %v", err)
	}
	// DR002: a removed machine never leaves removed, even for the superuser.
	h.rawSQL(`UPDATE machine SET status = 'retired' WHERE id = $1`, h.m.ID)
	h.rawSQL(`UPDATE machine SET status = 'removed' WHERE id = $1`, h.m.ID)
	if c := pgCode(exec(`UPDATE machine SET status = 'retired' WHERE id = $1`, h.m.ID)); c != "DR002" {
		t.Fatalf("leaving removed: %q, want DR002", c)
	}
}

func pgErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "other:" + err.Error()
}

func TestPgDirectiveSchemaInvariants(t *testing.T) {
	h := newPgDirHarness(t)
	ctx := context.Background()
	now := time.Now()
	insert := func(tenant, machine, group string, state string) error {
		return withTenant(ctx, h.app, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO agent_directive (tenant_id, machine_id, device_id, key_fp, group_id, kind, state, requested_by,
				    requested_at, not_before, request_expires_at)
				VALUES ($1, $2, 'dev', $3, $4, 'reinstall', $5, $6, $7, $7, $7)`,
				tenant, machine, hex.EncodeToString(make([]byte, 32)), group, state, h.owner, now)
			return err
		})
	}
	if err := insert(h.tenant, h.m.ID, h.group, "requested"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// At most ONE active directive per machine (the partial unique index).
	if c := pgErrorCode(insert(h.tenant, h.m.ID, h.group, "requested")); c != "23505" {
		t.Fatalf("second active directive: %q, want 23505", c)
	}
	// Composite FKs: a machine of ANOTHER tenant cannot be referenced even with the right tenant id...
	foreign := h.addMachineFn(h.group, MachineStatusRetired) // same tenant: fine
	if err := insert(h.tenant, foreign.ID, h.group, "requested"); err != nil {
		t.Fatalf("second machine: %v", err)
	}
	alienGroup := seedGroup(t, h.su, h.alien)
	var alienMachine string
	h.su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&alienMachine)
	h.rawSQL(`INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey) VALUES ($1,$2,$3,$4,'x',$5)`,
		alienMachine, h.alien, newUUID(), alienGroup, []byte{1})
	if c := pgErrorCode(insert(h.tenant, alienMachine, h.group, "requested")); c != "23503" {
		t.Fatalf("cross-tenant machine reference: %q, want 23503 (composite FK)", c)
	}
	if c := pgErrorCode(insert(h.tenant, foreign.ID, alienGroup, "failed")); c != "23503" {
		t.Fatalf("cross-tenant group reference: %q, want 23503", c)
	}
	// State-field CHECK: an 'issued' row without an artifact is impossible.
	h.rawSQL(`DELETE FROM agent_directive`)
	if c := pgErrorCode(insert(h.tenant, h.m.ID, h.group, "issued")); c != "23514" {
		t.Fatalf("issued without artifact: %q, want 23514", c)
	}
	// RLS: the other tenant sees nothing; the app role cannot delete evidence.
	if err := insert(h.tenant, h.m.ID, h.group, "requested"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := withTenant(ctx, h.app, h.alien, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM agent_directive`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("other tenant sees %d directives (err %v)", n, err)
	}
	if c := pgErrorCode(withTenant(ctx, h.app, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM agent_directive`)
		return err
	})); c != "42501" {
		t.Fatalf("app role DELETE: %q, want 42501 (insufficient privilege)", c)
	}
	// The sweep and tombstone functions: app role may call them, the boolean answers correctly.
	var removed bool
	if err := h.app.QueryRow(ctx, `SELECT cp_machine_key_removed($1)`, []byte{9, 9}).Scan(&removed); err != nil || removed {
		t.Fatalf("cp_machine_key_removed: %v %v", removed, err)
	}
}
