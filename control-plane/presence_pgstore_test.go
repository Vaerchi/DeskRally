package controlplane

// DB-gated proof for the machine-presence enrichment (migrations/0017), run as the least-privilege
// `rmt_app` role so RLS is genuinely in force — the interesting question is not "does the UPDATE
// run" but "can a cross-tenant device id from the shared signaling feed reach another tenant's
// row". Like every pgx test these need TEST_DATABASE_URL.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPgMachinePresenceUnderRLS covers the whole 0017 surface as rmt_app: last_seen persists, the
// group name is joined, the OS captured at enrollment round-trips, and — the load-bearing case —
// a device id belonging to ANOTHER tenant is silently skipped rather than stamped.
func TestPgMachinePresenceUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: PgMachineStore projects machine.ephemeral
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "pres-a", "dana@pres-a.test", "Original-Passw0rd!")
	tidB, _ := provisionUser(t, suPool, "pres-b", "eve@pres-b.test", "Other-Passw0rd!")
	gidA, _ := seedGroupMachine(t, suPool, tidA, "dev-a1")
	seedGroupMachine(t, suPool, tidB, "dev-b1")

	// Name tenant A's group so the join has something to resolve.
	if _, err := suPool.Exec(ctx,
		`UPDATE machine_group SET name = 'Front Office' WHERE id = $1::uuid`, gidA); err != nil {
		t.Fatalf("name group: %v", err)
	}

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)

	// --- An enrollment carries the OS through to the read projection.
	m := &Machine{
		TenantID: tidA, DeviceID: "dev-a2", GroupID: gidA, Name: "WS-07",
		Pubkey: "", OS: "Windows 11 Enterprise",
	}
	if err := store.EnrollMachine(ctx, tidA, m); err != nil {
		t.Fatalf("EnrollMachine as rmt_app: %v", err)
	}
	got, err := store.GetMachine(ctx, tidA, "dev-a2")
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if got.OS != "Windows 11 Enterprise" {
		t.Fatalf("os = %q, want the value captured at enrollment", got.OS)
	}
	if got.GroupName != "Front Office" {
		t.Fatalf("group_name = %q, want the joined machine_group.name", got.GroupName)
	}
	if got.LastSeen != nil {
		t.Fatalf("a freshly enrolled machine has last_seen = %v, want NULL", got.LastSeen)
	}

	// --- TouchLastSeen stamps the tenant's own machines...
	at := time.Now().UTC().Truncate(time.Millisecond)
	n, err := store.TouchLastSeen(ctx, tidA, []string{"dev-a1", "dev-a2"}, at)
	if err != nil {
		t.Fatalf("TouchLastSeen as rmt_app: %v", err)
	}
	if n != 2 {
		t.Fatalf("TouchLastSeen updated %d rows, want 2", n)
	}
	got, err = store.GetMachine(ctx, tidA, "dev-a1")
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if got.LastSeen == nil || got.LastSeen.UTC().Sub(at).Abs() > time.Second {
		t.Fatalf("last_seen = %v, want ~%v", got.LastSeen, at)
	}

	// --- ...and RLS makes a CROSS-TENANT id a no-op. The presence feed is shared across tenants,
	// so this method is routinely handed ids like dev-b1; it must write nothing and must not report
	// that the row exists.
	var beforeB *time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT last_seen FROM machine WHERE device_id = 'dev-b1'`).Scan(&beforeB); err != nil {
		t.Fatalf("read tenant B last_seen: %v", err)
	}
	if beforeB != nil {
		t.Fatalf("test premise: tenant B already has last_seen = %v", beforeB)
	}
	n, err = store.TouchLastSeen(ctx, tidA, []string{"dev-b1", "dev-does-not-exist"}, at)
	if err != nil {
		t.Fatalf("cross-tenant TouchLastSeen errored: %v", err)
	}
	if n != 0 {
		t.Fatalf("cross-tenant TouchLastSeen updated %d rows, want 0 — RLS must confine it", n)
	}
	var afterB *time.Time
	if err := suPool.QueryRow(ctx,
		`SELECT last_seen FROM machine WHERE device_id = 'dev-b1'`).Scan(&afterB); err != nil {
		t.Fatalf("re-read tenant B last_seen: %v", err)
	}
	if afterB != nil {
		t.Fatalf("a tenant-A-pinned TouchLastSeen stamped tenant B's machine: %v", afterB)
	}

	// An empty id list is a no-op that costs no round trip.
	if n, err := store.TouchLastSeen(ctx, tidA, nil, at); err != nil || n != 0 {
		t.Fatalf("empty TouchLastSeen = (%d, %v), want (0, nil)", n, err)
	}

	// --- ListMachines carries the enrichment too, still tenant-confined.
	list, err := store.ListMachines(ctx, tidA)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListMachines returned %d machines, want 2 (tenant A only)", len(list))
	}
	for _, lm := range list {
		if lm.GroupName != "Front Office" {
			t.Fatalf("listed machine %s group_name = %q, want the joined name", lm.DeviceID, lm.GroupName)
		}
		if lm.LastSeen == nil {
			t.Fatalf("listed machine %s has no last_seen after the stamp", lm.DeviceID)
		}
	}

	// A machine whose group row is gone must still LIST (display-only join, LEFT), because
	// GroupID — not the name — is what authorization scopes against.
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE machine_group SET name = '' WHERE id = $1::uuid`, gidA)
		return err
	}); err != nil {
		t.Fatalf("blank group name: %v", err)
	}
	if list, err := store.ListMachines(ctx, tidA); err != nil || len(list) != 2 {
		t.Fatalf("ListMachines with a blank group name = %d machines (%v), want 2", len(list), err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgRecordObservedOSUnderRLS proves the presence-driven machine.os refresh as rmt_app: a
// changed value persists, an identical value writes ZERO rows (the IS DISTINCT FROM guard — the
// steady state must not generate dead tuples on every console poll), and — the load-bearing case —
// a cross-tenant device id from the shared feed changes nothing and reveals nothing. Only a real
// database can pin these: the fake's map assignment cannot distinguish "wrote the same value" from
// "did not write", and RLS is not something an in-memory store exercises at all.
func TestPgRecordObservedOSUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool)
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "osr-a", "dana@osr-a.test", "Original-Passw0rd!")
	tidB, _ := provisionUser(t, suPool, "osr-b", "eve@osr-b.test", "Other-Passw0rd!")
	gidA, _ := seedGroupMachine(t, suPool, tidA, "osr-dev-a1")
	seedGroupMachine(t, suPool, tidB, "osr-dev-b1")

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)

	m := &Machine{TenantID: tidA, DeviceID: "osr-dev-a2", GroupID: gidA, Name: "WS-08", OS: "Windows 11 Pro 25H2 (build 26200)"}
	if err := store.EnrollMachine(ctx, tidA, m); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}

	// --- A genuinely new value persists and reports exactly one changed row.
	upgraded := "Windows 11 Pro 26H1 (build 27000)"
	n, err := store.RecordObservedOS(ctx, tidA, map[string]string{"osr-dev-a2": upgraded})
	if err != nil {
		t.Fatalf("RecordObservedOS as rmt_app: %v", err)
	}
	if n != 1 {
		t.Fatalf("RecordObservedOS changed %d rows, want 1", n)
	}
	got, err := store.GetMachine(ctx, tidA, "osr-dev-a2")
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if got.OS != upgraded {
		t.Fatalf("os = %q, want the refreshed %q", got.OS, upgraded)
	}

	// --- The same value again is a ZERO-row write: IS DISTINCT FROM is the dead-tuple guard.
	if n, err := store.RecordObservedOS(ctx, tidA, map[string]string{"osr-dev-a2": upgraded}); err != nil || n != 0 {
		t.Fatalf("unchanged RecordObservedOS = (%d, %v), want (0, nil)", n, err)
	}

	// --- A cross-tenant id from the shared feed writes nothing and reveals nothing.
	var beforeB string
	if err := suPool.QueryRow(ctx,
		`SELECT os FROM machine WHERE device_id = 'osr-dev-b1'`).Scan(&beforeB); err != nil {
		t.Fatalf("read tenant B os: %v", err)
	}
	n, err = store.RecordObservedOS(ctx, tidA, map[string]string{"osr-dev-b1": "Attacker-Chosen OS"})
	if err != nil {
		t.Fatalf("cross-tenant RecordObservedOS errored: %v", err)
	}
	if n != 0 {
		t.Fatalf("cross-tenant RecordObservedOS changed %d rows, want 0 — RLS must confine it", n)
	}
	var afterB string
	if err := suPool.QueryRow(ctx,
		`SELECT os FROM machine WHERE device_id = 'osr-dev-b1'`).Scan(&afterB); err != nil {
		t.Fatalf("re-read tenant B os: %v", err)
	}
	if afterB != beforeB {
		t.Fatalf("a tenant-A-pinned refresh rewrote tenant B's os: %q → %q", beforeB, afterB)
	}

	// --- The store enforces its own bounds regardless of what the feed or handler did: empty and
	// oversized values are dropped before any SQL runs.
	if n, err := store.RecordObservedOS(ctx, tidA, map[string]string{
		"osr-dev-a2": "",
	}); err != nil || n != 0 {
		t.Fatalf("empty-value RecordObservedOS = (%d, %v), want (0, nil)", n, err)
	}
	// Printable padding ON PURPOSE: machine.os is unbounded `text`, so an oversized PRINTABLE
	// value would be silently written if the Go-side bound vanished — that is the regime the bound
	// exists for. (A NUL-padded fixture would fail on encoding instead and never reach it.)
	if n, err := store.RecordObservedOS(ctx, tidA, map[string]string{
		"osr-dev-a2": strings.Repeat("x", maxMachineNameLen+1),
	}); err != nil || n != 0 {
		t.Fatalf("oversized RecordObservedOS = (%d, %v), want (0, nil)", n, err)
	}
	if got, _ := store.GetMachine(ctx, tidA, "osr-dev-a2"); got.OS != upgraded {
		t.Fatalf("bounded rejects still altered os: %q", got.OS)
	}
	// And an empty map is a no-op that costs no round trip.
	if n, err := store.RecordObservedOS(ctx, tidA, nil); err != nil || n != 0 {
		t.Fatalf("nil-map RecordObservedOS = (%d, %v), want (0, nil)", n, err)
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id IN ($1,$2)", tidA, tidB); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
