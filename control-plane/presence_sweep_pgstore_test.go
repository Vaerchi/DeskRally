package controlplane

// LIVE-POSTGRES: migration 0079 (cp_presence_stamp). The database is a FRESH one migrated by the real runner,
// so the function is owned by rmt_definer and its grants are the shipped ones, and the store runs as rmt_app.
// What only the database can prove: the sweep reaches machines in EVERY tenant with no tenant pinned, it
// writes last_seen and nothing else, forward-only and clamped to the database clock, and its reach stops
// at that column.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPgPresenceStampAcrossTenants(t *testing.T) {
	ctx := context.Background()
	su := freshMigrationDatabase(t)
	if _, err := Migrate(ctx, su, "migrations", MigrateOptions{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := su.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "rmt_app", ""
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	store := NewPgMachineStore(app)

	tidA, _ := provisionUser(t, su, "sweep-a", "a@sweep-a.test", "password-1234")
	tidB, _ := provisionUser(t, su, "sweep-b", "b@sweep-b.test", "password-1234")
	seedGroupMachine(t, su, tidA, "sw-a1")
	seedGroupMachine(t, su, tidB, "sw-b1")
	seedGroupMachine(t, su, tidB, "sw-b-off")

	lastSeen := func(dev string) *time.Time {
		t.Helper()
		var ts *time.Time
		if err := su.QueryRow(ctx, `SELECT last_seen FROM machine WHERE device_id = $1`, dev).Scan(&ts); err != nil {
			t.Fatalf("read %s: %v", dev, err)
		}
		return ts
	}
	snapshot := func() string {
		t.Helper()
		var s string
		if err := su.QueryRow(ctx, `SELECT string_agg(to_jsonb(m)::text, ',' ORDER BY device_id) FROM
			(SELECT * FROM machine) m`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// rmt_app, NO tenant pinned: both tenants' online machines are stamped, the offline one and an unknown id are not.
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	n, err := store.StampPresence(ctx, []string{"sw-a1", "sw-b1", "sw-unknown"}, at)
	if err != nil {
		t.Fatalf("StampPresence as rmt_app: %v", err)
	}
	if n != 2 {
		t.Fatalf("stamped %d rows, want 2 (one per tenant)", n)
	}
	for _, dev := range []string{"sw-a1", "sw-b1"} {
		if got := lastSeen(dev); got == nil || !got.Equal(at) {
			t.Fatalf("%s last_seen = %v, want %v", dev, got, at)
		}
	}
	if got := lastSeen("sw-b-off"); got != nil {
		t.Fatalf("an offline machine was stamped: %v", got)
	}

	// Forward-only: an older stamp changes nothing at all.
	before := snapshot()
	if n, err := store.StampPresence(ctx, []string{"sw-a1", "sw-b1"}, at.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("an older stamp updated %d rows (err %v), want 0", n, err)
	}
	if snapshot() != before {
		t.Fatal("an older stamp changed a machine row")
	}

	// Clamped to the database's now(): a stamp a day ahead lands at about now, not tomorrow.
	if _, err := store.StampPresence(ctx, []string{"sw-a1"}, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("future stamp: %v", err)
	}
	var dbNow time.Time
	if err := su.QueryRow(ctx, `SELECT now()`).Scan(&dbNow); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen("sw-a1"); got == nil || got.After(dbNow) || got.Before(at) {
		t.Fatalf("a future stamp left last_seen = %v; want clamped to at most the database clock %v", got, dbNow)
	}

	// The id list is bounded.
	big := make([]string, 100001)
	for i := range big {
		big[i] = "x"
	}
	_, err = store.StampPresence(ctx, big, at)
	mustFail(t, "100001 ids", err, "at most 100000")

	// The function's reach is ONE column: rmt_definer, which owns it, may update last_seen and nothing else on
	// machine. (A body that wrote another column would fail with permission denied, not succeed quietly.)
	var owner string
	if err := su.QueryRow(ctx, `SELECT proowner::regrole::text FROM pg_proc
		WHERE oid = 'public.cp_presence_stamp(text[], timestamptz)'::regprocedure`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != "rmt_definer" {
		t.Fatalf("cp_presence_stamp is owned by %s, want rmt_definer", owner)
	}
	for col, want := range map[string]bool{"last_seen": true, "status": false, "os": false, "group_id": false, "tenant_id": false} {
		var can bool
		if err := su.QueryRow(ctx, `SELECT has_column_privilege('rmt_definer', 'machine', $1, 'UPDATE')`, col).Scan(&can); err != nil {
			t.Fatal(err)
		}
		if can != want {
			t.Fatalf("rmt_definer UPDATE on machine.%s = %v, want %v", col, can, want)
		}
	}

	// EXECUTE: rmt_app yes (the sweeper), PUBLIC no.
	var appExec, publicExec bool
	if err := su.QueryRow(ctx, `SELECT has_function_privilege('rmt_app', 'cp_presence_stamp(text[], timestamptz)', 'EXECUTE'),
		has_function_privilege('public', 'cp_presence_stamp(text[], timestamptz)', 'EXECUTE')`).Scan(&appExec, &publicExec); err != nil {
		t.Fatal(err)
	}
	if !appExec || publicExec {
		t.Fatalf("EXECUTE: rmt_app=%v (want true), PUBLIC=%v (want false)", appExec, publicExec)
	}

	// The tenant-scoped console path is unchanged: rmt_app, pinned to tenant A, still cannot stamp tenant B.
	later := at.Add(30 * time.Second)
	if n, err := store.TouchLastSeen(ctx, tidA, []string{"sw-b-off"}, later); err != nil || n != 0 {
		t.Fatalf("TouchLastSeen pinned to A reached tenant B: %d rows, err %v", n, err)
	}
}
