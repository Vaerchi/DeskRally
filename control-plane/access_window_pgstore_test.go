package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// docs/57 against Postgres under RLS (the app role): the same rules the in-memory tests pin.

// The SQL predicate and the Go one agree on every vector (fake/pg must agree).
func TestAccessWindowGoAndPgAgree(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()
	for _, v := range windowVectors {
		at, _ := time.Parse(time.RFC3339, v.at)
		var open bool
		if err := suPool.QueryRow(ctx, `SELECT membership_window_open($1::smallint, $2::smallint, $3::smallint, $4, $5)`,
			int16(v.days), int16(v.start), int16(v.end), v.zone, at).Scan(&open); err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if open != v.open {
			t.Errorf("%s: pg membership_window_open(%s) = %v, want %v", v.name, v.at, open, v.open)
		}
	}
	var open bool
	if err := suPool.QueryRow(ctx, `SELECT membership_window_open(NULL, NULL, NULL, NULL, now())`).Scan(&open); err != nil || !open {
		t.Fatalf("no window must be open: %v %v", open, err)
	}
	// A zone pg cannot evaluate denies instead of raising.
	if err := suPool.QueryRow(ctx, `SELECT membership_window_open(127::smallint, 0::smallint, 1440::smallint, 'Mars/Olympus', now())`).Scan(&open); err != nil || open {
		t.Fatalf("an unknown zone must deny without an error: %v %v", open, err)
	}
}

func TestPgWindowGrantsOnlyWhenOpen(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "win-a", "a@win-a.test", "password-1234")
	ctx := context.Background()
	store := newPgUserStoreT(newAppRolePool(t, ctx))

	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleTechnician, Window: openWindow(), WindowSupplied: true}); err != nil {
		t.Fatalf("set open window: %v", err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); !g.Allows(CapStartSession) {
		t.Fatal("an open window grants")
	}
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleTechnician, Window: closedWindow(), WindowSupplied: true}); err != nil {
		t.Fatalf("set closed window: %v", err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); len(g.Members) != 0 {
		t.Fatal("a closed window grants nothing in pg")
	}
	stored, err := store.StoredGrantFor(ctx, tid, uid)
	if err != nil || len(stored.Members) != 1 || !sameWindow(stored.Members[0].Window, closedWindow()) {
		t.Fatalf("StoredGrantFor keeps the windowed row with its window: %+v %v", stored, err)
	}
	users, _ := store.ListUsers(ctx, tid)
	if len(users) != 1 || !sameWindow(users[0].AccessWindow, closedWindow()) || users[0].AccessWindowVaries || !users[0].AccessOutsideWindow {
		t.Fatalf("pg ListUsers: %+v", users)
	}
	sum, err := store.AccessSummary(ctx, tid, uid)
	if err != nil || !sameWindow(sum.AccessWindow, closedWindow()) || !sum.AccessOutsideWindow || sum.Email != "a@win-a.test" {
		t.Fatalf("pg AccessSummary: %+v %v", sum, err)
	}
	if _, err := store.AccessSummary(ctx, tid, newUUID()); !errors.Is(err, ErrNoUser) {
		t.Fatalf("AccessSummary of an unknown id = %v, want ErrNoUser", err)
	}
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleTechnician}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	g, _ := store.GrantFor(ctx, tid, uid)
	users, _ = store.ListUsers(ctx, tid)
	if !g.Allows(CapStartSession) || users[0].AccessWindow != nil || users[0].AccessOutsideWindow || users[0].AccessWindowVaries {
		t.Fatalf("no window = any time: allows=%v %+v", g.Allows(CapStartSession), users[0])
	}
}

func TestPgWindowAggregatesAndBadZone(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "win-b", "b@win-b.test", "password-1234")
	ctx := context.Background()
	store := newPgUserStoreT(newAppRolePool(t, ctx))
	closed := closedWindow()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := suPool.Exec(ctx, `DELETE FROM membership WHERE user_id = $1`, uid); err != nil {
			t.Fatal(err)
		}
		if _, err := suPool.Exec(ctx, sql, append([]any{tid, uid}, args...)...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// docs/57 r2: an EXPIRED unrestricted row plus a LIVE closed window: outside, window null, varies.
	seed(`
		INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids, expires_at)
		SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[], now() - interval '1 hour' FROM role r WHERE r.key = 'technician' AND r.tenant_id IS NULL
		UNION ALL
		SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[], NULL FROM role r WHERE r.key = 'readonly' AND r.tenant_id IS NULL`)
	if _, err := suPool.Exec(ctx, `UPDATE membership SET window_days = $2, window_start = 0, window_end = 1440, window_tz = 'UTC'
		WHERE user_id = $1 AND expires_at IS NULL`, uid, int16(closed.Days)); err != nil {
		t.Fatal(err)
	}
	sum, err := store.AccessSummary(ctx, tid, uid)
	if err != nil || sum.AccessWindow != nil || !sum.AccessWindowVaries || !sum.AccessOutsideWindow || sum.AccessExpired {
		t.Fatalf("expired unrestricted + live closed: %+v %v", sum, err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); len(g.Members) != 0 {
		t.Fatal("neither row grants")
	}

	// A zone pg cannot evaluate (written by SQL, bypassing the write check) denies THAT membership only;
	// GrantFor keeps the user's other membership and ListUsers / AccessSummary still answer.
	seed(`
		INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids, window_days, window_start, window_end, window_tz)
		SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[], 127, 0, 1440, 'Mars/Olympus' FROM role r WHERE r.key = 'technician' AND r.tenant_id IS NULL
		UNION ALL
		SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[], NULL, NULL, NULL, NULL FROM role r WHERE r.key = 'readonly' AND r.tenant_id IS NULL`)
	g, err := store.GrantFor(ctx, tid, uid)
	if err != nil || len(g.Members) != 1 || g.Members[0].Role != RoleReadOnly {
		t.Fatalf("bad zone must deny only its own row: %+v %v", g, err)
	}
	if users, err := store.ListUsers(ctx, tid); err != nil || len(users) != 1 {
		t.Fatalf("ListUsers must still answer with a bad zone: %v %v", users, err)
	}
	if _, err := store.AccessSummary(ctx, tid, uid); err != nil {
		t.Fatalf("AccessSummary must still answer with a bad zone: %v", err)
	}
	// docs/57 r3: an unrelated edit PRESERVES the stored (unsupported) window without re-checking it.
	seed(`
		INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids, window_days, window_start, window_end, window_tz)
		SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[], 127, 0, 1440, 'Mars/Olympus' FROM role r WHERE r.key = 'technician' AND r.tenant_id IS NULL`)
	stored, _ := store.StoredGrantFor(ctx, tid, uid)
	pw, _ := stored.AccessWindowSummary()
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleReadOnly, Window: pw}); err != nil {
		t.Fatalf("preserving an unsupported stored zone = %v, want success", err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); len(g.Members) != 0 {
		t.Fatal("the preserved unsupported zone keeps denying")
	}
	// ...but SUPPLYING it is refused by the database's own tz list.
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleReadOnly, Window: pw, WindowSupplied: true}); !errors.Is(err, ErrUnknownTimeZone) {
		t.Fatalf("supplying a zone pg does not know = %v, want ErrUnknownTimeZone", err)
	}
	if err := store.CreateUserAssignment(ctx, tid, newUUID(), "c@win-b.test", "C",
		Assignment{Role: RoleReadOnly, Window: pw, WindowSupplied: true}); !errors.Is(err, ErrUnknownTimeZone) {
		t.Fatalf("invite with a zone pg does not know = %v, want ErrUnknownTimeZone", err)
	}
}

// The schema owns completeness and ranges (docs/57 sec. 3).
func TestPgWindowSchemaChecks(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "win-c", "c@win-c.test", "password-1234")
	ctx := context.Background()
	for name, cols := range map[string]string{
		"partial (no zone)": "127, 0, 1440, NULL",
		"no days":           "0, 0, 1440, 'UTC'",
		"days over 127":     "128, 0, 1440, 'UTC'",
		"start 1440":        "1, 1440, 60, 'UTC'",
		"end 0":             "1, 60, 0, 'UTC'",
		"end 1441":          "1, 60, 1441, 'UTC'",
		"start = end":       "1, 60, 60, 'UTC'",
	} {
		_, err := suPool.Exec(ctx, `
			INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids, window_days, window_start, window_end, window_tz)
			SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[], `+cols+` FROM role r WHERE r.key = 'readonly' AND r.tenant_id IS NULL`, tid, uid)
		if err == nil {
			t.Errorf("%s: the schema accepted (%s)", name, cols)
		}
	}
}

// A windowed Owner row is not a permanent Owner: the last-Owner invariant refuses it.
func TestPgWindowedOwnerIsNotPermanent(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "win-d", "d@win-d.test", "password-1234")
	ctx := context.Background()
	store := newPgUserStoreT(newAppRolePool(t, ctx))
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleOwner}); err != nil {
		t.Fatalf("make owner: %v", err)
	}
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleOwner, Window: openWindow(), WindowSupplied: true}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("windowing the last permanent Owner = %v, want ErrLastOwner", err)
	}
}
