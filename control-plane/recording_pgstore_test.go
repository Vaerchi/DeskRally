package controlplane

// DB-gated proof for central recording storage (migration 0066), driven as the least-privilege rmt_app
// role RLS is enforced against. Needs TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a skip
// as a failure. The behavioural scenarios are the SAME ones the fake runs (recording_store_test.go);
// what is here is what only Postgres can prove: composite FKs, RLS, grants, the state/immutability
// triggers, the SECURITY DEFINER helpers, and the locks.

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyRecordingMigration lays 0066 on the schema newTestPool built. resetSchema does not know these
// tables (and DROP TABLE … CASCADE on their parents only removes the foreign keys), so they are dropped
// here first: the helper is re-runnable. Apply the app-role migration BEFORE this (the GRANTs in 0066
// are conditional on the role existing).
func applyRecordingMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	execScript(t, pool, `
		DROP FUNCTION IF EXISTS cp_recording_sweep_list();
		DROP FUNCTION IF EXISTS cp_recording_global_unwritten();
		DROP TABLE IF EXISTS session_recording_segment, session_recording, tenant_recording_policy CASCADE;
		DROP FUNCTION IF EXISTS session_recording_guard() CASCADE;
		DROP FUNCTION IF EXISTS session_recording_segment_guard() CASCADE;`)
	for _, f := range []string{"migrations/0066_central_recording.sql", "migrations/0067_recording_playback.sql", "migrations/0077_recording_lost.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		execScript(t, pool, string(b))
	}
}

type pgRecHarness struct {
	su           *pgxpool.Pool
	app          *pgxpool.Pool
	store        *PgRecordingStore
	tenantA      string
	tenantB      string
	userA, userB string
	machineA     string
	machineB     string
	sessionOf    func(tenant, machine string) string
}

func newPgRecHarness(t *testing.T) *pgRecHarness {
	t.Helper()
	ctx := context.Background()
	su := newTestPool(t) // skips without TEST_DATABASE_URL
	applyAppRoleMigration(t, su)
	applyRecordingMigration(t, su)
	h := &pgRecHarness{su: su}
	h.tenantA, h.userA = provisionUser(t, su, "rec-a", "a@rec-a.test", "password-1234")
	h.tenantB, h.userB = provisionUser(t, su, "rec-b", "b@rec-b.test", "password-1234")
	mk := func(tid, slug string) string {
		var gid, mid string
		if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&gid, &mid); err != nil {
			t.Fatal(err)
		}
		if _, err := su.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1, $2, 'G')`, gid, tid); err != nil {
			t.Fatalf("group: %v", err)
		}
		if _, err := su.Exec(ctx, `INSERT INTO machine (id, tenant_id, device_id, group_id, pubkey) VALUES ($1, $2, $3, $4, $5)`,
			mid, tid, "dev-"+slug, gid, []byte{0}); err != nil {
			t.Fatalf("machine: %v", err)
		}
		return mid
	}
	h.machineA, h.machineB = mk(h.tenantA, "rec-a"), mk(h.tenantB, "rec-b")
	h.sessionOf = func(tenant, machine string) string {
		user := h.userA
		if tenant == h.tenantB {
			user = h.userB
		}
		var id string
		if err := su.QueryRow(ctx, `INSERT INTO session_record (tenant_id, machine_id, technician_id) VALUES ($1, $2, $3) RETURNING id::text`,
			tenant, machine, user).Scan(&id); err != nil {
			t.Fatalf("session: %v", err)
		}
		return id
	}
	h.app = newAppRolePool(t, ctx)
	h.store = NewPgRecordingStore(h.app)
	t.Cleanup(h.store.Close) // the lock pool must not outlive the database a test drops
	return h
}

func TestRecordingStorePg(t *testing.T) {
	runRecordingStoreSuite(t, func(t *testing.T) *recEnv {
		h := newPgRecHarness(t)
		return &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB,
			session: h.sessionOf}
	})
}

func TestRecordingIDsBySessionPg(t *testing.T) {
	runRecordingIDsBySessionSuite(t, func(t *testing.T) *recEnv {
		h := newPgRecHarness(t)
		return &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB,
			session: h.sessionOf}
	})
}

func TestRecordingPlaybackStorePg(t *testing.T) {
	runRecordingPlaybackStoreSuite(t, func(t *testing.T) *recEnv {
		h := newPgRecHarness(t)
		return &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB,
			session: h.sessionOf}
	})
}

// What only Postgres can prove about 0067: the CHECKs that keep the playback metadata all-or-none and the
// failure reason a closed set, RLS on the list, and that the app role still cannot delete a row.
func TestRecordingPlaybackPgConstraintsAndIsolation(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	env.enable(t, h.tenantB, 30, 1<<30, 20<<30)
	ra := env.complete(t, h.tenantA, h.machineA)
	rb := env.complete(t, h.tenantB, h.machineB)

	// The failure reason is a closed set at the schema level, whatever the application does.
	if _, err := h.su.Exec(ctx, `UPDATE session_recording SET state = 'playback_failed', playback_error = 'free text' WHERE id = $1`, ra.ID); err == nil {
		t.Error("a free-text playback_error was accepted by the schema")
	}
	// The six per-segment playback fields are all-or-none.
	if _, err := h.su.Exec(ctx, `UPDATE session_recording_segment SET webm_len = 10 WHERE recording_id = $1 AND idx = 0`, ra.ID); err == nil {
		t.Error("a half-filled playback segment was accepted by the schema")
	}
	if _, err := h.su.Exec(ctx, `UPDATE session_recording_segment SET webm_len = 10, width = 9000, height = 1, start_ms = 0, duration_ms = 0, frames = 1
		WHERE recording_id = $1 AND idx = 0`, ra.ID); err == nil {
		t.Error("a 9000-pixel-wide playback segment was accepted by the schema")
	}
	// RLS: tenant A's pool never sees B's recording through the list, the detail or the outcome.
	for _, it := range func() []RecordingListItem {
		l, _ := h.store.ListRecordings(ctx, h.tenantA, RecordingListFilter{Limit: 100})
		return l
	}() {
		if it.ID == rb.ID {
			t.Fatal("tenant B's recording listed for tenant A")
		}
	}
	if _, err := h.store.GetRecording(ctx, h.tenantA, rb.ID); err == nil {
		t.Fatal("tenant A read tenant B's recording")
	}
	// The app role has no DELETE on the table (tombstones), still true after 0067.
	if err := withTenant(ctx, h.app, h.tenantA, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM session_recording WHERE id = $1`, ra.ID)
		return e
	}); err == nil {
		t.Error("the application role deleted a recording row")
	}
}

// insert a recording row as the superuser (constraints are tested as the table owner; RLS as rmt_app).
func (h *pgRecHarness) insertRow(t *testing.T, tenant, machine, session string, cols, vals string) error {
	t.Helper()
	_, err := h.su.Exec(context.Background(), `
		INSERT INTO session_recording (tenant_id, id, session_id, machine_id, upload_id, enrollment_fp, generation,
			state, segment_count, declared_bytes, reserved_bytes, key_id, wrapped_dek, retention_days`+cols+`)
		VALUES ($1, gen_random_uuid(), $2, $3, gen_random_uuid(), $4, 1, 'uploading', 1, 10, 100, 1, $5, 30`+vals+`)`,
		tenant, session, machine, make([]byte, 32), make([]byte, 72))
	return err
}

func TestRecordingPgMigrationIsIdempotentAndSeedsThePreset(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	r, _ := env.create(t, h.tenantA, h.machineA)
	for _, f := range []string{"migrations/0066_central_recording.sql", "migrations/0067_recording_playback.sql", "migrations/0077_recording_lost.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		execScript(t, h.su, string(b)) // again, on a populated schema
	}
	if got, err := h.store.GetRecording(ctx, h.tenantA, r.ID); err != nil || got.State != RecUploading {
		t.Fatalf("row after re-applying the migration: %+v %v", got, err)
	}
	if p, _ := h.store.GetPolicy(ctx, h.tenantA); p.RetentionDays != 30 {
		t.Fatalf("policy lost: %+v", p)
	}
	// view_recordings lands on Owner, Admin and Auditor — and only there — and once.
	for role, want := range map[string]bool{"owner": true, "admin": true, "auditor": true, "technician": false, "readonly": false} {
		var n int
		if err := h.su.QueryRow(ctx, `SELECT count(*) FROM unnest((SELECT capabilities FROM role WHERE tenant_id IS NULL AND key = $1)) c WHERE c = 'view_recordings'`, role).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if (n == 1) != want || n > 1 {
			t.Errorf("role %s holds view_recordings %d times, want %v", role, n, want)
		}
	}
}

func TestRecordingPgCompositeForeignKeysClosetheCrossTenantWrite(t *testing.T) {
	h := newPgRecHarness(t)
	sessA := h.sessionOf(h.tenantA, h.machineA)
	sessB := h.sessionOf(h.tenantB, h.machineB)
	// tenant A's recording naming tenant B's MACHINE, and tenant B's SESSION: a plain FK to the parent's
	// global primary key would accept both (FK checks bypass RLS); the (tenant_id, id) keys refuse.
	if code := pgCode(h.insertRow(t, h.tenantA, h.machineB, sessA, "", "")); code != "23503" {
		t.Fatalf("a recording naming another tenant's machine: SQLSTATE %q, want 23503", code)
	}
	if code := pgCode(h.insertRow(t, h.tenantA, h.machineA, sessB, "", "")); code != "23503" {
		t.Fatalf("a recording naming another tenant's session: SQLSTATE %q, want 23503", code)
	}
	if err := h.insertRow(t, h.tenantA, h.machineA, sessA, "", ""); err != nil {
		t.Fatalf("the legitimate insert: %v", err)
	}
	// A segment cannot point at a recording of another tenant either.
	var rid string
	if err := h.su.QueryRow(context.Background(), `SELECT id::text FROM session_recording WHERE tenant_id = $1`, h.tenantA).Scan(&rid); err != nil {
		t.Fatal(err)
	}
	_, err := h.su.Exec(context.Background(), `INSERT INTO session_recording_segment (tenant_id, recording_id, idx, declared_len) VALUES ($1, $2, 0, 10)`, h.tenantB, rid)
	if pgCode(err) != "23503" {
		t.Fatalf("a segment of tenant B under tenant A's recording: %v", err)
	}
	// A machine or session that still has a recording cannot be deleted out from under it (no cascade).
	if _, err := h.su.Exec(context.Background(), `DELETE FROM machine WHERE id = $1`, h.machineA); pgCode(err) != "23503" {
		t.Fatalf("deleting a machine with a recording: %v", err)
	}
	// Deleting the whole tenant still works (it cascades through tenant(id)).
	if _, err := h.su.Exec(context.Background(), `DELETE FROM tenant WHERE id = $1`, h.tenantA); err != nil {
		t.Fatalf("deleting a tenant with recordings: %v", err)
	}
	var n int
	h.su.QueryRow(context.Background(), `SELECT count(*) FROM session_recording WHERE tenant_id = $1`, h.tenantA).Scan(&n)
	if n != 0 {
		t.Fatalf("%d recording rows survived their tenant", n)
	}
}

func TestRecordingPgRowLevelSecurityAndGrants(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	env.enable(t, h.tenantB, 30, 1<<30, 20<<30)
	env.create(t, h.tenantA, h.machineA)
	env.create(t, h.tenantB, h.machineB)

	count := func(tenant, q string, args ...any) (n int) {
		err := withTenant(ctx, h.app, tenant, func(tx pgx.Tx) error { return tx.QueryRow(ctx, q, args...).Scan(&n) })
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return
	}
	if n := count(h.tenantA, `SELECT count(*) FROM session_recording`); n != 1 {
		t.Fatalf("tenant A sees %d recordings, want 1", n)
	}
	if n := count(h.tenantA, `SELECT count(*) FROM session_recording_segment`); n != 2 {
		t.Fatalf("tenant A sees %d segments, want 2", n)
	}
	if n := count(h.tenantA, `SELECT count(*) FROM tenant_recording_policy`); n != 1 {
		t.Fatalf("tenant A sees %d policies, want 1", n)
	}
	// Writing another tenant's tenant_id is refused by WITH CHECK.
	err := withTenant(ctx, h.app, h.tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE session_recording SET tenant_id = $1 WHERE tenant_id = $2`, h.tenantB, h.tenantA)
		return err
	})
	if err == nil {
		t.Fatal("tenant A moved a row into tenant B")
	}
	// No DELETE grant: tombstones cannot be deleted by the application, whatever the tenant.
	for _, tbl := range []string{"session_recording", "session_recording_segment"} {
		err := withTenant(ctx, h.app, h.tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM `+tbl)
			return err
		})
		if pgCode(err) != "42501" {
			t.Fatalf("DELETE FROM %s as rmt_app: %v, want permission denied (42501)", tbl, err)
		}
	}
}

func TestRecordingPgStateConstraints(t *testing.T) {
	h := newPgRecHarness(t)
	sess := h.sessionOf(h.tenantA, h.machineA)
	ts := ", evidence_complete_at, expires_at, provenance"
	tv := ", now(), now() + interval '1 day', 'no_matching_stop_event'"
	cases := []struct {
		name, state, cols, vals string
		wantOK                  bool
	}{
		{"uploading alone", "uploading", "", "", true},
		{"uploading with expiry", "uploading", ", expires_at", ", now()", false},
		{"uploading with provenance", "uploading", ", provenance", ", 'no_matching_stop_event'", false},
		{"evidence_complete complete", "evidence_complete", ts, tv, true},
		{"evidence_complete without provenance", "evidence_complete", ", evidence_complete_at, expires_at", ", now(), now()", false},
		{"evidence_complete without expiry", "evidence_complete", ", evidence_complete_at, provenance", ", now(), 'no_matching_stop_event'", false},
		{"unknown provenance", "evidence_complete", ", evidence_complete_at, expires_at, provenance", ", now(), now(), 'verified'", false},
		{"expired complete", "expired", ts + ", expired_at", tv + ", now()", true},
		{"expired without expired_at", "expired", ts, tv, false},
		{"deleted complete", "deleted", ts + ", expired_at, deleted_at", tv + ", now(), now()", true},
		{"deleted without deleted_at", "deleted", ts + ", expired_at", tv + ", now()", false},
		{"abandoned", "abandoned", "", "", true},
		{"refused with expiry", "refused", ", expires_at", ", now()", false},
		{"unknown state", "bogus", "", "", false},
	}
	for _, c := range cases {
		_, err := h.su.Exec(context.Background(), `
			INSERT INTO session_recording (tenant_id, id, session_id, machine_id, upload_id, enrollment_fp, generation,
				state, segment_count, declared_bytes, reserved_bytes, key_id, wrapped_dek, retention_days`+c.cols+`)
			VALUES ($1, gen_random_uuid(), $2, $3, gen_random_uuid(), $4, 1, $6, 1, 10, 100, 1, $5, 30`+c.vals+`)`,
			h.tenantA, sess, h.machineA, make([]byte, 32), make([]byte, 72), c.state)
		if (err == nil) != c.wantOK {
			t.Errorf("%s: err=%v wantOK=%v", c.name, err, c.wantOK)
		}
	}
	// The column defaults are the fail-closed ones: a bare row is storage OFF.
	if _, err := h.su.Exec(context.Background(), `INSERT INTO tenant_recording_policy (tenant_id) VALUES ($1)`, h.tenantB); err != nil {
		t.Fatal(err)
	}
	var days int
	h.su.QueryRow(context.Background(), `SELECT retention_days FROM tenant_recording_policy WHERE tenant_id = $1`, h.tenantB).Scan(&days)
	if days != 0 {
		t.Fatalf("the column default is %d days; the fail-closed default is 0 (storage off)", days)
	}
	// Policy range checks (UPDATEs of the existing row: an upsert whose insert half succeeds would not
	// reach the CHECK).
	for name, set := range map[string]string{
		"retention 366":      `retention_days = 366`,
		"retention -1":       `retention_days = -1`,
		"max cap over 1 GiB": `max_recording_bytes = 1073741825`,
		"max cap 0":          `max_recording_bytes = 0`,
		"negative quota":     `quota_bytes = -1`,
	} {
		_, err := h.su.Exec(context.Background(), `UPDATE tenant_recording_policy SET `+set+` WHERE tenant_id = $1`, h.tenantB)
		if pgCode(err) != "23514" {
			t.Errorf("policy %s: %v, want a CHECK violation", name, err)
		}
	}
}

func TestRecordingPgTriggersGuardImmutabilityAndTransitions(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	r, _ := env.create(t, h.tenantA, h.machineA, 100)
	su := func(q string, args ...any) error {
		_, err := h.su.Exec(ctx, q, append([]any{h.tenantA, r.ID}, args...)...)
		return err
	}
	// Immutable create-time metadata.
	for name, q := range map[string]string{
		"session_id":     `UPDATE session_recording SET session_id = gen_random_uuid() WHERE tenant_id = $1 AND id = $2`,
		"upload_id":      `UPDATE session_recording SET upload_id = gen_random_uuid() WHERE tenant_id = $1 AND id = $2`,
		"generation":     `UPDATE session_recording SET generation = 2 WHERE tenant_id = $1 AND id = $2`,
		"declared_bytes": `UPDATE session_recording SET declared_bytes = 11 WHERE tenant_id = $1 AND id = $2`,
		"reserved_bytes": `UPDATE session_recording SET reserved_bytes = 1 WHERE tenant_id = $1 AND id = $2`,
		"wrapped_dek":    `UPDATE session_recording SET wrapped_dek = '\x00'::bytea WHERE tenant_id = $1 AND id = $2`,
		"key_id":         `UPDATE session_recording SET key_id = 2 WHERE tenant_id = $1 AND id = $2`,
		"created_at":     `UPDATE session_recording SET created_at = now() - interval '1 year' WHERE tenant_id = $1 AND id = $2`,
		"retention_days": `UPDATE session_recording SET retention_days = 365 WHERE tenant_id = $1 AND id = $2`,
		"fingerprint":    `UPDATE session_recording SET enrollment_fp = '\x00'::bytea WHERE tenant_id = $1 AND id = $2`,
	} {
		if err := su(q); pgCode(err) != "23514" {
			t.Errorf("immutable column %s: %v, want the guard trigger's 23514", name, err)
		}
	}
	if err := su(`UPDATE session_recording_segment SET declared_len = 5 WHERE tenant_id = $1 AND recording_id = $2`); err == nil {
		t.Error("segment declared_len was updated")
	}
	if err := su(`UPDATE session_recording_segment SET committed_offset = 101 WHERE tenant_id = $1 AND recording_id = $2`); err == nil {
		t.Error("committed_offset beyond declared_len accepted")
	}
	// Illegal transitions from uploading.
	for _, to := range []string{"expired", "deleted", "playback_ready"} {
		if err := su(`UPDATE session_recording SET state = '` + to + `' WHERE tenant_id = $1 AND id = $2`); err == nil {
			t.Errorf("uploading -> %s accepted", to)
		}
	}
	// A legal walk, then every way back is refused, and a tombstone is final.
	env.commitAll(t, h.tenantA, r)
	if _, err := h.store.CompleteEvidence(ctx, h.tenantA, r.ID, completion(r)); err != nil {
		t.Fatal(err)
	}
	if err := su(`UPDATE session_recording SET expires_at = expires_at + interval '1 day' WHERE tenant_id = $1 AND id = $2`); err == nil {
		t.Error("expires_at was extended")
	}
	if err := su(`UPDATE session_recording SET expires_at = NULL WHERE tenant_id = $1 AND id = $2`); err == nil {
		t.Error("expires_at was cleared")
	}
	if err := su(`UPDATE session_recording SET evidence_complete_at = now() WHERE tenant_id = $1 AND id = $2`); err == nil {
		t.Error("evidence_complete_at was rewritten")
	}
	if err := su(`UPDATE session_recording SET expires_at = expires_at - interval '1 day' WHERE tenant_id = $1 AND id = $2`); err != nil {
		t.Errorf("shortening expires_at must be allowed: %v", err)
	}
	for _, to := range []string{"uploading", "abandoned", "refused", "deleted"} {
		if err := su(`UPDATE session_recording SET state = '` + to + `' WHERE tenant_id = $1 AND id = $2`); err == nil {
			t.Errorf("evidence_complete -> %s accepted", to)
		}
	}
	if err := h.store.MarkExpired(ctx, h.tenantA, r.ID); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"uploading", "evidence_complete", "playback_ready", "abandoned"} {
		if err := su(`UPDATE session_recording SET state = '` + to + `' WHERE tenant_id = $1 AND id = $2`); err == nil {
			t.Errorf("expired -> %s accepted", to)
		}
	}
	if err := h.store.MarkDeleted(ctx, h.tenantA, r.ID); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"uploading", "evidence_complete", "expired", "playback_ready", "abandoned", "refused"} {
		if err := su(`UPDATE session_recording SET state = '` + to + `' WHERE tenant_id = $1 AND id = $2`); err == nil {
			t.Errorf("deleted -> %s accepted: a tombstone was resurrected", to)
		}
	}
	// Abandoned/refused are final too.
	a, _ := env.create(t, h.tenantA, h.machineA, 100)
	h.store.AbandonRecording(ctx, h.tenantA, a.ID)
	if _, err := h.su.Exec(ctx, `UPDATE session_recording SET state = 'uploading' WHERE tenant_id = $1 AND id = $2`, h.tenantA, a.ID); err == nil {
		t.Error("abandoned -> uploading accepted")
	}
}

func TestRecordingPgDefinerFunctionsAreNarrow(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	for _, fn := range []string{"cp_recording_sweep_list", "cp_recording_global_unwritten"} {
		var secdef bool
		var acl *string
		var cfgArr []string
		if err := h.su.QueryRow(ctx, `SELECT prosecdef, proconfig, proacl::text FROM pg_proc WHERE proname = $1`, fn).Scan(&secdef, &cfgArr, &acl); err != nil {
			t.Fatalf("%s: %v", fn, err)
		}
		if !secdef {
			t.Errorf("%s is not SECURITY DEFINER", fn)
		}
		if !strings.Contains(strings.Join(cfgArr, ","), "search_path=public, pg_catalog") {
			t.Errorf("%s has no fixed search_path: %v", fn, cfgArr)
		}
		// A PUBLIC grant is an ACL element that STARTS with "=" ("{=X/owner,…}"); "owner=X/owner" is not one.
		if acl == nil || strings.Contains(*acl, "{=") || strings.Contains(*acl, ",=") || !strings.Contains(*acl, "rmt_app=X/") {
			t.Errorf("%s ACL = %v; EXECUTE must be revoked from PUBLIC and granted to rmt_app", fn, acl)
		}
	}
	// The definer reads across tenants for the sweeper, as rmt_app, with no tenant pinned.
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	env.enable(t, h.tenantB, 30, 1<<30, 20<<30)
	env.create(t, h.tenantA, h.machineA)
	env.create(t, h.tenantB, h.machineB)
	rows, err := h.store.SweepList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tenants := map[string]bool{}
	for _, r := range rows {
		tenants[r.TenantID] = true
	}
	if !tenants[h.tenantA] || !tenants[h.tenantB] {
		t.Fatalf("the sweeper's lister does not span tenants: %v", tenants)
	}
	var unwritten int64
	if err := h.app.QueryRow(ctx, `SELECT cp_recording_global_unwritten()`).Scan(&unwritten); err != nil || unwritten <= 0 {
		t.Fatalf("global unwritten = %d, %v", unwritten, err)
	}
}

func TestRecordingPgConcurrentCreatesSerialiseQuotaAndIdempotence(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	one := RecordingReservation([]int64{RecChunkSize})
	env.enable(t, h.tenantA, 30, RecChunkSize, 2*one+one/2) // room for exactly two
	var wins, quota atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		in := env.newRec(h.tenantA, h.machineA, RecChunkSize)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := h.store.CreateRecording(ctx, h.tenantA, in, recFree)
			switch {
			case err == nil && created:
				wins.Add(1)
			case err == ErrRecordingQuota:
				quota.Add(1)
			default:
				t.Errorf("create: created=%v err=%v", created, err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 2 || quota.Load() != 6 {
		t.Fatalf("%d creates won, %d hit the quota; want exactly 2 and 6 (the reservation must be atomic with the insert)", wins.Load(), quota.Load())
	}
	// The same id created concurrently: one row, the rest are replays.
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	same := env.newRec(h.tenantA, h.machineA, 100)
	var created atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, c, err := h.store.CreateRecording(ctx, h.tenantA, same, recFree)
			if err != nil {
				t.Errorf("replay create: %v", err)
			}
			if c {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("%d concurrent creates of one id inserted, want 1", created.Load())
	}
}

func TestRecordingPgChunkCommitAndAbandonAreSerialised(t *testing.T) {
	h := newPgRecHarness(t)
	ctx := context.Background()
	env := &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB, session: h.sessionOf}
	env.enable(t, h.tenantA, 30, 1<<30, 20<<30)
	r, _ := env.create(t, h.tenantA, h.machineA, 3*RecChunkSize)
	inFn := make(chan struct{})
	commitDone := make(chan time.Time, 1)
	go func() {
		err := h.store.UpdateSegment(ctx, h.tenantA, r.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) {
			close(inFn)
			time.Sleep(400 * time.Millisecond) // the disk write + fsync, inside the row lock
			return RecChunkSize, nil
		})
		if err != nil {
			t.Errorf("commit: %v", err)
		}
		commitDone <- time.Now()
	}()
	<-inFn
	if err := h.store.AbandonRecording(ctx, h.tenantA, r.ID); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	abandonDone := time.Now()
	if done := <-commitDone; abandonDone.Before(done.Add(-50 * time.Millisecond)) {
		t.Fatal("abandon completed while a chunk commit still held the lock: they are not serialised")
	}
	got, _ := h.store.GetRecording(ctx, h.tenantA, r.ID)
	if got.State != RecAbandoned || got.Segments[0].CommittedOffset != RecChunkSize {
		t.Fatalf("after the race: %+v", got)
	}
}
