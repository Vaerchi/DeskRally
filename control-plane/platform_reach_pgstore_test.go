package controlplane

// LIVE-POSTGRES: migration 0078 and docs/68. What only the database can prove: the two reach tables are
// unreachable for the control plane's role, the ingest role reaches those tables and nothing else,
// cp_platform_downloads refuses everyone but a fresh-enough operator session (and audits the read), the Go
// and SQL upserts agree, no client data reaches a row, and /adoption counts only the caller's own tenant.
//
// The database is a FRESH one migrated by the real runner (freshMigrationDatabase), so the grants tested are
// the ones production gets, not a fixture's approximation.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rmt/controlplane/reach"
)

type reachFixture struct {
	su, app, ingest    *pgxpool.Pool
	platform, customer string
	op, nonOp, custOwn string
	opSession          string
	opGen              int64
	store              *PgPlatformStore
	audit              *PgMgmtAuditStore
}

func newReachFixture(t *testing.T) *reachFixture {
	t.Helper()
	ctx := context.Background()
	su := freshMigrationDatabase(t)
	if _, err := Migrate(ctx, su, "migrations", MigrateOptions{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	f := &reachFixture{su: su}
	cfg := su.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "rmt_app", ""
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	f.app = app
	// The ingest role has no password in a test database (NOLOGIN); SET ROLE from the superuser connection is
	// exactly "connect as it" as far as privileges go.
	icfg := su.Config().Copy()
	icfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `SET ROLE rmt_reach_ingest`)
		return err
	}
	ingest, err := pgxpool.NewWithConfig(ctx, icfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ingest.Close)
	f.ingest = ingest

	f.platform, f.op = provisionUser(t, su, "main", "op@platform.test", "password-1234")
	f.customer, f.custOwn = provisionUser(t, su, "loam", "owner@loam.test", "password-1234")
	if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&f.nonOp); err != nil {
		t.Fatal(err)
	}
	mustExec(t, su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, 'other@platform.test')`, f.nonOp, f.platform)
	for _, u := range []struct{ id, tenant string }{{f.op, f.platform}, {f.nonOp, f.platform}, {f.custOwn, f.customer}} {
		mustExec(t, su, `INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at) VALUES ($1, $2, 'x', now())`, u.id, u.tenant)
		mustExec(t, su, `UPDATE app_user SET mfa_generation = nextval('mfa_generation_seq') WHERE id = $1`, u.id)
	}
	if err := su.QueryRow(ctx, `SELECT mfa_generation FROM app_user WHERE id = $1`, f.op).Scan(&f.opGen); err != nil {
		t.Fatal(err)
	}
	f.opSession = newSession(t, su, f.platform, f.op, "now()", f.opGen)
	mustExec(t, su, `INSERT INTO platform_config (tenant_id, set_by) VALUES ($1, 'test')`, f.platform)
	mustExec(t, su, `INSERT INTO platform_operator (user_id, tenant_id, granted_by) VALUES ($1, $2, 'test')`, f.op, f.platform)
	f.audit = NewPgMgmtAuditStore(app)
	f.store = NewPgPlatformStore(app, f.audit)
	return f
}

func (f *reachFixture) caller(user, session string) PlatformCaller {
	return PlatformCaller{UserID: user, TenantID: f.platform, SessionID: session, Email: "op@platform.test"}
}

func (f *reachFixture) seedDownloads(t *testing.T) {
	t.Helper()
	mustExec(t, f.su, `INSERT INTO download_daily (day, artifact, class, requests, completed, uniq, bytes, partial) VALUES
		('2026-11-01', 'DeskRallySupport.exe', 'human', 10, 4, 6, 100000, false),
		('2026-11-02', 'DeskRallySupport.exe', 'human', 3, NULL, 2, 30000, true),
		('2026-11-02', 'agent-manifest', 'update', 900, NULL, NULL, 270000, false),
		('2026-11-02', '-', 'noise', 55, NULL, NULL, 1000, false),
		('2024-01-01', 'DeskRallySupport.exe', 'human', 1, NULL, 1, 1, false)`)
}

func mustFail(t *testing.T, what string, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("%s: want an error containing %q, got %v", what, contains, err)
	}
}

func TestPgReachRolesAndGrants(t *testing.T) {
	f := newReachFixture(t)
	ctx := context.Background()

	// rmt_app: nothing on either table (0005's default privileges had granted it; 0078 revokes).
	for _, q := range []string{
		`SELECT count(*) FROM download_daily`, `SELECT count(*) FROM download_ingest_cursor`,
		`INSERT INTO download_daily (day, artifact, class) VALUES ('2026-11-01', 'x', 'noise')`,
		`UPDATE download_daily SET requests = 1`, `DELETE FROM download_daily`,
		`INSERT INTO download_ingest_cursor (file_id, last_name, byte_offset) VALUES ('00000000000000000000000000000000', 'x', 0)`,
		`DELETE FROM download_ingest_cursor`,
	} {
		_, err := f.app.Exec(ctx, q)
		mustFail(t, "rmt_app: "+q, err, "permission denied")
	}

	// The ingest role: its tables, fully; nothing else.
	for _, q := range []string{
		`INSERT INTO download_daily (day, artifact, class, requests) VALUES ('2026-11-01', 'x', 'noise', 1)`,
		`UPDATE download_daily SET requests = 2`,
		`SELECT count(*) FROM download_daily`,
		`INSERT INTO download_ingest_cursor (file_id, last_name, byte_offset) VALUES ('00000000000000000000000000000000', 'x', 0)`,
		`UPDATE download_ingest_cursor SET byte_offset = 5`,
		`SELECT count(*) FROM download_ingest_cursor`,
		`DELETE FROM download_daily`, `DELETE FROM download_ingest_cursor`,
	} {
		if _, err := f.ingest.Exec(ctx, q); err != nil {
			t.Fatalf("the ingest role must be able to run %q: %v", q, err)
		}
	}
	// One connection with a tenant context set: some policies read app.current_tenant without missing_ok, and the
	// rewriter expands them BEFORE the privilege check, which would turn "permission denied" into a different error.
	ic, err := f.ingest.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Release()
	if _, err := ic.Exec(ctx, `SELECT set_config('app.current_tenant', '00000000-0000-4000-8000-000000000000', false)`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM tenant`, `SELECT count(*) FROM app_user`, `SELECT count(*) FROM user_session`,
		`SELECT count(*) FROM machine`, `SELECT count(*) FROM audit_event`, `SELECT count(*) FROM platform_operator`,
		`SELECT count(*) FROM session_recording`, `SELECT count(*) FROM schema_migration`,
		`INSERT INTO tenant (slug, name, deployment_mode) VALUES ('zz', 'zz', 'saas')`,
		`TRUNCATE download_daily`,
		`CREATE TABLE zz_ingest_made (x int)`,
		`SELECT * FROM cp_platform_downloads('00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000', '2026-01-01', '2026-01-02')`,
	} {
		_, err := ic.Exec(ctx, q)
		mustFail(t, "ingest role: "+q, err, "permission denied")
	}
	// The inventory, independent of the probes above: the tables the role holds ANY privilege on.
	tables := queryStrings(t, f.su, `SELECT c.relname FROM pg_class c
		WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r','p','v','m','f')
		  AND has_table_privilege('rmt_reach_ingest', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
		ORDER BY 1`)
	if strings.Join(tables, ",") != "download_daily,download_ingest_cursor" {
		t.Fatalf("the ingest role has privileges on %v, want exactly the two reach tables", tables)
	}
	if n := queryStrings(t, f.su, `SELECT 'x' FROM pg_class c WHERE c.relkind = 'S' AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('rmt_reach_ingest', c.oid, 'USAGE,SELECT,UPDATE') END`); len(n) != 0 {
		t.Fatalf("the ingest role can use sequences: %v", n)
	}
	var super, bypass, login, createdb, createrole, repl, canCreate, canTruncate bool
	if err := f.su.QueryRow(ctx, `SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole, rolreplication,
		has_schema_privilege('rmt_reach_ingest', 'public', 'CREATE'), has_table_privilege('rmt_reach_ingest', 'download_daily', 'TRUNCATE')
		FROM pg_roles WHERE rolname = 'rmt_reach_ingest'`).Scan(&super, &bypass, &login, &createdb, &createrole, &repl, &canCreate, &canTruncate); err != nil {
		t.Fatal(err)
	}
	if super || bypass || login || createdb || createrole || repl || canCreate || canTruncate {
		t.Fatalf("ingest role attributes: super=%v bypassrls=%v login=%v (the deployment grants it) createdb=%v createrole=%v replication=%v create=%v truncate=%v",
			super, bypass, login, createdb, createrole, repl, canCreate, canTruncate)
	}

	// The definer that owns the read: SELECT on the counts, nothing on the cursor, no write.
	var defSel, defCur, defIns bool
	if err := f.su.QueryRow(ctx, `SELECT has_table_privilege('rmt_definer', 'download_daily', 'SELECT'),
		has_table_privilege('rmt_definer', 'download_ingest_cursor', 'SELECT,INSERT,UPDATE,DELETE'),
		has_table_privilege('rmt_definer', 'download_daily', 'INSERT,UPDATE,DELETE')`).Scan(&defSel, &defCur, &defIns); err != nil {
		t.Fatal(err)
	}
	if !defSel || defCur || defIns {
		t.Fatalf("rmt_definer: select=%v cursor=%v write=%v", defSel, defCur, defIns)
	}
	var owner string
	var appExec, publicExec, ingestExec bool
	if err := f.su.QueryRow(ctx, `SELECT proowner::regrole::text, has_function_privilege('rmt_app', oid, 'EXECUTE'),
		has_function_privilege('public', oid, 'EXECUTE'), has_function_privilege('rmt_reach_ingest', oid, 'EXECUTE')
		FROM pg_proc WHERE proname = 'cp_platform_downloads'`).Scan(&owner, &appExec, &publicExec, &ingestExec); err != nil {
		t.Fatal(err)
	}
	if owner != "rmt_definer" || !appExec || publicExec || ingestExec {
		t.Fatalf("cp_platform_downloads: owner=%s rmt_app=%v public=%v ingest=%v", owner, appExec, publicExec, ingestExec)
	}
	// The columns are a fixed set with nowhere to put an address, a User-Agent or a hash.
	cols := queryStrings(t, f.su, `SELECT table_name || '.' || column_name || ' ' || data_type FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name IN ('download_daily', 'download_ingest_cursor') ORDER BY 1`)
	want := "download_daily.artifact text,download_daily.bytes bigint,download_daily.class text,download_daily.completed integer," +
		"download_daily.day date,download_daily.partial boolean,download_daily.requests integer,download_daily.uniq integer," +
		"download_ingest_cursor.byte_offset bigint,download_ingest_cursor.complete boolean,download_ingest_cursor.file_id text,download_ingest_cursor.last_name text,download_ingest_cursor.updated_at timestamp with time zone"
	if strings.Join(cols, ",") != want {
		t.Fatalf("columns:\n%s\nwant\n%s", strings.Join(cols, ","), want)
	}
}

func TestPgPlatformDownloadsGate(t *testing.T) {
	f := newReachFixture(t)
	f.seedDownloads(t)
	ctx := context.Background()
	from, to := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	auditCount := func() int {
		var n int
		if err := f.su.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action = 'platform.reach.read'`, f.platform).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	rows, err := f.store.DownloadReport(ctx, f.caller(f.op, f.opSession), from, to, newUUID())
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	if len(rows) != 4 || rows[0].Day != "2026-11-01" || rows[0].Requests != 10 || rows[0].Completed == nil || *rows[0].Completed != 4 ||
		rows[0].UniqueIsh == nil || *rows[0].UniqueIsh != 6 || rows[1].Completed != nil || !rows[1].Partial {
		t.Fatalf("rows %+v", rows)
	}
	for _, r := range rows {
		if r.Day == "2024-01-01" {
			t.Fatal("a row outside the range was returned")
		}
	}
	if n := auditCount(); n != 1 {
		t.Fatalf("an allowed read must leave exactly one platform audit event, got %d", n)
	}
	verifyChain(t, f.audit, f.platform)

	// A denial leaves no audit event and returns the opaque error.
	stale := newSession(t, f.su, f.platform, f.op, "now() - interval '13 hours'", f.opGen)
	nonOpSess := newSession(t, f.su, f.platform, f.nonOp, "now()", 1)
	custSess := newSession(t, f.su, f.customer, f.custOwn, "now()", 1)
	noMFA := newSession(t, f.su, f.platform, f.op, "", 0)
	revoked := newSession(t, f.su, f.platform, f.op, "now()", f.opGen)
	mustExec(t, f.su, `UPDATE user_session SET revoked_at = now() WHERE id = $1`, revoked)
	wrongGen := newSession(t, f.su, f.platform, f.op, "now()", f.opGen+1000)
	for name, c := range map[string]PlatformCaller{
		"stale MFA (13 h)":                         f.caller(f.op, stale),
		"never verified MFA":                       f.caller(f.op, noMFA),
		"revoked session":                          f.caller(f.op, revoked),
		"MFA of another generation":                f.caller(f.op, wrongGen),
		"a platform user who is no operator":       f.caller(f.nonOp, nonOpSess),
		"an operator's id on a stranger's session": f.caller(f.op, nonOpSess),
		"a customer tenant's owner":                {UserID: f.custOwn, TenantID: f.customer, SessionID: custSess},
		"an API token (no session id)":             f.caller(f.op, ""),
		"a malformed session id":                   f.caller(f.op, "not-a-uuid"),
	} {
		if _, err := f.store.DownloadReport(ctx, c, from, to, newUUID()); !errors.Is(err, ErrPlatformDenied) {
			t.Errorf("%s: got %v, want ErrPlatformDenied", name, err)
		}
	}
	if n := auditCount(); n != 1 {
		t.Fatalf("denied reads left audit events: %d", n)
	}
	// An operator session that is 20 minutes old is fine for a READ (12 h), unlike a lifecycle change.
	fresh := newSession(t, f.su, f.platform, f.op, "now() - interval '20 minutes'", f.opGen)
	if _, err := f.store.DownloadReport(ctx, f.caller(f.op, fresh), from, to, newUUID()); err != nil {
		t.Fatalf("a 20-minute-old session reads: %v", err)
	}

	// The function itself, as the control plane's role: its own range bound and NULL handling.
	call := func(session any, from, to any) error {
		return withTenant(ctx, f.app, f.platform, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT * FROM cp_platform_downloads($1, $2, $3, $4)`, f.op, session, from, to)
			if err != nil {
				return err
			}
			rows.Close()
			return rows.Err()
		})
	}
	mustFail(t, "NULL session", call(nil, "2026-11-01", "2026-11-02"), "platform:")
	mustFail(t, "401-day range", call(f.opSession, "2025-10-01", "2026-11-05"), "the report range")
	mustFail(t, "reversed range", call(f.opSession, "2026-11-05", "2026-11-01"), "the report range")
	mustFail(t, "NULL bound", call(f.opSession, nil, "2026-11-01"), "the report range")
	if err := call(f.opSession, "2025-10-02", "2026-11-05"); err != nil {
		t.Fatalf("a 400-day range is allowed: %v", err)
	}
}

// reachRows reads the aggregates the way MemStore reports them, as the superuser.
func reachRows(t *testing.T, pool *pgxpool.Pool) []reach.Row {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT day::text, artifact, class, requests, completed, uniq, bytes, partial
		FROM download_daily ORDER BY day, class, artifact`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []reach.Row
	for rows.Next() {
		var r reach.Row
		var class string
		var req int32
		var c, u *int32
		if err := rows.Scan(&r.Day, &r.Artifact, &class, &req, &c, &u, &r.Bytes, &r.Partial); err != nil {
			t.Fatal(err)
		}
		r.Class, r.Requests = reach.Class(class), int64(req)
		if c != nil {
			v := int64(*c)
			r.Completed = &v
		}
		if u != nil {
			v := int64(*u)
			r.Uniq = &v
		}
		out = append(out, r)
	}
	return out
}

func rowsString(rs []reach.Row) string {
	var lines []string // sorted here: the stores order by different collations
	for _, r := range rs {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|req=%d|done=%d|uniq=%d|bytes=%d|partial=%v\n", r.Day, r.Artifact, r.Class, r.Requests, deref64(r.Completed), deref64(r.Uniq), r.Bytes, r.Partial))
	}
	sort.Strings(lines)
	return strings.Join(lines, "")
}

func deref64(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

// FAKE AND PG MUST AGREE: one script, both stores.
func TestPgReachStoreAgreesWithMemStore(t *testing.T) {
	f := newReachFixture(t)
	ctx := context.Background()
	mem := reach.NewMemStore()
	pg := &reach.PgStore{Pool: f.ingest}
	id := strings.Repeat("a", 32)
	id2 := strings.Repeat("b", 32)
	script := []reach.Batch{
		{Aggs: []reach.Agg{
			{Day: "2026-11-05", Artifact: "DeskRallySupport.exe", Class: reach.ClassHuman, Requests: 3, Bytes: 300, Completed: 1, CompletedKnown: true, Uniq: 2, Partial: true},
			{Day: "2026-11-05", Artifact: reach.NoiseArtifact, Class: reach.ClassNoise, Requests: 9, Bytes: 90, Uniq: -1},
		}, Cursor: reach.Cursor{FileID: id, Name: "access.log", Offset: 100}},
		{Aggs: []reach.Agg{ // adds; a smaller unique set must not lower it; a known-nothing delta keeps completed
			{Day: "2026-11-05", Artifact: "DeskRallySupport.exe", Class: reach.ClassHuman, Requests: 2, Bytes: 200, Uniq: 1},
		}, Cursor: reach.Cursor{FileID: id, Name: "access.log", Offset: 250}},
		{Aggs: []reach.Agg{ // completed NULL stays NULL until a line knows; then it starts from 0
			{Day: "2026-11-06", Artifact: "agent/new-msi-provisioning.ps1", Class: reach.ClassHuman, Requests: 1, Uniq: 1},
			{Day: "2026-11-06", Artifact: "agent/new-msi-provisioning.ps1", Class: reach.ClassHuman, Requests: 1, Uniq: -1},
		}, Cursor: reach.Cursor{FileID: id2, Name: "access-x.log.gz", Offset: 7}},
		{Aggs: []reach.Agg{
			{Day: "2026-11-06", Artifact: "agent/new-msi-provisioning.ps1", Class: reach.ClassHuman, Requests: 1, Completed: 0, CompletedKnown: true, Uniq: 3},
			{Day: "2026-11-06", Artifact: "DeskRallySupport.exe", Class: reach.ClassHuman, Requests: 1, Completed: 4, CompletedKnown: true, Uniq: 1},
			{Day: "2026-11-06", Artifact: "DeskRallySupport.exe", Class: reach.ClassHuman, Requests: 1, Completed: 2, CompletedKnown: true, Uniq: 1},
		}, Cursor: reach.Cursor{FileID: id2, Name: "access-x.log.gz", Offset: 9, Complete: true}},
		{Aggs: []reach.Agg{{Day: "2020-01-01", Artifact: "old", Class: reach.ClassOther, Requests: 1, Uniq: -1}}, Cursor: reach.Cursor{FileID: id2, Name: "access-x.log.gz", Offset: 9, Complete: true}},
	}
	for i, b := range script {
		// Within one batch the SAME key can repeat only across batches in real use; keep each batch's keys unique.
		seen := map[string]bool{}
		for _, a := range b.Aggs {
			k := a.Day + a.Artifact + string(a.Class)
			if seen[k] {
				// merge duplicates by running them as separate batches, in order
				b2 := reach.Batch{Aggs: []reach.Agg{a}, Cursor: b.Cursor}
				if err := mem.Commit(ctx, b2); err != nil {
					t.Fatal(err)
				}
				if err := pg.Commit(ctx, b2); err != nil {
					t.Fatalf("batch %d: %v", i, err)
				}
				continue
			}
			seen[k] = true
			b2 := reach.Batch{Aggs: []reach.Agg{a}, Cursor: b.Cursor}
			if err := mem.Commit(ctx, b2); err != nil {
				t.Fatal(err)
			}
			if err := pg.Commit(ctx, b2); err != nil {
				t.Fatalf("batch %d: %v", i, err)
			}
		}
	}
	if m, p := rowsString(mem.Rows()), rowsString(reachRows(t, f.su)); m != p {
		t.Fatalf("MemStore and PgStore disagree:\nmem:\n%s\npg:\n%s", m, p)
	}
	mc, _ := mem.Cursors(ctx)
	pc, err := pg.Cursors(ctx)
	if err != nil || fmt.Sprint(mc) != fmt.Sprint(pc) {
		t.Fatalf("cursors: mem %v pg %v %v", mc, pc, err)
	}
	// An atomic batch: a failing upsert leaves neither rows nor the cursor.
	bad := reach.Batch{Aggs: []reach.Agg{{Day: "2026-11-07", Artifact: "x", Class: reach.Class("bogus"), Requests: 1, Uniq: -1}},
		Cursor: reach.Cursor{FileID: strings.Repeat("c", 32), Name: "n", Offset: 1}}
	if err := pg.Commit(ctx, bad); err == nil {
		t.Fatal("a row with an invalid class must be refused by the CHECK")
	}
	if pc2, _ := pg.Cursors(ctx); len(pc2) != len(pc) {
		t.Fatalf("a failed batch moved the cursor: %v", pc2)
	}

	// Prune parity: old rows go, unseen stale cursors go, seen ones stay, an empty listing deletes no cursor.
	future := time.Now().Add(time.Hour)
	for name, s := range map[string]reach.Store{"mem": mem, "pg": pg} {
		if err := s.Prune(ctx, "2026-01-01", nil, future); err != nil {
			t.Fatal(err)
		}
		if cs, _ := s.Cursors(ctx); len(cs) != 2 {
			t.Fatalf("%s: an empty listing pruned cursors: %v", name, cs)
		}
		if err := s.Prune(ctx, "2026-01-01", []string{id}, future); err != nil {
			t.Fatal(err)
		}
		if cs, _ := s.Cursors(ctx); len(cs) != 1 || cs[id].FileID != id {
			t.Fatalf("%s: cursors after prune: %v", name, cs)
		}
	}
	if m, p := rowsString(mem.Rows()), rowsString(reachRows(t, f.su)); m != p || strings.Contains(p, "2020-01-01") {
		t.Fatalf("after prune:\nmem:\n%s\npg:\n%s", m, p)
	}
}

// THE PRIVACY ASSERTION, against the real tables: ingest a log full of distinctive addresses and agents, then
// dump every row of both tables and look for any of them, or any hash made from them.
func TestPgReachStoredRowsNeverContainAnIPUAOrHash(t *testing.T) {
	f := newReachFixture(t)
	ctx := context.Background()
	logDir := t.TempDir()
	ips := []string{"203.0.113.77", "198.51.100.200", "2001:db8::beef"}
	uas := []string{"Mozilla/5.0 (X11; SecretOS 9.9) Gecko/9999 Distinctive/42", "curl/9.99.9-privacy-probe"}
	now := time.Now().UTC()
	var lines []string
	for _, ip := range ips {
		for _, ua := range uas {
			lines = append(lines,
				fmt.Sprintf(`{"ts":%d.5,"status":200,"size":123,"request":{"remote_ip":%q,"method":"GET","uri":"/download/DeskRallySupport.exe","headers":{"User-Agent":[%q]}}}`, now.Add(-time.Minute).Unix(), ip, ua))
		}
	}
	if err := os.WriteFile(filepath.Join(logDir, "access.log"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saltPath := filepath.Join(t.TempDir(), "salt")
	in, err := reach.New(reach.Config{Dir: logDir, SaltFile: reach.SaltFile{Path: saltPath}, Store: &reach.PgStore{Pool: f.ingest},
		Sizes: func(string) (int64, bool) { return 123, true }, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := in.RunOnce(ctx); err != nil { // and a second pass: no double count
		t.Fatal(err)
	}
	rows := reachRows(t, f.su)
	if len(rows) != 1 || rows[0].Requests != 6 || rows[0].Uniq == nil || *rows[0].Uniq != 6 || rows[0].Completed == nil || *rows[0].Completed != 6 {
		t.Fatalf("premise: %s", rowsString(rows))
	}
	dump := strings.Join(queryStrings(t, f.su, `SELECT t::text FROM download_daily t UNION ALL SELECT c::text FROM download_ingest_cursor c`), "\n")
	salt, ok := reach.SaltFile{Path: saltPath}.Load()
	if !ok {
		t.Fatal("no salt file")
	}
	needles := []string{hex.EncodeToString(salt.Key[:])}
	for _, ip := range ips {
		needles = append(needles, ip)
		for _, ua := range uas {
			h := salt.ClientHash(ip, ua)
			needles = append(needles, ua, hex.EncodeToString(h[:]), hex.EncodeToString(h[:8]))
		}
	}
	for _, n := range needles {
		if strings.Contains(dump, n) {
			t.Fatalf("the database contains %q:\n%s", n, dump)
		}
	}
}

func TestPgAdoptionCountsOnlyTheCallersTenant(t *testing.T) {
	f := newReachFixture(t)
	ctx := context.Background()
	tenants := map[string]string{"A": f.platform, "B": f.customer}
	groups := map[string]string{}
	for k, tid := range tenants {
		var g string
		if err := f.su.QueryRow(ctx, `INSERT INTO machine_group (tenant_id, name) VALUES ($1, 'g') RETURNING id::text`, tid).Scan(&g); err != nil {
			t.Fatal(err)
		}
		groups[k] = g
	}
	machine := func(k, device string, ephemeral bool, enrolled, lastSeen, status, version string) {
		last := "NULL"
		if lastSeen != "" {
			last = lastSeen
		}
		mustExec(t, f.su, `INSERT INTO machine (tenant_id, device_id, group_id, hostname, pubkey, enrolled_at, last_seen, status, ephemeral, agent_version)
			VALUES ($1, $2, $3, $2, '\x00', `+enrolled+`, `+last+`, $4, $5, $6)`, tenants[k], device, groups[k], status, ephemeral, version)
	}
	// Tenant A: three real devices (two in the week of 2026-11-02, one earlier), one retired, one guest.
	machine("A", "a1", false, "'2026-11-03 10:00+00'", "now() - interval '1 day'", "active", "1.3.19+abc1234")
	machine("A", "a2", false, "'2026-11-08 23:00+00'", "now() - interval '40 days'", "active", "1.3.19+def5678")
	machine("A", "a3", false, "'2026-10-20 10:00+00'", "now() - interval '2 days'", "active", "1.3.17+abc")
	machine("A", "a4", false, "'2026-11-04 10:00+00'", "now()", "retired", "1.3.17+abc")
	machine("A", "a5", true, "'2026-11-04 10:00+00'", "now()", "active", "")
	machine("A", "a6", false, "'2026-11-05 10:00+00'", "", "active", "")
	// Tenant B has far more, so a leak would be obvious.
	for i := 0; i < 20; i++ {
		machine("B", fmt.Sprintf("b%d", i), false, "'2026-11-03 10:00+00'", "now()", "active", "9.9.9+b")
	}
	att := func(k, code, state string, redeemed, consented bool) {
		r, c := "NULL", "NULL"
		if redeemed {
			r = "'2026-11-04 10:00+00'"
		}
		if consented {
			c = "'2026-11-04 10:01+00'"
		}
		mustExec(t, f.su, `INSERT INTO attended_session (tenant_id, group_id, technician_id, code_hash, state, expires_at, created_at, redeemed_at, consented_at)
			VALUES ($1, $2, gen_random_uuid(), digest($3, 'sha256'), $4, now() + interval '1 day', '2026-11-04 09:00+00', `+r+`, `+c+`)`, tenants[k], groups[k], code, state)
	}
	att("A", "a-1", "pending", false, false)
	att("A", "a-2", "redeemed", true, false)
	att("A", "a-3", "declined", true, false)
	att("A", "a-4", "active", true, true)
	att("A", "a-5", "ended", true, true)
	for i := 0; i < 9; i++ {
		att("B", fmt.Sprintf("b-%d", i), "active", true, true)
	}
	mustExec(t, f.su, `INSERT INTO attended_session (tenant_id, group_id, technician_id, code_hash, state, expires_at, created_at)
		VALUES ($1, $2, gen_random_uuid(), digest('a-old', 'sha256'), 'pending', now() + interval '1 day', '2026-06-01 09:00+00')`, tenants["A"], groups["A"])

	st := NewPgAdoptionStore(f.app)
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	a, err := st.Report(ctx, tenants["A"], from, to)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(a.NewDevicesPerWeek) != "[{2026-10-19 1} {2026-11-02 4}]" { // a3 | a1 a2 (Sunday 23:00 UTC) a4 (retired, still enrolled that week) a6
		t.Fatalf("weeks: %v", a.NewDevicesPerWeek)
	}
	var total int64
	for _, w := range a.NewDevicesPerWeek {
		total += w.Count
	}
	if total != 5 { // a1 a2 a3 a4 a6; the guest machine a5 is not a device
		t.Fatalf("new devices in range = %d (%v), want 5", total, a.NewDevicesPerWeek)
	}
	if a.ActiveDevices30d != 2 { // a1, a3: a2 is 40 days stale, a4 is retired, a5 is a guest, a6 never seen
		t.Fatalf("active devices = %d, want 2", a.ActiveDevices30d)
	}
	if a.Funnel != (AttendedFunnel{Issued: 5, Redeemed: 4, Consented: 2, Active: 2}) {
		t.Fatalf("funnel = %+v (the June session is outside the range)", a.Funnel)
	}
	vs := map[string]int64{}
	for _, v := range a.AgentVersions {
		vs[v.Version] = v.Count
	}
	if vs["1.3.19"] != 2 || vs["1.3.17"] != 1 || vs["unknown"] != 1 || len(vs) != 3 {
		t.Fatalf("versions = %v (retired and guest machines excluded, the build suffix dropped)", vs)
	}
	b, err := st.Report(ctx, tenants["B"], from, to)
	if err != nil {
		t.Fatal(err)
	}
	if b.ActiveDevices30d != 20 || b.Funnel.Issued != 9 || len(b.AgentVersions) != 1 || b.AgentVersions[0].Version != "9.9.9" || b.AgentVersions[0].Count != 20 {
		t.Fatalf("tenant B report %+v", b)
	}
	// RLS, not the filter, is what scopes it: ask for B's rows while pinned to A.
	if err := withTenant(ctx, f.app, tenants["A"], func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM machine WHERE tenant_id = $1`, tenants["B"]).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("tenant A's connection sees %d of tenant B's machines", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// An empty tenant is a zeroed, well-formed report.
	empty, err := st.Report(ctx, "00000000-0000-4000-8000-000000000001", from, to)
	if err != nil || empty.ActiveDevices30d != 0 || empty.Funnel != (AttendedFunnel{}) || len(empty.NewDevicesPerWeek) != 0 || len(empty.AgentVersions) != 0 {
		t.Fatalf("empty tenant: %+v %v", empty, err)
	}
}
