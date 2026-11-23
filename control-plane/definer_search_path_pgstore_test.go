package controlplane

// LIVE-POSTGRES: migration 0074 (Codex H1). Every SECURITY DEFINER function must end its search_path
// in pg_temp, or the application role can shadow a table the function reads with a TEMP VIEW and run
// code as the function's owner, a superuser in production.
//
// The per-test fixture applies migrations piecemeal, so this test migrates a FRESH DATABASE with the
// real runner and the real migrations directory, exactly as `controlplane migrate` does in production:
// first everything before 0074 (the premise: the hazard exists and the shadow attack works), then 0074.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const definerSearchPathMigration = "0074_definer_search_path.sql"

// unsafeDefinerSQL lists every definer routine outside the system schemas whose search_path is not EXACTLY
// the canonical one. Exact equality, deliberately: `pg_temp, public, pg_temp` and `public, "evil,pg_temp"` both
// end in pg_temp and are both unsafe, so no "ends in pg_temp" pattern is a safe check.
const unsafeDefinerSQL = `
SELECT n.nspname || '.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ') ' ||
       COALESCE((SELECT c FROM unnest(p.proconfig) AS c WHERE c LIKE 'search\_path=%'), 'search_path unset')
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef
  AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  AND (SELECT c FROM unnest(p.proconfig) AS c WHERE c LIKE 'search\_path=%') IS DISTINCT FROM 'search_path=pg_catalog, public, pg_temp'
ORDER BY 1`

// routineSnapshotSQL is everything about a public routine that 0074 must NOT change: owner, ACL, body and
// every setting other than search_path.
const routineSnapshotSQL = `
SELECT p.oid::text || ' ' || p.proname || ' owner=' || p.proowner::regrole::text || ' acl=' || COALESCE(p.proacl::text, '-') ||
       ' secdef=' || p.prosecdef::text || ' md5=' || md5(p.prosrc) || ' other=' ||
       COALESCE((SELECT string_agg(c, ';' ORDER BY c) FROM unnest(p.proconfig) AS c WHERE c NOT LIKE 'search\_path=%'), '-')
FROM pg_catalog.pg_proc p WHERE p.pronamespace = 'public'::regnamespace
ORDER BY 1`

// Adversarial paths that END in pg_temp but leave temp relations resolving first; 0074 must normalize them.
const definerTrickPathsSQL = `
CREATE SCHEMA "evil,pg_temp";
CREATE FUNCTION public.zz_definer_dup_pg_temp() RETURNS int LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_temp, public, pg_temp AS 'SELECT 1';
CREATE FUNCTION public.zz_definer_quoted_pg_temp() RETURNS int LANGUAGE sql SECURITY DEFINER
    SET search_path = public, "evil,pg_temp" AS 'SELECT 1';`

// The attack: as rmt_app, a temp view named `tenant` whose column calls a temp function that refuses to
// run as anyone but rmt_app. cp_resolve_tenant_by_slug (granted to PUBLIC, reads `tenant` unqualified)
// evaluates the view only if pg_temp is searched before public — and then runs the function as its owner.
const definerShadowAttackSQL = `
BEGIN;
SET LOCAL ROLE rmt_app;
CREATE FUNCTION pg_temp.definer_canary() RETURNS uuid LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    IF current_user <> 'rmt_app' THEN
        RAISE EXCEPTION 'DEFINER EVALUATED THE ATTACKER TEMP VIEW as %', current_user;
    END IF;
    RETURN '11111111-2222-3333-4444-555555555555'::uuid;
END
$$;
CREATE TEMP VIEW tenant AS
    SELECT pg_temp.definer_canary() AS id, 'definer-shadow'::text AS slug, NULL::timestamptz AS disabled_at;
SELECT public.cp_resolve_tenant_by_slug('definer-shadow');
ROLLBACK;`

func freshMigrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin := newTestPool(t) // skips without TEST_DATABASE_URL
	ctx := context.Background()
	if err := execScriptRaw(ctx, admin, fixtureDefinerRepinSQL); err != nil { // an interrupted adoption test must not leave the cluster-wide role elevated
		t.Fatalf("re-pin rmt_definer: %v", err)
	}
	name := fmt.Sprintf("rmt_definer_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to %s: %v", name, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func queryStrings(t *testing.T, pool *pgxpool.Pool, sql string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), sql)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPgEveryDefinerFunctionPutsPgTempLast(t *testing.T) {
	pool := freshMigrationDatabase(t)
	ctx := context.Background()

	// Everything before 0074, in a copy of the real directory.
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	before, through := t.TempDir(), t.TempDir() // through: up to AND INCLUDING 0074 (later migrations may redefine routines)
	found := false
	for _, e := range entries {
		if e.Name() == definerSearchPathMigration {
			found = true
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() > definerSearchPathMigration {
			continue
		}
		body, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() != definerSearchPathMigration {
			if err := os.WriteFile(filepath.Join(before, e.Name()), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(through, e.Name()), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatalf("migrations/%s is missing", definerSearchPathMigration)
	}
	if _, err := Migrate(ctx, pool, before, MigrateOptions{}); err != nil {
		t.Fatalf("migrate up to 0073: %v", err)
	}

	// PREMISE: the hazard exists before 0074, and the shadow attack really runs code as the definer.
	execScript(t, pool, definerTrickPathsSQL)
	unsafeBefore := queryStrings(t, pool, unsafeDefinerSQL)
	for _, trick := range []string{"zz_definer_dup_pg_temp", "zz_definer_quoted_pg_temp"} {
		if !strings.Contains(strings.Join(unsafeBefore, "\n"), trick) {
			t.Fatalf("the check does not flag %s, whose path ends in pg_temp but is unsafe", trick)
		}
	}
	if len(unsafeBefore) == 0 {
		t.Fatal("premise: no unsafe definer function before 0074, so the query cannot be detecting anything")
	}
	t.Logf("before 0074, %d unsafe definer functions:\n  %s", len(unsafeBefore), strings.Join(unsafeBefore, "\n  "))
	if err := execScriptErr(ctx, pool, definerShadowAttackSQL); err == nil ||
		!strings.Contains(err.Error(), "DEFINER EVALUATED THE ATTACKER TEMP VIEW") {
		t.Fatalf("premise: before 0074 the shadow attack must run the canary as the definer, got %v", err)
	}

	// A definer routine OUTSIDE the application's routines is refused, not rewritten, and the refusal
	// rolls 0074 back whole: nothing is altered and the ledger does not record it.
	execScript(t, pool, `CREATE SCHEMA zz_other;
		CREATE FUNCTION zz_other.f() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = zz_other AS 'SELECT 1';`)
	if _, err := Migrate(ctx, pool, "migrations", MigrateOptions{}); err == nil ||
		!strings.Contains(err.Error(), "zz_other.f()") || !strings.Contains(err.Error(), "deliberate fix") {
		t.Fatalf("a definer routine in another schema must stop 0074, got %v", err)
	}
	if got := queryStrings(t, pool, unsafeDefinerSQL); len(got) != len(unsafeBefore)+1 {
		t.Fatalf("after the refused 0074, %d unsafe routines, want the %d from before plus zz_other.f: a partial apply", len(got), len(unsafeBefore))
	}
	execScript(t, pool, `DROP SCHEMA zz_other CASCADE`)
	snapshotBefore := queryStrings(t, pool, routineSnapshotSQL)

	// Production's step: only 0074 applies, and it changes search_path alone (a later migration may redefine bodies).
	rep, err := Migrate(ctx, pool, through, MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate through 0074: %v", err)
	}
	if len(rep.Applied) != 1 || rep.Applied[0] != definerSearchPathMigration {
		t.Fatalf("applied %v, want exactly %s", rep.Applied, definerSearchPathMigration)
	}
	if after := queryStrings(t, pool, routineSnapshotSQL); strings.Join(after, "\n") != strings.Join(snapshotBefore, "\n") {
		t.Fatalf("0074 changed more than search_path:\nbefore:\n  %s\nafter:\n  %s",
			strings.Join(snapshotBefore, "\n  "), strings.Join(after, "\n  "))
	}
	// Then everything after it, as the real directory: a later definer function must keep the canonical path too.
	if _, err := Migrate(ctx, pool, "migrations", MigrateOptions{}); err != nil {
		t.Fatalf("migrate the full directory: %v", err)
	}

	if unsafe := queryStrings(t, pool, unsafeDefinerSQL); len(unsafe) != 0 {
		t.Fatalf("SECURITY DEFINER functions without a trailing pg_temp after a full migrate "+
			"(a new definer function must SET search_path = pg_catalog, public, pg_temp):\n  %s",
			strings.Join(unsafe, "\n  "))
	}
	if err := execScriptErr(ctx, pool, definerShadowAttackSQL); err != nil {
		t.Fatalf("after 0074 the shadow attack must neither run the canary nor fail: %v", err)
	}
	// pg_temp last only helps while the schemas before it are trusted: nobody but the owner may create in public.
	var appCreate, publicCreate bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege('rmt_app', 'public', 'CREATE'),
		has_schema_privilege('public', 'public', 'CREATE')`).Scan(&appCreate, &publicCreate); err != nil {
		t.Fatal(err)
	}
	if appCreate || publicCreate {
		t.Fatalf("schema public is writable (rmt_app CREATE=%v, PUBLIC CREATE=%v): a definer path through public is not trusted", appCreate, publicCreate)
	}

	// 0074 moved pg_catalog ahead of public in functions that had `public, pg_catalog`. That changes no
	// resolution only while nothing in public shares a name with something in pg_catalog. One known
	// exception: pgcrypto (0001) installs gen_random_uuid() in public, and PostgreSQL 13+ has the same
	// built-in with the same signature and the same result (a random v4 UUID), so either is correct.
	clashes := queryStrings(t, pool, `
		SELECT 'relation/type ' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND EXISTS (SELECT 1 FROM pg_class k WHERE k.relnamespace = 'pg_catalog'::regnamespace AND k.relname = c.relname)
		UNION ALL
		SELECT 'type ' || ty.typname FROM pg_type ty WHERE ty.typnamespace = 'public'::regnamespace
		  AND EXISTS (SELECT 1 FROM pg_type k WHERE k.typnamespace = 'pg_catalog'::regnamespace AND k.typname = ty.typname)
		UNION ALL
		SELECT 'function ' || p.proname FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace
		  AND NOT (p.proname = 'gen_random_uuid' AND p.pronargs = 0)
		  AND EXISTS (SELECT 1 FROM pg_proc k WHERE k.pronamespace = 'pg_catalog'::regnamespace AND k.proname = p.proname)
		UNION ALL
		SELECT 'operator ' || o.oprname FROM pg_operator o WHERE o.oprnamespace = 'public'::regnamespace
		ORDER BY 1`)
	if len(clashes) != 0 {
		t.Fatalf("public objects share a name with pg_catalog ones, so 0074's pg_catalog-first path may "+
			"resolve differently:\n  %s", strings.Join(clashes, "\n  "))
	}

	// ALTER FUNCTION ... SET touches only the setting: EXECUTE grants survive (the PUBLIC grant on the
	// bootstrap resolver, and rmt_app's on a revoked-from-PUBLIC helper).
	var publicExec, appExec bool
	if err := pool.QueryRow(ctx, `SELECT has_function_privilege('public', 'public.cp_resolve_tenant_by_slug(text)', 'EXECUTE'),
		has_function_privilege('rmt_app', 'public.cp_recording_sweep_list()', 'EXECUTE')`).Scan(&publicExec, &appExec); err != nil {
		t.Fatal(err)
	}
	if !publicExec || !appExec {
		t.Fatalf("grants changed: PUBLIC on cp_resolve_tenant_by_slug=%v, rmt_app on cp_recording_sweep_list=%v", publicExec, appExec)
	}
}
