package controlplane

// LIVE-POSTGRES: migration 0076 and docs/67. Every application SECURITY DEFINER routine is owned by
// `rmt_definer`: BYPASSRLS (it exists to bypass RLS for pre-tenant lookups) and nothing else a superuser
// has, with exactly the table privileges those routines use. A defect in a definer routine must give
// "read/write these tables across tenants", never COPY ... TO PROGRAM or a new role.
//
// TestPgDefinerOwnerRole migrates a FRESH DATABASE with the real runner, like
// TestPgEveryDefinerFunctionPutsPgTempLast. TestPgFixtureRunsDefinersAsRmtDefiner closes the fixture trap:
// the per-test fixture applies migrations piecemeal as a superuser, so it must hand the functions to
// rmt_definer itself, and a store call must FAIL when a grant is missing.
//
// SERIALISATION ASSUMPTION. rmt_definer is a CLUSTER-wide role, and the adoption cases below briefly give it
// LOGIN/CREATEDB/CREATEROLE, a membership, or a database grant. That is safe only because every test run is
// serialised on the developer's machine and CI runs one job against its own cluster. Each such
// mutation registers its undo and a re-pin with t.Cleanup BEFORE it mutates, and every run that uses the role
// (the fixture hook, freshMigrationDatabase) first re-pins it (fixtureDefinerRepinSQL), so an interrupted run
// cannot leave the role elevated for the next one.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const definerOwnerMigration = "0076_definer_owner.sql"

// expectedDefinerPrivileges is EXACTLY what rmt_definer may do, written independently of the migration's
// GRANT lines. A new privilege is a deliberate change to this list AND to a migration, never a side effect.
var expectedDefinerPrivileges = []string{
	"COLUMN machine.last_seen UPDATE", // 0079: cp_presence_stamp writes this one column
	"agent_directive SELECT",
	"api_token SELECT",
	"app_user SELECT",
	"attended_session SELECT", "attended_session UPDATE",
	"download_daily SELECT", // 0078: cp_platform_downloads reads it
	"enrollment_token SELECT", "enrollment_token UPDATE",
	"help_request SELECT",
	"help_request_call SELECT",
	"help_request_op SELECT",
	"machine INSERT", "machine SELECT",
	"platform_config SELECT",
	"platform_operator SELECT",
	"session_record SELECT", "session_record UPDATE",
	"session_recording SELECT",
	"session_recording_segment SELECT",
	"session_ticket_redemption DELETE", "session_ticket_redemption INSERT", "session_ticket_redemption SELECT",
	"tenant INSERT", "tenant SELECT", "tenant UPDATE",
	"tenant_branding_pointer INSERT", "tenant_branding_pointer SELECT", "tenant_branding_pointer UPDATE",
	"tenant_branding_revision SELECT",
	"tenant_hostname_assignment INSERT", "tenant_hostname_assignment SELECT", "tenant_hostname_assignment UPDATE",
	"tenant_recording_policy SELECT",
	"tenant_session_policy SELECT",
	"user_credential_token SELECT", "user_credential_token UPDATE",
	"user_session SELECT", "user_session UPDATE",
	"user_totp SELECT",
}

// applicationDefinersNotOwnedSQL lists application definer routines whose owner is not rmt_definer.
const applicationDefinersNotOwnedSQL = `
SELECT p.oid::regprocedure::text || ' owner=' || p.proowner::regrole::text
FROM pg_catalog.pg_proc p
WHERE p.prosecdef AND p.pronamespace = 'public'::regnamespace
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
  AND p.proowner <> 'rmt_definer'::regrole
ORDER BY 1`

// executeAclSQL is every public routine's EXECUTE grants with the owner's own entry named OWNER, which is
// what ALTER OWNER rewrites. Everything else about the ACL must survive a change of owner.
const executeAclSQL = `
SELECT p.oid::regprocedure::text || ' ' || COALESCE((
    SELECT string_agg(e.entry, ',' ORDER BY e.entry) FROM (
        SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' WHEN a.grantee = p.proowner THEN 'OWNER' ELSE a.grantee::regrole::text END
               || ':' || a.privilege_type || ':' || a.is_grantable::text AS entry
        FROM aclexplode(p.proacl) a) e), 'default-acl')
FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace ORDER BY 1`

// effectiveExecuteSQL is who can really call every definer routine: PUBLIC, rmt_app, and the owner.
const effectiveExecuteSQL = `
SELECT p.oid::regprocedure::text || ' public=' || has_function_privilege('public', p.oid, 'EXECUTE')::text ||
       ' rmt_app=' || has_function_privilege('rmt_app', p.oid, 'EXECUTE')::text ||
       ' owner=' || has_function_privilege(p.proowner, p.oid, 'EXECUTE')::text
FROM pg_proc p WHERE p.prosecdef AND p.pronamespace = 'public'::regnamespace ORDER BY 1`

// withoutLaterRedefined drops the routines a migration AFTER 0076 (re)defines from a body listing. The full-directory
// Migrate in this test applies those too, and a later migration legitimately changing a function body (0077 redefines
// session_recording_guard) is not 0076 changing more than the owner.
func withoutLaterRedefined(t *testing.T, lines []string) []string {
	t.Helper()
	ents, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	def := regexp.MustCompile(`(?i)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:public\.)?([a-z_0-9]+)\s*\(`)
	later := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() <= definerOwnerMigration {
			continue
		}
		b, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range def.FindAllStringSubmatch(string(b), -1) {
			later[m[1]] = true
		}
	}
	var out []string
	for _, l := range lines {
		if name, _, ok := strings.Cut(l, "("); ok && later[strings.TrimPrefix(name, "public.")] {
			continue
		}
		out = append(out, l)
	}
	return out
}

// definerBodiesSQL is what 0076 must not change besides the owner: bodies, settings, security attribute.
const definerBodiesSQL = `
SELECT p.oid::regprocedure::text || ' md5=' || md5(p.prosrc) || ' secdef=' || p.prosecdef::text || ' cfg=' ||
       COALESCE(array_to_string(p.proconfig, ';'), '-')
FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace ORDER BY 1`

func definerPrivilegesSQL(role string) string {
	// table-level, column-level, schema, sequence, function (other than the ones it owns) and database grants
	return `
SELECT c.relname || ' ' || a.privilege_type FROM pg_class c, aclexplode(c.relacl) a
  WHERE a.grantee = '` + role + `'::regrole AND c.relkind IN ('r','p','v','m','f','S') AND c.relnamespace = 'public'::regnamespace
UNION ALL
SELECT 'COLUMN ' || c.relname || '.' || t.attname || ' ' || a.privilege_type FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid,
  aclexplode(t.attacl) a WHERE a.grantee = '` + role + `'::regrole
UNION ALL
SELECT 'SCHEMA ' || n.nspname || ' ' || a.privilege_type FROM pg_namespace n, aclexplode(n.nspacl) a WHERE a.grantee = '` + role + `'::regrole
UNION ALL
SELECT 'FUNCTION ' || p.oid::regprocedure::text || ' ' || a.privilege_type FROM pg_proc p, aclexplode(p.proacl) a
  WHERE a.grantee = '` + role + `'::regrole AND p.proowner <> '` + role + `'::regrole
UNION ALL
SELECT 'DATABASE ' || d.datname || ' ' || a.privilege_type FROM pg_database d, aclexplode(d.datacl) a WHERE a.grantee = '` + role + `'::regrole

ORDER BY 1`
}

// A definer function planted AFTER the migration, owned by rmt_definer: whatever its body tries, it has no
// superuser power. Its twin owned by the superuser is the premise (the same body really can create a role).
const definerPlantedSQL = `
CREATE FUNCTION public.zz_planted_role() RETURNS int LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN EXECUTE 'CREATE ROLE zz_planted_role_x NOLOGIN'; RETURN 1; END $$;
CREATE FUNCTION public.zz_planted_program() RETURNS int LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN EXECUTE 'COPY (SELECT 1) TO PROGRAM ''exit 0'''; RETURN 1; END $$;`

func TestPgDefinerOwnerRole(t *testing.T) {
	pool := freshMigrationDatabase(t)
	ctx := context.Background()

	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	before := t.TempDir() // everything before 0076
	found := false
	for _, e := range entries {
		if e.Name() == definerOwnerMigration {
			found = true
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() >= definerOwnerMigration {
			continue
		}
		body, err := os.ReadFile(filepath.Join("migrations", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(before, e.Name()), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatalf("migrations/%s is missing", definerOwnerMigration)
	}
	migration, err := os.ReadFile(filepath.Join("migrations", definerOwnerMigration))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, pool, before, MigrateOptions{}); err != nil {
		t.Fatalf("migrate up to 0075: %v", err)
	}

	// PREMISE: before 0076 the routines are owned by the migration role, a superuser, and the planted
	// function really can create a role (so the later refusal means something).
	if notOwned := queryStrings(t, pool, applicationDefinersNotOwnedSQL); len(notOwned) < 30 {
		t.Fatalf("premise: only %d application definer routines before 0076", len(notOwned))
	}
	execScript(t, pool, definerPlantedSQL)
	if _, err := pool.Exec(ctx, `SELECT public.zz_planted_role()`); err != nil {
		t.Fatalf("premise: a definer routine owned by the superuser must be able to create a role: %v", err)
	}
	execScript(t, pool, `DROP ROLE zz_planted_role_x; DROP FUNCTION public.zz_planted_role(); DROP FUNCTION public.zz_planted_program();`)

	// The migration role must be a superuser: as anyone else it stops, with the reason, before changing anything.
	execScript(t, pool, `DROP ROLE IF EXISTS zz_child; DROP ROLE IF EXISTS zz_notsuper; CREATE ROLE zz_notsuper NOLOGIN CREATEROLE;`) // a failed earlier run may have left zz_child, a member of rmt_definer
	err = execScriptErr(ctx, pool, "BEGIN; SET LOCAL ROLE zz_notsuper;\n"+string(migration)+"\nCOMMIT;")
	if err == nil || !strings.Contains(err.Error(), "not a superuser") {
		t.Fatalf("0076 as a non-superuser must refuse with a clear message, got %v", err)
	}
	execScript(t, pool, `DROP ROLE zz_notsuper`)

	// A definer routine OUTSIDE the application's routines is refused, not moved.
	execScript(t, pool, `CREATE SCHEMA zz_other;
		CREATE FUNCTION zz_other.f() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = zz_other AS 'SELECT 1';`)
	if _, err := Migrate(ctx, pool, "migrations", MigrateOptions{}); err == nil ||
		!strings.Contains(err.Error(), "zz_other.f()") || !strings.Contains(err.Error(), "deliberate decision") {
		t.Fatalf("a definer routine in another schema must stop 0076, got %v", err)
	}
	if notOwned := queryStrings(t, pool, applicationDefinersNotOwnedSQL); len(notOwned) < 30 {
		t.Fatalf("the refused 0076 left %d routines not owned by rmt_definer: a partial apply", len(notOwned))
	}
	execScript(t, pool, `DROP SCHEMA zz_other CASCADE`)

	// A pre-existing rmt_definer is adopted only if it is CLEAN: 0076 refuses (and changes nothing) otherwise, it
	// does not trim. The role is cluster-wide, so it may already exist; make sure it does. Every refusal case
	// registers its undo (and a re-pin of the role) with t.Cleanup BEFORE it mutates the cluster-wide role, so a
	// failure cannot leave rmt_definer elevated (see the file header).
	execScript(t, pool, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_definer') THEN
		CREATE ROLE rmt_definer NOLOGIN; END IF; END $$;`)
	dbName := pool.Config().ConnConfig.Database
	adoptionClean := ""
	refuses := func(name, setup, undo, want string) {
		t.Helper()
		t.Cleanup(func() {
			_ = execScriptRaw(context.Background(), pool, undo)
			_ = execScriptRaw(context.Background(), pool, fixtureDefinerRepinSQL)
		})
		if err := execScriptRaw(ctx, pool, setup); err != nil {
			t.Fatalf("%s: setup: %v", name, err)
		}
		stateBefore := definerAdoptionState(t, pool)
		_, err := Migrate(ctx, pool, "migrations", MigrateOptions{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: a pre-existing rmt_definer in that state must stop 0076 with %q, got %v", name, want, err)
		}
		if after := definerAdoptionState(t, pool); after != stateBefore {
			t.Fatalf("%s: the refused 0076 changed something (it must roll back whole):\nbefore:\n%s\nafter:\n%s", name, stateBefore, after)
		}
		if err := execScriptRaw(ctx, pool, undo); err != nil {
			t.Fatalf("%s: undo: %v", name, err)
		}
		if err := execScriptRaw(ctx, pool, fixtureDefinerRepinSQL); err != nil {
			t.Fatalf("%s: re-pin: %v", name, err)
		}
		if clean := definerAdoptionState(t, pool); clean != adoptionClean {
			t.Fatalf("%s: undo left the role dirty:\n%s", name, clean)
		}
	}
	execScript(t, pool, fixtureDefinerRepinSQL)
	adoptionClean = definerAdoptionState(t, pool)

	refuses("member", `DROP ROLE IF EXISTS zz_child; CREATE ROLE zz_child NOLOGIN; GRANT rmt_definer TO zz_child;`,
		`DROP ROLE IF EXISTS zz_child;`, "zz_child is a member of rmt_definer")
	refuses("member of", `DROP ROLE IF EXISTS zz_parent; CREATE ROLE zz_parent NOLOGIN; GRANT zz_parent TO rmt_definer;`,
		`DROP ROLE IF EXISTS zz_parent;`, "rmt_definer is a member of zz_parent")
	refuses("owned schema", `CREATE SCHEMA zz_owned_schema AUTHORIZATION rmt_definer;`,
		`DROP SCHEMA IF EXISTS zz_owned_schema CASCADE;`, "owns objects other than routines (schema zz_owned_schema)")
	refuses("owned table", `CREATE TABLE zz_owned_table (id int); ALTER TABLE zz_owned_table OWNER TO rmt_definer;`,
		`DROP TABLE IF EXISTS zz_owned_table;`, "zz_owned_table")
	// A direct CREATE on a schema survives REVOKE ... FROM PUBLIC, so it must be found. The elevated attributes
	// ride along: a refused run must not even have pinned them.
	refuses("direct CREATE on schema public", `ALTER ROLE rmt_definer LOGIN CREATEDB CREATEROLE; GRANT CREATE ON SCHEMA public TO rmt_definer;`,
		`REVOKE CREATE ON SCHEMA public FROM rmt_definer;`, "schema public CREATE")
	refuses("direct CREATE on the database", `GRANT CREATE ON DATABASE `+pgx.Identifier{dbName}.Sanitize()+` TO rmt_definer;`,
		`REVOKE CREATE ON DATABASE `+pgx.Identifier{dbName}.Sanitize()+` FROM rmt_definer;`, "database "+dbName+" CREATE")
	refuses("EXECUTE on an unexpected function", `GRANT EXECUTE ON FUNCTION public.cp_resolve_tenant_by_slug(text) TO rmt_definer;`,
		`REVOKE EXECUTE ON FUNCTION public.cp_resolve_tenant_by_slug(text) FROM rmt_definer;`, "routine cp_resolve_tenant_by_slug(text) EXECUTE")
	refuses("extra table privilege", `GRANT DELETE ON app_user TO rmt_definer;`,
		`REVOKE DELETE ON app_user FROM rmt_definer;`, "app_user DELETE false")
	refuses("grant option on an expected privilege", `GRANT SELECT ON app_user TO rmt_definer WITH GRANT OPTION;`,
		`REVOKE ALL ON app_user FROM rmt_definer;`, "app_user SELECT true")
	// REVOKE ALL in 0076 runs as the table owner, so a privilege another role granted survives it and would sit in
	// both snapshots; only the grantor check finds it.
	refuses("table privilege granted by a non-owner", `DROP ROLE IF EXISTS zz_grantor; CREATE ROLE zz_grantor NOLOGIN;
		GRANT SELECT, DELETE ON tenant TO zz_grantor WITH GRANT OPTION;
		SET ROLE zz_grantor; GRANT DELETE ON tenant TO rmt_definer; RESET ROLE;`,
		`REVOKE ALL ON tenant FROM zz_grantor CASCADE; DROP ROLE IF EXISTS zz_grantor;`, "tenant DELETE granted by zz_grantor")
	// PUBLIC reaches every role: no check on rmt_definer's own entries sees these, only the effective ones do.
	refuses("table privilege through PUBLIC", `GRANT DELETE ON app_user TO PUBLIC;`,
		`REVOKE DELETE ON app_user FROM PUBLIC;`, "app_user DELETE")
	refuses("sequence privilege through PUBLIC", `CREATE SEQUENCE zz_pub_seq; GRANT USAGE ON SEQUENCE zz_pub_seq TO PUBLIC;`,
		`DROP SEQUENCE IF EXISTS zz_pub_seq;`, "zz_pub_seq USAGE")
	// PUBLIC hygiene: anything PUBLIC holds beyond PostgreSQL's defaults reaches every role, so 0076 refuses it
	// wherever it sits (Codex r3: a column grant, a view outside public, a parameter).
	refuses("column privilege through PUBLIC", `GRANT UPDATE (email) ON app_user TO PUBLIC;`,
		`REVOKE UPDATE (email) ON app_user FROM PUBLIC;`, "column public.app_user.email UPDATE")
	refuses("view outside public readable by PUBLIC", `CREATE SCHEMA zz_pub_s; CREATE VIEW zz_pub_s.zz_v AS SELECT 1 AS x;
		GRANT USAGE ON SCHEMA zz_pub_s TO PUBLIC; GRANT SELECT ON zz_pub_s.zz_v TO PUBLIC;`,
		`DROP SCHEMA IF EXISTS zz_pub_s CASCADE;`, "relation zz_pub_s.zz_v SELECT")
	// Database privileges are cluster-wide: PUBLIC CREATE on ANOTHER database counts too.
	refuses("another database open to PUBLIC", `GRANT CREATE ON DATABASE postgres TO PUBLIC;`,
		`REVOKE CREATE ON DATABASE postgres FROM PUBLIC;`, "database postgres CREATE")
	refuses("column privilege", `GRANT UPDATE (email) ON app_user TO rmt_definer;`,
		`REVOKE ALL (email) ON app_user FROM rmt_definer;`, "column app_user.email UPDATE")
	refuses("sequence privilege", `CREATE SEQUENCE zz_seq; GRANT USAGE ON SEQUENCE zz_seq TO rmt_definer;`,
		`DROP SEQUENCE IF EXISTS zz_seq;`, "relation public.zz_seq USAGE")
	refuses("view privilege", `CREATE VIEW zz_view AS SELECT 1 AS x; GRANT SELECT ON zz_view TO rmt_definer;`,
		`DROP VIEW IF EXISTS zz_view;`, "relation public.zz_view SELECT")
	refuses("type privilege", `CREATE TYPE zz_type AS ENUM ('a'); GRANT USAGE ON TYPE zz_type TO rmt_definer;`,
		`DROP TYPE IF EXISTS zz_type;`, "type zz_type USAGE")
	refuses("default privileges", `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO rmt_definer;`,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM rmt_definer;`, "default privileges")
	refuses("language privilege", `GRANT USAGE ON LANGUAGE plpgsql TO rmt_definer;`,
		`REVOKE ALL ON LANGUAGE plpgsql FROM rmt_definer;`, "language plpgsql USAGE")
	refuses("foreign data wrapper privilege", `CREATE FOREIGN DATA WRAPPER zz_fdw; GRANT USAGE ON FOREIGN DATA WRAPPER zz_fdw TO rmt_definer;`,
		`DROP FOREIGN DATA WRAPPER IF EXISTS zz_fdw CASCADE;`, "foreign data wrapper zz_fdw USAGE")
	refuses("foreign server privilege", `CREATE FOREIGN DATA WRAPPER zz_fdw; CREATE SERVER zz_srv FOREIGN DATA WRAPPER zz_fdw; GRANT USAGE ON FOREIGN SERVER zz_srv TO rmt_definer;`,
		`DROP FOREIGN DATA WRAPPER IF EXISTS zz_fdw CASCADE;`, "foreign server zz_srv USAGE")
	refuses("large object privilege", `SELECT lo_create(424242); GRANT SELECT ON LARGE OBJECT 424242 TO rmt_definer;`,
		`DO $$ BEGIN PERFORM lo_unlink(424242); EXCEPTION WHEN undefined_object THEN NULL; END $$;`, "large object 424242 SELECT")
	var hasParamACL bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('pg_catalog.pg_parameter_acl') IS NOT NULL`).Scan(&hasParamACL); err != nil {
		t.Fatal(err)
	}
	if hasParamACL { // PostgreSQL 15+
		refuses("parameter privilege", `GRANT SET ON PARAMETER work_mem TO rmt_definer;`,
			`REVOKE ALL ON PARAMETER work_mem FROM rmt_definer;`, "parameter work_mem SET")
		refuses("parameter granted to PUBLIC", `GRANT SET ON PARAMETER session_replication_role TO PUBLIC;`,
			`REVOKE SET ON PARAMETER session_replication_role FROM PUBLIC;`, "parameter session_replication_role SET")
	}
	// EFFECTIVE privileges, with no ACL entry naming the role: a schema or the database open to PUBLIC. The PUBLIC
	// hygiene check now reports the schema grant first (same refusal, same rollback).
	refuses("a schema open to PUBLIC", `CREATE SCHEMA zz_open; GRANT CREATE ON SCHEMA zz_open TO PUBLIC;`,
		`DROP SCHEMA IF EXISTS zz_open CASCADE;`, "schema zz_open CREATE")
	refuses("the database open to PUBLIC", `GRANT CREATE ON DATABASE `+pgx.Identifier{dbName}.Sanitize()+` TO PUBLIC;`,
		`REVOKE CREATE ON DATABASE `+pgx.Identifier{dbName}.Sanitize()+` FROM PUBLIC;`, "database "+dbName+" CREATE")

	// A CLEAN pre-existing role is adopted: its attributes are pinned, USAGE on public and the expected table
	// grants are fine, and PostgreSQL 14's CREATE for PUBLIC on public is revoked.
	t.Cleanup(func() { _ = execScriptRaw(context.Background(), pool, fixtureDefinerRepinSQL) })
	execScript(t, pool, `ALTER ROLE rmt_definer LOGIN CREATEDB CREATEROLE;
		GRANT USAGE ON SCHEMA public TO rmt_definer;
		GRANT SELECT ON app_user TO rmt_definer;
		GRANT CREATE ON SCHEMA public TO PUBLIC;`)

	aclBefore := queryStrings(t, pool, executeAclSQL)
	effBefore := queryStrings(t, pool, effectiveExecuteSQL)
	bodiesBefore := queryStrings(t, pool, definerBodiesSQL)

	rep, err := Migrate(ctx, pool, "migrations", MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate the full directory: %v", err)
	}
	if len(rep.Applied) == 0 || rep.Applied[0] != definerOwnerMigration {
		t.Fatalf("applied %v, want %s first", rep.Applied, definerOwnerMigration)
	}

	// (1) THE GUARD: every application definer routine, including any a later migration adds, is owned by rmt_definer.
	if notOwned := queryStrings(t, pool, applicationDefinersNotOwnedSQL); len(notOwned) != 0 {
		t.Fatalf("SECURITY DEFINER routines not owned by rmt_definer after a full migrate (a new definer function "+
			"must end with ALTER ROUTINE ... OWNER TO rmt_definer, see 0076):\n  %s", strings.Join(notOwned, "\n  "))
	}

	// (2) The role: weak in every attribute but the deliberate BYPASSRLS, and it owns no table.
	var super, bypass, login, createdb, createrole, repl bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole, rolreplication
		FROM pg_roles WHERE rolname = 'rmt_definer'`).Scan(&super, &bypass, &login, &createdb, &createrole, &repl); err != nil {
		t.Fatalf("rmt_definer: %v", err)
	}
	if super || !bypass || login || createdb || createrole || repl {
		t.Fatalf("rmt_definer attributes: super=%v bypassrls=%v login=%v createdb=%v createrole=%v replication=%v; "+
			"want only BYPASSRLS", super, bypass, login, createdb, createrole, repl)
	}
	if owned := queryStrings(t, pool, `
		SELECT 'relation ' || relname FROM pg_class WHERE relowner = 'rmt_definer'::regrole
		UNION ALL SELECT 'schema ' || nspname FROM pg_namespace WHERE nspowner = 'rmt_definer'::regrole
		UNION ALL SELECT 'database ' || datname FROM pg_database WHERE datdba = 'rmt_definer'::regrole
		UNION ALL SELECT 'member of ' || roleid::regrole::text FROM pg_auth_members WHERE member = 'rmt_definer'::regrole
		UNION ALL SELECT 'member ' || member::regrole::text FROM pg_auth_members WHERE roleid = 'rmt_definer'::regrole
		ORDER BY 1`); len(owned) != 0 {
		t.Fatalf("rmt_definer owns or belongs to more than its routines:\n  %s", strings.Join(owned, "\n  "))
	}

	// (3) Its privileges equal the expected set exactly: no schema, sequence, function or database grants but USAGE on
	// public, and no column grant but 0079's machine.last_seen.
	got := queryStrings(t, pool, definerPrivilegesSQL("rmt_definer"))
	want := append([]string{"SCHEMA public USAGE"}, expectedDefinerPrivileges...)
	if g, w := normalizeSet(got), normalizeSet(want); g != w {
		t.Fatalf("rmt_definer privileges differ from the expected set (a new GRANT is a deliberate change here AND in a migration):\n got:\n  %s\nwant:\n  %s",
			strings.ReplaceAll(g, "\n", "\n  "), strings.ReplaceAll(w, "\n", "\n  "))
	}
	// Defence in depth for the set above: it must not reach the things that make a superuser a superuser.
	var canCreate, dbCreate bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege('rmt_definer', 'public', 'CREATE'),
		has_database_privilege('rmt_definer', current_database(), 'CREATE')`).Scan(&canCreate, &dbCreate); err != nil {
		t.Fatal(err)
	}
	var publicCreate bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege('public', 'public', 'CREATE')`).Scan(&publicCreate); err != nil {
		t.Fatal(err)
	}
	if publicCreate {
		t.Fatal("PUBLIC can still CREATE in schema public (PostgreSQL 14 default): 0076 must revoke it")
	}
	if canCreate || dbCreate {
		t.Fatalf("rmt_definer can CREATE in schema public (%v) or the database (%v)", canCreate, dbCreate)
	}

	// (4) EXECUTE ACLs and bodies are exactly what they were: ALTER OWNER rewrote only the owner's own entries.
	// (A routine a LATER migration defines, like 0078's cp_platform_downloads, is absent from the "before" lists
	// by construction and is checked by its own test; withoutLaterRedefined drops it from both sides.)
	if after := withoutLaterRedefined(t, queryStrings(t, pool, executeAclSQL)); strings.Join(after, "\n") != strings.Join(withoutLaterRedefined(t, aclBefore), "\n") {
		t.Fatalf("0076 changed function ACLs beyond the owner's own entry:\nbefore:\n  %s\nafter:\n  %s",
			strings.Join(aclBefore, "\n  "), strings.Join(after, "\n  "))
	}
	if after := withoutLaterRedefined(t, queryStrings(t, pool, effectiveExecuteSQL)); strings.Join(after, "\n") != strings.Join(withoutLaterRedefined(t, effBefore), "\n") {
		t.Fatalf("0076 changed who can EXECUTE a definer routine:\nbefore:\n  %s\nafter:\n  %s",
			strings.Join(effBefore, "\n  "), strings.Join(after, "\n  "))
	}
	if after := withoutLaterRedefined(t, queryStrings(t, pool, definerBodiesSQL)); strings.Join(after, "\n") != strings.Join(withoutLaterRedefined(t, bodiesBefore), "\n") {
		t.Fatalf("0076 changed more than the owner:\nbefore:\n  %s\nafter:\n  %s",
			strings.Join(bodiesBefore, "\n  "), strings.Join(after, "\n  "))
	}
	var publicExec, appExec bool
	if err := pool.QueryRow(ctx, `SELECT has_function_privilege('public', 'public.cp_resolve_tenant_by_slug(text)', 'EXECUTE'),
		has_function_privilege('rmt_app', 'public.cp_recording_sweep_list()', 'EXECUTE')`).Scan(&publicExec, &appExec); err != nil {
		t.Fatal(err)
	}
	if !publicExec || !appExec {
		t.Fatalf("grants changed: PUBLIC on cp_resolve_tenant_by_slug=%v, rmt_app on cp_recording_sweep_list=%v", publicExec, appExec)
	}

	// (5) The temp-view shadow attack (0074) stays inert, and schema public stays closed.
	if err := execScriptErr(ctx, pool, definerShadowAttackSQL); err != nil {
		t.Fatalf("after 0076 the shadow attack must neither run the canary nor fail: %v", err)
	}

	// (6) A definer function owned by rmt_definer cannot do a superuser-only thing, whatever its body says.
	execScript(t, pool, definerPlantedSQL+`
		ALTER FUNCTION public.zz_planted_role() OWNER TO rmt_definer;
		ALTER FUNCTION public.zz_planted_program() OWNER TO rmt_definer;`)
	for fn, denied := range map[string]string{
		"zz_planted_role":    "permission denied to create role",
		"zz_planted_program": "external program",
	} {
		_, err := pool.Exec(ctx, "SELECT public."+fn+"()")
		if err == nil || !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), denied) {
			t.Fatalf("%s owned by rmt_definer must be refused (%q), got %v", fn, denied, err)
		}
	}
	execScript(t, pool, `DROP FUNCTION public.zz_planted_role(); DROP FUNCTION public.zz_planted_program();`)

	// (7) Re-running the migration is a no-op: same owners, same grants.
	// 0076 refuses a pre-existing rmt_definer that holds more than ITS grants, and later migrations added some
	// (0078 download_daily SELECT, 0079 UPDATE on machine.last_seen): take them away for the re-run and give them
	// back after, as the real order would have it.
	execScript(t, pool, `REVOKE SELECT ON TABLE download_daily FROM rmt_definer; REVOKE UPDATE (last_seen) ON TABLE machine FROM rmt_definer`)
	execScript(t, pool, string(migration))
	execScript(t, pool, `GRANT SELECT ON TABLE download_daily TO rmt_definer; GRANT UPDATE (last_seen) ON TABLE machine TO rmt_definer`)
	if notOwned := queryStrings(t, pool, applicationDefinersNotOwnedSQL); len(notOwned) != 0 {
		t.Fatalf("after re-running 0076: %v", notOwned)
	}
	if again := queryStrings(t, pool, definerPrivilegesSQL("rmt_definer")); normalizeSet(again) != normalizeSet(got) {
		t.Fatalf("re-running 0076 changed rmt_definer's privileges:\n%v\n%v", got, again)
	}
}

func normalizeSet(in []string) string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// THE FIXTURE TRAP. The per-test fixture applies migrations piecemeal as a superuser; without the ownership
// step the definer functions would run as that superuser and a missing GRANT would only show in production.
// This test fails if the fixture leaves a definer function superuser-owned, and proves that a store call
// FAILS with "permission denied" when a grant rmt_definer needs is gone.
func TestPgFixtureRunsDefinersAsRmtDefiner(t *testing.T) {
	su := newTestPool(t) // resetSchema: 0001-0003 and the always-on migrations
	ctx := context.Background()
	applyAppRoleMigration(t, su)
	applyAttendedMigration(t, su)
	applyAPITokenMigration(t, su)

	if notOwned := queryStrings(t, su, applicationDefinersNotOwnedSQL); len(notOwned) != 0 {
		t.Fatalf("the fixture left definer functions owned by the test superuser, so store tests would not "+
			"notice a missing GRANT (definer_owner_fixture_test.go):\n  %s", strings.Join(notOwned, "\n  "))
	}

	resolver := NewPgTenantResolver(su)
	if _, err := resolver.ResolveTenant(ctx, "no-such-tenant"); err != ErrNoTenant {
		t.Fatalf("with every grant in place the lookup works, got %v", err)
	}
	for _, tc := range []struct{ revoke, table, call string }{
		{"SELECT", "tenant", `SELECT cp_resolve_tenant_by_slug('no-such-tenant')`},
		{"UPDATE", "user_session", `SELECT cp_session_touch_last_seen('\x00'::bytea, now())`},
		{"SELECT", "api_token", `SELECT count(*) FROM cp_api_token_resolve('\x00'::bytea)`},
	} {
		execScript(t, su, "REVOKE "+tc.revoke+" ON "+tc.table+" FROM rmt_definer")
		_, err := su.Exec(ctx, tc.call)
		execScript(t, su, "GRANT "+tc.revoke+" ON "+tc.table+" TO rmt_definer")
		if err == nil || !strings.Contains(err.Error(), "permission denied for table "+tc.table) {
			t.Fatalf("without %s on %s the definer call must fail with permission denied (the trap is back): %v",
				tc.revoke, tc.table, err)
		}
		if _, err := su.Exec(ctx, tc.call); err != nil {
			t.Fatalf("after the grant is restored %q must work: %v", tc.call, err)
		}
	}
	// And the store itself reports it, not a quiet ErrNoTenant.
	execScript(t, su, "REVOKE SELECT ON tenant FROM rmt_definer")
	_, err := resolver.ResolveTenant(ctx, "no-such-tenant")
	execScript(t, su, "GRANT SELECT ON tenant TO rmt_definer")
	if err == nil || err == ErrNoTenant || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the tenant resolver must surface the missing grant, got %v", err)
	}
}

// definerAdoptionState is everything a refused 0076 must leave exactly as it found it: the role's attributes,
// its privileges, what is not yet owned by it, and PUBLIC's CREATE on public.
func definerAdoptionState(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	parts := queryStrings(t, pool, definerPrivilegesSQL("rmt_definer"))
	parts = append(parts, queryStrings(t, pool, `SELECT 'attrs login=' || rolcanlogin::text || ' createdb=' || rolcreatedb::text ||
		' createrole=' || rolcreaterole::text || ' super=' || rolsuper::text || ' repl=' || rolreplication::text ||
		' bypass=' || rolbypassrls::text FROM pg_roles WHERE rolname = 'rmt_definer'`)...)
	parts = append(parts, queryStrings(t, pool, `SELECT 'public create=' || has_schema_privilege('public', 'public', 'CREATE')::text`)...)
	parts = append(parts, queryStrings(t, pool, `SELECT 'owned routine ' || p.oid::regprocedure::text FROM pg_proc p WHERE p.proowner = 'rmt_definer'::regrole`)...)
	parts = append(parts, queryStrings(t, pool, `SELECT 'notowned ' || count(*) FROM pg_proc p WHERE p.prosecdef AND p.pronamespace = 'public'::regnamespace AND p.proowner <> 'rmt_definer'::regrole`)...)
	parts = append(parts, queryStrings(t, pool, `SELECT 'member of ' || roleid::regrole::text FROM pg_auth_members WHERE member = 'rmt_definer'::regrole
		UNION ALL SELECT 'member ' || member::regrole::text FROM pg_auth_members WHERE roleid = 'rmt_definer'::regrole ORDER BY 1`)...)
	return strings.Join(parts, "\n")
}

// A run interrupted while rmt_definer was elevated must not persist: the re-pin that every run starts with
// puts the attributes and memberships back.
func TestPgFixtureRepinsElevatedDefinerRole(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_ = execScriptRaw(context.Background(), pool, `DROP ROLE IF EXISTS zz_repin_child; DROP ROLE IF EXISTS zz_repin_parent;`)
		_ = execScriptRaw(context.Background(), pool, fixtureDefinerRepinSQL)
	})
	if err := execScriptRaw(ctx, pool, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_definer') THEN
		CREATE ROLE rmt_definer NOLOGIN; END IF; END $$;
		DROP ROLE IF EXISTS zz_repin_child; DROP ROLE IF EXISTS zz_repin_parent;
		CREATE ROLE zz_repin_child NOLOGIN; CREATE ROLE zz_repin_parent NOLOGIN;
		GRANT rmt_definer TO zz_repin_child; GRANT zz_repin_parent TO rmt_definer;
		ALTER ROLE rmt_definer LOGIN CREATEDB CREATEROLE;`); err != nil {
		t.Fatal(err)
	}
	if err := execScriptRaw(ctx, pool, fixtureDefinerRepinSQL); err != nil {
		t.Fatal(err)
	}
	var pinned bool
	if err := pool.QueryRow(ctx, `SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND
		NOT rolreplication AND rolbypassrls FROM pg_roles WHERE rolname = 'rmt_definer'`).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	members := queryStrings(t, pool, `SELECT roleid::regrole::text || '>' || member::regrole::text FROM pg_auth_members
		WHERE roleid = 'rmt_definer'::regrole OR member = 'rmt_definer'::regrole`)
	if !pinned || len(members) != 0 {
		t.Fatalf("the re-pin left rmt_definer elevated: pinned=%v memberships=%v", pinned, members)
	}
}
