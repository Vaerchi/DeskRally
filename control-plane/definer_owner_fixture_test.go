package controlplane

// THE FIXTURE TRAP (docs/67). The per-test fixture applies migrations piecemeal, as the superuser test
// role, so without this file every SECURITY DEFINER function a store test calls would be OWNED by that
// superuser and run with every privilege: a missing GRANT for rmt_definer (migration 0076) would show up
// only in production. After any fixture script that creates a table or a definer function,
// ownDefinersLikeProduction does what 0076 does, for what exists so far:
//   - creates rmt_definer with the same attributes,
//   - applies 0076's own GRANT lines (parsed from the migration file, so the suite runs the REAL grants)
//     to the tables that exist,
//   - hands every application definer routine in public to rmt_definer.
// Databases made for the real-runner tests (freshMigrationDatabase) are skipped: they migrate through
// `Migrate`, which applies 0076 itself, and must be seen exactly as it leaves them.

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// fixtureDDLTrigger: scripts after which the definer ownership and grants may be stale.
	fixtureDDLTrigger = regexp.MustCompile(`(?i)SECURITY\s+DEFINER|CREATE\s+TABLE`)
	// definerGrantLine is one of 0076's one-line GRANT statements, optionally column-scoped (0079's UPDATE (last_seen)).
	definerGrantLine = regexp.MustCompile(`(?m)^GRANT +([A-Z, ]+?(?: *\([a-z_, ]+\))?) +ON TABLE +(\w+) +TO rmt_definer;`)
)

const fixtureDefinerRoleSQL = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_definer') THEN
        BEGIN
            CREATE ROLE rmt_definer NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END;
    END IF;
END
$$;
DO $$
BEGIN
    -- only when it differs: ALTER ROLE edits a cluster-wide catalog row, which concurrent suites race on
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_definer' AND NOT
               (NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND rolbypassrls)) THEN
        ALTER ROLE rmt_definer WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO rmt_definer;`

const fixtureDefinerOwnSQL = `
DO $$
DECLARE
    fn record;
BEGIN
    FOR fn IN
        SELECT n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef AND n.nspname = 'public' AND p.proowner <> 'rmt_definer'::pg_catalog.regrole
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e')
    LOOP
        EXECUTE pg_catalog.format('ALTER ROUTINE %I.%I(%s) OWNER TO rmt_definer', fn.nspname, fn.proname, fn.args);
    END LOOP;
END
$$;`

// definerGrantStatements returns 0076's GRANT lines whose table is in tables (the tables that exist now).
func definerGrantStatements(migration string, tables map[string]bool) []string {
	var out []string
	for _, m := range definerGrantLine.FindAllStringSubmatch(migration, -1) {
		if tables[m[2]] {
			out = append(out, "GRANT "+m[1]+" ON TABLE "+m[2]+" TO rmt_definer;")
		}
	}
	return out
}

// ownDefinersLikeProduction is the fixture's stand-in for migration 0076 (see the file comment).
func ownDefinersLikeProduction(ctx context.Context, pool *pgxpool.Pool) error {
	if strings.HasPrefix(pool.Config().ConnConfig.Database, "rmt_definer_") {
		return nil
	}
	if err := execScriptRaw(ctx, pool, fixtureDefinerRepinSQL); err != nil {
		return err
	}
	// 0076's grants, then every later migration's one-line grants to rmt_definer (0078 gives it SELECT on download_daily,
	// 0079 UPDATE on machine.last_seen).
	var b []byte
	for _, f := range []string{"migrations/0076_definer_owner.sql", "migrations/0078_download_reach.sql",
		"migrations/0079_presence_sweep.sql"} {
		part, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		b = append(b, part...)
		b = append(b, 0x0a)
	}
	if err := execScriptRaw(ctx, pool, fixtureDefinerRoleSQL); err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT c.relname FROM pg_catalog.pg_class c
		WHERE c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p')`)
	if err != nil {
		return err
	}
	tables := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		tables[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	grants := strings.Join(definerGrantStatements(string(b), tables), "\n")
	if grants != "" {
		if err := execScriptRaw(ctx, pool, grants); err != nil {
			return err
		}
	}
	return execScriptRaw(ctx, pool, fixtureDefinerOwnSQL)
}

// fixtureDefinerRepinSQL puts rmt_definer back to what migration 0076 guarantees, when the role exists: pinned
// attributes and no membership in either direction. It runs at the start of every test run that uses the role,
// so an interrupted adoption test (which elevates the cluster-wide role on purpose) cannot persist. It writes
// only when something differs, because the role is a cluster-wide catalog row.
const fixtureDefinerRepinSQL = `
DO $$
DECLARE
    m record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_definer') THEN
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_definer' AND NOT
               (NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND rolbypassrls)) THEN
        ALTER ROLE rmt_definer WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
    END IF;
    FOR m IN SELECT p.rolname AS parent, c.rolname AS child
             FROM pg_catalog.pg_auth_members a
             JOIN pg_catalog.pg_roles p ON p.oid = a.roleid JOIN pg_catalog.pg_roles c ON c.oid = a.member
             WHERE a.roleid = 'rmt_definer'::pg_catalog.regrole OR a.member = 'rmt_definer'::pg_catalog.regrole
    LOOP
        EXECUTE pg_catalog.format('REVOKE %I FROM %I', m.parent, m.child);
    END LOOP;
END
$$;`
