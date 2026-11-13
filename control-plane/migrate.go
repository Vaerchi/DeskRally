package controlplane

// Schema migration runner.
//
// WHY THIS EXISTS. Until now migrations were applied two ways, neither of which survives an UPDATE:
// Postgres's `/docker-entrypoint-initdb.d`, which runs only on FIRST INIT of an empty volume, and a
// hand-run `for f in migrations/*.sql; do psql -f "$f"; done` loop in docs/10. Nothing recorded what
// had been applied, and nothing could: there was no tracking table. Re-running the set blindly is
// not an option either — 24 of the `CREATE TABLE` statements carry no `IF NOT EXISTS`, so a second
// pass fails on the first file.
//
// That is fine for a machine somebody sets up once by hand. It is the blocker for automated deploy:
// this project added 38 migrations in ~91 loops, so a pipeline without a runner works right up until
// the first schema change and then takes the control plane down.
//
// DESIGN NOTES, each of which is a decision rather than an accident:
//
//   - **Runs as the OWNER, never as `rmt_app`.** `rmt_app` is deliberately `NOSUPERUSER` with only
//     DML grants (migrations/0005), so it has no DDL rights at all. The runner therefore takes its
//     own admin DSN. Conflating the two would undo the least-privilege split that makes row-level
//     security mean anything — see docs/18 §4b.
//   - **One transaction per file.** No migration uses `CREATE INDEX CONCURRENTLY` (checked), so each
//     can be atomic: a failure leaves that file wholly unapplied rather than half-applied.
//   - **The recorded SHA-256 is checked on every run.** An edited already-applied migration is a HARD
//     failure. Silent schema drift between a developer's box and production is the failure mode this
//     is really guarding against, and it is invisible without a hash.
//   - **Numeric version ordering, not lexical.** Every file today is 4-digit zero-padded so the two
//     agree, but that is a property of the current names, not a guarantee — docs/10 already warns
//     that plain sort puts `0100` after `0009`. Parsing the prefix also makes duplicates detectable.
//   - **Baselining is EXPLICIT.** A database that predates this runner has the schema but no tracking
//     table, and auto-detecting that would mean assuming every on-disk migration was applied. That
//     assumption is right on a fully-migrated box and silently destructive on a half-migrated one, so
//     the runner refuses and asks for `--baseline` instead of guessing.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrationFile is one `NNNN_name.sql` on disk.
type MigrationFile struct {
	Name    string // base name, e.g. "0005_app_role.sql"
	Version int    // the numeric prefix
	SQL     string
	SHA256  string // hex, of the file's bytes
}

// MigrationReport is what a run did, for logging and for tests to assert on.
type MigrationReport struct {
	Applied   []string // names applied by this run, in order
	Skipped   []string // names already recorded as applied
	Baselined []string // names recorded WITHOUT running (baseline mode only)
}

// migrationNamePattern anchors the numeric prefix. Anything not matching is not a migration and is
// ignored rather than guessed at — a stray `notes.sql` in the directory must not become schema.
var migrationNamePattern = regexp.MustCompile(`^(\d+)_[A-Za-z0-9._-]+\.sql$`)

// LoadMigrations reads `dir`, returning the migrations in VERSION order.
//
// Errors on a duplicate version number: two files claiming `0039` would apply in an order decided by
// the filesystem, which is exactly the kind of thing that works on one machine and not another.
func LoadMigrations(dir string) ([]MigrationFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}
	var out []MigrationFile
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationNamePattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("migration %s: unparseable version %q: %w", e.Name(), m[1], err)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf(
				"duplicate migration version %d: %q and %q — apply order would depend on the "+
					"filesystem, so this is refused rather than guessed", v, prev, e.Name())
		}
		seen[v] = e.Name()

		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(b)
		out = append(out, MigrationFile{
			Name:    e.Name(),
			Version: v,
			SQL:     string(b),
			SHA256:  hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// createTrackingTableSQL creates the ledger. Separate from the numbered migrations on purpose: it is
// the runner's own bookkeeping, it must exist before any migration can be recorded, and it therefore
// cannot itself be one of the things being tracked.
//
// `rmt_app` is REVOKEd from it. Migration 0005 sets ALTER DEFAULT PRIVILEGES granting DML on future
// tables to `rmt_app`, so without this the application role would inherit write access to its own
// schema history — which it has no business touching. The DO block tolerates `rmt_app` not existing
// yet, because on a fresh database this table is created before 0005 runs.
const createTrackingTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migration (
    name        text        PRIMARY KEY,
    version     integer     NOT NULL,
    sha256      text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    baselined   boolean     NOT NULL DEFAULT false
);
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        REVOKE ALL ON schema_migration FROM rmt_app;
    END IF;
END
$$;`

// revokeLedgerFromAppRoleSQL re-asserts the REVOKE after the migrations have run.
//
// WHY IT HAS TO RUN TWICE. On a FRESH database the ledger is created before any migration, so
// `rmt_app` does not exist yet and the guard above is a no-op. Migration 0005 then does
// `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rmt_app` — and ALL TABLES
// means every table existing AT THAT MOMENT, which includes the ledger created moments earlier. So
// the application role ended up with full DML on its own schema history on every new deployment,
// which is exactly what the REVOKE above was written to prevent and exactly when it could not.
//
// (`ALTER DEFAULT PRIVILEGES`, also in 0005, is forward-looking only and is NOT the culprit here.)
//
// Idempotent, so it costs nothing to re-assert on every run.
const revokeLedgerFromAppRoleSQL = `
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        REVOKE ALL ON schema_migration FROM rmt_app;
    END IF;
END
$$;`

// appliedMigrations reads the ledger. The bool reports whether the table exists at all.
func appliedMigrations(ctx context.Context, pool *pgxpool.Pool) (map[string]string, bool, error) {
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'schema_migration')`,
	).Scan(&exists); err != nil {
		return nil, false, fmt.Errorf("probe for schema_migration: %w", err)
	}
	if !exists {
		return nil, false, nil
	}
	rows, err := pool.Query(ctx, `SELECT name, sha256 FROM schema_migration`)
	if err != nil {
		return nil, true, fmt.Errorf("read schema_migration: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var n, h string
		if err := rows.Scan(&n, &h); err != nil {
			return nil, true, err
		}
		out[n] = h
	}
	return out, true, rows.Err()
}

// schemaLooksMigrated reports whether this database already carries the application schema. Used
// only to distinguish "fresh database" from "database that predates the runner".
func schemaLooksMigrated(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'tenant')`,
	).Scan(&exists)
	return exists, err
}

// ErrNeedsBaseline is returned when the database has the schema but no ledger. See the package note.
var ErrNeedsBaseline = fmt.Errorf(
	"this database has the application schema but no schema_migration ledger, so it predates the " +
		"migration runner. Re-running every migration would fail (24 CREATE TABLEs carry no " +
		"IF NOT EXISTS), and assuming they are all applied could be wrong on a half-migrated " +
		"database. VERIFY the schema is current, then run with --baseline to record the on-disk " +
		"migrations as applied WITHOUT running them")

// ErrBaselineOnEmptyDatabase is returned when --baseline is used on a database that has no
// application schema. Baselining records migrations as applied WITHOUT running them, so on an empty
// database it produces a ledger that claims a schema which does not exist — a state no later run can
// detect, because every subsequent migrate sees a full ledger and skips everything.
var ErrBaselineOnEmptyDatabase = fmt.Errorf(
	"--baseline was used on a database with no application schema. Baselining ADOPTS an existing " +
		"database that predates the runner; it records migrations as applied without running " +
		"them. On an empty database that writes a ledger for a schema that was never created, and " +
		"no later run can tell. Run WITHOUT --baseline to actually apply the migrations")

// ErrBaselineWithLedger is returned when --baseline is used on a database that already has a
// schema_migration ledger — there is nothing left to adopt, and honouring the flag would record any
// newly shipped migration as applied without running it.
var ErrBaselineWithLedger = fmt.Errorf(
	"--baseline was used on a database that already has a schema_migration ledger. There is " +
		"nothing to adopt, and honouring it would record every newly shipped migration as applied " +
		"WITHOUT running it. Remove --baseline (check the overlay's `command:` — a flag added once " +
		"for an adoption tends to stay there)")

// MigrateOptions controls one run.
type MigrateOptions struct {
	// Baseline records every on-disk migration as applied without executing it. For adopting a
	// database that predates the runner. Never use it on a database that is genuinely behind.
	Baseline bool
}

// Migrate brings `pool`'s database up to the set of migrations in `dir`.
//
// `pool` MUST be connected as a role with DDL rights (the owner), not as `rmt_app`.
func Migrate(ctx context.Context, pool *pgxpool.Pool, dir string, opts MigrateOptions) (MigrationReport, error) {
	var rep MigrationReport

	files, err := LoadMigrations(dir)
	if err != nil {
		return rep, err
	}
	if len(files) == 0 {
		return rep, fmt.Errorf("no migrations found in %s", dir)
	}

	applied, ledgerExists, err := appliedMigrations(ctx, pool)
	if err != nil {
		return rep, err
	}
	if !ledgerExists {
		migrated, err := schemaLooksMigrated(ctx, pool)
		if err != nil {
			return rep, err
		}
		if migrated && !opts.Baseline {
			return rep, ErrNeedsBaseline
		}
		// --baseline on a database with NO schema records all 38 migrations as applied without
		// running one of them, and exits 0. The operator who hits ErrNeedsBaseline is told to
		// "run with --baseline"; if they instead decide to start clean (`docker compose down -v`)
		// and then run the command they already had queued, they get an EMPTY database whose ledger
		// claims to be fully migrated. `migrate` succeeds, `service_completed_successfully` passes,
		// the control plane starts against no tables, and every later run reports "skipped=38".
		//
		// Baselining means "adopt a database that predates the runner". A database with nothing to
		// adopt is never that, so refuse rather than record a lie that no later run can detect.
		if opts.Baseline && !migrated {
			return rep, ErrBaselineOnEmptyDatabase
		}
		if _, err := pool.Exec(ctx, createTrackingTableSQL); err != nil {
			return rep, fmt.Errorf("create schema_migration: %w", err)
		}
		applied = map[string]string{}
	} else if opts.Baseline {
		// A STICKY --baseline is the other way this corrupts, and the likelier one. The flag lives
		// in the overlay's `command:` (deploy/docker-compose.prod.yml), which is where an operator
		// who needed it once would add it — and leave it. From then on every deploy that ships a NEW
		// migration records it as applied WITHOUT RUNNING IT, exit 0, no warning.
		//
		// Once the ledger exists there is nothing left to adopt, so the flag can only do harm.
		return rep, ErrBaselineWithLedger
	}

	// A migration RENAMED after being applied would otherwise re-run: the ledger is keyed on file
	// name, so `0007_foo.sql` -> `0007_bar.sql` looks like a brand-new migration, and the sha256
	// drift check never fires because there is no row under the new name. Re-running an applied
	// migration means a `CREATE TABLE` against a table that exists — a hard failure, which is the
	// good outcome — but on a migration that happens to be re-runnable it would silently re-apply.
	// Catch it by VERSION, which is the thing that is actually meant to be immutable.
	appliedVersions, err := appliedVersionMap(ctx, pool)
	if err != nil {
		return rep, err
	}
	for _, f := range files {
		if prev, ok := appliedVersions[f.Version]; ok && prev != f.Name {
			return rep, fmt.Errorf(
				"migration version %d was applied as %q but is now on disk as %q. A rename is "+
					"indistinguishable from a new migration to a name-keyed ledger, so this is "+
					"refused rather than re-applied. Restore the original name, or reconcile the "+
					"ledger by hand", f.Version, prev, f.Name)
		}
	}

	// Drift check BEFORE applying anything: an edited migration means the database and the
	// repository disagree about what was run, and continuing would layer new schema on an unknown
	// base. Checked across the whole set first so the error names the problem rather than appearing
	// halfway through a run.
	for _, f := range files {
		if want, ok := applied[f.Name]; ok && want != f.SHA256 {
			return rep, fmt.Errorf(
				"migration %s has CHANGED since it was applied (recorded sha256 %s, on disk %s). "+
					"The database and this checkout disagree about what has run; applying more on "+
					"top would build on an unknown base. Reconcile by hand", f.Name, want, f.SHA256)
		}
	}

	for _, f := range files {
		if _, ok := applied[f.Name]; ok {
			rep.Skipped = append(rep.Skipped, f.Name)
			continue
		}
		if opts.Baseline {
			if _, err := pool.Exec(ctx,
				`INSERT INTO schema_migration (name, version, sha256, baselined) VALUES ($1,$2,$3,true)`,
				f.Name, f.Version, f.SHA256); err != nil {
				return rep, fmt.Errorf("baseline %s: %w", f.Name, err)
			}
			rep.Baselined = append(rep.Baselined, f.Name)
			continue
		}
		if err := applyOne(ctx, pool, f); err != nil {
			return rep, err
		}
		rep.Applied = append(rep.Applied, f.Name)
	}

	// Now that 0005 has certainly run, re-assert the ledger REVOKE. See revokeLedgerFromAppRoleSQL.
	if _, err := pool.Exec(ctx, revokeLedgerFromAppRoleSQL); err != nil {
		return rep, fmt.Errorf("revoke schema_migration from rmt_app: %w", err)
	}
	return rep, nil
}

// appliedVersionMap reads version -> name from the ledger, for the rename check.
func appliedVersionMap(ctx context.Context, pool *pgxpool.Pool) (map[int]string, error) {
	rows, err := pool.Query(ctx, `SELECT version, name FROM schema_migration`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migration versions: %w", err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var n string
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out[v] = n
	}
	return out, rows.Err()
}

// applyOne runs a single migration and records it, in ONE transaction. If the SQL fails, the ledger
// row rolls back with it — so a failed migration is never recorded as applied, and a recorded one
// always really ran.
func applyOne(ctx context.Context, pool *pgxpool.Pool, f MigrationFile) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %s: %w", f.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, f.SQL); err != nil {
		return fmt.Errorf("migration %s failed: %w", f.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migration (name, version, sha256) VALUES ($1,$2,$3)`,
		f.Name, f.Version, f.SHA256); err != nil {
		return fmt.Errorf("record %s: %w", f.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %s: %w", f.Name, err)
	}
	return nil
}

// ProvisionAppRolePassword sets `rmt_app`'s password. Runs as the OWNER, after the migrations.
//
// WHY IT LIVES HERE. migrations/0005 creates `rmt_app` with NO password on purpose — "production
// provisions the password/DSN out-of-band so no throwaway secret is committed to a migration that
// ships in dist/servers/migrations". That leaves a step somebody must do, and it has an ordering
// constraint: the role does not exist until 0005 has run. Doing it from a Postgres init script
// worked only while migrations were applied by initdb; once the runner owns them, an init script
// runs too early and fails.
//
// Folding it into the runner removes the ordering trap entirely: migrations first, then this, in one
// container, as the one role that can do both. It is idempotent, so every deploy re-asserts it.
//
// It matters because the alternative is the control plane connecting as the OWNER — and the owner is
// the bootstrap SUPERUSER, which bypasses row-level security unconditionally. See docs/18 §4b.
func ProvisionAppRolePassword(ctx context.Context, pool *pgxpool.Pool, password string) error {
	if password == "" {
		return fmt.Errorf("empty password for rmt_app")
	}
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app')`).Scan(&exists); err != nil {
		return fmt.Errorf("probe for rmt_app: %w", err)
	}
	if !exists {
		return fmt.Errorf("role rmt_app does not exist — migrations/0005_app_role.sql should have " +
			"created it. Refusing to continue, because the only DSN that would work is the " +
			"superuser's, which bypasses row-level security")
	}
	// ALTER ROLE accepts no bind parameter for the password, and a DO block accepts none either —
	// `$1` inside `DO $$ … $$` is dollar-quoting, not a placeholder (caught by the test, which is
	// why this is two statements rather than one).
	//
	// So: have POSTGRES build the statement. `format(…%L…)` in a plain SELECT does take a parameter,
	// and `%L` applies the server's own literal quoting — including doubling any embedded quote and
	// emitting a correct E'' form for backslashes. Escaping the password in Go would be re-writing
	// that by hand, in the one place where getting it wrong is an injection into a privileged DDL
	// statement run as the owner.
	var stmt string
	if err := pool.QueryRow(ctx,
		`SELECT format('ALTER ROLE rmt_app WITH PASSWORD %L', $1::text)`, password).Scan(&stmt); err != nil {
		return fmt.Errorf("build ALTER ROLE for rmt_app: %w", err)
	}
	if _, err := pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("set rmt_app password: %w", err)
	}
	return nil
}

// Summary renders a report for a log line.
func (r MigrationReport) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "applied=%d skipped=%d", len(r.Applied), len(r.Skipped))
	if len(r.Baselined) > 0 {
		fmt.Fprintf(&b, " baselined=%d", len(r.Baselined))
	}
	if len(r.Applied) > 0 {
		fmt.Fprintf(&b, " [%s]", strings.Join(r.Applied, ", "))
	}
	return b.String()
}

// compile-time assertion that pgx.Tx is what applyOne uses; keeps the import honest if it is ever
// refactored to take an interface.
var _ = func(tx pgx.Tx) {}
