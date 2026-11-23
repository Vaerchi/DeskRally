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
//   - **One transaction per file**, so a failure leaves that file wholly unapplied rather than
//     half-applied. The one exception is a NO-TRANSACTION migration (see noTransactionMarker): a
//     single `CREATE INDEX CONCURRENTLY` / `DROP INDEX CONCURRENTLY`, which Postgres refuses to run in
//     a transaction. A plain CREATE INDEX holds a lock that blocks every write to the table for the
//     whole build, which on a large append-only table (audit, session history) is an outage; the
//     concurrent form does not block writes. That class is deliberately narrow; see applyNoTransaction.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrationFile is one `NNNN_name.sql` on disk.
type MigrationFile struct {
	Name    string // base name, e.g. "0005_app_role.sql"
	Version int    // the numeric prefix
	SQL     string
	SHA256  string // hex, of the file's bytes

	// NoTransaction is set for a file whose first line is noTransactionMarker. Such a file holds exactly
	// one concurrent index statement on IndexName; LoadMigrations refuses any other shape.
	NoTransaction bool
	IndexName     string
	IndexDrop     bool   // DROP INDEX CONCURRENTLY rather than CREATE
	IndexTable    string // CREATE only: the table the index must be on
	IndexUnique   bool   // CREATE only: CREATE UNIQUE INDEX
	// Statement is the ONE statement the runner executes for a no-transaction file: the validated text, never the
	// raw file, so nothing the check did not see (a comment line, a bare CR) is ever sent (Codex r3).
	Statement string
}

// noTransactionMarker, as a migration's FIRST line, makes it a no-transaction migration.
const noTransactionMarker = "-- deskrally:no-transaction"

// The only statements a no-transaction migration may hold, one per file, unqualified lower-case names.
//
// WHY SO NARROW. Outside a transaction the ledger INSERT cannot be atomic with the statement, so the runner checks
// the outcome itself, which is why it must know the index name, its table and whether it is UNIQUE.
//
// CREATE has NO `IF NOT EXISTS` (Codex r7): an index of that name appearing between the runner's pre-check and its
// statement (an external session) must make the CREATE FAIL, not be skipped and then mistaken for this migration's.
// A crash after the build and before the ledger row leaves an index the pre-check reports, with the ledger INSERT
// to issue if it is this migration's (see applyConcurrentCreate). DROP keeps IF EXISTS: dropping twice is harmless.
var (
	noTxCreatePattern = regexp.MustCompile(
		`(?is)^CREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+((?-i:[a-z_][a-z0-9_]*))\s+ON\s+(?:ONLY\s+)?((?-i:[a-z_][a-z0-9_]*))\s*(?:USING\s+[a-z_]+\s*)?\(.*$`)
	noTxDropPattern = regexp.MustCompile(`(?is)^DROP\s+INDEX\s+CONCURRENTLY\s+IF\s+EXISTS\s+((?-i:[a-z_][a-z0-9_]*))$`)
)

// noTransactionStatement returns the single statement of a no-transaction file: everything after the leading `--`
// comment lines, without its trailing `;`. That text, not the file, is what the runner executes.
//
// WHY "NO SEMICOLON" IS THE WHOLE RULE. In the simple query protocol statements are separated only by `;`, so text
// with no `;` in it is exactly one statement, whatever quotes, dollar quotes or comments it contains. Rules about
// those (block comments, a `--` line inside a multi-line literal, a bare CR ending a comment: Codex r1-r3) were each
// one more way to be wrong; refusing every `;` and executing only the checked text closes the class. A `;` inside a
// string literal is refused too, which costs nothing an index definition needs.
func noTransactionStatement(body string) (string, error) {
	// Find where the first line that is neither blank nor a `--` comment starts, treating CRLF, LF and a bare CR
	// as line ends (Postgres ends a line comment at any of them), then take the ORIGINAL bytes from there: the
	// executed text must be byte-for-byte the text in the reviewed, hashed file, literals included (Codex r4).
	start, lineStart := len(body), 0
	for lineStart < len(body) {
		lineEnd := strings.IndexAny(body[lineStart:], "\r\n")
		next := len(body)
		if lineEnd >= 0 {
			lineEnd += lineStart
			next = lineEnd + 1
			if body[lineEnd] == '\r' && next < len(body) && body[next] == '\n' {
				next++
			}
		} else {
			lineEnd = len(body)
		}
		t := strings.TrimSpace(body[lineStart:lineEnd])
		if t != "" && !strings.HasPrefix(t, "--") {
			start = lineStart
			break
		}
		lineStart = next
	}
	stmt := strings.TrimRight(body[start:], " \t\r\n")
	// Trailing `--` comment lines go too (Codex r5). One inside a multi-line literal would leave the literal open,
	// which Postgres refuses at apply time: a safe failure, never recorded.
	for {
		cut := strings.LastIndexAny(stmt, "\r\n")
		if cut < 0 || !strings.HasPrefix(strings.TrimSpace(stmt[cut+1:]), "--") {
			break
		}
		stmt = strings.TrimRight(stmt[:cut], " \t\r\n")
	}
	// `...; -- note` on the last line: drop the comment with the semicolon (Codex r6). A `--` that is really inside a
	// literal leaves the literal open, which Postgres refuses at apply time: a safe failure, never recorded.
	// The terminator is the FIRST `;` on the last line followed only by a `--` comment; the comment itself may contain
	// `;` (Codex r7).
	lastLine := strings.LastIndexAny(stmt, "\r\n") + 1
	for off := lastLine; off < len(stmt); {
		semi := strings.IndexByte(stmt[off:], ';')
		if semi < 0 {
			break
		}
		semi += off
		if strings.HasPrefix(strings.TrimSpace(stmt[semi+1:]), "--") {
			stmt = strings.TrimRight(stmt[:semi+1], " \t")
			break
		}
		off = semi + 1
	}
	stmt = strings.TrimSuffix(stmt, ";")
	stmt = strings.TrimSpace(stmt)
	if strings.Contains(stmt, ";") {
		return "", fmt.Errorf("it must hold exactly ONE statement with no other `;` anywhere (several would run " +
			"as one implicit transaction, where CONCURRENTLY fails)")
	}
	return stmt, nil
}

// classifyMigration sets the no-transaction fields of f, or explains why its shape is refused. Run at
// load time, so a malformed file stops the run before ANY migration is applied.
func classifyMigration(f *MigrationFile) error {
	body := strings.TrimPrefix(f.SQL, "\ufeff")
	firstLine := strings.TrimSpace(strings.SplitN(strings.ReplaceAll(body, "\r\n", "\n"), "\n", 2)[0])
	if firstLine != noTransactionMarker {
		if strings.Contains(body, noTransactionMarker) {
			return fmt.Errorf("migration %s: %q must be the FIRST line to take effect; elsewhere it would "+
				"silently leave the file transactional", f.Name, noTransactionMarker)
		}
		// No attempt to spot a concurrent build in a transactional file: text matching cannot tell a statement
		// from prose inside a string literal (Codex r2), and a misplaced one fails safely at apply time
		// ("cannot run inside a transaction block"), rolled back and never recorded.
		return nil
	}
	stmt, err := noTransactionStatement(body)
	if err != nil {
		return fmt.Errorf("migration %s is no-transaction: %w", f.Name, err)
	}
	if m := noTxCreatePattern.FindStringSubmatch(stmt); m != nil {
		f.NoTransaction, f.IndexUnique, f.IndexName, f.IndexTable, f.Statement = true, m[1] != "", m[2], m[3], stmt
		return nil
	}
	if m := noTxDropPattern.FindStringSubmatch(stmt); m != nil {
		f.NoTransaction, f.IndexName, f.IndexDrop, f.Statement = true, m[1], true, stmt
		return nil
	}
	return fmt.Errorf("migration %s is no-transaction, so it may hold only `CREATE [UNIQUE] INDEX CONCURRENTLY "+
		"<name> ON <table> ...` (no IF NOT EXISTS: a same-named index must make it fail, not be skipped) or "+
		"`DROP INDEX CONCURRENTLY IF EXISTS <name>`, with unqualified lower-case names", f.Name)
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
		mf := MigrationFile{
			Name:    e.Name(),
			Version: v,
			SQL:     string(b),
			SHA256:  hex.EncodeToString(sum[:]),
		}
		if err := classifyMigration(&mf); err != nil {
			return nil, err
		}
		out = append(out, mf)
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
func appliedMigrations(ctx context.Context, pool migrateDB) (map[string]string, bool, error) {
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
func schemaLooksMigrated(ctx context.Context, pool migrateDB) (bool, error) {
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

// migrateDB is what the runner needs from a database handle. Both *pgxpool.Pool and *pgxpool.Conn satisfy it; a
// run uses ONE acquired connection (see Migrate).
type migrateDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// migrateLockKey is the session advisory lock that serializes migration runs against one database. Arbitrary but
// fixed: every runner of this schema must use the same number.
const migrateLockKey int64 = 0x4452_6d69_6772_6174 // "DRmigrat"

// MigrateOptions controls one run.
type MigrateOptions struct {
	// Baseline records every on-disk migration as applied without executing it. For adopting a
	// database that predates the runner. Never use it on a database that is genuinely behind.
	Baseline bool
}

// Migrate brings `pool`'s database up to the set of migrations in `dir`.
//
// `pool` MUST be connected as a role with DDL rights (the owner), not as `rmt_app`.
//
// SERIALIZED. A run holds a session advisory lock on ONE connection from the first ledger read to the last write, and
// does all its work on that connection. Two runs started together (a second deploy, an operator re-running migrate
// beside the init container) used to interleave: both could pass the checks for the same pending file, and a
// no-transaction migration could even drop the other run's freshly built index after that run had recorded it
// (Codex r4). The second run now waits, then sees the first run's ledger. One connection also means one session,
// so search_path and role are the same for every step.
func Migrate(ctx context.Context, pool *pgxpool.Pool, dir string, opts MigrateOptions) (MigrationReport, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return MigrationReport{}, fmt.Errorf("acquire a connection for migrate: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return MigrationReport{}, fmt.Errorf("take the migration lock: %w", err)
	}
	// Released explicitly; if the connection dies first, the session ends and Postgres releases the lock with it.
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrateLockKey) }()
	return migrate(ctx, conn, dir, opts)
}

func migrate(ctx context.Context, pool migrateDB, dir string, opts MigrateOptions) (MigrationReport, error) {
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
		apply := applyOne
		if f.NoTransaction {
			apply = applyNoTransaction
		}
		if err := apply(ctx, pool, f); err != nil {
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
func appliedVersionMap(ctx context.Context, pool migrateDB) (map[int]string, error) {
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
func applyOne(ctx context.Context, pool migrateDB, f MigrationFile) error {
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

// indexValidity reports whether `name` (resolved by search_path) is an index, and if so whether it is VALID.
// Used for DROP, which names no table.
func indexValidity(ctx context.Context, conn migrateDB, name string) (exists, valid bool, err error) {
	err = conn.QueryRow(ctx,
		`SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)`, name).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return err == nil, valid, err
}

// targetIndex is the index of a given name in a given table's SCHEMA (where CREATE INDEX puts it, and where IF NOT
// EXISTS looks), whatever table it is on.
type targetIndex struct {
	exists, valid, unique, onTable bool
}

// lookupTargetIndex resolves `table` by search_path, then finds the index called `name` in that table's schema.
// The schema name is returned for a qualified DROP of an invalid leftover.
func lookupTargetIndex(ctx context.Context, conn migrateDB, table, name string) (targetIndex, string, error) {
	var tableOID uint32
	var schema string
	err := conn.QueryRow(ctx,
		`SELECT t.oid, n.nspname FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace
		 WHERE t.oid = to_regclass($1)`, table).Scan(&tableOID, &schema)
	if errors.Is(err, pgx.ErrNoRows) {
		return targetIndex{}, "", fmt.Errorf("table %s does not exist", table)
	}
	if err != nil {
		return targetIndex{}, "", err
	}
	var ti targetIndex
	var indrelid uint32
	err = conn.QueryRow(ctx,
		`SELECT i.indisvalid, i.indisunique, i.indrelid
		 FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
		 WHERE c.relname = $1 AND c.relnamespace = (SELECT relnamespace FROM pg_class WHERE oid = $2)`,
		name, tableOID).Scan(&ti.valid, &ti.unique, &indrelid)
	if errors.Is(err, pgx.ErrNoRows) {
		return targetIndex{}, schema, nil
	}
	if err != nil {
		return targetIndex{}, schema, err
	}
	ti.exists, ti.onTable = true, indrelid == tableOID
	return ti, schema, nil
}

// applyNoTransaction runs a no-transaction migration (classifyMigration has fixed its shape), then checks
// the outcome against the catalog before recording it. On the run's one locked connection (see Migrate).
//
// A FAILED CONCURRENT BUILD LEAVES AN INVALID INDEX behind (Postgres does not roll it back), and `IF NOT
// EXISTS` would then skip the rebuild and let the runner record an index the planner never uses and
// that, if UNIQUE, still enforces uniqueness on new writes. So an invalid index stops the run with the
// DROP to issue (see applyConcurrentCreate), and the result is verified valid; a failure is never recorded.
func applyNoTransaction(ctx context.Context, conn migrateDB, f MigrationFile) error {
	if f.IndexDrop {
		if _, err := conn.Exec(ctx, f.Statement); err != nil {
			return fmt.Errorf("migration %s failed: %w", f.Name, err)
		}
		exists, _, err := indexValidity(ctx, conn, f.IndexName)
		if err != nil {
			return fmt.Errorf("migration %s: verify index %s: %w", f.Name, f.IndexName, err)
		}
		if exists {
			return fmt.Errorf("migration %s: index %s still exists after DROP INDEX CONCURRENTLY", f.Name, f.IndexName)
		}
	} else if err := applyConcurrentCreate(ctx, conn, f); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx,
		`INSERT INTO schema_migration (name, version, sha256) VALUES ($1,$2,$3)`,
		f.Name, f.Version, f.SHA256); err != nil {
		return fmt.Errorf("record %s: %w", f.Name, err)
	}
	return nil
}

// applyConcurrentCreate builds the index and proves it is the one the file asks for: in the table's schema, on that
// table, VALID, and UNIQUE exactly when the file says so. Any index of that name already in the schema stops the run
// before the CREATE, and one appearing after this check makes the CREATE (which has no IF NOT EXISTS) fail.
func applyConcurrentCreate(ctx context.Context, conn migrateDB, f MigrationFile) error {
	ti, schema, err := lookupTargetIndex(ctx, conn, f.IndexTable, f.IndexName)
	if err != nil {
		return fmt.Errorf("migration %s: inspect index %s: %w", f.Name, f.IndexName, err)
	}
	if ti.exists {
		// The index name is already taken in the table's schema, and nothing here can prove the existing index is
		// THIS migration's definition (columns, expressions, predicate) without parsing SQL (Codex r6). Stop with what the operator needs to decide. The runner never
		// drops an index it did not create: every way of telling a dead build from a live one left a window in
		// which a finished build could be dropped (Codex r1-r5).
		qualified := pgx.Identifier{schema, f.IndexName}.Sanitize()
		var def string
		if err := conn.QueryRow(ctx, `SELECT pg_get_indexdef($1::regclass)`, qualified).Scan(&def); err != nil {
			def = "(unreadable: " + err.Error() + ")"
		}
		switch {
		case !ti.onTable:
			return fmt.Errorf("migration %s: the name %s is already used by an index on a DIFFERENT table (%s). "+
				"Rename this migration's index, or reconcile the existing one by hand", f.Name, qualified, def)
		case !ti.valid:
			// Only THIS migration's failed build is safe to drop: an invalid UNIQUE index of another definition still
			// enforces uniqueness on new writes (Codex r7), so the operator compares the two first.
			return fmt.Errorf("migration %s: index %s exists but is INVALID (%s); the migration says %q. If it is "+
				"this migration's failed build (the same definition) and no build is running (SELECT * FROM "+
				"pg_stat_progress_create_index), drop it with DROP INDEX CONCURRENTLY %s; and re-run migrate. "+
				"Otherwise rename this migration's index", f.Name, qualified, def, f.Statement, qualified)
		default:
			return fmt.Errorf("migration %s: index %s already exists (%s); the migration says %q. If they are the "+
				"same index (an earlier run built it and stopped before recording it), record it with INSERT INTO "+
				"schema_migration (name, version, sha256) VALUES ('%s', %d, '%s'); otherwise rename this "+
				"migration's index or drop the existing one, then re-run migrate",
				f.Name, qualified, def, f.Statement, f.Name, f.Version, f.SHA256)
		}
	}
	if _, err := conn.Exec(ctx, f.Statement); err != nil {
		return fmt.Errorf("migration %s failed: %w", f.Name, err)
	}
	ti, schema, err = lookupTargetIndex(ctx, conn, f.IndexTable, f.IndexName)
	if err != nil {
		return fmt.Errorf("migration %s: verify index %s: %w", f.Name, f.IndexName, err)
	}
	switch {
	case !ti.exists:
		return fmt.Errorf("migration %s: no index %s.%s after the statement (is the name taken by a table or "+
			"another relation?)", f.Name, schema, f.IndexName)
	case !ti.onTable:
		return fmt.Errorf("migration %s: index %s.%s is on a different table than %s; this migration is NOT "+
			"applied", f.Name, schema, f.IndexName, f.IndexTable)
	case ti.unique != f.IndexUnique:
		return fmt.Errorf("migration %s: index %s.%s exists but its uniqueness (unique=%v) is not what the file "+
			"asks for (unique=%v); this migration is NOT applied",
			f.Name, schema, f.IndexName, ti.unique, f.IndexUnique)
	case !ti.valid:
		return fmt.Errorf("migration %s: index %s.%s is INVALID after the build; not recording it", f.Name, schema, f.IndexName)
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
