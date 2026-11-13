package controlplane

// LIVE-POSTGRES tests for the migration runner. Gated behind TEST_DATABASE_URL like every other pg
// test here; verify-all.ps1 sets it and treats a skip as a failure.
//
// These cover the three behaviours that make automated deploy safe, and each one is a thing that
// would otherwise be discovered in production:
//
//   1. a second run is a NO-OP (idempotence) — without it every deploy re-runs 38 migrations and
//      fails on the first unguarded CREATE TABLE;
//   2. an EDITED already-applied migration is a hard failure (drift) — the database and the
//      checkout disagreeing about what ran is invisible without a recorded digest;
//   3. a FAILED migration is not recorded as applied (atomicity) — a half-applied file that the
//      ledger calls done is unrecoverable without hand surgery.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrateTestPool gives a pool on a schema this test owns exclusively. newTestPool hands back the
// shared test database, so each test here works in its own SCHEMA to avoid colliding with the
// application tables the other pg tests create and drop.
func migrateTestPool(t *testing.T, schema string) *pgxpool.Pool {
	t.Helper()
	pool := newTestPool(t) // skips without TEST_DATABASE_URL
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_, _ = pool.Exec(context.Background(), `SET search_path TO public`)
	})
	// current_schema() is what the runner probes, so point it at ours.
	if _, err := pool.Exec(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatalf("set search_path: %v", err)
	}
	return pool
}

func writeMigrationDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// THE PROPERTY AUTOMATED DEPLOY RESTS ON: running twice applies once.
//
// Without it, every deploy re-runs the whole set and dies on the first `CREATE TABLE` that carries
// no `IF NOT EXISTS` — which is 24 of them in the real migrations directory.
func TestPgMigrateIsIdempotent(t *testing.T) {
	pool := migrateTestPool(t, "mig_idem")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		// Deliberately UNGUARDED, mirroring the real migrations: if the runner re-ran this, it
		// would fail rather than silently succeed, which is what makes the assertion meaningful.
		"0001_a.sql": `CREATE TABLE mig_a (id int PRIMARY KEY);`,
		"0002_b.sql": `CREATE TABLE mig_b (id int PRIMARY KEY);`,
	})

	first, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(first.Applied) != 2 || len(first.Skipped) != 0 {
		t.Fatalf("first run = %+v, want 2 applied 0 skipped", first)
	}

	second, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("second run must be a no-op, got: %v", err)
	}
	if len(second.Applied) != 0 || len(second.Skipped) != 2 {
		t.Fatalf("second run = %+v, want 0 applied 2 skipped", second)
	}

	// And a NEW migration on a third run applies only itself — the incremental case every deploy
	// after the first one actually is.
	if err := os.WriteFile(filepath.Join(dir, "0003_c.sql"),
		[]byte(`CREATE TABLE mig_c (id int PRIMARY KEY);`), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if len(third.Applied) != 1 || third.Applied[0] != "0003_c.sql" || len(third.Skipped) != 2 {
		t.Fatalf("third run = %+v, want only 0003_c.sql applied", third)
	}
}

// An EDITED already-applied migration is refused, loudly, before anything else runs.
//
// Silent schema drift between a developer's box and production is the failure this guards. Note the
// assertion that NOTHING ELSE was applied: the check runs across the whole set up front, so the
// operator sees the problem named rather than discovering it halfway through a partial deploy.
func TestPgMigrateRefusesAnEditedMigration(t *testing.T) {
	pool := migrateTestPool(t, "mig_drift")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE drift_a (id int PRIMARY KEY);`,
	})
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("premise: first run failed: %v", err)
	}

	// Edit it, and add a NEW migration alongside — the new one must NOT be applied.
	if err := os.WriteFile(filepath.Join(dir, "0001_a.sql"),
		[]byte(`CREATE TABLE drift_a (id int PRIMARY KEY, extra text);`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0002_b.sql"),
		[]byte(`CREATE TABLE drift_b (id int PRIMARY KEY);`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil {
		t.Fatal("an edited already-applied migration was accepted; the database and the checkout " +
			"would silently disagree about what has run")
	}
	if !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("the error should say the migration changed, got %v", err)
	}

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'drift_b')`,
	).Scan(&exists); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if exists {
		t.Fatal("the drift check ran too late: a later migration was applied before it fired")
	}
}

// A FAILING migration is not recorded, and leaves nothing behind.
//
// The ledger row is written in the SAME transaction as the migration, so the two cannot disagree.
// A recorded-but-not-run migration is the worst state to be in: every later deploy skips it, and the
// schema is permanently missing whatever it created.
func TestPgMigrateDoesNotRecordAFailedMigration(t *testing.T) {
	pool := migrateTestPool(t, "mig_fail")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_ok.sql": `CREATE TABLE fail_ok (id int PRIMARY KEY);`,
		// Valid up to the second statement, so it half-applies unless it is transactional.
		"0002_bad.sql": `CREATE TABLE fail_partial (id int PRIMARY KEY);
		                 THIS IS NOT SQL;`,
	})

	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil {
		t.Fatal("a migration containing invalid SQL reported success")
	}
	if !strings.Contains(err.Error(), "0002_bad.sql") {
		t.Fatalf("the error should name the failing file, got %v", err)
	}

	// Not recorded...
	var recorded int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migration WHERE name = '0002_bad.sql'`).Scan(&recorded); err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if recorded != 0 {
		t.Fatal("a failed migration was recorded as applied; every later deploy would skip it")
	}
	// ...and its first statement rolled back with it.
	var partial bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'fail_partial')`,
	).Scan(&partial); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if partial {
		t.Fatal("the failing migration half-applied: its first statement survived, so it was not " +
			"wrapped in a transaction")
	}
	// The one that succeeded before it IS recorded — otherwise this test would pass against a
	// runner that recorded nothing at all.
	var ok int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migration WHERE name = '0001_ok.sql'`).Scan(&ok); err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if ok != 1 {
		t.Fatal("the migration that succeeded was not recorded")
	}
}

// A database that predates the runner is REFUSED, not guessed at — and `--baseline` adopts it
// without re-running anything.
//
// Auto-detecting "this schema looks migrated, assume everything ran" is right on a fully-migrated
// database and silently destructive on a half-migrated one. Refusing and asking is the only honest
// option, so both halves are pinned here.
func TestPgMigrateRequiresExplicitBaselineForAPreExistingSchema(t *testing.T) {
	pool := migrateTestPool(t, "mig_base")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE base_a (id int PRIMARY KEY);`,
	})

	// Simulate the pre-runner world: the schema exists (the runner probes for `tenant`), but there
	// is no ledger because it was applied by hand or by docker-entrypoint-initdb.
	if _, err := pool.Exec(ctx, `CREATE TABLE tenant (id int PRIMARY KEY)`); err != nil {
		t.Fatalf("stage pre-existing schema: %v", err)
	}

	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil {
		t.Fatal("a schema-bearing database with no ledger was migrated without --baseline; on a " +
			"half-migrated database that silently skips real work")
	}
	if !strings.Contains(err.Error(), "--baseline") {
		t.Fatalf("the refusal should tell the operator what to do, got %v", err)
	}

	// --baseline records without running: `base_a` must NOT be created.
	rep, err := Migrate(ctx, pool, dir, MigrateOptions{Baseline: true})
	if err != nil {
		t.Fatalf("baseline run: %v", err)
	}
	if len(rep.Baselined) != 1 || len(rep.Applied) != 0 {
		t.Fatalf("baseline run = %+v, want 1 baselined 0 applied", rep)
	}
	var created bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'base_a')`,
	).Scan(&created); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if created {
		t.Fatal("--baseline EXECUTED the migration; it must only record it")
	}

	// And a subsequent ordinary run is now a clean no-op, which is the point of baselining.
	after, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("run after baseline: %v", err)
	}
	if len(after.Applied) != 0 || len(after.Skipped) != 1 {
		t.Fatalf("after baseline = %+v, want 0 applied 1 skipped", after)
	}
}

// A FRESH database needs no baseline: no ledger AND no schema means "apply everything".
//
// The negative control for the test above. Without it, a runner that refused every database with no
// ledger would satisfy that one and be useless on the case that actually matters — a new deployment.
func TestPgMigrateAppliesEverythingToAFreshDatabase(t *testing.T) {
	pool := migrateTestPool(t, "mig_fresh")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE fresh_a (id int PRIMARY KEY);`,
		"0002_b.sql": `CREATE TABLE fresh_b (id int PRIMARY KEY);`,
	})

	rep, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("a fresh database must migrate without --baseline: %v", err)
	}
	if len(rep.Applied) != 2 {
		t.Fatalf("fresh run = %+v, want 2 applied", rep)
	}
	for _, tbl := range []string{"fresh_a", "fresh_b"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                WHERE table_schema = current_schema() AND table_name = $1)`, tbl,
		).Scan(&exists); err != nil {
			t.Fatalf("probe %s: %v", tbl, err)
		}
		if !exists {
			t.Fatalf("%s was recorded as applied but does not exist", tbl)
		}
	}
}

// The rmt_app password provisioning.
//
// WHY IT MATTERS: if this quietly no-ops, the operator's rmt_app DSN cannot authenticate, the
// obvious fix is to point DATABASE_URL at the owner instead — and the owner is the bootstrap
// SUPERUSER, which bypasses row-level security unconditionally (docs/18 §4b). A silent failure here
// leads directly to tenant isolation being off.
//
// NOT TESTED HERE, and deliberately rather than by omission: the absent-role branch. Roles are
// cluster-wide, not schema-scoped, so exercising it would mean dropping `rmt_app` out from under
// every other pg suite in this package — several of which connect as it. An earlier draft of this
// test t.Skip()ped when the role happened to exist, which is worse than not testing it: verify-all
// counts a skip as a FAILURE precisely so that a test which quietly declines to run cannot pass for
// one. The branch is covered by inspection instead.
func TestPgProvisionAppRolePassword(t *testing.T) {
	pool := migrateTestPool(t, "mig_prov")
	ctx := context.Background()

	// An empty password is refused rather than ALTERing the role to a blank secret.
	if err := ProvisionAppRolePassword(ctx, pool, ""); err == nil {
		t.Fatal("an empty password was accepted")
	}

	// PREMISE: this database has rmt_app (the harness applies 0005). Asserted, not assumed — the
	// positive case below would pass vacuously against a function that returned nil unconditionally
	// if the role were missing and the error path were the one being taken.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app')`).Scan(&exists); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !exists {
		t.Fatalf("premise not met: rmt_app does not exist in the test database, so provisioning " +
			"cannot be exercised. Apply migrations/0005_app_role.sql first.")
	}

	// Setting it is harmless to the other suites: this test database uses trust auth, so they
	// continue to connect as rmt_app with an empty password regardless.
	if err := ProvisionAppRolePassword(ctx, pool, "provision-test-password"); err != nil {
		t.Fatalf("provisioning against a real rmt_app failed: %v", err)
	}

	// Idempotent — every deploy re-asserts it, so a second call must not be an error.
	if err := ProvisionAppRolePassword(ctx, pool, "provision-test-password-2"); err != nil {
		t.Fatalf("re-provisioning failed; every redeploy would break: %v", err)
	}

	// It really wrote something: rolpassword is non-null for a role with a password set.
	var hasPassword bool
	if err := pool.QueryRow(ctx,
		`SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = 'rmt_app'`).Scan(&hasPassword); err != nil {
		// pg_authid needs superuser; if the harness role cannot read it, skip THIS assertion only
		// rather than the test — the calls above already proved the statements execute.
		t.Logf("cannot read pg_authid (%v); the execution assertions above still stand", err)
		return
	}
	if !hasPassword {
		t.Fatal("ProvisionAppRolePassword reported success but rmt_app still has no password")
	}
}

// A password full of SQL metacharacters survives intact.
//
// This is why the statement is built by POSTGRES (`format(%L)`) rather than escaped in Go. The value
// goes into a privileged DDL statement executed as the OWNER, so hand-rolled quoting here would be
// an injection into `ALTER ROLE` — and `openssl rand -base64` output legitimately contains
// characters that naive quoting mangles.
//
// An earlier attempt used `DO $$ … EXECUTE format(…, $1) … $$`, which does not work at all: inside a
// dollar-quoted block `$1` is quoting syntax, not a placeholder. The test caught it as "mismatched
// param and argument count" — which is the good outcome, but it is worth recording that the shape
// LOOKED right.
func TestPgProvisionAppRolePasswordSurvivesSQLMetacharacters(t *testing.T) {
	pool := migrateTestPool(t, "mig_quote")
	ctx := context.Background()

	// One of each thing that breaks a different naive escaping scheme: a single quote, a backslash,
	// a doubled quote, and a dollar-quote opener.
	q, bs := string(rune(39)), string(rune(92))
	nasty := "a" + q + "b" + bs + bs + "c" + q + q + "d$$e%f"

	if err := ProvisionAppRolePassword(ctx, pool, nasty); err != nil {
		t.Fatalf("a password containing SQL metacharacters was rejected: %v", err)
	}

	// The strongest available oracle: SCRAM verifiers are salted, so the stored value cannot be
	// compared byte-for-byte. What CAN be asserted is that the statement executed and stored
	// something — combined with the fact that a mis-quoted password would have been a syntax error
	// rather than a wrong-but-valid string.
	var ok bool
	if err := pool.QueryRow(ctx,
		`SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = 'rmt_app'`).Scan(&ok); err != nil {
		t.Logf("cannot read pg_authid (%v); the ALTER ROLE above still executed without error", err)
		return
	}
	if !ok {
		t.Fatal("the metacharacter password did not store")
	}
}

// A migration RENAMED after being applied is REFUSED, not silently re-run.
//
// Found by the loops-91/92 adversarial review. The ledger is keyed on file NAME, so
// `0007_foo.sql` -> `0007_bar.sql` looks like a brand-new migration and the sha256 drift check
// cannot fire — there is no row under the new name to compare against. The VERSION is the thing
// that is actually meant to be immutable, so that is what this checks.
func TestPgMigrateRefusesARenamedMigration(t *testing.T) {
	pool := migrateTestPool(t, "mig_rename")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_original.sql": `CREATE TABLE rename_a (id int PRIMARY KEY);`,
	})
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("premise: first run failed: %v", err)
	}

	// Rename it, contents unchanged. To a name-keyed ledger this is a new migration.
	if err := os.Rename(filepath.Join(dir, "0001_original.sql"),
		filepath.Join(dir, "0001_renamed.sql")); err != nil {
		t.Fatal(err)
	}

	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil {
		t.Fatal("a renamed already-applied migration was accepted; it would be re-applied, and on a " +
			"re-runnable migration that would happen silently")
	}
	if !strings.Contains(err.Error(), "0001_original.sql") || !strings.Contains(err.Error(), "0001_renamed.sql") {
		t.Fatalf("the error should name BOTH the recorded and the on-disk name, got %v", err)
	}

	// NEGATIVE CONTROL: restoring the name makes it a clean no-op again, so the check keys on the
	// rename rather than refusing every second run.
	if err := os.Rename(filepath.Join(dir, "0001_renamed.sql"),
		filepath.Join(dir, "0001_original.sql")); err != nil {
		t.Fatal(err)
	}
	rep, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("restoring the original name should be a clean no-op: %v", err)
	}
	if len(rep.Applied) != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("after restore = %+v, want 0 applied 1 skipped", rep)
	}
}

// The app role must NOT be able to write its own schema history.
//
// Found by the review, and the ordering is the whole bug: on a FRESH database the ledger is created
// before any migration, so `rmt_app` does not exist and the REVOKE inside createTrackingTableSQL is
// a no-op. Migration 0005 then runs `GRANT ... ON ALL TABLES IN SCHEMA public TO rmt_app`, and ALL
// TABLES includes the ledger created moments earlier — so the application role ended up with full
// DML on it on every new deployment. The REVOKE is now re-asserted after the migrations.
func TestPgMigrateRevokesTheLedgerFromTheAppRoleAfterMigrations(t *testing.T) {
	pool := migrateTestPool(t, "mig_revoke")
	ctx := context.Background()

	var roleExists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app')`).Scan(&roleExists); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !roleExists {
		t.Fatalf("premise not met: rmt_app does not exist in this test database, so the REVOKE has " +
			"nothing to act on. Apply migrations/0005_app_role.sql first.")
	}

	dir := writeMigrationDir(t, map[string]string{
		// Reproduces 0005's shape: grant DML on everything that exists, which includes the ledger.
		"0001_grant.sql": `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` +
			`mig_revoke TO rmt_app;`,
	})
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// After the run, rmt_app must hold NO privilege on the ledger.
	for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		var has bool
		if err := pool.QueryRow(ctx,
			`SELECT has_table_privilege('rmt_app', 'mig_revoke.schema_migration', $1)`, priv).Scan(&has); err != nil {
			t.Fatalf("has_table_privilege(%s): %v", priv, err)
		}
		if has {
			t.Fatalf("rmt_app still holds %s on schema_migration — a compromised app role could "+
				"forge the migration ledger (delete a row to re-run a migration, insert one to skip)", priv)
		}
	}
}

// --baseline on a database with NO schema must be REFUSED, not honoured.
//
// The path is short and entirely plausible: the operator hits ErrNeedsBaseline, whose text tells
// them to "run with --baseline". They decide to start clean instead (`docker compose down -v`
// destroys pgdata) and then run the command they already had queued. Without this refusal all
// migrations are recorded as applied without one of them executing, `migrate` exits 0,
// `service_completed_successfully` passes, and the control plane starts against an empty schema.
// Every later run then reports "skipped=N" — the state is unrecoverable without hand-editing the
// ledger, and nothing anywhere reports it.
func TestPgMigrateRefusesBaselineOnAnEmptyDatabase(t *testing.T) {
	pool := migrateTestPool(t, "mig_base_empty")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE empty_base_a (id int PRIMARY KEY);`,
	})

	// Premise, declared locally: the database really is empty — no `tenant`, so schemaLooksMigrated
	// is false. If a future change made this fixture arrive pre-migrated the test would silently
	// stop testing the empty case.
	var staged bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'tenant')`,
	).Scan(&staged); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if staged {
		t.Fatal("fixture is not an empty database, so it does not exercise the refusal")
	}

	_, err := Migrate(ctx, pool, dir, MigrateOptions{Baseline: true})
	if !errors.Is(err, ErrBaselineOnEmptyDatabase) {
		t.Fatalf("Migrate(--baseline) on an empty database = %v, want ErrBaselineOnEmptyDatabase", err)
	}

	// Nothing may have been written — neither the table nor a ledger claiming it exists.
	var ledger bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'schema_migration')`,
	).Scan(&ledger); err != nil {
		t.Fatalf("probe ledger: %v", err)
	}
	if ledger {
		t.Fatal("the refused baseline still created a ledger; a later run would trust it")
	}

	// Positive control: WITHOUT the flag the same empty database migrates normally. Without this,
	// "refuse every baseline" would pass.
	rep, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("a plain migrate on an empty database must work: %v", err)
	}
	if len(rep.Applied) != 1 || len(rep.Baselined) != 0 {
		t.Fatalf("plain migrate = %+v, want 1 applied 0 baselined", rep)
	}
}

// A STICKY --baseline must be refused once a ledger exists.
//
// This is the likelier of the two corruptions. The flag lives in the prod overlay's `command:`,
// which is exactly where an operator who needed it once would add it — and leave it. Every deploy
// afterwards that ships a NEW migration would record it as applied WITHOUT running it, exit 0, and
// say nothing. `!ledgerExists` was false, so no check ran at all.
func TestPgMigrateRefusesBaselineOnceTheLedgerExists(t *testing.T) {
	pool := migrateTestPool(t, "mig_base_sticky")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE sticky_a (id int PRIMARY KEY);`,
	})

	// A normal first deploy: ledger created, migration applied.
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	// The next release ships a second migration, and the operator left --baseline in `command:`.
	dir2 := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE sticky_a (id int PRIMARY KEY);`,
		"0002_b.sql": `CREATE TABLE sticky_b (id int PRIMARY KEY);`,
	})
	_, err := Migrate(ctx, pool, dir2, MigrateOptions{Baseline: true})
	if !errors.Is(err, ErrBaselineWithLedger) {
		t.Fatalf("Migrate(--baseline) with an existing ledger = %v, want ErrBaselineWithLedger", err)
	}

	// The refusal must be total: 0002 must be neither applied nor recorded, so the next correct run
	// still applies it.
	var recorded bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migration WHERE name = '0002_b.sql')`).Scan(&recorded); err != nil {
		t.Fatalf("probe ledger: %v", err)
	}
	if recorded {
		t.Fatal("the refused baseline still recorded 0002 — the exact silent skip this prevents")
	}

	// Positive control: dropping the flag applies it for real.
	rep, err := Migrate(ctx, pool, dir2, MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate without the flag: %v", err)
	}
	if len(rep.Applied) != 1 {
		t.Fatalf("migrate = %+v, want 0002 applied", rep)
	}
	var created bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'sticky_b')`,
	).Scan(&created); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !created {
		t.Fatal("0002 was reported applied but its table does not exist")
	}
}
