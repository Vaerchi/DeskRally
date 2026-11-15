package controlplane

// LIVE-POSTGRES tests for no-transaction (concurrent index) migrations. Gated on TEST_DATABASE_URL like
// every pg test here; verify-all.ps1 sets it and treats a skip as a failure.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func notxIndex(t *testing.T, pool *pgxpool.Pool, name string) (exists, valid bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)`, name).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false
	}
	if err != nil {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return true, valid
}

func notxLedgerHas(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM schema_migration WHERE name = $1`, name).Scan(&n); err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return n == 1
}

func notxExec(t *testing.T, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// The ordinary path: the index is built outside a transaction (inside one, Postgres refuses CONCURRENTLY,
// so success itself proves the runner did not wrap it), it is valid, it is recorded, and a re-run skips it.
func TestPgMigrateBuildsAConcurrentIndexOutsideATransaction(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_ok")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":   `CREATE TABLE notx_t (id int PRIMARY KEY, at timestamptz NOT NULL DEFAULT now());`,
		"0002_idx.sql": noTransactionMarker + "\n-- comment lines are fine\nCREATE INDEX CONCURRENTLY notx_t_at_idx ON notx_t (at);\n",
		"0003_u.sql":   `CREATE TABLE notx_after (id int PRIMARY KEY);`,
	})
	rep, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(rep.Applied) != 3 {
		t.Fatalf("applied %v, want all three (the run continues past a no-transaction file)", rep.Applied)
	}
	if exists, valid := notxIndex(t, pool, "notx_t_at_idx"); !exists || !valid {
		t.Fatalf("index exists=%v valid=%v, want a valid index", exists, valid)
	}
	if !notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("the no-transaction migration was not recorded")
	}
	again, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil || len(again.Applied) != 0 || len(again.Skipped) != 3 {
		t.Fatalf("second run = %+v, %v; want a no-op", again, err)
	}
}

// A crash between the statement and the ledger INSERT leaves the index built but unrecorded. The runner cannot prove
// an existing index is this migration's definition (Codex r6), so it stops with both definitions and the INSERT to
// issue if they match; after that, the next run skips the file.
func TestPgMigrateRecordsAConcurrentIndexBuiltByACrashedRun(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_crash")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql": `CREATE TABLE notx_c (id int PRIMARY KEY, v int);`,
	})
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("premise: %v", err)
	}
	notxExec(t, pool, `CREATE INDEX notx_c_v_idx ON notx_c (v)`) // the crashed run's work
	if err := os.WriteFile(filepath.Join(dir, "0002_idx.sql"),
		[]byte(noTransactionMarker+"\nCREATE INDEX CONCURRENTLY notx_c_v_idx ON notx_c (v);"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "INSERT INTO schema_migration (name, version, sha256) VALUES ('0002_idx.sql', 2, '") {
		t.Fatalf("re-run after the crash = %v; want a refusal giving the INSERT to record the existing index", err)
	}
	if notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("recorded an index the runner cannot prove is this migration's")
	}
	files, err := LoadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migration (name, version, sha256) VALUES ($1, $2, $3)`,
		files[1].Name, files[1].Version, files[1].SHA256); err != nil { // the operator follows the message
		t.Fatal(err)
	}
	rep, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err != nil || len(rep.Applied) != 0 || len(rep.Skipped) != 2 {
		t.Fatalf("after recording it by hand = %+v, %v; want both skipped", rep, err)
	}
}

// THE TRAP: a failed concurrent build leaves an INVALID index. Without the runner's check, the next run's
// IF NOT EXISTS would skip the rebuild and record an index the planner never uses (and that, being
// UNIQUE, still rejects new duplicate writes). The runner refuses with the exact DROP to issue (it never drops an
// index it did not create, Codex r5), and after the operator's DROP the next run builds and records it.
func TestPgMigrateRefusesAnInvalidIndexLeftByAFailedBuildUntilItIsDropped(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_invalid")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql": `CREATE TABLE notx_d (id int PRIMARY KEY, k int);`,
		"0002_u.sql": noTransactionMarker + "\nCREATE UNIQUE INDEX CONCURRENTLY notx_d_k_key ON notx_d (k);",
	})
	// Apply only 0001 first, then seed a duplicate so the UNIQUE build fails.
	only1 := writeMigrationDir(t, map[string]string{"0001_t.sql": `CREATE TABLE notx_d (id int PRIMARY KEY, k int);`})
	if _, err := Migrate(ctx, pool, only1, MigrateOptions{}); err != nil {
		t.Fatalf("premise: %v", err)
	}
	notxExec(t, pool, `INSERT INTO notx_d VALUES (1, 7), (2, 7)`)

	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err == nil {
		t.Fatal("a UNIQUE build over duplicate data succeeded")
	}
	if notxLedgerHas(t, pool, "0002_u.sql") {
		t.Fatal("a FAILED no-transaction migration was recorded as applied")
	}
	if exists, valid := notxIndex(t, pool, "notx_d_k_key"); !exists || valid {
		t.Fatalf("premise: expected Postgres to leave an INVALID index behind, got exists=%v valid=%v", exists, valid)
	}

	notxExec(t, pool, `DELETE FROM notx_d WHERE id = 2`) // the operator fixes the data
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), `DROP INDEX CONCURRENTLY "mig_notx_invalid"."notx_d_k_key"`) ||
		!strings.Contains(err.Error(), "the migration says") { // Codex r7: shows the requested definition to compare
		t.Fatalf("re-run with the invalid leftover = %v; want a refusal naming the DROP to issue", err)
	}
	if notxLedgerHas(t, pool, "0002_u.sql") {
		t.Fatal("recorded over an INVALID index")
	}
	notxExec(t, pool, `DROP INDEX CONCURRENTLY "mig_notx_invalid"."notx_d_k_key"`) // the operator follows the message
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("re-run after the DROP: %v", err)
	}
	if exists, valid := notxIndex(t, pool, "notx_d_k_key"); !exists || !valid {
		t.Fatalf("after the re-run exists=%v valid=%v; the index was not built", exists, valid)
	}
	if !notxLedgerHas(t, pool, "0002_u.sql") {
		t.Fatal("the successful re-run was not recorded")
	}
}

func TestPgMigrateDropsAnIndexConcurrently(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_drop")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":    `CREATE TABLE notx_e (id int PRIMARY KEY, v int); CREATE INDEX notx_e_v_idx ON notx_e (v);`,
		"0002_drop.sql": noTransactionMarker + "\nDROP INDEX CONCURRENTLY IF EXISTS notx_e_v_idx;",
	})
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if exists, _ := notxIndex(t, pool, "notx_e_v_idx"); exists {
		t.Fatal("index still exists after the drop migration")
	}
	if !notxLedgerHas(t, pool, "0002_drop.sql") {
		t.Fatal("the drop migration was not recorded")
	}
}

// A name already taken by a TABLE: the CREATE fails (no IF NOT EXISTS), and nothing is recorded.
func TestPgMigrateRefusesToRecordAnIndexWhoseNameIsATable(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_name")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":   `CREATE TABLE notx_f (id int PRIMARY KEY); CREATE TABLE notx_clash (id int);`,
		"0002_idx.sql": noTransactionMarker + "\nCREATE INDEX CONCURRENTLY notx_clash ON notx_f (id);",
	})
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err == nil {
		t.Fatal("recorded a migration whose index was never built (the name is a table)")
	}
	if notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("the migration was recorded although no index was built")
	}
}

// An index another session is STILL BUILDING is indisvalid=false too. The runner must not mistake it for a
// failed build's leftover and drop it out from under that session.
func TestPgMigrateDoesNotDropAnIndexAnotherSessionIsBuilding(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_busy")
	ctx := context.Background()
	base := writeMigrationDir(t, map[string]string{"0001_t.sql": `CREATE TABLE notx_g (id int PRIMARY KEY, v int);`})
	if _, err := Migrate(ctx, pool, base, MigrateOptions{}); err != nil {
		t.Fatalf("premise: %v", err)
	}
	// Separate connections, not from the pool: the pool's search_path is set on one of its connections.
	holder, err := pgx.Connect(ctx, testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(ctx)
	builder, err := pgx.Connect(ctx, testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close(ctx)

	// An open writer (ROW EXCLUSIVE) makes CREATE INDEX CONCURRENTLY wait part-way, after the (invalid)
	// index is in the catalog.
	if _, err := holder.Exec(ctx, `BEGIN; LOCK TABLE mig_notx_busy.notx_g IN ROW EXCLUSIVE MODE;`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := builder.Exec(ctx, `CREATE INDEX CONCURRENTLY notx_g_v_idx ON mig_notx_busy.notx_g (v)`)
		done <- err
	}()
	t.Cleanup(func() { _, _ = holder.Exec(context.Background(), `ROLLBACK`); <-done })

	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_progress_create_index
		                              WHERE index_relid = to_regclass('mig_notx_busy.notx_g_v_idx')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("premise: the concurrent build never reached the wait phase")
		}
		time.Sleep(50 * time.Millisecond)
	}

	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":   `CREATE TABLE notx_g (id int PRIMARY KEY, v int);`,
		"0002_idx.sql": noTransactionMarker + "\nCREATE INDEX CONCURRENTLY notx_g_v_idx ON notx_g (v);",
	})
	_, err = Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "is INVALID") {
		t.Fatalf("migrate during another session's build = %v; want the INVALID-index refusal", err)
	}
	if notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("recorded while another session was still building the index")
	}
	if _, err := holder.Exec(ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the other session's build was disturbed: %v", err)
	}
	done <- nil // satisfy the cleanup's receive
	if exists, valid := notxIndex(t, pool, "notx_g_v_idx"); !exists || !valid {
		t.Fatalf("after the other build finished exists=%v valid=%v", exists, valid)
	}
}

// Codex r1 Q1 (P1): IF NOT EXISTS skips the build when an index of that name already exists on ANOTHER table; the
// runner must not record the migration as applied.
func TestPgMigrateRefusesASameNamedIndexOnAnotherTable(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_other")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":   `CREATE TABLE notx_m (id int PRIMARY KEY, v int); CREATE TABLE notx_n (id int, v int); CREATE INDEX notx_v_idx ON notx_n (v);`,
		"0002_idx.sql": noTransactionMarker + "\nCREATE INDEX CONCURRENTLY notx_v_idx ON notx_m (v);",
	})
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "DIFFERENT table") {
		t.Fatalf("migrate = %v; want the different-table refusal", err)
	}
	if notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("recorded although the index named by the file is on another table")
	}
}

// Codex r1 Q1 (P1): a NON-unique index of that name already on the table must not satisfy a UNIQUE migration, or the
// uniqueness guarantee the file promises is silently absent.
func TestPgMigrateRefusesANonUniqueIndexForAUniqueMigration(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_uniq")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":   `CREATE TABLE notx_u (id int PRIMARY KEY, k int); CREATE INDEX notx_u_k ON notx_u (k);`,
		"0002_idx.sql": noTransactionMarker + "\nCREATE UNIQUE INDEX CONCURRENTLY notx_u_k ON notx_u (k);",
	})
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("migrate = %v; want the uniqueness refusal", err)
	}
	if notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("recorded a UNIQUE migration over a non-unique index")
	}
}

// Codex r1 Q3 (P1): with search_path a,b and the table only in b, a VALID same-named index in a must not hide the
// INVALID leftover in b (where CREATE INDEX puts the index and IF NOT EXISTS looks). The runner works in the
// table's schema: it reports b's invalid index (not a's valid one) and records nothing until that is resolved.
func TestPgMigrateChecksTheIndexInTheTablesSchema(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_qa")
	ctx := context.Background()
	notxExec(t, pool, `DROP SCHEMA IF EXISTS mig_notx_qb CASCADE`)
	notxExec(t, pool, `CREATE SCHEMA mig_notx_qb`)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS mig_notx_qb CASCADE`) })
	notxExec(t, pool, `CREATE TABLE mig_notx_qa.decoy (k int); CREATE INDEX notx_q_idx ON mig_notx_qa.decoy (k)`)
	notxExec(t, pool, `CREATE TABLE mig_notx_qb.notx_q (id int PRIMARY KEY, k int)`)
	notxExec(t, pool, `INSERT INTO mig_notx_qb.notx_q VALUES (1, 7), (2, 7)`)
	if _, err := pool.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY notx_q_idx ON mig_notx_qb.notx_q (k)`); err == nil {
		t.Fatal("premise: the UNIQUE build over duplicates succeeded")
	}
	notxExec(t, pool, `DELETE FROM mig_notx_qb.notx_q WHERE id = 2`)
	notxExec(t, pool, `SET search_path TO mig_notx_qa, mig_notx_qb`)

	dir := writeMigrationDir(t, map[string]string{
		"0001_idx.sql": noTransactionMarker + "\nCREATE UNIQUE INDEX CONCURRENTLY notx_q_idx ON notx_q (k);",
	})
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), `"mig_notx_qb"."notx_q_idx" exists but is INVALID`) {
		t.Fatalf("migrate = %v; want the refusal naming the INVALID index in the table's schema", err)
	}
	if notxLedgerHas(t, pool, "0001_idx.sql") {
		t.Fatal("recorded although the index in the table's schema is INVALID")
	}
	notxExec(t, pool, `DROP INDEX CONCURRENTLY mig_notx_qb.notx_q_idx`)
	if _, err := Migrate(ctx, pool, dir, MigrateOptions{}); err != nil {
		t.Fatalf("migrate after the DROP: %v", err)
	}
	var valid, unique bool
	if err := pool.QueryRow(ctx, `SELECT indisvalid, indisunique FROM pg_index
	                               WHERE indexrelid = 'mig_notx_qb.notx_q_idx'::regclass`).Scan(&valid, &unique); err != nil {
		t.Fatal(err)
	}
	if !valid || !unique {
		t.Fatalf("mig_notx_qb.notx_q_idx valid=%v unique=%v; not built in the table's schema", valid, unique)
	}
}

// Codex r4: migration runs are SERIALIZED by a session advisory lock. While another session holds it, Migrate waits;
// once released, it runs. Two interleaved runs could otherwise both act on the same pending no-transaction file.
func TestPgMigrateWaitsForTheMigrationLock(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_lock")
	ctx := context.Background()
	holder, err := pgx.Connect(ctx, testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(ctx)
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		t.Fatal(err)
	}
	unlocked := false
	t.Cleanup(func() {
		if !unlocked {
			_, _ = holder.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrateLockKey)
		}
	})
	dir := writeMigrationDir(t, map[string]string{"0001_t.sql": `CREATE TABLE notx_l (id int PRIMARY KEY);`})
	done := make(chan error, 1)
	go func() {
		_, err := Migrate(ctx, pool, dir, MigrateOptions{})
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("Migrate finished (%v) while another session held the migration lock", err)
	case <-time.After(700 * time.Millisecond):
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrateLockKey); err != nil {
		t.Fatal(err)
	}
	unlocked = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate after the lock was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Migrate did not run after the lock was released")
	}
	if !notxLedgerHas(t, pool, "0001_t.sql") {
		t.Fatal("the migration was not applied after the lock was released")
	}
}

// Codex r6 #1: a VALID unique index with the same name on the same table but DIFFERENT columns satisfies table,
// uniqueness and validity checks while IF NOT EXISTS skips the build. Any pre-existing index of that name stops the
// run with both definitions, so the email-uniqueness the file promises is never recorded without being built.
func TestPgMigrateRefusesASameNamedIndexWithDifferentColumns(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_cols")
	ctx := context.Background()
	dir := writeMigrationDir(t, map[string]string{
		"0001_t.sql":   `CREATE TABLE notx_e2 (id int PRIMARY KEY, email text); CREATE UNIQUE INDEX notx_e2_u ON notx_e2 (id);`,
		"0002_idx.sql": noTransactionMarker + "\nCREATE UNIQUE INDEX CONCURRENTLY notx_e2_u ON notx_e2 (email);",
	})
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "(id)") {
		t.Fatalf("migrate = %v; want a refusal showing the existing definition", err)
	}
	if notxLedgerHas(t, pool, "0002_idx.sql") {
		t.Fatal("recorded a UNIQUE (email) migration over a UNIQUE (id) index")
	}
}

// Codex r6 #4: an INVALID index of that name on a DIFFERENT table is a name collision, not this migration's failed
// build; the message must not tell the operator to drop it.
func TestPgMigrateDoesNotAdviseDroppingAnotherTablesInvalidIndex(t *testing.T) {
	pool := migrateTestPool(t, "mig_notx_coll")
	ctx := context.Background()
	notxExec(t, pool, `CREATE TABLE notx_f2 (id int PRIMARY KEY, k int); CREATE TABLE notx_g2 (id int, k int)`)
	notxExec(t, pool, `INSERT INTO notx_g2 VALUES (1, 7), (2, 7)`)
	if _, err := pool.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY notx_k_idx ON notx_g2 (k)`); err == nil {
		t.Fatal("premise: the UNIQUE build over duplicates succeeded")
	}
	dir := writeMigrationDir(t, map[string]string{
		"0001_idx.sql": noTransactionMarker + "\nCREATE UNIQUE INDEX CONCURRENTLY notx_k_idx ON notx_f2 (k);",
	})
	_, err := Migrate(ctx, pool, dir, MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "DIFFERENT table") || strings.Contains(err.Error(), "DROP INDEX") {
		t.Fatalf("migrate = %v; want the name-collision refusal without DROP advice", err)
	}
}
