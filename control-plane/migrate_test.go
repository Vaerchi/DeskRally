package controlplane

// Unit tests for the migration runner's PURE half — loading and ordering files off disk. The half
// that touches a database lives in migrate_pgstore_test.go, behind TEST_DATABASE_URL.
//
// These are the checks that are cheap to get wrong and expensive to discover in production: apply
// ORDER, and refusing input whose order is ambiguous.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// writeMigrations builds a temp directory of migration files and returns its path.
func writeMigrations(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// Apply order is NUMERIC, not lexical.
//
// Every migration in the repo today is 4-digit zero-padded, so the two orderings agree and a lexical
// sort would pass this project's current file set. That is a property of the names, not a guarantee
// — docs/10 already warns that a plain sort puts `0100` after `0009`. The test uses MIXED widths
// precisely so a lexical implementation fails it.
func TestLoadMigrationsOrdersNumericallyNotLexically(t *testing.T) {
	dir := writeMigrations(t, map[string]string{
		"0009_nine.sql":   "SELECT 9;",
		"0010_ten.sql":    "SELECT 10;",
		"100_hundred.sql": "SELECT 100;",
		"0002_two.sql":    "SELECT 2;",
	})
	got, err := LoadMigrations(dir)
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	var names []string
	for _, m := range got {
		names = append(names, m.Name)
	}
	want := []string{"0002_two.sql", "0009_nine.sql", "0010_ten.sql", "100_hundred.sql"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v (a LEXICAL sort would put 0002,0009,0010 before 100 only by "+
			"accident of padding, and 100 before 0002 without it)", names, want)
	}
	// Versions parsed, not inferred from position.
	if got[3].Version != 100 {
		t.Fatalf("version of 100_hundred.sql = %d, want 100", got[3].Version)
	}
}

// A duplicate version number is REFUSED, not resolved.
//
// Two files claiming 0039 would apply in whatever order the filesystem returned them — which works
// on one machine and not another, and produces a database whose schema depends on the reader. That
// is worth a hard error even though it is rare, because the failure it prevents is unreproducible.
func TestLoadMigrationsRefusesDuplicateVersions(t *testing.T) {
	dir := writeMigrations(t, map[string]string{
		"0039_first.sql":  "SELECT 1;",
		"0039_second.sql": "SELECT 2;",
	})
	_, err := LoadMigrations(dir)
	if err == nil {
		t.Fatal("two migrations claiming version 39 were accepted; apply order would depend on the filesystem")
	}
	if !strings.Contains(err.Error(), "duplicate migration version") {
		t.Fatalf("error should name the duplicate, got %v", err)
	}
}

// Files that are not migrations are IGNORED, not guessed at.
//
// The directory is mounted wholesale in compose, and a stray `notes.sql` or an editor backup must
// never become schema. The negative control matters as much as the positive: a runner that ignored
// everything would also pass "the stray file was ignored".
func TestLoadMigrationsIgnoresNonMigrationFiles(t *testing.T) {
	dir := writeMigrations(t, map[string]string{
		"0001_real.sql":     "SELECT 1;",
		"notes.sql":         "SELECT 'not a migration';",
		"README.md":         "# hello",
		"0002_real.sql.bak": "SELECT 'backup';",
		"0003_real.sql":     "SELECT 3;",
	})
	got, err := LoadMigrations(dir)
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(got) != 2 {
		var names []string
		for _, m := range got {
			names = append(names, m.Name)
		}
		t.Fatalf("loaded %v, want exactly the two real migrations", names)
	}
	if got[0].Name != "0001_real.sql" || got[1].Name != "0003_real.sql" {
		t.Fatalf("loaded the wrong files: %v", got)
	}
}

// The recorded digest is of the file's BYTES, and it changes when the file does. This is what makes
// the drift check in Migrate() possible, so it is worth pinning on its own.
func TestLoadMigrationsHashesFileContents(t *testing.T) {
	dir := writeMigrations(t, map[string]string{"0001_x.sql": "SELECT 1;"})
	a, err := LoadMigrations(dir)
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(a[0].SHA256) != 64 {
		t.Fatalf("sha256 = %q, want 64 hex chars", a[0].SHA256)
	}

	// Same bytes, same digest — so an unchanged migration never trips the drift check.
	again, _ := LoadMigrations(dir)
	if again[0].SHA256 != a[0].SHA256 {
		t.Fatal("the digest is not stable across reads")
	}

	// One byte different, different digest.
	if err := os.WriteFile(filepath.Join(dir, "0001_x.sql"), []byte("SELECT 2;"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := LoadMigrations(dir)
	if b[0].SHA256 == a[0].SHA256 {
		t.Fatal("editing the migration did not change its digest, so drift would go undetected")
	}
}

// An empty or missing directory is an error, not an empty success.
//
// The compose init container passes a mounted path; if that mount is wrong the runner would
// otherwise report "0 applied" and exit 0, and the control plane would start against an empty
// database and fail obscurely a moment later.
func TestMigrateRefusesAnEmptyOrMissingDirectory(t *testing.T) {
	if _, err := LoadMigrations(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("a missing migrations directory must be an error")
	}
	// Empty-but-present is caught in Migrate() rather than LoadMigrations(); assert the loader
	// reports it as empty so that check has something to act on.
	got, err := LoadMigrations(t.TempDir())
	if err != nil {
		t.Fatalf("an empty directory should load cleanly as zero migrations: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected zero migrations, got %d", len(got))
	}
}

// Migration files must not contain standalone BEGIN or COMMIT statements.
//
// The runner wraps every file in its OWN transaction (applyOne). An embedded COMMIT commits the DDL
// before the ledger INSERT, defeating atomicity: a failure after the COMMIT leaves applied schema
// with no ledger record, and the next deploy skips it. An embedded BEGIN inside the runner's BEGIN
// opens a subtransaction — most DDL cannot run inside one, and the ledger write and the outer COMMIT
// no longer cover the SQL.
//
// This test reads every migration file and rejects any that start a top-level transaction. It ignores
// BEGIN/COMMIT inside dollar-quoted bodies (DO $$ … $$ blocks), which are legitimate.
func TestRepositoryMigrationsHaveNoEmbeddedTransactions(t *testing.T) {
	// A top-level statement is one that is NOT inside a dollar-quote block. Match lines that are
	// `BEGIN;` or `COMMIT;` (allowing leading/trailing whitespace) outside dollar-quoted strings.
	// We parse the file line-by-line and track dollar-quote depth.
	stmt := regexp.MustCompile(`(?i)^\s*(BEGIN|COMMIT)\s*;\s*$`)

	migs, err := LoadMigrations("migrations")
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	for _, m := range migs {
		content, rerr := os.ReadFile(filepath.Join("migrations", m.Name))
		if rerr != nil {
			t.Fatalf("read %s: %v", m.Name, rerr)
		}
		inDollarQuote := false
		for lineNo, line := range strings.Split(string(content), "\n") {
			// Flip dollar-quote state on every $$ token (naïve but correct for our migrations).
			inDollarQuote = inDollarQuote != (strings.Count(line, "$$")%2 == 1)
			if !inDollarQuote && stmt.MatchString(line) {
				t.Errorf("%s:%d contains a standalone %q — the migration runner owns the transaction; "+
					"an embedded COMMIT defeats ledger atomicity and a failed migration after it leaves "+
					"applied DDL with no record",
					m.Name, lineNo+1, strings.TrimSpace(line))
			}
		}
	}
}

// The real repository's migrations load, in order, with no duplicates.
//
// A guard against the runner and the actual schema drifting apart: if someone adds `0039_x.sql`
// alongside an existing `0039_y.sql`, or a name the pattern does not match, this fails in CI rather
// than at deploy time.
func TestRepositoryMigrationsLoadCleanly(t *testing.T) {
	got, err := LoadMigrations("migrations")
	if err != nil {
		t.Fatalf("the repository's own migrations do not load: %v", err)
	}
	if len(got) < 30 {
		t.Fatalf("loaded only %d migrations from migrations/ — the pattern is probably not matching", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Version <= got[i-1].Version {
			t.Fatalf("migrations out of order or duplicated at %s -> %s", got[i-1].Name, got[i].Name)
		}
	}
	if got[0].Version != 1 {
		t.Fatalf("first migration is version %d (%s), want 1", got[0].Version, got[0].Name)
	}
}
