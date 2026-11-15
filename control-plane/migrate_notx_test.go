package controlplane

// No-transaction migrations (noTransactionMarker): the load-time shape rules. Every refusal here is a file
// that would otherwise fail halfway through a deploy, or apply in a way the runner cannot verify.

import (
	"strings"
	"testing"
)

func classify(t *testing.T, name, sql string) (MigrationFile, error) {
	t.Helper()
	f := MigrationFile{Name: name, SQL: sql}
	err := classifyMigration(&f)
	return f, err
}

func TestClassifyMigrationAcceptsTheConcurrentIndexShapes(t *testing.T) {
	cases := []struct {
		sql, index string
		drop       bool
	}{
		{noTransactionMarker + "\nCREATE INDEX CONCURRENTLY audit_at_idx ON audit_event (at);\n", "audit_at_idx", false},
		{noTransactionMarker + "\r\n-- why\r\ncreate unique index concurrently u_idx\r\n  on only t using btree (a, b) where b is not null;\r\n", "u_idx", false},
		{"\ufeff" + noTransactionMarker + "\nCREATE INDEX CONCURRENTLY x_idx ON t(a)", "x_idx", false},
		{noTransactionMarker + "\nDROP INDEX CONCURRENTLY IF EXISTS old_idx;\n", "old_idx", true},
		// Codex r3: a partial index with a literal is a normal migration; with no `;` inside, it is one statement.
		{noTransactionMarker + "\nCREATE INDEX CONCURRENTLY active_idx ON jobs (id) WHERE status = 'active';\n", "active_idx", false},
	}
	for _, c := range cases {
		f, err := classify(t, "0100_x.sql", c.sql)
		if err != nil {
			t.Errorf("%q refused: %v", c.sql, err)
			continue
		}
		if !f.NoTransaction || f.IndexName != c.index || f.IndexDrop != c.drop {
			t.Errorf("%q classified as %+v, want index %s drop=%v", c.sql, f, c.index, c.drop)
		}
		// The runner executes Statement, never the raw file: no comment line, marker or trailing semicolon.
		if strings.Contains(f.Statement, "--") || strings.Contains(f.Statement, ";") || strings.HasPrefix(f.Statement, " ") {
			t.Errorf("%q: executed statement %q carries more than the statement", c.sql, f.Statement)
		}
	}
}

func TestClassifyMigrationLeavesOrdinaryFilesTransactional(t *testing.T) {
	// 0011's comment says "lands concurrently"; prose in a comment is not a concurrent build.
	f, err := classify(t, "0011_x.sql", "-- an INDEX CONCURRENTLY note in a comment\nCREATE INDEX a_idx ON t(a);\n")
	if err != nil || f.NoTransaction {
		t.Fatalf("ordinary file = %+v, %v; want transactional, no error", f, err)
	}
}

func TestClassifyMigrationRefusesUnverifiableShapes(t *testing.T) {
	m := noTransactionMarker + "\n"
	cases := map[string]string{
		"marker not on the first line":       "-- note\n" + m + "CREATE INDEX CONCURRENTLY a ON t(a);",
		"two statements":                     m + "CREATE INDEX CONCURRENTLY a ON t(a);\nCREATE INDEX CONCURRENTLY b ON t(b);",
		"IF NOT EXISTS on create (Codex r7)": m + "CREATE INDEX CONCURRENTLY IF NOT EXISTS a ON t(a);",
		"no IF EXISTS on drop":               m + "DROP INDEX CONCURRENTLY a;",
		"not concurrent":                     m + "CREATE INDEX IF NOT EXISTS a ON t(a);",
		"other DDL":                          m + "ALTER TABLE t ADD COLUMN c int;",
		"schema-qualified table":             m + "CREATE INDEX CONCURRENTLY a ON public.t(a);",
		"schema-qualified drop":              m + "DROP INDEX CONCURRENTLY IF EXISTS public.a;",
		"quoted name":                        m + `CREATE INDEX CONCURRENTLY "A" ON t(a);`,
		"empty":                              m,
		// Codex r2: Postgres folds unquoted identifiers to lower case, so an upper-case one would be verified
		// under the wrong name.
		"upper-case index name":        m + "CREATE INDEX CONCURRENTLY I ON t(a);",
		"upper-case table name":        m + "CREATE INDEX CONCURRENTLY i ON T(a);",
		"comment inside the statement": m + "CREATE INDEX CONCURRENTLY i\n-- note\nON t(a);",
		"bare CR ending a comment":     m + "-- explanation\rSELECT 1;\nCREATE INDEX CONCURRENTLY i ON t(id);",
	}
	for what, sql := range cases {
		if _, err := classify(t, "0100_x.sql", sql); err == nil {
			t.Errorf("%s: accepted %q", what, sql)
		} else if !strings.Contains(err.Error(), "0100_x.sql") {
			t.Errorf("%s: error does not name the file: %v", what, err)
		}
	}
}

// LoadMigrations applies the rules, so a bad file stops the whole run before anything is applied.
func TestLoadMigrationsRefusesAMalformedNoTransactionFile(t *testing.T) {
	dir := writeMigrationDir(t, map[string]string{
		"0001_a.sql": `CREATE TABLE a (id int);`,
		"0002_b.sql": noTransactionMarker + "\nCREATE INDEX CONCURRENTLY IF NOT EXISTS b_idx ON a(id);",
	})
	if _, err := LoadMigrations(dir); err == nil {
		t.Fatal("a no-transaction CREATE with IF NOT EXISTS loaded")
	}
}

// Codex r1: the classifier records the table and UNIQUE, so the runner can verify the index it finds is THIS one.
func TestClassifyMigrationRecordsTheTableAndUniqueness(t *testing.T) {
	f, err := classify(t, "0100_x.sql", noTransactionMarker+"\nCREATE UNIQUE INDEX CONCURRENTLY u_idx ON only audit_event (a);")
	if err != nil || f.IndexTable != "audit_event" || !f.IndexUnique || f.IndexName != "u_idx" {
		t.Fatalf("got %+v, %v", f, err)
	}
	f, err = classify(t, "0100_x.sql", noTransactionMarker+"\nCREATE INDEX CONCURRENTLY p_idx ON t USING btree (a);")
	if err != nil || f.IndexTable != "t" || f.IndexUnique {
		t.Fatalf("got %+v, %v", f, err)
	}
}

// Codex r1-r5: THE invariant. Whatever a file hides from a line-based reading (a block comment, a `--` line inside a
// multi-line literal, a bare CR), the text the runner EXECUTES never carries a second statement: it is refused, or
// it is a single fragment with no `;` (an unterminated literal or comment, which Postgres rejects at apply time:
// a safe failure, never recorded).
func TestNoTransactionExecutedTextNeverCarriesASecondStatement(t *testing.T) {
	m := noTransactionMarker + "\n"
	for _, sql := range []string{
		m + "CREATE INDEX CONCURRENTLY i ON t ((length('\n-- '))); SELECT 1;",
		m + "CREATE INDEX CONCURRENTLY i ON t(id) /*\n-- */; SELECT 1;",
		m + "-- explanation\rSELECT 1;\nCREATE INDEX CONCURRENTLY i ON t(id);",
		m + "CREATE INDEX CONCURRENTLY i ON t(id);\n-- x'; SELECT 1; --",
	} {
		f, err := classify(t, "0100_x.sql", sql)
		if err == nil && (strings.Contains(f.Statement, ";") || strings.Contains(f.Statement, "SELECT 1")) {
			t.Errorf("%q: executes %q, which carries a second statement", sql, f.Statement)
		}
	}
}

// Codex r5: a comment after the statement is a normal migration; it is not executed.
func TestClassifyMigrationAcceptsATrailingComment(t *testing.T) {
	f, err := classify(t, "0100_x.sql", noTransactionMarker+"\nCREATE INDEX CONCURRENTLY jobs_idx ON jobs (id);\n-- Supports the maintenance query.\n")
	if err != nil || f.Statement != "CREATE INDEX CONCURRENTLY jobs_idx ON jobs (id)" {
		t.Fatalf("got %+v, %v", f, err)
	}
}

// Codex r1/r2 Q2: transactional files are not screened for concurrent builds: text cannot tell a statement from
// prose inside a (multi-line) literal, and a misplaced concurrent build fails safely at apply time.
func TestClassifyMigrationMatchesStatementsNotProse(t *testing.T) {
	for _, sql := range []string{
		"COMMENT ON TABLE audit_event IS 'Build its index concurrently during maintenance';\n",
		"COMMENT ON TABLE t IS $doc$\nCREATE INDEX CONCURRENTLY during maintenance.\n$doc$;\n",
	} {
		if f, err := classify(t, "0100_x.sql", sql); err != nil || f.NoTransaction {
			t.Fatalf("%q = %+v, %v; want an ordinary transactional file", sql, f, err)
		}
	}
}

// Codex r4: the executed statement is byte-for-byte the file's statement, so a CR inside a literal (part of an
// index predicate) is not rewritten; leading comment lines with any line ending are still dropped.
func TestNoTransactionStatementPreservesTheStatementBytes(t *testing.T) {
	stmt := "CREATE INDEX CONCURRENTLY n_idx ON t (id) WHERE note = 'a\rb\r\nc'"
	f, err := classify(t, "0100_x.sql", noTransactionMarker+"\r\n-- why\rthis\n\n"+stmt+";\r\n")
	if err == nil {
		t.Fatalf("a bare CR ends a comment, so `this` starts the statement; got %+v", f)
	}
	f, err = classify(t, "0100_x.sql", noTransactionMarker+"\r\n-- why\r-- more\n\n"+stmt+";\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if f.Statement != stmt {
		t.Fatalf("executed statement %q, want the file's bytes %q", f.Statement, stmt)
	}
}

// Codex r6 #2: `; -- note` after the statement on its last line is a normal migration.
func TestClassifyMigrationAcceptsAnInlineTrailingComment(t *testing.T) {
	f, err := classify(t, "0100_x.sql", noTransactionMarker+"\nCREATE INDEX CONCURRENTLY i ON t (id); -- supports lookup\n")
	if err != nil || f.Statement != "CREATE INDEX CONCURRENTLY i ON t (id)" {
		t.Fatalf("got %+v, %v", f, err)
	}
}

// Codex r7: the statement terminator is the FIRST ';' on the last line followed only by a comment; the comment may
// itself contain ';'.
func TestClassifyMigrationAcceptsASemicolonInsideTheTrailingComment(t *testing.T) {
	f, err := classify(t, "0100_x.sql", noTransactionMarker+"\nCREATE INDEX CONCURRENTLY i ON t (id); -- supports lookup; retain for reporting\n")
	if err != nil || f.Statement != "CREATE INDEX CONCURRENTLY i ON t (id)" {
		t.Fatalf("got %+v, %v", f, err)
	}
}
