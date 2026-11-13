package controlplane

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Inspect decoded SQL literals rather than Go source comments: a comment describing a fence
// is not a lock. A helper containing credential SQL is checked in its own function, so a
// caller's unrelated lock cannot accidentally bless an unfenced helper.
var credentialGuardTable = regexp.MustCompile(`(?i)\buser_credential\b`)
var credentialGuardWrite = regexp.MustCompile(`(?is)\b(?:insert\s+into|update|delete\s+from|merge\s+into|truncate(?:\s+table)?)\s+(?:only\s+)?(?:[a-z_][a-z_0-9]*\s*\.\s*)?user_credential\b`)
var credentialGuardFence = regexp.MustCompile(`(?is)^\s*select\s+1\s+from\s+app_user\s+where\s+id\s*=\s*\$[1-9][0-9]*(?:::uuid)?\s+for\s+update\s*;?\s*$`)
var credentialGuardRead = regexp.MustCompile(`(?is)^\s*select\b`)
var credentialGuardSQLComments = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\r\n]*`)

// Only execution arguments count as SQL. Constants may be assembled from other
// constants, but runtime construction in a credential writer must fail closed.
type credentialGuardExecution struct {
	call     *ast.CallExpr
	receiver ast.Expr
	text     string
	constant bool
}

func credentialGuardExpr(e ast.Expr) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), e)
	return b.String()
}

func credentialGuardFold(e ast.Expr, active map[*ast.Object]bool) (string, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return credentialGuardFold(x.X, active)
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			s, err := strconv.Unquote(x.Value)
			return s, err == nil
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			a, ok := credentialGuardFold(x.X, active)
			b, ok2 := credentialGuardFold(x.Y, active)
			return a + b, ok && ok2
		}
	case *ast.Ident:
		if x.Obj == nil || x.Obj.Kind != ast.Con || active[x.Obj] {
			return "", false
		}
		v, ok := x.Obj.Decl.(*ast.ValueSpec)
		if !ok {
			return "", false
		}
		active[x.Obj] = true
		defer delete(active, x.Obj)
		for i, name := range v.Names {
			if name.Name == x.Name && i < len(v.Values) {
				return credentialGuardFold(v.Values[i], active)
			}
		}
	}
	return "", false
}

func credentialGuardExecutionOf(n ast.Node) (credentialGuardExecution, bool) {
	c, ok := n.(*ast.CallExpr)
	if !ok {
		return credentialGuardExecution{}, false
	}
	m, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || (m.Sel.Name != "Exec" && m.Sel.Name != "Query" && m.Sel.Name != "QueryRow") || len(c.Args) < 2 {
		return credentialGuardExecution{}, false
	}
	s, constant := credentialGuardFold(c.Args[1], make(map[*ast.Object]bool))
	s = strings.ReplaceAll(credentialGuardSQLComments.ReplaceAllString(s, " "), `"`, "")
	return credentialGuardExecution{c, m.X, s, constant}, true
}

// The SQL placeholder determines which Go argument names the locked/written user.
var credentialGuardUser = regexp.MustCompile(`(?i)\b(?:user_id|u\s*\.\s*id|id)\s*=\s*\$([1-9][0-9]*)`)

func credentialGuardUserArg(q credentialGuardExecution) string {
	m := credentialGuardUser.FindStringSubmatch(q.text)
	if len(m) != 2 {
		return ""
	}
	n, _ := strconv.Atoi(m[1])
	if n+1 >= len(q.call.Args) {
		return ""
	}
	return credentialGuardExpr(q.call.Args[n+1])
}

func credentialGuardAborts(s *ast.IfStmt, name string) bool {
	b, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || b.Op != token.NEQ || credentialGuardExpr(b.X) != name || credentialGuardExpr(b.Y) != "nil" || s.Else != nil || len(s.Body.List) == 0 {
		return false
	}
	// A final unconditional return also permits production's earlier error mapping.
	_, ok = s.Body.List[len(s.Body.List)-1].(*ast.ReturnStmt)
	return ok
}

func credentialGuardCheckedFence(body *ast.BlockStmt, index int, q credentialGuardExecution) bool {
	stmt := body.List[index]
	var assignment *ast.AssignStmt
	var check *ast.IfStmt
	switch x := stmt.(type) {
	case *ast.IfStmt:
		assignment, _ = x.Init.(*ast.AssignStmt)
		check = x
	case *ast.AssignStmt:
		assignment = x
		if index+1 < len(body.List) {
			check, _ = body.List[index+1].(*ast.IfStmt)
			// `if err := other(); err != nil` would test a SHADOWING err, not the fence's: the check
			// that follows an assignment must have no initializer of its own.
			if check != nil && check.Init != nil {
				check = nil
			}
		}
	}
	if assignment == nil || check == nil || len(assignment.Rhs) != 1 || len(assignment.Lhs) == 0 {
		return false
	}
	name, ok := assignment.Lhs[len(assignment.Lhs)-1].(*ast.Ident)
	if !ok || name.Name == "_" || !credentialGuardAborts(check, name.Name) {
		return false
	}
	// QueryRow is not executed to completion until Scan checks its error.
	expr := assignment.Rhs[0]
	if m := q.call.Fun.(*ast.SelectorExpr); m.Sel.Name == "QueryRow" {
		scan, ok := expr.(*ast.CallExpr)
		if !ok {
			return false
		}
		selector, ok := scan.Fun.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "Scan" && selector.X == q.call
	}
	return expr == q.call
}

// credentialGuardDynamicSQLAllowed lists functions whose SQL is assembled at run time and was reviewed
// to never touch user_credential. Key: "<file>:<func>". Every entry needs its reason.
var credentialGuardDynamicSQLAllowed = map[string]string{
	"migrate.go:applyOne":                            "executes migration files; schema changes are reviewed as migrations, not runtime writers",
	"migrate.go:ProvisionAppRolePassword":            "ALTER ROLE for the rmt_app login password; no table write",
	"pgstore.go:ListAuditEventsAsc":                  "appends fixed predicates/paging to a SELECT over audit_event",
	"pgstore_credential_token.go:byHash":             "SELECT over user_credential_token chosen by its callers; read-only",
	"pgstore_dataplane.go:ListEventsFiltered":        "appends fixed predicates to a SELECT over audit_event",
	"pgstore_dataplane.go:SummarizeByAction":         "appends fixed predicates to a SELECT over audit_event",
	"pgstore_oidc.go:oidcLockConnectionMode":         "appends only a lock-strength clause to a SELECT on tenant_oidc",
	"pgstore_oidc.go:oidcLockUser":                   "appends only a lock-strength clause to a SELECT on app_user",
	"pgstore_help_request.go:Accept":                 "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:CancelForDevice":        "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:CancelForMachine":       "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:CreateForDevice":        "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:CurrentForDevice":       "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:Get":                    "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:ListOpen":               "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:ReopenAfterFailedStart": "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_help_request.go:reopenOnce":             "the body of ReopenAfterFailedStart (one attempt): splices the fixed help_request column list (helpColsP); never names user_credential",
	"pgstore_help_request.go:MarkDelivered":          "splices the fixed help_request column list (helpColsP) into an UPDATE/SELECT over help_request; never names user_credential",
	"pgstore_help_request.go:expireDueTx":            "splices the fixed help_request column list (helpColsP) into SELECT/UPDATE over help_request; never names user_credential",
	"pgstore_recording.go:loadRecording":             "appends only a fixed lock-strength clause (\"\", FOR SHARE, FOR UPDATE) to a SELECT on session_recording",
}

func credentialFenceViolations(filename string, source []byte) ([]string, error) {
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, filename, source, 0)
	if err != nil {
		return nil, err
	}
	var failures []string
	fail := func(pos token.Pos, message string) {
		failures = append(failures, fmt.Sprintf("%s: %s", fs.Position(pos), message))
	}
	var inspectBody func(string, *ast.BlockStmt)
	inspectBody = func(fnName string, body *ast.BlockStmt) {
		var executions []credentialGuardExecution
		var nested []*ast.BlockStmt
		ast.Inspect(body, func(n ast.Node) bool {
			if f, ok := n.(*ast.FuncLit); ok {
				nested = append(nested, f.Body)
				return false
			}
			if q, ok := credentialGuardExecutionOf(n); ok {
				executions = append(executions, q)
			}
			return true
		})
		writer := false
		for _, q := range executions {
			writer = writer || (q.constant && credentialGuardWrite.MatchString(q.text))
		}
		for _, q := range executions {
			if !q.constant {
				// SQL the guard cannot fold could name user_credential, so it is refused EVERYWHERE unless
				// the function is on the reviewed allow-list (whose entries say why it cannot write
				// credentials). Inside a credential-writing body it is refused even then.
				if _, allowed := credentialGuardDynamicSQLAllowed[filepath.Base(filename)+":"+fnName]; writer || !allowed {
					fail(q.call.Pos(), "nonconstant SQL execution ("+fnName+"); fold it to constants or allow-list it with a reason")
				}
				continue
			}
			if !credentialGuardTable.MatchString(q.text) {
				continue
			}
			if !credentialGuardWrite.MatchString(q.text) {
				if !credentialGuardRead.MatchString(q.text) || strings.Contains(q.text, ";") {
					fail(q.call.Pos(), "unsupported credential SQL; extend the guard explicitly")
				}
				continue
			}
			fenced := false
			for i, stmt := range body.List {
				if stmt.End() >= q.call.Pos() {
					break
				}
				ast.Inspect(stmt, func(n ast.Node) bool {
					f, ok := credentialGuardExecutionOf(n)
					if ok && f.constant && credentialGuardFence.MatchString(f.text) &&
						credentialGuardExpr(f.receiver) == credentialGuardExpr(q.receiver) &&
						credentialGuardUserArg(q) != "" && credentialGuardUserArg(f) == credentialGuardUserArg(q) &&
						credentialGuardCheckedFence(body, i, f) {
						fenced = true
					}
					return true
				})
			}
			if !fenced {
				fail(q.call.Pos(), "credential write lacks checked preceding fence for the same transaction and user")
			}
		}
		for _, b := range nested {
			inspectBody(fnName, b)
		}
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Body != nil {
				inspectBody(fn.Name.Name, fn.Body)
			}
			continue
		}
		// Unexecuted package SQL cannot establish ordering. Preserve the explicit
		// rejection of package-level write definitions, including concatenations.
		ast.Inspect(decl, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok {
				if s, constant := credentialGuardFold(e, make(map[*ast.Object]bool)); constant && credentialGuardWrite.MatchString(strings.ReplaceAll(credentialGuardSQLComments.ReplaceAllString(s, " "), `"`, "")) {
					fail(e.Pos(), "credential-writing SQL outside a function requires an explicit guard implementation")
					return false
				}
			}
			return true
		})
	}
	return failures, nil
}

func TestCredentialWritersHaveUserFence(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		failures, err := credentialFenceViolations(name, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, failure := range failures {
			t.Error(failure)
		}
	}
}

func TestCredentialFenceGuardFixtures(t *testing.T) {
	fence := "if err := tx.QueryRow(ctx, `SELECT 1 FROM app_user WHERE id = $1 FOR UPDATE`, user).Scan(&one); err != nil { return err };\n"
	writer := "_, err := tx.Exec(ctx, `UPDATE user_credential SET updated_at=clock_timestamp() WHERE user_id=$1`, user); return err"
	cases := []struct {
		name, body string
		fail       bool
	}{
		{"fenced", fence + writer, false},
		{"split-identifier", "_, err := tx.Exec(ctx, `UPDATE user_`+`credential SET updated_at=now() WHERE user_id=$1`, user); return err", true},
		{"ignored-fence-error", "_, _ = tx.Exec(ctx, `SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE`, user);" + writer, true},
		{"different-transaction", strings.ReplaceAll(fence, "tx.QueryRow", "otherTx.QueryRow") + writer, true},
		{"different-user", strings.ReplaceAll(fence, ", user)", ", otherUser)") + writer, true},
		{"folded-local-constants", "const table = `user_` + `credential`; const update = `UPDATE ` + table;" + fence + "_, err := tx.Exec(ctx, update + ` SET updated_at=now() WHERE user_id=$1`, user); return err", false},
		{"dynamic-execution", fence + "_, _ = tx.Exec(ctx, dynamicSQL);" + writer, true},
		{"checked-exec-fence", "_, err := tx.Exec(ctx, `SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE`, user); if err != nil { return err };" + strings.Replace(writer, "_, err :=", "_, err =", 1), false},
		{"multiline", fence + "_, err := tx.Exec(ctx, `INSERT\n INTO user_credential (user_id, tenant_id, password_hash)\n SELECT u.id, u.tenant_id, $2 FROM app_user u WHERE u.id = $1\n ON CONFLICT (user_id) DO UPDATE SET updated_at=now()`, user, hash); return err", false},
		// INSERT ... VALUES names the user only positionally, so the guard cannot tie the write to the
		// fence's user: it fails closed (the production upsert uses the INSERT ... SELECT form above).
		// A body whose ONLY credential write is assembled at run time must not pass for lack of a
		// constant write to trigger the check.
		{"dynamic-only-write", "sql := `UPDATE user_` + tableSuffix; _, err := tx.Exec(ctx, sql, user); return err", true},
		// The check after the fence must test the fence's own err, not a shadowing one.
		{"shadowed-fence-error", "_, err := tx.Exec(ctx, `SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE`, user); if err := other(); err != nil { return err };" + strings.Replace(writer, "_, err :=", "_, err =", 1), true},
		{"values-insert", fence + "_, err := tx.Exec(ctx, `INSERT INTO user_credential (user_id) VALUES ($1)`, user); return err", true},
		{"unfenced", writer, true},
		{"delete", "_, err := tx.Exec(ctx, `DELETE FROM user_credential WHERE user_id=$1`, user); return err", true},
		{"late", writer + ";" + fence, true},
		{"comment", "// SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE\n" + writer, true},
		{"sql-comment", "_, _ = tx.Exec(ctx, `/* SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE */ SELECT 1`);" + writer, true},
		{"unused-string", "_ = `SELECT 1 FROM app_user WHERE id=$1 FOR UPDATE`;" + writer, true},
		{"conditional", "if ready { " + fence + " };" + writer, true},
		{"sibling-closure", "_ = func() { " + fence + " }; _ = func() error { " + writer + " }; return nil", true},
		{"helper", fence + "return helper() }; func helper() error { " + writer, true},
		{"quoted", "_, err := tx.Exec(ctx, `UPDATE \"public\".\"user_credential\" SET updated_at=now()`); return err", true},
		{"unsupported", "_, err := tx.Exec(ctx, `WITH doomed AS (SELECT 1) DELETE FROM ONLY user_credential`); return err", true},
		{"split", "_, err := tx.Exec(ctx, `UPDATE `+`user_credential`+` SET updated_at=now()`); return err", true},
		{"read", "return tx.QueryRow(ctx, `SELECT updated_at FROM user_credential WHERE user_id=$1`, user).Scan(&epoch)", false},
		{"token-table", "_, err := tx.Exec(ctx, `UPDATE user_credential_token SET used_at=now()`); return err", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := []byte("package p\nfunc writer() error { " + tc.body + " }")
			failures, err := credentialFenceViolations("fixture.go", source)
			if err != nil {
				t.Fatal(err)
			}
			if (len(failures) > 0) != tc.fail {
				t.Fatalf("failures=%v, want failure=%v", failures, tc.fail)
			}
		})
	}
	failures, err := credentialFenceViolations("constant.go", []byte("package p\nconst sql = `UPDATE user_credential SET updated_at=now()`"))
	if err != nil || len(failures) == 0 {
		t.Fatalf("external SQL constant: %v, %v", failures, err)
	}
}
