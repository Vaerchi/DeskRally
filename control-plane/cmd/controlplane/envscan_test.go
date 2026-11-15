package main

// Env-read scanner and compose rule shared by compose_env_test.go.
//
// THIS FILE IS BYTE-IDENTICAL in control-plane/cmd/controlplane, server/signaling and server/relay. They
// are separate Go modules (a shared package would need a cross-module replace in each go.mod and the
// Docker builds), so the scanner is copied and compose_env_test.go asserts the copies have not drifted.
// Change one, change all three (copy the file over the others).
//
// THE SUPPORTED MODEL. The scan is syntactic (go/parser) and deliberately a small, provable subset: a loud
// false failure is acceptable, a silent miss is not. Anything outside the subset is reported, never skipped.
//
//  1. An env read is a call os.Getenv(name) / os.LookupEnv(name) (syscall alike; os and syscall are treated
//     alike, under any import alias). A dot-import of os or syscall is a failure.
//  2. A NAME resolves only from a string literal, a package-level CONST, or a concatenation of those. It never
//     resolves from a var (package-level or local: a package var can be reassigned from anywhere, so a var
//     is not an identity), a parameter, a struct field or a computed value. Such a name is reported.
//  3. A HELPER is a plain function (no receiver) with a string parameter that flows directly into an env
//     read or into a slot of another helper; calls to it must name a constant. Helpers are keyed by
//     (package directory, function name). A parameter the function assigns or takes the address of is not a
//     slot. A METHOD whose parameter flows into an env read is a failure (env-reading methods are
//     unsupported; use a function), which also closes method expressions (T.m(recv, args...) shifts slots).
//  4. A reference to a helper, or to os/syscall Getenv/LookupEnv, that is not the callee of a direct call
//     (an alias, an argument, a return, a store, a send, a method value) is a failure; the scan does not
//     model aliasing, it refuses it. The one exception is the explicit readerExemptions table: a listed
//     function takes the reader as a func(string) string parameter, may use it ONLY as the direct callee
//     of calls whose argument is a literal or const, and the names it calls with must EQUAL the table entry.
//     The call site that hands such a function os.Getenv is then accepted and records those names.
//  5. PACKAGE IDENTITY IS THE DIRECTORY, not the package name. Constants, helpers and exemptions are keyed by
//     directory. pkg.Name binds only when pkg is an import in that file whose IMPORT PATH maps (scanConfig.
//     Imports, from `go list`) to a scanned directory; the local name is the import's explicit name or the
//     package name declared in that directory. A call or reference to a name that matches any helper or
//     exemption but is not bound to one (a method, a field, an unmapped package) is a failure.
//  6. OUTSIDE THE MODEL (not detected, except where stated): unsafe pointer tricks, assembly, go:linkname
//     (a //go:linkname directive and import "C" are reported), cgo getenv, reflection, os/exec children
//     and third-party getenv wrappers (golang.org/x/sys). Code reading the environment that way is not seen.
//     Nor are IMPLICIT reads by the standard library and dependencies (HTTP_PROXY/NO_PROXY via
//     http.ProxyFromEnvironment, HOME/TMP via os.UserHomeDir/TempDir, PATH via exec.LookPath, pgx's PG*
//     variables): they are not this deployment's knobs, and compose need not forward them.
//  7. A package-level name declared more than once in a directory (per build-tag file) never resolves.
//
// TestScanDirsCoverEveryModulePackage asks the toolchain which of this module's packages the binary
// compiles, so a new package that reads the environment cannot be left out of scanDirs.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// envRead is one resolved env read: the variable, where it is read, and the top-level function ("" for a
// package-level declaration) that makes the read.
type envRead struct{ Name, Where, Func string }

type scanResult struct {
	Reads      []envRead
	Unresolved []string
}

// envExemption lets ONE function take os.Getenv as a value. Dir is the package directory (a path suffix,
// matched on a directory boundary: "control-plane"), Func the function, Names the exact set of variables it
// reads through its func(string) string parameter. An entry whose Dir is not among the scanned directories
// is inactive (the other binaries' copies of this file carry the same table).
type envExemption struct {
	Dir, Func string
	Names     []string
}

// readerExemptions: the known readers. Adding a name inside the function, or a new function that is handed
// os.Getenv, fails the scan until this table says so.
var readerExemptions = []envExemption{
	{"control-plane", "RecordingKeyringFromEnv", []string{"RECORDING_MASTER_KEY", "RECORDING_MASTER_KEY_ID", "RECORDING_MASTER_KEY_PREVIOUS"}},
}

// scanConfig: Imports maps an import path of this module to its directory; Exemptions is the reader table.
type scanConfig struct {
	Imports    map[string]string
	Exemptions []envExemption
}

// normDir is the identity of a package directory.
func normDir(d string) string {
	if a, err := filepath.Abs(d); err == nil {
		d = a
	}
	return strings.ToLower(filepath.ToSlash(filepath.Clean(d)))
}

func dirMatches(dir, suffix string) bool {
	suffix = strings.ToLower(filepath.ToSlash(suffix))
	return dir == suffix || strings.HasSuffix(dir, "/"+suffix)
}

// moduleImportDirs asks the toolchain for every package of this module the binary compiles: import path ->
// directory. The scanner binds pkg.Name selectors through it.
func moduleImportDirs(t *testing.T) map[string]string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if .Module}}{{if .Module.Main}}{{.ImportPath}} {{.Dir}}{{end}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ' ')
		if i < 0 {
			t.Fatalf("unexpected go list line %q", line)
		}
		m[line[:i]] = strings.TrimSpace(line[i+1:])
	}
	if len(m) == 0 {
		t.Fatal("go list reported no package of this module: the coverage check is blind")
	}
	return m
}

// parseNonTestFiles parses every non-test .go file in dirs (any build tag: a file for another OS is scanned too).
func parseNonTestFiles(t *testing.T, dirs []string) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			t.Fatal(err)
		}
		ents, err := os.ReadDir(abs)
		if err != nil {
			t.Fatalf("read %s: %v", d, err)
		}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(abs, n), nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", filepath.Join(abs, n), err)
			}
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatalf("scanned no source files in %v: the guard would pass vacuously", dirs)
	}
	return fset, files
}

// parseEnvFiles parses in-memory sources keyed by their path (the scanner's own fixtures); the path's
// directory is the package directory.
func parseEnvFiles(t *testing.T, srcs map[string]string) (*token.FileSet, []*ast.File) {
	t.Helper()
	paths := make([]string, 0, len(srcs))
	for p := range srcs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, srcs[p], parser.ParseComments)
		if err != nil {
			t.Fatalf("parse fixture %s: %v", p, err)
		}
		files = append(files, f)
	}
	return fset, files
}

// parseEnvSources parses in-memory sources that share one directory.
func parseEnvSources(t *testing.T, srcs ...string) (*token.FileSet, []*ast.File) {
	t.Helper()
	m := map[string]string{}
	for i, s := range srcs {
		m["fixture"+strconv.Itoa(i)+".go"] = s
	}
	return parseEnvFiles(t, m)
}

// fkey is a function's identity: its package DIRECTORY and its name.
type fkey struct{ dir, name string }

func markSlot(m map[fkey]map[int]bool, fn fkey, i int) bool {
	if m[fn][i] {
		return false
	}
	if m[fn] == nil {
		m[fn] = map[int]bool{}
	}
	m[fn][i] = true
	return true
}

// paramSlots returns a function's parameter positions keyed by the parameter's DECLARATION (go/parser's scope
// object), not its spelling: a block or closure local that shadows a parameter name is a different object, so
// `{ key := "CP_REAL"; os.Getenv(key) }` inside func(key string) is an unresolved local read, not the helper's
// parameter.
func paramSlots(fd *ast.FuncDecl) map[*ast.Object]int {
	idx := map[*ast.Object]int{}
	i := 0
	for _, fld := range fd.Type.Params.List {
		if len(fld.Names) == 0 {
			i++
			continue
		}
		for _, n := range fld.Names {
			if n.Obj != nil { // nil for "_", which nothing can refer to
				idx[n.Obj] = i
			}
			i++
		}
	}
	// A parameter the function ASSIGNS (anywhere in its body, closures included) or takes the address of no
	// longer carries the caller's value: `key = "CP_REAL"; os.Getenv(key)` reads CP_REAL whatever the caller
	// passed. Such a parameter is not a slot: a read through it is an unresolved local read.
	if fd.Body != nil {
		drop := func(e ast.Expr) {
			for p, ok := e.(*ast.ParenExpr); ok; p, ok = e.(*ast.ParenExpr) {
				e = p.X // (key) = ... and &(key) target the parameter as surely as key = ...
			}
			if id, ok := e.(*ast.Ident); ok && id.Obj != nil {
				delete(idx, id.Obj)
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, l := range v.Lhs {
					drop(l)
				}
			case *ast.IncDecStmt:
				drop(v.X)
			case *ast.UnaryExpr:
				if v.Op == token.AND {
					drop(v.X)
				}
			case *ast.RangeStmt:
				if v.Tok == token.ASSIGN {
					drop(v.Key)
					drop(v.Value)
				}
			}
			return true
		})
	}
	return idx
}

type exemptInfo struct {
	idx   int      // position of the func-typed parameter
	names []string // the exact names the table says it reads
}

func scanEnvFiles(fset *token.FileSet, files []*ast.File, cfg scanConfig) scanResult {
	var res scanResult
	fail := func(p token.Pos, msg string) {
		pos := fset.Position(p)
		res.Unresolved = append(res.Unresolved, filepath.ToSlash(pos.Filename)+":"+strconv.Itoa(pos.Line)+": "+msg)
	}
	whereOf := func(p token.Pos) string {
		pos := fset.Position(p)
		return filepath.ToSlash(pos.Filename) + ":" + strconv.Itoa(pos.Line)
	}

	// Package identity = directory.
	dirOf := map[*ast.File]string{}
	pkgOfDir := map[string]string{}
	funcsByDir := map[string]map[string]bool{} // plain (receiver-less) functions
	for _, f := range files {
		d := normDir(filepath.Dir(fset.Position(f.Pos()).Filename))
		dirOf[f] = d
		if pkgOfDir[d] == "" {
			pkgOfDir[d] = f.Name.Name
		}
		if funcsByDir[d] == nil {
			funcsByDir[d] = map[string]bool{}
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcsByDir[d][fd.Name.Name] = true
			}
		}
	}
	importDirs := map[string]string{}
	for p, d := range cfg.Imports {
		importDirs[p] = normDir(d)
	}

	// Imports: the local names a file gives os/syscall, the scanned directories it can name, and every other
	// import name (so a selector on a std/third-party package is not mistaken for an unbound one).
	osNames := map[*ast.File]map[string]bool{}
	impDir := map[*ast.File]map[string]string{}
	impAny := map[*ast.File]map[string]bool{}
	for _, f := range files {
		osNames[f], impDir[f], impAny[f] = map[string]bool{}, map[string]string{}, map[string]bool{}
		for _, im := range f.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				continue
			}
			name := ""
			if im.Name != nil {
				name = im.Name.Name
			}
			scanned, mapped := importDirs[p]
			mapped = mapped && pkgOfDir[scanned] != ""
			if p == "C" {
				fail(im.Pos(), `import "C": cgo can read the environment outside the syntactic model`)
			}
			switch name {
			case ".":
				if p == "os" || p == "syscall" || mapped {
					fail(im.Pos(), "dot-import of "+p+": its members are called without a selector the scan can see; import it by name")
				}
				continue
			case "_":
				continue
			}
			local := name
			if local == "" {
				if mapped {
					local = pkgOfDir[scanned]
				} else {
					local = p[strings.LastIndexByte(p, '/')+1:]
				}
			}
			impAny[f][local] = true
			if p == "os" || p == "syscall" {
				osNames[f][local] = true
			}
			if mapped {
				impDir[f][local] = scanned
			}
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:linkname") {
					fail(c.Pos(), "//go:linkname reaches runtime/syscall internals outside the syntactic model")
				}
			}
		}
	}

	// osMember reports the member of os/syscall that e selects. A local variable shadowing the package
	// name (x.Obj != nil) is not the package.
	osMember := func(f *ast.File, e ast.Expr) (string, bool) {
		if se, ok := e.(*ast.SelectorExpr); ok {
			if x, ok := se.X.(*ast.Ident); ok && x.Obj == nil && osNames[f][x.Name] {
				return se.Sel.Name, true
			}
		}
		return "", false
	}

	// Package-level string CONSTANTS only, per directory, resolved to a fixed point so const a = b + "X" works.
	// A var never resolves: a package-level var can be reassigned from any file, a local one anywhere.
	type def struct {
		file *ast.File
		name string
		expr ast.Expr
	}
	var defs []def
	topConst := map[*ast.ValueSpec]bool{}
	// A name declared at package level more than once in one directory (a const or var per build-tag file, e.g.
	// a windows and a !windows value) has no single value: every file is scanned whatever its tags, so the
	// read could be either. Such a name never resolves; a read through it is a failure.
	declCount := map[string]map[string]int{} // directory -> package-level const/var name -> declarations
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, id := range vs.Names {
					if declCount[dirOf[f]] == nil {
						declCount[dirOf[f]] = map[string]int{}
					}
					declCount[dirOf[f]][id.Name]++
				}
				if gd.Tok != token.CONST {
					continue
				}
				topConst[vs] = true
				if len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, id := range vs.Names {
					defs = append(defs, def{f, id.Name, vs.Values[i]})
				}
			}
		}
	}
	consts := map[string]map[string]string{} // directory -> constant name -> value
	var resolve func(f *ast.File, e ast.Expr) (string, bool)
	resolve = func(f *ast.File, e ast.Expr) (string, bool) {
		switch v := e.(type) {
		case *ast.ParenExpr:
			return resolve(f, v.X)
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				s, err := strconv.Unquote(v.Value)
				return s, err == nil
			}
		case *ast.Ident:
			if v.Obj != nil {
				if vs, ok := v.Obj.Decl.(*ast.ValueSpec); !ok || !topConst[vs] {
					return "", false // a local declaration, parameter or var: not a package-level const
				}
			}
			if declCount[dirOf[f]][v.Name] > 1 {
				return "", false
			}
			s, ok := consts[dirOf[f]][v.Name]
			return s, ok
		case *ast.SelectorExpr:
			if x, ok := v.X.(*ast.Ident); ok && x.Obj == nil {
				if d, ok := impDir[f][x.Name]; ok {
					if declCount[d][v.Sel.Name] > 1 {
						return "", false
					}
					s, ok := consts[d][v.Sel.Name]
					return s, ok
				}
			}
		case *ast.BinaryExpr:
			if v.Op == token.ADD {
				a, ok1 := resolve(f, v.X)
				b, ok2 := resolve(f, v.Y)
				return a + b, ok1 && ok2
			}
		}
		return "", false
	}
	for changed := true; changed; {
		changed = false
		for _, d := range defs {
			dir := dirOf[d.file]
			if _, done := consts[dir][d.name]; done {
				continue
			}
			if s, ok := resolve(d.file, d.expr); ok {
				if consts[dir] == nil {
					consts[dir] = map[string]string{}
				}
				consts[dir][d.name], changed = s, true
			}
		}
	}

	// bindFun binds a callee/reference expression to a plain function of a scanned directory: an identifier
	// in the same directory (a local variable of the same name is not it) or pkg.F through an import.
	bindFun := func(f *ast.File, e ast.Expr) (fkey, bool) {
		switch v := e.(type) {
		case *ast.Ident:
			if v.Obj != nil {
				if _, ok := v.Obj.Decl.(*ast.FuncDecl); !ok {
					return fkey{}, false
				}
			}
			d := dirOf[f]
			return fkey{d, v.Name}, funcsByDir[d][v.Name]
		case *ast.SelectorExpr:
			if x, ok := v.X.(*ast.Ident); ok && x.Obj == nil {
				if d, ok := impDir[f][x.Name]; ok {
					return fkey{d, v.Sel.Name}, funcsByDir[d][v.Sel.Name]
				}
			}
		}
		return fkey{}, false
	}

	// helper[k][i]: plain function k's string parameter i reaches an env read (directly or through another
	// helper). Methods are never helpers.
	helper := map[fkey]map[int]bool{}
	nameArgs := func(f *ast.File, c *ast.CallExpr) []ast.Expr {
		if m, ok := osMember(f, c.Fun); ok && (m == "Getenv" || m == "LookupEnv") {
			if len(c.Args) == 0 {
				return []ast.Expr{nil}
			}
			return c.Args[:1]
		}
		var out []ast.Expr
		if k, ok := bindFun(f, c.Fun); ok {
			for i := range helper[k] {
				if i < len(c.Args) {
					out = append(out, c.Args[i])
				} else {
					out = append(out, nil)
				}
			}
		}
		return out
	}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil || fd.Recv != nil {
					continue
				}
				pidx := paramSlots(fd)
				self := fkey{dirOf[f], fd.Name.Name}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						for _, a := range nameArgs(f, c) {
							if id, ok := a.(*ast.Ident); ok {
								if i, isParam := pidx[id.Obj]; isParam && markSlot(helper, self, i) {
									changed = true
								}
							}
						}
					}
					return true
				})
			}
		}
	}

	// The reader exemptions: validate each active entry against the function it names.
	exempt := map[fkey]exemptInfo{}
	anyName := map[string]bool{} // every helper and exemption name, wherever declared
	for k := range helper {
		if len(helper[k]) > 0 {
			anyName[k.name] = true
		}
	}
	for _, e := range cfg.Exemptions {
		anyName[e.Func] = true
		type found struct {
			f  *ast.File
			fd *ast.FuncDecl
		}
		var hits []found
		active := false
		for d := range pkgOfDir {
			if dirMatches(d, e.Dir) {
				active = true
			}
		}
		if !active {
			continue
		}
		for _, f := range files {
			if !dirMatches(dirOf[f], e.Dir) {
				continue
			}
			for _, decl := range f.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == e.Func {
					hits = append(hits, found{f, fd})
				}
			}
		}
		label := "reader exemption " + e.Dir + "." + e.Func
		if len(hits) != 1 {
			res.Unresolved = append(res.Unresolved, "envscan: "+label+": must exist exactly once, found "+strconv.Itoa(len(hits)))
			continue
		}
		f, fd := hits[0].f, hits[0].fd
		fi, nfunc, i := -1, 0, 0
		var pobj *ast.Object
		for _, fld := range fd.Type.Params.List {
			_, isFn := fld.Type.(*ast.FuncType)
			n := len(fld.Names)
			if n == 0 {
				n = 1
			}
			if isFn {
				nfunc += n
				fi = i
				if len(fld.Names) > 0 {
					pobj = fld.Names[0].Obj
				}
			}
			i += n
		}
		k := fkey{dirOf[f], e.Func}
		if nfunc != 1 || pobj == nil || fd.Body == nil {
			fail(fd.Pos(), label+": must have exactly one named func-typed parameter")
			continue
		}
		exempt[k] = exemptInfo{fi, e.Names}
		calleeOK := map[*ast.Ident]bool{}
		got := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CallExpr:
				if id, ok := v.Fun.(*ast.Ident); ok && id.Obj == pobj {
					calleeOK[id] = true
					if len(v.Args) == 1 {
						if s, ok := resolve(f, v.Args[0]); ok {
							got[s] = true
							break
						}
					}
					fail(v.Pos(), label+": its reader parameter is called with a name that is not a literal or package-level const")
				}
			case *ast.Ident:
				if v.Obj == pobj && !calleeOK[v] {
					fail(v.Pos(), label+": its reader parameter is used other than as the direct callee of a call (alias, return, store, send, address, reassignment, pass-on)")
				}
			}
			return true
		})
		want := map[string]bool{}
		for _, n := range e.Names {
			want[n] = true
		}
		same := len(got) == len(want)
		for n := range got {
			if !want[n] {
				same = false
			}
		}
		if !same {
			var g, w []string
			for n := range got {
				g = append(g, n)
			}
			for n := range want {
				w = append(w, n)
			}
			sort.Strings(g)
			sort.Strings(w)
			fail(fd.Pos(), label+": reads "+strings.Join(g, ",")+" but readerExemptions lists "+strings.Join(w, ",")+"; make them equal")
		}
	}

	// The final pass: record reads, report everything the scan cannot follow.
	for _, f := range files {
		dir := dirOf[f]
		for _, decl := range f.Decls {
			fdName, isMethod := "", false
			var pidx map[*ast.Object]int
			okSel := map[ast.Node]bool{}
			declared := map[*ast.Ident]bool{} // identifiers that declare or select a name rather than refer to one
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fdName, isMethod = fd.Name.Name, fd.Recv != nil
				pidx = paramSlots(fd)
				declared[fd.Name] = true
			}
			self := fkey{dir, fdName}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.Field:
					for _, id := range v.Names {
						declared[id] = true
					}
				case *ast.Ident:
					if declared[v] {
						return true
					}
					if v.Obj != nil {
						if _, isFn := v.Obj.Decl.(*ast.FuncDecl); !isFn {
							return true // a local variable, parameter, type or label of that name
						}
					}
					k := fkey{dir, v.Name}
					_, isExempt := exempt[k]
					switch {
					case funcsByDir[dir][v.Name]:
						if (len(helper[k]) > 0 || isExempt) && !okSel[v] {
							fail(v.Pos(), v.Name+" reads an env var and is used as a value; call it directly with a constant name")
						}
					case anyName[v.Name]:
						fail(v.Pos(), v.Name+" matches an env-reading helper or reader exemption but is not bound to it (no such function in this package directory); the scan refuses it")
					}
				case *ast.CallExpr:
					okSel[v.Fun] = true
					g := ""
					switch fn := v.Fun.(type) {
					case *ast.Ident:
						g = fn.Name
					case *ast.SelectorExpr:
						g = fn.Sel.Name
					}
					where := whereOf(v.Pos())
					if k, ok := bindFun(f, v.Fun); ok {
						if ex, isEx := exempt[k]; isEx && ex.idx < len(v.Args) {
							if m, ok := osMember(f, v.Args[ex.idx]); ok && m == "Getenv" {
								okSel[v.Args[ex.idx]] = true // handed to a listed reader; its names are fixed by the table
								for _, name := range ex.names {
									res.Reads = append(res.Reads, envRead{name, where, fdName})
								}
							}
						}
					}
					for _, a := range nameArgs(f, v) {
						if id, ok := a.(*ast.Ident); ok {
							if i, isParam := pidx[id.Obj]; isParam {
								if isMethod {
									fail(v.Pos(), fdName+" is a method whose parameter flows into an env read: env-reading methods are unsupported; use a function")
									continue
								}
								if helper[self][i] {
									continue // a helper's own parameter: its callers are scanned
								}
							}
						}
						if a != nil {
							if name, ok := resolve(f, a); ok {
								res.Reads = append(res.Reads, envRead{name, where, fdName})
								continue
							}
						}
						fail(v.Pos(), g+" reads an env var whose name this guard cannot resolve to a constant "+
							"(a variable, parameter, computed value or missing argument); name it with a literal or package-level const")
					}
				case *ast.SelectorExpr:
					declared[v.Sel] = true
					x, xIdent := v.X.(*ast.Ident)
					if xIdent && x.Obj != nil {
						xIdent = false // a local variable, not a package name
					}
					if m, ok := osMember(f, v); ok {
						declared[x] = true
						pkg := x.Name
						switch {
						case m == "Environ" || m == "ExpandEnv" || m == "Expand":
							fail(v.Pos(), pkg+"."+m+" reads the environment by names this guard cannot see")
						case (m == "Getenv" || m == "LookupEnv") && !okSel[v]:
							fail(v.Pos(), pkg+"."+m+" is used as a value the guard cannot follow "+
								"(only a function listed in readerExemptions may be handed it, and only os.Getenv)")
						}
						return true
					}
					if xIdent {
						if d, ok := impDir[f][x.Name]; ok {
							declared[x] = true
							k := fkey{d, v.Sel.Name}
							_, isExempt := exempt[k]
							if funcsByDir[d][v.Sel.Name] && (len(helper[k]) > 0 || isExempt) && !okSel[v] {
								fail(v.Pos(), v.Sel.Name+" reads an env var and is used as a value; call it directly with a constant name")
							}
							return true
						}
						if impAny[f][x.Name] {
							declared[x] = true
							return true // a std or third-party package member
						}
					}
					if anyName[v.Sel.Name] {
						fail(v.Pos(), v.Sel.Name+" matches an env-reading helper or reader exemption but is not bound to it through an import "+
							"of its package (a method, a field or an unmapped package); the scan refuses it")
					}
				}
				return true
			})
		}
	}
	sort.Strings(res.Unresolved)
	return res
}

// composeEnvKeysFromText merges, per service, the uncommented `environment:` keys of one compose file's
// text into out. It is a line scanner, not a YAML parser: the files use one fixed layout (services at two
// spaces, `environment:` at four, entries at six), and a commented-out line must NOT count as forwarded.
func composeEnvKeysFromText(raw string, out map[string]map[string]bool) {
	inServices, svc, inEnv := false, "", false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			inServices = trim == "services:"
			svc, inEnv = "", false
		case !inServices:
		case indent == 2 && strings.HasSuffix(trim, ":"):
			svc, inEnv = strings.TrimSuffix(trim, ":"), false
			if out[svc] == nil {
				out[svc] = map[string]bool{} // a service with no environment: is still PRESENT
			}
		case indent == 4:
			inEnv = trim == "environment:"
		case indent == 6 && inEnv && svc != "":
			key := trim
			if strings.HasPrefix(key, "- ") { // list form: - KEY=value
				key = strings.TrimSpace(key[2:])
				if i := strings.IndexByte(key, '='); i >= 0 {
					key = key[:i]
				}
			} else if i := strings.IndexByte(key, ':'); i >= 0 {
				key = key[:i]
			}
			out[svc][strings.Trim(key, `"'`)] = true
		}
	}
}

// composeEnvKeys reads the named compose files and merges their per-service environment keys.
func composeEnvKeys(t *testing.T, paths []string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		composeEnvKeysFromText(string(raw), out)
	}
	return out
}

// overlayClaim says an optional compose overlay (NOT part of the production file set) is the only thing
// that forwards a variable to a service.
type overlayClaim struct{ File, Service string }

// composeEnvRules is everything the compose rule needs, so its negative controls can drive it directly.
type composeEnvRules struct {
	Prod    map[string]map[string]bool // service -> keys forwarded by the production files
	Overlay map[string]map[string]bool // service -> keys forwarded ONLY by a verified optional overlay
	Allow   map[string]string          // variables deliberately not forwarded, with the reason
}

// checkOverlayClaims keeps each "forwarded by overlay X" claim true: the overlay must name the variable
// in that service, production must NOT (else the claim is stale), and the binary must still read it.
func checkOverlayClaims(claims map[string]overlayClaim, overlayKeys map[string]map[string]map[string]bool,
	prod map[string]map[string]bool, readNames map[string]bool) (problems []string) {
	for name, c := range claims {
		switch {
		case !overlayKeys[c.File][c.Service][name]:
			problems = append(problems, name+": claimed as forwarded by overlay "+c.File+" ("+c.Service+") but that overlay does not name it")
		case prod[c.Service][name]:
			problems = append(problems, name+": claimed overlay-only but the production files forward it too; remove the stale overlay claim")
		case !readNames[name]:
			problems = append(problems, name+": overlay claim but the binary no longer reads it; remove the stale overlay claim")
		}
	}
	sort.Strings(problems)
	return problems
}

// checkComposeEnv is the whole rule. needs maps the function making a read to the services any ONE of which
// must carry the variable (the server's reads need the server service; a migrate-only read needs migrate).
func checkComposeEnv(reads []envRead, needs func(fn string) []string, r composeEnvRules) (problems []string) {
	type agg struct {
		where   string
		missing bool
		covered bool // forwarded by production in at least one service the reads name
	}
	by := map[string]*agg{}
	for _, rd := range reads {
		a := by[rd.Name]
		if a == nil {
			a = &agg{where: rd.Where}
			by[rd.Name] = a
		}
		ok := false
		for _, s := range needs(rd.Func) {
			if r.Prod[s][rd.Name] || r.Overlay[s][rd.Name] {
				ok = true
			}
			if r.Prod[s][rd.Name] {
				a.covered = true
			}
		}
		if !ok && !a.missing {
			a.missing, a.where = true, rd.Where
		}
	}
	for name, a := range by {
		_, allowed := r.Allow[name]
		switch {
		case a.covered && allowed:
			problems = append(problems, name+": is forwarded AND allowlisted; remove the stale allowlist entry")
		case a.missing && !allowed:
			problems = append(problems, name+" (read at "+a.where+") is not forwarded to the service that reads it by deploy/docker-compose.yml + "+
				"docker-compose.prod.yml, so a .env setting would silently do nothing; forward it there with an empty-safe default, "+
				"or add it to composeEnvAllowlist (or composeOverlayClaims, for an optional overlay) with the reason")
		}
	}
	for name := range r.Allow {
		if by[name] == nil {
			problems = append(problems, name+": allowlisted but no longer read; remove the stale allowlist entry")
		}
	}
	sort.Strings(problems)
	return problems
}

func readNamesOf(reads []envRead) map[string]bool {
	m := map[string]bool{}
	for _, r := range reads {
		m[r.Name] = true
	}
	return m
}

// The scanner's own fixtures: each way a name could slip past it, scanned from small in-test sources.
//
// Expectations that changed with the conservative redesign (each now fails louder, deliberately):
// "package-level var" (a var is no longer an identity), "method helper" and "method value of a helper"
// (env-reading methods are a failure at the declaration), and the three reader-function fixtures (a reader
// parameter is no longer traced; os.Getenv handed to an unlisted function is a failure).
func TestEnvScannerFixtures(t *testing.T) {
	const pre = "package p\nimport \"os\"\nimport \"syscall\"\n" +
		"func envInt(key string, def int) int { if os.Getenv(key) != \"\" { return 1 }; return def }\n"
	scan := func(body string) scanResult {
		fset, files := parseEnvSources(t, pre+body)
		return scanEnvFiles(fset, files, scanConfig{})
	}
	names := func(r scanResult) string {
		var n []string
		for _, rd := range r.Reads {
			n = append(n, rd.Name)
		}
		sort.Strings(n)
		return strings.Join(n, ",")
	}
	cases := []struct {
		label      string
		body       string
		reads      string
		unresolved int
	}{
		{"direct literal", `func f() { _ = os.Getenv("CP_A"); envInt("CP_B", 1) }`, "CP_A,CP_B", 0},
		{"local variable into a helper", `func f() { key := "CP_NEW"; envInt(key, 10) }`, "", 1},
		{"local variable into os.Getenv", `func f() { key := "CP_NEW"; _ = os.Getenv(key) }`, "", 1},
		{"concatenated constants", `const pfx = "CP_"
const joined = pfx + "JOINED"
func f() { envInt(joined, 1); envInt(pfx+"TWO", 1) }`, "CP_JOINED,CP_TWO", 0},
		{"nested helper", `func envBool(k string) bool { return envInt(k, 0) == 1 }
func f() { envBool("CP_NESTED") }`, "CP_NESTED", 0},
		{"nested helper, unresolved at the outer call", `func envBool(k string) bool { return envInt(k, 0) == 1 }
func f() { k := "CP_X"; envBool(k) }`, "", 1},
		{"package-level var is no longer a name (A)", `var nm = "CP_PKG"
func f() { envInt(nm, 1) }`, "", 1},
		{"method helper is a failure at its declaration (C)", `type c struct{}
func (c) get(k string) string { return os.Getenv(k) }
func f(x c) { x.get("CP_METH"); k := "CP_BAD"; x.get(k) }`, "", 1},
		{"helper with no env in its name", `func fetchSetting(k string) string { return os.Getenv(k) }
func f() { fetchSetting("CP_ODD"); v := "CP_BAD"; fetchSetting(v) }`, "CP_ODD", 1},
		{"os.Getenv passed to an unlisted reader function (B)", `func fromEnv(get func(string) string) string { return get("CP_FN") }
func f() { fromEnv(os.Getenv) }`, "", 1},
		{"reader function handed on (B)", `func inner(get func(string) string) string { return get("CP_DEEP") }
func outer(g func(string) string) string { return inner(g) }
func f() { outer(os.Getenv) }`, "", 1},
		{"reader function never handed os.Getenv", `func fromMap(get func(string) string) string { return get("NOT_ENV") }
func f() { fromMap(func(string) string { return "" }) }`, "", 0},
		{"os.Getenv stored as a value", `var g = os.Getenv`, "", 1},
		{"wholesale environment read", `func f() { _ = os.ExpandEnv("$CP_HIDDEN") }`, "", 1},
		{"a helper-looking function whose parameter never reaches the environment", `func envLabel(s string) string { return s }
func f(v string) { envLabel(v) }`, "", 0},
		{"a computed name inside a helper", `func g(k string) { _ = os.Getenv("CP_" + k) }
func f() { g("X") }`, "", 1},
		{"helper aliased to a local function value", `func f() { g := envInt; g("CP_A", 1) }`, "", 1},
		{"helper passed as a value", `func use(h func(string, int) int) int { return h("CP_B", 1) }
func f() { use(envInt) }`, "", 1},
		{"method value of a method that reads (C)", `type c struct{}
func (c) get(k string) string { return os.Getenv(k) }
func f(x c) { h := x.get; h("CP_F") }`, "", 1},
		{"helper stored in a package-level var", `var g = envInt`, "", 1},
		{"syscall.Getenv literal is a read", `func f() { _, _ = syscall.Getenv("CP_SYS") }`, "CP_SYS", 0},
		{"syscall.Getenv with a local name", `func f() { k := "CP_X"; _, _ = syscall.Getenv(k) }`, "", 1},
		{"syscall.Getenv stored as a value", `var g = syscall.Getenv`, "", 1},
		{"syscall.Environ", `func f() { _ = syscall.Environ() }`, "", 1},
		{"a struct field is not the package-level const of the same name", `const Name = "CP_E"
type s struct{ Name string }
func f(x s) { envInt(x.Name, 1) }`, "", 1},
		{"a local variable shadows the package-level const", `const key = "CP_E"
func f() { key := "CP_REAL"; envInt(key, 1) }`, "", 1},
		{"a parameter shadows the package-level const (the caller names it)", `const key = "CP_E"
func f(key string) { envInt(key, 1) }
func g() { f("CP_P") }`, "CP_P", 0},
		{"a range variable shadows the package-level const", `const key = "CP_E"
func f(ks []string) { for _, key := range ks { envInt(key, 1) } }`, "", 1},
		{"the package-level const still resolves when nothing shadows it", `const key = "CP_E"
func f() { envInt(key, 1) }`, "CP_E", 0},
		{"a block local shadowing a helper's parameter is not the parameter", `func fetch(key string) string { { key := "CP_REAL"; return os.Getenv(key) } }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a closure local shadowing a helper's parameter is not the parameter", `func fetch(key string) string { return func() string { key := "CP_REAL"; return os.Getenv(key) }() }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a reassigned helper parameter is not the caller's value", `func fetch(key string) string { key = "CP_REAL"; return os.Getenv(key) }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a parameter reassigned by a capturing closure is not the caller's value", `func fetch(key string) string { func() { key = "CP_REAL" }(); return os.Getenv(key) }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a parameter whose address escapes is not the caller's value", `func set(p *string) { *p = "CP_REAL" }
func fetch(key string) string { set(&key); return os.Getenv(key) }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a parenthesised assignment target is still the parameter", `func fetch(key string) string { (key) = "CP_REAL"; return os.Getenv(key) }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a parenthesised address-of is still the parameter", `func set(p *string) { *p = "CP_REAL" }
func fetch(key string) string { set(&((key))); return os.Getenv(key) }
func g() { fetch("CP_DECOY") }`, "", 1},
		{"a reassigned reader parameter handed os.Getenv", `func fromEnv(get func(string) string) string { get = func(string) string { return "" }; return get("CP_X") }
func g() { fromEnv(os.Getenv) }`, "", 1},
		{"a closure that captures the parameter itself still makes a helper", `func fetch(key string) string { return func() string { return os.Getenv(key) }() }
func g() { fetch("CP_CAP") }`, "CP_CAP", 0},
		{"a local shadowing a reader parameter, os.Getenv handed to it", `func fromEnv(get func(string) string) string { { get := func(string) string { return "" }; return get("CP_X") } }
func g() { fromEnv(os.Getenv) }`, "", 1},

		// Codex r5 item 1 (A): a var never names an env var, however it is mutated.
		{"r5.1 package var reassigned in init", `var key = "CP_DECOY"
func init() { key = "CP_REAL" }
func f() { _ = os.Getenv(key) }`, "", 1},
		{"r5.1 package var reassigned in a closure", `var key = "CP_DECOY"
func init() { func() { key = "CP_REAL" }() }
func f() { envInt(key, 1) }`, "", 1},
		{"r5.1 package var whose address escapes", `var key = "CP_DECOY"
func set(p *string) { *p = "CP_REAL" }
func init() { set(&key) }
func f() { _ = os.Getenv(key) }`, "", 1},
		{"r5.1 var derived from a var", `var key = "CP_DECOY"
var other = key
func f() { _ = os.Getenv(other) }`, "", 1},
		{"r5.1 local const is not a package-level const", `func f() { const k = "CP_LOCAL"; _ = os.Getenv(k) }`, "", 1},
		{"r5.1 positive control: a const resolves", `const key = "CP_CONST"
const other = key + "_2"
func f() { _ = os.Getenv(key); envInt(other, 1) }`, "CP_CONST,CP_CONST_2", 0},
		{"r5.1 a var shadowing nothing next to a same-named const elsewhere is still a var", `var key = "CP_V"
func f() { envInt(key, 1) }`, "", 1},

		// Codex r5 item 2: an active reader parameter cannot escape (os.Getenv value to an unlisted function).
		{"r5.2 the escaping reader, unlisted", `func read(get func(string) string) string { _ = get("CP_VISIBLE"); h := get; return h("CP_HIDDEN") }
func f() { read(os.Getenv) }`, "", 1},
	}
	// The method rule's own message (the generic "cannot resolve" failure would also make the count 1).
	if r := scan("type c struct{}\nfunc (c) get(k string) string { return os.Getenv(k) }\n"); !strings.Contains(strings.Join(r.Unresolved, "\n"), "env-reading methods are unsupported") {
		t.Errorf("an env-reading method must be refused as such, got %v", r.Unresolved)
	}
	for _, c := range cases {
		r := scan(c.body)
		if got := names(r); got != c.reads || len(r.Unresolved) != c.unresolved {
			t.Errorf("%s: reads %q (want %q), unresolved %d (want %d): %v", c.label, got, c.reads, len(r.Unresolved), c.unresolved, r.Unresolved)
		}
	}

	// Multi-file / multi-directory / configured fixtures.
	type mcase struct {
		label      string
		srcs       map[string]string
		cfg        scanConfig
		reads      string
		unresolved int
		msg        string // a substring a failure must carry (the count alone cannot tell two rules apart)
	}
	imp := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	// A reader exemption for pkg.rd with the given names, and a body whose reader parameter is `get`.
	rd := func(body string, names ...string) mcase {
		return mcase{srcs: map[string]string{
			"pkg/a.go": "package pkg\nimport \"os\"\nvar _ = os.Getenv\nfunc rd(get func(string) string) string {\n" + body + "\n}\nfunc caller() { rd(os.Getenv) }\n",
		}, cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", names}}}}
	}
	withLabel := func(l, reads string, unresolved int, m mcase) mcase {
		m.label, m.reads, m.unresolved = l, reads, unresolved
		return m
	}
	// pkg/a.go above has `var _ = os.Getenv`, which would itself fail; the reader fixtures drop that line.
	rdp := func(l string, reads string, unresolved int, body string, names ...string) mcase {
		m := rd(body, names...)
		for k, v := range m.srcs {
			m.srcs[k] = strings.Replace(v, "var _ = os.Getenv\n", "", 1)
		}
		return withLabel(l, reads, unresolved, m)
	}
	mcases := []mcase{
		// Rule 7: a name declared per build-tag file has no single value, so it never resolves.
		{label: "the same const declared in two build-tag files of one directory", srcs: map[string]string{
			"pkg/a_win.go":  "//go:build windows\n\npackage pkg\nconst envKey = \"CP_WIN\"\n",
			"pkg/a_unix.go": "//go:build !windows\n\npackage pkg\nconst envKey = \"CP_UNIX\"\n",
			"pkg/use.go":    "package pkg\nimport \"os\"\nfunc f() { _ = os.Getenv(envKey) }\n",
		}, reads: "", unresolved: 1},
		{label: "a const in one build-tag file and a var of the same name in another", srcs: map[string]string{
			"pkg/a_win.go":  "//go:build windows\n\npackage pkg\nconst envKey = \"CP_WIN\"\n",
			"pkg/a_unix.go": "//go:build !windows\n\npackage pkg\nvar envKey = \"CP_UNIX\"\n",
			"pkg/use.go":    "package pkg\nimport \"os\"\nfunc f() { _ = os.Getenv(envKey) }\n",
		}, reads: "", unresolved: 1},
		{label: "a const declared once still resolves from another file of the directory", srcs: map[string]string{
			"pkg/a.go":   "package pkg\nconst envKey = \"CP_ONE\"\n",
			"pkg/use.go": "package pkg\nimport \"os\"\nfunc f() { _ = os.Getenv(envKey) }\n",
		}, reads: "CP_ONE", unresolved: 0},
		// Item 2 / rule B: the listed reader and every way its parameter could escape.
		rdp("B positive control: a listed reader called with consts", "CP_X,CP_Y", 0, `return get("CP_X") + get("CP_Y")`, "CP_X", "CP_Y"),
		rdp("r5.2 listed reader that aliases its parameter", "CP_VISIBLE", 1, `_ = get("CP_VISIBLE"); h := get; return h("CP_HIDDEN")`, "CP_VISIBLE"),
		rdp("r5.2 listed reader that returns its parameter", "CP_X", 1, `_ = get("CP_X"); return fmtGet(get)`, "CP_X"),
		rdp("r5.2 listed reader that stores its parameter", "CP_X", 1, `store = get; return get("CP_X")`, "CP_X"),
		rdp("r5.2 listed reader that sends its parameter", "CP_X", 1, `ch <- get; return get("CP_X")`, "CP_X"),
		rdp("r5.2 listed reader that passes its parameter on", "CP_X", 1, `other(get); return get("CP_X")`, "CP_X"),
		rdp("r5.2 listed reader that takes its address", "CP_X", 1, `p := &get; _ = p; return get("CP_X")`, "CP_X"),
		rdp("r5.2 listed reader that reassigns its parameter", "CP_X", 1, `get = nil; return get("CP_X")`, "CP_X"),
		rdp("r5.2 listed reader that parenthesises its callee", "CP_X", 2, `return (get)("CP_X")`, "CP_X"),
		rdp("B a listed reader calling with a variable", "CP_X", 2, `k := "CP_X"; return get(k)`, "CP_X"),
		rdp("B a listed reader calling with a computed name", "CP_X,SUFFIX", 2, `return get("CP_" + os.Getenv("SUFFIX"))`, "CP_X"),
		rdp("B a name added inside the reader forces a table change", "CP_X", 1, `return get("CP_X") + get("CP_NEW")`, "CP_X"),
		rdp("B a name listed but no longer read", "CP_GONE,CP_X", 1, `return get("CP_X")`, "CP_X", "CP_GONE"),
		{label: "B the listed function does not exist", srcs: map[string]string{"pkg/a.go": "package pkg\nfunc other() {}\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", []string{"CP_X"}}}}, unresolved: 1},
		{label: "B the listed function exists twice", srcs: map[string]string{
			"pkg/a.go": "package pkg\nfunc rd(get func(string) string) string { return get(\"CP_X\") }\n",
			"pkg/b.go": "package pkg\nfunc rd(get func(string) string) string { return get(\"CP_X\") }\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", []string{"CP_X"}}}}, unresolved: 1},
		{label: "B the listed function has two func parameters", srcs: map[string]string{
			"pkg/a.go": "package pkg\nfunc rd(get, other func(string) string) string { return get(\"CP_X\") }\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", []string{"CP_X"}}}}, unresolved: 1},
		{label: "B an inactive entry (no such directory scanned) is ignored", srcs: map[string]string{"pkg/a.go": "package pkg\nfunc other() {}\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"elsewhere", "rd", []string{"CP_X"}}}}},
		{label: "B a second function handed os.Getenv is still a failure", srcs: map[string]string{
			"pkg/a.go": "package pkg\nimport \"os\"\nfunc rd(get func(string) string) string { return get(\"CP_X\") }\nfunc rd2(get func(string) string) string { return get(\"CP_Y\") }\nfunc c() { rd(os.Getenv); rd2(os.Getenv) }\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", []string{"CP_X"}}}}, reads: "CP_X", unresolved: 1},
		{label: "B os.Getenv handed to the listed reader in the wrong slot is a value", srcs: map[string]string{
			"pkg/a.go": "package pkg\nimport \"os\"\nfunc rd(a string, get func(string) string) string { return get(\"CP_X\") }\nfunc c() { rd(\"x\", os.Getenv); rd(os.Getenv(\"CP_Y\"), nil); _ = rd }\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", []string{"CP_X"}}}}, reads: "CP_X,CP_Y", unresolved: 1},
		{label: "B the listed reader aliased as a value", srcs: map[string]string{
			"pkg/a.go": "package pkg\nimport \"os\"\nfunc rd(get func(string) string) string { return get(\"CP_X\") }\nfunc c() { g := rd; g(os.Getenv) }\n"},
			cfg: scanConfig{Exemptions: []envExemption{{"pkg", "rd", []string{"CP_X"}}}}, unresolved: 2},
		{label: "B positive control: the call site in another package records the names (package name differs from dir)", srcs: map[string]string{
			"pkg/a.go": "package config\nfunc Rd(get func(string) string) string { return get(\"CP_X\") + get(\"CP_Y\") }\n",
			"app/m.go": "package main\nimport \"os\"\nimport \"m/pkg\"\nfunc main() { config.Rd(os.Getenv) }\n"},
			cfg: scanConfig{Imports: imp("m/pkg", "pkg"), Exemptions: []envExemption{{"pkg", "Rd", []string{"CP_X", "CP_Y"}}}}, reads: "CP_X,CP_Y"},
		{label: "B a same-named function in another package is not the exemption", srcs: map[string]string{
			"pkg/a.go": "package config\nfunc Rd(get func(string) string) string { return get(\"CP_X\") }\n",
			"oth/a.go": "package oth\nfunc Rd(get func(string) string) string { return get(\"CP_Z\") }\n",
			"app/m.go": "package main\nimport \"os\"\nimport \"m/oth\"\nfunc main() { oth.Rd(os.Getenv) }\n"},
			cfg: scanConfig{Imports: imp("m/pkg", "pkg", "m/oth", "oth"), Exemptions: []envExemption{{"pkg", "Rd", []string{"CP_X"}}}}, unresolved: 1},

		// Item 1 across files.
		{label: "r5.1 cross-file assignment to a package var", srcs: map[string]string{
			"p/a.go": "package p\nimport \"os\"\nvar key = \"CP_DECOY\"\nfunc f() { _ = os.Getenv(key) }\n",
			"p/b.go": "package p\nfunc init() { key = \"CP_REAL\" }\n"}, unresolved: 1},
		{label: "r5.1 a const in another file resolves", srcs: map[string]string{
			"p/a.go": "package p\nimport \"os\"\nfunc f() { _ = os.Getenv(key) }\n",
			"p/b.go": "package p\nconst key = \"CP_FAR\"\n"}, reads: "CP_FAR"},

		// Item 3 / rule C: method expressions and method readers.
		{label: "r5.3 method expression shifts the arguments by the receiver", srcs: map[string]string{
			"p/a.go": "package p\nimport \"os\"\ntype C struct{}\nfunc (C) fetch(fallback, key string) string { return os.Getenv(key) }\nfunc f() { C.fetch(C{}, \"CP_DECOY\", \"CP_REAL\") }\n"}, unresolved: 1, msg: "env-reading methods are unsupported"},
		{label: "r5.3 a method whose parameter flows into a helper function", srcs: map[string]string{
			"p/a.go": "package p\nimport \"os\"\nfunc envInt(k string) string { return os.Getenv(k) }\ntype C struct{}\nfunc (C) fetch(key string) string { return envInt(key) }\nfunc f(c C) { c.fetch(\"CP_X\") }\n"}, unresolved: 1, msg: "env-reading methods are unsupported"},
		{label: "C positive control: a plain function with the same shape", srcs: map[string]string{
			"p/a.go": "package p\nimport \"os\"\nfunc fetch(fallback, key string) string { return os.Getenv(key) }\nfunc f() { fetch(\"CP_DECOY\", \"CP_REAL\") }\n"}, reads: "CP_REAL"},
		{label: "C a method with a helper's name called on a value is refused", srcs: map[string]string{
			"p/a.go": "package p\nimport \"os\"\nfunc fetch(key string) string { return os.Getenv(key) }\ntype C struct{}\nfunc (C) fetch(key string) string { return key }\nfunc f(c C) { c.fetch(\"CP_X\"); fetch(\"CP_Y\") }\n"}, reads: "CP_Y", unresolved: 1},

		// Item 4 / rule D: package identity is the directory.
		{label: "r5.4 two directories declare package config with the same const name", srcs: map[string]string{
			"a/a.go": "package config\nconst Name = \"CP_A\"\n",
			"b/b.go": "package config\nconst Name = \"CP_B\"\n",
			"m/m.go": "package main\nimport \"os\"\nimport \"m/b\"\nfunc main() { _ = os.Getenv(config.Name) }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a", "m/b", "b")}, reads: "CP_B"},
		{label: "r5.4 both imported under their own aliases", srcs: map[string]string{
			"a/a.go": "package config\nconst Name = \"CP_A\"\n",
			"b/b.go": "package config\nconst Name = \"CP_B\"\n",
			"m/m.go": "package main\nimport \"os\"\nimport ca \"m/a\"\nimport cb \"m/b\"\nfunc main() { _ = os.Getenv(ca.Name); _ = os.Getenv(cb.Name) }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a", "m/b", "b")}, reads: "CP_A,CP_B"},
		{label: "r5.4 a selector on an import path that maps to no scanned directory never binds to a same-named package", srcs: map[string]string{
			"a/a.go": "package config\nconst Name = \"CP_A\"\n",
			"m/m.go": "package main\nimport \"os\"\nimport \"third/party/config\"\nfunc main() { _ = os.Getenv(config.Name) }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a")}, unresolved: 1},
		{label: "r5.4 same-named helper in two directories: only the real one reads", srcs: map[string]string{
			"a/a.go": "package config\nimport \"os\"\nfunc Get(k string) string { return os.Getenv(k) }\n",
			"b/b.go": "package config\nfunc Get(k string) string { return k }\n",
			"m/m.go": "package main\nimport \"m/a\"\nimport b \"m/b\"\nfunc main() { config.Get(\"CP_A\"); b.Get(\"CP_B_NOT_ENV\") }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a", "m/b", "b")}, reads: "CP_A"},
		{label: "r5.4 a package const of the same name in this directory wins over another directory's", srcs: map[string]string{
			"a/a.go": "package config\nconst Name = \"CP_A\"\n",
			"m/m.go": "package main\nimport \"os\"\nconst Name = \"CP_M\"\nfunc main() { _ = os.Getenv(Name) }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a")}, reads: "CP_M"},
		{label: "r5.4 an unbound call matching a helper name is a failure", srcs: map[string]string{
			"a/a.go": "package config\nimport \"os\"\nfunc Get(k string) string { return os.Getenv(k) }\n",
			"m/m.go": "package main\nfunc main() { var x struct{ Get func(string) string }; x.Get(\"CP_HIDDEN\") }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a")}, unresolved: 1},
		{label: "r5.4 an unbound call matching an exemption name is a failure", srcs: map[string]string{
			"pkg/a.go": "package pkg\nfunc Rd(get func(string) string) string { return get(\"CP_X\") }\n",
			"m/m.go":   "package main\nimport \"os\"\nfunc main() { var x struct{ Rd func(func(string) string) string }; x.Rd(os.Getenv) }\n"},
			cfg: scanConfig{Imports: imp("m/pkg", "pkg"), Exemptions: []envExemption{{"pkg", "Rd", []string{"CP_X"}}}}, unresolved: 2},
		{label: "r5.4 an unbound bare name matching a helper elsewhere is a failure", srcs: map[string]string{
			"a/a.go": "package config\nimport \"os\"\nfunc Get(k string) string { return os.Getenv(k) }\n",
			"m/m.go": "package main\nfunc main() { Get(\"CP_HIDDEN\") }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a")}, unresolved: 1},
		{label: "r5.4 a helper of an imported directory called by import path name records the read", srcs: map[string]string{
			"a/a.go": "package config\nimport \"os\"\nfunc Get(k string) string { return os.Getenv(k) }\nconst Key = \"CP_K\"\n",
			"m/m.go": "package main\nimport \"m/a\"\nfunc main() { config.Get(config.Key); config.Get(\"CP_L\") }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a")}, reads: "CP_K,CP_L"},

		// Item 5 / rule E: dot-imports.
		{label: "r5.5 dot-import of os", srcs: map[string]string{"p/a.go": "package p\nimport . \"os\"\nfunc f() { _ = Getenv(\"CP_HIDDEN\") }\n"}, unresolved: 1},
		{label: "r5.5 dot-import of syscall", srcs: map[string]string{"p/a.go": "package p\nimport . \"syscall\"\nfunc f() { _, _ = Getenv(\"CP_HIDDEN\") }\n"}, unresolved: 1},
		{label: "r5.5 dot-import of a scanned package", srcs: map[string]string{
			"a/a.go": "package config\nimport \"os\"\nfunc Get(k string) string { return os.Getenv(k) }\n",
			"m/m.go": "package main\nimport . \"m/a\"\nfunc main() { Get(\"CP_HIDDEN\") }\n"},
			cfg: scanConfig{Imports: imp("m/a", "a")}, unresolved: 2},
		{label: "E positive control: a blank import of os is fine", srcs: map[string]string{"p/a.go": "package p\nimport _ \"os\"\nfunc f() {}\n"}},
		{label: "E positive control: an aliased os import still reads", srcs: map[string]string{"p/a.go": "package p\nimport o \"os\"\nfunc f() { _ = o.Getenv(\"CP_AL\") }\n"}, reads: "CP_AL"},

		// Item 6 / rule F: what is outside the model but detectable.
		{label: "r5.6 //go:linkname", srcs: map[string]string{"p/a.go": "package p\nimport _ \"unsafe\"\n//go:linkname getenv syscall.runtimeGetenv\nfunc getenv(k string) string\n"}, unresolved: 1},
		{label: "r5.6 cgo", srcs: map[string]string{"p/a.go": "package p\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\nfunc f() { _ = C.getenv }\n"}, unresolved: 1},
		{label: "F positive control: plain unsafe use is not flagged", srcs: map[string]string{"p/a.go": "package p\nimport \"unsafe\"\nvar _ = unsafe.Sizeof(0)\n"}},
	}
	for _, c := range mcases {
		fset, files := parseEnvFiles(t, c.srcs)
		r := scanEnvFiles(fset, files, c.cfg)
		if got := names(r); got != c.reads || len(r.Unresolved) != c.unresolved {
			t.Errorf("%s: reads %q (want %q), unresolved %d (want %d): %v", c.label, got, c.reads, len(r.Unresolved), c.unresolved, r.Unresolved)
		}
		if c.msg != "" && !strings.Contains(strings.Join(r.Unresolved, "\n"), c.msg) {
			t.Errorf("%s: a failure must say %q, got %v", c.label, c.msg, r.Unresolved)
		}
	}
	// A package-level var initialised from the environment is a read too, attributed to no function.
	r := scan(`var x = os.Getenv("CP_INIT")`)
	if len(r.Reads) != 1 || r.Reads[0].Name != "CP_INIT" || r.Reads[0].Func != "" {
		t.Errorf("package-level read: %+v", r)
	}
}

func TestComposeEnvKeysFromText(t *testing.T) {
	out := map[string]map[string]bool{}
	composeEnvKeysFromText("services:\n  a:\n    environment:\n      K1: \"x\"\n      # K2: y\n      - K3=z\n  b:\n    image: i\n", out)
	if !out["a"]["K1"] || out["a"]["K2"] || !out["a"]["K3"] || out["b"] == nil || len(out["b"]) != 0 {
		t.Fatalf("unexpected keys: %v", out)
	}
}

// The rule's negative controls: it must refuse each way the guard could be defeated.
func TestComposeEnvRuleNegativeControls(t *testing.T) {
	server := func(string) []string { return []string{"svc"} }
	reads := []envRead{{"CP_A", "x.go:1", "main"}, {"CP_B", "x.go:2", "main"}}
	prod := map[string]map[string]bool{"svc": {"CP_A": true}}
	if p := checkComposeEnv(reads, server, composeEnvRules{Prod: prod}); len(p) != 1 || !strings.HasPrefix(p[0], "CP_B ") {
		t.Fatalf("an unforwarded, unallowlisted read must be reported, got %v", p)
	}
	if p := checkComposeEnv(reads, server, composeEnvRules{Prod: prod, Allow: map[string]string{"CP_B": "why"}}); len(p) != 0 {
		t.Fatalf("an allowlisted read must pass, got %v", p)
	}
	both := map[string]map[string]bool{"svc": {"CP_A": true, "CP_B": true}}
	if p := checkComposeEnv(reads, server, composeEnvRules{Prod: both, Allow: map[string]string{"CP_B": "why"}}); len(p) != 1 {
		t.Fatalf("a forwarded+allowlisted entry is stale and must be reported, got %v", p)
	}
	if p := checkComposeEnv(reads, server, composeEnvRules{Prod: both, Allow: map[string]string{"CP_GONE": "why"}}); len(p) != 1 {
		t.Fatalf("an allowlist entry nothing reads is stale and must be reported, got %v", p)
	}
	// Per service: a read by the server must be in the server's environment, not merely in another service's.
	two := func(fn string) []string {
		if fn == "runMigrate" {
			return []string{"migrate"}
		}
		return []string{"server"}
	}
	split := []envRead{{"CP_S", "m.go:1", "main"}, {"CP_M", "m.go:2", "runMigrate"}}
	if p := checkComposeEnv(split, two, composeEnvRules{Prod: map[string]map[string]bool{"server": {"CP_S": true}, "migrate": {"CP_M": true}}}); len(p) != 0 {
		t.Fatalf("each variable in its own service must pass, got %v", p)
	}
	if p := checkComposeEnv(split, two, composeEnvRules{Prod: map[string]map[string]bool{"server": {"CP_M": true}, "migrate": {"CP_S": true}}}); len(p) != 2 {
		t.Fatalf("a variable forwarded only to the OTHER service must be reported, got %v", p)
	}
	// An optional overlay covers a read only when it is a verified claim, and a claim cannot go stale.
	ov := composeEnvRules{Prod: map[string]map[string]bool{"svc": {}}, Overlay: map[string]map[string]bool{"svc": {"CP_A": true}}}
	if p := checkComposeEnv(reads[:1], server, ov); len(p) != 0 {
		t.Fatalf("a verified overlay-only variable must pass, got %v", p)
	}
	if p := checkComposeEnv(reads[:1], server, composeEnvRules{Prod: map[string]map[string]bool{"svc": {}}}); len(p) != 1 {
		t.Fatalf("an overlay-only variable with no claim must be reported, got %v", p)
	}
	claims := map[string]overlayClaim{"CP_A": {"o.yml", "svc"}}
	okFiles := map[string]map[string]map[string]bool{"o.yml": {"svc": {"CP_A": true}}}
	if p := checkOverlayClaims(claims, okFiles, map[string]map[string]bool{"svc": {}}, map[string]bool{"CP_A": true}); len(p) != 0 {
		t.Fatalf("a true claim must pass, got %v", p)
	}
	if p := checkOverlayClaims(claims, map[string]map[string]map[string]bool{"o.yml": {"svc": {}}}, map[string]map[string]bool{"svc": {}}, map[string]bool{"CP_A": true}); len(p) != 1 {
		t.Fatalf("a claim the overlay does not back must be reported, got %v", p)
	}
	if p := checkOverlayClaims(claims, okFiles, prod, map[string]bool{"CP_A": true}); len(p) != 1 {
		t.Fatalf("a claim production also forwards is stale, got %v", p)
	}
	if p := checkOverlayClaims(claims, okFiles, map[string]map[string]bool{"svc": {}}, map[string]bool{}); len(p) != 1 {
		t.Fatalf("a claim for an unread variable is stale, got %v", p)
	}
}

// TestScanDirsCoverEveryModulePackage: every package of THIS module that the binary compiles (go list -deps,
// so transitively and as the toolchain sees it) must be in scanDirs. A new subpackage that reads the
// environment, or exposes an env helper, would otherwise be invisible to the guard. Third-party and standard
// packages are out of scope: their reads are not this deployment's knobs.
func TestScanDirsCoverEveryModulePackage(t *testing.T) {
	scanned := map[string]bool{}
	for _, d := range scanDirs {
		scanned[normDir(d)] = true
	}
	compiled := 0
	for _, dir := range moduleImportDirs(t) {
		compiled++
		if !scanned[normDir(dir)] {
			t.Errorf("the binary compiles %s, which is not in scanDirs: its env reads would not be checked", dir)
		}
	}
	if compiled == 0 {
		t.Fatal("go list reported no package of this module: the coverage check is blind")
	}
}
