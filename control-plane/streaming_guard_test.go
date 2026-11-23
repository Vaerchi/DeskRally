package controlplane

// Guard: a route that streams a long response must be registered through streaming(), or the build fails
// (external review: "add a test that fails when a streaming route is registered without it").
//
// Design: the route table is a net/http ServeMux and cannot be enumerated at runtime, and a behavioural driver
// would have to know which routes stream, which is the very thing that gets forgotten. So the guard reads the
// source: it finds every handler reachable from a registration on the tenant-bound `protected` mux that CAN stream
// (it, or a function it calls by name, builds a ZIP, copies to the client, ServeContent, flushes, or declares an
// attachment / NDJSON / event-stream / octet-stream content type) and requires the registration to be wrapped in
// streaming(). New streaming code is caught by what it does, not by anyone remembering to add it to a list. The
// pool behaviour itself is proven against PostgreSQL in streaming_pgstore_test.go.
//
// The guard FAILS CLOSED. It follows aliases of the protected mux (`mux := protected`, a *http.ServeMux parameter
// that receives it), handlers bound to variables (method values, func literals), inline forwarding literals and
// handler factories / wrappers. A registration whose handler it cannot resolve is a failure, not a pass, unless it
// is wrapped in streaming() or listed in streamingGuardAllow with a written reason. Negative fixtures below prove
// each indirection is flagged.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var streamLiteralMarkers = []string{"application/zip", "application/x-ndjson", "text/event-stream", "application/octet-stream", "Content-Disposition"}

var streamCallMarkers = map[string]bool{
	"zip.NewWriter": true, "io.Copy": true, "io.CopyN": true, "io.CopyBuffer": true,
	"http.ServeContent": true, "http.ServeFile": true, "http.NewResponseController": true,
}

// streamingGuardAllow lists registrations (keyed "file.go: handler") whose handler the guard cannot resolve
// or that mention a streaming marker but hold no tenant connection by construction. Every entry needs a reviewed
// reason beside it. Empty is the goal.
var streamingGuardAllow = map[string]string{}

type guardFunc struct {
	direct  bool
	why     string
	hasW    bool // takes an http.ResponseWriter: only such functions can stream to a client
	callees map[string]bool
}

func hasResponseWriter(ft *ast.FuncType) bool {
	if ft == nil || ft.Params == nil {
		return false
	}
	for _, f := range ft.Params.List {
		if se, ok := f.Type.(*ast.SelectorExpr); ok && se.Sel.Name == "ResponseWriter" {
			return true
		}
	}
	return false
}

// guardScan records whether the node streams directly and which functions it calls.
func guardScan(n ast.Node, g *guardFunc) {
	ast.Inspect(n, func(x ast.Node) bool {
		switch v := x.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				for _, m := range streamLiteralMarkers {
					if strings.Contains(v.Value, m) {
						g.direct, g.why = true, "literal "+m
					}
				}
			}
		case *ast.CallExpr:
			switch fn := v.Fun.(type) {
			case *ast.Ident:
				g.callees[fn.Name] = true
			case *ast.SelectorExpr:
				g.callees[fn.Sel.Name] = true
				if id, ok := fn.X.(*ast.Ident); ok {
					if streamCallMarkers[id.Name+"."+fn.Sel.Name] {
						g.direct, g.why = true, id.Name+"."+fn.Sel.Name
					}
					if fn.Sel.Name == "Flush" && (id.Name == "w" || id.Name == "flusher" || id.Name == "rc") {
						g.direct, g.why = true, id.Name+".Flush"
					}
				}
			}
		}
		return true
	})
}

type guard struct {
	funcs map[string]*guardFunc
	files []*ast.File
	fset  *token.FileSet
}

func guardBuild(fset *token.FileSet, files []*ast.File) *guard {
	g := &guard{funcs: map[string]*guardFunc{}, files: files, fset: fset}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			gf := g.funcs[fd.Name.Name]
			if gf == nil {
				gf = &guardFunc{callees: map[string]bool{}}
				g.funcs[fd.Name.Name] = gf
			}
			gf.hasW = gf.hasW || hasResponseWriter(fd.Type)
			guardScan(fd.Body, gf)
		}
	}
	// Only a function that holds the ResponseWriter can stream to the client: a hash helper that copies into
	// a hasher, or a DB driver Hijack, is not a streaming response.
	for _, gf := range g.funcs {
		if !gf.hasW {
			gf.direct = false
		}
	}
	for changed := true; changed; { // transitive closure over by-name calls
		changed = false
		for _, gf := range g.funcs {
			if gf.direct || !gf.hasW {
				continue
			}
			for c := range gf.callees {
				if cg := g.funcs[c]; cg != nil && cg.direct {
					gf.direct, gf.why, changed = true, "calls "+c+" ("+cg.why+")", true
					break
				}
			}
		}
	}
	return g
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// muxAliases returns the identifiers that denote the protected mux inside fd: the literal name, local
// assignments from an alias, and parameters that receive one (paramPos, filled by a fixpoint in check).
func muxAliases(fd *ast.FuncDecl, paramPos map[string]map[int]bool) map[string]bool {
	al := map[string]bool{"protected": true}
	idx := 0
	if fd.Type.Params != nil {
		for _, f := range fd.Type.Params.List {
			n := len(f.Names)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				if len(f.Names) > i && paramPos[fd.Name.Name][idx] {
					al[f.Names[i].Name] = true
				}
				idx++
			}
		}
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(fd.Body, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.AssignStmt:
				for i, l := range v.Lhs {
					id, ok := l.(*ast.Ident)
					if !ok || i >= len(v.Rhs) {
						continue
					}
					if r, ok := unparen(v.Rhs[i]).(*ast.Ident); ok && al[r.Name] && !al[id.Name] {
						al[id.Name], changed = true, true
					}
				}
			case *ast.ValueSpec:
				for i, id := range v.Names {
					if i >= len(v.Values) {
						continue
					}
					if r, ok := unparen(v.Values[i]).(*ast.Ident); ok && al[r.Name] && !al[id.Name] {
						al[id.Name], changed = true, true
					}
				}
			}
			return true
		})
	}
	return al
}

// localBindings maps a variable declared in fd to the expression it was assigned (method values, literals).
func localBindings(fd *ast.FuncDecl) map[string]ast.Expr {
	b := map[string]ast.Expr{}
	ast.Inspect(fd.Body, func(x ast.Node) bool {
		switch v := x.(type) {
		case *ast.AssignStmt:
			for i, l := range v.Lhs {
				if id, ok := l.(*ast.Ident); ok && i < len(v.Rhs) {
					b[id.Name] = v.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			for i, id := range v.Names {
				if i < len(v.Values) {
					b[id.Name] = v.Values[i]
				}
			}
		}
		return true
	})
	return b
}

// verdict: does the handler expression stream, and could it be resolved at all?
func (g *guard) verdict(e ast.Expr, binds map[string]ast.Expr, depth int) (stream, resolved bool, why string) {
	if depth > 6 {
		return false, false, ""
	}
	e = unparen(e)
	switch v := e.(type) {
	case *ast.FuncLit:
		// A literal is judged on what it does, wherever it forwards: markers in its body count (no hasW test,
		// fail closed), and so does calling any function that streams.
		lf := &guardFunc{callees: map[string]bool{}}
		guardScan(v.Body, lf)
		if lf.direct {
			return true, true, "inline literal: " + lf.why
		}
		for c := range lf.callees {
			if cg := g.funcs[c]; cg != nil && cg.direct {
				return true, true, "inline literal calls " + c + " (" + cg.why + ")"
			}
		}
		return false, true, ""
	case *ast.Ident:
		if b, ok := binds[v.Name]; ok {
			return g.verdict(b, binds, depth+1)
		}
		if gf := g.funcs[v.Name]; gf != nil {
			return gf.direct, true, gf.why
		}
		return false, false, ""
	case *ast.SelectorExpr:
		if gf := g.funcs[v.Sel.Name]; gf != nil {
			return gf.direct, true, gf.why
		}
		return false, false, ""
	case *ast.CallExpr:
		// A factory (s.handleX(true)), a conversion (http.HandlerFunc(h)) or a wrapper (s.guard(h)): judge the
		// callee's whole body and every handler-shaped argument.
		anyResolved := false
		if name := handlerName(v.Fun); name != "" {
			if gf := g.funcs[name]; gf != nil {
				anyResolved = true
				if fb := g.factoryStreams(name); fb != "" {
					return true, true, fb
				}
			}
		}
		for _, a := range v.Args {
			if s, r, w := g.verdict(a, binds, depth+1); r {
				anyResolved = true
				if s {
					return true, true, w
				}
			}
		}
		return false, anyResolved, ""
	}
	return false, false, ""
}

// factoryStreams reports a streaming marker inside a handler factory's whole body, including closures it returns.
func (g *guard) factoryStreams(name string) string {
	for _, f := range g.files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name && fd.Body != nil && !hasResponseWriter(fd.Type) {
				lf := &guardFunc{callees: map[string]bool{}}
				guardScan(fd.Body, lf)
				if lf.direct {
					return "factory " + name + ": " + lf.why
				}
			}
		}
	}
	return ""
}

func handlerName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.Ident:
		return v.Name
	case *ast.CallExpr:
		return handlerName(v.Fun)
	}
	return ""
}

// check returns the offending registrations and how many streaming()-wrapped registrations it saw.
func (g *guard) check() (bad []string, wrapped int) {
	// Fixpoint: which parameter positions of which functions receive the protected mux.
	paramPos := map[string]map[int]bool{}
	for changed := true; changed; {
		changed = false
		for _, f := range g.files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				al := muxAliases(fd, paramPos)
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					call, ok := x.(*ast.CallExpr)
					if !ok {
						return true
					}
					name := handlerName(call.Fun)
					for i, a := range call.Args {
						if id, ok := unparen(a).(*ast.Ident); ok && al[id.Name] && name != "" {
							if paramPos[name] == nil {
								paramPos[name] = map[int]bool{}
							}
							if !paramPos[name][i] {
								paramPos[name][i], changed = true, true
							}
						}
					}
					return true
				})
			}
		}
	}
	for _, f := range g.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			al := muxAliases(fd, paramPos)
			binds := localBindings(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); !ok || !al[id.Name] {
					return true // the root mux is outside the tenant-bound chain
				}
				pos := g.fset.Position(call.Pos())
				if wrap, ok := unparen(call.Args[1]).(*ast.CallExpr); ok {
					if id, ok := wrap.Fun.(*ast.Ident); ok && id.Name == "streaming" {
						wrapped++
						return true
					}
				}
				key := filepath.Base(pos.Filename) + ": " + handlerName(call.Args[1])
				if _, ok := streamingGuardAllow[key]; ok {
					return true
				}
				stream, resolved, why := g.verdict(call.Args[1], binds, 0)
				switch {
				case stream:
					bad = append(bad, pos.String()+": "+handlerName(call.Args[1])+" streams ("+why+") but is not wrapped in streaming()")
				case !resolved:
					bad = append(bad, pos.String()+": cannot resolve the handler of this registration; wrap it in streaming() or add a reviewed streamingGuardAllow entry (key \""+key+"\")")
				}
				return true
			})
		}
	}
	sort.Strings(bad)
	return
}

func guardParseDir(t *testing.T) *guard {
	t.Helper()
	fset := token.NewFileSet()
	paths, _ := filepath.Glob("*.go")
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		files = append(files, f)
	}
	return guardBuild(fset, files)
}

func guardParseSrc(t *testing.T, src string) *guard {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", "package controlplane\nimport (\"archive/zip\"; \"net/http\")\n"+src, 0)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return guardBuild(fset, []*ast.File{f})
}

func TestStreamingRoutesAreRegisteredThroughStreaming(t *testing.T) {
	bad, wrapped := guardParseDir(t).check()
	if len(bad) > 0 {
		t.Fatalf("streaming routes not registered through streaming(), or handlers the guard cannot resolve "+
			"(protected.HandleFunc(pattern, streaming(h)) releases the tenant-pinned connection):\n  %s",
			strings.Join(bad, "\n  "))
	}
	// A guard that scans nothing passes forever: the six known streaming routes must be seen.
	if wrapped < 6 {
		t.Fatalf("guard saw only %d streaming() registrations, want at least 6 (scan broken?)", wrapped)
	}
}

const guardFixtureHandlers = `
type Server struct{}
func (s *Server) handleDl(w http.ResponseWriter, r *http.Request) { zw := zip.NewWriter(w); _ = zw }
func (s *Server) handleQuiet(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
func (s *Server) wrap(h http.HandlerFunc) http.HandlerFunc { return h }
func streaming(h http.HandlerFunc) http.HandlerFunc { return h }
`

// Negative fixtures: every indirection that once escaped must be flagged, and the clean shapes must pass.
func TestStreamingGuardFlagsIndirectRegistrations(t *testing.T) {
	cases := []struct {
		name, body string
		wantBad    bool
	}{
		{"direct", `protected.HandleFunc("GET /x", s.handleDl)`, true},
		{"mux alias", `mux := protected; mux.HandleFunc("GET /x", s.handleDl)`, true},
		{"mux alias var decl", `var mux = protected; mux.HandleFunc("GET /x", s.handleDl)`, true},
		{"method value via variable", `h := s.handleDl; protected.HandleFunc("GET /x", h)`, true},
		{"inline forwarding literal", `protected.HandleFunc("GET /x", func(w http.ResponseWriter, r *http.Request) { s.handleDl(w, r) })`, true},
		{"literal streaming itself", `protected.HandleFunc("GET /x", func(w http.ResponseWriter, r *http.Request) { zw := zip.NewWriter(w); _ = zw })`, true},
		{"wrapper around streaming handler", `protected.HandleFunc("GET /x", s.wrap(s.handleDl))`, true},
		{"unresolvable handler", `protected.HandleFunc("GET /x", unknownPkg.Handler)`, true},
		{"unresolvable variable", `protected.HandleFunc("GET /x", mystery)`, true},
		{"wrapped in streaming", `protected.HandleFunc("GET /x", streaming(s.handleDl))`, false},
		{"wrapped via alias", `mux := protected; mux.HandleFunc("GET /x", streaming(s.handleDl))`, false},
		{"quiet handler", `protected.HandleFunc("GET /x", s.handleQuiet)`, false},
		{"quiet literal", `protected.HandleFunc("GET /x", func(w http.ResponseWriter, r *http.Request) { s.handleQuiet(w, r) })`, false},
		{"root mux ignored", `root.HandleFunc("GET /x", s.handleDl)`, false},
	}
	for _, c := range cases {
		src := guardFixtureHandlers + "func (s *Server) routes(protected, root *http.ServeMux) { " + c.body + " }\n"
		bad, _ := guardParseSrc(t, src).check()
		if c.wantBad && len(bad) == 0 {
			t.Errorf("%s: guard did NOT flag it", c.name)
		}
		if !c.wantBad && len(bad) != 0 {
			t.Errorf("%s: guard flagged a clean registration: %v", c.name, bad)
		}
	}
	// A mux handed to another function: the registration there, on a differently named parameter, is still scanned.
	src := guardFixtureHandlers + "func (s *Server) routes(protected *http.ServeMux) { s.mount(protected) }\n" +
		"func (s *Server) mount(m *http.ServeMux) { m.HandleFunc(\"GET /x\", s.handleDl) }\n"
	if bad, _ := guardParseSrc(t, src).check(); len(bad) == 0 {
		t.Error("mux passed to a helper: guard did NOT flag the registration on the helper's parameter")
	}
}

// releaseBoundConn belongs to binder.go and streaming(); a handler calling it by hand is the convention this
// change replaces, and it would not be covered by the guard above.
func TestReleaseBoundConnIsOnlyCalledByTheBinder(t *testing.T) {
	g := guardParseDir(t)
	for _, f := range g.files {
		if filepath.Base(g.fset.Position(f.Pos()).Filename) == "binder.go" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "releaseBoundConn" {
					t.Errorf("%s: call streaming() at registration instead of releaseBoundConn in the handler", g.fset.Position(c.Pos()))
				}
			}
			return true
		})
	}
}
