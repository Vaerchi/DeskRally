package controlplane

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// docs/49: the generalised agent end report. Same authority and store transition as guest-ended;
// the reason is validated (unknown values become "other") and reaches the store.
func TestSessionEndedRouteCarriesTheReason(t *testing.T) {
	const tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const device = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	const session = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	srv, machines := identityServer(t)
	if err := machines.EnrollMachine(context.Background(), tenant, &Machine{
		DeviceID: device, GroupID: groupG, Pubkey: testPubkeyHex(t),
	}); err != nil {
		t.Fatal(err)
	}
	stub := &guestEndStub{outcome: GuestEndEnded}
	srv.GuestEnds = stub
	post := func(path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	withReason := func(r string) string {
		return `{"device_id":"` + device + `","tenant_id":"` + tenant + `","reason":"` + r + `"}`
	}
	ended := "/internal/sessions/" + session + "/ended"

	if rec := post(ended, withReason("lease_lapsed"), ""); rec.Code != 401 {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := post(ended, withReason("lease_lapsed")[:len(withReason("lease_lapsed"))-1]+`,"x":1}`, deviceIdentityToken); rec.Code != 400 {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if len(stub.calls) != 0 {
		t.Fatal("store called before authorization/validation completed")
	}
	for reason, want := range map[string]SessionEndReason{
		"lease_lapsed": EndReasonLeaseLapsed, "viewer_left": EndReasonViewerLeft, "service_stop": EndReasonServiceStop,
		"guest_ended": EndReasonGuestEnded, "a-future-reason": EndReasonOther, "": EndReasonOther,
	} {
		stub.calls = nil
		if rec := post(ended, withReason(reason), deviceIdentityToken); rec.Code != 200 {
			t.Fatalf("%q: %d %s", reason, rec.Code, rec.Body.String())
		}
		if len(stub.calls) != 1 || stub.calls[0].reason != want || stub.calls[0].session != session {
			t.Fatalf("%q reached the store as %+v, want reason %q", reason, stub.calls, want)
		}
	}
	// The agent's queue age is optional, bounded, and reaches the store unchanged.
	withAge := func(age string) string {
		return `{"device_id":"` + device + `","tenant_id":"` + tenant + `","reason":"idle","queue_age_ms":` + age + `}`
	}
	stub.calls = nil
	if rec := post(ended, withAge("1234"), deviceIdentityToken); rec.Code != 200 {
		t.Fatalf("queue age: %d %s", rec.Code, rec.Body.String())
	}
	if len(stub.calls) != 1 || stub.calls[0].queueAgeMs == nil || *stub.calls[0].queueAgeMs != 1234 || stub.calls[0].reason != EndReasonIdle {
		t.Fatalf("queue age reached the store as %+v", stub.calls)
	}
	stub.calls = nil
	if rec := post(ended, withReason("idle"), deviceIdentityToken); rec.Code != 200 || len(stub.calls) != 1 || stub.calls[0].queueAgeMs != nil {
		t.Fatalf("an absent queue age must stay absent: %d %+v", rec.Code, stub.calls)
	}
	stub.calls = nil
	for _, bad := range []string{"-1", "2592000001", "1.5", `"5"`} {
		if rec := post(ended, withAge(bad), deviceIdentityToken); rec.Code != 400 {
			t.Fatalf("queue age %s: %d", bad, rec.Code)
		}
	}
	if rec := post(ended, withAge("2592000000"), deviceIdentityToken); rec.Code != 200 {
		t.Fatalf("queue age at the 30-day bound: %d", rec.Code)
	}
	stub.calls = nil
	// The original route still reports guest_ended, and refuses a reason field (strict body).
	stub.calls = nil
	guest := "/internal/sessions/" + session + "/guest-ended"
	if rec := post(guest, `{"device_id":"`+device+`","tenant_id":"`+tenant+`"}`, deviceIdentityToken); rec.Code != 200 {
		t.Fatalf("guest-ended: %d", rec.Code)
	}
	if len(stub.calls) != 1 || stub.calls[0].reason != EndReasonGuestEnded {
		t.Fatalf("guest-ended reached the store as %+v", stub.calls)
	}
	if rec := post(guest, withReason("viewer_left"), deviceIdentityToken); rec.Code != 400 {
		t.Fatalf("guest-ended accepted a reason field: %d", rec.Code)
	}
}

// docs/49 v4: signaling advertises session_ended_v1 only after this probe says the route exists.
func TestInternalCapabilities(t *testing.T) {
	srv, _ := identityServer(t)
	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/internal/capabilities", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := get(""); rec.Code != 401 {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := get("wrong"); rec.Code != 401 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if rec := get(deviceIdentityToken); rec.Code != 200 || strings.Contains(rec.Body.String(), SessionEndedFeature) {
		t.Fatalf("without a guest-end store the feature must not be advertised: %d %s", rec.Code, rec.Body.String())
	}
	srv.GuestEnds = &guestEndStub{outcome: GuestEndEnded}
	if rec := get(deviceIdentityToken); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"features":["`+SessionEndedFeature+`"]}` {
		t.Fatalf("with the route mounted the feature must be advertised exactly: %d %s", rec.Code, rec.Body.String())
	}
	// The dependency matrix: the feature is advertised exactly when /ended is mounted. A fresh
	// server per case, because the routes are fixed when the handler is first built.
	for _, c := range []struct {
		name            string
		guestEnds, mach bool
	}{{"both", true, true}, {"no machines", true, false}, {"no guest-end store", false, true}, {"neither", false, false}} {
		cs, machines := identityServer(t)
		cs.GuestEnds, cs.Machines = nil, nil
		if c.guestEnds {
			cs.GuestEnds = &guestEndStub{outcome: GuestEndEnded}
		}
		if c.mach {
			cs.Machines = machines
		}
		h := cs.Handler()
		serve := func(method, path, body string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		caps := serve("GET", "/internal/capabilities", "")
		want := `{"features":[]}`
		if c.guestEnds && c.mach {
			want = `{"features":["` + SessionEndedFeature + `"]}`
		}
		if caps.Code != 200 || strings.TrimSpace(caps.Body.String()) != want {
			t.Errorf("%s: capabilities %d %s, want %s", c.name, caps.Code, caps.Body.String(), want)
		}
		// An unmounted /ended falls through to the session-authenticated chain and answers 401, not
		// 404, so "mounted" means the handler ran: a valid token with an empty body is its 400.
		ended := serve("POST", "/internal/sessions/cccccccc-cccc-cccc-cccc-cccccccccccc/ended", `{}`)
		if mounted := ended.Code == 400; mounted != (c.guestEnds && c.mach) {
			t.Errorf("%s: /ended mounted=%v (%d), want %v", c.name, mounted, ended.Code, c.guestEnds && c.mach)
		}
	}
}

// docs/49 v4 invariant: a session_record id receives exactly one session ticket, minted for the row
// created in that request. The attended handler mints for attended ids (no session_record). Any NEW
// mint site (e.g. a "re-issue ticket on reconnect") would let one session id reach the agent twice, so
// the agent's end report could close a live second lifetime: this guard fails the build until docs/49
// is revisited.
//
// docs/51 §8.5 is the ONE reviewed extension: the mint moved into brokerSessionStart, shared by
// handleStartSession and by the session-transfer ticket endpoint, which hands the acceptor S2's ticket.
// It re-mints only while S2's id has no redemption row (the unredeemed earlier ticket is simply
// superseded) and answers 409 once it is redeemed, so S2's id still reaches the agent once. The second
// check below pins brokerSessionStart's callers so it cannot grow a third.
func TestSessionTicketsAreMintedOnlyAtSessionStart(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// Exact mint references per allowed function: brokerSessionStart mints once for a controller
	// and once for an observer (one of the two runs per call); handleConnectAttended mints once.
	allowed := map[string]struct {
		file  string
		mints int
	}{"brokerSessionStart": {"http_session_admission.go", 2}, "handleConnectAttended": {"http_attended.go", 1}}
	found := map[string]int{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		// Every declaration is scanned, including package-level initializers (which are never an
		// allowed mint site).
		for _, decl := range file.Decls {
			owner, node := "<package level>", ast.Node(decl)
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = fn.Name.Name
			}
			ast.Inspect(node, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "MintSessionTicket" && sel.Sel.Name != "MintObserverSessionTicket") {
					return true
				}
				if a, ok := allowed[owner]; ok && a.file == f {
					found[owner]++
					return true
				}
				t.Errorf("%s: %s references %s; session tickets may be minted only at session start (docs/49 v4)",
					fset.Position(sel.Pos()), owner, sel.Sel.Name)
				return true
			})
		}
	}
	for name, a := range allowed {
		if found[name] != a.mints {
			t.Errorf("%s holds %d ticket mint(s), want exactly %d: revisit docs/49 before changing session ticket issuance", name, found[name], a.mints)
		}
	}
	// brokerSessionStart is the mint, so its callers are the real mint sites: exactly the session start,
	// the session-transfer ticket endpoint (docs/51 §8.5) and a help-request accept, which IS a session start
	// bound to its request (docs/64 H-C1).
	callers := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			owner := "<package level>"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "brokerSessionStart" {
					callers[owner]++
				}
				return true
			})
		}
	}
	if len(callers) != 3 || callers["handleStartSession"] != 1 || callers["handleTransferTicket"] != 1 || callers["handleAcceptHelpRequest"] != 1 {
		t.Errorf("brokerSessionStart callers = %v, want exactly handleStartSession, handleTransferTicket and handleAcceptHelpRequest once each (docs/49 v4, docs/51 §8.5, docs/64 H-C1)", callers)
	}
}
