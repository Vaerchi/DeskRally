package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const helpTestRequestID = "abcdef01-2345-4678-89ab-cdef01234567"

func withHelpSupported(t *testing.T, v bool) {
	t.Helper()
	prev := helpRequestSupported.Load()
	helpRequestSupported.Store(v)
	fallbackHelpGate = newHelpGate() // a registry-less Server shares this gate: every test starts with a fresh one
	t.Cleanup(func() { helpRequestSupported.Store(prev) })
}

func helpDispatch(t *testing.T, s *Server, p *Peer, tag string, fields map[string]any) ServerToClient {
	t.Helper()
	c := p.conn.(*guestEndTestConn)
	fields["type"] = tag
	raw, _ := json.Marshal(fields)
	var msg ClientToServer
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	s.dispatch(p, msg)
	return guestEndTestReply(t, c)
}

func helpPeer(registered bool) *Peer {
	return &Peer{conn: &guestEndTestConn{sent: make(chan ServerToClient, 4)}, registered: registered,
		DeviceId: "authenticated-device", Tenant: "authenticated-tenant"}
}

type helpSeen struct {
	path string
	auth string
	body map[string]any
}

func helpCP(t *testing.T, status int, reply string) (*httptest.Server, chan helpSeen) {
	t.Helper()
	got := make(chan helpSeen, 16)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		got <- helpSeen{req.URL.Path, req.Header.Get("Authorization"), body}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(cp.Close)
	return cp, got
}

const helpOKReply = `{"created":true,"request":{"id":"` + helpTestRequestID + `","status":"open","note":"printer","created_at":"2026-10-31T10:00:00Z","expires_at":"2026-10-31T10:30:00Z"}}`

// Identity (device, tenant) comes from the CONNECTION: a body naming another device or tenant is
// ignored, and the route carries the authenticated device id.
func TestHelpRequestForwardsConnectionIdentity(t *testing.T) {
	withHelpSupported(t, true)
	cp, got := helpCP(t, 201, helpOKReply)
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	reply := helpDispatch(t, s, helpPeer(true), "help_request", map[string]any{
		"op_id": "op-1", "note": "printer", "device_id": "forged", "tenant_id": "forged", "device": "forged"})
	res, ok := reply.Payload.(HelpRequestResult)
	if !ok || reply.Type != "help_request_result" || res.Outcome != "ok" || res.Op != "help_request" || res.OpID != "op-1" ||
		res.Request == nil || res.Request.ID != helpTestRequestID || res.Request.Status != "open" {
		t.Fatalf("reply = %#v", reply)
	}
	seen := <-got
	if seen.path != "/internal/devices/authenticated-device/help-request" || seen.auth != "Bearer "+strings.Repeat("x", 256) {
		t.Fatalf("path/auth = %s / %q", seen.path, seen.auth)
	}
	if seen.body["tenant_id"] != "authenticated-tenant" || seen.body["op_id"] != "op-1" || seen.body["note"] != "printer" {
		t.Fatalf("body = %#v", seen.body)
	}
	if _, leaked := seen.body["device_id"]; leaked {
		t.Fatalf("a body device id was forwarded: %#v", seen.body)
	}
	if len(seen.body) != 3 {
		t.Fatalf("unexpected forwarded fields: %#v", seen.body)
	}
}

func TestHelpCancelAndStatusForwardIdentity(t *testing.T) {
	withHelpSupported(t, true)
	cp, got := helpCP(t, 200, `{"outcome":"cancelled","request":{"id":"`+helpTestRequestID+`","status":"cancelled"}}`)
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	reply := helpDispatch(t, s, helpPeer(true), "help_cancel", map[string]any{"request_id": helpTestRequestID, "tenant_id": "forged"})
	if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "ok" || res.Op != "help_cancel" || res.Request == nil || res.Request.Status != "cancelled" {
		t.Fatalf("cancel reply = %#v", reply)
	}
	seen := <-got
	if seen.path != "/internal/devices/authenticated-device/help-cancel" || seen.body["tenant_id"] != "authenticated-tenant" || seen.body["request_id"] != helpTestRequestID {
		t.Fatalf("cancel forwarded %s %#v", seen.path, seen.body)
	}
	reply = helpDispatch(t, s, helpPeer(true), "help_status", map[string]any{"tenant_id": "forged"})
	if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "ok" || res.Op != "help_status" {
		t.Fatalf("status reply = %#v", reply)
	}
	seen = <-got
	if seen.path != "/internal/devices/authenticated-device/help-status" || seen.body["tenant_id"] != "authenticated-tenant" || len(seen.body) != 1 {
		t.Fatalf("status forwarded %s %#v", seen.path, seen.body)
	}
}

// Nothing reaches the control plane from an unregistered peer, dev mode, a connection with no tenant, a
// control plane that does not list the feature, or a malformed message.
func TestHelpRequestRefusals(t *testing.T) {
	cp, got := helpCP(t, 201, helpOKReply)
	authed := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	dev := &Server{guestEnd: guestEndTestReporter(t, cp.URL)}
	valid := func() map[string]any { return map[string]any{"op_id": "op-1", "note": "x"} }
	refused := func(t *testing.T, reply ServerToClient, op string) {
		t.Helper()
		if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "refused" || res.Op != op {
			t.Fatalf("reply = %#v", reply)
		}
	}
	t.Run("unregistered", func(t *testing.T) {
		withHelpSupported(t, true)
		for _, tag := range []string{"help_request", "help_cancel", "help_status"} {
			reply := helpDispatch(t, authed, helpPeer(false), tag, map[string]any{"op_id": "op-1", "request_id": helpTestRequestID})
			if _, ok := reply.Payload.(Rejected); !ok {
				t.Fatalf("%s: reply = %#v", tag, reply)
			}
		}
	})
	t.Run("dev mode", func(t *testing.T) {
		withHelpSupported(t, true)
		refused(t, helpDispatch(t, dev, helpPeer(true), "help_request", valid()), "help_request")
	})
	t.Run("no tenant", func(t *testing.T) {
		withHelpSupported(t, true)
		p := helpPeer(true)
		p.Tenant = ""
		refused(t, helpDispatch(t, authed, p, "help_request", valid()), "help_request")
	})
	t.Run("control plane lacks the feature", func(t *testing.T) {
		withHelpSupported(t, false)
		refused(t, helpDispatch(t, authed, helpPeer(true), "help_request", valid()), "help_request")
	})
	t.Run("bad op ids", func(t *testing.T) {
		withHelpSupported(t, true)
		for _, op := range []string{"", "has space", "../x", strings.Repeat("a", 65), "semi;colon"} {
			reply := helpDispatch(t, authed, helpPeer(true), "help_request", map[string]any{"op_id": op})
			refused(t, reply, "help_request")
			if res := reply.Payload.(HelpRequestResult); res.OpID != "" {
				t.Fatalf("hostile op_id %q echoed back as %q", op, res.OpID)
			}
		}
	})
	t.Run("note over 200 characters", func(t *testing.T) {
		withHelpSupported(t, true)
		refused(t, helpDispatch(t, authed, helpPeer(true), "help_request", map[string]any{"op_id": "op-1", "note": strings.Repeat("é", 201)}), "help_request")
		// 200 multi-byte characters pass: the bound is characters, not bytes.
		reply := helpDispatch(t, authed, helpPeer(true), "help_request", map[string]any{"op_id": "op-1", "note": strings.Repeat("é", 200)})
		if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
			t.Fatalf("200 chars refused: %#v", reply)
		}
		<-got
	})
	t.Run("bad cancel id", func(t *testing.T) {
		withHelpSupported(t, true)
		refused(t, helpDispatch(t, authed, helpPeer(true), "help_cancel", map[string]any{"request_id": "../x"}), "help_cancel")
	})
	select {
	case s := <-got:
		t.Fatalf("a refused message reached the control plane: %+v", s)
	default:
	}
}

func TestHelpPeerRateLimit(t *testing.T) {
	withHelpSupported(t, true)
	cp, got := helpCP(t, 201, helpOKReply)
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}, reg: NewRegistry(time.Minute)}
	p := helpPeer(true)
	now := time.Now()
	key := helpGateKey(p.Tenant, p.DeviceId)
	for i := 0; i < helpPeerPerMinute; i++ {
		if !s.helpGate().admit(key, now) {
			t.Fatalf("message %d refused early", i)
		}
		s.helpGate().release(key)
	}
	reply := helpDispatch(t, s, p, "help_status", map[string]any{})
	if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "unavailable" {
		t.Fatalf("reply = %#v", reply)
	}
	// The window rolls: a minute later the budget is back.
	if !s.helpGate().admit(key, now.Add(61*time.Second)) {
		t.Fatal("budget did not recover after the window")
	}
	select {
	case s := <-got:
		t.Fatalf("a limited message reached the control plane: %+v", s)
	default:
	}
}

// Review finding 1: the budget belongs to the DEVICE and lives in the registry, so a new connection (a new
// Peer) of the same device does not start with a fresh budget; another device keeps its own.
func TestHelpBudgetSurvivesReconnect(t *testing.T) {
	withHelpSupported(t, true)
	cp, got := helpCP(t, 201, helpOKReply)
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}, reg: NewRegistry(time.Minute)}
	old := helpPeer(true)
	for i := 0; i < helpPeerPerMinute; i++ {
		if res, ok := helpDispatch(t, s, old, "help_status", map[string]any{}).Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
			t.Fatalf("message %d = %#v", i, res)
		}
		<-got
	}
	fresh := helpPeer(true) // the same device reconnects: a brand-new Peer
	if res, ok := helpDispatch(t, s, fresh, "help_status", map[string]any{}).Payload.(HelpRequestResult); !ok || res.Outcome != "unavailable" {
		t.Fatalf("a reconnected device got a fresh budget: %#v", res)
	}
	other := helpPeer(true)
	other.DeviceId = "another-device"
	if res, ok := helpDispatch(t, s, other, "help_status", map[string]any{}).Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
		t.Fatalf("another device was limited by the first one's budget: %#v", res)
	}
	// the same device id under ANOTHER tenant is a different key
	foreign := helpPeer(true)
	foreign.Tenant = "other-tenant"
	if res, ok := helpDispatch(t, s, foreign, "help_status", map[string]any{}).Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
		t.Fatalf("the budget key ignores the tenant: %#v", res)
	}
}

// The gate is bounded and entries lapse: at the key cap a NEW device is refused while live entries fill the
// table, existing devices keep working, and once the window passes the table frees up.
func TestHelpGateIsBoundedWithTTL(t *testing.T) {
	g := newHelpGate()
	g.maxKeys = 3
	t0 := time.Now()
	for _, k := range []string{"a", "b", "c"} {
		if !g.admit(k, t0) {
			t.Fatalf("%s refused", k)
		}
		g.release(k)
	}
	if g.admit("d", t0.Add(time.Second)) {
		t.Fatal("a new device was admitted past the table bound")
	}
	if !g.admit("a", t0.Add(time.Second)) {
		t.Fatal("a tracked device was refused at the cap")
	}
	g.release("a")
	if !g.admit("d", t0.Add(helpPeerWindow+time.Second)) {
		t.Fatal("lapsed entries were not evicted to make room")
	}
	g.release("d")
	g.mu.Lock()
	n := len(g.times)
	g.mu.Unlock()
	if n > g.maxKeys {
		t.Fatalf("table grew to %d, bound %d", n, g.maxKeys)
	}
	// nothing in flight, nothing leaked
	g.mu.Lock()
	inflight := len(g.inflight)
	g.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("%d in-flight slots leaked", inflight)
	}
}

// One device may hold at most helpInflightPerDevice jobs in the worker queue; the slot comes back when the
// reply is produced, and a job the queue refuses gives its slot back at once.
func TestHelpInflightCapPerDevice(t *testing.T) {
	withHelpSupported(t, true)
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(helpInflightPerDevice)
	var once int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if atomic.AddInt32(&once, 1) <= int32(helpInflightPerDevice) {
			started.Done()
			<-release
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(helpOKReply))
	}))
	defer cp.Close()
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(release) }) }
	defer open() // runs BEFORE cp.Close, so a failing assertion cannot hang the server shutdown
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}, reg: NewRegistry(time.Minute)}
	p := helpPeer(true)
	c := p.conn.(*guestEndTestConn)
	c.sent = make(chan ServerToClient, 8)
	send := func() {
		raw, _ := json.Marshal(map[string]any{"type": "help_status"})
		var msg ClientToServer
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatal(err)
		}
		s.dispatch(p, msg)
	}
	for i := 0; i < helpInflightPerDevice; i++ {
		send()
	}
	started.Wait() // both are inside the control-plane call: in flight
	send()         // one more from the same device
	third := guestEndTestReply(t, c)
	if res, ok := third.Payload.(HelpRequestResult); !ok || res.Outcome != "unavailable" {
		t.Fatalf("the over-cap message = %#v, want an immediate unavailable", third)
	}
	// another device is not held back by this one
	other := helpPeer(true)
	other.DeviceId = "bystander"
	if res, ok := helpDispatch(t, s, other, "help_status", map[string]any{}).Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
		t.Fatalf("a bystander device was blocked: %#v", res)
	}
	open()
	for i := 0; i < helpInflightPerDevice; i++ {
		if res, ok := guestEndTestReply(t, c).Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
			t.Fatalf("in-flight reply %d = %#v", i, res)
		}
	}
	// slots are back
	if res, ok := helpDispatch(t, s, p, "help_status", map[string]any{}).Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
		t.Fatalf("after the replies the device is still blocked: %#v", res)
	}
}

// The control plane's answers map to outcomes the agent can act on; 429 carries its retry hint.
func TestHelpOutcomeMapping(t *testing.T) {
	withHelpSupported(t, true)
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		tag     string
		want    string
		wantReq string
		retry   int
	}{
		{"created", 201, helpOKReply, "help_request", "ok", "open", 0},
		{"existing", 200, helpOKReply, "help_request", "ok", "open", 0},
		{"limited", 429, `{"error":"x","scope":"device_hour","retry_after_seconds":321}`, "help_request", "limited", "", 321},
		{"limited without hint", 429, `{}`, "help_request", "limited", "", 60},
		{"ineligible machine", 409, `{"error":"x","refused":true}`, "help_request", "refused", "", 0},
		{"suspended tenant", 403, `{"error":"tenant suspended"}`, "help_request", "refused", "", 0},
		{"cancel lost the race", 409, `{"error":"help request is accepted","request":{"id":"` + helpTestRequestID + `","status":"accepted"}}`, "help_cancel", "conflict", "accepted", 0},
		{"cancel unknown id", 404, `{"error":"help request not found"}`, "help_cancel", "not_found", "", 0},
		{"route absent 404", 404, `404 page not found`, "help_status", "unavailable", "", 0},
		{"older CP 401", 401, `{"error":"unauthorized"}`, "help_status", "unavailable", "", 0},
		{"CP error", 503, `{}`, "help_status", "unavailable", "", 0},
		{"unexpected status", 302, ``, "help_status", "unavailable", "", 0},
		{"oversized answer", 200, `{"request":{"note":"` + strings.Repeat("a", 9000) + `"}}`, "help_status", "unavailable", "", 0},
		{"status none", 200, `{"request":null}`, "help_status", "ok", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp, _ := helpCP(t, tc.status, tc.body)
			s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}, reg: NewRegistry(time.Minute)}
			fields := map[string]any{"op_id": "op-1", "request_id": helpTestRequestID}
			reply := helpDispatch(t, s, helpPeer(true), tc.tag, fields)
			res, ok := reply.Payload.(HelpRequestResult)
			if !ok || res.Outcome != tc.want || res.RetryAfterSeconds != tc.retry {
				t.Fatalf("reply = %#v, want outcome %s retry %d", reply, tc.want, tc.retry)
			}
			if tc.wantReq != "" && (res.Request == nil || res.Request.Status != tc.wantReq) {
				t.Fatalf("request = %#v, want status %s", res.Request, tc.wantReq)
			}
			// Every help_cancel answer names the request it is about (not_found carries no Request);
			// nothing else does.
			wantCancelOf := ""
			if tc.tag == "help_cancel" {
				wantCancelOf = helpTestRequestID
			}
			if res.CancelOf != wantCancelOf {
				t.Fatalf("cancel_of = %q, want %q", res.CancelOf, wantCancelOf)
			}
		})
	}
}

// A 5xx is retried (create is idempotent on op_id); a later success is the answer.
func TestHelpTransient5xxIsRetried(t *testing.T) {
	withHelpSupported(t, true)
	var mu sync.Mutex
	calls := 0
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(helpOKReply))
	}))
	defer cp.Close()
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	reply := helpDispatch(t, s, helpPeer(true), "help_request", map[string]any{"op_id": "op-1"})
	if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "ok" {
		t.Fatalf("reply = %#v", reply)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

// The forwarding queue is bounded: with every worker blocked, the queue admits exactly its depth and the
// next message is dropped (answered "unavailable"), never waited on.
func TestHelpQueueIsBounded(t *testing.T) {
	startHelpWorkers()
	release := make(chan struct{})
	started := make(chan struct{}, helpWorkerCount)
	accepted := 0
	var wg sync.WaitGroup
	mk := func() helpJob {
		wg.Add(1)
		return helpJob{
			run: func(context.Context) HelpRequestResult {
				select {
				case started <- struct{}{}:
				default:
				}
				<-release
				return HelpRequestResult{}
			},
			reply: func(HelpRequestResult) { wg.Done() },
		}
	}
	// Occupy every worker first, so the queue depth is measured against a stalled consumer.
	for i := 0; i < helpWorkerCount; i++ {
		if !enqueueHelp(mk()) {
			t.Fatalf("worker job %d refused", i)
		}
		accepted++
		<-started
	}
	for i := 0; i < helpQueueDepth; i++ {
		if !enqueueHelp(mk()) {
			t.Fatalf("queued job %d refused before the depth", i)
		}
		accepted++
	}
	if enqueueHelp(helpJob{run: func(context.Context) HelpRequestResult { return HelpRequestResult{} }, reply: func(HelpRequestResult) {}}) {
		t.Fatal("a job beyond the queue depth was admitted")
	}
	close(release)
	wg.Wait()
	if accepted != helpWorkerCount+helpQueueDepth {
		t.Fatalf("accepted = %d", accepted)
	}
}

// An overloaded queue is answered to the agent, not swallowed.
func TestHelpOverloadAnswersUnavailable(t *testing.T) {
	withHelpSupported(t, true)
	cp, _ := helpCP(t, 201, helpOKReply)
	s := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	startHelpWorkers()
	release := make(chan struct{})
	var wg sync.WaitGroup
	stall := func() helpJob {
		wg.Add(1)
		return helpJob{run: func(context.Context) HelpRequestResult { <-release; return HelpRequestResult{} }, reply: func(HelpRequestResult) { wg.Done() }}
	}
	// Fill workers and queue; admission may be racing the workers picking jobs up, so push until refused.
	for enqueueHelp(stall()) {
	}
	wg.Done() // the refused job's wg.Add never got a reply
	reply := helpDispatch(t, s, helpPeer(true), "help_status", map[string]any{})
	if res, ok := reply.Payload.(HelpRequestResult); !ok || res.Outcome != "unavailable" {
		t.Fatalf("reply = %#v", reply)
	}
	close(release)
	wg.Wait()
}

// The 1 KiB frame bound applies to help frames only, on the real read loop.
func TestHelpFrameBoundOnRealSocket(t *testing.T) {
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{maxTotal: 4, maxPending: 4, preAuthTimeout: 5 * time.Second})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	// Control: a small help frame from an unregistered peer is Rejected (dispatch ran).
	writeJSONMsg(t, c, "help_request", HelpRequest{OpID: "op-1", Note: "x"})
	readUntil(t, c, "rejected", 2*time.Second)
	// An oversized one never reaches dispatch: the frame bound answers first.
	writeJSONMsg(t, c, "help_request", HelpRequest{OpID: "op-1", Note: strings.Repeat("a", maxHelpFrameBytes)})
	raw := readUntil(t, c, "help_request_result", 2*time.Second)
	if !strings.Contains(string(raw), `"outcome":"refused"`) {
		t.Fatalf("oversized frame answer = %s", raw)
	}
	// The same size on a NON-help message is not this bound's business (a heartbeat of 1.1 KiB is
	// handled by dispatch: rejected as unregistered).
	writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: strings.Repeat("d", maxHelpFrameBytes)})
	readUntil(t, c, "rejected", 2*time.Second)
}

func TestHelpWireRoundTrip(t *testing.T) {
	var msg ClientToServer
	if err := json.Unmarshal([]byte(`{"type":"help_request","op_id":"o1","note":"hi"}`), &msg); err != nil {
		t.Fatal(err)
	}
	if p, ok := msg.Payload.(*HelpRequest); !ok || p.OpID != "o1" || p.Note != "hi" {
		t.Fatalf("decoded %#v", msg.Payload)
	}
	if err := json.Unmarshal([]byte(`{"type":"help_cancel","request_id":"r1"}`), &msg); err != nil {
		t.Fatal(err)
	}
	if p, ok := msg.Payload.(*HelpCancel); !ok || p.RequestID != "r1" {
		t.Fatalf("decoded %#v", msg.Payload)
	}
	if err := json.Unmarshal([]byte(`{"type":"help_status"}`), &msg); err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.Payload.(*HelpStatus); !ok {
		t.Fatalf("decoded %#v", msg.Payload)
	}
	raw, err := json.Marshal(ServerToClient{Payload: HelpRequestResult{Op: "help_status", Outcome: "ok"}})
	if err != nil || !strings.Contains(string(raw), `"type":"help_request_result"`) {
		t.Fatalf("encoded %s (%v)", raw, err)
	}
	var back ServerToClient
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if res, ok := back.Payload.(*HelpRequestResult); !ok || res.Outcome != "ok" {
		t.Fatalf("decoded %#v", back.Payload)
	}
}

// help_request_v1 is advertised next to session_ended_v1, only to an authenticated tenanted connection and
// only after the control plane's probe listed it; the probe reads both from one answer.
func TestHelpFeatureAdvertisement(t *testing.T) {
	withSessionEndedSupported(t, true)
	withHelpSupported(t, false)
	authed, err := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := NewServer(time.Minute, "relay-1:4444", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	features := func(s *Server, p *Peer) string {
		raw, _ := json.Marshal(ServerToClient{Payload: s.registeredMsg(p)})
		return string(raw)
	}
	if strings.Contains(features(authed, &Peer{Tenant: "t"}), "help_request_v1") {
		t.Fatal("advertised before the probe listed it")
	}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`{"features":["session_ended_v1","help_request_v1"]}`))
	}))
	defer cp.Close()
	if got := guestEndTestReporter(t, cp.URL).probeCapabilities(context.Background()); got != probeSupported {
		t.Fatalf("probe = %v", got)
	}
	if got := features(authed, &Peer{Tenant: "t"}); !strings.Contains(got, `"features":["session_ended_v1","help_request_v1"]`) {
		t.Fatalf("not advertised after a positive probe: %s", got)
	}
	if strings.Contains(features(dev, &Peer{Tenant: "t"}), "help_request_v1") {
		t.Fatal("dev mode advertised help")
	}
	if strings.Contains(features(authed, &Peer{}), "help_request_v1") {
		t.Fatal("advertised to a tenantless connection")
	}
	// A control plane that lists only session_ended_v1 (older) turns it back off.
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`{"features":["session_ended_v1"]}`))
	}))
	defer old.Close()
	if got := guestEndTestReporter(t, old.URL).probeCapabilities(context.Background()); got != probeSupported {
		t.Fatalf("probe = %v", got)
	}
	if strings.Contains(features(authed, &Peer{Tenant: "t"}), "help_request_v1") {
		t.Fatal("still advertised after the control plane stopped listing it")
	}
}

// A peer told session_ended_v1 but not help is reconnected when help flips on, and is NOT reconnected
// while help stays off (no reconnect loop).
func TestHelpFlipBouncesOnlyWhenSupported(t *testing.T) {
	withSessionEndedSupported(t, true)
	withHelpSupported(t, false)
	s, err := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	s.bounceDelay = func() time.Duration { return 0 }
	c := &fakeConn{}
	p := &Peer{DeviceId: "dev-help", Tenant: "tenant-1", conn: c}
	s.reg.Register(p)
	_ = s.registeredMsg(p) // told session_ended only
	time.Sleep(100 * time.Millisecond)
	if got := closeFrameReasons(c); len(got) != 0 {
		t.Fatalf("reconnected while help is unsupported: %q", got)
	}
	if n := s.bounceSessionEndedStale(); n != 0 {
		t.Fatalf("snapshot = %d, want 0", n)
	}
	helpRequestSupported.Store(true)
	if n := s.bounceSessionEndedStale(); n != 1 {
		t.Fatalf("snapshot after the flip = %d, want 1", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(closeFrameReasons(c)) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := closeFrameReasons(c); len(got) != 1 || got[0] != "capability changed; re-register" {
		t.Fatalf("close frames = %q", got)
	}
}
