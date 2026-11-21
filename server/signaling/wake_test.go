package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const testWakeChallenge = "0123456789abcdef0123456789abcdef"

func wakeLoopback(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &httptest.Server{Listener: listener, Config: &http.Server{Handler: h}}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func wakeFixture(t *testing.T) (*Server, *atomic.Int32) {
	t.Helper()
	s := &Server{reg: NewRegistry(time.Minute), now: time.Now}
	s.broker = NewBroker(s.reg, "test-public-key", "", nil)
	calls := new(atomic.Int32)
	cp := wakeLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var b struct {
			DeviceID string `json:"device_id"`
			Key      string `json:"device_pubkey"`
			wakeConnRef
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil ||
			b.DeviceID != agentAuthGoldenDevice || b.Key != agentAuthGoldenPubkeyHex ||
			b.Incarnation != s.reg.incarnation || b.Generation == 0 ||
			r.Header.Get("Authorization") != "Bearer "+presenceTestToken {
			t.Error("unexpected LAN service call")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/internal/devices/lan-epoch":
			fmt.Fprint(w, `{"epoch":7}`)
		case "/internal/devices/lan":
			fmt.Fprint(w, `{"status":"applied"}`)
		default:
			t.Error("unexpected CP route")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	s.wakeCP = newWakeClient(cp.URL, presenceTestToken)
	s.reg.wakeActive.Store(true)
	return s, calls
}

func wakeTestPeer(conn peerConn) *Peer {
	p := &Peer{DeviceId: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Tenant: agentAuthGoldenTenant, conn: conn}
	p.wake.proved = true
	p.wake.installedActive.Store(true)
	p.wake.lanFeature = true
	p.wake.wakeFeature = true
	return p
}

func wakeTestReady(p *Peer) {
	epoch := int64(7)
	p.wake.epoch = &epoch
	challenge, _ := lowerHex(testWakeChallenge, 16)
	value := [16]byte(challenge)
	p.wake.challenge.Store(&value)
	p.wake.acknowledged.Store(true)
}

func wakeReport(t *testing.T, raw string) *LanReport {
	t.Helper()
	var msg ClientToServer
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	return msg.Payload.(*LanReport)
}

func wakeTestRequest(s *Server, device string, forward bool, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.SetPathValue("device_id", device)
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	rec := httptest.NewRecorder()
	s.wakeHandler(presenceTestToken, forward)(rec, req)
	return rec
}

func wakeTestBody(t *testing.T, p *Peer, overrides map[string]string) string {
	t.Helper()
	ctx := wakeContextFor(p)
	claims := map[string]string{"tenant_id": p.Tenant, "relay_key_sha256": ctx.DeviceKeySHA256, "wake_challenge": ctx.Challenge}
	for key, value := range overrides {
		claims[key] = value
	}
	body, err := json.Marshal(map[string]any{"conn_ref": ctx.ConnRef, "artifact": map[string]any{"claims": claims, "sig": "00"}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestWakeLANReadinessAndReconnectBudget(t *testing.T) {
	s, calls := wakeFixture(t)
	conn := &fakeConn{}
	p := wakeTestPeer(conn)
	s.reg.Register(p)
	contextStatus := func() int { return wakeTestRequest(s, p.DeviceId, false, "").Code }
	hello := &WakeHello{Challenge: testWakeChallenge}
	s.handleWakeHello(p, hello)
	if contextStatus() != 409 || s.reg.Snapshot()[0].WakeCapable {
		t.Fatal("challenge alone made the relay ready")
	}
	p.wake.challenge.Store(nil)
	report := wakeReport(t, `{"type":"lan_report","seq":1,"device_id":"spoof","device_pubkey":"spoof","entries":[]}`)
	s.handleLanReport(p, report)
	if contextStatus() != 409 || s.reg.Snapshot()[0].WakeCapable || calls.Load() != 2 {
		t.Fatal("LAN ACK alone made the relay ready or used an unexpected call count")
	}
	s.handleWakeHello(p, hello)
	rec := wakeTestRequest(s, p.DeviceId, false, "")
	var ctx wakeContext
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ctx) != nil ||
		ctx.ConnRef != p.wake.ref || ctx.Epoch != 7 || ctx.Challenge != testWakeChallenge || len(ctx.DeviceKeySHA256) != 64 ||
		!s.reg.Snapshot()[0].WakeCapable {
		t.Fatal("ready relay did not expose the expected context")
	}
	s.handleLanReport(p, report)
	messages := conn.messages()
	if calls.Load() != 2 || len(messages) != 2 || messages[1].Payload != (LanReportAck{Seq: 1}) {
		t.Fatal("identical committed report was not acknowledged locally")
	}
	s.handleLanReport(p, wakeReport(t, `{"type":"lan_report","seq":2,"entries":[]}`))
	if calls.Load() != 3 {
		t.Fatal("third token was not used")
	}
	for range 4 {
		p = wakeTestPeer(&fakeConn{})
		s.reg.Register(p)
		s.handleLanReport(p, report)
	}
	if calls.Load() != 3 {
		t.Fatal("reconnect reset the device budget")
	}
}

func TestWakeLANShapeAndCanonicalDigest(t *testing.T) {
	for _, entries := range []string{
		"null", "[{},{},{},{},{}]",
		`[{"mac":"AA:bb:cc:dd:ee:ff","ipv4_network":"10.0.0.0/24"}]`,
		`[{"mac":"aa:bb:cc:dd:ee:ff","ipv4_network":"10.0.0.1/24"}]`,
		`[{"mac":"aa:bb:cc:dd:ee:ff","ipv4_network":"10.0.0.0/15"}]`,
		`[{"mac":"aa:bb:cc:dd:ee:ff","ipv4_network":"10.0.0.0/31"}]`,
		`[{"mac":"aa:bb:cc:dd:ee:ff","ipv4_network":"10.0.0.0/24","gateway_mac":"bad"}]`,
		`[{"mac":"00:00:00:00:00:00","ipv4_network":"10.0.0.0/24"}]`,
		`[{"mac":"01:00:00:00:00:01","ipv4_network":"10.0.0.0/24"}]`,
		`[{"mac":"02:00:00:00:00:01","ipv4_network":"10.0.0.0/24","gateway_mac":"00:00:00:00:00:00"}]`,
		`[{"mac":"02:00:00:00:00:01","ipv4_network":"10.0.0.0/24","gateway_mac":"01:00:00:00:00:01"}]`,
	} {
		if _, ok := wakeReport(t, `{"type":"lan_report","seq":1,"entries":`+entries+`}`).snapshotDigest(); ok {
			t.Errorf("accepted invalid entries: %s", entries)
		}
	}
	a := `{"mac":"aa:bb:cc:dd:ee:ff","ipv4_network":"10.0.0.0/24","gateway_mac":null}`
	b := `{"mac":"00:11:22:33:44:55","ipv4_network":"10.0.0.0/16","gateway_mac":"02:11:22:33:44:55"}`
	digest := func(entries string) ([32]byte, bool) {
		return wakeReport(t, `{"type":"lan_report","seq":1,"entries":[`+entries+`]}`).snapshotDigest()
	}
	one, ok1 := digest(a + "," + b)
	two, ok2 := digest(b + "," + a)
	_, duplicate := digest(a + "," + a)
	if !ok1 || !ok2 || one != two || duplicate {
		t.Fatal("snapshot ordering or duplicate validation failed")
	}
}

func TestWakeIneligibleRegistrations(t *testing.T) {
	for _, tc := range []struct {
		name, identityFields       string
		dev, supersede, restricted bool
	}{
		{name: "attended", identityFields: `"status":"active","ephemeral":true`},
		{name: "quarantined", identityFields: `"status":"quarantined","ephemeral":false`},
		{name: "retired", identityFields: `"status":"retired","ephemeral":false`},
		{name: "dev", dev: true},
		{name: "superseded", identityFields: `"status":"active","ephemeral":false`, supersede: true},
		{name: "restricted", restricted: true},
		{name: "missing ephemeral", identityFields: `"status":"active"`},
		{name: "missing status", identityFields: `"ephemeral":false`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := wakeFixture(t)
			conn := &fakeConn{}
			p := &Peer{conn: conn}
			if tc.restricted {
				p = wakeTestPeer(conn)
				p.restricted = true
				s.reg.RegisterRestricted(p)
			} else {
				if !tc.dev {
					cp := wakeLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						fmt.Fprintf(w, `{"tenant_id":%q,"pubkey":%q,%s}`, agentAuthGoldenTenant, agentAuthGoldenPubkeyHex, tc.identityFields)
					}))
					resolver, err := newHTTPIdentityResolver(cp.URL, presenceTestToken)
					if err != nil {
						t.Fatal(err)
					}
					s.identity = resolver
				}
				s.dispatch(p, ClientToServer{Payload: &RegisterAgent{
					Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Tenant: agentAuthGoldenTenant,
					Features: []string{lanFeature, wakeFeature},
				}})
				if !tc.dev {
					nonce := challengeNonce(t, conn)
					s.dispatch(p, ClientToServer{Payload: &AgentAuthResponse{
						Device: agentAuthGoldenDevice, Nonce: hex.EncodeToString(nonce),
						Sig: signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
					}})
				}
				if !p.registered {
					t.Fatal("fixture failed to register")
				}
			}
			if tc.supersede {
				replacement := wakeTestPeer(&fakeConn{})
				wakeTestReady(replacement)
				s.reg.Register(replacement)
			}
			s.dispatch(p, ClientToServer{Payload: &WakeHello{Challenge: testWakeChallenge}})
			s.dispatch(p, ClientToServer{Payload: wakeReport(t, `{"type":"lan_report","seq":1,"entries":[]}`)})
			if p.wake.challenge.Load() != nil || p.wake.acknowledged.Load() || calls.Load() != 0 {
				t.Fatal("ineligible socket changed wake state or called CP")
			}
			// Populate readiness independently so forward must reject the identity or connection fence.
			wakeTestReady(p)
			if got := wakeTestRequest(s, p.DeviceId, true, wakeTestBody(t, p, nil)); got.Code != 409 {
				t.Fatalf("ineligible relay got %d", got.Code)
			}
		})
	}
}

type wakeTestConn struct {
	fakeConn
	onWrite func() error
}

func (c *wakeTestConn) WriteJSON(v any) error {
	if frame, ok := v.(ServerToClient); ok && frame.Type == "wake" {
		if err := c.onWrite(); err != nil {
			return err
		}
	}
	return c.fakeConn.WriteJSON(v)
}

func TestWakeClaimFenceAndWriteFailure(t *testing.T) {
	s, _ := wakeFixture(t)
	writes := 0
	conn := &wakeTestConn{onWrite: func() error { writes++; return errors.New("socket write failed") }}
	p := wakeTestPeer(conn)
	wakeTestReady(p)
	s.reg.Register(p)
	for _, key := range []string{"tenant_id", "relay_key_sha256", "wake_challenge"} {
		rec := wakeTestRequest(s, p.DeviceId, true, wakeTestBody(t, p, map[string]string{key: "wrong"}))
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), "not_written") || writes != 0 {
			t.Fatalf("mismatched %s reached writer or got %d", key, rec.Code)
		}
	}
	rec := wakeTestRequest(s, p.DeviceId, true, wakeTestBody(t, p, nil))
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "write_failed") || writes != 1 {
		t.Fatal("attempted write failure misclassified")
	}
}

func TestWakeDeviceGateOrdersReplacement(t *testing.T) {
	for _, writeFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("write first=%t", writeFirst), func(t *testing.T) {
			s, _ := wakeFixture(t)
			entered, unblock := make(chan struct{}), make(chan struct{})
			conn := &wakeTestConn{onWrite: func() error {
				close(entered)
				select {
				case <-unblock:
					return nil
				case <-time.After(3 * time.Second):
					return errors.New("test writer timed out")
				}
			}}
			old := wakeTestPeer(conn)
			wakeTestReady(old)
			s.reg.Register(old)
			body := wakeTestBody(t, old, nil)
			next := wakeTestPeer(&fakeConn{})
			wakeTestReady(next)
			if !writeFirst {
				publishing, publish := make(chan struct{}), make(chan struct{})
				var first atomic.Bool
				s.reg.now = func() time.Time {
					if first.CompareAndSwap(false, true) {
						close(publishing)
						<-publish
					}
					return time.Now()
				}
				published := make(chan *Peer, 1)
				go func() { published <- s.reg.Register(next) }()
				select {
				case <-publishing:
				case <-time.After(time.Second):
					close(publish)
					t.Fatal("replacement did not reach publication")
				}
				done := make(chan int, 1)
				go func() { done <- wakeTestRequest(s, old.DeviceId, true, body).Code }()
				waiting := wakeGateHasWaiter(s.reg, old.DeviceId)
				close(publish)
				if !waiting || <-published != next || <-done != 409 ||
					len(conn.messages()) != 0 || len(next.conn.(*fakeConn).messages()) != 0 {
					t.Fatal("old order was not refused after replacement")
				}
				return
			}
			done := make(chan int, 1)
			go func() { done <- wakeTestRequest(s, old.DeviceId, true, body).Code }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("wake did not reach writer")
			}
			published := make(chan *Peer, 1)
			go func() { published <- s.reg.Register(next) }()
			// Wait for the replacement to contend on the same gate.
			waiting := wakeGateHasWaiter(s.reg, old.DeviceId)
			stillCurrent := s.reg.isCurrent(old)
			close(unblock)
			if !waiting || !stillCurrent || <-done != 202 || <-published != next ||
				next.wake.ref.Generation <= old.wake.ref.Generation || len(conn.messages()) != 1 {
				t.Fatal("replacement did not publish after the old peer's write")
			}
		})
	}
}

func TestWakeIncarnationCASRetry(t *testing.T) {
	s := &Server{reg: NewRegistry(time.Minute), now: time.Now}
	var gets, posts atomic.Int32
	cp := wakeLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprintf(w, `{"id":null,"revision":%d}`, gets.Add(1))
			return
		}
		var b struct {
			Incarnation string `json:"incarnation"`
			Expected    int32  `json:"expected_revision"`
		}
		attempt := posts.Add(1)
		if json.NewDecoder(r.Body).Decode(&b) != nil || b.Incarnation != s.reg.incarnation ||
			b.Expected != attempt || s.reg.wakeActive.Load() {
			t.Error("CAS did not use the current revision while paths were disabled")
		}
		if attempt == 1 {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"error":"revision_moved","revision":2}`)
			return
		}
		fmt.Fprint(w, `{"revision":3}`)
	}))
	s.wakeCP = newWakeClient(cp.URL, presenceTestToken)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.activateWake(ctx)
	if !s.reg.wakeActive.Load() || gets.Load() != 2 || posts.Load() != 2 {
		t.Fatal("activation did not reread and retry the CAS")
	}
}

func TestWakeResultIsRejectedWithoutCallingCP(t *testing.T) {
	s, calls := wakeFixture(t)
	runtime, send, read := dialWakeRelay(t, s)
	if p, ok := runtime.reg.Lookup(agentAuthGoldenDevice); !ok || !runtime.lanEligible(p) {
		t.Fatal("socket was not eligible")
	}
	send(map[string]string{"type": "wake_result"})
	if frame := read(); frame.Type != "rejected" || calls.Load() != 0 {
		t.Fatalf("unknown frame got %s with %d CP calls", frame.Type, calls.Load())
	}
}

// Exercise the production WebSocket read loop with a proved, wake-eligible agent.
func dialWakeRelay(t *testing.T, s *Server) (*Server, func(any), func() ServerToClient) {
	t.Helper()
	runtime := authServer(t, goldenResolver())
	runtime.wakeCP = s.wakeCP
	runtime.reg.incarnation = s.reg.incarnation
	runtime.reg.wakeActive.Store(true)
	runtime.identity.(*fakeResolver).identities[agentAuthGoldenDevice].Status = "active"
	runtime.identity.(*fakeResolver).identities[agentAuthGoldenDevice].Ephemeral = ptrBool(false)
	ws := wakeLoopback(t, http.HandlerFunc(runtime.handleWS))
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ws.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	send := func(v any) {
		t.Helper()
		if err := c.WriteJSON(v); err != nil {
			t.Fatal(err)
		}
	}
	read := func() ServerToClient {
		t.Helper()
		var frame ServerToClient
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := c.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		return frame
	}
	send(ClientToServer{Payload: RegisterAgent{Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Features: []string{wakeFeature, lanFeature}}})
	challenge, ok := read().Payload.(*AgentAuthChallenge)
	if !ok {
		t.Fatal("expected registration challenge")
	}
	nonce := mustHex(t, challenge.Nonce)
	send(ClientToServer{Payload: AgentAuthResponse{Device: agentAuthGoldenDevice, Nonce: challenge.Nonce,
		Sig: signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce)}})
	if frame := read(); frame.Type != "registered" {
		t.Fatalf("registration got %s", frame.Type)
	}
	return runtime, send, read
}

func TestWakeDisabledUntilActivation(t *testing.T) {
	s, calls := wakeFixture(t)
	s.reg.wakeActive.Store(false)
	conn := &fakeConn{}
	p := wakeTestPeer(conn)
	s.reg.Register(p)
	s.handleWakeHello(p, &WakeHello{Challenge: testWakeChallenge})
	report := wakeReport(t, `{"type":"lan_report","seq":1,"entries":[]}`)
	s.handleLanReport(p, report)
	if wakeTestRequest(s, p.DeviceId, false, "").Code != 409 ||
		wakeTestRequest(s, p.DeviceId, true, "").Code != 409 ||
		s.reg.Snapshot()[0].WakeCapable || calls.Load() != 0 || len(conn.messages()) != 0 {
		t.Fatal("a LAN or wake path ran before activation")
	}

	s.reg.wakeActive.Store(true)
	s.handleLanReport(p, report)
	rec := wakeTestRequest(s, p.DeviceId, false, "")
	var ctx wakeContext
	messages := conn.messages()
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ctx) != nil ||
		ctx.Challenge != testWakeChallenge || !s.reg.Snapshot()[0].WakeCapable ||
		calls.Load() != 2 || len(messages) != 1 || messages[0].Payload != (LanReportAck{Seq: 1}) {
		t.Fatal("the first acknowledged report did not make the early hello's connection ready")
	}
}

func TestWakeRevalidationRevokesEligibilityBetweenContextAndForward(t *testing.T) {
	installed, ephemeral := false, true
	for _, verdict := range []struct {
		name, status string
		ephemeral    *bool
	}{
		{"quarantined", "quarantined", &installed},
		{"missing status", "", &installed},
		{"missing installation flag", "active", nil},
		{"ephemeral", "active", &ephemeral},
	} {
		t.Run(verdict.name, func(t *testing.T) {
			s, _ := wakeFixture(t)
			conn := &fakeConn{}
			p := wakeTestPeer(conn)
			p.MultiSessionCapable = boolPtr(true)
			wakeTestReady(p)
			s.reg.Register(p)
			if rec := wakeTestRequest(s, p.DeviceId, false, ""); rec.Code != 200 {
				t.Fatalf("initial context returned %d", rec.Code)
			}
			rosterConn, session, before := joinBeforeWakeRevocation(t, s.broker, p)
			start := len(conn.messages())
			body := wakeTestBody(t, p, nil)
			id := &DeviceIdentity{DeviceID: p.DeviceId, TenantID: p.Tenant, Pubkey: p.Pubkey,
				Status: verdict.status, Ephemeral: verdict.ephemeral}
			s.identity = &fakeResolver{identities: map[string]*DeviceIdentity{p.DeviceId: id}}
			if dropped := s.RevalidateAgents(context.Background()); dropped != 0 {
				t.Fatalf("revalidation dropped %d peers", dropped)
			}
			rec := wakeTestRequest(s, p.DeviceId, true, body)
			var refusal struct {
				Error string `json:"error"`
			}
			if rec.Code != 409 || json.Unmarshal(rec.Body.Bytes(), &refusal) != nil || refusal.Error != "not_written" ||
				len(conn.messages()) != start {
				t.Fatalf("forward after revocation returned %d %s", rec.Code, rec.Body)
			}
			if p.wake.installedActive.Load() || p.wake.acknowledged.Load() || p.wake.challenge.Load() != nil ||
				s.reg.Snapshot()[0].WakeCapable {
				t.Fatal("revoked peer retained wake eligibility or readiness")
			}

			id.Status, id.Ephemeral = "active", &installed
			s.RevalidateAgents(context.Background())
			s.handleWakeHello(p, &WakeHello{Challenge: testWakeChallenge})
			if wakeTestRequest(s, p.DeviceId, false, "").Code != 409 || s.reg.Snapshot()[0].WakeCapable ||
				p.wake.installedActive.Load() || p.wake.challenge.Load() != nil {
				t.Fatal("active verdict restored eligibility without registration")
			}
			assertWakeRevocationKeepsSessions(t, s.broker, p, rosterConn, session, before)
		})
	}
}

func TestWakeRevalidationRevokesReplacementPublishedAfterSnapshot(t *testing.T) {
	s, _ := wakeFixture(t)
	old := wakeTestPeer(&fakeConn{})
	old.authSeq = s.reg.NextAuthSeq()
	s.reg.Register(old)
	snapshot := s.reg.registeredPeers()
	if len(snapshot) != 1 || snapshot[0] != old {
		t.Fatal("sweep did not snapshot the old peer")
	}

	conn := &fakeConn{}
	replacement := wakeTestPeer(conn)
	replacement.authSeq = s.reg.NextAuthSeq()
	if s.reg.Register(replacement) == nil {
		t.Fatal("replacement did not register")
	}
	wakeTestReady(replacement)
	if rec := wakeTestRequest(s, replacement.DeviceId, false, ""); rec.Code != http.StatusOK {
		t.Fatalf("replacement context returned %d", rec.Code)
	}
	body := wakeTestBody(t, replacement, nil)
	resolve := func(_ context.Context, device string) (*DeviceIdentity, error) {
		return &DeviceIdentity{DeviceID: device, TenantID: replacement.Tenant, Pubkey: replacement.Pubkey,
			Status: "quarantined", Ephemeral: ptrBool(false)}, nil
	}
	if dropped, failed := s.revalidateAgent(context.Background(), snapshot[0].DeviceId, time.Second, resolve); dropped || failed {
		t.Fatalf("quarantine verdict: dropped=%t failed=%t", dropped, failed)
	}
	rec := wakeTestRequest(s, replacement.DeviceId, true, body)
	var refusal struct {
		Error string `json:"error"`
	}
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &refusal) != nil ||
		refusal.Error != "not_written" || len(conn.messages()) != 0 || len(conn.rawFrames) != 0 || conn.closed {
		t.Fatalf("forward after replacement quarantine returned %d %s", rec.Code, rec.Body)
	}
}

func TestWakeGateContentionMissesHeartbeatWithoutRejectingRelay(t *testing.T) {
	fixture, _ := wakeFixture(t)
	s, send, read := dialWakeRelay(t, fixture)
	send(ClientToServer{Payload: WakeHello{Challenge: testWakeChallenge}})
	send(map[string]any{"type": "lan_report", "seq": 1, "entries": []LanEntry{}})
	if frame := read(); frame.Type != "lan_report_ack" {
		t.Fatalf("LAN report got %s", frame.Type)
	}
	p, ok := s.reg.Lookup(agentAuthGoldenDevice)
	if !ok {
		t.Fatal("relay was not registered")
	}
	release, ok := s.reg.gates.acquire(p.DeviceId, deviceGateTimeout)
	if !ok {
		t.Fatal("could not hold the Wake delivery gate")
	}
	defer release()
	s.reg.mu.RLock()
	before := p.LastSeen
	s.reg.mu.RUnlock()
	send(ClientToServer{Payload: Heartbeat{Device: p.DeviceId}})
	if !wakeGateHasWaiter(s.reg, p.DeviceId) {
		t.Fatal("heartbeat did not wait for the delivery gate")
	}
	// A second report is acknowledged locally. Its ACK proves that the read loop
	// finished the heartbeat while the delivery gate remained held.
	send(map[string]any{"type": "lan_report", "seq": 1, "entries": []LanEntry{}})
	if frame := read(); frame.Type != "lan_report_ack" {
		t.Fatalf("first frame after contended heartbeat was %s, want LAN ACK", frame.Type)
	}
	s.reg.mu.RLock()
	unchanged := p.LastSeen.Equal(before)
	s.reg.mu.RUnlock()
	release()
	if !unchanged {
		t.Fatal("contended heartbeat unexpectedly refreshed the relay")
	}
	if current, ok := s.reg.Lookup(p.DeviceId); !ok || current != p {
		t.Fatal("relay is no longer current")
	}
	if rec := wakeTestRequest(s, p.DeviceId, true, wakeTestBody(t, p, nil)); rec.Code != http.StatusAccepted {
		t.Fatalf("Wake to the still-connected relay returned %d", rec.Code)
	}
	if frame := read(); frame.Type != "wake" {
		t.Fatalf("relay received %s, want Wake", frame.Type)
	}
}

func TestWakeHTTPTimeoutLeavesNoConfirmedOutcome(t *testing.T) {
	s, _ := wakeFixture(t)
	entered, unblock := make(chan struct{}), make(chan struct{})
	p := wakeTestPeer(&wakeTestConn{onWrite: func() error {
		close(entered)
		<-unblock
		return nil
	}})
	wakeTestReady(p)
	s.reg.Register(p)
	mux := http.NewServeMux()
	s.mountWake(mux, presenceTestToken)
	endpoint := wakeLoopback(t, mux)
	body := wakeTestBody(t, p, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL+"/internal/devices/"+p.DeviceId+"/wake", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+presenceTestToken)
	type outcome struct {
		response *http.Response
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := endpoint.Client().Do(req)
		done <- outcome{resp, err}
	}()
	defer close(unblock)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("write did not start")
	}
	// The CP deadline expires while the write is in progress.
	got := <-done
	if got.response != nil {
		got.response.Body.Close()
	}
	if got.response != nil || !errors.Is(got.err, context.DeadlineExceeded) {
		t.Fatal("caller received a confirmed wake outcome after its deadline")
	}
}

func TestWakeLANRetriesSpendBudgetAndDroppedReportsStayUnacknowledged(t *testing.T) {
	s := &Server{reg: NewRegistry(time.Minute), now: time.Now}
	s.reg.wakeActive.Store(true)
	var allocations, reports atomic.Int32
	cp := wakeLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/devices/lan-epoch":
			if allocations.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, `{"epoch":7}`)
		case "/internal/devices/lan":
			reports.Add(1)
			fmt.Fprint(w, `{"status":"dropped"}`)
		default:
			t.Error("unexpected CP route")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	s.wakeCP = newWakeClient(cp.URL, presenceTestToken)
	conn := &fakeConn{}
	p := wakeTestPeer(conn)
	s.reg.Register(p)
	report := wakeReport(t, `{"type":"lan_report","seq":1,"entries":[]}`)
	for range 3 {
		s.handleLanReport(p, report)
	}
	if allocations.Load() != 2 || reports.Load() != 1 || len(conn.messages()) != 0 ||
		p.wake.acknowledged.Load() || p.wake.committed != nil {
		t.Fatal("retry bypassed the budget or a dropped report was acknowledged")
	}
}

func wakeGateHasWaiter(reg *Registry, device string) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		reg.gates.mu.Lock()
		lock := reg.gates.m[device]
		waiting := lock != nil && lock.refs == 2
		reg.gates.mu.Unlock()
		if waiting {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// docs/70: Registered advertises lan_v1 / wake_v1 only to an authenticated, tenanted, non-restricted connection
// whose key was proved, whose identity is an installed ACTIVE machine, and that asked for the feature.
func TestRegisteredAdvertisesLanAndWakeOnlyWhereUsable(t *testing.T) {
	authed, err := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	has := func(p *Peer, f string) bool {
		for _, got := range authed.registeredMsg(p).Features {
			if got == f {
				return true
			}
		}
		return false
	}
	ok := wakeTestPeer(&fakeConn{})
	if !has(ok, lanFeature) || !has(ok, wakeFeature) {
		t.Fatalf("eligible peer not told: %v", authed.registeredMsg(ok).Features)
	}
	cases := map[string]func(*Peer){
		"restricted":       func(p *Peer) { p.restricted = true },
		"not proved (dev)": func(p *Peer) { p.wake.proved = false },
		"not active":       func(p *Peer) { p.wake.installedActive.Store(false) },
		"tenantless":       func(p *Peer) { p.Tenant = "" },
	}
	for name, mutate := range cases {
		p := wakeTestPeer(&fakeConn{})
		mutate(p)
		if has(p, lanFeature) || has(p, wakeFeature) {
			t.Fatalf("%s: advertised %v", name, authed.registeredMsg(p).Features)
		}
	}
	onlyLan := wakeTestPeer(&fakeConn{})
	onlyLan.wake.wakeFeature = false
	if !has(onlyLan, lanFeature) || has(onlyLan, wakeFeature) {
		t.Fatalf("feature not tied to the agent's request: %v", authed.registeredMsg(onlyLan).Features)
	}
	dev, err := NewServer(time.Minute, "relay-1:4444", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fs := dev.registeredMsg(wakeTestPeer(&fakeConn{})).Features; len(fs) != 0 {
		t.Fatalf("dev-mode server advertised %v", fs)
	}
}


// Codex branch review r3: a control-plane not_eligible answer to a LAN report revokes the connection's Wake
// readiness, so an order issued before the change is never written to it.
func TestWakeLanNotEligibleRevokesReadinessBeforeForward(t *testing.T) {
	s, _ := wakeFixture(t)
	cp := wakeLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/devices/lan" {
			t.Errorf("unexpected CP route %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"error":"not_eligible"}`)
	}))
	s.wakeCP = newWakeClient(cp.URL, presenceTestToken)
	conn := &fakeConn{}
	p := wakeTestPeer(conn)
	p.MultiSessionCapable = boolPtr(true)
	wakeTestReady(p)
	s.reg.Register(p)
	if rec := wakeTestRequest(s, p.DeviceId, false, ""); rec.Code != 200 {
		t.Fatalf("initial context returned %d", rec.Code)
	}
	rosterConn, session, before := joinBeforeWakeRevocation(t, s.broker, p)
	body := wakeTestBody(t, p, nil)
	s.handleLanReport(p, wakeReport(t, `{"type":"lan_report","seq":2,"entries":[]}`))
	rec := wakeTestRequest(s, p.DeviceId, true, body)
	var refusal struct {
		Error string `json:"error"`
	}
	if rec.Code != 409 || json.Unmarshal(rec.Body.Bytes(), &refusal) != nil || refusal.Error != "not_written" {
		t.Fatalf("forward after not_eligible returned %d %s", rec.Code, rec.Body)
	}
	for _, m := range conn.messages() {
		if _, isWake := m.Payload.(Wake); isWake {
			t.Fatal("a wake frame was written after not_eligible")
		}
	}
	if p.wake.installedActive.Load() || p.wake.acknowledged.Load() || p.wake.challenge.Load() != nil ||
		s.reg.Snapshot()[0].WakeCapable {
		t.Fatal("not_eligible left the peer ready")
	}
	assertWakeRevocationKeepsSessions(t, s.broker, p, rosterConn, session, before)
}


// Codex branch review r4: a forward that already holds the delivery gate and is waiting for the WebSocket writer
// must not write after signaling learns not_eligible during that wait.
func TestWakeNotEligibleDuringWriterWaitStopsTheWrite(t *testing.T) {
	s, _ := wakeFixture(t)
	cp := wakeLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"error":"not_eligible"}`)
	}))
	s.wakeCP = newWakeClient(cp.URL, presenceTestToken)
	conn := &fakeConn{}
	p := wakeTestPeer(conn)
	wakeTestReady(p)
	s.reg.Register(p)
	body := wakeTestBody(t, p, nil)

	p.writeMu.Lock() // the writer is busy
	forwarded := make(chan *httptest.ResponseRecorder, 1)
	go func() { forwarded <- wakeTestRequest(s, p.DeviceId, true, body) }()
	deadline := time.Now().Add(2 * time.Second)
	for !wakeGateHeld(s.reg, p.DeviceId) {
		if time.Now().After(deadline) {
			p.writeMu.Unlock()
			t.Fatal("forward never took the delivery gate")
		}
		time.Sleep(time.Millisecond)
	}
	reported := make(chan struct{})
	go func() {
		s.handleLanReport(p, wakeReport(t, `{"type":"lan_report","seq":2,"entries":[]}`))
		close(reported)
	}()
	for !p.wake.revoked.Load() {
		if time.Now().After(deadline) {
			p.writeMu.Unlock()
			t.Fatal("not_eligible was not marked before the gate")
		}
		time.Sleep(time.Millisecond)
	}
	p.writeMu.Unlock() // the writer frees up; the forward re-checks and must refuse
	rec := <-forwarded
	<-reported
	var refusal struct {
		Error string `json:"error"`
	}
	if rec.Code != 409 || json.Unmarshal(rec.Body.Bytes(), &refusal) != nil || refusal.Error != "not_written" {
		t.Fatalf("forward returned %d %s", rec.Code, rec.Body)
	}
	for _, m := range conn.messages() {
		if _, isWake := m.Payload.(Wake); isWake {
			t.Fatal("a wake frame was written after not_eligible")
		}
	}
}

// wakeGateHeld reports whether some goroutine holds the device gate (a zero-wait acquire fails).
func wakeGateHeld(reg *Registry, device string) bool {
	release, ok := reg.gates.acquire(device, 0)
	if ok {
		release()
	}
	return !ok
}

func joinBeforeWakeRevocation(t *testing.T, b *Broker, agent *Peer) (*fakeConn, *Session, SessionParticipants) {
	t.Helper()
	conn := &fakeConn{}
	controller := &Peer{conn: conn}
	t.Cleanup(controller.stopRoster)
	session, err := b.ConnectRequest(controller, agent.DeviceId, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, session, waitRoster(t, conn, 1, 0)
}

func assertWakeRevocationKeepsSessions(t *testing.T, b *Broker, agent *Peer, conn *fakeConn, session *Session, before SessionParticipants) {
	t.Helper()
	b.mu.Lock()
	stillLive := b.sessions[session.Id] == session
	revision := b.rosterRevision
	b.mu.Unlock()
	if !agent.wake.revoked.Load() || !stillLive || revision != before.Revision {
		t.Fatal("Wake revocation changed the signaling membership or roster")
	}
	controller := &Peer{conn: &fakeConn{}}
	t.Cleanup(controller.stopRoster)
	if _, err := b.ConnectRequest(controller, agent.DeviceId, nil); err != nil {
		t.Fatalf("Wake revocation prevented a new signaling join: %v", err)
	}
	waitRoster(t, conn, 2, before.Revision)
}
