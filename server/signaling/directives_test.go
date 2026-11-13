package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ---------------------------------------------------------------------------
// Fake control plane (httptest) for the docs/65 directive contract.
// ---------------------------------------------------------------------------

var dirTestToken = strings.Repeat("x", 256)

const (
	dirU1 = "11111111-1111-4111-8111-111111111111"
	dirU2 = "22222222-2222-4222-8222-222222222222"
	dirU3 = "33333333-3333-4333-8333-333333333333"
	dirU4 = "44444444-4444-4444-8444-444444444444"
	dirU5 = "55555555-5555-4555-8555-555555555555"

	dirDevB     = "device-b"
	dirSeedB    = agentAuthWrongSeedHex // device B's enrolled key (any seed works)
	dirTenantID = agentAuthGoldenTenant
)

type cpIdentity struct {
	pub    string
	status string // "" / active / quarantined / retired / removed
}

type ackRecord struct {
	id   string
	body map[string]any
}

type fakeDirectiveCP struct {
	mu            sync.Mutex
	ids           map[string]*cpIdentity
	identity404   bool // answer 404 even for retired+restricted (an old control plane)
	idQueries     []string
	pending       map[string][]pendingDirective
	pendingCode   int
	pendingCalls  map[string]int
	delivered     []string // "device|id"
	acks          []ackRecord
	ackCode       int
	ackBody       string
	features      []string
	srv           *httptest.Server
	badAuthSeen   bool
	deliveredCode int
}

func seedPub(seedHex string) string {
	seed, _ := hex.DecodeString(seedHex)
	return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func newFakeDirectiveCP(t *testing.T) *fakeDirectiveCP {
	t.Helper()
	cp := &fakeDirectiveCP{
		ids:          map[string]*cpIdentity{agentAuthGoldenDevice: {pub: agentAuthGoldenPubkeyHex}, dirDevB: {pub: seedPub(dirSeedB)}},
		pending:      map[string][]pendingDirective{},
		pendingCalls: map[string]int{},
		features:     []string{"session_ended_v1", "directive_v1"},
	}
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+dirTestToken {
			cp.mu.Lock()
			cp.badAuthSeen = true
			cp.mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /internal/devices/{id}/identity", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		cp.mu.Lock()
		defer cp.mu.Unlock()
		cp.idQueries = append(cp.idQueries, r.URL.RawQuery)
		id, ok := cp.ids[r.PathValue("id")]
		switch {
		case !ok || id.status == "removed" || cp.identity404:
			w.WriteHeader(http.StatusNotFound)
		case id.status == "retired" && r.URL.Query().Get("restricted") != "1":
			w.WriteHeader(http.StatusNotFound) // contract: retired answers only restricted callers
		default:
			st := id.status
			if st == "" {
				st = "active"
			}
			_, _ = fmt.Fprintf(w, `{"device_id":%q,"tenant_id":%q,"pubkey":%q,"status":%q}`, r.PathValue("id"), dirTenantID, id.pub, st)
		}
	})
	mux.HandleFunc("GET /internal/devices/{id}/directives/pending", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		cp.mu.Lock()
		defer cp.mu.Unlock()
		dev := r.PathValue("id")
		cp.pendingCalls[dev]++
		if cp.pendingCode != 0 {
			w.WriteHeader(cp.pendingCode)
			return
		}
		list := cp.pending[dev]
		if list == nil {
			list = []pendingDirective{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"directives": list})
	})
	mux.HandleFunc("POST /internal/directives/{id}/delivered", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		var body struct {
			DeviceID string `json:"device_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		cp.mu.Lock()
		cp.delivered = append(cp.delivered, body.DeviceID+"|"+r.PathValue("id"))
		code := cp.deliveredCode
		cp.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
		}
	})
	mux.HandleFunc("POST /internal/directives/{id}/ack", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cp.mu.Lock()
		cp.acks = append(cp.acks, ackRecord{r.PathValue("id"), body})
		code, resp := cp.ackCode, cp.ackBody
		cp.mu.Unlock()
		if code == 0 {
			code, resp = 200, `{"outcome":"applied"}`
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(resp))
	})
	mux.HandleFunc("GET /internal/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		cp.mu.Lock()
		f := cp.features
		cp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"features": f})
	})
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *fakeDirectiveCP) setStatus(device, status string) {
	cp.mu.Lock()
	cp.ids[device].status = status
	cp.mu.Unlock()
}
func (cp *fakeDirectiveCP) setPending(device string, list ...pendingDirective) {
	cp.mu.Lock()
	cp.pending[device] = list
	cp.mu.Unlock()
}
func (cp *fakeDirectiveCP) calls(device string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.pendingCalls[device]
}
func (cp *fakeDirectiveCP) deliveredList() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.delivered...)
}
func (cp *fakeDirectiveCP) ackList() []ackRecord {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]ackRecord(nil), cp.acks...)
}

func pd(id string) pendingDirective {
	return pendingDirective{DirectiveID: id, Artifact: "artifact-" + id[:2]}
}

func withDirectiveSupported(t *testing.T, v bool) {
	t.Helper()
	prev := directiveSupported.Load()
	directiveSupported.Store(v)
	t.Cleanup(func() { directiveSupported.Store(prev) })
}

// directiveEnv is an enforcing server whose identity resolver and guest-end reporter both point at
// the fake control plane.
func directiveEnv(t *testing.T) (*fakeDirectiveCP, *Server, *httpIdentityResolver, *time.Time) {
	t.Helper()
	withDirectiveSupported(t, true)
	withSessionEndedSupported(t, false)
	cp := newFakeDirectiveCP(t)
	res, err := newHTTPIdentityResolver(cp.srv.URL, dirTestToken)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	res.now = func() time.Time { return clock }
	srv, err := NewServer(time.Minute, "relay-1:4444", nil, res)
	if err != nil {
		t.Fatal(err)
	}
	srv.guestEnd = guestEndTestReporter(t, cp.srv.URL)
	return cp, srv, res, &clock
}

// registerAs drives the full handshake for one device with the given advertised features.
func registerAs(t *testing.T, srv *Server, device, seedHex string, features []string) (*Peer, *fakeConn) {
	t.Helper()
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: device, Pubkey: seedPub(seedHex), Nat: NatOpen, Features: features,
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: device, Nonce: hex.EncodeToString(nonce),
		Sig: signAgentAuth(t, seedHex, device, dirTenantID, nonce),
	}})
	return peer, conn
}

func registerGolden(t *testing.T, srv *Server, features []string) (*Peer, *fakeConn) {
	return registerAs(t, srv, agentAuthGoldenDevice, agentAuthGoldenSeedHex, features)
}

var dirFeature = []string{directiveFeature}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func settle() { time.Sleep(250 * time.Millisecond) }

func directivesTo(c *fakeConn) []Directive {
	var out []Directive
	for _, m := range c.messages() {
		if d, ok := m.Payload.(Directive); ok {
			out = append(out, d)
		}
	}
	return out
}

func rejectedReasons(c *fakeConn) []string {
	var out []string
	for _, m := range c.messages() {
		if r, ok := m.Payload.(Rejected); ok {
			out = append(out, r.Reason)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// D-C1 restricted mode.
// ---------------------------------------------------------------------------

// A retired machine registers, but only in the restricted map: it is not in presence, connect_request to it
// fails exactly as for an offline device, and a normal incumbent it replaces is removed and closed.
func TestRestrictedPeerNotBrokerableNotPresentDoesNotDisplace(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	cp.setStatus(agentAuthGoldenDevice, "retired")

	incConn := &fakeConn{}
	incumbent := &Peer{DeviceId: agentAuthGoldenDevice, Tenant: dirTenantID, Pubkey: agentAuthGoldenPubkeyHex, conn: incConn, registered: true}
	srv.reg.Register(incumbent)

	peer, conn := registerGolden(t, srv, dirFeature)
	if !peer.registered || !peer.restricted {
		t.Fatalf("registered=%v restricted=%v, want a restricted registration", peer.registered, peer.restricted)
	}
	if _, ok := findMsg[Registered](conn.messages()); !ok {
		t.Fatal("a restricted peer still gets its Registered")
	}
	// The control plane just said the machine is RETIRED: the normal incumbent is no longer vouched for,
	// so it leaves presence and the broker at once (not at the next revalidation tick) and its socket is
	// closed.
	if got, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatalf("a retired registration left the normal incumbent brokerable: %v (same peer: %v)", got, got == incumbent)
	}
	if !incConn.closed {
		t.Fatal("the incumbent's socket was not closed by the retired registration")
	}
	if snap := srv.reg.Snapshot(); len(snap) != 0 {
		t.Fatalf("presence lists %d devices after retirement, want none", len(snap))
	}

	// With the incumbent gone the device is simply offline to everyone.
	srv.reg.Remove(agentAuthGoldenDevice, incConn)
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatal("restricted peer is brokerable via Lookup")
	}
	if len(srv.reg.Snapshot()) != 0 {
		t.Fatalf("restricted peer is in the presence feed: %#v", srv.reg.Snapshot())
	}
	if srv.reg.Len() != 0 {
		t.Fatalf("Len = %d: restricted peer counted as registered", srv.reg.Len())
	}
	if srv.reg.Heartbeat(agentAuthGoldenDevice) {
		t.Fatal("heartbeat resolved to the restricted peer")
	}
	reasonFor := func(target string) string {
		ctrlConn := &fakeConn{}
		ctrl := &Peer{conn: ctrlConn}
		if _, err := srv.broker.ConnectRequest(ctrl, target, nil); err == nil {
			t.Fatalf("connect_request to %s succeeded", target)
		}
		r := rejectedReasons(ctrlConn)
		if len(r) != 1 {
			t.Fatalf("rejections for %s: %q", target, r)
		}
		return strings.ReplaceAll(r[0], target, "<target>")
	}
	if got, want := reasonFor(agentAuthGoldenDevice), reasonFor("never-registered"); got != want {
		t.Fatalf("restricted device fails differently from an offline one: %q vs %q", got, want)
	}
	if peer.conn.(*fakeConn).closed {
		t.Fatal("the restricted connection must stay open")
	}
}

// Every message except directive_ack is silently ignored on a restricted connection: no reply at all
// (a Rejected makes every agent drop and reconnect — a loop), nothing is acted on, and the connection
// stays open.
func TestRestrictedPeerOtherMessagesIgnored(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	cp.setStatus(agentAuthGoldenDevice, "retired")
	peer, conn := registerGolden(t, srv, dirFeature)
	if !peer.restricted {
		t.Fatal("not restricted")
	}
	ticket := &SignedSessionTicket{}
	for name, payload := range map[string]any{
		"heartbeat":   &Heartbeat{Device: agentAuthGoldenDevice},
		"connect":     &ConnectRequest{Target: "other", Ticket: ticket},
		"guest_ended": &GuestEndedSession{ControlPlaneSession: dirU1},
		"session_end": &SessionEnded{ControlPlaneSession: dirU1, Reason: "idle"},
		"candidate":   &CandidateMsg{Session: "s", Candidate: Candidate{Addr: "1.2.3.4:5", Kind: CandidateHost}},
		"sdp":         &SdpMsg{Session: "s", Sdp: "v=0", Kind: SdpOffer},
		"register":    &RegisterAgent{Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen},
		"auth_resp":   &AgentAuthResponse{Device: agentAuthGoldenDevice},
	} {
		before := len(conn.messages())
		srv.dispatch(peer, ClientToServer{Payload: payload})
		if after := conn.messages()[before:]; len(after) != 0 {
			t.Fatalf("%s: %d replies (%#v), want none — a Rejected makes the agent reconnect in a loop", name, len(after), after[0].Payload)
		}
	}
	if conn.closed {
		t.Fatal("an ignored message closed the restricted connection")
	}
	if !peer.restricted {
		t.Fatal("the connection left restricted mode")
	}
}

// Restricted peers advertise directive_v1 (if supported) but never session_ended_v1, receive their
// pending directives, and may acknowledge them.
func TestRestrictedPeerReceivesDirectivesAndAcks(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	withSessionEndedSupported(t, true)
	cp.setStatus(agentAuthGoldenDevice, "retired")
	cp.setPending(agentAuthGoldenDevice, pd(dirU1))
	peer, conn := registerGolden(t, srv, dirFeature)

	reg, _ := findMsg[Registered](conn.messages())
	if len(reg.Features) != 1 || reg.Features[0] != directiveFeature {
		t.Fatalf("restricted Registered.Features = %v, want only directive_v1", reg.Features)
	}
	waitUntil(t, "directive relay to the restricted peer", func() bool { return len(directivesTo(conn)) == 1 })
	if d := directivesTo(conn)[0]; d.DirectiveID != dirU1 || d.Artifact != "artifact-11" {
		t.Fatalf("relayed %#v", d)
	}
	waitUntil(t, "delivered report", func() bool { return len(cp.deliveredList()) == 1 })

	srv.dispatch(peer, ClientToServer{Payload: &DirectiveAck{DirectiveID: dirU1, From: "accepted", To: "executing", TsMs: 5, Sig: "ab"}})
	waitUntil(t, "ack result", func() bool { _, ok := findMsg[DirectiveAckResult](conn.messages()); return ok })
	res, _ := findMsg[DirectiveAckResult](conn.messages())
	if res.Outcome != "applied" || res.DirectiveID != dirU1 || res.From != "accepted" || res.To != "executing" || res.TsMs != 5 {
		t.Fatalf("ack result %#v", res)
	}
}

// Cleanup removes the restricted entry; a later NORMAL registration of the device replaces (and
// closes) a lingering restricted one.
func TestRestrictedCleanupAndNormalRegistrationReplaces(t *testing.T) {
	cp, srv, _, clock := directiveEnv(t)
	cp.setStatus(agentAuthGoldenDevice, "retired")
	peer, conn := registerGolden(t, srv, nil)
	if !srv.reg.isCurrent(peer) {
		t.Fatal("restricted peer is not current")
	}
	srv.cleanup(peer)
	if srv.reg.isCurrent(peer) || len(srv.reg.restricted) != 0 {
		t.Fatal("cleanup left the restricted entry behind")
	}

	// Un-retire: a second restricted peer lingers, then the normal registration replaces it.
	peer2, conn2 := registerGolden(t, srv, nil)
	_ = conn
	cp.setStatus(agentAuthGoldenDevice, "")
	*clock = clock.Add(2 * time.Minute) // expire the cached "retired" identity
	normal, _ := registerGolden(t, srv, nil)
	if normal.restricted || !normal.registered {
		t.Fatal("un-retired machine did not register normally")
	}
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); !ok {
		t.Fatal("normal registration not brokerable")
	}
	if srv.reg.isCurrent(peer2) || len(srv.reg.restricted) != 0 {
		t.Fatal("the restricted entry survived a normal registration")
	}
	if got := closeFrameReasons(conn2); len(got) != 1 || got[0] != "superseded by re-registration" {
		t.Fatalf("restricted conn close frames = %q", got)
	}
}

// Active and quarantined machines register normally and are present.
func TestActiveAndQuarantinedPeersRegisterNormally(t *testing.T) {
	for _, status := range []string{"", "active", "quarantined"} {
		t.Run("status="+status, func(t *testing.T) {
			cp, srv, _, _ := directiveEnv(t)
			cp.setStatus(agentAuthGoldenDevice, status)
			peer, _ := registerGolden(t, srv, nil)
			if peer.restricted || !peer.registered {
				t.Fatalf("restricted=%v registered=%v", peer.restricted, peer.registered)
			}
			if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); !ok {
				t.Fatal("not brokerable")
			}
			if len(srv.reg.Snapshot()) != 1 || len(srv.reg.restricted) != 0 {
				t.Fatal("not present / leaked into the restricted map")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Identity resolution contract.
// ---------------------------------------------------------------------------

func TestIdentityRequestAlwaysCarriesRestricted(t *testing.T) {
	cp, srv, res, _ := directiveEnv(t)
	if _, err := res.Resolve(context.Background(), agentAuthGoldenDevice); err != nil {
		t.Fatal(err)
	}
	if _, err := res.ResolveFresh(context.Background(), agentAuthGoldenDevice); err != nil {
		t.Fatal(err)
	}
	registerGolden(t, srv, nil)
	_ = srv.RevalidateAgents(context.Background())
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.idQueries) < 2 {
		t.Fatalf("only %d identity requests seen", len(cp.idQueries))
	}
	for _, q := range cp.idQueries {
		if q != "restricted=1" {
			t.Fatalf("identity request query %q, want restricted=1", q)
		}
	}
}

// An old control plane answers a retired machine 404 (it ignores restricted=1): unknown, refused.
func TestRetiredAnswered404IsUnknown(t *testing.T) {
	cp, srv, res, _ := directiveEnv(t)
	cp.setStatus(agentAuthGoldenDevice, "retired")
	cp.mu.Lock()
	cp.identity404 = true
	cp.mu.Unlock()
	if _, err := res.Resolve(context.Background(), agentAuthGoldenDevice); err != ErrDeviceUnknown {
		t.Fatalf("Resolve = %v, want ErrDeviceUnknown", err)
	}
	peer, conn := registerGolden(t, srv, dirFeature)
	if peer.registered || !conn.closed {
		t.Fatalf("a 404'd retired machine registered=%v closed=%v", peer.registered, conn.closed)
	}
	if len(srv.reg.restricted) != 0 || srv.reg.Len() != 0 {
		t.Fatal("a 404'd retired machine entered a registry map")
	}
}

func TestIdentityStatusIsParsedAndValidated(t *testing.T) {
	stub := &identityStub{status: 200, body: `{"device_id":"d","tenant_id":"t","pubkey":"` + strings.Repeat("ab", 32) + `","status":"retired"}`}
	r, _ := testResolver(t, stub)
	id, err := r.Resolve(context.Background(), "d")
	if err != nil || id.Status != "retired" {
		t.Fatalf("identity %#v, err %v", id, err)
	}
	stub2 := &identityStub{status: 200, body: `{"device_id":"d","tenant_id":"t","pubkey":"` + strings.Repeat("ab", 32) + `","status":"exploded"}`}
	r2, _ := testResolver(t, stub2)
	if _, err := r2.Resolve(context.Background(), "d"); err == nil || err == ErrDeviceUnknown {
		t.Fatalf("an unknown status must fail closed with a transport-class error, got %v", err)
	}
	stub3 := &identityStub{status: 200, body: okBody("d", "t", strings.Repeat("ab", 32))}
	r3, _ := testResolver(t, stub3)
	if id, err := r3.Resolve(context.Background(), "d"); err != nil || id.Status != "" {
		t.Fatalf("an older control plane (no status) must still resolve: %#v %v", id, err)
	}
}

// ---------------------------------------------------------------------------
// Relay on registration.
// ---------------------------------------------------------------------------

func TestRelayOnRegistrationOnlyToTheAuthenticatedPeer(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	cp.setPending(agentAuthGoldenDevice, pd(dirU1), pd(dirU2))
	cp.setPending(dirDevB, pd(dirU3))

	peerB, connB := registerAs(t, srv, dirDevB, dirSeedB, dirFeature)
	_ = peerB
	waitUntil(t, "B's directive", func() bool { return len(directivesTo(connB)) == 1 })
	peerA, connA := registerGolden(t, srv, dirFeature)
	_ = peerA
	waitUntil(t, "A's directives", func() bool { return len(directivesTo(connA)) == 2 })
	settle()

	if got := directivesTo(connA); got[0].DirectiveID != dirU1 || got[1].DirectiveID != dirU2 {
		t.Fatalf("A received %#v", got)
	}
	if got := directivesTo(connB); len(got) != 1 || got[0].DirectiveID != dirU3 {
		t.Fatalf("B received %#v (a directive for another device leaked, or B's was lost)", got)
	}
	reg, _ := findMsg[Registered](connA.messages())
	if len(reg.Features) != 1 || reg.Features[0] != directiveFeature {
		t.Fatalf("Registered.Features = %v", reg.Features)
	}
	waitUntil(t, "delivered reports", func() bool { return len(cp.deliveredList()) == 3 })
	want := map[string]bool{agentAuthGoldenDevice + "|" + dirU1: true, agentAuthGoldenDevice + "|" + dirU2: true, dirDevB + "|" + dirU3: true}
	for _, d := range cp.deliveredList() {
		if !want[d] {
			t.Fatalf("unexpected delivered report %q", d)
		}
		delete(want, d)
	}
}

func TestNoRelayWithoutTheFeature(t *testing.T) {
	t.Run("agent did not advertise", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		cp.setPending(agentAuthGoldenDevice, pd(dirU1))
		_, conn := registerGolden(t, srv, nil)
		settle()
		if cp.calls(agentAuthGoldenDevice) != 0 || len(directivesTo(conn)) != 0 {
			t.Fatal("directives were fetched/relayed for an agent that did not advertise directive_v1")
		}
		if reg, _ := findMsg[Registered](conn.messages()); len(reg.Features) != 0 {
			t.Fatalf("Registered advertised %v to an agent that did not ask", reg.Features)
		}
	})
	t.Run("unrecognised spelling", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		cp.setPending(agentAuthGoldenDevice, pd(dirU1))
		_, conn := registerGolden(t, srv, []string{"DIRECTIVE_V1", "directive_v2", "directive_v1 "})
		settle()
		if cp.calls(agentAuthGoldenDevice) != 0 || len(directivesTo(conn)) != 0 {
			t.Fatal("relayed on a misspelt feature")
		}
	})
	t.Run("control plane does not serve directives", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		withDirectiveSupported(t, false)
		cp.setPending(agentAuthGoldenDevice, pd(dirU1))
		peer, conn := registerGolden(t, srv, dirFeature)
		settle()
		if cp.calls(agentAuthGoldenDevice) != 0 || len(directivesTo(conn)) != 0 {
			t.Fatal("relayed while the control plane does not advertise directive_v1")
		}
		if reg, _ := findMsg[Registered](conn.messages()); len(reg.Features) != 0 {
			t.Fatalf("advertised %v while unsupported", reg.Features)
		}
		if !peer.directiveStale.Load() {
			t.Fatal("the peer that asked but was not told must be recorded stale")
		}
	})
	t.Run("dev mode", func(t *testing.T) {
		withDirectiveSupported(t, true)
		srv, err := NewServer(time.Minute, "relay-1:4444", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		cp := newFakeDirectiveCP(t)
		srv.guestEnd = guestEndTestReporter(t, cp.srv.URL)
		conn := &fakeConn{}
		srv.dispatch(&Peer{conn: conn}, ClientToServer{Payload: &RegisterAgent{Device: "dev", Pubkey: "pk", Nat: NatOpen, Features: dirFeature}})
		settle()
		if cp.calls("dev") != 0 || len(directivesTo(conn)) != 0 {
			t.Fatal("dev mode relayed directives")
		}
	})
}

func TestRelayFailureNeverFailsRegistration(t *testing.T) {
	for _, code := range []int{401, 404, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			cp, srv, _, _ := directiveEnv(t)
			cp.mu.Lock()
			cp.pendingCode = code
			cp.mu.Unlock()
			peer, conn := registerGolden(t, srv, dirFeature)
			waitUntil(t, "the fetch attempt", func() bool { return cp.calls(agentAuthGoldenDevice) == 1 })
			settle()
			if !peer.registered || conn.closed {
				t.Fatalf("registration failed (registered=%v closed=%v)", peer.registered, conn.closed)
			}
			if _, ok := findMsg[Registered](conn.messages()); !ok || len(directivesTo(conn)) != 0 {
				t.Fatal("expected Registered and no directive")
			}
		})
	}
}

// Malformed entries are skipped and at most 4 directives are delivered.
func TestPendingListIsBounded(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	cp.setPending(agentAuthGoldenDevice,
		pendingDirective{DirectiveID: "not-a-uuid", Artifact: "x"},
		pendingDirective{DirectiveID: dirU5, Artifact: strings.Repeat("a", maxDirectiveArtifactBytes+1)},
		pendingDirective{DirectiveID: dirU5, Artifact: ""},
		pd(dirU1), pd(dirU2), pd(dirU3), pd(dirU4), pd("66666666-6666-4666-8666-666666666666"))
	_, conn := registerGolden(t, srv, dirFeature)
	waitUntil(t, "four directives", func() bool { return len(directivesTo(conn)) == 4 })
	settle()
	got := directivesTo(conn)
	if len(got) != 4 || got[0].DirectiveID != dirU1 || got[3].DirectiveID != dirU4 {
		t.Fatalf("delivered %#v", got)
	}
}

// ---------------------------------------------------------------------------
// Notify route.
// ---------------------------------------------------------------------------

func notifyServer(t *testing.T, srv *Server, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv.mountDirectiveNotify(mux, token)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func postNotify(t *testing.T, ts *httptest.Server, device, auth, body string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/internal/devices/"+device+"/directive-pending", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestNotifyRouteNeedsTheToken(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	ts := notifyServer(t, srv, dirTestToken)
	_, conn := registerGolden(t, srv, dirFeature)
	waitUntil(t, "registration fetch", func() bool { return cp.calls(agentAuthGoldenDevice) == 1 })
	cp.setPending(agentAuthGoldenDevice, pd(dirU1))

	for name, auth := range map[string]string{"none": "", "wrong": "Bearer " + strings.Repeat("y", 256), "scheme": "Basic " + dirTestToken, "prefix": "Bearer " + dirTestToken[:100]} {
		if got := postNotify(t, ts, agentAuthGoldenDevice, auth, ""); got != http.StatusUnauthorized {
			t.Fatalf("%s token: status %d, want 401", name, got)
		}
	}
	settle()
	if cp.calls(agentAuthGoldenDevice) != 1 || len(directivesTo(conn)) != 0 {
		t.Fatal("an unauthorized notify triggered a fetch")
	}
	if got := postNotify(t, ts, agentAuthGoldenDevice, "Bearer "+dirTestToken, ""); got != http.StatusNoContent {
		t.Fatalf("authorized notify status %d, want 204", got)
	}
	waitUntil(t, "directive after notify", func() bool { return len(directivesTo(conn)) == 1 })
}

func TestNotifyRouteIsAbsentWithoutAToken(t *testing.T) {
	_, srv, _, _ := directiveEnv(t)
	for _, tok := range []string{"", "short"} {
		ts := notifyServer(t, srv, tok)
		if got := postNotify(t, ts, "d", "Bearer "+tok, ""); got != http.StatusNotFound {
			t.Fatalf("token %q: status %d, want 404 (not mounted)", tok, got)
		}
	}
}

// 204 whether or not the device is connected (no presence oracle); body is bounded and ignored.
func TestNotifyAlways204(t *testing.T) {
	_, srv, _, _ := directiveEnv(t)
	ts := notifyServer(t, srv, dirTestToken)
	registerGolden(t, srv, dirFeature)
	auth := "Bearer " + dirTestToken
	for name, dev := range map[string]string{"connected": agentAuthGoldenDevice, "offline": "nobody", "oversized id": strings.Repeat("z", 300)} {
		for _, body := range []string{"", "garbage{", strings.Repeat("A", 1<<20)} {
			if got := postNotify(t, ts, dev, auth, body); got != http.StatusNoContent {
				t.Fatalf("%s (body %d bytes): %d, want 204", name, len(body), got)
			}
		}
	}
}

func TestNotifyRelaysOnlyToTheNamedDevice(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	ts := notifyServer(t, srv, dirTestToken)
	_, connA := registerGolden(t, srv, dirFeature)
	_, connB := registerAs(t, srv, dirDevB, dirSeedB, dirFeature)
	waitUntil(t, "registration fetches", func() bool { return cp.calls(agentAuthGoldenDevice) == 1 && cp.calls(dirDevB) == 1 })
	cp.setPending(agentAuthGoldenDevice, pd(dirU1))
	cp.setPending(dirDevB, pd(dirU2))

	postNotify(t, ts, agentAuthGoldenDevice, "Bearer "+dirTestToken, "")
	waitUntil(t, "A's directive", func() bool { return len(directivesTo(connA)) == 1 })
	settle()
	if got := directivesTo(connA); got[0].DirectiveID != dirU1 {
		t.Fatalf("A got %#v", got)
	}
	if len(directivesTo(connB)) != 0 || cp.calls(dirDevB) != 1 {
		t.Fatalf("a notify for A reached B (directives %d, fetches %d)", len(directivesTo(connB)), cp.calls(dirDevB))
	}
}

func TestNotifyIgnoredWithoutAnEligiblePeer(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	ts := notifyServer(t, srv, dirTestToken)
	cp.setPending(agentAuthGoldenDevice, pd(dirU1))
	postNotify(t, ts, agentAuthGoldenDevice, "Bearer "+dirTestToken, "") // not connected
	registerGolden(t, srv, nil)                                          // connected, no feature
	postNotify(t, ts, agentAuthGoldenDevice, "Bearer "+dirTestToken, "")
	settle()
	if cp.calls(agentAuthGoldenDevice) != 0 {
		t.Fatalf("%d fetches for an offline / feature-less device", cp.calls(agentAuthGoldenDevice))
	}
}

func TestNotifyReachesARestrictedPeer(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	ts := notifyServer(t, srv, dirTestToken)
	cp.setStatus(agentAuthGoldenDevice, "retired")
	peer, conn := registerGolden(t, srv, dirFeature)
	if !peer.restricted {
		t.Fatal("not restricted")
	}
	waitUntil(t, "registration fetch", func() bool { return cp.calls(agentAuthGoldenDevice) == 1 })
	cp.setPending(agentAuthGoldenDevice, pd(dirU1))
	postNotify(t, ts, agentAuthGoldenDevice, "Bearer "+dirTestToken, "")
	waitUntil(t, "directive on the restricted peer", func() bool { return len(directivesTo(conn)) == 1 })
}

// A directive is relayed (and reported delivered) once per connection, however often it is pending.
func TestNoDuplicateRelayOnTheSameConnection(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	srv.directiveNotifyWindow = time.Millisecond
	ts := notifyServer(t, srv, dirTestToken)
	cp.setPending(agentAuthGoldenDevice, pd(dirU1))
	_, conn := registerGolden(t, srv, dirFeature)
	waitUntil(t, "first relay", func() bool { return len(directivesTo(conn)) == 1 })
	for i := 0; i < 3; i++ {
		postNotify(t, ts, agentAuthGoldenDevice, "Bearer "+dirTestToken, "")
		time.Sleep(30 * time.Millisecond)
	}
	waitUntil(t, "refetches", func() bool { return cp.calls(agentAuthGoldenDevice) >= 3 })
	settle()
	if n := len(directivesTo(conn)); n != 1 {
		t.Fatalf("directive relayed %d times on one connection", n)
	}
	if n := len(cp.deliveredList()); n != 1 {
		t.Fatalf("delivered reported %d times", n)
	}
	// A NEW connection (reconnect) gets it again: the ledger is per connection.
	_, conn2 := registerGolden(t, srv, dirFeature)
	waitUntil(t, "relay on the new connection", func() bool { return len(directivesTo(conn2)) == 1 })
}

func TestNotifyIsThrottledPerDevice(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	srv.directiveNotifyWindow = 400 * time.Millisecond
	_, conn := registerGolden(t, srv, dirFeature)
	waitUntil(t, "registration fetch", func() bool { return cp.calls(agentAuthGoldenDevice) == 1 })

	cp.setPending(agentAuthGoldenDevice, pd(dirU1))
	for i := 0; i < 30; i++ {
		srv.notifyDirectivePending(agentAuthGoldenDevice)
	}
	waitUntil(t, "first directive", func() bool { return len(directivesTo(conn)) == 1 })
	// A newer issuance inside the window is not lost: one trailing fetch picks it up.
	cp.setPending(agentAuthGoldenDevice, pd(dirU1), pd(dirU2))
	for i := 0; i < 30; i++ {
		srv.notifyDirectivePending(agentAuthGoldenDevice)
	}
	waitUntil(t, "trailing fetch", func() bool { return len(directivesTo(conn)) == 2 })
	time.Sleep(900 * time.Millisecond)
	// 1 registration + 1 immediate + 1 trailing = 3, nowhere near the 60 notifications.
	if n := cp.calls(agentAuthGoldenDevice); n > 4 {
		t.Fatalf("%d control-plane fetches for 60 notifications", n)
	}
}

func TestNotifyIsBoundedByTheConcurrencyLimit(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	_, _ = registerGolden(t, srv, dirFeature)
	waitUntil(t, "registration fetch", func() bool { return cp.calls(agentAuthGoldenDevice) == 1 })
	for i := 0; i < cap(directiveSlots); i++ {
		if !acquireDirectiveSlot(0) {
			t.Fatal("could not fill the slots")
		}
	}
	defer func() {
		for i := 0; i < cap(directiveSlots); i++ {
			releaseDirectiveSlot()
		}
	}()
	srv.notifyDirectivePending(agentAuthGoldenDevice)
	settle()
	if cp.calls(agentAuthGoldenDevice) != 1 {
		t.Fatal("a notify fetched although every control-plane slot was busy")
	}
}

// ---------------------------------------------------------------------------
// Acknowledgements (D-C8).
// ---------------------------------------------------------------------------

func authedAckPeer(srv *Server) (*Peer, *fakeConn) {
	conn := &fakeConn{}
	return &Peer{conn: conn, registered: true, DeviceId: agentAuthGoldenDevice, Tenant: dirTenantID, directiveV1: true}, conn
}

func validAck() *DirectiveAck {
	return &DirectiveAck{DirectiveID: dirU1, From: "accepted", To: "complete", TsMs: 1730000000123, Detail: "ok; 100%", Sig: "ab12"}
}

func ackResult(t *testing.T, c *fakeConn) DirectiveAckResult {
	t.Helper()
	waitUntil(t, "ack result", func() bool { _, ok := findMsg[DirectiveAckResult](c.messages()); return ok })
	r, _ := findMsg[DirectiveAckResult](c.messages())
	return r
}

func TestAckIsForwardedVerbatimWithTheConnectionsDeviceId(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	peer, conn := authedAckPeer(srv)
	ack := validAck()
	srv.dispatch(peer, ClientToServer{Payload: ack})
	if r := ackResult(t, conn); r.Outcome != "applied" || r.DirectiveID != dirU1 {
		t.Fatalf("result %#v", r)
	}
	acks := cp.ackList()
	if len(acks) != 1 || acks[0].id != dirU1 {
		t.Fatalf("acks %#v", acks)
	}
	b := acks[0].body
	want := map[string]any{"device_id": agentAuthGoldenDevice, "from": "accepted", "to": "complete", "ts_ms": float64(1730000000123), "detail": "ok; 100%", "sig": "ab12"}
	if len(b) != len(want) {
		t.Fatalf("body %v", b)
	}
	for k, v := range want {
		if b[k] != v {
			t.Fatalf("field %s = %v, want %v (body %v)", k, b[k], v, b)
		}
	}
}

// The device id can only come from the connection: a message that names one is refused by the
// strict decoder before it reaches a handler.
func TestAckWithADeviceFieldIsRejectedByTheDecoder(t *testing.T) {
	base := `{"type":"directive_ack","directive_id":"` + dirU1 + `","from":"a","to":"b","ts_ms":1,"detail":"","sig":"ab"`
	var ok ClientToServer
	if err := json.Unmarshal([]byte(base+`}`), &ok); err != nil {
		t.Fatalf("the well-formed ack was refused: %v", err)
	}
	for _, extra := range []string{`,"device_id":"other-device"`, `,"device":"x"`, `,"tenant_id":"t"`, `,"anything":1`} {
		var m ClientToServer
		if err := json.Unmarshal([]byte(base+extra+`}`), &m); err == nil {
			t.Fatalf("an ack with %s was accepted", extra)
		}
	}
}

func TestAckWireBounds(t *testing.T) {
	good := validAck()
	mk := func(mut func(a *DirectiveAck)) error {
		a := *good
		mut(&a)
		raw, _ := json.Marshal(ClientToServer{Payload: &a})
		var m ClientToServer
		return json.Unmarshal(raw, &m)
	}
	if err := mk(func(*DirectiveAck) {}); err != nil {
		t.Fatalf("good ack refused: %v", err)
	}
	if err := mk(func(a *DirectiveAck) { a.Detail = strings.Repeat("d", maxDirectiveDetailBytes) }); err != nil {
		t.Fatalf("max-size detail refused: %v", err)
	}
	for name, mut := range map[string]func(a *DirectiveAck){
		"detail":     func(a *DirectiveAck) { a.Detail = strings.Repeat("d", maxDirectiveDetailBytes+1) },
		"sig":        func(a *DirectiveAck) { a.Sig = strings.Repeat("a", maxDirectiveSigBytes+1) },
		"from":       func(a *DirectiveAck) { a.From = strings.Repeat("f", maxDirectiveAddrBytes+1) },
		"to":         func(a *DirectiveAck) { a.To = strings.Repeat("t", maxDirectiveAddrBytes+1) },
		"id empty":   func(a *DirectiveAck) { a.DirectiveID = "" },
		"id garbage": func(a *DirectiveAck) { a.DirectiveID = "not-a-uuid" },
		"id braces":  func(a *DirectiveAck) { a.DirectiveID = "{" + dirU1[:34] + "}" },
	} {
		if err := mk(mut); err == nil {
			t.Fatalf("%s: out-of-bounds ack accepted", name)
		}
	}
}

func TestAckOutcomeMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
		want string
	}{
		{"applied", 200, `{"outcome":"applied"}`, "applied"},
		{"replay", 200, `{"outcome":"replay"}`, "replay"},
		{"unknown outcome", 200, `{"outcome":"ok"}`, "unavailable"},
		{"garbage 200", 200, `nope`, "unavailable"},
		{"400", 400, `{"error":"x"}`, "refused"},
		{"403", 403, `{"error":"x"}`, "refused"},
		{"404", 404, `{"error":"x"}`, "refused"},
		{"409", 409, `{"error":"x"}`, "refused"},
		{"401", 401, ``, "unavailable"},
		{"429", 429, ``, "unavailable"},
		{"500", 500, ``, "unavailable"},
		{"503", 503, ``, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp, srv, _, _ := directiveEnv(t)
			cp.mu.Lock()
			cp.ackCode, cp.ackBody = tc.code, tc.body
			cp.mu.Unlock()
			peer, conn := authedAckPeer(srv)
			srv.dispatch(peer, ClientToServer{Payload: validAck()})
			if got := ackResult(t, conn).Outcome; got != tc.want {
				t.Fatalf("outcome %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("transport error", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		cp.srv.Close()
		peer, conn := authedAckPeer(srv)
		srv.dispatch(peer, ClientToServer{Payload: validAck()})
		if got := ackResult(t, conn).Outcome; got != "unavailable" {
			t.Fatalf("outcome %q", got)
		}
	})
}

func TestAckGates(t *testing.T) {
	t.Run("unregistered", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		peer, conn := authedAckPeer(srv)
		peer.registered = false
		srv.dispatch(peer, ClientToServer{Payload: validAck()})
		if len(rejectedReasons(conn)) != 1 || len(cp.ackList()) != 0 {
			t.Fatal("an unregistered connection's ack was not rejected")
		}
	})
	t.Run("no directive_v1", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		peer, conn := authedAckPeer(srv)
		peer.directiveV1 = false
		srv.dispatch(peer, ClientToServer{Payload: validAck()})
		settle()
		if len(rejectedReasons(conn)) != 1 || len(cp.ackList()) != 0 {
			t.Fatal("an ack from a connection that never advertised directive_v1 was forwarded")
		}
	})
	t.Run("dev mode", func(t *testing.T) {
		withDirectiveSupported(t, true)
		cp := newFakeDirectiveCP(t)
		srv, _ := NewServer(time.Minute, "relay-1:4444", nil, nil)
		srv.guestEnd = guestEndTestReporter(t, cp.srv.URL)
		peer, conn := authedAckPeer(srv)
		srv.dispatch(peer, ClientToServer{Payload: validAck()})
		if r := ackResult(t, conn); r.Outcome != "refused" || len(cp.ackList()) != 0 {
			t.Fatalf("dev-mode ack: %#v", r)
		}
	})
	t.Run("control plane not serving directives", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		withDirectiveSupported(t, false)
		peer, conn := authedAckPeer(srv)
		srv.dispatch(peer, ClientToServer{Payload: validAck()})
		if r := ackResult(t, conn); r.Outcome != "unavailable" || len(cp.ackList()) != 0 {
			t.Fatalf("ack while unsupported: %#v", r)
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		cp, srv, _, _ := directiveEnv(t)
		peer, conn := authedAckPeer(srv)
		for i := 0; i < directiveAckPerMinute; i++ {
			srv.dispatch(peer, ClientToServer{Payload: validAck()})
			want := i + 1
			waitUntil(t, "ack forwarded", func() bool { return len(cp.ackList()) == want })
		}
		waitUntil(t, "all acks forwarded", func() bool { return len(cp.ackList()) == directiveAckPerMinute })
		srv.dispatch(peer, ClientToServer{Payload: validAck()})
		waitUntil(t, "the over-limit reply", func() bool {
			var n int
			for _, m := range conn.messages() {
				if r, ok := m.Payload.(DirectiveAckResult); ok && r.Outcome == "unavailable" {
					n++
				}
			}
			return n == 1
		})
		settle()
		if len(cp.ackList()) != directiveAckPerMinute {
			t.Fatalf("the over-limit ack reached the control plane (%d)", len(cp.ackList()))
		}
	})
}

// ---------------------------------------------------------------------------
// Capability probe: the directive_v1 flag.
// ---------------------------------------------------------------------------

func TestProbeSetsDirectiveSupportedAlongsideSessionEnded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantOut    probeOutcome
		wantDirect bool
	}{
		{"both", 200, `{"features":["session_ended_v1","directive_v1"]}`, probeSupported, true},
		{"only session_ended", 200, `{"features":["session_ended_v1"]}`, probeSupported, false},
		{"only directive", 200, `{"features":["directive_v1"]}`, probeUnsupported, true},
		{"neither", 200, `{"features":[]}`, probeUnsupported, false},
		{"404", 404, ``, probeUnsupported, false},
		{"401", 401, ``, probeUnsupported, false},
		{"503", 503, ``, probeUnsettled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer cp.Close()
			rep := guestEndTestReporter(t, cp.URL)
			o, d := rep.probeCapabilitySet(context.Background())
			if o != tc.wantOut || d != tc.wantDirect {
				t.Fatalf("probe = (%v,%v), want (%v,%v)", o, d, tc.wantOut, tc.wantDirect)
			}
			// The single-result wrapper is the unchanged session_ended_v1 view.
			if got := rep.probeCapabilities(context.Background()); got != tc.wantOut {
				t.Fatalf("probeCapabilities = %v, want %v", got, tc.wantOut)
			}
		})
	}
}

func TestApplyDirectiveProbe(t *testing.T) {
	withDirectiveSupported(t, false)
	if applyDirectiveProbe(probeUnsettled, true) || directiveSupported.Load() {
		t.Fatal("an unsettled probe changed the directive flag")
	}
	if !applyDirectiveProbe(probeUnsupported, true) || !directiveSupported.Load() {
		t.Fatal("a settled probe listing directive_v1 did not flip the flag")
	}
	if applyDirectiveProbe(probeSupported, true) {
		t.Fatal("a refresh reported a flip")
	}
	applyDirectiveProbe(probeUnsettled, false) // transient failure keeps the answer
	if !directiveSupported.Load() {
		t.Fatal("a transient failure cleared the flag")
	}
	applyDirectiveProbe(probeUnsupported, false) // rollback
	if directiveSupported.Load() {
		t.Fatal("a rollback did not clear the flag")
	}
}

func TestRunCapabilityProbeFlipsDirectiveAndNotifies(t *testing.T) {
	withDirectiveSupported(t, false)
	withSessionEndedSupported(t, false)
	withCapabilitySettledOnce(t, false)
	cp := newFakeDirectiveCP(t)
	cp.mu.Lock()
	cp.features = []string{"directive_v1"} // session_ended_v1 absent: only the directive flag flips
	cp.mu.Unlock()
	rep := guestEndTestReporter(t, cp.srv.URL)
	var mu sync.Mutex
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rep.RunCapabilityProbe(ctx, func() { mu.Lock(); calls++; mu.Unlock() })
	waitUntil(t, "directive flag", func() bool { return directiveSupported.Load() })
	waitUntil(t, "bounce notification", func() bool { mu.Lock(); defer mu.Unlock(); return calls == 1 })
	if sessionEndedSupported.Load() {
		t.Fatal("session_ended_v1 flipped though the control plane did not list it")
	}
}

func registeredFeatures(t *testing.T, s *Server, p *Peer) []string {
	t.Helper()
	return s.registeredMsg(p).Features
}

func TestRegisteredAdvertisesDirectiveOnlyWhereItCanBeUsed(t *testing.T) {
	withDirectiveSupported(t, true)
	withSessionEndedSupported(t, true)
	authed, _ := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	dev, _ := NewServer(time.Minute, "relay-1:4444", nil, nil)
	join := func(f []string) string { return strings.Join(f, ",") }

	if got := join(registeredFeatures(t, authed, &Peer{Tenant: "t", directiveV1: true})); got != "session_ended_v1,directive_v1" {
		t.Fatalf("normal peer: %q", got)
	}
	if got := join(registeredFeatures(t, authed, &Peer{Tenant: "t"})); got != "session_ended_v1" {
		t.Fatalf("a peer that did not ask: %q", got)
	}
	if got := join(registeredFeatures(t, authed, &Peer{Tenant: "t", directiveV1: true, restricted: true})); got != "directive_v1" {
		t.Fatalf("restricted peer: %q (must never be told session_ended_v1)", got)
	}
	if got := join(registeredFeatures(t, authed, &Peer{directiveV1: true})); got != "" {
		t.Fatalf("tenantless peer: %q", got)
	}
	if got := join(registeredFeatures(t, dev, &Peer{Tenant: "t", directiveV1: true})); got != "" {
		t.Fatalf("dev mode: %q", got)
	}
	withDirectiveSupported(t, false)
	if got := join(registeredFeatures(t, authed, &Peer{Tenant: "t", directiveV1: true})); got != "session_ended_v1" {
		t.Fatalf("unsupported CP: %q", got)
	}
}

// A peer that asked for directive_v1 before the control plane confirmed it is reconnected when the
// probe flips, and one that was told (or never asked) is left alone.
func TestBounceReconnectsPeersThatMissedDirectiveV1(t *testing.T) {
	withDirectiveSupported(t, false)
	withSessionEndedSupported(t, true) // isolate the directive bounce from the session_ended one
	s, _ := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	s.bounceDelay = func() time.Duration { return 0 }
	mk := func(dev string, asked, restricted bool) (*Peer, *fakeConn) {
		c := &fakeConn{}
		p := &Peer{DeviceId: dev, Tenant: "t", conn: c, directiveV1: asked, restricted: restricted}
		if restricted {
			s.reg.RegisterRestricted(p)
		} else {
			s.reg.Register(p)
		}
		_ = s.registeredMsg(p)
		return p, c
	}
	_, missed := mk("missed", true, false)
	_, missedRestricted := mk("missed-restricted", true, true)
	_, neverAsked := mk("never-asked", false, false)
	directiveSupported.Store(true)
	_, told := mk("told", true, false)
	if n := s.bounceSessionEndedStale(); n < 2 {
		t.Fatalf("scheduled %d bounces, want the two stale peers", n)
	}
	waitUntil(t, "bounce", func() bool {
		return len(closeFrameReasons(missed)) == 1 && len(closeFrameReasons(missedRestricted)) == 1
	})
	settle()
	for name, c := range map[string]*fakeConn{"told": told, "never-asked": neverAsked} {
		if got := closeFrameReasons(c); len(got) != 0 {
			t.Fatalf("%s was closed: %q", name, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Revalidation of restricted peers.
// ---------------------------------------------------------------------------

func registerRestrictedDirect(srv *Server, device, tenant, pubkey string) (*Peer, *fakeConn) {
	conn := &fakeConn{}
	p := &Peer{DeviceId: device, Tenant: tenant, Pubkey: pubkey, conn: conn, registered: true, restricted: true}
	srv.reg.RegisterRestricted(p)
	return p, conn
}

func TestRevalidateRestrictedPeers(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	resolver := &fakeResolver{identities: map[string]*DeviceIdentity{
		"still-retired": {DeviceID: "still-retired", TenantID: tenant, Pubkey: "aa", Status: "retired"},
		"now-active":    {DeviceID: "now-active", TenantID: tenant, Pubkey: "bb", Status: "active"},
		"now-legacy":    {DeviceID: "now-legacy", TenantID: tenant, Pubkey: "cc"}, // no status field at all
		"now-quar":      {DeviceID: "now-quar", TenantID: tenant, Pubkey: "dd", Status: "quarantined"},
		"retired-now":   {DeviceID: "retired-now", TenantID: tenant, Pubkey: "ee", Status: "retired"},
		"active-stays":  {DeviceID: "active-stays", TenantID: tenant, Pubkey: "ff", Status: "active"},
	}}
	srv := authServer(t, resolver)
	keep, keepConn := registerRestrictedDirect(srv, "still-retired", tenant, "aa")
	_, activeConn := registerRestrictedDirect(srv, "now-active", tenant, "bb")
	_, legacyConn := registerRestrictedDirect(srv, "now-legacy", tenant, "cc")
	_, quarConn := registerRestrictedDirect(srv, "now-quar", tenant, "dd")
	_, goneConn := registerRestrictedDirect(srv, "removed", tenant, "gg") // CP answers 404
	retiredNormalConn := registerVerified(srv, "retired-now", tenant, "ee")
	staysConn := registerVerified(srv, "active-stays", tenant, "ff")

	if n := srv.RevalidateAgents(context.Background()); n != 5 {
		t.Fatalf("closed %d, want 5", n)
	}
	if !srv.reg.isCurrent(keep) || keepConn.closed {
		t.Fatal("a still-retired restricted peer was dropped")
	}
	if _, ok := srv.reg.Lookup("active-stays"); !ok || staysConn.closed {
		t.Fatal("an active normal peer was disturbed")
	}
	for name, c := range map[string]*fakeConn{"now-active": activeConn, "now-legacy": legacyConn, "now-quar": quarConn, "retired-now(normal)": retiredNormalConn} {
		if !c.closed {
			t.Fatalf("%s was not closed", name)
		}
		if code := closeCode(t, c); code != websocket.CloseNormalClosure {
			t.Fatalf("%s: close code %d, want a CLEAN close (%d) so the agent re-registers", name, code, websocket.CloseNormalClosure)
		}
	}
	if !goneConn.closed {
		t.Fatal("a restricted peer the control plane 404s was kept")
	}
	if len(srv.reg.restricted) != 1 {
		t.Fatalf("restricted map holds %d entries, want only the still-retired one", len(srv.reg.restricted))
	}
	if _, ok := srv.reg.Lookup("retired-now"); ok {
		t.Fatal("a peer retired while connected is still brokerable")
	}
}

// docs/65 sec. 8: a machine an Owner FORGOT is, to signaling, a REMOVED machine - the control plane's identity answer is
// 404, exactly as after a confirmed removal. The restricted connection it still held is dropped by the revalidation sweep that
// already disowns every removed machine's peer (no new protocol, no new internal route), with the policy-violation close, and
// the device's next registration is refused with the one generic reason.
func TestRevalidateDropsAForgottenMachinesRestrictedConnectionAndItsNextRegistrationIsRefused(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	cp.setStatus(agentAuthGoldenDevice, "retired")
	peer, conn := registerGolden(t, srv, dirFeature)
	if !peer.registered || !peer.restricted {
		t.Fatalf("registered=%v restricted=%v, want a restricted registration of the retired machine", peer.registered, peer.restricted)
	}
	// Still retired: the sweep keeps the connection (the control case: it does not drop everyone).
	if n := srv.RevalidateAgents(context.Background()); n != 0 || conn.closed || !srv.reg.isCurrent(peer) {
		t.Fatalf("dropped=%d closed=%v current=%v: a still-retired machine's connection was disturbed", n, conn.closed, srv.reg.isCurrent(peer))
	}

	cp.setStatus(agentAuthGoldenDevice, "removed") // the Owner forgot it: the same tombstone a confirmed removal applies
	if n := srv.RevalidateAgents(context.Background()); n != 1 {
		t.Fatalf("dropped %d connections, want the forgotten machine's", n)
	}
	if srv.reg.isCurrent(peer) || len(srv.reg.restricted) != 0 {
		t.Fatal("the forgotten machine's restricted connection is still registered")
	}
	if !conn.closed || closeCode(t, conn) != websocket.ClosePolicyViolation {
		t.Fatalf("closed=%v code=%d, want the socket closed with the policy-violation frame (%d)", conn.closed, closeCode(t, conn), websocket.ClosePolicyViolation)
	}

	// Its next registration: the handshake never completes, and the reason is the one generic string.
	conn2 := &fakeConn{}
	again := &Peer{conn: conn2}
	srv.dispatch(again, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen, Features: dirFeature,
	}})
	nonce := challengeNonce(t, conn2)
	srv.dispatch(again, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice, Nonce: hex.EncodeToString(nonce),
		Sig: signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, dirTenantID, nonce),
	}})
	if again.registered || len(srv.reg.restricted) != 0 {
		t.Fatalf("registered=%v restricted entries=%d: a forgotten machine registered again", again.registered, len(srv.reg.restricted))
	}
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatal("a forgotten machine is brokerable")
	}
	if reason := rejectionReason(t, conn2); reason != agentAuthRejectionReason {
		t.Fatalf("rejection reason %q, want the generic %q", reason, agentAuthRejectionReason)
	}
}

// ---------------------------------------------------------------------------
// Wire shapes.
// ---------------------------------------------------------------------------

func jsonMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDirectiveMessagesExactWireShape(t *testing.T) {
	check := func(name string, got map[string]any, want map[string]any) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: keys %v, want %v", name, got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s: %s = %v, want %v", name, k, got[k], v)
			}
		}
	}
	check("directive", jsonMap(t, ServerToClient{Payload: Directive{DirectiveID: dirU1, Artifact: "RMTDIRECTIVEv1.sig"}}),
		map[string]any{"type": "directive", "directive_id": dirU1, "artifact": "RMTDIRECTIVEv1.sig"})
	check("directive_ack_result", jsonMap(t, ServerToClient{Payload: DirectiveAckResult{DirectiveID: dirU1, Outcome: "refused"}}),
		map[string]any{"type": "directive_ack_result", "directive_id": dirU1, "outcome": "refused"})
	check("directive_ack", jsonMap(t, ClientToServer{Payload: validAck()}),
		map[string]any{"type": "directive_ack", "directive_id": dirU1, "from": "accepted", "to": "complete", "ts_ms": float64(1730000000123), "detail": "ok; 100%", "sig": "ab12"})

	// register_agent: features omitted when empty, present when set.
	if _, ok := jsonMap(t, ClientToServer{Payload: &RegisterAgent{Device: "d", Pubkey: "p", Nat: NatOpen}})["features"]; ok {
		t.Fatal("features must be omitted when unset")
	}
	if got := jsonMap(t, ClientToServer{Payload: &RegisterAgent{Device: "d", Pubkey: "p", Nat: NatOpen, Features: dirFeature}})["features"]; fmt.Sprint(got) != "[directive_v1]" {
		t.Fatalf("features = %v", got)
	}
}

func TestDirectiveMessagesRoundTrip(t *testing.T) {
	for _, payload := range []any{Directive{DirectiveID: dirU1, Artifact: "a"}, DirectiveAckResult{DirectiveID: dirU1, Outcome: "replay"}} {
		raw, _ := json.Marshal(ServerToClient{Payload: payload})
		var got ServerToClient
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		switch want := payload.(type) {
		case Directive:
			if p, ok := got.Payload.(*Directive); !ok || *p != want {
				t.Fatalf("got %#v", got.Payload)
			}
		case DirectiveAckResult:
			if p, ok := got.Payload.(*DirectiveAckResult); !ok || *p != want {
				t.Fatalf("got %#v", got.Payload)
			}
		}
	}
	raw, _ := json.Marshal(ClientToServer{Payload: validAck()})
	var got ClientToServer
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if p, ok := got.Payload.(*DirectiveAck); !ok || *p != *validAck() || got.Type != "directive_ack" {
		t.Fatalf("ack round trip: %#v", got)
	}
}

func TestBoundFeatures(t *testing.T) {
	long := strings.Repeat("a", maxFeatureBytes)
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"nil", nil, ""},
		{"valid", []string{"directive_v1", "x9"}, "directive_v1,x9"},
		{"max length ok", []string{long}, long},
		{"too long dropped", []string{long + "a", "ok"}, "ok"},
		{"uppercase dropped", []string{"Directive_v1", "ok"}, "ok"},
		{"charset", []string{"a-b", "a b", "a.b", "", "é", "ok"}, "ok"},
		{"dedup", []string{"ok", "ok", "ok"}, "ok"},
		{"only first 8 examined", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "directive_v1"}, "a,b,c,d,e,f,g,h"},
	} {
		if got := strings.Join(boundFeatures(tc.in), ","); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// And end to end: a ninth-position directive_v1 is not honoured.
	_, srv, _, _ := directiveEnv(t)
	feats := []string{"a", "b", "c", "d", "e", "f", "g", "h", directiveFeature}
	peer, _ := registerGolden(t, srv, feats)
	if peer.directiveV1 {
		t.Fatal("a feature beyond the 8th entry was honoured")
	}
	peer2, _ := registerGolden(t, srv, []string{"a", directiveFeature})
	if !peer2.directiveV1 {
		t.Fatal("a valid directive_v1 was not honoured")
	}
}
