package main

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// errConn embeds fakeConn but makes WriteJSON always return a fixed error. All other
// peerConn methods are promoted from the embedded fakeConn unchanged.
type errConn struct {
	fakeConn
}

func (e *errConn) WriteJSON(v interface{}) error {
	return errors.New("write: connection reset by peer")
}

// findMsg returns the first payload of type T among a peer's received messages. Server-side
// sends carry value payloads (Peer.Send is called with values), so it asserts the value type.
func findMsg[T any](msgs []ServerToClient) (T, bool) {
	var zero T
	for _, m := range msgs {
		if p, ok := m.Payload.(T); ok {
			return p, true
		}
	}
	return zero, false
}

// indexOfMsg returns the position of the first payload of type T, or -1. Position — not mere
// presence — is what the ordering test below needs.
func indexOfMsg[T any](msgs []ServerToClient) int {
	for i, m := range msgs {
		if _, ok := m.Payload.(T); ok {
			return i
		}
	}
	return -1
}

// **ice_servers must arrive BEFORE brokered, on both peers.**
//
// This is the one property of the ICE handout that is not self-evident from reading either side.
// Both clients construct their RTCPeerConnection the instant they see `brokered`, and ICE servers
// cannot be added to a live peer connection without renegotiation — so a list sent afterwards is
// silently ignored and the session loses its relayed path with nothing logged anywhere. A WebSocket
// preserves order per connection, which is what makes "send it first" sufficient.
//
// Presence alone would NOT catch a regression here: moving the send below the `brokered` calls
// leaves both messages in the transcript and every other assertion green.
func TestIceServersArriveBeforeBrokered(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil).WithTurn(TurnConfig{
		URLs:     []string{"turn:turn.example:3478?transport=udp"},
		Secret:   "shared-with-coturn",
		TTL:      time.Hour,
		StunURLs: []string{"stun:stun.example:3478"},
	})

	agentConn := &fakeConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn))
	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err != nil {
		t.Fatalf("ConnectRequest error: %v", err)
	}

	for name, conn := range map[string]*fakeConn{"controller": ctrlConn, "agent": agentConn} {
		msgs := conn.messages()
		iceAt := indexOfMsg[IceServers](msgs)
		brokeredAt := indexOfMsg[Brokered](msgs)
		if iceAt < 0 {
			t.Fatalf("%s never received ice_servers", name)
		}
		if brokeredAt < 0 {
			t.Fatalf("%s never received brokered", name)
		}
		if iceAt > brokeredAt {
			t.Fatalf("%s received ice_servers at %d, AFTER brokered at %d — the peer connection is "+
				"already built by then and the ICE servers are silently discarded", name, iceAt, brokeredAt)
		}

		ice, _ := findMsg[IceServers](msgs)
		if ice.Session != sess.Id {
			t.Fatalf("%s ice_servers session %q, want %q", name, ice.Session, sess.Id)
		}
		// The `type` discriminant is injected by the envelope, not carried on the payload — assert
		// it where it actually lives, or a payload that never reaches the wire correctly would
		// still look tagged here.
		if msgs[iceAt].Type != "" && msgs[iceAt].Type != "ice_servers" {
			t.Fatalf("%s ice_servers envelope tag is %q", name, msgs[iceAt].Type)
		}
		// STUN + TURN, with the credential only on the TURN entry.
		if len(ice.Servers) != 2 {
			t.Fatalf("%s expected 2 ICE servers, got %+v", name, ice.Servers)
		}
		if ice.Servers[1].Username == "" || ice.Servers[1].Credential == "" {
			t.Fatalf("%s TURN entry carries no credential: %+v", name, ice.Servers[1])
		}
	}

	// Both peers must get credentials issued at the same instant — different ones would mean two
	// coturn allocations for one session, and a confusing pair of entries in its logs.
	ctrlIce, _ := findMsg[IceServers](ctrlConn.messages())
	agentIce, _ := findMsg[IceServers](agentConn.messages())
	if ctrlIce.Servers[1].Username != agentIce.Servers[1].Username {
		t.Fatalf("peers received different TURN usernames: %q vs %q",
			ctrlIce.Servers[1].Username, agentIce.Servers[1].Username)
	}
}

// With no TURN configured — the LAN default — both peers still receive an ice_servers message,
// carrying an empty list. Sending it unconditionally keeps the ordering contract simple (a client
// never has to decide how long to wait for a message that may not come) and costs one tiny frame.
func TestIceServersIsStillSentWhenNothingIsConfigured(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn))
	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	if _, err := broker.ConnectRequest(controller, "agent-dev", nil); err != nil {
		t.Fatalf("ConnectRequest error: %v", err)
	}
	ice, ok := findMsg[IceServers](ctrlConn.messages())
	if !ok {
		t.Fatal("controller received no ice_servers on a LAN-configured broker")
	}
	if len(ice.Servers) != 0 {
		t.Fatalf("expected an empty list, got %+v", ice.Servers)
	}
}

func TestBrokerConnectRequestBrokersBothPeers(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn))
	agent, _ := reg.Lookup("agent-dev")

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err != nil {
		t.Fatalf("ConnectRequest error: %v", err)
	}
	if sess == nil || sess.Id == "" {
		t.Fatal("expected a session with an id")
	}

	// Each side gets a brokered with the OTHER peer's pinned pubkey.
	ctrlBrokered, ok := findMsg[Brokered](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive brokered")
	}
	if ctrlBrokered.PeerDevice != "agent-dev" || ctrlBrokered.PeerPubkey != "ed25519:agent" {
		t.Fatalf("controller brokered pinned wrong peer: %+v", ctrlBrokered)
	}
	if ctrlBrokered.Session != sess.Id {
		t.Fatalf("controller brokered session %q, want %q", ctrlBrokered.Session, sess.Id)
	}

	agentBrokered, ok := findMsg[Brokered](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive brokered")
	}
	if agentBrokered.PeerDevice != "ctrl-dev" || agentBrokered.PeerPubkey != "ed25519:ctrl" {
		t.Fatalf("agent brokered pinned wrong peer: %+v", agentBrokered)
	}

	// Both sides get the SAME relay token pointed at the SAME relay.
	ctrlRelay, ok := findMsg[RelayAssignment](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive relay_assignment")
	}
	agentRelay, ok := findMsg[RelayAssignment](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive relay_assignment")
	}
	if ctrlRelay.Token != agentRelay.Token {
		t.Fatalf("relay tokens differ: %q vs %q", ctrlRelay.Token, agentRelay.Token)
	}
	if ctrlRelay.RelayAddr != "relay-1:4444" {
		t.Fatalf("relay addr = %q, want relay-1:4444", ctrlRelay.RelayAddr)
	}
	_ = agent
}

func TestBrokerConnectRequestRejectsUnknownTarget(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl", conn: ctrlConn}

	if _, err := broker.ConnectRequest(controller, "missing", nil); err == nil {
		t.Fatal("expected error for unknown target")
	}
	if _, ok := findMsg[Rejected](ctrlConn.messages()); !ok {
		t.Fatal("controller should have received rejected")
	}
}

// Pins clipForLog's exact output for the broker's identifiers (the helper is shared with agent auth).
func TestClipForLogExactOutputForBrokerIDs(t *testing.T) {
	if got := clipForLog("short"); got != "short" {
		t.Fatalf("short id changed: %q", got)
	}
	exact := strings.Repeat("a", 128)
	if got := clipForLog(exact); got != exact {
		t.Fatalf("128-byte id changed: %q", got)
	}
	got := clipForLog(strings.Repeat("a", 129))
	if want := strings.Repeat("a", 128) + "...(129 bytes)"; got != want {
		t.Fatalf("clipped ASCII = %q, want %q", got, want)
	}
	// 127 ASCII bytes then a 3-byte rune: the byte-128 cut lands inside the rune.
	multi := strings.Repeat("a", 127) + "€" + strings.Repeat("b", 10)
	got = clipForLog(multi)
	if !utf8.ValidString(got) {
		t.Fatalf("clipped multibyte id is not valid UTF-8: %q", got)
	}
	if want := strings.Repeat("a", 127) + "...(140 bytes)"; got != want {
		t.Fatalf("clipped multibyte = %q, want %q", got, want)
	}
}

func TestBrokerErrorsClipAttackerIds(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)
	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl", conn: ctrlConn}
	huge := strings.Repeat("x", 60*1024)

	bounded := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected error", what)
		}
		if len(err.Error()) >= 512 {
			t.Fatalf("%s: error is %d bytes, want < 512", what, len(err.Error()))
		}
		if strings.Contains(err.Error(), huge) {
			t.Fatalf("%s: error contains the full attacker string", what)
		}
	}

	_, err := broker.ConnectRequest(controller, huge, nil)
	bounded("ConnectRequest", err)
	bounded("RelayCandidate", broker.RelayCandidate(huge, controller, Candidate{Addr: "9.9.9.9:1", Kind: CandidateHost}))
	bounded("RelaySdp", broker.RelaySdp(huge, controller, "v=0", SdpOffer))

	// Positive control: short ids still appear in full.
	_, err = broker.ConnectRequest(controller, "missing-dev", nil)
	if err == nil || !strings.Contains(err.Error(), "target missing-dev not available") {
		t.Fatalf("short target not reported in full: %v", err)
	}
	err = broker.RelayCandidate("no-such-session", controller, Candidate{Addr: "9.9.9.9:1", Kind: CandidateHost})
	if err == nil || !strings.Contains(err.Error(), "unknown session no-such-session") {
		t.Fatalf("short session not reported in full: %v", err)
	}
	err = broker.RelaySdp("no-such-session", controller, "v=0", SdpOffer)
	if err == nil || !strings.Contains(err.Error(), "unknown session no-such-session") {
		t.Fatalf("short session not reported in full (sdp): %v", err)
	}

	// A legal brokered session still succeeds.
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatOpen, &fakeConn{}))
	sess, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err != nil {
		t.Fatalf("legal ConnectRequest: %v", err)
	}
	if err := broker.RelaySdp(sess.Id, controller, "v=0", SdpOffer); err != nil {
		t.Fatalf("legal RelaySdp: %v", err)
	}
}

// A holder of ANY valid ticket reaches verifyTicket's device-mismatch error with a target of its
// choosing (the signature verifies before the comparison), and ConnectRequest's caller logs it.
func TestTicketDeviceMismatchErrorClipsTarget(t *testing.T) {
	claims := ticketGoldenClaims()

	// Negative control FIRST: the unmodified golden ticket is admitted for its own device, so the
	// refusals below are the device comparison, not a broken signature or setup.
	broker, controller, _ := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("premise not met: the golden ticket was refused for its own device: %v", err)
	}

	huge := strings.Repeat("x", 60*1024)
	broker2, controller2, _ := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
	_, err := broker2.ConnectRequest(controller2, huge, mintTicket(t, claims))
	if err == nil || !errors.Is(err, errTicketInvalid) {
		t.Fatalf("oversized mismatching target: err = %v, want errTicketInvalid", err)
	}
	if !strings.Contains(err.Error(), "connect_request targets") {
		t.Fatalf("refused for the wrong reason (want the device mismatch): %v", err)
	}
	if len(err.Error()) >= 512 || strings.Contains(err.Error(), huge) {
		t.Fatalf("mismatch error is %d bytes / carries the full target; want it clipped", len(err.Error()))
	}

	// Positive control: a short mismatching target is still reported in full.
	broker3, controller3, _ := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
	_, err = broker3.ConnectRequest(controller3, "other-device", mintTicket(t, claims))
	if err == nil || !strings.Contains(err.Error(), `connect_request targets "other-device"`) {
		t.Fatalf("short mismatching target not reported in full: %v", err)
	}
}

func TestBrokerRelayCandidate(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatOpen, agentConn))

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	cand := Candidate{Addr: "9.9.9.9:1", Kind: CandidateHost}
	if err := broker.RelayCandidate(sess.Id, controller, cand); err != nil {
		t.Fatalf("RelayCandidate: %v", err)
	}
	// The candidate must arrive at the agent (the far side), not echo to the controller.
	got, ok := findMsg[CandidateMsg](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive relayed candidate")
	}
	if got.Candidate != cand || got.Session != sess.Id {
		t.Fatalf("relayed candidate mismatch: %+v", got)
	}

	// Unknown session is an error.
	if err := broker.RelayCandidate("no-such-session", controller, cand); err == nil {
		t.Fatal("expected error relaying candidate for unknown session")
	}
}

func TestBrokerRelaySdp(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatOpen, agentConn))

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	const sdpBody = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
	if err := broker.RelaySdp(sess.Id, controller, sdpBody, SdpOffer); err != nil {
		t.Fatalf("RelaySdp: %v", err)
	}

	// The SDP must arrive at the agent (the far side).
	got, ok := findMsg[SdpMsg](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive relayed SDP")
	}
	if got.Sdp != sdpBody {
		t.Fatalf("SDP body mismatch: got %q, want %q", got.Sdp, sdpBody)
	}
	if got.Kind != SdpOffer {
		t.Fatalf("SDP kind mismatch: got %q, want %q", got.Kind, SdpOffer)
	}
	if got.Session != sess.Id {
		t.Fatalf("SDP session mismatch: got %q, want %q", got.Session, sess.Id)
	}

	// Must NOT echo to the controller.
	if _, echoed := findMsg[SdpMsg](ctrlConn.messages()); echoed {
		t.Fatal("SDP must not echo back to the controller")
	}

	// Unknown session is an error.
	if err := broker.RelaySdp("no-such-session", controller, sdpBody, SdpOffer); err == nil {
		t.Fatal("expected error relaying SDP for unknown session")
	}
}

func TestRemovePeerSessionsCleansBothSides(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	connA := &fakeConn{}
	agentA := mkPeer("agent-a", "ed25519:a", NatFullCone, connA)
	reg.Register(agentA)

	connB := &fakeConn{}
	agentB := mkPeer("agent-b", "ed25519:b", NatFullCone, connB)
	reg.Register(agentB)

	// Session 1: agentA is Target, agentB is Requester.
	sess1, err := broker.ConnectRequest(agentB, "agent-a", nil)
	if err != nil {
		t.Fatalf("ConnectRequest sess1: %v", err)
	}

	// Session 2: agentA is Requester, agentB is Target.
	sess2, err := broker.ConnectRequest(agentA, "agent-b", nil)
	if err != nil {
		t.Fatalf("ConnectRequest sess2: %v", err)
	}

	broker.RemovePeerSessions(agentA)

	cand := Candidate{Addr: "1.2.3.4:5", Kind: CandidateHost}
	if err := broker.RelayCandidate(sess1.Id, agentB, cand); err == nil {
		t.Fatal("expected error for sess1 after RemovePeerSessions, got nil")
	}
	if err := broker.RelayCandidate(sess2.Id, agentA, cand); err == nil {
		t.Fatal("expected error for sess2 after RemovePeerSessions, got nil")
	}
}

func TestRemovePeerSessionsNilIsNoop(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn))

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	// Must not panic.
	broker.RemovePeerSessions(nil)

	cand := Candidate{Addr: "1.2.3.4:5", Kind: CandidateHost}
	if err := broker.RelayCandidate(sess.Id, controller, cand); err != nil {
		t.Fatalf("session unreachable after RemovePeerSessions(nil): %v", err)
	}
}

func TestBrokerConnectRequestRejectsSelf(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	conn := &fakeConn{}
	peer := mkPeer("self-dev", "ed25519:self", NatFullCone, conn)
	reg.Register(peer)

	_, err := broker.ConnectRequest(peer, "self-dev", nil)
	if err == nil {
		t.Fatal("expected error when connecting to self")
	}
	if _, ok := findMsg[Rejected](conn.messages()); !ok {
		t.Fatal("peer should have received Rejected when connecting to self")
	}
}

func TestRelayCandidateRejectsNonMemberSender(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentAConn := &fakeConn{}
	reg.Register(mkPeer("agent-a", "ed25519:agent-a", NatOpen, agentAConn))

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-a", nil)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	agentBConn := &fakeConn{}
	agentB := mkPeer("agent-b", "ed25519:agent-b", NatOpen, agentBConn)
	reg.Register(agentB)

	cand := Candidate{Addr: "9.9.9.9:1", Kind: CandidateHost}
	if err := broker.RelayCandidate(sess.Id, agentB, cand); err == nil {
		t.Fatal("expected error when non-member sender relays a candidate")
	}
}

func TestRelaySdpRejectsNonMemberSender(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentAConn := &fakeConn{}
	reg.Register(mkPeer("agent-a", "ed25519:agent-a", NatOpen, agentAConn))

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	sess, err := broker.ConnectRequest(controller, "agent-a", nil)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	agentBConn := &fakeConn{}
	agentB := mkPeer("agent-b", "ed25519:agent-b", NatOpen, agentBConn)
	reg.Register(agentB)

	if err := broker.RelaySdp(sess.Id, agentB, "v=0", SdpOffer); err == nil {
		t.Fatal("expected error when non-member sender relays an SDP")
	}
}

// TestBrokerConnectRequestRejectsWhenAgentSendFails covers broker.go:205-214: the block that
// drops the session, notifies the requester, and returns an error when agent.Send(Brokered{})
// fails. fakeConn.WriteJSON always returns nil, so without errConn this path has zero coverage.
func TestBrokerConnectRequestRejectsWhenAgentSendFails(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	// Agent's connection always rejects writes; Send(Brokered{}) will fail.
	agentConn := &errConn{}
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn))

	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}

	// (1) ConnectRequest must return a non-nil error.
	_, err := broker.ConnectRequest(controller, "agent-dev", nil)
	if err == nil {
		t.Fatal("expected ConnectRequest to return an error when agent send fails")
	}

	// (2) The controller must receive Rejected with the exact reason string from broker.go:213.
	rejected, ok := findMsg[Rejected](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive Rejected after agent send failure")
	}
	if rejected.Reason != "peer became unreachable" {
		t.Fatalf("Rejected.Reason = %q, want %q", rejected.Reason, "peer became unreachable")
	}

	// (3) The session must have been dropped (broker.go:212 dropSession). The session id is
	// recovered from the IceServers message the controller received — it is sent before the
	// Brokered attempt, so the controller holds it even on the failure path.
	ice, ok := findMsg[IceServers](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive IceServers; cannot verify session was dropped")
	}
	// Critically: use the AGENT as `from`, not the controller. If the session was leaked
	// (dropSession removed by a mutation), the relay routes to the controller's fakeConn whose
	// WriteJSON returns nil — RelayCandidate succeeds and the assertion catches the mutation.
	// Using the controller as sender routes to errConn regardless of session state, masking
	// the dropSession mutation because errConn.WriteJSON always returns a non-nil error.
	agentPeer, _ := reg.Lookup("agent-dev")
	cand := Candidate{Addr: "1.2.3.4:5", Kind: CandidateHost}
	if err := broker.RelayCandidate(ice.Session, agentPeer, cand); err == nil {
		t.Fatal("RelayCandidate succeeded on a session that should have been dropped")
	}
}

// TestBrokerConnectRequestDropsSessionWhenRequesterSendFails covers broker.go:216-224: the block
// that drops the session and returns an error when requester.Send(Brokered{}) fails. The agent
// uses a fakeConn so agent.Send succeeds and the session is registered; the requester uses errConn
// so the requester-notify branch fails. A mutation removing dropSession on broker.go:223 leaks the
// session; RelayCandidate on a leaked session would succeed via the agent's fakeConn (nil write),
// and this test detects that by asserting RelayCandidate must return an error.
func TestBrokerConnectRequestDropsSessionWhenRequesterSendFails(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	// Agent uses fakeConn so agent.Send(Brokered{}) succeeds; the session is created and the
	// Brokered payload (with session ID) lands in agentConn before the requester path runs.
	agentConn := &fakeConn{}
	agentPeer := mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn)
	reg.Register(agentPeer)

	// Requester uses errConn so requester.Send(Brokered{}) fails at broker.go:216.
	requesterConn := &errConn{}
	requester := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: requesterConn}

	// (1) ConnectRequest must return a non-nil error.
	_, err := broker.ConnectRequest(requester, "agent-dev", nil)
	if err == nil {
		t.Fatal("expected ConnectRequest to return an error when requester send fails")
	}

	// (2) The session must have been dropped (broker.go:223 dropSession). Recover the session ID
	// from the Brokered message the agent received — it arrives before the requester branch runs.
	brokered, ok := findMsg[Brokered](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive Brokered; cannot verify session was dropped")
	}
	// Send from the requester so the relay would route the candidate to the agent (fakeConn).
	// If the session was leaked by a dropSession mutation, routing to the agent's fakeConn returns
	// nil — RelayCandidate succeeds — and this assertion catches it.
	// Sending from the agent instead would route to the requester's errConn, which always errors
	// regardless of session state, masking the mutation.
	cand := Candidate{Addr: "1.2.3.4:5", Kind: CandidateHost}
	if err := broker.RelayCandidate(brokered.Session, requester, cand); err == nil {
		t.Fatal("RelayCandidate succeeded on a session that should have been dropped")
	}
}

// TestConnectRequest_RejectsBusySingleSessionAgent verifies that a second ConnectRequest to a
// single-session-only agent (MultiSessionCapable == nil or false) is rejected atomically once
// the first session is active, and that the requester receives a Rejected message explaining why.
//
// The fix (broker.go) performs the admission check INSIDE the b.mu.Lock() critical section that
// also inserts the session, so two concurrent requests cannot both see 0 existing sessions and
// both proceed past the gate — eliminating the TOCTOU window that existed in any check-before-lock
// approach.
func TestConnectRequest_RejectsBusySingleSessionAgent(t *testing.T) {
	reg := NewRegistry(time.Minute)
	// Dev mode (nil ticketPub): no ticket required, any client may broker.
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	agent := mkPeer("agent-dev", "ed25519:agent", NatFullCone, agentConn)
	// MultiSessionCapable is nil by default in mkPeer — single-session-only.
	reg.Register(agent)

	ctrl1Conn := &fakeConn{}
	ctrl1 := &Peer{DeviceId: "ctrl-1", Pubkey: "ed25519:ctrl1", conn: ctrl1Conn}

	ctrl2Conn := &fakeConn{}
	ctrl2 := &Peer{DeviceId: "ctrl-2", Pubkey: "ed25519:ctrl2", conn: ctrl2Conn}

	// First request: must succeed — no existing session.
	if _, err := broker.ConnectRequest(ctrl1, "agent-dev", nil); err != nil {
		t.Fatalf("first ConnectRequest: %v", err)
	}

	// Second request: must be rejected because agent is single-session and already has 1 session.
	_, err := broker.ConnectRequest(ctrl2, "agent-dev", nil)
	if err == nil {
		t.Fatal("second ConnectRequest to a busy single-session agent must return an error")
	}

	// The second requester must have received a Rejected message.
	rejected, ok := findMsg[Rejected](ctrl2Conn.messages())
	if !ok {
		t.Fatal("second controller did not receive Rejected")
	}
	const wantSubstr = "single-session agent already has an active session"
	if !strings.Contains(rejected.Reason, wantSubstr) {
		t.Fatalf("Rejected.Reason = %q, want it to contain %q", rejected.Reason, wantSubstr)
	}

	// The broker must still have exactly ONE session for this device (not two).
	broker.mu.Lock()
	count := len(broker.deviceSessions["agent-dev"])
	broker.mu.Unlock()
	if count != 1 {
		t.Fatalf("deviceSessions[agent-dev] has %d entries after rejection, want 1", count)
	}
}

// TestConnectRequest_AllowsMultiSessionAgent verifies that two concurrent ConnectRequests to the
// same agent BOTH succeed when the agent declared MultiSessionCapable = true.
func TestConnectRequest_AllowsMultiSessionAgent(t *testing.T) {
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)

	agentConn := &fakeConn{}
	agent := mkPeer("ms-agent", "ed25519:agent", NatFullCone, agentConn)
	// Mark the agent as multi-session-capable.
	multiTrue := true
	agent.MultiSessionCapable = &multiTrue
	reg.Register(agent)

	ctrl1Conn := &fakeConn{}
	ctrl1 := &Peer{DeviceId: "ctrl-1", Pubkey: "ed25519:ctrl1", conn: ctrl1Conn}

	ctrl2Conn := &fakeConn{}
	ctrl2 := &Peer{DeviceId: "ctrl-2", Pubkey: "ed25519:ctrl2", conn: ctrl2Conn}

	sess1, err := broker.ConnectRequest(ctrl1, "ms-agent", nil)
	if err != nil {
		t.Fatalf("first ConnectRequest to multi-session agent: %v", err)
	}
	sess2, err := broker.ConnectRequest(ctrl2, "ms-agent", nil)
	if err != nil {
		t.Fatalf("second ConnectRequest to multi-session agent: %v", err)
	}

	if sess1.Id == sess2.Id {
		t.Fatalf("both sessions got the same ID %q — must be distinct", sess1.Id)
	}

	// Both sessions must appear in deviceSessions.
	broker.mu.Lock()
	count := len(broker.deviceSessions["ms-agent"])
	broker.mu.Unlock()
	if count != 2 {
		t.Fatalf("deviceSessions[ms-agent] has %d entries, want 2", count)
	}

	// Neither controller should have received a Rejected.
	if _, ok := findMsg[Rejected](ctrl1Conn.messages()); ok {
		t.Fatal("ctrl1 unexpectedly received Rejected for a multi-session-capable agent")
	}
	if _, ok := findMsg[Rejected](ctrl2Conn.messages()); ok {
		t.Fatal("ctrl2 unexpectedly received Rejected for a multi-session-capable agent")
	}
}
