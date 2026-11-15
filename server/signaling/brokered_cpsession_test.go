package main

// Loop 86: `brokered` carries the CONTROL-PLANE session id from the verified ticket.
//
// WHY THIS HOP EXISTS. The agent had no way to learn its own control-plane session id — the ticket
// goes controller→signaling, and the policy goes control-plane→viewer→agent. So `SessionPolicy::verify`
// could not compare the policy's `session_id` against anything, and a `control` policy captured in one
// session was replayable into a later one at the same machine for its whole TTL. That was harmless
// only while every `control` policy named an EPHEMERAL attended device; migration 0037 ended that, and
// this field is what replaces the containment.
//
// SIGNALING IS THE RIGHT SOURCE because it is the only party that has proven the id: verifyTicket
// checked the control plane's signature over the claims, the device binding, the expiry and a
// non-empty session id, and ConnectRequest then burned the ticket single-use both locally and in the
// control plane's shared ledger. The agent already relies on signaling to broker only ticket-bearing
// controllers, so this is not a new trust relationship.

import (
	"strings"
	"testing"
	"time"
)

// The headline: BOTH peers learn the ticket's control-plane session id, and it is NOT the broker's own
// session id. Conflating the two would look correct in every log while binding the agent's policy check
// to a value the control plane never signed.
func TestBrokeredCarriesTheVerifiedTicketsControlPlaneSession(t *testing.T) {
	claims := ticketGoldenClaims()
	broker, controller, ctrlConn := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
	agent, ok := broker.reg.Lookup(claims.DeviceID)
	if !ok {
		t.Fatal("premise not met: the agent is not registered")
	}
	agentConn := agent.conn.(*fakeConn)

	sess, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims))
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	agentBrokered, ok := findMsg[Brokered](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive brokered")
	}
	if agentBrokered.ControlPlaneSession != claims.SessionID {
		t.Fatalf("agent brokered control_plane_session = %q, want the ticket's %q — the agent cannot "+
			"bind a session policy without it", agentBrokered.ControlPlaneSession, claims.SessionID)
	}
	// The two ids are DIFFERENT values with different meanings. If this ever fails as "equal", the
	// broker is echoing its own id and the binding is against a number the control plane never signed.
	if agentBrokered.ControlPlaneSession == agentBrokered.Session {
		t.Fatalf("the control-plane session id equals the broker's own session id (%q) — these are "+
			"different identifiers and the policy binds to the control plane's", agentBrokered.Session)
	}
	if agentBrokered.Session != sess.Id {
		t.Fatalf("agent brokered session = %q, want the broker's %q", agentBrokered.Session, sess.Id)
	}

	// The requester supplied the ticket, so telling it back discloses nothing it did not already hold.
	ctrlBrokered, ok := findMsg[Brokered](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive brokered")
	}
	if ctrlBrokered.ControlPlaneSession != claims.SessionID {
		t.Fatalf("controller brokered control_plane_session = %q, want %q",
			ctrlBrokered.ControlPlaneSession, claims.SessionID)
	}
}

// A server that verifies NO tickets must advertise NOTHING, even when a ticket happens to be supplied.
//
// This is the security-relevant half. With `-insecure-no-ticket-verification` an inbound ticket is
// unverified attacker input: echoing its session id would let a caller NAME the session the agent binds
// its policy to, which is precisely the substitution the binding exists to prevent. Empty is the
// fail-closed answer — the agent reads a missing id as "unknown" and rejects every policy.
func TestBrokeredAdvertisesNoControlPlaneSessionWhenTicketsAreNotVerified(t *testing.T) {
	claims := ticketGoldenClaims()
	reg := NewRegistry(time.Minute)
	// nil pubkey = SIGNALING_TICKET_PUBKEY unset = dev mode.
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)
	agentConn := &fakeConn{}
	reg.Register(mkPeer(claims.DeviceID, "ed25519:agent", NatOpen, agentConn))
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: &fakeConn{}}

	// A ticket IS presented — and must still be ignored, because nothing verified it.
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("dev-mode ConnectRequest: %v", err)
	}
	got, ok := findMsg[Brokered](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive brokered")
	}
	if got.ControlPlaneSession != "" {
		t.Fatalf("a server that verifies no tickets advertised control_plane_session = %q — an "+
			"unverified claim must never become the id an agent binds its policy to", got.ControlPlaneSession)
	}

	// And the ticketless dev path must not panic on the nil ticket, which is the shape every existing
	// LAN/e2e flow uses.
	agentConn2 := &fakeConn{}
	reg2 := NewRegistry(time.Minute)
	broker2 := NewBroker(reg2, "ed25519:server", "relay-1:4444", nil)
	reg2.Register(mkPeer("agent-dev", "ed25519:agent", NatOpen, agentConn2))
	ctrl2 := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: &fakeConn{}}
	if _, err := broker2.ConnectRequest(ctrl2, "agent-dev", nil); err != nil {
		t.Fatalf("dev-mode ConnectRequest with a NIL ticket: %v", err)
	}
	if got, ok := findMsg[Brokered](agentConn2.messages()); !ok || got.ControlPlaneSession != "" {
		t.Fatalf("nil-ticket broker produced %+v", got)
	}
}

// The wire shape stays backward compatible: an empty control-plane session is OMITTED, so a
// pre-loop-86 peer sees byte-identical `brokered` JSON. (`brokered` is dropped WHOLESALE by the Rust
// client on a decode error, so its shape is load-bearing — see the peer_device scar in
// crates/protocol/src/signaling.rs.)
func TestBrokeredOmitsAnEmptyControlPlaneSession(t *testing.T) {
	raw, err := ServerToClient{Payload: &Brokered{
		Session: "s1", PeerDevice: "dev-1", PeerPubkey: "ed25519:peer",
	}}.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if containsKey(string(raw), "control_plane_session") {
		t.Fatalf("an empty control_plane_session was serialized: %s", raw)
	}
	withID, err := ServerToClient{Payload: &Brokered{
		Session: "s1", PeerDevice: "dev-1", PeerPubkey: "ed25519:peer",
		ControlPlaneSession: "22222222-2222-2222-2222-222222222222",
	}}.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal (2): %v", err)
	}
	if !containsKey(string(withID), "control_plane_session") {
		t.Fatalf("a present control_plane_session was NOT serialized: %s", withID)
	}
}

// containsKey reports whether the marshalled JSON declares `key` at all — the distinction
// `omitempty` turns on, which a value comparison against "" could not see.
func containsKey(s, key string) bool {
	return strings.Contains(s, `"`+key+`"`)
}
