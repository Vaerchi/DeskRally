package main

// Loop 91: `brokered` also carries the TECHNICIAN id from the verified ticket.
//
// WHY THIS HOP EXISTS, stated locally so it cannot drift. The agent seals its own audit events and
// stamps `technician_id` into the HASHED canonical preimage; `POST /audit/ingest` then answers 403
// unless that id equals the console user forwarding the batch (control-plane/audit.go, the loop-88
// hardening). So the agent has to learn who the technician is — and the two parties who could
// volunteer one are exactly the two that must not:
//
//   - the VIEWER, because a technician naming themselves is precisely the self-attribution the 403
//     exists to refuse, moved one hop upstream where the 403 cannot see it (the forwarder would be
//     the genuine caller, and the event would name someone else); and
//   - an UNVERIFIED ticket, because its claims are attacker-chosen.
//
// Signaling is the right source for the same reason it is the right source for the control-plane
// session id: it is the only party that has PROVEN the claim. verifyTicket checked the control
// plane's signature over the claims, the device binding and the expiry, and ConnectRequest burned
// the ticket single-use. `technician_id` was inside that signature from the start; loop 91 is the
// first thing to read it.

import (
	"testing"
	"time"
)

// devBrokerTenant is ticketBrokerTenant with NO ticket public key: the dev/LAN/e2e shape, where
// signaling verifies nothing and must therefore vouch for nothing.
func devBrokerTenant(t *testing.T, agentDevice, agentTenant string) (*Broker, *Peer, *fakeConn) {
	t.Helper()
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)
	broker.nowMs = func() int64 { return ticketGoldenClaims().IssuedAtMs }
	agent := mkPeer(agentDevice, "ed25519:agent", NatOpen, &fakeConn{})
	agent.Tenant = agentTenant
	reg.Register(agent)
	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}
	return broker, controller, ctrlConn
}

// The headline: both peers learn the ticket's technician id, and it is the id the control plane
// SIGNED — not the broker's own session id, and not empty.
func TestBrokeredCarriesTheVerifiedTicketsTechnician(t *testing.T) {
	claims := ticketGoldenClaims()
	broker, controller, ctrlConn := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
	agent, ok := broker.reg.Lookup(claims.DeviceID)
	if !ok {
		t.Fatal("premise not met: the agent is not registered")
	}
	agentConn := agent.conn.(*fakeConn)

	if claims.TechnicianID == "" {
		t.Fatal("premise not met: the golden claims carry no technician id")
	}

	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	agentBrokered, ok := findMsg[Brokered](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive brokered")
	}
	if agentBrokered.TechnicianID != claims.TechnicianID {
		t.Fatalf("agent brokered technician_id = %q, want the ticket's %q — without it the agent "+
			"seals its audit chain for nobody and the control plane refuses the batch",
			agentBrokered.TechnicianID, claims.TechnicianID)
	}
	// Distinct from every other id on the message. A broker echoing the wrong field would look
	// correct in a log and produce a chain attributed to a machine or a rendezvous.
	if agentBrokered.TechnicianID == agentBrokered.Session ||
		agentBrokered.TechnicianID == agentBrokered.ControlPlaneSession ||
		agentBrokered.TechnicianID == agentBrokered.PeerDevice {
		t.Fatalf("technician_id collides with another id on the message: %+v", agentBrokered)
	}

	// The requester supplied the ticket, so telling it back discloses nothing it did not hold.
	ctrlBrokered, ok := findMsg[Brokered](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive brokered")
	}
	if ctrlBrokered.TechnicianID != claims.TechnicianID {
		t.Fatalf("controller brokered technician_id = %q, want %q",
			ctrlBrokered.TechnicianID, claims.TechnicianID)
	}
}

// FAIL CLOSED. A server that verifies no tickets must advertise NO technician, even when a ticket is
// present on the wire — under `-insecure-no-ticket-verification` those claims are unverified
// attacker input, and advertising them would let a caller NAME the technician an agent attributes a
// whole session's audit trail to.
//
// The agent's reading of an empty value is deliberately fail-closed the useful way: it seals the
// chain with a nil technician, the control plane refuses that batch, and the session keeps only its
// local trail (helper log, recording sidecar) rather than gaining a central record naming nobody.
func TestBrokeredAdvertisesNoTechnicianWhenTicketsAreNotVerified(t *testing.T) {
	claims := ticketGoldenClaims()
	// A broker with NO ticket public key — the dev/LAN/e2e shape.
	broker, controller, ctrlConn := devBrokerTenant(t, claims.DeviceID, claims.TenantID)
	agent, ok := broker.reg.Lookup(claims.DeviceID)
	if !ok {
		t.Fatal("premise not met: the agent is not registered")
	}
	agentConn := agent.conn.(*fakeConn)

	// A ticket IS supplied, and it is a genuinely signed one. The point is that this server did not
	// verify it, so it must not vouch for anything in it.
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	agentBrokered, ok := findMsg[Brokered](agentConn.messages())
	if !ok {
		t.Fatal("agent did not receive brokered")
	}
	if agentBrokered.TechnicianID != "" {
		t.Fatalf("a server that verifies no tickets advertised technician_id %q — that value is "+
			"attacker-chosen and the agent would attribute its whole audit trail to it",
			agentBrokered.TechnicianID)
	}
	ctrlBrokered, ok := findMsg[Brokered](ctrlConn.messages())
	if !ok {
		t.Fatal("controller did not receive brokered")
	}
	if ctrlBrokered.TechnicianID != "" {
		t.Fatalf("controller brokered technician_id = %q, want empty", ctrlBrokered.TechnicianID)
	}

	// A nil ticket must not PANIC even when the admission gate rejects the request (the agent
	// is single-session and already has one active session after the first ConnectRequest above).
	// We only verify that the call returns without panicking; an error is expected and acceptable.
	_, _ = broker.ConnectRequest(controller, claims.DeviceID, nil)
}

// `omitempty`: an empty technician is ABSENT from the wire, so a server that vouches for none emits
// the pre-loop-91 shape byte-for-byte and an older agent decodes it unchanged.
func TestBrokeredOmitsAnEmptyTechnician(t *testing.T) {
	absent, err := ServerToClient{Payload: &Brokered{
		Session: "s1", PeerDevice: "dev-1", PeerPubkey: "ed25519:peer",
	}}.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if containsKey(string(absent), "technician_id") {
		t.Fatalf("an empty technician_id was serialized: %s", absent)
	}
	present, err := ServerToClient{Payload: &Brokered{
		Session: "s1", PeerDevice: "dev-1", PeerPubkey: "ed25519:peer",
		TechnicianID: "22222222-2222-2222-2222-222222222222",
	}}.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal (2): %v", err)
	}
	if !containsKey(string(present), "technician_id") {
		t.Fatalf("a present technician_id was NOT serialized: %s", present)
	}
}

// A signed ticket with an EMPTY technician claim must be REFUSED at verification, not brokered.
//
// `technician_id` has been inside the signed preimage since the ticket existed, but nothing ever
// checked it was non-empty — the sibling checks on `session_id` and `tenant_id` were there and this
// one was not. Before loop 91 that was inert, because nothing read the field. Now it decides who a
// session's entire audit trail is attributed to, so a control plane that minted an empty one would
// produce a ticket that verified cleanly and then yielded a chain naming nobody. Refusing it here
// puts the failure at the seam that can explain it, instead of at ingest time as a bare 403.
func TestVerifyTicketRefusesAnEmptyTechnicianClaim(t *testing.T) {
	claims := ticketGoldenClaims()

	// Negative control FIRST: the unmodified claims verify. Without this leg a verifier that
	// refused everything would satisfy the assertion below.
	broker, controller, _ := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("premise not met: the unmodified golden ticket was refused: %v", err)
	}

	// The measurement: same claims, technician cleared, RE-SIGNED so the signature is valid. This
	// must be refused on the empty claim, not because the signature stopped matching.
	empty := claims
	empty.TechnicianID = ""
	broker2, controller2, _ := ticketBrokerTenant(t, empty.DeviceID, empty.TenantID)
	_, err := broker2.ConnectRequest(controller2, empty.DeviceID, mintTicket(t, empty))
	if err == nil {
		t.Fatal("a signed ticket with an empty technician claim was accepted; the session's whole " +
			"audit trail would be attributed to nobody")
	}
}
