package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// =====================================================================================
// GOLDEN CROSS-MODULE VECTOR (M2) — the proof this port and control-plane/ticket.go build the
// SAME canonical bytes. The identical fixture (and expected hex) lives in
// control-plane/ticket_test.go; if either module's encoder drifts, its golden test fails.
// DO NOT change a value here without changing it identically there.
// =====================================================================================

const (
	ticketGoldenSeedHex   = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	ticketGoldenPubkeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"

	ticketGoldenPreimageHex = "524d545449434b4554763100010000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000002431313131313131312d313131312d313131312d313131312d3131313131313131313131310000000d74656e616e742d676f6c64656e0000002433333333333333332d333333332d333333332d333333332d33333333333333333333333300000192cc09140000000192cc0ae8c0"
	ticketGoldenSigHex      = "b9a0410a9c14acba175a98d04a9a482bde5f08c682b17b708c08268e9eb17df25b691924e587403a69d180afcb2d90d4463e0097ed60c46e970c74d65aa78a06"
)

func ticketGoldenClaims() TicketClaims {
	return TicketClaims{
		V:            1,
		SessionID:    "22222222-2222-2222-2222-222222222222",
		TechnicianID: "11111111-1111-1111-1111-111111111111",
		TenantID:     "tenant-golden",
		DeviceID:     "33333333-3333-3333-3333-333333333333",
		IssuedAtMs:   1730000000000,
		ExpiresAtMs:  1730000120000,
	}
}

// mintTicket signs claims with the golden issuer key, exactly as the control plane's
// MintSessionTicket does — the test-side stand-in for a real POST /sessions.
func mintTicket(t *testing.T, claims TicketClaims) *SignedSessionTicket {
	t.Helper()
	seed, err := hex.DecodeString(ticketGoldenSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, ticketSigningBytes(claims))
	return &SignedSessionTicket{Claims: claims, Sig: hex.EncodeToString(sig)}
}

func ticketGoldenPubkey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, err := hex.DecodeString(ticketGoldenPubkeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	return ed25519.PublicKey(pub)
}

func TestTicketGoldenVectorMatchesControlPlane(t *testing.T) {
	claims := ticketGoldenClaims()
	if got := hex.EncodeToString(ticketSigningBytes(claims)); got != ticketGoldenPreimageHex {
		t.Fatalf("canonical preimage drift vs control-plane/ticket.go:\n got  %s\n want %s",
			got, ticketGoldenPreimageHex)
	}
	signed := mintTicket(t, claims)
	if signed.Sig != ticketGoldenSigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", signed.Sig, ticketGoldenSigHex)
	}
	if err := verifyTicket(ticketGoldenPubkey(t), signed, claims.IssuedAtMs, claims.DeviceID); err != nil {
		t.Fatalf("golden ticket rejected: %v", err)
	}
}

func TestVerifyTicketChecks(t *testing.T) {
	pub := ticketGoldenPubkey(t)
	good := ticketGoldenClaims()
	now := good.IssuedAtMs

	tests := []struct {
		name    string
		ticket  *SignedSessionTicket
		nowMs   int64
		target  string
		wantErr bool
	}{
		{"valid", mintTicket(t, good), now, good.DeviceID, false},
		{"missing", nil, now, good.DeviceID, true},
		{"expired", mintTicket(t, good), good.ExpiresAtMs + 1, good.DeviceID, true},
		{"at expiry still valid", mintTicket(t, good), good.ExpiresAtMs, good.DeviceID, false},
		{"wrong device", mintTicket(t, good), now, "some-other-device", true},
		{"garbage sig", &SignedSessionTicket{Claims: good, Sig: "not-hex"}, now, good.DeviceID, true},
		{"wrong-key sig", func() *SignedSessionTicket {
			s := mintTicket(t, good)
			s.Sig = s.Sig[2:] + s.Sig[:2] // valid hex, wrong bytes
			return s
		}(), now, good.DeviceID, true},
		{"tampered claims", func() *SignedSessionTicket {
			s := mintTicket(t, good)
			s.Claims.DeviceID = "some-other-device" // resign nothing: signature no longer covers claims
			return s
		}(), now, "some-other-device", true},
		{"unsupported version", func() *SignedSessionTicket {
			c := good
			c.V = 3
			return mintTicket(t, c)
		}(), now, good.DeviceID, true},
		// A ticket with no tenant binding is unusable: the tenant claim is what stops a ticket
		// minted elsewhere from authorizing this device.
		{"no tenant binding", func() *SignedSessionTicket {
			c := good
			c.TenantID = ""
			return mintTicket(t, c)
		}(), now, good.DeviceID, true},
		// A ticket must name the session it was minted for, or it cannot be made single-use.
		{"no session id", func() *SignedSessionTicket {
			c := good
			c.SessionID = ""
			return mintTicket(t, c)
		}(), now, good.DeviceID, true},
		// A ticket with no technician id would attribute the session audit trail to nobody.
		{"no technician id", func() *SignedSessionTicket {
			c := good
			c.TechnicianID = ""
			return mintTicket(t, c)
		}(), now, good.DeviceID, true},
		// An issuance timestamp far in this server's future would stretch the ticket's effective
		// window, since exp_ms is derived from it.
		{"issued beyond the skew allowance", mintTicket(t, good), good.IssuedAtMs - ticketMaxClockSkewMs - 1, good.DeviceID, true},
		{"issued within the skew allowance", mintTicket(t, good), good.IssuedAtMs - ticketMaxClockSkewMs, good.DeviceID, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyTicket(pub, tt.ticket, tt.nowMs, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyTicket = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ticketBroker builds a broker enforcing tickets against the golden pubkey, with a registered
// agent that declares NO tenant (the pre-M2 registration shape), a controller, and the clock
// pinned to the golden iat.
func ticketBroker(t *testing.T, agentDevice string) (*Broker, *Peer, *fakeConn) {
	t.Helper()
	return ticketBrokerTenant(t, agentDevice, "")
}

// ticketBrokerTenant is ticketBroker with the registered agent declaring agentTenant.
func ticketBrokerTenant(t *testing.T, agentDevice, agentTenant string) (*Broker, *Peer, *fakeConn) {
	t.Helper()
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", ticketGoldenPubkey(t))
	broker.nowMs = func() int64 { return ticketGoldenClaims().IssuedAtMs }
	agent := mkPeer(agentDevice, "ed25519:agent", NatOpen, &fakeConn{})
	agent.Tenant = agentTenant
	reg.Register(agent)
	ctrlConn := &fakeConn{}
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: ctrlConn}
	return broker, controller, ctrlConn
}

func TestBrokerConnectRequestWithValidTicketBrokers(t *testing.T) {
	claims := ticketGoldenClaims()
	broker, controller, ctrlConn := ticketBroker(t, claims.DeviceID)

	sess, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims))
	if err != nil {
		t.Fatalf("ConnectRequest with valid ticket: %v", err)
	}
	if sess == nil || sess.Id == "" {
		t.Fatal("expected a brokered session")
	}
	if _, ok := findMsg[Brokered](ctrlConn.messages()); !ok {
		t.Fatal("controller did not receive brokered")
	}
}

func TestBrokerConnectRequestTicketRejections(t *testing.T) {
	claims := ticketGoldenClaims()
	expired := claims
	expired.ExpiresAtMs = claims.IssuedAtMs - 1
	wrongDevice := claims
	wrongDevice.DeviceID = "44444444-4444-4444-4444-444444444444"

	tests := []struct {
		name   string
		ticket *SignedSessionTicket
	}{
		{"missing ticket", nil},
		{"expired ticket", mintTicket(t, expired)},
		{"ticket for another device", mintTicket(t, wrongDevice)},
		{"garbage signature", &SignedSessionTicket{Claims: claims, Sig: "zz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broker, controller, ctrlConn := ticketBroker(t, claims.DeviceID)
			if _, err := broker.ConnectRequest(controller, claims.DeviceID, tt.ticket); err == nil {
				t.Fatal("expected ConnectRequest to fail")
			}
			// The requester sees only the GENERIC rejection — no oracle about which check failed
			// — and is never brokered.
			rej, ok := findMsg[Rejected](ctrlConn.messages())
			if !ok {
				t.Fatal("controller should have received rejected")
			}
			if rej.Reason != "connect request not authorized" {
				t.Fatalf("rejection reason %q leaks the failing check", rej.Reason)
			}
			if _, ok := findMsg[Brokered](ctrlConn.messages()); ok {
				t.Fatal("rejected controller must not be brokered")
			}
		})
	}
}

// A ticket minted in ANOTHER tenant must not broker to an agent that declared its own tenant,
// even when the device id matches — the cross-tenant remote-control path.
func TestBrokerRejectsTicketFromAnotherTenant(t *testing.T) {
	claims := ticketGoldenClaims() // tenant "tenant-golden"
	broker, controller, ctrlConn := ticketBrokerTenant(t, claims.DeviceID, "tenant-victim")

	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err == nil {
		t.Fatal("a ticket minted in a different tenant must not broker")
	}
	rej, ok := findMsg[Rejected](ctrlConn.messages())
	if !ok {
		t.Fatal("controller should have received rejected")
	}
	if rej.Reason != "connect request not authorized" {
		t.Fatalf("rejection reason %q leaks the failing check", rej.Reason)
	}
	if _, ok := findMsg[Brokered](ctrlConn.messages()); ok {
		t.Fatal("cross-tenant requester must not be brokered")
	}
	// …and the agent itself was never told about the attempt.
	agent, _ := broker.reg.Lookup(claims.DeviceID)
	if _, ok := findMsg[Brokered](agent.conn.(*fakeConn).messages()); ok {
		t.Fatal("target agent must not be brokered to a cross-tenant requester")
	}
}

// The matching tenant brokers normally; an agent that declared no tenant still brokers (the
// pre-M2 registration shape), so the tenant cross-check never breaks an existing agent.
func TestBrokerTicketTenantMatching(t *testing.T) {
	claims := ticketGoldenClaims()
	for name, agentTenant := range map[string]string{
		"declared tenant matches":  claims.TenantID,
		"agent declares no tenant": "",
	} {
		t.Run(name, func(t *testing.T) {
			broker, controller, ctrlConn := ticketBrokerTenant(t, claims.DeviceID, agentTenant)
			if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
				t.Fatalf("ConnectRequest: %v", err)
			}
			if _, ok := findMsg[Brokered](ctrlConn.messages()); !ok {
				t.Fatal("controller did not receive brokered")
			}
		})
	}
}

// A ticket is single-use, not a bearer credential replayable for its whole TTL: the second
// connect_request presenting the same ticket is refused with the generic reason even though the
// signature is still valid and the ticket is not yet expired.
func TestBrokerRejectsReusedTicket(t *testing.T) {
	claims := ticketGoldenClaims()
	broker, controller, ctrlConn := ticketBroker(t, claims.DeviceID)

	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("first use: %v", err)
	}

	replayConn := &fakeConn{}
	replayer := &Peer{DeviceId: "thief", Pubkey: "ed25519:thief", conn: replayConn}
	if _, err := broker.ConnectRequest(replayer, claims.DeviceID, mintTicket(t, claims)); err == nil {
		t.Fatal("a spent ticket must not broker a second session")
	}
	rej, ok := findMsg[Rejected](replayConn.messages())
	if !ok {
		t.Fatal("replayer should have received rejected")
	}
	if rej.Reason != "connect request not authorized" {
		t.Fatalf("rejection reason %q leaks the failing check", rej.Reason)
	}
	if _, ok := findMsg[Brokered](replayConn.messages()); ok {
		t.Fatal("a spent ticket must not broker")
	}
	// The first, legitimate use was still brokered.
	if _, ok := findMsg[Brokered](ctrlConn.messages()); !ok {
		t.Fatal("the first use of the ticket should have brokered")
	}
}

// A ticket that never brokered anything is not burned: a rejected attempt (offline agent) leaves
// the technician's ticket usable once the agent comes back.
func TestBrokerDoesNotSpendTicketOnFailedBroker(t *testing.T) {
	claims := ticketGoldenClaims()
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", ticketGoldenPubkey(t))
	broker.nowMs = func() int64 { return claims.IssuedAtMs }
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: &fakeConn{}}

	// Agent offline: rejected before the commit point.
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err == nil {
		t.Fatal("expected the offline agent to be rejected")
	}
	// Agent comes online; the same ticket still works.
	reg.Register(mkPeer(claims.DeviceID, "ed25519:agent", NatOpen, &fakeConn{}))
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("ticket was burned by a rejected attempt: %v", err)
	}
}

// Spent entries do not accumulate past the tickets' own expiry — verifyTicket refuses them from
// then on, so remembering them would be pure leak.
func TestSpentTicketsPrunesExpiredEntries(t *testing.T) {
	s := newSpentTickets()
	if !s.consume("sess-1", 1_000, 500) {
		t.Fatal("first use should be accepted")
	}
	if s.consume("sess-1", 1_000, 500) {
		t.Fatal("second use should be refused")
	}
	if !s.consume("sess-2", 2_000, 1_001) {
		t.Fatal("an unspent session id should be accepted")
	}
	if len(s.spent) != 1 {
		t.Fatalf("spent set holds %d entries, want 1 after pruning the expired one", len(s.spent))
	}
}

func TestBrokerWithoutTicketPubkeyStillBrokers(t *testing.T) {
	// Dev mode (SIGNALING_TICKET_PUBKEY unset → nil pubkey): a ticketless connect_request still
	// brokers, preserving every existing local/e2e flow.
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil)
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatOpen, &fakeConn{}))
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: &fakeConn{}}

	if _, err := broker.ConnectRequest(controller, "agent-dev", nil); err != nil {
		t.Fatalf("dev-mode ConnectRequest without ticket: %v", err)
	}
}

func TestConnectRequestTicketRoundTripsJSON(t *testing.T) {
	// The optional wire field decodes back into the envelope (backward-compatible: absent →
	// nil, present → the same claims + sig).
	msg := ClientToServer{Payload: ConnectRequest{
		Target: "dev-x",
		Ticket: mintTicket(t, ticketGoldenClaims()),
	}}
	raw, err := msg.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ClientToServer
	if err := decoded.UnmarshalJSON(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cr, ok := decoded.Payload.(*ConnectRequest)
	if !ok {
		t.Fatalf("payload = %T", decoded.Payload)
	}
	if cr.Ticket == nil || cr.Ticket.Sig != ticketGoldenSigHex || cr.Ticket.Claims != ticketGoldenClaims() {
		t.Fatalf("ticket did not round-trip: %+v", cr.Ticket)
	}

	var legacy ClientToServer
	if err := legacy.UnmarshalJSON([]byte(`{"type":"connect_request","target":"dev-x"}`)); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if legacy.Payload.(*ConnectRequest).Ticket != nil {
		t.Fatal("ticketless connect_request must decode with a nil ticket")
	}
}
