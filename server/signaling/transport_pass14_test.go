package main

// Pass 14: Signaling broker ticket admission gate — fresh key material.
//
// The golden-vector tests in ticket_test.go prove the canonical preimage is byte-identical
// to control-plane/ticket.go's. This file proves that the BROKER-LEVEL ADMISSION GATE works
// end-to-end with a FRESHLY GENERATED Ed25519 key pair — not a precomputed fixture — so
// the gate cannot have been hard-coded against a known vector.
//
// Six cases:
//
//   TestPass14_Signaling_ValidTicketBrokers
//     A valid ticket signed by the fresh key → broker accepts, both peers receive brokered.
//
//   TestPass14_Signaling_TamperedClaimRejected
//     Ticket whose session_id has been changed AFTER signing → broker rejects (bad signature).
//
//   TestPass14_Signaling_AbsentTicketRejected
//     connect_request with no ticket on a ticket-enforcing broker → broker rejects.
//
//   TestPass14_Signaling_WrongDeviceRejected
//     Ticket bound to device-B is presented for device-A → broker rejects (device binding).
//
//   TestPass14_Signaling_ReplayedTicketRejected
//     Same valid ticket presented a second time → broker rejects (single-use ledger).
//
//   TestPass14_Signaling_ABTicketsAreIndependent
//     Ticket minted for session-A cannot be used to broker session-B, and vice versa.

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// ─── harness ──────────────────────────────────────────────────────────────────

// p14Issuer is a freshly generated Ed25519 key pair. Each test that calls
// newP14Issuer gets its own key so tests cannot share state via a package global.
type p14Issuer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newP14Issuer(t *testing.T) *p14Issuer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return &p14Issuer{pub: pub, priv: priv}
}

// mint signs claims with the fresh issuer key and returns a SignedSessionTicket.
func (k *p14Issuer) mint(claims TicketClaims) *SignedSessionTicket {
	sig := ed25519.Sign(k.priv, ticketSigningBytes(claims))
	return &SignedSessionTicket{Claims: claims, Sig: hex.EncodeToString(sig)}
}

// freshClaims returns a ticket claims struct whose timestamps are valid at nowMs.
func freshClaims(sessionID, technicianID, tenantID, deviceID string, nowMs int64) TicketClaims {
	return TicketClaims{
		V:            1,
		SessionID:    sessionID,
		TechnicianID: technicianID,
		TenantID:     tenantID,
		DeviceID:     deviceID,
		IssuedAtMs:   nowMs,
		ExpiresAtMs:  nowMs + 120_000, // 2 minutes — matches CP sessionTicketTTL
	}
}

// p14Broker builds a Broker that enforces tickets against key.pub, with two registered
// agents (deviceA and deviceB under the same tenant). The broker's clock is pinned to
// nowMs so freshClaims-minted tickets are not expired. Returns the broker and two fake
// controller peers (one per agent) so callers can call ConnectRequest.
func p14Broker(t *testing.T, key *p14Issuer, deviceA, deviceB, tenant string, nowMs int64) (
	broker *Broker,
	ctrlA *Peer, connA *fakeConn,
	ctrlB *Peer, connB *fakeConn,
) {
	t.Helper()
	reg := NewRegistry(time.Minute)
	broker = NewBroker(reg, "ed25519:srv", "relay:4444", key.pub)
	broker.nowMs = func() int64 { return nowMs }

	agentA := mkPeer(deviceA, "ed25519:agentA", NatOpen, &fakeConn{})
	agentA.Tenant = tenant
	reg.Register(agentA)

	agentB := mkPeer(deviceB, "ed25519:agentB", NatOpen, &fakeConn{})
	agentB.Tenant = tenant
	reg.Register(agentB)

	connA = &fakeConn{}
	ctrlA = &Peer{DeviceId: "ctrl-a", Pubkey: "ed25519:ctrlA", conn: connA}

	connB = &fakeConn{}
	ctrlB = &Peer{DeviceId: "ctrl-b", Pubkey: "ed25519:ctrlB", conn: connB}
	return
}

// ─── test fixtures ─────────────────────────────────────────────────────────────

const (
	p14DeviceA    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	p14DeviceB    = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	p14SessionA   = "11111111-1111-1111-1111-111111111111"
	p14SessionB   = "22222222-2222-2222-2222-222222222222"
	p14TechA      = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"
	p14TechB      = "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2"
	p14TenantPass = "pass14-tenant"
)

// p14NowMs is a fixed reference time (well in the past is fine — ticket validation uses
// the broker's pinned clock, not wall clock, so it never expires in tests).
const p14NowMs = int64(1_750_000_000_000)

// ─── tests ────────────────────────────────────────────────────────────────────

// TestPass14_Signaling_ValidTicketBrokers proves that a ticket signed by the fresh
// issuer key is accepted by the broker and causes both peers to receive brokered.
func TestPass14_Signaling_ValidTicketBrokers(t *testing.T) {
	key := newP14Issuer(t)
	broker, ctrlA, connA, _, _ := p14Broker(t, key, p14DeviceA, p14DeviceB, p14TenantPass, p14NowMs)

	claims := freshClaims(p14SessionA, p14TechA, p14TenantPass, p14DeviceA, p14NowMs)
	ticket := key.mint(claims)

	sess, err := broker.ConnectRequest(ctrlA, p14DeviceA, ticket)
	if err != nil {
		t.Fatalf("ConnectRequest with fresh valid ticket: %v", err)
	}
	if sess == nil || sess.Id == "" {
		t.Fatal("expected a brokered session")
	}
	if _, ok := findMsg[Brokered](connA.messages()); !ok {
		t.Fatal("controller did not receive brokered after valid ticket admission")
	}
}

// TestPass14_Signaling_TamperedClaimRejected proves that modifying a ticket claim
// AFTER signing causes the Ed25519 check to fail, so the broker refuses the request.
func TestPass14_Signaling_TamperedClaimRejected(t *testing.T) {
	key := newP14Issuer(t)
	broker, ctrlA, connA, _, _ := p14Broker(t, key, p14DeviceA, p14DeviceB, p14TenantPass, p14NowMs)

	claims := freshClaims(p14SessionA, p14TechA, p14TenantPass, p14DeviceA, p14NowMs)
	ticket := key.mint(claims)

	// Tamper the session_id after signing — the signature now covers the original preimage.
	ticket.Claims.SessionID = p14SessionB

	if _, err := broker.ConnectRequest(ctrlA, p14DeviceA, ticket); err == nil {
		t.Fatal("ConnectRequest with tampered session_id succeeded — signature is not checked")
	}
	if _, ok := findMsg[Brokered](connA.messages()); ok {
		t.Fatal("brokered was sent despite a tampered ticket")
	}
}

// TestPass14_Signaling_AbsentTicketRejected proves that a connect_request with NO
// ticket is refused when the broker enforces ticket verification.
func TestPass14_Signaling_AbsentTicketRejected(t *testing.T) {
	key := newP14Issuer(t)
	broker, ctrlA, connA, _, _ := p14Broker(t, key, p14DeviceA, p14DeviceB, p14TenantPass, p14NowMs)

	if _, err := broker.ConnectRequest(ctrlA, p14DeviceA, nil); err == nil {
		t.Fatal("ConnectRequest with nil ticket succeeded on a ticket-enforcing broker")
	}
	if _, ok := findMsg[Brokered](connA.messages()); ok {
		t.Fatal("brokered was sent without any ticket")
	}
}

// TestPass14_Signaling_WrongDeviceRejected proves that a ticket bound to device-B
// cannot be used to connect to device-A — the broker's device-binding check fires.
func TestPass14_Signaling_WrongDeviceRejected(t *testing.T) {
	key := newP14Issuer(t)
	broker, ctrlA, connA, _, _ := p14Broker(t, key, p14DeviceA, p14DeviceB, p14TenantPass, p14NowMs)

	// Ticket is signed for device-B.
	claims := freshClaims(p14SessionA, p14TechA, p14TenantPass, p14DeviceB, p14NowMs)
	ticket := key.mint(claims)

	// Presented for device-A.
	if _, err := broker.ConnectRequest(ctrlA, p14DeviceA, ticket); err == nil {
		t.Fatal("device-B ticket accepted for device-A — device binding not checked")
	}
	if _, ok := findMsg[Brokered](connA.messages()); ok {
		t.Fatal("brokered sent for wrong-device ticket")
	}
}

// TestPass14_Signaling_ReplayedTicketRejected proves that presenting the same valid
// ticket a second time is refused by the single-use ledger (spentTickets).
func TestPass14_Signaling_ReplayedTicketRejected(t *testing.T) {
	key := newP14Issuer(t)
	// Use a single broker for both uses — the local spentTickets map covers this.
	broker, ctrlA, connA, ctrlB, connB := p14Broker(t, key, p14DeviceA, p14DeviceB, p14TenantPass, p14NowMs)

	claims := freshClaims(p14SessionA, p14TechA, p14TenantPass, p14DeviceA, p14NowMs)
	ticket := key.mint(claims)

	// First use: must succeed.
	if _, err := broker.ConnectRequest(ctrlA, p14DeviceA, ticket); err != nil {
		t.Fatalf("first ConnectRequest: %v", err)
	}
	if _, ok := findMsg[Brokered](connA.messages()); !ok {
		t.Fatal("first use: controller did not receive brokered")
	}

	// Second use of the SAME ticket by a different controller: must be refused.
	if _, err := broker.ConnectRequest(ctrlB, p14DeviceA, ticket); err == nil {
		t.Fatal("second use of the same ticket succeeded — single-use ledger not enforced")
	}
	if _, ok := findMsg[Brokered](connB.messages()); ok {
		t.Fatal("brokered sent on ticket replay")
	}
}

// TestPass14_Signaling_ABTicketsAreIndependent proves that ticket-A (signed for
// session-A on device-A by technician-A) cannot be used to broker session-B on
// device-B, and vice versa. Cross-session ticket reuse is closed by the device
// binding plus the distinct per-session preimage.
func TestPass14_Signaling_ABTicketsAreIndependent(t *testing.T) {
	key := newP14Issuer(t)
	broker, ctrlA, connA, ctrlB, connB := p14Broker(t, key, p14DeviceA, p14DeviceB, p14TenantPass, p14NowMs)

	ticketA := key.mint(freshClaims(p14SessionA, p14TechA, p14TenantPass, p14DeviceA, p14NowMs))
	ticketB := key.mint(freshClaims(p14SessionB, p14TechB, p14TenantPass, p14DeviceB, p14NowMs))

	// Ticket-A for device-B must be rejected (device binding mismatch).
	if _, err := broker.ConnectRequest(ctrlA, p14DeviceB, ticketA); err == nil {
		t.Fatal("ticket-A accepted for device-B — cross-device ticket reuse succeeded")
	}
	if _, ok := findMsg[Brokered](connA.messages()); ok {
		t.Fatal("brokered sent for cross-device ticket-A on device-B")
	}

	// Ticket-B for device-A must be rejected (device binding mismatch).
	if _, err := broker.ConnectRequest(ctrlB, p14DeviceA, ticketB); err == nil {
		t.Fatal("ticket-B accepted for device-A — cross-device ticket reuse succeeded")
	}
	if _, ok := findMsg[Brokered](connB.messages()); ok {
		t.Fatal("brokered sent for cross-device ticket-B on device-A")
	}

	// Each ticket does work for its own device.
	if _, err := broker.ConnectRequest(ctrlA, p14DeviceA, ticketA); err != nil {
		t.Fatalf("ticket-A rejected for device-A: %v", err)
	}
	if _, ok := findMsg[Brokered](connA.messages()); !ok {
		t.Fatal("ticket-A: brokered not received for device-A")
	}
	if _, err := broker.ConnectRequest(ctrlB, p14DeviceB, ticketB); err != nil {
		t.Fatalf("ticket-B rejected for device-B: %v", err)
	}
	if _, ok := findMsg[Brokered](connB.messages()); !ok {
		t.Fatal("ticket-B: brokered not received for device-B")
	}
}
