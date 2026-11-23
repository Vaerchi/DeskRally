package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// register_agent's optional `tenant` is what the broker cross-checks a session ticket against, so
// it must survive dispatch onto the registered Peer. Dev mode (nil resolver) only — in enforced
// mode the tenant comes from the control plane, not the wire (TestAgentAuthAdoptsControlPlaneIdentity).
func TestRegisterAgentRecordsTenant(t *testing.T) {
	srv, err := NewServer(time.Minute, "relay-1:4444", nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	self := &Peer{conn: &fakeConn{}}
	srv.dispatch(self, ClientToServer{Payload: &RegisterAgent{
		Device: "dev-1", Pubkey: "ed25519:agent", Tenant: "tenant-1", Nat: NatOpen,
	}})

	registered, ok := srv.reg.Lookup("dev-1")
	if !ok {
		t.Fatal("register_agent did not register the peer")
	}
	if registered.Tenant != "tenant-1" || registered.Pubkey != "ed25519:agent" {
		t.Fatalf("registered peer = %+v, want tenant-1 / ed25519:agent", registered)
	}

	// An agent that omits the field registers with no tenant (pre-M2 shape), which the broker
	// treats as "cannot be cross-checked" rather than "matches everything".
	other := &Peer{conn: &fakeConn{}}
	srv.dispatch(other, ClientToServer{Payload: &RegisterAgent{Device: "dev-2", Pubkey: "pk", Nat: NatOpen}})
	if got, _ := srv.reg.Lookup("dev-2"); got.Tenant != "" {
		t.Fatalf("tenantless registration recorded tenant %q", got.Tenant)
	}
}

func TestTicketPubkeyFromEnv(t *testing.T) {
	const validHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"

	t.Setenv("SIGNALING_TICKET_PUBKEY", "")
	pub, err := ticketPubkeyFromEnv()
	if pub != nil || err != nil {
		// Unset is reported as (nil, nil); main() is what turns that into a fatal startup error.
		t.Fatalf("unset = (%v, %v), want (nil, nil)", pub, err)
	}

	t.Setenv("SIGNALING_TICKET_PUBKEY", "  "+validHex+"  ")
	pub, err = ticketPubkeyFromEnv()
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("valid key = (%x, %v), want a 32-byte key", pub, err)
	}

	for _, bad := range []string{"not-hex", validHex + "ab", "abcd"} {
		t.Setenv("SIGNALING_TICKET_PUBKEY", bad)
		if _, err := ticketPubkeyFromEnv(); err == nil || !strings.Contains(err.Error(), "SIGNALING_TICKET_PUBKEY") {
			t.Fatalf("%q accepted (err %v), want a rejection", bad, err)
		}
	}
}

// The all-zeros placeholder must be REFUSED, not accepted as a key.
//
// deploy/.env.example ships 64 zeros and the runbook tells the operator to boot stage 1 with them,
// because the real value cannot be known until the control plane has run once — a genuine
// chicken-and-egg. The hazard is the operator who never comes back to replace it: all-zeros is a
// well-formed 32-byte value, so this used to be accepted, and it is a LOW-ORDER Ed25519 point, so
// signatures from anyone verify against it. Session tickets become universally forgeable and
// nothing looks wrong — signaling starts, agents register, sessions broker.
func TestTicketPubkeyRejectsTheAllZeroPlaceholder(t *testing.T) {
	t.Setenv("SIGNALING_TICKET_PUBKEY", strings.Repeat("0", 64))
	pub, err := ticketPubkeyFromEnv()
	if err == nil {
		t.Fatal("the all-zeros placeholder was ACCEPTED as a ticket issuer key — every session " +
			"ticket would be forgeable and the deployment would look healthy")
	}
	if pub != nil {
		t.Errorf("a rejected key must not also be returned, got %x", pub)
	}
	// The message has to tell the operator what to do; "invalid key" would send them to the wrong file.
	for _, want := range []string{"placeholder", "grant_issuer_pubkey"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q so the operator knows where the real value is: %v", want, err)
		}
	}
}

// Positive control. Without it, "reject everything" would pass the test above.
func TestTicketPubkeyAcceptsARealKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	t.Setenv("SIGNALING_TICKET_PUBKEY", hex.EncodeToString(pub))
	got, gerr := ticketPubkeyFromEnv()
	if gerr != nil {
		t.Fatalf("a real Ed25519 public key was rejected: %v", gerr)
	}
	if !bytes.Equal(got, pub) {
		t.Fatalf("returned key = %x, want %x", got, pub)
	}
}

// Unset stays nil-with-no-error — main() decides whether that is fatal, gated on the explicit
// -insecure-no-ticket-verification opt-out. Pinning it here so the new rejection cannot creep into
// breaking the documented dev path.
func TestTicketPubkeyUnsetIsNotAnError(t *testing.T) {
	t.Setenv("SIGNALING_TICKET_PUBKEY", "")
	pub, err := ticketPubkeyFromEnv()
	if err != nil || pub != nil {
		t.Fatalf("unset = (%x, %v), want (nil, nil)", pub, err)
	}
}
