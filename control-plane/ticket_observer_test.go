package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestObserverTicketLayoutsAndSignatures(t *testing.T) {
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	// Independently pinned pre-change layout: domain, version, four u32be
	// length-prefixed strings, then two i64be timestamps. No access suffix.
	const legacyHex = "524d545449434b4554763100010000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000002431313131313131312d313131312d313131312d313131312d3131313131313131313131310000000d74656e616e742d676f6c64656e0000002433333333333333332d333333332d333333332d333333332d33333333333333333333333300000192cc09140000000192cc0ae8c0"
	legacy, err := hex.DecodeString(legacyHex)
	if err != nil {
		t.Fatal(err)
	}
	control := iss.MintSessionTicket(goldenSessionID, goldenTechnicianID,
		goldenTicketTenantID, goldenMachineID, goldenIssuedAtMs, goldenTicketExpiresAtMs)
	if control.Claims.V != 1 || control.Claims.Access != "" {
		t.Fatalf("legacy claims changed: %+v", control.Claims)
	}
	if got := ticketSigningBytes(control.Claims); !bytes.Equal(got, legacy) {
		t.Fatalf("v1 preimage changed:\n got %x\nwant %x", got, legacy)
	}
	wire, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Claims map[string]json.RawMessage `json:"claims"`
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, present := envelope.Claims["access"]; present {
		t.Fatalf("legacy wire acquired access: %s", wire)
	}

	observer := iss.MintObserverSessionTicket(goldenSessionID, goldenTechnicianID,
		goldenTicketTenantID, goldenMachineID, goldenIssuedAtMs, goldenTicketExpiresAtMs)
	if observer.Claims.V != 2 || observer.Claims.Access != "view_only" {
		t.Fatalf("observer claims: %+v", observer.Claims)
	}
	// V2 retains the domain and v1 body, changes the signed version byte,
	// and appends u32be(9) followed by the nine UTF-8 bytes of view_only.
	wantObserver := append([]byte(nil), legacy...)
	wantObserver[12] = 2
	wantObserver = append(wantObserver, 0, 0, 0, 9)
	wantObserver = append(wantObserver, []byte("view_only")...)
	if got := ticketSigningBytes(observer.Claims); !bytes.Equal(got, wantObserver) {
		t.Fatalf("v2 preimage:\n got %x\nwant %x", got, wantObserver)
	}
	pub := iss.priv.Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name     string
		ticket   SignedSessionTicket
		preimage []byte
	}{
		{"control", control, legacy},
		{"observer", observer, wantObserver},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := hex.DecodeString(tc.ticket.Sig)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(pub, tc.preimage, sig) {
				t.Fatal("signature does not verify over independently constructed preimage")
			}
		})
	}
	changed := observer.Claims
	changed.Access = "control"
	sig, err := hex.DecodeString(observer.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, ticketSigningBytes(changed), sig) {
		t.Fatal("observer signature permits changing access")
	}
}
