package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// Fixed control-plane layout: unchanged domain, version 2, original fields,
// then u32be(9) and the UTF-8 bytes of view_only.
const observerGoldenPreimageHex = "524d545449434b4554763100020000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000002431313131313131312d313131312d313131312d313131312d3131313131313131313131310000000d74656e616e742d676f6c64656e0000002433333333333333332d333333332d333333332d333333332d33333333333333333333333300000192cc09140000000192cc0ae8c000000009766965775f6f6e6c79"

func TestObserverControlPlaneGoldenVector(t *testing.T) {
	claims := ticketGoldenClaims()
	claims.V, claims.Access = 2, "view_only"
	preimage, err := hex.DecodeString(observerGoldenPreimageHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ticketSigningBytes(claims), preimage) {
		t.Fatalf("V2 preimage drift: got %x, want %x", ticketSigningBytes(claims), preimage)
	}
	seed, err := hex.DecodeString(ticketGoldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	// Sign the independent literal, not the signaling encoder's output.
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), preimage)
	ticket := &SignedSessionTicket{Claims: claims, Sig: hex.EncodeToString(sig)}
	if err := verifyTicket(ticketGoldenPubkey(t), ticket, claims.IssuedAtMs, claims.DeviceID); err != nil {
		t.Fatal(err)
	}
	ticket.Claims.Access = "control"
	if err := verifyTicket(ticketGoldenPubkey(t), ticket, claims.IssuedAtMs, claims.DeviceID); !errors.Is(err, errTicketInvalid) {
		t.Fatalf("tampered access accepted: %v", err)
	}
	// Changing only the signed version and access to a valid V1 pair must
	// still fail: V2 cannot be downgraded without a new signature.
	ticket.Claims.V, ticket.Claims.Access = 1, ""
	if err := verifyTicket(ticketGoldenPubkey(t), ticket, claims.IssuedAtMs, claims.DeviceID); !errors.Is(err, errTicketInvalid) {
		t.Fatalf("downgraded ticket accepted: %v", err)
	}
}

func TestObserverVersionAccessPairs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v      int
		access string
		valid  bool
	}{
		{"legacy", 1, "", true},
		{"observer", 2, "view_only", true},
		{"v2 control", 2, "control", false},
		{"v2 missing", 2, "", false},
		{"v2 unknown", 2, "unknown", false},
		{"v1 observer", 1, "view_only", false},
		{"v1 control", 1, "control", false},
		{"unknown version", 3, "view_only", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := ticketGoldenClaims()
			claims.V, claims.Access = tc.v, tc.access
			err := verifyTicket(ticketGoldenPubkey(t), mintTicket(t, claims), claims.IssuedAtMs, claims.DeviceID)
			if (err == nil) != tc.valid {
				t.Fatalf("verifyTicket = %v, valid = %v", err, tc.valid)
			}
		})
	}
	// Every spelling encoding/json would decode into Access counts as present (Codex signaling review v1).
	for _, field := range []string{`"access":""`, `"access":null`, `"Access":""`, `"ACCESS":null`, `"aCcEsS":""`} {
		value := field
		ticket := mintTicket(t, ticketGoldenClaims())
		raw, err := json.Marshal(ticket)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.Replace(raw, []byte(`"claims":{`), []byte(`"claims":{`+field+`,`), 1)
		var decoded SignedSessionTicket
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := verifyTicket(ticketGoldenPubkey(t), &decoded, decoded.Claims.IssuedAtMs, decoded.Claims.DeviceID); !errors.Is(err, errTicketInvalid) {
			t.Fatalf("V1 explicit access %s accepted: %v", value, err)
		}
	}
}

func TestObserverBrokeredAndParticipants(t *testing.T) {
	for _, mode := range []string{"control", "view_only", "dev", "dev unverified observer"} {
		t.Run(mode, func(t *testing.T) {
			claims := ticketGoldenClaims()
			if mode == "view_only" || mode == "dev unverified observer" {
				claims.V, claims.Access = 2, "view_only"
			}
			broker, controller, ctrlConn := ticketBrokerTenant(t, claims.DeviceID, claims.TenantID)
			ticket := mintTicket(t, claims)
			wantAccess, wantTechnician := "control", claims.TechnicianID
			if mode == "view_only" {
				wantAccess = "view_only"
			}
			if mode == "dev" || mode == "dev unverified observer" {
				broker.ticketPub = nil
				wantTechnician = ""
				if mode == "dev" {
					ticket = nil
				}
			}
			agent, ok := broker.reg.Lookup(claims.DeviceID)
			if !ok {
				t.Fatal("agent missing")
			}
			sess, err := broker.ConnectRequest(controller, claims.DeviceID, ticket)
			if err != nil {
				t.Fatal(err)
			}
			for name, conn := range map[string]*fakeConn{"agent": agent.conn.(*fakeConn), "controller": ctrlConn} {
				got, ok := findMsg[Brokered](conn.messages())
				if !ok {
					t.Fatalf("%s missing brokered", name)
				}
				if got.Access != wantAccess || got.AccessVersion != 1 || got.TechnicianID != wantTechnician {
					t.Fatalf("%s brokered = %+v", name, got)
				}
				raw, err := (ServerToClient{Payload: got}).MarshalJSON()
				if err != nil {
					t.Fatal(err)
				}
				var wire struct {
					Access  string `json:"access"`
					Version int    `json:"access_version"`
				}
				if err := json.Unmarshal(raw, &wire); err != nil {
					t.Fatal(err)
				}
				if wire.Access != wantAccess || wire.Version != 1 {
					t.Fatalf("invalid wire metadata: %s", raw)
				}
				participants, ok := findMsg[SessionParticipants](conn.messages())
				if !ok || len(participants.Participants) != 1 {
					t.Fatalf("%s participants = %+v", name, participants)
				}
				entry := participants.Participants[0]
				if entry.SessionID != sess.Id || entry.TechnicianID != wantTechnician || entry.Access != wantAccess {
					t.Fatalf("%s participant = %+v", name, entry)
				}
			}
		})
	}
}
