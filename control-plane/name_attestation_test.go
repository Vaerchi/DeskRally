package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNameAttestationGoldenVector(t *testing.T) {
	raw, err := os.ReadFile("../docs/73-name-attestation-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Claims   nameClaims `json:"claims"`
		Preimage string     `json:"preimage_hex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	issuer, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	ticket := goldenTicketClaims()
	actual := issuer.mintNameAttestation(ticket, vector.Claims.DisplayName)
	preimage, err := hex.DecodeString(vector.Preimage)
	if err != nil {
		t.Fatal(err)
	}
	if actual == nil || actual.Claims != vector.Claims || !bytes.Equal(nameSigningBytes(actual.Claims), preimage) {
		t.Fatal("minted claims or canonical preimage drifted")
	}
	wantSig := ed25519.Sign(issuer.priv, preimage)
	if actual.Sig != hex.EncodeToString(wantSig) {
		t.Fatal("minted signature does not match the golden preimage")
	}
	pub := issuer.priv.Public().(ed25519.PublicKey)
	ticketSig, err := hex.DecodeString(goldenTicketSigHex)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, preimage, ticketSig) || ed25519.Verify(pub, ticketSigningBytes(ticket), wantSig) {
		t.Fatal("ticket and name signature domains overlap")
	}
}

func TestManagedSessionNameIssuance(t *testing.T) {
	issuer, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		label, access, displayName, want string
		version                          int
	}{
		{"control", "control", "Ada\t Lovelace", "Ada Lovelace", 1},
		{"observer", "view_only", "Grace", "Grace", 2},
		{"empty name", "control", "", "", 1},
		{"only control characters", "control", "\t\u0085", "", 1},
		{"truncate at rune boundary", "control", strings.Repeat("a", 127) + "é", strings.Repeat("a", 127), 1},
		{"keep a rune ending at the byte limit", "control", strings.Repeat("a", 126) + "é", strings.Repeat("a", 126) + "é", 1},
	} {
		t.Run(tc.label, func(t *testing.T) {
			c := goldenTicketClaims()
			users := NewInMemoryUserStore()
			users.AddUser(&AuthUser{ID: c.TechnicianID, TenantID: c.TenantID,
				DisplayName: tc.displayName, Email: "fallback@example.test"}, nil)
			srv := &Server{Grants: issuer, AuthAPI: &AuthService{Users: users}}
			rec := &SessionRecord{ID: c.SessionID, Access: tc.access}
			machine := &Machine{ID: c.DeviceID, DeviceID: c.DeviceID}
			out, refusal := srv.brokerSessionStart(context.Background(), rec, machine,
				c.TechnicianID, c.TenantID, GroupSessionPolicy{}, SessionBindingWarn, "")
			if refusal != nil {
				t.Fatal("managed session mint refused")
			}
			signaling := out["signaling"].(map[string]any)
			ticket := signaling["ticket"].(SignedSessionTicket)
			if ticket.Claims.V != tc.version {
				t.Fatalf("ticket version = %d, want %d", ticket.Claims.V, tc.version)
			}
			attestation, present := signaling["name_attestation"]
			if tc.want == "" {
				if present {
					t.Fatal("empty name must omit the attestation")
				}
				return
			}
			a, ok := attestation.(*nameAttestation)
			if !ok || a.Claims.DisplayName != tc.want || a.Claims.SessionID != ticket.Claims.SessionID ||
				a.Claims.TechnicianID != ticket.Claims.TechnicianID || a.Claims.ExpiresAtMs != ticket.Claims.ExpiresAtMs {
				t.Fatal("attestation does not match the display name and ticket")
			}
		})
	}
}
