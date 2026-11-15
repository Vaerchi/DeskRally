package controlplane

// Session-ticket canonicalization + POST /sessions handler tests (M2).
//
// The golden fixture here is duplicated in server/signaling/ticket_test.go — the two modules keep
// independent copies of the canonical encoder, and these constants are the tripwire: if either
// side's encoder drifts, its golden hex stops matching. DO NOT change a value here without
// changing it identically there.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

// Golden session-ticket fixture (same issuer seed as the grant golden vector).
//
//	seed:          goldenSeedHex (pubkey goldenPubkeyHex)
//	session_id:    22222222-2222-2222-2222-222222222222
//	technician_id: 11111111-1111-1111-1111-111111111111
//	tenant_id:     tenant-golden
//	device_id:     33333333-3333-3333-3333-333333333333
//	iat_ms:        1730000000000
//	exp_ms:        1730000120000
const (
	goldenTicketTenantID    = "tenant-golden"
	goldenTicketExpiresAtMs = int64(1730000120000)

	goldenTicketPreimageHex = "524d545449434b4554763100010000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000002431313131313131312d313131312d313131312d313131312d3131313131313131313131310000000d74656e616e742d676f6c64656e0000002433333333333333332d333333332d333333332d333333332d33333333333333333333333300000192cc09140000000192cc0ae8c0"
	goldenTicketSigHex      = "b9a0410a9c14acba175a98d04a9a482bde5f08c682b17b708c08268e9eb17df25b691924e587403a69d180afcb2d90d4463e0097ed60c46e970c74d65aa78a06"
)

func goldenTicketClaims() TicketClaims {
	return TicketClaims{
		V:            1,
		SessionID:    goldenSessionID,
		TechnicianID: goldenTechnicianID,
		TenantID:     goldenTicketTenantID,
		DeviceID:     goldenMachineID,
		IssuedAtMs:   goldenIssuedAtMs,
		ExpiresAtMs:  goldenTicketExpiresAtMs,
	}
}

func TestTicketGoldenVectorV1(t *testing.T) {
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	msg := ticketSigningBytes(goldenTicketClaims())
	if got := hex.EncodeToString(msg); got != goldenTicketPreimageHex {
		t.Fatalf("ticket canonical preimage drift:\n got  %s\n want %s", got, goldenTicketPreimageHex)
	}
	signed := iss.MintSessionTicket(goldenSessionID, goldenTechnicianID, goldenTicketTenantID,
		goldenMachineID, goldenIssuedAtMs, goldenTicketExpiresAtMs)
	if signed.Sig != goldenTicketSigHex {
		t.Fatalf("ticket signature drift:\n got  %s\n want %s", signed.Sig, goldenTicketSigHex)
	}
	if !verifyGolden(t, msg, signed.Sig) {
		t.Fatal("golden ticket does not verify against the issuer public key")
	}
}

func TestTicketDomainTagDistinctFromGrant(t *testing.T) {
	// Domain separation is the whole point: the ticket tag must differ from the grant tag (and
	// keep the 12-byte parallel), so no ticket preimage can collide with a grant preimage.
	want := []byte{0x52, 0x4d, 0x54, 0x54, 0x49, 0x43, 0x4b, 0x45, 0x54, 0x76, 0x31, 0x00}
	if !bytes.Equal(ticketDomainTag, want) {
		t.Fatalf("ticket domain tag = % x, want % x", ticketDomainTag, want)
	}
	if bytes.Equal(ticketDomainTag, grantDomainTag) {
		t.Fatal("ticket domain tag must differ from the grant domain tag")
	}
}

// TestStartSessionReturnsVerifiableTicket: POST /sessions with an issuer wired returns the
// "signaling" envelope whose ticket verifies against the issuer pubkey and is bound to the
// session's device + record.
func TestStartSessionReturnsVerifiableTicket(t *testing.T) {
	p := &Principal{
		UserID:   techUserUUID,
		TenantID: "tenant-123",
		Grant:    NewGrant(techUserUUID, "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv.Grants = iss
	srv.SignalingURL = "ws://signal.example:8080/ws"

	if code := apiJSON(t, srv, "POST", "/enroll", `{"machine_id":"dev-1","group_id":"g1"}`, nil); code != http.StatusCreated {
		t.Fatalf("enroll = %d", code)
	}
	var started struct {
		Session   SessionRecord `json:"session"`
		Signaling struct {
			URL       string              `json:"url"`
			DeviceID  string              `json:"device_id"`
			SessionID string              `json:"session_id"`
			Ticket    SignedSessionTicket `json:"ticket"`
		} `json:"signaling"`
	}
	if code := apiJSON(t, srv, "POST", "/sessions", `{"machine_id":"dev-1"}`, &started); code != http.StatusCreated {
		t.Fatalf("start session = %d", code)
	}

	sig := started.Signaling
	if sig.URL != "ws://signal.example:8080/ws" {
		t.Fatalf("signaling url = %q", sig.URL)
	}
	if sig.DeviceID != "dev-1" || sig.SessionID != started.Session.ID {
		t.Fatalf("signaling coords = %+v (session %s)", sig, started.Session.ID)
	}

	c := sig.Ticket.Claims
	if c.V != 1 || c.SessionID != started.Session.ID || c.TechnicianID != techUserUUID ||
		c.TenantID != "tenant-123" || c.DeviceID != "dev-1" {
		t.Fatalf("ticket claims = %+v", c)
	}
	if c.ExpiresAtMs-c.IssuedAtMs != sessionTicketTTL.Milliseconds() {
		t.Fatalf("ticket TTL = %dms, want %dms", c.ExpiresAtMs-c.IssuedAtMs, sessionTicketTTL.Milliseconds())
	}
	now := time.Now().UnixMilli()
	if c.IssuedAtMs > now+1000 || c.ExpiresAtMs < now {
		t.Fatalf("ticket window [%d,%d] not current (now %d)", c.IssuedAtMs, c.ExpiresAtMs, now)
	}
	// The ticket must verify against the issuer's public key over the canonical bytes.
	pub, _ := hex.DecodeString(iss.PublicKeyHex())
	sigBytes, err := hex.DecodeString(sig.Ticket.Sig)
	if err != nil {
		t.Fatalf("decode ticket sig: %v", err)
	}
	if !ed25519.Verify(pub, ticketSigningBytes(c), sigBytes) {
		t.Fatal("session ticket does not verify against the issuer public key")
	}
}

// TestStartSessionDefaultsSignalingURL: with no configured URL the default dev rendezvous is
// returned; with no issuer wired the response carries no signaling envelope at all.
func TestStartSessionSignalingWiring(t *testing.T) {
	p := &Principal{
		UserID:   techUserUUID,
		TenantID: "tenant-123",
		Grant:    NewGrant(techUserUUID, "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}

	srv, _ := newTestServer(p)
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv.Grants = iss
	var withDefault struct {
		Signaling *struct {
			URL string `json:"url"`
		} `json:"signaling"`
	}
	if code := apiJSON(t, srv, "POST", "/sessions", `{"machine_id":"dev-1"}`, &withDefault); code != http.StatusCreated {
		t.Fatalf("start session = %d", code)
	}
	if withDefault.Signaling == nil || withDefault.Signaling.URL != DefaultSignalingURL {
		t.Fatalf("signaling = %+v, want default url %s", withDefault.Signaling, DefaultSignalingURL)
	}

	// No issuer → no signaling envelope (the record alone, as before M2).
	bare, _ := newTestServer(p)
	var noIssuer struct {
		Signaling *struct{} `json:"signaling"`
	}
	if code := apiJSON(t, bare, "POST", "/sessions", `{"machine_id":"dev-1"}`, &noIssuer); code != http.StatusCreated {
		t.Fatalf("start session (no issuer) = %d", code)
	}
	if noIssuer.Signaling != nil {
		t.Fatal("response without an issuer must not carry a signaling envelope")
	}
}
