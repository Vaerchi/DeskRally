package controlplane

// Session tickets (M2 / ADR-002 session brokering).
//
// POST /sessions now returns a short-TTL Ed25519-signed SESSION TICKET alongside the persisted
// session record. The ticket authorizes exactly one signaling rendezvous: the viewer presents it
// in `connect_request`, and the signaling server (server/signaling/ticket.go) verifies it against
// the control plane's grant-issuer public key before brokering the WebRTC session. Without it,
// any WS client could connect_request any agent.
//
// The signature covers a canonical v1 binary preimage (ticketSigningBytes) in the same
// domain-separated, big-endian, length-prefixed style as the backstage grant (grant.go) but under
// a DISTINCT domain tag ("RMTTICKETv1"), so a ticket can never verify as a grant or vice versa.
// server/signaling/ticket.go ports this canonicalization byte-for-byte — the golden-vector tests
// in BOTH modules pin the same fixture, so cross-module drift breaks tests loudly.

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"
)

// sessionTicketTTL is how long a minted session ticket stays valid. Deliberately short: it
// authorizes only the signaling rendezvous, which the viewer performs immediately after
// POST /sessions (mirrors backstageGrantTTL's rationale).
const sessionTicketTTL = 2 * time.Minute

// DefaultSignalingURL is the signaling WS endpoint returned by POST /sessions when
// Server.SignalingURL (env CP_SIGNALING_URL) is unset — the local dev/e2e rendezvous.
const DefaultSignalingURL = "ws://127.0.0.1:8080/ws"

// ticketDomainTag is the 12-byte canonical-v1 domain-separation tag for session tickets: ASCII
// "RMTTICKETv1" followed by one 0x00 byte. DISTINCT from grantDomainTag ("RMTGRANTv1\x00\x00"),
// so ticket and grant preimages can never be confused. Must equal the signaling server's copy.
var ticketDomainTag = []byte("RMTTICKETv1\x00")

// ticketVersion is the canonical claims version signed into the preimage (claims.v).
const ticketVersion = 1

// TicketClaims is the signed body of a session ticket. IDs are carried as length-prefixed UTF-8
// strings in the preimage (NOT raw UUID bytes like the grant) because tenant/device ids are not
// guaranteed to be canonical UUIDs.
type TicketClaims struct {
	V            int    `json:"v"`
	SessionID    string `json:"session_id"`
	TechnicianID string `json:"technician_id"`
	TenantID     string `json:"tenant_id"`
	DeviceID     string `json:"device_id"`
	IssuedAtMs   int64  `json:"iat_ms"`
	ExpiresAtMs  int64  `json:"exp_ms"`
	Access       string `json:"access,omitempty"`
}

// SignedSessionTicket mirrors SignedGrant's envelope: the claims plus a hex Ed25519 signature
// over their canonical v1 preimage. The JSON shape is what the signaling server deserializes.
type SignedSessionTicket struct {
	Claims TicketClaims `json:"claims"`
	Sig    string       `json:"sig"`
}

// ticketSigningBytes builds the canonical v1/v2 session-ticket preimage:
//
//	ticketDomainTag (the SAME bytes "RMTTICKETv1\x00" in both versions)
//	u8 claims.v (1 for legacy control; 2 for observers)
//	lpStr session_id | technician_id | tenant_id | device_id (u32be byte length + UTF-8 bytes)
//	i64 iat_ms | exp_ms (big-endian)
//	v2 ONLY: lpStr access (u32be byte length + UTF-8 bytes, "view_only")
//
// V1 has no suffix and remains byte-identical. V2 signs the version and appended access;
// retaining the domain tag follows the v1-layout-plus-access contract. Signaling MUST
// implement this exact layout and reject unsupported versions or invalid version/access pairs.
func ticketSigningBytes(c TicketClaims) []byte {
	var w canonicalWriter
	w.buf = append(w.buf, ticketDomainTag...)
	w.u8(byte(c.V))
	w.lpStr(c.SessionID)
	w.lpStr(c.TechnicianID)
	w.lpStr(c.TenantID)
	w.lpStr(c.DeviceID)
	w.i64(c.IssuedAtMs)
	w.i64(c.ExpiresAtMs)
	if c.V == 2 {
		w.lpStr(c.Access)
	}
	return w.buf
}

// MintSessionTicket signs a legacy v1 control ticket. Its signature and wire shape
// remain unchanged; observers use MintObserverSessionTicket. Times are Unix milliseconds.
func (gi *GrantIssuer) MintSessionTicket(sessionID, technicianID, tenantID, deviceID string, issuedAtMs, expiresAtMs int64) SignedSessionTicket {
	claims := TicketClaims{
		V:            ticketVersion,
		SessionID:    sessionID,
		TechnicianID: technicianID,
		TenantID:     tenantID,
		DeviceID:     deviceID,
		IssuedAtMs:   issuedAtMs,
		ExpiresAtMs:  expiresAtMs,
	}
	sig := ed25519.Sign(gi.priv, ticketSigningBytes(claims))
	return SignedSessionTicket{Claims: claims, Sig: hex.EncodeToString(sig)}
}
