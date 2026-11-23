package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
)

// MintObserverSessionTicket has no caller-controlled access argument: only observers use
// v2, and their mode must be covered by the signature before signaling brokers either peer.
func (gi *GrantIssuer) MintObserverSessionTicket(sessionID, technicianID, tenantID, deviceID string, issuedAtMs, expiresAtMs int64) SignedSessionTicket {
	claims := TicketClaims{
		V:            2,
		SessionID:    sessionID,
		TechnicianID: technicianID,
		TenantID:     tenantID,
		DeviceID:     deviceID,
		IssuedAtMs:   issuedAtMs,
		ExpiresAtMs:  expiresAtMs,
		Access:       "view_only",
	}
	sig := ed25519.Sign(gi.priv, ticketSigningBytes(claims))
	return SignedSessionTicket{Claims: claims, Sig: hex.EncodeToString(sig)}
}
