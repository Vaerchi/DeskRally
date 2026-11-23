package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

type nameClaims struct {
	V            int    `json:"v"`
	SessionID    string `json:"session_id"`
	TechnicianID string `json:"technician_id"`
	DisplayName  string `json:"display_name"`
	ExpiresAtMs  int64  `json:"exp_ms"`
}

type nameAttestation struct {
	Claims nameClaims `json:"claims"`
	Sig    string     `json:"sig"`
}

// Keep this preimage in sync with control-plane/name_attestation.go.
func nameSigningBytes(c nameClaims) []byte {
	buf := append([]byte("RMTNAMEv1\x00\x00\x00"), byte(c.V))
	lp := func(s string) {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
		buf = append(buf, s...)
	}
	lp(c.SessionID)
	lp(c.TechnicianID)
	lp(c.DisplayName)
	return binary.BigEndian.AppendUint64(buf, uint64(c.ExpiresAtMs))
}

// verifiedDisplayName runs only for a verified ticket. Failure is advisory.
func verifiedDisplayName(pub ed25519.PublicKey, raw json.RawMessage, ticket TicketClaims, nowMs int64) string {
	var attestation nameAttestation
	if len(raw) == 0 || !utf8.Valid(raw) || json.Unmarshal(raw, &attestation) != nil {
		return ""
	}
	c := attestation.Claims
	if c.V != 1 || c.SessionID != ticket.SessionID || c.TechnicianID != ticket.TechnicianID ||
		c.ExpiresAtMs != ticket.ExpiresAtMs || nowMs > c.ExpiresAtMs ||
		c.DisplayName == "" || len(c.DisplayName) > 128 || strings.ContainsFunc(c.DisplayName, unicode.IsControl) {
		return ""
	}
	sig, err := hex.DecodeString(attestation.Sig)
	if err != nil || !ed25519.Verify(pub, nameSigningBytes(c), sig) {
		return ""
	}
	return c.DisplayName
}
