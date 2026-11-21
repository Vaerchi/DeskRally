package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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

// Keep this preimage in sync with server/signaling/name_attestation.go.
func nameSigningBytes(c nameClaims) []byte {
	var w canonicalWriter
	w.buf = append(w.buf, "RMTNAMEv1\x00\x00\x00"...)
	w.u8(byte(c.V))
	w.lpStr(c.SessionID)
	w.lpStr(c.TechnicianID)
	w.lpStr(c.DisplayName)
	w.i64(c.ExpiresAtMs)
	return w.buf
}

func sanitizeDisplayName(name string) string {
	var out strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) {
			continue
		}
		if out.Len()+utf8.RuneLen(r) > 128 {
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}

func (gi *GrantIssuer) mintNameAttestation(ticket TicketClaims, displayName string) *nameAttestation {
	name := sanitizeDisplayName(displayName)
	if name == "" {
		return nil
	}
	claims := nameClaims{
		V: 1, SessionID: ticket.SessionID, TechnicianID: ticket.TechnicianID,
		DisplayName: name, ExpiresAtMs: ticket.ExpiresAtMs,
	}
	sig := ed25519.Sign(gi.priv, nameSigningBytes(claims))
	return &nameAttestation{Claims: claims, Sig: hex.EncodeToString(sig)}
}

func (s *Server) sessionNameAttestation(ctx context.Context, ticket TicketClaims) *nameAttestation {
	users := s.transferUsers()
	if users == nil {
		return nil
	}
	if names, ok := users.(interface {
		findUserDisplayName(context.Context, string, string) (string, error)
	}); ok {
		name, err := names.findUserDisplayName(ctx, ticket.TenantID, ticket.TechnicianID)
		if err != nil {
			return nil
		}
		return s.Grants.mintNameAttestation(ticket, name)
	}
	user, err := users.FindUserByID(ctx, ticket.TenantID, ticket.TechnicianID)
	if err != nil || user == nil {
		return nil
	}
	return s.Grants.mintNameAttestation(ticket, user.DisplayName)
}
