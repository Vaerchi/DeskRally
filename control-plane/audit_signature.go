package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

func agentAuditSigningBytes(hash string) []byte {
	return append([]byte("RMT-AUDIT-SIGN-v1\x00"), []byte(hash)...)
}

func validAgentAuditSignature(e AuditEvent, pinnedKey string) bool {
	pub, err := hex.DecodeString(pinnedKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || e.AgentPubkey != pinnedKey {
		return false
	}
	sig, err := hex.DecodeString(e.AgentSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, agentAuditSigningBytes(e.Hash), sig)
}

func (s *Server) verifyAgentAudit(ctx context.Context, tenantID, sessionID string, events []AuditEvent) error {
	keys := make(map[string]string)
	for _, e := range events {
		if !s.RequireAgentAuditSignatures && e.AgentSignature == "" {
			continue
		}
		key, ok := keys[e.MachineID]
		if !ok {
			if s.Machines == nil {
				return errors.New("machine key store unavailable")
			}
			machine, err := s.Machines.GetMachineByID(ctx, tenantID, e.MachineID)
			if errors.Is(err, ErrMachineNotFound) {
				machine, err = s.Machines.GetMachine(ctx, tenantID, e.MachineID)
			}
			if err == nil && machine != nil {
				key = machine.Pubkey
			} else if errors.Is(err, ErrMachineNotFound) && s.Attended != nil {
				// Redemption snapshots the ephemeral key before cleanup deletes the machine.
				att, aerr := s.Attended.Get(ctx, tenantID, sessionID)
				if aerr == nil && att.DeviceID == e.MachineID {
					key = att.AgentPubkey
				}
			}
			if key == "" {
				return errors.New("no pinned agent key")
			}
			keys[e.MachineID] = key
		}
		if !validAgentAuditSignature(e, key) {
			return errors.New("invalid agent signature")
		}
	}
	return nil
}
