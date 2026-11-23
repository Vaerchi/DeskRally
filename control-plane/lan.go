package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"
)

type LanEntry struct {
	MAC         string  `json:"mac"`
	IPv4Network string  `json:"ipv4_network"`
	GatewayMAC  *string `json:"gateway_mac"`
}

type LanOutcome string

const (
	LanApplied          LanOutcome = "applied"
	LanDuplicate        LanOutcome = "duplicate"
	LanDropped          LanOutcome = "dropped"
	LanStaleIncarnation LanOutcome = "stale_incarnation"
	LanSuperseded       LanOutcome = "superseded"
	LanNotEligible      LanOutcome = "not_eligible"
	LanStaleEpoch       LanOutcome = "stale_epoch"
	LanSeqReused        LanOutcome = "seq_reused"
	LanBadRequest       LanOutcome = "bad_request"
)

type LanStore interface {
	GetSignalingIncarnation(context.Context) (id *string, revision int64, err error)
	ActivateSignalingIncarnation(ctx context.Context, incarnation string, expectedRevision int64) (ok bool, revision int64, err error)
	AllocateLanEpoch(ctx context.Context, deviceID, devicePubKey, incarnation string, generation int64) (epoch int64, outcome LanOutcome, err error)
	IngestLanReport(ctx context.Context, deviceID, devicePubKey, incarnation string, generation, epoch, seq int64, digest []byte, entries []LanEntry) (LanOutcome, error)
	PurgeStaleLanFacts(ctx context.Context, olderThan time.Duration) (int64, error)
}

var errInvalidIncarnation = errors.New("invalid incarnation activation")

func validLanConnection(deviceID, incarnation string, generation int64) bool {
	return deviceID != "" && generation >= 0 && incarnation != ""
}

func validLanMAC(value string) bool {
	_, err := wakeMAC(value)
	return err == nil
}

func validLanReport(epoch, seq int64, digest []byte, entries []LanEntry) bool {
	if epoch < 0 || seq < 0 || len(digest) != sha256.Size || len(entries) > 4 {
		return false
	}
	seen := make(map[[2]string]bool, len(entries))
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry.IPv4Network)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 ||
			prefix.Masked().String() != entry.IPv4Network || !validLanMAC(entry.MAC) ||
			(entry.GatewayMAC != nil && !validLanMAC(*entry.GatewayMAC)) {
			return false
		}
		key := [2]string{entry.MAC, entry.IPv4Network}
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func matchesLanDeviceKey(stored, presented []byte) bool {
	return len(stored) == ed25519.PublicKeySize && bytes.Equal(stored, presented)
}

type lanWatermark struct {
	incarnation string
	generation  int64
	epoch       int64
	seq         int64
	digest      []byte
}

// allocate reports whether the updated watermark needs to be saved.
func (s *lanWatermark) allocate(incarnation string, generation int64) (bool, LanOutcome) {
	if s.incarnation == incarnation {
		if generation < s.generation {
			return false, LanSuperseded
		}
		if generation == s.generation {
			return false, ""
		}
	}
	s.epoch++
	s.incarnation, s.generation = incarnation, generation
	s.seq, s.digest = 0, nil
	return true, ""
}

func (s lanWatermark) report(incarnation string, generation, epoch, seq int64, digest []byte) LanOutcome {
	switch {
	case s.epoch != epoch || s.incarnation != incarnation || s.generation != generation:
		return LanStaleEpoch
	case seq < s.seq:
		return LanDropped
	case seq == s.seq && bytes.Equal(digest, s.digest):
		return LanDuplicate
	case seq == s.seq:
		return LanSeqReused
	default:
		return LanApplied
	}
}

type memoryLanState struct {
	lanWatermark
	entries    []LanEntry
	receivedAt time.Time
}

var _ LanStore = (*InMemoryMachineStore)(nil)

func (s *InMemoryMachineStore) GetSignalingIncarnation(context.Context) (*string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lanIncarnation == "" {
		return nil, s.lanRevision, nil
	}
	id := s.lanIncarnation
	return &id, s.lanRevision, nil
}

func (s *InMemoryMachineStore) ActivateSignalingIncarnation(_ context.Context, incarnation string, expectedRevision int64) (bool, int64, error) {
	id, ok := parsePgUUID(incarnation)
	if !ok || expectedRevision < 0 {
		return false, 0, errInvalidIncarnation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lanIncarnation == id {
		return true, s.lanRevision, nil
	}
	if s.lanRevision != expectedRevision {
		return false, s.lanRevision, nil
	}
	s.lanIncarnation = id
	s.lanRevision++
	return true, s.lanRevision, nil
}

// Caller holds the machine store's lock through the entire LAN operation.
func (s *InMemoryMachineStore) lanDevice(deviceID, pubKey, incarnation string) (*Machine, LanOutcome) {
	if s.lanIncarnation != incarnation {
		return nil, LanStaleIncarnation
	}
	presented, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, LanNotEligible
	}
	for _, machine := range s.machines {
		if machine.DeviceID == deviceID {
			stored, err := hex.DecodeString(machine.Pubkey)
			if err == nil && machine.Status == MachineStatusActive && !machine.Ephemeral && matchesLanDeviceKey(stored, presented) {
				return machine, ""
			}
			break
		}
	}
	return nil, LanNotEligible
}

func (s *InMemoryMachineStore) AllocateLanEpoch(_ context.Context, deviceID, pubKey, incarnation string, generation int64) (int64, LanOutcome, error) {
	id, _ := parsePgUUID(incarnation)
	if !validLanConnection(deviceID, id, generation) {
		return 0, LanBadRequest, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	machine, outcome := s.lanDevice(deviceID, pubKey, id)
	if outcome != "" {
		return 0, outcome, nil
	}
	state := s.lanStates[machine.ID]
	changed, outcome := state.allocate(id, generation)
	if outcome != "" {
		return 0, outcome, nil
	}
	if changed {
		if s.lanStates == nil {
			s.lanStates = make(map[string]memoryLanState)
		}
		s.lanStates[machine.ID] = state
	}
	return state.epoch, "", nil
}

func (s *InMemoryMachineStore) IngestLanReport(_ context.Context, deviceID, pubKey, incarnation string, generation, epoch, seq int64, digest []byte, entries []LanEntry) (LanOutcome, error) {
	id, _ := parsePgUUID(incarnation)
	if !validLanConnection(deviceID, id, generation) || !validLanReport(epoch, seq, digest, entries) {
		return LanBadRequest, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	machine, outcome := s.lanDevice(deviceID, pubKey, id)
	if outcome != "" {
		return outcome, nil
	}
	state := s.lanStates[machine.ID]
	outcome = state.report(id, generation, epoch, seq, digest)
	if outcome == LanApplied {
		state.seq, state.digest = seq, bytes.Clone(digest)
		state.receivedAt = time.Now()
		state.entries = make([]LanEntry, len(entries))
		for i, entry := range entries {
			if entry.GatewayMAC != nil {
				gateway := *entry.GatewayMAC
				entry.GatewayMAC = &gateway
			}
			state.entries[i] = entry
		}
		s.lanStates[machine.ID] = state
	}
	return outcome, nil
}

func (s *InMemoryMachineStore) PurgeStaleLanFacts(_ context.Context, olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-olderThan)
	var deleted int64
	for id, state := range s.lanStates {
		if state.receivedAt.Before(cutoff) && len(state.entries) > 0 {
			deleted += int64(len(state.entries))
			state.entries = nil
			s.lanStates[id] = state
		}
	}
	return deleted, nil
}
