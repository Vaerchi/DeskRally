package controlplane

// Session-ticket redemption (M2 follow-up) — the SHARED single-use ledger for RMTTICKETv1 tickets.
//
// POST /sessions mints a short-TTL, Ed25519-signed session ticket (ticket.go) that authorizes
// exactly ONE signaling rendezvous. The signaling server enforced "exactly one" from an in-process
// map, which meant two replicas honoured the same ticket twice and a restart honoured it again.
// Single use is a property of the TICKET, not of a process, so the ledger belongs where the ticket
// was issued: here.
//
// The signaling server reaches this through the service-token-gated
// POST /internal/session-tickets/redeem (http.go), the sibling of the device-identity lookup, and
// keeps its local map as the fast path in front of it. Everything the redemption needs to be safe —
// signature, version, expiry, tenant binding, device binding — has already been checked by the
// caller; this side records a fact and reports whether it was new.
//
// Follows the repo's interface-plus-fakes pattern: TicketRedemptionStore here with an in-memory
// fake for DEV/tests, pgx implementation over cp_session_ticket_redeem (migrations/0023) in
// pgstore_ticketredemption.go.

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrTicketAlreadyRedeemed is the DEFINITIVE answer that a ticket's one use is already spent. It is
// the only error a store returns that means "this is a replay"; every other error means the ledger
// could not answer, which is a different thing entirely and is treated differently by the caller
// (server/signaling/ticketredeem.go).
var ErrTicketAlreadyRedeemed = errors.New("session ticket already redeemed")

// TicketRedemption is one recorded redemption, as the store returns it on the FIRST use.
type TicketRedemption struct {
	TenantID   string    `json:"tenant_id"`
	SessionID  string    `json:"session_id"`
	DeviceID   string    `json:"device_id"`
	RedeemedAt time.Time `json:"redeemed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// TicketRedemptionStore records the single use of a session ticket.
//
// RedeemTicket must be ATOMIC: check-and-record in one indivisible step. A read followed by a write
// is not good enough — two replicas redeeming the same ticket concurrently would both read "unused"
// and both succeed, which is the same failure this ledger exists to close, merely at a shorter
// window. The pgx implementation gets this from a single INSERT ... ON CONFLICT DO NOTHING.
//
// It returns ErrTicketAlreadyRedeemed for a replay, the recorded row for a first use, and any other
// error only when the ledger genuinely could not be consulted.
type TicketRedemptionStore interface {
	RedeemTicket(ctx context.Context, tenantID, sessionID, deviceID string, expiresAt time.Time) (*TicketRedemption, error)
	// WasRedeemed reports whether a redemption row exists for the session: the control plane's evidence that
	// signaling vouched for it (session transfer, docs/51 §8, gates on it). A read; it never records.
	WasRedeemed(ctx context.Context, tenantID, sessionID string) (bool, error)
}

// InMemoryTicketRedemptionStore is the non-persistent TicketRedemptionStore for DEV mode and unit
// tests. It is a real ledger for one process, which is precisely what production must NOT rely on —
// so it is wired only where there is no database at all (cmd/controlplane DEV mode). Expired entries
// are pruned on each redemption, mirroring the pg function's reap and the signaling map's.
type InMemoryTicketRedemptionStore struct {
	mu       sync.Mutex
	redeemed map[string]TicketRedemption // tenant_id + "\x00" + session_id -> row
	// everRedeemed is never pruned: the in-memory twin of session_record.redeemed_at (migration 0060),
	// so WasRedeemed agrees with the pg store after the ledger entry is gone.
	everRedeemed map[string]bool

	// Now is the clock, swappable in tests. Nil means time.Now.
	Now func() time.Time
}

// NewInMemoryTicketRedemptionStore constructs an empty in-memory ledger.
func NewInMemoryTicketRedemptionStore() *InMemoryTicketRedemptionStore {
	return &InMemoryTicketRedemptionStore{redeemed: make(map[string]TicketRedemption), everRedeemed: make(map[string]bool)}
}

var _ TicketRedemptionStore = (*InMemoryTicketRedemptionStore)(nil)

func (s *InMemoryTicketRedemptionStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// RedeemTicket implements TicketRedemptionStore. The whole operation is under one mutex, so the
// check and the record cannot interleave — the in-memory equivalent of the SQL function's single
// statement.
func (s *InMemoryTicketRedemptionStore) RedeemTicket(_ context.Context, tenantID, sessionID, deviceID string, expiresAt time.Time) (*TicketRedemption, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, rec := range s.redeemed {
		if now.After(rec.ExpiresAt) {
			delete(s.redeemed, k)
		}
	}
	key := tenantID + "\x00" + sessionID
	if _, ok := s.redeemed[key]; ok {
		return nil, ErrTicketAlreadyRedeemed
	}
	rec := TicketRedemption{
		TenantID:   tenantID,
		SessionID:  sessionID,
		DeviceID:   deviceID,
		RedeemedAt: now,
		ExpiresAt:  expiresAt,
	}
	s.redeemed[key] = rec
	if s.everRedeemed == nil {
		s.everRedeemed = make(map[string]bool)
	}
	s.everRedeemed[key] = true
	return &rec, nil
}

// WasRedeemed implements TicketRedemptionStore: whether the session's ticket was EVER redeemed (the
// durable marker, not the prunable ledger entry), matching the pg store.
func (s *InMemoryTicketRedemptionStore) WasRedeemed(_ context.Context, tenantID, sessionID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.everRedeemed[tenantID+"\x00"+sessionID], nil
}
