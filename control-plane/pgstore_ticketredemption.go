package controlplane

// PgTicketRedemptionStore — the pgx-backed TicketRedemptionStore over `session_ticket_redemption`
// + cp_session_ticket_redeem (migrations/0023_session_ticket_redemption.sql).
//
// Redemption is a PRE-TENANT path, like enrollment-token and credential-token redemption: the
// caller is the signaling server, which authenticates with a service token and holds no tenant
// principal, so nothing can be pinned for RLS. It therefore runs on the pool directly through the
// SECURITY DEFINER function rather than through withTenant — the same shape as
// PgEnrollmentTokenStore.RedeemToken.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgTicketRedemptionStore is the pgx-backed TicketRedemptionStore.
type PgTicketRedemptionStore struct {
	Pool *pgxpool.Pool
}

// NewPgTicketRedemptionStore constructs a PgTicketRedemptionStore.
func NewPgTicketRedemptionStore(pool *pgxpool.Pool) *PgTicketRedemptionStore {
	return &PgTicketRedemptionStore{Pool: pool}
}

var _ TicketRedemptionStore = (*PgTicketRedemptionStore)(nil)

// RedeemTicket implements TicketRedemptionStore via the SECURITY DEFINER function: ONE
// INSERT ... ON CONFLICT DO NOTHING RETURNING, so check-and-record is a single indivisible step and
// two replicas racing the same ticket cannot both win. No row returned means the conflict fired —
// the ticket was already redeemed.
//
// The uuid gate is here rather than in the handler for the reason pathid.go sets out: a uuid is a
// constraint of the PostgreSQL SCHEMA, so only a pg store may assume it. Catching it before the
// round trip also keeps the error legible; letting it reach the cast would surface as an opaque
// SQLSTATE 22P02 that reads like a driver fault. Either way the caller treats it as "the ledger
// could not answer", never as a redemption verdict.
func (s *PgTicketRedemptionStore) RedeemTicket(ctx context.Context, tenantID, sessionID, deviceID string, expiresAt time.Time) (*TicketRedemption, error) {
	if namesNoUUIDRow(tenantID) {
		return nil, fmt.Errorf("ticket redemption: tenant id %q cannot name a uuid row", tenantID)
	}
	if namesNoUUIDRow(sessionID) {
		return nil, fmt.Errorf("ticket redemption: session id %q cannot name a uuid row", sessionID)
	}
	var rec TicketRedemption
	err := s.Pool.QueryRow(ctx, `
		SELECT tenant_id::text, session_id::text, device_id, redeemed_at, expires_at
		FROM cp_session_ticket_redeem($1, $2, $3, $4)
	`, tenantID, sessionID, deviceID, expiresAt).
		Scan(&rec.TenantID, &rec.SessionID, &rec.DeviceID, &rec.RedeemedAt, &rec.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTicketAlreadyRedeemed
		}
		return nil, err
	}
	return &rec, nil
}

// WasRedeemed implements TicketRedemptionStore: a pure READ, tenant-pinned like every other reader. It
// answers from session_record.redeemed_at, the DURABLE marker cp_session_ticket_redeem stamps on a new
// redemption (migration 0060), OR the ledger row. The ledger alone forgets a session about an hour after
// its ticket expired (the opportunistic reap), which would refuse to transfer any longer session and
// would let a transferred session's ticket be re-minted and redeemed a second time.
func (s *PgTicketRedemptionStore) WasRedeemed(ctx context.Context, tenantID, sessionID string) (bool, error) {
	if namesNoUUIDRow(sessionID) {
		return false, nil
	}
	var ok bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM session_record WHERE id = $1 AND redeemed_at IS NOT NULL)
			    OR EXISTS (SELECT 1 FROM session_ticket_redemption WHERE session_id = $1)`, sessionID).Scan(&ok)
	})
	return ok, err
}
