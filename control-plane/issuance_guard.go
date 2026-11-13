package controlplane

// Issuance is serialized with tenant suspension (platform-operator design v5).
//
// Every handler that mints something an agent will honour (session ticket, session policy / lease,
// backstage grant, elevation grant) calls holdIssuance BEFORE reading the clock for the signed
// validity window, and holds it until the handler returns. holdIssuance takes a SHARED,
// session-level advisory lock keyed by the tenant on the request's pinned connection, then re-reads
// tenant.disabled_at. cp_platform_set_suspended takes the EXCLUSIVE transaction-level lock on the
// same key before it updates the tenant row. So:
//
//   - a mint already holding the shared lock finishes (and its absolute expiry is already fixed)
//     before the suspension can commit: every successful mint is ordered before the commit, and
//     expires within commit + its TTL;
//   - a mint arriving while the suspension is in flight waits on the shared lock, then reads
//     disabled_at after the commit and is refused.
//
// A shared advisory lock, rather than FOR SHARE on the tenant row as the design text puts it, because
// these handlers make several store calls, each its own transaction on the pinned connection; a row
// lock would end with the first of them. The session-level lock spans them all. Lock order is the
// same as the suspension's: this key first, then any audit chain lock.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// errIssuanceSuspended: the tenant was suspended; nothing may be minted.
var errIssuanceSuspended = errors.New("tenant suspended")

func issuanceLockKey(tenantID string) string { return "tenant_issuance:" + canonicalUUIDish(tenantID) }

// holdIssuance returns the release function the caller must defer. Without a pinned Postgres
// connection (the in-memory/dev stores) there is no suspension to serialize with: no-op.
func (s *Server) holdIssuance(ctx context.Context, tenantID string) (func(), error) {
	bc := boundConnFrom(ctx)
	if bc == nil {
		return func() {}, nil
	}
	if bc.tenantID != tenantID {
		return nil, errors.New("issuance: request is bound to another tenant")
	}
	key := issuanceLockKey(tenantID)
	if _, err := bc.conn.Exec(ctx, `SELECT pg_advisory_lock_shared(hashtextextended($1, 0))`, key); err != nil {
		return nil, err
	}
	release := func() {
		rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		_, _ = bc.conn.Exec(rctx, `SELECT pg_advisory_unlock_shared(hashtextextended($1, 0))`, key)
	}
	var suspended bool
	// withTenant runs on the pinned connection (it ignores the pool when one is bound).
	err := withTenant(ctx, nil, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT disabled_at IS NOT NULL FROM tenant WHERE id = $1`, tenantID).Scan(&suspended)
	})
	if err != nil {
		release()
		return nil, err
	}
	if suspended {
		release()
		return nil, errIssuanceSuspended
	}
	return release, nil
}

// writeIssuanceRefused answers a refused or failed holdIssuance.
func writeIssuanceRefused(w http.ResponseWriter, err error) {
	if errors.Is(err, errIssuanceSuspended) {
		writeError(w, http.StatusForbidden, "tenant suspended")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "could not authorize issuance; retry")
}

// issuanceNow is the clock read for a signed validity window; it exists so the call sites read the
// time only after holdIssuance (a reviewer can grep for it).
func issuanceNow() int64 { return time.Now().UTC().UnixMilli() }
