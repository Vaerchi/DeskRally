package controlplane

// PgTenantSessionPolicyStore — the pgx-backed TenantSessionPolicyStore over `tenant_session_policy`
// (migrations/0029). Get + Set run tenant-pinned via withTenant, so RLS confines both to the caller's
// tenant. Set is an upsert (one row per tenant); Get returns the zero SessionPolicy (unlimited) for no
// row. The ENFORCEMENT read is not here — it lives in PgSessionRecordStore.StartSessionWithinLimit,
// which counts open sessions and inserts under one advisory lock so the check and the insert are atomic.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgTenantSessionPolicyStore is the pgx-backed TenantSessionPolicyStore.
type PgTenantSessionPolicyStore struct {
	Pool *pgxpool.Pool
}

// NewPgTenantSessionPolicyStore constructs a PgTenantSessionPolicyStore.
func NewPgTenantSessionPolicyStore(pool *pgxpool.Pool) *PgTenantSessionPolicyStore {
	return &PgTenantSessionPolicyStore{Pool: pool}
}

var _ TenantSessionPolicyStore = (*PgTenantSessionPolicyStore)(nil)

// Get implements TenantSessionPolicyStore: the tenant's row, or a zero SessionPolicy (unlimited) when none.
func (s *PgTenantSessionPolicyStore) Get(ctx context.Context, tenantID string) (SessionPolicy, error) {
	var p SessionPolicy
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT max_concurrent_sessions, max_session_seconds FROM tenant_session_policy WHERE tenant_id = $1`, tenantID).
			Scan(&p.MaxConcurrentSessions, &p.MaxSessionSeconds)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // unset → the zero SessionPolicy (no limits)
		}
		return err
	})
	if err != nil {
		return SessionPolicy{}, err
	}
	return p, nil
}

// Set implements TenantSessionPolicyStore: upsert the single per-tenant row (RLS WITH CHECK confines it).
func (s *PgTenantSessionPolicyStore) Set(ctx context.Context, tenantID string, p SessionPolicy) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_session_policy (tenant_id, max_concurrent_sessions, max_session_seconds, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (tenant_id) DO UPDATE
			SET max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
			    max_session_seconds     = EXCLUDED.max_session_seconds,
			    updated_at              = now()
		`, tenantID, p.MaxConcurrentSessions, p.MaxSessionSeconds)
		return err
	})
}

// ListTenantsWithMaxAge implements TenantSessionPolicyStore: returns all (tenantID, maxAge) pairs
// where MaxSessionSeconds > 0, using the cp_list_tenant_max_ages() SECURITY DEFINER function
// (migration 0050) which bypasses RLS to perform this deliberate cross-tenant read.
func (s *PgTenantSessionPolicyStore) ListTenantsWithMaxAge(ctx context.Context) ([]TenantMaxAge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT tenant_id::text, max_session_seconds FROM cp_list_tenant_max_ages()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantMaxAge
	for rows.Next() {
		var tid string
		var secs int
		if err := rows.Scan(&tid, &secs); err != nil {
			return nil, err
		}
		out = append(out, TenantMaxAge{
			TenantID: tid,
			MaxAge:   time.Duration(secs) * time.Second,
		})
	}
	return out, rows.Err()
}
