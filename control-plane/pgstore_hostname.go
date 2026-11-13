package controlplane

// Postgres HostnameStore over migration 0071. Each lifecycle change runs in ONE transaction on the request's
// connection pinned to the platform tenant: the definer function first (it checks the operator, takes the
// tenant's branding-pointer lock and the per-host lock), then the platform-chain audit event, then the
// target tenant's chain event (the same orchestration platform.go uses). Any failure rolls back all three.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgHostnameStore implements HostnameStore.
type PgHostnameStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

// NewPgHostnameStore wires the store; the audit store must share the pool.
func NewPgHostnameStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgHostnameStore {
	return &PgHostnameStore{Pool: pool, Audit: audit}
}

var _ HostnameStore = (*PgHostnameStore)(nil)

const hostnameCols = `id::text, host, tenant_id::text, kind, state, created_by, created_at, activated_at, released_at, released_by, quarantined_until`

func scanHostname(row pgx.Row) (*HostnameAssignment, error) {
	var a HostnameAssignment
	var releasedBy *string
	if err := row.Scan(&a.ID, &a.Host, &a.TenantID, &a.Kind, &a.State, &a.CreatedBy, &a.CreatedAt,
		&a.ActivatedAt, &a.ReleasedAt, &releasedBy, &a.QuarantinedUntil); err != nil {
		return nil, err
	}
	if releasedBy != nil {
		a.ReleasedBy = *releasedBy
	}
	return &a, nil
}

// hostnameErr maps the database's codes to the package's errors.
func hostnameErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "42501", "22P02":
			return ErrPlatformDenied
		case "P0002":
			if pgErr.Message == "hostname: no such tenant" {
				return ErrPlatformNoTenant
			}
			return ErrHostnameNotFound
		case "23505":
			return ErrHostnameTaken
		case "HQ001":
			return ErrHostnameQuarantined
		case "HS001":
			return ErrHostnameState
		case "22023", "23514":
			return ErrHostnameInvalid
		case "55P03":
			return ErrHostnameBusy
		}
	}
	return err
}

func (s *PgHostnameStore) audited(ctx context.Context, c PlatformCaller, action string, extra map[string]any,
	run func(tx pgx.Tx) (*HostnameAssignment, error)) (*HostnameAssignment, error) {
	if c.SessionID == "" || s.Audit == nil {
		return nil, ErrPlatformDenied
	}
	var out *HostnameAssignment
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		a, err := run(tx)
		if err != nil {
			return err
		}
		out = a
		meta := map[string]any{"host": a.Host, "assignment_id": a.ID, "tenant_id": a.TenantID, "state": a.State}
		for k, v := range extra {
			meta[k] = v
		}
		raw := operatorMeta(c, newUUID(), meta)
		if err := s.Audit.appendTx(ctx, tx, c.TenantID, &MgmtAuditEvent{
			ActorUserID: c.UserID, Action: "platform.hostname." + action, TargetKind: "tenant_hostname", TargetID: a.ID, Metadata: raw,
		}); err != nil {
			return fmt.Errorf("platform audit: %w", err)
		}
		if err := s.Audit.appendTx(ctx, tx, a.TenantID, &MgmtAuditEvent{
			Action: "tenant.hostname." + action, TargetKind: "tenant_hostname", TargetID: a.ID, Metadata: raw,
		}); err != nil {
			return fmt.Errorf("tenant audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, hostnameErr(err)
	}
	return out, nil
}

func (s *PgHostnameStore) Assign(ctx context.Context, c PlatformCaller, tenantID, host string, extra map[string]any) (*HostnameAssignment, error) {
	if !isUUID(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	return s.audited(ctx, c, "assign", extra, func(tx pgx.Tx) (*HostnameAssignment, error) {
		return scanHostname(tx.QueryRow(ctx, `SELECT `+hostnameCols+` FROM cp_platform_hostname_assign($1, $2, $3, $4, $5)`,
			c.UserID, c.SessionID, tenantID, host, operatorLabel(c)))
	})
}

func (s *PgHostnameStore) Activate(ctx context.Context, c PlatformCaller, id string, extra map[string]any) (*HostnameAssignment, error) {
	if !isUUID(id) {
		return nil, ErrHostnameNotFound
	}
	return s.audited(ctx, c, "activate", extra, func(tx pgx.Tx) (*HostnameAssignment, error) {
		return scanHostname(tx.QueryRow(ctx, `SELECT `+hostnameCols+` FROM cp_platform_hostname_activate($1, $2, $3)`,
			c.UserID, c.SessionID, id))
	})
}

func (s *PgHostnameStore) Release(ctx context.Context, c PlatformCaller, id string, days int, extra map[string]any) (*HostnameAssignment, error) {
	if !isUUID(id) {
		return nil, ErrHostnameNotFound
	}
	return s.audited(ctx, c, "release", extra, func(tx pgx.Tx) (*HostnameAssignment, error) {
		return scanHostname(tx.QueryRow(ctx, `SELECT `+hostnameCols+` FROM cp_platform_hostname_release($1, $2, $3, $4, $5)`,
			c.UserID, c.SessionID, id, operatorLabel(c), days))
	})
}

func (s *PgHostnameStore) Reactivate(ctx context.Context, c PlatformCaller, releasedID string, activate bool, extra map[string]any) (*HostnameAssignment, error) {
	if !isUUID(releasedID) {
		return nil, ErrHostnameNotFound
	}
	return s.audited(ctx, c, "reactivate", extra, func(tx pgx.Tx) (*HostnameAssignment, error) {
		return scanHostname(tx.QueryRow(ctx, `SELECT `+hostnameCols+` FROM cp_platform_hostname_reactivate($1, $2, $3, $4, $5)`,
			c.UserID, c.SessionID, releasedID, operatorLabel(c), activate))
	})
}

func (s *PgHostnameStore) List(ctx context.Context, c PlatformCaller, tenantID string) ([]HostnameAssignment, error) {
	if c.SessionID == "" {
		return nil, ErrPlatformDenied
	}
	var tid any
	if tenantID != "" {
		if !isUUID(tenantID) {
			return nil, ErrPlatformNoTenant
		}
		tid = tenantID
	}
	out := []HostnameAssignment{}
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+hostnameCols+` FROM cp_platform_hostname_list($1, $2, $3)`,
			c.UserID, c.SessionID, tid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanHostname(rows)
			if err != nil {
				return err
			}
			out = append(out, *a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, hostnameErr(err)
	}
	return out, nil
}

// LiveHostnamesAmong returns which of hosts has a live (pending or active) assignment: the startup collision check
// (a default or legacy host that is also assigned is a refusal to start, docs/66 2.1).
func LiveHostnamesAmong(ctx context.Context, pool *pgxpool.Pool, hosts []string) ([]string, error) {
	rows, err := pool.Query(ctx, `SELECT cp_hostname_live_among($1)`, hosts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
