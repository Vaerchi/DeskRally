package controlplane

// Platform operator (coordination/designs/platform-operator-view-v2.md + v3/v4/v5 deltas; migration
// 0054). The operator is a NAMED user of the configured platform tenant holding a grant that only the
// owner-role CLI can write, using an interactive session whose TOTP verification is bound to the
// user's current mfa_generation. Every check lives in the cp_platform_* SECURITY DEFINER functions;
// this file adds the one thing those functions deliberately do not do: the audit trail.
//
// AUDIT (design deviation accepted by Codex 2026-10-16): each lifecycle change runs in ONE
// transaction on the request's own connection: the definer function first (it takes the tenant row
// lock), then the platform-chain event, then the target tenant's chain event, both through
// PgMgmtAuditStore.appendTx (the same bounded lock, stamping and read-back re-hash every audit
// append uses). Any failure rolls back the tenant change and both events. This orchestration is the
// only application caller of cp_platform_create_tenant / cp_platform_set_suspended.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrPlatformDenied: not an operator, wrong tenant, or the session lacks a current second-factor
// verification (the DB check raised insufficient_privilege). Callers answer 403 and reveal no more.
var ErrPlatformDenied = errors.New("platform operator access denied")

// ErrPlatformNoTenant: the target tenant does not exist.
var ErrPlatformNoTenant = errors.New("no such tenant")

// PlatformCaller identifies the authenticated operator request. SessionID is the interactive
// session's row id: API tokens carry none, so they can never pass the DB check.
type PlatformCaller struct {
	UserID    string
	TenantID  string
	SessionID string
	Email     string
}

// PlatformTenant is the metadata the operator may see about any tenant (v2 §3, least metadata).
type PlatformTenant struct {
	ID               string     `json:"id"`
	Slug             string     `json:"slug"`
	Name             string     `json:"name"`
	DeploymentMode   string     `json:"deployment_mode"`
	CreatedAt        time.Time  `json:"created_at"`
	DisabledAt       *time.Time `json:"disabled_at,omitempty"`
	UserCount        int64      `json:"user_count"`
	UnleasedMachines bool       `json:"unleased_machines"`
}

// PlatformWhoami answers the console: is the caller an operator, is its session's MFA valid for reads
// (12 h), and fresh enough for a change (15 min).
type PlatformWhoami struct {
	Operator bool `json:"operator"`
	MFAOK    bool `json:"mfa_ok"`
	MFAFresh bool `json:"mfa_fresh"`
}

// PlatformStore is the operator surface. Only the pgx implementation exists: these checks are
// database-enforced and a fake would test nothing that matters.
type PlatformStore interface {
	Whoami(ctx context.Context, c PlatformCaller) (PlatformWhoami, error)
	ListTenants(ctx context.Context, c PlatformCaller) ([]PlatformTenant, error)
	CreateTenant(ctx context.Context, c PlatformCaller, slug, name, mode, correlation string) (*Tenant, error)
	SetSuspended(ctx context.Context, c PlatformCaller, tenantID string, suspended bool, reason, correlation string) (*Tenant, error)
	// DownloadReport is the audited cross-tenant reach read (platform_reach.go, migration 0078).
	DownloadReport(ctx context.Context, c PlatformCaller, from, to time.Time, correlation string) ([]ReachRow, error)
}

// PgPlatformStore implements PlatformStore over migration 0054.
type PgPlatformStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

// NewPgPlatformStore wires the store; the audit store must share the pool (same connection binding).
func NewPgPlatformStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgPlatformStore {
	return &PgPlatformStore{Pool: pool, Audit: audit}
}

func platformErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "42501":
			return ErrPlatformDenied
		case "P0002":
			return ErrPlatformNoTenant
		case "23505":
			return ErrTenantSlugTaken
		case "22P02": // a malformed uuid argument never names a real caller or tenant
			return ErrPlatformDenied
		}
	}
	return err
}

func (s *PgPlatformStore) Whoami(ctx context.Context, c PlatformCaller) (PlatformWhoami, error) {
	var w PlatformWhoami
	if c.SessionID == "" || !isUUID(c.UserID) || !isUUID(c.SessionID) {
		return w, nil
	}
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT operator, mfa_ok, mfa_fresh FROM cp_platform_whoami($1, $2)`,
			c.UserID, c.SessionID).Scan(&w.Operator, &w.MFAOK, &w.MFAFresh)
	})
	return w, platformErr(err)
}

func (s *PgPlatformStore) ListTenants(ctx context.Context, c PlatformCaller) ([]PlatformTenant, error) {
	if c.SessionID == "" {
		return nil, ErrPlatformDenied
	}
	var out []PlatformTenant
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, slug, name, deployment_mode, created_at, disabled_at, user_count, unleased_machines
			FROM cp_platform_list_tenants($1, $2)`, c.UserID, c.SessionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t PlatformTenant
			if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.DeploymentMode, &t.CreatedAt, &t.DisabledAt,
				&t.UserCount, &t.UnleasedMachines); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, platformErr(err)
}

// operatorMeta is the attribution both chains record: the real operator, never a customer user.
func operatorMeta(c PlatformCaller, correlation string, extra map[string]any) json.RawMessage {
	m := map[string]any{
		"actor_kind":         "platform_operator",
		"operator_user_id":   c.UserID,
		"operator_tenant_id": c.TenantID,
		"operator_email":     c.Email,
		"correlation_id":     correlation,
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func (s *PgPlatformStore) CreateTenant(ctx context.Context, c PlatformCaller, slug, name, mode, correlation string) (*Tenant, error) {
	if c.SessionID == "" || s.Audit == nil {
		return nil, ErrPlatformDenied
	}
	var t Tenant
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT id::text, slug, name, deployment_mode, created_at
			FROM cp_platform_create_tenant($1, $2, $3, $4, $5)`,
			c.UserID, c.SessionID, slug, name, mode).Scan(&t.ID, &t.Slug, &t.Name, &t.DeploymentMode, &t.CreatedAt); err != nil {
			return err
		}
		meta := operatorMeta(c, correlation, map[string]any{"slug": t.Slug, "name": t.Name, "deployment_mode": t.DeploymentMode})
		if err := s.Audit.appendTx(ctx, tx, c.TenantID, &MgmtAuditEvent{
			ActorUserID: c.UserID, Action: "platform.tenant.create", TargetKind: "tenant", TargetID: t.ID, Metadata: meta,
		}); err != nil {
			return fmt.Errorf("platform audit: %w", err)
		}
		// The new tenant's own chain starts with who created it.
		if err := s.Audit.appendTx(ctx, tx, t.ID, &MgmtAuditEvent{
			Action: "tenant.created_by_platform", TargetKind: "tenant", TargetID: t.ID, Metadata: meta,
		}); err != nil {
			return fmt.Errorf("tenant audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, platformErr(err)
	}
	return &t, nil
}

func (s *PgPlatformStore) SetSuspended(ctx context.Context, c PlatformCaller, tenantID string, suspended bool, reason, correlation string) (*Tenant, error) {
	if c.SessionID == "" || s.Audit == nil {
		return nil, ErrPlatformDenied
	}
	if !isUUID(tenantID) {
		return nil, ErrPlatformNoTenant
	}
	var t Tenant
	var disabledAt *time.Time
	err := withTenant(ctx, s.Pool, c.TenantID, func(tx pgx.Tx) error {
		// The definer takes the tenant row lock FIRST (lock order: tenant row, then chain locks).
		if err := tx.QueryRow(ctx, `
			SELECT id::text, slug, name, deployment_mode, created_at, disabled_at
			FROM cp_platform_set_suspended($1, $2, $3, $4)`,
			c.UserID, c.SessionID, tenantID, suspended).Scan(&t.ID, &t.Slug, &t.Name, &t.DeploymentMode, &t.CreatedAt, &disabledAt); err != nil {
			return err
		}
		platformAction, tenantAction := "platform.tenant.resume", "tenant.resumed_by_platform"
		if suspended {
			platformAction, tenantAction = "platform.tenant.suspend", "tenant.suspended_by_platform"
		}
		meta := operatorMeta(c, correlation, map[string]any{"slug": t.Slug, "reason": reason})
		if err := s.Audit.appendTx(ctx, tx, c.TenantID, &MgmtAuditEvent{
			ActorUserID: c.UserID, Action: platformAction, TargetKind: "tenant", TargetID: t.ID, Metadata: meta,
		}); err != nil {
			return fmt.Errorf("platform audit: %w", err)
		}
		// The customer sees who suspended them. No customer actor id: the operator is in metadata.
		if err := s.Audit.appendTx(ctx, tx, t.ID, &MgmtAuditEvent{
			Action: tenantAction, TargetKind: "tenant", TargetID: t.ID, Metadata: meta,
		}); err != nil {
			return fmt.Errorf("tenant audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, platformErr(err)
	}
	t.Disabled = disabledAt != nil
	return &t, nil
}
