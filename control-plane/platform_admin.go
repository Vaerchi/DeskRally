package controlplane

// Operator-side administration of the platform grant (migration 0055), run by the controlplane CLI
// with the OWNER connection (MIGRATE_DATABASE_URL): rmt_app can neither read nor write
// platform_config / platform_operator. Each change commits in ONE transaction with its event on the
// platform tenant's management audit chain (appendTx), so a grant can never exist unaudited.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PlatformOperatorRow is one granted operator, for `controlplane platform list`.
type PlatformOperatorRow struct {
	Email     string
	TenantID  string
	GrantedAt time.Time
	GrantedBy string
}

func platformAdminTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// One lock for every platform administration operation, taken before any configuration is read,
	// so set-tenant, grant and revoke never decide from a configuration another command is changing
	// (a grant read under tenant A must not land after a set-tenant to B deleted the grants). Waits are
	// bounded so a stuck administrator transaction fails a CLI run instead of hanging it.
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', '10000', true)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform_admin', 0))`); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EnsureOwnerBypassesRLS refuses a connection whose role is subject to row-level security: the
// administration queries read tenant/app_user rows of more than one tenant and would otherwise see
// none (and fail confusingly) on a FORCE-RLS schema.
func EnsureOwnerBypassesRLS(ctx context.Context, pool *pgxpool.Pool) error {
	var super, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil {
		return err
	}
	if !super && !bypass {
		return errors.New("this connection's role is subject to row-level security; use the schema owner (MIGRATE_DATABASE_URL) with SUPERUSER or BYPASSRLS")
	}
	return nil
}

func tenantIDBySlug(ctx context.Context, tx pgx.Tx, slug string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM tenant WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("no tenant with slug %q", slug)
	}
	return id, err
}

func platformTenantTx(ctx context.Context, tx pgx.Tx) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM platform_config WHERE singleton`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("no platform tenant configured (run `controlplane platform set-tenant --slug <slug>` first)")
	}
	return id, err
}

func adminMeta(by string, extra map[string]any) json.RawMessage {
	m := map[string]any{"actor_kind": "platform_admin_cli", "performed_by": by}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

// PlatformSetTenant names the platform tenant (by slug). Changing it revokes every existing grant in
// the same transaction: a grant is valid only inside the tenant it was given in.
func PlatformSetTenant(ctx context.Context, pool *pgxpool.Pool, slug, by string) (string, error) {
	audit := NewPgMgmtAuditStore(pool)
	var tid string
	err := platformAdminTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		if tid, err = tenantIDBySlug(ctx, tx, slug); err != nil {
			return err
		}
		var previous *string
		_ = tx.QueryRow(ctx, `SELECT tenant_id::text FROM platform_config WHERE singleton`).Scan(&previous)
		if previous != nil && *previous == tid {
			return nil
		}
		revoked, err := tx.Exec(ctx, `DELETE FROM platform_operator`)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO platform_config (singleton, tenant_id, set_by) VALUES (true, $1, $2)
			ON CONFLICT (singleton) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, set_at = now(), set_by = EXCLUDED.set_by`,
			tid, by); err != nil {
			return err
		}
		return audit.appendTx(ctx, tx, tid, &MgmtAuditEvent{
			Action: "platform.config.set_tenant", TargetKind: "tenant", TargetID: tid,
			Metadata: adminMeta(by, map[string]any{"slug": slug, "grants_revoked": revoked.RowsAffected()}),
		})
	})
	return tid, err
}

// PlatformGrant makes the user with `email` in the platform tenant an operator.
func PlatformGrant(ctx context.Context, pool *pgxpool.Pool, email, by string) error {
	audit := NewPgMgmtAuditStore(pool)
	return platformAdminTx(ctx, pool, func(tx pgx.Tx) error {
		tid, err := platformTenantTx(ctx, tx)
		if err != nil {
			return err
		}
		var uid string
		err = tx.QueryRow(ctx, `SELECT id::text FROM app_user WHERE tenant_id = $1 AND lower(email) = lower($2) AND disabled_at IS NULL`,
			tid, strings.TrimSpace(email)).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no enabled user %q in the platform tenant", email)
		}
		if err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `INSERT INTO platform_operator (user_id, tenant_id, granted_by) VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO NOTHING`, uid, tid, by)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return nil // already an operator; nothing changed, nothing to audit
		}
		return audit.appendTx(ctx, tx, tid, &MgmtAuditEvent{
			Action: "platform.operator.grant", TargetKind: "user", TargetID: uid,
			Metadata: adminMeta(by, map[string]any{"email": email}),
		})
	})
}

// PlatformRevoke removes the operator grant of the user with `email` in the platform tenant.
func PlatformRevoke(ctx context.Context, pool *pgxpool.Pool, email, by string) error {
	audit := NewPgMgmtAuditStore(pool)
	return platformAdminTx(ctx, pool, func(tx pgx.Tx) error {
		tid, err := platformTenantTx(ctx, tx)
		if err != nil {
			return err
		}
		var uid string
		err = tx.QueryRow(ctx, `
			DELETE FROM platform_operator o USING app_user u
			 WHERE o.user_id = u.id AND u.tenant_id = $1 AND lower(u.email) = lower($2)
			RETURNING o.user_id::text`, tid, strings.TrimSpace(email)).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%q is not a platform operator", email)
		}
		if err != nil {
			return err
		}
		return audit.appendTx(ctx, tx, tid, &MgmtAuditEvent{
			Action: "platform.operator.revoke", TargetKind: "user", TargetID: uid,
			Metadata: adminMeta(by, map[string]any{"email": email}),
		})
	})
}

// PlatformList returns the configured platform tenant's slug and its operators.
func PlatformList(ctx context.Context, pool *pgxpool.Pool) (string, []PlatformOperatorRow, error) {
	var slug string
	var rows []PlatformOperatorRow
	err := platformAdminTx(ctx, pool, func(tx pgx.Tx) error {
		tid, err := platformTenantTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT slug FROM tenant WHERE id = $1`, tid).Scan(&slug); err != nil {
			return err
		}
		r, err := tx.Query(ctx, `
			SELECT u.email, o.tenant_id::text, o.granted_at, o.granted_by
			  FROM platform_operator o JOIN app_user u ON u.id = o.user_id
			 WHERE o.tenant_id = $1 ORDER BY o.granted_at`, tid)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var row PlatformOperatorRow
			if err := r.Scan(&row.Email, &row.TenantID, &row.GrantedAt, &row.GrantedBy); err != nil {
				return err
			}
			rows = append(rows, row)
		}
		return r.Err()
	})
	return slug, rows, err
}
