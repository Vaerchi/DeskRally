package controlplane

// PgWebhookStore — the pgx-backed WebhookStore over `tenant_webhook` (migration 0047),
// RLS-scoped per tenant via withTenant.
//
// Three-place rule (same as all pg stores in this package):
//   Create's INSERT, List's SELECT+Scan, and ListDeliveriesForEvent's SELECT+Scan
//   must all agree on which columns are read/written. Missing one column in one place
//   is not a compile error — it is a field that silently reads back as its zero value.
//
// Secret handling: the secret column IS read by ListDeliveriesForEvent (the dispatcher
// needs it for HMAC signing) but is NOT read by List (the API response withholds it).
// Both are intentional.
//
// No UPDATE: webhooks are immutable after creation (change = delete + re-create).

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgWebhookStore is the pgx-backed WebhookStore.
type PgWebhookStore struct {
	Pool *pgxpool.Pool
}

// NewPgWebhookStore constructs a PgWebhookStore.
func NewPgWebhookStore(pool *pgxpool.Pool) *PgWebhookStore {
	return &PgWebhookStore{Pool: pool}
}

var _ WebhookStore = (*PgWebhookStore)(nil)

// Create implements WebhookStore. A per-tenant advisory lock serializes concurrent
// Creates for the same tenant, making the count check and the INSERT one atomic operation.
// Returns ErrWebhookCapExceeded when the tenant already has cap webhooks registered.
func (s *PgWebhookStore) Create(ctx context.Context, tenantID string, w *TenantWebhook, secret string, cap int) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Lock is transaction-scoped (released on commit or rollback).
		// hashtextextended('webhook_create:' || tenantID, 0) produces a namespaced int64
		// key, matching the established pattern of every other advisory lock in this package
		// (session_start, mgmt_audit_chain, credential_token_mint, …). The namespace prefix
		// prevents collisions with the IP-allowlist lock and future locks that also hash tenant UUIDs.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('webhook_create:' || $1, 0))`, tenantID); err != nil {
			return err
		}
		// RLS (app.current_tenant set by withTenant) already scopes this count to the
		// current tenant, so no explicit WHERE clause is needed. The advisory lock above
		// ensures concurrent Creates for the same tenant see a consistent count.
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_webhook`).Scan(&n); err != nil {
			return err
		}
		if n >= cap {
			return ErrWebhookCapExceeded
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_webhook (id, tenant_id, url, secret, events, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, w.ID, tenantID, w.URL, secret, w.Events, w.CreatedAt)
		return err
	})
}

// List implements WebhookStore. Returns newest-first; the secret column is not read.
func (s *PgWebhookStore) List(ctx context.Context, tenantID string) ([]TenantWebhook, error) {
	out := []TenantWebhook{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		out = out[:0]
		rows, err := tx.Query(ctx, `
			SELECT id, url, events, created_at
			FROM tenant_webhook
			ORDER BY created_at DESC, id::text COLLATE "C"
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w TenantWebhook
			if err := rows.Scan(&w.ID, &w.URL, &w.Events, &w.CreatedAt); err != nil {
				return err
			}
			if w.Events == nil {
				w.Events = []string{}
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}

// Delete implements WebhookStore. Returns (true, nil) on success, (false, nil) if not found.
func (s *PgWebhookStore) Delete(ctx context.Context, tenantID, id string) (bool, error) {
	var found bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM tenant_webhook WHERE id = $1`, id)
		if err != nil {
			return err
		}
		found = tag.RowsAffected() > 0
		return nil
	})
	return found, err
}

// ListDeliveriesForEvent implements WebhookStore.
// Returns (id, url, secret) for every webhook in tenantID that subscribed to event
// (by naming it, or by having an empty events list = subscribe to everything).
func (s *PgWebhookStore) ListDeliveriesForEvent(ctx context.Context, tenantID, event string) ([]WebhookDelivery, error) {
	var out []WebhookDelivery
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		out = nil
		rows, err := tx.Query(ctx, `
			SELECT id, url, secret
			FROM tenant_webhook
			WHERE events = '{}' OR $1 = ANY(events)
		`, event)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d WebhookDelivery
			if err := rows.Scan(&d.ID, &d.URL, &d.Secret); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

