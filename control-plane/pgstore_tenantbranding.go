package controlplane

// PgTenantBrandingStore — the pgx-backed TenantBrandingStore over `tenant_branding`
// (migrations/0028). Get + Set run tenant-pinned via withTenant, so RLS confines both to the
// caller's tenant. Set is an upsert (one row per tenant); Get returns the zero Branding for no row.

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgTenantBrandingStore is the pgx-backed TenantBrandingStore.
type PgTenantBrandingStore struct {
	Pool *pgxpool.Pool
}

// NewPgTenantBrandingStore constructs a PgTenantBrandingStore.
func NewPgTenantBrandingStore(pool *pgxpool.Pool) *PgTenantBrandingStore {
	return &PgTenantBrandingStore{Pool: pool}
}

var _ TenantBrandingStore = (*PgTenantBrandingStore)(nil)

// Get implements TenantBrandingStore: the tenant's row, or a zero Branding (defaults) when none.
func (s *PgTenantBrandingStore) Get(ctx context.Context, tenantID string) (Branding, error) {
	var b Branding
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT product_name, accent_color, logo_data_uri FROM tenant_branding WHERE tenant_id = $1`, tenantID).
			Scan(&b.ProductName, &b.AccentColor, &b.LogoDataURI)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // unset → the zero Branding (all defaults)
		}
		return err
	})
	if err != nil {
		return Branding{}, err
	}
	return b, nil
}

// Set implements TenantBrandingStore: upsert the single per-tenant row (RLS WITH CHECK confines it).
func (s *PgTenantBrandingStore) Set(ctx context.Context, tenantID string, b Branding) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_branding (tenant_id, product_name, accent_color, logo_data_uri, updated_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (tenant_id) DO UPDATE
			SET product_name  = EXCLUDED.product_name,
			    accent_color  = EXCLUDED.accent_color,
			    logo_data_uri = EXCLUDED.logo_data_uri,
			    updated_at    = now()
		`, tenantID, b.ProductName, b.AccentColor, b.LogoDataURI)
		return err
	})
}
