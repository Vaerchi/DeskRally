package controlplane

// PgAPITokenStore — the pgx-backed APITokenStore over `api_token` + cp_api_token_resolve
// (migrations/0027_api_token.sql).
//
// Mint/list/revoke are management-plane operations and run tenant-pinned via withTenant (RLS
// USING/WITH CHECK confine them to the caller's tenant). Resolution is the PRE-TENANT auth path —
// the bearer secret is the only key and no tenant is pinned yet — so it runs on the pool directly
// through the SECURITY DEFINER resolver, mirroring cp_session_by_token / cp_enrollment_token_redeem.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgAPITokenStore is the pgx-backed APITokenStore.
type PgAPITokenStore struct {
	Pool *pgxpool.Pool
}

// NewPgAPITokenStore constructs a PgAPITokenStore.
func NewPgAPITokenStore(pool *pgxpool.Pool) *PgAPITokenStore {
	return &PgAPITokenStore{Pool: pool}
}

var _ APITokenStore = (*PgAPITokenStore)(nil)

// apiTokenColumns is the metadata projection shared by list + resolve. token_hash is deliberately
// absent: it never leaves the database.
const apiTokenColumns = `
	id::text, tenant_id::text, name, capabilities, COALESCE(created_by::text, ''),
	created_at, expires_at, revoked_at`

func scanAPIToken(row pgx.Row) (*APIToken, error) {
	var (
		t         APIToken
		caps      []string
		expiresAt *time.Time
		revokedAt *time.Time
	)
	if err := row.Scan(&t.ID, &t.TenantID, &t.Name, &caps, &t.CreatedBy,
		&t.CreatedAt, &expiresAt, &revokedAt); err != nil {
		return nil, err
	}
	t.Capabilities = make([]Capability, len(caps))
	for i, c := range caps {
		t.Capabilities[i] = Capability(c)
	}
	t.ExpiresAt = expiresAt
	t.RevokedAt = revokedAt
	return &t, nil
}

// Mint implements APITokenStore: generate the secret, insert its hash tenant-pinned (RLS WITH
// CHECK confines the row to the pinned tenant), and return the plaintext exactly once. The
// capabilities are stored verbatim — the handler is the gate that confines them to
// apiTokenGrantableCaps.
func (s *PgAPITokenStore) Mint(ctx context.Context, tenantID, name string, caps []Capability, createdBy string, expiresAt *time.Time) (string, *APIToken, error) {
	plaintext, err := newAPITokenSecret()
	if err != nil {
		return "", nil, err
	}
	capStrs := make([]string, len(caps))
	for i, c := range caps {
		capStrs[i] = string(c)
	}
	tok := &APIToken{TenantID: tenantID, Name: name, Capabilities: cloneCaps(caps), CreatedBy: createdBy, ExpiresAt: expiresAt}
	err = withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO api_token (tenant_id, name, token_hash, capabilities, created_by, expires_at)
			VALUES ($1, $2, $3, $4, NULLIF($5,'')::uuid, $6)
			RETURNING id::text, created_at
		`, tenantID, name, HashToken(plaintext), capStrs, createdBy, expiresAt).
			Scan(&tok.ID, &tok.CreatedAt)
	})
	if err != nil {
		return "", nil, err
	}
	return plaintext, tok, nil
}

// List implements APITokenStore: the tenant's token metadata, newest first.
func (s *PgAPITokenStore) List(ctx context.Context, tenantID string) ([]APIToken, error) {
	var out []APIToken
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+apiTokenColumns+`
			FROM api_token
			ORDER BY created_at DESC, id DESC
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanAPIToken(rows)
			if err != nil {
				return err
			}
			out = append(out, *t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke implements APITokenStore: idempotent (COALESCE keeps the first revocation time); an id
// RLS can't see in the pinned tenant affects 0 rows → not found.
func (s *PgAPITokenStore) Revoke(ctx context.Context, tenantID, id string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE api_token SET revoked_at = COALESCE(revoked_at, now())
			WHERE id = $1
		`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrAPITokenNotFound
		}
		return nil
	})
}

// Resolve implements APITokenStore via the SECURITY DEFINER resolver: returns the live row or
// nothing. No row — unknown, revoked, expired, suspended tenant — is ErrAPITokenNotFound,
// indistinguishable to the caller by design.
func (s *PgAPITokenStore) Resolve(ctx context.Context, plaintext string) (*APIToken, error) {
	t, err := scanAPIToken(s.Pool.QueryRow(ctx, `
		SELECT `+apiTokenColumns+`
		FROM cp_api_token_resolve($1)
	`, HashToken(plaintext)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAPITokenNotFound
		}
		return nil, err
	}
	return t, nil
}
