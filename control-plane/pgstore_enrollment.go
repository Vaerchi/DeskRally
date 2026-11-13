package controlplane

// PgEnrollmentTokenStore — the pgx-backed EnrollmentTokenStore over `enrollment_token`
// (migrations/0001_core.sql) + cp_enrollment_token_redeem (migrations/0007_enrollment.sql).
//
// Mint/list/revoke are management-plane operations and run tenant-pinned via withTenant (RLS
// USING/WITH CHECK confine them to the caller's tenant). Redemption is the PRE-TENANT path —
// the installer is unauthenticated and the token hash is the only key — so it runs on the pool
// directly through the SECURITY DEFINER bootstrap function, mirroring cp_session_by_token.

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgEnrollmentTokenStore is the pgx-backed EnrollmentTokenStore.
type PgEnrollmentTokenStore struct {
	Pool *pgxpool.Pool
}

// NewPgEnrollmentTokenStore constructs a PgEnrollmentTokenStore.
func NewPgEnrollmentTokenStore(pool *pgxpool.Pool) *PgEnrollmentTokenStore {
	return &PgEnrollmentTokenStore{Pool: pool}
}

var _ EnrollmentTokenStore = (*PgEnrollmentTokenStore)(nil)

// enrollmentTokenColumns is the metadata projection shared by list + redeem. token_hash is
// deliberately absent: it never leaves the database.
const enrollmentTokenColumns = `
	id::text, tenant_id::text, group_id::text, COALESCE(created_by::text, ''),
	created_at, expires_at, max_uses, uses, (revoked_at IS NOT NULL)`

func scanEnrollmentToken(row pgx.Row) (*EnrollmentToken, error) {
	var t EnrollmentToken
	if err := row.Scan(&t.ID, &t.TenantID, &t.GroupID, &t.CreatedBy,
		&t.CreatedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked); err != nil {
		return nil, err
	}
	return &t, nil
}

// MintToken implements EnrollmentTokenStore: generate the secret, insert its hash
// tenant-pinned (RLS WITH CHECK + the composite group FK confine the row to the pinned tenant
// and a group within it), and return the plaintext exactly once.
func (s *PgEnrollmentTokenStore) MintToken(ctx context.Context, tenantID string, tok *EnrollmentToken) (string, error) {
	plaintext, err := newEnrollmentSecret()
	if err != nil {
		return "", err
	}
	err = withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO enrollment_token (tenant_id, group_id, token_hash, created_by, expires_at, max_uses)
			VALUES ($1, $2, $3, NULLIF($4,'')::uuid, $5, $6)
			RETURNING id::text, created_at, uses
		`, tenantID, tok.GroupID, HashToken(plaintext), tok.CreatedBy, tok.ExpiresAt, tok.MaxUses).
			Scan(&tok.ID, &tok.CreatedAt, &tok.Uses)
	})
	if err != nil {
		return "", err
	}
	tok.TenantID = tenantID
	tok.Revoked = false
	return plaintext, nil
}

// ListTokens implements EnrollmentTokenStore: the tenant's token metadata, newest first.
func (s *PgEnrollmentTokenStore) ListTokens(ctx context.Context, tenantID string) ([]EnrollmentToken, error) {
	var out []EnrollmentToken
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+enrollmentTokenColumns+`
			FROM enrollment_token
			ORDER BY created_at DESC
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t EnrollmentToken
			if err := rows.Scan(&t.ID, &t.TenantID, &t.GroupID, &t.CreatedBy,
				&t.CreatedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeToken implements EnrollmentTokenStore: idempotent (COALESCE keeps the first
// revocation time); an id RLS can't see in the pinned tenant affects 0 rows → not found.
func (s *PgEnrollmentTokenStore) RevokeToken(ctx context.Context, tenantID, id string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE enrollment_token SET revoked_at = COALESCE(revoked_at, now())
			WHERE id = $1
		`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrEnrollmentTokenNotFound
		}
		return nil
	})
}

// RedeemToken implements EnrollmentTokenStore via the SECURITY DEFINER bootstrap function:
// one atomic UPDATE validates and consumes a use, returning the row; no row means invalid —
// unknown, revoked, expired, and exhausted are indistinguishable to the caller by design.
func (s *PgEnrollmentTokenStore) RedeemToken(ctx context.Context, plaintext string) (*EnrollmentToken, error) {
	t, err := scanEnrollmentToken(s.Pool.QueryRow(ctx, `
		SELECT `+enrollmentTokenColumns+`
		FROM cp_enrollment_token_redeem($1)
	`, HashToken(plaintext)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEnrollmentTokenInvalid
		}
		return nil, err
	}
	return t, nil
}
