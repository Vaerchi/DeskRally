package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SetEmail implements UserStore: atomically update app_user.email and advance
// user_credential.updated_at in a single withTenant transaction.
//
// The two-statement shape is deliberate:
//
//  1. UPDATE app_user SET email = $2 WHERE id = $1 AND disabled_at IS NULL
//     → 0 rows: user absent in pinned tenant or disabled → ErrNoUser
//     → unique_violation (23505): newEmail already taken → ErrEmailExists (mapped after withTenant)
//
//  2. UPDATE user_credential SET updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
//     WHERE user_id = $1 AND updated_at = $3 RETURNING updated_at
//     → 0 rows: epoch advanced by a concurrent credential change → rollback → ErrStaleCredential
//
// Both updates run under the same transaction, so a unique-violation rollback also rolls back
// the email write, and a stale-epoch rollback also rolls back the email write. The caller's
// pre-verified session is invalidated the moment the new epoch is committed, because
// SessionAuthenticator.Authenticate compares session.CredentialEpoch against the stored one.
//
// clock_timestamp() (wall time, not transaction start) keeps the new epoch strictly after the old
// when two email changes land in the same transaction boundary; the GREATEST(..., old+1µs) fallback
// handles coarser-than-microsecond clocks without sacrificing monotonicity.
// ChangePassword implements UserStore: replace the password only while the credential epoch still
// equals expectedEpoch. Same lock order as SetPassword and SetEmail (the app_user row first); the
// epoch compare and the write are one UPDATE, so a change that committed after the caller's
// verification makes this a no-op that reports ErrStaleCredential.
func (s *PgUserStore) ChangePassword(ctx context.Context, tenantID, userID, phcHash string, expectedEpoch time.Time) (time.Time, error) {
	if namesNoUUIDRow(userID) {
		return time.Time{}, ErrNoUser
	}
	var epoch time.Time
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var locked int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM app_user WHERE id = $1 FOR UPDATE`, userID).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoUser
			}
			return err
		}
		err := tx.QueryRow(ctx, `
			UPDATE user_credential
			   SET password_hash = $2,
			       updated_at    = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
			 WHERE user_id = $1 AND tenant_id = $3 AND updated_at = $4
			   AND EXISTS (SELECT 1 FROM app_user WHERE id = $1 AND disabled_at IS NULL)
			RETURNING updated_at
		`, userID, phcHash, tenantID, expectedEpoch).Scan(&epoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStaleCredential
		}
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	return epoch.UTC(), nil
}

func (s *PgUserStore) SetEmail(ctx context.Context, tenantID, userID, newEmail string, expectedEpoch time.Time) (time.Time, error) {
	if namesNoUUIDRow(userID) {
		return time.Time{}, ErrNoUser
	}
	var newEpoch time.Time
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// SSO fencing design v3.1: all credential writers first lock the always-present
		// app_user row, in the same relative order as OIDC issuance and linking.
		var locked int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM app_user WHERE id = $1 FOR UPDATE`, userID).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoUser
			}
			return err
		}
		ct, err := tx.Exec(ctx, `
			UPDATE app_user SET email = $2
			 WHERE id = $1 AND tenant_id = $3 AND disabled_at IS NULL
			   AND EXISTS (SELECT 1 FROM tenant WHERE id = $3 AND disabled_at IS NULL)
		`, userID, newEmail, tenantID)
		if err != nil {
			return err // unique_violation propagates here; isUniqueViolation maps it after withTenant
		}
		if ct.RowsAffected() == 0 {
			return ErrNoUser
		}
		err = tx.QueryRow(ctx, `
			UPDATE user_credential
			   SET updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
			 WHERE user_id = $1 AND tenant_id = $3
			   AND updated_at = $2
			RETURNING updated_at
		`, userID, expectedEpoch, tenantID).Scan(&newEpoch)
		if errors.Is(err, pgx.ErrNoRows) {
			// Epoch no longer matches: a concurrent password change/reset committed between
			// the caller's VerifyPasswordCtx and this write. Roll back the email update too.
			return ErrStaleCredential
		}
		return err
	})
	if isUniqueViolation(err) {
		return time.Time{}, ErrEmailExists
	}
	if err != nil {
		return time.Time{}, err
	}
	return newEpoch.UTC(), nil
}
