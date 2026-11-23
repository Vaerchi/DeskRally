package controlplane

// Password history — blocks reuse of recent passwords on POST /me/password and
// POST /auth/password/redeem (docs/01 §10).
//
// Design:
//   - passwordHistoryDepth retired hashes are kept per user. The CURRENT credential is in
//     user_credential, not here — it is checked separately by HandleChangePassword before any
//     history lookup.
//   - The check runs argon2id verification against each stored hash, so it is as timing-safe
//     as login and carries the same F01 capacity concern (throttle protects this path).
//   - The store is optional in AuthService. When PasswordHistory is nil, no history is recorded
//     or checked — the existing "must differ from current" check still applies.

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// passwordHistoryDepth is the number of RETIRED passwords stored per user. A candidate new
// password is rejected if it matches any of the stored hashes. Combined with the always-checked
// current credential, this prevents reuse of the last (passwordHistoryDepth + 1) passwords.
const passwordHistoryDepth = 4

// ErrPasswordReused is returned when the proposed new password matches a recent retired hash.
var ErrPasswordReused = errors.New("password was used recently; choose a different password")

// PasswordHistoryStore records and retrieves retired password hashes per user.
type PasswordHistoryStore interface {
	// RecordPassword pushes phcHash (a just-retired argon2id PHC string) into the history for
	// (tenantID, userID). The store trims to passwordHistoryDepth entries after each insert,
	// keeping only the most recent ones.
	RecordPassword(ctx context.Context, tenantID, userID, phcHash string) error
	// RecentHashes returns up to n most recently retired PHC hashes for (tenantID, userID),
	// newest first. These are the PREVIOUS credentials, not the current one.
	RecentHashes(ctx context.Context, tenantID, userID string, n int) ([]string, error)
}

// -------------------------------------------------------------------------------------
// InMemory implementation
// -------------------------------------------------------------------------------------

type pwHistEntry struct {
	tenantID string
	userID   string
	hash     string
}

// InMemoryPasswordHistoryStore is the test / dev implementation.
type InMemoryPasswordHistoryStore struct {
	mu      sync.Mutex
	entries []pwHistEntry // ordered newest-first within each (tenant, user) partition
}

var _ PasswordHistoryStore = (*InMemoryPasswordHistoryStore)(nil)

// RecordPassword prepends the hash and trims the per-user list to passwordHistoryDepth entries.
func (s *InMemoryPasswordHistoryStore) RecordPassword(_ context.Context, tenantID, userID, phcHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prepend the new entry.
	s.entries = append([]pwHistEntry{{tenantID: tenantID, userID: userID, hash: phcHash}}, s.entries...)
	// Trim: keep at most passwordHistoryDepth entries for this (tenant, user) pair.
	// Use a fresh slice (not s.entries[:0]) — reusing the backing array would alias the source
	// and corrupt entries as the loop reads from and writes to the same positions.
	var kept []pwHistEntry
	count := 0
	for _, e := range s.entries {
		if e.tenantID == tenantID && e.userID == userID {
			if count >= passwordHistoryDepth {
				continue // drop this old entry
			}
			count++
		}
		kept = append(kept, e)
	}
	s.entries = kept
	return nil
}

// RecentHashes returns up to n retired hashes for (tenantID, userID), newest first.
func (s *InMemoryPasswordHistoryStore) RecentHashes(_ context.Context, tenantID, userID string, n int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.entries {
		if len(out) >= n {
			break
		}
		if e.tenantID == tenantID && e.userID == userID {
			out = append(out, e.hash)
		}
	}
	return out, nil
}

// -------------------------------------------------------------------------------------
// Postgres implementation
// -------------------------------------------------------------------------------------

// PgPasswordHistoryStore is the pgx-backed PasswordHistoryStore.
type PgPasswordHistoryStore struct {
	Pool *pgxpool.Pool
}

var _ PasswordHistoryStore = (*PgPasswordHistoryStore)(nil)

// NewPgPasswordHistoryStore constructs a PgPasswordHistoryStore.
func NewPgPasswordHistoryStore(pool *pgxpool.Pool) *PgPasswordHistoryStore {
	return &PgPasswordHistoryStore{Pool: pool}
}

// RecordPassword inserts the hash and trims the per-user history to passwordHistoryDepth rows.
// Both operations run under withTenant (RLS pinned) so the policy confines them to the right tenant.
func (s *PgPasswordHistoryStore) RecordPassword(ctx context.Context, tenantID, userID, phcHash string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Insert the new entry.
		_, err := tx.Exec(ctx, `
			INSERT INTO user_password_history (tenant_id, user_id, phc_hash)
			VALUES ($1, $2, $3)
		`, tenantID, userID, phcHash)
		if err != nil {
			return err
		}
		// Trim: delete any rows beyond the most recent passwordHistoryDepth for this user.
		// The subquery selects the IDs of the rows to KEEP (newest N), the DELETE removes everything
		// else for the same user. This is a single statement — no gap between count and delete.
		_, err = tx.Exec(ctx, `
			DELETE FROM user_password_history
			WHERE tenant_id = $1 AND user_id = $2
			  AND id NOT IN (
			      SELECT id FROM user_password_history
			      WHERE tenant_id = $1 AND user_id = $2
			      ORDER BY recorded_at DESC
			      LIMIT $3
			  )
		`, tenantID, userID, passwordHistoryDepth)
		return err
	})
}

// RecentHashes returns up to n most recently retired PHC hashes, newest first.
func (s *PgPasswordHistoryStore) RecentHashes(ctx context.Context, tenantID, userID string, n int) ([]string, error) {
	var hashes []string
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT phc_hash
			FROM user_password_history
			WHERE tenant_id = $1 AND user_id = $2
			ORDER BY recorded_at DESC
			LIMIT $3
		`, tenantID, userID, n)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				return err
			}
			hashes = append(hashes, h)
		}
		return rows.Err()
	})
	return hashes, err
}

// -------------------------------------------------------------------------------------
// Helper used by handlers
// -------------------------------------------------------------------------------------

// checkPasswordHistory verifies that candidate does not match any recently retired hash stored
// for (tenantID, userID). Returns ErrPasswordReused on a match, nil on clear, or a store/argon2
// error when the check cannot be completed.
//
// When store is nil the check is skipped (no history configured).
func checkPasswordHistory(ctx context.Context, store PasswordHistoryStore, tenantID, userID, candidate string) error {
	if store == nil {
		return nil
	}
	hashes, err := store.RecentHashes(ctx, tenantID, userID, passwordHistoryDepth)
	if err != nil {
		return err
	}
	for _, h := range hashes {
		match, verr := VerifyPasswordCtx(ctx, h, candidate)
		if IsHashCapacityError(verr) {
			return verr
		}
		if verr != nil {
			// Corrupt stored hash — skip it rather than blocking the change.
			continue
		}
		if match {
			return ErrPasswordReused
		}
	}
	return nil
}
