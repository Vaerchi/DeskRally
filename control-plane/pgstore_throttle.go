package controlplane

// PgThrottleStore — the Postgres-backed ThrottleStore (migrations/0015_throttle.sql), giving
// every control-plane replica ONE shared online-guessing budget instead of a per-process one.
//
// Unlike every other Pg store here it deliberately does NOT go through withTenant/RLS: throttle
// state is global, pre-tenant by nature (login/redeem run before any tenant is resolved, IP keys
// have no tenant at all), so queries run directly on the pool — the same posture as the
// SECURITY DEFINER cp_* lookups on other pre-tenant paths, minus the function (the table holds
// no tenant data to confine).
//
// Atomicity: Bump is ONE upsert whose conflict arm both increments and applies the idle-decay
// restart, so two replicas failing the same key concurrently serialize on the row lock and never
// lose an increment (the race the in-memory mutex used to hide).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxThrottleKeyLen bounds stored key width: account keys embed attacker-supplied slugs/emails
// (request bodies are capped, but 64 KiB of key per row is still an amplification). Longer keys
// are stored as a fixed-width digest form; the digest keeps per-key semantics exactly.
const maxThrottleKeyLen = 256

// PgThrottleStore is the pgx-backed ThrottleStore.
type PgThrottleStore struct {
	Pool *pgxpool.Pool
}

// NewPgThrottleStore constructs a PgThrottleStore.
func NewPgThrottleStore(pool *pgxpool.Pool) *PgThrottleStore { return &PgThrottleStore{Pool: pool} }

// VerifyReadable reports whether this store can actually SELECT from its table, so a caller can
// refuse to start rather than discover it one login at a time.
//
// Found during a restore rehearsal against the live deployment, and it is the nastiest shape a
// failed backup takes. `pg_dump --no-privileges` strips every GRANT. Restoring that dump and running
// `migrate` does NOT put them back: the ledger reports the schema current, so `applied=0 skipped=39`
// and 0005_app_role.sql never re-runs — it only resets rmt_app's password. What comes up starts
// cleanly, logs "production mode", derives the correct grant_issuer_pubkey, and then answers EVERY
// login with:
//
//	HTTP 429 {"error":"too many attempts"}
//
// Nobody is being rate-limited. The throttle cannot read `throttle_counter`, so it fails closed —
// which is the correct behaviour, and is indistinguishable from the thing it is not. The real cause
// (`permission denied for table throttle_counter`, SQLSTATE 42501) appears only in container logs.
//
// The engineer who found it had full log access and still spent three wrong hypotheses on it, one of
// them the true-but-misleading "throttle locks are rows and survive a restart". An operator
// mid-recovery has less. This does not change the fail-closed behaviour at request time; it moves
// the DISCOVERY from an outage to a boot log.
//
// A COUNT, not a `LIMIT 1`: an empty table and an unreadable one must give different answers, and
// `SELECT ... LIMIT 1` returns no rows in both cases. `count(*)` errors on the permission failure and
// returns 0 on an empty table, which is exactly the distinction being drawn.
func (s *PgThrottleStore) VerifyReadable(ctx context.Context) error {
	var n int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM throttle_counter`).Scan(&n); err != nil {
		return fmt.Errorf("throttle_counter is not readable: %w", err)
	}
	return nil
}

var _ ThrottleStore = (*PgThrottleStore)(nil)

// storeKey normalizes a key into something PostgreSQL can actually hold: long keys — and any key
// carrying a byte `text` cannot represent — become "sha256:<hex>". Distinct keys stay distinct, and
// the digest form cannot collide with a verbatim key — every real key starts with its endpoint
// namespace ("login:", "totp:", "redeem:", …), never "sha256:".
//
// The NUL clause is defence at the STORAGE BOUNDARY, deliberately kept even though `accountKey` no
// longer emits one. A key is assembled from tenant ids, emails and uuids, and the cost of one of
// those someday carrying an unstorable byte is not a bad row — the throttle fails CLOSED, so it is
// a permanent 429 on a credential endpoint, which is exactly how the NUL separator went unnoticed.
// Normalizing here means no future key shape can reintroduce that outage.
func storeKey(key string) string {
	if len(key) <= maxThrottleKeyLen && !strings.ContainsRune(key, 0) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func storeKeys(keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = storeKey(k)
	}
	return out
}

// Bump implements ThrottleStore: one atomic upsert. The conflict arm restarts an idle-decayed
// entry (last failure before staleBefore, no live lock) at 1, otherwise increments.
func (s *PgThrottleStore) Bump(ctx context.Context, key string, now, staleBefore time.Time) (int, error) {
	var failures int
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO throttle_counter (key, failures, last_failure)
		VALUES ($1, 1, $2)
		ON CONFLICT (key) DO UPDATE SET
			failures = CASE
				WHEN throttle_counter.last_failure < $3
				     AND (throttle_counter.locked_until IS NULL OR throttle_counter.locked_until < $2)
				THEN 1
				ELSE throttle_counter.failures + 1
			END,
			last_failure = $2
		RETURNING failures
	`, storeKey(key), now, staleBefore).Scan(&failures)
	return failures, err
}

// Reserve implements ThrottleStore: the check and the charge are ONE upsert. The conflict arm's
// WHERE refuses (no row returned) while a lock is live; otherwise it applies the idle-decay
// restart, increments, and stores the lock the new count earns, all under the row lock.
func (s *PgThrottleStore) Reserve(ctx context.Context, key string, now, staleBefore time.Time, free int, base, max time.Duration) (bool, time.Duration, error) {
	var failures int
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO throttle_counter AS t (key, failures, last_failure, locked_until)
		VALUES ($1, 1, $2,
			CASE WHEN 1 > $4::int THEN $2::timestamptz + LEAST($6::float8, $5::float8) * interval '1 second' END)
		ON CONFLICT (key) DO UPDATE SET
			failures = CASE
				WHEN t.last_failure < $3 AND (t.locked_until IS NULL OR t.locked_until < $2) THEN 1
				ELSE t.failures + 1
			END,
			last_failure = $2,
			locked_until = CASE
				WHEN (CASE WHEN t.last_failure < $3 AND (t.locked_until IS NULL OR t.locked_until < $2)
				           THEN 1 ELSE t.failures + 1 END) > $4::int
				THEN $2::timestamptz + LEAST($6::float8,
					$5::float8 * power(2::float8, LEAST(60::float8, ((CASE WHEN t.last_failure < $3 AND (t.locked_until IS NULL OR t.locked_until < $2)
					           THEN 1 ELSE t.failures + 1 END) - $4::int - 1)::float8))) * interval '1 second'
				ELSE NULL
			END
		WHERE t.locked_until IS NULL OR t.locked_until <= $2
		RETURNING failures
	`, storeKey(key), now, staleBefore, free, base.Seconds(), max.Seconds()).Scan(&failures)
	if err == nil {
		return true, 0, nil
	}
	if err != pgx.ErrNoRows {
		return false, 0, err
	}
	until, merr := s.MaxLockedUntil(ctx, []string{key}, now)
	if merr != nil {
		return false, 0, merr
	}
	wait := until.Sub(now)
	if wait <= 0 {
		wait = time.Second
	}
	return false, wait, nil
}

// Unbump implements ThrottleStore: refund one reserved failure.
func (s *PgThrottleStore) Unbump(ctx context.Context, key string, free int) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE throttle_counter SET
			failures = GREATEST(failures - 1, 0),
			locked_until = CASE WHEN failures - 1 <= $2::int THEN NULL ELSE locked_until END
		WHERE key = $1
	`, storeKey(key), free)
	return err
}

// SetLock implements ThrottleStore. The zero time clears the lock (stored as NULL).
func (s *PgThrottleStore) SetLock(ctx context.Context, key string, until time.Time) error {
	var untilArg any
	if !until.IsZero() {
		untilArg = until
	}
	_, err := s.Pool.Exec(ctx,
		`UPDATE throttle_counter SET locked_until = $2 WHERE key = $1`, storeKey(key), untilArg)
	return err
}

// MaxLockedUntil implements ThrottleStore: the latest still-live lockout among keys.
func (s *PgThrottleStore) MaxLockedUntil(ctx context.Context, keys []string, now time.Time) (time.Time, error) {
	var until *time.Time
	err := s.Pool.QueryRow(ctx, `
		SELECT MAX(locked_until) FROM throttle_counter
		WHERE key = ANY($1) AND locked_until > $2
	`, storeKeys(keys), now).Scan(&until)
	if err != nil && err != pgx.ErrNoRows {
		return time.Time{}, err
	}
	if until == nil {
		return time.Time{}, nil
	}
	return *until, nil
}

// Clear implements ThrottleStore.
func (s *PgThrottleStore) Clear(ctx context.Context, keys []string) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM throttle_counter WHERE key = ANY($1)`, storeKeys(keys))
	return err
}

// Cleanup implements ThrottleStore: drop idle, unlocked entries (the map GC equivalent).
func (s *PgThrottleStore) Cleanup(ctx context.Context, staleBefore, now time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		DELETE FROM throttle_counter
		WHERE last_failure < $1 AND (locked_until IS NULL OR locked_until < $2)
	`, staleBefore, now)
	return err
}
