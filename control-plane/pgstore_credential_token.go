package controlplane

// PgCredentialTokenStore — the pgx-backed CredentialTokenStore over `user_credential_token`
// (migrations/0020_credential_token.sql) plus its two SECURITY DEFINER helpers.
//
// Mint and RevokeForUser are management-plane operations with an authenticated caller, so they run
// tenant-pinned via withTenant and RLS confines them. Peek and Consume are the PRE-TENANT path —
// the redeemer has no session, the token hash is the only key — so they run on the pool directly
// through cp_credential_token_peek / cp_credential_token_consume, mirroring how enrollment
// redemption uses cp_enrollment_token_redeem.

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgCredentialTokenStore is the pgx-backed CredentialTokenStore.
type PgCredentialTokenStore struct {
	Pool *pgxpool.Pool
}

// NewPgCredentialTokenStore constructs a PgCredentialTokenStore.
func NewPgCredentialTokenStore(pool *pgxpool.Pool) *PgCredentialTokenStore {
	return &PgCredentialTokenStore{Pool: pool}
}

var _ CredentialTokenStore = (*PgCredentialTokenStore)(nil)

// credentialTokenColumns is the metadata projection. token_hash is deliberately absent: it never
// leaves the database.
const credentialTokenColumns = `
	id::text, tenant_id::text, user_id::text, COALESCE(created_by::text, ''),
	created_at, expires_at, (consumed_at IS NOT NULL), (revoked_at IS NOT NULL)`

func scanCredentialToken(row pgx.Row) (*CredentialToken, error) {
	var t CredentialToken
	if err := row.Scan(&t.ID, &t.TenantID, &t.UserID, &t.CreatedBy,
		&t.CreatedAt, &t.ExpiresAt, &t.Consumed, &t.Revoked); err != nil {
		return nil, err
	}
	t.CreatedAt = t.CreatedAt.UTC()
	t.ExpiresAt = t.ExpiresAt.UTC()
	return &t, nil
}

// Mint implements CredentialTokenStore.
//
// ONE TRANSACTION IS NOT ENOUGH TO MAKE "at most one live link" TRUE, and the first version of this
// method assumed it was. Under READ COMMITTED — which withTenant pins deliberately — the supersede
// UPDATE cannot see a row a concurrent transaction has INSERTed but not committed, and there is
// nothing for it to block on, so two mints for the same user interleave like this:
//
//	T1  UPDATE … SET revoked_at (sees nothing to revoke)   T2  UPDATE … SET revoked_at (cannot see T1's row)
//	T1  INSERT link A                                      T2  INSERT link B
//	T1  COMMIT                                             T2  COMMIT      → A and B are BOTH live
//
// Two live account-takeover links while the administrator who clicked twice believes there is one,
// and while the older one is displayed as superseded. Serialized here with a per-user advisory lock
// taken as the transaction's first act, the same instrument PgMgmtAuditStore.RecordEvent uses to
// order appends: the second mint waits, then its UPDATE sees the first's committed row and revokes
// it. The lock is transaction-scoped, so it is released by COMMIT or ROLLBACK with nothing to leak.
//
// The lock ORDERS the writers; `uq_user_credential_token_one_live` (migration 0020) is what makes
// the invariant true regardless — a partial unique index over the live rows, so a path that skipped
// the lock collides instead of quietly leaving a second live link behind. Same belt-and-braces
// shape as 0019's uq_backstage_audit_tenant_ingest.
//
// The tenant_id written is NOT the parameter — it is SELECTed from the user's own row, the same
// discipline PgUserStore.SetPassword uses and for the same reason: app_user is read under RLS, so a
// user id belonging to another tenant matches NO row, inserts nothing, and surfaces as ErrNoUser.
// Passing the tenant in directly would let a caller that resolved the wrong user mint a takeover
// token stamped with the pinned tenant, which the RLS WITH CHECK would accept because the row it is
// handed looks in-tenant. Deriving it from the row being credentialed makes "whose account does
// this token unlock" a fact the database decides.
//
// Disabled users are refused here as well as in the redeem functions: minting a link nobody can
// redeem is a silent failure, and reporting it at mint time is what tells the administrator that
// the account they are trying to help is disabled.
func (s *PgCredentialTokenStore) Mint(ctx context.Context, tenantID, userID, createdBy string, expiresAt time.Time) (string, *CredentialToken, error) {
	plaintext, err := newEnrollmentSecret()
	if err != nil {
		return "", nil, err
	}
	var tok *CredentialToken
	err = withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Bound the WAIT for the per-user lock, for the reason the two audit-chain lock sites state:
		// unbounded waiters sit on pgxpool connections until the pool is empty and every tenant's
		// requests stall, whereas a bounded wait fails fast, loudly, and confined to the one user.
		// is_local = true, so it reverts when the transaction ends — it must, since the connection
		// goes back to the pool.
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
			strconv.FormatInt(mgmtAuditLockWait.Milliseconds(), 10)); err != nil {
			return err
		}
		// Serialize mints for THIS user before reading anything. hashtextextended keys the lock on
		// the user id; a hash collision between two different users costs one of them a brief wait
		// and nothing else, which is why a hash is acceptable where a shared counter would not be.
		//
		// The key is NAMESPACED and CANONICAL, matching 'mgmt_audit_chain:' and
		// 'backstage_audit_chain:' at the sibling sites:
		//
		//   * namespaced, so this lock cannot collide with a DIFFERENT subsystem's lock that happens
		//     to hash the same — a collision within one namespace is a brief wait, but across
		//     namespaces it is one subsystem blocking on another for no reason;
		//   * canonical, because this is the one predicate here that hashes a STRING. Every other one
		//     compares a `uuid` column and is spelling-insensitive for free. MEASURED before the fix,
		//     with 8 concurrent mints alternating `abc…`/`ABC…` for the SAME user: two locks were
		//     taken, the mints did not serialize, and 3 of 8 died on the
		//     `uq_user_credential_token_one_live` index (SQLSTATE 23505) — surfacing to an
		//     administrator as a 500 on a button they are entitled to press. The invariant itself
		//     held (never two live links), because that index is the backstop; the lock's job is to
		//     stop legitimate callers colliding in the first place.
		//
		// Only the LOCK KEY is canonicalized. The UPDATE and INSERT below keep the raw `userID`:
		// they compare a uuid column, so they are already spelling-insensitive, and rewriting their
		// parameter would be a separate behaviour change with its own blast radius.
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended('credential_token_mint:' || $1, 0))`,
			canonicalUUIDish(userID)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE user_credential_token
			   SET revoked_at = now()
			 WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
		`, userID); err != nil {
			return err
		}
		t, err := scanCredentialToken(tx.QueryRow(ctx, `
			INSERT INTO user_credential_token (tenant_id, user_id, token_hash, created_by, expires_at)
			SELECT u.tenant_id, u.id, $2, NULLIF($3,'')::uuid, $4
			  FROM app_user u
			 WHERE u.id = $1 AND u.disabled_at IS NULL
			RETURNING `+credentialTokenColumns+`
		`, userID, HashToken(plaintext), createdBy, expiresAt))
		if errors.Is(err, pgx.ErrNoRows) {
			// The SELECT matched nothing: an unknown user, a user in another tenant (RLS hid the
			// row), or a disabled one. Fail closed rather than minting a token for an account this
			// caller could not see.
			return ErrNoUser
		}
		if err != nil {
			return err
		}
		tok = t
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return plaintext, tok, nil
}

// Peek implements CredentialTokenStore via the STABLE SECURITY DEFINER lookup: resolve the token
// without consuming it, so the password policy can be applied before the one-shot link is spent.
func (s *PgCredentialTokenStore) Peek(ctx context.Context, plaintext string) (*CredentialToken, error) {
	return s.byHash(ctx, `SELECT `+credentialTokenColumns+` FROM cp_credential_token_peek($1)`, plaintext)
}

// Consume implements CredentialTokenStore via the atomic SECURITY DEFINER consume: one UPDATE
// validates and marks the token used, so two racing redemptions cannot both win. No row means
// invalid — unknown, expired, consumed, revoked, disabled user and suspended tenant are
// indistinguishable to the caller by design.
func (s *PgCredentialTokenStore) Consume(ctx context.Context, plaintext string) (*CredentialToken, error) {
	return s.byHash(ctx, `SELECT `+credentialTokenColumns+` FROM cp_credential_token_consume($1)`, plaintext)
}

// byHash runs one of the pre-tenant helpers on the pool and maps "no row" to the single opaque
// error. It goes to the POOL, never to a request-bound connection: this path has no pinned tenant
// (it is what discovers one), and the SECURITY DEFINER function is the only thing authorized to
// look across tenants.
func (s *PgCredentialTokenStore) byHash(ctx context.Context, sql, plaintext string) (*CredentialToken, error) {
	t, err := scanCredentialToken(s.Pool.QueryRow(ctx, sql, HashToken(plaintext)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCredentialTokenInvalid
		}
		return nil, err
	}
	return t, nil
}

// RevokeForUser implements CredentialTokenStore: cancel every outstanding link for a user. Runs
// tenant-pinned, so RLS confines it to the caller's tenant and a user id from another tenant
// matches no rows and reports 0 — never an error the caller could use to probe for the id.
func (s *PgCredentialTokenStore) RevokeForUser(ctx context.Context, tenantID, userID string) (int, error) {
	// An id no `uuid` column could hold owns no tokens, so nothing is revoked — the same answer the
	// UPDATE would give for a well-formed id naming no user, instead of a 500 (pathid.go).
	if namesNoUUIDRow(userID) {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE user_credential_token
			   SET revoked_at = now()
			 WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
		`, userID)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
