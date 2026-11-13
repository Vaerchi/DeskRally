package controlplane

// PgAttendedStore — the pgx-backed AttendedStore over `attended_session` + cp_attended_*
// (migrations/0013_attended_sessions.sql).
//
// Technician methods (Create/Get/MarkActive/End/SetPromoteToken) run tenant-pinned via withTenant
// (RLS confines them to the caller's tenant). The guest methods (Redeem/Consent/ByToken) are the
// PRE-TENANT path — the guest presents only a code or attend token, with no tenant context — so
// they run on the pool directly through the SECURITY DEFINER cp_attended_* functions, exactly like
// enrollment-token redemption (pgstore_enrollment.go).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgAttendedStore is the pgx-backed AttendedStore.
type PgAttendedStore struct {
	Pool *pgxpool.Pool
	// LookupPool, when set, serves the anonymous redeem lookup instead of Pool (docs/66 release gate R1). nil uses Pool.
	LookupPool *pgxpool.Pool
}

// NewPgAttendedStore constructs a PgAttendedStore.
func NewPgAttendedStore(pool *pgxpool.Pool) *PgAttendedStore {
	return &PgAttendedStore{Pool: pool}
}

var _ AttendedStore = (*PgAttendedStore)(nil)

// attendedColumns is the projection shared by the scans. code_hash/token_hash are deliberately
// absent — they never leave the database. promote_token IS included (the guest reads it via status).
//
// attendedColumns and scanAttended are ONE unit and must be edited together: they are positional
// pairs with no compile-time coupling, and adjacent entries share types (three strings in a row,
// three *time.Time in a row), so a reordering typechecks cleanly and only a pg test asserting
// VALUE-DISTINCT fields can catch it. Every read path goes through this pair, which is why adding a
// column here is all it takes for Get/MarkActive/End/Consent/ByToken to carry it.
//
// promote_result_* columns added by migration 0052: nullable; absent until the guest calls
// /promote-complete. scanAttended populates PromoteResult only when promote_result_at IS NOT NULL.
const attendedColumns = `
	id::text, tenant_id::text, group_id::text, technician_id::text, COALESCE(device_id,''),
	state, reason, consent_user, promote_token, require_session_policy,
	created_at, expires_at, redeemed_at, consented_at, ended_at, agent_pubkey,
	promote_result_success, COALESCE(promote_result_error,''), promote_result_at,
	COALESCE(promote_attempt_nonce,'')`

func scanAttended(row pgx.Row) (*AttendedSession, error) {
	var a AttendedSession
	var prSuccess *bool
	var prError string
	var prAt *time.Time
	if err := row.Scan(&a.ID, &a.TenantID, &a.GroupID, &a.TechnicianID, &a.DeviceID,
		&a.State, &a.Reason, &a.ConsentUser, &a.PromoteToken, &a.RequireSessionPolicy,
		&a.CreatedAt, &a.ExpiresAt, &a.RedeemedAt, &a.ConsentedAt, &a.EndedAt, &a.AgentPubkey,
		&prSuccess, &prError, &prAt, &a.PromoteAttemptNonce); err != nil {
		return nil, err
	}
	if prAt != nil {
		s := prSuccess != nil && *prSuccess
		a.PromoteResult = &PromoteResult{Success: s, Error: prError, At: *prAt}
	}
	return &a, nil
}

// Create implements AttendedStore: mint the code, insert the pending row tenant-pinned, return the
// plaintext code once.
func (s *PgAttendedStore) Create(ctx context.Context, tenantID string, sess *AttendedSession) (string, error) {
	// The INSERT names a FIXED column list and the RETURNING re-reads only the store-assigned
	// fields, so any other field a caller pre-set on `sess` is dropped here. That is deliberate for
	// require_session_policy in particular: the floor is decided at REDEEM, never at create, and the
	// fake's Create overwrites it to false to keep the two stores telling the same story. Do not
	// "fix" this by widening the INSERT.
	code, err := mintAttendCode(func(_ string, hash []byte) error {
		err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `
			INSERT INTO attended_session (tenant_id, group_id, technician_id, code_hash, reason, expires_at)
			VALUES ($1, $2, $3, $4, $5, now() + $6::interval)
			RETURNING id::text, state, created_at, expires_at
		`, tenantID, sess.GroupID, sess.TechnicianID, hash, sess.Reason,
				fmt.Sprintf("%d seconds", int(AttendedCodeTTL.Seconds()))).
				Scan(&sess.ID, &sess.State, &sess.CreatedAt, &sess.ExpiresAt)
		})
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" && conflict.ConstraintName == "attended_session_code_hash_idx" {
			return errAttendCodeCollision
		}
		return err
	})
	if err != nil {
		return "", err
	}
	sess.TenantID = tenantID
	// Zeroed for the same reason the fake's Create zeroes it: both stores must hand back the SAME created
	// session. The INSERT above already ignores a caller-set value, so the row is right either way — but
	// without this line the STRUCT still carries the caller's claim, and a handler that believed it would
	// act on a floor no database row records. That is the fake/pg divergence class this repo keeps paying
	// for, in the one direction a pg-only test would miss.
	//
	// SCOPED CLAIM, so nobody reads more into it than it earns: this makes the two Creates agree about
	// `require_session_policy`, not about everything. Five other fields (ConsentUser, PromoteToken,
	// RedeemedAt, ConsentedAt, EndedAt) are still copied by the fake and dropped by this INSERT, and the
	// fake additionally zeroes DeviceID where this store does not. All of it is unreachable today —
	// handleCreateAttended sets only GroupID/TechnicianID/Reason — and the correct fix, if anyone ever
	// needs one, is to zero every non-inserted field in BOTH Creates, never to widen the INSERT.
	sess.RequireSessionPolicy = false
	sess.AgentPubkey = ""
	return code, nil
}

// Get implements AttendedStore.
func (s *PgAttendedStore) Get(ctx context.Context, tenantID, id string) (*AttendedSession, error) {
	// An id no `uuid` column could hold is a miss, not a 500 (pathid.go).
	if namesNoUUIDRow(id) {
		return nil, ErrAttendedNotFound
	}
	var out *AttendedSession
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		a, err := scanAttended(tx.QueryRow(ctx, `SELECT `+attendedColumns+` FROM attended_session WHERE id = $1`, id))
		if err != nil {
			return err
		}
		out = a
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAttendedNotFound
		}
		return nil, err
	}
	return out, nil
}

// MarkActive implements AttendedStore: consented→active (idempotent for active). A row that exists
// but is in another state → ErrAttendedNotConsented; an unknown id → ErrAttendedNotFound.
func (s *PgAttendedStore) MarkActive(ctx context.Context, tenantID, id string) (*AttendedSession, error) {
	var out *AttendedSession
	var notConsented bool
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		a, err := scanAttended(tx.QueryRow(ctx, `
			UPDATE attended_session SET state = 'active'
			WHERE id = $1 AND state IN ('consented','active')
			RETURNING `+attendedColumns, id))
		if errors.Is(err, pgx.ErrNoRows) {
			// Distinguish "not consented yet" from "unknown" so the handler returns 409 vs 404.
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT true FROM attended_session WHERE id = $1`, id).Scan(&exists); e != nil {
				return ErrAttendedNotFound
			}
			notConsented = true
			return nil
		}
		if err != nil {
			return err
		}
		out = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	if notConsented {
		return nil, ErrAttendedNotConsented
	}
	return out, nil
}

// ReassignTechnician implements AttendedStore: the previous technician is read under the row lock
// in the same transaction as the write, so concurrent handoffs each report the one they replaced.
func (s *PgAttendedStore) ReassignTechnician(ctx context.Context, tenantID, id, technicianID string) (string, error) {
	if namesNoUUIDRow(id) {
		return "", ErrAttendedNotFound
	}
	var prev string
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT technician_id::text FROM attended_session WHERE id = $1 FOR UPDATE`, id).Scan(&prev); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrAttendedNotFound
			}
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE attended_session SET technician_id = $2 WHERE id = $1`, id, technicianID)
		return err
	})
	if err != nil {
		return "", err
	}
	return prev, nil
}

// End implements AttendedStore: mark ended (idempotent), clear the promote token, reap the ephemeral
// machine — all tenant-pinned in one transaction.
func (s *PgAttendedStore) End(ctx context.Context, tenantID, id string) (*AttendedSession, error) {
	var out *AttendedSession
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		a, err := scanAttended(tx.QueryRow(ctx, `
			UPDATE attended_session
			SET state = 'ended', ended_at = COALESCE(ended_at, now()), promote_token = ''
			WHERE id = $1
			RETURNING `+attendedColumns, id))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrAttendedNotFound
			}
			return err
		}
		out = a
		if a.DeviceID != "" {
			if _, err := tx.Exec(ctx, `DELETE FROM machine WHERE device_id = $1 AND ephemeral`, a.DeviceID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetRequireSessionPolicy implements AttendedStore: record that redemption told this guest to open
// the session floored. Deliberately `SET require_session_policy = true` rather than taking a value —
// see the interface comment for why the flag is write-once.
func (s *PgAttendedStore) SetRequireSessionPolicy(ctx context.Context, tenantID, id string) error {
	// An id no `uuid` column could hold is a miss, not a 500 (pathid.go), same as Get.
	if namesNoUUIDRow(id) {
		return ErrAttendedNotFound
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE attended_session SET require_session_policy = true WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrAttendedNotFound
		}
		return nil
	})
}

// SetPromoteToken implements AttendedStore.
func (s *PgAttendedStore) SetPromoteToken(ctx context.Context, tenantID, id, plaintext string) error {
	if namesNoUUIDRow(id) {
		return ErrAttendedNotFound
	}
	// Mint a nonce for new/retry attempts. Empty for revocation — the SQL sets promote_attempt_nonce=''
	// on revocation so a late guest call cannot match an empty nonce and slip through.
	var nonce string
	if plaintext != "" {
		n, err := newPromoteAttemptNonce()
		if err != nil {
			return err
		}
		nonce = n
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Attempt-binding invariants on SET:
		//
		// Non-empty token (new or retry attempt):
		//   • Stamp promote_requested_at (COALESCE — don't reset the original clock).
		//   • Mint a fresh promote_attempt_nonce so a delayed old attempt's result is rejected
		//     by the nonce mismatch guard before the no-overwrite guard can wrongly block the new one.
		//   • Clear prior result columns so the UI sees this attempt's outcome, not a stale one.
		//
		// Empty token (explicit revocation, NOT called by End):
		//   • Clear promote_requested_at so cp_attended_set_promote_result rejects any late call.
		//   • Clear promote_attempt_nonce so no late result can match an empty nonce accidentally.
		//   • Keep promote_result_* intact (historical record of the last completed attempt).
		//
		// End() directly sets promote_token='' without calling SetPromoteToken, so the
		// End path does NOT clear promote_requested_at — an in-progress install can still
		// post its result within the bounded post-end grace window.
		ct, err := tx.Exec(ctx, `UPDATE attended_session
			SET promote_token = $2,
			    promote_attempt_nonce = CASE WHEN $2 != '' THEN $3 ELSE '' END,
			    promote_requested_at = CASE
			        WHEN $2 != '' THEN COALESCE(promote_requested_at, now())
			        ELSE NULL
			    END,
			    promote_result_success = CASE WHEN $2 != '' THEN NULL ELSE promote_result_success END,
			    promote_result_error   = CASE WHEN $2 != '' THEN '' ELSE promote_result_error END,
			    promote_result_at      = CASE WHEN $2 != '' THEN NULL ELSE promote_result_at END
			WHERE id = $1 AND ($2 = '' OR state IN ('consented', 'active'))`, id, plaintext, nonce)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM attended_session WHERE id = $1)`, id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrAttendedNotFound
			}
			return ErrAttendedNotPromotable
		}
		return nil
	})
}

// SetPromoteResult implements AttendedStore: record the guest's install outcome keyed by attend
// token. Uses cp_attended_set_promote_result (SECURITY DEFINER, migration 0052) so the UPDATE
// bypasses the tenant-isolation RLS policy — the guest is pre-tenant, exactly as with consent.
func (s *PgAttendedStore) SetPromoteResult(ctx context.Context, attendToken, attemptNonce string, result PromoteResult) error {
	hash := HashToken(attendToken)
	var ok *bool
	if err := s.Pool.QueryRow(ctx,
		`SELECT cp_attended_set_promote_result($1, $2, $3, $4)`,
		hash, result.Success, result.Error, attemptNonce,
	).Scan(&ok); err != nil {
		return err
	}
	if ok == nil {
		return ErrAttendedInvalid // unknown or expired attend token
	}
	if !*ok {
		return ErrAttendedPromoteCompleteConflict
	}
	return nil
}

// Redeem implements AttendedStore via cp_attended_redeem: one atomic transaction validates the code,
// mints the ephemeral machine (device_id minted HERE, server-side), pins the pubkey, records the
// attend-token hash, and advances to redeemed. No row → invalid (generic).
func (s *PgAttendedStore) Redeem(ctx context.Context, code, pubkeyHex, name string) (*AttendedRedeem, error) {
	return s.redeem(ctx, code, pubkeyHex, name, RedeemScope{Unscoped: true})
}

// RedeemScoped implements AttendedStore via cp_attended_redeem_scoped (migration 0071): the host's CURRENT
// state is resolved and enforced inside the same SQL statement that takes the row lock, with a bounded
// (50 ms) lock wait. An unscoped redemption keeps calling the six-argument cp_attended_redeem, the wrapper,
// so a deployment on the old call shape behaves exactly as before.
func (s *PgAttendedStore) RedeemScoped(ctx context.Context, code, pubkeyHex, name string, scope RedeemScope) (*AttendedRedeem, error) {
	return s.redeem(ctx, code, pubkeyHex, name, scope)
}

func (s *PgAttendedStore) redeem(ctx context.Context, code, pubkeyHex, name string, scope RedeemScope) (*AttendedRedeem, error) {
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("attended pubkey is not valid hex: %w", err)
	}
	attendToken, err := newEnrollmentSecret()
	if err != nil {
		return nil, err
	}
	deviceID := newUUID()
	var r AttendedRedeem
	args := []any{HashToken(normalizeAttendCode(code)), pub, name, deviceID, HashToken(attendToken),
		time.Now().Add(AttendedSessionTTL)}
	// Bounded lifecycle (pgbounded.go, docs/66 2f): explicit acquire, socket deadline, a failed connection is
	// destroyed and never returned to the pool.
	err = boundedLookup(ctx, lookupPoolOr(s.LookupPool, s.Pool), func(c *pgxpool.Conn) error {
		var row pgx.Row
		if scope.Unscoped {
			row = c.QueryRow(ctx, `
		SELECT session_id::text, tenant_id::text, group_id::text, device_id
		FROM cp_attended_redeem($1, $2, $3, $4, $5, $6)
	`, args...)
		} else {
			row = c.QueryRow(ctx, `
		SELECT session_id::text, tenant_id::text, group_id::text, device_id
		FROM cp_attended_redeem_scoped($1, $2, $3, $4, $5, $6, $7, false)
	`, append(args, scope.Host)...)
		}
		return row.Scan(&r.SessionID, &r.TenantID, &r.GroupID, &r.DeviceID)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAttendedInvalid
		}
		return nil, err
	}
	r.AttendToken = attendToken
	return &r, nil
}

// Consent implements AttendedStore via cp_attended_consent (PRE-TENANT, by attend token).
func (s *PgAttendedStore) Consent(ctx context.Context, attendToken string, accept bool, consentUser string) (*AttendedSession, error) {
	a, err := scanAttended(s.Pool.QueryRow(ctx, `
		SELECT `+attendedColumns+` FROM cp_attended_consent($1, $2, $3)
	`, HashToken(attendToken), accept, consentUser))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAttendedInvalid
		}
		return nil, err
	}
	return a, nil
}

// ByToken implements AttendedStore via cp_attended_by_token (PRE-TENANT, status polling).
func (s *PgAttendedStore) ByToken(ctx context.Context, attendToken string) (*AttendedSession, error) {
	a, err := scanAttended(s.Pool.QueryRow(ctx, `
		SELECT `+attendedColumns+` FROM cp_attended_by_token($1)
	`, HashToken(attendToken)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAttendedInvalid
		}
		return nil, err
	}
	return a, nil
}

// List filters before LIMIT so inaccessible rows neither leak nor hide permitted sessions.
func (s *PgAttendedStore) List(ctx context.Context, tenantID string, scope GroupScope, limit, offset int) ([]AttendedSession, error) {
	out := make([]AttendedSession, 0)
	// The COVERED ids (assigned + descendants, docs/62 D3): this reader pushes the scope into SQL instead
	// of going through Covers, so it must read the same expansion Covers does. An empty covered set on a
	// group-limited scope matches nothing (`group_id = ANY('{}')`); it never degrades to tenant-wide.
	groups := scope.CoveredIDs()
	if groups == nil {
		groups = []string{}
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+attendedColumns+` FROM attended_session
   WHERE tenant_id = $1 AND ($2::boolean OR group_id = ANY($3::uuid[]))
   ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5`, tenantID, scope.All, groups, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanAttended(rows)
			if err != nil {
				return err
			}
			out = append(out, *row)
		}
		return rows.Err()
	})
	return out, err
}
