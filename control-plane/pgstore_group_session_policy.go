package controlplane

// PgGroupSessionPolicyStore — the pgx-backed GroupSessionPolicyStore over `group_session_policy`
// (migrations/0034 + 0035 + 0040 + 0043 + 0044 + 0045 + 0046), RLS-scoped per tenant via withTenant. Mirrors PgTenantSessionPolicyStore:
// Get returns the ZERO policy for no row; Set is an upsert, and a policy that IsDefault DELETEs the row so
// List shows only groups an admin has decided something about (the fake does the same). Since 0035 the row
// has carried more than one setting — the seat cap, enforce_view_only and, since 0040,
// allow_backstage_under_view_only — which is why the delete test is IsDefault() and not a bare cap == 0.
//
// EVERY column added here has to land in THREE places in this file: Get's SELECT + Scan, Set's INSERT column
// list + ON CONFLICT DO UPDATE SET, and List's SELECT + Scan. A column added to two of the three is not a
// compile error; it is a field that reads back as false from whichever path was missed. The ENFORCEMENT read
// is not here — it lives in
// PgSessionRecordStore.StartSessionWithinLimit, which counts the group's OPEN sessions inside the same
// advisory-locked transaction as the insert. A cross-tenant write is impossible: the composite FK to
// machine_group(tenant_id, id) has no row for another tenant's group (RLS hides it), so the INSERT 23503s.

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgGroupSessionPolicyStore is the pgx-backed GroupSessionPolicyStore.
type PgGroupSessionPolicyStore struct {
	Pool *pgxpool.Pool
}

// NewPgGroupSessionPolicyStore constructs a PgGroupSessionPolicyStore.
func NewPgGroupSessionPolicyStore(pool *pgxpool.Pool) *PgGroupSessionPolicyStore {
	return &PgGroupSessionPolicyStore{Pool: pool}
}

var _ GroupSessionPolicyStore = (*PgGroupSessionPolicyStore)(nil)

// Get implements GroupSessionPolicyStore: the group's stored policy, or the zero policy (unlimited, not
// view-only) when no row exists. GroupID is filled in either way.
func (s *PgGroupSessionPolicyStore) Get(ctx context.Context, tenantID, groupID string) (GroupSessionPolicy, error) {
	out := GroupSessionPolicy{GroupID: groupID}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT max_concurrent_sessions, enforce_view_only, allow_backstage_under_view_only,
			        prohibit_recording, require_recording, max_session_duration_seconds, max_idle_seconds
			 FROM group_session_policy WHERE group_id = $1`,
			groupID).Scan(&out.MaxConcurrentSessions, &out.EnforceViewOnly, &out.AllowBackstageUnderViewOnly,
			&out.ProhibitRecording, &out.RequireRecording, &out.MaxSessionDurationSeconds, &out.MaxIdleSeconds)
		if errors.Is(e, pgx.ErrNoRows) {
			// No row is a real answer (the default policy), not an error — same as an unset tenant policy.
			return nil
		}
		return e
	})
	return out, err
}

// Set implements GroupSessionPolicyStore: upsert the group's policy. An all-default policy DELETEs the row
// (so List reflects only groups an admin has decided something about) — matching the in-memory fake.
//
// The delete test is policy.IsDefault(), NOT cap == 0: since loop 80 the row also carries enforce_view_only
// (and since 0040 allow_backstage_under_view_only), and deleting on a zero cap alone would silently drop a
// group's view-only mandate when its cap was cleared.
// The composite FK makes a write against another tenant's (or a nonexistent) group fail with 23503; the
// handler pre-checks existence so that is only a backstop.
func (s *PgGroupSessionPolicyStore) Set(ctx context.Context, tenantID, groupID string, policy GroupSessionPolicy) error {
	return s.set(ctx, tenantID, groupID, policy, nil)
}

// SetIfTree implements GroupSessionPolicyStore: Set conditional on the tenant's group tree still being at
// expectTree (docs/62 R2); the shared tree lock is held to the end of the transaction, so a reparent cannot
// interleave between the check and the write.
func (s *PgGroupSessionPolicyStore) SetIfTree(ctx context.Context, tenantID, groupID string, policy GroupSessionPolicy, expectTree int64) error {
	return s.set(ctx, tenantID, groupID, policy, &expectTree)
}

func (s *PgGroupSessionPolicyStore) set(ctx context.Context, tenantID, groupID string, policy GroupSessionPolicy, expectTree *int64) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if expectTree != nil {
			if err := checkGroupTreeVersionTx(ctx, tx, tenantID, *expectTree); err != nil {
				return err
			}
		}
		if policy.IsDefault() {
			_, err := tx.Exec(ctx, `DELETE FROM group_session_policy WHERE group_id = $1`, groupID)
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO group_session_policy (tenant_id, group_id, max_concurrent_sessions, enforce_view_only,
			                                  allow_backstage_under_view_only, prohibit_recording, require_recording,
			                                  max_session_duration_seconds, max_idle_seconds, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
			ON CONFLICT (tenant_id, group_id)
			DO UPDATE SET max_concurrent_sessions          = EXCLUDED.max_concurrent_sessions,
			              enforce_view_only                = EXCLUDED.enforce_view_only,
			              allow_backstage_under_view_only  = EXCLUDED.allow_backstage_under_view_only,
			              prohibit_recording               = EXCLUDED.prohibit_recording,
			              require_recording                = EXCLUDED.require_recording,
			              max_session_duration_seconds     = EXCLUDED.max_session_duration_seconds,
			              max_idle_seconds                 = EXCLUDED.max_idle_seconds,
			              updated_at                       = now()
		`, tenantID, groupID, policy.MaxConcurrentSessions, policy.EnforceViewOnly, policy.AllowBackstageUnderViewOnly,
			policy.ProhibitRecording, policy.RequireRecording, policy.MaxSessionDurationSeconds, policy.MaxIdleSeconds)
		return err
	})
}

// List implements GroupSessionPolicyStore: every group in the tenant with a policy row, ordered by group id.
// COLLATE "C" forces byte-order so the order matches the fake's Go string sort on the ::text form (uuids are
// lowercase-ASCII so it cannot bite today, but the discipline keeps fake and pg in step).
func (s *PgGroupSessionPolicyStore) List(ctx context.Context, tenantID string) ([]GroupSessionPolicy, error) {
	out := []GroupSessionPolicy{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		out = out[:0]
		rows, err := tx.Query(ctx,
			`SELECT group_id::text, max_concurrent_sessions, enforce_view_only, allow_backstage_under_view_only,
			        prohibit_recording, require_recording, max_session_duration_seconds, max_idle_seconds
			 FROM group_session_policy
			 ORDER BY group_id::text COLLATE "C"`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c GroupSessionPolicy
			if err := rows.Scan(&c.GroupID, &c.MaxConcurrentSessions, &c.EnforceViewOnly,
				&c.AllowBackstageUnderViewOnly, &c.ProhibitRecording, &c.RequireRecording,
				&c.MaxSessionDurationSeconds, &c.MaxIdleSeconds); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteForGroup implements GroupSessionPolicyStore. In Postgres the row is ALREADY gone by the time the
// handler calls this -- migration 0034's composite FK carries ON DELETE CASCADE -- so this is normally a
// no-op DELETE. It is implemented rather than stubbed so the two stores share one contract: the in-memory
// store has no cascade and genuinely needs the call, and a same-named method that did nothing here would
// hide a future schema change that dropped the cascade.
func (s *PgGroupSessionPolicyStore) DeleteForGroup(ctx context.Context, tenantID, groupID string) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM group_session_policy WHERE group_id = $1`, groupID)
		return err
	})
}
