package controlplane

// pgx-backed implementations of the data-plane stores that back the (formerly stubbed)
// protected handlers: session records, management-plane audit, and tenants. Same contract as
// pgstore.go: every tenant-scoped query runs through withTenant, which (a) uses the request's
// PgBinder-bound connection when present and (b) pins app.current_tenant transaction-locally,
// so RLS confines everything to the caller's tenant. None of the queries below carry an
// explicit tenant_id filter in their WHERE clause — that is the point: PostgreSQL enforces it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// isUniqueViolation reports whether err is a PostgreSQL unique_violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isForeignKeyViolation reports whether err is a PostgreSQL foreign_key_violation (SQLSTATE 23503) —
// the composite FK firing when a machine_property names a machine that does not exist IN THE PINNED
// TENANT (another tenant's machine is invisible under RLS, so its (tenant_id, id) pair is absent too).
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// -------------------------------------------------------------------------------------
// PgSessionRecordStore — SessionRecordStore over session_record JOIN machine. The join
// denormalizes the machine's group (authorization scoping), device id, and hostname into the
// returned records; RLS scopes both tables to the pinned tenant.
// -------------------------------------------------------------------------------------

// PgSessionRecordStore is the pgx-backed SessionRecordStore.
type PgSessionRecordStore struct {
	Pool *pgxpool.Pool
}

// NewPgSessionRecordStore constructs a PgSessionRecordStore.
func NewPgSessionRecordStore(pool *pgxpool.Pool) *PgSessionRecordStore {
	return &PgSessionRecordStore{Pool: pool}
}

var _ SessionRecordStore = (*PgSessionRecordStore)(nil)

const selectSessionRecord = `
	SELECT s.id::text, s.tenant_id::text, s.machine_id::text, s.technician_id::text,
	       s.started_at, s.ended_at, s.consent_policy, s.granted_caps,
	       m.group_id::text, m.device_id, m.hostname, m.alias, s.note, s.access,
	       s.transferred_from::text, s.end_reason, s.agent_ended_at
	FROM session_record s
	JOIN machine m ON m.id = s.machine_id
`

// scanSessionRecordFields scans one selectSessionRecord row into r (the transfer columns are nullable).
func scanSessionRecordFields(row pgx.Row, r *SessionRecord) error {
	var transferredFrom, endReason *string
	if err := row.Scan(&r.ID, &r.TenantID, &r.MachineID, &r.TechnicianID,
		&r.StartedAt, &r.EndedAt, &r.ConsentPolicy, &r.GrantedCaps,
		&r.MachineGroupID, &r.MachineDeviceID, &r.MachineName, &r.MachineAlias, &r.Note, &r.Access,
		&transferredFrom, &endReason, &r.AgentEndedAt); err != nil {
		return err
	}
	if transferredFrom != nil {
		r.TransferredFrom = *transferredFrom
	}
	if endReason != nil {
		r.EndReason = *endReason
	}
	return nil
}

func scanSessionRecord(row pgx.Row) (*SessionRecord, error) {
	var r SessionRecord
	if err := scanSessionRecordFields(row, &r); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionRecordNotFound
		}
		return nil, err
	}
	return &r, nil
}

// StartSession implements SessionRecordStore: insert tenant-pinned; the DB assigns id and
// started_at, read back into rec. The composite RLS WITH CHECK + the machine FK confine the
// row to the pinned tenant and a machine within it.
func (s *PgSessionRecordStore) StartSession(ctx context.Context, tenantID string, rec *SessionRecord) error {
	if err := normalizeSessionRecordAccess(rec); err != nil {
		return err
	}
	// Direct observer writers must take the same lock/count path as HTTP admission.
	if rec.Access == "view_only" {
		return s.StartSessionWithinLimit(ctx, tenantID, rec, SessionStartLimits{MaxObserversPerMachine: 2})
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return insertSessionRecordTx(ctx, tx, tenantID, rec)
	})
}

// nullableGroupID maps an empty admitted-group id to SQL NULL (a group-less/ephemeral session), so the
// session_record.group_id snapshot is NULL rather than a failed ”::uuid cast, and never matches a per-group
// count.
func nullableGroupID(groupID string) any {
	if groupID == "" {
		return nil
	}
	return groupID
}

// sessionStartLockWait bounds how long one POST /sessions waits for its tenant's start lock before it
// gives up — the same bound the mgmt-audit and credential-mint advisory-lock sites use, and for the same
// reason (an unbounded waiter pins its pgxpool connection and starves every tenant). 3s is far longer than
// a count+insert takes, so it only trips under genuine overload; a var so a future test can shorten it.
var sessionStartLockWait = 3 * time.Second

// StartSessionWithinLimit implements SessionRecordStore: enforce the tenant's concurrency cap atomically.
//
// The count and the insert run in ONE withTenant transaction, opened by a per-tenant
// pg_advisory_xact_lock so concurrent starts SERIALIZE — without it two starts under READ COMMITTED
// could each SELECT count = limit-1 and both INSERT, exceeding the cap ("one transaction is not
// atomicity"). limit <= 0 is unlimited: skip the lock/count and do the plain insert.
func (s *PgSessionRecordStore) StartSessionWithinLimit(ctx context.Context, tenantID string, rec *SessionRecord, limits SessionStartLimits) error {
	if err := normalizeSessionRecordAccess(rec); err != nil {
		return err
	}
	observerCapApplies := rec.Access == "view_only"
	if observerCapApplies && (limits.MaxObserversPerMachine <= 0 || limits.MaxObserversPerMachine > 2) {
		limits.MaxObserversPerMachine = 2
	}
	// Observers always take the tenant lock, even without tenant/group seat caps. This
	// serializes the per-machine count across CP instances without introducing a second lock order.
	// A session admitted against a group always takes the locked path (docs/62 R7): the capped ancestors
	// are resolved from the CURRENT tree inside the transaction, so "no caps at resolve time" proves nothing.
	groupCapApplies := len(limits.seatCaps()) > 0 || rec.MachineGroupID != "" || limits.GroupID != ""
	if limits.Tenant <= 0 && !groupCapApplies && !observerCapApplies {
		return s.StartSession(ctx, tenantID, rec)
	}
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		return admitSessionTx(ctx, tx, tenantID, rec, limits)
	})
}

// lockSessionAdmissionTx takes the per-tenant admission lock every session start serializes on. Lock
// order for anything that also touches a transfer offer or its sessions is FIXED (docs/51 §9.2):
// this lock FIRST, then the offer row, then S1.
func lockSessionAdmissionTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	// Bound the wait for the per-tenant lock. Unbounded, a burst of starts would sit on pgxpool
	// connections until the pool drains and EVERY tenant stalls — the cross-tenant DoS the mgmt-audit
	// and credential-mint sites bound against. is_local=true reverts it when the tx ends (the
	// connection returns to the pool); a timeout raises 55P03, surfaced as a fast fail-closed error.
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		strconv.FormatInt(sessionStartLockWait.Milliseconds(), 10)); err != nil {
		return err
	}
	// Serialize per-tenant session starts. The key hashes the CANONICAL tenant id (not the caller's
	// spelling) so two spellings of one uuid take the SAME lock; the lock is released at COMMIT. One
	// per-tenant lock also serializes the GROUP count in admitSessionTx — every start for the tenant (in
	// any group) takes this same lock, so two concurrent starts in one group cannot both read "under the cap".
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('session_start:' || $1, 0))`,
		canonicalUUIDish(tenantID))
	return err
}

// admitSessionTx is the count-and-insert body of StartSessionWithinLimit, factored out so a transfer's
// finalize admits S2 through EXACTLY the protocol POST /sessions uses. The caller must already hold the
// tenant admission lock (lockSessionAdmissionTx) inside tx; the counts see every row this tx has already
// written, so a transfer that ends S1 first sees its own seat freed.
func admitSessionTx(ctx context.Context, tx pgx.Tx, tenantID string, rec *SessionRecord, limits SessionStartLimits) error {
	observerCapApplies := rec.Access == "view_only"
	if limits.Tenant > 0 {
		var active int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM session_record WHERE tenant_id = $1 AND ended_at IS NULL`, tenantID).
			Scan(&active); err != nil {
			return err
		}
		if active >= limits.Tenant {
			return ErrConcurrentSessionLimit
		}
	}
	// The STORE is authoritative for which ancestors are capped (docs/62 R7, review finding 1): the caller's
	// GroupCaps were resolved before this transaction and a reparent may have moved the admitted group under
	// a capped ancestor since. So: take the SHARED tree lock (a reparent holds it exclusively until commit),
	// then resolve the capped ancestor-or-self set from the CURRENT tree and policy rows. The caller's caps
	// stay in the set (the union, the stricter of a duplicate wins) only so a direct caller that never wrote a
	// policy row keeps its meaning.
	caps := limits.seatCaps()
	if admitted := admissionGroups(rec, limits); len(admitted) > 0 {
		if err := lockGroupTreeTx(ctx, tx, tenantID, true); err != nil {
			return err
		}
		current, err := currentSeatCapsTx(ctx, tx, tenantID, admitted)
		if err != nil {
			return err
		}
		caps = mergeSeatCaps(caps, current)
	}
	if len(caps) > 0 {
		// Count OPEN sessions ADMITTED against each capped ancestor-or-self's SUBTREE (docs/62 R7) — the
		// session_record.group_id snapshot, NOT a live JOIN to machine.group_id, so a machine moved to
		// another group mid-session keeps its seat where it was admitted (matching the in-memory fake,
		// which counts rec.MachineGroupID). The subtree is read from the LIVE tree under the tenant
		// admission lock the caller holds, so sibling admissions under a shared ancestor serialize; the
		// root itself is always counted (array_append) so a cap on a group the tree no longer knows still
		// counts its own snapshot.
		for _, c := range caps {
			var activeInSubtree int
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM session_record
				WHERE tenant_id = $1 AND ended_at IS NULL
				  AND group_id = ANY (array_append(cp_group_subtree($1::uuid, ARRAY[$2::uuid]), $2::uuid))`,
				tenantID, c.GroupID).
				Scan(&activeInSubtree); err != nil {
				return err
			}
			if activeInSubtree >= c.Cap {
				return ErrGroupConcurrentSessionLimit
			}
		}
	}
	if observerCapApplies {
		var active int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM session_record
			WHERE tenant_id = $1 AND machine_id = $2
			  AND ended_at IS NULL AND access = 'view_only'
		`, tenantID, rec.MachineID).Scan(&active); err != nil {
			return err
		}
		if active >= limits.MaxObserversPerMachine {
			return ErrObserverSessionLimit
		}
	}
	return insertSessionRecordTx(ctx, tx, tenantID, rec)
}

// currentSeatCapsTx reads, from the CURRENT tree and policy rows, every ancestor-or-self of the admitted
// groups that has a positive seat cap. The caller holds the shared tree lock, so no reparent can commit
// between this read and the count that follows.
func currentSeatCapsTx(ctx context.Context, tx pgx.Tx, tenantID string, groups []string) ([]GroupSeatCap, error) {
	first, second := any(nil), any(nil)
	if len(groups) > 0 {
		first = groups[0]
	}
	if len(groups) > 1 {
		second = groups[1]
	}
	rows, err := tx.Query(ctx, `
		SELECT p.group_id::text, p.max_concurrent_sessions
		  FROM group_session_policy p
		 WHERE p.tenant_id = $1::uuid AND p.max_concurrent_sessions > 0
		   AND p.group_id = ANY (cp_group_ancestors($1::uuid, $2::uuid) || cp_group_ancestors($1::uuid, $3::uuid))
		 ORDER BY p.group_id::text COLLATE "C"`, tenantID, first, second)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupSeatCap
	for rows.Next() {
		var c GroupSeatCap
		if err := rows.Scan(&c.GroupID, &c.Cap); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReapExpiredSessions implements SessionRecordStore: end every OPEN session older than maxAge, RLS-pinned
// to the tenant. A single bulk UPDATE (atomic per row); needs no advisory lock — it never conflicts with
// the start-path count (a reaped row is already ended, so it drops out of the count either way).
func (s *PgSessionRecordStore) ReapExpiredSessions(ctx context.Context, tenantID string, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE session_record SET ended_at = now()
			WHERE tenant_id = $1 AND ended_at IS NULL
			  AND started_at < now() - make_interval(secs => $2)
		`, tenantID, maxAge.Seconds())
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// ReapExpiredGroupSessions implements SessionRecordStore: end every OPEN session for groupID older than
// maxAge, RLS-pinned to the tenant. Only sessions whose admitted group (group_id column) matches groupID
// are affected — sessions in other groups with longer or absent duration limits are left untouched.
func (s *PgSessionRecordStore) ReapExpiredGroupSessions(ctx context.Context, tenantID, groupID string, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE session_record SET ended_at = now()
			WHERE tenant_id = $1 AND group_id = $2 AND ended_at IS NULL
			  AND started_at < now() - make_interval(secs => $3)
		`, tenantID, groupID, maxAge.Seconds())
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// EndSessionsForMachine implements SessionRecordStore: end every OPEN session for machineID in the
// tenant (RLS-pinned to tenantID). Called immediately after quarantine/retire so the machine's live
// session is cut off at the control-plane level — the agent's own lease will lapse momentarily, but
// this closes the seat atomically so the concurrency count drops without waiting for the agent.
func (s *PgSessionRecordStore) EndSessionsForMachine(ctx context.Context, tenantID, machineID string) (int, error) {
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE session_record SET ended_at = now()
			WHERE tenant_id = $1 AND machine_id = $2 AND ended_at IS NULL
		`, tenantID, machineID)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// GetSession implements SessionRecordStore.
func (s *PgSessionRecordStore) GetSession(ctx context.Context, tenantID, id string) (*SessionRecord, error) {
	// An id no `uuid` column could hold is a miss, not a 500 (pathid.go).
	if namesNoUUIDRow(id) {
		return nil, ErrSessionRecordNotFound
	}
	var out *SessionRecord
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		r, err := scanSessionRecord(tx.QueryRow(ctx, selectSessionRecord+"WHERE s.id = $1", id))
		out = r
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EndSession implements SessionRecordStore: stamp ended_at once (idempotent — an already-ended
// session keeps its original end time), then return the updated joined record.
func (s *PgSessionRecordStore) EndSession(ctx context.Context, tenantID, id string, at time.Time) (*SessionRecord, error) {
	var out *SessionRecord
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE session_record SET ended_at = $2
			WHERE id = $1 AND ended_at IS NULL
		`, id, at)
		if err != nil {
			return err
		}
		r, err := scanSessionRecord(tx.QueryRow(ctx, selectSessionRecord+"WHERE s.id = $1", id))
		if err != nil {
			return err
		}
		_ = ct // 0 rows affected simply means it was already ended; the re-read returns the truth
		out = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetSessionNote implements SessionRecordStore: overwrite the session's free-text note, then return
// the updated joined record. RLS pins the tenant; an id no uuid column could hold is a miss (not a 500).
func (s *PgSessionRecordStore) SetSessionNote(ctx context.Context, tenantID, id, note string) (*SessionRecord, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrSessionRecordNotFound
	}
	var out *SessionRecord
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE session_record SET note = $2 WHERE id = $1`, id, note); err != nil {
			return err
		}
		// Re-read under the same tenant/RLS. An unknown id — or one belonging to another tenant —
		// updates zero rows AND misses this JOIN, so scanSessionRecord returns ErrSessionRecordNotFound
		// (same as EndSession); a hit returns the updated joined record.
		r, err := scanSessionRecord(tx.QueryRow(ctx, selectSessionRecord+"WHERE s.id = $1", id))
		if err != nil {
			return err
		}
		out = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListSessions implements SessionRecordStore: the tenant's sessions, newest first.
func (s *PgSessionRecordStore) ListSessions(ctx context.Context, tenantID string, filter SessionSummaryFilter) ([]SessionRecord, error) {
	var out []SessionRecord
	since, until := nullableTimes(filter)
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectSessionRecord+
			"WHERE ($1::timestamptz IS NULL OR s.started_at >= $1) "+
			"AND ($2::timestamptz IS NULL OR s.started_at <= $2) "+
			"ORDER BY s.started_at DESC LIMIT 10001", since, until)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r SessionRecord
			if err := scanSessionRecordFields(rows, &r); err != nil {
				return err
			}
			if err := appendListRow(&out, r); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SummarizeByMachine implements SessionRecordStore: GROUP the tenant's sessions BY machine, joining
// the machine row for the (denormalized) name + group. RLS pins the tenant; the count is over every
// session_record row (open and ended). Ordered most sessions first, ties by name then id so the order
// is deterministic. The tie-break text columns carry COLLATE "C" — a BYTE-ORDER collation forced so
// the count-tie order matches the fake's Go byte-wise string `<` REGARDLESS of the cluster's locale
// (hostnames are machine-controlled and routinely mixed-case, so a locale collation would otherwise
// reorder equal-count machines differently from the fake — the same fake/pg divergence SummarizeByAction
// guards against below).
// nullableTimes converts a SessionSummaryFilter's Since/Until to pointers so a ZERO time maps to SQL NULL
// (an unbounded side) rather than the year-0001 zero instant — which as a real bound would exclude every
// row on the Until side. Go escape analysis keeps the addressed copy alive for the returned pointers.
func nullableTimes(f SessionSummaryFilter) (since, until *time.Time) {
	if !f.Since.IsZero() {
		since = &f.Since
	}
	if !f.Until.IsZero() {
		until = &f.Until
	}
	return since, until
}

func (s *PgSessionRecordStore) SummarizeByMachine(ctx context.Context, tenantID string, filter SessionSummaryFilter) ([]MachineSessionCount, error) {
	var out []MachineSessionCount
	since, until := nullableTimes(filter)
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT s.machine_id::text, m.hostname, m.group_id::text, count(*),
			       COALESCE(SUM(GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (s.ended_at - s.started_at)))))
			                FILTER (WHERE s.ended_at IS NOT NULL), 0)::bigint AS total_seconds
			FROM session_record s
			JOIN machine m ON m.id = s.machine_id
			WHERE ($1::timestamptz IS NULL OR s.started_at >= $1)
			  AND ($2::timestamptz IS NULL OR s.started_at <= $2)
			GROUP BY s.machine_id, m.hostname, m.group_id
			ORDER BY count(*) DESC, m.hostname COLLATE "C", s.machine_id::text COLLATE "C" LIMIT 10001`, since, until)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c MachineSessionCount
			if err := rows.Scan(&c.MachineID, &c.MachineName, &c.MachineGroupID, &c.Count, &c.TotalSeconds); err != nil {
				return err
			}
			if err := appendListRow(&out, c); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SummarizeByTechnician implements SessionRecordStore: GROUP the tenant's sessions BY (technician, machine
// group), joining the machine row for the group (session_record has no group column — the group is the
// machine's, exactly as SummarizeByMachine reads m.group_id). RLS pins the tenant; the count is over every
// session (open and ended). Ordered by (technician, group) with COLLATE "C" — byte order so the SET matches
// the fake's Go byte-wise sort regardless of the cluster's locale (the loop-62 tie-break lesson); the order
// is otherwise not load-bearing since the handler re-aggregates per technician after narrowing by group.
func (s *PgSessionRecordStore) SummarizeByTechnician(ctx context.Context, tenantID string, filter SessionSummaryFilter) ([]TechnicianGroupSessionCount, error) {
	var out []TechnicianGroupSessionCount
	since, until := nullableTimes(filter)
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT s.technician_id::text, m.group_id::text, count(*),
			       COALESCE(SUM(GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (s.ended_at - s.started_at)))))
			                FILTER (WHERE s.ended_at IS NOT NULL), 0)::bigint AS total_seconds
			FROM session_record s
			JOIN machine m ON m.id = s.machine_id
			WHERE ($1::timestamptz IS NULL OR s.started_at >= $1)
			  AND ($2::timestamptz IS NULL OR s.started_at <= $2)
			GROUP BY s.technician_id, m.group_id
			ORDER BY s.technician_id::text COLLATE "C", m.group_id::text COLLATE "C" LIMIT 10001`, since, until)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c TechnicianGroupSessionCount
			if err := rows.Scan(&c.TechnicianID, &c.MachineGroupID, &c.Count, &c.TotalSeconds); err != nil {
				return err
			}
			if err := appendListRow(&out, c); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// -------------------------------------------------------------------------------------
// PgMgmtAuditStore — MgmtAuditStore over audit_event. INSERT + SELECT only (0006 revokes
// UPDATE/DELETE from the app role, so append-only is DB-enforced, not just convention).
// -------------------------------------------------------------------------------------

// PgMgmtAuditStore is the pgx-backed MgmtAuditStore.
type PgMgmtAuditStore struct {
	Pool *pgxpool.Pool
	// corrupt mutates the row read back from the INSERT before the round-trip guard checks it,
	// standing in for a Postgres normalization the canonicalizer fails to absorb. TEST ONLY —
	// nil in production, set only by TestPgMgmtAuditChainRoundTripGuard.
	corrupt func(*MgmtAuditEvent)
}

// NewPgMgmtAuditStore constructs a PgMgmtAuditStore.
func NewPgMgmtAuditStore(pool *pgxpool.Pool) *PgMgmtAuditStore { return &PgMgmtAuditStore{Pool: pool} }

// mgmtAuditLockWait bounds how long one append waits for its tenant's chain lock before giving
// up. Generous enough that ordinary bursts serialize invisibly (the lock is held for the length
// of one insert), short enough that a contended tenant cannot pin pool connections. A var only
// so TestPgMgmtAuditChainLockWaitIsBounded can shorten it; never reassigned in production.
var mgmtAuditLockWait = 3 * time.Second

// pgErrLockNotAvailable is SQLSTATE 55P03, which is what a lock_timeout expiry raises.
const pgErrLockNotAvailable = "55P03"

var _ MgmtAuditStore = (*PgMgmtAuditStore)(nil)

// RecordEvent implements MgmtAuditStore. Empty actor/target ids become SQL NULL (their columns
// are nullable uuids with SET NULL / no-target semantics).
//
// Chained since 0014: the tenant's tail (highest seq + its hash) is read and the new link
// computed IN Go inside the same transaction. Appends are serialized per tenant with a
// transaction-scoped advisory lock — management audit is written by many concurrent handlers
// (unlike the single-writer backstage chain), and without the lock two appends would read the
// same tail and collide on uq_audit_event_tenant_seq. id and occurred_at are assigned HERE, not
// by column defaults, because both feed the hash preimage (occurred_at ms-truncated by
// stampMgmtChainFields so the timestamptz round-trip is exact).
func (s *PgMgmtAuditStore) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return s.appendTx(ctx, tx, tenantID, e)
	})
}

// appendTx appends e to tenantID's management audit chain INSIDE the caller's transaction: the same
// bounded chain lock, tail read, stamping, INSERT ... RETURNING and read-back re-hash RecordEvent has
// always done (RecordEvent is now this plus its own transaction). It points the transaction-local
// tenant context at tenantID first, so RLS admits the insert; a caller that continues the
// transaction for another tenant must set the context again. It never commits, never opens a
// transaction, and returns every error, so a caller's mutation rolls back with a failed append. Used
// by the platform-operator orchestration (one transaction for the tenant change and both chains).
func (s *PgMgmtAuditStore) appendTx(ctx context.Context, tx pgx.Tx, tenantID string, e *MgmtAuditEvent) error {
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID); err != nil {
		return err
	}
	{
		// Bound the WAIT for the chain lock. The lock itself is held for microseconds (a tail
		// read, a hash, an insert), so a wait this long means something pathological: a stuck
		// transaction, or a flood of appends against one tenant — and unauthenticated endpoints
		// write audit events (a failed login records auth.login_failed), so a flood does not
		// even need credentials. Unbounded, those waiters sit on pgxpool connections until the
		// pool is empty and EVERY tenant's requests stall; bounded, the damage stays a fast,
		// loud, fail-closed error confined to the tenant under attack. set_config's third
		// argument is is_local, so this reverts when the transaction ends — it must, since the
		// connection goes back to the pool. (Verified against a live server: lock_timeout does
		// apply to pg_advisory_xact_lock waits, which is not true of every wait in Postgres.)
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
			strconv.FormatInt(mgmtAuditLockWait.Milliseconds(), 10)); err != nil {
			return err
		}
		// The lock key is built from the CANONICAL tenant id, not the caller's spelling. Every
		// other tenant predicate here is a uuid comparison and so is spelling-insensitive for
		// free; this one hashes a string, so two spellings of one tenant would take two
		// different locks, both appends would read the same tail, and the serialization this
		// lock exists to provide would silently not happen.
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended('mgmt_audit_chain:' || $1, 0))`,
			canonicalUUIDish(tenantID)); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgErrLockNotAvailable {
				return fmt.Errorf("mgmt audit %s: timed out after %s waiting for tenant %s's "+
					"audit chain lock; the append was refused rather than queued: %w",
					e.Action, mgmtAuditLockWait, tenantID, err)
			}
			return err
		}
		// The tail read filters on tenant_id EXPLICITLY, unlike every other query here. RLS
		// would scope it for the app role, but this read does not merely return data — it
		// decides the seq and prev_hash the next row is STAMPED with. Under a pool whose role
		// bypasses RLS (a superuser DATABASE_URL, which nothing rejects at startup) an
		// unfiltered read returns the globally-highest seq, so one tenant's chain would be
		// stamped onto another's tail: a permanent gap plus a foreign link that the append-only
		// REVOKE (0006) makes unrepairable, i.e. verify reporting tamper forever on an
		// untampered trail. Self-scoping mirrors the backstage chain's tailTx (pgstore.go).
		tailSeq, tailHash := int64(-1), ""
		err := tx.QueryRow(ctx, `
			SELECT seq, hash FROM audit_event
			WHERE tenant_id = $1 AND seq IS NOT NULL
			ORDER BY seq DESC
			LIMIT 1
		`, tenantID).Scan(&tailSeq, &tailHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		cp := *e
		cp.SourceIP = sourceIPFrom(ctx)
		if err := stampMgmtChainFields(&cp, tenantID, tailSeq, tailHash); err != nil {
			return err
		}
		meta := cp.Metadata
		if len(meta) == 0 {
			meta = json.RawMessage("{}")
		}
		// RETURNING the SAME projection the readers use, so what comes back is what a later
		// GET /audit/verify will hash — see the read-back check below.
		stored, err := scanMgmtAuditEvent(tx.QueryRow(ctx, `
			INSERT INTO audit_event
			       (id, tenant_id, actor_user_id, action, target_kind, target_id,
			        occurred_at, metadata, seq, prev_hash, hash, source_ip)
			VALUES ($1, $2, NULLIF($3,'')::uuid, $4, NULLIF($5,''), NULLIF($6,'')::uuid,
			        $7, $8, $9, $10, $11, NULLIF($12,'')::inet)
			RETURNING `+mgmtAuditColumns,
			cp.ID, tenantID, cp.ActorUserID, cp.Action, cp.TargetKind, cp.TargetID,
			cp.OccurredAt, []byte(meta), *cp.Seq, cp.PrevHash, cp.Hash, cp.SourceIP))
		if err != nil {
			return err
		}
		if err := s.corruptForTest(&stored); err != nil {
			return err
		}
		// THE ROUND-TRIP GUARD. Postgres normalizes on the way in — jsonb numbers are `numeric`,
		// the uuid type re-renders its accepted spellings — so a field can be hashed as one
		// thing and read back as another. The canonicalizer absorbs every such normalization we
		// know of (mgmtaudit_canonical.go), but "every one we know of" is exactly the assumption
		// that broke here before, and the failure mode is the worst kind: 0006 revokes
		// UPDATE/DELETE, so a row whose stored form does not re-hash is UNREPAIRABLE and makes
		// GET /audit/verify cry tamper forever on an honest trail.
		//
		// So instead of trusting the canonicalizer, verify it: re-hash what the INSERT actually
		// stored, in the same transaction, and roll back if it disagrees. An unanticipated
		// normalization then costs one failed management action with a precise error, instead of
		// silently poisoning the tenant's audit chain for good. The cost is nil — RETURNING adds
		// no round trip.
		back, err := recomputeMgmtAuditHash(stored)
		if err != nil {
			return fmt.Errorf("mgmt audit %s: stored row cannot be re-hashed: %w", cp.Action, err)
		}
		if back != cp.Hash {
			return fmt.Errorf("mgmt audit %s: refusing to append — Postgres normalized a hashed "+
				"field (stored row re-hashes to %s, not %s); appending it would make the tenant's "+
				"chain verify as tampered forever", cp.Action, back, cp.Hash)
		}
		*e = cp
		return nil
	}
}

// corruptForTest is the seam that lets a test simulate a storage-layer normalization the
// canonicalizer does NOT absorb — the only way to exercise the round-trip guard above, since by
// construction no such normalization is known (if one were, it would be fixed rather than
// tested). Nil in production; see TestPgMgmtAuditChainRoundTripGuard.
func (s *PgMgmtAuditStore) corruptForTest(e *MgmtAuditEvent) error {
	if s.corrupt == nil {
		return nil
	}
	s.corrupt(e)
	return nil
}

// selectMgmtAuditEvent is the shared projection for mgmt audit reads. Chain columns come back
// nullable: legacy pre-0014 rows have no seq/prev_hash/hash.
//
// Every query built on it filters tenant_id EXPLICITLY — a deliberate deviation from this file's
// "RLS is the filter, that is the point" convention, for the same reason as the tail read above:
// the mgmt audit is a per-tenant hash CHAIN, so a cross-tenant row is not a mere leak, it makes
// two interleaved chains look like one gapped chain and turns verification into a false tamper
// report. Under the app role the predicate is redundant; under an RLS-exempt role it is what
// keeps the chain semantics correct.
// mgmtAuditColumns is the projection itself, split out so RecordEvent's INSERT ... RETURNING can
// read a freshly written row back through the EXACT expressions the readers use. If the two ever
// drifted, the write-time round-trip guard would be checking something other than what verify
// later hashes — which is precisely the bug it exists to catch.
const mgmtAuditColumns = `
	id::text, tenant_id::text,
	COALESCE(actor_user_id::text, ''), action,
	COALESCE(target_kind, ''), COALESCE(target_id::text, ''),
	occurred_at, metadata, seq, COALESCE(prev_hash, ''), COALESCE(hash, ''),
	COALESCE(host(source_ip), '')
`

const selectMgmtAuditEvent = `SELECT ` + mgmtAuditColumns + ` FROM audit_event `

// mgmtAuditScanner is satisfied by both pgx.Row (single-row RETURNING) and pgx.Rows (list
// queries), so one scan definition serves the write path and the read paths.
type mgmtAuditScanner interface{ Scan(dest ...any) error }

func scanMgmtAuditEvent(sc mgmtAuditScanner) (MgmtAuditEvent, error) {
	var e MgmtAuditEvent
	var meta []byte
	if err := sc.Scan(&e.ID, &e.TenantID, &e.ActorUserID, &e.Action,
		&e.TargetKind, &e.TargetID, &e.OccurredAt, &meta,
		&e.Seq, &e.PrevHash, &e.Hash, &e.SourceIP); err != nil {
		return MgmtAuditEvent{}, err
	}
	e.Metadata = json.RawMessage(meta)
	return e, nil
}

func scanMgmtAuditRows(rows pgx.Rows) ([]MgmtAuditEvent, error) {
	defer rows.Close()
	var out []MgmtAuditEvent
	for rows.Next() {
		e, err := scanMgmtAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListEvents implements MgmtAuditStore: newest first, bounded. Chained rows sort by seq (the
// authoritative order); legacy rows (NULL seq) sort after them by time.
func (s *PgMgmtAuditStore) ListEvents(ctx context.Context, tenantID string, limit int) ([]MgmtAuditEvent, error) {
	return s.ListEventsFiltered(ctx, tenantID, limit, AuditFilter{})
}

// ListEventsFiltered implements MgmtAuditStore: ListEvents narrowed by an exact-match filter. The
// filter clauses are appended as PARAMETERIZED predicates (never interpolated), so a hostile action
// or target_kind value is data, not SQL. Applied inside the WHERE so LIMIT bounds the matching rows.
func (s *PgMgmtAuditStore) ListEventsFiltered(ctx context.Context, tenantID string, limit int, filter AuditFilter) ([]MgmtAuditEvent, error) {
	if limit <= 0 {
		limit = defaultMgmtAuditListLimit
	}
	where := "WHERE tenant_id = $1"
	args := []any{tenantID}
	if filter.Action != "" {
		args = append(args, filter.Action)
		where += fmt.Sprintf(" AND action = $%d", len(args))
	}
	if filter.TargetKind != "" {
		args = append(args, filter.TargetKind)
		where += fmt.Sprintf(" AND target_kind = $%d", len(args))
	}
	if filter.Actor != "" {
		// Compare the column's TEXT form (not a ::uuid-cast of the arg): it matches the in-memory
		// store's string compare, and a non-uuid actor string simply matches nothing instead of
		// raising a cast error the way `$N::uuid` would.
		args = append(args, filter.Actor)
		where += fmt.Sprintf(" AND actor_user_id::text = $%d", len(args))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		where += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}
	if !filter.Until.IsZero() {
		args = append(args, filter.Until)
		where += fmt.Sprintf(" AND occurred_at <= $%d", len(args))
	}
	if c := filter.Before; c != nil {
		// Strictly after the cursor in the listing order (seq DESC NULLS LAST, occurred_at DESC, id DESC).
		args = append(args, c.OccurredAt, c.ID)
		tAt, idAt := len(args)-1, len(args)
		if c.Seq != nil {
			args = append(args, *c.Seq)
			sAt := len(args)
			where += fmt.Sprintf(" AND (seq < $%d OR seq IS NULL OR (seq = $%d AND (occurred_at, id) < ($%d, $%d::uuid)))",
				sAt, sAt, tAt, idAt)
		} else {
			where += fmt.Sprintf(" AND seq IS NULL AND (occurred_at, id) < ($%d, $%d::uuid)", tAt, idAt)
		}
	}
	args = append(args, limit)
	query := selectMgmtAuditEvent + "\n" + where +
		fmt.Sprintf("\nORDER BY seq DESC NULLS LAST, occurred_at DESC, id DESC\nLIMIT $%d", len(args))
	var out []MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		out, err = scanMgmtAuditRows(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SummarizeByAction implements MgmtAuditStore: GROUP BY action with a count, RLS-scoped. The WHERE is
// built identically to ListEventsFiltered (same filter semantics, incl. actor_user_id::text so a
// non-uuid actor matches nothing rather than raising a cast error), so the two agree on the match set.
func (s *PgMgmtAuditStore) SummarizeByAction(ctx context.Context, tenantID string, filter AuditFilter) ([]AuditActionCount, error) {
	where := "WHERE tenant_id = $1"
	args := []any{tenantID}
	if filter.Action != "" {
		args = append(args, filter.Action)
		where += fmt.Sprintf(" AND action = $%d", len(args))
	}
	if filter.TargetKind != "" {
		args = append(args, filter.TargetKind)
		where += fmt.Sprintf(" AND target_kind = $%d", len(args))
	}
	if filter.Actor != "" {
		args = append(args, filter.Actor)
		where += fmt.Sprintf(" AND actor_user_id::text = $%d", len(args))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		where += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}
	if !filter.Until.IsZero() {
		args = append(args, filter.Until)
		where += fmt.Sprintf(" AND occurred_at <= $%d", len(args))
	}
	// action COLLATE "C" forces a BYTE-ORDER tie-break so the count-tie order matches the fake's Go
	// byte-wise string sort deterministically — the default column collation (glibc/Windows) would
	// otherwise diverge from Go's `<` for non-ASCII/uppercase actions (fake-and-pg-must-agree).
	query := `SELECT action, count(*) FROM audit_event ` + where + ` GROUP BY action ORDER BY count(*) DESC, action COLLATE "C" LIMIT 10001`
	out := []AuditActionCount{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ac AuditActionCount
			if err := rows.Scan(&ac.Action, &ac.Count); err != nil {
				return err
			}
			if err := appendListRow(&out, ac); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountUnchained implements MgmtAuditStore: the tenant's rows the chain walk cannot attest —
// legacy pre-0014 rows, or anything inserted around the chain, which is why verify reports it.
//
// "Cannot attest" is defined as the complement of what the walk visits, not just `seq IS NULL`.
// The walk starts its cursor at -1 and pages on `seq > cursor`, so a row planted at a NEGATIVE
// seq would be skipped by the walk AND missed by an `IS NULL` count, and verify would report a
// fully-covered, intact chain over it. 0016 adds a CHECK that makes such a row impossible; this
// predicate is the belt to that migration's braces, so the coverage arithmetic stays closed even
// if the constraint is ever dropped.
func (s *PgMgmtAuditStore) CountUnchained(ctx context.Context, tenantID string) (int64, error) {
	var n int64
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND (seq IS NULL OR seq < 0)`,
			tenantID).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ListEventsAsc implements MgmtAuditStore: chained events with seq > afterSeq, ascending —
// the cursor walk behind chain verification and the SIEM export.
func (s *PgMgmtAuditStore) ListEventsAsc(ctx context.Context, tenantID string, afterSeq int64, limit int) ([]MgmtAuditEvent, error) {
	if limit <= 0 {
		limit = defaultMgmtAuditListLimit
	}
	var out []MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectMgmtAuditEvent+`
			WHERE tenant_id = $1 AND seq > $2
			ORDER BY seq ASC
			LIMIT $3
		`, tenantID, afterSeq, limit)
		if err != nil {
			return err
		}
		out, err = scanMgmtAuditRows(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// -------------------------------------------------------------------------------------
// PgTenantStore — TenantStore over tenant + cp_create_tenant (0006).
// -------------------------------------------------------------------------------------

// PgTenantStore is the pgx-backed TenantStore.
type PgTenantStore struct {
	Pool *pgxpool.Pool
}

// NewPgTenantStore constructs a PgTenantStore.
func NewPgTenantStore(pool *pgxpool.Pool) *PgTenantStore { return &PgTenantStore{Pool: pool} }

var _ TenantStore = (*PgTenantStore)(nil)

// ListTenants implements TenantStore. Under the RLS-subject app role the policy on tenant is
// `id = current_setting('app.current_tenant')`, so this returns exactly the caller's own row.
func (s *PgTenantStore) ListTenants(ctx context.Context, tenantID string) ([]Tenant, error) {
	out := []Tenant{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, slug, name, deployment_mode, created_at,
			       (disabled_at IS NOT NULL), require_2fa
			FROM tenant
			ORDER BY created_at
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Tenant
			if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.DeploymentMode, &t.CreatedAt, &t.Disabled, &t.Require2FA); err != nil {
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

// GetSecurityPolicy implements TenantStore: returns the current security policy for the pinned tenant.
func (s *PgTenantStore) GetSecurityPolicy(ctx context.Context, tenantID string) (TenantSecurityPolicy, error) {
	var p TenantSecurityPolicy
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT require_2fa FROM tenant`).Scan(&p.Require2FA)
	})
	if err != nil {
		return TenantSecurityPolicy{}, err
	}
	return p, nil
}

// SetRequire2FA implements TenantStore: updates the require_2fa flag for the pinned tenant.
func (s *PgTenantStore) SetRequire2FA(ctx context.Context, tenantID string, require bool) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant SET require_2fa = $1`, require)
		return err
	})
}

// CreateTenant implements TenantStore via the SECURITY DEFINER cp_create_tenant function
// (0006): the RLS policy on tenant forbids the pinned app connection from inserting any OTHER
// tenant's row, so provisioning must run privileged — the same bootstrap pattern as 0003. A
// slug collision surfaces as ErrTenantSlugTaken.
func (s *PgTenantStore) CreateTenant(ctx context.Context, tenantID string, t *Tenant) error {
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id::text, created_at FROM cp_create_tenant($1, $2, $3)
		`, t.Slug, t.Name, t.DeploymentMode).Scan(&t.ID, &t.CreatedAt)
	})
	if err != nil {
		if isUniqueViolation(err) {
			return ErrTenantSlugTaken
		}
		return err
	}
	return nil
}
