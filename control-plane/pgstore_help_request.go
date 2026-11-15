package controlplane

// The Postgres half of guest help requests (docs/64, migration 0069). The fake in help_request.go and
// this store are driven by ONE shared suite (help_request_test.go): every rule below exists there too.
//
// LOCKS. A creation that must INSERT serializes per tenant on `help_request:<tenant>` (open-cap and budget
// admission, H-C2); replays and already-open returns never take it, and the per-device call counter is a
// single atomic upsert (chargeCall). Reopen-after-failed-start does not take it either (see there).
// Accept takes the tenant's SESSION ADMISSION lock first (the same one POST /sessions takes, so seat caps
// are counted against a stable set), then the request row FOR UPDATE, then the machine row FOR SHARE (a
// retire/quarantine UPDATE waits for the accept and then cancels what is left), and appends its audit row
// last, in the management-audit chain's usual position. A device cancel takes the machine FOR SHARE, then
// the request row FOR UPDATE. Nothing takes the admission lock after a request row, so there is no cycle.

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgHelpRequestStore is the pgx-backed HelpRequestStore.
type PgHelpRequestStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

// NewPgHelpRequestStore constructs the store. audit may be nil only in tests that do not read the trail.
func NewPgHelpRequestStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgHelpRequestStore {
	return &PgHelpRequestStore{Pool: pool, Audit: audit}
}

var _ HelpRequestStore = (*PgHelpRequestStore)(nil)

// helpLockWait bounds the wait for the per-tenant creation lock (a var so a test can shorten it).
var helpLockWait = 3 * time.Second

// helpReopenLockWait / helpReopenAttempts: the compensating reopen waits much longer than a creation does, and
// is retried, because losing it would strand an accepted request (vars so a test can shorten them).
var (
	helpReopenLockWait = 15 * time.Second
	helpReopenAttempts = 3
)

func helpColsP(p string) string {
	return p + `id::text, ` + p + `tenant_id::text, ` + p + `machine_id::text, ` + p + `device_id, ` +
		`coalesce(` + p + `group_id::text, ''), ` + p + `note, ` + p + `status, ` + p + `created_at, ` + p + `expires_at, ` +
		p + `closed_at, coalesce(` + p + `accepted_by::text, ''), ` + p + `accepted_at, ` +
		`coalesce(` + p + `session_id::text, ''), coalesce(` + p + `cancel_reason, ''), coalesce(` + p + `delivery, '')`
}

var helpCols = helpColsP("")

func scanHelpRequest(row pgx.Row) (*HelpRequest, error) {
	var r HelpRequest
	if err := row.Scan(&r.ID, &r.TenantID, &r.MachineID, &r.DeviceID, &r.GroupID, &r.Note, &r.Status,
		&r.CreatedAt, &r.ExpiresAt, &r.ClosedAt, &r.AcceptedBy, &r.AcceptedAt, &r.SessionID, &r.CancelReason, &r.Delivery); err != nil {
		return nil, err
	}
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
	if r.ClosedAt != nil {
		t := r.ClosedAt.UTC()
		r.ClosedAt = &t
	}
	if r.AcceptedAt != nil {
		t := r.AcceptedAt.UTC()
		r.AcceptedAt = &t
	}
	return &r, nil
}

func (s *PgHelpRequestStore) appendAudit(ctx context.Context, tx pgx.Tx, tenantID string, res *HelpResult, e *MgmtAuditEvent) error {
	if s.Audit != nil {
		if err := s.Audit.appendTx(ctx, tx, tenantID, e); err != nil {
			return err
		}
	}
	res.Events = append(res.Events, e)
	return nil
}

// lockHelpTx takes the per-tenant creation lock, bounded. A timeout is reported as busy (429).
func lockHelpTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	return lockHelpTxWait(ctx, tx, tenantID, helpLockWait)
}

func lockHelpTxWait(ctx context.Context, tx pgx.Tx, tenantID string, wait time.Duration) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		strconv.FormatInt(wait.Milliseconds(), 10)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('help_request:' || $1, 0))`,
		canonicalUUIDish(tenantID))
	return mapHelpLockErr(err)
}

func mapHelpLockErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgErrLockNotAvailable {
		return &HelpLimitError{Scope: "busy", RetryAfter: 2 * time.Second}
	}
	return err
}

// expireDueTx is the lazy expiry every deciding method runs FIRST (H-C6): each due open row of the tenant
// becomes `expired` and its audit row commits in this transaction.
//
// LOCK ORDER (one, everywhere): [machine row FOR SHARE] -> tenant help lock -> request rows. Row locks are
// therefore never held while waiting for the tenant lock: a plain read finds out whether anything is due, and
// only then is the tenant lock taken (re-entrant for a caller that already holds it) before the rows are
// locked and transitioned. Sweep and every creation take the same path, so they cannot deadlock.
func (s *PgHelpRequestStore) expireDueTx(ctx context.Context, tx pgx.Tx, tenantID string, now time.Time, res *HelpResult) (int, error) {
	var anyDue bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM help_request
		WHERE tenant_id = $1 AND status = 'open' AND expires_at <= $2)`, tenantID, now).Scan(&anyDue); err != nil {
		return 0, err
	}
	if !anyDue {
		return 0, nil
	}
	if err := lockHelpTx(ctx, tx, tenantID); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT `+helpCols+` FROM help_request
		WHERE tenant_id = $1 AND status = 'open' AND expires_at <= $2
		ORDER BY id LIMIT $3 FOR UPDATE`, tenantID, now, helpExpireBatch)
	if err != nil {
		return 0, err
	}
	var due []*HelpRequest
	for rows.Next() {
		r, err := scanHelpRequest(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range due {
		if _, err := tx.Exec(ctx, `UPDATE help_request SET status = 'expired', closed_at = $3
			WHERE tenant_id = $1 AND id = $2 AND status = 'open'`, tenantID, r.ID, helpClip(now)); err != nil {
			return 0, err
		}
		if err := s.appendAudit(ctx, tx, tenantID, res, helpAuditEvent(AuditHelpExpired, r.ID, "",
			helpDeviceMeta(r, map[string]any{"reason": "ttl"}))); err != nil {
			return 0, err
		}
	}
	return len(due), nil
}

type helpMachineRow struct {
	ID, DeviceID, GroupID, Status string
	Ephemeral                     bool
}

func helpMachineEligible(m *helpMachineRow) bool {
	return !m.Ephemeral && m.Status == MachineStatusActive
}

// CreateForDevice implements HelpRequestStore.
func (s *PgHelpRequestStore) CreateForDevice(ctx context.Context, tenantID, deviceID, opID, note string, now time.Time) (*HelpCreateResult, error) {
	if !validHelpOpID(opID) {
		return nil, ErrHelpInvalidOp
	}
	note = normalizeHelpNote(note)
	out := &HelpCreateResult{}
	// The durable per-device CALL budget runs first, in its own committed transaction, for EVERY call: a
	// replayed op_id and an already-open return below never reach the creation budgets, and a refusal that
	// rolled the counter back would not count at all. No tenant lock is held here.
	if err := s.chargeCall(ctx, tenantID, deviceID, now); err != nil {
		return nil, err
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*out = HelpCreateResult{}
		var m helpMachineRow
		err := tx.QueryRow(ctx, `
			SELECT id::text, device_id, coalesce(group_id::text, ''), status, ephemeral
			FROM machine WHERE tenant_id = $1 AND device_id = $2 FOR SHARE`, tenantID, deviceID).
			Scan(&m.ID, &m.DeviceID, &m.GroupID, &m.Status, &m.Ephemeral)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrHelpMachineIneligible
		}
		if err != nil {
			return err
		}
		if !helpMachineEligible(&m) {
			return ErrHelpMachineIneligible
		}
		var suspended bool
		if err := tx.QueryRow(ctx, `SELECT disabled_at IS NOT NULL FROM tenant WHERE id = $1`, tenantID).Scan(&suspended); err != nil {
			return err
		}
		if suspended {
			return ErrHelpTenantSuspended
		}
		// EXPIRY BEFORE COUNT: a lapsed open row must not hold the machine's slot or the tenant's cap.
		if _, err := s.expireDueTx(ctx, tx, tenantID, now, &out.HelpResult); err != nil {
			return err
		}
		// op_id replay (24 h): the same request back, whatever state it is in now. Run again after the tenant
		// lock is taken, because a concurrent call with the same op_id may have committed while this one waited.
		replayNow := func() (*HelpRequest, error) {
			var replayID string
			err := tx.QueryRow(ctx, `SELECT request_id::text FROM help_request_op
				WHERE tenant_id = $1 AND device_id = $2 AND op_id = $3 AND created_at > $4`,
				tenantID, m.DeviceID, opID, now.Add(-helpOpDedupWindow)).Scan(&replayID)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request WHERE tenant_id = $1 AND id = $2`, tenantID, replayID))
		}
		if r, err := replayNow(); err != nil {
			return err
		} else if r != nil {
			out.Request, out.Replayed = r, true
			return nil
		}
		// An UNEXPIRED mapping is never overwritten: only a lapsed (older than the window) row is replaced.
		upsertOp := func(requestID string) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO help_request_op (tenant_id, device_id, op_id, request_id, created_at)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (tenant_id, device_id, op_id)
				DO UPDATE SET request_id = EXCLUDED.request_id, created_at = EXCLUDED.created_at
				WHERE help_request_op.created_at <= $6`,
				tenantID, m.DeviceID, opID, requestID, helpClip(now), now.Add(-helpOpDedupWindow))
			return err
		}
		// A second request while one is open is idempotent: it refreshes nothing, records NO op row (a
		// device cycling op ids must not grow the ledger) and takes no tenant lock.
		openNow := func() (*HelpRequest, error) {
			open, err := scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request
				WHERE tenant_id = $1 AND machine_id = $2 AND status = 'open'`, tenantID, m.ID))
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
			return open, err
		}
		if open, err := openNow(); err != nil {
			return err
		} else if open != nil {
			out.Request, out.Replayed = open, true
			return nil
		}
		// A row must be INSERTED: only now serialize on the tenant (open-cap and budget admission), then
		// re-read, because a creation may have committed while this call waited for the lock.
		if err := lockHelpTx(ctx, tx, tenantID); err != nil {
			return err
		}
		if r, err := replayNow(); err != nil {
			return err
		} else if r != nil {
			out.Request, out.Replayed = r, true
			return nil
		}
		if open, err := openNow(); err != nil {
			return err
		} else if open != nil {
			out.Request, out.Replayed = open, true
			return nil
		}
		// Durable budgets (H-C2): creations, whatever became of them.
		times := func(device bool, since time.Time) ([]time.Time, error) {
			q := `SELECT created_at FROM help_request WHERE tenant_id = $1 AND created_at > $2`
			args := []any{tenantID, since}
			if device {
				q += ` AND device_id = $3`
				args = append(args, m.DeviceID)
			}
			rows, err := tx.Query(ctx, q+` ORDER BY created_at LIMIT 2000`, args...)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			var ts []time.Time
			for rows.Next() {
				var t time.Time
				if err := rows.Scan(&t); err != nil {
					return nil, err
				}
				ts = append(ts, t)
			}
			return ts, rows.Err()
		}
		devDay, err := times(true, now.Add(-24*time.Hour))
		if err != nil {
			return err
		}
		var devHour []time.Time
		for _, t := range devDay {
			if t.After(now.Add(-time.Hour)) {
				devHour = append(devHour, t)
			}
		}
		if len(devHour) >= helpDeviceHourlyLimit {
			return &HelpLimitError{helpLimitScopeDevHour, helpRetryAfter(devHour, helpDeviceHourlyLimit, time.Hour, now)}
		}
		if len(devDay) >= helpDeviceDailyLimit {
			return &HelpLimitError{helpLimitScopeDevDay, helpRetryAfter(devDay, helpDeviceDailyLimit, 24*time.Hour, now)}
		}
		tenHour, err := times(false, now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if len(tenHour) >= helpTenantHourlyLimit {
			return &HelpLimitError{helpLimitScopeTenHour, helpRetryAfter(tenHour, helpTenantHourlyLimit, time.Hour, now)}
		}
		var openCount int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM help_request WHERE tenant_id = $1 AND status = 'open'`, tenantID).Scan(&openCount); err != nil {
			return err
		}
		if openCount >= helpTenantOpenCap {
			return &HelpLimitError{helpLimitScopeTenOpen, time.Minute}
		}
		var r *HelpRequest
		err = inSavepoint(ctx, tx, func() error {
			var e error
			r, e = scanHelpRequest(tx.QueryRow(ctx, `
				INSERT INTO help_request (tenant_id, machine_id, device_id, group_id, note, status, created_at, expires_at)
				VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, 'open', $6, $7)
				RETURNING `+helpCols,
				tenantID, m.ID, m.DeviceID, m.GroupID, note, helpClip(now), helpClip(now.Add(helpRequestTTL))))
			return e
		})
		if pgOneOpenViolation(err) {
			// A compensating reopen (which holds no tenant lock) put this machine's request back between the
			// check above and this insert: that open request is the answer.
			if open, oerr := openNow(); oerr != nil {
				return oerr
			} else if open != nil {
				out.Request, out.Replayed = open, true
				return nil
			}
		}
		if err != nil {
			return err
		}
		if err := upsertOp(r.ID); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpRequested, r.ID, "",
			helpDeviceMeta(r, map[string]any{"note_length": len([]rune(r.Note))}))); err != nil {
			return err
		}
		out.Request, out.Created = r, true
		return nil
	})
	if err != nil {
		return nil, mapHelpLockErr(err)
	}
	return out, nil
}

// chargeCall bumps the device's per-hour call counter in its own transaction and refuses (429) once the
// hour's calls exceed helpDeviceCallsPerHour. The upsert is atomic, so concurrent calls cannot both read
// the same count.
func (s *PgHelpRequestStore) chargeCall(ctx context.Context, tenantID, deviceID string, now time.Time) error {
	var n int
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO help_request_call (tenant_id, device_id, bucket, n) VALUES ($1, $2, $3, 1)
			ON CONFLICT (tenant_id, device_id, bucket) DO UPDATE SET n = help_request_call.n + 1
			RETURNING n`, tenantID, deviceID, helpCallBucket(now)).Scan(&n)
	})
	if err != nil {
		return err
	}
	if n > helpDeviceCallsPerHour {
		return helpCallLimitError(now)
	}
	return nil
}

// deviceMachineTx resolves the device's machine id (FOR SHARE) or ErrHelpRequestNotFound.
func deviceMachineTx(ctx context.Context, tx pgx.Tx, tenantID, deviceID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM machine WHERE tenant_id = $1 AND device_id = $2 FOR SHARE`,
		tenantID, deviceID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrHelpRequestNotFound
	}
	return id, err
}

// CancelForDevice implements HelpRequestStore.
func (s *PgHelpRequestStore) CancelForDevice(ctx context.Context, tenantID, deviceID, requestID string, now time.Time) (*HelpTransitionResult, error) {
	if _, ok := parsePgUUID(requestID); !ok {
		return nil, ErrHelpRequestNotFound
	}
	out := &HelpTransitionResult{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*out = HelpTransitionResult{}
		machineID, err := deviceMachineTx(ctx, tx, tenantID, deviceID)
		if err != nil {
			return err
		}
		if _, err := s.expireDueTx(ctx, tx, tenantID, now, &out.HelpResult); err != nil {
			return err
		}
		// FOR UPDATE: a concurrent accept holds this row until it commits; this statement then re-reads the
		// committed status, so exactly one of accept / cancel / expiry wins and the rest see its result.
		r, err := scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request
			WHERE tenant_id = $1 AND id = $2 AND machine_id = $3 FOR UPDATE`, tenantID, requestID, machineID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrHelpRequestNotFound
		}
		if err != nil {
			return err
		}
		switch r.Status {
		case HelpStatusOpen:
			r, err = scanHelpRequest(tx.QueryRow(ctx, `
				UPDATE help_request SET status = 'cancelled', closed_at = $3, cancel_reason = $4
				WHERE tenant_id = $1 AND id = $2 AND status = 'open' RETURNING `+helpCols,
				tenantID, r.ID, helpClip(now), HelpCancelGuest))
			if err != nil {
				return err
			}
			if err := s.appendAudit(ctx, tx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpCancelled, r.ID, "",
				helpDeviceMeta(r, map[string]any{"reason": HelpCancelGuest}))); err != nil {
				return err
			}
			out.Changed = true
		case HelpStatusCancelled:
		default:
			out.Conflict = true
		}
		out.Request = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CurrentForDevice implements HelpRequestStore.
func (s *PgHelpRequestStore) CurrentForDevice(ctx context.Context, tenantID, deviceID string, now time.Time) (*HelpTransitionResult, error) {
	out := &HelpTransitionResult{}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*out = HelpTransitionResult{}
		machineID, err := deviceMachineTx(ctx, tx, tenantID, deviceID)
		if errors.Is(err, ErrHelpRequestNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := s.expireDueTx(ctx, tx, tenantID, now, &out.HelpResult); err != nil {
			return err
		}
		// Open first, else the newest within the lookback.
		r, err := scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request
			WHERE tenant_id = $1 AND machine_id = $2 AND created_at > $3
			ORDER BY (status = 'open') DESC, created_at DESC, id LIMIT 1`,
			tenantID, machineID, now.Add(-helpCurrentLookback)))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.Request = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

const helpJoinCols = `, m.hostname, m.alias, coalesce(m.group_id::text, ''), m.status, m.device_id`

func scanHelpWithMachine(row pgx.Row) (*HelpRequestWithMachine, error) {
	var v HelpRequestWithMachine
	r := &v.HelpRequest
	if err := row.Scan(&r.ID, &r.TenantID, &r.MachineID, &r.DeviceID, &r.GroupID, &r.Note, &r.Status,
		&r.CreatedAt, &r.ExpiresAt, &r.ClosedAt, &r.AcceptedBy, &r.AcceptedAt, &r.SessionID, &r.CancelReason, &r.Delivery,
		&v.MachineName, &v.MachineAlias, &v.MachineGroupID, &v.MachineStatus, &v.MachineDevice); err != nil {
		return nil, err
	}
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
	if r.ClosedAt != nil {
		t := r.ClosedAt.UTC()
		r.ClosedAt = &t
	}
	if r.AcceptedAt != nil {
		t := r.AcceptedAt.UTC()
		r.AcceptedAt = &t
	}
	return &v, nil
}

// ListOpen implements HelpRequestStore.
func (s *PgHelpRequestStore) ListOpen(ctx context.Context, tenantID string, now time.Time) ([]HelpRequestWithMachine, *HelpResult, error) {
	res := &HelpResult{}
	var out []HelpRequestWithMachine
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*res, out = HelpResult{}, nil
		if _, err := s.expireDueTx(ctx, tx, tenantID, now, res); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+helpColsP("r.")+helpJoinCols+`
			FROM help_request r JOIN machine m ON m.tenant_id = r.tenant_id AND m.id = r.machine_id
			WHERE r.tenant_id = $1 AND r.status = 'open' ORDER BY r.created_at, r.id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanHelpWithMachine(rows)
			if err != nil {
				return err
			}
			out = append(out, *v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	return out, res, nil
}

// Get implements HelpRequestStore.
func (s *PgHelpRequestStore) Get(ctx context.Context, tenantID, requestID string, now time.Time) (*HelpRequestWithMachine, *HelpResult, error) {
	if _, ok := parsePgUUID(requestID); !ok {
		return nil, nil, ErrHelpRequestNotFound
	}
	res := &HelpResult{}
	var out *HelpRequestWithMachine
	notFound := false
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*res, out, notFound = HelpResult{}, nil, false
		if _, err := s.expireDueTx(ctx, tx, tenantID, now, res); err != nil {
			return err
		}
		v, err := scanHelpWithMachine(tx.QueryRow(ctx, `SELECT `+helpColsP("r.")+helpJoinCols+`
			FROM help_request r JOIN machine m ON m.tenant_id = r.tenant_id AND m.id = r.machine_id
			WHERE r.tenant_id = $1 AND r.id = $2`, tenantID, requestID))
		if errors.Is(err, pgx.ErrNoRows) {
			notFound = true // the lazy expiry above still commits; not-found is reported after
			return nil
		}
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if notFound {
		return nil, res, ErrHelpRequestNotFound
	}
	return out, res, nil
}

// Accept implements HelpRequestStore (H-C1).
func (s *PgHelpRequestStore) Accept(ctx context.Context, tenantID string, in HelpAcceptInput) (*HelpAcceptResult, error) {
	out := &HelpAcceptResult{Outcome: HelpAcceptNotFound}
	if _, ok := parsePgUUID(in.RequestID); !ok {
		return out, nil
	}
	if err := normalizeSessionRecordAccess(in.Record); err != nil {
		return nil, err
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*out = HelpAcceptResult{Outcome: HelpAcceptNotFound}
		// The same per-tenant admission lock POST /sessions takes: seat counts are stable until commit and
		// two accepts of one request serialize here.
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		r, err := scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, in.RequestID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.Status == HelpStatusAccepted && in.OpID != "" && r.AcceptedBy == canonicalUUIDish(in.TechnicianID) {
			var op *string
			if err := tx.QueryRow(ctx, `SELECT accept_op FROM help_request WHERE tenant_id = $1 AND id = $2`,
				tenantID, r.ID).Scan(&op); err != nil {
				return err
			}
			if op != nil && *op == in.OpID {
				rec, err := scanSessionRecord(tx.QueryRow(ctx, selectSessionRecord+` WHERE s.tenant_id = $1 AND s.id = $2`,
					tenantID, r.SessionID))
				if err == nil {
					out.Outcome, out.Request, out.Record = HelpAcceptReplayed, r, rec
					return nil
				}
				if !errors.Is(err, ErrSessionRecordNotFound) {
					return err
				}
			}
		}
		if r.Status == HelpStatusOpen && !in.Now.Before(r.ExpiresAt) {
			if _, err := tx.Exec(ctx, `UPDATE help_request SET status = 'expired', closed_at = $3
				WHERE tenant_id = $1 AND id = $2 AND status = 'open'`, tenantID, r.ID, helpClip(in.Now)); err != nil {
				return err
			}
			r.Status = HelpStatusExpired
			t := helpClip(in.Now)
			r.ClosedAt = &t
			if err := s.appendAudit(ctx, tx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpExpired, r.ID, "",
				helpDeviceMeta(r, map[string]any{"reason": "ttl"}))); err != nil {
				return err
			}
		}
		if r.Status != HelpStatusOpen {
			out.Outcome, out.Request = HelpAcceptConflict, r
			return nil
		}
		var m helpMachineRow
		err = tx.QueryRow(ctx, `SELECT id::text, device_id, coalesce(group_id::text, ''), status, ephemeral
			FROM machine WHERE tenant_id = $1 AND id = $2 FOR SHARE`, tenantID, r.MachineID).
			Scan(&m.ID, &m.DeviceID, &m.GroupID, &m.Status, &m.Ephemeral)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !helpMachineEligible(&m) {
			out.Outcome, out.Request = HelpAcceptIneligible, r
			return nil
		}
		// The admission the handler computed was for the group the machine had THEN. If it moved, refuse:
		// the caller re-evaluates the actor's coverage of the new group (H-C5).
		if m.GroupID != canonicalUUIDish(in.AdmissionGroupID) || canonicalUUIDish(in.Record.MachineID) != r.MachineID {
			out.Outcome, out.Request = HelpAcceptGroupChanged, r
			return nil
		}
		switch in.presenceOf(m.DeviceID) {
		case HelpPresenceOffline:
			out.Outcome, out.Request = HelpAcceptOffline, r
			return nil
		case HelpPresenceUnknown:
			out.Outcome, out.Request = HelpAcceptPresenceUnknown, r
			return nil
		}
		if err := admitSessionTx(ctx, tx, tenantID, in.Record, in.Limits); err != nil {
			return err
		}
		var opArg any
		if in.OpID != "" {
			opArg = in.OpID
		}
		r, err = scanHelpRequest(tx.QueryRow(ctx, `
			UPDATE help_request SET status = 'accepted', accepted_by = $3, accepted_at = $4, closed_at = $4,
			       accept_op = $5, session_id = $6, delivery = 'pending'
			WHERE tenant_id = $1 AND id = $2 AND status = 'open' RETURNING `+helpCols,
			tenantID, r.ID, in.TechnicianID, helpClip(in.Now), opArg, in.Record.ID))
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, tenantID, &out.HelpResult, helpAuditEvent(AuditHelpAccepted, r.ID, in.TechnicianID,
			helpAcceptedMeta(r, m.GroupID, in.Record.ID))); err != nil {
			return err
		}
		out.Outcome, out.Request, out.Record = HelpAcceptAccepted, r, in.Record
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pgOneOpenViolation reports a violation of the one-open-request-per-machine index.
func pgOneOpenViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "uq_help_request_one_open_per_machine"
}

// inSavepoint runs fn inside a savepoint so a failed statement (a unique violation) can be handled without
// aborting the whole transaction.
func inSavepoint(ctx context.Context, tx pgx.Tx, fn func() error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(); err != nil {
		_ = sp.Rollback(ctx)
		return err
	}
	return sp.Commit(ctx)
}

// ReopenAfterFailedStart implements HelpRequestStore.
//
// A reopen ADDS an open request, so it goes through the same serialized admission as a creation: it takes
// the tenant help lock (order: machine FOR SHARE, tenant lock, request row) and counts the tenant's open
// requests under it. Policy: reopen only while under helpTenantOpenCap; at the cap the request is cancelled
// with reason `capacity` (audited) rather than pushing the queue above the cap. Because stranding the request
// 'accepted' on a lock timeout would be worse than waiting, the lock wait is long (helpReopenLockWait) and the
// whole attempt is retried a bounded number of times. The one-open-per-machine index still decides the
// superseded branch. A machine no longer in service closes the request as cancelled (H-C5).
func (s *PgHelpRequestStore) ReopenAfterFailedStart(ctx context.Context, tenantID, requestID, sessionID string, now time.Time) (*HelpTransitionResult, error) {
	out := &HelpTransitionResult{}
	if _, ok := parsePgUUID(requestID); !ok {
		return out, nil
	}
	var err error
	for attempt := 0; attempt < helpReopenAttempts; attempt++ {
		err = s.reopenOnce(ctx, tenantID, requestID, sessionID, now, out)
		var le *HelpLimitError
		if !errors.As(err, &le) || le.Scope != "busy" {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PgHelpRequestStore) reopenOnce(ctx context.Context, tenantID, requestID, sessionID string, now time.Time, out *HelpTransitionResult) error {
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*out = HelpTransitionResult{}
		var machineID string
		if err := tx.QueryRow(ctx, `SELECT machine_id::text FROM help_request WHERE tenant_id = $1 AND id = $2`,
			tenantID, requestID).Scan(&machineID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		var m helpMachineRow
		if err := tx.QueryRow(ctx, `SELECT id::text, device_id, coalesce(group_id::text, ''), status, ephemeral
			FROM machine WHERE tenant_id = $1 AND id = $2 FOR SHARE`, tenantID, machineID).
			Scan(&m.ID, &m.DeviceID, &m.GroupID, &m.Status, &m.Ephemeral); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if err := lockHelpTxWait(ctx, tx, tenantID, helpReopenLockWait); err != nil {
			return err
		}
		r, err := scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, requestID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// CLAIM: only a session whose ticket was never delivered may be given up on. A delivered one is the
		// technician's now (a retry may even be using it): conflict, and the caller must not end it.
		if r.Status != HelpStatusAccepted || r.SessionID != canonicalUUIDish(sessionID) || r.Delivery != HelpDeliveryPending {
			out.Request, out.Conflict = r, true
			return nil
		}
		failed := r.SessionID
		const clear = `accepted_by = NULL, accepted_at = NULL, accept_op = NULL, session_id = NULL, delivery = NULL`
		closeAs := func(status, reason string) (*HelpRequest, error) {
			var reasonArg any
			if reason != "" {
				reasonArg = reason
			}
			return scanHelpRequest(tx.QueryRow(ctx, `UPDATE help_request SET status = $3, closed_at = $4, cancel_reason = $5, `+clear+`
				WHERE tenant_id = $1 AND id = $2 RETURNING `+helpCols, tenantID, r.ID, status, helpClip(now), reasonArg))
		}
		var event *MgmtAuditEvent
		switch {
		case !now.Before(r.ExpiresAt):
			r, err = closeAs(HelpStatusExpired, "")
			if err == nil {
				event = helpAuditEvent(AuditHelpExpired, r.ID, "", helpDeviceMeta(r,
					map[string]any{"reason": "accept_failed", "failed_session_id": failed}))
			}
		case !helpMachineEligible(&m):
			// Retired / quarantined while the accept was in flight: never reopen onto a machine out of service.
			reason := HelpCancelRetired
			if m.Status == MachineStatusQuarantined {
				reason = HelpCancelQuarantined
			}
			r, err = closeAs(HelpStatusCancelled, reason)
			if err == nil {
				event = helpAuditEvent(AuditHelpCancelled, r.ID, "", helpDeviceMeta(r,
					map[string]any{"reason": reason, "failed_session_id": failed, "actor_kind": "system"}))
			}
		default:
			var openCount int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM help_request WHERE tenant_id = $1 AND status = 'open'`, tenantID).Scan(&openCount); err != nil {
				return err
			}
			if openCount >= helpTenantOpenCap {
				r, err = closeAs(HelpStatusCancelled, HelpCancelCapacity)
				if err == nil {
					event = helpAuditEvent(AuditHelpCancelled, r.ID, "", helpDeviceMeta(r,
						map[string]any{"reason": HelpCancelCapacity, "failed_session_id": failed, "actor_kind": "system"}))
				}
				break
			}
			var reopened *HelpRequest
			err = inSavepoint(ctx, tx, func() error {
				var e error
				reopened, e = scanHelpRequest(tx.QueryRow(ctx, `UPDATE help_request SET status = 'open', closed_at = NULL, cancel_reason = NULL, `+clear+`
					WHERE tenant_id = $1 AND id = $2 RETURNING `+helpCols, tenantID, r.ID))
				return e
			})
			switch {
			case err == nil:
				r = reopened
				event = helpAuditEvent(AuditHelpReopened, r.ID, "", helpDeviceMeta(r,
					map[string]any{"reason": "accept_failed", "failed_session_id": failed}))
			case pgOneOpenViolation(err):
				r, err = closeAs(HelpStatusCancelled, HelpCancelSuperseded)
				if err == nil {
					event = helpAuditEvent(AuditHelpCancelled, r.ID, "", helpDeviceMeta(r,
						map[string]any{"reason": HelpCancelSuperseded, "failed_session_id": failed}))
				}
			}
		}
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, tenantID, &out.HelpResult, event); err != nil {
			return err
		}
		out.Changed, out.Request = true, r
		return nil
	})
	return err
}

// MarkDelivered implements HelpRequestStore: compare-and-swap pending -> delivered for the accepted request's
// session. Not Changed means the claim was lost (or already delivered); Request holds the current state.
func (s *PgHelpRequestStore) MarkDelivered(ctx context.Context, tenantID, requestID, sessionID string, now time.Time) (*HelpTransitionResult, error) {
	out := &HelpTransitionResult{}
	if _, ok := parsePgUUID(requestID); !ok {
		return out, nil
	}
	if _, ok := parsePgUUID(sessionID); !ok {
		return out, nil
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*out = HelpTransitionResult{}
		r, err := scanHelpRequest(tx.QueryRow(ctx, `UPDATE help_request SET delivery = 'delivered'
			WHERE tenant_id = $1 AND id = $2 AND status = 'accepted' AND session_id = $3 AND delivery = 'pending'
			RETURNING `+helpCols, tenantID, requestID, sessionID))
		if err == nil {
			out.Changed, out.Request = true, r
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		r, err = scanHelpRequest(tx.QueryRow(ctx, `SELECT `+helpCols+` FROM help_request WHERE tenant_id = $1 AND id = $2`, tenantID, requestID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.Request, out.Conflict = r, true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CancelForMachine implements HelpRequestStore.
func (s *PgHelpRequestStore) CancelForMachine(ctx context.Context, tenantID, machineID, reason string, now time.Time) (*HelpResult, error) {
	res := &HelpResult{}
	if _, ok := parsePgUUID(machineID); !ok {
		return res, nil
	}
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		*res = HelpResult{}
		rows, err := tx.Query(ctx, `UPDATE help_request SET status = 'cancelled', closed_at = $3, cancel_reason = $4
			WHERE tenant_id = $1 AND machine_id = $2 AND status = 'open' RETURNING `+helpCols,
			tenantID, machineID, helpClip(now), reason)
		if err != nil {
			return err
		}
		var done []*HelpRequest
		for rows.Next() {
			r, err := scanHelpRequest(rows)
			if err != nil {
				rows.Close()
				return err
			}
			done = append(done, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range done {
			if err := s.appendAudit(ctx, tx, tenantID, res, helpAuditEvent(AuditHelpCancelled, r.ID, "",
				helpDeviceMeta(r, map[string]any{"reason": reason, "actor_kind": "system"}))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Sweep implements HelpRequestStore: expire what is due, prune closed requests older than 30 days and the
// op ledger, tenant by tenant. cp_help_request_due_tenants (SECURITY DEFINER) names the tenants with work.
func (s *PgHelpRequestStore) Sweep(ctx context.Context, now time.Time) (*HelpSweepResult, error) {
	rows, err := s.Pool.Query(ctx, `SELECT tenant_id::text FROM cp_help_request_due_tenants($1, $2, $3) LIMIT $4`,
		now, now.Add(-helpClosedRetention), now.Add(-helpOpDedupWindow), helpSweepTenantsPerRun)
	if err != nil {
		return nil, err
	}
	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		tenants = append(tenants, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &HelpSweepResult{}
	for _, t := range tenants {
		var res HelpResult
		var expired, pruned int
		err := withTenant(ctx, s.Pool, t, func(tx pgx.Tx) error {
			res, expired, pruned = HelpResult{}, 0, 0
			if err := lockHelpTx(ctx, tx, t); err != nil {
				return err
			}
			n, err := s.expireDueTx(ctx, tx, t, now, &res)
			if err != nil {
				return err
			}
			expired = n
			tag, err := tx.Exec(ctx, `DELETE FROM help_request WHERE tenant_id = $1 AND status <> 'open' AND closed_at < $2`,
				t, now.Add(-helpClosedRetention))
			if err != nil {
				return err
			}
			pruned = int(tag.RowsAffected())
			if _, err = tx.Exec(ctx, `DELETE FROM help_request_op WHERE tenant_id = $1 AND created_at < $2`,
				t, now.Add(-helpOpDedupWindow)); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `DELETE FROM help_request_call WHERE tenant_id = $1 AND bucket < $2`,
				t, helpCallBucket(now.Add(-helpOpDedupWindow)))
			return err
		})
		if err != nil {
			// One tenant's failure must not starve the rest; the lazy expiry still protects correctness.
			continue
		}
		out.Tenants++
		out.Expired += expired
		out.Pruned += pruned
		for _, e := range res.Events {
			out.Events = append(out.Events, HelpSweepEvent{TenantID: t, Event: e})
		}
	}
	return out, nil
}
