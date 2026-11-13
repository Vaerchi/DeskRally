package controlplane

// PgDirectiveStore - DirectiveStore over agent_directive / tenant_directive_policy (migrations/0068),
// RLS-pinned through withTenant like every other store. See directive.go for the protocol.
//
// LOCK ORDER (every method that takes more than one): the tenant issuance lock (SHARED, transaction level -
// the same key cp_platform_set_suspended takes exclusively, so a suspension serializes with issuance), the
// tenant quota lock, the machine row, the directive row, and last the management-audit chain. Each
// transition appends its audit row INSIDE the same transaction, BEFORE the state it describes is written,
// so a failing audit store leaves no directive, no issuance and no delivery.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgDirectiveStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore

	// UninstallHourlyCap / ReinstallDailyCap / ReinstallHourlyCap: the quotas (defaults by NewPgDirectiveStore).
	UninstallHourlyCap int
	ReinstallDailyCap  int
	ReinstallHourlyCap int

	// testAfterPolicyRead (tests only) runs inside Issue's transaction right after the policy read: it lets a
	// test pause issuance exactly where a concurrent policy change used to be able to slip in.
	testAfterPolicyRead func()
	// testAfterForgetLock (tests only) runs inside ForgetMachine's transaction right after the machine row was
	// locked FOR UPDATE, and testAfterAckLock inside ApplyAckVia's right after the directive row was locked: a
	// test holds one of them open to show the other must wait for its commit, in both orders.
	testAfterForgetLock func()
	testAfterAckLock    func()
}

func NewPgDirectiveStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgDirectiveStore {
	return &PgDirectiveStore{Pool: pool, Audit: audit,
		UninstallHourlyCap: DefaultUninstallHourlyCap, ReinstallDailyCap: DefaultReinstallDailyCap,
		ReinstallHourlyCap: DefaultReinstallHourlyCap}
}

var _ DirectiveStore = (*PgDirectiveStore)(nil)

const selectDirective = `
	SELECT id::text, tenant_id::text, machine_id::text, device_id, key_fp, group_id::text, kind, state,
	       requested_by::text, requested_at, not_before, request_expires_at, require_approval, policy_version,
	       approved_by::text, approved_at, cancelled_by::text, cancelled_at, cancel_reason, issued_at, expires_at,
	       nonce, artifact, delivered_at, acked_at, state_detail, updated_at,
	       requested_session_id, requested_cred_epoch, requested_mfa_gen,
	       approved_session_id, approved_cred_epoch, approved_mfa_gen, last_ack_ts_ms, agent_state
	FROM agent_directive
`

func scanDirective(row pgx.Row) (*AgentDirective, error) {
	var d AgentDirective
	var kind, state string
	var approvedBy, cancelledBy, cancelReason, artifact *string
	var reqEpoch, apprEpoch *time.Time
	var agentState string
	if err := row.Scan(&d.ID, &d.TenantID, &d.MachineID, &d.DeviceID, &d.KeyFP, &d.GroupID, &kind, &state,
		&d.RequestedBy, &d.RequestedAt, &d.NotBefore, &d.RequestExpiresAt, &d.RequireApproval, &d.PolicyVersion,
		&approvedBy, &d.ApprovedAt, &cancelledBy, &d.CancelledAt, &cancelReason, &d.IssuedAt, &d.ExpiresAt,
		&d.Nonce, &artifact, &d.DeliveredAt, &d.AckedAt, &d.StateDetail, &d.UpdatedAt,
		&d.RequestedSession, &reqEpoch, &d.RequestedMFAGen,
		&d.ApprovedSession, &apprEpoch, &d.ApprovedMFAGen, &d.LastAckTsMs, &agentState); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDirectiveNotFound
		}
		return nil, err
	}
	d.Kind, d.State, d.AgentState = DirectiveKind(kind), DirectiveState(state), DirectiveState(agentState)
	if reqEpoch != nil {
		d.RequestedEpoch = reqEpoch.UTC()
	}
	if apprEpoch != nil {
		d.ApprovedEpoch = apprEpoch.UTC()
	}
	for _, f := range []struct {
		src *string
		dst *string
	}{{approvedBy, &d.ApprovedBy}, {cancelledBy, &d.CancelledBy}, {cancelReason, &d.CancelReason}, {artifact, &d.Artifact}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	return &d, nil
}

func (s *PgDirectiveStore) appendAudit(ctx context.Context, tx pgx.Tx, tenantID string, e *MgmtAuditEvent) error {
	return s.Audit.appendTx(ctx, tx, tenantID, e)
}

// lockTenantIssuance takes the SHARED transaction-level issuance lock (bounded wait) and reports whether the
// tenant is suspended. The suspension reads/writes under the EXCLUSIVE lock on the same key.
func lockTenantIssuance(ctx context.Context, tx pgx.Tx, tenantID string) (suspended bool, err error) {
	if _, err = tx.Exec(ctx, `SELECT set_config('lock_timeout', '5000', true)`); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, issuanceLockKey(tenantID)); err != nil {
		return false, err
	}
	err = tx.QueryRow(ctx, `SELECT disabled_at IS NOT NULL FROM tenant WHERE id = $1`, tenantID).Scan(&suspended)
	return suspended, err
}

// lockTenantIssuanceExclusive is the EXCLUSIVE form of the issuance lock, taken by a policy change. Every
// request and every issuance reads the policy while holding the shared form until its transaction commits,
// so a policy change (including the first one, when no policy row exists to lock) can neither slip between
// an issuance's policy read and its commit nor be missed by it: they serialize on this one key.
func lockTenantIssuanceExclusive(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', '5000', true)`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, issuanceLockKey(tenantID))
	return err
}

func lockDirectiveQuota(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('directive_quota:' || $1, 0))`, canonicalUUIDish(tenantID))
	return err
}

func dbNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var t time.Time
	err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&t)
	return t.UTC(), err
}

const lockMachineForShare = `
	SELECT id::text, tenant_id::text, device_id, group_id::text, status, pubkey
	FROM machine WHERE id = $1 FOR SHARE`

const lockMachineForUpdate = `
	SELECT id::text, tenant_id::text, device_id, group_id::text, status, pubkey
	FROM machine WHERE id = $1 FOR UPDATE`

// lockMachine reads the machine FOR SHARE (or FOR UPDATE when the caller will write it).
func lockMachine(ctx context.Context, tx pgx.Tx, machineID string, forUpdate bool) (*Machine, error) {
	var m Machine
	var pub []byte
	var row pgx.Row
	if forUpdate {
		row = tx.QueryRow(ctx, lockMachineForUpdate, machineID)
	} else {
		row = tx.QueryRow(ctx, lockMachineForShare, machineID)
	}
	err := row.Scan(&m.ID, &m.TenantID, &m.DeviceID, &m.GroupID, &m.Status, &pub)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMachineNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(pub) > 0 {
		m.Pubkey = hex.EncodeToString(pub)
	}
	return &m, nil
}

func lockDirective(ctx context.Context, tx pgx.Tx, id string) (*AgentDirective, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrDirectiveNotFound
	}
	return scanDirective(tx.QueryRow(ctx, selectDirective+"WHERE id = $1 FOR UPDATE", id))
}

func (s *PgDirectiveStore) policyTx(ctx context.Context, tx pgx.Tx, tenantID string) (DirectivePolicy, error) {
	var p DirectivePolicy
	err := tx.QueryRow(ctx, `SELECT require_second_approver, version FROM tenant_directive_policy WHERE tenant_id = $1`, tenantID).
		Scan(&p.RequireSecondApprover, &p.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectivePolicy{}, nil
	}
	return p, err
}

func (s *PgDirectiveStore) Request(ctx context.Context, tenantID string, in DirectiveRequestInput) (*AgentDirective, error) {
	if !in.Kind.Valid() {
		return nil, ErrDirectiveBadTransition
	}
	if namesNoUUIDRow(in.MachineID) {
		return nil, ErrMachineNotFound
	}
	var out *AgentDirective
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		suspended, err := lockTenantIssuance(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if suspended {
			outErr = ErrDirectiveTenantSuspended
			return nil
		}
		if err := lockDirectiveQuota(ctx, tx, tenantID); err != nil {
			return err
		}
		m, err := lockMachine(ctx, tx, in.MachineID, false)
		if err != nil {
			outErr = err
			return nil
		}
		switch {
		case m.Status == MachineStatusRemoved:
			outErr = ErrDirectiveMachineRemoved
			return nil
		case m.Pubkey == "":
			outErr = ErrDirectiveNoKey
			return nil
		case !sameUserID(m.GroupID, in.ExpectGroupID):
			outErr = ErrDirectiveMachineChanged
			return nil
		case in.Kind == DirectiveUninstall && m.Status != MachineStatusRetired:
			outErr = ErrDirectiveNotRetired
			return nil
		case in.Kind == DirectiveReinstall && m.Status == MachineStatusRetired:
			outErr = ErrDirectiveMachineRetired
			return nil
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_directive WHERE machine_id = $1 AND state IN
			('requested', 'issued', 'accepted', 'executing', 'reboot_pending', 'removal_unconfirmed'))`, m.ID).Scan(&active); err != nil {
			return err
		}
		if active {
			outErr = ErrDirectiveActiveExists
			return nil
		}
		var used int
		if in.Kind == DirectiveUninstall {
			// Issued in the rolling hour (whatever became of them) plus live reservations.
			err = tx.QueryRow(ctx, quotaTenantQuery, tenantID, "uninstall", 3600).Scan(&used)
			if err == nil && used >= s.UninstallHourlyCap {
				outErr = ErrDirectiveQuota
				return nil
			}
		} else {
			err = tx.QueryRow(ctx, quotaMachineQuery, m.ID, "reinstall", 86400).Scan(&used)
			if err == nil && used >= s.ReinstallDailyCap {
				outErr = ErrDirectiveQuota
				return nil
			}
			if err == nil {
				// The tenant-wide hourly cap (a reinstall has no window and no approval).
				err = tx.QueryRow(ctx, quotaTenantQuery, tenantID, "reinstall", 3600).Scan(&used)
				if err == nil && used >= s.ReinstallHourlyCap {
					outErr = ErrDirectiveQuota
					return nil
				}
			}
		}
		if err != nil {
			return err
		}
		pol, err := s.policyTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		d := &AgentDirective{
			ID: newUUID(), TenantID: tenantID, MachineID: m.ID, DeviceID: m.DeviceID, KeyFP: fingerprintOf(m.Pubkey),
			GroupID: m.GroupID, Kind: in.Kind, State: DirectiveRequested, RequestedBy: in.RequestedBy,
			RequestedAt: now, NotBefore: now, RequestExpiresAt: now.Add(directiveRequestTTL), UpdatedAt: now,
			RequestedSession: in.RequestedSession, RequestedEpoch: in.RequestedEpoch, RequestedMFAGen: in.RequestedMFAGen,
		}
		if in.Kind == DirectiveUninstall {
			d.NotBefore = now.Add(directiveCancelWindow)
			d.RequireApproval = pol.RequireSecondApprover
			d.PolicyVersion = pol.Version
		}
		// AUDIT FIRST: the row that says this was requested exists before the request does.
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent(in.RequestedBy, "directive.requested", d, map[string]any{
			"not_before": d.NotBefore, "require_approval": d.RequireApproval})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_directive (id, tenant_id, machine_id, device_id, key_fp, group_id, kind, state, requested_by,
			    requested_at, not_before, request_expires_at, require_approval, policy_version, updated_at,
			    requested_session_id, requested_cred_epoch, requested_mfa_gen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'requested', $8, $9, $10, $11, $12, $13, $9, $14, $15, $16)`,
			d.ID, tenantID, d.MachineID, d.DeviceID, d.KeyFP, d.GroupID, string(d.Kind), d.RequestedBy,
			d.RequestedAt, d.NotBefore, d.RequestExpiresAt, d.RequireApproval, d.PolicyVersion,
			d.RequestedSession, nullTime(d.RequestedEpoch), d.RequestedMFAGen); err != nil {
			if isUniqueViolation(err) {
				outErr = ErrDirectiveActiveExists
				return errRollbackKeep // roll back the audit row too, surface outErr
			}
			return err
		}
		out = d
		return nil
	})
	if errors.Is(err, errRollbackKeep) {
		return nil, outErr
	}
	if err != nil {
		return nil, err
	}
	return out, outErr
}

// The quota queries (constants: the repo's SQL guard refuses a non-constant statement). Both count what was
// ISSUED in the window (issued_at, including directives that later expired or failed) plus the live
// RESERVATIONS (state requested); issuance counts issuances only (quotaIssued*).
const (
	quotaTenantQuery = `SELECT
		(SELECT count(*) FROM agent_directive WHERE tenant_id = $1 AND kind = $2
		    AND issued_at > now() - make_interval(secs => $3)) +
		(SELECT count(*) FROM agent_directive WHERE tenant_id = $1 AND kind = $2 AND state = 'requested')`
	quotaMachineQuery = `SELECT
		(SELECT count(*) FROM agent_directive WHERE machine_id = $1 AND kind = $2
		    AND issued_at > now() - make_interval(secs => $3)) +
		(SELECT count(*) FROM agent_directive WHERE machine_id = $1 AND kind = $2 AND state = 'requested')`
	quotaIssuedTenantQuery = `SELECT count(*) FROM agent_directive WHERE tenant_id = $1 AND kind = $2
		AND issued_at > now() - make_interval(secs => $3)`
	quotaIssuedMachineQuery = `SELECT count(*) FROM agent_directive WHERE machine_id = $1 AND kind = $2
		AND issued_at > now() - make_interval(secs => $3)`
)

// errRollbackKeep aborts the transaction (rolling back anything already appended) while the caller returns
// the sentinel it stashed in outErr.
var errRollbackKeep = errors.New("rollback and report the stashed outcome")

// nullTime stores the zero time as NULL ("no local credential").
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func (s *PgDirectiveStore) Approve(ctx context.Context, tenantID, id string, approver DirectiveActor) (*AgentDirective, error) {
	approverID := approver.UserID
	var out *AgentDirective
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		d, err := lockDirective(ctx, tx, id)
		if err != nil {
			outErr = err
			return nil
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case d.State != DirectiveRequested:
			out, outErr = d, ErrDirectiveNotPending
		case !now.Before(d.RequestExpiresAt):
			out, outErr = d, ErrDirectiveExpired
		case !d.RequireApproval:
			out, outErr = d, ErrDirectiveApprovalNotNeeded
		case sameUserID(d.RequestedBy, approverID):
			out, outErr = d, ErrDirectiveSelfApproval
		case d.ApprovedBy != "":
			out, outErr = d, ErrDirectiveAlreadyApproved
		}
		if outErr != nil {
			return nil
		}
		// Approval restarts the cancel window so it never issues immediately; no room left = expired.
		nb := now.Add(directiveCancelWindow)
		if nb.Before(d.NotBefore) {
			nb = d.NotBefore
		}
		if !nb.Before(d.RequestExpiresAt) {
			out, outErr = d, ErrDirectiveExpired
			return nil
		}
		d.ApprovedBy, d.ApprovedAt, d.UpdatedAt, d.NotBefore = approverID, &now, now, nb
		d.ApprovedSession, d.ApprovedEpoch, d.ApprovedMFAGen = approver.SessionID, approver.CredentialEpoch, approver.MFAGeneration
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent(approverID, "directive.approved", d, map[string]any{"not_before": nb})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_directive SET approved_by = $2, approved_at = $3, updated_at = $3, not_before = $4,
			approved_session_id = $5, approved_cred_epoch = $6, approved_mfa_gen = $7
			WHERE id = $1 AND state = 'requested'`, d.ID, approverID, now, nb,
			approver.SessionID, nullTime(approver.CredentialEpoch), approver.MFAGeneration); err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

func (s *PgDirectiveStore) Cancel(ctx context.Context, tenantID, id, actorID, reason string) (*AgentDirective, error) {
	if reason == "" {
		reason = "cancelled"
	}
	var out *AgentDirective
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		d, err := lockDirective(ctx, tx, id)
		if err != nil {
			outErr = err
			return nil
		}
		if d.State != DirectiveRequested {
			out, outErr = d, ErrDirectiveNotCancellable
			return nil
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		d.State, d.CancelledBy, d.CancelledAt, d.CancelReason, d.UpdatedAt = DirectiveCancelled, actorID, &now, reason, now
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent(actorID, "directive.cancelled", d, map[string]any{"reason": reason})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_directive SET state = 'cancelled', cancelled_by = $2, cancelled_at = $3,
			cancel_reason = $4, updated_at = $3 WHERE id = $1 AND state = 'requested'`, d.ID, actorID, now, reason); err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

func (s *PgDirectiveStore) Issue(ctx context.Context, tenantID, id string, deps DirectiveIssueDeps) (*AgentDirective, error) {
	if deps.Authority == nil || deps.Issuer == nil {
		return nil, errors.New("directive issuance is not configured")
	}
	if namesNoUUIDRow(id) {
		return nil, ErrDirectiveNotFound
	}
	var out *AgentDirective
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		suspended, err := lockTenantIssuance(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if suspended {
			outErr = ErrDirectiveTenantSuspended
			return nil
		}
		if err := lockDirectiveQuota(ctx, tx, tenantID); err != nil {
			return err
		}
		// The machine id is immutable, so it can be read before the row is locked; the lock order is
		// machine then directive everywhere.
		var machineID string
		if err := tx.QueryRow(ctx, `SELECT machine_id::text FROM agent_directive WHERE id = $1`, id).Scan(&machineID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				outErr = ErrDirectiveNotFound
				return nil
			}
			return err
		}
		m, merr := lockMachine(ctx, tx, machineID, false)
		if merr != nil && !errors.Is(merr, ErrMachineNotFound) {
			return merr
		}
		if errors.Is(merr, ErrMachineNotFound) {
			m = nil
		}
		d, err := lockDirective(ctx, tx, id)
		if err != nil {
			outErr = err
			return nil
		}
		if d.State != DirectiveRequested {
			out, outErr = d, ErrDirectiveNotIssuable
			return nil
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		// end() records the system's decision (cancel / expire) and commits it: the refusal is durable.
		end := func(state DirectiveState, action, reason string) error {
			d.State, d.UpdatedAt = state, now
			if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", action, d, map[string]any{"reason": reason})); err != nil {
				return err
			}
			if state == DirectiveCancelled {
				d.CancelledAt, d.CancelReason = &now, reason
				_, err = tx.Exec(ctx, `UPDATE agent_directive SET state = 'cancelled', cancelled_at = $2, cancel_reason = $3, updated_at = $2
					WHERE id = $1 AND state = 'requested'`, d.ID, now, reason)
				outErr = &DirectiveRefusedError{Reason: reason}
			} else {
				_, err = tx.Exec(ctx, `UPDATE agent_directive SET state = 'expired', updated_at = $2 WHERE id = $1 AND state = 'requested'`, d.ID, now)
				outErr = ErrDirectiveExpired
			}
			out = d
			return err
		}
		switch {
		case !now.Before(d.RequestExpiresAt):
			return end(DirectiveExpired, "directive.expired", "the request was not issued in time")
		case now.Before(d.NotBefore):
			out, outErr = d, ErrDirectiveTooEarly
			return nil
		case d.RequireApproval && d.ApprovedBy == "":
			out, outErr = d, ErrDirectiveNeedsApproval
			return nil
		}
		pol, err := s.policyTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if s.testAfterPolicyRead != nil {
			s.testAfterPolicyRead()
		}
		quotaOK := true
		if d.Kind == DirectiveUninstall {
			var used int
			if err := tx.QueryRow(ctx, quotaIssuedTenantQuery, tenantID, "uninstall", 3600).Scan(&used); err != nil {
				return err
			}
			quotaOK = used < s.UninstallHourlyCap
		} else {
			// Per-device daily and tenant-wide hourly, issuances only (this row is not issued yet).
			var daily, hourly int
			if err := tx.QueryRow(ctx, quotaIssuedMachineQuery, d.MachineID, "reinstall", 86400).Scan(&daily); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, quotaIssuedTenantQuery, tenantID, "reinstall", 3600).Scan(&hourly); err != nil {
				return err
			}
			quotaOK = daily < s.ReinstallDailyCap && hourly < s.ReinstallHourlyCap
		}
		if reason := directiveLocalChecks(d, m, pol, quotaOK); reason != "" {
			return end(DirectiveCancelled, "directive.cancelled", reason)
		}
		for _, who := range directiveActors(d) {
			if err := deps.Authority(ctx, who, m.GroupID); err != nil {
				if errors.Is(err, ErrDirectiveAuthorityLost) {
					return end(DirectiveCancelled, "directive.cancelled", ErrDirectiveAuthorityLost.Error())
				}
				return err
			}
		}
		claims, issued, expires, nonce, err := buildDirectiveClaims(d, now)
		if err != nil {
			return err
		}
		artifact, err := deps.Issuer.Sign(claims)
		if err != nil {
			return err
		}
		d.State, d.IssuedAt, d.ExpiresAt, d.Nonce, d.Artifact, d.UpdatedAt, d.GroupID =
			DirectiveIssued, &issued, &expires, nonce, artifact, now, m.GroupID
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", "directive.issued", d, map[string]any{
			"requested_by": d.RequestedBy, "approved_by": d.ApprovedBy, "expires_at": expires})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_directive SET state = 'issued', issued_at = $2, expires_at = $3, nonce = $4,
			artifact = $5, group_id = $6, updated_at = $7 WHERE id = $1 AND state = 'requested'`,
			d.ID, issued, expires, nonce, artifact, m.GroupID, now); err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

func (s *PgDirectiveStore) Get(ctx context.Context, tenantID, id string) (*AgentDirective, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrDirectiveNotFound
	}
	var out *AgentDirective
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		d, err := scanDirective(tx.QueryRow(ctx, selectDirective+"WHERE id = $1", id))
		out = d
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// The queries are CONSTANTS (the repo's SQL guard refuses a non-constant statement). The LIMIT literals must
// equal directiveListLimit / directivePendingLimit; the array-length tricks below fail the build if they drift.
const (
	listDirectivesByMachine = selectDirective + "WHERE machine_id = $1 ORDER BY requested_at DESC LIMIT 200"
	listDirectivesByTenant  = selectDirective + "ORDER BY requested_at DESC LIMIT 200"
	// The state list is directive.go DirectiveState.active(); TestPgActiveListMatchesActiveStates pins them together.
	listActiveDirectives = selectDirective + `
		WHERE state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending', 'removal_unconfirmed')
		  AND ($1::timestamptz IS NULL OR requested_at < $1 OR (requested_at = $1 AND id > $2::uuid))
		ORDER BY requested_at DESC, id LIMIT $3`
	pendingDirectivesQuery = selectDirective + `
		WHERE device_id = $1 AND key_fp = $2
		  AND ((state = 'issued' AND expires_at > now()) OR state IN ('accepted', 'executing', 'reboot_pending'))
		ORDER BY requested_at LIMIT 4`
)

var (
	_ = [1]struct{}{}[directiveListLimit-200]
	_ = [1]struct{}{}[directivePendingLimit-4]
)

func collectDirectives(rows pgx.Rows) ([]AgentDirective, error) {
	defer rows.Close()
	var out []AgentDirective
	for rows.Next() {
		d, err := scanDirective(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (s *PgDirectiveStore) List(ctx context.Context, tenantID, machineID string) ([]AgentDirective, error) {
	if machineID != "" && namesNoUUIDRow(machineID) {
		return nil, nil
	}
	var out []AgentDirective
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var rows pgx.Rows
		var err error
		if machineID != "" {
			rows, err = tx.Query(ctx, listDirectivesByMachine, machineID)
		} else {
			rows, err = tx.Query(ctx, listDirectivesByTenant)
		}
		if err != nil {
			return err
		}
		out, err = collectDirectives(rows)
		return err
	})
	return out, err
}

func (s *PgDirectiveStore) ListActive(ctx context.Context, tenantID string, before time.Time, beforeID string, limit int) ([]AgentDirective, error) {
	if limit <= 0 || limit > directiveListLimit {
		limit = directiveListLimit
	}
	var cursor, cursorID any
	if !before.IsZero() {
		cursor = before
		cursorID = beforeID
	}
	var out []AgentDirective
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, listActiveDirectives, cursor, cursorID, limit)
		if err != nil {
			return err
		}
		out, err = collectDirectives(rows)
		return err
	})
	return out, err
}

func (s *PgDirectiveStore) PendingForDevice(ctx context.Context, tenantID, deviceID, keyFP string) ([]AgentDirective, error) {
	var out []AgentDirective
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, pendingDirectivesQuery, deviceID, keyFP)
		if err != nil {
			return err
		}
		out, err = collectDirectives(rows)
		return err
	})
	return out, err
}
func (s *PgDirectiveStore) MarkDelivered(ctx context.Context, tenantID, id, deviceID string) error {
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		d, err := lockDirective(ctx, tx, id)
		if err != nil || d.DeviceID != deviceID {
			outErr = ErrDirectiveNotFound
			return nil
		}
		if d.DeliveredAt != nil || !d.State.active() {
			return nil
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		d.DeliveredAt, d.UpdatedAt = &now, now
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", "directive.delivered", d, nil)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE agent_directive SET delivered_at = $2, updated_at = $2 WHERE id = $1`, d.ID, now)
		return err
	})
	if err != nil {
		return err
	}
	return outErr
}

// FinalAckTarget reads cp_directive_final_ack_target (migration 0070): SECURITY DEFINER, no tenant context.
func (s *PgDirectiveStore) FinalAckTarget(ctx context.Context, id string) (*DirectiveFinalAckTarget, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrDirectiveNotFound
	}
	var t DirectiveFinalAckTarget
	var kind, state string
	var pub []byte
	err := s.Pool.QueryRow(ctx, `SELECT tenant_id::text, device_id, key_fp, kind, state, updated_at, db_now, pubkey
		FROM cp_directive_final_ack_target($1::uuid)`, id).Scan(&t.TenantID, &t.DeviceID, &t.KeyFP, &kind, &state,
		&t.UpdatedAt, &t.Now, &pub)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDirectiveNotFound
		}
		return nil, err
	}
	t.Kind, t.State, t.MachinePubkey = DirectiveKind(kind), DirectiveState(state), hex.EncodeToString(pub)
	t.UpdatedAt, t.Now = t.UpdatedAt.UTC(), t.Now.UTC()
	return &t, nil
}

func (s *PgDirectiveStore) ApplyAck(ctx context.Context, tenantID, id, deviceID string, a DirectiveAck) (*AgentDirective, bool, error) {
	return s.ApplyAckVia(ctx, tenantID, id, deviceID, a, "")
}

func (s *PgDirectiveStore) ApplyAckVia(ctx context.Context, tenantID, id, deviceID string, a DirectiveAck, channel string) (*AgentDirective, bool, error) {
	to, from := directiveAckTarget(a.To), directiveAckTarget(a.From)
	if len(a.Detail) > maxDirectiveDetailBytes {
		return nil, false, ErrDirectiveBadTransition
	}
	if namesNoUUIDRow(id) {
		return nil, false, ErrDirectiveNotFound
	}
	var out *AgentDirective
	var applied bool
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Pre-read (unlocked) to learn the machine and whether this ack will write it: lock order is
		// machine then directive.
		var machineID, kind string
		if err := tx.QueryRow(ctx, `SELECT machine_id::text, kind FROM agent_directive WHERE id = $1`, id).Scan(&machineID, &kind); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				outErr = ErrDirectiveNotFound
				return nil
			}
			return err
		}
		completesUninstall := to == DirectiveComplete && DirectiveKind(kind) == DirectiveUninstall
		var lockedMachine *Machine
		// The final-ack route authenticated against the key it READ before this transaction; re-check it under
		// the machine row lock, for every result (a failed removal locks the machine too).
		if completesUninstall || channel == directiveFinalAckChannel {
			m, err := lockMachine(ctx, tx, machineID, true)
			if err != nil {
				return err
			}
			lockedMachine = m
		}
		d, err := lockDirective(ctx, tx, id)
		if err != nil {
			outErr = err
			return nil
		}
		if d.DeviceID != deviceID {
			outErr = ErrDirectiveNotFound
			return nil
		}
		if s.testAfterAckLock != nil {
			s.testAfterAckLock()
		}
		if channel == directiveFinalAckChannel && !directiveCompletionMachineOK(d, lockedMachine) {
			out, outErr = d, ErrDirectiveKeyChanged
			return nil
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case channel == directiveFinalAckChannel && !finalAckWindowOpen(d.State, d.UpdatedAt, now):
			// Judged on the LOCKED row and the database clock, before the replay branch and any write.
			out, outErr = d, ErrDirectiveFinalAckWindowClosed
		case time.UnixMilli(a.TsMs).After(now.Add(directiveClockSkew)):
			out, outErr = d, ErrDirectiveBadTimestamp
		case !directiveTransitionAllowed(from, to):
			out, outErr = d, ErrDirectiveBadTransition
		case d.State == to:
			out = d // exact replay: no-op
		case !directiveAckFromMatches(d, from, to):
			out, outErr = d, ErrDirectiveBadTransition
		case a.TsMs <= d.LastAckTsMs || time.UnixMilli(a.TsMs).Before(now.Add(-directiveAckMaxAge)):
			// A validly signed OLD ack must not move the row: strictly newer than the last accepted, and recent.
			out, outErr = d, ErrDirectiveStaleAck
		case from == DirectiveIssued && to == DirectiveAccepted && d.ExpiresAt != nil && !now.Before(*d.ExpiresAt):
			out, outErr = d, ErrDirectiveExpired
		}
		if outErr != nil || out != nil {
			return nil
		}
		if completesUninstall && !directiveCompletionMachineOK(d, lockedMachine) {
			// The machine is no longer the one this directive was issued for (re-enrolled / re-keyed).
			out, outErr = d, ErrDirectiveKeyChanged
			return nil
		}
		d.State, d.AckedAt, d.StateDetail, d.UpdatedAt, d.LastAckTsMs = to, &now, a.Detail, now, a.TsMs
		d.AgentState = to
		meta := map[string]any{"from": a.From, "actor_kind": "agent", "detail": a.Detail}
		if channel != "" {
			meta["channel"] = channel
		}
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", "directive."+a.To, d, meta)); err != nil {
			return err
		}
		if completesUninstall {
			if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", "machine.removed", d, map[string]any{"via_directive": d.ID})); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_directive SET state = $2, acked_at = $3, state_detail = $4, updated_at = $3,
			last_ack_ts_ms = $5, agent_state = $2 WHERE id = $1`,
			d.ID, string(to), now, a.Detail, a.TsMs); err != nil {
			return err
		}
		if completesUninstall {
			// The directive left its active state just above, so machine_directive_guard lets this through.
			if err := tombstoneMachineTx(ctx, tx, d.MachineID); err != nil {
				return err
			}
		}
		out, applied = d, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, applied, outErr
}

// tombstoneMachineTx is the D-C9 tombstone: the machine becomes 'removed' (terminal). It is the ONE statement a
// confirmed removal (ApplyAckVia) and an Owner's forget (ForgetMachine) both run, in the transaction that has
// just ended the machine's active directive, so machine_directive_guard lets it through (and DR002 keeps it
// there for good). Identity lookup (cp_machine_identity_by_device_id) and enrollment of the key
// (cp_machine_key_removed) read the status; nothing here touches the device id or the key.
func tombstoneMachineTx(ctx context.Context, tx pgx.Tx, machineID string) error {
	if _, err := tx.Exec(ctx, `UPDATE machine SET status = 'removed' WHERE id = $1`, machineID); err != nil {
		return mapMachineGuardError(err)
	}
	return nil
}

// forgetActiveDirectivesQuery locks (FOR UPDATE) every ACTIVE directive of one machine, oldest first. The
// state list is DirectiveState.active() (TestForgetQuerySQLMatchesActiveStates pins them together). At most one
// row can match: agent_directive_one_active.
const forgetActiveDirectivesQuery = selectDirective + `
	WHERE machine_id = $1
	  AND state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending', 'removal_unconfirmed')
	ORDER BY requested_at, id FOR UPDATE`

func (s *PgDirectiveStore) ForgetMachine(ctx context.Context, tenantID string, in ForgetMachineInput) (*ForgetResult, error) {
	if namesNoUUIDRow(in.MachineID) {
		return nil, ErrMachineNotFound
	}
	var out *ForgetResult
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// A bounded wait, like the issuance lock: a stuck transaction on this machine fails this forget fast and
		// loudly instead of queueing connections behind it.
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', '5000', true)`); err != nil {
			return err
		}
		// THE machine row lock (FOR UPDATE): a request, an issuance (both FOR SHARE) and a final-ack apply (FOR
		// UPDATE) on this machine serialize with this forget; whichever commits first is seen by the other.
		// Lock order, as everywhere: machine, directive, audit chain.
		m, err := lockMachine(ctx, tx, in.MachineID, true)
		if errors.Is(err, ErrMachineNotFound) {
			outErr = err
			return nil
		}
		if err != nil {
			return err
		}
		if s.testAfterForgetLock != nil {
			s.testAfterForgetLock()
		}
		switch {
		case m.Status == MachineStatusRemoved:
			out = &ForgetResult{AlreadyRemoved: true} // idempotent: nothing written, no second audit row
			return nil
		case !sameUserID(m.GroupID, in.ExpectGroupID):
			outErr = ErrDirectiveMachineChanged
			return nil
		case m.Status != MachineStatusRetired:
			outErr = ErrForgetNotRetired
			return nil
		}
		rows, err := tx.Query(ctx, forgetActiveDirectivesQuery, m.ID)
		if err != nil {
			return err
		}
		closed, err := collectDirectives(rows)
		if err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		// AUDIT FIRST: every row exists before the state it describes, in this one transaction, so a failing
		// audit store leaves the machine and every directive untouched. The rows are built from the directives
		// as they are BEFORE the closure (their state is the "from" of directive.forgotten).
		for _, e := range forgetAuditEvents(in.ActorID, m, closed) {
			if err := s.appendAudit(ctx, tx, tenantID, e); err != nil {
				return err
			}
		}
		for i := range closed {
			if _, err := tx.Exec(ctx, `UPDATE agent_directive SET state = 'forgotten', state_detail = $2, updated_at = $3 WHERE id = $1`,
				closed[i].ID, forgottenDetail, now); err != nil {
				return err
			}
			closed[i].State, closed[i].StateDetail, closed[i].UpdatedAt = DirectiveForgotten, forgottenDetail, now
		}
		// The directive(s) left their active state just above, so machine_directive_guard lets the tombstone through.
		if err := tombstoneMachineTx(ctx, tx, m.ID); err != nil {
			return err
		}
		out = &ForgetResult{Closed: closed}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

func (s *PgDirectiveStore) Policy(ctx context.Context, tenantID string) (DirectivePolicy, error) {
	var p DirectivePolicy
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		p, err = s.policyTx(ctx, tx, tenantID)
		return err
	})
	return p, err
}

func (s *PgDirectiveStore) SetPolicy(ctx context.Context, tenantID, actorID string, requireSecond bool) (DirectivePolicy, error) {
	var out DirectivePolicy
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockTenantIssuanceExclusive(ctx, tx, tenantID); err != nil {
			return err
		}
		cur, err := s.policyTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if cur.RequireSecondApprover == requireSecond {
			out = cur
			return nil
		}
		next := DirectivePolicy{RequireSecondApprover: requireSecond, Version: cur.Version + 1}
		raw, _ := json.Marshal(map[string]any{"require_second_approver": requireSecond, "version": next.Version})
		if err := s.appendAudit(ctx, tx, tenantID, &MgmtAuditEvent{ActorUserID: actorID,
			Action: "tenant.directive_policy_set", TargetKind: "tenant", TargetID: tenantID, Metadata: raw}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_directive_policy (tenant_id, require_second_approver, version, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (tenant_id) DO UPDATE SET require_second_approver = EXCLUDED.require_second_approver,
			    version = EXCLUDED.version, updated_at = now()`, tenantID, requireSecond, next.Version); err != nil {
			return err
		}
		out = next
		return nil
	})
	return out, err
}

func (s *PgDirectiveStore) SweepCandidates(ctx context.Context, limit int) ([]DirectiveSweepItem, error) {
	rows, err := s.Pool.Query(ctx, `SELECT tenant_id::text, directive_id::text, action
		FROM cp_directive_sweep_candidates(now(), make_interval(secs => $1), $2)`, directiveUnconfirmedAfter.Seconds(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectiveSweepItem
	for rows.Next() {
		var it DirectiveSweepItem
		if err := rows.Scan(&it.TenantID, &it.DirectiveID, &it.Action); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *PgDirectiveStore) Expire(ctx context.Context, tenantID, id string) (*AgentDirective, error) {
	var out *AgentDirective
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		d, err := lockDirective(ctx, tx, id)
		if err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		due := (d.State == DirectiveRequested && !now.Before(d.RequestExpiresAt)) ||
			(d.State == DirectiveIssued && d.ExpiresAt != nil && !now.Before(*d.ExpiresAt))
		if !due {
			return nil
		}
		from := string(d.State)
		d.State, d.UpdatedAt = DirectiveExpired, now
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", "directive.expired", d, map[string]any{"from": from})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_directive SET state = 'expired', updated_at = $2 WHERE id = $1`, d.ID, now); err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PgDirectiveStore) MarkUnconfirmed(ctx context.Context, tenantID, id string) (*AgentDirective, error) {
	var out *AgentDirective
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		d, err := lockDirective(ctx, tx, id)
		if err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		if !(d.State == DirectiveAccepted || d.State == DirectiveExecuting || d.State == DirectiveRebootPending) ||
			now.Before(d.UpdatedAt.Add(directiveUnconfirmedAfter)) {
			return nil
		}
		from := string(d.State)
		d.AgentState = d.State // the last state the agent was known to be in; the outcome below is ours
		d.State, d.StateDetail, d.UpdatedAt = DirectiveRemovalUnconfirmed, "the agent never reported a result", now
		if d.Kind == DirectiveReinstall {
			d.State = DirectiveFailed
		}
		if err := s.appendAudit(ctx, tx, tenantID, newDirectiveAuditEvent("", "directive."+string(d.State), d, map[string]any{"from": from})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_directive SET state = $2, state_detail = $3, updated_at = $4, agent_state = $5 WHERE id = $1`,
			d.ID, string(d.State), d.StateDetail, now, string(d.AgentState)); err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
