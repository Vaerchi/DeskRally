package controlplane

// PgSessionTransferStore — SessionTransferStore over session_transfer (migrations/0060), RLS-pinned
// through withTenant like every other store. See session_transfer.go for the protocol and the FIXED
// LOCK ORDER every method here follows: admission lock, then the offer row, then S1's row, then the
// management-audit chain (appended inside the same transaction, so a transition and its audit commit
// together or not at all).

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgSessionTransferStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

func NewPgSessionTransferStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgSessionTransferStore {
	return &PgSessionTransferStore{Pool: pool, Audit: audit}
}

var _ SessionTransferStore = (*PgSessionTransferStore)(nil)

const selectTransfer = `
	SELECT id::text, tenant_id::text, session_id::text, machine_id::text, group_id::text, from_user_id::text,
	       to_user_id::text, note, state, created_at, expires_at, releasing_at, accepted_by::text,
	       new_session_id::text, failure_reason
	FROM session_transfer
`

func scanTransfer(row pgx.Row) (*SessionTransfer, error) {
	var t SessionTransfer
	var group, to, acceptedBy, newSession, failure *string
	var state string
	if err := row.Scan(&t.ID, &t.TenantID, &t.SessionID, &t.MachineID, &group, &t.FromUserID,
		&to, &t.Note, &state, &t.CreatedAt, &t.ExpiresAt, &t.ReleasingAt, &acceptedBy, &newSession, &failure); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTransferNotFound
		}
		return nil, err
	}
	t.State = TransferState(state)
	for _, f := range []struct {
		src *string
		dst *string
	}{{group, &t.GroupID}, {to, &t.ToUserID}, {acceptedBy, &t.AcceptedBy}, {newSession, &t.NewSessionID}, {failure, &t.FailureReason}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	return &t, nil
}

// appendAudit appends one event inside tx (the chain lock is taken last, after every row lock).
func (s *PgSessionTransferStore) appendAudit(ctx context.Context, tx pgx.Tx, tenantID string, e *MgmtAuditEvent) error {
	return s.Audit.appendTx(ctx, tx, tenantID, e)
}

// lockOffer reads one offer FOR UPDATE. The caller already holds the admission lock.
func lockOffer(ctx context.Context, tx pgx.Tx, id string) (*SessionTransfer, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrTransferNotFound
	}
	return scanTransfer(tx.QueryRow(ctx, selectTransfer+"WHERE id = $1 FOR UPDATE", id))
}

type lockedS1 struct {
	TechnicianID string
	Access       string
	EndedAt      *time.Time
	AgentEndedAt *time.Time
	EndReason    *string
	MachineID    string
	GroupID      *string // the machine's CURRENT group
}

// lockSession reads S1 FOR UPDATE (the row, not the machine it joins).
func lockSession(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (*lockedS1, error) {
	var r lockedS1
	err := tx.QueryRow(ctx, `
		SELECT s.technician_id::text, s.access, s.ended_at, s.agent_ended_at, s.end_reason,
		       s.machine_id::text, m.group_id::text
		FROM session_record s JOIN machine m ON m.id = s.machine_id
		WHERE s.tenant_id = $1 AND s.id = $2
		FOR UPDATE OF s`, tenantID, sessionID).
		Scan(&r.TechnicianID, &r.Access, &r.EndedAt, &r.AgentEndedAt, &r.EndReason, &r.MachineID, &r.GroupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionRecordNotFound
	}
	return &r, err
}

func (s *PgSessionTransferStore) CreateOffer(ctx context.Context, tenantID string, in TransferOfferInput) (*SessionTransfer, error) {
	if namesNoUUIDRow(in.SessionID) {
		return nil, ErrSessionRecordNotFound
	}
	var out *SessionTransfer
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		// The live offer (at most one: the unique index) BEFORE S1, per the lock order.
		old, err := scanTransfer(tx.QueryRow(ctx, selectTransfer+
			`WHERE tenant_id = $1 AND session_id = $2 AND state IN ('pending', 'releasing') FOR UPDATE`,
			tenantID, in.SessionID))
		if err != nil && !errors.Is(err, ErrTransferNotFound) {
			return err
		}
		if err != nil {
			old = nil
		}
		s1, err := lockSession(ctx, tx, tenantID, in.SessionID)
		if err != nil {
			outErr = err
			return nil
		}
		if s1.EndedAt != nil || s1.Access != "control" || !sameUserID(s1.TechnicianID, in.FromUserID) {
			outErr = ErrTransferSessionNotHeld
			return nil
		}
		if old != nil {
			if old.State == TransferReleasing {
				outErr = ErrTransferReleasing
				return nil
			}
			var expired bool
			if err := tx.QueryRow(ctx, `SELECT expires_at <= clock_timestamp() FROM session_transfer WHERE id = $1`, old.ID).
				Scan(&expired); err != nil {
				return err
			}
			next, action, actor := TransferSuperseded, "session.transfer_superseded", in.FromUserID
			if expired {
				next, action, actor = TransferExpired, "session.transfer_expired", ""
			}
			if _, err := tx.Exec(ctx, `UPDATE session_transfer SET state = $2 WHERE id = $1 AND state = 'pending'`,
				old.ID, string(next)); err != nil {
				return err
			}
			old.State = next
			if err := s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent(actor, action, old, nil)); err != nil {
				return err
			}
		}
		// machine_id, group_id and from_user_id are DERIVED from the locked S1 row, never the request.
		t, err := scanTransfer(tx.QueryRow(ctx, `
			INSERT INTO session_transfer (tenant_id, session_id, machine_id, group_id, from_user_id, to_user_id, note, state, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', now() + make_interval(secs => $8))
			RETURNING id::text, tenant_id::text, session_id::text, machine_id::text, group_id::text, from_user_id::text,
			          to_user_id::text, note, state, created_at, expires_at, releasing_at, accepted_by::text,
			          new_session_id::text, failure_reason`,
			tenantID, in.SessionID, s1.MachineID, s1.GroupID, s1.TechnicianID, nullableGroupID(in.ToUserID), in.Note,
			transferOfferTTL.Seconds()))
		if err != nil {
			if isUniqueViolation(err) {
				outErr = ErrTransferReleasing
				return nil
			}
			return err
		}
		if err := s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent(in.FromUserID, "session.transfer_offered", t, nil)); err != nil {
			return err
		}
		out = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

func (s *PgSessionTransferStore) Cancel(ctx context.Context, tenantID, id, actor string) (*SessionTransfer, error) {
	var out *SessionTransfer
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		t, err := lockOffer(ctx, tx, id)
		if err != nil {
			outErr = err
			return nil
		}
		if !sameUserID(t.FromUserID, actor) {
			outErr = ErrTransferForbidden
			return nil
		}
		if t.State != TransferPending {
			out, outErr = t, ErrTransferNotPending
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE session_transfer SET state = 'cancelled' WHERE id = $1 AND state = 'pending'`, t.ID); err != nil {
			return err
		}
		t.State = TransferCancelled
		if err := s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent(actor, "session.transfer_cancelled", t, nil)); err != nil {
			return err
		}
		out = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

func (s *PgSessionTransferStore) Get(ctx context.Context, tenantID, id string) (*SessionTransfer, error) {
	if namesNoUUIDRow(id) {
		return nil, ErrTransferNotFound
	}
	var out *SessionTransfer
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		t, err := scanTransfer(tx.QueryRow(ctx, selectTransfer+"WHERE id = $1", id))
		out = t
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// collectTransfers drains a transfer query. The two listings below each carry their own CONSTANT SQL (the
// repo's SQL guards refuse a query assembled at run time); the LIMIT literal is transferListLimit.
func collectTransfers(rows pgx.Rows) ([]SessionTransfer, error) {
	defer rows.Close()
	out := []SessionTransfer{}
	for rows.Next() {
		t, err := scanTransfer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *PgSessionTransferStore) ListIncoming(ctx context.Context, tenantID, userID string) ([]SessionTransfer, error) {
	if namesNoUUIDRow(userID) {
		return []SessionTransfer{}, nil
	}
	var out []SessionTransfer
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectTransfer+`
			WHERE state = 'pending' AND expires_at > clock_timestamp() AND from_user_id <> $1
			  AND (to_user_id IS NULL OR to_user_id = $1)
			  AND EXISTS (SELECT 1 FROM session_record s
			              WHERE s.tenant_id = session_transfer.tenant_id AND s.id = session_transfer.session_id AND s.ended_at IS NULL)
			ORDER BY created_at DESC, id LIMIT 200`, userID)
		if err != nil {
			return err
		}
		out, err = collectTransfers(rows)
		return err
	})
	return out, err
}

func (s *PgSessionTransferStore) ListOutgoing(ctx context.Context, tenantID, userID string) ([]SessionTransfer, error) {
	if namesNoUUIDRow(userID) {
		return []SessionTransfer{}, nil
	}
	var out []SessionTransfer
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectTransfer+`
			WHERE from_user_id = $1 AND (state = 'releasing' OR (state = 'pending' AND expires_at > clock_timestamp()))
			ORDER BY created_at DESC, id LIMIT 200`, userID)
		if err != nil {
			return err
		}
		out, err = collectTransfers(rows)
		return err
	})
	return out, err
}

func (s *PgSessionTransferStore) Accept(ctx context.Context, tenantID, id, acceptor string) (*SessionTransfer, error) {
	var out *SessionTransfer
	var outErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		t, err := lockOffer(ctx, tx, id)
		if err != nil {
			outErr = err
			return nil
		}
		out = t
		if sameUserID(t.FromUserID, acceptor) || t.ToUserID != "" && !sameUserID(t.ToUserID, acceptor) {
			out, outErr = nil, ErrTransferForbidden
			return nil
		}
		switch t.State {
		case TransferReleasing, TransferAccepted, TransferFailed:
			if t.AcceptedBy != "" && sameUserID(t.AcceptedBy, acceptor) {
				return nil // a repeat accept is a status read: no mutation, no audit
			}
		}
		if t.State != TransferPending {
			outErr = ErrTransferNotPending
			return nil
		}
		// Expiry is enforced in DB time, and applies to 'pending' only.
		var expired bool
		if err := tx.QueryRow(ctx, `SELECT expires_at <= clock_timestamp() FROM session_transfer WHERE id = $1`, t.ID).
			Scan(&expired); err != nil {
			return err
		}
		if expired {
			if _, err := tx.Exec(ctx, `UPDATE session_transfer SET state = 'expired' WHERE id = $1 AND state = 'pending'`, t.ID); err != nil {
				return err
			}
			t.State = TransferExpired
			outErr = ErrTransferExpired
			return s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent("", "session.transfer_expired", t, nil))
		}
		s1, err := lockSession(ctx, tx, tenantID, t.SessionID)
		if err != nil && !errors.Is(err, ErrSessionRecordNotFound) {
			return err
		}
		if err != nil || s1.EndedAt != nil {
			outErr = ErrTransferSessionEnded
			return nil
		}
		// State-conditional: only a still-pending row moves.
		ct, err := tx.Exec(ctx, `
			UPDATE session_transfer SET state = 'releasing', accepted_by = $2, releasing_at = clock_timestamp()
			WHERE id = $1 AND state = 'pending'`, t.ID, acceptor)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			outErr = ErrTransferNotPending
			return nil
		}
		t, err = scanTransfer(tx.QueryRow(ctx, selectTransfer+"WHERE id = $1", t.ID))
		if err != nil {
			return err
		}
		out = t
		return s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent(acceptor, "session.transfer_accepted", t, nil))
	})
	if err != nil {
		return nil, err
	}
	return out, outErr
}

// failTx moves a releasing (or pending-finalize) offer to failed and audits it. The caller holds the locks.
func (s *PgSessionTransferStore) failTx(ctx context.Context, tx pgx.Tx, tenantID string, t *SessionTransfer, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	ct, err := tx.Exec(ctx, `UPDATE session_transfer SET state = 'failed', failure_reason = $2 WHERE id = $1 AND state = 'releasing'`,
		t.ID, reason)
	if err != nil {
		return err
	}
	if ct.RowsAffected() != 1 {
		return nil
	}
	t.State, t.FailureReason = TransferFailed, reason
	return s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent("", "session.transfer_failed", t, map[string]any{"reason": reason}))
}

// reconcileTx applies the time rules to t (loaded FOR UPDATE under the admission lock) and, when admit
// is non-nil and the agent has reported S1 gone, finalizes. The pg twin of reconcileLocked.
func (s *PgSessionTransferStore) reconcileTx(ctx context.Context, tx pgx.Tx, tenantID string, t *SessionTransfer, admit TransferAdmitter) error {
	switch t.State {
	case TransferPending:
		var expired bool
		if err := tx.QueryRow(ctx, `SELECT expires_at <= clock_timestamp() FROM session_transfer WHERE id = $1`, t.ID).
			Scan(&expired); err != nil {
			return err
		}
		if expired {
			if _, err := tx.Exec(ctx, `UPDATE session_transfer SET state = 'expired' WHERE id = $1 AND state = 'pending'`, t.ID); err != nil {
				return err
			}
			t.State = TransferExpired
			return s.appendAudit(ctx, tx, tenantID, newTransferAuditEvent("", "session.transfer_expired", t, nil))
		}
	case TransferReleasing:
		s1, err := lockSession(ctx, tx, tenantID, t.SessionID)
		if err != nil {
			return err
		}
		if s1.AgentEndedAt != nil {
			// The deadline is judged by WHEN the report first arrived (both stamps are DB time), never by
			// when this reconcile happens to run: a report that came after releasing_at + 60 s fails the
			// offer even if no poll or sweep marked it failed first; a timely one still finalizes on a
			// delayed retry.
			if t.ReleasingAt != nil && s1.AgentEndedAt.After(t.ReleasingAt.Add(transferReleaseTimeout)) {
				return s.failTx(ctx, tx, tenantID, t, transferFailReleaseTimeout)
			}
			if admit == nil {
				return nil // the acceptor's poll (or the end report) finalizes
			}
			return s.finalizeTx(ctx, tx, tenantID, t, s1, admit)
		}
		var timedOut bool
		if err := tx.QueryRow(ctx, `SELECT releasing_at + make_interval(secs => $2) <= clock_timestamp() FROM session_transfer WHERE id = $1`,
			t.ID, transferReleaseTimeout.Seconds()).Scan(&timedOut); err != nil {
			return err
		}
		if timedOut {
			return s.failTx(ctx, tx, tenantID, t, transferFailReleaseTimeout)
		}
	}
	return nil
}

// finalizeTx is §8's finalizeTransferIfReleased body: the offer is releasing and S1 (locked) carries
// agent_ended_at. It ends S1 if still open, re-derives the acceptor's authority (admit), admits S2
// through admitSessionTx (the counts see S1 ended) and completes the offer, all in tx. An S2 refusal
// fails the offer but KEEPS S1's end: the agent has already said it is gone.
func (s *PgSessionTransferStore) finalizeTx(ctx context.Context, tx pgx.Tx, tenantID string, t *SessionTransfer, s1 *lockedS1, admit TransferAdmitter) error {
	adm, aerr := admit(withoutBoundConn(ctx), t) // the callback reads other stores: never on the request-bound connection that is inside tx
	var refused *TransferRefusedError
	if aerr != nil && !errors.As(aerr, &refused) {
		return aerr // infrastructure failure: roll back untouched, retried by the next report or poll
	}
	endedS1 := false
	if s1.EndedAt == nil {
		ct, err := tx.Exec(ctx, `UPDATE session_record SET ended_at = clock_timestamp(), end_reason = 'transferred'
		                          WHERE tenant_id = $1 AND id = $2 AND ended_at IS NULL`, tenantID, t.SessionID)
		if err != nil {
			return err
		}
		endedS1 = ct.RowsAffected() == 1
	} else if s1.EndReason == nil {
		if _, err := tx.Exec(ctx, `UPDATE session_record SET end_reason = 'transferred'
		                            WHERE tenant_id = $1 AND id = $2 AND end_reason IS NULL`, tenantID, t.SessionID); err != nil {
			return err
		}
	}
	if endedS1 {
		if err := s.appendAudit(ctx, tx, tenantID, transferSessionEndEvent(t)); err != nil {
			return err
		}
	}
	reason := ""
	if refused != nil {
		reason = refused.Reason
	} else {
		if err := normalizeSessionRecordAccess(adm.Rec); err != nil {
			return err
		}
		// A savepoint, so a failing insert (an FK, say) cannot poison the transaction that still has to
		// record the failure.
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		admitErr := admitSessionTx(ctx, sp, tenantID, adm.Rec, adm.Limits)
		if admitErr != nil {
			if rerr := sp.Rollback(ctx); rerr != nil {
				return rerr
			}
			if isBusinessAdmissionFailure(admitErr) {
				reason = admissionFailureReason(admitErr)
			} else {
				return admitErr
			}
		} else if err := sp.Commit(ctx); err != nil {
			return err
		}
	}
	if reason != "" {
		return s.failTx(ctx, tx, tenantID, t, reason)
	}
	ct, err := tx.Exec(ctx, `UPDATE session_transfer SET state = 'accepted', new_session_id = $2 WHERE id = $1 AND state = 'releasing'`,
		t.ID, adm.Rec.ID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() != 1 {
		return errors.New("session transfer finalize: the offer left the releasing state under its lock")
	}
	t.State, t.NewSessionID = TransferAccepted, adm.Rec.ID
	return s.appendAudit(ctx, tx, tenantID, transferSessionStartEvent(t, adm.Rec.ID, adm.StartMeta))
}

// isBusinessAdmissionFailure: the admission refusals that fail the offer (a full seat cap or an invalid
// access), as opposed to an infrastructure error, which rolls the finalize back to be retried.
// ErrGroupTreeChanged (a tree-lock timeout behind a concurrent group move, docs/62) is deliberately NOT here: it
// is transient, so the whole finalize — including S1's end — rolls back and the offer stays `releasing` for the
// next Reconcile, rather than failing a hand-off that would succeed a moment later.
func isBusinessAdmissionFailure(err error) bool {
	return errors.Is(err, ErrConcurrentSessionLimit) || errors.Is(err, ErrGroupConcurrentSessionLimit) ||
		errors.Is(err, ErrObserverSessionLimit) || isForeignKeyViolation(err)
}

func (s *PgSessionTransferStore) Reconcile(ctx context.Context, tenantID, id string, admit TransferAdmitter) (*SessionTransfer, error) {
	var out *SessionTransfer
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		t, err := lockOffer(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := s.reconcileTx(ctx, tx, tenantID, t, admit); err != nil {
			return err
		}
		t, err = scanTransfer(tx.QueryRow(ctx, selectTransfer+"WHERE id = $1", t.ID))
		out = t
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PgSessionTransferStore) RecordAgentEnded(ctx context.Context, tenantID, sessionID string, at time.Time, admit TransferAdmitter) error {
	if namesNoUUIDRow(sessionID) {
		return nil
	}
	// finalizeErr carries a finalize failure OUT of a transaction that still commits the report's stamp.
	var finalizeErr error
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Peek WITHOUT the lock: the report handler has already committed S1's end, so an accept that
		// could still win (it needs S1 open) committed BEFORE that end and is visible here. Only a
		// releasing offer needs the locked path; the common case (no transfer) takes no admission lock.
		var releasing string
		err := tx.QueryRow(ctx, `SELECT id::text FROM session_transfer
		                          WHERE tenant_id = $1 AND session_id = $2 AND state = 'releasing'`, tenantID, sessionID).Scan(&releasing)
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = tx.Exec(ctx, `UPDATE session_record SET agent_ended_at = clock_timestamp()
			                        WHERE tenant_id = $1 AND id = $2 AND agent_ended_at IS NULL`, tenantID, sessionID)
			return err
		}
		if err != nil {
			return err
		}
		// Same lock order as accept: admission lock, the offer, then S1.
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		t, err := lockOffer(ctx, tx, releasing)
		if err != nil {
			return err
		}
		s1, err := lockSession(ctx, tx, tenantID, sessionID)
		if err != nil {
			return err
		}
		// First report wins; a duplicate changes nothing.
		if s1.AgentEndedAt == nil {
			// DATABASE time, like releasing_at: the release deadline compares the two, so neither may
			// carry the application server's clock (skew would move the deadline).
			var stamped time.Time
			if err := tx.QueryRow(ctx, `UPDATE session_record SET agent_ended_at = clock_timestamp()
			                             WHERE tenant_id = $1 AND id = $2 AND agent_ended_at IS NULL
			                             RETURNING agent_ended_at`, tenantID, sessionID).Scan(&stamped); err != nil {
				return err
			}
			s1.AgentEndedAt = &stamped
		}
		// A terminal offer is never revived: only a still-releasing one finalizes.
		if t.State != TransferReleasing {
			return nil
		}
		// Finalize in a SAVEPOINT (Codex impl round 2): a transient finalize failure must not erase the
		// first report's stamp, or a report that arrived on time would be judged late on the retry. The
		// stamp commits; the finalize work rolls back; the caller still sees the error and retries.
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		if ferr := s.reconcileTx(ctx, sp, tenantID, t, admit); ferr != nil {
			if rbErr := sp.Rollback(ctx); rbErr != nil {
				return rbErr
			}
			finalizeErr = ferr
			return nil
		}
		return sp.Commit(ctx)
	})
	if err != nil {
		return err
	}
	return finalizeErr
}

func (s *PgSessionTransferStore) LiveForSession(ctx context.Context, tenantID, sessionID string) (*SessionTransfer, error) {
	if namesNoUUIDRow(sessionID) {
		return nil, nil
	}
	var out *SessionTransfer
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		t, err := scanTransfer(tx.QueryRow(ctx, selectTransfer+
			`WHERE session_id = $1 AND (state IN ('releasing', 'accepted') OR (state = 'failed' AND releasing_at IS NOT NULL))
			 ORDER BY created_at DESC LIMIT 1`, sessionID))
		if errors.Is(err, ErrTransferNotFound) {
			return nil
		}
		out = t
		return err
	})
	return out, err
}

func (s *PgSessionTransferStore) ExpireStale(ctx context.Context, tenantID string) (int, error) {
	n := 0
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := lockSessionAdmissionTx(ctx, tx, tenantID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, selectTransfer+`
			WHERE (state = 'pending' AND expires_at <= clock_timestamp())
			   OR (state = 'releasing' AND releasing_at + make_interval(secs => $1) <= clock_timestamp())
			ORDER BY id LIMIT 500`, transferReleaseTimeout.Seconds())
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			t, err := scanTransfer(rows)
			if err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, t.ID)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			t, err := lockOffer(ctx, tx, id)
			if err != nil {
				return err
			}
			before := t.State
			if err := s.reconcileTx(ctx, tx, tenantID, t, nil); err != nil {
				return err
			}
			if t.State != before {
				n++
			}
		}
		return nil
	})
	return n, err
}
