package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgGuestEndStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

func NewPgGuestEndStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgGuestEndStore {
	return &PgGuestEndStore{Pool: pool, Audit: audit}
}

var _ GuestEndStore = (*PgGuestEndStore)(nil)

func (s *PgGuestEndStore) EndSessionForDevice(ctx context.Context, tenantID, sessionID, deviceID string, at time.Time, report SessionEndReport) (GuestEndOutcome, error) {
	reason := normalizeEndReason(string(report.Reason))
	if namesNoUUIDRow(sessionID) {
		return GuestEndNotFound, nil
	}
	var outcome GuestEndOutcome
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// Lock the reporting device's machine FIRST and hold it to commit, so its ownership cannot
		// change under this transaction (Codex impl review). FOR KEY SHARE conflicts with a DELETE
		// of the row and with any change to device_id (a unique-indexed key column) and with nothing
		// else, so ordinary machine writes (status, group, last_seen) are not blocked.
		//
		// Lock order: machine → session_record → management-audit chain. Every other writer that
		// touches both tables takes the machine first too — the attended End's DELETE FROM machine
		// (pgstore_attended.go) cascades to session_record — and the admin end, the reaper and the
		// lease paths take session rows only, auditing (if at all) in a separate transaction. A
		// deadlock Postgres still detects aborts this whole transaction; the handler maps the error
		// to 503 "unavailable" and the agent retries.
		var lockedMachine string
		err := tx.QueryRow(ctx,
			`SELECT id::text FROM machine WHERE device_id = $1 FOR KEY SHARE`, deviceID).Scan(&lockedMachine)
		if errors.Is(err, pgx.ErrNoRows) {
			// The device has no machine in this tenant (RLS) any more. Still say whether the record
			// exists, so a stale report is "other device", not "unknown session".
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM session_record WHERE tenant_id = $1 AND id = $2)`,
				tenantID, sessionID).Scan(&exists); err != nil {
				return err
			}
			outcome = GuestEndNotFound
			if exists {
				outcome = GuestEndOtherDevice
			}
			return nil
		}
		if err != nil {
			return err
		}
		var id, machineID string
		err = tx.QueryRow(ctx, `
			UPDATE session_record SET ended_at = $3
			WHERE tenant_id = $1 AND id = $2 AND ended_at IS NULL AND machine_id = $4
			RETURNING id::text, machine_id::text
		`, tenantID, sessionID, at, lockedMachine).Scan(&id, &machineID)
		if err == nil {
			meta := map[string]string{
				"actor_kind": "device", "device_id": canonicalUUIDish(deviceID),
				// docs/49: an agent-reported end's ended_at is when the control plane OBSERVED it.
				"reason": string(reason), "via": "signaling", "machine_id": machineID,
				"observed_by": "agent_report",
			}
			if report.QueueAgeMs != nil {
				meta["queue_age_ms"] = strconv.FormatInt(*report.QueueAgeMs, 10)
			}
			metadata, err := json.Marshal(meta)
			if err != nil {
				return err
			}
			if err := s.Audit.appendTx(ctx, tx, tenantID, &MgmtAuditEvent{
				Action: "session.end", TargetKind: "session", TargetID: id, Metadata: metadata,
			}); err != nil {
				return err
			}
			outcome = GuestEndEnded
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// A competing UPDATE waits and rechecks ended_at. This subsequent READ COMMITTED
		// statement sees its committed end; no timestamp comparison can attribute it to us.
		var endedAt *time.Time
		var device *string
		err = tx.QueryRow(ctx, `
			SELECT s.ended_at, m.device_id::text
			FROM session_record s LEFT JOIN machine m ON m.id = s.machine_id
			WHERE s.tenant_id = $1 AND s.id = $2
		`, tenantID, sessionID).Scan(&endedAt, &device)
		if errors.Is(err, pgx.ErrNoRows) {
			outcome = GuestEndNotFound
			return nil
		}
		if err != nil {
			return err
		}
		if device == nil || canonicalUUIDish(*device) != canonicalUUIDish(deviceID) {
			outcome = GuestEndOtherDevice
			return nil
		}
		// Same device and still open, yet the guarded UPDATE matched nothing: something this code
		// does not understand (e.g. a device-id spelling the uuid comparison rejected). Never report
		// that as already_ended — the agent would stop retrying an end that never happened.
		if endedAt == nil {
			return fmt.Errorf("guest end: session %s is open for device %s but was not ended", sessionID, deviceID)
		}
		outcome = GuestEndAlreadyEnded
		return nil
	})
	if err != nil {
		return "", err
	}
	return outcome, nil
}
