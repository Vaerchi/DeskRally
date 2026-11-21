package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	errRunNotFound       = errors.New("run not found")
	errRunConflict       = errors.New("run already has a different result")
	errRunReceiptRefused = errors.New("run receipt refused")
)

// insertRunRecordTx reads the pinned key and acquires the run's FK locks before the audit chain.
func insertRunRecordTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, sessionID, machineID, shell, runAs, command string, item *ToolboxItem) error {
	source := "command"
	var itemID, itemName, itemVersion, itemScope, itemOwner any
	if item != nil {
		source = "toolbox"
		itemID, itemName, itemVersion, itemScope, itemOwner = item.ID, item.Name, item.Version, item.Scope(), item.Owner
	}
	execHash := sha256.Sum256([]byte(command))
	var matched bool
	err := tx.QueryRow(ctx, `
		WITH session_machine AS (
			SELECT s.tenant_id, s.id AS session_id, s.machine_id, s.technician_id, m.device_id, m.pubkey, m.ephemeral
			FROM session_record s
			JOIN machine m ON m.tenant_id = s.tenant_id AND m.id = s.machine_id
			WHERE s.tenant_id = $1 AND s.id = $2 AND s.machine_id = $3
		), inserted AS (
			INSERT INTO run_record (tenant_id, request_id, session_id, machine_id, device_id, device_key_sha256,
				technician_id, source, item_id, item_name, item_version, item_scope, item_owner_id, shell, run_as, exec_sha256)
			SELECT tenant_id, $4::uuid, session_id, machine_id, device_id,
				CASE WHEN length(pubkey) = 32 THEN sha256(pubkey) END,
				technician_id, $5::text, $6::uuid, $7::text, $8::bigint, $9::text, $10::uuid, $11::text, $12::text, $13::bytea
			FROM session_machine WHERE NOT ephemeral
			RETURNING request_id
		)
		SELECT EXISTS (SELECT 1 FROM inserted) OR EXISTS (SELECT 1 FROM session_machine WHERE ephemeral)`,
		tenantID, sessionID, machineID, requestID, source, itemID, itemName, itemVersion,
		itemScope, itemOwner, shell, runAs, execHash[:]).Scan(&matched)
	if err == nil && !matched {
		return errors.New("run session does not belong to the machine")
	}
	return err
}

func (s *PgMgmtAuditStore) recordCommandRun(ctx context.Context, tenantID, requestID, sessionID, machineID, shell, runAs, command string, ev *MgmtAuditEvent) error {
	return withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if err := insertRunRecordTx(ctx, tx, tenantID, requestID, sessionID, machineID, shell, runAs, command, nil); err != nil {
			return err
		}
		return s.appendTx(ctx, tx, tenantID, ev)
	})
}

// Call with the machine already locked. Keyless machines have no device identity to serialize.
func lockRunDeviceKey(ctx context.Context, tx pgx.Tx, key []byte, shared bool) error {
	if len(key) != ed25519.PublicKeySize {
		return nil
	}
	if shared {
		_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended('devkey:' || encode($1::bytea, 'hex'), 0))`, key)
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('devkey:' || encode($1::bytea, 'hex'), 0))`, key)
	return err
}

// completeRun returns a webhook event only for a newly committed shared or ad-hoc completion.
func (s *PgMgmtAuditStore) completeRun(ctx context.Context, tenantID, technicianID, requestID string, readReceipt func() ([]byte, error)) (*MgmtAuditEvent, error) {
	if !isUUID(requestID) {
		return nil, errRunNotFound
	}
	var dispatch *MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var machineID string
		var submittedAt time.Time
		err := tx.QueryRow(ctx, `SELECT machine_id::text, clock_timestamp() FROM run_record
			WHERE tenant_id = $1 AND request_id = $2 AND technician_id = $3`,
			tenantID, requestID, technicianID).Scan(&machineID, &submittedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return errRunNotFound
		}
		if err != nil {
			return err
		}
		artifact, err := readReceipt()
		if err != nil {
			return err
		}
		machine, err := lockMachine(ctx, tx, machineID, false)
		if err != nil {
			return err
		}
		key, _ := hex.DecodeString(machine.Pubkey)
		if err := lockRunDeviceKey(ctx, tx, key, true); err != nil {
			return err
		}
		var sessionID, deviceID, source, itemScope, shell, runAs string
		var execHash, pinnedHash, previousDigest []byte
		var requestedAt time.Time
		err = tx.QueryRow(ctx, `SELECT session_id::text, device_id, source, coalesce(item_scope, ''),
			shell, run_as, exec_sha256, device_key_sha256, receipt_digest, requested_at
			FROM run_record WHERE tenant_id = $1 AND request_id = $2 AND technician_id = $3 AND machine_id = $4
			FOR UPDATE`, tenantID, requestID, technicianID, machineID).
			Scan(&sessionID, &deviceID, &source, &itemScope, &shell, &runAs, &execHash, &pinnedHash, &previousDigest, &requestedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return errRunNotFound
		}
		if err != nil {
			return err
		}
		_, msg, sig, decodeErr := decodeRunReceipt(artifact)
		digest := sha256.Sum256(append(msg, sig...))
		if previousDigest != nil {
			if decodeErr == nil && bytes.Equal(digest[:], previousDigest) {
				return nil
			}
			return errRunConflict
		}
		if machine.Status == MachineStatusRemoved || len(key) != ed25519.PublicKeySize {
			return errRunReceiptRefused
		}
		// A separate READ COMMITTED statement sees a tombstone committed while the key lock was waiting.
		var removed bool
		if err := tx.QueryRow(ctx, `SELECT cp_machine_key_removed($1::bytea)`, key).Scan(&removed); err != nil {
			return err
		}
		keyHash := sha256.Sum256(key)
		if removed || !bytes.Equal(keyHash[:], pinnedHash) || decodeErr != nil {
			return errRunReceiptRefused
		}
		claims, err := VerifyRunReceipt(ed25519.PublicKey(key), artifact)
		if err != nil || claims.TenantID != machine.TenantID || claims.DeviceID != deviceID ||
			claims.SessionID != sessionID || claims.RequestID != canonicalUUIDish(requestID) ||
			claims.Shell != shell || claims.RunAs != runAs || claims.ExecSHA256 != hex.EncodeToString(execHash) {
			return errRunReceiptRefused
		}
		finishedAt := time.UnixMilli(claims.FinishedAtMs)
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		if submittedAt.After(requestedAt.Add(24*time.Hour)) ||
			finishedAt.Before(requestedAt.Add(-5*time.Minute)) || finishedAt.After(now.Add(5*time.Minute)) {
			return errRunReceiptRefused
		}
		if _, err := tx.Exec(ctx, `UPDATE run_record SET outcome = $2, exit_code = $3, truncated = $4,
			finished_at = $5, receipt_digest = $6, completed_at = $7 WHERE request_id = $1`,
			requestID, claims.Outcome, claims.ExitCode, claims.Truncated, finishedAt, digest[:], now); err != nil {
			return err
		}
		meta, _ := json.Marshal(map[string]any{
			"request_id": claims.RequestID, "outcome": claims.Outcome, "exit_code": claims.ExitCode, "truncated": claims.Truncated,
		})
		event := &MgmtAuditEvent{ActorUserID: technicianID, Action: source + ".run_completed",
			TargetKind: "machine", TargetID: machineID, Metadata: meta}
		if err := s.appendTx(ctx, tx, tenantID, event); err != nil {
			return err
		}
		if itemScope != "personal" {
			dispatch = event
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dispatch, nil
}

type runHistoryEntry struct {
	RequestID      string    `json:"request_id"`
	RequestedAt    time.Time `json:"requested_at"`
	TechnicianName string    `json:"technician_name"`
	ItemName       string    `json:"item_name"`
	ItemVersion    *int64    `json:"item_version,omitempty"`
	ItemDeleted    bool      `json:"item_deleted"`
	RunAs          string    `json:"run_as"`
	Result         string    `json:"result"`
}

func runHistoryResult(outcome string, exitCode *int32) string {
	switch outcome {
	case "exited":
		return fmt.Sprintf("exit %d", *exitCode)
	case "timed_out":
		return "timed out"
	case "start_failed":
		return "could not start"
	default:
		return "no result reported"
	}
}

func (s *PgMgmtAuditStore) listRunHistory(ctx context.Context, p *Principal, id string, byItem bool, limit, offset int) ([]runHistoryEntry, error) {
	out := make([]runHistoryEntry, 0)
	machines, canViewMachines := p.Grant.ScopeFor(CapViewMachines)
	audit, canViewAudit := p.Grant.ScopeFor(CapViewAudit)
	if !canViewMachines || !canViewAudit || !isUUID(id) {
		return out, nil
	}
	target := "r.machine_id"
	if byItem {
		target = "r.item_id"
	}
	err := withTenant(ctx, s.Pool, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT r.request_id::text, r.requested_at, coalesce(u.display_name, ''),
				coalesce(r.item_name, 'ad-hoc command'), r.item_version,
				r.item_id IS NOT NULL AND i.id IS NULL, r.run_as, coalesce(r.outcome, ''), r.exit_code
			FROM run_record r
			JOIN machine m ON m.tenant_id = r.tenant_id AND m.id = r.machine_id
			LEFT JOIN app_user u ON u.tenant_id = r.tenant_id AND u.id = r.technician_id
			LEFT JOIN toolbox_item i ON i.tenant_id = r.tenant_id AND i.id = r.item_id
			WHERE r.tenant_id = $1 AND `+target+` = $3
				AND ($4 OR m.group_id::text = ANY($5::text[]))
				AND ($6 OR m.group_id::text = ANY($7::text[]))
				AND (r.source = 'command' OR r.item_scope = 'shared' OR r.item_owner_id = $2)
			ORDER BY r.requested_at DESC, r.request_id DESC LIMIT $8 OFFSET $9`,
			p.TenantID, p.UserID, id, machines.All, machines.CoveredIDs(), audit.All, audit.CoveredIDs(), limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var entry runHistoryEntry
			var outcome string
			var exitCode *int32
			if err := rows.Scan(&entry.RequestID, &entry.RequestedAt, &entry.TechnicianName, &entry.ItemName,
				&entry.ItemVersion, &entry.ItemDeleted, &entry.RunAs, &outcome, &exitCode); err != nil {
				return err
			}
			entry.Result = runHistoryResult(outcome, exitCode)
			out = append(out, entry)
		}
		return rows.Err()
	})
	return out, err
}
