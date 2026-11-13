package controlplane

// PgToolboxStore: ToolboxStore over toolbox_item (migration 0056). Tenant isolation is RLS (every
// call runs in withTenant on the request's pinned connection); PERSONAL isolation is the
// toolboxVisible predicate, which every statement below carries. Each mutation and its management
// audit event commit in ONE transaction (appendTx), and update/delete compare the version in the
// same statement.

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgToolboxStore struct {
	Pool  *pgxpool.Pool
	Audit *PgMgmtAuditStore
}

func NewPgToolboxStore(pool *pgxpool.Pool, audit *PgMgmtAuditStore) *PgToolboxStore {
	return &PgToolboxStore{Pool: pool, Audit: audit}
}

// toolboxVisible is THE personal-visibility predicate; $2 is always the caller.
const toolboxVisible = `(owner_user_id IS NULL OR owner_user_id = $2::uuid)`

const toolboxColumns = `id::text, owner_user_id::text, name, description, shell, run_as, body, body_sha256,
	version, created_by::text, created_at, updated_by::text, updated_at`

func scanToolboxItem(row pgx.Row, tenantID string) (*ToolboxItem, error) {
	var it ToolboxItem
	if err := row.Scan(&it.ID, &it.Owner, &it.Name, &it.Description, &it.Shell, &it.RunAs, &it.Body, &it.BodySHA256,
		&it.Version, &it.CreatedBy, &it.CreatedAt, &it.UpdatedBy, &it.UpdatedAt); err != nil {
		return nil, err
	}
	it.TenantID = tenantID
	return &it, nil
}

func toolboxAuditMeta(it *ToolboxItem, extra map[string]any) json.RawMessage {
	m := map[string]any{
		"item_id": it.ID, "name": it.Name, "scope": it.Scope(), "version": it.Version,
		"body_sha256": it.BodySHA256, "shell": it.Shell, "run_as": it.RunAs,
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func (s *PgToolboxStore) List(ctx context.Context, tenantID, callerID string) ([]ToolboxItem, error) {
	var out []ToolboxItem
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+toolboxColumns+` FROM toolbox_item
			WHERE tenant_id = $1::uuid AND `+toolboxVisible+`
			ORDER BY owner_user_id IS NOT NULL, lower(name)`, tenantID, callerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			it, err := scanToolboxItem(rows, tenantID)
			if err != nil {
				return err
			}
			out = append(out, *it)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PgToolboxStore) Get(ctx context.Context, tenantID, callerID, id string) (*ToolboxItem, error) {
	if !isUUID(id) {
		return nil, ErrToolboxNotFound
	}
	var it *ToolboxItem
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		it, err = scanToolboxItem(tx.QueryRow(ctx, `SELECT `+toolboxColumns+` FROM toolbox_item
			WHERE tenant_id = $1::uuid AND `+toolboxVisible+` AND id = $3::uuid`, tenantID, callerID, id), tenantID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrToolboxNotFound
	}
	return it, err
}

func (s *PgToolboxStore) Create(ctx context.Context, tenantID, callerID string, personal bool, f ToolboxFields, id string) (*ToolboxItem, *MgmtAuditEvent, error) {
	if err := ValidateToolboxFields(&f); err != nil {
		return nil, nil, err
	}
	var owner *string
	if personal {
		owner = &callerID // the owner is always the authenticated caller
	}
	var it *ToolboxItem
	var ev *MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var err error
		it, err = scanToolboxItem(tx.QueryRow(ctx, `INSERT INTO toolbox_item
			(id, tenant_id, owner_user_id, name, description, shell, run_as, body, body_sha256, created_by, updated_by)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10::uuid, $10::uuid)
			RETURNING `+toolboxColumns,
			id, tenantID, owner, f.Name, f.Description, f.Shell, f.RunAs, f.Body, ToolboxBodySHA256(f.Body), callerID), tenantID)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrToolboxNameTaken
			}
			return err
		}
		ev = &MgmtAuditEvent{ActorUserID: callerID, Action: "toolbox.item.create", TargetKind: "toolbox_item",
			TargetID: it.ID, Metadata: toolboxAuditMeta(it, nil)}
		return s.Audit.appendTx(ctx, tx, tenantID, ev)
	})
	if err != nil {
		return nil, nil, err
	}
	return it, ev, nil
}

// lockForChange reads the visible row FOR UPDATE and applies the shared-item rule. It distinguishes
// "not visible" (404) from "visible, wrong version" (409) without leaking other users' items: a hidden
// personal item is 404 whatever version is supplied.
func (s *PgToolboxStore) lockForChange(ctx context.Context, tx pgx.Tx, tenantID, callerID string, perms ToolboxPerms, id string, expectedVersion int64) (*ToolboxItem, error) {
	if !isUUID(id) {
		return nil, ErrToolboxNotFound
	}
	it, err := scanToolboxItem(tx.QueryRow(ctx, `SELECT `+toolboxColumns+` FROM toolbox_item
		WHERE tenant_id = $1::uuid AND `+toolboxVisible+` AND id = $3::uuid FOR UPDATE`, tenantID, callerID, id), tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrToolboxNotFound
	}
	if err != nil {
		return nil, err
	}
	if it.Owner == nil && !perms.ManageShared {
		return nil, ErrToolboxSharedDenied
	}
	if it.Owner != nil && !perms.UsePersonal {
		return nil, ErrToolboxPersonalDenied
	}
	if it.Version != expectedVersion {
		return nil, ErrToolboxVersion
	}
	return it, nil
}

func (s *PgToolboxStore) Update(ctx context.Context, tenantID, callerID string, perms ToolboxPerms, id string, expectedVersion int64, f ToolboxFields) (*ToolboxItem, *MgmtAuditEvent, error) {
	if err := ValidateToolboxFields(&f); err != nil {
		return nil, nil, err
	}
	var it *ToolboxItem
	var ev *MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if _, err := s.lockForChange(ctx, tx, tenantID, callerID, perms, id, expectedVersion); err != nil {
			return err
		}
		// The version compare is repeated in the statement itself; scope and owner are never set here.
		var err error
		it, err = scanToolboxItem(tx.QueryRow(ctx, `UPDATE toolbox_item
			SET name = $4, description = $5, shell = $6, run_as = $7, body = $8, body_sha256 = $9,
			    version = version + 1, updated_by = $2::uuid, updated_at = now()
			WHERE tenant_id = $1::uuid AND `+toolboxVisible+` AND id = $3::uuid AND version = $10
			RETURNING `+toolboxColumns,
			tenantID, callerID, id, f.Name, f.Description, f.Shell, f.RunAs, f.Body, ToolboxBodySHA256(f.Body), expectedVersion), tenantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrToolboxVersion
		}
		if err != nil {
			if isUniqueViolation(err) {
				return ErrToolboxNameTaken
			}
			return err
		}
		ev = &MgmtAuditEvent{ActorUserID: callerID, Action: "toolbox.item.update", TargetKind: "toolbox_item",
			TargetID: it.ID, Metadata: toolboxAuditMeta(it, nil)}
		return s.Audit.appendTx(ctx, tx, tenantID, ev)
	})
	if err != nil {
		return nil, nil, err
	}
	return it, ev, nil
}

func (s *PgToolboxStore) Delete(ctx context.Context, tenantID, callerID string, perms ToolboxPerms, id string, expectedVersion int64) (*MgmtAuditEvent, error) {
	var ev *MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		it, err := s.lockForChange(ctx, tx, tenantID, callerID, perms, id, expectedVersion)
		if err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `DELETE FROM toolbox_item
			WHERE tenant_id = $1::uuid AND `+toolboxVisible+` AND id = $3::uuid AND version = $4`,
			tenantID, callerID, id, expectedVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return ErrToolboxVersion
		}
		ev = &MgmtAuditEvent{ActorUserID: callerID, Action: "toolbox.item.delete", TargetKind: "toolbox_item",
			TargetID: it.ID, Metadata: toolboxAuditMeta(it, nil)}
		return s.Audit.appendTx(ctx, tx, tenantID, ev)
	})
	if err != nil {
		return nil, err
	}
	return ev, nil
}

func (s *PgToolboxStore) RecordRun(ctx context.Context, tenantID, callerID, id string, expectedVersion int64, sessionID, machineID, requestID string) (*ToolboxRunRequest, *MgmtAuditEvent, error) {
	if !isUUID(id) {
		return nil, nil, ErrToolboxNotFound
	}
	var run *ToolboxRunRequest
	var ev *MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		// ONE snapshot: the audit fields and the returned command both come from this row. FOR SHARE
		// keeps a concurrent update from committing between this read and the audit append.
		it, err := scanToolboxItem(tx.QueryRow(ctx, `SELECT `+toolboxColumns+` FROM toolbox_item
			WHERE tenant_id = $1::uuid AND `+toolboxVisible+` AND id = $3::uuid FOR SHARE`, tenantID, callerID, id), tenantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrToolboxNotFound
		}
		if err != nil {
			return err
		}
		if it.Version != expectedVersion {
			return ErrToolboxVersion
		}
		var actorEmail string
		if err := tx.QueryRow(ctx, `SELECT email FROM app_user WHERE id = $1::uuid`, callerID).Scan(&actorEmail); err != nil {
			return err
		}
		run = &ToolboxRunRequest{RequestID: requestID, Item: *it, SessionID: sessionID, MachineID: machineID,
			Command: ToolboxCommand(it.Shell, it.Body)}
		ev = &MgmtAuditEvent{ActorUserID: callerID, Action: "toolbox.run_requested", TargetKind: "session",
			TargetID: sessionID, Metadata: toolboxAuditMeta(it, map[string]any{
				"request_id": requestID, "session_id": sessionID, "machine_id": machineID,
				"actor_email": actorEmail, "outcome": "unknown",
			})}
		return s.Audit.appendTx(ctx, tx, tenantID, ev)
	})
	if err != nil {
		return nil, nil, err
	}
	return run, ev, nil
}
