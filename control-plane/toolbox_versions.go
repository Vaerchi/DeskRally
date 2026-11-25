package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Toolbox version history (migration 0089, decision 2026-11-24). Every create and update writes the saved snapshot in
// the same transaction; the console lists them and can load an old body back into the editor, which then saves as an
// ordinary update (so a restore is itself a new, audited version).

// maxToolboxVersionsKept bounds history per item; older rows are pruned when a new one is written.
const maxToolboxVersionsKept = 50

// ToolboxVersion is one saved snapshot of an item.
type ToolboxVersion struct {
	Version     int64     `json:"version"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Shell       string    `json:"shell"`
	RunAs       string    `json:"run_as"`
	Body        string    `json:"body"`
	BodySHA256  string    `json:"body_sha256"`
	SavedBy     string    `json:"saved_by,omitempty"` // the saver's email, when known
	SavedAt     time.Time `json:"saved_at"`
}

// insertToolboxVersionTx records it (as just written) and prunes the item's history to the newest
// maxToolboxVersionsKept rows. Runs inside the caller's tenant-bound transaction.
func insertToolboxVersionTx(ctx context.Context, tx pgx.Tx, tenantID, callerID string, it *ToolboxItem) error {
	if _, err := tx.Exec(ctx, `INSERT INTO toolbox_item_version
		(tenant_id, item_id, version, name, description, shell, run_as, body, body_sha256, saved_by)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10::uuid)`,
		tenantID, it.ID, it.Version, it.Name, it.Description, it.Shell, it.RunAs, it.Body, it.BodySHA256, callerID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM toolbox_item_version
		WHERE tenant_id = $1::uuid AND item_id = $2::uuid AND version <= $3`,
		tenantID, it.ID, it.Version-maxToolboxVersionsKept)
	return err
}

// handleToolboxVersions: GET /toolbox/{id}/versions. The same callers who may list the toolbox may read an item's
// history (it holds nothing the current item does not already show them).
func (s *Server) handleToolboxVersions(w http.ResponseWriter, r *http.Request) {
	p, ok := s.toolboxCaller(w, r, CapStartSession, CapManageToolbox)
	if !ok {
		return
	}
	versions, err := s.Toolbox.Versions(r.Context(), p.TenantID, p.UserID, r.PathValue("id"))
	if err != nil {
		writeToolboxErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}
