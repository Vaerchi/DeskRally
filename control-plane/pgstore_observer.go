package controlplane

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// One insert projection keeps plain and capped admission from drifting. Access has no
// update API: leases and command authorization read the mode originally admitted here.
func insertSessionRecordTx(ctx context.Context, tx pgx.Tx, tenantID string, rec *SessionRecord) error {
	caps := rec.GrantedCaps
	if caps == nil {
		caps = []string{}
	}
	policy := rec.ConsentPolicy
	if policy == "" {
		policy = "unattended"
	}
	return tx.QueryRow(ctx, `
		INSERT INTO session_record
		    (tenant_id, machine_id, technician_id, consent_policy, granted_caps, group_id, access, transferred_from, source_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9,'')::inet)
		RETURNING id::text, started_at, consent_policy, access
	`, tenantID, rec.MachineID, rec.TechnicianID, policy, caps,
		nullableGroupID(rec.MachineGroupID), rec.Access, nullableGroupID(rec.TransferredFrom), validIPText(rec.SourceIP)).
		Scan(&rec.ID, &rec.StartedAt, &rec.ConsentPolicy, &rec.Access)
}
