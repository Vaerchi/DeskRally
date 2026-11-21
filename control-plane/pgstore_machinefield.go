package controlplane

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

func lockMachineFieldsTx(ctx context.Context, tx pgx.Tx, tenant string, shared bool) error {
	if shared {
		_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended('fields:' || $1::uuid::text, 0))`, tenant)
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('fields:' || $1::uuid::text, 0))`, tenant)
	return err
}

func listMachineFieldsTx(ctx context.Context, tx pgx.Tx, tenant string) (machineFieldList, error) {
	list := machineFieldList{Fields: []MachineField{}}
	var fields []byte
	err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT revision FROM machine_field_order WHERE tenant_id = $1), 0),
		       COALESCE(jsonb_agg(jsonb_build_object('key', key, 'id', id, 'label', label,
		           'type', type, 'choices', choices, 'position', position, 'version', version)
		           ORDER BY position, key), '[]'::jsonb)
		FROM machine_field WHERE tenant_id = $1
	`, tenant).Scan(&list.OrderRevision, &fields)
	if err != nil {
		return list, err
	}
	return list, json.Unmarshal(fields, &list.Fields)
}

func (s *PgMachinePropertyStore) listFields(ctx context.Context, tenant string) (machineFieldList, error) {
	var list machineFieldList
	err := withTenant(ctx, s.Pool, tenant, func(tx pgx.Tx) error {
		var err error
		list, err = listMachineFieldsTx(ctx, tx, tenant)
		return err
	})
	return list, err
}

func appendFieldAuditTx(ctx context.Context, tx pgx.Tx, tenant string, audit MgmtAuditStore, events []*MgmtAuditEvent) error {
	if audit == nil || len(events) == 0 {
		return nil
	}
	pgAudit, ok := audit.(*PgMgmtAuditStore)
	if !ok {
		return errors.New("machine fields require a transactional PostgreSQL audit store")
	}
	for _, event := range events {
		if err := pgAudit.appendTx(ctx, tx, tenant, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *PgMachinePropertyStore) changeFields(ctx context.Context, p *Principal, audit MgmtAuditStore, c *machineFieldChange) ([]*MgmtAuditEvent, error) {
	tenant := p.TenantID
	var events []*MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenant, func(tx pgx.Tx) error {
		if err := lockMachineFieldsTx(ctx, tx, tenant, false); err != nil {
			return err
		}
		list, err := listMachineFieldsTx(ctx, tx, tenant)
		if err != nil {
			return err
		}
		if err := c.apply(&list); err != nil {
			return err
		}
		f := c.field
		switch c.action {
		case "created":
			_, err = tx.Exec(ctx, `
				INSERT INTO machine_field (tenant_id, key, id, label, type, choices, position, version)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			`, tenant, f.Key, f.ID, f.Label, f.Type, f.Choices, f.Position, f.Version)
		case "updated":
			_, err = tx.Exec(ctx, `
				UPDATE machine_field SET label = $3, type = $4, choices = $5,
				    version = $6, updated_at = now()
				WHERE tenant_id = $1 AND key = $2
			`, tenant, f.Key, f.Label, f.Type, f.Choices, f.Version)
		case "deleted":
			_, err = tx.Exec(ctx, `DELETE FROM machine_field WHERE tenant_id = $1 AND key = $2`, tenant, f.Key)
		case "reordered":
			_, err = tx.Exec(ctx, `
				UPDATE machine_field f SET position = (ordered.pos - 1)::int, updated_at = now()
				FROM unnest($2::text[]) WITH ORDINALITY AS ordered(key, pos)
				WHERE f.tenant_id = $1 AND f.key = ordered.key AND f.position <> ordered.pos - 1
			`, tenant, c.keys)
		}
		if err != nil {
			return err
		}
		if c.action != "updated" {
			if _, err := tx.Exec(ctx, `
				INSERT INTO machine_field_order (tenant_id, revision) VALUES ($1, $2)
				ON CONFLICT (tenant_id) DO UPDATE SET revision = EXCLUDED.revision
			`, tenant, list.OrderRevision); err != nil {
				return err
			}
		}
		events = []*MgmtAuditEvent{c.event(p)}
		return appendFieldAuditTx(ctx, tx, tenant, audit, events)
	})
	return events, err
}

func lookupMachineFieldTx(ctx context.Context, tx pgx.Tx, tenant, key string) (*MachineField, error) {
	var field MachineField
	err := tx.QueryRow(ctx, `
		SELECT label, type, choices FROM machine_field WHERE tenant_id = $1 AND key = $2
	`, tenant, key).Scan(&field.Label, &field.Type, &field.Choices)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &field, err
}

func (s *PgMachinePropertyStore) editProperties(ctx context.Context, p *Principal, _ MachineStore, audit MgmtAuditStore, edit *machinePropertyEdit) ([]*MgmtAuditEvent, error) {
	tenant := p.TenantID
	var events []*MgmtAuditEvent
	err := withTenant(ctx, s.Pool, tenant, func(tx pgx.Tx) error {
		if !edit.remove {
			if err := lockMachineFieldsTx(ctx, tx, tenant, true); err != nil {
				return err
			}
		}
		if version := expectTreeVersion(p.Grant); version != nil {
			if err := checkGroupTreeVersionTx(ctx, tx, tenant, *version); err != nil {
				return err
			}
		}
		var field *MachineField
		if !edit.remove {
			var err error
			field, err = lookupMachineFieldTx(ctx, tx, tenant, edit.key)
			if err != nil {
				return err
			}
			// Bulk validation is request-wide and precedes machine and property work.
			if edit.bulk && field != nil {
				if err := edit.canonicalize(*field); err != nil {
					return err
				}
			}
		}
		// Hold machine rows in UUID order through the property writes and audit append.
		for _, target := range edit.targets {
			var group string
			err := tx.QueryRow(ctx, `
				SELECT group_id::text FROM machine WHERE tenant_id = $1 AND id = $2 FOR SHARE
			`, tenant, target.id).Scan(&group)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				edit.results[target.index].Error = "unknown machine"
			case err != nil:
				return err
			default:
				if err := edit.checkScope(p, target, group); err != nil {
					return err
				}
			}
		}
		if !edit.bulk && field != nil && edit.results[0].Error == "" {
			if err := edit.canonicalize(*field); err != nil {
				return err
			}
		}
		for _, target := range edit.targets {
			result := &edit.results[target.index]
			if result.Error != "" {
				continue
			}
			if edit.remove {
				tag, err := tx.Exec(ctx, `
					DELETE FROM machine_property WHERE tenant_id = $1 AND machine_id = $2 AND key = $3
				`, tenant, target.id, edit.key)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					result.Error = "not set"
					continue
				}
			} else {
				if err := upsertMachinePropertyTx(ctx, tx, tenant, target.id, edit.key, edit.value); err != nil {
					return err
				}
			}
			result.OK = true
			events = append(events, edit.event(p, target.id))
		}
		return appendFieldAuditTx(ctx, tx, tenant, audit, events)
	})
	return events, err
}

func upsertMachinePropertyTx(ctx context.Context, tx pgx.Tx, tenant, machine, key, value string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO machine_property (tenant_id, machine_id, key, value) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, machine_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, tenant, machine, key, value)
	return err
}

func (s *PgMachinePropertyStore) reportField(ctx context.Context, p *Principal, _ MachineStore, key string, scope GroupScope, cursor *machineFieldCursor) (machineFieldReport, error) {
	var report machineFieldReport
	var id string
	var version int64
	var rows []byte
	var lastID string
	if cursor != nil {
		lastID = cursor.LastID
	}
	groups := scope.CoveredIDs()
	err := withTenant(ctx, s.Pool, p.TenantID, func(tx pgx.Tx) error {
		// The CASE date branch only constructs a date from a checked year and month.
		// Canonical number syntax uses ASCII digits and requires any fraction to end in a nonzero digit.
		return tx.QueryRow(ctx, `
			WITH field AS (
				SELECT id, version, type, choices FROM machine_field WHERE tenant_id = $1 AND key = $2
			), violations AS MATERIALIZED (
				SELECT m.id AS machine_id, m.hostname AS machine_name, mp.value
				FROM field f
				JOIN machine_property mp ON mp.tenant_id = $1 AND mp.key = $2
				JOIN machine m ON m.tenant_id = mp.tenant_id AND m.id = mp.machine_id
				WHERE NOT m.ephemeral AND ($3 OR m.group_id::text COLLATE "C" = ANY($4::text[]))
				AND NOT CASE f.type
					WHEN 'text' THEN true
					WHEN 'boolean' THEN mp.value COLLATE "C" IN ('true', 'false')
					WHEN 'choice' THEN mp.value COLLATE "C" = ANY(f.choices)
					WHEN 'number' THEN mp.value COLLATE "C" ~ '^-?(0|[1-9][0-9]{0,14})([.][0-9]{0,5}[1-9])?$'
					                   AND mp.value <> '-0'
					WHEN 'date' THEN CASE
						WHEN mp.value COLLATE "C" ~ '^(19[0-9]{2}|2[0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
						THEN substring(mp.value, 9, 2)::int <= EXTRACT(DAY FROM (
							make_date(substring(mp.value, 1, 4)::int, substring(mp.value, 6, 2)::int, 1)
							+ interval '1 month' - interval '1 day'))
						ELSE false END
					ELSE false END
			), page AS (
				SELECT * FROM violations
				WHERE NULLIF($5::text, '') IS NULL OR machine_id > NULLIF($5::text, '')::uuid
				ORDER BY machine_id LIMIT $6
			)
			SELECT field.id::text, field.version, (SELECT count(*) FROM violations),
			       COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY page.machine_id) FROM page), '[]'::jsonb)
			FROM field
		`, p.TenantID, key, scope.All, groups, lastID, machineFieldPageSize+1).Scan(&id, &version, &report.Total, &rows)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return report, missingReportedField(cursor)
		}
		return report, err
	}
	if err := checkFieldCursor(cursor, p.TenantID, key, id, version); err != nil {
		return report, err
	}
	if err := json.Unmarshal(rows, &report.Machines); err != nil {
		return report, err
	}
	report.finish(p.TenantID, key, id, version)
	return report, nil
}
