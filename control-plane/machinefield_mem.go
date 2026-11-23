package controlplane

import (
	"context"
	"errors"
	"slices"
	"sort"
)

func (s *InMemoryMachinePropertyStore) listFields(_ context.Context, tenant string) (machineFieldList, error) {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	list := s.fields[tenant]
	list.Fields = append([]MachineField{}, list.Fields...)
	for i := range list.Fields {
		list.Fields[i].Choices = slices.Clone(list.Fields[i].Choices)
	}
	return list, nil
}

func (s *InMemoryMachinePropertyStore) changeFields(ctx context.Context, p *Principal, audit MgmtAuditStore, c *machineFieldChange) ([]*MgmtAuditEvent, error) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	list := s.fields[p.TenantID]
	list.Fields = slices.Clone(list.Fields)
	c.field.Choices = slices.Clone(c.field.Choices)
	if err := c.apply(&list); err != nil {
		return nil, err
	}
	events := []*MgmtAuditEvent{c.event(p)}
	if audit != nil {
		if err := appendAuditBatch(ctx, audit, p.TenantID, events); err != nil {
			return nil, err
		}
	}
	s.fields[p.TenantID] = list
	return events, nil
}

func (s *InMemoryMachinePropertyStore) editProperties(ctx context.Context, p *Principal, machines MachineStore, audit MgmtAuditStore, edit *machinePropertyEdit) ([]*MgmtAuditEvent, error) {
	memory, ok := machines.(*InMemoryMachineStore)
	if !ok {
		return nil, errors.New("in-memory property edits require an in-memory machine store")
	}
	if !edit.remove {
		s.fieldsMu.RLock()
		defer s.fieldsMu.RUnlock()
	}
	var events []*MgmtAuditEvent
	apply := func() error {
		var field *MachineField
		if !edit.remove {
			for _, candidate := range s.fields[p.TenantID].Fields {
				if candidate.Key == edit.key {
					field = &candidate
					break
				}
			}
		}
		if edit.bulk && field != nil {
			if err := edit.canonicalize(*field); err != nil {
				return err
			}
		}
		memory.mu.Lock()
		defer memory.mu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, target := range edit.targets {
			result := &edit.results[target.index]
			machine, err := memory.getMachineByIDLocked(p.TenantID, target.id)
			if errors.Is(err, ErrMachineNotFound) {
				result.Error = "unknown machine"
				continue
			}
			if err != nil {
				return err
			}
			if err := edit.checkScope(p, target, machine.GroupID); err != nil {
				return err
			}
			if result.Error != "" {
				continue
			}
			if !edit.bulk && field != nil {
				if err := edit.canonicalize(*field); err != nil {
					return err
				}
			}
			if edit.remove {
				if _, present := s.props[mpKey(p.TenantID, target.id)][edit.key]; !present {
					result.Error = "not set"
					continue
				}
			}
			result.OK = true
			events = append(events, edit.event(p, target.id))
		}
		if err := appendMachinePropertyAudit(ctx, audit, p.TenantID, events); err != nil {
			return err
		}
		for _, target := range edit.targets {
			if !edit.results[target.index].OK {
				continue
			}
			k := mpKey(p.TenantID, target.id)
			if edit.remove {
				delete(s.props[k], edit.key)
			} else {
				s.setPropertyLocked(k, edit.key, edit.value)
			}
		}
		return nil
	}
	if expected := expectTreeVersion(p.Grant); expected != nil {
		memory.mu.Lock()
		tree := memory.tree
		memory.mu.Unlock()
		if tree != nil {
			err := tree.withTree(p.TenantID, func(_ GroupTree, current int64) error {
				if *expected != current {
					return ErrGroupTreeChanged
				}
				return apply()
			})
			return events, err
		}
	}
	err := apply()
	return events, err
}

func (s *InMemoryMachinePropertyStore) reportField(_ context.Context, p *Principal, machines MachineStore, key string, scope GroupScope, cursor *machineFieldCursor) (machineFieldReport, error) {
	report := machineFieldReport{Machines: []machineFieldViolation{}}
	memory, ok := machines.(*InMemoryMachineStore)
	if !ok {
		return report, errors.New("in-memory field report requires an in-memory machine store")
	}
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	var field *MachineField
	for _, candidate := range s.fields[p.TenantID].Fields {
		if candidate.Key == key {
			field = &candidate
			break
		}
	}
	if field == nil {
		return report, missingReportedField(cursor)
	}
	if err := checkFieldCursor(cursor, p.TenantID, key, field.ID, field.Version); err != nil {
		return report, err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, machine := range memory.machines {
		if machine.TenantID != p.TenantID || machine.Ephemeral || !scope.Covers(machine.GroupID) {
			continue
		}
		value, present := s.props[mpKey(p.TenantID, machine.ID)][key]
		if !present || fieldValueConforms(*field, value) {
			continue
		}
		report.Total++
		if cursor == nil || machine.ID > cursor.LastID {
			report.Machines = append(report.Machines, machineFieldViolation{machine.ID, machine.Name, value})
		}
	}
	sort.Slice(report.Machines, func(i, j int) bool { return report.Machines[i].MachineID < report.Machines[j].MachineID })
	report.finish(p.TenantID, key, field.ID, field.Version)
	return report, nil
}

func appendMachinePropertyAudit(ctx context.Context, audit MgmtAuditStore, tenant string, events []*MgmtAuditEvent) error {
	if audit == nil || len(events) == 0 {
		return nil
	}
	if len(events) == 1 {
		return audit.RecordEvent(ctx, tenant, events[0])
	}
	batch, ok := audit.(interface {
		appendBatch(context.Context, string, []*MgmtAuditEvent) error
	})
	if !ok {
		return errors.New("bulk property edits require an atomic audit batch")
	}
	return batch.appendBatch(ctx, tenant, events)
}
