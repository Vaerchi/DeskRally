package controlplane

import (
	"encoding/json"
	"errors"
	"sort"
)

type machinePropertyTarget struct {
	id    string
	index int
}

type machinePropertyEdit struct {
	key, value                   string
	remove, bulk, invalidUnicode bool
	targets                      []machinePropertyTarget
	results                      []bulkStatusResult
}

func (edit *machinePropertyEdit) prepare(ids []string, allowSynthetic bool) error {
	edit.results = make([]bulkStatusResult, len(ids))
	seen := make(map[string]bool, len(ids))
	for i, raw := range ids {
		edit.results[i].MachineID = raw
		id, ok := parsePgUUID(raw)
		if !ok {
			if !allowSynthetic {
				edit.results[i].Error = "unknown machine"
				continue
			}
			id = raw
		}
		if seen[id] {
			return errors.New("duplicate machine id")
		}
		seen[id] = true
		edit.targets = append(edit.targets, machinePropertyTarget{id: id, index: i})
	}
	sort.Slice(edit.targets, func(i, j int) bool { return edit.targets[i].id < edit.targets[j].id })
	return nil
}

func (edit *machinePropertyEdit) checkScope(p *Principal, target machinePropertyTarget, group string) error {
	if err := p.Grant.RequireMachine(CapManageMachines, group); err != nil {
		if !edit.bulk {
			return err
		}
		edit.results[target.index].Error = "denied"
	}
	return nil
}

func (edit *machinePropertyEdit) canonicalize(field MachineField) error {
	value, ok := canonicalFieldValue(field, edit.value)
	if !ok || (field.Type != "text" && edit.invalidUnicode) {
		return invalidFieldValue{label: field.Label}
	}
	edit.value = value
	return nil
}

func (edit *machinePropertyEdit) event(p *Principal, id string) *MgmtAuditEvent {
	action := "machine.property.set"
	if edit.remove {
		action = "machine.property.delete"
	}
	meta := map[string]any{"key": edit.key}
	if edit.bulk {
		meta["bulk"] = true
	}
	raw, _ := json.Marshal(meta)
	return &MgmtAuditEvent{
		ActorUserID: p.UserID, Action: action, TargetKind: "machine", TargetID: id, Metadata: raw,
	}
}
