package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxMachineFields = 100
const machineFieldPageSize = 200

type MachineField struct {
	Key      string   `json:"key"`
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Choices  []string `json:"choices"`
	Position int      `json:"position"`
	Version  int64    `json:"version"`
}

type machineFieldList struct {
	Fields        []MachineField `json:"fields"`
	OrderRevision int64          `json:"order_revision"`
}

func validFieldString(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validDefinitionKey(key string) bool {
	return validateMachinePropertyKey(key) == nil && validFieldString(key) &&
		strings.TrimSpace(key) == key && key != "." && key != ".."
}

func validMachineField(field MachineField) bool {
	if !validDefinitionKey(field.Key) || len(field.Label) == 0 || len(field.Label) > 128 || !validFieldString(field.Label) {
		return false
	}
	switch field.Type {
	case "text", "number", "date", "boolean":
		return len(field.Choices) == 0
	case "choice":
		if len(field.Choices) == 0 || len(field.Choices) > 64 {
			return false
		}
		for i, choice := range field.Choices {
			if len(choice) == 0 || len(choice) > 128 || !validFieldString(choice) || strings.Trim(choice, " ") != choice {
				return false
			}
			for _, prior := range field.Choices[:i] {
				if strings.EqualFold(prior, choice) {
					return false
				}
			}
		}
		return true
	}
	return false
}

var fieldNumberInput = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
var fieldDateInput = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

func canonicalFieldValue(field MachineField, input string) (string, bool) {
	if field.Type == "text" {
		return input, true
	}
	if !validFieldString(input) {
		return "", false
	}
	value := strings.Trim(input, " ")
	if value == "" {
		return "", false
	}
	switch field.Type {
	case "number":
		if len(input) > 64 || !fieldNumberInput.MatchString(value) {
			return "", false
		}
		digits, negative := strings.CutPrefix(value, "-")
		integer, fraction, _ := strings.Cut(digits, ".")
		integer = strings.TrimLeft(integer, "0")
		if integer == "" {
			integer = "0"
		}
		fraction = strings.TrimRight(fraction, "0")
		if len(integer) > 15 || len(fraction) > 6 || (negative && integer == "0" && fraction == "") {
			return "", false
		}
		if fraction != "" {
			integer += "." + fraction
		}
		if negative {
			integer = "-" + integer
		}
		return integer, true
	case "date":
		if !fieldDateInput.MatchString(value) || value < "1900-01-01" || value > "2999-12-31" {
			return "", false
		}
		_, err := time.Parse(time.DateOnly, value)
		return value, err == nil
	case "boolean":
		return value, value == "true" || value == "false"
	case "choice":
		return value, slices.Contains(field.Choices, value)
	}
	return "", false
}

func fieldValueConforms(field MachineField, value string) bool {
	canonical, ok := canonicalFieldValue(field, value)
	return ok && canonical == value
}

var (
	errFieldMissing     = errors.New("unknown machine field")
	errFieldConflict    = errors.New("machine field changed, retry")
	errFieldPermutation = errors.New("keys must be an exact permutation of the current machine fields")
	errFieldLimit       = errors.New("at most 100 machine fields")
)

type invalidFieldValue struct{ label string }

func (e invalidFieldValue) Error() string { return fmt.Sprintf("invalid value for field %s", e.label) }

type machineFieldChange struct {
	action   string
	field    MachineField
	keys     []string
	revision int64
}

// apply updates a private snapshot. Both stores publish it only after auditing succeeds.
func (c *machineFieldChange) apply(list *machineFieldList) error {
	fields := list.Fields
	i := slices.IndexFunc(fields, func(f MachineField) bool { return f.Key == c.field.Key })
	switch c.action {
	case "created":
		if i >= 0 {
			return errFieldConflict
		}
		if len(fields) >= maxMachineFields {
			return errFieldLimit
		}
		c.field.ID, c.field.Version = newUUID(), 1
		if len(fields) != 0 {
			c.field.Position = fields[len(fields)-1].Position + 1
		}
		list.Fields = append(fields, c.field)
	case "updated", "deleted":
		if i < 0 {
			return errFieldMissing
		}
		old := fields[i]
		if old.ID != c.field.ID || old.Version != c.field.Version {
			return errFieldConflict
		}
		if c.action == "updated" {
			c.field.Position, c.field.Version = old.Position, old.Version+1
			fields[i] = c.field
			return nil
		}
		c.field = old
		list.Fields = slices.Delete(fields, i, i+1)
	case "reordered":
		if c.revision != list.OrderRevision {
			return errFieldConflict
		}
		if len(c.keys) != len(fields) {
			return errFieldPermutation
		}
		byKey := make(map[string]MachineField, len(fields))
		for _, field := range fields {
			byKey[field.Key] = field
		}
		for i, key := range c.keys {
			field, ok := byKey[key]
			if !ok {
				return errFieldPermutation
			}
			delete(byKey, key)
			field.Position = i
			fields[i] = field
		}
	}
	list.OrderRevision++
	c.revision = list.OrderRevision
	return nil
}

func (c machineFieldChange) event(p *Principal) *MgmtAuditEvent {
	meta := map[string]any{"key": c.field.Key, "type": c.field.Type, "choice_count": len(c.field.Choices)}
	if c.action == "reordered" {
		meta = map[string]any{"order_revision": c.revision, "keys": c.keys}
	}
	raw, _ := json.Marshal(meta)
	return &MgmtAuditEvent{
		ActorUserID: p.UserID, Action: "machine_field." + c.action,
		TargetKind: "machine_field", TargetID: c.field.ID, Metadata: raw,
	}
}

type machineFieldCursor struct {
	TenantID string `json:"tenant_id"`
	Key      string `json:"key"`
	FieldID  string `json:"field_id"`
	Version  int64  `json:"field_version"`
	LastID   string `json:"last_id"`
}

type machineFieldViolation struct {
	MachineID   string `json:"machine_id"`
	MachineName string `json:"machine_name"`
	Value       string `json:"value"`
}
