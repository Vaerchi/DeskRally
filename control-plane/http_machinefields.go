package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"unicode/utf8"
)

type machineFieldStore interface {
	listFields(context.Context, string) (machineFieldList, error)
	changeFields(context.Context, *Principal, MgmtAuditStore, *machineFieldChange) ([]*MgmtAuditEvent, error)
	reportField(context.Context, *Principal, MachineStore, string, GroupScope, *machineFieldCursor) (machineFieldReport, error)
	editProperties(context.Context, *Principal, MachineStore, MgmtAuditStore, *machinePropertyEdit) ([]*MgmtAuditEvent, error)
}

func (s *Server) fieldStore(w http.ResponseWriter) machineFieldStore {
	store, ok := s.MachineProperties.(machineFieldStore)
	if !ok {
		writeError(w, http.StatusInternalServerError, "machine field store not configured")
		return nil
	}
	return store
}

func writeMachineFieldError(w http.ResponseWriter, err error) {
	var invalid invalidFieldValue
	switch {
	case errors.As(err, &invalid), errors.Is(err, errFieldPermutation), errors.Is(err, errFieldLimit):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errFieldMissing):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errFieldConflict), errors.Is(err, ErrGroupTreeChanged):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "could not complete machine field operation")
	}
}

func (s *Server) dispatchMachineFieldEvents(p *Principal, events []*MgmtAuditEvent) {
	if s.Dispatcher != nil && s.MgmtAudit != nil {
		for _, event := range events {
			s.Dispatcher.Dispatch(p.TenantID, event)
		}
	}
}

func (s *Server) handleListMachineFields(w http.ResponseWriter, r *http.Request) {
	store := s.fieldStore(w)
	if store == nil {
		return
	}
	list, err := store.listFields(r.Context(), principalFrom(r.Context()).TenantID)
	if err != nil {
		writeMachineFieldError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// hasUnpairedJSONSurrogate scans raw JSON escapes before their decoded strings
// can lose the distinction between a lone surrogate and a literal U+FFFD.
// The caller supplies syntactically valid JSON.
func hasUnpairedJSONSurrogate(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		unit, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		switch {
		case unit >= 0xdc00 && unit <= 0xdfff:
			return true
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return true
			}
			low, _ := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 6
		}
	}
	return false
}

func decodeMachineFieldJSON(w http.ResponseWriter, r *http.Request, dst any, message string) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSmallJSONBodyBytes))
	if err != nil && writeIfBodyTooLarge(w, err) {
		return false
	}
	if err != nil || !utf8.Valid(data) || !json.Valid(data) || hasUnpairedJSONSurrogate(data) || json.Unmarshal(data, dst) != nil {
		writeError(w, http.StatusBadRequest, message)
		return false
	}
	return true
}

func (s *Server) handleChangeMachineFields(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if scope, ok := p.Grant.ScopeFor(CapManageTenant); !ok || !scope.All {
		writeError(w, http.StatusForbidden, "tenant-wide manage tenant capability required")
		return
	}
	store := s.fieldStore(w)
	if store == nil {
		return
	}
	var change machineFieldChange
	status := http.StatusOK
	switch {
	case r.URL.Path == "/machine-field-order":
		var req struct {
			OrderRevision *int64   `json:"order_revision"`
			Keys          []string `json:"keys"`
		}
		if !decodeMachineFieldJSON(w, r, &req, "malformed field order") {
			return
		}
		if req.OrderRevision == nil || *req.OrderRevision < 0 || req.Keys == nil {
			writeError(w, http.StatusBadRequest, "order_revision and keys are required")
			return
		}
		change = machineFieldChange{action: "reordered", keys: req.Keys, revision: *req.OrderRevision}
	case r.Method == http.MethodDelete:
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query["id"]) != 1 || len(query["version"]) != 1 {
			writeError(w, http.StatusBadRequest, "valid id and version are required")
			return
		}
		version, err := strconv.ParseInt(query.Get("version"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "valid id and version are required")
			return
		}
		change = machineFieldChange{action: "deleted", field: MachineField{
			Key: r.PathValue("key"), ID: query.Get("id"), Version: version,
		}}
		status = http.StatusNoContent
	default:
		var req MachineField
		if !decodeMachineFieldJSON(w, r, &req, "malformed machine field") {
			return
		}
		change = machineFieldChange{action: "updated", field: req}
		if r.Method == http.MethodPost {
			change.action = "created"
			change.field.Position = 0
			status = http.StatusCreated
		} else {
			change.field.Key = r.PathValue("key")
		}
		if !validMachineField(change.field) {
			writeError(w, http.StatusBadRequest, "invalid machine field definition")
			return
		}
		if change.field.Type != "choice" {
			change.field.Choices = nil
		}
	}
	if change.action == "updated" || change.action == "deleted" {
		id, ok := parsePgUUID(change.field.ID)
		if !ok || change.field.Version < 1 || !validDefinitionKey(change.field.Key) {
			writeError(w, http.StatusBadRequest, "valid id and version are required")
			return
		}
		change.field.ID = id
	}
	events, err := store.changeFields(r.Context(), p, s.MgmtAudit, &change)
	if err != nil {
		writeMachineFieldError(w, err)
		return
	}
	s.dispatchMachineFieldEvents(p, events)
	switch change.action {
	case "deleted":
		w.WriteHeader(status)
	case "reordered":
		writeJSON(w, status, map[string]int64{"order_revision": change.revision})
	default:
		writeJSON(w, status, map[string]any{"field": change.field})
	}
}

type machineFieldReport struct {
	Machines   []machineFieldViolation `json:"machines"`
	Total      int64                   `json:"total"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

func (report *machineFieldReport) finish(tenant, key, id string, version int64) {
	if len(report.Machines) <= machineFieldPageSize {
		return
	}
	report.Machines = report.Machines[:machineFieldPageSize]
	last := report.Machines[machineFieldPageSize-1].MachineID
	raw, _ := json.Marshal(machineFieldCursor{canonicalUUIDish(tenant), key, id, version, last})
	report.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
}

func readMachineFieldCursor(encoded string) (*machineFieldCursor, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	var cursor machineFieldCursor
	bad := errors.New("invalid machine field cursor")
	if err != nil || !utf8.Valid(raw) || json.Unmarshal(raw, &cursor) != nil ||
		!validDefinitionKey(cursor.Key) || cursor.Version < 1 {
		return nil, bad
	}
	tenantID, validTenant := parsePgUUID(cursor.TenantID)
	fieldID, validField := parsePgUUID(cursor.FieldID)
	lastID, validLast := parsePgUUID(cursor.LastID)
	if !validTenant || !validField || !validLast {
		return nil, bad
	}
	cursor.TenantID, cursor.FieldID, cursor.LastID = tenantID, fieldID, lastID
	return &cursor, nil
}

func checkFieldCursor(cursor *machineFieldCursor, tenant, key, id string, version int64) error {
	if cursor != nil && (cursor.TenantID != canonicalUUIDish(tenant) || cursor.Key != key ||
		cursor.FieldID != id || cursor.Version != version) {
		return errFieldConflict
	}
	return nil
}

func missingReportedField(cursor *machineFieldCursor) error {
	if cursor != nil {
		return errFieldConflict
	}
	return errFieldMissing
}

func (s *Server) handleMachineFieldReport(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	scope, ok := p.Grant.ScopeFor(CapViewMachines)
	if !ok {
		writeError(w, http.StatusForbidden, "machine field report unavailable")
		return
	}
	store := s.fieldStore(w)
	if store == nil {
		return
	}
	key := r.PathValue("key")
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !validDefinitionKey(key) || len(query["cursor"]) > 1 {
		writeError(w, http.StatusBadRequest, "invalid machine field report request")
		return
	}
	var cursor *machineFieldCursor
	if query.Has("cursor") {
		cursor, err = readMachineFieldCursor(query.Get("cursor"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	report, err := store.reportField(r.Context(), p, s.Machines, key, scope, cursor)
	if err != nil {
		writeMachineFieldError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
