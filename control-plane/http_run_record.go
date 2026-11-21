package controlplane

import (
	"errors"
	"io"
	"net/http"
	"strconv"
)

var errRunBody = errors.New("invalid run result body")

func (s *Server) handleRunResult(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	store, ok := s.MgmtAudit.(*PgMgmtAuditStore)
	if !ok || store == nil {
		writeError(w, http.StatusInternalServerError, "run store not configured")
		return
	}
	event, err := store.completeRun(r.Context(), p.TenantID, p.UserID, r.PathValue("request_id"), func() ([]byte, error) {
		// Tenant middleware has already buffered the body at the small tier.
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSmallJSONBodyBytes))
		if err != nil {
			if !writeIfBodyTooLarge(w, err) {
				writeError(w, http.StatusBadRequest, errRunBody.Error())
			}
			return nil, errRunBody
		}
		fields, ok := strictSignedJSONObject(raw, "receipt", "")
		if !ok {
			writeError(w, http.StatusBadRequest, errRunBody.Error())
			return nil, errRunBody
		}
		return fields["receipt"], nil
	})
	switch {
	case errors.Is(err, errRunBody):
		return
	case errors.Is(err, errRunNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errRunConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errRunReceiptRefused):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not record run result")
	default:
		s.dispatchToolboxEvent(p.TenantID, event)
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleMachineRunHistory(w http.ResponseWriter, r *http.Request) {
	s.handleRunHistory(w, r, false)
}

func (s *Server) handleToolboxRunHistory(w http.ResponseWriter, r *http.Request) {
	s.handleRunHistory(w, r, true)
}

func (s *Server) handleRunHistory(w http.ResponseWriter, r *http.Request, byItem bool) {
	limit, offset := 50, 0
	var err error
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 100 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 100")
			return
		}
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		offset, err = strconv.Atoi(value)
		if err != nil || offset < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a nonnegative integer")
			return
		}
	}
	store, ok := s.MgmtAudit.(*PgMgmtAuditStore)
	if !ok || store == nil {
		writeError(w, http.StatusInternalServerError, "run store not configured")
		return
	}
	runs, err := store.listRunHistory(r.Context(), principalFrom(r.Context()), r.PathValue("id"), byItem, limit+1, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load run history")
		return
	}
	var next *int
	if len(runs) > limit {
		runs = runs[:limit]
		value := offset + limit
		next = &value
	}
	writeJSON(w, http.StatusOK, struct {
		Runs       []runHistoryEntry `json:"runs"`
		NextOffset *int              `json:"next_offset,omitempty"`
	}{Runs: runs, NextOffset: next})
}
