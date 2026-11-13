package controlplane

// Management-audit chain endpoints: SIEM export + chain verification, both read-only GETs
// behind CapViewAudit (same gate as GET /audit; GETs pass csrfMiddleware untouched).
//
//	GET /audit/export?after_seq=N&limit=M  → NDJSON (application/x-ndjson), one chained
//	    MgmtAuditEvent per line in ascending seq order. A SIEM collector pages by re-requesting
//	    with after_seq = the last line's seq; each line carries seq/prev_hash/hash so the
//	    collector can (re)verify the chain independently of this server.
//	GET /audit/verify?after_seq=N&limit=M → walks the tenant's chain server-side, recomputing every
//	    hash. BOUNDED and resumable: a response with completed=false carries next_after_seq, and the
//	    resumed walk re-anchors on that event's stored hash so consecutive pages compose.

import (
	"encoding/json"
	"net/http"
	"strconv"
)

const (
	defaultMgmtAuditExportLimit = 1000
	maxMgmtAuditExportLimit     = 10000
)

// handleExportAudit streams a page of the tenant's chained audit trail as NDJSON.
func (s *Server) handleExportAudit(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	// The chain export is only meaningful tenant-wide (http_mgmtaudit_scope.go).
	if !requireTenantWideAudit(w, p) {
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}
	afterSeq := int64(-1)
	if v := r.URL.Query().Get("after_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < -1 {
			writeError(w, http.StatusBadRequest, "after_seq must be an integer >= -1")
			return
		}
		afterSeq = n
	}
	limit := defaultMgmtAuditExportLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxMgmtAuditExportLimit {
			writeError(w, http.StatusBadRequest,
				"limit must be a positive integer <= "+strconv.Itoa(maxMgmtAuditExportLimit))
			return
		}
		limit = n
	}
	releaseSlot, ok := s.acquireAuditStream(w, p)
	if !ok {
		return
	}
	defer releaseSlot()
	events, err := s.MgmtAudit.ListEventsAsc(r.Context(), p.TenantID, afterSeq, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not export audit events")
		return
	}
	// All reads are done: give the pinned tenant connection back before writing to a possibly slow
	// client (review #5).
	releaseBoundConn(r.Context())
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store") // audit trail: sensitive tenant data (docs/25 F10)
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w) // Encode appends the newline NDJSON wants
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return // client went away mid-stream; nothing sensible left to send
		}
	}
}

// handleVerifyAudit re-walks the tenant's chain and reports whether it is intact.
//
// The walk is BOUNDED and resumable (?after_seq=&limit=), because it is the most expensive read
// on this surface — a SHA-256 per event over a chain that only grows — and an unbounded one lets
// any CapViewAudit holder replay a full-table scan at will. A response with completed=false
// carries next_after_seq to continue from; the resumed walk re-anchors on that event's hash, so
// paging proves exactly what one unbroken walk would.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	// Chain verification walks (and reports counts over) the whole tenant chain.
	if !requireTenantWideAudit(w, p) {
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}
	afterSeq := int64(-1)
	if v := r.URL.Query().Get("after_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < -1 {
			writeError(w, http.StatusBadRequest, "after_seq must be an integer >= -1")
			return
		}
		afterSeq = n
	}
	limit := maxMgmtAuditVerifyEvents
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > maxMgmtAuditVerifyEvents {
			writeError(w, http.StatusBadRequest,
				"limit must be a positive integer <= "+strconv.Itoa(maxMgmtAuditVerifyEvents))
			return
		}
		limit = n
	}
	res, err := VerifyMgmtAuditChainFrom(r.Context(), s.MgmtAudit, p.TenantID, afterSeq, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not verify audit chain")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
