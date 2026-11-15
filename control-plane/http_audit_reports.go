package controlplane

// The audit log, its summary, and the session reports. Split out of http.go (routing and middleware stay there).

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}
	limit := 0 // 0 → store default
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = min(n, 1000)
	}
	// Optional filters (docs/01 §5): ?action= and ?target_kind= are exact-match; ?actor= restricts to
	// one actor_user_id; ?since=/?until= (RFC3339) bound a CLOSED time range [since, until]. All are
	// applied BEFORE the limit, so `limit` bounds the MATCHING events. This lets an auditor pull "every
	// machine.enroll by user X between two timestamps" — the SOC2/HIPAA review query.
	filter, ok := parseAuditFilter(w, r)
	if !ok {
		return
	}
	// ?cursor= continues a previous listing (the next_cursor of a truncated scoped answer, or the
	// position of any event); it is an exact composite position, not a timestamp.
	if v := r.URL.Query().Get("cursor"); v != "" {
		c, derr := decodeAuditCursor(v)
		if derr != nil {
			writeError(w, http.StatusBadRequest, "cursor is malformed")
			return
		}
		filter.Before = c
	}
	var events []MgmtAuditEvent
	var cut *AuditCursor
	var err error
	if scope, _ := p.Grant.ScopeFor(CapViewAudit); scope.All {
		events, err = s.MgmtAudit.ListEventsFiltered(r.Context(), p.TenantID, limit, filter)
	} else {
		// A group-scoped holder sees only events attributable to machines/groups in their scope
		// (http_mgmtaudit_scope.go); fail closed if a lookup errors.
		events, cut, err = s.newMgmtAuditScoper(p).listScoped(r.Context(), limit, filter)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list audit events")
		return
	}
	if events == nil {
		events = []MgmtAuditEvent{}
	}
	resp := map[string]any{"events": events}
	if cut != nil {
		// The scan cap was reached before the trail was exhausted: say so, and say where to resume.
		resp["truncated"] = true
		resp["next_cursor"] = encodeAuditCursor(cut)
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseAuditFilter reads the shared ?action=/?target_kind=/?actor=/?since=/?until= query params into an
// AuditFilter (docs/01 §5). On a malformed since/until it writes a 400 and returns ok=false — the caller
// must return. Shared by GET /audit (list) and GET /audit/summary (Reports).
// parseSinceUntil parses the optional ?since=/?until= RFC3339 query params into a CLOSED [since, until]
// instant range (a zero time = "no bound" on that side). Returns ok=false after writing a 400 if either is
// malformed. Shared by the audit filter and the session-activity reports so both accept the same range syntax.
func parseSinceUntil(w http.ResponseWriter, r *http.Request) (since, until time.Time, ok bool) {
	if v := strings.TrimSpace(r.URL.Query().Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC3339 timestamp")
			return time.Time{}, time.Time{}, false
		}
		since = t
	}
	if v := strings.TrimSpace(r.URL.Query().Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be an RFC3339 timestamp")
			return time.Time{}, time.Time{}, false
		}
		until = t
	}
	return since, until, true
}

func parseAuditFilter(w http.ResponseWriter, r *http.Request) (AuditFilter, bool) {
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return AuditFilter{}, false
	}
	return AuditFilter{
		Action:     strings.TrimSpace(r.URL.Query().Get("action")),
		TargetKind: strings.TrimSpace(r.URL.Query().Get("target_kind")),
		Actor:      strings.TrimSpace(r.URL.Query().Get("actor")),
		Since:      since,
		Until:      until,
	}, true
}

// handleAuditSummary (GET /audit/summary) returns per-action event counts for the §5 Reports view — an
// aggregation of the SAME tenant-scoped, CapViewAudit-gated audit trail GET /audit reads, over the same
// optional ?actor=/?target_kind=/?since=/?until= filter (no ?action= is expected — the summary GROUPS by
// action — though a set ?action= simply narrows to that one action's count).
func (s *Server) handleAuditSummary(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewAudit); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured")
		return
	}
	filter, ok := parseAuditFilter(w, r)
	if !ok {
		return
	}
	var summary []AuditActionCount
	var partial bool
	var err error
	if scope, _ := p.Grant.ScopeFor(CapViewAudit); scope.All {
		summary, err = s.MgmtAudit.SummarizeByAction(r.Context(), p.TenantID, filter)
	} else {
		summary, partial, err = s.newMgmtAuditScoper(p).summarizeScoped(r.Context(), filter)
	}
	if err != nil {
		writeListError(w, err, "could not summarize audit")
		return
	}
	if summary == nil {
		summary = []AuditActionCount{}
	}
	resp := map[string]any{"summary": summary}
	if partial {
		// The scoped scan cap cut the walk short: these counts are a lower bound, not the total.
		resp["partial"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReportSessionsByMachine (GET /reports/sessions-by-machine) returns per-machine session counts
// for the §5 Reports view — an aggregation of the SAME tenant-scoped, CapViewSessions-gated session
// records GET /sessions reads. RLS pins the tenant; then, exactly like the session list, the rows are
// confined to the machine groups the caller's memberships cover (a tenant-wide Require(cap) still owes
// the per-group narrowing).
func (s *Server) handleReportSessionsByMachine(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return
	}
	all, err := s.SessionRecords.SummarizeByMachine(r.Context(), p.TenantID, SessionSummaryFilter{Since: since, Until: until})
	if err != nil {
		writeListError(w, err, "could not summarize sessions")
		return
	}
	visible := make([]MachineSessionCount, 0, len(all))
	for _, c := range all {
		if p.Grant.AllowsInGroup(CapViewSessions, c.MachineGroupID) {
			visible = append(visible, c)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions_by_machine": visible})
}

// handleReportSessionsByTechnician (GET /reports/sessions-by-technician) returns per-technician session
// counts + total time for the §5 Reports view. Like the by-machine report it is gated CapViewSessions and
// RLS-pinned to the tenant, but because a technician's sessions span multiple machine groups, the store
// returns per-(technician, group) sub-counts and the NARROWING happens BEFORE aggregation: rows in groups
// the caller cannot view are dropped, then the survivors are summed per technician (a scoped viewer must
// never see a technician's totals from groups outside their scope). The result is sorted most sessions
// first, ties by technician id. The technician is returned by id; the console resolves the label.
func (s *Server) handleReportSessionsByTechnician(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return
	}
	sub, err := s.SessionRecords.SummarizeByTechnician(r.Context(), p.TenantID, SessionSummaryFilter{Since: since, Until: until})
	if err != nil {
		writeListError(w, err, "could not summarize sessions")
		return
	}
	// Narrow FIRST (drop groups the caller cannot view), THEN aggregate per technician.
	byTech := make(map[string]*TechnicianSessionCount)
	order := make([]string, 0)
	for _, c := range sub {
		if !p.Grant.AllowsInGroup(CapViewSessions, c.MachineGroupID) {
			continue
		}
		t, ok := byTech[c.TechnicianID]
		if !ok {
			t = &TechnicianSessionCount{TechnicianID: c.TechnicianID}
			byTech[c.TechnicianID] = t
			order = append(order, c.TechnicianID)
		}
		t.Count += c.Count
		t.TotalSeconds += c.TotalSeconds
	}
	out := make([]TechnicianSessionCount, 0, len(byTech))
	for _, id := range order {
		out = append(out, *byTech[id])
	}
	// Most sessions first; ties by technician id (byte order) for a stable, deterministic result.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].TechnicianID < out[j].TechnicianID
	})
	writeJSON(w, http.StatusOK, map[string]any{"sessions_by_technician": out})
}
