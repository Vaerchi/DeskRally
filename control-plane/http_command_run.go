package controlplane

// POST /sessions/{id}/command-run — centrally authorize + AUDIT an ad-hoc command before the viewer
// sends it to the agent as an ordinary RunCommand.
//
// This mirrors the toolbox-run grant (http_toolbox.go / handleRunToolboxItem) for a command the
// operator types rather than a saved item. Why it exists: a plain RunCommand is gated only agent-side
// (view-only / pending-command latch) and leaves NO record in the management audit trail — only the
// toolbox path audits what ran. A fleet-wide ad-hoc run (bulk commands across many machines) is a
// higher-risk action than a vetted saved script, so it must be at least as well audited. The viewer's
// bulk command path calls this once per machine's held session; the audit names the session, the
// machine and the exact command, and only AFTER it commits is the authoritative command text handed
// back for dispatch.
//
// No agent change: the command the agent runs is the same ToolboxCommand transform the toolbox path
// already emits (a cmd line as-is; a PowerShell body wrapped around its base64), so the audited text
// and the executed text are one and the same.

import "net/http"

// runCommandBody is the request for POST /sessions/{id}/command-run. Body is the raw script the
// operator typed (a cmd line or a PowerShell script); it is validated and length-capped exactly like a
// toolbox item's body.
type runCommandBody struct {
	Shell string `json:"shell"`
	RunAs string `json:"run_as"`
	Body  string `json:"body"`
}

// commandAuditPreviewBytes caps how much of the command text is stored inline in the audit metadata.
// The full command is identified by its sha256; the preview keeps a readable head without letting a
// single bulk run write 25 × 16 KiB of body into the audit log.
const commandAuditPreviewBytes = 2048

func (s *Server) handleRunCommand(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req runCommandBody
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed command-run request"); err != nil {
		return
	}
	// Validate the command BEFORE touching the session, with the same rules (and length caps) a saved
	// toolbox item gets, so the two paths can never diverge (ValidateCommandShellRunAsBody).
	if err := ValidateCommandShellRunAsBody(req.Shell, req.RunAs, req.Body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The session exactly as a lease renewal would authorize it: the holder's capability on the
	// machine's LIVE group, their ownership of the record, the machine's status, and the effective
	// access. Nothing is minted or extended.
	held, refusal := s.checkHeldSession(r.Context(), p, r.PathValue("id"), "run a command")
	if refusal != nil {
		refusal.write(w)
		return
	}
	// A cleared group mandate must never make an observer's held record actuating.
	if held.Rec.Access == "view_only" {
		writeError(w, http.StatusForbidden, "this session is an observer; commands cannot run")
		return
	}
	if held.Access == SessionAccessViewOnly {
		writeError(w, http.StatusConflict, "this session is view-only; commands cannot run")
		return
	}
	// Unlike a generic mutation, this endpoint's ENTIRE purpose is the central audit, so it must fail
	// CLOSED when no audit store is wired: recordMgmtAudit silently no-ops in that configuration (it is
	// nil only in pure-RBAC skeleton tests), which would hand out a runnable command with no record.
	// Refuse before that can happen, rather than quietly breaking the guarantee the endpoint exists for.
	if s.MgmtAudit == nil {
		writeError(w, http.StatusInternalServerError, "audit store not configured; commands cannot run")
		return
	}
	requestID := newUUID()
	// Audit FIRST, and fail the request if the audit cannot be written (recordMgmtAudit returns the
	// error for exactly this): a command that cannot be recorded must not be handed out to run.
	if err := s.recordMgmtAudit(r, "command.run_requested", "session", held.Rec.ID, map[string]any{
		"request_id":      requestID,
		"session_id":      held.Rec.ID,
		"machine_id":      held.Rec.MachineID,
		"shell":           req.Shell,
		"run_as":          req.RunAs,
		"command_sha256":  ToolboxBodySHA256(req.Body),
		"command_preview": previewBytes(req.Body, commandAuditPreviewBytes),
		"outcome":         "unknown",
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record the command run; nothing was dispatched")
		return
	}
	// The audit has committed; only now is the authoritative command handed out.
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": requestID,
		"shell":      req.Shell,
		"run_as":     req.RunAs,
		"command":    ToolboxCommand(req.Shell, req.Body),
	})
}

// previewBytes returns the longest valid-UTF-8 prefix of s that fits in limit bytes (never splitting a
// rune), so an audit preview is bounded without ever emitting a broken code point.
func previewBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// utf8RuneStart reports whether b is the first byte of a UTF-8 sequence (not a 10xxxxxx continuation).
func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
