package controlplane

// Ad-hoc command-run grant (POST /sessions/{id}/command-run) against real Postgres as rmt_app, through
// the HTTP handlers — the sibling of TestPgToolboxRunRequest. Proves it authorizes exactly as a held
// session, audits `command.run_requested` BEFORE handing out the command, returns the authoritative
// ToolboxCommand transform, and that every refusal (not the holder, cross-tenant, view-only,
// quarantined, ended, un-auditable, or an invalid command) records nothing.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

type cmdRunResp struct {
	RequestID string `json:"request_id"`
	Shell     string `json:"shell"`
	RunAs     string `json:"run_as"`
	Command   string `json:"command"`
}

func cmdRun(t *testing.T, srv *Server, sessionID, shell, runAs, body string) (int, cmdRunResp) {
	t.Helper()
	var out cmdRunResp
	code := apiJSON(t, srv, "POST", "/sessions/"+sessionID+"/command-run",
		fmt.Sprintf(`{"shell":%q,"run_as":%q,"body":%q}`, shell, runAs, body), &out)
	return code, out
}

func TestPgAdhocCommandRun(t *testing.T) {
	f := newToolboxFixture(t)
	ctx := context.Background()
	body := "Write-Output 'hi' \"$env:COMPUTERNAME\" 😀"

	var started struct {
		Session SessionRecord `json:"session"`
	}
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions", `{"machine_id":"tb-dev"}`, &started); code != http.StatusCreated {
		t.Fatalf("start session = %d", code)
	}
	sid := started.Session.ID
	machineID := started.Session.MachineID

	// Invalid commands are 400 BEFORE the session is looked at: a bogus session id still gets 400, so
	// malformed input never reveals whether a session exists.
	for _, c := range []struct {
		name, shell, runAs, body string
	}{
		{"bad run_as", "cmd", "root", "dir"},
		{"bad shell", "bash", "system", "ls"},
		{"empty body", "cmd", "system", "   "},
		{"cmd multiline", "cmd", "system", "dir\r\ndir"},
		{"powershell over limit", "powershell", "system", strings.Repeat("a", MaxToolboxPowerShellBytes+1)},
	} {
		if code, _ := cmdRun(t, f.ownerSrv, "no-such-session", c.shell, c.runAs, c.body); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", c.name, code)
		}
	}

	// Happy path: the command is authoritative (the same transform the toolbox path emits) and audited.
	code, run := cmdRun(t, f.ownerSrv, sid, "powershell", "system", body)
	if code != http.StatusOK || run.Command != ToolboxCommand("powershell", body) || run.Shell != "powershell" ||
		run.RunAs != "system" || run.RequestID == "" {
		t.Fatalf("run = %d %+v", code, run)
	}
	var meta []byte
	if err := f.su.QueryRow(ctx, `SELECT metadata FROM audit_event WHERE tenant_id = $1 AND action = 'command.run_requested'`, f.tenant).Scan(&meta); err != nil {
		t.Fatalf("run audit row: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(meta, &m)
	if m["request_id"] != run.RequestID || m["outcome"] != "unknown" || m["command_sha256"] != ToolboxBodySHA256(body) ||
		m["session_id"] != sid || m["machine_id"] != machineID || m["shell"] != "powershell" || m["run_as"] != "system" ||
		m["command_preview"] != body {
		t.Fatalf("run audit metadata = %s", meta)
	}

	// Fail closed when no audit store is wired: the endpoint must refuse rather than hand out a command
	// it cannot record (the whole point of the endpoint). Same session, otherwise valid.
	owner := &Principal{UserID: f.owner, TenantID: f.tenant, SessionID: "sess-" + f.owner,
		Grant: NewGrant(f.owner, f.tenant, NewMembership(RoleOwner, AllGroups()))}
	noAudit := f.serverFor(owner)
	noAudit.MgmtAudit = nil
	if code, resp := cmdRun(t, noAudit, sid, "cmd", "system", "whoami"); code != http.StatusInternalServerError || resp.Command != "" {
		t.Fatalf("command with no audit store = %d %+v, want 500 and no command", code, resp)
	}

	// Refusals (each records nothing).
	if code, _ := cmdRun(t, f.techSrv, sid, "cmd", "system", "whoami"); code != http.StatusForbidden {
		t.Fatalf("command on another technician's session = %d, want 403", code)
	}
	if code, _ := cmdRun(t, f.alienSrv, sid, "cmd", "system", "whoami"); code != http.StatusNotFound {
		t.Fatalf("cross-tenant command = %d, want 404", code)
	}
	// View-only group mandate.
	mustExec(t, f.su, `INSERT INTO group_session_policy (tenant_id, group_id, enforce_view_only) VALUES ($1, $2, true)`, f.tenant, f.groupID)
	if code, _ := cmdRun(t, f.ownerSrv, sid, "cmd", "system", "whoami"); code != http.StatusConflict {
		t.Fatalf("command in a view-only group = %d, want 409", code)
	}
	mustExec(t, f.su, `DELETE FROM group_session_policy WHERE group_id = $1`, f.groupID)
	// Quarantined machine.
	mustExec(t, f.su, `UPDATE machine SET status = 'quarantined' WHERE device_id = 'tb-dev'`)
	if code, _ := cmdRun(t, f.ownerSrv, sid, "cmd", "system", "whoami"); code != http.StatusConflict {
		t.Fatalf("command on a quarantined machine = %d, want 409", code)
	}
	mustExec(t, f.su, `UPDATE machine SET status = 'active' WHERE device_id = 'tb-dev'`)
	// The audit append fails: the command is refused and nothing is handed out.
	mustExec(t, f.su, `REVOKE INSERT ON audit_event FROM rmt_app`)
	code, failed := cmdRun(t, f.ownerSrv, sid, "cmd", "system", "whoami")
	mustExec(t, f.su, `GRANT INSERT ON audit_event TO rmt_app`)
	if code != http.StatusInternalServerError || failed.Command != "" {
		t.Fatalf("command with a failing audit = %d %+v, want 500 and no command", code, failed)
	}
	// Ended session.
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions/"+sid+"/end", "", nil); code != http.StatusOK {
		t.Fatalf("end session = %d", code)
	}
	if code, _ := cmdRun(t, f.ownerSrv, sid, "cmd", "system", "whoami"); code != http.StatusConflict {
		t.Fatalf("command on an ended session = %d, want 409", code)
	}

	var n int
	if err := f.su.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action = 'command.run_requested'`, f.tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("command.run_requested rows = %d (%v), want exactly 1 (refusals record nothing)", n, err)
	}
}
