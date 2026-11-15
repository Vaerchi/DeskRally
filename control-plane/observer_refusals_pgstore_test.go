package controlplane

import (
	"fmt"
	"net/http"
	"testing"
)

func TestObserverPGRefusesToolboxAndElevation(t *testing.T) {
	f := newObserverPGFixture(t)
	// The holder is an owner with all command and elevation permissions.
	// The group allows control, so refusal must come from admission mode.
	code, started := observerStart(t, f.ownerSrv, "view_only")
	if code != http.StatusCreated {
		t.Fatalf("observer start = %d", code)
	}
	code, item := tbCreate(t, f.ownerSrv, "shared", "Observer refusal probe", "powershell", "Get-Date")
	if code != http.StatusCreated {
		t.Fatalf("create toolbox item = %d", code)
	}
	before := observerAuditMetadata(t, f, "run_requested", "")
	body := fmt.Sprintf(`{"session_id":%q,"expected_version":%d}`, started.Session.ID, item.Version)
	if code := apiJSON(t, f.ownerSrv, "POST", "/toolbox/"+item.ID+"/runs", body, nil); code != http.StatusForbidden {
		t.Fatalf("observer toolbox run = %d, want 403", code)
	}
	after := observerAuditMetadata(t, f, "run_requested", "")
	if len(after) != len(before) {
		t.Fatalf("refused observer run emitted run_requested: before=%+v after=%+v", before, after)
	}
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions/"+started.Session.ID+"/elevation", `{}`, nil); code != http.StatusForbidden {
		t.Fatalf("observer elevation mint = %d, want 403", code)
	}
	// Security audit 2026-10-18: a backstage grant naming the observer session is refused too, and
	// the same mint for a CONTROL session succeeds — the refusal comes from the admission mode, not
	// from anything else about this caller, machine or group.
	grantBody := func(sessionID string) string {
		return fmt.Sprintf(`{"machine_id":%q,"session_id":%q}`, observerTestDevice, sessionID)
	}
	if code := apiJSON(t, f.ownerSrv, "POST", "/grant/mint", grantBody(started.Session.ID), nil); code != http.StatusForbidden {
		t.Fatalf("observer backstage grant mint = %d, want 403", code)
	}
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	if code := apiJSON(t, f.ownerSrv, "POST", "/grant/mint", grantBody(control.Session.ID), nil); code != http.StatusOK {
		t.Fatalf("control-session backstage grant mint = %d, want 200", code)
	}
	var access string
	var open bool
	if err := f.su.QueryRow(t.Context(), `SELECT access, ended_at IS NULL FROM session_record WHERE tenant_id = $1 AND id = $2`, f.tenant, started.Session.ID).Scan(&access, &open); err != nil {
		t.Fatal(err)
	}
	if access != "view_only" || !open {
		t.Fatalf("refusals changed held session: access=%q open=%v", access, open)
	}
}
