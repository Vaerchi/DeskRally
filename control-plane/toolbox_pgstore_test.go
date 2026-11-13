package controlplane

// Shared Toolbox against real Postgres as rmt_app, through the HTTP handlers (docs/design-shared-
// toolbox.md "Tests").

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

type toolboxFixture struct {
	su, app            *pgxpool.Pool
	tenant, other      string // tenant ids
	owner, tech, alien string // owner (all caps) and technician in `tenant`; alien in `other`
	groupID            string
	ownerSrv, techSrv  *Server
	alienSrv           *Server
	// serverFor builds a server over the fixture's stores for any principal.
	serverFor func(p *Principal) *Server
}

func newToolboxFixture(t *testing.T) *toolboxFixture {
	t.Helper()
	ctx := context.Background()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyMgmtAuditChainMigration(t, su)
	applyAttendedMigration(t, su)
	applyMigrationFile(t, su, "migrations/0056_toolbox.sql") // group_session_policy is in the base test schema
	f := &toolboxFixture{su: su}
	f.tenant, f.owner = provisionUser(t, su, "acme", "owner@acme.test", "password-1234")
	f.other, f.alien = provisionUser(t, su, "other", "owner@other.test", "password-1234")
	if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&f.tech); err != nil {
		t.Fatal(err)
	}
	mustExec(t, su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, 'tech@acme.test')`, f.tech, f.tenant)
	f.groupID, _ = seedGroupMachine(t, su, f.tenant, "tb-dev")
	f.app = newAppRolePool(t, ctx)
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	f.serverFor = func(p *Principal) *Server {
		srv := NewServer(StubAuthenticator{Principal: p}, NewPgBinder(f.app))
		srv.Machines = NewPgMachineStore(f.app)
		srv.SessionRecords = NewPgSessionRecordStore(f.app)
		audit := NewPgMgmtAuditStore(f.app)
		srv.MgmtAudit = audit
		srv.GroupSessionPolicies = NewPgGroupSessionPolicyStore(f.app)
		srv.Toolbox = NewPgToolboxStore(f.app, audit)
		srv.Grants = iss
		return srv
	}
	mk := func(user, tenant string, role Role) *Server {
		return f.serverFor(&Principal{UserID: user, TenantID: tenant, SessionID: "sess-" + user,
			Grant: NewGrant(user, tenant, NewMembership(role, AllGroups()))})
	}
	f.ownerSrv = mk(f.owner, f.tenant, RoleOwner)
	f.techSrv = mk(f.tech, f.tenant, RoleTechnician)
	f.alienSrv = mk(f.alien, f.other, RoleOwner)
	return f
}

type tbItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Scope      string `json:"scope"`
	Version    int64  `json:"version"`
	Body       string `json:"body"`
	BodySHA256 string `json:"body_sha256"`
	Mine       bool   `json:"mine"`
}

func tbCreate(t *testing.T, srv *Server, scope, name, shell, body string) (int, tbItem) {
	t.Helper()
	req, _ := json.Marshal(map[string]any{"name": name, "scope": scope, "shell": shell, "run_as": "system", "body": body})
	var out struct {
		Item tbItem `json:"item"`
	}
	code := apiJSON(t, srv, "POST", "/toolbox", string(req), &out)
	return code, out.Item
}

func tbList(t *testing.T, srv *Server) []tbItem {
	t.Helper()
	var out struct {
		Items []tbItem `json:"items"`
	}
	if code := apiJSON(t, srv, "GET", "/toolbox", "", &out); code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	return out.Items
}

func tbNames(items []tbItem) string {
	var n []string
	for _, it := range items {
		n = append(n, it.Name)
	}
	return strings.Join(n, ",")
}

func tbUpdate(t *testing.T, srv *Server, id string, version int64, name string, extra map[string]any) int {
	t.Helper()
	body := map[string]any{"name": name, "shell": "powershell", "run_as": "system", "body": "Get-Date", "expected_version": version}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return apiJSON(t, srv, "PUT", "/toolbox/"+id, string(b), nil)
}

func TestPgToolboxScopesAndVisibility(t *testing.T) {
	f := newToolboxFixture(t)

	if code, _ := tbCreate(t, f.techSrv, "shared", "tech shared", "cmd", "dir"); code != http.StatusForbidden {
		t.Fatalf("technician creating a shared item = %d, want 403", code)
	}
	code, shared := tbCreate(t, f.ownerSrv, "shared", "Disk usage", "powershell", "Get-PSDrive")
	if code != http.StatusCreated || shared.Scope != "shared" {
		t.Fatalf("owner creating a shared item = %d %+v", code, shared)
	}
	code, mine := tbCreate(t, f.techSrv, "personal", "My script", "cmd", "whoami")
	if code != http.StatusCreated || mine.Scope != "personal" || !mine.Mine {
		t.Fatalf("technician creating a personal item = %d %+v", code, mine)
	}
	if code, _ := tbCreate(t, f.ownerSrv, "shared", "disk USAGE", "cmd", "dir"); code != http.StatusConflict {
		t.Fatalf("duplicate shared name (case-insensitive) = %d, want 409", code)
	}
	// The owner may reuse a name another user holds personally (names are per scope).
	if code, _ := tbCreate(t, f.ownerSrv, "personal", "My script", "cmd", "hostname"); code != http.StatusCreated {
		t.Fatalf("same name in a different personal scope = %d, want 201", code)
	}

	if got := tbNames(tbList(t, f.techSrv)); got != "Disk usage,My script" {
		t.Fatalf("technician sees %q", got)
	}
	ownerSees := tbList(t, f.ownerSrv)
	for _, it := range ownerSees {
		if it.ID == mine.ID {
			t.Fatal("another user's personal item is visible to the tenant owner")
		}
	}
	if len(tbList(t, f.alienSrv)) != 0 {
		t.Fatal("another tenant sees this tenant's items")
	}

	// Another user's personal item is 404 on every route, whatever version is sent; manage_toolbox does
	// not bypass personal ownership.
	for _, v := range []int64{mine.Version, mine.Version + 7} {
		if code := tbUpdate(t, f.ownerSrv, mine.ID, v, "hijack", nil); code != http.StatusNotFound {
			t.Fatalf("owner updating the technician's personal item (version %d) = %d, want 404", v, code)
		}
		if code := apiJSON(t, f.ownerSrv, "DELETE", fmt.Sprintf("/toolbox/%s?expected_version=%d", mine.ID, v), "", nil); code != http.StatusNotFound {
			t.Fatalf("owner deleting the technician's personal item = %d, want 404", code)
		}
	}
	// A shared item is visible to the technician but not changeable without manage_toolbox.
	if code := tbUpdate(t, f.techSrv, shared.ID, shared.Version, "renamed", nil); code != http.StatusForbidden {
		t.Fatalf("technician updating a shared item = %d, want 403", code)
	}
	// Scope is immutable.
	if code := tbUpdate(t, f.ownerSrv, shared.ID, shared.Version, "x", map[string]any{"scope": "personal"}); code != http.StatusBadRequest {
		t.Fatalf("update carrying a scope = %d, want 400", code)
	}
	// Cross-tenant: the other tenant's owner cannot reach the item even by id.
	if code := tbUpdate(t, f.alienSrv, shared.ID, shared.Version, "x", nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant update = %d, want 404", code)
	}
}

func TestPgToolboxVersioningAndAudit(t *testing.T) {
	f := newToolboxFixture(t)
	_, it := tbCreate(t, f.ownerSrv, "shared", "Name", "powershell", "Get-Date")
	if it.Version != 1 || it.BodySHA256 != ToolboxBodySHA256("Get-Date") {
		t.Fatalf("created %+v", it)
	}
	// A name-only change still bumps the version (every update does).
	if code := tbUpdate(t, f.ownerSrv, it.ID, 1, "Renamed", nil); code != http.StatusOK {
		t.Fatalf("update = %d", code)
	}
	if code := tbUpdate(t, f.ownerSrv, it.ID, 1, "Stale", nil); code != http.StatusConflict {
		t.Fatalf("stale update = %d, want 409", code)
	}
	if code := apiJSON(t, f.ownerSrv, "DELETE", "/toolbox/"+it.ID+"?expected_version=1", "", nil); code != http.StatusConflict {
		t.Fatalf("stale delete = %d, want 409", code)
	}
	if code := apiJSON(t, f.ownerSrv, "DELETE", "/toolbox/"+it.ID+"?expected_version=2", "", nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", code)
	}
	rows, err := f.su.Query(context.Background(),
		`SELECT action, metadata FROM audit_event WHERE tenant_id = $1 AND action LIKE 'toolbox.%' ORDER BY seq`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var a string
		var meta []byte
		if err := rows.Scan(&a, &meta); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
		if strings.Contains(string(meta), "Get-Date") {
			t.Fatalf("%s audit metadata carries the script body: %s", a, meta)
		}
	}
	if got := strings.Join(actions, ","); got != "toolbox.item.create,toolbox.item.update,toolbox.item.delete" {
		t.Fatalf("audit actions = %q", got)
	}
}

func TestPgToolboxBodyBoundariesThroughHandlers(t *testing.T) {
	f := newToolboxFixture(t)
	cases := []struct {
		name, shell, body string
		want              int
	}{
		{"cmd 7800 three-byte BMP (23400 bytes)", "cmd", strings.Repeat("€", MaxToolboxCmdUnits), http.StatusCreated},
		{"cmd 7801 three-byte BMP", "cmd", strings.Repeat("€", MaxToolboxCmdUnits+1), http.StatusBadRequest},
		{"cmd 3900 non-BMP (7800 units)", "cmd", strings.Repeat("😀", MaxToolboxCmdUnits/2), http.StatusCreated},
		{"cmd 7801 units with non-BMP", "cmd", strings.Repeat("😀", MaxToolboxCmdUnits/2) + "a", http.StatusBadRequest},
		{"powershell 16384 bytes", "powershell", strings.Repeat("a", MaxToolboxPowerShellBytes), http.StatusCreated},
		{"powershell 16385 bytes", "powershell", strings.Repeat("a", MaxToolboxPowerShellBytes+1), http.StatusBadRequest},
		{"powershell 16384 bytes of control characters (JSON-escaped 6x)", "powershell", "x" + strings.Repeat("\x01", MaxToolboxPowerShellBytes-1), http.StatusCreated},
	}
	for i, c := range cases {
		if code, _ := tbCreate(t, f.ownerSrv, "shared", fmt.Sprintf("case %d", i), c.shell, c.body); code != c.want {
			t.Errorf("%s = %d, want %d", c.name, code, c.want)
		}
	}
}

type tbRunResp struct {
	RequestID string `json:"request_id"`
	Shell     string `json:"shell"`
	RunAs     string `json:"run_as"`
	Command   string `json:"command"`
}

func tbRun(t *testing.T, srv *Server, itemID, sessionID string, version int64) (int, tbRunResp) {
	t.Helper()
	var out tbRunResp
	code := apiJSON(t, srv, "POST", "/toolbox/"+itemID+"/runs",
		fmt.Sprintf(`{"session_id":%q,"expected_version":%d}`, sessionID, version), &out)
	return code, out
}

func TestPgToolboxRunRequest(t *testing.T) {
	f := newToolboxFixture(t)
	ctx := context.Background()
	body := "Write-Output 'hello' \"$env:COMPUTERNAME\" 😀"
	_, it := tbCreate(t, f.ownerSrv, "shared", "Hello", "powershell", body)
	_, techMine := tbCreate(t, f.techSrv, "personal", "Mine", "cmd", "whoami")

	var started struct {
		Session SessionRecord `json:"session"`
	}
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions", `{"machine_id":"tb-dev"}`, &started); code != http.StatusCreated {
		t.Fatalf("start session = %d", code)
	}
	sid := started.Session.ID

	code, run := tbRun(t, f.ownerSrv, it.ID, sid, it.Version)
	if code != http.StatusOK || run.Command != ToolboxCommand("powershell", body) || run.Shell != "powershell" || run.RunAs != "system" || run.RequestID == "" {
		t.Fatalf("run = %d %+v", code, run)
	}
	var meta []byte
	if err := f.su.QueryRow(ctx, `SELECT metadata FROM audit_event WHERE tenant_id = $1 AND action = 'toolbox.run_requested'`, f.tenant).Scan(&meta); err != nil {
		t.Fatalf("run audit row: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(meta, &m)
	if m["request_id"] != run.RequestID || m["outcome"] != "unknown" || m["body_sha256"] != ToolboxBodySHA256(body) ||
		m["session_id"] != sid || m["actor_email"] != "owner@acme.test" || m["version"] != float64(it.Version) {
		t.Fatalf("run audit metadata = %s", meta)
	}

	// Refusals.
	if code, _ := tbRun(t, f.ownerSrv, it.ID, sid, it.Version+1); code != http.StatusConflict {
		t.Fatalf("run at a stale version = %d, want 409", code)
	}
	if code, _ := tbRun(t, f.ownerSrv, techMine.ID, sid, techMine.Version); code != http.StatusNotFound {
		t.Fatalf("running another user's personal item = %d, want 404", code)
	}
	if code, _ := tbRun(t, f.techSrv, it.ID, sid, it.Version); code != http.StatusForbidden {
		t.Fatalf("running on another technician's session = %d, want 403", code)
	}
	if code, _ := tbRun(t, f.alienSrv, it.ID, sid, it.Version); code != http.StatusNotFound {
		t.Fatalf("cross-tenant run = %d, want 404", code)
	}
	// View-only group mandate.
	mustExec(t, f.su, `INSERT INTO group_session_policy (tenant_id, group_id, enforce_view_only) VALUES ($1, $2, true)`, f.tenant, f.groupID)
	if code, _ := tbRun(t, f.ownerSrv, it.ID, sid, it.Version); code != http.StatusConflict {
		t.Fatalf("run in a view-only group = %d, want 409", code)
	}
	mustExec(t, f.su, `DELETE FROM group_session_policy WHERE group_id = $1`, f.groupID)
	// Quarantined machine.
	mustExec(t, f.su, `UPDATE machine SET status = 'quarantined' WHERE device_id = 'tb-dev'`)
	if code, _ := tbRun(t, f.ownerSrv, it.ID, sid, it.Version); code != http.StatusConflict {
		t.Fatalf("run on a quarantined machine = %d, want 409", code)
	}
	mustExec(t, f.su, `UPDATE machine SET status = 'active' WHERE device_id = 'tb-dev'`)
	// The audit append fails: the run is refused and no command is handed out.
	mustExec(t, f.su, `REVOKE INSERT ON audit_event FROM rmt_app`)
	code, failed := tbRun(t, f.ownerSrv, it.ID, sid, it.Version)
	mustExec(t, f.su, `GRANT INSERT ON audit_event TO rmt_app`)
	if code != http.StatusInternalServerError || failed.Command != "" {
		t.Fatalf("run with a failing audit = %d %+v, want 500 and no command", code, failed)
	}
	// Ended session.
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions/"+sid+"/end", "", nil); code != http.StatusOK {
		t.Fatalf("end session = %d", code)
	}
	if code, _ := tbRun(t, f.ownerSrv, it.ID, sid, it.Version); code != http.StatusConflict {
		t.Fatalf("run on an ended session = %d, want 409", code)
	}
	var n int
	if err := f.su.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action = 'toolbox.run_requested'`, f.tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("run_requested rows = %d (%v), want exactly 1 (refusals record nothing)", n, err)
	}
}

func TestPgToolboxCrossTenantOwnerRefusedBySchema(t *testing.T) {
	f := newToolboxFixture(t)
	// Directly, as the superuser (bypassing the handlers): an item in `tenant` owned by a user of
	// `other` violates the composite FK.
	_, err := f.su.Exec(context.Background(), `INSERT INTO toolbox_item
		(id, tenant_id, owner_user_id, name, shell, run_as, body, body_sha256, created_by, updated_by)
		VALUES (gen_random_uuid(), $1, $2, 'x', 'cmd', 'system', 'dir', $3, $2, $2)`, f.tenant, f.alien, ToolboxBodySHA256("dir"))
	if err == nil || !strings.Contains(err.Error(), "toolbox_item_owner_same_tenant") {
		t.Fatalf("cross-tenant owner insert: %v, want the composite FK violation", err)
	}
}

// TestPgToolboxRefusesTextTheDecoderWouldChange: invalid UTF-8 and an unpaired surrogate escape are
// 400 at the HTTP layer, and nothing is stored or audited (encoding/json would have replaced them with
// U+FFFD and stored something other than what was sent).
func TestPgToolboxRefusesTextTheDecoderWouldChange(t *testing.T) {
	f := newToolboxFixture(t)
	for name, raw := range map[string]string{
		"raw invalid UTF-8":     "{\"name\":\"x\",\"scope\":\"shared\",\"shell\":\"cmd\",\"run_as\":\"system\",\"body\":\"dir \xff\"}",
		"lone surrogate escape": `{"name":"y","scope":"shared","shell":"cmd","run_as":"system","body":"dir \uD800"}`,
	} {
		if code := apiJSON(t, f.ownerSrv, "POST", "/toolbox", raw, nil); code != http.StatusBadRequest {
			t.Errorf("%s: create = %d, want 400", name, code)
		}
	}
	_, it := tbCreate(t, f.ownerSrv, "shared", "ok", "cmd", "dir")
	if code := apiJSON(t, f.ownerSrv, "PUT", "/toolbox/"+it.ID,
		fmt.Sprintf(`{"name":"ok","shell":"cmd","run_as":"system","body":"dir \uDC00","expected_version":%d}`, it.Version), nil); code != http.StatusBadRequest {
		t.Errorf("update with a lone low surrogate = %d, want 400", code)
	}
	var items, audits int
	_ = f.su.QueryRow(context.Background(), `SELECT count(*) FROM toolbox_item`).Scan(&items)
	_ = f.su.QueryRow(context.Background(), `SELECT count(*) FROM audit_event WHERE action LIKE 'toolbox.%'`).Scan(&audits)
	if items != 1 || audits != 1 {
		t.Fatalf("items=%d audits=%d, want only the one valid create", items, audits)
	}
	if got := tbList(t, f.ownerSrv); len(got) != 1 || got[0].Version != it.Version || got[0].Body != "dir" {
		t.Fatalf("the refused update changed the item: %+v", got)
	}
}

// TestPgToolboxManageOnlyRole: a custom role holding manage_toolbox ALONE manages shared items (the
// design's table), but cannot keep personal items or request runs, and still never sees anyone's
// personal items.
func TestPgToolboxManageOnlyRole(t *testing.T) {
	f := newToolboxFixture(t)
	var librarian string
	if err := f.su.QueryRow(context.Background(), "SELECT gen_random_uuid()::text").Scan(&librarian); err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, 'librarian@acme.test')`, librarian, f.tenant)
	m := Membership{Role: "librarian", Scope: AllGroups(), caps: newCapabilitySet([]Capability{CapManageToolbox})}
	p := &Principal{UserID: librarian, TenantID: f.tenant, SessionID: "sess-librarian", Grant: NewGrant(librarian, f.tenant, m)}
	lib := f.serverFor(p)

	code, shared := tbCreate(t, lib, "shared", "Shared by librarian", "cmd", "dir")
	if code != http.StatusCreated {
		t.Fatalf("manage-only role creating a shared item = %d, want 201", code)
	}
	if code := tbUpdate(t, lib, shared.ID, shared.Version, "Renamed", nil); code != http.StatusOK {
		t.Fatalf("manage-only role updating a shared item = %d, want 200", code)
	}
	if code, _ := tbCreate(t, lib, "personal", "Mine", "cmd", "dir"); code != http.StatusForbidden {
		t.Fatalf("manage-only role creating a personal item = %d, want 403", code)
	}
	_, techMine := tbCreate(t, f.techSrv, "personal", "Tech's", "cmd", "whoami")
	for _, it := range tbList(t, lib) {
		if it.ID == techMine.ID {
			t.Fatal("manage_toolbox reveals another user's personal item")
		}
	}
	if code := tbUpdate(t, lib, techMine.ID, techMine.Version, "x", nil); code != http.StatusNotFound {
		t.Fatalf("manage-only role updating another user's personal item = %d, want 404", code)
	}
	if code, _ := tbRun(t, lib, shared.ID, "00000000-0000-0000-0000-000000000001", 2); code != http.StatusForbidden {
		t.Fatalf("manage-only role requesting a run = %d, want 403", code)
	}
}

// TestPgToolboxRefusesAPITokens: an API token's principal (no interactive session; UserID is the
// token's id) is refused on every toolbox route, even holding every capability.
func TestPgToolboxRefusesAPITokens(t *testing.T) {
	f := newToolboxFixture(t)
	_, it := tbCreate(t, f.ownerSrv, "shared", "Shared", "cmd", "dir")
	tokenID := "11111111-2222-3333-4444-555555555555"
	tok := f.serverFor(&Principal{UserID: tokenID, TenantID: f.tenant,
		Grant: NewGrant(tokenID, f.tenant, NewCapabilityMembership(AllCapabilities, AllGroups()))})
	if code := apiJSON(t, tok, "GET", "/toolbox", "", nil); code != http.StatusForbidden {
		t.Errorf("token list = %d, want 403", code)
	}
	if code, _ := tbCreate(t, tok, "personal", "x", "cmd", "dir"); code != http.StatusForbidden {
		t.Errorf("token personal create = %d, want 403", code)
	}
	if code, _ := tbCreate(t, tok, "shared", "y", "cmd", "dir"); code != http.StatusForbidden {
		t.Errorf("token shared create = %d, want 403", code)
	}
	if code := tbUpdate(t, tok, it.ID, it.Version, "z", nil); code != http.StatusForbidden {
		t.Errorf("token update = %d, want 403", code)
	}
	if code, _ := tbRun(t, tok, it.ID, "00000000-0000-0000-0000-000000000001", it.Version); code != http.StatusForbidden {
		t.Errorf("token run = %d, want 403", code)
	}
}
