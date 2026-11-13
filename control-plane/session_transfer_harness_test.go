package controlplane

// One scenario harness, two backends: the session-transfer tests (session_transfer_test.go) run the SAME
// scenarios against the in-memory stores and against real Postgres as rmt_app, which is how this repo
// keeps "fake and pg must agree" honest. Every request goes through the real HTTP handlers; the only
// seams are the ones production has no HTTP route for (time passing, the ticket redemption signaling
// records, an administrator editing a role).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	transferTestDevice   = "22222222-2222-4222-8222-222222222222"
	transferTestAgentOK  = "0.1.6+test"
	transferTestAgentOld = "0.1.5+test"
)

// liveGrantAuth is an Authenticator that, like SessionAuthenticator, resolves the Grant from the user
// store on EVERY request, so a role change made mid-test is seen by the next call.
type liveGrantAuth struct {
	users  UserStore
	tenant string
	user   string
}

func (a liveGrantAuth) Authenticate(r *http.Request) (*Principal, error) {
	g, err := a.users.GrantFor(r.Context(), a.tenant, a.user)
	if err != nil {
		return nil, err
	}
	return &Principal{UserID: a.user, TenantID: a.tenant, Grant: g, SessionID: "sess-" + a.user}, nil
}

// memGuestEnds is the in-memory GuestEndStore, returning PgGuestEndStore's outcomes.
type memGuestEnds struct{ records *InMemorySessionRecordStore }

func (f memGuestEnds) EndSessionForDevice(ctx context.Context, tenantID, sessionID, deviceID string, at time.Time, _ SessionEndReport) (GuestEndOutcome, error) {
	rec, err := f.records.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return GuestEndNotFound, nil
	}
	if !strings.EqualFold(rec.MachineDeviceID, deviceID) {
		return GuestEndOtherDevice, nil
	}
	if rec.EndedAt != nil {
		return GuestEndAlreadyEnded, nil
	}
	if _, err := f.records.EndSession(ctx, tenantID, sessionID, at); err != nil {
		return GuestEndNotFound, nil
	}
	return GuestEndEnded, nil
}

type transferHarness struct {
	t  *testing.T
	pg bool

	tenant, alienTenant string
	// alice holds sessions; bob is a technician scoped to `group`; carol a tenant-wide technician;
	// dave read-only (no start_session); frank an Admin; erin owns the other tenant.
	alice, bob, carol, dave, frank, erin string
	group, otherGroup                    string
	machine                              string // machine PK

	// build returns a server authenticated as user (in `tenant`, or the alien tenant for erin).
	build func(user string) *Server
	users UserStore

	// backend seams
	redeem    func(sessionID string)
	advance   func(d time.Duration)
	setCap    func(n int)
	records   SessionRecordStore
	transfers SessionTransferStore
	audit     MgmtAuditStore
	rawSQL    func(sql string, args ...any) // pg only
	su, app   *pgxpool.Pool                 // pg only: the superuser pool and the rmt_app pool
	machines  MachineStore
	help      HelpRequestStore // docs/64 help requests (http_help_request_test.go)
	// presence control (http_help_request_test.go): mode "" = every known device online, "empty" = nobody,
	// "error" = unreachable.
	presenceMode atomic.Value
	extraMu      sync.Mutex
	extraDevices []string

	srvs map[string]*Server
	mu   sync.Mutex
}

func (h *transferHarness) srv(user string) *Server {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.srvs[user]; ok {
		return s
	}
	s := h.build(user)
	h.srvs[user] = s
	return s
}

// do performs one request as user and returns status plus the decoded JSON object (nil if not an object).
func (h *transferHarness) do(user, method, path, body string) (int, map[string]any) {
	h.t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	h.srv(user).Handler().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

// start opens an unattended control session as user through POST /sessions and returns its id.
func (h *transferHarness) start(user string) string {
	h.t.Helper()
	code, out := h.do(user, "POST", "/sessions", `{"machine_id":"`+transferTestDevice+`"}`)
	if code != http.StatusCreated {
		h.t.Fatalf("start session as %s = %d %v", user, code, out)
	}
	return out["session"].(map[string]any)["id"].(string)
}

// startVouched opens a session and records the signaling redemption that vouches for it.
func (h *transferHarness) startVouched(user string) string {
	h.t.Helper()
	id := h.start(user)
	h.redeem(id)
	return id
}

// offer makes an offer on session as user (to = "" escalates to the group); it returns status + body.
func (h *transferHarness) offer(user, session, to, note string) (int, map[string]any) {
	body := map[string]string{"note": note}
	if to != "" {
		body["to_user_id"] = to
	}
	raw, _ := json.Marshal(body)
	return h.do(user, "POST", "/sessions/"+session+"/transfer", string(raw))
}

func (h *transferHarness) mustOffer(user, session, to string) string {
	h.t.Helper()
	code, out := h.offer(user, session, to, "")
	if code != http.StatusCreated {
		h.t.Fatalf("offer as %s = %d %v", user, code, out)
	}
	return out["transfer"].(map[string]any)["id"].(string)
}

func (h *transferHarness) accept(user, id string) (int, map[string]any) {
	return h.do(user, "POST", "/session-transfers/"+id+"/accept", "")
}

func (h *transferHarness) get(user, id string) (int, map[string]any) {
	return h.do(user, "GET", "/session-transfers/"+id, "")
}

// state is the offer's current state, read straight from the store (no reconcile).
func (h *transferHarness) transfer(id string) *SessionTransfer {
	h.t.Helper()
	tr, err := h.transfers.Get(context.Background(), h.tenant, id)
	if err != nil {
		h.t.Fatalf("get transfer %s: %v", id, err)
	}
	return tr
}

func (h *transferHarness) session(id string) *SessionRecord {
	h.t.Helper()
	rec, err := h.records.GetSession(context.Background(), h.tenant, id)
	if err != nil {
		h.t.Fatalf("get session %s: %v", id, err)
	}
	return rec
}

func (h *transferHarness) openSessions() []SessionRecord {
	h.t.Helper()
	all, err := h.records.ListSessions(context.Background(), h.tenant, SessionSummaryFilter{})
	if err != nil {
		h.t.Fatal(err)
	}
	var open []SessionRecord
	for _, r := range all {
		if r.EndedAt == nil {
			open = append(open, r)
		}
	}
	return open
}

// agentEnd delivers the agent's docs/49 end report for a session through the real internal route.
func (h *transferHarness) agentEnd(session string) int {
	h.t.Helper()
	body := `{"device_id":"` + transferTestDevice + `","tenant_id":"` + h.tenant + `","reason":"viewer_left"}`
	req := httptest.NewRequest("POST", "/internal/sessions/"+session+"/ended", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
	rec := httptest.NewRecorder()
	h.srv(h.alice).Handler().ServeHTTP(rec, req)
	return rec.Code
}

// auditActions lists the actions of the tenant's management-audit events, oldest first.
func (h *transferHarness) auditEvents() []MgmtAuditEvent {
	h.t.Helper()
	ev, err := h.audit.ListEvents(context.Background(), h.tenant, 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	for i, j := 0, len(ev)-1; i < j; i, j = i+1, j-1 {
		ev[i], ev[j] = ev[j], ev[i]
	}
	return ev
}

func (h *transferHarness) auditCount(action string) int {
	n := 0
	for _, e := range h.auditEvents() {
		if e.Action == action {
			n++
		}
	}
	return n
}

func (h *transferHarness) auditFor(action, targetID string) []MgmtAuditEvent {
	var out []MgmtAuditEvent
	for _, e := range h.auditEvents() {
		if e.Action == action && (targetID == "" || e.TargetID == targetID) {
			out = append(out, e)
		}
	}
	return out
}

func (h *transferHarness) setRole(user string, role Role) {
	h.t.Helper()
	if err := h.users.SetUserRole(context.Background(), h.tenant, user, role, nil); err != nil {
		h.t.Fatal(err)
	}
}

func (h *transferHarness) setAgent(version string) {
	h.t.Helper()
	if _, err := h.machines.RecordAgentVersion(context.Background(), h.tenant, map[string]string{transferTestDevice: version}); err != nil {
		h.t.Fatal(err)
	}
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func transferOf(out map[string]any) map[string]any {
	tr, _ := out["transfer"].(map[string]any)
	return tr
}

// forEachBackend runs fn once against the in-memory stores and once against Postgres (skipped, loudly,
// without TEST_DATABASE_URL — the verification gate treats a skip as a failure).
func forEachBackend(t *testing.T, fn func(t *testing.T, h *transferHarness)) {
	t.Run("memory", func(t *testing.T) { fn(t, newMemTransferHarness(t)) })
	t.Run("pg", func(t *testing.T) { fn(t, newPgTransferHarness(t)) })
}

func newMemTransferHarness(t *testing.T) *transferHarness {
	t.Helper()
	ctx := context.Background()
	h := &transferHarness{t: t, srvs: map[string]*Server{}}
	h.tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	h.alienTenant = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	h.alice, h.bob, h.carol, h.dave, h.frank, h.erin = newUUID(), newUUID(), newUUID(), newUUID(), newUUID(), newUUID()
	h.group, h.otherGroup = newUUID(), newUUID()

	users := NewInMemoryUserStore()
	add := func(id, tenant, name string, role Role, scope GroupScope) {
		users.AddUser(&AuthUser{ID: id, TenantID: tenant, Email: strings.ToLower(name) + "@test.example", DisplayName: name},
			NewGrant(id, tenant, NewMembership(role, scope)))
	}
	add(h.alice, h.tenant, "Alice", RoleTechnician, AllGroups())
	add(h.bob, h.tenant, "Bob", RoleTechnician, Groups(h.group))
	add(h.carol, h.tenant, "Carol", RoleTechnician, AllGroups())
	add(h.dave, h.tenant, "Dave", RoleReadOnly, AllGroups())
	add(h.frank, h.tenant, "Frank", RoleAdmin, AllGroups())
	add(h.erin, h.alienTenant, "Erin", RoleOwner, AllGroups())
	h.users = users

	machines := NewInMemoryMachineStore()
	m := &Machine{DeviceID: transferTestDevice, GroupID: h.group, Name: "host-1", Pubkey: testPubkeyHex(t), AgentVersion: transferTestAgentOK}
	if err := machines.EnrollMachine(ctx, h.tenant, m); err != nil {
		t.Fatal(err)
	}
	h.machine = m.ID
	h.machines = machines

	records := NewInMemorySessionRecordStore()
	audit := NewInMemoryMgmtAuditStore()
	var skew time.Duration
	var skewMu sync.Mutex
	transfers := NewInMemorySessionTransferStore(records, audit)
	transfers.Now = func() time.Time { skewMu.Lock(); defer skewMu.Unlock(); return time.Now().Add(skew) }
	redemptions := NewInMemoryTicketRedemptionStore()
	tenantPolicies := NewInMemoryTenantSessionPolicyStore()
	groupPolicies := NewInMemoryGroupSessionPolicyStore()
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	h.records, h.transfers, h.audit = records, transfers, audit
	h.help = NewInMemoryHelpRequestStore(machines, records, audit)
	h.redeem = func(id string) {
		if _, err := redemptions.RedeemTicket(ctx, h.tenant, id, transferTestDevice, time.Now().Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	h.advance = func(d time.Duration) { skewMu.Lock(); skew += d; skewMu.Unlock() }
	h.setCap = func(n int) {
		if err := tenantPolicies.Set(ctx, h.tenant, SessionPolicy{MaxConcurrentSessions: n}); err != nil {
			t.Fatal(err)
		}
	}
	h.build = func(user string) *Server {
		tenant := h.tenant
		if user == h.erin {
			tenant = h.alienTenant
		}
		srv := NewServer(liveGrantAuth{users: users, tenant: tenant, user: user}, NoopBinder{})
		srv.Machines, srv.SessionRecords, srv.SessionTransfers, srv.MgmtAudit = machines, records, transfers, audit
		srv.TicketRedemptions, srv.SessionPolicies, srv.GroupSessionPolicies = redemptions, tenantPolicies, groupPolicies
		srv.Grants, srv.SignalingURL = iss, "ws://signal.example/ws"
		srv.AuthAPI = &AuthService{Users: users}
		srv.GuestEnds = memGuestEnds{records}
		srv.HelpRequests = h.help
		srv.Presence = harnessPresence{h}
		srv.DeviceIdentityToken = deviceIdentityToken
		srv.DisableThrottle = true
		return srv
	}
	return h
}

func newPgTransferHarness(t *testing.T) *transferHarness {
	t.Helper()
	ctx := context.Background()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyMgmtAuditChainMigration(t, su)
	applyMachineDeviceUniqueMigration(t, su) // 0008
	applyDeviceIdentityMigration(t, su)      // 0010
	applyAttendedMigration(t, su)
	applyTicketRedemptionMigration(t, su)
	applyTenantSessionPolicyMigration(t, su)
	applyMigrationFile(t, su, "migrations/0069_help_request.sql")
	h := &transferHarness{t: t, pg: true, srvs: map[string]*Server{}}
	h.tenant, h.alice = provisionUser(t, su, "acme", "alice@acme.test", "password-1234")
	h.alienTenant, h.erin = provisionUser(t, su, "other", "erin@other.test", "password-1234")
	h.group, h.machine = seedGroupMachine(t, su, h.tenant, transferTestDevice)
	h.otherGroup = seedGroup(t, su, h.tenant)
	mustExec(t, su, `UPDATE app_user SET display_name = 'Alice' WHERE id = $1`, h.alice)
	mustExec(t, su, `UPDATE app_user SET display_name = 'Erin' WHERE id = $1`, h.erin)
	mustExec(t, su, `UPDATE machine SET agent_version = $2, require_session_policy = false WHERE id = $1`, h.machine, transferTestAgentOK)
	addUser := func(name string, role string, scoped ...string) string {
		var id string
		if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
			t.Fatal(err)
		}
		mustExec(t, su, `INSERT INTO app_user (id, tenant_id, email, display_name) VALUES ($1, $2, $3, $4)`,
			id, h.tenant, strings.ToLower(name)+"@acme.test", name)
		if scoped == nil {
			scoped = []string{}
		}
		mustExec(t, su, `INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
		                 VALUES ($1, $2, (SELECT id FROM role WHERE key = $3 AND tenant_id IS NULL), $4::uuid[])`,
			h.tenant, id, role, scoped)
		return id
	}
	h.bob = addUser("Bob", "technician", h.group)
	h.carol = addUser("Carol", "technician")
	h.dave = addUser("Dave", "readonly")
	h.frank = addUser("Frank", "admin")

	app := newAppRolePool(t, ctx)
	h.su, h.app = su, app
	users := newPgUserStoreT(app)
	h.users = users
	audit := NewPgMgmtAuditStore(app)
	records := NewPgSessionRecordStore(app)
	transfers := NewPgSessionTransferStore(app, audit)
	redemptions := NewPgTicketRedemptionStore(app)
	machines := NewPgMachineStore(app)
	tenantPolicies := NewPgTenantSessionPolicyStore(app)
	groupPolicies := NewPgGroupSessionPolicyStore(app)
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	h.records, h.transfers, h.audit, h.machines = records, transfers, audit, machines
	h.help = NewPgHelpRequestStore(app, audit)
	h.rawSQL = func(sql string, args ...any) { mustExec(t, su, sql, args...) }
	h.redeem = func(id string) {
		if _, err := redemptions.RedeemTicket(ctx, h.tenant, id, transferTestDevice, time.Now().Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// Time passing: every stamp the rules compare against moves into the past.
	h.advance = func(d time.Duration) {
		mustExec(t, su, `UPDATE session_transfer SET created_at = created_at - $1::interval,
			expires_at = expires_at - $1::interval, releasing_at = releasing_at - $1::interval`,
			fmt.Sprintf("%d seconds", int(d.Seconds())))
		// The agent's report stamp ages with them: the release deadline compares it to releasing_at.
		mustExec(t, su, `UPDATE session_record SET agent_ended_at = agent_ended_at - $1::interval WHERE agent_ended_at IS NOT NULL`,
			fmt.Sprintf("%d seconds", int(d.Seconds())))
	}
	h.setCap = func(n int) {
		if err := tenantPolicies.Set(ctx, h.tenant, SessionPolicy{MaxConcurrentSessions: n}); err != nil {
			t.Fatal(err)
		}
	}
	h.build = func(user string) *Server {
		tenant := h.tenant
		if user == h.erin {
			tenant = h.alienTenant
		}
		srv := NewServer(liveGrantAuth{users: users, tenant: tenant, user: user}, NewPgBinder(app))
		srv.Machines, srv.SessionRecords, srv.SessionTransfers, srv.MgmtAudit = machines, records, transfers, audit
		srv.TicketRedemptions, srv.SessionPolicies, srv.GroupSessionPolicies = redemptions, tenantPolicies, groupPolicies
		srv.Grants, srv.SignalingURL = iss, "ws://signal.example/ws"
		srv.AuthAPI = &AuthService{Users: users}
		srv.GuestEnds = NewPgGuestEndStore(app, audit)
		srv.HelpRequests = h.help
		srv.Presence = harnessPresence{h}
		srv.DeviceIdentityToken = deviceIdentityToken
		srv.DisableThrottle = true
		return srv
	}
	return h
}

func (h *transferHarness) mustAccept(user, id string) {
	h.t.Helper()
	if code, out := h.accept(user, id); code != http.StatusOK {
		h.t.Fatalf("accept as %s = %d %v", user, code, out)
	}
}
