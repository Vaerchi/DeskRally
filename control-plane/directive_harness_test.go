package controlplane

// One scenario harness, two backends: the fleet-directive tests (directive_test.go) run the SAME scenarios
// against the in-memory stores and against real Postgres as rmt_app ("fake and pg must agree"). Every request
// goes through the real HTTP handlers; the only seams are the ones production has no HTTP route for (time
// passing, a step-up the console would do through TOTP, an administrator editing a role, a tenant suspension).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func applyFleetDirectiveMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0068_fleet_directives.sql")
	if err != nil {
		t.Fatalf("read 0068: %v", err)
	}
	execScript(t, pool, string(b))
}

// dirAuth resolves the grant from the user store on EVERY request (a role change mid-test is seen by the
// next call) and carries a REAL session id so the step-up check has a session to read.
type dirAuth struct {
	users             UserStore
	tenant, user, sid string
}

func (a dirAuth) Authenticate(r *http.Request) (*Principal, error) {
	g, err := a.users.GrantFor(r.Context(), a.tenant, a.user)
	if err != nil {
		return nil, err
	}
	return &Principal{UserID: a.user, TenantID: a.tenant, Grant: g, SessionID: a.sid}, nil
}

// tokenAuth is an API-token principal: no session, a tenant-wide capability membership.
type tokenAuth struct {
	tenant string
	caps   []Capability
}

func (a tokenAuth) Authenticate(r *http.Request) (*Principal, error) {
	id := newUUID()
	return &Principal{UserID: id, TenantID: a.tenant, Grant: NewGrant(id, a.tenant, NewCapabilityMembership(a.caps, AllGroups()))}, nil
}

type recNotifier struct {
	mu   sync.Mutex
	got  []string
	fail bool
}

func (n *recNotifier) Notify(_ context.Context, deviceID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, deviceID)
	if n.fail {
		return errors.New("signaling is down")
	}
	return nil
}

// waitFor polls (the notifier is called from a goroutine after commit) until device was notified at least n times.
func (n *recNotifier) waitFor(device string, nTimes int) bool {
	for i := 0; i < 100; i++ {
		if n.count(device) >= nTimes {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (n *recNotifier) count(device string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, d := range n.got {
		if d == device {
			c++
		}
	}
	return c
}

// dirMachine is one machine of the harness with its device key.
type dirMachine struct {
	ID, Device string
	Priv       ed25519.PrivateKey
	Pub        string
}

type dirHarness struct {
	t  *testing.T
	pg bool

	tenant, alien string
	// owner and owner2 are Owners; admin and tech lack remove_agent; ro is read-only; erin owns the alien tenant.
	owner, owner2, admin, tech, ro, erin string
	group, otherGroup                    string
	m                                    dirMachine // the primary machine, RETIRED

	users    UserStore
	machines MachineStore
	dirs     DirectiveStore
	audit    MgmtAuditStore
	sessions *SessionManager
	issuer   *DirectiveIssuer
	grants   *GrantIssuer
	notes    *recNotifier
	enroll   EnrollmentTokenStore

	// backend seams
	advance      func(d time.Duration)
	setSuspended func(bool)
	bypassGuard  func(fn func())
	setPubkey    func(machineID, pubHex string)
	addMachineFn func(group, status string) dirMachine
	failAudit    func(on bool)
	// failAuditAction refuses only the audit rows of one action ("" clears it): the way to fail a LATER append of
	// a multi-row transition, which failAudit (every append) cannot.
	failAuditAction func(action string)
	setCaps      func(uninstallPerHour, reinstallPerDay int)
	rawSQL       func(sql string, args ...any) // pg only
	su, app      *pgxpool.Pool                 // pg only

	sess    map[string]*Session
	srvs    map[string]*Server
	mu      sync.Mutex
	lastAck time.Time
	clock   func() time.Time // memory backend: the store's (skewable) clock; pg uses real time
}

func newDirKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, hex.EncodeToString(pub)
}

func forEachDirBackend(t *testing.T, fn func(t *testing.T, h *dirHarness)) {
	t.Run("memory", func(t *testing.T) { fn(t, newMemDirHarness(t)) })
	t.Run("pg", func(t *testing.T) { fn(t, newPgDirHarness(t)) })
}

const directiveTestSeed = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

func (h *dirHarness) initCommon() {
	t := h.t
	iss, err := NewDirectiveIssuerFromHex(directiveTestSeed[:64])
	if err != nil {
		t.Fatal(err)
	}
	h.issuer = iss
	g, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	h.grants = g
	h.notes = &recNotifier{}
	h.sess = map[string]*Session{}
	h.srvs = map[string]*Server{}
}

func newMemDirHarness(t *testing.T) *dirHarness {
	t.Helper()
	ctx := context.Background()
	h := &dirHarness{t: t}
	h.initCommon()
	h.tenant, h.alien = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	h.owner, h.owner2, h.admin, h.tech, h.ro, h.erin = newUUID(), newUUID(), newUUID(), newUUID(), newUUID(), newUUID()
	h.group, h.otherGroup = newUUID(), newUUID()

	users := NewInMemoryUserStore()
	add := func(id, tenant, name string, role Role) {
		users.AddUser(&AuthUser{ID: id, TenantID: tenant, Email: strings.ToLower(name) + "@test.example", DisplayName: name},
			NewGrant(id, tenant, NewMembership(role, AllGroups())))
	}
	add(h.owner, h.tenant, "Owner", RoleOwner)
	add(h.owner2, h.tenant, "Owner2", RoleOwner)
	add(h.admin, h.tenant, "Admin", RoleAdmin)
	add(h.tech, h.tenant, "Tech", RoleTechnician)
	add(h.ro, h.tenant, "RO", RoleReadOnly)
	add(h.erin, h.alien, "Erin", RoleOwner)
	h.users = users

	machines := NewInMemoryMachineStore()
	h.machines = machines
	audit := &failAuditStore{MgmtAuditStore: NewInMemoryMgmtAuditStore()}
	h.audit = audit
	dirs := NewInMemoryDirectiveStore(machines, audit)
	var skew time.Duration
	var skewMu sync.Mutex
	dirs.Now = func() time.Time { skewMu.Lock(); defer skewMu.Unlock(); return time.Now().Add(skew) }
	var suspended bool
	dirs.TenantSuspended = func(string) bool { skewMu.Lock(); defer skewMu.Unlock(); return suspended }
	h.dirs = dirs
	h.clock = dirs.Now
	h.advance = func(d time.Duration) { skewMu.Lock(); skew += d; skewMu.Unlock() }
	h.setSuspended = func(on bool) { skewMu.Lock(); suspended = on; skewMu.Unlock() }
	h.bypassGuard = func(fn func()) {
		machines.setDirectiveGuard(nil)
		defer machines.setDirectiveGuard(dirs.HasActive)
		fn()
	}
	h.setPubkey = func(machineID, pubHex string) {
		machines.mu.Lock()
		defer machines.mu.Unlock()
		for _, m := range machines.machines {
			if m.ID == machineID {
				m.Pubkey = pubHex
			}
		}
	}
	h.setCaps = func(u, r int) { dirs.UninstallHourlyCap, dirs.ReinstallDailyCap = u, r }
	h.failAudit = func(on bool) { audit.fail(on) }
	h.failAuditAction = func(action string) { audit.failOnly(action) }
	h.sessions = NewSessionManager(NewInMemorySessionStore())
	h.enroll = NewInMemoryEnrollmentTokenStore()
	h.addMachineFn = func(group, status string) dirMachine {
		priv, pub := newDirKey(t)
		m := &Machine{DeviceID: newUUID(), GroupID: group, Name: "host-" + newUUID()[:4], Pubkey: pub, Status: status}
		if err := machines.EnrollMachine(ctx, h.tenant, m); err != nil {
			t.Fatal(err)
		}
		return dirMachine{ID: m.ID, Device: m.DeviceID, Priv: priv, Pub: pub}
	}
	h.m = h.addMachineFn(h.group, MachineStatusRetired)
	return h
}

func newPgDirHarness(t *testing.T) *dirHarness {
	t.Helper()
	ctx := context.Background()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyMgmtAuditChainMigration(t, su)
	applyMachineDeviceUniqueMigration(t, su) // 0008
	applyDeviceIdentityMigration(t, su)      // 0010
	applyAttendedMigration(t, su)            // 0013 (+ later attended migrations)
	applyEnrollmentMigration(t, su)          // 0007
	applyEnrollmentTenantActiveMigration(t, su)
	applyFleetDirectiveMigration(t, su) // 0068, last: it redefines the identity function
	applyMigrationFile(t, su, "migrations/0070_directive_final_ack.sql")
	applyMigrationFile(t, su, "migrations/0073_directive_forgotten.sql") // the 'forgotten' state (docs/65 sec. 8)
	h := &dirHarness{t: t, pg: true, su: su}
	h.initCommon()
	h.tenant, h.owner = provisionUser(t, su, "acme", "owner@acme.test", "password-1234")
	h.alien, h.erin = provisionUser(t, su, "other", "erin@other.test", "password-1234")
	h.group = seedGroup(t, su, h.tenant)
	h.otherGroup = seedGroup(t, su, h.tenant)
	mustExec(t, su, `UPDATE membership SET role_id = (SELECT id FROM role WHERE key='owner' AND tenant_id IS NULL) WHERE user_id = $1`, h.owner)
	mustExec(t, su, `UPDATE membership SET role_id = (SELECT id FROM role WHERE key='owner' AND tenant_id IS NULL) WHERE user_id = $1`, h.erin)
	addUser := func(name, role string) string {
		var id string
		if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
			t.Fatal(err)
		}
		mustExec(t, su, `INSERT INTO app_user (id, tenant_id, email, display_name) VALUES ($1, $2, $3, $4)`,
			id, h.tenant, strings.ToLower(name)+"@acme.test", name)
		mustExec(t, su, `INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
		                 VALUES ($1, $2, (SELECT id FROM role WHERE key = $3 AND tenant_id IS NULL), '{}'::uuid[])`,
			h.tenant, id, role)
		return id
	}
	h.owner2, h.admin, h.tech, h.ro = addUser("Owner2", "owner"), addUser("Admin", "admin"), addUser("Tech", "technician"), addUser("RO", "readonly")

	app := newAppRolePool(t, ctx)
	h.app = app
	h.users = newPgUserStoreT(app)
	pgAudit := NewPgMgmtAuditStore(app)
	h.audit = pgAudit
	h.machines = NewPgMachineStore(app)
	pgDirs := NewPgDirectiveStore(app, pgAudit)
	h.dirs = pgDirs
	h.sessions = NewSessionManager(NewPgSessionStore(app))
	h.enroll = NewPgEnrollmentTokenStore(app)
	h.rawSQL = func(sql string, args ...any) { mustExec(t, su, sql, args...) }
	h.advance = func(d time.Duration) {
		mustExec(t, su, `UPDATE agent_directive SET
			requested_at = requested_at - $1::interval, not_before = not_before - $1::interval,
			request_expires_at = request_expires_at - $1::interval, issued_at = issued_at - $1::interval,
			expires_at = expires_at - $1::interval, delivered_at = delivered_at - $1::interval,
			acked_at = acked_at - $1::interval, updated_at = updated_at - $1::interval`, fmt.Sprintf("%d seconds", int(d.Seconds())))
	}
	h.setSuspended = func(on bool) {
		if on {
			mustExec(t, su, `UPDATE tenant SET disabled_at = now() WHERE id = $1`, h.tenant)
		} else {
			mustExec(t, su, `UPDATE tenant SET disabled_at = NULL WHERE id = $1`, h.tenant)
		}
	}
	h.bypassGuard = func(fn func()) {
		mustExec(t, su, `ALTER TABLE machine DISABLE TRIGGER machine_directive_guard`)
		defer mustExec(t, su, `ALTER TABLE machine ENABLE TRIGGER machine_directive_guard`)
		fn()
	}
	h.setPubkey = func(machineID, pubHex string) {
		raw, _ := hex.DecodeString(pubHex)
		mustExec(t, su, `UPDATE machine SET pubkey = $2 WHERE id = $1`, machineID, raw)
	}
	h.setCaps = func(u, r int) { pgDirs.UninstallHourlyCap, pgDirs.ReinstallDailyCap = u, r }
	h.failAudit = func(on bool) {
		if on {
			mustExec(t, su, `CREATE OR REPLACE FUNCTION test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit store is down'; END $$`)
			mustExec(t, su, `CREATE TRIGGER test_fail_audit BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION test_fail_audit()`)
		} else {
			mustExec(t, su, `DROP TRIGGER IF EXISTS test_fail_audit ON audit_event`)
		}
	}
	h.failAuditAction = func(action string) {
		mustExec(t, su, `DROP TRIGGER IF EXISTS test_fail_audit_action ON audit_event`)
		if action != "" {
			mustExec(t, su, `CREATE OR REPLACE FUNCTION test_fail_audit_action() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit store is down'; END $$`)
			mustExec(t, su, `CREATE TRIGGER test_fail_audit_action BEFORE INSERT ON audit_event FOR EACH ROW WHEN (NEW.action = '`+action+`') EXECUTE FUNCTION test_fail_audit_action()`)
		}
	}
	h.addMachineFn = func(group, status string) dirMachine {
		priv, pub := newDirKey(t)
		raw, _ := hex.DecodeString(pub)
		var id string
		if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
			t.Fatal(err)
		}
		dev := newUUID()
		mustExec(t, su, `INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey, status) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, h.tenant, dev, group, "host-"+dev[:4], raw, status)
		return dirMachine{ID: id, Device: dev, Priv: priv, Pub: pub}
	}
	h.m = h.addMachineFn(h.group, MachineStatusRetired)
	return h
}

// failAuditStore wraps an audit store and can be told to refuse (the pg twin is a trigger on audit_event).
type failAuditStore struct {
	MgmtAuditStore
	mu         sync.Mutex
	failing    bool
	failAction string
	yield      bool // after a successful append hand the CPU over, widening the window a racing writer can land in
}

func (s *failAuditStore) failOnly(action string) { s.mu.Lock(); s.failAction = action; s.mu.Unlock() }

// discardEvents forwards the fake's rollback hook (embedding the interface would hide it), so a fake store that
// rolls back its audit rows still can through this wrapper.
func (s *failAuditStore) discardEvents(tenantID string, hashes map[string]bool) {
	if a, ok := s.MgmtAuditStore.(interface {
		discardEvents(string, map[string]bool)
	}); ok {
		a.discardEvents(tenantID, hashes)
	}
}

// appendBatch forwards the atomic batch append, but first applies the injected failure to EVERY event: a failing
// action fails the whole batch before anything is committed (the pg twin is a trigger inside one transaction).
func (s *failAuditStore) appendBatch(ctx context.Context, tenantID string, events []*MgmtAuditEvent) error {
	s.mu.Lock()
	f := s.failing
	for _, e := range events {
		if s.failAction != "" && e.Action == s.failAction {
			f = true
		}
	}
	s.mu.Unlock()
	if f {
		return errors.New("audit store is down")
	}
	if a, ok := s.MgmtAuditStore.(interface {
		appendBatch(context.Context, string, []*MgmtAuditEvent) error
	}); ok {
		return a.appendBatch(ctx, tenantID, events)
	}
	for _, e := range events {
		if err := s.MgmtAuditStore.RecordEvent(ctx, tenantID, e); err != nil {
			return err
		}
	}
	return nil
}

func (s *failAuditStore) fail(on bool) { s.mu.Lock(); s.failing = on; s.mu.Unlock() }

func (s *failAuditStore) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	s.mu.Lock()
	f := s.failing || (s.failAction != "" && e.Action == s.failAction)
	s.mu.Unlock()
	if f {
		return errors.New("audit store is down")
	}
	err := s.MgmtAuditStore.RecordEvent(ctx, tenantID, e)
	if s.yield {
		runtime.Gosched()
	}
	return err
}

func (h *dirHarness) sessionFor(user string) *Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sess[user]; ok {
		return s
	}
	tenant := h.tenant
	if user == h.erin {
		tenant = h.alien
	}
	_, s, err := h.sessions.Issue(context.Background(), tenant, user, time.Time{})
	if err != nil {
		h.t.Fatalf("issue session: %v", err)
	}
	h.sess[user] = s
	return s
}

func (h *dirHarness) newServer(auth Authenticator) *Server {
	var binder TenantBinder = NoopBinder{}
	if h.pg {
		binder = NewPgBinder(h.app)
	}
	srv := NewServer(auth, binder)
	srv.Machines, srv.MgmtAudit, srv.Directives = h.machines, h.audit, h.dirs
	srv.DirectiveIssuer, srv.DirectiveNotifier, srv.Grants = h.issuer, h.notes, h.grants
	srv.AuthAPI = &AuthService{Users: h.users, Sessions: h.sessions}
	srv.EnrollmentTokens = h.enroll
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.DisableThrottle = true
	return srv
}

func (h *dirHarness) srv(user string) *Server {
	h.mu.Lock()
	if s, ok := h.srvs[user]; ok {
		h.mu.Unlock()
		return s
	}
	h.mu.Unlock()
	tenant := h.tenant
	if user == h.erin {
		tenant = h.alien
	}
	s := h.newServer(dirAuth{users: h.users, tenant: tenant, user: user, sid: h.sessionFor(user).ID})
	h.mu.Lock()
	h.srvs[user] = s
	h.mu.Unlock()
	return s
}

func (h *dirHarness) do(user, method, path, body string) (int, map[string]any) {
	h.t.Helper()
	return h.doOn(h.srv(user), method, path, body, "")
}

func (h *dirHarness) doOn(srv *Server, method, path, body, bearer string) (int, map[string]any) {
	h.t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

// internal performs a signaling-style call with the service token.
func (h *dirHarness) internal(method, path, body string) (int, map[string]any) {
	h.t.Helper()
	return h.doOn(h.srv(h.owner), method, path, body, deviceIdentityToken)
}

func (h *dirHarness) stepUp(user string) {
	h.t.Helper()
	ctx := context.Background()
	s := h.sessionFor(user)
	gen := int64(1)
	if h.pg {
		mustExec(h.t, h.su, `UPDATE app_user SET mfa_generation = nextval('mfa_generation_seq') WHERE id = $1`, user)
		if err := h.su.QueryRow(ctx, `SELECT mfa_generation FROM app_user WHERE id = $1`, user).Scan(&gen); err != nil {
			h.t.Fatal(err)
		}
	}
	if !h.pg {
		// The fake session store cannot see the user store: keep the user's generation in step with the one
		// the session is marked against, as the pg branch above does.
		us := h.users.(*InMemoryUserStore)
		us.mu.Lock()
		u := us.users[userKey(s.TenantID, user)]
		us.bumpMFAGeneration(u)
		gen = u.MFAGeneration
		us.mu.Unlock()
	}
	ok, err := h.sessions.Store.MarkMFAVerified(ctx, s.TenantID, user, s.ID, gen)
	if err != nil || !ok {
		h.t.Fatalf("mark step-up: %v %v", ok, err)
	}
}

func (h *dirHarness) ageStepUp(user string, d time.Duration) {
	h.t.Helper()
	s := h.sessionFor(user)
	if h.pg {
		mustExec(h.t, h.su, `UPDATE user_session SET mfa_verified_at = mfa_verified_at - $2::interval WHERE id = $1`, s.ID, fmt.Sprintf("%d seconds", int(d.Seconds())))
		return
	}
	st := h.sessions.Store.(*InMemorySessionStore)
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, x := range st.byHash {
		if x.ID == s.ID && x.MFAVerifiedAt != nil {
			at := x.MFAVerifiedAt.Add(-d)
			x.MFAVerifiedAt = &at
		}
	}
}

func (h *dirHarness) setRole(user string, role Role) {
	h.t.Helper()
	if err := h.users.SetUserRole(context.Background(), h.tenant, user, role, nil); err != nil {
		h.t.Fatal(err)
	}
}

func (h *dirHarness) machine(id string) *Machine {
	h.t.Helper()
	m, err := h.machines.GetMachineByID(context.Background(), h.tenant, id)
	if err != nil {
		h.t.Fatal(err)
	}
	return m
}

func (h *dirHarness) row(id string) *AgentDirective {
	h.t.Helper()
	d, err := h.dirs.Get(context.Background(), h.tenant, id)
	if err != nil {
		h.t.Fatalf("get directive %s: %v", id, err)
	}
	return d
}

func (h *dirHarness) auditActions() []string {
	h.t.Helper()
	ev, err := h.audit.ListEvents(context.Background(), h.tenant, 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for i := len(ev) - 1; i >= 0; i-- {
		out = append(out, ev[i].Action)
	}
	return out
}

func (h *dirHarness) auditCount(action string) int {
	n := 0
	for _, a := range h.auditActions() {
		if a == action {
			n++
		}
	}
	return n
}

func (h *dirHarness) body(kind string, m dirMachine) string {
	name := h.machine(m.ID).Name
	raw, _ := json.Marshal(map[string]string{"kind": kind, "confirm": name})
	return string(raw)
}

// request posts a directive request as user and returns status + body.
func (h *dirHarness) request(user, kind string, m dirMachine) (int, map[string]any) {
	h.t.Helper()
	return h.do(user, "POST", "/machines/"+m.ID+"/directives", h.body(kind, m))
}

func dirIDOf(out map[string]any) string {
	d, _ := out["directive"].(map[string]any)
	id, _ := d["id"].(string)
	return id
}

func dirStateOf(out map[string]any) string {
	d, _ := out["directive"].(map[string]any)
	s, _ := d["state"].(string)
	return s
}

// mustRequestUninstall: fresh step-up, then request; returns the directive id.
func (h *dirHarness) mustRequestUninstall(user string, m dirMachine) string {
	h.t.Helper()
	h.stepUp(user)
	code, out := h.request(user, "uninstall", m)
	if code != http.StatusCreated {
		h.t.Fatalf("request uninstall as %s = %d %v", user, code, out)
	}
	return dirIDOf(out)
}

func (h *dirHarness) sweep() {
	h.t.Helper()
	if _, err := h.srv(h.owner).SweepDirectivesOnce(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

// issueNow lets the cancel window pass and runs the sweeper (what the background loop does).
func (h *dirHarness) issueNow(id string) *AgentDirective {
	h.t.Helper()
	h.advance(directiveCancelWindow + time.Minute)
	h.sweep()
	return h.row(id)
}

// ackJSON builds the internal-route body for an acknowledgement signed by priv for the stored row.
func (h *dirHarness) ackJSON(id string, m dirMachine, priv ed25519.PrivateKey, from, to, detail string, ts time.Time) string {
	h.t.Helper()
	d := h.row(id)
	a, err := SignDirectiveAck(priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, from, to, ts.UnixMilli(), detail)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"device_id": m.Device, "from": from, "to": to, "ts_ms": a.TsMs, "detail": detail, "sig": a.Sig})
	return string(raw)
}

func (h *dirHarness) ack(id string, m dirMachine, from, to string) (int, map[string]any) {
	h.t.Helper()
	return h.internal("POST", "/internal/directives/"+id+"/ack", h.ackJSON(id, m, m.Priv, from, to, "", h.nextAckTime()))
}

// nextAckTime is a strictly increasing "agent clock" (the store requires strictly increasing ts_ms per
// directive; two acks inside one millisecond would otherwise collide).
func (h *dirHarness) nextAckTime() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := time.Now()
	if h.clock != nil {
		t = h.clock()
	}
	if t.Before(h.lastAck.Add(2 * time.Millisecond)) { // ts_ms is truncated: keep whole milliseconds apart
		t = h.lastAck.Add(2 * time.Millisecond)
	}
	h.lastAck = t
	return t
}

// drive walks an ISSUED directive through the given states with valid acks.
func (h *dirHarness) drive(id string, m dirMachine, states ...string) {
	h.t.Helper()
	from := string(h.row(id).State)
	for _, to := range states {
		if code, out := h.ack(id, m, from, to); code != http.StatusOK {
			h.t.Fatalf("ack %s->%s = %d %v", from, to, code, out)
		}
		from = to
	}
}

func (h *dirHarness) identity(device string, restricted bool) (int, map[string]any) {
	q := ""
	if restricted {
		q = "?restricted=1"
	}
	return h.internal("GET", "/internal/devices/"+device+"/identity"+q, "")
}

func (h *dirHarness) pending(device string) []map[string]any {
	h.t.Helper()
	code, out := h.internal("GET", "/internal/devices/"+device+"/directives/pending", "")
	if code != http.StatusOK {
		h.t.Fatalf("pending = %d %v", code, out)
	}
	list, _ := out["directives"].([]any)
	var res []map[string]any
	for _, x := range list {
		res = append(res, x.(map[string]any))
	}
	return res
}
