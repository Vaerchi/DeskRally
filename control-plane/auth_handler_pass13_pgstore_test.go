package controlplane

// Pass 13: PG-backed real authenticated handler matrix.
//
// Extends pass-12's six in-memory scenarios onto a freshly migrated disposable
// PostgreSQL database with:
//   - non-superuser / non-BYPASSRLS rmt_app role (FORCE RLS enforced)
//   - PgBinder for per-request tenant isolation
//   - PgUserStore + PgSessionStore + PgSessionRecordStore + PgMachineStore +
//     PgMgmtAuditStore — all backed by appPool, subject to RLS
//   - real SessionAuthenticator (no StubAuthenticator)
//   - real argon2id password verify at login, real CSRF double-submit
//
// Plus four boundary assertions added by codex-auth-handler-review.md §Next gate:
//   7. Logout with open session → subsequent renewal 401 (auth revoked)
//   8. Missing / wrong CSRF on mutation → 403, zero audit mutation
//   9. Cross-user renewal refused (Alice cannot renew Bob's session) → 403
//  10. Signed renewal claims verified (technician_id, session_id, machine_id, access)
//
// Run (disposable PG required — do NOT point at production):
//
//	TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5490/rmt_test?sslmode=disable \
//	  go test ./control-plane -run TestPass13_Pg_ -v -count=1
//
// The test skips silently when TEST_DATABASE_URL is unset, so it never blocks CI.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ─── constants ────────────────────────────────────────────────────────────────

const (
	p13TenantAlpha = "pg13-alpha"
	p13TenantBeta  = "pg13-beta"

	p13AliceEmail = "alice@pg13-alpha.test"
	p13BobEmail   = "bob@pg13-alpha.test"
	p13AdminEmail = "admin@pg13-alpha.test"
	p13CarolEmail = "carol@pg13-beta.test"

	p13AlicePw = "alice-pg13-correct-horse-battery-staple"
	p13BobPw   = "bob-pg13-correct-horse-battery-staple"
	p13AdminPw = "admin-pg13-correct-horse-battery-staple"
	p13CarolPw = "carol-pg13-correct-horse-battery-staple"
)

// ─── FORCE RLS assertion ──────────────────────────────────────────────────────

// p13AssertForceRLS confirms that the key tenant-scoped tables carry
// FORCE ROW LEVEL SECURITY — the flag that subjects even the TABLE OWNER to
// RLS. Without it, connecting as the migration/owner role would bypass all
// tenant policies silently. This is distinct from the role-attribute check
// (AssertLeastPrivilegeRole): that proves the APP role is unprivileged; this
// proves the TABLE is configured to enforce even when it is the owner.
func p13AssertForceRLS(t *testing.T, suPool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	tables := []string{
		"app_user", "user_session", "machine",
		"session_record", "audit_event", "membership",
	}
	for _, table := range tables {
		var forced bool
		if err := suPool.QueryRow(ctx,
			`SELECT relforcerowsecurity FROM pg_class WHERE relname = $1 AND relkind = 'r'`,
			table).Scan(&forced); err != nil {
			t.Fatalf("FORCE RLS probe on %q: %v", table, err)
		}
		if !forced {
			t.Errorf("table %q lacks FORCE ROW LEVEL SECURITY — RLS bypassed for table owner", table)
		}
	}
}

// ─── provisioners ─────────────────────────────────────────────────────────────

// p13ProvisionAlpha creates tenant-alpha with four users (Alice, Bob, Admin
// scoped-technicians + all-groups admin) and two machines inside one
// withTenant transaction on suPool.
//
// Alice and Bob get technician memberships scoped to group-east only. Admin
// gets an admin membership with AllGroups (empty scoped_group_ids = '{}'). The
// group IDs used as scoped_group_ids ARE the actual machine_group.id UUIDs, so
// GrantFor returns a properly scoped grant over the REAL rows.
//
// Returns: alphaTid, aliceUID, bobUID, adminUID, eastGID, westGID,
//
//	m1DevID (east machine device id), m2DevID (west machine device id)
func p13ProvisionAlpha(t *testing.T, suPool *pgxpool.Pool) (
	alphaTid, aliceUID, bobUID, adminUID, eastGID, westGID, m1DevID, m2DevID string,
) {
	t.Helper()
	ctx := context.Background()

	// Generate all UUIDs from the DB's gen_random_uuid() so they are canonical
	// and guaranteed unique within this run. Using the DB generator also validates
	// the pool is live before any provisioning starts.
	uuids := make([]string, 8)
	rows, err := suPool.Query(ctx, `SELECT gen_random_uuid()::text FROM generate_series(1,8)`)
	if err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	for i := 0; rows.Next(); i++ {
		if err := rows.Scan(&uuids[i]); err != nil {
			t.Fatalf("scan uuid %d: %v", i, err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("uuid rows: %v", err)
	}
	alphaTid, aliceUID, bobUID, adminUID, eastGID, westGID = uuids[0], uuids[1], uuids[2], uuids[3], uuids[4], uuids[5]

	// Device IDs for machines: must be real UUIDs so MintSessionPolicy's
	// canonical preimage (which calls uuidBytes) does not fail.
	m1DevID = newUUID()
	m2DevID = newUUID()
	m1MachineID := uuids[6]
	m2MachineID := uuids[7]

	aliceHash, err := HashPassword(p13AlicePw)
	if err != nil {
		t.Fatalf("hash alice: %v", err)
	}
	bobHash, err := HashPassword(p13BobPw)
	if err != nil {
		t.Fatalf("hash bob: %v", err)
	}
	adminHash, err := HashPassword(p13AdminPw)
	if err != nil {
		t.Fatalf("hash admin: %v", err)
	}

	// One withTenant block: tenant → groups → users → memberships → machines.
	if err := withTenant(ctx, suPool, alphaTid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,$2,$2,'self_hosted')`,
			alphaTid, p13TenantAlpha); err != nil {
			return err
		}
		// Groups must exist before memberships that reference them.
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'East')`,
			eastGID, alphaTid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'West')`,
			westGID, alphaTid); err != nil {
			return err
		}
		// Users + credentials.
		for _, row := range []struct{ id, email, hash string }{
			{aliceUID, p13AliceEmail, aliceHash},
			{bobUID, p13BobEmail, bobHash},
			{adminUID, p13AdminEmail, adminHash},
		} {
			if _, err := tx.Exec(ctx,
				`INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
				row.id, alphaTid, row.email); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_credential (user_id, tenant_id, password_hash) VALUES ($1,$2,$3)`,
				row.id, alphaTid, row.hash); err != nil {
				return err
			}
		}
		// Resolve global role IDs once per block.
		var techRoleID, adminRoleID string
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key='technician' AND tenant_id IS NULL`).Scan(&techRoleID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key='admin' AND tenant_id IS NULL`).Scan(&adminRoleID); err != nil {
			return err
		}
		// Alice: technician scoped to east group only.
		if _, err := tx.Exec(ctx,
			`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids) VALUES ($1,$2,$3,ARRAY[$4::uuid])`,
			alphaTid, aliceUID, techRoleID, eastGID); err != nil {
			return err
		}
		// Bob: same scope as Alice.
		if _, err := tx.Exec(ctx,
			`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids) VALUES ($1,$2,$3,ARRAY[$4::uuid])`,
			alphaTid, bobUID, techRoleID, eastGID); err != nil {
			return err
		}
		// Admin: admin role, all groups (empty scoped_group_ids).
		if _, err := tx.Exec(ctx,
			`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids) VALUES ($1,$2,$3,'{}')`,
			alphaTid, adminUID, adminRoleID); err != nil {
			return err
		}
		// Machines. pubkey is a placeholder byte; the store only reads it for
		// the signaling identity path (not exercised in this pass).
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey)
			 VALUES ($1,$2,$3,$4,'m1-alpha-east',$5)`,
			m1MachineID, alphaTid, m1DevID, eastGID, []byte{0}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey)
			 VALUES ($1,$2,$3,$4,'m2-alpha-west',$5)`,
			m2MachineID, alphaTid, m2DevID, westGID, []byte{0}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("provision alpha: %v", err)
	}

	return
}

// p13ProvisionBeta creates tenant-beta with Carol and one machine.
// Carol is a technician scoped to west group.
func p13ProvisionBeta(t *testing.T, suPool *pgxpool.Pool) (
	betaTid, carolUID, westBetaGID, mcDevID string,
) {
	t.Helper()
	ctx := context.Background()

	uuids := make([]string, 4)
	rows, err := suPool.Query(ctx, `SELECT gen_random_uuid()::text FROM generate_series(1,4)`)
	if err != nil {
		t.Fatalf("gen beta uuids: %v", err)
	}
	for i := 0; rows.Next(); i++ {
		if err := rows.Scan(&uuids[i]); err != nil {
			t.Fatalf("scan beta uuid %d: %v", i, err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("beta uuid rows: %v", err)
	}
	betaTid, carolUID, westBetaGID = uuids[0], uuids[1], uuids[2]
	mcMachineID := uuids[3]
	mcDevID = newUUID()

	carolHash, err := HashPassword(p13CarolPw)
	if err != nil {
		t.Fatalf("hash carol: %v", err)
	}

	if err := withTenant(ctx, suPool, betaTid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,$2,$2,'self_hosted')`,
			betaTid, p13TenantBeta); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'West-Beta')`,
			westBetaGID, betaTid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
			carolUID, betaTid, p13CarolEmail); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_credential (user_id, tenant_id, password_hash) VALUES ($1,$2,$3)`,
			carolUID, betaTid, carolHash); err != nil {
			return err
		}
		var techRoleID string
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key='technician' AND tenant_id IS NULL`).Scan(&techRoleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids) VALUES ($1,$2,$3,ARRAY[$4::uuid])`,
			betaTid, carolUID, techRoleID, westBetaGID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO machine (id, tenant_id, device_id, group_id, hostname, pubkey)
			 VALUES ($1,$2,$3,$4,'mc-beta-west',$5)`,
			mcMachineID, betaTid, mcDevID, westBetaGID, []byte{0}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("provision beta: %v", err)
	}

	return
}

// ─── fixture ──────────────────────────────────────────────────────────────────

// pass13PgFixture holds the full PG-backed server and all provisioned IDs for
// one test run. Each test constructs its own fixture via newPass13PgFixture,
// which resets the schema and re-provisions, guaranteeing independence.
type pass13PgFixture struct {
	suPool  *pgxpool.Pool
	appPool *pgxpool.Pool
	srv     *Server
	handler http.Handler

	// Tenant IDs (resolved from provisioning, not hardcoded slugs).
	alphaTid string
	betaTid  string

	// User IDs in tenant-alpha.
	aliceUID string
	bobUID   string
	adminUID string

	// User ID in tenant-beta.
	carolUID string

	// Group IDs: east + west inside alpha; west inside beta.
	eastGID      string
	westAlphaGID string
	westBetaGID  string

	// Machine device IDs (real UUIDs — required for MintSessionPolicy).
	m1DevID string // alpha / east — Alice and Bob may start here
	m2DevID string // alpha / west — Alice and Bob are out-of-scope
	mcDevID string // beta  / west — Carol's; alpha users see 404

	// suAudit is backed by suPool (superuser) so test code can read audit events
	// without needing to pin app.current_tenant through a request context.
	// The server's MgmtAudit is still backed by appPool (RLS-enforced writes).
	suAudit *PgMgmtAuditStore
}

// newPass13PgFixture builds the full PG-backed fixture for one test.
//
// Schema lifecycle:
//  1. newTestPool resets and re-migrates the base schema.
//  2. Opt-in migrations are applied in dependency order.
//  3. Provisioning inserts two tenants, four users, three machines via suPool.
//  4. All server stores are backed by appPool (rmt_app, RLS-subject).
//
// The test is skipped if TEST_DATABASE_URL is unset, so the fixture never
// needs a real DB in CI unless the operator deliberately targets one.
func newPass13PgFixture(t *testing.T) *pass13PgFixture {
	t.Helper()

	// suPool: superuser/owner — migrations, provisioning, and test-side reads.
	// newTestPool skips the test when TEST_DATABASE_URL is unset and resets
	// the schema, so every TestPass13_Pg_ run starts from a blank database.
	suPool := newTestPool(t)

	// Opt-in migrations, applied in dependency order on suPool.
	// 0005 must precede 0013 (0013 GRANTs to rmt_app, so the role must exist).
	applyAppRoleMigration(t, suPool)        // 0005: rmt_app role + object grants
	applyAttendedMigration(t, suPool)       // 0013+0036+0042+0052: PgMachineStore columns
	applyMgmtAuditChainMigration(t, suPool) // 0014+0016: PgMgmtAuditStore chain columns

	ctx := context.Background()

	// appPool: rmt_app — all server stores, genuinely RLS-subject.
	appPool := newAppRolePool(t, ctx)

	// ── Least-privilege role verification ────────────────────────────────────
	// rmt_app must be NOSUPERUSER + NOBYPASSRLS. This is what makes RLS real.
	if err := AssertLeastPrivilegeRole(ctx, appPool); err != nil {
		t.Fatalf("rmt_app least-privilege assertion: %v", err)
	}
	// The superuser pool MUST be refused by the same guard (proves the guard is
	// not inert and validates the two-pool separation below).
	if err := AssertLeastPrivilegeRole(ctx, suPool); err == nil {
		t.Error("superuser pool accepted by least-privilege guard — guard is inert")
	}

	// ── FORCE RLS structural check ────────────────────────────────────────────
	p13AssertForceRLS(t, suPool)

	// ── Provisioning ──────────────────────────────────────────────────────────
	alphaTid, aliceUID, bobUID, adminUID, eastGID, westAlphaGID, m1DevID, m2DevID :=
		p13ProvisionAlpha(t, suPool)
	betaTid, carolUID, westBetaGID, mcDevID :=
		p13ProvisionBeta(t, suPool)

	// ── Build auth chain — all on appPool for RLS ─────────────────────────────
	users := newPgUserStoreT(appPool)
	sessions := NewSessionManager(NewPgSessionStore(appPool))
	authSvc := &AuthService{
		Users:           users,
		Sessions:        sessions,
		Tenants:         NewPgTenantResolver(appPool),
		Issuer:          "RMT",
		DisableThrottle: true, // prevent rate-limiter interference in rapid-fire test logins
	}

	issuer, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("generate grant issuer: %v", err)
	}

	// ── Build server — appPool for ALL stores ─────────────────────────────────
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(appPool))
	srv.AuthAPI        = authSvc
	srv.Machines       = NewPgMachineStore(appPool)
	srv.SessionRecords = NewPgSessionRecordStore(appPool)
	srv.MgmtAudit      = NewPgMgmtAuditStore(appPool)
	srv.Grants         = issuer
	// Share ONE audit store so auth events (auth.logout, auth.login_failed) and
	// handler events (session.start, session.end) appear in the same chain.
	authSvc.MgmtAudit = srv.MgmtAudit

	return &pass13PgFixture{
		suPool:       suPool,
		appPool:      appPool,
		srv:          srv,
		handler:      srv.Handler(),
		alphaTid:     alphaTid,
		betaTid:      betaTid,
		aliceUID:     aliceUID,
		bobUID:       bobUID,
		adminUID:     adminUID,
		carolUID:     carolUID,
		eastGID:      eastGID,
		westAlphaGID: westAlphaGID,
		westBetaGID:  westBetaGID,
		m1DevID:      m1DevID,
		m2DevID:      m2DevID,
		mcDevID:      mcDevID,
		suAudit:      NewPgMgmtAuditStore(suPool),
	}
}

// ─── helper methods ────────────────────────────────────────────────────────────

// loginAs drives the full production login chain: slug resolution (TenantResolver),
// email lookup (FindUserByEmail / argon2id VerifyPassword), session issue,
// cookie derivation. Returns (sessionCookie, csrfCookie, csrfToken).
func (f *pass13PgFixture) loginAs(t *testing.T, tenant, email, password string) (*http.Cookie, *http.Cookie, string) {
	t.Helper()
	rec := doJSON(t, f.handler, "POST", "/auth/login",
		loginRequest{Tenant: tenant, Email: email, Password: password}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s/%s = %d: %s", tenant, email, rec.Code, rec.Body.String())
	}
	sess := sessionCookieFrom(rec)
	csrfCookie, csrfTok := csrfFrom(t, rec)
	return sess, csrfCookie, csrfTok
}

// startSession calls POST /sessions and expects 201. Returns the decoded
// SessionRecord. Fatals on any other status.
func (f *pass13PgFixture) startSession(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, deviceID string) *SessionRecord {
	t.Helper()
	rec := doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: deviceID}, csrfTok, sess, csrfCookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start session device=%s = %d: %s", deviceID, rec.Code, rec.Body.String())
	}
	var body struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode start-session body: %v (%s)", err, rec.Body.String())
	}
	return &body.Session
}

// startSessionRaw calls POST /sessions and returns the raw recorder (for
// negative-case tests where the caller must check the status code).
func (f *pass13PgFixture) startSessionRaw(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, deviceID string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: deviceID}, csrfTok, sess, csrfCookie)
}

// endSession calls POST /sessions/{id}/end and returns the HTTP status code.
func (f *pass13PgFixture) endSession(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, sessionID string) int {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/sessions/"+sessionID+"/end",
		nil, csrfTok, sess, csrfCookie).Code
}

// renewLease calls POST /sessions/{id}/policy and returns the HTTP status code.
func (f *pass13PgFixture) renewLease(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, sessionID string) int {
	t.Helper()
	return f.renewLeaseRaw(t, sess, csrfCookie, csrfTok, sessionID).Code
}

// renewLeaseRaw returns the raw recorder for renewal (used by the claim-
// inspection test to decode the body on a 200).
func (f *pass13PgFixture) renewLeaseRaw(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/sessions/"+sessionID+"/policy",
		nil, csrfTok, sess, csrfCookie)
}

// logout calls POST /auth/logout. Fatals on a non-2xx.
func (f *pass13PgFixture) logout(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok string) {
	t.Helper()
	rec := doJSONWith(t, f.handler, "POST", "/auth/logout",
		nil, csrfTok, sess, csrfCookie)
	if rec.Code < 200 || rec.Code >= 300 {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
}

// listSessions calls GET /sessions (CSRF-exempt) and returns the status code.
func (f *pass13PgFixture) listSessions(t *testing.T, sess *http.Cookie) int {
	t.Helper()
	return doJSON(t, f.handler, "GET", "/sessions", nil, sess).Code
}

// auditEventsFor reads audit events for tenantID from suPool (bypassing RLS
// so no request context / tenant pin is needed). Returns events newest-first.
func (f *pass13PgFixture) auditEventsFor(t *testing.T, tenantID string) []MgmtAuditEvent {
	t.Helper()
	events, err := f.suAudit.ListEvents(context.Background(), tenantID, 500)
	if err != nil {
		t.Fatalf("list audit events for %s: %v", tenantID, err)
	}
	return events
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestPass13_Pg_SameGroupConcurrentSessions is the PG counterpart of
// TestPass12_SameGroupConcurrentSessions. Proves Alice and Bob each open an
// independent session on M1 through the full PG-backed auth + RLS chain.
func TestPass13_Pg_SameGroupConcurrentSessions(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1DevID)

	if sessionA.TechnicianID != f.aliceUID {
		t.Fatalf("sessionA.TechnicianID = %q, want Alice %q", sessionA.TechnicianID, f.aliceUID)
	}
	if sessionB.TechnicianID != f.bobUID {
		t.Fatalf("sessionB.TechnicianID = %q, want Bob %q", sessionB.TechnicianID, f.bobUID)
	}
	if sessionA.TenantID != f.alphaTid {
		t.Fatalf("sessionA.TenantID = %q, want %q", sessionA.TenantID, f.alphaTid)
	}
	if sessionA.MachineGroupID != f.eastGID {
		t.Fatalf("sessionA.MachineGroupID = %q, want east %q", sessionA.MachineGroupID, f.eastGID)
	}
	if sessionA.ID == sessionB.ID {
		t.Fatalf("sessionA and sessionB share session ID %q — must be distinct rows", sessionA.ID)
	}
	if sessionA.EndedAt != nil {
		t.Fatalf("sessionA.EndedAt is set — must be open immediately after start")
	}
	if sessionB.EndedAt != nil {
		t.Fatalf("sessionB.EndedAt is set — must be open immediately after start")
	}
}

// TestPass13_Pg_CrossTenantRejection is the PG counterpart of
// TestPass12_CrossTenantRejection. Carol (tenant-beta) attempts to start a
// session on M1 (tenant-alpha). PgMachineStore looks up (tenant-beta, m1DevID)
// → not found → 404, not 403. Information-hiding verified against real DB.
func TestPass13_Pg_CrossTenantRejection(t *testing.T) {
	f := newPass13PgFixture(t)

	carolSess, carolCSRFCookie, carolCSRFTok := f.loginAs(t, p13TenantBeta, p13CarolEmail, p13CarolPw)

	rec := doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: f.m1DevID},
		carolCSRFTok, carolSess, carolCSRFCookie)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant start session = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// TestPass13_Pg_OutOfScopeGroupRejection is the PG counterpart of
// TestPass12_OutOfScopeGroupRejection. Alice (east scope) is denied 403 on
// M2 (west group), then permitted 201 on M1 (east). The group is read from
// the DB row — Alice cannot widen her scope by supplying a different group.
func TestPass13_Pg_OutOfScopeGroupRejection(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)

	rec := doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: f.m2DevID},
		aliceCSRFTok, aliceSess, aliceCSRFCookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope start = %d, want 403: %s", rec.Code, rec.Body.String())
	}

	// Same credential on the in-scope machine must succeed (proves the 403
	// above is the group-scope gate, not a blanket technician denial).
	rec2 := doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: f.m1DevID},
		aliceCSRFTok, aliceSess, aliceCSRFCookie)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("in-scope start (negative control) = %d, want 201: %s", rec2.Code, rec2.Body.String())
	}
}

// TestPass13_Pg_AdminEndsSessionWhileOtherRenews is the PG counterpart of
// TestPass12_AdminEndsSessionWhileOtherRenews. Admin ends Alice's session via
// the handler; Alice's next renewal returns 409; Bob's independent session
// continues to renew (200). All three parties have separate PG sessions.
func TestPass13_Pg_AdminEndsSessionWhileOtherRenews(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)
	adminSess, adminCSRFCookie, adminCSRFTok := f.loginAs(t, p13TenantAlpha, p13AdminEmail, p13AdminPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1DevID)

	// Sanity: both renew before anything is ended.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("Alice renew before end = %d, want 200", got)
	}
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob renew before end = %d, want 200", got)
	}

	// Admin ends Alice's session through the production handler.
	if got := f.endSession(t, adminSess, adminCSRFCookie, adminCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("admin end Alice's session = %d, want 200", got)
	}

	// F03 finding: Alice's renewal is now 409 Conflict.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusConflict {
		t.Fatalf("Alice renew after admin end = %d, want 409", got)
	}
	// Second attempt also fails — no race window.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusConflict {
		t.Fatalf("Alice second renew = %d, want 409", got)
	}

	// Bob's independent session must keep renewing without disruption.
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob renew after Alice's end = %d, want 200", got)
	}
}

// TestPass13_Pg_LogoutRevokesAuthWhileOtherSurvives is the PG counterpart of
// TestPass12_LogoutRevokesAuthWhileOtherSurvives. Alice's POST /auth/logout
// revokes her PG session token; subsequent GET /sessions → 401. Bob's
// independent PG session is unaffected.
func TestPass13_Pg_LogoutRevokesAuthWhileOtherSurvives(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)

	if got := f.listSessions(t, aliceSess); got != http.StatusOK {
		t.Fatalf("Alice before logout = %d, want 200", got)
	}
	if got := f.listSessions(t, bobSess); got != http.StatusOK {
		t.Fatalf("Bob before logout = %d, want 200", got)
	}

	f.logout(t, aliceSess, aliceCSRFCookie, aliceCSRFTok)

	// cp_session_revoke (SECURITY DEFINER) marks Alice's token revoked in the DB.
	if got := f.listSessions(t, aliceSess); got != http.StatusUnauthorized {
		t.Fatalf("Alice after logout = %d, want 401", got)
	}

	// Bob's token is independent; it was NOT revoked.
	if got := f.listSessions(t, bobSess); got != http.StatusOK {
		t.Fatalf("Bob after Alice's logout = %d, want 200", got)
	}
	// Bob can still use CSRF-protected mutations.
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1DevID)
	if sessionB.TechnicianID != f.bobUID {
		t.Fatalf("Bob post-logout session technician = %q, want %q", sessionB.TechnicianID, f.bobUID)
	}
}

// TestPass13_Pg_AuditPrincipals is the PG counterpart of TestPass12_AuditPrincipals.
// Verifies that every management audit event written to the real audit_event
// table carries the correct actor_user_id. The negative assertion — no
// session.end attributed to Alice — is load-bearing: it confirms the chain
// uses the CALLER'S principal, not the session's technician.
func TestPass13_Pg_AuditPrincipals(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)
	adminSess, adminCSRFCookie, adminCSRFTok := f.loginAs(t, p13TenantAlpha, p13AdminEmail, p13AdminPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1DevID)

	if got := f.endSession(t, adminSess, adminCSRFCookie, adminCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("admin end = %d", got)
	}
	f.logout(t, aliceSess, aliceCSRFCookie, aliceCSRFTok)

	events := f.auditEventsFor(t, f.alphaTid)

	// session.start by Alice.
	evA := firstEventWith(t, events, "session.start", f.aliceUID)
	if evA.TargetKind != "session" {
		t.Fatalf("session.start(Alice) TargetKind = %q, want %q", evA.TargetKind, "session")
	}
	if evA.TargetID != sessionA.ID {
		t.Fatalf("session.start(Alice) TargetID = %q, want sessionA.ID %q", evA.TargetID, sessionA.ID)
	}

	// session.start by Bob.
	evB := firstEventWith(t, events, "session.start", f.bobUID)
	if evB.TargetID != sessionB.ID {
		t.Fatalf("session.start(Bob) TargetID = %q, want sessionB.ID %q", evB.TargetID, sessionB.ID)
	}

	// session.end must be attributed to Admin, NOT Alice (the critical assertion).
	evEnd := firstEventWith(t, events, "session.end", f.adminUID)
	if evEnd.TargetID != sessionA.ID {
		t.Fatalf("session.end(admin) TargetID = %q, want sessionA.ID %q", evEnd.TargetID, sessionA.ID)
	}
	for _, e := range events {
		if e.Action == "session.end" && e.ActorUserID == f.aliceUID {
			t.Fatalf("session.end attributed to Alice — must be the admin who issued the end call")
		}
	}

	// auth.logout by Alice.
	evLogout := firstEventWith(t, events, "auth.logout", f.aliceUID)
	if evLogout.TenantID != f.alphaTid {
		t.Fatalf("auth.logout TenantID = %q, want %q", evLogout.TenantID, f.alphaTid)
	}
}

// TestPass13_Pg_LogoutWithSessionThenRenewal401 adds the boundary assertion
// from codex-auth-handler-review.md §Next gate: Alice starts a remote session,
// then logs out (auth token revoked in PgSessionStore). Her next renewal attempt
// returns 401 — not 409 — because SessionAuthenticator.Authenticate sees the
// revoked token BEFORE the handler checks the session's EndedAt.
//
// This distinguishes "auth revoked" (401) from "session administratively ended"
// (409 in TestPass13_Pg_AdminEndsSessionWhileOtherRenews) and proves that
// self-logout is also an effective remote-session termination path within one
// lease TTL.
func TestPass13_Pg_LogoutWithSessionThenRenewal401(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1DevID)

	// Establish baseline: both can renew before logout.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("Alice renew before logout = %d, want 200", got)
	}
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob renew before logout = %d, want 200", got)
	}

	// Alice logs out. Her cp_session token is revoked in PgSessionStore.
	f.logout(t, aliceSess, aliceCSRFCookie, aliceCSRFTok)

	// Alice's renewal now hits SessionAuthenticator.Authenticate, which calls
	// cp_session_by_token → finds the token revoked → ErrSessionRevoked →
	// authMiddleware returns 401. The renewal handler never executes.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusUnauthorized {
		t.Fatalf("Alice renew after logout = %d, want 401 (auth revoked, not 409 ended)", got)
	}

	// Bob's session is independent. His renewal must remain 200.
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob renew after Alice's logout = %d, want 200", got)
	}
}

// TestPass13_Pg_MissingCSRFMutation403 proves that POST /sessions without a
// valid CSRF token is refused at the CSRF middleware (403) and that neither an
// audit event nor a session_record row is written by either refused request.
//
// Two cases: missing CSRF header (no X-CSRF-Token header at all) and wrong
// CSRF token (header present, value incorrect). Both audit event count and
// session_record row count are captured before and after each refused request;
// neither may change. This closes the codex-pg-auth-review.md §2 gap: the
// prior assertion compared audit counts only and could not distinguish a
// session_record insert without a corresponding audit write.
func TestPass13_Pg_MissingCSRFMutation403(t *testing.T) {
	f := newPass13PgFixture(t)
	ctx := context.Background()

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)

	// Snapshot: audit event count before any mutation attempt.
	before := f.auditEventsFor(t, f.alphaTid)

	// Snapshot: session_record row count before any mutation attempt. suPool
	// bypasses RLS (superuser), so the count is authoritative regardless of
	// app.current_tenant. The WHERE clause scopes to alpha's tenant only.
	var sessionRecsBefore int
	if err := f.suPool.QueryRow(ctx,
		`SELECT count(*) FROM session_record WHERE tenant_id = $1`, f.alphaTid,
	).Scan(&sessionRecsBefore); err != nil {
		t.Fatalf("count session_record before: %v", err)
	}

	// Case 1: missing CSRF header entirely (doJSON does not send X-CSRF-Token).
	rec := doJSON(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: f.m1DevID}, aliceSess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header = %d, want 403", rec.Code)
	}

	// Case 2: wrong CSRF token value (header present, value wrong).
	rec2 := doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: f.m1DevID},
		"totally-wrong-csrf-token", aliceSess, aliceCSRFCookie)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF token = %d, want 403", rec2.Code)
	}

	// Assert: no audit event written by either refused request.
	after := f.auditEventsFor(t, f.alphaTid)
	if len(after) != len(before) {
		t.Fatalf("audit event count changed after CSRF refusals: before=%d after=%d (unexpected DB write)",
			len(before), len(after))
	}

	// Assert: no session_record row inserted by either refused request.
	var sessionRecsAfter int
	if err := f.suPool.QueryRow(ctx,
		`SELECT count(*) FROM session_record WHERE tenant_id = $1`, f.alphaTid,
	).Scan(&sessionRecsAfter); err != nil {
		t.Fatalf("count session_record after: %v", err)
	}
	if sessionRecsAfter != sessionRecsBefore {
		t.Fatalf("session_record count changed after CSRF refusals: before=%d after=%d (unexpected row insertion)",
			sessionRecsBefore, sessionRecsAfter)
	}

	// Sanity: the same credential succeeds with the correct CSRF token, proving
	// the 403 above is the CSRF gate, not a broken auth or machine lookup.
	sessOK := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)
	if sessOK.TechnicianID != f.aliceUID {
		t.Fatalf("sanity start technician = %q, want Alice %q", sessOK.TechnicianID, f.aliceUID)
	}
}

// TestPass13_Pg_CrossUserRenewalRefused adds the boundary assertion from
// codex-auth-handler-review.md §Next gate: Alice cannot renew Bob's session.
// handleRenewSessionPolicy checks sameUserID(p.UserID, rec.TechnicianID) before
// any mutation and returns 403, so the ended_at timestamp is never touched.
//
// This is distinct from the admin-end test: an admin holds CapStartSession
// tenant-wide and could PASS the group-scope check on Bob's session. Without the
// ownership check, an admin could keep Bob's session alive (the exact opposite of
// incident-response intent) or accidentally stamp ended_at via the max-age path.
func TestPass13_Pg_CrossUserRenewalRefused(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)
	adminSess, adminCSRFCookie, adminCSRFTok := f.loginAs(t, p13TenantAlpha, p13AdminEmail, p13AdminPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1DevID)

	// Alice cannot renew Bob's session.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionB.ID); got != http.StatusForbidden {
		t.Fatalf("Alice renew Bob's session = %d, want 403", got)
	}
	// Bob cannot renew Alice's session.
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionA.ID); got != http.StatusForbidden {
		t.Fatalf("Bob renew Alice's session = %d, want 403", got)
	}
	// Admin cannot renew either Alice's or Bob's session (admin has CapStartSession
	// tenant-wide, which passes the group-scope check, but not the ownership check).
	if got := f.renewLease(t, adminSess, adminCSRFCookie, adminCSRFTok, sessionA.ID); got != http.StatusForbidden {
		t.Fatalf("Admin renew Alice's session = %d, want 403", got)
	}
	if got := f.renewLease(t, adminSess, adminCSRFCookie, adminCSRFTok, sessionB.ID); got != http.StatusForbidden {
		t.Fatalf("Admin renew Bob's session = %d, want 403", got)
	}

	// Both sessions remain live — the 403 must not have mutated ended_at.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("Alice own renew after cross-user refusals = %d, want 200", got)
	}
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob own renew after cross-user refusals = %d, want 200", got)
	}
}

// TestPass13_Pg_SignedRenewalClaimsVerified adds the claim-inspection assertion
// from codex-auth-handler-review.md §Next gate. A 200 renewal response carries
// a signed SignedSessionPolicy; this test decodes its JSON wire form and verifies
// the claims are bound to the correct (technician_id, session_id, machine_id)
// triple and carry access="control".
//
// This is the distinction from merely asserting HTTP 200: a handler that returns
// 200 with incorrect or unbound claims would pass a status-only check. The signed
// payload is what the agent enforces — verifying it here closes the gap between
// "the server responded" and "the server produced the right artifact".
func TestPass13_Pg_SignedRenewalClaimsVerified(t *testing.T) {
	f := newPass13PgFixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1DevID)

	rec := f.renewLeaseRaw(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("renewal = %d (body: %s), want 200", rec.Code, rec.Body.String())
	}

	// Decode the outer response envelope.
	var outer struct {
		SessionPolicy struct {
			Access      string `json:"access"`
			Signed      string `json:"signed"`
			LeaseTTLMs  int64  `json:"lease_ttl_ms"`
			ExpiresAtMs int64  `json:"expires_at_ms"`
		} `json:"session_policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &outer); err != nil {
		t.Fatalf("decode renewal body: %v — body: %s", err, rec.Body.String())
	}

	// The outer `access` field is the wire-readable summary.
	if outer.SessionPolicy.Access != string(SessionAccessControl) {
		t.Fatalf("session_policy.access = %q, want %q", outer.SessionPolicy.Access, SessionAccessControl)
	}
	if outer.SessionPolicy.LeaseTTLMs <= 0 {
		t.Fatalf("session_policy.lease_ttl_ms = %d, want > 0", outer.SessionPolicy.LeaseTTLMs)
	}
	if outer.SessionPolicy.ExpiresAtMs <= 0 {
		t.Fatalf("session_policy.expires_at_ms = %d, want > 0", outer.SessionPolicy.ExpiresAtMs)
	}
	if outer.SessionPolicy.Signed == "" {
		t.Fatal("session_policy.signed is empty — no signed artifact produced")
	}

	// Decode the inner signed JSON (a SignedSessionPolicy in its wire form).
	var ssp SignedSessionPolicy
	if err := json.Unmarshal([]byte(outer.SessionPolicy.Signed), &ssp); err != nil {
		t.Fatalf("decode SignedSessionPolicy: %v — signed: %s", err, outer.SessionPolicy.Signed)
	}

	// Policy body binding: each field must match the provisioned identity.
	// These are the claims the agent verifies against its own device uuid and
	// the technician's stored id — a mismatch here is a mismatch there.
	if ssp.Claims.Policy.TechnicianID != f.aliceUID {
		t.Fatalf("claims.policy.technician_id = %q, want Alice %q",
			ssp.Claims.Policy.TechnicianID, f.aliceUID)
	}
	if ssp.Claims.Policy.SessionID != sessionA.ID {
		t.Fatalf("claims.policy.session_id = %q, want sessionA.ID %q",
			ssp.Claims.Policy.SessionID, sessionA.ID)
	}
	if ssp.Claims.Policy.MachineID != f.m1DevID {
		t.Fatalf("claims.policy.machine_id = %q, want M1 device id %q",
			ssp.Claims.Policy.MachineID, f.m1DevID)
	}
	if ssp.Claims.Policy.Access != SessionAccessControl {
		t.Fatalf("claims.policy.access = %q, want %q",
			ssp.Claims.Policy.Access, SessionAccessControl)
	}

	// Temporal sanity: claims must be stamped with a non-zero time window.
	if ssp.Claims.IssuedAtMs <= 0 {
		t.Fatalf("claims.issued_at_ms = %d, want > 0", ssp.Claims.IssuedAtMs)
	}
	if ssp.Claims.ExpiresAtMs <= ssp.Claims.IssuedAtMs {
		t.Fatalf("claims.expires_at_ms (%d) must be > issued_at_ms (%d)",
			ssp.Claims.ExpiresAtMs, ssp.Claims.IssuedAtMs)
	}

	// Signature fields must be present. The Sig field (sig_v1) is the v1-preimage
	// signature that new agents verify; SigCompat (sig) carries the v0-compat sig
	// for non-restrictive policies. Both must be non-empty for a control-level policy.
	if ssp.Sig == "" {
		t.Fatal("sig_v1 is empty — v1 authoritative signature missing")
	}
	if ssp.SigCompat == "" {
		t.Fatal("sig (v0 compat) is empty — backward-compat signature missing for control-level policy")
	}
}
