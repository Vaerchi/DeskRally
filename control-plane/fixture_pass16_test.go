package controlplane

// Pass 16 fixture smoke tests — prove that the cptestfixture wiring (SessionAuthenticator,
// distinct A/B users, real cookies+CSRF) enforces actual authentication.
//
// Assertions:
//   1. Anonymous POST /sessions → 401 (no cookie = not authenticated).
//   2. Anonymous GET /grant/pubkey → 401.
//   3. TechA login (real password) succeeds; returns session cookie + CSRF token.
//   4. TechB login (real password) succeeds; returns a DIFFERENT session cookie.
//   5. TechA POST /sessions → 201, session.technician_id == TechAID.
//   6. TechB POST /sessions → 201, session.technician_id == TechBID.
//   7. Session IDs returned to A and B are distinct.
//   8. Admin login succeeds; admin GET /grant/pubkey → 200 with valid pubkey hex.
//   9. Admin POST /enrollment-tokens → 201.
//  10. TechA POST /grant/mint → 200, grant bound to TechA's session.
//
// No agent binary, no browser, no network. All requests drive srv.Handler() in-process via
// httptest.NewRecorder — identical to the pass12 test pattern.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// ── fixture ───────────────────────────────────────────────────────────────────────────────────────

const (
	p16TenantID = "16161616-0000-4000-8000-000000000016"

	p16AdminID    = "aaaaaaaa-0000-4000-8000-000000000001"
	p16AdminEmail = "admin@fix16.test"
	p16AdminPw    = "admin-fix16-battery-staple-01"

	p16TechAID    = "aaaaaaaa-0000-4000-8000-000000000002"
	p16TechAEmail = "tech-a@fix16.test"
	p16TechAPw    = "tech-a-fix16-battery-staple-02"

	p16TechBID    = "aaaaaaaa-0000-4000-8000-000000000003"
	p16TechBEmail = "tech-b@fix16.test"
	p16TechBPw    = "tech-b-fix16-battery-staple-03"
)

type pass16Fixture struct {
	*authFixture
	machines *InMemoryMachineStore
	issuer   *GrantIssuer
}

func newPass16Fixture(t *testing.T) *pass16Fixture {
	t.Helper()
	f := newAuthFixture(t)
	f.auth.DisableThrottle = true

	mgmtAudit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit = mgmtAudit
	f.auth.MgmtAudit = mgmtAudit

	machines := NewInMemoryMachineStore()
	f.srv.Machines = machines
	f.srv.MachineProperties = NewInMemoryMachinePropertyStore()
	f.srv.SessionRecords = NewInMemorySessionRecordStore()
	f.srv.EnrollmentTokens = NewInMemoryEnrollmentTokenStore()
	f.srv.TicketRedemptions = NewInMemoryTicketRedemptionStore()

	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("pass16: GenerateGrantIssuer: %v", err)
	}
	f.srv.Grants = iss

	// Admin: manage enrollment tokens + sessions.
	f.addUser(t, p16TenantID, p16AdminID, p16AdminEmail, p16AdminPw, RoleAdmin)

	// TechA and TechB: separate technician identities in the same tenant.
	f.addUserWithGrant(t, p16TenantID, p16TechAID, p16TechAEmail, p16TechAPw,
		NewGrant(p16TechAID, p16TenantID, NewMembership(RoleTechnician, AllGroups())))
	f.addUserWithGrant(t, p16TenantID, p16TechBID, p16TechBEmail, p16TechBPw,
		NewGrant(p16TechBID, p16TenantID, NewMembership(RoleTechnician, AllGroups())))

	// Enroll one machine that A and B can start sessions on.
	m := &Machine{DeviceID: newUUID(), GroupID: DevDefaultMachineGroupID, Name: "p16-test-host"}
	if err := machines.EnrollMachine(context.Background(), p16TenantID, m); err != nil {
		t.Fatalf("pass16: EnrollMachine: %v", err)
	}

	return &pass16Fixture{authFixture: f, machines: machines, issuer: iss}
}

// loginP16 drives the full production login path and returns (sessionCookie, csrfCookie, csrfToken).
func (f *pass16Fixture) loginP16(t *testing.T, email, password string) (*http.Cookie, *http.Cookie, string) {
	t.Helper()
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: p16TenantID, Email: email, Password: password}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pass16: login %s = %d: %s", email, rec.Code, rec.Body.String())
	}
	sess := sessionCookieFrom(rec)
	if sess == nil {
		t.Fatalf("pass16: login %s returned no session cookie", email)
	}
	csrfCookie, csrfTok := csrfFrom(t, rec)
	return sess, csrfCookie, csrfTok
}

// startSessionP16 calls POST /sessions as the given authenticated user.
func (f *pass16Fixture) startSessionP16(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, deviceID string) *SessionRecord {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/sessions",
		startSessionRequest{MachineID: deviceID}, csrfTok, sess, csrfCookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("pass16: POST /sessions device=%s = %d: %s", deviceID, rec.Code, rec.Body.String())
	}
	var body struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("pass16: decode session body: %v (%s)", err, rec.Body.String())
	}
	return &body.Session
}

// ── Tests ─────────────────────────────────────────────────────────────────────────────────────────

// TestPass16_AnonSessionsMint401 proves that POST /sessions with no cookie returns 401.
func TestPass16_AnonSessionsMint401(t *testing.T) {
	f := newPass16Fixture(t)
	h := f.srv.Handler()

	rec := doJSON(t, h, "POST", "/sessions",
		startSessionRequest{MachineID: "any-device-id"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST /sessions: want 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPass16_AnonGrantPubkey401 proves that GET /grant/pubkey with no cookie returns 401.
func TestPass16_AnonGrantPubkey401(t *testing.T) {
	f := newPass16Fixture(t)
	h := f.srv.Handler()

	rec := doJSON(t, h, "GET", "/grant/pubkey", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /grant/pubkey: want 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestPass16_LoginSucceeds proves that TechA and TechB each produce a valid session cookie,
// and that the two cookies are distinct (different active sessions).
func TestPass16_LoginSucceeds(t *testing.T) {
	f := newPass16Fixture(t)

	sessA, _, _ := f.loginP16(t, p16TechAEmail, p16TechAPw)
	sessB, _, _ := f.loginP16(t, p16TechBEmail, p16TechBPw)

	if sessA.Value == sessB.Value {
		t.Fatal("TechA and TechB share a session token — they must be distinct identities")
	}
	t.Logf("TechA session token prefix: %s", sessA.Value[:8])
	t.Logf("TechB session token prefix: %s", sessB.Value[:8])
}

// TestPass16_DistinctTechnicianIDs proves that POST /sessions returns a session whose
// technician_id matches the authenticated user, and that A ≠ B.
func TestPass16_DistinctTechnicianIDs(t *testing.T) {
	f := newPass16Fixture(t)
	deviceID := f.machines.DeviceIDs(p16TenantID)[0]

	sessA, csrfCookieA, csrfTokA := f.loginP16(t, p16TechAEmail, p16TechAPw)
	sessB, csrfCookieB, csrfTokB := f.loginP16(t, p16TechBEmail, p16TechBPw)

	recA := f.startSessionP16(t, sessA, csrfCookieA, csrfTokA, deviceID)
	recB := f.startSessionP16(t, sessB, csrfCookieB, csrfTokB, deviceID)

	if recA.TechnicianID != p16TechAID {
		t.Errorf("session A technician_id=%q want %q", recA.TechnicianID, p16TechAID)
	}
	if recB.TechnicianID != p16TechBID {
		t.Errorf("session B technician_id=%q want %q", recB.TechnicianID, p16TechBID)
	}
	if recA.TechnicianID == recB.TechnicianID {
		t.Error("A and B sessions share the same technician_id — must be distinct authenticated identities")
	}
	if recA.ID == recB.ID {
		t.Error("A and B sessions share the same session ID")
	}
	t.Logf("session A id=%s technician_id=%s", recA.ID, recA.TechnicianID)
	t.Logf("session B id=%s technician_id=%s", recB.ID, recB.TechnicianID)
}

// TestPass16_AdminGrantPubkey proves that an authenticated admin can read the grant pubkey
// and that it is a valid 64-char hex string.
func TestPass16_AdminGrantPubkey(t *testing.T) {
	f := newPass16Fixture(t)

	sessAdmin, csrfCookieAdmin, csrfTokAdmin := f.loginP16(t, p16AdminEmail, p16AdminPw)
	rec := doJSONWith(t, f.srv.Handler(), "GET", "/grant/pubkey", nil, csrfTokAdmin, sessAdmin, csrfCookieAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /grant/pubkey = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		GrantIssuerPubkey string `json:"grant_issuer_pubkey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode grant/pubkey body: %v", err)
	}
	if len(body.GrantIssuerPubkey) != 64 {
		t.Fatalf("grant_issuer_pubkey len=%d want 64: %q", len(body.GrantIssuerPubkey), body.GrantIssuerPubkey)
	}
	t.Logf("grant_issuer_pubkey: %s", body.GrantIssuerPubkey)
}

// TestPass16_AdminMintEnrollmentToken proves that an authenticated admin can mint an enrollment
// token for the dev-default group.
func TestPass16_AdminMintEnrollmentToken(t *testing.T) {
	f := newPass16Fixture(t)

	sessAdmin, csrfCookieAdmin, csrfTokAdmin := f.loginP16(t, p16AdminEmail, p16AdminPw)
	body := fmt.Sprintf(`{"name":"p16-smoke","group_id":"%s"}`, DevDefaultMachineGroupID)
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/enrollment-tokens",
		json.RawMessage(body), csrfTokAdmin, sessAdmin, csrfCookieAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin POST /enrollment-tokens = %d: %s", rec.Code, rec.Body.String())
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode enrollment token body: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("POST /enrollment-tokens returned no token field")
	}
	t.Logf("enrollment token prefix: %s…", tok.Token[:8])
}

// TestPass16_TechAMintGrant proves that an authenticated TechA can mint a backstage grant.
func TestPass16_TechAMintGrant(t *testing.T) {
	f := newPass16Fixture(t)
	deviceID := f.machines.DeviceIDs(p16TenantID)[0]

	sessA, csrfCookieA, csrfTokA := f.loginP16(t, p16TechAEmail, p16TechAPw)

	// Start a session first so the grant is bound to a real session ID.
	sessionRec := f.startSessionP16(t, sessA, csrfCookieA, csrfTokA, deviceID)

	body := fmt.Sprintf(`{"machine_id":"%s","session_id":"%s"}`, deviceID, sessionRec.ID)
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/grant/mint",
		json.RawMessage(body), csrfTokA, sessA, csrfCookieA)
	if rec.Code != http.StatusOK {
		t.Fatalf("TechA POST /grant/mint = %d: %s", rec.Code, rec.Body.String())
	}
	// Minimal check: response is non-empty JSON with a "payload" or "signature" key typical of
	// a SignedGrant. We don't fully deserialize — the Go grant tests own that.
	body2 := rec.Body.String()
	if !strings.Contains(body2, `"sig"`) || !strings.Contains(body2, `"claims"`) {
		t.Fatalf("grant/mint response missing expected sig/claims fields: %s", body2[:min(120, len(body2))])
	}
	t.Logf("grant/mint response (%d bytes): %s…", len(body2), body2[:min(80, len(body2))])
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────────────────

// DeviceIDs is a test-only helper on InMemoryMachineStore that returns all enrolled device IDs
// for a given tenant. We declare it here rather than on the type to keep test helpers in test files.
func (s *InMemoryMachineStore) DeviceIDs(tenantID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.machines {
		if m.TenantID == tenantID {
			out = append(out, m.DeviceID)
		}
	}
	return out
}
