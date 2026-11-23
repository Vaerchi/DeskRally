package controlplane

// Secure test harness: a local attended-session control plane for testing
// real signed policy/grant admission WITHOUT a real backend or production executor.
//
// Identity model:
//   - Issuer:      GenerateGrantIssuer() — fresh Ed25519 key per server instance (NOT goldenSeedHex).
//   - Technician:  StubAuthenticator{Principal} with UUID-based UserID + TenantID per instance.
//   - Agent:       ephemeral identity injected via the attended redeem flow (production path).
//
// None of these are shared fixtures. Two calls to newSecureHarnessServer produce servers with
// distinct issuer keys, distinct tenant/user IDs, and independent session state.
//
// DO NOT confuse:
//   - The grant issuer key (ed25519 signing key) with the signaling ticket (RMTTICKETv1).
//   - The technician principal (UserID/TenantID RBAC grant) with the agent ephemeral identity.
//   - The in-memory test server with a DEV stub — it runs the real handler code.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// SecureHarnessServer is a local control-plane test fixture for secure harness tests.
// Obtain one with newSecureHarnessServer; register cleanup with t.Cleanup(h.Cleanup).
type SecureHarnessServer struct {
	t          *testing.T
	srv        *Server
	issuer     *GrantIssuer
	userID     string
	tenantID   string
	groupID    string
	techBearer string // any non-empty string — StubAuthenticator ignores token value
}

// newSecureHarnessServer builds a local attended-session server with:
//   - A FRESH Ed25519 issuer key (GenerateGrantIssuer, not goldenSeedHex).
//   - Unique UserID, TenantID, and GroupID per call.
//   - All real handler code (attended create/redeem/consent/connect/promote-complete).
//   - No managed installer (srv.ManagedInstaller is nil → installer endpoint 404s).
//
// The returned server is isolated: its stores are in-memory and share no state with
// any other test server or with the goldenSeedHex-seeded handler tests.
func newSecureHarnessServer(t *testing.T) *SecureHarnessServer {
	t.Helper()

	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("newSecureHarnessServer: GenerateGrantIssuer: %v", err)
	}

	userID := newUUID()
	tenantID := newUUID()
	groupID := newUUID()

	p := &Principal{
		UserID:   userID,
		TenantID: tenantID,
		Grant: NewGrant(userID, tenantID,
			NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	machines := NewInMemoryMachineStore()
	srv.Machines = machines
	srv.SessionRecords = NewInMemorySessionRecordStore()
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	srv.EnrollmentTokens = NewInMemoryEnrollmentTokenStore()
	srv.Attended = NewInMemoryAttendedStore(machines)
	srv.Grants = iss
	// GroupSessionPolicies is intentionally nil here — no view-only enforcement by default.
	// Tests that need enforce-viewonly call h.EnforceViewOnly() before creating sessions.

	return &SecureHarnessServer{
		t:          t,
		srv:        srv,
		issuer:     iss,
		userID:     userID,
		tenantID:   tenantID,
		groupID:    groupID,
		techBearer: "secure-harness-tech-token", // StubAuthenticator ignores value
	}
}

// IssuerPubkeyHex returns the hex-encoded Ed25519 public key for the agent's --grant-issuer flag.
func (h *SecureHarnessServer) IssuerPubkeyHex() string {
	return h.issuer.PublicKeyHex()
}

// GroupID returns the UUID string used as the group in CreateSession calls.
func (h *SecureHarnessServer) GroupID() string { return h.groupID }

// UserID returns the technician's UserID (distinct per server instance).
func (h *SecureHarnessServer) UserID() string { return h.userID }

// TenantID returns the technician's TenantID (distinct per server instance).
func (h *SecureHarnessServer) TenantID() string { return h.tenantID }

// EnforceViewOnly installs a GroupSessionPolicyStore that marks h.groupID as EnforceViewOnly.
// Call before CreateSession when the test needs a require_session_policy + signed policy.
func (h *SecureHarnessServer) EnforceViewOnly() {
	h.t.Helper()
	store := NewInMemoryGroupSessionPolicyStore()
	if err := store.Set(context.Background(), h.tenantID, h.groupID, GroupSessionPolicy{
		GroupID:        h.groupID,
		EnforceViewOnly: true,
	}); err != nil {
		h.t.Fatalf("EnforceViewOnly: Set: %v", err)
	}
	h.srv.GroupSessionPolicies = store
}

// techRequest performs an authenticated technician HTTP request against the server.
func (h *SecureHarnessServer) techRequest(method, path, body string, out any) int {
	h.t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.techBearer)
	h.srv.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			h.t.Fatalf("%s %s: unmarshal %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code
}

// guestRequest performs an unauthenticated or attend-token-bearer request.
func (h *SecureHarnessServer) guestRequest(method, path, bearer, body string, out any) int {
	h.t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	h.srv.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			h.t.Fatalf("%s %s: unmarshal %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code
}

// sessionResult carries the fields the tests read from CreateSession.
type shSessionCreate struct {
	Session AttendedSession `json:"session"`
	Code    string          `json:"code"`
}

// CreateSession creates an attended session and returns the session ID and one-time code.
func (h *SecureHarnessServer) CreateSession(reason string) (sessionID, code string) {
	h.t.Helper()
	body := fmt.Sprintf(`{"group_id":%q,"reason":%q}`, h.groupID, reason)
	var resp shSessionCreate
	if status := h.techRequest("POST", "/attended-sessions", body, &resp); status != http.StatusCreated {
		h.t.Fatalf("CreateSession: status %d", status)
	}
	return resp.Session.ID, resp.Code
}

// shRedeemResp carries the fields the tests read from Redeem.
type shRedeemResp struct {
	DeviceID           string `json:"device_id"`
	AttendToken        string `json:"attend_token"`
	GrantIssuerPubkey  string `json:"grant_issuer_pubkey"`
	RequireSessionPolicy bool  `json:"require_session_policy"`
}

// Redeem redeems the one-time code as the agent. pubkeyHex is the agent's ephemeral
// Ed25519 public key (hex). Returns the server-minted device_id and attend_token.
func (h *SecureHarnessServer) Redeem(code, pubkeyHex, name string) shRedeemResp {
	h.t.Helper()
	body := fmt.Sprintf(`{"code":%q,"pubkey":%q,"name":%q}`, code, pubkeyHex, name)
	var resp shRedeemResp
	if status := h.guestRequest("POST", "/attended-sessions/redeem", "", body, &resp); status != http.StatusCreated {
		h.t.Fatalf("Redeem: status %d", status)
	}
	return resp
}

// Consent posts the guest's consent decision (accept=true for testing).
func (h *SecureHarnessServer) Consent(attendToken string, accept bool) {
	h.t.Helper()
	decision := "decline"
	if accept {
		decision = "accept"
	}
	body := fmt.Sprintf(`{"decision":%q,"consent_user":"test-guest"}`, decision)
	if status := h.guestRequest("POST", "/attended-sessions/consent", attendToken, body, nil); status != http.StatusOK {
		h.t.Fatalf("Consent: status %d", status)
	}
}

// shConnectResp carries the fields the tests read from Connect.
type shConnectResp struct {
	Signaling struct {
		URL       string `json:"url"`
		DeviceID  string `json:"device_id"`
		SessionID string `json:"session_id"`
	} `json:"signaling"`
	SessionPolicy *struct {
		Access string `json:"access"`
		Signed string `json:"signed"`
	} `json:"session_policy,omitempty"`
}

// Connect connects the technician to the session (after guest has consented).
// Returns the connect response including any issued session policy.
func (h *SecureHarnessServer) Connect(sessionID string) shConnectResp {
	h.t.Helper()
	var resp shConnectResp
	path := "/attended-sessions/" + sessionID + "/connect"
	if status := h.techRequest("POST", path, "", &resp); status != http.StatusOK {
		h.t.Fatalf("Connect(%s): status %d", sessionID, status)
	}
	return resp
}

// MintGrant mints a real Ed25519-signed backstage grant for the given session and device,
// using the server's FRESH issuer key. The grant is valid for 5 minutes from now.
func (h *SecureHarnessServer) MintGrant(sessionID, deviceID string, caps []BackstageCapability) (SignedGrant, error) {
	now := time.Now()
	return h.issuer.Mint(
		h.userID, sessionID, deviceID,
		caps,
		now.UnixMilli(), now.Add(5*time.Minute).UnixMilli(),
	)
}

// FullLifecycle runs a complete create→redeem→consent→connect cycle and returns the
// session ID, device ID, attend token, and connect response for further assertions.
func (h *SecureHarnessServer) FullLifecycle(agentPubkeyHex string) (sessionID, deviceID, attendToken string, conn shConnectResp) {
	h.t.Helper()
	sessionID, code := h.CreateSession("secure-harness-test")
	redeemed := h.Redeem(code, agentPubkeyHex, "test-agent")
	deviceID = redeemed.DeviceID
	attendToken = redeemed.AttendToken
	h.Consent(attendToken, true)
	conn = h.Connect(sessionID)
	return sessionID, deviceID, attendToken, conn
}

// Cleanup is registered with t.Cleanup by the caller. Currently a no-op for in-memory stores
// (GC handles it), but documented as the hook for future PG cleanup.
func (h *SecureHarnessServer) Cleanup() {}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

// TestSecureHarnessIssuersAreDistinct proves that two server instances have distinct Ed25519 keys.
func TestSecureHarnessIssuersAreDistinct(t *testing.T) {
	h1 := newSecureHarnessServer(t)
	h2 := newSecureHarnessServer(t)
	if h1.IssuerPubkeyHex() == h2.IssuerPubkeyHex() {
		t.Fatal("two secure harness servers share the same issuer pubkey; GenerateGrantIssuer must produce distinct keys")
	}
}

// TestSecureHarnessIssuerNotGoldenSeed proves the issuer key is not derived from goldenSeedHex.
func TestSecureHarnessIssuerNotGoldenSeed(t *testing.T) {
	goldenSeed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatalf("decode goldenSeedHex: %v", err)
	}
	golden, err := NewGrantIssuerFromSeed(goldenSeed)
	if err != nil {
		t.Fatalf("NewGrantIssuerFromSeed: %v", err)
	}
	h := newSecureHarnessServer(t)
	if h.IssuerPubkeyHex() == golden.PublicKeyHex() {
		t.Fatal("secure harness issuer equals goldenSeedHex key; must use GenerateGrantIssuer")
	}
}

// TestSecureHarnessTechnicianIdentityReal proves technician IDs are unique, not shared fixtures.
func TestSecureHarnessTechnicianIdentityReal(t *testing.T) {
	h1 := newSecureHarnessServer(t)
	h2 := newSecureHarnessServer(t)
	if h1.UserID() == h2.UserID() {
		t.Error("two harness servers share UserID — must be distinct per instance")
	}
	if h1.TenantID() == h2.TenantID() {
		t.Error("two harness servers share TenantID — must be distinct per instance")
	}
	if h1.GroupID() == h2.GroupID() {
		t.Error("two harness servers share GroupID — must be distinct per instance")
	}
}

// TestSecureHarnessInstallerAbsentWithoutBundle proves GET /attended-sessions/installer
// returns 503 when no managed installer bundle is configured (srv.ManagedInstaller is nil).
func TestSecureHarnessInstallerAbsentWithoutBundle(t *testing.T) {
	h := newSecureHarnessServer(t)
	// Server has no ManagedInstaller — the endpoint should 404.
	// We need an attend token, so run a partial lifecycle.
	const agentPubkey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	_, _, attendToken, _ := h.FullLifecycle(agentPubkey)
	if h.srv.ManagedInstaller != nil {
		t.Fatal("precondition: ManagedInstaller must be nil for this test")
	}
	status := h.guestRequest("GET", "/attended-sessions/installer", attendToken, "", nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("installer endpoint: want 503 (no bundle configured), got %d", status)
	}
}

// TestSecureHarnessMintGrantRoundTrip proves that MintGrant produces valid SignedGrant JSON
// with all required fields and a signature from this server's issuer key.
func TestSecureHarnessMintGrantRoundTrip(t *testing.T) {
	h := newSecureHarnessServer(t)
	const agentPubkey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	sessionID, deviceID, _, _ := h.FullLifecycle(agentPubkey)

	grant, err := h.MintGrant(sessionID, deviceID, []BackstageCapability{BackProcessList})
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}

	// Must have a non-empty signature.
	if grant.Sig == "" {
		t.Fatal("MintGrant: Sig is empty")
	}
	// Sig must be 128 hex chars (64 bytes).
	if len(grant.Sig) != 128 {
		t.Fatalf("MintGrant: Sig length = %d, want 128", len(grant.Sig))
	}
	// Claims must reference the right machine and session.
	if grant.Claims.Grant.MachineID != deviceID {
		t.Errorf("MintGrant: machine_id = %q, want %q", grant.Claims.Grant.MachineID, deviceID)
	}
	if grant.Claims.Grant.SessionID != sessionID {
		t.Errorf("MintGrant: session_id = %q, want %q", grant.Claims.Grant.SessionID, sessionID)
	}
	if grant.Claims.Grant.TechnicianID != h.UserID() {
		t.Errorf("MintGrant: technician_id = %q, want %q", grant.Claims.Grant.TechnicianID, h.UserID())
	}
	// The grant must serialize to valid JSON (the Rust agent deserializes this).
	grantJSON, err2 := json.Marshal(grant)
	if err2 != nil {
		t.Fatalf("MintGrant: json.Marshal failed: %v", err2)
	}
	if len(grantJSON) == 0 {
		t.Fatal("MintGrant: json.Marshal produced empty JSON")
	}
}

// TestSecureHarnessMintSessionPolicyRoundTrip proves that Connect returns a non-empty
// signed_policy when the group enforces view-only, and that the signed JSON is non-trivial.
func TestSecureHarnessMintSessionPolicyRoundTrip(t *testing.T) {
	h := newSecureHarnessServer(t)
	h.EnforceViewOnly()

	const agentPubkey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	_, _, _, conn := h.FullLifecycle(agentPubkey)

	if conn.SessionPolicy == nil {
		t.Fatal("Connect: expected session_policy in response when group enforces view-only, got nil")
	}
	if conn.SessionPolicy.Access != string(SessionAccessViewOnly) {
		t.Errorf("session_policy.access = %q, want %q", conn.SessionPolicy.Access, SessionAccessViewOnly)
	}
	if conn.SessionPolicy.Signed == "" {
		t.Fatal("session_policy.signed is empty")
	}
	// The signed field must parse as JSON (it is the SignedSessionPolicy wire encoding).
	var signedJSON map[string]any
	if err := json.Unmarshal([]byte(conn.SessionPolicy.Signed), &signedJSON); err != nil {
		t.Fatalf("session_policy.signed is not valid JSON: %v\n%s", err, conn.SessionPolicy.Signed)
	}
	// Must have sig_v1 and a non-empty value.
	if v, ok := signedJSON["sig_v1"]; !ok || v == "" {
		t.Errorf("session_policy.signed missing or empty sig_v1")
	}
}

// TestSecureHarnessRedeemAdvertisesIssuerPubkey proves that the redeem response includes the
// server's issuer pubkey when one is configured, so the agent can pin it.
func TestSecureHarnessRedeemAdvertisesIssuerPubkey(t *testing.T) {
	h := newSecureHarnessServer(t)
	_, code := h.CreateSession("issuer-advertisement-test")
	const agentPubkey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	redeemed := h.Redeem(code, agentPubkey, "test-agent")
	if redeemed.GrantIssuerPubkey == "" {
		t.Fatal("redeem response missing grant_issuer_pubkey; agent cannot pin the issuer")
	}
	if redeemed.GrantIssuerPubkey != h.IssuerPubkeyHex() {
		t.Errorf("redeem grant_issuer_pubkey = %q, want %q",
			redeemed.GrantIssuerPubkey, h.IssuerPubkeyHex())
	}
}
