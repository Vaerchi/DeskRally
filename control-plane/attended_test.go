package controlplane

// Handler-level tests for attended (on-demand) sessions over the in-memory stores (no DB). These
// exercise the CONSENT GATE end to end: a ticket is unobtainable until the guest reports consent.
// The pgx twin (attended_pgstore_test.go) proves the same against the SECURITY DEFINER functions.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newAttendedServer wires an owner-principal server with the attended store, its backing machine
// store, and a grant issuer (so /connect can mint a real RMTTICKETv1).
func newAttendedServer(t *testing.T) (*Server, *InMemoryMachineStore) {
	t.Helper()
	p := &Principal{
		UserID:   "00000000-0000-0000-0000-0000000000aa",
		TenantID: "00000000-0000-0000-0000-0000000000bb",
		Grant: NewGrant("00000000-0000-0000-0000-0000000000aa", "00000000-0000-0000-0000-0000000000bb",
			NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	machines := NewInMemoryMachineStore()
	srv.Machines = machines
	srv.SessionRecords = NewInMemorySessionRecordStore()
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	srv.EnrollmentTokens = NewInMemoryEnrollmentTokenStore()
	srv.Attended = NewInMemoryAttendedStore(machines)
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv.Grants = iss
	return srv, machines
}

// apiJSONAuth is apiJSON with a Bearer attend token (the guest's credential).
func apiJSONAuth(t *testing.T, srv *Server, method, path, bearer, body string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	srv.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: bad JSON %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code
}

const attendTestPubkey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
const attendTestGroup = "00000000-0000-0000-0000-0000000000cc"

type attendedCreateResp struct {
	Session  AttendedSession `json:"session"`
	Code     string          `json:"code"`
	JoinCode string          `json:"join_code"`
	JoinURL  string          `json:"join_url"`
}
type attendedRedeemResp struct {
	DeviceID     string `json:"device_id"`
	TenantID     string `json:"tenant_id"`
	SignalingURL string `json:"signaling_url"`
	AttendToken  string `json:"attend_token"`
}
type attendedConnectResp struct {
	Signaling struct {
		URL       string              `json:"url"`
		DeviceID  string              `json:"device_id"`
		SessionID string              `json:"session_id"`
		Ticket    SignedSessionTicket `json:"ticket"`
	} `json:"signaling"`
}

// TestAttendedConsentGate is the load-bearing test: no ticket before consent, a valid ticket after.
func TestAttendedConsentGate(t *testing.T) {
	srv, _ := newAttendedServer(t)

	// 1. Technician creates the session → a one-time code.
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	if created.Session.ID == "" || created.JoinCode == "" || created.Session.State != AttendedPending {
		t.Fatalf("unexpected create response: %+v", created)
	}
	id := created.Session.ID

	// 2. Connect BEFORE redemption → refused (409, awaiting consent).
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+id+"/connect", "", nil); code != http.StatusConflict {
		t.Fatalf("connect before redeem: status %d, want 409", code)
	}

	// 3. Guest redeems the code → ephemeral identity + attend token.
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if redeemed.DeviceID == "" || redeemed.AttendToken == "" {
		t.Fatalf("redeem response missing fields: %+v", redeemed)
	}

	// 4. Connect AFTER redeem but BEFORE consent → still refused.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+id+"/connect", "", nil); code != http.StatusConflict {
		t.Fatalf("connect before consent: status %d, want 409", code)
	}

	// 5. Guest consents (authenticated by its attend token).
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("consent: status %d", code)
	}

	// 6. NOW connect succeeds and returns a ticket bound to the ephemeral device.
	var conn attendedConnectResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+id+"/connect", "", &conn); code != http.StatusOK {
		t.Fatalf("connect after consent: status %d", code)
	}
	if conn.Signaling.Ticket.Claims.DeviceID != redeemed.DeviceID {
		t.Fatalf("ticket device %q != redeemed device %q", conn.Signaling.Ticket.Claims.DeviceID, redeemed.DeviceID)
	}
	if conn.Signaling.Ticket.Sig == "" {
		t.Fatal("ticket carries no signature")
	}
	// The ticket must actually verify against the issuer key (it is what signaling checks).
	iss, _ := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	pub, _ := hex.DecodeString(iss.PublicKeyHex())
	sig, _ := hex.DecodeString(conn.Signaling.Ticket.Sig)
	if !ed25519.Verify(pub, ticketSigningBytes(conn.Signaling.Ticket.Claims), sig) {
		t.Fatal("connect ticket does not verify against the grant issuer key")
	}
}

func TestAttendedDeclineBlocksConnect(t *testing.T) {
	srv, _ := newAttendedServer(t)
	var created attendedCreateResp
	apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created)
	var redeemed attendedRedeemResp
	apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, &redeemed)
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"decline"}`, nil); code != http.StatusOK {
		t.Fatalf("decline: status %d", code)
	}
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/connect", "", nil); code == http.StatusOK {
		t.Fatal("connect must NOT succeed after decline")
	}
}

func TestAttendedRedeemGenericErrors(t *testing.T) {
	srv, _ := newAttendedServer(t)
	var created attendedCreateResp
	apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created)

	// A bad code → generic 403.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"ZZZZZZZZZZZZ","pubkey":"`+attendTestPubkey+`"}`, nil); code != http.StatusForbidden {
		t.Fatalf("bad code: status %d, want 403", code)
	}
	// Redeeming the real code once works…
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, nil); code != http.StatusCreated {
		t.Fatalf("first redeem: status %d", code)
	}
	// …and a SECOND redemption of the same code is refused (single use).
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, nil); code != http.StatusForbidden {
		t.Fatalf("second redeem: status %d, want 403", code)
	}
	// A malformed pubkey is a 400 before any code check.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"nothex"}`, nil); code != http.StatusBadRequest {
		t.Fatalf("bad pubkey: status %d, want 400", code)
	}
}

// TestAttendedEphemeralIdentity proves the guest's ephemeral key is resolvable by the identity
// lookup (so signaling can authenticate it) while live, hidden from the fleet listing, and refused
// once expired.
func TestAttendedEphemeralIdentity(t *testing.T) {
	srv, machines := newAttendedServer(t)
	var created attendedCreateResp
	apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created)
	var redeemed attendedRedeemResp
	apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, &redeemed)

	// Resolvable while live.
	id, err := machines.LookupDeviceIdentity(context.Background(), redeemed.DeviceID)
	if err != nil || id.Pubkey != attendTestPubkey {
		t.Fatalf("ephemeral identity not resolvable: id=%+v err=%v", id, err)
	}
	// Hidden from the fleet listing.
	all, _ := machines.ListMachines(context.Background(), redeemed.TenantID)
	for _, m := range all {
		if m.DeviceID == redeemed.DeviceID {
			t.Fatal("ephemeral machine must not appear in ListMachines")
		}
	}
}

func TestAttendedEphemeralExpiryRefused(t *testing.T) {
	srv, machines := newAttendedServer(t)
	// Backdate the attended store's clock so the ephemeral machine's expires_at is already past.
	srv.Attended.(*InMemoryAttendedStore).Now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	var created attendedCreateResp
	// Create uses the backdated clock for expires_at too, but the code is redeemed immediately below
	// under the same clock, so it is still "pending & unexpired" relative to that clock.
	apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created)
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem under backdated clock: status %d", code)
	}
	// The machine's expires_at = (now-2h)+30m, which is in the past relative to real now, so identity
	// resolution (which uses real time) must refuse it.
	if _, err := machines.LookupDeviceIdentity(context.Background(), redeemed.DeviceID); err == nil {
		t.Fatal("expired ephemeral machine must NOT resolve an identity")
	}
}

func TestAttendedPromoteStashesEnrollmentToken(t *testing.T) {
	srv, _ := newAttendedServer(t)
	var created attendedCreateResp
	apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created)
	var redeemed attendedRedeemResp
	apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, &redeemed)
	apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken, `{"decision":"accept"}`, nil)

	// Before promote, status carries no promote payload.
	var before map[string]any
	apiJSONAuth(t, srv, "GET", "/attended-sessions/status", redeemed.AttendToken, "", &before)
	if _, ok := before["promote"]; ok {
		t.Fatal("status should not carry promote before /promote")
	}
	// Promote → the guest's next status poll carries an enrollment token to redeem.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/promote", "", nil); code != http.StatusOK {
		t.Fatalf("promote: status %d", code)
	}
	var after struct {
		State   string `json:"state"`
		Promote *struct {
			EnrollmentToken string `json:"enrollment_token"`
		} `json:"promote"`
	}
	apiJSONAuth(t, srv, "GET", "/attended-sessions/status", redeemed.AttendToken, "", &after)
	if after.Promote == nil || after.Promote.EnrollmentToken == "" {
		t.Fatalf("status after promote missing enrollment token: %+v", after)
	}
}

// Security audit 2026-10-18: a connect by a peer technician (recovering a closed creator tab) is a
// HANDOFF. The session's technician becomes the connecting one — so the agent-signed audit trail of
// what they then do is accepted — and the takeover is on the management audit record. A connect by
// the creator records no handoff (negative control).
func TestAttendedConnectByAPeerIsARecordedHandoff(t *testing.T) {
	for _, peer := range []bool{false, true} {
		srv, _ := newAttendedServer(t)
		var created attendedCreateResp
		apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created)
		const creator = "00000000-0000-0000-0000-0000000000cc"
		store := srv.Attended.(*InMemoryAttendedStore)
		if peer {
			store.mu.Lock()
			store.sessions[created.Session.ID].TechnicianID = creator
			store.mu.Unlock()
		}
		var redeemed attendedRedeemResp
		apiJSON(t, srv, "POST", "/attended-sessions/redeem",
			`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`"}`, &redeemed)
		if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
			`{"decision":"accept"}`, nil); code != http.StatusOK {
			t.Fatalf("consent: status %d", code)
		}
		if code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/connect", "", nil); code != http.StatusOK {
			t.Fatalf("connect: status %d", code)
		}
		got, err := srv.Attended.Get(t.Context(), attendTestTenant, created.Session.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.TechnicianID != "00000000-0000-0000-0000-0000000000aa" {
			t.Fatalf("peer=%v: technician after connect = %q, want the connecting technician", peer, got.TechnicianID)
		}
		from, recorded := connectAuditMeta(t, srv)["handoff_from_technician_id"]
		if peer && (!recorded || from != creator) {
			t.Fatalf("handoff not recorded: %v", from)
		}
		if !peer && recorded {
			t.Fatalf("creator's own connect recorded a handoff from %v", from)
		}
	}
}

