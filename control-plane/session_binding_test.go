package controlplane

// docs/69 §3.1: every brokered session carries `device_binding`. These pin the control-plane half: what
// is issued, when it is withheld, and that a malformed console key changes no state.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	bindTestTenant = "55555555-5555-4555-8555-555555555555"
	bindTestUser   = "66666666-6666-4666-8666-666666666666"
	bindTestDevice = "77777777-7777-4777-8777-777777777777"
)

func bindTestIssuer(t *testing.T) *GrantIssuer {
	t.Helper()
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, err := NewGrantIssuerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func bindTestDeviceKey() (string, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey)), priv
}

func TestAttachDeviceBindingIssuesAVerifiableGrant(t *testing.T) {
	iss := bindTestIssuer(t)
	srv := &Server{Grants: iss, BindingEnabled: true}
	deviceKey, _ := bindTestDeviceKey()
	resp := map[string]any{}
	if r := srv.attachDeviceBinding(resp, goldenSessionID, bindTestDevice, strings.ToUpper(deviceKey), bindTestUser,
		bindTestTenant, SessionAccessViewOnly, goldenBindConsolePubHex, 1_000); r != nil {
		t.Fatalf("refused: %+v", r)
	}
	b := resp["device_binding"].(map[string]any)
	if b["mode"] != "warn" || b["device_pubkey"] != deviceKey || b["unavailable"] != nil {
		t.Fatalf("binding = %+v", b)
	}
	var g SignedBindingGrant
	if err := json.Unmarshal([]byte(b["grant"].(string)), &g); err != nil {
		t.Fatal(err)
	}
	want := bindingGrantClaims{SessionID: goldenSessionID, DeviceID: bindTestDevice, TenantID: bindTestTenant,
		TechnicianID: bindTestUser, Access: SessionAccessViewOnly, ConsolePubkey: goldenBindConsolePubHex,
		IssuedAtMs: 1_000, ExpiresAtMs: 1_000 + bindingGrantTTL.Milliseconds()}
	if g.Claims != want {
		t.Fatalf("claims = %+v\nwant %+v", g.Claims, want)
	}
	msg, _ := bindingGrantSigningBytes(g.Claims)
	pub, _ := hex.DecodeString(iss.PublicKeyHex())
	sig, _ := hex.DecodeString(g.Sig)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the issued grant does not verify against the issuer key")
	}
}

func TestAttachDeviceBindingWithholdsInWarnAndRefusesInRequire(t *testing.T) {
	deviceKey, _ := bindTestDeviceKey()
	for _, tc := range []struct {
		name, deviceKey, consoleKey, tenant string
		reason                              string
	}{
		{"no console key", deviceKey, "", bindTestTenant, "console did not send a key"},
		{"machine has no key", "", goldenBindConsolePubHex, bindTestTenant, "machine has no enrolled device key"},
		{"machine key malformed", "00", goldenBindConsolePubHex, bindTestTenant, "machine has no enrolled device key"},
		{"grant cannot be minted", deviceKey, goldenBindConsolePubHex, "tenant-123", "grant could not be issued"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warn := &Server{Grants: bindTestIssuer(t), BindingEnabled: true}
			resp := map[string]any{}
			if r := warn.attachDeviceBinding(resp, goldenSessionID, bindTestDevice, tc.deviceKey, bindTestUser, tc.tenant,
				SessionAccessControl, tc.consoleKey, 1); r != nil {
				t.Fatalf("warn refused: %+v", r)
			}
			b := resp["device_binding"].(map[string]any)
			if b["unavailable"] != tc.reason || b["grant"] != nil || b["device_pubkey"] != nil {
				t.Fatalf("warn binding = %+v, want unavailable %q and no grant", b, tc.reason)
			}

			require := &Server{Grants: bindTestIssuer(t), BindingEnabled: true, BindingMode: func(string) SessionBindingMode { return SessionBindingRequire }}
			if r := require.attachDeviceBinding(map[string]any{}, goldenSessionID, bindTestDevice, tc.deviceKey, bindTestUser,
				tc.tenant, SessionAccessControl, tc.consoleKey, 1); r == nil {
				t.Fatal("require mode brokered a session it cannot bind")
			}
		})
	}
}

func TestSessionBindingModeFailsClosedOnAnUnknownValue(t *testing.T) {
	s := &Server{BindingMode: func(string) SessionBindingMode { return "" }}
	if got := s.sessionBindingMode(bindTestTenant); got != SessionBindingRequire {
		t.Fatalf("unknown mode read as %q, want require", got)
	}
	if got := (&Server{}).sessionBindingMode(bindTestTenant); got != SessionBindingWarn {
		t.Fatalf("unwired mode = %q, want warn (Ed 11-15)", got)
	}
}

// Over HTTP: POST /sessions answers with device_binding, and a malformed console key is refused with 400
// before any session record exists.
func TestStartSessionCarriesDeviceBinding(t *testing.T) {
	owner := &Principal{UserID: bindTestUser, TenantID: bindTestTenant,
		Grant: NewGrant(bindTestUser, bindTestTenant, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	srv.Grants = bindTestIssuer(t)
	srv.BindingEnabled = true
	start := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions", strings.NewReader(body)))
		return rec
	}

	rec := start(`{"machine_id":"22222222-2222-4222-8222-222222222222","console_pubkey":"` + goldenBindConsolePubHex + `"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		DeviceBinding map[string]any `json:"device_binding"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// The permissive dev store fabricates machines with no enrolled key: warn mode brokers, unbound.
	if out.DeviceBinding["mode"] != "warn" || out.DeviceBinding["unavailable"] != "machine has no enrolled device key" {
		t.Fatalf("device_binding = %+v", out.DeviceBinding)
	}

	before, _ := srv.SessionRecords.ListSessions(t.Context(), bindTestTenant, SessionSummaryFilter{})
	bad := start(`{"machine_id":"22222222-2222-4222-8222-222222222222","console_pubkey":"not-a-key"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("malformed console key = %d, want 400: %s", bad.Code, bad.Body.String())
	}
	after, _ := srv.SessionRecords.ListSessions(t.Context(), bindTestTenant, SessionSummaryFilter{})
	if len(after) != len(before) {
		t.Fatalf("a refused start created a session record (%d -> %d)", len(before), len(after))
	}
}

// POST /sessions/{id}/binding-failed: only the session's technician, only a known reason, audited.
func TestSessionBindingFailedIsAuditedForTheTechnicianOnly(t *testing.T) {
	ctx := t.Context()
	tech := &Principal{UserID: bindTestUser, TenantID: bindTestTenant,
		Grant: NewGrant(bindTestUser, bindTestTenant, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(tech)
	rec := &SessionRecord{MachineID: "m1", TechnicianID: bindTestUser, MachineGroupID: "group-a", MachineName: "HOST"}
	if err := srv.SessionRecords.StartSession(ctx, bindTestTenant, rec); err != nil {
		t.Fatal(err)
	}
	post := func(h http.Handler, id, body string) int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", "/sessions/"+id+"/binding-failed", strings.NewReader(body)))
		return rr.Code
	}
	if c := post(srv.Handler(), rec.ID, `{"reason":"something else"}`); c != http.StatusBadRequest {
		t.Fatalf("unknown reason = %d, want 400", c)
	}
	if c := post(srv.Handler(), "99999999-9999-4999-8999-999999999999", `{"reason":"bad_signature"}`); c != http.StatusNotFound {
		t.Fatalf("unknown session = %d, want 404", c)
	}
	other := &Principal{UserID: "88888888-8888-4888-8888-888888888888", TenantID: bindTestTenant,
		Grant: NewGrant("88888888-8888-4888-8888-888888888888", bindTestTenant, NewMembership(RoleOwner, AllGroups()))}
	srv.Auth = StubAuthenticator{Principal: other}
	if c := post(srv.Handler(), rec.ID, `{"reason":"bad_signature"}`); c != http.StatusForbidden {
		t.Fatalf("another user = %d, want 403", c)
	}
	srv.Auth = StubAuthenticator{Principal: tech}
	if c := post(srv.Handler(), rec.ID, `{"reason":"fingerprint_mismatch"}`); c != http.StatusOK {
		t.Fatalf("technician = %d, want 200", c)
	}
	events, err := srv.MgmtAudit.ListEvents(ctx, bindTestTenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == "session.binding_failed" {
			n++
			if e.TargetID != rec.ID || !strings.Contains(string(e.Metadata), `"reason":"fingerprint_mismatch"`) {
				t.Fatalf("audit event = %+v", e)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d session.binding_failed events, want exactly 1 (refused reports must not be recorded)", n)
	}
}

// docs/69 §3.7 step 2: an installed agent without a pinned key fetches it without any session.
func TestAgentGrantIssuerPubkeyIsPublic(t *testing.T) {
	srv, _ := newTestServer(nil)
	srv.Grants = bindTestIssuer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/agent/grant-issuer-pubkey", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out["grant_issuer_pubkey"] != srv.Grants.PublicKeyHex() {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

// docs/69 rollout: with binding OFF (the default until the answering agent ships) a start carries no
// device_binding at all, even when the console sent a key, so the console shows no mark and holds nothing.
func TestSessionBindingIsOffByDefault(t *testing.T) {
	srv := &Server{Grants: bindTestIssuer(t)}
	deviceKey, _ := bindTestDeviceKey()
	resp := map[string]any{}
	if r := srv.attachDeviceBinding(resp, goldenSessionID, bindTestDevice, deviceKey, bindTestUser, bindTestTenant,
		SessionAccessControl, goldenBindConsolePubHex, 1); r != nil {
		t.Fatalf("refused: %+v", r)
	}
	if _, present := resp["device_binding"]; present {
		t.Fatalf("binding is off but the response carries device_binding: %+v", resp)
	}
}
