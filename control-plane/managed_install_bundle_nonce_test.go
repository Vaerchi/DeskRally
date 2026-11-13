package controlplane

// Tests for the attempt-nonce binding on GET /attended-sessions/installer (P2 fix).
//
// The race to prevent: technician issues promote (nonce A), guest's status poll returns nonce A,
// technician reissues while guest downloads (nonce B in DB now), guest's GET /installer carries
// nonce A → server reads session → nonce B ≠ A → 409. Guest's poller then sees nonce B (different
// token) and starts a fresh attempt, preventing a silent double-install.
//
// Without the fix: GET /installer sent no nonce, so the server packaged whichever token was
// current at GET time (B), guest installed B but posted nonce A → nonce mismatch at result →
// poller restarts with B → installs again.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newInstallerAttendedServer wires an attended server (in-memory store) with a real ManagedInstaller
// so that GET /attended-sessions/installer can succeed after a full promote lifecycle.
func newInstallerAttendedServer(t *testing.T) *Server {
	t.Helper()
	srv, _ := newAttendedServer(t)
	_, srv.ManagedInstaller = installerFixture(t)
	return srv
}

// installerSessionFixture builds a session through the full create → redeem → consent → promote
// lifecycle and returns the server, session ID, and guest attend token.
func installerSessionFixture(t *testing.T) (srv *Server, sessID, attendToken string) {
	t.Helper()
	srv = newInstallerAttendedServer(t)

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"nonce test"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	sessID = created.Session.ID

	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"PC"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	attendToken = redeemed.AttendToken

	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", attendToken,
		`{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("consent: status %d", code)
	}

	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+sessID+"/promote", "", nil); code != http.StatusOK {
		t.Fatalf("promote: status %d", code)
	}

	return srv, sessID, attendToken
}

// currentAttemptNonce reads the nonce from GET /attended-sessions/status for the given attend token.
func currentAttemptNonce(t *testing.T, srv *Server, attendToken string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/attended-sessions/status", nil)
	req.Header.Set("Authorization", "Bearer "+attendToken)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Promote *struct {
			AttemptNonce string `json:"attempt_nonce"`
		} `json:"promote"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("status parse: %v", err)
	}
	if resp.Promote == nil {
		t.Fatal("status: promote field absent — was promote stashed?")
	}
	return resp.Promote.AttemptNonce
}

// installerGET issues GET /attended-sessions/installer with the given attend token and optional
// attempt_nonce query parameter, returning the HTTP status code.
func installerGET(t *testing.T, srv *Server, attendToken, attemptNonce string) int {
	t.Helper()
	path := "/attended-sessions/installer"
	if attemptNonce != "" {
		path += "?attempt_nonce=" + attemptNonce
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+attendToken)
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// TestInstallBundleNoNonceIsBackwardsCompatible confirms that callers that do not send a nonce
// (e.g. old clients) still get 200 — the nonce check is opt-in (only applied when nonce ≠ "").
func TestInstallBundleNoNonceIsBackwardsCompatible(t *testing.T) {
	srv, _, attendToken := installerSessionFixture(t)
	if code := installerGET(t, srv, attendToken, ""); code != http.StatusOK {
		t.Errorf("no nonce: got %d, want 200 (backwards compatible)", code)
	}
}

// TestInstallBundleCorrectNonceSucceeds confirms that sending the nonce received in the status
// response results in 200 — the bundle is served when the attempt is still current.
func TestInstallBundleCorrectNonceSucceeds(t *testing.T) {
	srv, _, attendToken := installerSessionFixture(t)
	nonce := currentAttemptNonce(t, srv, attendToken)
	if nonce == "" {
		t.Fatal("status returned empty attempt_nonce — was SetPromoteToken called?")
	}
	if code := installerGET(t, srv, attendToken, nonce); code != http.StatusOK {
		t.Errorf("correct nonce: got %d, want 200", code)
	}
}

// TestInstallBundleWrongNonceRejected confirms that sending a nonce that does not match the
// current attempt is rejected with 409. This is the core of the P2 fix: a stale nonce from a
// previous (or concurrent) attempt cannot download the current attempt's token.
func TestInstallBundleWrongNonceRejected(t *testing.T) {
	srv, _, attendToken := installerSessionFixture(t)
	const wrongNonce = "0000000000000000000000000000000000000000000000000000000000000000"
	if code := installerGET(t, srv, attendToken, wrongNonce); code != http.StatusConflict {
		t.Errorf("wrong nonce: got %d, want 409", code)
	}
}

// TestInstallBundleStaleNonceAfterReissueRejected simulates the race: technician issues promote
// (nonce A), then reissues while guest download is pending (nonce B). The guest's GET with nonce
// A must be rejected so it does not install the new attempt's token under the old nonce.
//
// Sequential state manipulation proves the invariant without goroutines: calling POST /promote
// twice mints two different nonces, placing the store in the post-reissue state.
func TestInstallBundleStaleNonceAfterReissueRejected(t *testing.T) {
	srv, sessID, attendToken := installerSessionFixture(t)

	// Capture nonce A (from the first promote call in the fixture).
	nonceA := currentAttemptNonce(t, srv, attendToken)
	if nonceA == "" {
		t.Fatal("nonce A is empty after first promote")
	}

	// Technician reissues — mints nonce B.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+sessID+"/promote", "", nil); code != http.StatusOK {
		t.Fatalf("reissue promote: status %d", code)
	}
	nonceB := currentAttemptNonce(t, srv, attendToken)
	if nonceB == "" {
		t.Fatal("nonce B is empty after second promote")
	}
	if nonceA == nonceB {
		t.Fatal("nonce did not rotate on reissue — SetPromoteToken must mint a fresh nonce each time")
	}

	// Guest's GET with stale nonce A must be rejected.
	if code := installerGET(t, srv, attendToken, nonceA); code != http.StatusConflict {
		t.Errorf("stale nonce A after reissue: got %d, want 409", code)
	}

	// Guest's GET with current nonce B must succeed.
	if code := installerGET(t, srv, attendToken, nonceB); code != http.StatusOK {
		t.Errorf("current nonce B after reissue: got %d, want 200", code)
	}
}
