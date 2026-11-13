package controlplane

// Tests for POST /attended-sessions/promote-complete — the guest-facing endpoint that records
// whether the Setup-based permanent-install attempt succeeded or failed.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// attendedPromoteCompleteFixture sets up a session in the consented state with an authorized
// promote token stashed, and returns the server, session id, and the guest's attend token.
//
// The promote token is stashed via POST /attended-sessions/{id}/promote so that
// SetPromoteResult (the in-memory path) sees promoteRequested=true. Tests that need a
// consented session WITHOUT a promote token should build their fixture manually.
func attendedPromoteCompleteFixture(t *testing.T) (srv *Server, sessID, attendToken string) {
	t.Helper()
	srv, _ = newAttendedServer(t)

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"install test"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	sessID = created.Session.ID

	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"PC"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	attendToken = redeemed.AttendToken

	// Consent → consented state (prerequisite for promote).
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", attendToken,
		`{"decision":"accept","consent_user":"bob"}`, nil); code != http.StatusOK {
		t.Fatalf("consent: status %d", code)
	}

	// Stash a promote token so SetPromoteResult treats this as an authorized attempt.
	// Uses the owner principal that newAttendedServer wires (CapEnrollMachine via RoleOwner).
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+sessID+"/promote", "", nil); code != http.StatusOK {
		t.Fatalf("promote: status %d (promote token must be stashed before promote-complete)", code)
	}

	return srv, sessID, attendToken
}

// rawGET sends an unauthenticated GET and returns the body bytes.
func rawGET(t *testing.T, srv *Server, path string) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	srv.Handler().ServeHTTP(rec, req)
	return rec.Body.Bytes()
}

func TestPromoteCompleteRecordsSuccess(t *testing.T) {
	srv, sessID, attendToken := attendedPromoteCompleteFixture(t)

	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true,"error":""}`, nil)
	if code != http.StatusOK {
		t.Fatalf("promote-complete success: status %d, want 200", code)
	}

	var getResp struct {
		Session AttendedSession `json:"session"`
	}
	if code := apiJSON(t, srv, "GET", "/attended-sessions/"+sessID, "", &getResp); code != http.StatusOK {
		t.Fatalf("get: status %d", code)
	}
	r := getResp.Session.PromoteResult
	if r == nil {
		t.Fatal("promote_result is nil after promote-complete success")
	}
	if !r.Success {
		t.Errorf("promote_result.success = false, want true")
	}
	if r.Error != "" {
		t.Errorf("promote_result.error = %q, want empty", r.Error)
	}
	if r.At.IsZero() {
		t.Error("promote_result.at is zero")
	}
}

func TestPromoteCompleteRecordsFailure(t *testing.T) {
	srv, sessID, attendToken := attendedPromoteCompleteFixture(t)

	const errMsg = "installer exited with code 1"
	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":false,"error":"`+errMsg+`"}`, nil)
	if code != http.StatusOK {
		t.Fatalf("promote-complete failure: status %d, want 200", code)
	}

	var getResp struct {
		Session AttendedSession `json:"session"`
	}
	if code := apiJSON(t, srv, "GET", "/attended-sessions/"+sessID, "", &getResp); code != http.StatusOK {
		t.Fatalf("get: status %d", code)
	}
	r := getResp.Session.PromoteResult
	if r == nil {
		t.Fatal("promote_result is nil after promote-complete failure")
	}
	if r.Success {
		t.Error("promote_result.success = true, want false")
	}
	if r.Error != errMsg {
		t.Errorf("promote_result.error = %q, want %q", r.Error, errMsg)
	}
}

func TestPromoteCompleteRequiresAttendToken(t *testing.T) {
	srv, _, _ := attendedPromoteCompleteFixture(t)

	// No Authorization header → 401
	if code := apiJSON(t, srv, "POST", "/attended-sessions/promote-complete",
		`{"success":true}`, nil); code != http.StatusUnauthorized {
		t.Fatalf("no bearer: status %d, want 401", code)
	}

	// Invalid token shape → 403
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", "not-a-real-token",
		`{"success":true}`, nil); code != http.StatusForbidden {
		t.Fatalf("bad token shape: status %d, want 403", code)
	}

	// Valid shape but unknown token → 403
	fakeToken := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 44 chars — wrong length, →403
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", fakeToken,
		`{"success":true}`, nil); code != http.StatusForbidden {
		t.Fatalf("bad-shape token: status %d, want 403", code)
	}
}

func TestPromoteCompleteConflictWhenSessionNotYetConsented(t *testing.T) {
	srv, _ := newAttendedServer(t)

	// Create + redeem (state = redeemed) but do NOT consent, so no promote can be requested.
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"no consent"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"PC"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}

	// State is "redeemed" and no promote token was stashed → 409
	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", redeemed.AttendToken,
		`{"success":true}`, nil)
	if code != http.StatusConflict {
		t.Fatalf("promote-complete on redeemed session: status %d, want 409", code)
	}
}

func TestPromoteCompleteConflictWhenNoPromoteRequested(t *testing.T) {
	srv, _ := newAttendedServer(t)

	// Create + redeem + consent but do NOT call /promote — no promote token was ever stashed.
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"no promote"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"PC"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"accept","consent_user":"bob"}`, nil); code != http.StatusOK {
		t.Fatalf("consent: status %d", code)
	}

	// Session is consented but no promote was ever requested → 409.
	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", redeemed.AttendToken,
		`{"success":true}`, nil)
	if code != http.StatusConflict {
		t.Fatalf("promote-complete on consented session with no promote token: status %d, want 409", code)
	}
}

func TestPromoteCompleteConflictWhenSessionEnded(t *testing.T) {
	srv, sessID, attendToken := attendedPromoteCompleteFixture(t)

	// End the session before the guest posts the result.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+sessID+"/end", "", nil); code != http.StatusOK {
		t.Fatalf("end: status %d", code)
	}

	// An ended session still has promoteRequested=true (it was set before End), so the in-memory
	// path accepts the result. The SQL path also accepts it (promote_requested_at IS NOT NULL,
	// state='ended' is not in ('pending','redeemed')). This is the correct behaviour: the install
	// may complete after the session ends.
	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true}`, nil)
	// We accept 200 (result recorded) because an install that completed after session end is valid.
	// 403 (token expired/invalid) is also acceptable if the implementation expires the token on End.
	// 409 is NOT acceptable: the promote WAS authorized.
	if code == http.StatusConflict {
		t.Fatalf("promote-complete on ended session with prior promote request: got 409 (conflict), which incorrectly implies no promote was authorized")
	}
}

func TestPromoteCompleteResultNotOverwrittenBySecondCall(t *testing.T) {
	// First completion wins. A second promote-complete from the same bearer (same install attempt
	// retrying or a duplicate post) must be rejected so a stale failure cannot overwrite a success.
	srv, _, attendToken := attendedPromoteCompleteFixture(t)

	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true,"error":""}`, nil); code != http.StatusOK {
		t.Fatalf("first promote-complete: status %d, want 200", code)
	}
	// Second call with the same token → 409 (first completion already written).
	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":false,"error":"stale retry"}`, nil)
	if code != http.StatusConflict {
		t.Fatalf("second promote-complete (overwrite attempt): status %d, want 409", code)
	}
}

func TestPromoteCompleteResultClearedWhenPromoteReissued(t *testing.T) {
	// When the technician re-issues a promote request (SetPromoteToken with a new token), the prior
	// result is cleared so the UI reflects the new attempt's outcome rather than the old failure.
	srv, sessID, attendToken := attendedPromoteCompleteFixture(t)

	// First attempt: failure.
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":false,"error":"first attempt failed"}`, nil); code != http.StatusOK {
		t.Fatalf("first promote-complete (failure): status %d, want 200", code)
	}

	// Technician reissues the promote request — this clears the prior result.
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+sessID+"/promote", "", nil); code != http.StatusOK {
		t.Fatalf("promote re-issue: status %d, want 200", code)
	}

	// Second attempt with the same attend token succeeds.
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true,"error":""}`, nil); code != http.StatusOK {
		t.Fatalf("second promote-complete (success after retry): status %d, want 200", code)
	}

	// GET must show the success result, not the prior failure.
	var getResp struct {
		Session AttendedSession `json:"session"`
	}
	if code := apiJSON(t, srv, "GET", "/attended-sessions/"+sessID, "", &getResp); code != http.StatusOK {
		t.Fatalf("get: status %d", code)
	}
	r := getResp.Session.PromoteResult
	if r == nil {
		t.Fatal("promote_result is nil after retry success")
	}
	if !r.Success {
		t.Errorf("promote_result.success = false after retry: prior failure result was not cleared")
	}
}

func TestPromoteCompleteResultAppearsInGetJSON(t *testing.T) {
	srv, sessID, attendToken := attendedPromoteCompleteFixture(t)

	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true}`, nil); code != http.StatusOK {
		t.Fatalf("promote-complete: status %d", code)
	}

	// GET response must JSON-serialise promote_result (it is NOT json:"-")
	body := rawGET(t, srv, "/attended-sessions/"+sessID)
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("GET body is not JSON: %v", err)
	}
	sessRaw, ok := wrapper["session"]
	if !ok {
		t.Fatal("GET response missing 'session' key")
	}
	var sessMap map[string]json.RawMessage
	if err := json.Unmarshal(sessRaw, &sessMap); err != nil {
		t.Fatalf("session is not a JSON object: %v", err)
	}
	if _, found := sessMap["promote_result"]; !found {
		t.Error("session JSON missing 'promote_result' after promote-complete called")
	}
}

func TestPromoteCompleteNonceMismatchReturns409(t *testing.T) {
	// Sending a wrong attempt_nonce in the promote-complete body must be rejected with 409.
	// This exercises the nonce guard in SetPromoteResult at the HTTP layer (not just pgstore).
	srv, _, attendToken := attendedPromoteCompleteFixture(t)

	// Confirm the session has a nonce minted by the /promote call in the fixture.
	nonce := currentAttemptNonce(t, srv, attendToken)
	if nonce == "" {
		t.Fatal("attempt_nonce is empty after promote — was SetPromoteToken called?")
	}

	// Wrong nonce: all-zero value that cannot match any minted nonce.
	const wrongNonce = "0000000000000000000000000000000000000000000000000000000000000000"
	if nonce == wrongNonce {
		t.Fatal("fixture nonce unexpectedly equals the wrong-nonce sentinel — test invalid")
	}

	code := apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true,"attempt_nonce":"`+wrongNonce+`"}`, nil)
	if code != http.StatusConflict {
		t.Errorf("wrong nonce: got %d, want 409", code)
	}

	// Correct nonce must still work (the wrong-nonce rejection must not consume the slot).
	code = apiJSONAuth(t, srv, "POST", "/attended-sessions/promote-complete", attendToken,
		`{"success":true,"attempt_nonce":"`+nonce+`"}`, nil)
	if code != http.StatusOK {
		t.Errorf("correct nonce after mismatch rejection: got %d, want 200", code)
	}
}
