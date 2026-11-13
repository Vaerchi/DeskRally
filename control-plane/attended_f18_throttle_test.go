package controlplane

// Tests for the F18 per-source throttle added to handleConsentAttended and handleStatusAttended.
//
// Coverage contract — four tests, two per endpoint:
//
//  1. Lockout test (kills M1 "Fail removed" and M2 "Allow removed"):
//     Send FreeAttempts+1 bad tokens from one IP; the (FreeAttempts+2)th call must be 429, and the
//     spy must prove the store was NOT called (throttle blocked it).
//     M1 (Fail removed): no lockout ever set → (FreeAttempts+2)th call gets 403 → test FAILS ✓
//     M2 (Allow removed): lockout set but check skipped → store called → 403 → test FAILS ✓
//
//  2. Reset test (kills M3 "Reset removed"):
//     Send 1 bad token (free attempt, no lockout yet), then 1 successful call (Reset clears the
//     counter), then 2 more bad tokens. With Reset, the counter restarts from 0 after the success
//     so the 2nd bad token is "free" and the 3rd sets the lockout but passes Allow itself → 403.
//     Without Reset, the 2nd bad token is the 2nd failure total → lockout set; the 3rd bad token's
//     Allow fires immediately → 429. Test asserts the 3rd bad token is 403, so the mutant FAILS ✓.
//
// Throttle profile: FreeAttempts=1 (1 free attempt before the 2nd failure sets a lockout). The
// BaseDelay is high enough that it cannot expire during a test without the clock being advanced.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tightThrottle returns a Throttle configured so only FreeAttempts=1 failed attempt is free; the
// second failure sets a long lockout that cannot expire during a test.
func tightThrottle() *Throttle {
	return NewThrottle(ThrottleConfig{
		FreeAttempts: 1,
		BaseDelay:    60 * time.Second,
		MaxDelay:     5 * time.Minute,
		Reset:        5 * time.Minute,
	})
}

// badConsentReq issues one POST /attended-sessions/consent with the given token and returns the
// response code. RemoteAddr is pinned explicitly so the throttle key is the same across all calls
// regardless of httptest defaults — the lockout tests depend on counter accumulation from one IP.
func badConsentReq(srv *Server, token string) int {
	req := httptest.NewRequest(http.MethodPost, "/attended-sessions/consent",
		strings.NewReader(`{"decision":"accept"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// badStatusReq issues one GET /attended-sessions/status with the given token and returns the code.
// RemoteAddr is pinned for the same reason as badConsentReq.
func badStatusReq(srv *Server, token string) int {
	req := httptest.NewRequest(http.MethodGet, "/attended-sessions/status", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// unknownToken is a syntactically valid 43-char base64url token the in-memory store will always
// reject as invalid.
const unknownToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// --- handleConsentAttended throttle tests ---

// TestConsentAttended_ThrottleLocksOutAfterRepeatGuesses verifies that once the per-source failure
// budget is exhausted the next attempt gets 429 without touching the backing store.
// Kills M1 (Fail removed → no lockout → 429 becomes 403) and M2 (Allow removed → store called →
// throttled-response not sent).
func TestConsentAttended_ThrottleLocksOutAfterRepeatGuesses(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Throttle = tightThrottle()

	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	// FreeAttempts=1: first bad token is free, second sets the lockout.
	if code := badConsentReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("attempt 1: got %d, want 403", code)
	}
	if code := badConsentReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("attempt 2: got %d, want 403", code)
	}
	// After 2 failures the lockout is live. The third attempt must be throttled before the store.
	if code := badConsentReq(srv, unknownToken); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3 (locked out): got %d, want 429", code)
	}
	// The store was called exactly for the two exhaust attempts; the throttled attempt must not have
	// reached it.
	if spy.consentCalls != 2 {
		t.Fatalf("Consent store calls: got %d, want 2 (throttled attempt must not reach store)",
			spy.consentCalls)
	}
}

// TestConsentAttended_SuccessResetsThrottleBudget verifies that a successful consent call clears
// the per-source failure counter so the same IP is not permanently locked out by prior guesses.
//
// Sequence (FreeAttempts=1):
//   - bad → 403 (free attempt, counter=1)
//   - good → 200 (Reset, counter=0)
//   - bad → 403 (counter=1, free again)
//   - bad → 403 (counter=2, lockout set inside handler but Allow already passed for THIS call)
//
// Without Reset: counter stays at 1 after the good call; the third bad token is failure #2 →
// lockout set after step 3; the FOURTH call's Allow fires and returns 429.
// Assert step 4 = 403 (with Reset) vs 429 (without Reset).
func TestConsentAttended_SuccessResetsThrottleBudget(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Throttle = tightThrottle()

	realToken := redeemAttendToken(t, srv)

	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	// Bad token: free attempt (counter=1, no lockout).
	if code := badConsentReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("step 1 (bad): got %d, want 403", code)
	}

	// Valid token: success — Reset must clear the counter to 0.
	// apiJSONAuth uses httptest.NewRequest which also defaults RemoteAddr to 192.0.2.1:1234,
	// matching badConsentReq, so the Reset fires against the same throttle key as the Fail calls.
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent",
		realToken, `{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("step 2 (good): got %d, want 200", code)
	}

	// After Reset, counter=0. Two bad tokens: first is free (counter=1), second sets lockout
	// (counter=2) but Allow passes for the call that sets the lock.
	if code := badConsentReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("step 3 (bad after reset): got %d, want 403", code)
	}
	// Without Reset, counter=1 after step 2; step 3 Fail makes it 2 → lockout set after step 3.
	// Step 4's Allow then fires → 429. With Reset, step 4 is the 2nd failure; Allow still passes
	// (lockout was not set before this call) → 403.
	if code := badConsentReq(srv, unknownToken); code != http.StatusForbidden {
		// Without Reset: lockout was set by step 3's Fail, so this call's Allow returns 429.
		t.Fatalf("step 4 (bad): got %d, want 403 (Reset must clear the counter so lockout is deferred)",
			code)
	}
}

// --- handleStatusAttended throttle tests ---

// TestStatusAttended_ThrottleLocksOutAfterRepeatGuesses verifies the same lockout behaviour on the
// status polling endpoint. Kills M1 and M2 for handleStatusAttended.
func TestStatusAttended_ThrottleLocksOutAfterRepeatGuesses(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Throttle = tightThrottle()

	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	if code := badStatusReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("attempt 1: got %d, want 403", code)
	}
	if code := badStatusReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("attempt 2: got %d, want 403", code)
	}
	if code := badStatusReq(srv, unknownToken); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3 (locked out): got %d, want 429", code)
	}
	if spy.byTokenCalls != 2 {
		t.Fatalf("ByToken store calls: got %d, want 2 (throttled attempt must not reach store)",
			spy.byTokenCalls)
	}
}

// TestStatusAttended_SuccessResetsThrottleBudget verifies that a successful status poll clears the
// per-source counter. Kills M3 for handleStatusAttended.
func TestStatusAttended_SuccessResetsThrottleBudget(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Throttle = tightThrottle()

	realToken := redeemAttendToken(t, srv)

	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	// Bad: free attempt (counter=1).
	if code := badStatusReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("step 1 (bad): got %d, want 403", code)
	}

	// Good: Reset clears counter to 0. Same RemoteAddr (192.0.2.1:1234 default) as badStatusReq.
	if code := apiJSONAuth(t, srv, "GET", "/attended-sessions/status", realToken, "", nil); code != http.StatusOK {
		t.Fatalf("step 2 (good): got %d, want 200", code)
	}

	// Two more bad tokens; step 4 must still pass Allow (403, not 429).
	if code := badStatusReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("step 3 (bad after reset): got %d, want 403", code)
	}
	if code := badStatusReq(srv, unknownToken); code != http.StatusForbidden {
		t.Fatalf("step 4 (bad): got %d, want 403 (Reset must clear the counter so lockout is deferred)",
			code)
	}
}
