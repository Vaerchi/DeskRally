package controlplane

// Tests for the malformed attend-token rejection added as partial F18 mitigation.
//
// Coverage contract:
//   - Both handleConsentAttended and handleStatusAttended reject impossible token shapes with 403
//     BEFORE touching the store (zero store calls, body not read for consent).
//   - Missing/empty Authorization header still produces 401 (existing behavior preserved).
//   - A valid-shaped token unknown to the store reaches the store exactly once (403 from DB, not
//     from the shape guard) — proving the guard does not over-reject.
//   - A real server-minted token (obtained via the full HTTP redeem surface) produces 200 on both
//     routes, proving the validator does not reject legitimately generated tokens.
//
// Limitations: this is PARTIAL F18. An attacker who generates correctly shaped 43-char base64url
// strings still reaches the database. Existing pool/deadline settings do not guarantee
// availability or fairness under saturation; no rate-limiter is added here.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// spyAttendedStore wraps an AttendedStore and counts calls to Consent and ByToken only.
// All other methods delegate unchanged to the inner store.
type spyAttendedStore struct {
	AttendedStore
	consentCalls int
	byTokenCalls int
}

func (s *spyAttendedStore) Consent(ctx context.Context, attendToken string, accept bool, consentUser string) (*AttendedSession, error) {
	s.consentCalls++
	return s.AttendedStore.Consent(ctx, attendToken, accept, consentUser)
}

func (s *spyAttendedStore) ByToken(ctx context.Context, attendToken string) (*AttendedSession, error) {
	s.byTokenCalls++
	return s.AttendedStore.ByToken(ctx, attendToken)
}

// readSpy is a body reader that counts Read calls. Wrapping a request body in this lets tests
// assert that the handler never consumed the body before returning.
type readSpy struct {
	r     io.Reader
	reads int
}

func (s *readSpy) Read(p []byte) (int, error) {
	s.reads++
	return s.r.Read(p)
}

// redeemAttendToken uses the full HTTP surface of srv to create an attended session and redeem
// it, returning the plaintext attend token. srv.Attended must be set before calling.
func redeemAttendToken(t *testing.T, srv *Server) string {
	t.Helper()
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"shape-test"}`, &created); code != http.StatusCreated {
		t.Fatalf("create attended: status %d", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"shape-guest"}`, &redeemed); code != http.StatusCreated {
		t.Fatalf("redeem attended: status %d", code)
	}
	if redeemed.AttendToken == "" {
		t.Fatal("redeem returned empty attend_token")
	}
	return redeemed.AttendToken
}

// malformedTokenCases lists tokens that must never reach the store on either route.
var malformedTokenCases = []struct {
	name  string
	token string
}{
	{"short_3", "abc"},
	{"short_42", strings.Repeat("a", 42)},
	{"oversize_44", strings.Repeat("a", 44)},
	{"oversize_100", strings.Repeat("a", 100)},
	{"inner_space", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaa"}, // 43 bytes with space
	{"padding_equals", strings.Repeat("a", 42) + "="},
	{"plus_sign", strings.Repeat("a", 42) + "+"},
	{"forward_slash", strings.Repeat("a", 42) + "/"},
	{"dot", strings.Repeat("a", 42) + "."},
	{"at_sign", strings.Repeat("a", 42) + "@"},
	{"non_ascii_0x80", strings.Repeat("a", 42) + "\x80"},
	// Unicode 'é' is two UTF-8 bytes → len = 43 bytes total; both bytes fail the ASCII guard.
	{"unicode_e_acute", strings.Repeat("a", 41) + "é"},
}

// --- handleConsentAttended ---

func TestConsentAttended_MissingOrEmptyBearer(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"no_header", ""},
		{"bearer_space_only", "Bearer "},
		{"bearer_whitespace", "Bearer   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newAttendedServer(t)
			spy := &spyAttendedStore{AttendedStore: srv.Attended}
			srv.Attended = spy

			req := httptest.NewRequest(http.MethodPost, "/attended-sessions/consent",
				strings.NewReader(`{"decision":"accept"}`))
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: got %d, want 401", tc.name, rec.Code)
			}
			if spy.consentCalls != 0 {
				t.Fatalf("%s: Consent called %d times, want 0", tc.name, spy.consentCalls)
			}
		})
	}
}

func TestConsentAttended_MalformedToken_Rejects403_NoStoreCall_NoBodyRead(t *testing.T) {
	for _, tc := range malformedTokenCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newAttendedServer(t)
			spy := &spyAttendedStore{AttendedStore: srv.Attended}
			srv.Attended = spy

			body := &readSpy{r: strings.NewReader(`{"decision":"accept","consent_user":"alice"}`)}
			req := httptest.NewRequest(http.MethodPost, "/attended-sessions/consent", body)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("token %q: got %d, want 403", tc.token, rec.Code)
			}
			if spy.consentCalls != 0 {
				t.Fatalf("token %q: Consent called %d times, want 0", tc.token, spy.consentCalls)
			}
			if body.reads != 0 {
				t.Fatalf("token %q: body was read %d times before shape rejection, want 0", tc.token, body.reads)
			}
		})
	}
}

func TestConsentAttended_ValidShapeUnknownToken_ReachesStoreOnce(t *testing.T) {
	srv, _ := newAttendedServer(t)
	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	// All-'a' 43-char string is a syntactically valid base64url token the store does not know.
	unknownToken := strings.Repeat("a", 43)
	req := httptest.NewRequest(http.MethodPost, "/attended-sessions/consent",
		strings.NewReader(`{"decision":"accept"}`))
	req.Header.Set("Authorization", "Bearer "+unknownToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 (invalid token from store)", rec.Code)
	}
	if spy.consentCalls != 1 {
		t.Fatalf("Consent called %d times, want 1", spy.consentCalls)
	}
}

func TestConsentAttended_RealToken_Succeeds(t *testing.T) {
	srv, _ := newAttendedServer(t)
	// Obtain a real token via the HTTP surface before installing the spy.
	realToken := redeemAttendToken(t, srv)

	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent",
		realToken, `{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("consent with real token: got %d, want 200", code)
	}
	if spy.consentCalls != 1 {
		t.Fatalf("Consent called %d times, want 1", spy.consentCalls)
	}
}

// --- handleStatusAttended ---

func TestStatusAttended_MissingOrEmptyBearer(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"no_header", ""},
		{"bearer_space_only", "Bearer "},
		{"bearer_whitespace", "Bearer   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newAttendedServer(t)
			spy := &spyAttendedStore{AttendedStore: srv.Attended}
			srv.Attended = spy

			req := httptest.NewRequest(http.MethodGet, "/attended-sessions/status", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: got %d, want 401", tc.name, rec.Code)
			}
			if spy.byTokenCalls != 0 {
				t.Fatalf("%s: ByToken called %d times, want 0", tc.name, spy.byTokenCalls)
			}
		})
	}
}

func TestStatusAttended_MalformedToken_Rejects403_NoStoreCall(t *testing.T) {
	for _, tc := range malformedTokenCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newAttendedServer(t)
			spy := &spyAttendedStore{AttendedStore: srv.Attended}
			srv.Attended = spy

			req := httptest.NewRequest(http.MethodGet, "/attended-sessions/status", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("token %q: got %d, want 403", tc.token, rec.Code)
			}
			if spy.byTokenCalls != 0 {
				t.Fatalf("token %q: ByToken called %d times, want 0", tc.token, spy.byTokenCalls)
			}
		})
	}
}

func TestStatusAttended_ValidShapeUnknownToken_ReachesStoreOnce(t *testing.T) {
	srv, _ := newAttendedServer(t)
	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	unknownToken := strings.Repeat("a", 43)
	req := httptest.NewRequest(http.MethodGet, "/attended-sessions/status", nil)
	req.Header.Set("Authorization", "Bearer "+unknownToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 (invalid token from store)", rec.Code)
	}
	if spy.byTokenCalls != 1 {
		t.Fatalf("ByToken called %d times, want 1", spy.byTokenCalls)
	}
}

func TestStatusAttended_RealToken_Succeeds(t *testing.T) {
	srv, _ := newAttendedServer(t)
	realToken := redeemAttendToken(t, srv)

	spy := &spyAttendedStore{AttendedStore: srv.Attended}
	srv.Attended = spy

	if code := apiJSONAuth(t, srv, "GET", "/attended-sessions/status",
		realToken, "", nil); code != http.StatusOK {
		t.Fatalf("status with real token: got %d, want 200", code)
	}
	if spy.byTokenCalls != 1 {
		t.Fatalf("ByToken called %d times, want 1", spy.byTokenCalls)
	}
}

// TestValidAttendTokenShape_Unit is a direct unit test of the validator.
func TestValidAttendTokenShape_Unit(t *testing.T) {
	valid := []string{
		strings.Repeat("a", 43),
		strings.Repeat("Z", 43),
		strings.Repeat("0", 43),
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_aaaaa", // 43 chars, mixed valid chars
	}
	for _, s := range valid {
		if !validAttendTokenShape(s) {
			t.Errorf("validAttendTokenShape(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("a", 42),
		strings.Repeat("a", 44),
		strings.Repeat("a", 42) + "=",
		strings.Repeat("a", 42) + "+",
		strings.Repeat("a", 42) + "/",
		strings.Repeat("a", 42) + " ",
		strings.Repeat("a", 42) + "\x00",
		strings.Repeat("a", 42) + "\x80",
	}
	for _, s := range invalid {
		if validAttendTokenShape(s) {
			t.Errorf("validAttendTokenShape(%q) = true, want false", s)
		}
	}
}
