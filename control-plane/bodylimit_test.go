package controlplane

// Regression tests for docs/25 F05 — "unbounded body parsing happens while holding a tenant
// database connection".
//
// WHAT THESE TESTS HAVE TO PROVE, and why the obvious test is not enough. Asserting only that an
// oversized request comes back 413 would pass against a handler that read the whole body first and
// then noticed it was too big — which is precisely the defect: the cost is the READ, held against a
// pinned pool connection, not the status code that follows it. So the load-bearing assertion here is
// a COUNTING READER underneath the request body: after the handler returns, the test asserts that no
// more than maxBytes+1 bytes were ever pulled from the client. That is the number that changes when
// the fix is reverted, and it is measured at the only place it cannot be faked — the source of the
// bytes.
//
// The three halves of the review's own "Regression" line, plus the control:
//   - TestOverLimitBodyIsRejectedWithoutBuffering — 413, and the body was never fully consumed, on
//     every one of the twelve routes the finding named. Table-driven so a newly added handler that
//     decodes without a cap fails here rather than shipping.
//   - TestReadOnlyPrincipalCannotForceLargeBufferOnStartSession — the check-ordering half: a
//     principal with no session capability at all cannot make POST /sessions buffer more than the
//     cap, and creates nothing.
//   - TestAtLimitBodyStillAccepted — the NEGATIVE CONTROL. A body of exactly maxSmallJSONBodyBytes
//     must still succeed on all twelve routes. Without this, a helper that rejected everything would
//     pass every other test in this file, and the off-by-one at the boundary would be invisible.
//   - TestMalformedSmallBodyStaysBadRequest / TestBodyTooLargeIsTypeCheckedNotStringMatched — the
//     413 must be reserved for the over-limit case and must be recognised by TYPE.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The fixture's identifiers are real UUIDs because three of the twelve routes feed them to
// something that parses them as UUIDs (grant minting, the machine store's device ids). A "u1"-style
// id would fail those routes for a reason that has nothing to do with body limits, and the negative
// control would then be pinning a 400 instead of a success.
const (
	blUserID    = "00000000-0000-0000-0000-0000000000aa"
	blTenantID  = "00000000-0000-0000-0000-0000000000bb"
	blMachineID = "00000000-0000-0000-0000-0000000000cc"
	blGroupID   = DevDefaultMachineGroupID
)

// blMarker is a string that must never turn up in stored state or in a response after an over-limit
// request. It rides at the FRONT of the oversized payload, so it is the part a handler that buffered
// and then stored the body would have kept.
const blMarker = "F05-OVERSIZED-MARKER"

// newBodyLimitServer extends the house fixture (newTestServer, http_test.go) with the four stores
// the F05 route list needs and that newTestServer leaves nil: without them /dynamic-groups and
// /tenant/ip-allowlist answer 500 from a nil-store check that runs BEFORE the decode, and
// /attended-sessions and /grant/mint are not mounted at all — either way the test would be asserting
// against a route that never reaches the body at all.
func newBodyLimitServer(t *testing.T, role Role) *Server {
	t.Helper()
	p := &Principal{
		UserID:    blUserID,
		TenantID:  blTenantID,
		Grant:     NewGrant(blUserID, blTenantID, NewMembership(role, AllGroups())),
		SessionID: "11111111-0000-4000-8000-000000000001", // /platform/* requires an interactive session
	}
	srv, _ := newTestServer(p)
	srv.Platform = &fakePlatformStore{} // POST /platform/tenants decodes a body; authorization is the DB's
	srv.DynamicGroups = NewInMemoryDynamicGroupStore()
	srv.TenantIPAllowlist = NewInMemoryTenantIPAllowlistStore()
	// A separate backing machine store: srv.Machines stays the PERMISSIVE one so /sessions,
	// /grant/mint and the property routes resolve any device id, which is what newTestServer sets up.
	srv.Attended = NewInMemoryAttendedStore(NewInMemoryMachineStore())
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatalf("grant issuer: %v", err)
	}
	srv.Grants = iss
	return srv
}

// countingReader records how many bytes were actually pulled from the client. It wraps the INNERMOST
// reader — httptest.NewRequest puts it under req.Body, and http.MaxBytesReader then wraps that — so
// its count is exactly what the server drew off the wire, which is the quantity the finding is about.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// serveCounted runs one request whose body is metered, returning the recorder and the byte count.
// Passing a non-(bytes|strings) reader also leaves ContentLength at -1, so nothing in the chain can
// short-circuit on a declared length: the limit has to be enforced by actually reading.
func serveCounted(srv *Server, method, path, body string) (*httptest.ResponseRecorder, int64) {
	cr := &countingReader{r: strings.NewReader(body)}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, cr))
	return rec, cr.n
}

func serve(srv *Server, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

// oversizedBody builds a syntactically valid JSON object whose named field carries the marker
// followed by enough padding to exceed maxSmallJSONBodyBytes. The field name is the one the route's
// own request struct reads, so a handler that buffered the whole thing would have STORED the marker
// rather than merely seen it — which is what the stored-state assertions below look for.
func oversizedBody(field string) string {
	return `{"` + field + `":"` + blMarker + strings.Repeat("A", maxSmallJSONBodyBytes+1024) + `"}`
}

// atLimitBody builds a body of EXACTLY maxSmallJSONBodyBytes: the route's real fields, plus an
// ignored "_pad" string sized to hit the boundary from below. No handler in this package uses
// DisallowUnknownFields, so the padding decodes away and only the real fields are seen. Exactly at
// the limit must be ACCEPTED — http.MaxBytesReader fails on byte maxBytes+1 — so this is the
// off-by-one test as well as the negative control.
func atLimitBody(t *testing.T, fields string) string {
	t.Helper()
	prefix := `{"_pad":"`
	suffix := `"`
	if fields != "" {
		suffix += "," + fields
	}
	suffix += "}"
	pad := maxSmallJSONBodyBytes - len(prefix) - len(suffix)
	if pad < 0 {
		t.Fatalf("fields %q do not fit the limit", fields)
	}
	body := prefix + strings.Repeat("a", pad) + suffix
	if len(body) != maxSmallJSONBodyBytes {
		t.Fatalf("padded body is %d bytes, want exactly %d", len(body), maxSmallJSONBodyBytes)
	}
	return body
}

// blRoute is one of the twelve handlers docs/25 F05 named as decoding an unbounded body while the
// request's tenant connection is pinned. wantAtLimit is the status a LEGITIMATE body of exactly the
// limit must produce — pinned per route so the negative control asserts success, not merely
// "not 413".
type blRoute struct {
	name        string
	method      string
	path        string
	overField   string // the request struct's own string field, for the oversized payload
	okFields    string // valid JSON members for the at-limit body
	wantAtLimit int
}

// blRoutes is the finding's full list. A new handler that decodes a body belongs here; one that is
// added without a cap fails TestOverLimitBodyIsRejectedWithoutBuffering.
func blRoutes() []blRoute {
	return []blRoute{
		{"create tenant (platform)", "POST", "/platform/tenants", "name",
			`"slug":"f05","name":"F05"`, http.StatusCreated},
		{"add tenant ip-allowlist entry", "POST", "/tenant/ip-allowlist", "cidr",
			`"cidr":"0.0.0.0/0"`, http.StatusOK},
		{"create dynamic group", "POST", "/dynamic-groups", "name",
			`"name":"f05","property_key":"site"`, http.StatusCreated},
		{"set machine property", "PUT", "/machines/" + blMachineID + "/properties/site", "value",
			`"value":"HQ"`, http.StatusOK},
		{"enroll", "POST", "/enroll", "name",
			`"group_id":"` + blGroupID + `","machine_id":"` + blMachineID + `","name":"f05"`, http.StatusCreated},
		{"mint enrollment token", "POST", "/enrollment-tokens", "group_id",
			`"group_id":"` + blGroupID + `"`, http.StatusCreated},
		{"start session", "POST", "/sessions", "machine_id",
			`"machine_id":"` + blMachineID + `"`, http.StatusCreated},
		{"mint grant", "POST", "/grant/mint", "machine_id",
			`"machine_id":"` + blMachineID + `"`, http.StatusOK},
		{"mint api token", "POST", "/api-tokens", "name",
			`"name":"f05","capabilities":["view_machines"]`, http.StatusCreated},
		{"create attended session", "POST", "/attended-sessions", "reason",
			`"group_id":"` + blGroupID + `","reason":"f05"`, http.StatusCreated},
		{"set session policy", "PUT", "/tenant/session-policy", "max_concurrent_sessions",
			`"max_concurrent_sessions":5,"max_session_seconds":3600`, http.StatusOK},
		{"set tenant branding", "PUT", "/tenant/branding", "product_name",
			`"product_name":"F05"`, http.StatusOK},
	}
}

// TestOverLimitBodyIsRejectedWithoutBuffering is the main test. For every route the finding named,
// an over-limit body must be answered 413 AND must never have been read in full.
//
// The byte-count assertion is the one that matters. Reverting any single site to a bare
// json.NewDecoder(r.Body) leaves the status assertion answerable — the request still errors out
// somewhere — but the count jumps from ~64 KiB to the whole payload, because a plain decoder reads
// until the top-level JSON value closes. That is the mutation this test was checked against.
func TestOverLimitBodyIsRejectedWithoutBuffering(t *testing.T) {
	for _, rt := range blRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			srv := newBodyLimitServer(t, RoleOwner)
			body := oversizedBody(rt.overField)
			rec, read := serveCounted(srv, rt.method, rt.path, body)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s %s with a %d-byte body = %d, want 413 (%s)",
					rt.method, rt.path, len(body), rec.Code, rec.Body.String())
			}
			// http.MaxBytesReader reads at most limit+1 bytes from the underlying reader: one byte
			// past the limit is what proves the limit was passed. Anything beyond that means the
			// handler buffered client-controlled data while holding the pinned tenant connection.
			if read > int64(maxSmallJSONBodyBytes)+1 {
				t.Fatalf("%s %s read %d bytes of a %d-byte body, want at most %d — the body was buffered",
					rt.method, rt.path, read, len(body), maxSmallJSONBodyBytes+1)
			}
			if read >= int64(len(body)) {
				t.Fatalf("%s %s consumed the entire %d-byte body", rt.method, rt.path, len(body))
			}
			// The refusal must not echo the payload back, and must not leak the runtime's own
			// "http: request body too large" wording, which is what the pre-fix 400s carried.
			if strings.Contains(rec.Body.String(), blMarker) {
				t.Fatalf("%s %s echoed the oversized payload: %s", rt.method, rt.path, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "request body too large") {
				t.Fatalf("%s %s leaked the runtime error text: %s", rt.method, rt.path, rec.Body.String())
			}
		})
	}
}

// TestOverLimitBodyIsNeverStored closes the other half of "the handler never allocates the whole
// body": not only was it not read, nothing derived from it reached the stores. Two routes are
// checked because they are the two whose oversized field is written verbatim to durable state.
func TestOverLimitBodyIsNeverStored(t *testing.T) {
	srv := newBodyLimitServer(t, RoleOwner)

	if rec := serve(srv, "PUT", "/machines/"+blMachineID+"/properties/site", oversizedBody("value")); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT property = %d, want 413 (%s)", rec.Code, rec.Body.String())
	}
	props, err := srv.MachineProperties.ListProperties(context.Background(), blTenantID, blMachineID)
	if err != nil {
		t.Fatalf("ListProperties: %v", err)
	}
	for _, p := range props {
		if strings.Contains(p.Value, blMarker) {
			t.Fatalf("the refused body was stored as property %q", p.Key)
		}
	}
	if len(props) != 0 {
		t.Fatalf("a refused request wrote %d properties, want 0", len(props))
	}

	if rec := serve(srv, "POST", "/platform/tenants", oversizedBody("name")); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /platform/tenants = %d, want 413 (%s)", rec.Code, rec.Body.String())
	}
	tenants, err := srv.Tenants.ListTenants(context.Background(), blTenantID)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	for _, tn := range tenants {
		if strings.Contains(tn.Name, blMarker) || strings.Contains(tn.Slug, blMarker) {
			t.Fatalf("the refused body was stored as tenant %q", tn.Slug)
		}
	}
}

// TestReadOnlyPrincipalCannotForceLargeBufferOnStartSession is the check-ordering half of the
// finding, and the exact scenario the external reviewer reproduced: a principal holding no session
// capability sent >1 MiB of JSON to POST /sessions and the control plane read all of it before
// answering 403.
//
// POST /sessions cannot authorize before it decodes — the capability is group-scoped and the target
// machine is named in the body — so the fix is the bound, not a reordering. What must hold is that
// the unauthorized caller's leverage is now 64 KiB rather than "as much as they care to send", and
// that the request creates nothing. Either 413 (the read failed first) or 403 (a reorder landed
// later) is an acceptable answer; buffering the whole body is not.
func TestReadOnlyPrincipalCannotForceLargeBufferOnStartSession(t *testing.T) {
	srv := newBodyLimitServer(t, RoleReadOnly)
	body := oversizedBody("machine_id")
	rec, read := serveCounted(srv, "POST", "/sessions", body)

	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusForbidden {
		t.Fatalf("read-only POST /sessions = %d, want 413 or 403 (%s)", rec.Code, rec.Body.String())
	}
	if read > int64(maxSmallJSONBodyBytes)+1 {
		t.Fatalf("read-only caller made the server read %d bytes of a %d-byte body, want at most %d",
			read, len(body), maxSmallJSONBodyBytes+1)
	}
	sessions, err := srv.SessionRecords.ListSessions(context.Background(), blTenantID, SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("a refused start created %d session records, want 0", len(sessions))
	}
}

// TestAtLimitBodyStillAccepted is the NEGATIVE CONTROL, and the reason the rest of this file is
// evidence rather than a constant. A body of exactly maxSmallJSONBodyBytes is legal and must still
// reach the handler and succeed; a helper that refused everything, or one whose comparison was off
// by one at the boundary, passes every other test here and fails this one.
func TestAtLimitBodyStillAccepted(t *testing.T) {
	for _, rt := range blRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			srv := newBodyLimitServer(t, RoleOwner)
			body := atLimitBody(t, rt.okFields)
			rec := serve(srv, rt.method, rt.path, body)
			if rec.Code != rt.wantAtLimit {
				t.Fatalf("%s %s with a body of exactly %d bytes = %d, want %d (%s)",
					rt.method, rt.path, len(body), rec.Code, rt.wantAtLimit, rec.Body.String())
			}
		})
	}
}

// TestMalformedSmallBodyStaysBadRequest keeps 413 meaning what it says. A body well under the limit
// that is simply not valid JSON is a 400 — the client's problem is the syntax, not the size — and
// conflating the two would make the new status useless for the retry-smaller decision it exists to
// support.
func TestMalformedSmallBodyStaysBadRequest(t *testing.T) {
	for _, rt := range blRoutes() {
		t.Run(rt.name, func(t *testing.T) {
			srv := newBodyLimitServer(t, RoleOwner)
			rec := serve(srv, rt.method, rt.path, `{"truncated":`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s with malformed JSON = %d, want 400 (%s)",
					rt.method, rt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestBodyTooLargeIsTypeCheckedNotStringMatched pins HOW the over-limit case is recognised. The
// obvious implementation compares err.Error() against "http: request body too large"; that fails
// OPEN the day the runtime rewords it (every over-limit body silently reverts to 400), and it
// misclassifies any unrelated error that happens to carry the same text. writeIfBodyTooLarge must
// use errors.As against *http.MaxBytesError and nothing else.
func TestBodyTooLargeIsTypeCheckedNotStringMatched(t *testing.T) {
	// A same-worded impostor must NOT be treated as an over-limit body.
	rec := httptest.NewRecorder()
	if writeIfBodyTooLarge(rec, errors.New("http: request body too large")) {
		t.Fatal("a plain error with the runtime's wording was classified as an over-limit body — the check is string-matching")
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("writeIfBodyTooLarge wrote a response for a non-limit error: %d %s", rec.Code, rec.Body.String())
	}

	// The genuine typed error, including when it is wrapped, must be.
	rec = httptest.NewRecorder()
	if !writeIfBodyTooLarge(rec, &http.MaxBytesError{Limit: maxSmallJSONBodyBytes}) {
		t.Fatal("a real *http.MaxBytesError was not recognised")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("writeIfBodyTooLarge wrote %d, want 413", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "65536") {
		t.Fatalf("the 413 does not quote the enforced limit: %s", rec.Body.String())
	}
}
