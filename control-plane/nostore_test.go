package controlplane

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every JSON response must carry `Cache-Control: no-store` (docs/25 F10).
//
// This API answers with session tokens, signed session tickets, backstage grants, enrollment
// tokens, credential-setup links, API tokens and per-tenant fleet data. The header is set inside
// `writeJSON` rather than on the handlers that obviously need it, because a per-handler header
// covers only the ones somebody remembered and the next sensitive endpoint would be unprotected by
// default — the same reasoning that put the argon2 bound inside `VerifyPassword` rather than on
// `/auth/login`.
//
// So these tests assert the property AT THE CHOKE POINT, and then assert that the choke point is
// genuinely the only exit.

func TestWriteJSONSetsNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"session_token": "sensitive"})

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (the pre-existing behaviour must survive)", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// `no-store`, NOT `no-cache`. no-cache still permits a shared cache to STORE the response and only
// requires revalidation, which for a body containing a bearer token is the wrong half of the
// guarantee. Asserted explicitly so a later "tidy-up" to no-cache is a visible change.
func TestWriteJSONUsesNoStoreAndNotNoCache(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, struct{}{})
	if got := rec.Header().Get("Cache-Control"); got == "no-cache" {
		t.Fatalf("Cache-Control = %q; no-cache permits storing the response, which is not the guarantee wanted", got)
	}
}

// The error path carries the header too. An error body is not automatically harmless — a 403 from a
// token endpoint still tells a cache which token was rejected.
func TestErrorResponsesAlsoCarryNoStore(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(w http.ResponseWriter)
	}{
		{"writeError", func(w http.ResponseWriter) { writeError(w, http.StatusForbidden, "nope") }},
		{"writeJSON 500", func(w http.ResponseWriter) { writeJSON(w, http.StatusInternalServerError, struct{}{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.write(rec)
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

// THE ASSERTION THAT KEEPS THE CHOKE POINT A CHOKE POINT.
//
// Setting the header in one function is only worth anything if that function is the only exit. If a
// handler is later written with `w.Write([]byte(...))` or its own `json.NewEncoder(w).Encode(...)`,
// it bypasses this entirely and the test above still passes — the shape of a defence that exists at
// one call site and not its siblings.
//
// This walks the package's own source rather than trusting a comment about it. `nostore_test.go`
// itself is excluded, since it names those calls in order to forbid them.
func TestNoHandlerBypassesWriteJSON(t *testing.T) {
	offenders := findDirectBodyWriters(t)
	if len(offenders) > 0 {
		t.Errorf("these write a response body without going through writeJSON, so nothing guarantees "+
			"Cache-Control: no-store (docs/25 F10). Route them through writeJSON, or — if a raw body is "+
			"genuinely required, as the NDJSON audit exports are — set the header there and add the site "+
			"to knownRawBodyWriters in this file:\n  %s", joinLines(offenders))
	}
}

// Sites that legitimately write a raw body and therefore set `Cache-Control: no-store` themselves.
//
// The two NDJSON audit exports stream events one JSON object per line, which writeJSON cannot
// express. They were found BY this test rather than by reading the code: both bypassed writeJSON and
// so carried no no-store at all, while serving a tenant's audit trail — the exact "defence at one
// call site and not its siblings" shape. Each now sets the header next to its Content-Type.
//
// writeJSON's own encoder line is here because it IS the choke point.
//
// KEYED ON THE MATCHED LINE, NOT THE FILENAME, and that distinction is the whole value of the
// check. The first version allow-listed by file, which exempted the ENTIRE file — and `http.go` is
// thousands of lines holding most of the handlers, so a new `w.Write(...)` added there would have
// walked straight past the guard that exists to catch exactly that. Keying on the line means a new
// raw writer is caught wherever it appears, including in a file already on the list.
var knownRawBodyWriters = map[string]string{
	`_ = json.NewEncoder(w).Encode(v)`: "the writeJSON choke point itself",
	`enc := json.NewEncoder(w) // Encode appends the newline NDJSON wants`: "NDJSON audit exports " +
		"(http_backstage_audit.go, http_mgmtaudit.go); each sets no-store beside its Content-Type",
	`_ = json.NewEncoder(w).Encode(buildOpenAPIDocument(serverURL))`: "the public OpenAPI spec " +
		"(publicapi.go handlePublicAPISpec): compiled-in route metadata with NO tenant data, so it " +
		"deliberately sets Cache-Control: public, max-age=300 beside its Content-Type — the one site " +
		"here that is cacheable rather than no-store, which is correct for a data-free public document",
	// Central recording playback/download (docs/63 C8, http_recording_playback.go): streamed WebM / ZIP bodies
	// that writeJSON cannot express. Every recording route calls recNoStore (Cache-Control: private,
	// no-store) BEFORE it decides anything, including every refusal;
	// TestRecordingRoutesAreNoStoreAndTheRawWritersSayWhy pins that.
	`return d.w.Write(p)`: "recording stream/download progress-deadline writer (http_recording_playback.go deadlineWriter); " +
		"headers were set by recNoStore at the top of the route",
	`if _, err := dw.Write(chunk); err != nil {`: "recording stream, first chunk (http_recording_playback.go); private, no-store set by recNoStore",
	`if _, err := dw.Write(b); err != nil {`: "recording stream, later chunks (http_recording_playback.go); private, no-store set by recNoStore",
	`if _, err := mw.Write(mb); err != nil {`: "recording evidence ZIP manifest entry (http_recording_playback.go); private, no-store set by recNoStore",
	`_, _ = w.Write(resp.body)`: "the public branding routes (publicbranding.go writeBrandResponse): a prebuilt response whose " +
		"headers are set just above it, Cache-Control: no-store among them on EVERY outcome, neutral, published, 400 and 429",
	`_, _ = w.Write([]byte("ok"))`:        "GET /healthz (http_health.go): fixed plain-text liveness, no tenant data, sets no-store",
	`_, _ = w.Write([]byte("ready"))`:     "GET /readyz ready (http_health.go): fixed plain-text, no tenant data, sets no-store",
	`_, _ = w.Write([]byte("not ready"))`: "GET /readyz not-ready (http_health.go): fixed plain-text, no tenant data, sets no-store",
	"_, _ = io.WriteString(w, \"<!doctype html><html><head><meta charset=\\\"utf-8\\\"><title>Sign-in unsuccessful</title></head><body><p>\"+message+\"</p><a href=\\\"/console\\\">Return to sign-in</a></body></html>\")": "the SSO sign-in failure page (http_oidc.go oidcFailurePage): fixed HTML text, sets no-store, " +
		"no-referrer, a deny-all CSP and nosniff beside its Content-Type",
}

// findDirectBodyWriters greps the package's own non-test sources for a response body written without
// writeJSON. Reading the source is the point: a comment claiming "everything goes through writeJSON"
// is exactly the kind of statement that stops being true without anyone noticing.
func findDirectBodyWriters(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	// A response body reaching `w` by any route other than writeJSON.
	pattern := regexp.MustCompile(`w\.Write\(|json\.NewEncoder\(w\)|io\.WriteString\(w|fmt\.Fprint[a-zA-Z]*\(w`)

	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if !pattern.MatchString(line) {
				continue
			}
			if _, ok := knownRawBodyWriters[strings.TrimSpace(line)]; ok {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d: %s", name, i+1, strings.TrimSpace(line)))
		}
	}
	return out
}

func joinLines(s []string) string { return strings.Join(s, "\n  ") }

// The allow-list must not become a place things are quietly parked: every file in it has to still
// exist AND still contain a raw writer, or the entry is stale and is hiding the next one.
func TestKnownRawBodyWritersAreAllStillReal(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	present := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			present[strings.TrimSpace(line)] = true
		}
	}
	for line, why := range knownRawBodyWriters {
		if !present[line] {
			t.Errorf("allow-listed raw writer is no longer in the source, so the entry is stale and "+
				"will mask the next one that looks like it. Remove it.\n  line: %s\n  why:  %s", line, why)
		}
	}
}

// And the allow-listed raw writers must actually set the header they are trusted to set.
func TestAllowListedRawWritersSetNoStoreThemselves(t *testing.T) {
	for _, name := range []string{"http_backstage_audit.go", "http_mgmtaudit.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(b), `w.Header().Set("Cache-Control", "no-store")`) {
			t.Errorf("%s streams a raw body and is trusted to set Cache-Control: no-store itself, "+
				"but does not", name)
		}
	}
}
