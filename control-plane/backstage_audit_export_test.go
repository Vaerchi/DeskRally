package controlplane

// Tests for GET /audit/backstage/export — the read half of the H2 backstage trail.
//
// WHAT CARRIES WHICH GUARANTEE (the loop rule about premises): everything here runs against
// InMemoryAuditStore, so it pins the HANDLER and the ordering/cursor CONTRACT — status codes,
// capability gate, NDJSON framing, paging arithmetic, the exported field set. It cannot pin
// PERSISTENCE or RLS, because the fake is a map that returns whatever it was handed and has no
// notion of a tenant policy. Those live in TestPgBackstageAuditExportUnderRLS
// (audit_pgstore_test.go), which reads back through a real Postgres as the least-privilege app
// role. Both are needed: deleting a column from the pg projection leaves every test here green.

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// exportSessionA sorts ABOVE exportSessionB as a uuid. Tests seed A first, so ingest order (A
// then B) deliberately DISAGREES with (session_id, seq) order (B then A) — the only arrangement
// that can distinguish the two. With the sessions the other way round, a store that reverted to
// the old snapshot ordering passes every assertion here.
const (
	exportSessionA = "22222222-0000-0000-0000-000000000000" // ingested first, sorts second
	exportSessionB = "11111111-0000-0000-0000-000000000000" // ingested second, sorts first
)

// auditorPrincipal is a read-only auditor: CapViewAudit but NOT CapBackstageShell. Exporting must
// work for exactly this principal — an auditor who cannot read the trail is the whole point.
func auditorPrincipal() *Principal {
	return &Principal{
		UserID:   "u-aud",
		TenantID: "tenant-123",
		Grant:    NewGrant("u-aud", "tenant-123", NewMembership(RoleAuditor, AllGroups())),
	}
}

// seedChain names a session and how many events to append to it.
type seedChain struct {
	session string
	count   uint64
}

// seedChains appends the chains IN THE GIVEN ORDER and returns the server. The order is a slice,
// not a map, on purpose: the export pages in ingest order, and Go randomizes map iteration — a
// map here would make the expected output nondeterministic and the test flaky in a way that looks
// like an ordering bug in the code under test.
func seedChains(t *testing.T, p *Principal, tenantID string, chains []seedChain) *Server {
	t.Helper()
	srv, store := auditServer(p)
	for _, c := range chains {
		if _, err := store.AppendAudit(context.Background(), tenantID, c.session, chainRange(c.session, 0, c.count)); err != nil {
			t.Fatalf("seed %s: %v", c.session, err)
		}
	}
	return srv
}

// getExport issues the GET and returns the recorder.
func getExport(srv *Server, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit/backstage/export"+query, nil))
	return rec
}

// decodeNDJSON parses an NDJSON body into events, failing on any malformed line.
func decodeNDJSON(t *testing.T, body string) []AuditEvent {
	t.Helper()
	var out []AuditEvent
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			t.Fatalf("NDJSON must not contain blank lines; body:\n%s", body)
		}
		var e AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %q is not valid JSON: %v", line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestBackstageExportEmitsEveryChainInIngestOrder(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{
		{exportSessionA, 3},
		{exportSessionB, 2},
	})

	rec := getExport(srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson", ct)
	}
	if h := rec.Header().Get("X-Rmt-Next-After-Ingest-Seq"); h != "4" {
		t.Fatalf("cursor header = %q, want 4 (the last of 5 events, 0-based)", h)
	}
	got := decodeNDJSON(t, rec.Body.String())
	if len(got) != 5 {
		t.Fatalf("exported %d events, want 5", len(got))
	}
	// Ingest order: chain A was appended first, then B. Both chains START AT SEQ 0 — the property
	// that makes `seq` useless as a global cursor, which is why ingest_seq exists.
	want := []struct {
		session string
		seq     uint64
	}{
		{exportSessionA, 0}, {exportSessionA, 1}, {exportSessionA, 2},
		{exportSessionB, 0}, {exportSessionB, 1},
	}
	for i, w := range want {
		if got[i].SessionID != w.session || got[i].Seq != w.seq {
			t.Fatalf("event %d = (%s, %d), want (%s, %d)", i, got[i].SessionID, got[i].Seq, w.session, w.seq)
		}
	}
}

// THE REGRESSION TEST FOR THE DEFECT THAT CAUSED THIS REDESIGN.
//
// The first version of this export paged on `(session_id, seq)`. That is a valid total order over
// a snapshot, so every test passed — but it is not an APPEND order, and a collector that drained
// the trail and resumed from its cursor never again saw anything ingested under a LOWER-sorting
// session uuid. Since session ids are random v4 uuids, that is about half of everything ingested
// afterwards, lost silently.
//
// The direction is the entire point, so this test declares its OWN session ids rather than using
// the shared exportSessionA/B: an earlier version reused them, and when those constants were later
// flipped for an unrelated ordering test, this test silently began draining the LOWER-sorting
// session and appending a higher one — the arrangement the old code handles correctly. It kept
// passing while testing nothing. A regression test whose premise lives in another declaration is
// one edit away from being decorative.
func TestBackstageExportResumesAcrossLaterAppends(t *testing.T) {
	// drainedHigh is consumed FIRST and sorts LAST; laterLow arrives AFTER and sorts FIRST. Under
	// the old (session_id, seq) cursor, laterLow's events are forever below the stored cursor and
	// are never returned again.
	const drainedHigh = "ffffffff-0000-0000-0000-000000000000"
	const laterLow = "00000000-0000-0000-0000-000000000001"

	p := auditorPrincipal()
	srv, store := auditServer(p)
	ctx := context.Background()

	// A collector drains the trail: one chain, and it stores the cursor it was handed.
	if _, err := store.AppendAudit(ctx, "tenant-123", drainedHigh, chainRange(drainedHigh, 0, 2)); err != nil {
		t.Fatalf("seed drainedHigh: %v", err)
	}
	drained := getExport(srv, "")
	if n := len(decodeNDJSON(t, drained.Body.String())); n != 2 {
		t.Fatalf("first drain returned %d events, want 2", n)
	}
	cursor := drained.Header().Get("X-Rmt-Next-After-Ingest-Seq")
	if cursor == "" {
		t.Fatal("no cursor header on the first drain; a collector has nothing to resume from")
	}

	// Normal operation continues: the drained chain grows, AND a brand-new session starts whose
	// uuid sorts BELOW the one already consumed.
	if _, err := store.AppendAudit(ctx, "tenant-123", drainedHigh, chainRange(drainedHigh, 2, 1)); err != nil {
		t.Fatalf("extend drainedHigh: %v", err)
	}
	if _, err := store.AppendAudit(ctx, "tenant-123", laterLow, chainRange(laterLow, 0, 2)); err != nil {
		t.Fatalf("new lower-sorting session: %v", err)
	}

	resumed := decodeNDJSON(t, getExport(srv, "?after_ingest_seq="+cursor).Body.String())
	if len(resumed) != 3 {
		t.Fatalf("resumed export returned %d events, want 3 (drainedHigh seq 2, then laterLow seq 0 and 1) — "+
			"a cursor that is not an append order silently loses everything ingested below it", len(resumed))
	}
	if resumed[0].SessionID != drainedHigh || resumed[0].Seq != 2 {
		t.Fatalf("first resumed event = (%s,%d), want (%s,2)", resumed[0].SessionID, resumed[0].Seq, drainedHigh)
	}
	if resumed[1].SessionID != laterLow || resumed[2].SessionID != laterLow {
		t.Fatalf("the newly-created lower-sorting session was not exported: %+v", resumed)
	}
}

// The exported line must be exactly what the agent hashed, so a collector can re-verify it.
func TestBackstageExportLineIsTheHashableEvent(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{{exportSessionA, 1}})

	rec := getExport(srv, "")
	got := decodeNDJSON(t, rec.Body.String())
	if len(got) != 1 {
		t.Fatalf("exported %d events, want 1", len(got))
	}
	// Re-hash the exported event through the SAME canonical encoder the ingest path verifies with.
	// If export ever drops or rewrites a hashed field, this fails — which is the entire promise the
	// endpoint makes to a SIEM collector.
	h, err := recomputeHash(got[0])
	if err != nil {
		t.Fatalf("recomputeHash on the exported event: %v", err)
	}
	if h != got[0].Hash {
		t.Fatalf("exported event does not re-hash to its own hash: got %s, carried %s", h, got[0].Hash)
	}
	if got[0].PrevHash != GenesisPrevHash {
		t.Fatalf("seq 0 prev_hash = %q, want the genesis value", got[0].PrevHash)
	}
}

func TestBackstageExportSessionFilterAndPaging(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{
		{exportSessionA, 3},
		{exportSessionB, 2},
	})

	// Filter to one chain.
	got := decodeNDJSON(t, getExport(srv, "?session_id="+exportSessionB).Body.String())
	if len(got) != 2 {
		t.Fatalf("filtered export returned %d events, want 2", len(got))
	}
	for _, e := range got {
		if e.SessionID != exportSessionB {
			t.Fatalf("filter leaked session %s", e.SessionID)
		}
	}

	// Page the whole tenant one event at a time, following the cursor header exactly as a
	// collector would. The loop bound is 5x the expected count so a stuck cursor shows up as a
	// wrong total rather than as a hang.
	var paged []AuditEvent
	cursor := ""
	for i := 0; i < 25; i++ {
		q := "?limit=1"
		if cursor != "" {
			q += "&after_ingest_seq=" + cursor
		}
		rec := getExport(srv, q)
		page := decodeNDJSON(t, rec.Body.String())
		if len(page) == 0 {
			break
		}
		if len(page) != 1 {
			t.Fatalf("limit=1 returned %d events", len(page))
		}
		paged = append(paged, page[0])
		nextCursor := rec.Header().Get("X-Rmt-Next-After-Ingest-Seq")
		if nextCursor == cursor {
			t.Fatalf("cursor did not advance past %q — a collector would spin forever", cursor)
		}
		cursor = nextCursor
	}
	if len(paged) != 5 {
		t.Fatalf("paging one at a time yielded %d events, want 5", len(paged))
	}
	full := decodeNDJSON(t, getExport(srv, "").Body.String())
	for i := range full {
		if paged[i].SessionID != full[i].SessionID || paged[i].Seq != full[i].Seq {
			t.Fatalf("paged event %d = (%s,%d), unpaged = (%s,%d)",
				i, paged[i].SessionID, paged[i].Seq, full[i].SessionID, full[i].Seq)
		}
	}
}

// With no cursor at all the export must start BEFORE the tenant's first event. ingest_seq starts
// at 0, so the "beginning" cursor is -1; a handler that left it at Go's zero value would silently
// swallow ingest_seq 0 — the genesis event of the tenant's first chain, the one carrying the empty
// prev_hash that proves where the trail began.
func TestBackstageExportWithoutCursorIncludesTheFirstEvent(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{{exportSessionA, 2}})

	got := decodeNDJSON(t, getExport(srv, "").Body.String())
	if len(got) != 2 || got[0].Seq != 0 {
		t.Fatalf("got %d events starting at seq %d, want 2 starting at seq 0", len(got), seqOf(got))
	}
	if got[0].PrevHash != GenesisPrevHash {
		t.Fatalf("first exported event prev_hash = %q, want the genesis value", got[0].PrevHash)
	}
	// Explicitly asking for the start sentinel must be identical to omitting the parameter.
	same := decodeNDJSON(t, getExport(srv, "?after_ingest_seq=-1").Body.String())
	if len(same) != len(got) {
		t.Fatalf("after_ingest_seq=-1 returned %d events, omitted returned %d", len(same), len(got))
	}
}

// The tenant is taken from the authenticated principal, never from the query. Another tenant's
// chain must not appear even though the fake holds it.
func TestBackstageExportIsTenantScoped(t *testing.T) {
	p := auditorPrincipal()
	srv, store := auditServer(p)
	if _, err := store.AppendAudit(context.Background(), "tenant-123", exportSessionA, chainRange(exportSessionA, 0, 2)); err != nil {
		t.Fatalf("seed own tenant: %v", err)
	}
	if _, err := store.AppendAudit(context.Background(), "other-tenant", exportSessionB, chainRange(exportSessionB, 0, 2)); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	got := decodeNDJSON(t, getExport(srv, "").Body.String())
	if len(got) != 2 {
		t.Fatalf("exported %d events, want only this tenant's 2", len(got))
	}
	for _, e := range got {
		if e.SessionID != exportSessionA {
			t.Fatalf("cross-tenant leak: exported session %s", e.SessionID)
		}
	}
}

// A technician holds CapBackstageShell (they may WRITE the trail) but not CapViewAudit, and must
// not be able to read it back. This is the asymmetry the route comment describes.
func TestBackstageExportRequiresViewAuditCapability(t *testing.T) {
	srv := seedChains(t, technicianPrincipal(), "tenant-123", []seedChain{{exportSessionA, 1}})
	if rec := getExport(srv, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("technician export status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestBackstageExportRejectsMalformedParameters(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{{exportSessionA, 1}})

	cases := []struct {
		name  string
		query string
	}{
		{"session_id not a uuid", "?session_id=nope"},
		// The management export's parameter name, rejected rather than ignored.
		{"after_seq (the mgmt export's cursor)", "?after_seq=1"},
		{"after_ingest_seq not a number", "?after_ingest_seq=x"},
		{"after_ingest_seq below the start sentinel", "?after_ingest_seq=-2"},
		{"limit zero", "?limit=0"},
		{"limit negative", "?limit=-1"},
		{"limit above the cap", "?limit=999999"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rec := getExport(srv, c.query); rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// An empty trail is an empty body and a 200 — not a 404 and not a blank line, either of which
// would make a collector treat "nothing happened yet" as an error or as a malformed record.
func TestBackstageExportEmptyTrailIsAnEmptyBody(t *testing.T) {
	srv, _ := auditServer(auditorPrincipal())
	rec := getExport(srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
	// The cursor is still returned, echoing the start sentinel, so a collector that polls an idle
	// trail can store a cursor and resume from it instead of re-reading from the beginning.
	if h := rec.Header().Get("X-Rmt-Next-After-Ingest-Seq"); h != "-1" {
		t.Fatalf("empty-trail cursor = %q, want -1 (the caller's own cursor echoed back)", h)
	}
}

// An empty PAGE (caught up, but the trail is not empty) must echo the caller's own cursor back —
// not reset to the start, which would make the collector re-read the entire trail on every poll,
// and not advance, which would skip whatever arrives next. This is a documented contract in both
// stores and had no coverage until the review pointed that out.
func TestBackstageExportCaughtUpEchoesTheCursor(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{{exportSessionA, 2}})

	drained := getExport(srv, "")
	cursor := drained.Header().Get("X-Rmt-Next-After-Ingest-Seq")
	if cursor != "1" {
		t.Fatalf("cursor after draining 2 events = %q, want 1", cursor)
	}
	caughtUp := getExport(srv, "?after_ingest_seq="+cursor)
	if caughtUp.Body.Len() != 0 {
		t.Fatalf("caught-up page body = %q, want empty", caughtUp.Body.String())
	}
	if h := caughtUp.Header().Get("X-Rmt-Next-After-Ingest-Seq"); h != cursor {
		t.Fatalf("caught-up cursor = %q, want the caller's own %q echoed back", h, cursor)
	}
}

// The exported line must carry EXACTLY the AuditEvent's fields — no ingest_seq, no ingested_at, no
// row id. A collector re-hashes the line as it stands, so a control-plane field smuggled into the
// body would make it hash bytes the agent never hashed and report tampering on an intact trail.
// Decoding into AuditEvent cannot catch that (unknown keys are ignored), so this compares the raw
// JSON object's key set.
func TestBackstageExportLineHasNoExtraFields(t *testing.T) {
	srv := seedChains(t, auditorPrincipal(), "tenant-123", []seedChain{{exportSessionA, 1}})

	line := strings.TrimSpace(getExport(srv, "").Body.String())
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatalf("exported line is not a JSON object: %v", err)
	}
	want := map[string]bool{
		"id": true, "seq": true, "session_id": true, "technician_id": true, "machine_id": true,
		"occurred_at_unix_ms": true, "action": true, "outcome": true, "prev_hash": true, "hash": true,
	}
	for k := range raw {
		if !want[k] {
			t.Fatalf("exported line carries unexpected field %q — the body must be exactly the "+
				"hashed AuditEvent; cursor metadata belongs in the response header", k)
		}
	}
	for k := range want {
		if _, ok := raw[k]; !ok {
			t.Fatalf("exported line is missing hashed field %q", k)
		}
	}
}

// seqOf is a nil-safe accessor so a failure message can report the first seq without panicking on
// the empty slice the assertion is complaining about.
func seqOf(events []AuditEvent) uint64 {
	if len(events) == 0 {
		return 0
	}
	return events[0].Seq
}
