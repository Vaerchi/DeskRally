package controlplane

// Tests for the hash-chained management audit (0014): chain assignment, tamper detection,
// metadata canonicalization, the pinned canonical-preimage vector, and the SIEM export /
// verify endpoints. The pgx twin lives in dataplane_pgstore_test.go.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMgmtAuditChainAssignsLinks(t *testing.T) {
	store := NewInMemoryMgmtAuditStore()
	ctx := context.Background()

	a1 := &MgmtAuditEvent{Action: "machine.enroll", TargetKind: "machine", TargetID: newUUID()}
	a2 := &MgmtAuditEvent{Action: "session.start", Metadata: json.RawMessage(`{"k":"v"}`)}
	b1 := &MgmtAuditEvent{Action: "tenant.create"}
	for _, rec := range []struct {
		tenant string
		e      *MgmtAuditEvent
	}{{"tenant-a", a1}, {"tenant-a", a2}, {"tenant-b", b1}} {
		if err := store.RecordEvent(ctx, rec.tenant, rec.e); err != nil {
			t.Fatalf("RecordEvent(%s): %v", rec.e.Action, err)
		}
	}

	// Chains are per tenant: a starts 0,1; b starts over at 0.
	for _, tc := range []struct {
		e        *MgmtAuditEvent
		wantSeq  int64
		wantPrev string
	}{{a1, 0, MgmtGenesisPrevHash}, {a2, 1, a1.Hash}, {b1, 0, MgmtGenesisPrevHash}} {
		if tc.e.Seq == nil || *tc.e.Seq != tc.wantSeq {
			t.Fatalf("%s seq = %v, want %d", tc.e.Action, tc.e.Seq, tc.wantSeq)
		}
		if tc.e.PrevHash != tc.wantPrev {
			t.Fatalf("%s prev_hash = %q, want %q", tc.e.Action, tc.e.PrevHash, tc.wantPrev)
		}
		if !isHex64(tc.e.Hash) {
			t.Fatalf("%s hash = %q, not 64-hex", tc.e.Action, tc.e.Hash)
		}
		if tc.e.ID == "" || tc.e.OccurredAt.IsZero() {
			t.Fatalf("%s missing id/occurred_at: %+v", tc.e.Action, tc.e)
		}
		// The ms truncation contract: what was hashed is exactly what a timestamptz stores.
		if !tc.e.OccurredAt.Equal(tc.e.OccurredAt.Truncate(time.Millisecond)) {
			t.Fatalf("%s occurred_at not ms-truncated: %v", tc.e.Action, tc.e.OccurredAt)
		}
	}

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		res, err := VerifyMgmtAuditChain(ctx, store, tenant)
		if err != nil || !res.OK {
			t.Fatalf("verify %s = %+v (%v), want OK", tenant, res, err)
		}
	}
	resA, _ := VerifyMgmtAuditChain(ctx, store, "tenant-a")
	if resA.CheckedEvents != 2 {
		t.Fatalf("tenant-a checked = %d, want 2", resA.CheckedEvents)
	}
}

func TestMgmtAuditChainDetectsTamper(t *testing.T) {
	ctx := context.Background()
	seed := func(t *testing.T) *InMemoryMgmtAuditStore {
		t.Helper()
		store := NewInMemoryMgmtAuditStore()
		for _, action := range []string{"machine.enroll", "session.start", "session.end"} {
			if err := store.RecordEvent(ctx, "tenant-a", &MgmtAuditEvent{Action: action}); err != nil {
				t.Fatalf("seed %s: %v", action, err)
			}
		}
		return store
	}

	t.Run("field edit is caught by content re-hash", func(t *testing.T) {
		store := seed(t)
		if !store.tamperEvent("tenant-a", 1, func(e *MgmtAuditEvent) { e.Action = "session.start.forged" }) {
			t.Fatal("tamper target not found")
		}
		res, err := VerifyMgmtAuditChain(ctx, store, "tenant-a")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.OK || res.FirstBadSeq == nil || *res.FirstBadSeq != 1 ||
			!strings.Contains(res.Reason, "content hash") {
			t.Fatalf("verify after edit = %+v, want !OK at seq 1 (content hash)", res)
		}
	})

	t.Run("deleted middle link is a seq gap", func(t *testing.T) {
		store := seed(t)
		if !store.dropEvent("tenant-a", 1) {
			t.Fatal("drop target not found")
		}
		res, err := VerifyMgmtAuditChain(ctx, store, "tenant-a")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.OK || res.FirstBadSeq == nil || *res.FirstBadSeq != 2 ||
			!strings.Contains(res.Reason, "seq gap") {
			t.Fatalf("verify after delete = %+v, want !OK at seq 2 (seq gap)", res)
		}
	})

	t.Run("deleted genesis is a seq gap at 0", func(t *testing.T) {
		store := seed(t)
		if !store.dropEvent("tenant-a", 0) {
			t.Fatal("drop target not found")
		}
		res, err := VerifyMgmtAuditChain(ctx, store, "tenant-a")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.OK || res.FirstBadSeq == nil || *res.FirstBadSeq != 1 {
			t.Fatalf("verify after genesis delete = %+v, want !OK at seq 1", res)
		}
	})

	t.Run("pointer-consistent edit still caught", func(t *testing.T) {
		// Re-stamp the edited event's hash so its own pointer looks right; the NEXT event's
		// prev_hash then no longer matches — linkage break at seq 2.
		store := seed(t)
		if !store.tamperEvent("tenant-a", 1, func(e *MgmtAuditEvent) {
			e.Action = "session.start.forged"
			h, err := recomputeMgmtAuditHash(*e)
			if err != nil {
				t.Fatalf("re-hash forged event: %v", err)
			}
			e.Hash = h
		}) {
			t.Fatal("tamper target not found")
		}
		res, err := VerifyMgmtAuditChain(ctx, store, "tenant-a")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.OK || res.FirstBadSeq == nil || *res.FirstBadSeq != 2 ||
			!strings.Contains(res.Reason, "broken link") {
			t.Fatalf("verify after re-stamped edit = %+v, want !OK at seq 2 (broken link)", res)
		}
	})
}

// The hash must be a function of the metadata VALUE, not its spelling — Postgres jsonb does not
// preserve key order or whitespace, so a spelling-sensitive hash would report false tampers.
func TestMgmtAuditMetadataCanonicalization(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{`{"b": 2, "a": 1}`, `{"a":1,"b":2}`},
		{"", `{}`},
		{`{"nested": { "z" : [1, 2 ] , "a" : null }}`, `{"nested":{"a":null,"z":[1,2]}}`},
		{`{"n": 1e3}`, `{"n":1000}`},
	} {
		got, err := canonicalMetadata(json.RawMessage(tc.in))
		if err != nil || got != tc.want {
			t.Fatalf("canonicalMetadata(%q) = %q (%v), want %q", tc.in, got, err, tc.want)
		}
	}

	base := MgmtAuditEvent{
		ID: newUUID(), TenantID: "tenant-a", Action: "x",
		OccurredAt: time.UnixMilli(1738000000123).UTC(),
		PrevHash:   MgmtGenesisPrevHash,
	}
	seq := int64(0)
	base.Seq = &seq
	a, b := base, base
	a.Metadata = json.RawMessage(`{"b": 2, "a": 1}`)
	b.Metadata = json.RawMessage(`{"a":1,"b":2}`)
	ha, errA := recomputeMgmtAuditHash(a)
	hb, errB := recomputeMgmtAuditHash(b)
	if errA != nil || errB != nil || ha != hb {
		t.Fatalf("hashes differ for equivalent metadata: %q vs %q (%v, %v)", ha, hb, errA, errB)
	}
}

// Pinned canonical mgmt-audit v1 vector. The chain is Go-only (no cross-language twin), so this
// exists to make ANY change to the preimage encoding fail loudly — an encoding change silently
// re-namespaces every stored hash and would make old chains verify as tampered.
func TestMgmtAuditVectorV1(t *testing.T) {
	if len(mgmtAuditDomainTag) != 12 {
		t.Fatalf("domain tag length = %d, want 12", len(mgmtAuditDomainTag))
	}
	for _, other := range [][]byte{grantDomainTag, auditDomainTag, ticketDomainTag} {
		if bytes.Equal(mgmtAuditDomainTag, other) {
			t.Fatalf("mgmt audit domain tag collides with %q", other)
		}
	}

	seq := int64(7)
	e := MgmtAuditEvent{
		ID:          "0f9c5da2-4f3a-4f6e-9d2b-8c7a6b5e4d3c",
		TenantID:    "a1b2c3d4-e5f6-4a0b-8c9d-0e1f2a3b4c5d",
		ActorUserID: "",
		Action:      "session.start",
		TargetKind:  "session",
		TargetID:    "D9E8F7A6-B5C4-4D3E-A2B1-C0D9E8F7A6B5", // uppercase: pins the lowering
		OccurredAt:  time.UnixMilli(1738000000123).UTC(),
		Metadata:    json.RawMessage(`{"b": 2, "a": "x"}`),
		Seq:         &seq,
		PrevHash:    "00000000000000000000000000000000000000000000000000000000000000aa",
	}
	pre, err := mgmtAuditPreimage(e)
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	// Decodes as: tag "RMTMAUDITv1\x00" || str(id) || u64(7) || str(tenant) || str("")
	// || str("session.start") || str("session") || str(lowercased target) || i64(1738000000123)
	// || str(`{"a":"x","b":2}`) || str(prev) — each str u32be-length-prefixed.
	const wantPreimageHex = "524d544d41554449547631000000002430663963356461322d346633612d346636652d396432622d38633761366235653464336300000000000000070000002461316232633364342d653566362d346130622d386339642d306531663261336234633564000000000000000d73657373696f6e2e73746172740000000773657373696f6e0000002464396538663761362d623563342d346433652d613262312d63306439653866376136623500000194a8df647b0000000f7b2261223a2278222c2262223a327d0000004030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030306161"
	// Independently confirmed: SHA-256 of the preimage bytes above (computed outside Go).
	const wantHash = "98625ff04a2aedac9ecf74c96e8a5275a00410310f5697ef97f858052b421233"
	if got := hex.EncodeToString(pre); got != wantPreimageHex {
		t.Fatalf("preimage drifted:\n got %s\nwant %s", got, wantPreimageHex)
	}
	if got, _ := recomputeMgmtAuditHash(e); got != wantHash {
		t.Fatalf("hash drifted: got %s, want %s", got, wantHash)
	}
}

// -------------------------------------------------------------------------------------
// HTTP: GET /audit/export (NDJSON) + GET /audit/verify
// -------------------------------------------------------------------------------------

func TestAuditExportAndVerifyEndpoints(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleAuditor, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	for _, action := range []string{"machine.enroll", "session.start", "session.end"} {
		if err := srv.MgmtAudit.RecordEvent(ctx, "tenant-123", &MgmtAuditEvent{Action: action}); err != nil {
			t.Fatalf("seed %s: %v", action, err)
		}
	}
	// Another tenant's event must not leak into the export.
	if err := srv.MgmtAudit.RecordEvent(ctx, "tenant-other", &MgmtAuditEvent{Action: "tenant.create"}); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("export content-type = %q", ct)
	}
	var lines []MgmtAuditEvent
	sc := bufio.NewScanner(bytes.NewReader(rec.Body.Bytes()))
	for sc.Scan() {
		var e MgmtAuditEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", sc.Text(), err)
		}
		lines = append(lines, e)
	}
	if len(lines) != 3 {
		t.Fatalf("export lines = %d, want 3", len(lines))
	}
	for i, e := range lines {
		if e.Seq == nil || *e.Seq != int64(i) || e.TenantID != "tenant-123" || !isHex64(e.Hash) {
			t.Fatalf("export line %d = %+v, want ascending chained tenant-123 event", i, e)
		}
	}

	// Cursor paging: after_seq=0 skips the genesis event.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit/export?after_seq=0&limit=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("paged export = %d", rec.Code)
	}
	var paged MgmtAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &paged); err != nil ||
		paged.Seq == nil || *paged.Seq != 1 {
		t.Fatalf("paged export = %s (%v), want the seq-1 event only", rec.Body.String(), err)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit/verify", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d (%s)", rec.Code, rec.Body.String())
	}
	var res MgmtAuditVerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || !res.OK || res.CheckedEvents != 3 {
		t.Fatalf("verify = %s (%v), want ok with 3 checked", rec.Body.String(), err)
	}

	// Bad query params are 400s.
	for _, path := range []string{"/audit/export?after_seq=x", "/audit/export?limit=0", "/audit/export?limit=999999"} {
		rec = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s = %d, want 400", path, rec.Code)
		}
	}
}

func TestAuditExportRequiresCapViewAudit(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleTechnician, AllGroups())),
	}
	srv, _ := newTestServer(p)
	for _, path := range []string{"/audit/export", "/audit/verify"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("GET %s as technician = %d, want 403", path, rec.Code)
		}
	}
}

// TestParsePgUUIDMatchesPostgres pins the uuid canonicalizer against the spellings a live
// PostgreSQL 16 actually accepts and rejects (each case below was run through
// '<literal>'::uuid::text on the server). The chain's correctness depends on this parser being a
// SUPERSET of nothing and a subset of nothing in the dangerous direction: a spelling Postgres
// accepts but this rejects gets hashed verbatim at write and canonically at read-back, which is
// a permanent false tamper. Accepting more than Postgres does is merely a failed INSERT.
func TestParsePgUUIDMatchesPostgres(t *testing.T) {
	const canonical = "2d5b0f1e-1111-4222-8333-444455556666"
	for _, in := range []string{
		canonical,
		"{2d5b0f1e-1111-4222-8333-444455556666}", // braced
		"2d5b0f1e111142228333444455556666",       // dashless
		"{2d5b0f1e111142228333444455556666}",     // braced + dashless
		"2D5B0F1E-1111-4222-8333-444455556666",   // uppercase
		"2D5B0F1E111142228333444455556666",       // uppercase dashless
		"2d5b0f1e-111142228333444455556666",      // hyphens are independently optional…
		"2d5b0f1e11114222-8333-444455556666",     // …at every group boundary
		"{2D5B0F1E-1111-4222-8333-444455556666}", // braced + uppercase
	} {
		got, ok := parsePgUUID(in)
		if !ok || got != canonical {
			t.Fatalf("parsePgUUID(%q) = %q, %v; want %q, true", in, got, ok, canonical)
		}
		if canonicalUUIDish(in) != canonical {
			t.Fatalf("canonicalUUIDish(%q) = %q, want %q", in, canonicalUUIDish(in), canonical)
		}
	}

	for _, in := range []string{
		" 2d5b0f1e-1111-4222-8333-444455556666",    // leading space — Postgres rejects
		"2d5b0f1e-1111-4222-8333-444455556666 ",    // trailing space — Postgres rejects
		"2d5b0f1e--1111-4222-8333-444455556666",    // doubled hyphen — Postgres rejects
		"2d5b0f-1e1111-4222-8333-444455556666",     // hyphen off a group boundary
		"{ 2d5b0f1e-1111-4222-8333-444455556666 }", // spaces inside the braces
		"{2d5b0f1e-1111-4222-8333-444455556666",    // unmatched brace
		"2d5b0f1e-1111-4222-8333-44445555666",      // 31 hex digits
		"2d5b0f1e-1111-4222-8333-4444555566667",    // 33 hex digits
		"2d5b0f1e-1111-4222-8333-44445555666g",     // non-hex digit
		"",
		"tenant-123", // the DEV/test principal shape: must NOT be treated as a uuid
		"u1",
	} {
		if got, ok := parsePgUUID(in); ok {
			t.Fatalf("parsePgUUID(%q) = %q, true; want rejected", in, got)
		}
	}

	// Non-uuid ids keep the old behaviour — lowercased, otherwise verbatim — because the
	// in-memory store and the HTTP tests chain events for principals like "tenant-123".
	if got := canonicalUUIDish("Tenant-123"); got != "tenant-123" {
		t.Fatalf("canonicalUUIDish(non-uuid) = %q, want %q", got, "tenant-123")
	}
	if got := canonicalUUIDish(""); got != "" {
		t.Fatalf("canonicalUUIDish(\"\") = %q, want empty", got)
	}
}

// TestCanonicalMetadataNormalizesNegativeZero pins the other half of the false-tamper fix. jsonb
// numbers are `numeric`, which has no signed zero, so '{"a":-0}'::jsonb reads back as {"a": 0};
// Go marshals a negative-zero float64 as "-0". Hashing the caller's spelling would therefore
// guarantee the read-back disagrees. Every spelling of negative zero must collapse, at any depth.
func TestCanonicalMetadataNormalizesNegativeZero(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"a":-0}`, `{"a":0}`},
		{`{"a":-0.0}`, `{"a":0}`},
		{`{"a":-0e0}`, `{"a":0}`},
		{`{"a":-0.0e10}`, `{"a":0}`},
		{`{"a":[1,-0,3]}`, `{"a":[1,0,3]}`}, // array ORDER is meaningful and preserved
		{`{"a":{"b":[-0]}}`, `{"a":{"b":[0]}}`},
		{`[-0]`, `[0]`},
		{`-0`, `0`},
		// Non-zero numbers and non-numbers are untouched — in particular the STRING "-0",
		// which jsonb stores verbatim and must therefore keep hashing verbatim.
		{`{"a":-1.5,"b":"-0","c":null,"d":true}`, `{"a":-1.5,"b":"-0","c":null,"d":true}`},
	} {
		got, err := canonicalMetadata(json.RawMessage(tc.in))
		if err != nil {
			t.Fatalf("canonicalMetadata(%s): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("canonicalMetadata(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}

	// The hash is what actually matters: the two spellings must be indistinguishable.
	seq := int64(0)
	base := MgmtAuditEvent{ID: newUUID(), TenantID: "tenant-a", Action: "x",
		OccurredAt: time.UnixMilli(1738000000123).UTC(), PrevHash: MgmtGenesisPrevHash, Seq: &seq}
	neg, pos := base, base
	neg.Metadata = json.RawMessage(`{"delta":-0}`)
	pos.Metadata = json.RawMessage(`{"delta":0}`)
	hNeg, errA := recomputeMgmtAuditHash(neg)
	hPos, errB := recomputeMgmtAuditHash(pos)
	if errA != nil || errB != nil || hNeg != hPos {
		t.Fatalf("negative zero hashes differently: %q vs %q (%v, %v)", hNeg, hPos, errA, errB)
	}
}

// TestVerifyMgmtAuditChainIsBoundedAndResumable covers the cap that keeps GET /audit/verify from
// being an authenticated full-table scan: a walk stops at maxEvents, says so, and hands back a
// cursor that resumes where it left off. The properties that matter are that paging COVERS the
// whole chain and still CATCHES tampering — a cap that quietly stopped looking would be worse
// than no cap at all.
func TestVerifyMgmtAuditChainIsBoundedAndResumable(t *testing.T) {
	ctx := context.Background()
	seed := func(t *testing.T, n int) *InMemoryMgmtAuditStore {
		t.Helper()
		store := NewInMemoryMgmtAuditStore()
		for i := 0; i < n; i++ {
			if err := store.RecordEvent(ctx, "tenant-a", &MgmtAuditEvent{
				Action: "session.start", Metadata: json.RawMessage(`{"i":` + strconv.Itoa(i) + `}`),
			}); err != nil {
				t.Fatalf("seed %d: %v", i, err)
			}
		}
		return store
	}

	t.Run("paging covers the whole chain", func(t *testing.T) {
		store := seed(t, 25)
		var total int64
		pages := 0
		after := int64(-1)
		for {
			res, err := VerifyMgmtAuditChainFrom(ctx, store, "tenant-a", after, 7)
			if err != nil {
				t.Fatalf("verify(after=%d): %v", after, err)
			}
			if !res.OK {
				t.Fatalf("verify(after=%d) = %+v, want OK", after, res)
			}
			total += res.CheckedEvents
			pages++
			if res.Completed {
				if res.NextAfterSeq != nil {
					t.Fatalf("completed result carries a cursor: %+v", res)
				}
				break
			}
			if res.NextAfterSeq == nil {
				t.Fatalf("incomplete result carries no cursor: %+v", res)
			}
			after = *res.NextAfterSeq
			if pages > 10 {
				t.Fatal("paging did not terminate")
			}
		}
		if total != 25 {
			t.Fatalf("paged verification checked %d events, want 25", total)
		}
	})

	t.Run("a full walk that ends exactly on the cap is reported complete", func(t *testing.T) {
		store := seed(t, 10)
		res, err := VerifyMgmtAuditChainFrom(ctx, store, "tenant-a", -1, 10)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !res.OK || !res.Completed || res.CheckedEvents != 10 || res.NextAfterSeq != nil {
			t.Fatalf("verify = %+v, want a COMPLETE 10-event walk with no cursor", res)
		}
	})

	t.Run("tampering past the cursor is still caught after resuming", func(t *testing.T) {
		store := seed(t, 20)
		if !store.tamperEvent("tenant-a", 15, func(e *MgmtAuditEvent) { e.Action = "forged" }) {
			t.Fatal("tamper target not found")
		}
		// The first page is clean; the tamper only shows up once paging reaches it.
		first, err := VerifyMgmtAuditChainFrom(ctx, store, "tenant-a", -1, 5)
		if err != nil || !first.OK || first.Completed {
			t.Fatalf("first page = %+v (%v), want a clean incomplete page", first, err)
		}
		res, err := VerifyMgmtAuditChainFrom(ctx, store, "tenant-a", *first.NextAfterSeq, 100)
		if err != nil {
			t.Fatalf("resumed verify: %v", err)
		}
		if res.OK || res.FirstBadSeq == nil || *res.FirstBadSeq != 15 {
			t.Fatalf("resumed verify = %+v, want !OK at seq 15", res)
		}
	})

	t.Run("resuming anchors on the real event, so a page cannot start from a forged link", func(t *testing.T) {
		// Drop the event the cursor points at. A resumed walk that trusted the next row's own
		// prev_hash would sail straight past the hole; anchoring makes it a hard failure.
		store := seed(t, 10)
		if !store.dropEvent("tenant-a", 4) {
			t.Fatal("drop target not found")
		}
		res, err := VerifyMgmtAuditChainFrom(ctx, store, "tenant-a", 4, 100)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.OK || !strings.Contains(res.Reason, "cannot resume at seq 4") {
			t.Fatalf("resume onto a deleted anchor = %+v, want a refusal naming seq 4", res)
		}
	})

	t.Run("an unbounded walk is unchanged", func(t *testing.T) {
		store := seed(t, 12)
		res, err := VerifyMgmtAuditChain(ctx, store, "tenant-a")
		if err != nil || !res.OK || res.CheckedEvents != 12 || !res.Completed {
			t.Fatalf("unbounded verify = %+v (%v), want a complete 12-event walk", res, err)
		}
	})
}

// TestAuditVerifyEndpointPaging pins the HTTP surface of the cap: the cursor/limit params, their
// validation, and that an incomplete page is visibly incomplete to a client.
func TestAuditVerifyEndpointPaging(t *testing.T) {
	p := &Principal{
		UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleAuditor, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		if err := srv.MgmtAudit.RecordEvent(ctx, "tenant-123",
			&MgmtAuditEvent{Action: "session.start"}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	get := func(t *testing.T, path string) MgmtAuditVerifyResult {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", path, rec.Code, rec.Body.String())
		}
		var res MgmtAuditVerifyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("GET %s body %s: %v", path, rec.Body.String(), err)
		}
		return res
	}

	res := get(t, "/audit/verify?limit=2")
	if !res.OK || res.Completed || res.CheckedEvents != 2 || res.NextAfterSeq == nil || *res.NextAfterSeq != 1 {
		t.Fatalf("capped verify = %+v, want an incomplete 2-event page resuming after seq 1", res)
	}
	res = get(t, "/audit/verify?after_seq=1&limit=100")
	if !res.OK || !res.Completed || res.CheckedEvents != 4 {
		t.Fatalf("resumed verify = %+v, want a complete 4-event remainder", res)
	}
	// The default is still a whole-chain answer for chains under the cap.
	if res := get(t, "/audit/verify"); !res.OK || !res.Completed || res.CheckedEvents != 6 {
		t.Fatalf("default verify = %+v, want a complete 6-event walk", res)
	}

	for _, path := range []string{
		"/audit/verify?after_seq=x", "/audit/verify?after_seq=-2",
		"/audit/verify?limit=0", "/audit/verify?limit=-1", "/audit/verify?limit=999999999",
	} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s = %d, want 400", path, rec.Code)
		}
	}
}
