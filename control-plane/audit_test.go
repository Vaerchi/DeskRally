package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -------------------------------------------------------------------------------------
// Test chain builder. Since H2b the store RECOMPUTES each event's content hash, so events must
// carry REAL canonical audit v1 hashes (recomputeHash), not fabricated ones. mkAuditEvent stamps
// the correct hash; chainRange builds a genuinely-linked chain (each prev_hash == the real hash of
// its predecessor) so linkage AND content verification both pass for an untampered batch.
// -------------------------------------------------------------------------------------

func hex64(n uint64) string { return fmt.Sprintf("%064x", n) }

// The technician the ingest fixtures speak for. It is ONE constant used by both `mkAuditEvent` and
// `technicianPrincipal` because `POST /audit/ingest` now requires the batch's `technician_id` to be
// the authenticated caller: a forwarded backstage record attributes an action to a person, and the
// server must not take the body's word for who that was. Before that check the fixture was
// internally inconsistent — principal "u1" forwarding events stamped for this uuid — and every
// ingest test passed anyway, which is precisely the gap.
const auditTechUser = "11111111-1111-1111-1111-111111111111"

// Default action/outcome used by the chain helpers — a representative service_control + ok.
var (
	defaultAuditAction  = json.RawMessage(`{"kind":"service_control","service":"spooler","verb":"stop"}`)
	defaultAuditOutcome = json.RawMessage(`{"result":"ok"}`)
)

// mkAuditEvent builds one AuditEvent and stamps the CORRECT canonical audit v1 hash via
// recomputeHash (H2b). Deterministic in seq. Panics on a canonicalization error (a test bug).
func mkAuditEvent(sessionID string, seq uint64, prevHash string, action, outcome json.RawMessage) AuditEvent {
	e := AuditEvent{
		ID:               fmt.Sprintf("00000000-0000-0000-0000-%012d", seq),
		Seq:              seq,
		SessionID:        sessionID,
		TechnicianID:     auditTechUser,
		MachineID:        "22222222-2222-2222-2222-222222222222",
		OccurredAtUnixMs: int64(1000 + seq),
		Action:           action,
		Outcome:          outcome,
		PrevHash:         prevHash,
	}
	h, err := recomputeHash(e)
	if err != nil {
		panic(fmt.Sprintf("mkAuditEvent(seq %d): %v", seq, err))
	}
	e.Hash = h
	return e
}

// chainRange builds [start, start+count) as a genuinely hash-linked batch. It always builds from
// seq 0 (so prev_hash links are the real predecessor hashes) and returns the requested window;
// this makes a continuation batch chain correctly onto a previously-stored tail.
func chainRange(sessionID string, start, count uint64) []AuditEvent {
	total := start + count
	all := make([]AuditEvent, 0, total)
	prev := GenesisPrevHash
	for s := uint64(0); s < total; s++ {
		e := mkAuditEvent(sessionID, s, prev, defaultAuditAction, defaultAuditOutcome)
		all = append(all, e)
		prev = e.Hash
	}
	return all[start:total]
}

// chainEvent is the single-event window of chainRange.
func chainEvent(sessionID string, seq uint64) AuditEvent {
	return chainRange(sessionID, 0, seq+1)[seq]
}

const testSession = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

// -------------------------------------------------------------------------------------
// Store-level tests (InMemoryAuditStore) — the atomic linkage choke point.
// -------------------------------------------------------------------------------------

func TestAuditStoreValidInitialChain(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()

	batch := chainRange(testSession, 0, 3)
	wantHash := batch[2].Hash
	tail, err := s.AppendAudit(ctx, "t1", testSession, batch)
	if err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if !tail.Exists || tail.Seq != 2 || tail.Hash != wantHash {
		t.Fatalf("tail = %+v, want seq 2 hash %s", tail, wantHash)
	}
	got, _ := s.AuditTail(ctx, "t1", testSession)
	if got != tail {
		t.Fatalf("AuditTail = %+v, want %+v", got, tail)
	}
}

func TestAuditStoreContinuationExtends(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	cont := chainRange(testSession, 3, 2)
	wantHash := cont[len(cont)-1].Hash
	tail, err := s.AppendAudit(ctx, "t1", testSession, cont)
	if err != nil {
		t.Fatalf("continuation: %v", err)
	}
	if tail.Seq != 4 || tail.Hash != wantHash {
		t.Fatalf("tail = %+v, want seq 4 hash %s", tail, wantHash)
	}
}

func TestAuditStoreBrokenLinkageRejectedNothingStored(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	batch := chainRange(testSession, 0, 3)
	batch[2].PrevHash = hex64(999) // does not equal batch[1].Hash

	_, err := s.AppendAudit(ctx, "t1", testSession, batch)
	var le *LinkageError
	if !bytesAsLinkage(err, &le) || le.At != 2 {
		t.Fatalf("err = %v, want *LinkageError at index 2", err)
	}
	if tail, _ := s.AuditTail(ctx, "t1", testSession); tail.Exists {
		t.Fatalf("chain should be empty after a rejected batch, got tail %+v", tail)
	}
}

func TestAuditStoreSeqGapRejected(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	batch := []AuditEvent{chainEvent(testSession, 0), chainEvent(testSession, 2)} // skips seq 1
	_, err := s.AppendAudit(ctx, "t1", testSession, batch)
	var le *LinkageError
	if !bytesAsLinkage(err, &le) {
		t.Fatalf("err = %v, want *LinkageError for seq gap", err)
	}
}

func TestAuditStoreDuplicateReplayRejected(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	// Replay an already-stored range that ends BEFORE the tail (seq 0..1, tail 2): nothing in it can
	// be proven stored, so it is refused. A re-send that REACHES the tail with the tail's hash is an
	// idempotent no-op instead (audit_idempotent_test.go).
	_, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 2))
	var le *LinkageError
	if !bytesAsLinkage(err, &le) {
		t.Fatalf("err = %v, want *LinkageError for duplicate/replay", err)
	}
	// Tail unchanged.
	if tail, _ := s.AuditTail(ctx, "t1", testSession); tail.Seq != 2 {
		t.Fatalf("tail after rejected replay = %+v, want seq 2", tail)
	}
}

func TestAuditStoreCrossSessionIsolation(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	const sessB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("session A: %v", err)
	}
	// Session B starts its own chain at seq 0 — unaffected by A's tail.
	if _, err := s.AppendAudit(ctx, "t1", sessB, chainRange(sessB, 0, 1)); err != nil {
		t.Fatalf("session B should start fresh at seq 0: %v", err)
	}
	if tail, _ := s.AuditTail(ctx, "t1", testSession); tail.Seq != 2 {
		t.Fatalf("session A tail = %+v, want seq 2 (untouched by B)", tail)
	}
	if tail, _ := s.AuditTail(ctx, "t1", sessB); tail.Seq != 0 {
		t.Fatalf("session B tail = %+v, want seq 0", tail)
	}
}

// bytesAsLinkage is errors.As specialized to *LinkageError, kept tiny to read at call sites.
func bytesAsLinkage(err error, target **LinkageError) bool {
	le, ok := err.(*LinkageError)
	if ok {
		*target = le
	}
	return ok
}

// -------------------------------------------------------------------------------------
// HTTP endpoint tests — POST /audit/ingest through the full auth → tenant middleware chain.
// -------------------------------------------------------------------------------------

func auditServer(p *Principal) (*Server, *InMemoryAuditStore) {
	store := NewInMemoryAuditStore()
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.Audit = store
	return srv, store
}

func technicianPrincipal() *Principal {
	return &Principal{
		UserID:   auditTechUser,
		TenantID: "tenant-123",
		Grant:    NewGrant(auditTechUser, "tenant-123", NewMembership(RoleTechnician, AllGroups())),
	}
}

func postIngest(t *testing.T, srv *Server, body auditIngestRequest) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/audit/ingest", bytes.NewReader(buf))
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestIngestValidBatchStored(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	batch := chainRange(testSession, 0, 3)
	wantHash := batch[2].Hash
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: batch})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp auditIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted != 3 || resp.TailSeq != 2 || resp.TailHash != wantHash {
		t.Fatalf("response = %+v, want accepted 3 tail_seq 2 tail_hash %s", resp, wantHash)
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); tail.Seq != 2 {
		t.Fatalf("stored tail = %+v, want seq 2", tail)
	}
}

func TestIngestBrokenLinkageRejected(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	batch := chainRange(testSession, 0, 3)
	batch[1].PrevHash = hex64(42) // break the link at index 1

	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: batch})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); tail.Exists {
		t.Fatalf("nothing should be stored after a rejected batch, got %+v", tail)
	}
}

func TestIngestSessionMismatchRejected(t *testing.T) {
	srv, _ := auditServer(technicianPrincipal())
	batch := chainRange(testSession, 0, 2)
	batch[1].SessionID = "cccccccc-cccc-cccc-cccc-cccccccccccc" // foreign session inside the batch

	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: batch})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for session mismatch", rec.Code)
	}
}

func TestIngestUnauthenticatedRejected(t *testing.T) {
	srv, _ := auditServer(nil) // StubAuthenticator returns a nil principal
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: chainRange(testSession, 0, 1)})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIngestAuditorForbidden(t *testing.T) {
	// An Auditor holds CapViewAudit (read) but NOT CapBackstageShell (write the chain), so it
	// cannot forward/ingest — only a technician session can.
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleAuditor, AllGroups())),
	}
	srv, _ := auditServer(p)
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: chainRange(testSession, 0, 1)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for auditor", rec.Code)
	}
}

// =====================================================================================
// H2b content tamper-evidence — a field-level edit that keeps the chain pointers consistent is
// caught by content re-hashing (recomputeHash != hash), not by linkage. Nothing is stored.
// =====================================================================================

func TestAuditStoreContentTamperRejectedNothingStored(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	batch := chainRange(testSession, 0, 3)
	// Alter a FIELD of event 1's action but leave its (now-stale) hash and every prev_hash pointer
	// untouched — linkage is still self-consistent, so only content re-hashing can catch this.
	batch[1].Action = json.RawMessage(`{"kind":"service_control","service":"defrag","verb":"stop"}`)

	_, err := s.AppendAudit(ctx, "t1", testSession, batch)
	var ce *ContentTamperError
	if !errors.As(err, &ce) || ce.At != 1 {
		t.Fatalf("err = %v, want *ContentTamperError at index 1", err)
	}
	if tail, _ := s.AuditTail(ctx, "t1", testSession); tail.Exists {
		t.Fatalf("chain should be empty after a content-tampered batch, got tail %+v", tail)
	}
}

func TestIngestContentTamperRejected(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	batch := chainRange(testSession, 0, 3)
	batch[2].Outcome = json.RawMessage(`{"result":"denied","reason":"forged"}`) // field edit, hash stale

	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: batch})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for content tamper (body %s)", rec.Code, rec.Body.String())
	}
	if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); tail.Exists {
		t.Fatalf("nothing should be stored after a content-tampered batch, got %+v", tail)
	}
}

// =====================================================================================
// GOLDEN CROSS-LANGUAGE AUDIT VECTORS (H2b) — the SAME three fixtures as
// agent/src/backstage/audit.rs (tests::audit_golden_vector_v1). Both languages must produce the
// SAME canonical-audit-v1 preimage hex AND the SAME SHA-256 hash hex. If either side's audit
// encoder drifts, its hex stops matching. DO NOT change a value without changing the Rust test.
// =====================================================================================

const (
	auditGoldenSession = "11111111-1111-1111-1111-111111111111"
	auditGoldenTech    = "22222222-2222-2222-2222-222222222222"
	auditGoldenMachine = "33333333-3333-3333-3333-333333333333"

	goldenAPreimageHex = "524d5441554449547631000044444444444444444444444444444444000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0914000000000b66696c655f62726f77736500000018433a5c55736572735c616c6963655c446f63756d656e7473000000026f6b00000000"
	goldenAHash        = "9f9ad6566756dd1bac7537dada03baf3e6b0ec799180e6be19c126163d9c63e4"
	goldenBPreimageHex = "524d5441554449547631000055555555555555555555555555555555000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0917e80000000e72656769737472795f777269746500000019484b4c4d5c534f4654574152455c41636d655c436f6e66696700000007456e61626c656401000000013000000001310000000664656e696564000000116361706162696c6974795f64656e6965640000004039663961643635363637353664643162616337353337646164613033626166336536623065633739393138306536626531396331323631363364396336336534"
	goldenBHash        = "51e7b2b3ec830d99caa629fb2db8f4536653cef12fe794f14c084546d7cebeb9"
	goldenCPreimageHex = "524d5441554449547631000066666666666666666666666666666666000000000000000211111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc091bd00000000c70726f636573735f6b696c6c00001092000000086576696c2e6578650000000a434f52505c616c696365000000066661696c65640000000d6163636573735f64656e6965640000004035316537623262336563383330643939636161363239666232646238663435333636353363656631326665373934663134633038343534366437636562656239"
	goldenCHash        = "9e1dfef64f1a36ef9daf511167197956bc7d8cf01ff222d6d9ed6895910a456b"
)

func goldenAuditEvent(id string, seq uint64, occurredMs int64, action, outcome json.RawMessage, prev string) AuditEvent {
	return AuditEvent{
		ID:               id,
		Seq:              seq,
		SessionID:        auditGoldenSession,
		TechnicianID:     auditGoldenTech,
		MachineID:        auditGoldenMachine,
		OccurredAtUnixMs: occurredMs,
		Action:           action,
		Outcome:          outcome,
		PrevHash:         prev,
	}
}

func assertGolden(t *testing.T, name string, e AuditEvent, wantPre, wantHash string) {
	t.Helper()
	pre, err := auditPreimage(e)
	if err != nil {
		t.Fatalf("%s: auditPreimage: %v", name, err)
	}
	if got := hex.EncodeToString(pre); got != wantPre {
		t.Fatalf("%s preimage drift:\n got  %s\n want %s", name, got, wantPre)
	}
	h, err := recomputeHash(e)
	if err != nil {
		t.Fatalf("%s: recomputeHash: %v", name, err)
	}
	if h != wantHash {
		t.Fatalf("%s hash drift:\n got  %s\n want %s", name, h, wantHash)
	}
}

func TestAuditGoldenVectorV1(t *testing.T) {
	// A — read op (file_browse) + ok, genesis prev_hash.
	a := goldenAuditEvent(
		"44444444-4444-4444-4444-444444444444", 0, 1730000000000,
		json.RawMessage(`{"kind":"file_browse","path":"C:\\Users\\alice\\Documents"}`),
		json.RawMessage(`{"result":"ok"}`), "")
	assertGolden(t, "A", a, goldenAPreimageHex, goldenAHash)

	// B — with-fields op (registry_write, Some(before)) + denied, chains onto A.
	b := goldenAuditEvent(
		"55555555-5555-5555-5555-555555555555", 1, 1730000001000,
		json.RawMessage(`{"kind":"registry_write","path":"HKLM\\SOFTWARE\\Acme\\Config","value":"Enabled","before":"0","after":"1"}`),
		json.RawMessage(`{"result":"denied","reason":"capability_denied"}`), goldenAHash)
	assertGolden(t, "B", b, goldenBPreimageHex, goldenBHash)

	// C — process_kill (u32 pid) + failed, chains onto B.
	c := goldenAuditEvent(
		"66666666-6666-6666-6666-666666666666", 2, 1730000002000,
		json.RawMessage(`{"kind":"process_kill","pid":4242,"image":"evil.exe","owner":"CORP\\alice"}`),
		json.RawMessage(`{"result":"failed","error":"access_denied"}`), goldenBHash)
	assertGolden(t, "C", c, goldenCPreimageHex, goldenCHash)
}

func TestAuditDomainTagBytes(t *testing.T) {
	want := []byte{0x52, 0x4d, 0x54, 0x41, 0x55, 0x44, 0x49, 0x54, 0x76, 0x31, 0x00, 0x00}
	if !bytes.Equal(auditDomainTag, want) {
		t.Fatalf("audit domain tag = % x, want % x", auditDomainTag, want)
	}
	if bytes.Equal(auditDomainTag, grantDomainTag) {
		t.Fatal("audit and grant domain tags must differ (domain separation)")
	}
}

// TestIngestUnstorableNULRejectedAsBadRequest covers a value that is perfectly well-formed and
// correctly hashed, yet can never be stored: `action`/`outcome` land in jsonb columns, and
// PostgreSQL's jsonb cannot represent U+0000 in a string, while Go's JSON decoder accepts it.
//
// The failure this prevents is not a lost event, it is a STUCK CHAIN. The agent's chain is
// strictly sequential — it cannot skip event N — so before this guard the batch failed at the
// INSERT with a generic 500 and the agent re-POSTed the identical bytes forever, meaning that
// backstage session's entire audit trail was never persisted. Reachable from ordinary agent data:
// ConPTY output, registry values, and `Outcome::Failed{error}` strings all carry raw OS bytes.
//
// A 400 is the load-bearing part: it tells the agent to stop retrying and names the field.
func TestIngestUnstorableNULRejectedAsBadRequest(t *testing.T) {
	nulEscape := string([]byte{'\\', 'u', '0', '0', '0', '0'})

	for _, tc := range []struct {
		name            string
		action, outcome json.RawMessage
	}{
		{
			name:    "in outcome",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:\\"}`),
			outcome: json.RawMessage(`{"result":"failed","error":"boom` + nulEscape + `"}`),
		},
		{
			name:    "in action",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:\\a` + nulEscape + `b"}`),
			outcome: json.RawMessage(`{"result":"ok"}`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, store := auditServer(technicianPrincipal())
			e := mkAuditEvent(testSession, 0, GenesisPrevHash, tc.action, tc.outcome)

			// Sanity: the event is otherwise VALID — it is not a tamper, and its hash is right.
			// (mkAuditEvent computes the canonical hash, so this proves the guard is what fires.)
			if got, err := recomputeHash(e); err != nil || got != e.Hash {
				t.Fatalf("fixture is not correctly hashed: %v / %s vs %s", err, got, e.Hash)
			}

			rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: []AuditEvent{e}})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — a 5xx makes the agent retry an unstorable batch "+
					"forever and the session's chain never advances (body %s)", rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "cannot be stored") ||
				!strings.Contains(body, "U+0000") {
				t.Fatalf("400 body does not explain the problem: %s", body)
			}
			if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); tail.Exists {
				t.Fatalf("nothing should be stored after a rejected batch, got %+v", tail)
			}
		})
	}

	// The in-memory fake and the pg store must AGREE about what is storable — the check lives in
	// verifyLinkage, which both call, precisely so dev/test does not accept what production cannot.
	e := mkAuditEvent(testSession, 0, GenesisPrevHash,
		json.RawMessage(`{"kind":"file_browse","path":"C:\\"}`),
		json.RawMessage(`{"result":"failed","error":"x`+nulEscape+`"}`))
	var ue *UnstorableError
	if err := verifyLinkage(AuditTail{}, []AuditEvent{e}); !errors.As(err, &ue) {
		t.Fatalf("verifyLinkage = %v, want *UnstorableError", err)
	}
	if ue.Field != "outcome" {
		t.Fatalf("UnstorableError names field %q, want outcome", ue.Field)
	}

	// And an ordinary control character (not U+0000) must still be ACCEPTED — jsonb stores those
	// fine, so rejecting them would break real shell output for no reason.
	ok := mkAuditEvent(testSession, 0, GenesisPrevHash,
		json.RawMessage(`{"kind":"file_browse","path":"tab\there\u0007bell"}`),
		json.RawMessage(`{"result":"ok"}`))
	if err := verifyLinkage(AuditTail{}, []AuditEvent{ok}); err != nil {
		t.Fatalf("verifyLinkage rejected a batch with ordinary control characters: %v", err)
	}
}
