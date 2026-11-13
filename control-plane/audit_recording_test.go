package controlplane

// Cross-language golden vectors + the ingest gate, for the SESSION-scoped audit trail (loop 91).
//
// WHY THIS FILE EXISTS. The loop-90 design note (docs/14) said adding an AuditAction variant was
// "the whole wire change - no new preimage, no golden vector". That was measured FALSE before any
// of it shipped: encodeAuditAction ends in
//
//	default: return fmt.Errorf("unknown audit action kind %q", probe.Kind)
//
// and verifyLinkage recomputes every ingested event's hash. So a Rust variant with no Go arm turns
// the batch into a ContentTamperError -> 400, and because the agent's chain is strictly sequential
// it can never move past that event: the WHOLE session's audit trail wedges, permanently. Same
// failure mode as the U+0000 bug, reached by a different route. These vectors are the tripwire, and
// they are pinned in BOTH languages so neither side can drift alone.
//
// The Rust twin is agent/src/backstage/audit.rs :: audit_golden_recording_vector_v1. DO NOT change
// a constant here without changing it identically there.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	goldenR1PreimageHex = "524d5441554449547631000077777777777777777777777777777777000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc091400000000117265636f7264696e675f7374617274656400000192cc09140000000006443a5c726563000000026f6b00000000"
	goldenR1Hash        = "d9ae995d1d27cc8c5a9fcb664dcc148f88b24e4fc4826d9cd82d85143519de1c"
	goldenR2PreimageHex = "524d5441554449547631000088888888888888888888888888888888000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc09fe60000000117265636f7264696e675f73746f7070656400000000000003910000000000404289010000000a73697a655f6c696d6974000000000000002f000000020000004061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161000000406262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626200000006443a5c726563000000026f6b0000004064396165393935643164323763633863356139666362363634646363313438663838623234653466633438323664396364383264383531343335313964653163"
	goldenR2Hash        = "e1bc99fee152ba5ccc91d697003ee2b4d99b81183c40bcfa451af1c9a764a73e"
)

// The directory both vectors carry: D:\rec, assembled from the byte rather than written as an
// escape. The Rust twin does the same, and for a measured reason - a doubled backslash in the
// source that produced these files was silently collapsed to \r (a carriage return), which would
// have pinned a golden vector over a path no Windows agent can ever produce.
func goldenRecordingDir() string { return "D:" + string(rune(92)) + "rec" }

func TestAuditGoldenRecordingV1(t *testing.T) {
	dir := goldenRecordingDir()
	if len(dir) != 6 {
		t.Fatalf("the golden directory must be a real path, got %q", dir)
	}
	// json.Marshal escapes the backslash exactly as serde does, so the two languages agree on the
	// bytes that reach encodeAuditAction. Building the JSON rather than writing it literally is
	// what keeps that true.
	dirJSON, err := json.Marshal(dir)
	if err != nil {
		t.Fatalf("marshal dir: %v", err)
	}

	// R1 - recording_started, genesis. i64 timestamp then a length-prefixed directory.
	r1 := goldenAuditEvent(
		"77777777-7777-7777-7777-777777777777", 0, 1730000000000,
		json.RawMessage(`{"kind":"recording_started","started_at_unix_ms":1730000000000,"directory":`+string(dirJSON)+`}`),
		json.RawMessage(`{"result":"ok"}`), "")
	assertGolden(t, "R1", r1, goldenR1PreimageHex, goldenR1Hash)

	// R2 - recording_stopped, chaining onto R1. Deliberately the AWKWARD shape rather than a clean
	// single-segment recording: a PRESENT `truncated` (so the Option tag byte is exercised), a
	// non-zero dropped count, and TWO segment digests (the u32 count prefix and a multi-element
	// list). A clean one-segment vector would still pass against a Go mirror that dropped the count
	// prefix or wrote the Option tag the other way round. This one cannot.
	r2 := goldenAuditEvent(
		"88888888-8888-8888-8888-888888888888", 1, 1730000060000,
		json.RawMessage(`{"kind":"recording_stopped","frames":913,"payload_bytes":4211337,`+
			`"truncated":"size_limit","dropped_frames":47,"segment_sha256":["`+
			strings.Repeat("aa", 32)+`","`+strings.Repeat("bb", 32)+`"],"directory":`+string(dirJSON)+`}`),
		json.RawMessage(`{"result":"ok"}`), goldenR1Hash)
	assertGolden(t, "R2", r2, goldenR2PreimageHex, goldenR2Hash)
}

// A recording_stopped whose `segment_sha256` key is ABSENT must be REFUSED, not hashed as an empty
// list.
//
// Rust encodes the list as u32be(count) then each element, so "key missing" and "empty list" would
// share a preimage if Go decoded a missing key to nil. Refusing the missing key keeps "this
// recording produced no files" a statement the agent has to make explicitly, rather than something
// a stripped field can say on its behalf.
func TestRecordingStoppedRequiresTheSegmentDigestList(t *testing.T) {
	e := goldenAuditEvent(
		"88888888-8888-8888-8888-888888888888", 0, 1730000060000,
		json.RawMessage(`{"kind":"recording_stopped","frames":1,"payload_bytes":1,"truncated":null,"dropped_frames":0,"directory":""}`),
		json.RawMessage(`{"result":"ok"}`), "")
	if _, err := auditPreimage(e); err == nil {
		t.Fatal("a recording_stopped with no segment_sha256 key must be refused, not hashed as empty")
	}

	// Negative control: the same event WITH an explicit empty list encodes fine. Without this leg a
	// preimage function that rejected every recording_stopped would satisfy the assertion above.
	ok := goldenAuditEvent(
		"88888888-8888-8888-8888-888888888888", 0, 1730000060000,
		json.RawMessage(`{"kind":"recording_stopped","frames":1,"payload_bytes":1,"truncated":null,"dropped_frames":0,"segment_sha256":[],"directory":""}`),
		json.RawMessage(`{"result":"ok"}`), "")
	if _, err := auditPreimage(ok); err != nil {
		t.Fatalf("an explicit empty digest list must encode: %v", err)
	}
}

// An UNKNOWN action kind is still refused. This is the guard the two new arms were added to
// satisfy, and it has to keep failing closed for the NEXT variant somebody adds to the Rust enum
// without coming here - which is the entire reason this file exists.
func TestUnknownAuditActionKindIsStillRefused(t *testing.T) {
	e := goldenAuditEvent(
		"88888888-8888-8888-8888-888888888888", 0, 1730000060000,
		json.RawMessage(`{"kind":"teleport_the_guest","where":"mars"}`),
		json.RawMessage(`{"result":"ok"}`), "")
	_, err := auditPreimage(e)
	if err == nil {
		t.Fatal("an unknown action kind must be refused")
	}
	if !strings.Contains(err.Error(), "teleport_the_guest") {
		t.Fatalf("the refusal should name the unknown kind, got %v", err)
	}
}

// =====================================================================================
// The ingest capability gate, widened in loop 91 to CapBackstageShell OR CapStartSession.
// =====================================================================================

// principalWithCaps builds a principal holding EXACTLY the listed capabilities, through a custom
// membership - the only way to separate CapStartSession from CapBackstageShell, because every stock
// preset that grants one grants the other. That is exactly why the old single-capability gate
// looked correct: on the presets it was, and only a CUSTOM role could fall through it.
func principalWithCaps(caps ...Capability) *Principal {
	return &Principal{
		UserID:   auditTechUser,
		TenantID: "tenant-123",
		Grant:    NewGrant(auditTechUser, "tenant-123", NewCapabilityMembership(caps, AllGroups())),
	}
}

// THE FINDING THIS CLOSES. A technician who may run a session - and therefore may RECORD one, since
// the agent gates recording on nothing else - but may not open a backstage shell had their entire
// forwarded batch answered 403. The console SWALLOWS flush failures by design (a briefly-unreachable
// control plane must not tear down a live support session), so the recording audit trail would have
// been silently and permanently absent for that role while every visible part of the feature worked.
func TestIngestAcceptsAStartSessionOnlyTechnician(t *testing.T) {
	srv, store := auditServer(principalWithCaps(CapStartSession, CapViewMachines))
	batch := chainRange(testSession, 0, 2)

	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: batch})
	if rec.Code != http.StatusOK {
		t.Fatalf("a start_session-only technician was refused: %d (body %s)", rec.Code, rec.Body.String())
	}
	// And it really was STORED. A 200 that dropped the batch would be worse than the 403, because
	// nothing downstream would ever notice.
	tail, err := store.AuditTail(t.Context(), "tenant-123", testSession)
	if err != nil {
		t.Fatalf("AuditTail: %v", err)
	}
	if !tail.Exists || tail.Seq != 1 {
		t.Fatalf("tail = %+v, want the batch stored through seq 1", tail)
	}
}

// The backstage-shell-only half of the OR still works. Without this leg a gate that accepted
// everything would pass the test above.
func TestIngestStillAcceptsABackstageShellOnlyTechnician(t *testing.T) {
	srv, _ := auditServer(principalWithCaps(CapBackstageShell))
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: chainRange(testSession, 0, 1)})
	if rec.Code != http.StatusOK {
		t.Fatalf("a backstage-shell-only technician was refused: %d (body %s)", rec.Code, rec.Body.String())
	}
}

// THE NEGATIVE CONTROL, and what makes this a widening rather than an opening: a principal holding
// NEITHER capability is still refused. CapViewAudit is the pointed choice - an Auditor may READ this
// trail and must never be able to write it.
func TestIngestStillRefusesAPrincipalWithNeitherCapability(t *testing.T) {
	srv, store := auditServer(principalWithCaps(CapViewAudit, CapViewMachines, CapViewSessions))
	rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: chainRange(testSession, 0, 1)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a principal with neither capability", rec.Code)
	}
	if tail, err := store.AuditTail(t.Context(), "tenant-123", testSession); err == nil && tail.Exists {
		t.Fatal("a refused batch must not have been stored")
	}
}

// RequireAny's own contract, tested away from the HTTP layer: an EMPTY list must DENY rather than
// vacuously allow. A ranged loop over an empty slice falls straight through, so a "return nil after
// the loop" implementation would make RequireAny() with no arguments an unconditional allow - an
// insecure default nobody chose, in a brand-new choke point.
func TestRequireAnyDeniesOnAnEmptyCapabilityList(t *testing.T) {
	g := NewGrant("u", "tenant-123", NewMembership(RoleOwner, AllGroups()))
	if err := g.RequireAny(); err == nil {
		t.Fatal("RequireAny() with no capabilities must DENY, even for an owner")
	}
	if err := g.RequireAny(CapBackstageShell); err != nil {
		t.Fatalf("an owner holds backstage_shell: %v", err)
	}
	ro := NewGrant("u", "tenant-123", NewMembership(RoleReadOnly, AllGroups()))
	if err := ro.RequireAny(CapBackstageShell, CapStartSession); err == nil {
		t.Fatal("a read-only role holds neither capability and must be denied")
	}
}
