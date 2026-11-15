package controlplane

// LIVE-POSTGRES proof for the loop-91 session-scoped audit trail: session-recording events EXTEND
// the session's existing chain instead of forking a new one, and they SURVIVE the round trip
// through jsonb.
//
// Gated behind TEST_DATABASE_URL like every other pg test here; verify-all.ps1 sets it, and treats a
// skip as a failure.
//
// PREMISE, DECLARED LOCALLY so it cannot drift with a doc:
//
// The backstage trail is hash-chained PER SESSION, not per tenant. `tailTx` (pgstore.go) keys the
// tail read on `session_id` ALONE, and every new session_id starts at seq 0 with prev_hash "". The
// per-TENANT ordering is `ingest_seq`, which migration 0019's own header says is deliberately
// EXCLUDED from the hashed preimage. So "extend the tenant's chain rather than fork it" is not a
// statement about a tenant-wide hash chain — there isn't one — and testing for one would pin a
// property the schema does not have. What is real, and what loop 91 actually changed, is this:
//
//	ONE SESSION == ONE CHAIN, and a recording event is just another event on it.
//
// Before the lift, the agent built its chain inside `Dispatcher::new` from a backstage GRANT. A
// session with no grant had no chain at all, and a SECOND grant restarted the chain at seq 0 — a
// fork the console's seq-keyed dedupe then silently discarded. These tests pin the post-lift shape
// at the layer that actually persists it, plus the two ways jsonb has previously eaten an event.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The action bodies a real agent seals. Built through json.Marshal rather than written as literals
// so the escaping of the Windows path is produced the same way serde produces it.
func recordingStartedAction(t *testing.T, dir string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"kind":               "recording_started",
		"started_at_unix_ms": int64(1730000000000),
		"directory":          dir,
	})
	if err != nil {
		t.Fatalf("marshal recording_started: %v", err)
	}
	return b
}

func recordingStoppedAction(t *testing.T, dir string, digests []string, truncated any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"kind":           "recording_stopped",
		"frames":         uint64(913),
		"payload_bytes":  uint64(4211337),
		"truncated":      truncated,
		"dropped_frames": uint64(0),
		"segment_sha256": digests,
		"directory":      dir,
	})
	if err != nil {
		t.Fatalf("marshal recording_stopped: %v", err)
	}
	return b
}

// THE HEADLINE. A session that already has backstage events gets its recording events appended to
// the SAME chain: contiguous seq, prev_hash linking to the stored tail, one row per event, and the
// tenant's ingest_seq advancing densely across the boundary.
//
// A fork would show up here as a LinkageError on the second append (seq 0 against a stored tail of
// 2), which is exactly the failure the pre-lift agent produced and the console hid by de-duplicating
// on seq. Asserting the SUCCESS and then reading the rows back is what distinguishes "extended" from
// "silently dropped".
func TestPgRecordingEventsExtendTheSessionChain(t *testing.T) {
	pool := newTestPool(t) // skips without TEST_DATABASE_URL; applies 0001-0003
	applyAuditMigration(t, pool)

	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := NewPgAuditStore(pool)
	ctx := context.Background()

	const sess = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	dir := goldenRecordingDir()

	// 1. The session's chain already exists — a backstage batch, as a grant-holding technician
	//    produces. This is the state a recording arrives INTO, and having it is what makes the
	//    "extend" claim testable at all.
	pre := chainRange(sess, 0, 3)
	tail, err := store.AppendAudit(ctx, tid, sess, pre)
	if err != nil {
		t.Fatalf("premise not met: the backstage prefix did not store: %v", err)
	}
	if tail.Seq != 2 {
		t.Fatalf("premise not met: tail = %+v, want seq 2", tail)
	}

	// 2. The recording events, chained onto that tail exactly as the agent chains them: seq 3 then
	//    seq 4, each prev_hash the predecessor's hash.
	digests := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	started := mkAuditEvent(sess, 3, tail.Hash, recordingStartedAction(t, dir), defaultAuditOutcome)
	stopped := mkAuditEvent(sess, 4, started.Hash,
		recordingStoppedAction(t, dir, digests, "size_limit"), defaultAuditOutcome)

	newTail, err := store.AppendAudit(ctx, tid, sess, []AuditEvent{started, stopped})
	if err != nil {
		t.Fatalf("recording events did not EXTEND the session chain: %v", err)
	}
	if newTail.Seq != 4 || newTail.Hash != stopped.Hash {
		t.Fatalf("tail after recording = %+v, want seq 4 hash %s", newTail, stopped.Hash)
	}

	// 3. Read the whole chain back and prove it is ONE chain: five rows, seq 0..4 with no gap, every
	//    prev_hash equal to its predecessor's hash, and — the part a seq check alone would miss —
	//    the recording events' prev_hash pointing at the BACKSTAGE event before them.
	rows, err := pool.Query(ctx, `
		SELECT seq, prev_hash, hash, ingest_seq, action->>'kind'
		FROM backstage_audit_event
		WHERE tenant_id = $1 AND session_id = $2
		ORDER BY seq ASC`, tid, sess)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	defer rows.Close()

	type row struct {
		seq       int64
		prev      string
		hash      string
		ingestSeq int64
		kind      string
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.seq, &r.prev, &r.hash, &r.ingestSeq, &r.kind); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("stored %d rows, want 5 — a fork would store the recording pair under a second "+
			"chain (or not at all)", len(got))
	}
	prev := GenesisPrevHash
	for i, r := range got {
		if r.seq != int64(i) {
			t.Fatalf("row %d has seq %d — the chain is not contiguous", i, r.seq)
		}
		if r.prev != prev {
			t.Fatalf("row %d prev_hash = %q, want the predecessor's hash %q — this is the fork",
				i, r.prev, prev)
		}
		prev = r.hash
	}
	if got[3].kind != "recording_started" || got[4].kind != "recording_stopped" {
		t.Fatalf("the recording events are not at seq 3,4: got kinds %q,%q", got[3].kind, got[4].kind)
	}
	// The recording pair links to the BACKSTAGE event, not to a genesis of its own. This is the
	// assertion a per-batch check could not make, and it is the definition of "extended".
	if got[3].prev != got[2].hash || got[3].prev == GenesisPrevHash {
		t.Fatalf("recording_started's prev_hash = %q; it must be the preceding backstage event's "+
			"hash %q, and must NOT be genesis", got[3].prev, got[2].hash)
	}
	// The tenant's ingest cursor is dense across the boundary (0019): a collector tailing it must
	// not skip, and a batch must be contiguous in it.
	for i, r := range got {
		if r.ingestSeq != int64(i) {
			t.Fatalf("row %d ingest_seq = %d, want %d — the tenant cursor gapped across the "+
				"backstage/recording boundary", i, r.ingestSeq, i)
		}
	}
}

// The recording action SURVIVES jsonb byte-for-byte, and the stored row still re-hashes to the
// agent's digest.
//
// This is the `hash-what-STORAGE-returns` discipline, and it is not theoretical for these two
// variants: `segment_sha256` is the first ARRAY in an audit action, `truncated` is a JSON null on a
// clean recording, and `directory` carries backslashes. jsonb does not preserve key order or
// insignificant whitespace, so a naive round-trip check would pass while a re-hash failed — which is
// the failure that matters, because verifyLinkage re-hashes on every subsequent append.
func TestPgRecordingActionSurvivesJsonbAndStillRehashes(t *testing.T) {
	pool := newTestPool(t)
	applyAuditMigration(t, pool)

	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := NewPgAuditStore(pool)
	ctx := context.Background()

	const sess = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	dir := goldenRecordingDir()
	digests := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}

	// A CLEAN recording: `truncated` is JSON null, which is the legal "ran to completion" value and
	// the one a stripped key would be mistaken for.
	ev := mkAuditEvent(sess, 0, GenesisPrevHash,
		recordingStoppedAction(t, dir, digests, nil), defaultAuditOutcome)
	if _, err := store.AppendAudit(ctx, tid, sess, []AuditEvent{ev}); err != nil {
		t.Fatalf("append: %v", err)
	}

	var storedAction, storedOutcome []byte
	var storedHash, storedPrev string
	var storedSeq int64
	var storedOccurred int64
	var storedID, storedTech, storedMachine string
	err := pool.QueryRow(ctx, `
		SELECT id::text, seq, technician_id::text, machine_id::text, occurred_at_ms,
		       action, outcome, prev_hash, hash
		FROM backstage_audit_event WHERE tenant_id = $1 AND session_id = $2`, tid, sess).
		Scan(&storedID, &storedSeq, &storedTech, &storedMachine, &storedOccurred,
			&storedAction, &storedOutcome, &storedPrev, &storedHash)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	// Re-hash what STORAGE returned, not what we sent.
	back := AuditEvent{
		ID:               storedID,
		Seq:              uint64(storedSeq),
		SessionID:        sess,
		TechnicianID:     storedTech,
		MachineID:        storedMachine,
		OccurredAtUnixMs: storedOccurred,
		Action:           json.RawMessage(storedAction),
		Outcome:          json.RawMessage(storedOutcome),
		PrevHash:         storedPrev,
	}
	rehashed, err := recomputeHash(back)
	if err != nil {
		t.Fatalf("recomputeHash on the STORED row: %v — the control plane could not re-verify its "+
			"own stored recording event", err)
	}
	if rehashed != storedHash {
		t.Fatalf("the stored recording event no longer re-hashes:\n stored   %s\n recomputed %s\n"+
			" action as stored: %s", storedHash, rehashed, storedAction)
	}

	// And the fields a reviewer actually needs survived: the digests in ORDER, and the directory
	// with its backslash intact.
	var parsed struct {
		Kind      string   `json:"kind"`
		Digests   []string `json:"segment_sha256"`
		Directory string   `json:"directory"`
		Truncated *string  `json:"truncated"`
	}
	if err := json.Unmarshal(storedAction, &parsed); err != nil {
		t.Fatalf("stored action is not the recording shape: %v", err)
	}
	if parsed.Kind != "recording_stopped" {
		t.Fatalf("kind = %q", parsed.Kind)
	}
	if len(parsed.Digests) != 2 || parsed.Digests[0] != digests[0] || parsed.Digests[1] != digests[1] {
		t.Fatalf("segment digests did not survive in order: %v", parsed.Digests)
	}
	if parsed.Directory != dir {
		t.Fatalf("directory = %q, want %q — the path a reviewer is told to go and look in", parsed.Directory, dir)
	}
	if parsed.Truncated != nil {
		t.Fatalf("a clean recording came back as truncated %q", *parsed.Truncated)
	}
}

// A SECOND session on the same tenant still starts its own chain at seq 0. The per-session scope is
// the design, not an accident of the lift, and a change that made the chain tenant-wide would break
// every concurrent session — so this is the negative control for the test above.
func TestPgASecondSessionStillStartsItsOwnRecordingChain(t *testing.T) {
	pool := newTestPool(t)
	applyAuditMigration(t, pool)

	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := NewPgAuditStore(pool)
	ctx := context.Background()

	const sessA = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	const sessB = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	dir := goldenRecordingDir()

	a := mkAuditEvent(sessA, 0, GenesisPrevHash, recordingStartedAction(t, dir), defaultAuditOutcome)
	if _, err := store.AppendAudit(ctx, tid, sessA, []AuditEvent{a}); err != nil {
		t.Fatalf("session A: %v", err)
	}
	b := mkAuditEvent(sessB, 0, GenesisPrevHash, recordingStartedAction(t, dir), defaultAuditOutcome)
	tailB, err := store.AppendAudit(ctx, tid, sessB, []AuditEvent{b})
	if err != nil {
		t.Fatalf("a second session's genesis was refused, so the chain is not per-session: %v", err)
	}
	if tailB.Seq != 0 {
		t.Fatalf("session B tail = %+v, want its own seq 0", tailB)
	}

	// The tenant-wide cursor still advanced across the two chains, which is what a SIEM collector
	// tails. Two independent hash chains, one ingest order.
	var maxIngest int64
	if err := pool.QueryRow(ctx,
		`SELECT max(ingest_seq) FROM backstage_audit_event WHERE tenant_id = $1`, tid).
		Scan(&maxIngest); err != nil {
		t.Fatalf("ingest cursor: %v", err)
	}
	if maxIngest != 1 {
		t.Fatalf("tenant ingest_seq reached %d across two sessions, want 1", maxIngest)
	}
}
