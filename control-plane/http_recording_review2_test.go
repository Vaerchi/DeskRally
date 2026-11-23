package controlplane

// Codex implementation review r2 (docs/63): per-recording serialisation of finish / refusal / promotion /
// rollback / abandonment (A1, X5), the bounded finish (A2), the full finish replay comparison (A3) and the
// upload lifetime enforced on every request (X7). Each test names the defect it fails without.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- A1: finish rollback vs a concurrent finish -----------------------------------------------

// undoRaceStore fails the first CompleteEvidence with a non-state error (a database outage), then — at
// the instant the rollback reads the row's state — releases a second finish for the same recording and
// gives it time to commit. Without per-recording serialisation that second finish completes inside the
// rollback's check-then-unpromote window and the rollback then moves ACKNOWLEDGED evidence back to incoming.
type undoRaceStore struct {
	RecordingStore
	failOnce atomic.Bool
	armed    atomic.Bool
	trigger  func()
}

func (s *undoRaceStore) CompleteEvidence(ctx context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error) {
	if s.failOnce.CompareAndSwap(true, false) {
		s.armed.Store(true)
		return nil, errors.New("simulated database outage")
	}
	return s.RecordingStore.CompleteEvidence(ctx, tenantID, id, c)
}

func (s *undoRaceStore) GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error) {
	row, err := s.RecordingStore.GetRecording(ctx, tenantID, id)
	if s.armed.CompareAndSwap(true, false) {
		s.trigger()
	}
	return row, err
}

func TestRecordingFinishRollbackCannotUndoAConcurrentCompletion(t *testing.T) {
	var rs *undoRaceStore
	var h *recH
	var u *recUpload
	type res struct {
		st int
		m  map[string]any
	}
	second := make(chan res, 1)
	h = newRecH(t, recHOpts{wireUp: func(h *recH) {
		rs = &undoRaceStore{RecordingStore: h.store}
		rs.failOnce.Store(true)
		h.srv.Recording.Store = rs
	}})
	rs.trigger = func() {
		go func() {
			st, m := h.finish(u)
			second <- res{st, m}
		}()
		time.Sleep(700 * time.Millisecond) // enough for an unserialised second finish to commit
	}
	u = newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	if st, m := h.finish(u); st != 500 {
		t.Fatalf("first finish: %d %v, want 500 (the injected outage)", st, m)
	}
	r2 := <-second
	if r2.st != 200 {
		t.Fatalf("second finish: %d %v", r2.st, r2.m)
	}
	row := h.row(u)
	if row.State != RecEvidenceComplete {
		t.Fatalf("state %s", row.State)
	}
	if !h.files.FinalExists(h.tenant, u.id, 0, RepIVF) {
		t.Fatal("acknowledged evidence was moved back to incoming by the first finish's rollback")
	}
	if got := h.readFinal(row, 0); string(got) != string(u.data[0]) {
		t.Fatal("final evidence differs from what was uploaded")
	}
}

// ---- A1/X5: the sweeper's abandonment vs a finish between promotion and commit ------------------

type sweepDuringCompleteStore struct {
	RecordingStore
	hook func()
}

func (s *sweepDuringCompleteStore) CompleteEvidence(ctx context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error) {
	if s.hook != nil {
		hk := s.hook
		s.hook = nil
		hk()
	}
	return s.RecordingStore.CompleteEvidence(ctx, tenantID, id, c)
}

func TestRecordingAbandonSerialisesWithAFinishInFlight(t *testing.T) {
	var h *recH
	var u *recUpload
	var ss *sweepDuringCompleteStore
	h = newRecH(t, recHOpts{wireUp: func(h *recH) {
		ss = &sweepDuringCompleteStore{RecordingStore: h.store}
		h.srv.Recording.Store = ss
	}})
	u = newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	row0 := h.row(u)
	var rep RecordingSweepReport
	swept := make(chan struct{})
	ss.hook = func() { // runs after every segment was promoted, right before the state commit
		go func() {
			defer close(swept)
			h.srv.Recording.sweepRetentionRow(context.Background(), RecordingSweepRow{TenantID: h.tenant, ID: u.id, UploadID: row0.UploadID,
				State: RecUploading, CreatedAt: row0.CreatedAt}, SweepAbandon, time.Now(), RecordingSweepConfig{DeletionLagAlert: time.Hour}, &rep)
		}()
		time.Sleep(500 * time.Millisecond)
	}
	if st, m := h.finish(u); st != 200 {
		t.Fatalf("finish: %d %v (an abandonment slipped in between promotion and commit)", st, m)
	}
	<-swept
	if rep.Abandoned != 0 {
		t.Fatal("the sweeper abandoned a recording whose finish was committing")
	}
	row := h.row(u)
	if row.State != RecEvidenceComplete || !h.files.FinalExists(h.tenant, u.id, 0, RepIVF) {
		t.Fatalf("state %s, final exists=%v", row.State, h.files.FinalExists(h.tenant, u.id, 0, RepIVF))
	}
}

// ---- X5: an admitted PUT cannot write after the recording was abandoned -------------------------

type abandonBeforeUpdateStore struct {
	RecordingStore
	files *RecordingStorage
	once  sync.Once
}

func (s *abandonBeforeUpdateStore) UpdateSegment(ctx context.Context, tenantID, id string, idx int, fn SegmentUpdateFn) error {
	s.once.Do(func() { // the PUT is admitted and has read its body; cleanup then runs
		row, _ := s.RecordingStore.GetRecording(ctx, tenantID, id)
		if err := s.RecordingStore.AbandonRecording(ctx, tenantID, id); err != nil {
			panic(err)
		}
		_, _ = s.files.RemoveIncoming(row.UploadID)
	})
	return s.RecordingStore.UpdateSegment(ctx, tenantID, id, idx, fn)
}

func TestRecordingAdmittedPutCannotWriteAfterAbandon(t *testing.T) {
	var h *recH
	h = newRecH(t, recHOpts{wireUp: func(h *recH) {
		h.srv.Recording.Store = &abandonBeforeUpdateStore{RecordingStore: h.store, files: h.files}
	}})
	u := newRecUpload(2 * mib)
	h.mustCreate(u)
	upload := h.row(u).UploadID
	if st, m := h.put(u, 0, 0); st != 409 {
		t.Fatalf("put after abandon: %d %v, want 409", st, m)
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".incoming", upload)); err == nil {
		t.Fatal("a PUT admitted before the abandonment re-created the incoming directory")
	}
	if got := h.row(u); got.State != RecAbandoned || got.Segments[0].CommittedOffset != 0 {
		t.Fatalf("row %s offset %d", got.State, got.Segments[0].CommittedOffset)
	}
}

// ---- A2: a bounded, serialised, coalesced finish -----------------------------------------------

// blockingAudit makes the provenance scan wait for its context (a hung audit database).
type blockingAudit struct {
	AuditStore
	calls atomic.Int32
}

func (b *blockingAudit) ListAuditEventsAsc(ctx context.Context, _ string, _ AuditExportQuery) ([]AuditEvent, int64, error) {
	b.calls.Add(1)
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

// finishWithin runs a finish and fails the test (cutting the connections so the server handler can end)
// when it has not answered in d.
func (h *recH) finishWithin(u *recUpload, d time.Duration) (int, map[string]any) {
	h.t.Helper()
	type res struct {
		st int
		m  map[string]any
	}
	ch := make(chan res, 1)
	go func() {
		st, m := h.finish(u)
		ch <- res{st, m}
	}()
	select {
	case r := <-ch:
		return r.st, r.m
	case <-time.After(d):
		h.ts.CloseClientConnections()
		h.t.Fatalf("finish still running after %s: its work is not bounded", d)
		return 0, nil
	}
}

func TestRecordingFinishHasAnExplicitWorkBudget(t *testing.T) {
	ba := &blockingAudit{}
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{FinishWork: 400 * time.Millisecond}, wireUp: func(h *recH) {
		ba.AuditStore = h.audit
		h.srv.Audit = ba
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	st, m := h.finishWithin(u, 6*time.Second)
	if st != 503 || jstr(m, "error") != "audit_unavailable" {
		t.Fatalf("%d %v, want 503 audit_unavailable once the finish budget is spent", st, m)
	}
	if h.row(u).State != RecUploading || h.files.FinalExists(h.tenant, u.id, 0, RepIVF) {
		t.Fatal("a timed-out finish left state behind")
	}
}

func TestRecordingSegmentDigestStopsWhenCancelled(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(3 * EnvFrameSize)
	h.mustCreate(u)
	h.putAll(u)
	row := h.row(u)
	if _, err := h.srv.recSegmentDigest(context.Background(), row, 0); err != nil {
		t.Fatalf("uncancelled digest: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.srv.recSegmentDigest(ctx, row, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled digest pass returned %v, want context.Canceled", err)
	}
}

// endlessAudit pages forever: every page holds one unrelated event and a cursor that advances.
type endlessAudit struct {
	AuditStore
	pages atomic.Int32
}

func (e *endlessAudit) ListAuditEventsAsc(_ context.Context, _ string, q AuditExportQuery) ([]AuditEvent, int64, error) {
	e.pages.Add(1)
	return []AuditEvent{{SessionID: q.SessionID, Action: json.RawMessage(`{"kind":"noise"}`)}}, q.AfterIngestSeq + 1, nil
}

func TestRecordingProvenanceTraversalIsBounded(t *testing.T) {
	old := recProvenanceMaxPages
	recProvenanceMaxPages = 5
	defer func() { recProvenanceMaxPages = old }()
	ea := &endlessAudit{}
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		ea.AuditStore = h.audit
		h.srv.Audit = ea
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	st, m := h.finishWithin(u, 6*time.Second)
	if st != 503 || jstr(m, "error") != "audit_unavailable" {
		t.Fatalf("%d %v, want 503 audit_unavailable for an unbounded chain", st, m)
	}
	if n := ea.pages.Load(); n != 5 {
		t.Fatalf("scanned %d pages, want exactly the bound (5)", n)
	}
	if h.row(u).State != RecUploading {
		t.Fatal("state moved although provenance could not be established")
	}
}

// slowAudit counts provenance scans (one per real verification) and makes each slow enough that
// concurrent finishes overlap.
type slowAudit struct {
	AuditStore
	calls atomic.Int32
}

func (s *slowAudit) ListAuditEventsAsc(ctx context.Context, tenantID string, q AuditExportQuery) ([]AuditEvent, int64, error) {
	s.calls.Add(1)
	time.Sleep(150 * time.Millisecond)
	return s.AuditStore.ListAuditEventsAsc(ctx, tenantID, q)
}

func TestRecordingConcurrentFinishesAreCoalesced(t *testing.T) {
	sa := &slowAudit{}
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		sa.AuditStore = h.audit
		h.srv.Audit = sa
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	const n = 5
	sts := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			st, _ := h.finish(u)
			sts <- st
		}()
	}
	for i := 0; i < n; i++ {
		if st := <-sts; st != 200 {
			t.Fatalf("concurrent finish %d answered %d, want 200 (replay of the winner)", i, st)
		}
	}
	if c := sa.calls.Load(); c != 1 {
		t.Fatalf("%d verification passes ran for %d concurrent finishes of one recording, want 1", c, n)
	}
}

// ---- A3: the replay comparison covers frames and payload_bytes ---------------------------------

func (h *recH) finishWith(u *recUpload, extra map[string]any) (int, map[string]any) {
	h.t.Helper()
	body := map[string]any{"recording_id": u.id, "generation": 1, "digests": u.digest, "truncated": nil, "dropped_frames": 0}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: raw})
	return st, m
}

func TestRecordingFinishReplayComparesFramesAndPayload(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	if st, m := h.finishWith(u, map[string]any{"frames": 5, "payload_bytes": 10}); st != 200 {
		t.Fatalf("finish: %d %v", st, m)
	}
	cases := []struct {
		name  string
		extra map[string]any
		want  int
	}{
		{"identical replay", map[string]any{"frames": 5, "payload_bytes": 10}, 200},
		{"different frames", map[string]any{"frames": 6, "payload_bytes": 10}, 409},
		{"different payload", map[string]any{"frames": 5, "payload_bytes": 11}, 409},
		{"frames absent", map[string]any{"payload_bytes": 10}, 409},
		{"payload absent", map[string]any{"frames": 5}, 409},
		{"both absent", map[string]any{}, 409},
	}
	for _, c := range cases {
		if st, m := h.finishWith(u, c.extra); st != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, st, m, c.want)
		}
	}
	// And the other way round: stored without the optional claims, replayed with them.
	h2 := newRecH(t, recHOpts{})
	u2 := newRecUpload(100)
	h2.mustCreate(u2)
	h2.putAll(u2)
	if st, m := h2.finishWith(u2, nil); st != 200 {
		t.Fatalf("finish: %d %v", st, m)
	}
	if st, m := h2.finishWith(u2, map[string]any{"frames": 5}); st != 409 {
		t.Fatalf("replay adding frames: %d %v, want 409", st, m)
	}
	if st, m := h2.finishWith(u2, nil); st != 200 {
		t.Fatalf("identical bare replay: %d %v", st, m)
	}
}

// racedCompletionStore completes the recording with ANOTHER claim first (a concurrent finish that won
// outside this process's lock), so the real CompleteEvidence answers ErrRecordingState.
type racedCompletionStore struct {
	RecordingStore
	other EvidenceCompletion
	done  bool
}

func (s *racedCompletionStore) CompleteEvidence(ctx context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error) {
	if !s.done {
		s.done = true
		if _, err := s.RecordingStore.CompleteEvidence(ctx, tenantID, id, s.other); err != nil {
			panic(err)
		}
	}
	return s.RecordingStore.CompleteEvidence(ctx, tenantID, id, c)
}

func TestRecordingConcurrentCompletionPathComparesFramesAndPayload(t *testing.T) {
	five := int64(5)
	for _, tc := range []struct {
		name  string
		extra map[string]any
		want  int
	}{
		{"same claim", map[string]any{"frames": 5}, 200},
		{"other frames", map[string]any{"frames": 6}, 409},
		{"frames where the winner had none", map[string]any{"frames": 5, "payload_bytes": 9}, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var u *recUpload
			h := newRecH(t, recHOpts{})
			u = newRecUpload(100)
			zero := int64(0)
			h.srv.Recording.Store = &racedCompletionStore{RecordingStore: h.store, other: EvidenceCompletion{
				Digests: u.digest, DroppedFrames: &zero, Frames: &five, Provenance: ProvNoStopEvent}}
			h.mustCreate(u)
			h.putAll(u)
			if st, m := h.finishWith(u, tc.extra); st != tc.want {
				t.Fatalf("%d %v, want %d", st, m, tc.want)
			}
		})
	}
}

// ---- X7: the upload lifetime holds on every request, not only at the sweep ---------------------

func TestRecordingUploadLifetimeIsEnforcedOnEveryRequest(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(2 * mib)
	h.store.Now = func() time.Time { return time.Now().Add(-RecMaxUploadLifetime - time.Minute) } // created 24 h + 1 min ago
	h.mustCreate(u)
	h.store.Now = nil
	if st, m := h.put(u, 0, 0); st != 410 || jstr(m, "error") != "upload_expired" {
		t.Fatalf("put: %d %v, want 410 upload_expired (no sweep has run)", st, m)
	}
	if st, _ := h.head(u, 0); st != 410 {
		t.Fatalf("head: %d, want 410", st)
	}
	if st, m := h.finish(u); st != 410 {
		t.Fatalf("finish: %d %v, want 410", st, m)
	}
	if st, m := h.create(u); st != 410 || jstr(m, "error") != "upload_expired" {
		t.Fatalf("create replay: %d %v, want 410 (a replay must not revive a dead upload)", st, m)
	}
	if h.row(u).Segments[0].CommittedOffset != 0 {
		t.Fatal("bytes were committed to an expired upload")
	}
	// Just inside the bound still works.
	v := newRecUpload(100)
	h.store.Now = func() time.Time { return time.Now().Add(-RecMaxUploadLifetime + time.Minute) }
	h.mustCreate(v)
	h.store.Now = nil
	h.putAll(v)
	if st, m := h.finish(v); st != http.StatusOK {
		t.Fatalf("an upload inside its lifetime: %d %v", st, m)
	}
}

// ---- B2 at the sweeper: a shortened deadline holds after the policy is lengthened or turned off -----

func TestRecordingSweepPersistsAShortenedDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after int // the policy in force when the second sweep runs
	}{{"lengthened to 90 days", 90}, {"storage switched off", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRecH(t, recHOpts{})
			u := h.complete(100) // retention 30 days
			h.setPolicyDays(5)
			h.skew(24 * time.Hour)
			if rep := h.sweep(); rep.Expired != 0 {
				t.Fatalf("expired a day into a 5-day retention: %+v", rep)
			}
			got := h.row(u)
			if want := got.EvidenceCompleteAt.Add(5 * 24 * time.Hour); !got.ExpiresAt.Equal(want) {
				t.Fatalf("the sweep did not persist the shortened deadline: %v, want %v", got.ExpiresAt, want)
			}
			h.setPolicyDays(tc.after)
			h.skew(10 * 24 * time.Hour)
			rep := h.sweep()
			if rep.Expired != 1 || rep.Deleted != 1 {
				t.Fatalf("day 10 with a durable 5-day deadline: %+v (the longer schedule came back)", rep)
			}
		})
	}
}

// ---- review r3: the authoritative post-lock load runs under the finish budget -----------------------

// stallSecondLoadStore blocks the SECOND GetRecording of a recording (the post-lock re-read) until the
// context it was given is done.
type stallSecondLoadStore struct {
	RecordingStore
	calls atomic.Int32
}

func (s *stallSecondLoadStore) GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error) {
	if s.calls.Add(1) == 2 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.RecordingStore.GetRecording(ctx, tenantID, id)
}

func TestRecordingFinishPostLockLoadEndsWithTheFinishBudget(t *testing.T) {
	var ss *stallSecondLoadStore
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{FinishWork: 400 * time.Millisecond}, wireUp: func(h *recH) {
		ss = &stallSecondLoadStore{RecordingStore: h.store}
		h.srv.Recording.Store = ss
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	ss.calls.Store(0)
	// The request context stays live (the client waits); only FinishWork can end the stalled load.
	st, m := h.finishWithin(u, 6*time.Second)
	if st != 503 || jstr(m, "error") != "busy" {
		t.Fatalf("%d %v, want 503 busy when the post-lock load outlives FinishWork", st, m)
	}
	if h.row(u).State != RecUploading {
		t.Fatal("state moved")
	}
}
