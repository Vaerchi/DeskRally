package controlplane

// The playback job (docs/63 C7): upload real IVF through the signed API, then remux it. Every test goes
// through the real storage layer and real envelopes; the WebM that comes out is read back from the volume
// with the oracle in recording_webm_test.go.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ivfUpload builds an upload whose segments are the given IVF files.
func ivfUpload(files ...[]byte) *recUpload {
	u := &recUpload{id: newUUID()}
	for _, d := range files {
		u.lens = append(u.lens, len(d))
		u.data = append(u.data, d)
		s := sha256.Sum256(d)
		u.digest = append(u.digest, hex.EncodeToString(s[:]))
	}
	return u
}

// completeUpload runs create -> put -> finish and returns the row at evidence_complete.
func (h *recH) completeUpload(u *recUpload) *RecordingRow {
	h.t.Helper()
	h.mustCreate(u)
	h.putAll(u)
	if st, m := h.finish(u); st != http.StatusOK {
		h.t.Fatalf("finish: %d %v", st, m)
	}
	r := h.row(u)
	if r.State != RecEvidenceComplete {
		h.t.Fatalf("state after finish = %s", r.State)
	}
	return r
}

func framesA() []tFrame {
	var f []tFrame
	for i := 0; i < 40; i++ {
		fr := tFrame{size: 300 + i*11, pts: uint64(i) * 3000}
		if i%15 == 0 {
			fr.key, fr.size = true, 900
		}
		f = append(f, fr)
	}
	return f
}

func framesB(startTicks uint64) []tFrame {
	var f []tFrame
	for i := 0; i < 25; i++ {
		fr := tFrame{size: 250 + i*7, pts: startTicks + uint64(i)*4500}
		if i == 0 || i == 12 {
			fr.key, fr.size = true, 700
		}
		f = append(f, fr)
	}
	return f
}

// readPlayback decrypts a segment's WebM copy from the volume.
func (h *recH) readPlayback(r *RecordingRow, idx int) []byte {
	h.t.Helper()
	pb := r.Segments[idx].Playback
	if pb == nil {
		h.t.Fatalf("segment %d has no playback metadata", idx)
	}
	f, size, err := h.files.OpenFinal(r.TenantID, r.ID, uint32(idx), RepWebM)
	if err != nil {
		h.t.Fatalf("open playback %d: %v", idx, err)
	}
	defer f.Close()
	meta, _ := recEnvMeta(r, idx, pb.WebMLen, RepWebM)
	rd, err := OpenEnvelope(f, size, h.keys, EnvelopeExpect{TenantID: meta.TenantID, RecordingID: meta.RecordingID, Segment: meta.Segment, Rep: RepWebM, Generation: meta.Generation}, false)
	if err != nil {
		h.t.Fatalf("open playback envelope %d: %v", idx, err)
	}
	var out bytes.Buffer
	if _, err := rd.WriteTo(&out); err != nil {
		h.t.Fatalf("decrypt playback %d: %v", idx, err)
	}
	return out.Bytes()
}

func incomingEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, ".incoming"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestMuxJobProducesPlaybackAndLeavesEvidenceByteIdentical(t *testing.T) {
	h := newRecH(t, recHOpts{})
	a, b := framesA(), framesB(10*90000)
	ivfA := buildIVF(320, 200, 90000, 1, a, uint32(len(a)))
	ivfB := buildIVF(640, 360, 90000, 1, b, uint32(len(b)))
	u := ivfUpload(ivfA, ivfB)
	r := h.completeUpload(u)
	evBefore := [][]byte{h.readFinal(r, 0), h.readFinal(r, 1)}

	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err != nil {
		t.Fatalf("mux: %v", err)
	}
	r = h.row(u)
	if r.State != RecPlaybackReady || r.PlaybackError != "" {
		t.Fatalf("state = %s (%s)", r.State, r.PlaybackError)
	}
	// Per-segment metadata is what the IVF said, on the recording's own timeline.
	p0, p1 := r.Segments[0].Playback, r.Segments[1].Playback
	if p0.Width != 320 || p0.Height != 200 || p0.Frames != 40 || p0.StartMs != 0 ||
		p1.Width != 640 || p1.Height != 360 || p1.Frames != 25 || p1.StartMs != 10_000 {
		t.Fatalf("playback metadata: %+v %+v", p0, p1)
	}
	if p1.StartMs < p0.StartMs+p0.DurationMs-100 || p0.DurationMs <= 0 || p1.DurationMs <= 0 {
		t.Errorf("timeline overlap/zero duration: %+v %+v", p0, p1)
	}
	// The stored WebM is the muxer's output for exactly these frames (independent oracle).
	out0, out1 := h.readPlayback(r, 0), h.readPlayback(r, 1)
	verifyAgainstIVF(t, out0, a, 320, 200, 90000, 1)
	verifyAgainstIVF(t, out1, b, 640, 360, 90000, 1)
	if int64(len(out0)) != p0.WebMLen || int64(len(out1)) != p1.WebMLen {
		t.Errorf("stored length differs from the recorded one: %d/%d vs %d/%d", len(out0), len(out1), p0.WebMLen, p1.WebMLen)
	}
	// EVIDENCE is byte-identical, digests unchanged, and the evidence files are still the only IVF there.
	for i := range evBefore {
		if !bytes.Equal(h.readFinal(r, i), evBefore[i]) || r.Segments[i].SHA256 != u.digest[i] {
			t.Errorf("evidence segment %d changed", i)
		}
	}
	if left := incomingEntries(t, h.dir); len(left) != 0 {
		t.Errorf("temp directories left behind: %v", left)
	}
	// Idempotent: running again on a ready recording does nothing.
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err != nil || h.row(u).State != RecPlaybackReady {
		t.Fatalf("second run: %v state %s", err, h.row(u).State)
	}
}

func TestMuxJobFailureNeverTouchesTheEvidence(t *testing.T) {
	cases := map[string]struct {
		data  []byte
		limit func(*MuxLimits)
		code  string
	}{
		"not IVF at all": {data: randBytes(5000), code: MuxInvalid},
		"valid container, frames over the server bound": {
			data:  buildIVF(64, 48, 90000, 1, framesA(), 0),
			limit: func(l *MuxLimits) { l.MaxFrames = 5 },
			code:  MuxLimit,
		},
		"truncated IVF": {
			data: func() []byte { b := buildIVF(64, 48, 90000, 1, framesA(), 0); return b[:len(b)-9] }(),
			code: MuxInvalid,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRecH(t, recHOpts{})
			if c.limit != nil {
				l := DefaultMuxLimits()
				c.limit(&l)
				h.srv.Recording.MuxConfig.Limits = &l
			}
			u := ivfUpload(c.data)
			r := h.completeUpload(u)
			before := h.readFinal(r, 0)
			completedAt := *r.EvidenceCompleteAt
			if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err == nil {
				t.Fatal("a bad input produced no error")
			}
			r = h.row(u)
			if r.State != RecPlaybackFailed || r.PlaybackError != c.code {
				t.Fatalf("state = %s reason = %q, want playback_failed / %s", r.State, r.PlaybackError, c.code)
			}
			// Evidence is intact: bytes, digest, completion time; no playback file, no temp directory.
			if !bytes.Equal(h.readFinal(r, 0), before) || r.Segments[0].SHA256 != u.digest[0] || !r.EvidenceCompleteAt.Equal(completedAt) {
				t.Error("a muxer failure changed the evidence")
			}
			if h.files.FinalExists(h.tenant, u.id, 0, RepWebM) {
				t.Error("a failed mux left a playback file")
			}
			if left := incomingEntries(t, h.dir); len(left) != 0 {
				t.Errorf("temp directories left behind: %v", left)
			}
			// A failed recording is not retried implicitly by the sweep (it would starve the workers on a
			// pathological input every tick) ...
			rep, err := h.srv.Recording.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range rep.PlaybackPending {
				if p.ID == u.id {
					t.Error("a playback_failed recording is offered to the muxer again by the sweep")
				}
			}
			// ... but the job itself accepts an explicit retry from playback_failed.
			if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err == nil {
				t.Error("the retry of a still-bad input reported success")
			}
		})
	}
}

func TestMuxJobRefusesASegmentThatStartsBeforeThePreviousEnded(t *testing.T) {
	h := newRecH(t, recHOpts{})
	a := framesA() // ends at ~1.3 s
	b := framesB(0)
	b[0].pts = 0 // overlaps segment 0: wall-clock goes backwards across the boundary
	// segment 0's last frame is at 39*3000 ticks = 1.3 s; start segment 1 at 0.5 s
	for i := range b {
		b[i].pts = 45000 + uint64(i)*3000
	}
	u := ivfUpload(buildIVF(64, 48, 90000, 1, a, 0), buildIVF(64, 48, 90000, 1, b, 0))
	h.completeUpload(u)
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err == nil {
		t.Fatal("overlapping segments were accepted")
	}
	if r := h.row(u); r.State != RecPlaybackFailed || r.PlaybackError != MuxInvalid {
		t.Fatalf("state = %s reason = %q", r.State, r.PlaybackError)
	}
}

func TestMuxJobWindowFollowsTheSessionLength(t *testing.T) {
	h := newRecH(t, recHOpts{})
	// The session lasted one second; the recording claims frames an hour in. The window (session length
	// + 15 min of slack) refuses it.
	frames := []tFrame{{size: 100, pts: 0, key: true}, {size: 100, pts: 90000 * 3600}}
	u := ivfUpload(buildIVF(64, 48, 90000, 1, frames, 0))
	h.completeUpload(u)
	sess, _ := h.sessions.GetSession(context.Background(), h.tenant, h.session)
	if _, err := h.sessions.EndSession(context.Background(), h.tenant, h.session, sess.StartedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err == nil {
		t.Fatal("frames an hour into a one-second session were accepted")
	}
	if r := h.row(u); r.State != RecPlaybackFailed || r.PlaybackError != MuxLimit {
		t.Fatalf("state = %s reason = %q, want playback_failed / limit_exceeded", r.State, r.PlaybackError)
	}
}

func TestMuxJobOnlyDerivesFromTheVerifiedEvidence(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u)
	// The stored digest no longer matches what pass 2 reads (simulates the evidence differing from what
	// finish verified): the job must refuse rather than publish a copy of unverified bytes.
	h.store.mu.Lock()
	h.store.rows[recKey(h.tenant, u.id)].Segments[0].SHA256 = hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	h.store.mu.Unlock()
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err == nil {
		t.Fatal("a copy was published for bytes that do not match the verified digest")
	}
	if r := h.row(u); r.State != RecPlaybackFailed || r.PlaybackError != MuxInconsistent {
		t.Fatalf("state = %s reason = %q", r.State, r.PlaybackError)
	}
	if h.files.FinalExists(h.tenant, u.id, 0, RepWebM) {
		t.Error("a playback file was PUBLISHED for unverified evidence")
	}
}

func TestMuxJobCancellationRecordsNothingAndBudgetRecordsFailure(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u)

	// Shutdown (cancel): the row stays evidence_complete, so the next process retries it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.srv.MuxRecording(ctx, h.tenant, u.id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled job: %v", err)
	}
	if r := h.row(u); r.State != RecEvidenceComplete || r.PlaybackError != "" {
		t.Fatalf("a cancelled job recorded an outcome: %s %q", r.State, r.PlaybackError)
	}
	if left := incomingEntries(t, h.dir); len(left) != 0 {
		t.Errorf("a cancelled job left temp directories: %v", left)
	}

	// The job's own time budget ran out: playback_failed(time_budget), NOT retried forever.
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	if err := h.srv.MuxRecording(dctx, h.tenant, u.id); err == nil {
		t.Fatal("an expired job succeeded")
	}
	if r := h.row(u); r.State != RecPlaybackFailed || r.PlaybackError != MuxTimeBudget {
		t.Fatalf("state = %s reason = %q, want playback_failed / time_budget", r.State, r.PlaybackError)
	}
	// An explicit retry with a healthy budget succeeds (failed -> ready).
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if r := h.row(u); r.State != RecPlaybackReady || r.PlaybackError != "" {
		t.Fatalf("after retry: %s %q", r.State, r.PlaybackError)
	}
}

func TestMuxJobConcurrentRunsLeaveOneValidOutcome(t *testing.T) {
	h := newRecH(t, recHOpts{})
	a := framesA()
	u := ivfUpload(buildIVF(64, 48, 90000, 1, a, 0), buildIVF(64, 48, 90000, 1, framesB(90000*5), 0))
	h.completeUpload(u)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = h.srv.MuxRecording(context.Background(), h.tenant, u.id)
		}()
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("run %d: %v", i, e)
		}
	}
	r := h.row(u)
	if r.State != RecPlaybackReady {
		t.Fatalf("state = %s", r.State)
	}
	verifyAgainstIVF(t, h.readPlayback(r, 0), a, 64, 48, 90000, 1)
	verifyAgainstIVF(t, h.readPlayback(r, 1), framesB(90000*5), 64, 48, 90000, 1)
	if left := incomingEntries(t, h.dir); len(left) != 0 {
		t.Errorf("temp directories left behind: %v", left)
	}
}

// ---- the worker pool --------------------------------------------------------------------------

func waitState(t *testing.T, h *recH, u *recUpload, want string) *RecordingRow {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := h.row(u)
		if r.State == want {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = %s (%s), want %s", r.State, r.PlaybackError, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPlaybackQueueRunsAfterFinishAndTheSweepRecoversWhatItDropped(t *testing.T) {
	h := newRecH(t, recHOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Finished while the pool is NOT running: nothing is queued (EnqueuePlayback says so), the row waits.
	u1 := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u1)
	if h.srv.EnqueuePlayback(h.tenant, u1.id) {
		t.Fatal("EnqueuePlayback accepted a job with no workers running")
	}
	if h.row(u1).State != RecEvidenceComplete {
		t.Fatal("state moved without a worker")
	}

	h.srv.StartRecordingPlayback(ctx)
	// The sweep re-offers every evidence_complete row.
	h.srv.runRecordingSweep(ctx)
	waitState(t, h, u1, RecPlaybackReady)

	// A recording finished while the pool runs is remuxed by the finish handler's own enqueue.
	u2 := ivfUpload(buildIVF(32, 32, 90000, 1, framesB(0), 0))
	h.mustCreate(u2)
	h.putAll(u2)
	if st, m := h.finish(u2); st != http.StatusOK {
		t.Fatalf("finish: %d %v", st, m)
	}
	waitState(t, h, u2, RecPlaybackReady)
}

// gateStore blocks GetRecording once ARMED (until released), so a test can hold a worker mid-job and fill
// the queue behind it deterministically. It is armed only after the uploads are done: the upload routes
// call GetRecording too.
type gateStore struct {
	*InMemoryRecordingStore
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *gateStore) GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error) {
	if g.armed.Load() {
		blocked := false
		g.once.Do(func() { blocked = true })
		if blocked {
			close(g.entered)
			select {
			case <-g.release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return g.InMemoryRecordingStore.GetRecording(ctx, tenantID, id)
}

func newGateH(t *testing.T, workers, queue int) (*recH, *gateStore) {
	gate := &gateStore{entered: make(chan struct{}), release: make(chan struct{})}
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		gate.InMemoryRecordingStore = h.store
		h.srv.Recording.Store = gate
		h.srv.Recording.MuxConfig = RecordingMuxConfig{Workers: workers, QueueMax: queue}
	}})
	return h, gate
}

func TestPlaybackQueueIsBoundedDedupedAndNeverBlocksTheCaller(t *testing.T) {
	h, gate := newGateH(t, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mk := func() *recUpload {
		u := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
		h.completeUpload(u) // the pool is not running yet: nothing is enqueued by the finish
		return u
	}
	u1, u2, u3 := mk(), mk(), mk()
	gate.armed.Store(true)
	h.srv.StartRecordingPlayback(ctx)

	if !h.srv.EnqueuePlayback(h.tenant, u1.id) {
		t.Fatal("the first job was not accepted")
	}
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never picked up a job")
	}
	// A job already running is not queued a second time (the queue has a free slot here, so only the
	// duplicate check can refuse it).
	if h.srv.EnqueuePlayback(h.tenant, u1.id) {
		t.Fatal("a job already running was queued twice")
	}
	if !h.srv.EnqueuePlayback(h.tenant, u2.id) {
		t.Fatal("the one free queue slot refused a job")
	}
	start := time.Now()
	if h.srv.EnqueuePlayback(h.tenant, u3.id) {
		t.Error("a full queue accepted another job")
	}
	if time.Since(start) > time.Second {
		t.Error("EnqueuePlayback blocked on a full queue")
	}
	if h.srv.EnqueuePlayback(h.tenant, u1.id) || h.srv.EnqueuePlayback(h.tenant, u2.id) {
		t.Error("a job already running or queued was queued twice")
	}
	close(gate.release)
	waitState(t, h, u1, RecPlaybackReady)
	waitState(t, h, u2, RecPlaybackReady)
	// u3 was dropped by the full queue and is still waiting; the sweep re-offers it.
	if st := h.row(u3).State; st != RecEvidenceComplete {
		t.Fatalf("the dropped job's state = %s", st)
	}
	h.srv.runRecordingSweep(ctx)
	waitState(t, h, u3, RecPlaybackReady)
}

func TestPlaybackJobCancelledByShutdownRecordsNothingAndWorkersStop(t *testing.T) {
	h, gate := newGateH(t, 1, 4)
	ctx, cancel := context.WithCancel(context.Background())
	u := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u)
	gate.armed.Store(true)
	h.srv.StartRecordingPlayback(ctx)
	if !h.srv.EnqueuePlayback(h.tenant, u.id) {
		t.Fatal("not accepted")
	}
	<-gate.entered // the job is in flight
	cancel()
	h.srv.Recording.mux.wg.Wait() // the worker returned
	if r := h.row(u); r.State != RecEvidenceComplete || r.PlaybackError != "" {
		t.Fatalf("a job cancelled by shutdown recorded %s %q", r.State, r.PlaybackError)
	}
	// The pool restarts cleanly afterwards and finishes the job (the next process's retry).
	waitRunningFalse(t, h)
	gate.armed.Store(false)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	h.srv.StartRecordingPlayback(ctx2)
	h.srv.runRecordingSweep(ctx2)
	waitState(t, h, u, RecPlaybackReady)
}

func waitRunningFalse(t *testing.T, h *recH) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m := &h.srv.Recording.mux
		m.mu.Lock()
		running := m.running
		m.mu.Unlock()
		if !running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the pool never reported stopped")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type panicStore struct {
	*InMemoryRecordingStore
	armed atomic.Bool
	once  sync.Once
}

func (p *panicStore) GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error) {
	if p.armed.Load() {
		boom := false
		p.once.Do(func() { boom = true })
		if boom {
			panic("boom")
		}
	}
	return p.InMemoryRecordingStore.GetRecording(ctx, tenantID, id)
}

func TestPlaybackWorkerSurvivesAPanicInAJob(t *testing.T) {
	ps := &panicStore{}
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		ps.InMemoryRecordingStore = h.store
		h.srv.Recording.Store = ps
		h.srv.Recording.MuxConfig = RecordingMuxConfig{Workers: 1, QueueMax: 4}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u1 := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u1)
	ps.armed.Store(true)
	h.srv.StartRecordingPlayback(ctx)
	if !h.srv.EnqueuePlayback(h.tenant, u1.id) { // the job panics inside the worker on its first GetRecording
		t.Fatal("not accepted")
	}
	// The single worker must survive and take the next job.
	u2 := ivfUpload(buildIVF(64, 48, 90000, 1, framesB(0), 0))
	h.mustCreate(u2)
	h.putAll(u2)
	if st, m := h.finish(u2); st != http.StatusOK {
		t.Fatalf("finish: %d %v", st, m)
	}
	waitState(t, h, u2, RecPlaybackReady)
	// The panicking job's recording is not stuck: it was parked as playback_failed("internal").
	if r := waitState(t, h, u1, RecPlaybackFailed); r.PlaybackError != "internal" {
		t.Errorf("reason = %q", r.PlaybackError)
	}
}

// The job only ever works on a completed, not-yet-expired recording: an expired one (its files are being or
// have been deleted) must not get a playback file written into a directory the sweeper is about to remove.
func TestMuxJobIgnoresRecordingsThatAreNotWaitingForPlayback(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u)
	if err := h.store.MarkExpired(context.Background(), h.tenant, u.id); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u.id); err != nil {
		t.Fatalf("mux of an expired recording: %v", err)
	}
	if h.files.FinalExists(h.tenant, u.id, 0, RepWebM) {
		t.Error("a playback file was written for an expired recording")
	}
	if r := h.row(u); r.State != RecExpired {
		t.Errorf("state = %s", r.State)
	}
	// ... and one that is already ready is left alone (its file is not rewritten).
	u2 := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	h.completeUpload(u2)
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u2.id); err != nil {
		t.Fatal(err)
	}
	r := h.row(u2)
	before := h.readPlayback(r, 0)
	st1, _ := os.Stat(filepath.Join(h.dir, h.tenant, u2.id, "0000.webm.enc"))
	time.Sleep(20 * time.Millisecond)
	if err := h.srv.MuxRecording(context.Background(), h.tenant, u2.id); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(filepath.Join(h.dir, h.tenant, u2.id, "0000.webm.enc"))
	if !st1.ModTime().Equal(st2.ModTime()) || !bytes.Equal(before, h.readPlayback(h.row(u2), 0)) {
		t.Error("a ready recording's playback file was rewritten")
	}
}
