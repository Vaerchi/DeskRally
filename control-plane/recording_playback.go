package controlplane

// The playback job: remux a completed recording's IVF evidence into WebM, off the request path
// (docs/63 D7, §2a C7).
//
//	finish -> evidence_complete  (the upload path, http_recording_upload.go)
//	          └─ EnqueuePlayback ─> bounded queue ─> worker ─> MuxRecording ─> playback_ready | playback_failed
//
// EVIDENCE AND PLAYBACK ARE SEPARATE. The job reads the evidence copy and writes new files; it never
// modifies, truncates or deletes an evidence file, and it never touches the segment digests. A muxer
// failure moves the row to playback_failed with a CLOSED reason code — the evidence stays complete, stays
// downloadable, and expires on its own schedule.
//
// BOUNDS. The queue is bounded (a full queue drops the enqueue — never blocks the upload handler — and the
// recording is picked up again by the next sweep, which re-enqueues every evidence_complete row), the
// worker count is fixed, every job has a time budget, and shutdown cancels the running jobs. A job that
// was cancelled by shutdown records NOTHING: the row stays evidence_complete and the next process retries
// it. A job that ran out of ITS budget records playback_failed("time_budget") — retrying forever would
// let one pathological input starve the workers every five minutes.
//
// CONCURRENCY ACROSS REPLICAS. Every attempt writes its temp files under its OWN fresh incoming directory
// and publishes with an atomic rename, so two replicas muxing the same recording at once cannot corrupt
// each other's output (each file is a complete, independently valid envelope); the store admits exactly
// one of them as the outcome (RecordPlayback refuses ready -> ready).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"sync"
	"time"
)

// RecordingMuxConfig tunes the playback worker pool; zero values mean defaults.
type RecordingMuxConfig struct {
	Workers   int           // default 2
	QueueMax  int           // default 64
	JobBudget time.Duration // per recording, default 10 minutes
	// Limits are the server-owned muxer bounds; nil = DefaultMuxLimits().
	Limits *MuxLimits
}

func (c RecordingMuxConfig) withDefaults() RecordingMuxConfig {
	if c.Workers <= 0 {
		c.Workers = 2
	}
	if c.QueueMax <= 0 {
		c.QueueMax = 64
	}
	if c.JobBudget <= 0 {
		c.JobBudget = 10 * time.Minute
	}
	return c
}

func (c RecordingMuxConfig) limits() MuxLimits {
	if c.Limits != nil {
		return *c.Limits
	}
	return DefaultMuxLimits()
}

type muxJob struct{ tenantID, id string }

// recMux is the worker pool's state, hung off RecordingWiring.
type recMux struct {
	mu      sync.Mutex
	cfg     RecordingMuxConfig
	jobs    chan muxJob
	pending map[string]struct{} // queued or running
	wg      sync.WaitGroup
	running bool
}

func (m *recMux) key(j muxJob) string { return j.tenantID + "/" + j.id }

// StartRecordingPlayback starts the worker pool; it stops (and cancels running jobs) with ctx. It is a
// no-op when central recording is not wired or the pool is already running.
func (s *Server) StartRecordingPlayback(ctx context.Context) {
	w := &s.Recording
	if !w.ready() {
		return
	}
	m := &w.mux
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.cfg = w.MuxConfig.withDefaults()
	m.jobs = make(chan muxJob, m.cfg.QueueMax)
	m.pending = make(map[string]struct{})
	m.running = true
	m.mu.Unlock()
	for i := 0; i < m.cfg.Workers; i++ {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-m.jobs:
					s.runMuxJob(ctx, j)
				}
			}
		}()
	}
	go func() { // stopped: let a later Start begin afresh
		<-ctx.Done()
		m.wg.Wait()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
}

// EnqueuePlayback queues a remux. It never blocks and never fails the caller: false means "not queued"
// (pool not running, already queued, or the queue is full) and the sweep will offer the recording again.
func (s *Server) EnqueuePlayback(tenantID, id string) bool {
	m := &s.Recording.mux
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return false
	}
	j := muxJob{tenantID, id}
	if _, dup := m.pending[m.key(j)]; dup {
		return false
	}
	select {
	case m.jobs <- j:
		m.pending[m.key(j)] = struct{}{}
		return true
	default:
		log.Printf("recording playback: queue full; %s will be picked up by the next sweep", id)
		return false
	}
}

func (s *Server) runMuxJob(parent context.Context, j muxJob) {
	m := &s.Recording.mux
	defer func() {
		m.mu.Lock()
		delete(m.pending, m.key(j))
		m.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, m.cfg.JobBudget)
	defer cancel()
	defer func() { // a panic in a worker must not take the control plane down
		if p := recover(); p != nil {
			log.Printf("recording playback: PANIC remuxing %s: %v", j.id, p)
			_ = s.Recording.Store.RecordPlayback(context.WithoutCancel(parent), j.tenantID, j.id,
				PlaybackResult{OK: false, Reason: "internal"})
		}
	}()
	if err := s.MuxRecording(ctx, j.tenantID, j.id); err != nil {
		log.Printf("recording playback: %s: %v", j.id, err)
	}
}

// muxFailureCode classifies a job error into the closed reason set. cancelled means "record nothing".
func muxFailureCode(ctx context.Context, err error) (code string, cancelled bool) {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)):
		return MuxTimeBudget, false
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return "", true
	}
	var me *MuxError
	if errors.As(err, &me) {
		return me.Code, false
	}
	return "internal", false
}

// MuxRecording remuxes one recording's evidence into its playback copy and records the outcome. It is
// synchronous (the worker calls it; tests call it directly) and idempotent: a recording that is not
// evidence_complete or playback_failed is left alone.
func (s *Server) MuxRecording(ctx context.Context, tenantID, id string) error {
	w := &s.Recording
	row, err := w.Store.GetRecording(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if row.State != RecEvidenceComplete && row.State != RecPlaybackFailed {
		return nil
	}
	if s.recLogicallyExpired(row.State, row.ExpiresAt) {
		return nil // past its retention: no new playback copy for content that is about to be deleted
	}
	lim := w.MuxConfig.limits()
	// The recording's WINDOW (C7): no frame may be later than the session itself lasted (plus slack for
	// clock edges). A session still open or unknown keeps the default window.
	if s.SessionRecords != nil {
		if sess, serr := s.SessionRecords.GetSession(ctx, tenantID, row.SessionID); serr == nil && sess.EndedAt != nil {
			if span := sess.EndedAt.Sub(sess.StartedAt).Milliseconds() + 15*60*1000; span > 0 && span < lim.MaxSpanMs {
				lim.MaxSpanMs = span
			}
		}
	}

	var tempDirs []string
	cleanup := func() {
		for _, u := range tempDirs {
			if _, rerr := w.Files.RemoveIncoming(u); rerr != nil {
				log.Printf("recording playback: remove temp %s: %v (the orphan pass will quarantine it)", u, rerr)
			}
		}
	}
	segs, err := s.muxSegments(ctx, row, lim, &tempDirs)
	cleanup()
	if errors.Is(err, errMuxRowGone) {
		s.muxAbandon(ctx, row) // the row left the playback states mid-job: record nothing, leave nothing behind
		return nil
	}
	if err != nil {
		code, cancelled := muxFailureCode(ctx, err)
		if cancelled {
			return err
		}
		if rerr := w.Store.RecordPlayback(context.WithoutCancel(ctx), tenantID, id, PlaybackResult{OK: false, Reason: code}); rerr != nil {
			if errors.Is(rerr, ErrRecordingState) {
				s.muxAbandon(ctx, row) // the row moved on (expiry) while this attempt had published earlier segments
				return err
			}
			return errors.Join(err, rerr)
		}
		return err
	}
	if rerr := w.Store.RecordPlayback(context.WithoutCancel(ctx), tenantID, id, PlaybackResult{OK: true, Segments: segs}); rerr != nil {
		if errors.Is(rerr, ErrRecordingState) {
			// A concurrent job got there first (its files are valid), or an expiry did: in that case the
			// retention unlink may have run BEFORE this attempt's last publish, which would have recreated
			// the directory, so look again and remove it.
			s.muxAbandon(ctx, row)
			return nil
		}
		return rerr
	}
	return nil
}

func (s *Server) muxSegments(ctx context.Context, row *RecordingRow, lim MuxLimits, tempDirs *[]string) ([]PlaybackSegment, error) {
	var out []PlaybackSegment
	var prevLastMs int64 = -1
	for i, seg := range row.Segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Pass 1 (validate + index) and pass 2 (write) read the SAME authenticated evidence file.
		rd1, closeFn1, err := s.recOpenSegmentReader(row, i, false)
		if err != nil {
			return nil, &MuxError{Code: MuxIO, Msg: "opening the evidence copy", Err: err}
		}
		info, err := ScanIVF(ctx, rd1.Sequential(), seg.DeclaredLen, lim)
		closeFn1()
		if err != nil {
			return nil, err
		}
		if info.FirstMs() < prevLastMs { // monotonic across the whole recording, not just inside a segment
			return nil, muxErr(MuxInvalid, "segment %d starts before segment %d ended", i, i-1)
		}
		prevLastMs = info.LastMs()
		plan, err := PlanWebM(info)
		if err != nil {
			return nil, err
		}

		rd2, closeFn2, err := s.recOpenSegmentReader(row, i, false)
		if err != nil {
			return nil, &MuxError{Code: MuxIO, Msg: "reopening the evidence copy", Err: err}
		}
		sum := sha256.New()
		tempUpload, werr := s.writePlaybackFile(ctx, row, i, plan, io.TeeReader(rd2.Sequential(), sum), tempDirs)
		closeFn2()
		if werr != nil {
			return nil, werr
		}
		// What pass 2 consumed must be exactly the evidence the upload verified: the playback copy is only
		// ever derived from digest-verified bytes.
		if got := hex.EncodeToString(sum.Sum(nil)); got != seg.SHA256 {
			return nil, muxErr(MuxInconsistent, "segment %d no longer matches its verified digest", i)
		}
		// Re-check the row IMMEDIATELY before publishing: a recording that expired or was deleted while this
		// job was running must not get a directory back (C6: mark expired, then unlink, so a publish that
		// follows the unlink is the only way an orphan appears).
		// The check and the publish are ONE step under the recording's lock: retention (mark expired,
		// unlink, mark deleted) runs under the same lock, so it cannot slip between them.
		if err := s.muxPublish(ctx, row, tempUpload, i); err != nil {
			return nil, err
		}
		out = append(out, PlaybackSegment{Index: i, WebMLen: plan.Size(), Width: info.Width, Height: info.Height,
			StartMs: plan.StartMs(), DurationMs: plan.DurationMs(), Frames: int64(info.Frames())})
	}
	return out, nil
}

// muxPublish re-checks the row and atomically publishes one playback segment, holding the recording lock.
func (s *Server) muxPublish(ctx context.Context, row *RecordingRow, tempUpload string, idx int) error {
	w := &s.Recording
	unlock, err := w.Store.LockRecording(ctx, row.TenantID, row.ID)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &MuxError{Code: MuxIO, Msg: "locking the recording", Err: err}
	}
	defer unlock()
	if !s.muxRowOpen(ctx, row) {
		return errMuxRowGone
	}
	if err := w.Files.Promote(tempUpload, row.TenantID, row.ID, uint32(idx), RepWebM); err != nil {
		return &MuxError{Code: MuxIO, Msg: "publishing the playback copy", Err: err}
	}
	return nil
}

// errMuxRowGone: the row is no longer evidence_complete / playback_failed (expired, deleted, refused, ...).
var errMuxRowGone = errors.New("recording left the playback states while the remux was running")

// muxRowOpen reports whether the row can still accept a playback copy. A row that cannot be read counts
// as closed: nothing is published on a guess.
func (s *Server) muxRowOpen(ctx context.Context, row *RecordingRow) bool {
	cur, err := s.Recording.Store.GetRecording(context.WithoutCancel(ctx), row.TenantID, row.ID)
	return err == nil && (cur.State == RecEvidenceComplete || cur.State == RecPlaybackFailed)
}

// muxAbandon cleans up after an attempt that lost its row. Only an expired or deleted row has its
// directory removed (retention owns that deletion and the row is already past it); a playback_ready row
// belongs to the job that won, and an unreadable or unknown row is left for the orphan pass.
func (s *Server) muxAbandon(ctx context.Context, row *RecordingRow) {
	w := &s.Recording
	cur, err := w.Store.GetRecording(context.WithoutCancel(ctx), row.TenantID, row.ID)
	if err != nil || (cur.State != RecExpired && cur.State != RecDeleted) {
		return
	}
	if _, rerr := w.Files.RemoveRecording(row.TenantID, row.ID); rerr != nil {
		log.Printf("recording playback: remove %s after it expired mid-job: %v (the orphan pass will quarantine it)", row.ID, rerr)
	}
}

// writePlaybackFile writes one segment's WebM into a fresh incoming directory (recorded in tempDirs so
// the caller removes it whatever happens) as an encrypted envelope.
func (s *Server) writePlaybackFile(ctx context.Context, row *RecordingRow, idx int, plan *WebMPlan, src io.Reader, tempDirs *[]string) (string, error) {
	w := &s.Recording
	temp := newUUID()
	*tempDirs = append(*tempDirs, temp)
	f, err := w.Files.OpenIncoming(temp, uint32(idx), RepWebM, true)
	if err != nil {
		return "", &MuxError{Code: MuxIO, Msg: "creating the playback copy", Err: err}
	}
	defer f.Close()
	meta, err := recEnvMeta(row, idx, plan.Size(), RepWebM)
	if err != nil {
		return "", err
	}
	env, err := CreateEnvelope(f, w.Keys, row.Key(), meta)
	if err != nil {
		return "", &MuxError{Code: MuxIO, Msg: "starting the playback envelope", Err: err}
	}
	if err := plan.Write(ctx, src, env); err != nil {
		return "", err
	}
	if err := env.Close(); err != nil { // full length written + fsync
		return "", &MuxError{Code: MuxIO, Msg: "finishing the playback envelope", Err: err}
	}
	return temp, nil
}
