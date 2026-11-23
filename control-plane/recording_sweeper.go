package controlplane

// Retention and orphan-quarantine sweeper for central recordings (docs/63 D5, §2a C6, C10), run on the
// existing 5-minute reaper tick (session_reaper.go).
//
//	RETENTION   abandon uploads older than 24 h; expire rows whose retention has run out; delete files.
//	            Each row goes  mark expired (durable)  ->  unlink  ->  mark deleted. A failed unlink leaves
//	            the row 'expired' and is retried on the next tick; the age of the oldest such row is the
//	            deletion lag, which is logged loudly and exposed through RecordingHealth.
//	ORPHANS     walk the volume BY NAME. A UUID-named directory with no live row is MOVED to .quarantine/
//	            with a manifest — the orphan pass NEVER deletes. Anything not UUID-named is skipped and
//	            reported. After the 14-day grace a quarantined entry (which this code created, with a
//	            manifest) is purged: the one place an orphan is ever deleted.
//
// In reconciliation mode the 'lost' pass (recording_reconcile.go) also runs, ahead of the retention step.
//
// The orphan pass is DISABLED when the database could not be read this tick (an empty "live" set from a
// failed or restored database would make every recording an orphan) and in reconciliation mode (a
// restore is being reconciled — blobs with no row are quarantined by an operator-run drill, never by
// the timer). It also holds when the candidate count looks like a database/volume mismatch rather than
// stray orphans, and it never touches a directory younger than MinOrphanAge (a create or promote racing
// the snapshot).

import (
	"context"
	"errors"
	"log"
	"time"
)

// RecordingSweepConfig tunes the sweeper; zero values mean defaults.
type RecordingSweepConfig struct {
	MinOrphanAge         time.Duration // default 1h
	MaxQuarantinePerPass int           // default 50
	// DeletionLagAlert is the lag above which a deletion failure is logged as an ALERT (default 1h).
	DeletionLagAlert time.Duration
}

// RecordingSweepReport is what one pass did (also used by tests).
type RecordingSweepReport struct {
	Abandoned, Expired, Deleted, DeleteFailed int
	Quarantined                               int
	QuarantinePurged                          int
	// Skipped lists names the sweeper refused to classify (non-uuid names, links, foreign entries).
	Skipped []string
	// OrphansHeld is non-empty when the orphan pass did not run or held back, and says why.
	OrphansHeld string
	// OldestDeletionLag is the age (since expiry) of the oldest row still awaiting confirmed deletion.
	OldestDeletionLag time.Duration
	// PlaybackPending lists completed recordings whose playback copy has not been produced yet (queue
	// overflow, a restart mid-job, a replica that never enqueued): the caller re-offers them to the muxer.
	PlaybackPending []RecordingSweepRow
}

// RecordingHealth is the sweeper's last-known state, for monitoring (R4 wires it to an alert).
type RecordingHealth struct {
	LastSweepAt       time.Time
	LastSweepOK       bool
	OldestDeletionLag time.Duration
	FreeBytes         uint64
	FloorBytes        uint64
	BelowFloor        bool
	QuarantineHeld    string
}

// RecordingHealth returns the last recorded health snapshot.
func (s *Server) RecordingHealth() RecordingHealth {
	s.Recording.statsMu.Lock()
	defer s.Recording.statsMu.Unlock()
	return s.Recording.stats
}

// runRecordingSweep is the reaper-tick hook. It never panics the reaper and never returns an error: a
// sweep failure is logged and the next tick tries again.
func (s *Server) runRecordingSweep(ctx context.Context) {
	w := &s.Recording
	if !w.ready() {
		return
	}
	if w.ReconcileMode {
		// An operator-run restore reconciliation: files that went missing become lost, files that came back
		// are restored. Never runs outside the mode (ReconcileRecordingLost refuses).
		if _, err := s.ReconcileRecordingLost(ctx); err != nil {
			log.Printf("recording sweep: lost pass: %v", err)
		}
	}
	w.init()
	rep, err := w.Sweep(ctx)
	if err != nil {
		log.Printf("recording sweep: %v", err)
		return
	}
	for _, r := range rep.PlaybackPending {
		s.EnqueuePlayback(r.TenantID, r.ID)
	}
}

// Sweep performs one pass.
func (w *RecordingWiring) Sweep(ctx context.Context) (RecordingSweepReport, error) {
	var rep RecordingSweepReport
	w.init()
	cfg := w.SweepConfig
	if cfg.MinOrphanAge <= 0 {
		cfg.MinOrphanAge = time.Hour
	}
	if cfg.MaxQuarantinePerPass <= 0 {
		cfg.MaxQuarantinePerPass = 50
	}
	if cfg.DeletionLagAlert <= 0 {
		cfg.DeletionLagAlert = time.Hour
	}
	now := w.now()

	w.noteDisk()
	rows, err := w.Store.SweepList(ctx)
	if err != nil {
		rep.OrphansHeld = "database unreachable"
		w.noteSweep(now, false, rep)
		return rep, err
	}

	// ---- retention -------------------------------------------------------------------------------
	for _, row := range rows {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		// Persist a shortened deadline FIRST (under the row lock), so classification and every later sweep
		// act on the durable value: lengthening the policy or switching storage off afterwards must not
		// restore the longer schedule (C10).
		if recRetentionLive(row.State) && row.PolicyRetentionDays > 0 {
			if eff, ok := row.EffectiveExpiry(); ok && row.ExpiresAt != nil && eff.Before(*row.ExpiresAt) {
				if exp, _, err := w.Store.ApplyRetention(ctx, row.TenantID, row.ID); err == nil {
					row.ExpiresAt = &exp
				} else if !errors.Is(err, ErrRecordingState) {
					log.Printf("recording sweep: persist shortened retention for %s: %v (using the computed deadline this tick)", row.ID, err)
				}
			}
		}
		action := ClassifySweep(row, now)
		if action == SweepNone {
			continue
		}
		w.sweepRetentionRow(ctx, row, action, now, cfg, &rep)
	}

	for _, row := range rows {
		if row.State == RecEvidenceComplete && ClassifySweep(row, now) == SweepNone {
			rep.PlaybackPending = append(rep.PlaybackPending, row)
		}
	}

	// ---- orphans ---------------------------------------------------------------------------------
	switch {
	case w.ReconcileMode:
		rep.OrphansHeld = "reconciliation mode"
	default:
		w.orphanPass(ctx, rows, now, cfg, &rep)
	}
	w.noteSweep(now, true, rep)
	if rep.Abandoned+rep.Expired+rep.Deleted+rep.Quarantined+rep.QuarantinePurged > 0 || rep.OrphansHeld != "" && rep.OrphansHeld != "reconciliation mode" {
		log.Printf("recording sweep: abandoned=%d expired=%d deleted=%d delete_failed=%d quarantined=%d purged=%d skipped=%d held=%q",
			rep.Abandoned, rep.Expired, rep.Deleted, rep.DeleteFailed, rep.Quarantined, rep.QuarantinePurged, len(rep.Skipped), rep.OrphansHeld)
	}
	return rep, nil
}

// sweepRetentionRow applies one retention action UNDER THE RECORDING'S LOCK. The lock serialises it with a
// finish (which promotes files and commits evidence), with a refusal and with the playback publish: nothing
// can write into the directories this removes after the state mark, and no concurrent finish can promote
// into a row this has just abandoned.
func (w *RecordingWiring) sweepRetentionRow(ctx context.Context, row RecordingSweepRow, action SweepAction, now time.Time, cfg RecordingSweepConfig, rep *RecordingSweepReport) {
	unlock, err := w.Store.LockRecording(ctx, row.TenantID, row.ID)
	if err != nil {
		log.Printf("recording sweep: lock %s: %v (retried next tick)", row.ID, err)
		return
	}
	defer unlock()
	switch action {
	case SweepAbandon:
		// Mark first (durable, and it forbids any further chunk commit), then unlink: nothing can
		// write to the directory after the mark, so there is no window in which a late chunk
		// resurrects it.
		if err := w.Store.AbandonRecording(ctx, row.TenantID, row.ID); err != nil {
			if !errors.Is(err, ErrRecordingState) {
				log.Printf("recording sweep: abandon %s: %v", row.ID, err)
			}
			return
		}
		rep.Abandoned++
		if _, err := w.Files.RemoveIncoming(row.UploadID); err != nil {
			log.Printf("recording sweep: remove incoming %s: %v (the orphan pass will quarantine it)", row.UploadID, err)
		}
		return
	case SweepExpire:
		if err := w.Store.MarkExpired(ctx, row.TenantID, row.ID); err != nil {
			log.Printf("recording sweep: expire %s: %v", row.ID, err)
			return
		}
		rep.Expired++
		expired := now
		row.ExpiredAt = &expired
	}
	// SweepExpire (just marked) and SweepDeleteNow (marked on an earlier tick): unlink, confirm.
	if _, err := w.Files.RemoveRecording(row.TenantID, row.ID); err != nil {
		rep.DeleteFailed++
		since := row.CreatedAt
		if row.ExpiredAt != nil {
			since = *row.ExpiredAt
		}
		lag := now.Sub(since)
		if lag > rep.OldestDeletionLag {
			rep.OldestDeletionLag = lag
		}
		if lag >= cfg.DeletionLagAlert {
			log.Printf("recording sweep: ALERT deletion lag %s for expired recording %s/%s: %v", lag.Round(time.Second), row.TenantID, row.ID, err)
		} else {
			log.Printf("recording sweep: delete %s/%s failed (will retry): %v", row.TenantID, row.ID, err)
		}
		return
	}
	if err := w.Store.MarkDeleted(ctx, row.TenantID, row.ID); err != nil {
		log.Printf("recording sweep: confirm deletion %s: %v", row.ID, err)
		return
	}
	rep.Deleted++
}

func (w *RecordingWiring) orphanPass(ctx context.Context, rows []RecordingSweepRow, now time.Time, cfg RecordingSweepConfig, rep *RecordingSweepReport) {
	live := make(map[string]struct{}, len(rows))
	liveUpload := make(map[string]struct{})
	for _, r := range rows {
		live[r.TenantID+"/"+r.ID] = struct{}{}
		if r.State == RecUploading {
			liveUpload[r.UploadID] = struct{}{}
		}
	}

	type cand struct {
		tenant, rec, upload string
	}
	var cands []cand
	dirs := 0

	tenants, err := w.Files.ListTenantDirs()
	if err != nil {
		rep.OrphansHeld = "cannot list the volume: " + err.Error()
		return
	}
	rep.Skipped = append(rep.Skipped, tenants.Skipped...)
	for _, t := range tenants.IDs {
		recs, err := w.Files.ListRecordingDirs(t)
		if err != nil {
			rep.Skipped = append(rep.Skipped, t)
			continue
		}
		rep.Skipped = append(rep.Skipped, recs.Skipped...)
		for _, id := range recs.IDs {
			dirs++
			if _, ok := live[t+"/"+id]; ok {
				continue
			}
			if mt, err := w.Files.RecordingDirModTime(t, id); err != nil || now.Sub(mt) < cfg.MinOrphanAge {
				continue // young (a create/promote racing the snapshot) or unreadable: leave it
			}
			cands = append(cands, cand{tenant: t, rec: id})
		}
	}
	incoming, err := w.Files.ListIncomingDirs()
	if err != nil {
		rep.OrphansHeld = "cannot list .incoming: " + err.Error()
		return
	}
	rep.Skipped = append(rep.Skipped, incoming.Skipped...)
	for _, u := range incoming.IDs {
		dirs++
		if _, ok := liveUpload[u]; ok {
			continue
		}
		if mt, err := w.Files.IncomingDirModTime(u); err != nil || now.Sub(mt) < cfg.MinOrphanAge {
			continue
		}
		cands = append(cands, cand{upload: u})
	}

	// A database that does not describe the volume (wrong database, partial restore, lost table) looks
	// like "most of the volume is orphaned". Hold everything rather than move it.
	if dirs >= 10 && len(cands)*2 > dirs {
		rep.OrphansHeld = "held: most directories on the volume have no live row (database/volume mismatch?)"
		log.Printf("recording sweep: ALERT %d of %d directories have no live row; orphan pass held", len(cands), dirs)
		return
	}
	for i, c := range cands {
		if i >= cfg.MaxQuarantinePerPass {
			rep.OrphansHeld = "held: per-pass quarantine limit reached"
			break
		}
		var err error
		if c.upload != "" {
			_, err = w.Files.QuarantineIncoming(c.upload, "in-flight upload with no live uploading row", now)
		} else {
			_, err = w.Files.QuarantineRecording(c.tenant, c.rec, "recording directory with no live row", now)
		}
		if err != nil {
			log.Printf("recording sweep: quarantine %s%s%s: %v", c.tenant, "/", c.rec+c.upload, err)
			rep.Skipped = append(rep.Skipped, c.tenant+"/"+c.rec+c.upload)
			continue
		}
		rep.Quarantined++
	}
	purged, skipped, err := w.Files.PurgeQuarantine(now, QuarantineGrace)
	if err != nil {
		log.Printf("recording sweep: purge quarantine: %v", err)
	}
	rep.QuarantinePurged = purged
	rep.Skipped = append(rep.Skipped, skipped...)
	if len(rep.Skipped) > 0 {
		n := len(rep.Skipped)
		if n > 5 {
			n = 5
		}
		log.Printf("recording sweep: %d entries skipped (never deleted), e.g. %q", len(rep.Skipped), rep.Skipped[:n])
	}
}

func (w *RecordingWiring) noteDisk() {
	free, err := w.freeBytes()
	w.statsMu.Lock()
	defer w.statsMu.Unlock()
	w.stats.FloorBytes = w.cfg.FloorBytes
	if err != nil {
		w.stats.FreeBytes, w.stats.BelowFloor = 0, true
		return
	}
	w.stats.FreeBytes = free
	w.stats.BelowFloor = free < w.cfg.FloorBytes
	if w.stats.BelowFloor {
		log.Printf("recording sweep: ALERT recordings volume free space %d is below the floor %d; new uploads are refused (507)", free, w.cfg.FloorBytes)
	}
}

func (w *RecordingWiring) noteSweep(at time.Time, ok bool, rep RecordingSweepReport) {
	w.statsMu.Lock()
	defer w.statsMu.Unlock()
	w.stats.LastSweepAt, w.stats.LastSweepOK = at, ok
	w.stats.OldestDeletionLag = rep.OldestDeletionLag
	w.stats.QuarantineHeld = rep.OrphansHeld
}

// ReconcileUploads is the startup reconciliation (C2): for every recording still 'uploading', make the
// in-flight files agree with what the database acknowledged. A segment whose file is missing,
// unreadable, shorter than its committed offset, or LONGER than it (bytes written but never acknowledged:
// the file is never truncated and overwritten, since re-sealing those frame indexes under the same nonce
// prefix would reuse nonces, see ResumeEnvelope) is reset to zero so the agent re-sends it under a fresh
// prefix (not counted as a failure).
func (w *RecordingWiring) ReconcileUploads(ctx context.Context) (checked, reset int, err error) {
	w.init()
	rows, err := w.Store.SweepList(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, sr := range rows {
		if sr.State != RecUploading {
			continue
		}
		row, err := w.Store.GetRecording(ctx, sr.TenantID, sr.ID)
		if err != nil || row.State != RecUploading {
			continue
		}
		for _, sg := range row.Segments {
			if sg.CommittedOffset == 0 {
				continue
			}
			checked++
			if !w.reconcileSegment(row, sg) {
				if err := w.Store.ResetSegment(ctx, row.TenantID, row.ID, sg.Index); err == nil {
					reset++
					log.Printf("recording reconcile: %s segment %d lost its bytes; reset to 0", row.ID, sg.Index)
				}
			}
		}
	}
	return checked, reset, nil
}

func (w *RecordingWiring) reconcileSegment(row *RecordingRow, sg RecordingSegment) bool {
	meta, err := recEnvMeta(row, sg.Index, sg.DeclaredLen, RepIVF)
	if err != nil {
		return false
	}
	f, err := w.Files.OpenIncoming(row.UploadID, uint32(sg.Index), RepIVF, false)
	if err != nil {
		return false
	}
	defer f.Close()
	ew, err := ResumeEnvelope(f, w.Keys, row.Key(), meta, uint64(sg.CommittedOffset)) // refuses (never truncates) a file with an unacknowledged tail
	if err != nil {
		return false
	}
	return ew.Sync() == nil
}

// StartRecordingServices runs the startup reconciliation once (bounded). Call it before the reaper
// starts; it is a no-op when central recording is not wired.
func (s *Server) StartRecordingServices(ctx context.Context) {
	w := &s.Recording
	if !w.ready() {
		return
	}
	s.StartRecordingPlayback(ctx) // the remux workers; independent of the reconciliation below
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	checked, reset, err := w.ReconcileUploads(rctx)
	if err != nil {
		log.Printf("recording reconcile: %v", err)
		return
	}
	log.Printf("recording: startup reconciliation checked %d committed segment(s), reset %d", checked, reset)
	if w.ReconcileMode {
		if _, err := s.ReconcileRecordingLost(rctx); err != nil {
			log.Printf("recording reconcile: lost pass: %v", err)
		}
	}
}
