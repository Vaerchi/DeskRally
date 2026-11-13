package controlplane

// Restore reconciliation for central recordings: the 'lost' pass (docs/63 §2a C6/C11, docs/22 restore drill).
//
// The recordings volume is OUTSIDE the backup contract, so after a database restore (or a volume that was
// replaced) the database can name recordings whose files are not there. This pass makes the rows say so:
//
//	evidence_complete / playback_ready / playback_failed, evidence file missing  ->  lost   (never served)
//	lost, every evidence file present again                                       ->  back  (restore-on-reappear)
//	playback_ready, evidence present but the WebM playback copy missing           ->  playback_failed (io_error)
//
// WHICH STATES. Only the three that promise the evidence copy is on disk. uploading holds only .incoming
// (the startup ReconcileUploads already resets a segment whose bytes are gone), expired is already being
// unlinked so a missing file is the goal, and deleted / abandoned / refused hold nothing. A lost row keeps its
// retention schedule: the sweeper expires it like any other and its unlink is an idempotent no-op.
//
// IT RUNS ONLY WHEN THE OPERATOR ASKED (RECORDING_RECONCILE_MODE=1, the same switch that holds the orphan
// pass), at startup and on every sweep tick while the switch is set. Outside that mode nothing in this file
// changes a row: a volume that is briefly unmounted in normal operation must never mark recordings lost.
//
// SAFETY — it mirrors the orphan pass's hold (recording_sweeper.go): an unmounted or replaced volume looks
// exactly like "everything is missing", so the pass HOLDS (marks nothing, logs an ALERT, reports why) when
//   - the volume root cannot be read, or
//   - there are at least reconcileHoldMin promising rows and more than half of them are missing, or
//   - no tenant directory exists on the volume at all while rows claim blobs (an empty volume), or
//   - fewer than reconcileHoldMin rows are checked and EVERY one is missing (a replaced volume that holds only
//     somebody else's tenant directory would otherwise sail through the small-population case).
//
// The last two are overridden only by RECORDING_RECONCILE_ACCEPT_MISSING=1, the operator's statement that the
// volume IS mounted and the files really are gone. An unreadable root is never overridden, and the root is re-checked
// before EVERY lost decision (inside the recording's lock): a volume that detaches mid-pass stops the pass at
// that point whatever ACCEPT_MISSING says (the switch waives counts, never the root checks). A row whose files
// cannot be INSPECTED (permissions, a link, another filesystem, or a segment file that exists but is EMPTY) is left alone and counted as unreadable,
// never as lost. When held, nothing at all is changed — restores included — so a held pass is a pure report.
//
// RESTORE-ON-REAPPEAR is allowed, in reconcile mode only, because the pass's only evidence is "the files are
// there again", it is cheap, and the alternative (a recording that is lost forever though its bytes are back
// after a later volume restore) is the worse failure. The row returns to the state it was lost from; a
// playback_ready row whose WebM did not come back returns to evidence_complete so the muxer rebuilds it.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
)

const (
	recAuditLost     = "recording.lost"
	recAuditRestored = "recording.restored"

	// reconcileHoldMin is the smallest population over which "more than half missing" is read as a
	// database/volume mismatch (the orphan pass uses the same 10).
	reconcileHoldMin = 10
)

// RecordingReconcileReport is what one reconciliation pass did (also used by tests).
type RecordingReconcileReport struct {
	// Checked is the number of NOT-yet-lost promising rows whose files could be inspected (the hold ratio's
	// denominator, so it can shift between passes as rows become lost); Present is how many had their files.
	Checked, Present int
	MarkedLost       int
	Restored         int
	PlaybackDemoted  int
	StillLost        int // lost rows whose files are still missing
	Unreadable       int // rows whose files could not be inspected: left alone
	AuditFailed      int
	// Held is non-empty when the pass changed nothing, and says why.
	Held string
}

type reconcileKind int

const (
	reconcileLose reconcileKind = iota + 1
	reconcileRestore
	reconcileDemote
)

type reconcileItem struct {
	tenant, id string
	kind       reconcileKind
}

// ReconcileRecordingLost runs the pass. It is a no-op returning Held "not in reconciliation mode" unless the
// operator switched reconcile mode on.
func (s *Server) ReconcileRecordingLost(ctx context.Context) (RecordingReconcileReport, error) {
	var rep RecordingReconcileReport
	w := &s.Recording
	if !w.ready() || !w.ReconcileMode {
		rep.Held = "not in reconciliation mode"
		return rep, nil
	}
	rows, err := w.Store.SweepList(ctx)
	if err != nil {
		rep.Held = "database unreachable"
		log.Printf("recording reconcile: lost pass: %v", err)
		return rep, err
	}
	tenants, err := w.Files.ListTenantDirs()
	if err != nil {
		rep.Held = "cannot read the volume root: " + err.Error()
		log.Printf("recording reconcile: ALERT %s; nothing was marked lost", rep.Held)
		return rep, nil
	}

	// hadTenants: the volume showed tenant directories when the pass began. It is what makes "now empty" a
	// DETACH rather than the empty volume the operator may have accepted with ACCEPT_MISSING.
	hadTenants := len(tenants.IDs) > 0
	var plan []reconcileItem
	for _, sr := range rows {
		if !recPromisesBlob(sr.State) && sr.State != RecLost {
			continue
		}
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		row, err := w.Store.GetRecording(ctx, sr.TenantID, sr.ID)
		if err != nil {
			rep.Unreadable++
			continue
		}
		kind, ok := w.reconcileClassify(row)
		if !ok {
			rep.Unreadable++
			continue
		}
		switch {
		case row.State == RecLost && kind == 0:
			rep.StillLost++
		case row.State == RecLost:
			plan = append(plan, reconcileItem{row.TenantID, row.ID, kind})
		case kind == reconcileLose:
			rep.Checked++
			plan = append(plan, reconcileItem{row.TenantID, row.ID, kind})
		default:
			rep.Checked++
			rep.Present++
			if kind == reconcileDemote {
				plan = append(plan, reconcileItem{row.TenantID, row.ID, kind})
			}
		}
	}

	lose := 0
	for _, it := range plan {
		if it.kind == reconcileLose {
			lose++
		}
	}
	if lose > 0 && !w.ReconcileAcceptMissing {
		switch {
		case rep.Checked >= reconcileHoldMin && lose*2 > rep.Checked:
			rep.Held = "held: most recordings have no files on the volume (wrong or unmounted volume?)"
		case rep.Checked < reconcileHoldMin && rep.Present == 0 && lose == rep.Checked:
			rep.Held = "held: none of the recordings has its files on the volume (wrong or unmounted volume?)"
		case len(tenants.IDs) == 0:
			rep.Held = "held: the volume holds no recordings at all (empty or unmounted?)"
		}
		if rep.Held != "" {
			log.Printf("recording reconcile: ALERT %d of %d recordings are missing their files; %s. Nothing was changed. "+
				"Mount the right volume, or set RECORDING_RECONCILE_ACCEPT_MISSING=1 if the files really are gone", lose, rep.Checked, rep.Held)
			s.logReconcileSummary(rep)
			return rep, nil
		}
	}

	for _, it := range plan {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		// A volume that detaches mid-pass makes every remaining row look missing. The hold above judged the plan
		// once, so reconcileApply re-validates the root for EVERY lost decision (see rootGone) and we stop, keeping
		// what was done, the moment it reports the volume gone; the next tick starts over with the real picture.
		if gone := s.reconcileApply(ctx, it, hadTenants, &rep); gone != "" {
			rep.Held = gone
			log.Printf("recording reconcile: ALERT %s after %d marked; the rest was left alone", rep.Held, rep.MarkedLost)
			break
		}
	}
	s.logReconcileSummary(rep)
	return rep, nil
}

func (s *Server) logReconcileSummary(rep RecordingReconcileReport) {
	log.Printf("recording reconcile: lost pass: checked=%d present=%d marked_lost=%d restored=%d playback_demoted=%d still_lost=%d unreadable=%d audit_failed=%d held=%q",
		rep.Checked, rep.Present, rep.MarkedLost, rep.Restored, rep.PlaybackDemoted, rep.StillLost, rep.Unreadable, rep.AuditFailed, rep.Held)
}

// reconcileClassify inspects one row's files. ok=false means the files could not be inspected. kind is 0 when
// nothing needs doing (present, or still lost).
func (w *RecordingWiring) reconcileClassify(row *RecordingRow) (kind reconcileKind, ok bool) {
	// A row with no segment rows cannot be judged (MissingFinal of 0 segments reports "nothing missing"), so it
	// is left alone rather than lost or "restored" unverified. (row.SegmentCount is only len(Segments), so it
	// is no independent authority; segment rows are written and restored with the row.)
	n := len(row.Segments)
	if n == 0 {
		return 0, false
	}
	missing, err := w.Files.MissingFinal(row.TenantID, row.ID, n, RepIVF)
	if err != nil {
		return 0, false
	}
	switch {
	case row.State == RecLost && missing == 0:
		return reconcileRestore, true
	case row.State == RecLost:
		return 0, true
	case missing > 0:
		return reconcileLose, true
	case row.State == RecPlaybackReady:
		wm, err := w.Files.MissingFinal(row.TenantID, row.ID, n, RepWebM)
		if err != nil {
			return 0, false
		}
		if wm > 0 {
			return reconcileDemote, true
		}
	}
	return 0, true
}

// reconcileApply performs one planned change UNDER THE RECORDING'S LOCK and re-checks the files inside it, so
// a finish, a playback publish or a retention step cannot interleave with the decision.
func (s *Server) reconcileApply(ctx context.Context, it reconcileItem, hadTenants bool, rep *RecordingReconcileReport) (gone string) {
	w := &s.Recording
	unlock, err := w.Store.LockRecording(ctx, it.tenant, it.id)
	if err != nil {
		log.Printf("recording reconcile: lock %s: %v (retried next tick)", it.id, err)
		return ""
	}
	defer unlock()
	row, err := w.Store.GetRecording(ctx, it.tenant, it.id)
	if err != nil {
		return ""
	}
	kind, ok := w.reconcileClassify(row)
	if !ok || kind != it.kind {
		return "" // changed under us (or became uninspectable): the next pass decides
	}
	switch kind {
	case reconcileLose:
		// The last look before the irreversible-looking write, inside the lock: a root that went away since the
		// plan was made turns every file into "missing". Unconditional: ACCEPT_MISSING never reaches this.
		if w.reconcileBeforeMark != nil {
			w.reconcileBeforeMark()
		}
		if why := w.rootGone(hadTenants); why != "" {
			return why
		}
		from, err := w.Store.MarkLost(ctx, it.tenant, it.id)
		if err != nil {
			if !errors.Is(err, ErrRecordingState) {
				log.Printf("recording reconcile: mark lost %s: %v", it.id, err)
			}
			return
		}
		rep.MarkedLost++
		s.reconcileAudit(ctx, recAuditLost, row, map[string]any{"lost_from": from}, rep)
	case reconcileRestore:
		to := row.LostFrom
		if to == RecPlaybackReady {
			if wm, werr := w.Files.MissingFinal(row.TenantID, row.ID, len(row.Segments), RepWebM); werr != nil || wm > 0 {
				to = RecEvidenceComplete // the playback copy did not come back: the muxer rebuilds it
			}
		}
		if !recPromisesBlob(to) {
			to = RecEvidenceComplete
		}
		if err := w.Store.RestoreLost(ctx, it.tenant, it.id, to); err != nil {
			if !errors.Is(err, ErrRecordingState) { // expired meanwhile is not an error
				log.Printf("recording reconcile: restore %s: %v", it.id, err)
			}
			return
		}
		rep.Restored++
		s.reconcileAudit(ctx, recAuditRestored, row, map[string]any{"restored_to": to}, rep)
	case reconcileDemote:
		if err := w.Store.RecordPlayback(ctx, it.tenant, it.id, PlaybackResult{OK: false, Reason: MuxIO}); err != nil {
			if !errors.Is(err, ErrRecordingState) {
				log.Printf("recording reconcile: demote %s: %v", it.id, err)
			}
			return
		}
		rep.PlaybackDemoted++
	}
	return ""
}

// rootGone is the unconditional volume check run immediately before every lost decision, inside the recording's
// lock. It returns why the volume can no longer be trusted, or "" if it can. It is NOT affected by
// RECORDING_RECONCILE_ACCEPT_MISSING (that switch only waives the count-based holds): an unreadable root is
// never accepted, and neither is a root that showed tenant directories when the pass began and shows none now
// (a detach / remount mid-pass). A volume that was ALREADY empty at the start is the case the operator
// accepted, so it stays acceptable. The cost is one directory listing per mark.
func (w *RecordingWiring) rootGone(hadTenants bool) string {
	t, err := w.Files.ListTenantDirs()
	if err != nil {
		return "held mid-pass: cannot read the volume root: " + err.Error()
	}
	if hadTenants && len(t.IDs) == 0 {
		return "held mid-pass: the volume went away while marking"
	}
	return ""
}

// reconcileAudit persists the audit row for a lost/restored transition. It runs AFTER the durable state
// change (the state is itself the record) and a failure is counted and logged, never silent.
func (s *Server) reconcileAudit(ctx context.Context, action string, row *RecordingRow, meta map[string]any, rep *RecordingReconcileReport) {
	if s.MgmtAudit == nil {
		rep.AuditFailed++
		log.Printf("recording reconcile: %s %s: no audit store configured", action, row.ID)
		return
	}
	m := map[string]any{"recording_id": row.ID, "session_id": row.SessionID, "machine_id": row.MachineID, "reason": "files missing after a restore"}
	if action == recAuditRestored {
		m["reason"] = "files present again"
	}
	for k, v := range meta {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		rep.AuditFailed++
		return
	}
	e := &MgmtAuditEvent{Action: action, TargetKind: recAuditKind, TargetID: row.ID, Metadata: raw, OccurredAt: s.Recording.now()}
	if err := s.MgmtAudit.RecordEvent(ctx, row.TenantID, e); err != nil {
		rep.AuditFailed++
		log.Printf("recording reconcile: audit %s %s: %v", action, row.ID, err)
		return
	}
	if s.Dispatcher != nil {
		s.Dispatcher.Dispatch(row.TenantID, e)
	}
}
