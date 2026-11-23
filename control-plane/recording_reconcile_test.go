package controlplane

// The restore reconciliation 'lost' pass (recording_reconcile.go, docs/63 C11): real files on a real volume
// directory, the in-memory store, and the real console routes.

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (c *consoleH) recDir(u *recUpload) string { return filepath.Join(c.dir, c.tenant, u.id) }

func (c *consoleH) reconcile(t *testing.T) RecordingReconcileReport {
	t.Helper()
	rep, err := c.srv.ReconcileRecordingLost(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return rep
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		in, err := os.Open(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(filepath.Join(dst, e.Name()), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		in.Close()
		out.Close()
	}
}

func (c *consoleH) completeSmall() *recUpload {
	u := ivfUpload(buildIVF(64, 48, 90000, 1, framesA(), 0))
	c.completeUpload(u)
	return u
}

func TestReconcileMarksMissingRecordingsLostAndNeverServesThem(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	lostFx := c.ready(framesA())
	okFx := c.ready(framesA())
	if err := os.RemoveAll(c.recDir(lostFx.u)); err != nil {
		t.Fatal(err)
	}
	rep := c.reconcile(t)
	if rep.MarkedLost != 1 || rep.Held != "" || rep.Present != 1 || rep.Checked != 2 || rep.AuditFailed != 0 {
		t.Fatalf("report: %+v", rep)
	}
	got := c.row(lostFx.u)
	if got.State != RecLost || got.LostFrom != RecPlaybackReady || got.LostAt == nil {
		t.Fatalf("lost row: %+v", got)
	}
	if st := c.row(okFx.u).State; st != RecPlaybackReady {
		t.Fatalf("a recording whose files are present changed state: %s", st)
	}
	// Audited, once, with the origin state.
	evs := c.rows(recAuditLost)
	if len(evs) != 1 || evs[0].TargetID != lostFx.u.id || !strings.Contains(string(evs[0].Metadata), `"lost_from":"playback_ready"`) {
		t.Fatalf("audit rows: %+v", evs)
	}
	// Every content route answers a definite 410 'lost' and releases nothing (no audit row for a playback).
	for _, s := range []string{"/playlist", "/segments/0/stream", "/download"} {
		st, _, b := c.get("owner", lostFx.path(s))
		m := jsonOf(t, b)
		if st != http.StatusGone || m["error"] != RecLost || m["state"] != RecLost {
			t.Errorf("lost %s: %d %s", s, st, b)
		}
	}
	if st, _, _ := c.do("owner", http.MethodHead, lostFx.path("/download"), nil); st != http.StatusGone {
		t.Errorf("lost HEAD download: %d", st)
	}
	for _, a := range []string{recAuditPlayback, recAuditDownload} {
		for _, e := range c.rows(a) {
			if e.TargetID == lostFx.u.id {
				t.Errorf("%s audit row written for a lost recording: %+v", a, e)
			}
		}
	}
	// Detail and list say lost and not playable.
	d := jsonOf(t, func() []byte { _, _, b := c.get("owner", lostFx.path("")); return b }())
	if d["state"] != RecLost || d["playable"] != false || d["lost_at"] == nil {
		t.Errorf("detail: %v", d)
	}
	_, _, lb := c.get("owner", "/recordings")
	list := jsonOf(t, lb)
	found := false
	for _, it := range list["recordings"].([]any) {
		m := it.(map[string]any)
		if m["id"] == lostFx.u.id {
			found = m["state"] == RecLost && m["playable"] == false
		}
	}
	if !found {
		t.Errorf("list does not show the lost recording as lost: %s", lb)
	}
	// The healthy neighbour still plays.
	if st, _, _ := c.get("owner", okFx.path("/playlist")); st != http.StatusOK {
		t.Errorf("the intact recording stopped playing: %d", st)
	}
	// No muxer job for a lost row: a direct request is a no-op and the state does not move.
	if err := c.srv.MuxRecording(context.Background(), c.tenant, lostFx.u.id); err != nil {
		t.Errorf("a mux attempt on a lost recording must be a quiet no-op: %v", err)
	}
	if st := c.row(lostFx.u).State; st != RecLost {
		t.Fatalf("state after a mux attempt: %s", st)
	}
	// A second pass is a no-op (still lost, not re-audited).
	if rep := c.reconcile(t); rep.MarkedLost != 0 || rep.StillLost != 1 || len(c.rows(recAuditLost)) != 1 {
		t.Fatalf("second pass: %+v", rep)
	}
	// The sweeper does not offer it to the muxer.
	if rep := c.sweep(); len(rep.PlaybackPending) != 0 {
		t.Fatalf("a lost recording was queued for playback: %+v", rep.PlaybackPending)
	}
}

// OUTSIDE reconcile mode nothing marks a row lost: a volume that is briefly missing in normal operation must
// not rewrite the database.
func TestReconcileDoesNothingOutsideReconcileMode(t *testing.T) {
	c := newConsoleH(t)
	c.completeSmall() // an intact peer: a lone missing row would (rightly) look like a wrong volume
	u := c.completeSmall()
	if err := os.RemoveAll(c.recDir(u)); err != nil {
		t.Fatal(err)
	}
	c.srv.Recording.ReconcileMode = false
	rep := c.reconcile(t)
	if rep.Held != "not in reconciliation mode" || rep.MarkedLost+rep.Restored+rep.PlaybackDemoted != 0 {
		t.Fatalf("report outside the mode: %+v", rep)
	}
	c.srv.runRecordingSweep(context.Background()) // the timer path
	c.sweep()
	if st := c.row(u).State; st != RecEvidenceComplete {
		t.Fatalf("a row was changed outside reconcile mode: %s", st)
	}
	if len(c.rows(recAuditLost)) != 0 {
		t.Fatal("an audit row was written outside reconcile mode")
	}
	// Switch it on: now it is found.
	c.srv.Recording.ReconcileMode = true
	if rep := c.reconcile(t); rep.MarkedLost != 1 {
		t.Fatalf("in the mode: %+v", rep)
	}
}

func TestReconcileHoldsWhenTheVolumeRootIsUnreadable(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	u := c.completeSmall()
	files, err := OpenRecordingStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files.Close() // every walk of this root now fails: an unmounted / vanished volume
	c.srv.Recording.Files = files
	buf := captureLog(t)
	rep := c.reconcile(t)
	if !strings.Contains(rep.Held, "cannot read the volume root") || rep.MarkedLost != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if st := c.row(u).State; st != RecEvidenceComplete {
		t.Fatalf("state %s after a held pass", st)
	}
	if !strings.Contains(buf.String(), "ALERT") {
		t.Fatalf("a held pass must log loudly: %s", buf.String())
	}
	// The accept switch does NOT override an unreadable root.
	c.srv.Recording.ReconcileAcceptMissing = true
	if rep := c.reconcile(t); rep.MarkedLost != 0 || rep.Held == "" {
		t.Fatalf("accept-missing overrode an unreadable root: %+v", rep)
	}
}

func TestReconcileHoldsWhenMostFilesAreMissing(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	var ups []*recUpload
	for i := 0; i < 12; i++ {
		ups = append(ups, c.completeSmall())
	}
	// 7 of 12 missing: more than half, and above the minimum population -> HOLD, nothing marked.
	for _, u := range ups[:7] {
		if err := os.RemoveAll(c.recDir(u)); err != nil {
			t.Fatal(err)
		}
	}
	buf := captureLog(t)
	rep := c.reconcile(t)
	if !strings.HasPrefix(rep.Held, "held: most recordings") || rep.MarkedLost != 0 {
		t.Fatalf("report: %+v", rep)
	}
	for _, u := range ups {
		if st := c.row(u).State; st != RecEvidenceComplete {
			t.Fatalf("a held pass changed %s to %s", u.id, st)
		}
	}
	if !strings.Contains(buf.String(), "ALERT 7 of 12") {
		t.Fatalf("log: %s", buf.String())
	}
	// The operator's explicit statement overrides the proportion hold.
	c.srv.Recording.ReconcileAcceptMissing = true
	rep = c.reconcile(t)
	if rep.Held != "" || rep.MarkedLost != 7 {
		t.Fatalf("with accept-missing: %+v", rep)
	}
}

// Exactly half missing is NOT "more than half": the threshold is strict.
func TestReconcileExactlyHalfMissingProceeds(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	var ups []*recUpload
	for i := 0; i < 10; i++ {
		ups = append(ups, c.completeSmall())
	}
	for _, u := range ups[:5] {
		os.RemoveAll(c.recDir(u))
	}
	if rep := c.reconcile(t); rep.Held != "" || rep.MarkedLost != 5 {
		t.Fatalf("report: %+v", rep)
	}
}

func TestReconcileBelowThePopulationMinimumJustMarks(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	a, b, keep := c.completeSmall(), c.completeSmall(), c.completeSmall()
	os.RemoveAll(c.recDir(a))
	os.RemoveAll(c.recDir(b))
	rep := c.reconcile(t) // 2 of 3 missing, but only 3 candidates: a handful of real losses, not a mismatch
	if rep.Held != "" || rep.MarkedLost != 2 {
		t.Fatalf("report: %+v", rep)
	}
	if c.row(keep).State != RecEvidenceComplete {
		t.Fatal("the intact recording moved")
	}
}

// A replaced volume that holds only another tenant's directory: every checked row is missing, but the tenant
// directory exists and fewer than reconcileHoldMin rows are checked. Without the small-population rule this
// would mark them all lost.
func TestReconcileHoldsWhenEveryRowOfASmallPopulationIsMissing(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	a, b := c.completeSmall(), c.completeSmall()
	os.RemoveAll(c.recDir(a))
	os.RemoveAll(c.recDir(b)) // the tenant directory itself still exists
	rep := c.reconcile(t)
	if !strings.Contains(rep.Held, "none of the recordings") || rep.MarkedLost != 0 || c.row(a).State != RecEvidenceComplete {
		t.Fatalf("report: %+v", rep)
	}
	c.srv.Recording.ReconcileAcceptMissing = true
	if rep := c.reconcile(t); rep.MarkedLost != 2 || rep.Held != "" {
		t.Fatalf("with accept-missing: %+v", rep)
	}
}

func TestReconcileHoldsOnAnEmptyVolume(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	u := c.completeSmall()
	os.RemoveAll(filepath.Join(c.dir, c.tenant)) // the whole tenant directory is gone: the volume holds nothing
	rep := c.reconcile(t)
	if !strings.Contains(rep.Held, "held:") || rep.MarkedLost != 0 || c.row(u).State != RecEvidenceComplete {
		t.Fatalf("report: %+v state %s", rep, c.row(u).State)
	}
	c.srv.Recording.ReconcileAcceptMissing = true
	if rep := c.reconcile(t); rep.MarkedLost != 1 || c.row(u).State != RecLost {
		t.Fatalf("with accept-missing: %+v", rep)
	}
}

func TestReconcileRestoresARowWhoseFilesReappear(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	c.completeSmall() // an intact peer: a lone missing row would (rightly) look like a wrong volume
	fx := c.ready(framesA())
	keepDir := filepath.Join(t.TempDir(), "backup")
	copyTree(t, c.recDir(fx.u), keepDir)
	os.RemoveAll(c.recDir(fx.u))
	if rep := c.reconcile(t); rep.MarkedLost != 1 {
		t.Fatalf("lose: %+v", rep)
	}
	// The files come back (a later volume restore): the row returns to the state it was lost from.
	copyTree(t, keepDir, c.recDir(fx.u))
	rep := c.reconcile(t)
	if rep.Restored != 1 || rep.StillLost != 0 {
		t.Fatalf("restore: %+v", rep)
	}
	if st := c.row(fx.u).State; st != RecPlaybackReady {
		t.Fatalf("state after restore = %s", st)
	}
	if st, _, _ := c.get("owner", fx.path("/playlist")); st != http.StatusOK {
		t.Fatalf("restored recording does not play: %d", st)
	}
	if len(c.rows(recAuditRestored)) != 1 {
		t.Fatalf("restore audit rows: %+v", c.rows(recAuditRestored))
	}

	// Only the evidence came back, not the playback copy: evidence_complete, so the muxer rebuilds it.
	fx2 := c.ready(framesA())
	evOnly := filepath.Join(t.TempDir(), "evidence-only")
	copyTree(t, c.recDir(fx2.u), evOnly)
	os.Remove(filepath.Join(evOnly, segName(0, RepWebM)))
	os.RemoveAll(c.recDir(fx2.u))
	c.reconcile(t)
	copyTree(t, evOnly, c.recDir(fx2.u))
	if rep := c.reconcile(t); rep.Restored != 1 {
		t.Fatalf("restore evidence only: %+v", rep)
	}
	if st := c.row(fx2.u).State; st != RecEvidenceComplete {
		t.Fatalf("state = %s, want evidence_complete (the muxer rebuilds the playback copy)", st)
	}
}

func TestReconcileDemotesAReadyRecordingWhosePlaybackCopyIsMissing(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	fx := c.ready(framesA())
	if err := os.Remove(filepath.Join(c.recDir(fx.u), segName(0, RepWebM))); err != nil {
		t.Fatal(err)
	}
	rep := c.reconcile(t)
	if rep.PlaybackDemoted != 1 || rep.MarkedLost != 0 {
		t.Fatalf("report: %+v", rep)
	}
	got := c.row(fx.u)
	if got.State != RecPlaybackFailed || got.PlaybackError != MuxIO {
		t.Fatalf("row: %s / %s", got.State, got.PlaybackError)
	}
	if st, _, _ := c.get("owner", fx.path("/download")); st != http.StatusOK {
		t.Fatalf("the evidence must still be downloadable: %d", st)
	}
}

// A lost row still ages out by retention and its row is cleaned up; there is nothing to delete on disk.
func TestReconcileLostRowStillExpiresAndIsDeletedByRetention(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	c.completeSmall() // an intact peer: a lone missing row would (rightly) look like a wrong volume
	u := c.completeSmall()
	os.RemoveAll(c.recDir(u))
	c.reconcile(t)
	c.skew(10 * 24 * time.Hour)
	if rep := c.sweep(); rep.Expired != 0 || c.row(u).State != RecLost {
		t.Fatalf("swept inside the window: %+v", rep)
	}
	c.skew(31 * 24 * time.Hour)
	rep := c.sweep()
	if rep.Expired != 2 || rep.Deleted != 2 || rep.DeleteFailed != 0 { // the lost row and its intact peer
		t.Fatalf("sweep: %+v", rep)
	}
	if got := c.row(u); got.State != RecDeleted || got.DeletedAt == nil {
		t.Fatalf("row: %+v", got)
	}
}

// An EXISTING zero-byte segment file is damage, not a loss: the row is left alone and counted unreadable,
// and a zero-byte file reappearing after a loss does NOT restore the row.
func TestReconcileEmptySegmentFileIsNotLostAndNeverRestores(t *testing.T) {
	c := newConsoleH(t)
	c.srv.Recording.ReconcileMode = true
	c.completeSmall() // an intact peer, so the hold rules stay out of the way
	u := c.completeSmall()
	seg := filepath.Join(c.recDir(u), segName(0, RepIVF))
	good, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := c.reconcile(t)
	if rep.MarkedLost != 0 || rep.Unreadable != 1 || rep.Held != "" || c.row(u).State != RecEvidenceComplete {
		t.Fatalf("an empty segment file: %+v state %s", rep, c.row(u).State)
	}
	// ACCEPT_MISSING does not turn damage into a loss either.
	c.srv.Recording.ReconcileAcceptMissing = true
	if rep := c.reconcile(t); rep.MarkedLost != 0 || c.row(u).State != RecEvidenceComplete {
		t.Fatalf("accept-missing marked an empty-file row lost: %+v", rep)
	}
	c.srv.Recording.ReconcileAcceptMissing = false

	// Really lose it, then let an EMPTY file reappear: still lost.
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	if rep := c.reconcile(t); rep.MarkedLost != 1 {
		t.Fatalf("lose: %+v", rep)
	}
	if err := os.WriteFile(seg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rep = c.reconcile(t)
	if rep.Restored != 0 || rep.Unreadable != 1 || c.row(u).State != RecLost {
		t.Fatalf("an empty file restored the row: %+v state %s", rep, c.row(u).State)
	}
	// The real bytes coming back do restore it.
	if err := os.WriteFile(seg, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := c.reconcile(t); rep.Restored != 1 || c.row(u).State != RecEvidenceComplete {
		t.Fatalf("restore with real bytes: %+v state %s", rep, c.row(u).State)
	}
}

// The root checks are unconditional and run before EVERY lost decision: the volume vanishing after the
// initial holds were judged stops the pass at the next candidate, even with ACCEPT_MISSING=1.
func TestReconcileStopsWhenTheVolumeVanishesMidPass(t *testing.T) {
	for _, accept := range []bool{false, true} {
		for _, how := range []string{"tenant-dir", "root-closed"} {
			t.Run(how+map[bool]string{false: "", true: "+accept"}[accept], func(t *testing.T) {
				c := newConsoleH(t)
				c.srv.Recording.ReconcileMode = true
				c.srv.Recording.ReconcileAcceptMissing = accept
				var ups []*recUpload
				for i := 0; i < 12; i++ {
					ups = append(ups, c.completeSmall())
				}
				for _, u := range ups[:3] { // 3 of 12 missing: the initial holds pass
					if err := os.RemoveAll(c.recDir(u)); err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				c.srv.Recording.reconcileBeforeMark = func() {
					calls++
					if calls != 2 { // the first mark goes through; the volume detaches before the second
						return
					}
					if how == "root-closed" { // the root itself becomes unreadable (a handle that went away)
						c.srv.Recording.Files.Close()
						return
					}
					if err := os.RemoveAll(filepath.Join(c.dir, c.tenant)); err != nil {
						t.Error(err)
					}
				}
				buf := captureLog(t)
				rep := c.reconcile(t)
				if rep.MarkedLost != 1 || !strings.HasPrefix(rep.Held, "held mid-pass") {
					t.Fatalf("report: %+v", rep)
				}
				lost := 0
				for _, u := range ups {
					if c.row(u).State == RecLost {
						lost++
					}
				}
				if lost != 1 {
					t.Fatalf("%d rows were marked lost after the volume vanished, want exactly the 1 before it", lost)
				}
				if !strings.Contains(buf.String(), "ALERT held mid-pass") {
					t.Fatalf("no ALERT: %s", buf.String())
				}
			})
		}
	}
}
