package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// skewed makes the sweeper's clock run `d` ahead of real time (the stores stamp rows with real time).
func (h *recH) skew(d time.Duration) {
	var off atomic.Int64
	off.Store(int64(d))
	h.srv.Recording.Now = func() time.Time { return time.Now().Add(time.Duration(off.Load())) }
}

func (h *recH) complete(lens ...int) *recUpload {
	h.t.Helper()
	u := newRecUpload(lens...)
	h.mustCreate(u)
	h.putAll(u)
	if st, m := h.finish(u); st != 200 {
		h.t.Fatalf("finish: %d %v", st, m)
	}
	return u
}

func (h *recH) sweep() RecordingSweepReport {
	h.t.Helper()
	rep, err := h.srv.Recording.Sweep(context.Background())
	if err != nil {
		h.t.Fatalf("sweep: %v", err)
	}
	return rep
}

func (h *recH) setPolicyDays(days int) {
	h.t.Helper()
	if err := h.store.SetPolicy(context.Background(), h.tenant, RecordingPolicy{RetentionDays: days, MaxRecordingBytes: 1 << 30, QuotaBytes: 20 << 30}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *recH) exists(rel ...string) bool {
	_, err := os.Lstat(filepath.Join(append([]string{h.dir}, rel...)...))
	return err == nil
}

func TestRecordingSweepRetentionExpiresThenDeletes(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := h.complete(mib/4, 100)
	r := h.row(u)

	// Inside the retention window nothing happens.
	h.skew(29 * 24 * time.Hour)
	if rep := h.sweep(); rep.Expired+rep.Deleted != 0 || !h.exists(h.tenant, u.id) {
		t.Fatalf("swept inside the window: %+v", rep)
	}
	// Past it: marked expired (durable), unlinked, then confirmed deleted.
	h.skew(31 * 24 * time.Hour)
	rep := h.sweep()
	if rep.Expired != 1 || rep.Deleted != 1 || rep.DeleteFailed != 0 {
		t.Fatalf("sweep: %+v", rep)
	}
	if h.exists(h.tenant, u.id) {
		t.Fatal("expired recording's files are still on the volume")
	}
	got := h.row(u)
	if got.State != RecDeleted || got.ExpiredAt == nil || got.DeletedAt == nil {
		t.Fatalf("row after deletion: %+v", got)
	}
	// The tombstone stays: the id is never reusable; the audit-style row outlives the blob.
	h.skew(0)
	if st, m := h.create(u); st != 410 {
		t.Fatalf("create after deletion: %d %v", st, m)
	}
	if st, _, _ := h.do(call{op: UploadOpHead, rec: u.id}); st != 410 {
		t.Fatalf("head after deletion: %d", st)
	}
	// A second sweep is a no-op.
	if rep := h.sweep(); rep.Expired+rep.Deleted+rep.Quarantined != 0 {
		t.Fatalf("second sweep did something: %+v", rep)
	}
	_ = r
}

func TestRecordingSweepDeletionFailureIsRetriedAndReportedAsLag(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := h.complete(100)
	// Someone left a foreign file in the recording's directory: the sweeper must refuse to delete it.
	foreign := filepath.Join(h.dir, h.tenant, u.id, "notes.txt")
	os.WriteFile(foreign, []byte("not ours"), 0o600)

	h.skew(31 * 24 * time.Hour)
	rep := h.sweep()
	if rep.Expired != 1 || rep.Deleted != 0 || rep.DeleteFailed != 1 {
		t.Fatalf("first sweep: %+v", rep)
	}
	if st := h.row(u).State; st != RecExpired {
		t.Fatalf("state %s: logical expiry and confirmed deletion are separate; want expired", st)
	}
	if !h.exists(h.tenant, u.id, segName(0, RepIVF)) {
		t.Fatal("the evidence file was deleted although the directory was refused")
	}
	h.skew(31*24*time.Hour + 3*time.Hour)
	rep = h.sweep()
	if rep.DeleteFailed != 1 || rep.OldestDeletionLag < time.Hour {
		t.Fatalf("second sweep: %+v; the deletion lag must grow and be reported", rep)
	}
	if hl := h.srv.RecordingHealth(); hl.OldestDeletionLag < time.Hour || !hl.LastSweepOK {
		t.Fatalf("health: %+v", hl)
	}
	// Fix the cause: the next tick deletes and confirms.
	os.Remove(foreign)
	rep = h.sweep()
	if rep.Deleted != 1 || rep.DeleteFailed != 0 || h.row(u).State != RecDeleted || h.exists(h.tenant, u.id) {
		t.Fatalf("after the fix: %+v state=%s", rep, h.row(u).State)
	}
}

func TestRecordingSweepRetentionPolicyChanges(t *testing.T) {
	// Shortening retention applies to existing rows on the next sweep; turning storage off and lengthening
	// never extend them (C10).
	for _, tc := range []struct {
		name       string
		policyDays int
		at         time.Duration
		wantExpire bool
	}{
		{"shortened below the age", 5, 6 * 24 * time.Hour, true},
		{"shortened but not yet reached", 5, 4 * 24 * time.Hour, false},
		{"storage turned off keeps the stored schedule (not yet)", 0, 6 * 24 * time.Hour, false},
		{"storage turned off keeps the stored schedule (reached)", 0, 31 * 24 * time.Hour, true},
		{"lengthened never extends", 365, 31 * 24 * time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRecH(t, recHOpts{})
			u := h.complete(100)
			h.setPolicyDays(tc.policyDays)
			h.skew(tc.at)
			rep := h.sweep()
			if (rep.Expired == 1) != tc.wantExpire {
				t.Fatalf("expired=%d, want %v (%+v)", rep.Expired, tc.wantExpire, rep)
			}
			if !tc.wantExpire && h.row(u).State != RecEvidenceComplete {
				t.Fatalf("state %s", h.row(u).State)
			}
		})
	}
}

func TestRecordingSweepAbandonsStaleUploads(t *testing.T) {
	h := newRecH(t, recHOpts{})
	fresh := newRecUpload(mib)
	stale := newRecUpload(mib)
	h.mustCreate(stale)
	h.put(stale, 0, 0)
	h.mustCreate(fresh)
	h.put(fresh, 0, 0)

	h.skew(RecMaxUploadLifetime - time.Hour)
	if rep := h.sweep(); rep.Abandoned != 0 {
		t.Fatalf("abandoned before the lifetime bound: %+v", rep)
	}
	h.skew(RecMaxUploadLifetime + time.Minute)
	rep := h.sweep()
	if rep.Abandoned != 2 { // both are older than 24 h of sweeper time now
		t.Fatalf("sweep: %+v", rep)
	}
	for _, u := range []*recUpload{stale, fresh} {
		if h.row(u).State != RecAbandoned {
			t.Fatalf("state %s", h.row(u).State)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(h.dir, ".incoming")); len(ents) != 0 {
		t.Fatalf("abandoned uploads' bytes remain: %v", ents)
	}
	// An abandoned upload cannot continue and its id cannot be reused.
	h.skew(0)
	if st, _ := h.put(stale, 0, mib/2); st != 410 && st != 409 {
		t.Fatalf("put to an abandoned upload: %d", st)
	}
	if st, _ := h.create(stale); st != 410 {
		t.Fatalf("create of an abandoned id: %d", st)
	}
}

func TestRecordingSweepReleasesAbandonedQuota(t *testing.T) {
	h := newRecH(t, recHOpts{})
	one := RecordingReservation([]int64{mib})
	h.store.SetPolicy(context.Background(), h.tenant, RecordingPolicy{RetentionDays: 30, MaxRecordingBytes: mib, QuotaBytes: one + one/2})
	a := newRecUpload(mib)
	h.mustCreate(a)
	if st, _ := h.create(newRecUpload(mib)); st != 507 {
		t.Fatalf("quota not holding: %d", st)
	}
	h.skew(RecMaxUploadLifetime + time.Minute)
	h.sweep()
	h.skew(0)
	if st, m := h.create(newRecUpload(mib)); st != 201 {
		t.Fatalf("after the abandoned upload released its reservation: %d %v", st, m)
	}
}

// ---- the orphan pass --------------------------------------------------------------------------

func (h *recH) mkOrphan(tenant, rec string, age time.Duration, body string) string {
	h.t.Helper()
	dir := filepath.Join(h.dir, tenant, rec)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0000.ivf.enc"), []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(dir, old, old); err != nil {
		h.t.Fatal(err)
	}
	return dir
}

func (h *recH) quarantineEntries() []string {
	ents, _ := os.ReadDir(filepath.Join(h.dir, ".quarantine"))
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestRecordingOrphanPassQuarantinesNeverDeletes(t *testing.T) {
	h := newRecH(t, recHOpts{})
	live := h.complete(100) // a recording with a live row: must never be touched
	uploading := newRecUpload(mib)
	h.mustCreate(uploading)
	h.put(uploading, 0, 0)
	// The live upload's directory is OLD too, so only the liveness check (not the age guard) protects it.
	liveOld := time.Now().Add(-3 * time.Hour)
	os.Chtimes(filepath.Join(h.dir, ".incoming", h.row(uploading).UploadID), liveOld, liveOld)

	orphanT, orphanR := newUUID(), newUUID()
	h.mkOrphan(orphanT, orphanR, 3*time.Hour, "ORPHAN-EVIDENCE")
	h.mkOrphan(h.tenant, newUUID(), 3*time.Hour, "ORPHAN-IN-LIVE-TENANT")
	young := h.mkOrphan(h.tenant, newUUID(), time.Minute, "YOUNG") // racing a create: left alone
	staleUpload := newUUID()
	os.MkdirAll(filepath.Join(h.dir, ".incoming", staleUpload), 0o700)
	os.WriteFile(filepath.Join(h.dir, ".incoming", staleUpload, "0000.ivf.enc"), []byte("STALE"), 0o600)
	old := time.Now().Add(-3 * time.Hour)
	os.Chtimes(filepath.Join(h.dir, ".incoming", staleUpload), old, old)
	// Odd names: never classified, never touched, however old.
	weird := filepath.Join(h.dir, h.tenant, "lost+found")
	os.MkdirAll(weird, 0o700)
	os.WriteFile(filepath.Join(weird, "x"), []byte("x"), 0o600)
	os.Chtimes(weird, old, old)
	os.WriteFile(filepath.Join(h.dir, h.tenant, "README.txt"), []byte("hi"), 0o600)

	rep := h.sweep()
	if rep.Quarantined != 3 {
		t.Fatalf("quarantined %d, want 3 (two orphans and one stale incoming): %+v", rep.Quarantined, rep)
	}
	if h.exists(orphanT, orphanR) {
		t.Fatal("orphan still in place")
	}
	// Moved, not deleted: the bytes are in quarantine, with a manifest.
	found := false
	for _, name := range h.quarantineEntries() {
		if b, err := os.ReadFile(filepath.Join(h.dir, ".quarantine", name, "0000.ivf.enc")); err == nil && string(b) == "ORPHAN-EVIDENCE" {
			found = true
			if man, _ := os.ReadFile(filepath.Join(h.dir, ".quarantine", name, manifestName)); !strings.Contains(string(man), "no live row") {
				t.Fatalf("manifest: %s", man)
			}
		}
	}
	if !found {
		t.Fatalf("orphan bytes are not in quarantine: %v", h.quarantineEntries())
	}
	for what, path := range map[string]string{
		"live evidence": filepath.Join(h.tenant, live.id, segName(0, RepIVF)),
		"live upload":   filepath.Join(".incoming", h.row(uploading).UploadID, segName(0, RepIVF)),
		"young orphan":  filepath.Join(h.tenant, filepath.Base(young), "0000.ivf.enc"),
		"odd name":      filepath.Join(h.tenant, "lost+found", "x"),
		"stray file":    filepath.Join(h.tenant, "README.txt"),
	} {
		if !h.exists(path) {
			t.Errorf("%s was touched by the orphan pass", what)
		}
	}
	skipped := strings.Join(rep.Skipped, "|")
	if !strings.Contains(skipped, "lost+found") || !strings.Contains(skipped, "README.txt") {
		t.Fatalf("non-UUID names must be REPORTED as skipped: %v", rep.Skipped)
	}
	if h.row(live).State != RecEvidenceComplete {
		t.Fatal("the live recording was disturbed")
	}
}

func TestRecordingQuarantinePurgeOnlyAfterGrace(t *testing.T) {
	h := newRecH(t, recHOpts{})
	h.mkOrphan(newUUID(), newUUID(), 3*time.Hour, "X")
	h.sweep()
	if len(h.quarantineEntries()) != 1 {
		t.Fatalf("quarantine: %v", h.quarantineEntries())
	}
	h.skew(QuarantineGrace - time.Hour)
	if rep := h.sweep(); rep.QuarantinePurged != 0 || len(h.quarantineEntries()) != 1 {
		t.Fatalf("purged inside the grace period: %+v", rep)
	}
	h.skew(QuarantineGrace + time.Hour)
	if rep := h.sweep(); rep.QuarantinePurged != 1 || len(h.quarantineEntries()) != 0 {
		t.Fatalf("not purged after the grace period: %+v %v", rep, h.quarantineEntries())
	}
}

type flakyStore struct {
	RecordingStore
	listErr error
}

func (f *flakyStore) SweepList(ctx context.Context) ([]RecordingSweepRow, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.RecordingStore.SweepList(ctx)
}

func TestRecordingOrphanPassIsDisabledWhenTheDatabaseCannotBeRead(t *testing.T) {
	h := newRecH(t, recHOpts{})
	live := h.complete(100)
	orphan := h.mkOrphan(newUUID(), newUUID(), 3*time.Hour, "O")
	fs := &flakyStore{RecordingStore: h.store, listErr: errors.New("connection refused")}
	h.srv.Recording.Store = fs
	rep, err := h.srv.Recording.Sweep(context.Background())
	if err == nil || rep.Quarantined != 0 || rep.OrphansHeld == "" {
		t.Fatalf("sweep with an unreadable database: err=%v rep=%+v", err, rep)
	}
	if _, serr := os.Stat(orphan); serr != nil || !h.exists(h.tenant, live.id) {
		t.Fatal("something was moved while the database was unreadable (an empty live set would orphan everything)")
	}
	if hl := h.srv.RecordingHealth(); hl.LastSweepOK {
		t.Fatalf("health says the sweep was fine: %+v", hl)
	}
	// Database back: the orphan is quarantined.
	fs.listErr = nil
	if rep := h.sweep(); rep.Quarantined != 1 {
		t.Fatalf("after recovery: %+v", rep)
	}
}

func TestRecordingOrphanPassIsDisabledInReconciliationMode(t *testing.T) {
	h := newRecH(t, recHOpts{})
	orphan := h.mkOrphan(newUUID(), newUUID(), 3*time.Hour, "O")
	h.srv.Recording.ReconcileMode = true
	rep := h.sweep()
	if rep.Quarantined != 0 || rep.OrphansHeld != "reconciliation mode" {
		t.Fatalf("%+v", rep)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("orphan moved in reconciliation mode")
	}
	h.skew(QuarantineGrace + time.Hour)
	// ...and the quarantine purge is off too (nothing is ever deleted while a restore is reconciled).
	h.srv.Recording.ReconcileMode = false
	h.sweep() // quarantines it at the skewed time
	h.srv.Recording.ReconcileMode = true
	h.skew(2*QuarantineGrace + time.Hour)
	if rep := h.sweep(); rep.QuarantinePurged != 0 {
		t.Fatalf("purged in reconciliation mode: %+v", rep)
	}
}

func TestRecordingOrphanPassHoldsOnADatabaseVolumeMismatch(t *testing.T) {
	h := newRecH(t, recHOpts{})
	var dirs []string
	for i := 0; i < 12; i++ { // a volume full of recordings the database has never heard of
		dirs = append(dirs, h.mkOrphan(newUUID(), newUUID(), 3*time.Hour, "D"))
	}
	rep := h.sweep()
	if rep.Quarantined != 0 || !strings.HasPrefix(rep.OrphansHeld, "held") {
		t.Fatalf("a volume that is mostly 'orphans' must be held, not moved: %+v", rep)
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			t.Fatal("a directory was moved during the hold")
		}
	}
}

func TestRecordingOrphanPassPerPassLimit(t *testing.T) {
	h := newRecH(t, recHOpts{})
	for i := 0; i < 6; i++ {
		h.complete(100) // enough live directories that the orphans are a minority
	}
	for i := 0; i < 8; i++ {
		h.complete(100)
	}
	h.srv.Recording.SweepConfig.MaxQuarantinePerPass = 3
	for i := 0; i < 5; i++ {
		h.mkOrphan(newUUID(), newUUID(), 3*time.Hour, "D")
	}
	rep := h.sweep()
	if rep.Quarantined != 3 || !strings.Contains(rep.OrphansHeld, "limit") {
		t.Fatalf("%+v", rep)
	}
	if rep := h.sweep(); rep.Quarantined != 2 {
		t.Fatalf("second pass: %+v", rep)
	}
}

func TestRecordingSweepNeverFollowsLinks(t *testing.T) {
	h := newRecH(t, recHOpts{})
	outside := t.TempDir()
	victim := filepath.Join(outside, newUUID(), "0000.ivf.enc")
	os.MkdirAll(filepath.Dir(victim), 0o700)
	os.WriteFile(victim, []byte("precious"), 0o600)
	// A tenant directory that is a link out of the volume, and a recording directory that is one.
	linkDir(t, outside, filepath.Join(h.dir, newUUID()))
	tdir := filepath.Join(h.dir, newUUID())
	os.MkdirAll(tdir, 0o700)
	linkDir(t, filepath.Join(outside, filepath.Base(filepath.Dir(victim))), filepath.Join(tdir, newUUID()))
	old := time.Now().Add(-5 * time.Hour)
	os.Chtimes(tdir, old, old)

	rep := h.sweep()
	if rep.Quarantined != 0 {
		t.Fatalf("a link was treated as an orphan directory and moved: %+v", rep)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "precious" {
		t.Fatalf("the file behind the link was touched: %v %q", err, b)
	}
	if len(rep.Skipped) < 2 {
		t.Fatalf("links must be reported as skipped: %v", rep.Skipped)
	}
}

func TestRecordingSweepRidesTheReaperTick(t *testing.T) {
	// The reaper's own stores are not wired here: the recording sweep must still run (it is deferred, so
	// it runs however RunReaperSweep returns).
	h := newRecH(t, recHOpts{})
	u := h.complete(100)
	h.skew(31 * 24 * time.Hour)
	h.srv.RunReaperSweep(context.Background())
	if h.row(u).State != RecDeleted || h.exists(h.tenant, u.id) {
		t.Fatalf("the reaper tick did not run the recording sweep: state=%s", h.row(u).State)
	}
	// Not wired at all: a no-op, not a panic.
	(&Server{}).RunReaperSweep(context.Background())
}

func TestRecordingStartRecordingServicesReconciles(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := newRecUpload(2*mib, 10)
	h.mustCreate(u)
	h.put(u, 0, 0)
	os.Remove(h.incomingPath(u, 0))
	h.srv.StartRecordingServices(context.Background())
	if h.row(u).Segments[0].CommittedOffset != 0 {
		t.Fatal("startup reconciliation did not forget the lost bytes")
	}
	(&Server{}).StartRecordingServices(context.Background()) // unwired: no-op
}
