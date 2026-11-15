package controlplane

// C1 (review r2): directory components are PINNED, not re-resolved. These tests swap an intermediate
// directory for a link to ANOTHER directory INSIDE the volume (os.Root alone would follow such a link) in
// each window: before a component is opened, after the directory was pinned, and between unlinks during a
// deletion. Nothing of the other tenant or the other recording may be read, moved or deleted.
// C2: required directory fsync failures are propagated.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const stOther = "55555555-5555-4555-8555-555555555555"

// swapDirForLink moves the real directory aside and puts an in-volume link to `victim` in its place.
func swapDirForLink(t *testing.T, dir, rel, victim string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.Rename(p, p+".moved"); err != nil {
		t.Fatalf("cannot move %s aside: %v", rel, err)
	}
	linkInRoot(t, victim, p)
}

func unswap(dir, rel string) {
	p := filepath.Join(dir, filepath.FromSlash(rel))
	os.Remove(p)
	os.Rename(p+".moved", p)
}

func raceFixture(t *testing.T) (*RecordingStorage, string, string) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "genuine")
	victimDir := filepath.Join(dir, stTenant2, stOther)
	writeFile(t, filepath.Join(victimDir, "0000.ivf.enc"), "victim-evidence")
	return s, dir, victimDir
}

func victimIntact(t *testing.T, victimDir string) {
	t.Helper()
	if b, err := os.ReadFile(filepath.Join(victimDir, "0000.ivf.enc")); err != nil || string(b) != "victim-evidence" {
		t.Fatalf("the other tenant's evidence was touched: %v %q", err, b)
	}
}

func closeIf(f *os.File) {
	if f != nil {
		f.Close()
	}
}

func TestStorageDirSwappedBeforeItIsOpenedIsRefused(t *testing.T) {
	for _, level := range []string{stTenant, stTenant + "/" + stRec} {
		t.Run(level, func(t *testing.T) {
			s, dir, victimDir := raceFixture(t)
			target := filepath.Join(dir, stTenant2) // the whole other tenant...
			if level != stTenant {
				target = victimDir // ...or just the other recording
			}
			swapped := false
			s.beforePin = func(rel string) {
				if rel == level && !swapped {
					swapped = true
					swapDirForLink(t, dir, rel, target)
				}
			}
			ops := map[string]func() error{
				"open":   func() error { f, _, err := s.OpenFinal(stTenant, stRec, 0, RepIVF); closeIf(f); return err },
				"remove": func() error { _, err := s.RemoveRecording(stTenant, stRec); return err },
				"quarantine": func() error {
					_, err := s.QuarantineRecording(stTenant, stRec, "x", time.Now())
					return err
				},
			}
			for name, op := range ops {
				swapped = false
				err := op()
				if swapped {
					unswap(dir, level)
				}
				if !errors.Is(err, ErrUnsafePath) {
					t.Errorf("%s through a directory swapped before it was opened: %v, want ErrUnsafePath", name, err)
				}
			}
			victimIntact(t, victimDir)
		})
	}
}

// After the directory is pinned, replacing its path with a link to another recording changes nothing: the
// handle still names the original.
func TestStoragePinnedDirIsNotRedirectedBySwapAfterPinning(t *testing.T) {
	s, dir, victimDir := raceFixture(t)
	rel := stTenant + "/" + stRec
	s.afterPin = func(r string) {
		if r == rel {
			s.afterPin = nil
			swapDirForLink(t, dir, rel, victimDir)
		}
	}
	f, _, err := s.OpenFinal(stTenant, stRec, 0, RepIVF)
	if err != nil {
		t.Fatalf("open through the pinned handle: %v", err)
	}
	defer f.Close()
	b := make([]byte, 64)
	n, _ := f.Read(b)
	if string(b[:n]) != "genuine" {
		t.Fatalf("read %q through a swapped path: the pinned handle must keep naming the ORIGINAL directory", b[:n])
	}
	victimIntact(t, victimDir)
}

// Deletion: the swap happens after the directory was pinned (before the first unlink) and again between
// two unlinks. The unlinks go through the handle, the victim is untouched, and because the parent no longer
// names the pinned directory the entry is not removed and the call reports it.
func TestStorageDeletionNeverFollowsASwappedDirectory(t *testing.T) {
	for _, when := range []string{"after pin", "between unlinks"} {
		t.Run(when, func(t *testing.T) {
			s, dir, victimDir := raceFixture(t)
			writeFile(t, filepath.Join(dir, stTenant, stRec, "0001.ivf.enc"), "second")
			rel := stTenant + "/" + stRec
			swap := func() { swapDirForLink(t, dir, rel, victimDir) }
			if when == "after pin" {
				s.afterPin = func(r string) {
					if r == rel {
						s.afterPin = nil
						swap()
					}
				}
			} else {
				n := 0
				s.beforeRemove = func(string) {
					if n++; n == 2 {
						swap()
					}
				}
			}
			_, err := s.RemoveRecording(stTenant, stRec)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("delete during a swap: %v, want ErrUnsafePath (the parent no longer names the directory that was emptied)", err)
			}
			victimIntact(t, victimDir)
			if _, err := os.Lstat(filepath.Join(dir, stTenant, stRec)); err != nil {
				t.Fatalf("the substituted link was removed: %v", err)
			}
		})
	}
}

// Promote / quarantine through a swapped source or destination directory touch only the pinned ones.
func TestStoragePromoteAndQuarantineRefuseASwappedDirectory(t *testing.T) {
	t.Run("promote destination swapped before open", func(t *testing.T) {
		s, dir, victimDir := raceFixture(t)
		writeFile(t, filepath.Join(dir, ".incoming", stUpload, "0000.ivf.enc"), "incoming-bytes")
		rel := stTenant + "/" + stRec
		s.beforePin = func(r string) {
			if r == rel {
				s.beforePin = nil
				swapDirForLink(t, dir, rel, victimDir)
			}
		}
		if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("promote into a swapped directory: %v", err)
		}
		victimIntact(t, victimDir)
		if _, err := os.Stat(filepath.Join(dir, ".incoming", stUpload, "0000.ivf.enc")); err != nil {
			t.Fatalf("the incoming file moved: %v", err)
		}
	})
	t.Run("quarantine source swapped after pin", func(t *testing.T) {
		s, dir, victimDir := raceFixture(t)
		rel := stTenant + "/" + stRec
		s.afterPin = func(r string) {
			if r == rel {
				s.afterPin = nil
				swapDirForLink(t, dir, rel, victimDir)
			}
		}
		if _, err := s.QuarantineRecording(stTenant, stRec, "x", time.Now()); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("quarantine of a swapped directory: %v", err)
		}
		victimIntact(t, victimDir)
		ents, _ := os.ReadDir(filepath.Join(dir, ".quarantine"))
		if len(ents) != 0 {
			t.Fatalf("something was quarantined: %v", ents)
		}
	})
}

// ---- C2: required directory fsync failures are propagated ---------------------------------------

func TestStorageDeletionStaysPendingWhenTheParentSyncFails(t *testing.T) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "a")
	s.syncFail = func(rel string) error {
		if rel == stTenant {
			return errors.New("injected EIO")
		}
		return nil
	}
	if _, err := s.RemoveRecording(stTenant, stRec); err == nil || !strings.Contains(err.Error(), "injected EIO") {
		t.Fatalf("RemoveRecording hid a parent-directory fsync failure: %v", err)
	}
	// The retry (directory already gone) must STILL sync the parent, so the removal becomes durable.
	if _, err := s.RemoveRecording(stTenant, stRec); err == nil {
		t.Fatal("the retry reported success without syncing the parent")
	}
	s.syncFail = nil
	if n, err := s.RemoveRecording(stTenant, stRec); err != nil || n != 0 {
		t.Fatalf("retry after the fault cleared: %d %v", n, err)
	}
}

func TestStorageQuarantineSyncsEntryAndBothParentsAndReportsFailure(t *testing.T) {
	for _, failAt := range []string{stTenant, dirQuarantine, "entry"} {
		t.Run(failAt, func(t *testing.T) {
			s, dir := newStorage(t)
			writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "a")
			s.syncFail = func(rel string) error {
				if rel == failAt || (failAt == "entry" && strings.HasPrefix(rel, dirQuarantine+"/")) {
					return errors.New("injected EIO")
				}
				return nil
			}
			name, err := s.QuarantineRecording(stTenant, stRec, "x", time.Now())
			if err == nil || !strings.Contains(err.Error(), "injected EIO") {
				t.Fatalf("a failed %s sync was not reported: %v", failAt, err)
			}
			if name == "" {
				t.Fatal("the quarantine entry (which exists) must be named in the failure")
			}
			// The entry exists with its manifest: nothing is lost, the caller is just told the step failed.
			if _, serr := os.Stat(filepath.Join(dir, ".quarantine", name, manifestName)); serr != nil {
				t.Fatalf("manifest missing: %v", serr)
			}
		})
	}
	t.Run("all three are synced on success", func(t *testing.T) {
		s, dir := newStorage(t)
		writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "a")
		var synced []string
		s.syncFail = func(rel string) error { synced = append(synced, rel); return nil }
		name, err := s.QuarantineRecording(stTenant, stRec, "x", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{".quarantine/" + name: false, dirQuarantine: false, stTenant: false}
		for _, r := range synced {
			if _, ok := want[r]; ok {
				want[r] = true
			}
		}
		for r, ok := range want {
			if !ok {
				t.Errorf("%q was not fsynced (synced: %v)", r, synced)
			}
		}
	})
}

func TestStoragePromoteReportsASyncFailure(t *testing.T) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, ".incoming", stUpload, "0000.ivf.enc"), "x")
	s.syncFail = func(rel string) error {
		if rel == stTenant+"/"+stRec {
			return errors.New("injected EIO")
		}
		return nil
	}
	if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("a failed destination fsync was swallowed")
	}
}

// The sweeper keeps a recording 'expired' (deletion pending, lag reported) when the unlink's parent sync
// fails, and only then marks it deleted once a retry has synced.
func TestSweepKeepsDeletionPendingWhenTheParentSyncFails(t *testing.T) {
	h := newRecH(t, recHOpts{})
	u := h.complete(100)
	h.files.syncFail = func(rel string) error {
		if rel == h.tenant {
			return errors.New("injected EIO")
		}
		return nil
	}
	h.skew(31 * 24 * time.Hour)
	rep := h.sweep()
	if rep.Deleted != 0 || rep.DeleteFailed != 1 || h.row(u).State != RecExpired {
		t.Fatalf("an unsynced removal was confirmed: %+v state %s", rep, h.row(u).State)
	}
	h.files.syncFail = nil
	if rep := h.sweep(); rep.Deleted != 1 || h.row(u).State != RecDeleted {
		t.Fatalf("retry: %+v state %s", rep, h.row(u).State)
	}
}

// ---- review r3: idempotent success paths redo the required directory syncs ------------------------

// syncRecorder fails every sync of the labels in fail, and records every label it is asked to sync.
type syncRecorder struct {
	fail map[string]bool
	seen []string
}

func (r *syncRecorder) hook(rel string) error {
	r.seen = append(r.seen, rel)
	if r.fail[rel] {
		return errors.New("injected EIO")
	}
	return nil
}

func (r *syncRecorder) saw(rel string) bool {
	for _, s := range r.seen {
		if s == rel {
			return true
		}
	}
	return false
}

func TestStoragePromoteRetryAfterAFailedSyncResyncsBeforeAcknowledging(t *testing.T) {
	for _, failAt := range []string{stTenant + "/" + stRec, dirIncoming + "/" + stUpload} {
		t.Run(failAt, func(t *testing.T) {
			s, dir := newStorage(t)
			writeFile(t, filepath.Join(dir, ".incoming", stUpload, "0000.ivf.enc"), "x")
			rec := &syncRecorder{fail: map[string]bool{failAt: true}}
			s.syncFail = rec.hook
			if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
				t.Fatal("the failed sync was swallowed")
			}
			// The rename itself happened: the retry sees an already-promoted file.
			if _, err := os.Stat(filepath.Join(dir, stTenant, stRec, "0000.ivf.enc")); err != nil {
				t.Fatalf("test premise: the rename did not happen: %v", err)
			}
			// Retry while the sync still fails: it must NOT be acknowledged.
			if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
				t.Fatal("a retry acknowledged an already-promoted file although the directory sync still fails")
			}
			// Retry with the fault cleared: success, and the syncs were actually performed.
			rec2 := &syncRecorder{}
			s.syncFail = rec2.hook
			if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err != nil {
				t.Fatalf("retry after the fault cleared: %v", err)
			}
			for _, want := range []string{stTenant + "/" + stRec, dirIncoming} {
				if !rec2.saw(want) {
					t.Errorf("the idempotent success never synced %q (synced %v)", want, rec2.seen)
				}
			}
		})
	}
}

func TestStorageUnpromoteRetryAfterAFailedSyncResyncs(t *testing.T) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "x")
	rec := &syncRecorder{fail: map[string]bool{dirIncoming + "/" + stUpload: true}}
	s.syncFail = rec.hook
	if err := s.Unpromote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("the failed sync was swallowed")
	}
	if err := s.Unpromote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("a retry acknowledged an already-moved file although the sync still fails")
	}
	rec2 := &syncRecorder{}
	s.syncFail = rec2.hook
	if err := s.Unpromote(stUpload, stTenant, stRec, 0, RepIVF); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{dirIncoming + "/" + stUpload, stTenant + "/" + stRec} {
		if !rec2.saw(want) {
			t.Errorf("the idempotent success never synced %q (synced %v)", want, rec2.seen)
		}
	}
}

// A directory created by an attempt whose parent sync failed exists on the retry; the retry must still
// sync the parent before it succeeds.
func TestStorageCreatedDirectoryWhoseParentSyncFailedIsResyncedOnRetry(t *testing.T) {
	s, _ := newStorage(t)
	rec := &syncRecorder{fail: map[string]bool{dirIncoming: true}}
	s.syncFail = rec.hook
	if f, err := s.OpenIncoming(stUpload, 0, RepIVF, true); err == nil {
		f.Close()
		t.Fatal("the failed parent sync was swallowed")
	}
	if f, err := s.OpenIncoming(stUpload, 0, RepIVF, true); err == nil {
		f.Close()
		t.Fatal("a retry succeeded although the created directory's parent still cannot be synced")
	}
	rec2 := &syncRecorder{}
	s.syncFail = rec2.hook
	f, err := s.OpenIncoming(stUpload, 0, RepIVF, true)
	if err != nil {
		t.Fatalf("retry after the fault cleared: %v", err)
	}
	f.Close()
	if !rec2.saw(dirIncoming) {
		t.Fatalf("the retry succeeded without syncing the parent (synced %v)", rec2.seen)
	}
	// Once synced it is not synced again by every later open (the chunk path must stay cheap).
	rec3 := &syncRecorder{}
	s.syncFail = rec3.hook
	f, err = s.OpenIncoming(stUpload, 0, RepIVF, true)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if rec3.saw(dirIncoming) {
		t.Fatalf("a clean directory was re-synced on every open: %v", rec3.seen)
	}
}

// The source directory is already gone (finish removed the empty upload directory after a promotion whose
// destination sync failed): the retry is still not acknowledged without the destination sync.
func TestStoragePromoteRetryWithTheSourceDirectoryGoneStillSyncs(t *testing.T) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, ".incoming", stUpload, "0000.ivf.enc"), "x")
	dst := stTenant + "/" + stRec
	rec := &syncRecorder{fail: map[string]bool{dst: true}}
	s.syncFail = rec.hook
	if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("the failed sync was swallowed")
	}
	if err := os.RemoveAll(filepath.Join(dir, ".incoming", stUpload)); err != nil {
		t.Fatal(err)
	}
	if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("a retry acknowledged an already-promoted file although the destination sync still fails")
	}
	rec2 := &syncRecorder{}
	s.syncFail = rec2.hook
	if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err != nil || !rec2.saw(dst) {
		t.Fatalf("retry: err=%v synced=%v", err, rec2.seen)
	}
}
