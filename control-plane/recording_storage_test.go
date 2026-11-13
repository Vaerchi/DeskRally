package controlplane

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	stTenant  = "11111111-1111-4111-8111-111111111111"
	stRec     = "22222222-2222-4222-8222-222222222222"
	stUpload  = "33333333-3333-4333-8333-333333333333"
	stTenant2 = "44444444-4444-4444-8444-444444444444"
)

func newStorage(t *testing.T) (*RecordingStorage, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenRecordingStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

// link makes a directory link (symlink, or on Windows without the privilege a junction) at newname
// pointing at target. A test that cannot create a link FAILS rather than skips: the refusal it proves
// would otherwise go unproven.
func linkDir(t *testing.T, target, newname string) {
	t.Helper()
	if err := os.Symlink(target, newname); err == nil {
		return
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/c", "mklink", "/J", newname, target).CombinedOutput()
		if err == nil {
			return
		}
		t.Fatalf("cannot create a symlink or junction: %v %s", err, out)
	}
	t.Fatal("cannot create a symlink")
}

func linkFile(t *testing.T, target, newname string) {
	t.Helper()
	if err := os.Symlink(target, newname); err != nil {
		t.Fatalf("cannot create a file symlink (enable Developer Mode on Windows): %v", err)
	}
}

// linkInRoot makes a link with a RELATIVE target, so it stays inside the volume: os.Root follows such a
// link (it only refuses ones that leave the root), which is exactly what this layer must not do.
func linkInRoot(t *testing.T, target, newname string) {
	t.Helper()
	rel, err := filepath.Rel(filepath.Dir(newname), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, newname); err != nil {
		t.Fatalf("cannot create a symlink (enable Developer Mode on Windows): %v", err)
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStoragePathsAreIdsOnly(t *testing.T) {
	s, _ := newStorage(t)
	for _, bad := range []string{"../x", "..", "", "ABCDEF00-0000-4000-8000-000000000000", "11111111111141118111111111111111", stTenant + "/../x", "a\\b"} {
		if _, _, err := s.OpenFinal(bad, stRec, 0, RepIVF); err == nil {
			t.Errorf("OpenFinal accepted tenant %q", bad)
		}
		if _, err := s.RemoveRecording(stTenant, bad); err == nil {
			t.Errorf("RemoveRecording accepted recording %q", bad)
		}
		if _, err := s.OpenIncoming(bad, 0, RepIVF, true); err == nil {
			t.Errorf("OpenIncoming accepted upload %q", bad)
		}
		if _, err := s.QuarantineRecording(bad, stRec, "x", time.Now()); err == nil {
			t.Errorf("QuarantineRecording accepted %q", bad)
		}
	}
	if finalFileRel(stTenant, stRec, 7, RepWebM) != stTenant+"/"+stRec+"/0007.webm.enc" {
		t.Fatal("final path layout changed")
	}
	if incomingFileRel(stUpload, 12, RepIVF) != ".incoming/"+stUpload+"/0012.ivf.enc" {
		t.Fatal("incoming path layout changed")
	}
}

func TestStorageIncomingPromoteAndReadBack(t *testing.T) {
	s, dir := newStorage(t)
	f, err := s.OpenIncoming(stUpload, 3, RepIVF, true)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("hello"), 0)
	f.Close()
	// Reopen (resume) keeps the bytes.
	f, err = s.OpenIncoming(stUpload, 3, RepIVF, true)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	f.ReadAt(b, 0)
	f.Close()
	if string(b) != "hello" {
		t.Fatalf("reopen lost bytes: %q", b)
	}
	if err := s.Promote(stUpload, stTenant, stRec, 3, RepIVF); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".incoming", stUpload, "0003.ivf.enc")); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	// Idempotent: promoting again succeeds (source gone, destination valid).
	if err := s.Promote(stUpload, stTenant, stRec, 3, RepIVF); err != nil {
		t.Fatalf("second promote: %v", err)
	}
	g, size, err := s.OpenFinal(stTenant, stRec, 3, RepIVF)
	if err != nil || size != 5 {
		t.Fatalf("open final: %v size %d", err, size)
	}
	g.Close()
	if !s.FinalExists(stTenant, stRec, 3, RepIVF) || s.FinalExists(stTenant, stRec, 4, RepIVF) {
		t.Fatal("FinalExists wrong")
	}
	// Promote with no source and no destination fails.
	if err := s.Promote(stUpload, stTenant, stRec, 9, RepIVF); err == nil {
		t.Fatal("promote of nothing succeeded")
	}
}

func TestStorageRefusesLinkedDirectoriesAndNeverDeletesThroughThem(t *testing.T) {
	s, dir := newStorage(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, stRec, "0000.ivf.enc")
	writeFile(t, victim, "precious")

	// <root>/<tenant> is a link to a directory OUTSIDE the root that contains <recording>/0000.ivf.enc.
	linkDir(t, outside, filepath.Join(dir, stTenant))

	if _, err := s.RemoveRecording(stTenant, stRec); err == nil {
		t.Fatal("RemoveRecording followed a linked tenant directory")
	}
	if _, _, err := s.OpenFinal(stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("OpenFinal followed a linked tenant directory")
	}
	if _, err := s.QuarantineRecording(stTenant, stRec, "x", time.Now()); err == nil {
		t.Fatal("QuarantineRecording followed a linked tenant directory")
	}
	if err := s.Promote(stUpload, stTenant, stRec, 0, RepIVF); err == nil {
		t.Fatal("Promote wrote through a linked tenant directory")
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "precious" {
		t.Fatalf("the file outside the root was touched: %v %q", err, b)
	}
	// Listing reports the link as skipped and does not list it as a tenant.
	l, err := s.ListTenantDirs()
	if err != nil {
		t.Fatal(err)
	}
	if len(l.IDs) != 0 || len(l.Skipped) != 1 {
		t.Fatalf("listing = %+v; a linked tenant directory must be skipped", l)
	}
}

func TestStorageRefusesLinkedRecordingDirAndLinkedEntries(t *testing.T) {
	s, dir := newStorage(t)
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "0000.ivf.enc"), "precious")
	if err := os.MkdirAll(filepath.Join(dir, stTenant), 0o700); err != nil {
		t.Fatal(err)
	}
	// <tenant>/<recording> itself is a link.
	linkDir(t, outside, filepath.Join(dir, stTenant, stRec))
	if _, err := s.RemoveRecording(stTenant, stRec); err == nil {
		t.Fatal("RemoveRecording followed a linked recording directory")
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "0000.ivf.enc")); string(b) != "precious" {
		t.Fatal("outside file deleted")
	}
	l, _ := s.ListRecordingDirs(stTenant)
	if len(l.IDs) != 0 || len(l.Skipped) != 1 {
		t.Fatalf("listing = %+v", l)
	}
}

func TestStorageRemoveRefusesUnexpectedEntriesBeforeDeletingAnything(t *testing.T) {
	s, dir := newStorage(t)
	rdir := filepath.Join(dir, stTenant, stRec)
	writeFile(t, filepath.Join(rdir, "0000.ivf.enc"), "a")
	writeFile(t, filepath.Join(rdir, "0001.ivf.enc"), "b")
	writeFile(t, filepath.Join(rdir, "notes.txt"), "someone's file")
	if _, err := s.RemoveRecording(stTenant, stRec); !errors.Is(err, ErrUnexpectedEntry) {
		t.Fatalf("RemoveRecording with a foreign file: %v", err)
	}
	for _, n := range []string{"0000.ivf.enc", "0001.ivf.enc", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(rdir, n)); err != nil {
			t.Fatalf("%s was deleted although the directory was refused: %v", n, err)
		}
	}
	// A DIRECTORY named like a segment file is also not a regular file.
	os.Remove(filepath.Join(rdir, "notes.txt"))
	if err := os.Mkdir(filepath.Join(rdir, "0002.ivf.enc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveRecording(stTenant, stRec); err == nil {
		t.Fatal("a directory posing as a segment file was accepted")
	}
	if _, err := os.Stat(filepath.Join(rdir, "0000.ivf.enc")); err != nil {
		t.Fatal("known file deleted before the refusal")
	}
	os.Remove(filepath.Join(rdir, "0002.ivf.enc"))
	n, err := s.RemoveRecording(stTenant, stRec)
	if err != nil || n != 2 {
		t.Fatalf("clean removal: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(rdir); !os.IsNotExist(err) {
		t.Fatal("directory still there")
	}
	// Idempotent.
	if n, err := s.RemoveRecording(stTenant, stRec); err != nil || n != 0 {
		t.Fatalf("second removal: n=%d err=%v", n, err)
	}
}

func TestStorageListingReportsOddNamesAndNeverTouchesThem(t *testing.T) {
	s, dir := newStorage(t)
	os.MkdirAll(filepath.Join(dir, stTenant, stRec), 0o700)
	os.MkdirAll(filepath.Join(dir, stTenant, "not-a-uuid"), 0o700)
	writeFile(t, filepath.Join(dir, stTenant, "stray-file"), "x")
	os.MkdirAll(filepath.Join(dir, stTenant, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"), 0o700) // upper-case uuid is not canonical
	os.MkdirAll(filepath.Join(dir, "lost+found"), 0o700)
	writeFile(t, filepath.Join(dir, "rootfile"), "x")

	l, err := s.ListRecordingDirs(stTenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.IDs) != 1 || l.IDs[0] != stRec || len(l.Skipped) != 3 {
		t.Fatalf("recording listing = %+v", l)
	}
	tl, _ := s.ListTenantDirs()
	if len(tl.IDs) != 1 || tl.IDs[0] != stTenant || len(tl.Skipped) != 2 {
		t.Fatalf("tenant listing = %+v", tl)
	}
	for _, p := range []string{filepath.Join(dir, stTenant, "not-a-uuid"), filepath.Join(dir, "lost+found"), filepath.Join(dir, "rootfile")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was touched", p)
		}
	}
}

func TestStorageQuarantineMovesWithManifestAndPurgesOnlyAfterGrace(t *testing.T) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "evidence")
	now := time.Unix(1_800_000_000, 0)
	name, err := s.QuarantineRecording(stTenant, stRec, "no live row", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, stTenant, stRec)); !os.IsNotExist(err) {
		t.Fatal("orphan still in place")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".quarantine", name, "0000.ivf.enc")); string(b) != "evidence" {
		t.Fatal("content lost in quarantine")
	}
	man, err := os.ReadFile(filepath.Join(dir, ".quarantine", name, manifestName))
	if err != nil || !strings.Contains(string(man), "no live row") || !strings.Contains(string(man), "0000.ivf.enc") {
		t.Fatalf("manifest: %v %s", err, man)
	}
	// Within grace: nothing is purged.
	if n, _, err := s.PurgeQuarantine(now.Add(QuarantineGrace-time.Hour), QuarantineGrace); err != nil || n != 0 {
		t.Fatalf("purged inside grace: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".quarantine", name)); err != nil {
		t.Fatal("quarantine entry gone inside grace")
	}
	// An entry without a manifest, and a foreign name, are skipped even past grace.
	writeFile(t, filepath.Join(dir, ".quarantine", "1700000000-nomanifest", "0000.ivf.enc"), "x")
	os.MkdirAll(filepath.Join(dir, ".quarantine", "random-name"), 0o700)
	n, skipped, err := s.PurgeQuarantine(now.Add(QuarantineGrace+time.Hour), QuarantineGrace)
	if err != nil || n != 1 || len(skipped) != 2 {
		t.Fatalf("purge: n=%d skipped=%v err=%v", n, skipped, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".quarantine", "1700000000-nomanifest", "0000.ivf.enc")); err != nil {
		t.Fatal("a manifest-less entry was deleted")
	}
	if _, err := os.Stat(filepath.Join(dir, ".quarantine", name)); !os.IsNotExist(err) {
		t.Fatal("expired quarantine entry not purged")
	}
}

func TestStorageQuarantineRefusesDirectoryWithLink(t *testing.T) {
	s, dir := newStorage(t)
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "x"), "keep")
	rdir := filepath.Join(dir, stTenant, stRec)
	writeFile(t, filepath.Join(rdir, "0000.ivf.enc"), "e")
	linkDir(t, outside, filepath.Join(rdir, "sub"))
	if _, err := s.QuarantineRecording(stTenant, stRec, "x", time.Now()); !errors.Is(err, ErrUnexpectedEntry) {
		t.Fatalf("quarantine of a directory holding a link: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rdir, "0000.ivf.enc")); err != nil {
		t.Fatal("directory was moved despite the refusal")
	}
}

// os.Root refuses a link that leaves the root, but follows one that stays inside it. A recording store
// must follow neither: <tenant B> -> <tenant A> is exactly how a delete or a read for one tenant gets
// steered at another tenant's recordings.
func TestStorageRefusesLinksThatStayInsideTheRoot(t *testing.T) {
	s, dir := newStorage(t)
	victim := filepath.Join(dir, stTenant, stRec, "0000.ivf.enc")
	writeFile(t, victim, "tenant-A-evidence")
	// <root>/<tenant2> is a link to <root>/<tenant>: both are inside the volume.
	linkInRoot(t, filepath.Join(dir, stTenant), filepath.Join(dir, stTenant2))

	if _, err := s.RemoveRecording(stTenant2, stRec); err == nil {
		t.Fatal("RemoveRecording followed an in-root link into another tenant's directory")
	}
	if _, _, err := s.OpenFinal(stTenant2, stRec, 0, RepIVF); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenFinal through an in-root link: %v", err)
	}
	if _, err := s.QuarantineRecording(stTenant2, stRec, "x", time.Now()); err == nil {
		t.Fatal("QuarantineRecording followed an in-root link")
	}
	if err := s.Promote(stUpload, stTenant2, stRec, 0, RepIVF); err == nil {
		t.Fatal("Promote wrote through an in-root link")
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "tenant-A-evidence" {
		t.Fatalf("the other tenant's evidence was touched: %v %q", err, b)
	}
	l, _ := s.ListTenantDirs()
	if len(l.IDs) != 1 || l.IDs[0] != stTenant || len(l.Skipped) != 1 {
		t.Fatalf("listing = %+v; the in-root link must be skipped, not listed as a tenant", l)
	}
	if rl, err := s.ListRecordingDirs(stTenant2); err == nil && len(rl.IDs) != 0 {
		t.Fatalf("recordings listed through an in-root link: %+v", rl)
	}

	// The same one level down: a recording directory that links to a sibling recording.
	other := "55555555-5555-4555-8555-555555555555"
	writeFile(t, filepath.Join(dir, stTenant, other, "0000.ivf.enc"), "sibling")
	os.RemoveAll(filepath.Join(dir, stTenant2)) // drop the first link (a link: only the link goes)
	if err := os.MkdirAll(filepath.Join(dir, stTenant2), 0o700); err != nil {
		t.Fatal(err)
	}
	linkInRoot(t, filepath.Join(dir, stTenant, other), filepath.Join(dir, stTenant2, stRec))
	if _, err := s.RemoveRecording(stTenant2, stRec); err == nil {
		t.Fatal("RemoveRecording followed an in-root recording link")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, stTenant, other, "0000.ivf.enc")); string(b) != "sibling" {
		t.Fatal("the sibling recording was deleted through a link")
	}
	// ...and a file link that stays inside the root.
	linkInRoot(t, victim, filepath.Join(dir, stTenant, other, "0001.ivf.enc"))
	if _, _, err := s.OpenFinal(stTenant, other, 1, RepIVF); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenFinal through an in-root file link: %v", err)
	}
	if _, err := s.RemoveRecording(stTenant, other); err == nil {
		t.Fatal("RemoveRecording deleted a directory holding a file link")
	}
	if b, _ := os.ReadFile(victim); string(b) != "tenant-A-evidence" {
		t.Fatal("the link's target was touched")
	}
}

// A file swapped for a link between the path check and the open is caught by comparing what was opened
// with a fresh Lstat of the path.
func TestStorageOpenIsRevalidatedAgainstASwap(t *testing.T) {
	s, dir := newStorage(t)
	writeFile(t, filepath.Join(dir, stTenant, stRec, "0000.ivf.enc"), "genuine")
	writeFile(t, filepath.Join(dir, "elsewhere"), "someone else's file")
	s.afterCheck = func(rel string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.Remove(p)
		linkInRoot(t, filepath.Join(dir, "elsewhere"), p) // an in-root link, so os.Root itself would follow it
	}
	f, _, err := s.OpenFinal(stTenant, stRec, 0, RepIVF)
	if err == nil {
		f.Close()
		t.Fatal("a file swapped for a link after the check was opened")
	}
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
}

func TestStorageFileSymlinkRefused(t *testing.T) {
	s, dir := newStorage(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	writeFile(t, secret, "secret")
	rdir := filepath.Join(dir, stTenant, stRec)
	os.MkdirAll(rdir, 0o700)
	linkFile(t, secret, filepath.Join(rdir, "0000.ivf.enc"))
	if _, _, err := s.OpenFinal(stTenant, stRec, 0, RepIVF); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenFinal through a file symlink: %v", err)
	}
	if _, err := s.RemoveRecording(stTenant, stRec); err == nil {
		t.Fatal("RemoveRecording accepted a symlink entry")
	}
	if b, _ := os.ReadFile(secret); string(b) != "secret" {
		t.Fatal("target of the symlink was touched")
	}
}

func TestStorageFreeBytes(t *testing.T) {
	s, _ := newStorage(t)
	n, err := s.FreeBytes()
	if err != nil || n == 0 {
		t.Fatalf("FreeBytes = %d, %v", n, err)
	}
}
