package controlplane

// Recording storage on a writable volume (docs/63 D3, §2a C6).
//
// EVERY operation is relative to a PINNED DIRECTORY HANDLE. A path is never checked and then re-resolved:
//
//   - The volume is opened once as a trusted os.Root. To reach <tenant>/<recording> (or
//     .incoming/<upload>, .quarantine/<entry>) the layer walks the path ONE COMPONENT AT A TIME: Lstat the
//     name in the already-pinned parent (it must be a plain directory — never a symlink, junction/reparse
//     point or other irregular file — on the volume's own device), OpenRoot that name, and then require the
//     opened handle to be the very directory the Lstat saw (os.SameFile) and again on the volume's device.
//     os.Root.OpenRoot follows a symlink that stays inside the root; if one is swapped in between the
//     Lstat and the open, the handle lands on a DIFFERENT directory than the Lstat described and the
//     comparison refuses it. What follows is then done through that handle with single-component names:
//     the handle (a descriptor / NT handle) keeps naming the original directory even if the path above it
//     is renamed, replaced with a link, or has a filesystem mounted over it.
//   - Files are opened, stat-ed, renamed and unlinked by NAME INSIDE a pinned directory. A file opened
//     through os.Root could still be a link that stays inside THAT directory, so the opened handle is
//     compared with a fresh Lstat of the name (a swap between check and open is refused).
//   - Moving between two directories (promote, quarantine) uses renameat(2) on the two pinned directory
//     descriptors on Linux, so neither path is re-resolved. os.Root offers no two-handle rename, so on other
//     platforms (Windows development hosts; production is Linux in Docker) the rename goes through the
//     volume root by relative path and the result is VERIFIED against the pinned handles afterwards: a
//     substitution inside that one call is reported (ErrUnsafePath), not prevented. os.Root itself still
//     guarantees it cannot leave the volume.
//   - Directory fsync (rename/create/unlink durability) is REQUIRED: a failure is returned and the caller
//     treats the step as not done (deletion stays pending and is retried, quarantine reports failure).
//     Windows cannot fsync a directory handle at all, so there — and only there — it is an explicit no-op
//     (NTFS journals metadata; a rename is durable once it returns). Every other platform propagates.
//
// Paths are DERIVED ONLY from ids: <tenant uuid>/<recording uuid>/<NNNN>.<ivf|webm>.enc for finished
// files, .incoming/<upload uuid>/<NNNN>.ivf.enc for in-flight uploads, .quarantine/<unix>-<…> for
// apparent orphans. Callers hand over canonical lower-case UUID strings and small integers, never a
// name taken from a request, a database text column or a directory listing — and the directory
// listings this file produces are used for REPORTING and QUARANTINE decisions only: nothing in a
// listing is ever passed to a delete as a name (Remove* take ids, and enumerate their own directory
// against a closed set of expected file names, refusing anything else).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dirIncoming   = ".incoming"
	dirQuarantine = ".quarantine"
	manifestName  = "MANIFEST.json"
	// QuarantineGrace is how long a quarantined orphan is kept before it may be purged.
	QuarantineGrace = 14 * 24 * time.Hour
)

var (
	// ErrUnsafePath is returned for a symlink, junction, non-regular file, wrong-type component or a
	// cross-device component.
	ErrUnsafePath = errors.New("recording storage: unsafe path component (symlink, non-regular file or other filesystem)")
	// ErrUnexpectedEntry is returned when a recording directory holds something this layer never wrote.
	ErrUnexpectedEntry = errors.New("recording storage: unexpected entry in a recording directory; refusing to delete")

	segFileRe = regexp.MustCompile(`^[0-9]{4}\.(ivf|webm)\.enc$`)
	quarRe    = regexp.MustCompile(`^([0-9]{1,12})-(.+)$`)
)

// RecordingStorage is the filesystem layer. Create it with OpenRecordingStorage.
type RecordingStorage struct {
	root    *os.Root
	rootDir string
	rootDev uint64
	devOK   bool

	// TEST SEAMS (always nil in production), each called in exactly the window a test wants to attack.
	afterCheck   func(rel string)       // file: between the Lstat of a name and its open
	beforePin    func(rel string)       // directory component: between its Lstat and OpenRoot
	afterPin     func(rel string)       // after a directory was pinned, before anything is done through it
	beforeRemove func(rel string)       // before each unlink during a recording's deletion
	syncFail     func(rel string) error // injected directory-fsync failure ("" = the volume root)

	// dirtyDirs holds directories this process created whose PARENT sync failed: a later pin of the same
	// directory (which now simply exists) must redo that sync before it succeeds.
	dirtyMu   sync.Mutex
	dirtyDirs map[string]struct{}
}

// OpenRecordingStorage opens (creating if needed) the recordings volume directory and its two fixed
// subdirectories.
func OpenRecordingStorage(dir string) (*RecordingStorage, error) {
	if dir == "" {
		return nil, errors.New("recording storage directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	s := &RecordingStorage{root: root, rootDir: dir}
	if fi, err := root.Stat("."); err == nil {
		s.rootDev, s.devOK = devOf(fi)
	}
	for _, d := range []string{dirIncoming, dirQuarantine} {
		p, err := s.pin(true, d)
		if err != nil {
			root.Close()
			return nil, err
		}
		p.Close()
	}
	return s, nil
}

// Close releases the root handle.
func (s *RecordingStorage) Close() error { return s.root.Close() }

// Dir is the volume directory (for logs and tests).
func (s *RecordingStorage) Dir() string { return s.rootDir }

// ---- path derivation (ids only) ---------------------------------------------------------------

func segName(seg uint32, rep EnvRep) string { return fmt.Sprintf("%04d.%s.enc", seg, rep.ext()) }

func mustUUIDs(ids ...string) error {
	for _, id := range ids {
		if !recIsUUID(id) {
			return fmt.Errorf("recording storage: %q is not a canonical uuid", id)
		}
	}
	return nil
}

// ---- pinned directories -----------------------------------------------------------------------

func isPlainDir(fi fs.FileInfo) bool { return fi.Mode().Type() == fs.ModeDir }

func isPlainFile(fi fs.FileInfo) bool { return fi.Mode().Type() == 0 }

func validName(p string) bool {
	return p != "" && p != "." && p != ".." && !strings.ContainsAny(p, `/\:`)
}

func (s *RecordingStorage) devBad(fi fs.FileInfo) bool {
	if !s.devOK {
		return false
	}
	d, ok := devOf(fi)
	return ok && d != s.rootDev
}

func joinRel(parts []string) string { return strings.Join(parts, "/") }

// pinChild opens the plain directory `name` of an already-pinned parent as a pinned handle of its own.
// rel is the component's full relative path (diagnostics and test seams only). create makes a missing
// directory (0700).
func (s *RecordingStorage) pinChild(parent *os.Root, rel, name string, create bool) (*os.Root, error) {
	if !validName(name) {
		return nil, ErrUnsafePath
	}
	fi, err := parent.Lstat(name)
	if err != nil && create && errors.Is(err, fs.ErrNotExist) {
		if merr := parent.Mkdir(name, 0o700); merr != nil && !errors.Is(merr, fs.ErrExist) {
			return nil, merr
		}
		if serr := s.syncDir(parent, parentLabel(rel)); serr != nil {
			s.markDirty(rel) // created, but not yet durable: the next pin redoes the sync
			return nil, serr
		}
		fi, err = parent.Lstat(name)
	} else if err == nil && create && s.isDirty(rel) {
		// An earlier attempt made this directory and failed to sync its parent: redo it before succeeding.
		if serr := s.syncDir(parent, parentLabel(rel)); serr != nil {
			return nil, serr
		}
		s.clearDirty(rel)
	}
	if err != nil {
		return nil, err
	}
	if !isPlainDir(fi) || s.devBad(fi) {
		return nil, ErrUnsafePath
	}
	if s.beforePin != nil {
		s.beforePin(rel)
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrUnsafePath, err)
	}
	st, err := child.Stat(".")
	// The handle must be the directory the Lstat described: a link (or another directory) swapped in
	// between the two lands the handle elsewhere, and that is refused here.
	if err != nil || !isPlainDir(st) || !os.SameFile(fi, st) || s.devBad(st) {
		child.Close()
		return nil, ErrUnsafePath
	}
	return child, nil
}

func (s *RecordingStorage) markDirty(rel string) {
	s.dirtyMu.Lock()
	defer s.dirtyMu.Unlock()
	if s.dirtyDirs == nil {
		s.dirtyDirs = map[string]struct{}{}
	}
	s.dirtyDirs[rel] = struct{}{}
}

func (s *RecordingStorage) isDirty(rel string) bool {
	s.dirtyMu.Lock()
	defer s.dirtyMu.Unlock()
	_, ok := s.dirtyDirs[rel]
	return ok
}

func (s *RecordingStorage) clearDirty(rel string) {
	s.dirtyMu.Lock()
	defer s.dirtyMu.Unlock()
	delete(s.dirtyDirs, rel)
}

// syncPinnedIfPresent fsyncs the directory named by parts when it exists (a missing one has nothing to
// sync); every other failure is returned.
func (s *RecordingStorage) syncPinnedIfPresent(parts ...string) error {
	d, err := s.pin(false, parts...)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer d.Close()
	return s.syncDir(d, joinRel(parts))
}

// pin walks parts from the volume root, component by component, and returns a pinned handle on the last
// directory (the root itself for no parts). The caller must Close it.
func (s *RecordingStorage) pin(create bool, parts ...string) (*os.Root, error) {
	cur, err := s.root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	for i, p := range parts {
		next, err := s.pinChild(cur, joinRel(parts[:i+1]), p, create)
		cur.Close()
		if err != nil {
			return nil, err
		}
		cur = next
	}
	if s.afterPin != nil {
		s.afterPin(joinRel(parts))
	}
	return cur, nil
}

// syncDir fsyncs a pinned directory so a rename/create/unlink in it is durable. The failure is RETURNED:
// the caller must not claim the step done. Windows cannot fsync a directory handle, so there it is an
// explicit no-op (see the file comment); the injected failure of the test seam still applies there.
func (s *RecordingStorage) syncDir(r *os.Root, rel string) error {
	if s.syncFail != nil {
		if err := s.syncFail(rel); err != nil {
			return fmt.Errorf("recording storage: sync %q: %w", rel, err)
		}
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := r.Open(".")
	if err != nil {
		return fmt.Errorf("recording storage: sync %q: %w", rel, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("recording storage: sync %q: %w", rel, err)
	}
	return nil
}

// openIn opens an existing regular file `name` of a pinned directory, re-validating it against a fresh
// Lstat so a swap between check and open is caught.
func (s *RecordingStorage) openIn(dir *os.Root, rel, name string, flag int) (*os.File, fs.FileInfo, error) {
	if !validName(name) {
		return nil, nil, ErrUnsafePath
	}
	pre, err := dir.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !isPlainFile(pre) || s.devBad(pre) {
		return nil, nil, ErrUnsafePath
	}
	if s.afterCheck != nil {
		s.afterCheck(rel)
	}
	f, err := dir.OpenFile(name, flag, 0o600)
	if err != nil {
		// A name swapped for a link after the check fails to open (os.Root refuses a link that leaves the
		// pinned directory): say what happened rather than report an opaque path error.
		if post, lerr := dir.Lstat(name); lerr == nil && !isPlainFile(post) {
			return nil, nil, fmt.Errorf("%w: %v", ErrUnsafePath, err)
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	post, err := dir.Lstat(name)
	if err != nil || !isPlainFile(fi) || !isPlainFile(post) || !os.SameFile(fi, post) || !os.SameFile(fi, pre) || s.devBad(fi) {
		f.Close()
		return nil, nil, ErrUnsafePath
	}
	return f, fi, nil
}

// plainFileIn reports the state of a name in a pinned directory: nil error = a plain regular file,
// fs.ErrNotExist = absent, anything else = unsafe or unreadable.
func (s *RecordingStorage) plainFileIn(dir *os.Root, name string) (fs.FileInfo, error) {
	fi, err := dir.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !isPlainFile(fi) || s.devBad(fi) {
		return nil, ErrUnsafePath
	}
	return fi, nil
}

// ---- incoming (in-flight) files ---------------------------------------------------------------

// OpenIncoming opens (create=true: creates if absent) the in-flight envelope file of one segment of an
// upload. The returned file is positioned by the envelope writer (WriteAt); callers fsync it.
func (s *RecordingStorage) OpenIncoming(upload string, seg uint32, rep EnvRep, create bool) (*os.File, error) {
	if err := mustUUIDs(upload); err != nil {
		return nil, err
	}
	dir, err := s.pin(create, dirIncoming, upload)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	name := segName(seg, rep)
	rel := dirIncoming + "/" + upload + "/" + name
	if create {
		// Create exclusively when absent; otherwise open the existing (checked) file.
		if f, err := dir.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
			f.Close()
			if err := s.syncDir(dir, dirIncoming+"/"+upload); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	f, _, err := s.openIn(dir, rel, name, os.O_RDWR)
	return f, err
}

// OpenIncomingRead opens an in-flight file read-only.
func (s *RecordingStorage) OpenIncomingRead(upload string, seg uint32, rep EnvRep) (*os.File, int64, error) {
	if err := mustUUIDs(upload); err != nil {
		return nil, 0, err
	}
	dir, err := s.pin(false, dirIncoming, upload)
	if err != nil {
		return nil, 0, err
	}
	defer dir.Close()
	name := segName(seg, rep)
	f, fi, err := s.openIn(dir, dirIncoming+"/"+upload+"/"+name, name, os.O_RDONLY)
	if err != nil {
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// OpenFinal opens a finished envelope file read-only and returns its size.
func (s *RecordingStorage) OpenFinal(tenant, rec string, seg uint32, rep EnvRep) (*os.File, int64, error) {
	if err := mustUUIDs(tenant, rec); err != nil {
		return nil, 0, err
	}
	dir, err := s.pin(false, tenant, rec)
	if err != nil {
		return nil, 0, err
	}
	defer dir.Close()
	name := segName(seg, rep)
	f, fi, err := s.openIn(dir, tenant+"/"+rec+"/"+name, name, os.O_RDONLY)
	if err != nil {
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// moveEntry renames srcName of the pinned srcDir to dstName of the pinned dstDir and VERIFIES that what
// arrived is the entry that was inspected (ident). Linux: renameat(2) on the two directory descriptors, no
// path is resolved. Elsewhere: os.Root.Rename by volume-relative path, verified afterwards (see the file
// comment for what that does and does not prevent).
func (s *RecordingStorage) moveEntry(srcDir *os.Root, srcRel, srcName string, dstDir *os.Root, dstRel, dstName string, ident fs.FileInfo) error {
	if err := renameBetween(s, srcDir, srcRel, srcName, dstDir, dstRel, dstName); err != nil {
		return err
	}
	post, err := dstDir.Lstat(dstName)
	if err != nil || !os.SameFile(ident, post) {
		return fmt.Errorf("%w: %s did not arrive as the entry that was inspected", ErrUnsafePath, dstRel)
	}
	return nil
}

// Promote atomically moves an in-flight file to its final place (same filesystem, rename), fsyncing
// both directories. It is idempotent: when the source is gone and the destination is a valid regular
// file, the earlier attempt already did it.
func (s *RecordingStorage) Promote(upload, tenant, rec string, seg uint32, rep EnvRep) error {
	if err := mustUUIDs(upload, tenant, rec); err != nil {
		return err
	}
	name := segName(seg, rep)
	srcRel, dstRel := dirIncoming+"/"+upload, tenant+"/"+rec
	dstDir, err := s.pin(true, tenant, rec)
	if err != nil {
		return err
	}
	defer dstDir.Close()
	// An attempt that renamed but then failed a directory sync is retried and must NOT be acknowledged
	// without those syncs: every idempotent success below redoes them (the destination, its parents, and
	// the source side wherever it still exists).
	alreadyPromoted := func(src *os.Root) error {
		if err := s.syncPromoteSide(dstDir, tenant, rec); err != nil {
			return err
		}
		if src != nil {
			if err := s.syncDir(src, srcRel); err != nil {
				return err
			}
		}
		return s.syncPinnedIfPresent(dirIncoming)
	}
	srcDir, err := s.pin(false, dirIncoming, upload)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, derr := s.plainFileIn(dstDir, name); derr == nil {
				return alreadyPromoted(nil) // already promoted
			}
		}
		return err
	}
	defer srcDir.Close()
	ident, err := s.plainFileIn(srcDir, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, derr := s.plainFileIn(dstDir, name); derr == nil {
				return alreadyPromoted(srcDir) // already promoted
			}
		}
		return err
	}
	// A destination that exists must itself be a plain file (never rename over a link).
	if _, err := s.plainFileIn(dstDir, name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.moveEntry(srcDir, srcRel+"/"+name, name, dstDir, dstRel+"/"+name, name, ident); err != nil {
		return err
	}
	if err := s.syncPromoteSide(dstDir, tenant, rec); err != nil {
		return err
	}
	if err := s.syncDir(srcDir, srcRel); err != nil {
		return err
	}
	return s.syncPinnedIfPresent(dirIncoming)
}

// syncPromoteSide fsyncs the destination directory and the chain above it that Promote may have created
// (the tenant directory in the volume root), so a retry after a failed sync is durable before success.
func (s *RecordingStorage) syncPromoteSide(dstDir *os.Root, tenant, rec string) error {
	if err := s.syncDir(dstDir, tenant+"/"+rec); err != nil {
		return err
	}
	if err := s.syncPinnedIfPresent(tenant); err != nil {
		return err
	}
	return s.syncPinnedIfPresent()
}

// Unpromote is Promote's inverse for a recording whose evidence was never committed: it moves a final
// file back to the incoming area. Idempotent: a missing final file (never promoted, or already moved
// back) is success. The caller must only use it while the row is still 'uploading' and holds the
// recording's lock.
func (s *RecordingStorage) Unpromote(upload, tenant, rec string, seg uint32, rep EnvRep) error {
	if err := mustUUIDs(upload, tenant, rec); err != nil {
		return err
	}
	name := segName(seg, rep)
	srcRel, dstRel := tenant+"/"+rec, dirIncoming+"/"+upload
	// "Nothing to move back" is success only after the syncs of an earlier, possibly half-synced move.
	moved := func(src *os.Root) error {
		if src != nil {
			if err := s.syncDir(src, srcRel); err != nil {
				return err
			}
		}
		if err := s.syncPinnedIfPresent(tenant); err != nil {
			return err
		}
		if err := s.syncPinnedIfPresent(dirIncoming, upload); err != nil {
			return err
		}
		return s.syncPinnedIfPresent(dirIncoming)
	}
	srcDir, err := s.pin(false, tenant, rec)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return moved(nil)
		}
		return err
	}
	defer srcDir.Close()
	ident, err := s.plainFileIn(srcDir, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return moved(srcDir)
		}
		return err
	}
	dstDir, err := s.pin(true, dirIncoming, upload)
	if err != nil {
		return err
	}
	defer dstDir.Close()
	if _, err := s.plainFileIn(dstDir, name); err == nil {
		return nil // both exist: leave the incoming copy authoritative and do not overwrite it
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.moveEntry(srcDir, srcRel+"/"+name, name, dstDir, dstRel+"/"+name, name, ident); err != nil {
		return err
	}
	if err := s.syncDir(dstDir, dstRel); err != nil {
		return err
	}
	return s.syncDir(srcDir, srcRel)
}

// FinalExists reports whether the finished file exists as a plain file.
func (s *RecordingStorage) FinalExists(tenant, rec string, seg uint32, rep EnvRep) bool {
	if mustUUIDs(tenant, rec) != nil {
		return false
	}
	dir, err := s.pin(false, tenant, rec)
	if err != nil {
		return false
	}
	defer dir.Close()
	_, err = s.plainFileIn(dir, segName(seg, rep))
	return err == nil
}

// ErrSegmentEmpty: a segment file exists but has no bytes. An envelope is never empty (it carries a header),
// so this is damage or a truncated restore, not a lost file.
var ErrSegmentEmpty = errors.New("recording segment file exists but is empty")

// MissingFinal counts how many of a finished recording's n segment files of one representation are ABSENT
// (the restore reconciliation, docs/63 C11). Absent means exactly fs.ErrNotExist: a directory or file that
// cannot be inspected for any OTHER reason (permissions, a link, not a regular file, another filesystem) or
// that exists but is EMPTY (ErrSegmentEmpty) is an ERROR, never a count, so an unreadable or damaged volume
// can never be mistaken for a lost one, and a zero-byte file is never "restored" as if the evidence had come
// back. Beyond that, presence is judged by name and type only; the bytes are verified by the finish/playback
// paths that wrote them, not here.
func (s *RecordingStorage) MissingFinal(tenant, rec string, n int, rep EnvRep) (int, error) {
	if err := mustUUIDs(tenant, rec); err != nil {
		return 0, err
	}
	dir, err := s.pin(false, tenant, rec)
	if errors.Is(err, fs.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	missing := 0
	for i := 0; i < n; i++ {
		fi, err := s.plainFileIn(dir, segName(uint32(i), rep))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			missing++
		case err != nil:
			return 0, err
		case fi.Size() == 0:
			return 0, ErrSegmentEmpty // present but empty: damaged, not absent (see above)
		}
	}
	return missing, nil
}

// ---- deletion (by id, against a closed set of names) ------------------------------------------

type dirEntry struct {
	name string
	info fs.FileInfo
}

// readDirPinned lists a pinned directory, Lstat()ing every entry through the handle.
func readDirPinned(dir *os.Root) ([]dirEntry, error) {
	d, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]dirEntry, 0, len(names))
	for _, n := range names {
		fi, err := dir.Lstat(n)
		if err != nil {
			return nil, err
		}
		out = append(out, dirEntry{n, fi})
	}
	return out, nil
}

// removeDirOfSegments deletes the directory named by parts, which must contain ONLY regular files named
// like segment files (plus allowExtra). Anything else — a symlink, a subdirectory, an odd name — aborts
// BEFORE any deletion, so a surprise is reported and nothing is touched. Every unlink goes through the
// pinned directory handle, so a path swapped after the pin cannot redirect a delete; the directory entry
// itself is removed only if the parent still names the pinned directory. The parent's fsync is REQUIRED
// and its failure is returned (the caller keeps the deletion pending); it is also repeated when the
// directory is already gone, so a retry makes an earlier unsynced removal durable.
func (s *RecordingStorage) removeDirOfSegments(parts []string, allowExtra string) (int, error) {
	parentParts, name := parts[:len(parts)-1], parts[len(parts)-1]
	rel := joinRel(parts)
	parent, err := s.pin(false, parentParts...)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil // no parent directory: nothing was ever here
	}
	if err != nil {
		return 0, err
	}
	defer parent.Close()
	parentRel := joinRel(parentParts)
	dir, err := s.pinChild(parent, rel, name, false)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, s.syncDir(parent, parentRel) // idempotent, and durable
	}
	if err != nil {
		return 0, err
	}
	closed := false
	defer func() {
		if !closed {
			dir.Close()
		}
	}()
	if s.afterPin != nil {
		s.afterPin(rel)
	}
	ents, err := readDirPinned(dir)
	if err != nil {
		return 0, err
	}
	for _, e := range ents {
		if !isPlainFile(e.info) || !(segFileRe.MatchString(e.name) || (allowExtra != "" && e.name == allowExtra)) {
			return 0, fmt.Errorf("%w: %s/%s", ErrUnexpectedEntry, rel, e.name)
		}
	}
	n := 0
	for _, e := range ents {
		if s.beforeRemove != nil {
			s.beforeRemove(rel + "/" + e.name)
		}
		if err := dir.Remove(e.name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return n, err
		}
		n++
	}
	// Remove the (now empty) directory only if the parent still names the directory we emptied.
	dstat, err := dir.Stat(".")
	if err != nil {
		return n, err
	}
	cur, err := parent.Lstat(name)
	if err != nil || !os.SameFile(dstat, cur) {
		return n, fmt.Errorf("%w: %s was replaced while it was being deleted", ErrUnsafePath, rel)
	}
	dir.Close() // an open handle would keep a directory from being removed on Windows
	closed = true
	if err := parent.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return n, err
	}
	return n, s.syncDir(parent, parentRel)
}

// RemoveRecording deletes a recording's directory (idempotent: absent is success). The tenant
// directory is left in place (removing it would race with a concurrent create).
func (s *RecordingStorage) RemoveRecording(tenant, rec string) (int, error) {
	if err := mustUUIDs(tenant, rec); err != nil {
		return 0, err
	}
	return s.removeDirOfSegments([]string{tenant, rec}, "")
}

// RemoveIncoming deletes an upload's in-flight directory (idempotent).
func (s *RecordingStorage) RemoveIncoming(upload string) (int, error) {
	if err := mustUUIDs(upload); err != nil {
		return 0, err
	}
	return s.removeDirOfSegments([]string{dirIncoming, upload}, "")
}

// ---- listing (reporting and quarantine decisions only) ----------------------------------------

// Listing is the result of walking one level of the volume by NAME.
type Listing struct {
	IDs     []string // canonical-uuid-named plain directories
	Skipped []string // anything else (non-uuid name, file, symlink, dotfile…), reported, never touched
}

func (s *RecordingStorage) listUUIDDirs(parts ...string) (Listing, error) {
	var l Listing
	dir, err := s.pin(false, parts...)
	if err != nil {
		return l, err
	}
	defer dir.Close()
	ents, err := readDirPinned(dir)
	if err != nil {
		return l, err
	}
	rel := joinRel(parts)
	for _, e := range ents {
		full := e.name
		if rel != "" {
			full = rel + "/" + e.name
		}
		if rel == "" && (e.name == dirIncoming || e.name == dirQuarantine) {
			continue
		}
		if !recIsUUID(e.name) || !isPlainDir(e.info) {
			l.Skipped = append(l.Skipped, full)
			continue
		}
		l.IDs = append(l.IDs, e.name)
	}
	return l, nil
}

// ListTenantDirs lists tenant directories at the top of the volume.
func (s *RecordingStorage) ListTenantDirs() (Listing, error) { return s.listUUIDDirs() }

// ListRecordingDirs lists the recording directories of one tenant.
func (s *RecordingStorage) ListRecordingDirs(tenant string) (Listing, error) {
	if err := mustUUIDs(tenant); err != nil {
		return Listing{}, err
	}
	return s.listUUIDDirs(tenant)
}

// ListIncomingDirs lists in-flight upload directories.
func (s *RecordingStorage) ListIncomingDirs() (Listing, error) { return s.listUUIDDirs(dirIncoming) }

func (s *RecordingStorage) dirModTime(parts ...string) (time.Time, error) {
	dir, err := s.pin(false, parts...)
	if err != nil {
		return time.Time{}, err
	}
	defer dir.Close()
	fi, err := dir.Stat(".")
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

// RecordingDirModTime returns a recording directory's modification time (very young directories are
// left alone by the orphan pass).
func (s *RecordingStorage) RecordingDirModTime(tenant, rec string) (time.Time, error) {
	if err := mustUUIDs(tenant, rec); err != nil {
		return time.Time{}, err
	}
	return s.dirModTime(tenant, rec)
}

// IncomingDirModTime is RecordingDirModTime for an in-flight directory.
func (s *RecordingStorage) IncomingDirModTime(upload string) (time.Time, error) {
	if err := mustUUIDs(upload); err != nil {
		return time.Time{}, err
	}
	return s.dirModTime(dirIncoming, upload)
}

// ---- quarantine -------------------------------------------------------------------------------

type quarantineManifest struct {
	Reason        string           `json:"reason"`
	QuarantinedAt time.Time        `json:"quarantined_at"`
	Origin        string           `json:"origin"`
	Files         []quarantineFile `json:"files"`
}

type quarantineFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// quarantine moves the directory named by srcParts into .quarantine and writes its manifest THROUGH THE
// MOVED DIRECTORY'S OWN HANDLE. Required durability: the manifest file, the quarantine entry (which holds
// it), the quarantine directory and the source's parent are all fsynced, and any failure is returned —
// after the rename the entry exists (and is never deleted before its grace), but the caller is told the
// step did not complete.
func (s *RecordingStorage) quarantine(srcParts []string, label, reason string, now time.Time) (string, error) {
	srcRel := joinRel(srcParts)
	srcName := srcParts[len(srcParts)-1]
	parentParts := srcParts[:len(srcParts)-1]
	src, err := s.pin(false, srcParts...)
	if err != nil {
		return "", err
	}
	srcOpen := true
	defer func() {
		if srcOpen {
			src.Close()
		}
	}()
	ents, err := readDirPinned(src)
	if err != nil {
		return "", err
	}
	man := quarantineManifest{Reason: reason, QuarantinedAt: now.UTC(), Origin: srcRel}
	for _, e := range ents {
		// A plain file is recorded; anything else (a link, a subdirectory) is a reason to leave the
		// directory exactly where it is and report.
		if !isPlainFile(e.info) {
			return "", fmt.Errorf("%w: %s/%s", ErrUnexpectedEntry, srcRel, e.name)
		}
		man.Files = append(man.Files, quarantineFile{e.name, e.info.Size()})
	}
	ident, err := src.Stat(".")
	if err != nil {
		return "", err
	}
	parent, err := s.pin(false, parentParts...)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if cur, err := parent.Lstat(srcName); err != nil || !os.SameFile(ident, cur) {
		return "", fmt.Errorf("%w: %s was replaced before it could be quarantined", ErrUnsafePath, srcRel)
	}
	qdir, err := s.pin(false, dirQuarantine)
	if err != nil {
		return "", err
	}
	defer qdir.Close()
	name := strconv.FormatInt(now.Unix(), 10) + "-" + label
	dstName := name
	for i := 1; ; i++ {
		if _, err := qdir.Lstat(dstName); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if i > 50 {
			return "", errors.New("recording storage: quarantine name collision")
		}
		dstName = name + "-" + strconv.Itoa(i)
	}
	src.Close() // a directory with an open handle cannot be renamed on Windows; it is re-pinned below
	srcOpen = false
	dstRel := dirQuarantine + "/" + dstName
	if err := s.moveEntry(parent, srcRel, srcName, qdir, dstRel, dstName, ident); err != nil {
		return "", err
	}
	entry, err := s.pinChild(qdir, dstRel, dstName, false)
	if err != nil {
		return dstName, err
	}
	defer entry.Close()
	if st, err := entry.Stat("."); err != nil || !os.SameFile(ident, st) {
		return dstName, fmt.Errorf("%w: %s is not the directory that was moved", ErrUnsafePath, dstRel)
	}
	b, _ := json.MarshalIndent(man, "", "  ")
	f, err := entry.OpenFile(manifestName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return dstName, err
	}
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		return dstName, errors.Join(werr, serr, cerr)
	}
	// The entry (its new manifest name), the quarantine directory (the entry's name) and the old parent
	// (the removed name) must all be durable before this reports success.
	if err := s.syncDir(entry, dstRel); err != nil {
		return dstName, err
	}
	if err := s.syncDir(qdir, dirQuarantine); err != nil {
		return dstName, err
	}
	return dstName, s.syncDir(parent, joinRel(parentParts))
}

// QuarantineRecording moves a recording directory into .quarantine with a manifest. It NEVER deletes.
func (s *RecordingStorage) QuarantineRecording(tenant, rec, reason string, now time.Time) (string, error) {
	if err := mustUUIDs(tenant, rec); err != nil {
		return "", err
	}
	return s.quarantine([]string{tenant, rec}, tenant+"-"+rec, reason, now)
}

// QuarantineIncoming moves an in-flight directory into .quarantine with a manifest.
func (s *RecordingStorage) QuarantineIncoming(upload, reason string, now time.Time) (string, error) {
	if err := mustUUIDs(upload); err != nil {
		return "", err
	}
	return s.quarantine([]string{dirIncoming, upload}, "incoming-"+upload, reason, now)
}

// QuarantineEntry is one entry under .quarantine.
type QuarantineEntry struct {
	Name string
	At   time.Time
}

// ListQuarantine lists well-formed quarantine entries; other names are reported in the second result.
func (s *RecordingStorage) ListQuarantine() ([]QuarantineEntry, []string, error) {
	q, err := s.pin(false, dirQuarantine)
	if err != nil {
		return nil, nil, err
	}
	defer q.Close()
	ents, err := readDirPinned(q)
	if err != nil {
		return nil, nil, err
	}
	var out []QuarantineEntry
	var skipped []string
	for _, e := range ents {
		m := quarRe.FindStringSubmatch(e.name)
		if m == nil || !isPlainDir(e.info) {
			skipped = append(skipped, dirQuarantine+"/"+e.name)
			continue
		}
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		out = append(out, QuarantineEntry{Name: e.name, At: time.Unix(sec, 0)})
	}
	return out, skipped, nil
}

// PurgeQuarantine removes quarantine entries older than the grace period — the ONLY place an orphan is
// ever deleted, and only after QuarantineGrace. Each entry is a directory this layer created (a
// well-formed name, a manifest, plain segment files); anything else is skipped and reported.
func (s *RecordingStorage) PurgeQuarantine(now time.Time, grace time.Duration) (purged int, skipped []string, err error) {
	entries, sk, err := s.ListQuarantine()
	if err != nil {
		return 0, sk, err
	}
	skipped = sk
	for _, e := range entries {
		if now.Sub(e.At) < grace {
			continue
		}
		rel := dirQuarantine + "/" + e.Name
		hasManifest := func() bool {
			d, perr := s.pin(false, dirQuarantine, e.Name)
			if perr != nil {
				return false
			}
			defer d.Close()
			_, merr := s.plainFileIn(d, manifestName)
			return merr == nil
		}()
		if !hasManifest {
			skipped = append(skipped, rel)
			continue
		}
		if _, rerr := s.removeDirOfSegments([]string{dirQuarantine, e.Name}, manifestName); rerr != nil {
			skipped = append(skipped, rel)
			continue
		}
		purged++
	}
	return purged, skipped, nil
}

// parentLabel is the syncDir label of rel's parent ("" = the volume root).
func parentLabel(rel string) string {
	if d := path.Dir(rel); d != "." {
		return d
	}
	return ""
}

func finalDirRel(tenant, rec string) string { return tenant + "/" + rec }

func finalFileRel(tenant, rec string, seg uint32, rep EnvRep) string {
	return finalDirRel(tenant, rec) + "/" + segName(seg, rep)
}

func incomingDirRel(upload string) string { return dirIncoming + "/" + upload }

func incomingFileRel(upload string, seg uint32, rep EnvRep) string {
	return incomingDirRel(upload) + "/" + segName(seg, rep)
}
