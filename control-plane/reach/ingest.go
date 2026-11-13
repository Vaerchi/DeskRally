package reach

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var errFailedCommit = errors.New("reach: commit failed")

// SizeFunc returns the current size of a human artifact (its path under /download/), or ok=false when it is
// not known. Completed downloads are counted only when it is: otherwise the figure is stored as NULL
// ("unknown"), never as 0 (docs/68 section 3).
type SizeFunc func(artifact string) (size int64, ok bool)

// DirSizes reads artifact sizes from a read-only mount of the artifact directory Caddy serves /download/ from.
// The request URI is never used as a path. What IS used is the artifact NAME that Classify produced from a
// fixed regex (letters, digits, dots, hyphens and slashes in a fixed shape; no "..", no escape, no absolute
// form), joined under the one fixed directory the operator configured (REACH_ARTIFACT_DIR) and stat'ed
// read-only. The checks below are a second fence: the name must be a local, forward-slash relative path
// (filepath.IsLocal), and the joined result is verified to stay inside dir. The size is the file's size NOW:
// a log line about an older, differently sized build of the same name is judged against the current one (the
// caveat the report prints).
func DirSizes(dir string) SizeFunc {
	if dir == "" {
		return func(string) (int64, bool) { return 0, false }
	}
	return func(artifact string) (int64, bool) {
		p, ok := artifactPath(dir, artifact)
		if !ok {
			return 0, false
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return 0, false
		}
		return fi.Size(), true
	}
}

// artifactPath joins a validated artifact name under dir, or refuses. It never returns a path outside dir.
func artifactPath(dir, artifact string) (string, bool) {
	if artifact == "" || strings.ContainsAny(artifact, "\\:\x00") || strings.Contains(artifact, "..") ||
		path.IsAbs(artifact) || strings.HasPrefix(artifact, "/") || strings.Contains(artifact, "//") {
		return "", false
	}
	local := filepath.FromSlash(artifact)
	if !filepath.IsLocal(local) {
		return "", false
	}
	p := filepath.Join(dir, local)
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return p, true
}

// Config wires one Ingester.
type Config struct {
	Dir      string // the log directory (Caddy's /data), mounted read-only
	LogName  string // "access.log"
	Sizes    SizeFunc
	SaltFile SaltFile
	Store    Store
	Now      func() time.Time
	Logf     func(format string, args ...any)

	// CommitEvery is how many lines one transaction covers (default 20000). MaxUniq caps one day's client
	// set per artifact (default 500000 = 16 MiB of hashes); past it the figure is a flagged lower bound.
	CommitEvery int
	MaxUniq     int
	// Process-wide bounds on the unique-ish machinery, because artifact names are attacker-influenced (a
	// versioned name per request): MaxTotalUniq caps the client hashes held across ALL artifacts (default
	// 2,000,000 is about 150 MB of Go map entries), MaxArtifacts caps the artifacts that get a client set and the artifact-size cache
	// (default 256). Past either, the affected rows are flagged partial; request counts are never dropped.
	MaxTotalUniq int
	MaxArtifacts int
	// Work budgets (decompressed bytes): per segment (default 512 MiB; Caddy rolls at 20 MiB) and per pass
	// (default 2 GiB). A segment past its cap is given up on (logged by name, counted in Stats.Capped, cursor
	// set so it is never re-read); a pass past its budget stops cleanly and resumes next pass.
	MaxSegmentBytes int64
	MaxPassBytes    int64
	MaxSkipBytes    int64 // re-read budget for already-counted prefixes per pass (default 8 GiB)
	// Retention is how long daily rows are kept (default 25 months); StaleCursor how long an unseen
	// segment's cursor is kept (default 60 days).
	RetentionMonths int
	StaleCursor     time.Duration
}

// Stats is what one run saw. It carries counts only.
type Stats struct {
	Segments, Lines, Malformed, Oversize int
	ReadErrors                           int  // segments whose read stopped on a real error, not a clean end
	Capped                               int  // segments given up on for exceeding MaxSegmentBytes
	Skipped                              int  // rolled segments already read to their end (cursor complete): not opened
	BudgetStopped                        bool // the pass stopped early on MaxPassBytes
	Counted                              map[Class]int64
}

type aggKey struct {
	day, artifact string
	class         Class
}

// Ingester turns the log into daily aggregates. One instance lives for the process: it keeps the unique-ish
// client sets in memory between runs, which is why the job is a long-running loop and not a cron one-shot (a
// one-shot would have to throw the sets away every hour and could never report a daily figure).
type Ingester struct {
	cfg  Config
	salt Salt
	// sets: client hashes for the CURRENT salt's day, per artifact. Dropped when the salt rotates.
	sets map[string]map[[32]byte]struct{}
	// partialDays: days whose unique-ish figure is a lower bound because this process did not see the whole
	// day from its start (it was started mid-day, or the salt file was missing).
	partialDays map[string]bool
	sizeCache   map[string]sizeEntry
	totalHashes int // client hashes held across all of sets

	// Salt hygiene. diskStale: the file may still hold a key that is expired (or not the current one) and
	// could not be overwritten or removed; rotationFailed: the new day's key could not be made. While either
	// holds the ingest fails CLOSED: no unique-ish counting at all (rows partial), loud log, retried each pass.
	diskStale      bool
	rotationFailed bool

	passLeft int64
	skipLeft int64
	// beforeOpen is a test seam: called after discovery and before a discovered segment is opened.
	beforeOpen func(Segment)
}

type sizeEntry struct {
	size int64
	ok   bool
}

// New loads (or creates) the salt. A missing, unreadable or malformed salt file means a NEW salt for today and
// today marked partial; a good one is reloaded, and its day is marked partial too, because the in-memory client
// set of a day that was already running was lost with the previous process.
func New(cfg Config) (*Ingester, error) {
	if cfg.Store == nil || cfg.Dir == "" {
		return nil, errors.New("reach: Store and Dir are required")
	}
	if cfg.LogName == "" {
		cfg.LogName = "access.log"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Sizes == nil {
		cfg.Sizes = func(string) (int64, bool) { return 0, false }
	}
	if cfg.CommitEvery <= 0 {
		cfg.CommitEvery = 20000
	}
	if cfg.MaxUniq <= 0 {
		cfg.MaxUniq = 500000
	}
	if cfg.MaxTotalUniq <= 0 {
		cfg.MaxTotalUniq = 2_000_000
	}
	if cfg.MaxArtifacts <= 0 {
		cfg.MaxArtifacts = 256
	}
	if cfg.MaxSegmentBytes <= 0 {
		cfg.MaxSegmentBytes = DefaultMaxSegmentBytes
	}
	if cfg.MaxPassBytes <= 0 {
		cfg.MaxPassBytes = DefaultMaxPassBytes
	}
	if cfg.MaxSkipBytes <= 0 {
		cfg.MaxSkipBytes = 8 << 30
	}
	if cfg.RetentionMonths <= 0 {
		cfg.RetentionMonths = 25
	}
	if cfg.StaleCursor <= 0 {
		cfg.StaleCursor = 60 * 24 * time.Hour
	}
	in := &Ingester{cfg: cfg, sets: map[string]map[[32]byte]struct{}{}, partialDays: map[string]bool{}, sizeCache: map[string]sizeEntry{}}
	today := DayString(cfg.Now())
	if s, ok := cfg.SaltFile.Load(); ok {
		in.salt = s
		if s.Day < today {
			// A key left from an earlier day: it must not outlive its day because the process was down.
			in.rotateTo(today)
		}
	} else {
		s, err := newSalt(today)
		if err != nil {
			return nil, err
		}
		in.salt = s
		in.persistSalt()
	}
	in.partialDays[in.salt.Day] = true
	return in, nil
}

// SaltDay is the UTC day of the salt in use (for tests and the startup log line).
func (in *Ingester) SaltDay() string { return in.salt.Day }

// failClosed: no unique-ish counting while an expired key cannot be removed from disk or no current key exists.
func (in *Ingester) failClosed() bool { return in.diskStale || in.rotationFailed }

// persistSalt writes the current key to the salt file. When it cannot, it tries to ERASE the file instead (an
// old key must not stay behind). If the file may still hold a key it cannot remove, the ingest fails closed
// (diskStale) and the next pass retries; a failure with nothing on disk is only a warning (a restart then
// marks the day partial).
func (in *Ingester) persistSalt() {
	err := in.cfg.SaltFile.Store(in.salt)
	if err == nil {
		in.diskStale = false
		return
	}
	if eerr := in.cfg.SaltFile.Erase(); eerr == nil {
		in.diskStale = false
		in.cfg.Logf("reach: salt file not written (%v); removed it instead, a restart will mark the day partial", err)
		return
	}
	if !in.cfg.SaltFile.Exists() {
		in.diskStale = false
		in.cfg.Logf("reach: salt file not written (%v); a restart will mark the day partial", err)
		return
	}
	in.diskStale = true
	in.cfg.Logf("reach: SALT FILE CANNOT BE OVERWRITTEN OR REMOVED (%v): an expired key may remain on disk; unique-ish counting is OFF (rows partial) until it can be, retried every pass", err)
}

// rotateTo makes day the salt's day: a fresh key, the previous one overwritten (or erased) on disk, the old
// day's client sets dropped, so nothing that remains can link the two days.
func (in *Ingester) rotateTo(day string) {
	in.sets = map[string]map[[32]byte]struct{}{}
	in.totalHashes = 0
	for d := range in.partialDays {
		if d < day {
			delete(in.partialDays, d)
		}
	}
	old := in.salt.Day
	in.salt.Key = [32]byte{} // best effort: the old day's key does not linger in memory (the GC alone would not clear it)
	s, err := newSalt(day)
	if err != nil {
		in.rotationFailed = true
		in.salt = Salt{Day: old}
		in.cfg.Logf("reach: SALT ROTATION FAILED (%v): unique-ish counting is OFF (rows partial) until a new key can be made, retried every pass", err)
		if eerr := in.cfg.SaltFile.Erase(); eerr != nil && in.cfg.SaltFile.Exists() {
			in.diskStale = true
			in.cfg.Logf("reach: the previous salt file could not be removed either (%v)", eerr)
		} else {
			in.diskStale = false
		}
		return
	}
	in.rotationFailed = false
	in.salt = s
	in.persistSalt()
}

// settleSalt runs at the start of every pass: it retries whatever a failed rotation or erasure left undone.
func (in *Ingester) settleSalt(today string) {
	switch {
	case in.rotationFailed:
		in.rotateTo(today)
	case in.diskStale:
		in.persistSalt()
	}
}

func (in *Ingester) artifactSize(artifact string) (int64, bool) {
	if e, ok := in.sizeCache[artifact]; ok {
		return e.size, e.ok
	}
	if len(in.sizeCache) >= in.cfg.MaxArtifacts {
		return 0, false // bounded work and memory: past the bound the size is "unknown" (completed stays NULL)
	}
	sz, ok := in.cfg.Sizes(artifact)
	in.sizeCache[artifact] = sizeEntry{sz, ok}
	return sz, ok
}

// observe folds one parsed line into the batch.
func (in *Ingester) observe(aggs map[aggKey]*Agg, e Entry, today string) Class {
	day := DayString(e.TS)
	res := Classify(e.Method, e.URI, e.Status)
	k := aggKey{day, res.Artifact, res.Class}
	a := aggs[k]
	if a == nil {
		a = &Agg{Day: day, Artifact: res.Artifact, Class: res.Class, Uniq: -1}
		aggs[k] = a
	}
	a.Requests++
	a.Bytes += e.Size
	if res.Class != ClassHuman {
		return res.Class
	}
	sz, sizeOK := in.artifactSize(res.Artifact)
	if complete, known := Completed(e.Status, e.Size, sz, sizeOK); known {
		a.CompletedKnown = true
		if complete {
			a.Completed++
		}
	}
	// Unique-ish. The line's day must be the salt's day. A newer day (not in the future) rotates the salt
	// in step with the DATA, so the first lines after midnight are covered even when the run that reads them
	// is hours later; an older day has no salt any more and its figure stays a lower bound.
	if e.IP == "" {
		a.Partial = true
		return ClassHuman
	}
	// FAIL CLOSED: while an expired key cannot be erased from disk (or no current key exists) nothing is hashed.
	if !in.failClosed() && day > in.salt.Day && day <= today {
		in.rotateTo(day)
	}
	if in.failClosed() || day != in.salt.Day {
		a.Partial = true
		return ClassHuman
	}
	set := in.sets[res.Artifact]
	if set == nil {
		if len(in.sets) >= in.cfg.MaxArtifacts { // many versioned names: no new set, the row is a flagged lower bound
			a.Partial = true
			return ClassHuman
		}
		set = map[[32]byte]struct{}{}
		in.sets[res.Artifact] = set
	}
	h := in.salt.ClientHash(e.IP, e.UA)
	if _, seen := set[h]; !seen {
		if len(set) >= in.cfg.MaxUniq || in.totalHashes >= in.cfg.MaxTotalUniq {
			a.Partial = true
		} else {
			set[h] = struct{}{}
			in.totalHashes++
		}
	}
	a.Uniq = int64(len(set))
	if in.partialDays[day] {
		a.Partial = true
	}
	return ClassHuman
}

func flush(aggs map[aggKey]*Agg) []Agg {
	out := make([]Agg, 0, len(aggs))
	for _, a := range aggs {
		out = append(out, *a)
	}
	return out
}

// RunOnce reads every segment from its cursor, commits the aggregates, rotates the salt if the UTC day has
// changed, and prunes. It stops at the first store error: the next run re-reads from the last committed cursor.
// The salt's expiry does NOT depend on the pass succeeding: rotation (and the retry of a failed erasure) runs
// however the pass ends.
func (in *Ingester) RunOnce(ctx context.Context) (Stats, error) {
	st := Stats{Counted: map[Class]int64{}}
	in.sizeCache = map[string]sizeEntry{}
	in.passLeft = in.cfg.MaxPassBytes
	in.skipLeft = in.cfg.MaxSkipBytes
	now := in.cfg.Now().UTC()
	today := DayString(now)
	in.settleSalt(today)
	defer func() {
		if today > in.salt.Day || in.rotationFailed {
			in.rotateTo(today)
		} else if in.diskStale {
			in.persistSalt()
		}
	}()

	segs, err := ListSegments(ctx, in.cfg.Dir, in.cfg.LogName)
	if err != nil {
		return st, err
	}
	cursors, err := in.cfg.Store.Cursors(ctx)
	if err != nil {
		return st, err
	}
	var seen []string
	done := map[string]bool{} // ids consumed this pass: one segment is never read twice in a pass
	for _, seg := range segs {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		seen = append(seen, seg.ID)
		if in.passLeft <= 0 {
			st.BudgetStopped = true
			continue // still listed in seen: its cursor is not pruned
		}
		if cursors[seg.ID].Complete {
			// Read to its end in an earlier pass (or given up on at the cap): not opened, not re-read, no
			// budget spent. Progress to the newer segments is therefore guaranteed however much history exists.
			st.Skipped++
			continue
		}
		if in.beforeOpen != nil {
			in.beforeOpen(seg)
		}
		id, err := in.readSegment(ctx, seg, cursors, done, today, &st)
		if id != "" && id != seg.ID {
			seen = append(seen, id)
		}
		if err != nil {
			return st, err
		}
	}
	if st.BudgetStopped {
		in.cfg.Logf("reach: pass stopped on the %d-byte budget; the rest resumes next pass", in.cfg.MaxPassBytes)
	}
	keepFrom := DayString(now.AddDate(0, -in.cfg.RetentionMonths, 0))
	if err := in.cfg.Store.Prune(ctx, keepFrom, seen, now.Add(-in.cfg.StaleCursor)); err != nil {
		return st, err
	}
	return st, nil
}

// readSegment opens the listed candidate ONCE, takes its identity from that very handle, looks the cursor up
// by THAT identity and reads the same handle. If Caddy rolled the file between discovery and now, the
// handle is whatever the path names at this instant, and it is judged and counted as exactly that file (its own
// id, its own cursor); the file that was rolled away is found again, under its new name, by the next pass.
// It returns the id actually read ("" when nothing was).
func (in *Ingester) readSegment(ctx context.Context, seg Segment, cursors map[string]Cursor, done map[string]bool, today string, st *Stats) (string, error) {
	lim := &limits{ctx: ctx, segLeft: in.cfg.MaxSegmentBytes, passLeft: &in.passLeft, skipLeft: &in.skipLeft}
	o, err := seg.openIdentified(ctx, lim)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return "", cerr
		}
		if errors.Is(err, errPassBudget) {
			st.BudgetStopped = true
			return "", nil
		}
		in.cfg.Logf("reach: skip %s: %v", seg.Name, err) // vanished, renamed or compressed since discovery: next pass
		return "", nil
	}
	defer o.Close()
	if !o.Ready {
		return "", nil // empty or still being written (for instance a fresh file after a roll)
	}
	id := o.ID
	if done[id] {
		return id, nil
	}
	done[id] = true
	st.Segments++
	cur := cursors[id]
	if cur.Complete { // the handle turned out to be a finished segment (a roll since discovery)
		st.Skipped++
		return id, nil
	}

	offset := cur.Offset
	o.limited.skipping = false
	if offset >= in.cfg.MaxSegmentBytes {
		// Given up on in an earlier pass (see below): never re-read.
		st.Capped++
		in.cfg.Logf("reach: %s is over the %d-byte segment cap and was already given up on", seg.Name, in.cfg.MaxSegmentBytes)
		return id, nil
	}
	if offset > 0 && o.zr == nil {
		// An uncompressed segment is SEEKED to its cursor: the counted prefix costs nothing. (Shorter than its
		// cursor cannot happen to a real Caddy file; if it does, resume from its end rather than recount.)
		n, serr := o.seekTo(offset)
		if serr != nil {
			in.cfg.Logf("reach: skip %s: %v", seg.Name, serr)
			return id, nil
		}
		if n < offset {
			in.cfg.Logf("reach: %s is shorter (%d) than its cursor (%d); resuming at its end", seg.Name, n, offset)
		}
		offset = n
		o.limited.segLeft = in.cfg.MaxSegmentBytes - offset
	} else if offset > 0 {
		// A gzip cannot seek: skip what is already counted (ctx and budget are checked inside every read).
		o.limited.skipping = true
		n, cerr := io.CopyN(io.Discard, o.br, offset)
		o.limited.skipping = false
		if cerr != nil {
			if ctx.Err() != nil {
				return id, ctx.Err()
			}
			if errors.Is(cerr, errPassBudget) {
				st.BudgetStopped = true
				return id, nil
			}
			in.cfg.Logf("reach: %s is shorter (%d) than its cursor (%d); resuming at its end", seg.Name, n, offset)
			offset = n
		}
	}
	lr := newLineReader(o.br, offset)
	aggs := map[aggKey]*Agg{}
	lines := 0
	atEOF, corrupt := false, false
	commitAt := func(off int64, complete bool) error {
		if len(aggs) == 0 && off == cur.Offset && !(complete && !cur.Complete) {
			return nil // nothing new: leave the cursor row untouched
		}
		b := Batch{Aggs: flush(aggs), Cursor: Cursor{FileID: id, Name: seg.Name, Offset: off, Complete: complete}}
		if err := in.cfg.Store.Commit(ctx, b); err != nil {
			return err
		}
		cur.Offset = off
		cur.Complete = complete
		aggs = map[aggKey]*Agg{}
		lines = 0
		return nil
	}
	for {
		line, oversize, err := lr.Next()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				atEOF = true
			case ctx.Err() != nil:
				if cerr := commitAt(lr.Consumed, false); cerr != nil {
					return id, cerr
				}
				return id, ctx.Err()
			case errors.Is(err, errPassBudget):
				st.BudgetStopped = true
			case errors.Is(err, errSegmentCap), errors.Is(err, errRawCap):
				// A decompression bomb or an absurd file: keep what was read, then mark the segment finished
				// (offset = the cap) so it is never read again; by NAME only, never content.
				st.Capped++
				in.cfg.Logf("reach: %s exceeded the %d-byte segment cap after %d bytes; the rest of it is not counted", seg.Name, in.cfg.MaxSegmentBytes, lr.Consumed)
				off := lr.Consumed
				if off < in.cfg.MaxSegmentBytes {
					off = in.cfg.MaxSegmentBytes
				}
				return id, commitAt(off, !seg.Active) // over the cap = done, for a rolled segment
			default:
				// A corrupt or truncated rolled segment: keep what was read (it commits below, so the cursor
				// does not stall on lines already counted), say so by NAME only (never content), and count it.
				st.ReadErrors++
				in.cfg.Logf("reach: read error in %s after %d bytes: %v", seg.Name, lr.Consumed, err)
				// A rolled .gz never changes, so the same error would recur every pass and re-decompress its
				// prefix each time: give up on the rest of it (marked complete below), as for the cap.
				corrupt = seg.Gz
			}
			break
		}
		st.Lines++
		lines++
		if oversize {
			st.Oversize++
		} else if e, perr := ParseLine(line); perr != nil {
			st.Malformed++
		} else {
			st.Counted[in.observe(aggs, e, today)]++
		}
		if lines >= in.cfg.CommitEvery {
			if err := commitAt(lr.Consumed, false); err != nil {
				return id, err
			}
			if err := ctx.Err(); err != nil {
				return id, err
			}
		}
	}
	// A ROLLED segment read to its clean end is final (Caddy no longer writes it): mark it complete in the same
	// transaction as its last aggregates. The active file never is; a budget stop is not an end, and neither is a
	// read error on a plain file (a .gz read error is permanent: see above).
	return id, commitAt(lr.Consumed, (atEOF || corrupt) && !seg.Active)
}
