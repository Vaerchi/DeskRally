package reach

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// Codex round 2 regressions (docs/68 section 12, "Codex round 2").

func segName(hour int) string {
	return "access-2026-11-05T" + string(rune('0'+hour/10)) + string(rune('0'+hour%10)) + "-00-00.000.log"
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// A. Already-counted history must not starve a newer segment, however small the skip budget is.
func TestRolledHistoryExceedingTheSkipBudgetDoesNotStarveTheNewestSegment(t *testing.T) {
	r := newRig(t)
	for h := 1; h <= 6; h++ {
		r.write(segName(h), lines(600, h)...)
	}
	r.run(r.ingester()) // pass 1 with the default budgets: all six read to their end
	if got := humanReq(r, t, "2026-11-05"); got != 3600 {
		t.Fatalf("premise: %d requests, want 3600", got)
	}
	cs, _ := r.store.Cursors(context.Background())
	for id, c := range cs {
		if !c.Complete {
			t.Fatalf("rolled segment %s read to its end is not marked complete: %+v", id, c)
		}
	}

	r.write(segName(8), lines(20, 8)...) // a newer rolled segment appears
	one := fileSize(t, r.path(segName(1)))
	// The prefixes of the six old segments alone are several times this budget.
	in := r.ingesterWith(func(c *Config) { c.MaxSkipBytes = one + one/2 })
	var skipped int
	for pass := 0; pass < 3; pass++ {
		st := r.run(in)
		skipped += st.Skipped
	}
	if got := humanReq(r, t, "2026-11-05"); got != 3620 {
		t.Fatalf("requests = %d, want 3620 (the newest segment read once, history never recounted)", got)
	}
	if skipped < 6 {
		t.Fatalf("complete segments were opened again: skipped %d", skipped)
	}
}

// A. Cursors that are not marked complete (an uncompressed segment is SEEKED, so its counted prefix costs nothing)
// still let the newest segment through in a bounded number of passes, each completing what it reaches.
func TestUncompleteCursorsAreSeekedNotReReadAndTheNewestIsReachedInBoundedPasses(t *testing.T) {
	r := newRig(t)
	for h := 1; h <= 6; h++ {
		r.write(segName(h), lines(600, h)...)
	}
	segs, err := ListSegments(context.Background(), r.dir, "access.log")
	if err != nil || len(segs) != 6 {
		t.Fatalf("segments %d %v", len(segs), err)
	}
	for _, s := range segs { // counted in an earlier life, before cursors carried a complete flag
		r.store.cursors[s.ID] = Cursor{FileID: s.ID, Name: s.Name, Offset: fileSize(t, s.Path)}
	}
	r.write(segName(8), lines(20, 8)...)
	// Room for the 64 KiB identity prefetch of one or two segments per pass, NOT for a segment's prefix re-read (they are ~150 KiB).
	in := r.ingesterWith(func(c *Config) { c.MaxSkipBytes = 100 << 10 })
	passes := 0
	for ; passes < 10 && humanReq0(r) < 20; passes++ {
		r.run(in)
	}
	if got := humanReq0(r); got != 20 {
		t.Fatalf("requests = %d after %d passes, want exactly 20 (newest read, no prefix recounted)", got, passes)
	}
}

func humanReq0(r *rig) int64 {
	for _, row := range r.store.Rows() {
		if row.Class == ClassHuman {
			return row.Requests
		}
	}
	return 0
}

// A. A rolled segment that hit the size cap is done for good; the active file never is complete.
func TestCappedRolledSegmentIsCompleteAndTheActiveFileNeverIs(t *testing.T) {
	r := newRig(t)
	r.write(segName(1), lines(5000, 1)...)
	r.write("access.log", lines(3, 9)...)
	in := r.ingesterWith(func(c *Config) { c.MaxSegmentBytes = 100_000 })
	r.run(in)
	cs, _ := r.store.Cursors(context.Background())
	var complete, incomplete int
	for _, c := range cs {
		if c.Complete {
			complete++
		} else {
			incomplete++
		}
	}
	if complete != 1 || incomplete != 1 {
		t.Fatalf("complete=%d incomplete=%d: want the capped rolled segment complete and the active file not (%+v)", complete, incomplete, cs)
	}
	if st := r.run(in); st.Skipped != 1 || st.Lines != 0 {
		t.Fatalf("the capped segment was opened again: %+v", st)
	}
}

// B. A cancelled context stops the open before any file or gzip work, in discovery too; header bytes are charged.
func TestOpenHonoursCancellationBeforeAnyReadAndChargesGzipHeaderBytes(t *testing.T) {
	r := newRig(t)
	r.write(segName(1), lines(3, 1)...)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Header.Extra = bytes.Repeat([]byte{'x'}, 5000) // a legal but large header field
	zw.Write([]byte(lines(1, 2)[0] + "\n"))
	zw.Close()
	gzName := "access-2026-11-05T02-00-00.000.log.gz"
	if err := os.WriteFile(r.path(gzName), gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	plain := Segment{Path: r.path(segName(1)), Name: segName(1)}
	if _, err := plain.openIdentified(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("an uncompressed open on a cancelled ctx: err = %v", err)
	}
	if _, err := ListSegments(cancelled, r.dir, "access.log"); !errors.Is(err, context.Canceled) {
		t.Fatalf("discovery on a cancelled ctx: err = %v", err)
	}

	budget := int64(1 << 20)
	lim := &limits{ctx: context.Background(), segLeft: 100, passLeft: &budget, skipLeft: &budget} // 100 compressed bytes
	if _, err := (Segment{Path: r.path(gzName), Name: gzName, Gz: true}).openIdentified(context.Background(), lim); !errors.Is(err, errRawCap) {
		t.Fatalf("a 5000-byte gzip header against a 100-byte cap: err = %v, want errRawCap", err)
	}
	// Control: with room, the same file opens.
	lim = &limits{ctx: context.Background(), segLeft: 1 << 20, passLeft: &budget, skipLeft: &budget}
	o, err := (Segment{Path: r.path(gzName), Name: gzName, Gz: true}).openIdentified(context.Background(), lim)
	if err != nil || !o.Ready {
		t.Fatalf("control open: %v", err)
	}
	o.Close()
}

// C. Only "does not exist" means absent. Any other Lstat error keeps the ingest failing closed.
func TestSaltFileExistsOnlyAbsentOnNotExist(t *testing.T) {
	perm := &fs.PathError{Op: "lstat", Path: "salt", Err: fs.ErrPermission}
	miss := &fs.PathError{Op: "lstat", Path: "salt", Err: fs.ErrNotExist}
	if !(SaltFile{lstatHook: func(string) (fs.FileInfo, error) { return nil, perm }}).Exists() {
		t.Fatal("a permission error must read as possibly present")
	}
	if !(SaltFile{lstatHook: func(string) (fs.FileInfo, error) { return nil, errors.New("i/o error") }}).Exists() {
		t.Fatal("an I/O error must read as possibly present")
	}
	if (SaltFile{lstatHook: func(string) (fs.FileInfo, error) { return nil, miss }}).Exists() {
		t.Fatal("not-exist is absent")
	}
}

func TestUnreadableSaltPathStaysFailClosedWhenTheKeyCannotBeErased(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lstatErr  error
		wantStale bool
	}{
		{"permission error", &fs.PathError{Op: "lstat", Err: fs.ErrPermission}, true},
		{"file really gone", &fs.PathError{Op: "lstat", Err: fs.ErrNotExist}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			var logs []string
			in := r.ingesterWith(func(c *Config) {
				c.SaltFile = SaltFile{Path: r.salt,
					storeHook: func(Salt) error { return errors.New("disk full") },
					eraseHook: func() error { return errors.New("file busy") },
					lstatHook: func(string) (fs.FileInfo, error) { return nil, tc.lstatErr },
				}
				c.Logf = func(f string, a ...any) { logs = append(logs, f) }
			})
			if in.diskStale != tc.wantStale || in.failClosed() != tc.wantStale {
				t.Fatalf("diskStale = %v, want %v", in.diskStale, tc.wantStale)
			}
			if tc.wantStale && !strings.Contains(strings.Join(logs, "\n"), "CANNOT BE OVERWRITTEN OR REMOVED") {
				t.Fatalf("no loud log: %v", logs)
			}
		})
	}
}
