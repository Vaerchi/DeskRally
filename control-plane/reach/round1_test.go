package reach

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Codex round 1 regressions (docs/68 section 12, "Codex round 1").

func (r *rig) ingesterWith(mod func(*Config)) *Ingester {
	r.t.Helper()
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	r.store.Now = func() time.Time { return r.now }
	cfg := Config{
		Dir: r.dir, LogName: "access.log", SaltFile: SaltFile{Path: r.salt}, Store: r.store,
		Now:   func() time.Time { return r.now },
		Logf:  func(string, ...any) {},
		Sizes: func(a string) (int64, bool) { s, ok := r.sizes[a]; return s, ok },
	}
	mod(&cfg)
	in, err := New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return in
}

func humanReq(r *rig, t *testing.T, day string) int64 {
	t.Helper()
	return rowOf(t, r.store, day, "DeskRallySupport.exe", ClassHuman).Requests
}

// 1. A roll between discovery and the read.
func TestRollBetweenDiscoveryAndReadIsReadAsTheFileItIsAndCountsEachLineOnce(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"), human(tsOf("2026-11-05", 2), "198.51.100.2", "UA"))
	in := r.ingester()
	r.run(in) // cursor for the first segment: its first two lines

	r.appendRaw("access.log", human(tsOf("2026-11-05", 3), "198.51.100.3", "UA")+"\n") // late line, not read yet
	rolled := "access-2026-11-05T09-00-00.000.log"
	fired := false
	in.beforeOpen = func(seg Segment) {
		if fired || !seg.Active {
			return
		}
		fired = true
		// Caddy rolls AFTER discovery listed access.log and BEFORE the ingest opens it: the path now names a
		// different, larger file whose first line has another timestamp.
		if err := os.Rename(r.path("access.log"), r.path(rolled)); err != nil {
			t.Fatal(err)
		}
		var fresh []string
		for i := 0; i < 4; i++ {
			fresh = append(fresh, human(tsOf("2026-11-05", 4)+float64(i), fmt.Sprintf("198.51.100.%d", 10+i), "UA"))
		}
		r.write("access.log", fresh...)
	}
	r.run(in)
	if !fired {
		t.Fatal("the seam never fired")
	}
	in.beforeOpen = nil
	r.run(in) // the rolled file is found under its new name
	r.run(in)
	if got := humanReq(r, t, "2026-11-05"); got != 7 {
		t.Fatalf("requests = %d, want 7 (2 + late 1 + 4 in the replacement file, each exactly once)", got)
	}
}

// 2. The decompressed-byte cap, the pass budget, and cancellation during reads.
func lines(n int, hour int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, human(tsOf("2026-11-05", hour)+float64(i), fmt.Sprintf("198.51.100.%d", i%250), "UA"))
	}
	return out
}

func TestSegmentOverTheCapIsGivenUpOnByNameAndNeverReReadAndBombCostIsBounded(t *testing.T) {
	r := newRig(t)
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A gzip that inflates to ~2 MiB of valid lines (a stand-in for a bomb).
	var raw bytes.Buffer
	for _, l := range lines(5000, 1) {
		raw.WriteString(l + "\n")
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw.Bytes())
	zw.Close()
	if err := os.WriteFile(r.path("access-2026-11-05T09-00-00.000.log.gz"), gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs []string
	const cap = 100_000
	in := r.ingesterWith(func(c *Config) {
		c.MaxSegmentBytes = cap
		c.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	})
	st := r.run(in)
	if st.Capped != 1 {
		t.Fatalf("Capped = %d, want 1 (stats %+v)", st.Capped, st)
	}
	if read := in.cfg.MaxPassBytes - in.passLeft; read > cap {
		t.Fatalf("decompressed %d bytes, cap is %d", read, cap)
	}
	if st.Lines == 0 || st.Lines >= 5000 {
		t.Fatalf("lines = %d: the part before the cap counts, the rest does not", st.Lines)
	}
	named := false
	for _, l := range logs {
		if strings.Contains(l, "access-2026-11-05T09-00-00.000.log.gz") && strings.Contains(l, "cap") {
			named = true
		}
		if strings.Contains(l, "198.51.100") || strings.Contains(l, "UA") {
			t.Fatalf("log carries content: %q", l)
		}
	}
	if !named {
		t.Fatalf("capped segment not logged by name: %v", logs)
	}
	cs, _ := r.store.Cursors(context.Background())
	for _, c := range cs {
		if c.Offset < cap {
			t.Fatalf("cursor %+v not pinned at the cap", c)
		}
	}
	before := humanReq(r, t, "2026-11-05")
	st2 := r.run(in)
	if st2.Lines != 0 || st2.Skipped != 1 || humanReq(r, t, "2026-11-05") != before {
		t.Fatalf("a capped segment was read again: %+v", st2)
	}
}

func TestPassBudgetStopsCleanlyAndResumesWithoutDoubleCounting(t *testing.T) {
	r := newRig(t)
	r.write("access-2026-11-05T05-00-00.000.log", lines(400, 1)...)
	r.write("access-2026-11-05T09-00-00.000.log", lines(400, 3)...)
	fi, _ := os.Stat(r.path("access-2026-11-05T05-00-00.000.log"))
	in := r.ingesterWith(func(c *Config) { c.MaxPassBytes = fi.Size() / 2 })
	st := r.run(in)
	if !st.BudgetStopped {
		t.Fatalf("budget not hit: %+v", st)
	}
	got := humanReq(r, t, "2026-11-05")
	if got >= 800 {
		t.Fatalf("after the first pass %d requests", got)
	}
	for i := 0; i < 12; i++ {
		r.run(in)
	}
	if got := humanReq(r, t, "2026-11-05"); got != 800 {
		t.Fatalf("after resuming: %d, want 800 exactly", got)
	}
}

func TestCancellationIsHonouredWhileReadingNotOnlyBetweenBatches(t *testing.T) {
	r := newRig(t)
	r.write("access.log", lines(30, 1)...)
	in := r.ingester()
	ctx, cancel := context.WithCancel(context.Background())
	in.beforeOpen = func(Segment) { cancel() } // cancelled after discovery, before the read starts
	_, err := in.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(r.store.Rows()) != 0 {
		t.Fatalf("a cancelled pass counted lines: %+v", r.store.Rows())
	}
	// And while skipping an already-counted prefix.
	in.beforeOpen = nil
	r.run(in)
	r.appendRaw("access.log", lines(1, 5)[0]+"\n")
	ctx2, cancel2 := context.WithCancel(context.Background())
	in.beforeOpen = func(Segment) { cancel2() }
	if _, err := in.RunOnce(ctx2); !errors.Is(err, context.Canceled) {
		t.Fatalf("skip phase: err = %v", err)
	}
}

// 3. Process-wide bounds.
func TestGlobalBoundsFlagRowsPartialAndNeverDropRequests(t *testing.T) {
	artifact := func(i int) string { return fmt.Sprintf("server/deskrally-server-1.0.%d.tar.gz", i) }
	req := func(i int, c int) string {
		return logLine(tsOf("2026-11-05", 1)+float64(i*100+c), fmt.Sprintf("198.51.100.%d", c), "GET", "/download/"+artifact(i), "UA", 200, 10)
	}
	t.Run("artifact bound", func(t *testing.T) {
		r := newRig(t)
		var ls []string
		for i := 0; i < 6; i++ {
			for c := 0; c < 3; c++ {
				ls = append(ls, req(i, c))
			}
		}
		r.write("access.log", ls...)
		calls := 0
		in := r.ingesterWith(func(c *Config) {
			c.MaxArtifacts = 2
			c.Sizes = func(string) (int64, bool) { calls++; return 10, true }
		})
		r.run(in)
		if calls > 2 {
			t.Fatalf("size lookups = %d, want <= 2 (the cache bound)", calls)
		}
		for i := 0; i < 6; i++ {
			row := rowOf(t, r.store, "2026-11-05", artifact(i), ClassHuman)
			if row.Requests != 3 {
				t.Fatalf("%s: requests %d, want 3 (never dropped)", artifact(i), row.Requests)
			}
			if i < 2 && (row.Uniq == nil || *row.Uniq != 3) {
				t.Fatalf("%s should have its figure: %+v", artifact(i), row)
			}
			if i >= 2 && (row.Uniq != nil || !row.Partial) {
				t.Fatalf("%s past the bound must be partial with no figure: %+v", artifact(i), row)
			}
		}
	})
	t.Run("total hash bound", func(t *testing.T) {
		r := newRig(t)
		var ls []string
		for i := 0; i < 3; i++ {
			for c := 0; c < 3; c++ {
				ls = append(ls, req(i, c))
			}
		}
		r.write("access.log", ls...)
		in := r.ingesterWith(func(c *Config) { c.MaxTotalUniq = 4 })
		r.run(in)
		var held int
		for _, s := range in.sets {
			held += len(s)
		}
		if held != 4 || in.totalHashes != 4 {
			t.Fatalf("hashes held %d / counter %d, want 4", held, in.totalHashes)
		}
		for i := 0; i < 3; i++ {
			if row := rowOf(t, r.store, "2026-11-05", artifact(i), ClassHuman); row.Requests != 3 {
				t.Fatalf("requests dropped: %+v", row)
			}
		}
		if row := rowOf(t, r.store, "2026-11-05", artifact(1), ClassHuman); !row.Partial {
			t.Fatalf("an artifact that hit the total bound must be partial: %+v", row)
		}
	})
}

// 4. Salt hygiene.
func saltFailing(r *rig, fail *bool) SaltFile {
	plain := SaltFile{Path: r.salt}
	return SaltFile{
		Path: r.salt,
		storeHook: func(s Salt) error {
			if *fail {
				return errors.New("disk full")
			}
			return plain.Store(s)
		},
		eraseHook: func() error {
			if *fail {
				return errors.New("file busy")
			}
			return plain.Erase()
		},
	}
}

func TestExpiredKeyThatCannotBeRemovedFailsClosedAndIsRetriedEveryPass(t *testing.T) {
	r := newRig(t)
	fail := false
	var logs []string
	r.write("access.log", human(tsOf("2026-11-05", 10), "198.51.100.1", "UA"))
	in := r.ingesterWith(func(c *Config) {
		c.SaltFile = saltFailing(r, &fail)
		c.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	})
	r.run(in)
	day5, _ := readSalt(t, r.salt)

	fail = true
	r.now = time.Date(2026, 11, 6, 0, 30, 0, 0, time.UTC)
	r.appendRaw("access.log", human(tsOf("2026-11-06", 0)+60, "198.51.100.1", "UA")+"\n"+human(tsOf("2026-11-06", 0)+120, "198.51.100.2", "UA")+"\n")
	r.run(in)
	if s, _ := readSalt(t, r.salt); s.Key != day5.Key {
		t.Fatal("premise: the file should still hold the old key")
	}
	row := rowOf(t, r.store, "2026-11-06", "DeskRallySupport.exe", ClassHuman)
	if row.Requests != 2 || row.Uniq != nil || !row.Partial {
		t.Fatalf("while the old key is on disk: no unique-ish figure, row partial, requests kept: %+v", row)
	}
	loud := false
	for _, l := range logs {
		if strings.Contains(l, "CANNOT BE OVERWRITTEN OR REMOVED") {
			loud = true
		}
	}
	if !loud {
		t.Fatalf("no loud log: %v", logs)
	}

	// Still failing on the next pass: still closed.
	r.run(in)
	if s, _ := readSalt(t, r.salt); s.Key != day5.Key || !in.diskStale {
		t.Fatal("should still be failing closed")
	}

	// The fault clears: the very next pass erases the old key, with no new line needed.
	fail = false
	r.run(in)
	after, raw := readSalt(t, r.salt)
	if after.Day != "2026-11-06" || after.Key == day5.Key || in.diskStale {
		t.Fatalf("erasure not retried: %s", raw)
	}
	r.appendRaw("access.log", human(tsOf("2026-11-06", 1), "198.51.100.3", "UA")+"\n")
	r.run(in)
	if row := rowOf(t, r.store, "2026-11-06", "DeskRallySupport.exe", ClassHuman); row.Uniq == nil || *row.Uniq != 1 {
		t.Fatalf("counting did not resume: %+v", row)
	}
}

func TestSaltRotatesEvenWhenThePassFails(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 10), "198.51.100.1", "UA"))
	in := r.ingester()
	r.run(in)
	day5, _ := readSalt(t, r.salt)
	r.now = time.Date(2026, 11, 6, 0, 5, 0, 0, time.UTC)
	gone := r.dir + "-gone"
	if err := os.Rename(r.dir, gone); err != nil { // discovery fails
		t.Fatal(err)
	}
	if _, err := in.RunOnce(context.Background()); err == nil {
		t.Fatal("premise: discovery should fail")
	}
	after, raw := readSalt(t, r.salt)
	if after.Day != "2026-11-06" || after.Key == day5.Key || strings.Contains(raw, fmt.Sprintf("%x", day5.Key[:])) {
		t.Fatalf("a failed pass left yesterday's key: %s", raw)
	}
}

func TestExpiredKeyOnDiskAtStartupIsReplacedAtOnce(t *testing.T) {
	r := newRig(t)
	if err := (SaltFile{Path: r.salt}).Store(Salt{Day: "2026-11-04", Key: [32]byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	in := r.ingester()
	s, raw := readSalt(t, r.salt)
	if s.Day != "2026-11-05" || s.Key == [32]byte{1, 2, 3} || in.SaltDay() != "2026-11-05" {
		t.Fatalf("an earlier day's key survived the restart: %s", raw)
	}
}

// 5. The segment id carries no personal data.
func TestSegmentIDDependsOnlyOnTheServerTimestampText(t *testing.T) {
	a := logLine(1793880000.123456, "203.0.113.7", "GET", "/download/DeskRallySupport.exe", "Mozilla/5.0 A", 200, 1)
	b := logLine(1793880000.123456, "2001:db8::1:2:3:4", "POST", "/other/very/long/path?x=1", strings.Repeat("U", 300), 404, 99999)
	c := logLine(1793880000.123457, "203.0.113.7", "GET", "/download/DeskRallySupport.exe", "Mozilla/5.0 A", 200, 1)
	ida, _, oka := segmentID([]byte(a + "\n"))
	idb, _, okb := segmentID([]byte(b + "\n"))
	idc, _, okc := segmentID([]byte(c + "\n"))
	if !oka || !okb || !okc {
		t.Fatal("ids not derived")
	}
	if ida != idb {
		t.Fatalf("the id depends on the IP, User-Agent, URI or length: %s vs %s", ida, idb)
	}
	if ida == idc {
		t.Fatal("different timestamps must give different ids")
	}
	if len(ida) != 32 || strings.Trim(ida, "0123456789abcdef") != "" {
		t.Fatalf("id %q is not 32 lowercase hex (the migration's CHECK)", ida)
	}
	if _, _, ok := segmentID([]byte(`{"level":"info","msg":"no timestamp"}` + "\n")); ok {
		t.Fatal("a line with no ts must not identify a segment")
	}
	if _, _, ok := segmentID([]byte(a[:len(a)/2])); ok {
		t.Fatal("an incomplete first line must not identify a segment yet")
	}
}

// 6. The artifact name never escapes the artifact directory.
func TestDirSizesCannotEscapeTheArtifactDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "art")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.bin"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := DirSizes(dir)
	if s, ok := f("ok.bin"); !ok || s != 5 {
		t.Fatalf("control: %d %v", s, ok)
	}
	for _, bad := range []string{
		"../secret.txt", "..", "a/../../secret.txt", "./../secret.txt", "..%2fsecret.txt", "%2e%2e/secret.txt", "%2e%2e%2fsecret.txt",
		"/etc/passwd", filepath.ToSlash(filepath.Join(parent, "secret.txt")), `..\secret.txt`, `C:\x`, "C:/x", "a//b", "x\x00y", ".", "./ok.bin/../../secret.txt",
	} {
		if _, ok := f(bad); ok {
			t.Errorf("%q must not resolve", bad)
		}
		if p, ok := artifactPath(dir, bad); ok {
			// A percent form is just a literal file name under dir (no decoding happens anywhere); it must stay inside.
			rel, _ := filepath.Rel(dir, p)
			if !strings.Contains(bad, "%") || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Errorf("%q joined to %q (rel %q)", bad, p, rel)
			}
		}
	}
}

// Logged text carries counts and file names only: never an IP, a User-Agent or a hash, whichever way a pass
// fails. (SQL arguments are day/artifact/class/counts and the cursor's id, name and offset, so a database
// error cannot echo them either.)
func TestLoggedTextNeverCarriesClientData(t *testing.T) {
	r := newRig(t)
	var logs []string
	ip, ua := "203.0.113.77", "Distinctive/UA-privacy-probe-42"
	r.write("access-2026-11-05T05-00-00.000.log", lines(3, 1)...)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	for i := 0; i < 50; i++ {
		zw.Write([]byte(human(tsOf("2026-11-05", 2), ip, ua) + "\n"))
	}
	zw.Close()
	b := buf.Bytes()
	if err := os.WriteFile(r.path("access-2026-11-05T09-00-00.000.log.gz"), b[:len(b)-12], 0o644); err != nil {
		t.Fatal(err)
	}
	r.write("access.log", human(tsOf("2026-11-05", 4), ip, ua), "not json "+ip+" "+ua)
	in := r.ingesterWith(func(c *Config) {
		c.MaxSegmentBytes = 5000
		c.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	})
	r.store.FailNextCommit = true
	in.RunOnce(context.Background())
	r.run(in)
	salt, _ := readSalt(t, r.salt)
	h := salt.ClientHash(ip, ua)
	all := strings.Join(logs, "\n")
	for _, n := range []string{ip, ua, fmt.Sprintf("%x", h[:]), fmt.Sprintf("%x", h[:8]), fmt.Sprintf("%x", salt.Key[:])} {
		if strings.Contains(all, n) {
			t.Fatalf("log contains %q:\n%s", n, all)
		}
	}
	if len(logs) == 0 {
		t.Fatal("premise: nothing was logged")
	}
}
