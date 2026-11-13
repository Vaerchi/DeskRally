package reach

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) // the fixture clock

type rig struct {
	t     *testing.T
	dir   string
	salt  string
	store *MemStore
	now   time.Time
	sizes map[string]int64
}

func newRig(t *testing.T) *rig {
	t.Helper()
	d := t.TempDir()
	return &rig{t: t, dir: filepath.Join(d, "logs"), salt: filepath.Join(d, "tmpfs", "salt"), store: NewMemStore(), now: t0,
		sizes: map[string]int64{"DeskRallySupport.exe": 10_000_000}}
}

func (r *rig) ingester() *Ingester {
	r.t.Helper()
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	r.store.Now = func() time.Time { return r.now }
	in, err := New(Config{
		Dir: r.dir, LogName: "access.log", SaltFile: SaltFile{Path: r.salt}, Store: r.store,
		Now:   func() time.Time { return r.now },
		Logf:  func(string, ...any) {},
		Sizes: func(a string) (int64, bool) { s, ok := r.sizes[a]; return s, ok },
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return in
}

func (r *rig) path(name string) string { return filepath.Join(r.dir, name) }

// write replaces a file; appendTo adds to it.
func (r *rig) write(name string, lines ...string) {
	r.t.Helper()
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.path(name), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) appendRaw(name, raw string) {
	r.t.Helper()
	f, err := os.OpenFile(r.path(name), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		r.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(raw); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) run(in *Ingester) Stats {
	r.t.Helper()
	st, err := in.RunOnce(context.Background())
	if err != nil {
		r.t.Fatalf("RunOnce: %v", err)
	}
	return st
}

func tsOf(day string, hour int) float64 {
	d, _ := time.Parse("2006-01-02", day)
	return float64(d.Add(time.Duration(hour) * time.Hour).Unix())
}

func human(ts float64, ip, ua string) string {
	return logLine(ts, ip, "GET", "/download/DeskRallySupport.exe", ua, 200, 10_000_000)
}

func rowOf(t *testing.T, s *MemStore, day, artifact string, c Class) Row {
	t.Helper()
	for _, r := range s.Rows() {
		if r.Day == day && r.Artifact == artifact && r.Class == c {
			return r
		}
	}
	t.Fatalf("no row %s %s %s in %+v", day, artifact, c, s.Rows())
	return Row{}
}

func TestIngestCountsByClassAndDay(t *testing.T) {
	r := newRig(t)
	r.write("access.log",
		human(tsOf("2026-11-04", 3), "198.51.100.1", "UA-a"),
		human(tsOf("2026-11-05", 1), "198.51.100.2", "UA-b"),
		logLine(tsOf("2026-11-05", 2), "198.51.100.2", "GET", "/download/DeskRallySupport.exe", "UA-b", 206, 5000), // a resume
		logLine(tsOf("2026-11-05", 2), "198.51.100.3", "GET", "/download/DeskRallySupport.exe", "UA-c", 200, 4096), // went away
		logLine(tsOf("2026-11-05", 2), "198.51.100.3", "HEAD", "/download/DeskRallySupport.exe", "UA-c", 200, 0),
		logLine(tsOf("2026-11-05", 3), "198.51.100.4", "GET", "/download/agent/v2/canary/manifest.json", "", 200, 300),
		logLine(tsOf("2026-11-05", 3), "198.51.100.4", "GET", "/download/agent/releases/1.3.19/DeskRallyAgent.msi", "", 200, 9000),
		logLine(tsOf("2026-11-05", 4), "198.51.100.5", "GET", "/wp-login.php", "scan", 404, 10),
		`this is not json`,
		strings.Repeat("x", 70<<10), // an over-long line
	)
	in := r.ingester()
	st := r.run(in)
	if st.Lines != 10 || st.Malformed != 1 || st.Oversize != 1 {
		t.Fatalf("stats %+v", st)
	}
	d5 := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if d5.Requests != 3 || d5.Completed == nil || *d5.Completed != 1 {
		t.Fatalf("2026-11-05 human: %+v (completed %v)", d5, d5.Completed)
	}
	if d4 := rowOf(t, r.store, "2026-11-04", "DeskRallySupport.exe", ClassHuman); d4.Requests != 1 {
		t.Fatalf("2026-11-04 human: %+v", d4)
	}
	if u := rowOf(t, r.store, "2026-11-05", "agent-manifest", ClassUpdate); u.Requests != 1 || u.Uniq != nil {
		t.Fatalf("update row: %+v", u)
	}
	if n := rowOf(t, r.store, "2026-11-05", NoiseArtifact, ClassNoise); n.Requests != 2 {
		t.Fatalf("noise row (HEAD + scanner): %+v", n)
	}
}

func TestIngestResumeNeverDoubleCounts(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"), human(tsOf("2026-11-05", 2), "198.51.100.2", "UA"))
	in := r.ingester()
	r.run(in)
	r.run(in) // nothing new
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 2 {
		t.Fatalf("after a re-run: %d, want 2", got)
	}
	r.appendRaw("access.log", human(tsOf("2026-11-05", 3), "198.51.100.3", "UA")+"\n")
	r.run(in)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 3 {
		t.Fatalf("after one new line: %d, want 3", got)
	}
	// A brand-new process (restart) with the same store resumes from the cursor.
	in2 := r.ingester()
	r.run(in2)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 3 {
		t.Fatalf("after a restart: %d, want 3", got)
	}
}

func TestIngestPartialLastLineIsReadOnceItIsComplete(t *testing.T) {
	r := newRig(t)
	whole := human(tsOf("2026-11-05", 2), "198.51.100.2", "UA")
	r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"))
	r.appendRaw("access.log", whole[:len(whole)/2]) // the writer is mid-line
	in := r.ingester()
	r.run(in)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 1 {
		t.Fatalf("a partial line must not be counted: %d", got)
	}
	r.appendRaw("access.log", whole[len(whole)/2:]+"\n")
	st := r.run(in)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 2 || st.Malformed != 0 {
		t.Fatalf("after completion: %d requests, %d malformed", got, st.Malformed)
	}
}

func TestIngestRollOverAndGzipDoNotDoubleCountOrLoseLines(t *testing.T) {
	r := newRig(t)
	first := []string{human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"), human(tsOf("2026-11-05", 2), "198.51.100.2", "UA")}
	r.write("access.log", first...)
	in := r.ingester()
	r.run(in)

	// Lines arrive just before Caddy rolls; then it renames the file and starts a new one.
	late := human(tsOf("2026-11-05", 3), "198.51.100.3", "UA")
	r.appendRaw("access.log", late+"\n")
	rolled := "access-2026-11-05T09-00-00.000.log"
	if err := os.Rename(r.path("access.log"), r.path(rolled)); err != nil {
		t.Fatal(err)
	}
	r.write("access.log", human(tsOf("2026-11-05", 4), "198.51.100.4", "UA"))
	r.run(in)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 4 {
		t.Fatalf("after the roll: %d, want 4 (the late line is read from the renamed file, nothing twice)", got)
	}

	// Then Caddy compresses the rolled file and removes the original: the same content under a new name.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	raw, _ := os.ReadFile(r.path(rolled))
	zw.Write(raw)
	zw.Close()
	if err := os.WriteFile(r.path(rolled+".gz"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.path(rolled)); err != nil {
		t.Fatal(err)
	}
	r.appendRaw("access.log", human(tsOf("2026-11-05", 5), "198.51.100.5", "UA")+"\n")
	r.run(in)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 5 {
		t.Fatalf("after gzip: %d, want 5", got)
	}

	// A fresh process over the same files and store: still 5.
	r.run(r.ingester())
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 5 {
		t.Fatalf("after a restart over rolled + gzipped files: %d, want 5", got)
	}
	// While the compressor runs both copies exist; they are one segment.
	if err := os.WriteFile(r.path(rolled), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	r.run(in)
	if got := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman).Requests; got != 5 {
		t.Fatalf("with the .log and .log.gz side by side: %d, want 5", got)
	}
}

func TestIngestCrashBeforeCommitCountsOnce(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"), human(tsOf("2026-11-05", 2), "198.51.100.2", "UA"))
	in := r.ingester()
	r.store.FailNextCommit = true
	if _, err := in.RunOnce(context.Background()); err == nil {
		t.Fatal("a failed commit must fail the run")
	}
	if len(r.store.Rows()) != 0 {
		t.Fatalf("a failed commit left rows: %+v", r.store.Rows())
	}
	r.run(in)
	r.run(in)
	row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if row.Requests != 2 || row.Uniq == nil || *row.Uniq != 2 {
		t.Fatalf("after the retry: %+v (the re-read must not double the count, and the set is idempotent)", row)
	}
}

func TestIngestCommitsInChunksAndResumesInsideAFile(t *testing.T) {
	r := newRig(t)
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, human(tsOf("2026-11-05", 1)+float64(i), fmt.Sprintf("198.51.100.%d", i), "UA"))
	}
	r.write("access.log", lines...)
	r.store.Now = func() time.Time { return r.now }
	in, _ := New(Config{Dir: r.dir, SaltFile: SaltFile{Path: r.salt}, Store: r.store, Now: func() time.Time { return r.now }, Logf: func(string, ...any) {}, CommitEvery: 10})
	r.run(in)
	row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if row.Requests != 25 || row.Uniq == nil || *row.Uniq != 25 {
		t.Fatalf("chunked ingest: %+v", row)
	}
}

func TestUniqueIsPerArtifactPerDayAndCountsDistinctClients(t *testing.T) {
	r := newRig(t)
	script := func(ts float64, ip, ua string) string {
		return logLine(ts, ip, "GET", "/download/agent/new-msi-provisioning.ps1", ua, 200, 2000)
	}
	r.write("access.log",
		human(tsOf("2026-11-05", 1), "198.51.100.1", "UA-x"),
		human(tsOf("2026-11-05", 2), "198.51.100.1", "UA-x"), // the same client again
		human(tsOf("2026-11-05", 3), "198.51.100.1", "UA-y"), // same IP, another UA: another client
		human(tsOf("2026-11-05", 4), "198.51.100.2", "UA-x"),
		script(tsOf("2026-11-05", 5), "198.51.100.1", "UA-x"),
	)
	in := r.ingester()
	r.run(in)
	exe := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if exe.Requests != 4 || *exe.Uniq != 3 {
		t.Fatalf("exe: %+v uniq=%d", exe, *exe.Uniq)
	}
	if ps := rowOf(t, r.store, "2026-11-05", "agent/new-msi-provisioning.ps1", ClassHuman); *ps.Uniq != 1 {
		t.Fatalf("script uniq: %+v", ps)
	}
}

func TestCompletedIsNullWhenSizeUnknown(t *testing.T) {
	r := newRig(t)
	delete(r.sizes, "DeskRallySupport.exe")
	r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"))
	r.run(r.ingester())
	row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if row.Requests != 1 || row.Completed != nil {
		t.Fatalf("unknown artifact size must store completed as NULL, not 0: %+v", row)
	}
}

func TestDirSizes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "DeskRallySupport.exe"), make([]byte, 77), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server", "deskrally-server-1.0.0.tar.gz"), make([]byte, 9), 0o644); err != nil {
		t.Fatal(err)
	}
	f := DirSizes(dir)
	if s, ok := f("DeskRallySupport.exe"); !ok || s != 77 {
		t.Fatalf("exe: %d %v", s, ok)
	}
	if s, ok := f("server/deskrally-server-1.0.0.tar.gz"); !ok || s != 9 {
		t.Fatalf("tarball: %d %v", s, ok)
	}
	for _, bad := range []string{"", "missing.exe", "../x", "/etc/passwd", `a\b`, "server", "C:/x"} {
		if _, ok := f(bad); ok {
			t.Errorf("%q must not resolve", bad)
		}
	}
	if _, ok := DirSizes("")("DeskRallySupport.exe"); ok {
		t.Fatal("no directory configured must be unknown")
	}
}

func TestRetentionAndCursorPrune(t *testing.T) {
	r := newRig(t)
	old := time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC) // more than 25 months before t0
	r.write("access.log", human(float64(old.Unix()), "198.51.100.1", "UA"), human(tsOf("2026-11-05", 1), "198.51.100.2", "UA"))
	in := r.ingester()
	r.run(in)
	days := map[string]bool{}
	for _, row := range r.store.Rows() {
		days[row.Day] = true
	}
	if days["2024-09-01"] || !days["2026-11-05"] {
		t.Fatalf("retention: %v", days)
	}
	// A cursor of a segment that is gone and old is dropped; one that is still on disk never is, however old.
	r.store.mu.Lock()
	r.store.cursors["gone"] = Cursor{FileID: "gone"}
	r.store.updated["gone"] = t0.Add(-90 * 24 * time.Hour)
	for id := range r.store.cursors {
		if id != "gone" {
			r.store.updated[id] = t0.Add(-90 * 24 * time.Hour)
		}
	}
	r.store.mu.Unlock()
	r.run(in)
	cs, _ := r.store.Cursors(context.Background())
	if _, ok := cs["gone"]; ok || len(cs) != 1 {
		t.Fatalf("cursors after prune: %+v", cs)
	}
	// An empty listing (a broken mount) deletes no cursor.
	if err := os.Remove(r.path("access.log")); err != nil {
		t.Fatal(err)
	}
	r.store.mu.Lock()
	for id := range r.store.cursors {
		r.store.updated[id] = t0.Add(-90 * 24 * time.Hour)
	}
	r.store.mu.Unlock()
	r.run(in)
	if cs, _ := r.store.Cursors(context.Background()); len(cs) != 1 {
		t.Fatalf("an empty log directory must not prune cursors: %+v", cs)
	}
}

// ---- salt -----------------------------------------------------------------------------------------------

func readSalt(t *testing.T, path string) (Salt, string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := SaltFile{Path: path}.Load()
	if !ok {
		t.Fatalf("salt file unreadable: %q", b)
	}
	return s, string(b)
}

func TestSaltRotatesAtMidnightAndOverwritesThePriorKey(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 10), "198.51.100.1", "UA"))
	in := r.ingester()
	r.run(in)
	day1, raw1 := readSalt(t, r.salt)
	if day1.Day != "2026-11-05" {
		t.Fatalf("salt day %s", day1.Day)
	}
	if fi, err := os.Stat(r.salt); err != nil || fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("salt file mode %v %v", fi, err)
	}

	// The next day's first request arrives in the data: the salt rotates in step with it.
	r.now = time.Date(2026, 11, 6, 0, 30, 0, 0, time.UTC)
	r.appendRaw("access.log", human(tsOf("2026-11-06", 0)+60, "198.51.100.1", "UA")+"\n")
	r.run(in)
	day2, raw2 := readSalt(t, r.salt)
	if day2.Day != "2026-11-06" || day2.Key == day1.Key {
		t.Fatalf("no rotation: %s %x", day2.Day, day2.Key[:4])
	}
	if strings.Contains(raw2, hex.EncodeToString(day1.Key[:])) || raw1 == raw2 {
		t.Fatal("the previous day's key is still in the salt file")
	}
	// The SAME client has two unrelated hashes on the two days, so the days cannot be joined.
	if day1.ClientHash("198.51.100.1", "UA") == day2.ClientHash("198.51.100.1", "UA") {
		t.Fatal("one client hashes the same under two days' salts")
	}
	a := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	b := rowOf(t, r.store, "2026-11-06", "DeskRallySupport.exe", ClassHuman)
	if *a.Uniq != 1 || *b.Uniq != 1 || b.Partial {
		t.Fatalf("per-day uniq across the rotation: %+v %+v", a, b)
	}
}

func TestSaltRotatesIdleWhenTheDayChangesWithNoNewLines(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 10), "198.51.100.1", "UA"))
	in := r.ingester()
	r.run(in)
	before, _ := readSalt(t, r.salt)
	r.now = time.Date(2026, 11, 6, 0, 5, 0, 0, time.UTC)
	r.run(in)
	after, raw := readSalt(t, r.salt)
	if after.Day != "2026-11-06" || after.Key == before.Key || strings.Contains(raw, hex.EncodeToString(before.Key[:])) {
		t.Fatalf("idle rotation: %s", raw)
	}
}

func TestSaltReloadedAfterRestartMidDayAndTheDayIsPartial(t *testing.T) {
	r := newRig(t)
	r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"))
	in := r.ingester()
	r.run(in)
	before, _ := readSalt(t, r.salt)
	if row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman); !row.Partial {
		// The very first run is itself partial (the process did not see the day from its start).
		t.Fatalf("first-run day should be partial: %+v", row)
	}
	// Restart: the same key is reloaded, not regenerated.
	r.appendRaw("access.log", human(tsOf("2026-11-05", 2), "198.51.100.1", "UA")+"\n"+human(tsOf("2026-11-05", 3), "198.51.100.9", "UA")+"\n")
	in2 := r.ingester()
	after, _ := readSalt(t, r.salt)
	if after.Key != before.Key {
		t.Fatal("a restart mid-day must reload the day's salt")
	}
	r.run(in2)
	row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if !row.Partial {
		t.Fatal("a restart mid-day must mark the day's unique-ish figure partial")
	}
	// The restarted process only saw the new lines: its smaller set must not LOWER the stored figure.
	if row.Requests != 3 || *row.Uniq < 1 {
		t.Fatalf("after the restart: %+v", row)
	}
}

func TestMissingOrBrokenSaltFileMeansNewSaltAndPartial(t *testing.T) {
	for name, content := range map[string]*string{"missing": nil, "garbage": ptr("not a salt"), "short key": ptr("2026-11-05\nabcd\n"), "bad day": ptr("yesterday\n" + strings.Repeat("a", 64) + "\n")} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if content != nil {
				if err := os.MkdirAll(filepath.Dir(r.salt), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(r.salt, []byte(*content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"))
			in := r.ingester()
			r.run(in)
			s, _ := readSalt(t, r.salt)
			if s.Day != "2026-11-05" || s.Key == [32]byte{} {
				t.Fatalf("no fresh salt written: %+v", s)
			}
			if row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman); !row.Partial {
				t.Fatalf("a missing salt must mark the day partial: %+v", row)
			}
		})
	}
}

func TestLinesOlderThanTheSaltHaveNoUniqueFigureAndAreFlagged(t *testing.T) {
	r := newRig(t)
	// The salt is for today (2026-11-05); a backlog line from two days ago has no salt any more.
	r.write("access.log", human(tsOf("2026-11-03", 5), "198.51.100.1", "UA"))
	r.run(r.ingester())
	row := rowOf(t, r.store, "2026-11-03", "DeskRallySupport.exe", ClassHuman)
	if row.Requests != 1 || row.Uniq != nil || !row.Partial {
		t.Fatalf("catch-up of a day with no salt: %+v", row)
	}
}

func TestSetCapMakesTheFigureAFlaggedLowerBound(t *testing.T) {
	r := newRig(t)
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, human(tsOf("2026-11-05", 1)+float64(i), fmt.Sprintf("198.51.100.%d", i), "UA"))
	}
	r.write("access.log", lines...)
	in, _ := New(Config{Dir: r.dir, SaltFile: SaltFile{Path: r.salt}, Store: r.store, Now: func() time.Time { return r.now }, Logf: func(string, ...any) {}, MaxUniq: 3})
	r.run(in)
	row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman)
	if row.Requests != 6 || *row.Uniq != 3 || !row.Partial {
		t.Fatalf("capped set: %+v", row)
	}
}

// THE PRIVACY ASSERTION: nothing a client sent, and nothing derived from it, is in what is stored.
func TestStoredRowsAndCursorsNeverContainAnIPUAOrHash(t *testing.T) {
	r := newRig(t)
	ips := []string{"203.0.113.77", "198.51.100.200", "2001:db8::beef"}
	uas := []string{"Mozilla/5.0 (X11; SecretOS 9.9) Gecko/9999 Distinctive/42", "curl/9.99.9-privacy-probe"}
	var lines []string
	for _, ip := range ips {
		for _, ua := range uas {
			lines = append(lines, human(tsOf("2026-11-05", 2), ip, ua))
		}
	}
	r.write("access.log", lines...)
	in := r.ingester()
	r.run(in)
	salt, _ := readSalt(t, r.salt)

	dump := fmt.Sprintf("%+v\n", r.store.Rows())
	for _, row := range r.store.Rows() {
		dump += fmt.Sprintf("%+v %v %v\n", row, deref(row.Completed), deref(row.Uniq))
	}
	cs, _ := r.store.Cursors(context.Background())
	dump += fmt.Sprintf("%+v\n", cs)
	var needles []string
	for _, ip := range ips {
		needles = append(needles, ip)
		for _, ua := range uas {
			h := salt.ClientHash(ip, ua)
			needles = append(needles, ua, hex.EncodeToString(h[:]), hex.EncodeToString(h[:8]), fmt.Sprintf("%x", h[:]))
		}
	}
	needles = append(needles, hex.EncodeToString(salt.Key[:]))
	for _, n := range needles {
		if strings.Contains(dump, n) {
			t.Fatalf("stored state contains %q:\n%s", n, dump)
		}
	}
	if row := rowOf(t, r.store, "2026-11-05", "DeskRallySupport.exe", ClassHuman); *row.Uniq != 6 {
		t.Fatalf("premise: six distinct clients, got %d", *row.Uniq)
	}
	// The ingest's own log line carries counts only.
	if got := fmt.Sprintf("%+v", Stats{Counted: map[Class]int64{ClassHuman: 6}}); strings.Contains(got, "203.0.113") {
		t.Fatal(got)
	}
}

func ptr(s string) *string { return &s }

func deref(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

// A truncated rolled .log.gz is a real fault, not a clean end: it is counted in Stats.ReadErrors (and logged by
// name) instead of stalling the cursor in silence, and a clean segment is not counted as one.
func TestIngestTruncatedGzipIsReported(t *testing.T) {
	r := newRig(t)
	in := r.ingester()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	for i := 1; i <= 50; i++ {
		zw.Write([]byte(human(tsOf("2026-11-05", 1), "198.51.100.1", "UA") + "\n"))
	}
	zw.Close()
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if err := os.WriteFile(r.path("access-2026-11-05T09-00-00.000.log.gz"), b[:len(b)-12], 0o644); err != nil {
		t.Fatal(err)
	}
	if st := r.run(in); st.ReadErrors != 1 {
		t.Fatalf("ReadErrors = %d, want 1 for a truncated gzip", st.ReadErrors)
	}
	// A rolled .gz never changes: it is given up on (complete), not re-decompressed and re-reported every pass.
	if st := r.run(in); st.ReadErrors != 0 || st.Skipped != 1 {
		t.Fatalf("second pass: ReadErrors = %d, Skipped = %d; want 0 and 1", st.ReadErrors, st.Skipped)
	}
	r2 := newRig(t)
	r2.write("access.log", human(tsOf("2026-11-05", 1), "198.51.100.1", "UA"))
	if st := r2.run(r2.ingester()); st.ReadErrors != 0 {
		t.Fatalf("ReadErrors = %d, want 0 for a clean segment", st.ReadErrors)
	}
}
