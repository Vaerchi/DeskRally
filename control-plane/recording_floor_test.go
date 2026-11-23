package controlplane

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordingFloorFromEnv(t *testing.T) {
	ok := []struct {
		in   string
		want uint64
	}{
		{"", 5 << 30},       // unset/empty = the built-in 5 GiB
		{"   ", 5 << 30},    // whitespace-only counts as empty
		{"512", 512 << 20},  // the minimum
		{"5120", 5 << 30},   // the default spelled out
		{" 8192 ", 8 << 30}, // trimmed
		{"1048576", 1 << 40},
	}
	for _, c := range ok {
		got, err := RecordingFloorFromEnv(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: got %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	// Nonsense is an ERROR naming the variable, never a silent fall-back to some other floor.
	for _, in := range []string{"abc", "0", "-5", "511", "1048577", "5.5", "5GiB", "0x2000", "5368709120" /* bytes typed as MiB */} {
		got, err := RecordingFloorFromEnv(in)
		if err == nil || got != 0 || !strings.Contains(err.Error(), "RECORDING_DISK_FLOOR_MIB") {
			t.Errorf("%q: got %d, %v; want a refusal naming RECORDING_DISK_FLOOR_MIB", in, got, err)
		}
		// ...and never echoes the offending value back (only the multi-character, non-numeric ones can be
		// told apart from the bounds that the message legitimately prints).
		if err != nil && (in == "abc" || in == "5GiB" || in == "0x2000" || in == "5368709120" || in == "5.5") && strings.Contains(err.Error(), in) {
			t.Errorf("%q: the error echoes the raw value: %v", in, err)
		}
	}
}

func TestRecordingUploadConfigDefaultFloorIsFiveGiB(t *testing.T) {
	if got := (RecordingUploadConfig{}).withDefaults().FloorBytes; got != 5<<30 {
		t.Fatalf("default floor = %d, want 5 GiB", got)
	}
	if got := (RecordingUploadConfig{FloorBytes: 7 << 30}).withDefaults().FloorBytes; got != 7<<30 {
		t.Fatalf("an explicit floor was overwritten: %d", got)
	}
}

// captureLog collects log output for the test (the package logs through the std logger).
func captureLog(t *testing.T) *lockedBuf {
	t.Helper()
	b := &lockedBuf{}
	old := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuf) count(sub string) int { return strings.Count(l.String(), sub) }

// A create refused for the disk floor logs the ALERT at once (not only on the 5-minute sweep tick), and a
// burst of refusals logs it at most once a minute.
func TestRecordingCreateRefusalAlertsAndIsRateLimited(t *testing.T) {
	free := uint64(1 << 20) // far below floor + reservation
	h := newRecH(t, recHOpts{cfg: RecordingUploadConfig{FloorBytes: 100 << 20, FreeBytes: func() (uint64, error) { return free, nil }}})
	var offset time.Duration
	var mu sync.Mutex
	h.srv.Recording.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(offset) }
	buf := captureLog(t)

	refuse := func() {
		t.Helper()
		u := newRecUpload(1000)
		if st, m, _ := h.do(call{op: UploadOpCreate, rec: u.id, body: h.createBodyFor(u, h.session, 1)}); st != 507 {
			t.Fatalf("create: %d %v, want 507", st, m)
		}
	}
	for i := 0; i < 25; i++ {
		refuse()
	}
	if n := buf.count("ALERT a create was refused"); n != 1 {
		t.Fatalf("a burst of 25 refusals logged %d ALERT lines, want exactly 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "floor 104857600") {
		t.Fatalf("the ALERT does not state the floor: %s", buf.String())
	}
	mu.Lock()
	offset = 61 * time.Second
	mu.Unlock()
	refuse()
	refuse()
	if n := buf.count("ALERT a create was refused"); n != 2 {
		t.Fatalf("after a minute the next refusal must alert again once; got %d lines total", n)
	}
	// A clock stepped BACKWARDS must not reopen the window (checked directly: the HTTP path's own per-IP
	// limiter would answer 429 before reaching the alert).
	before0 := buf.count("ALERT a create was refused")
	mu.Lock()
	offset = 0 // was +61s: a 61 second step back
	mu.Unlock()
	lim := RecordingCreateLimits{FreeKnown: true, FreeBytes: 1, FloorBytes: 100 << 20}
	h.srv.Recording.alertFloorRefusal(lim)
	h.srv.Recording.alertFloorRefusal(lim)
	if n := buf.count("ALERT a create was refused"); n != before0 {
		t.Fatalf("a backward clock step bypassed the one-minute suppression; %d -> %d lines", before0, n)
	}
	// A refusal that is NOT about room does not alert (storage off here would be 403, quota 507 tenant_quota).
	before := buf.count("ALERT")
	h2 := newRecH(t, recHOpts{noPolicy: true})
	u := newRecUpload(100)
	if st, _, _ := h2.do(call{op: UploadOpCreate, rec: u.id, body: h2.createBodyFor(u, h2.session, 1)}); st != 403 {
		t.Fatalf("storage off: %d", st)
	}
	if buf.count("ALERT") != before {
		t.Fatalf("a storage_off refusal raised a disk ALERT")
	}
}

func TestRecordingFloorAlertWhenVolumeUnmeasurable(t *testing.T) {
	w := &RecordingWiring{}
	buf := captureLog(t)
	w.alertFloorRefusal(RecordingCreateLimits{FloorBytes: 5 << 30})
	w.alertFloorRefusal(RecordingCreateLimits{FloorBytes: 5 << 30})
	if buf.count("could not be measured") != 1 {
		t.Fatalf("unmeasurable volume alert: %q", buf.String())
	}
}
