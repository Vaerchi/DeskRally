package controlplane

// Review r2 cross-part checks: X1 (bounded ReadRange) and X2 (logical expiry before the sweeper runs).

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// X1: one ReadRange call never allocates an unbounded slice; larger spans are the caller's to stream.
func TestEnvelopeReadRangeIsBounded(t *testing.T) {
	total := EnvMaxReadRange + 3*EnvFrameSize
	e := newEnvFixture(t, total)
	plain := randBytes(total)
	path := filepath.Join(t.TempDir(), "seg.enc")
	writeEnvFile(t, e, plain, path)
	r, err := openEnvFile(t, e, path, false)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := r.ReadRange(0, EnvMaxReadRange); err != nil || len(b) != EnvMaxReadRange {
		t.Fatalf("a range at the bound: %d bytes, %v", len(b), err)
	}
	if b, err := r.ReadRange(0, EnvMaxReadRange+1); !errors.Is(err, ErrEnvelopeRange) || b != nil {
		t.Fatalf("a range over the bound: %d bytes, %v; want ErrEnvelopeRange and no allocation", len(b), err)
	}
	if _, err := r.ReadRange(1, int64(total)); !errors.Is(err, ErrEnvelopeRange) {
		t.Fatalf("a range past the end: %v", err)
	}
	// The same bound for a huge request against the declared maximum: refused before anything is allocated.
	if _, err := r.ReadRange(0, 8<<30); !errors.Is(err, ErrEnvelopeRange) {
		t.Fatalf("an 8 GiB range: %v", err)
	}
}

// X2: past expires_at the recording is expired for every route even though no sweep has flipped the state.
func TestConsoleRefusesARecordingPastItsLogicalExpiryBeforeTheSweeper(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	if st, _, _ := c.get("owner", fx.path("/segments/0/stream")); st != 200 {
		t.Fatalf("before expiry: %d", st)
	}
	u := ivfUpload(buildIVF(320, 200, 90000, 1, framesA(), uint32(len(framesA()))))
	c.completeUpload(u)            // uploaded while the clock is still inside the window
	c.advance(31 * 24 * time.Hour) // retention is 30 days; NO sweep runs
	if got := c.row(fx.u).State; got != RecPlaybackReady {
		t.Fatalf("test bug: the sweeper must not have run (state %s)", got)
	}
	for _, route := range []string{"/playlist", "/segments/0/stream", "/download"} {
		st, _, body := c.get("owner", fx.path(route))
		if st != http.StatusGone {
			t.Errorf("%s past its expiry: %d %s, want 410", route, st, body)
		}
		if len(body) > 0 && (body[0] == 0x1a || (len(body) > 1 && body[0] == 'P' && body[1] == 'K')) {
			t.Errorf("%s released content after expiry", route)
		}
	}
	st, _, body := c.get("owner", fx.path(""))
	if st != 200 || jsonOf(t, body)["state"] != RecExpired || jsonOf(t, body)["playable"] != false {
		t.Fatalf("detail past expiry: %d %s", st, body)
	}
	st, _, body = c.get("owner", "/recordings")
	if st != 200 {
		t.Fatalf("list: %d", st)
	}
	items, _ := jsonOf(t, body)["recordings"].([]any)
	if len(items) != 2 {
		t.Fatalf("list: %s", body)
	}
	for _, x := range items {
		if it, _ := x.(map[string]any); it["state"] != RecExpired || it["playable"] != false {
			t.Fatalf("list item past expiry: %v", it)
		}
	}
	// And the muxer does not build a copy for it.
	if err := c.srv.MuxRecording(t.Context(), c.tenant, u.id); err != nil {
		t.Fatal(err)
	}
	if c.row(u).State != RecEvidenceComplete {
		t.Fatalf("a logically expired recording was remuxed: %s", c.row(u).State)
	}
	if _, err := os.Stat(filepath.Join(c.dir, c.tenant, u.id, segName(0, RepWebM))); err == nil {
		t.Fatal("a playback file was written for an expired recording")
	}
}
