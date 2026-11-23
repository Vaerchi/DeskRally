package controlplane

// D2 (review r2): the stream and download routes establish and CHECK a write deadline before any header or
// byte, fail closed when the connection cannot enforce one, and a failed refresh stops the write.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// noDeadlineWriter hides every optional capability of the real writer: its ResponseController cannot set a
// deadline (http.ErrNotSupported), as behind a wrapper that does not implement the interface.
type noDeadlineWriter struct{ http.ResponseWriter }

func TestConsoleStreamAndDownloadFailClosedWithoutADeadline(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(framesA())
	inner := c.srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(noDeadlineWriter{w}, r)
	}))
	t.Cleanup(ts.Close)
	for _, route := range []string{"/segments/0/stream", "/download"} {
		req, _ := http.NewRequest("GET", ts.URL+fx.path(route), nil)
		req.Header.Set("X-Test-Principal", "owner")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", route, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s without deadline support: %d, want 500", route, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "webm") || strings.Contains(ct, "zip") {
			t.Errorf("%s: content type %q was committed before the deadline was established", route, ct)
		}
		if len(body) > 0 && !strings.Contains(string(body), "deadlines_unavailable") {
			t.Errorf("%s: unexpected body %q", route, body)
		}
		if strings.HasPrefix(string(body), "\x1a\x45\xdf\xa3") || strings.HasPrefix(string(body), "PK") {
			t.Errorf("%s released content without a deadline", route)
		}
	}
}

// flakyDeadlineResponse accepts the first SetWriteDeadline and refuses every later one.
type flakyDeadlineResponse struct {
	http.ResponseWriter
	calls  int
	wrote  int
	failAt int // 1-based call number that starts failing
}

func (f *flakyDeadlineResponse) SetWriteDeadline(time.Time) error {
	f.calls++
	if f.calls >= f.failAt {
		return errors.New("deadline refused")
	}
	return nil
}

func (f *flakyDeadlineResponse) Write(p []byte) (int, error) {
	f.wrote += len(p)
	return len(p), nil
}

func TestDeadlineWriterPropagatesRefreshFailuresAndWritesNothing(t *testing.T) {
	f := &flakyDeadlineResponse{ResponseWriter: httptest.NewRecorder(), failAt: 3}
	dw, err := newDeadlineWriter(f, time.Second) // call 1
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dw.Write([]byte("ok")); err != nil { // call 2
		t.Fatalf("first write: %v", err)
	}
	n, err := dw.Write([]byte("must not be sent")) // call 3 fails
	if err == nil || n != 0 || f.wrote != 2 {
		t.Fatalf("a failed deadline refresh still wrote: n=%d err=%v wrote=%d", n, err, f.wrote)
	}
	// And a connection that cannot set a deadline at all is refused up front.
	if _, err := newDeadlineWriter(noDeadlineWriter{httptest.NewRecorder()}, time.Second); err == nil {
		t.Fatal("newDeadlineWriter accepted a writer without deadline support")
	}
}
