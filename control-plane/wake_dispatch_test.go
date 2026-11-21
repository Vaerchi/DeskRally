package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type wakeRoundTripper func(*http.Request) (*http.Response, error)

func (f wakeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPWakeDispatcher(t *testing.T) {
	incarnation := newUUID()
	d := HTTPWakeDispatcher{
		BaseURL: "http://signaling.invalid/",
		Token:   "test-service-auth",
	}
	ctx := context.Background()
	install := func(code int, body string, check func(*http.Request)) {
		d.Client = &http.Client{Transport: wakeRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+d.Token {
				t.Fatal("incorrect internal request authentication or method")
			}
			check(r)
			if code == 0 {
				return nil, errors.New("transport failed")
			}
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	checkContext := func(r *http.Request) {
		if r.URL.EscapedPath() != "/internal/devices/relay%2Fid/wake-context" || r.ContentLength != 0 {
			t.Fatal("incorrect wake-context route or body")
		}
	}
	install(200, `{"conn_ref":{"incarnation":"`+incarnation+`","generation":7},"epoch":9,
		"challenge":"11000000000000000000000000000000",
		"device_key_sha256":"2200000000000000000000000000000000000000000000000000000000000000"}`, checkContext)
	got, outcome := d.WakeContext(ctx, "relay/id")
	if outcome != WakeContextReady || got.ConnRef != (WakeConnRef{Incarnation: incarnation, Generation: 7}) ||
		got.Epoch != 9 || got.Challenge != ([16]byte{0x11}) || got.DeviceKeySHA256 != ([32]byte{0x22}) {
		t.Fatal("incorrect decoded wake context")
	}
	for _, tc := range []struct {
		code int
		body string
		want WakeOutcome
	}{
		{409, `{"error":"not_ready"}`, WakeNotReady},
		{409, `{"error":"not_written"}`, WakeNoAnswer},
		{409, `{"error":`, WakeNoAnswer},
		{409, `{"error":"not_ready"}` + strings.Repeat(" ", 4096), WakeNoAnswer},
		{200, "{}", WakeNoAnswer},
		{0, "", WakeNoAnswer},
	} {
		install(tc.code, tc.body, checkContext)
		if _, outcome := d.WakeContext(ctx, "relay/id"); outcome != tc.want {
			t.Errorf("context HTTP %d produced %q, want %q", tc.code, outcome, tc.want)
		}
	}
	checkForward := func(r *http.Request) {
		if r.URL.EscapedPath() != "/internal/devices/relay%2Fid/wake" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("incorrect wake route or content type")
		}
		var body struct {
			Ref      WakeConnRef     `json:"conn_ref"`
			Artifact json.RawMessage `json:"artifact"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			body.Ref != got.ConnRef || string(body.Artifact) != `{"sig":"fixture"}` {
			t.Fatal("incorrect wake forward body")
		}
	}
	for _, tc := range []struct {
		code int
		body string
		want WakeOutcome
	}{
		{202, "", WakeWritten},
		{409, `{"error":"not_written"}`, WakeNotWritten},
		{409, `{"error":"not_ready"}`, WakeNoAnswer},
		{409, `{"error":"other","error":"not_written"}`, WakeNoAnswer},
		{409, `{"error":`, WakeNoAnswer},
		{409, `{"error":"not_written"} {}`, WakeNoAnswer},
		{409, `{"error":"not_written"}` + strings.Repeat(" ", 4096), WakeNoAnswer},
		{502, `{"error":"write_failed"}`, WakeWriteFailed},
		{502, "", WakeNoAnswer},
		{500, `{"error":"not_written"}`, WakeNoAnswer},
		{0, "", WakeNoAnswer},
	} {
		install(tc.code, tc.body, checkForward)
		if outcome := d.Forward(ctx, "relay/id", got.ConnRef, []byte(`{"sig":"fixture"}`)); outcome != tc.want {
			t.Errorf("forward HTTP %d produced %q, want %q", tc.code, outcome, tc.want)
		}
	}
}
