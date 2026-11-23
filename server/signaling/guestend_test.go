package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const guestEndTestSession = "12345678-1234-1234-1234-123456789abc"

// Embedding avoids guessing the rest of peerConn; dispatch needs only these two methods.
// A channel keeps asynchronous replies observable without racing a fake's message slice.
type guestEndTestConn struct {
	peerConn
	sent chan ServerToClient
}

func (c *guestEndTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *guestEndTestConn) WriteJSON(v interface{}) error {
	c.sent <- v.(ServerToClient)
	return nil
}

func guestEndTestReply(t *testing.T, c *guestEndTestConn) ServerToClient {
	t.Helper()
	select {
	case msg := <-c.sent:
		return msg
	case <-time.After(4 * time.Second):
		t.Fatal("missing guest end reply")
		return ServerToClient{}
	}
}

func guestEndTestReporter(t *testing.T, base string) *GuestEndReporter {
	t.Helper()
	r, err := newHTTPGuestEndReporter(base, strings.Repeat("x", 256))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// guestEndStubResolver stands in for the control-plane identity resolver: its presence is what marks
// agent authentication as enforced; the dispatch path never calls it.
type guestEndStubResolver struct{}

func (guestEndStubResolver) Resolve(context.Context, string) (*DeviceIdentity, error) {
	return nil, ErrDeviceUnknown
}

func TestGuestEndDispatch(t *testing.T) {
	var calls int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		if req.Method != http.MethodPost || req.URL.Path != "/internal/sessions/"+guestEndTestSession+"/guest-ended" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		if req.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 256) || req.Header.Get("Content-Type") != "application/json" {
			t.Error("missing service headers")
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body) != 2 || body["device_id"] != "authenticated-device" || body["tenant_id"] != "authenticated-tenant" {
			t.Errorf("unexpected body: %#v, %v", body, err)
		}
		_, _ = w.Write([]byte(`{"outcome":"ended"}`))
	}))
	defer cp.Close()
	authed := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	// Dev mode: no identity resolver, so "registered" only means "asserted" — never reported.
	devMode := &Server{guestEnd: guestEndTestReporter(t, cp.URL)}
	for _, tc := range []struct {
		name       string
		server     *Server
		registered bool
		id         string
		limited    bool
		outcome    string
		wantCalls  int32
	}{
		{"unregistered", authed, false, guestEndTestSession, false, "", 0},
		{"malformed", authed, true, "../bad", false, "refused", 0},
		{"rate limited", authed, true, guestEndTestSession, true, "unavailable", 0},
		{"registered", authed, true, guestEndTestSession, false, "ended", 1},
		{"dev mode asserted device", devMode, true, guestEndTestSession, false, "refused", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.server
			atomic.StoreInt32(&calls, 0)
			c := &guestEndTestConn{sent: make(chan ServerToClient, 1)}
			p := &Peer{conn: c, registered: tc.registered, DeviceId: "authenticated-device", Tenant: "authenticated-tenant"}
			if tc.limited {
				for i := 0; i < 30; i++ {
					p.guestEndTimes = append(p.guestEndTimes, time.Now())
				}
			}
			// Sibling decoding is permissive; extra identity fields must have no effect.
			raw, _ := json.Marshal(map[string]string{"type": "guest_ended_session", "control_plane_session": tc.id, "device_id": "forged", "tenant_id": "forged"})
			var msg ClientToServer
			if err := json.Unmarshal(raw, &msg); err != nil {
				t.Fatal(err)
			}
			s.dispatch(p, msg)
			got := guestEndTestReply(t, c)
			if !tc.registered {
				if _, ok := got.Payload.(Rejected); !ok || got.Type != "rejected" {
					t.Fatalf("expected rejection, got %#v", got)
				}
			} else {
				result, ok := got.Payload.(GuestEndedResult)
				if !ok || result.Outcome != tc.outcome || result.ControlPlaneSession != tc.id || got.Type != "guest_ended_result" {
					t.Fatalf("unexpected result: %#v", got)
				}
			}
			if got := atomic.LoadInt32(&calls); got != tc.wantCalls {
				t.Fatalf("requests = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestGuestEndOutcomeMapping(t *testing.T) {
	for _, tc := range []struct {
		status   int
		body     string
		outcome  string
		attempts int32
	}{
		{200, `{"outcome":"ended"}`, "ended", 1},
		{200, `{"outcome":"already_ended"}`, "already_ended", 1},
		{200, `{"outcome":"unknown"}`, "unavailable", 1},
		{200, `{`, "unavailable", 1},
		{400, `{}`, "refused", 1},
		{401, `{}`, "unavailable", 1},
		{403, `{}`, "refused", 1},
		{404, `{}`, "refused", 1},
		{429, `{}`, "unavailable", 1},
		{503, `{"outcome":"unavailable"}`, "unavailable", 3},
	} {
		t.Run(http.StatusText(tc.status)+tc.body, func(t *testing.T) {
			var calls int32
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer cp.Close()
			r := guestEndTestReporter(t, cp.URL)
			if got := r.Report(context.Background(), guestEndTestSession, "device", "tenant"); got != tc.outcome {
				t.Fatalf("outcome = %q, want %q", got, tc.outcome)
			}
			if got := atomic.LoadInt32(&calls); got != tc.attempts {
				t.Fatalf("attempts = %d, want %d", got, tc.attempts)
			}
		})
	}
}

func TestGuestEndNotConfigured(t *testing.T) {
	var calls int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer cp.Close()
	for _, config := range [][2]string{{cp.URL, ""}, {"", strings.Repeat("x", 256)}} {
		r, err := newHTTPGuestEndReporter(config[0], config[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := r.Report(context.Background(), guestEndTestSession, "device", "tenant"); got != "unavailable" {
			t.Fatalf("outcome = %q", got)
		}
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("unconfigured reporter contacted CP")
	}
}

func TestGuestEndSaturation(t *testing.T) {
	entered := make(chan struct{}, 9)
	release := make(chan struct{})
	var calls int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte(`{"outcome":"ended"}`))
	}))
	defer cp.Close()
	r := guestEndTestReporter(t, cp.URL)
	done := make(chan string, 8)
	// Cleanup releases handlers even when an assertion fails, then joins all report workers.
	defer func() {
		close(release)
		for i := 0; i < 8; i++ {
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Error("report worker did not finish")
			}
		}
	}()
	for i := 0; i < 8; i++ {
		go func() { done <- r.Report(context.Background(), guestEndTestSession, "device", "tenant") }()
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("eight requests did not reach CP")
		}
	}
	// A second reporter must share the same process-wide ceiling.
	other := guestEndTestReporter(t, cp.URL)
	ninth := make(chan string, 1)
	go func() { ninth <- other.Report(context.Background(), guestEndTestSession, "device", "tenant") }()
	select {
	case got := <-ninth:
		if got != "unavailable" {
			t.Fatalf("ninth outcome = %q", got)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("saturated reporter waited for capacity")
	}
	if atomic.LoadInt32(&calls) != 8 {
		t.Fatal("ninth request reached CP")
	}
}

func TestGuestEndRollingLimit(t *testing.T) {
	p := &Peer{}
	now := time.Now()
	for i := 0; i < 30; i++ {
		if !p.allowGuestEnd(now) {
			t.Fatalf("report %d refused early", i)
		}
	}
	if p.allowGuestEnd(now.Add(59 * time.Second)) {
		t.Fatal("31st report admitted within a minute")
	}
	if !p.allowGuestEnd(now.Add(time.Minute)) {
		t.Fatal("expired budget was not restored")
	}
}

func TestGuestEndWireRoundTrip(t *testing.T) {
	clientRaw, err := json.Marshal(ClientToServer{Payload: GuestEndedSession{ControlPlaneSession: guestEndTestSession}})
	if err != nil {
		t.Fatal(err)
	}
	var client ClientToServer
	if err := json.Unmarshal(clientRaw, &client); err != nil {
		t.Fatal(err)
	}
	p, ok := client.Payload.(*GuestEndedSession)
	if !ok || client.Type != "guest_ended_session" || p.ControlPlaneSession != guestEndTestSession {
		t.Fatalf("unexpected client message: %#v", client)
	}
	serverRaw, err := json.Marshal(ServerToClient{Payload: GuestEndedResult{ControlPlaneSession: guestEndTestSession, Outcome: "ended"}})
	if err != nil {
		t.Fatal(err)
	}
	var server ServerToClient
	if err := json.Unmarshal(serverRaw, &server); err != nil {
		t.Fatal(err)
	}
	result, ok := server.Payload.(*GuestEndedResult)
	if !ok || server.Type != "guest_ended_result" || result.ControlPlaneSession != guestEndTestSession || result.Outcome != "ended" {
		t.Fatalf("unexpected server message: %#v", server)
	}
}
