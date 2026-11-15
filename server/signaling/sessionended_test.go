package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func withSessionEndedSupported(t *testing.T, v bool) {
	t.Helper()
	prev := sessionEndedSupported.Load()
	sessionEndedSupported.Store(v)
	t.Cleanup(func() { sessionEndedSupported.Store(prev) })
}

func sessionEndedDispatch(t *testing.T, s *Server, p *Peer, fields map[string]any) ServerToClient {
	t.Helper()
	c := p.conn.(*guestEndTestConn)
	fields["type"] = "session_ended"
	raw, _ := json.Marshal(fields)
	var msg ClientToServer
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	s.dispatch(p, msg)
	return guestEndTestReply(t, c)
}

// The agent's report reaches /ended with the CONNECTION's identity, a bounded reason and a clamped
// queue age; dev mode and unregistered peers never reach the control plane.
func TestSessionEndedDispatch(t *testing.T) {
	type seen struct {
		path string
		body map[string]any
	}
	got := make(chan seen, 8)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		got <- seen{req.URL.Path, body}
		_, _ = w.Write([]byte(`{"outcome":"ended"}`))
	}))
	defer cp.Close()
	authed := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	newPeer := func(registered bool) *Peer {
		return &Peer{conn: &guestEndTestConn{sent: make(chan ServerToClient, 1)}, registered: registered,
			DeviceId: "authenticated-device", Tenant: "authenticated-tenant"}
	}
	for _, tc := range []struct {
		name      string
		reason    any
		age       any
		wantReas  string
		wantAge   any // nil = absent
		wantAgeOK bool
	}{
		{"plain", "lease_lapsed", 1500, "lease_lapsed", float64(1500), true},
		{"no age", "idle", nil, "idle", nil, true},
		{"unknown shape reason", "Robert'); DROP", 5, "other", float64(5), true},
		{"overlong reason", strings.Repeat("a", 33), 5, "other", float64(5), true},
		{"negative age dropped", "policy", -7, "policy", nil, true},
		{"huge age clamped", "service_stop", int64(1) << 50, "service_stop", float64(maxQueueAgeMs), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]any{"control_plane_session": guestEndTestSession, "reason": tc.reason,
				"device_id": "forged", "tenant_id": "forged"}
			if tc.age != nil {
				fields["queue_age_ms"] = tc.age
			}
			reply := sessionEndedDispatch(t, authed, newPeer(true), fields)
			res, ok := reply.Payload.(SessionEndedResult)
			if !ok || reply.Type != "session_ended_result" || res.Outcome != "ended" || res.ControlPlaneSession != guestEndTestSession {
				t.Fatalf("reply = %#v", reply)
			}
			var s seen
			select {
			case s = <-got:
			case <-time.After(4 * time.Second):
				t.Fatal("no request reached the control plane")
			}
			if s.path != "/internal/sessions/"+guestEndTestSession+"/ended" {
				t.Fatalf("path = %s", s.path)
			}
			if s.body["device_id"] != "authenticated-device" || s.body["tenant_id"] != "authenticated-tenant" || s.body["reason"] != tc.wantReas {
				t.Fatalf("body = %#v", s.body)
			}
			if age, present := s.body["queue_age_ms"]; (tc.wantAge == nil) == present || (present && age != tc.wantAge) {
				t.Fatalf("queue_age_ms = %#v (present %v), want %#v", age, present, tc.wantAge)
			}
		})
	}
	t.Run("dev mode refused", func(t *testing.T) {
		dev := &Server{guestEnd: guestEndTestReporter(t, cp.URL)}
		reply := sessionEndedDispatch(t, dev, newPeer(true), map[string]any{"control_plane_session": guestEndTestSession, "reason": "idle"})
		if res, ok := reply.Payload.(SessionEndedResult); !ok || res.Outcome != "refused" {
			t.Fatalf("reply = %#v", reply)
		}
	})
	t.Run("unregistered rejected", func(t *testing.T) {
		reply := sessionEndedDispatch(t, authed, newPeer(false), map[string]any{"control_plane_session": guestEndTestSession, "reason": "idle"})
		if _, ok := reply.Payload.(Rejected); !ok {
			t.Fatalf("reply = %#v", reply)
		}
	})
	t.Run("malformed id refused", func(t *testing.T) {
		reply := sessionEndedDispatch(t, authed, newPeer(true), map[string]any{"control_plane_session": "../x", "reason": "idle"})
		if res, ok := reply.Payload.(SessionEndedResult); !ok || res.Outcome != "refused" {
			t.Fatalf("reply = %#v", reply)
		}
	})
	t.Run("one budget for both report kinds", func(t *testing.T) {
		p := newPeer(true)
		for i := 0; i < 30; i++ {
			p.guestEndTimes = append(p.guestEndTimes, time.Now())
		}
		reply := sessionEndedDispatch(t, authed, p, map[string]any{"control_plane_session": guestEndTestSession, "reason": "idle"})
		if res, ok := reply.Payload.(SessionEndedResult); !ok || res.Outcome != "unavailable" {
			t.Fatalf("reply = %#v", reply)
		}
	})
	select {
	case s := <-got:
		t.Fatalf("an unexpected request reached the control plane: %+v", s)
	default:
	}
}

// docs/49 v4: a missing route (404 without the handler's error, or the 401 an unmounted internal
// route answers) is RETRYABLE; only the handler's own "session not found" is terminal.
func TestSessionEndedOutcomeMapping(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		outcome  string
		attempts int32
	}{
		{"ended", 200, `{"outcome":"ended"}`, "ended", 1},
		{"already", 200, `{"outcome":"already_ended"}`, "already_ended", 1},
		{"handler not found", 404, `{"error":"session not found"}`, "refused", 1},
		{"unknown device", 404, `{"error":"unknown device"}`, "unavailable", 1},
		{"route absent 404", 404, "404 page not found\n", "unavailable", 1},
		{"route absent 401", 401, `{"error":"unauthorized"}`, "unavailable", 1},
		{"bad request", 400, `{}`, "refused", 1},
		{"other device", 403, `{}`, "refused", 1},
		{"transient", 503, `{"outcome":"unavailable"}`, "unavailable", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer cp.Close()
			r := guestEndTestReporter(t, cp.URL)
			if got := r.reportEnded(context.Background(), guestEndTestSession, "d", "t", "idle", nil); got != tc.outcome {
				t.Fatalf("outcome = %q, want %q", got, tc.outcome)
			}
			if got := atomic.LoadInt32(&calls); got != tc.attempts {
				t.Fatalf("attempts = %d, want %d", got, tc.attempts)
			}
		})
	}
	// The guest-ended route keeps its original mapping: any 404 is terminal there.
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(404)
	}))
	defer cp.Close()
	if got := guestEndTestReporter(t, cp.URL).Report(context.Background(), guestEndTestSession, "d", "t"); got != "refused" {
		t.Fatalf("guest-ended 404 = %q", got)
	}
}

func TestCapabilityProbe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   probeOutcome
	}{
		{"supported", 200, `{"features":["session_ended_v1"]}`, probeSupported},
		{"supported among others", 200, `{"features":["x","session_ended_v1"]}`, probeSupported},
		{"not listed", 200, `{"features":[]}`, probeUnsupported},
		{"route absent 404", 404, "404 page not found", probeUnsupported},
		{"older CP 401", 401, `{"error":"unauthorized"}`, probeUnsupported},
		{"forbidden", 403, `{}`, probeUnsupported},
		{"transient", 503, `{}`, probeUnsettled},
		{"garbage", 200, `{`, probeUnsettled},
		{"oversized", 200, `{"features":["` + strings.Repeat("a", 5000) + `"]}`, probeUnsettled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet || req.URL.Path != "/internal/capabilities" || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 256) {
					t.Errorf("unexpected probe: %s %s", req.Method, req.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer cp.Close()
			if got := guestEndTestReporter(t, cp.URL).probeCapabilities(context.Background()); got != tc.want {
				t.Fatalf("probe = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("network error is unsettled", func(t *testing.T) {
		cp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		base := cp.URL
		cp.Close()
		if got := guestEndTestReporter(t, base).probeCapabilities(context.Background()); got != probeUnsettled {
			t.Fatalf("probe = %v", got)
		}
	})
	t.Run("unconfigured is unsupported", func(t *testing.T) {
		r, _ := newHTTPGuestEndReporter("", "")
		if got := r.probeCapabilities(context.Background()); got != probeUnsupported {
			t.Fatalf("probe = %v", got)
		}
	})
}

// The refresh flips what NEW registrations are told, and a transient failure keeps the last
// definitive answer.
func TestCapabilityRefreshFlipsRegistered(t *testing.T) {
	withSessionEndedSupported(t, false)
	authed, err := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := NewServer(time.Minute, "relay-1:4444", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenanted := &Peer{Tenant: "authenticated-tenant"}
	features := func(s *Server) string {
		raw, err := json.Marshal(ServerToClient{Payload: s.registeredMsg(tenanted)})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if strings.Contains(features(authed), "features") {
		t.Fatalf("advertised before any probe: %s", features(authed))
	}
	if d := applyProbe(probeSupported); d != capabilityRefresh {
		t.Fatalf("settled delay = %v", d)
	}
	if !strings.Contains(features(authed), `"features":["session_ended_v1"]`) {
		t.Fatalf("not advertised after a positive probe: %s", features(authed))
	}
	if d := applyProbe(probeUnsettled); d != capabilityRetry || !sessionEndedSupported.Load() {
		t.Fatalf("a transient failure changed the answer (delay %v)", d)
	}
	// Dev mode never advertises: every end report would be refused there.
	if strings.Contains(features(dev), "features") {
		t.Fatalf("dev mode advertised: %s", features(dev))
	}
	// A connection without a control-plane tenant would have every report refused locally.
	if raw, _ := json.Marshal(ServerToClient{Payload: authed.registeredMsg(&Peer{})}); strings.Contains(string(raw), "features") {
		t.Fatalf("advertised to a tenantless connection: %s", raw)
	}
	applyProbe(probeUnsupported)
	if strings.Contains(features(authed), "features") {
		t.Fatalf("still advertised after a rollback: %s", features(authed))
	}
}

func TestSessionEndedWireRoundTrip(t *testing.T) {
	age := int64(42)
	raw, err := json.Marshal(ClientToServer{Payload: SessionEnded{ControlPlaneSession: guestEndTestSession, Reason: "idle", QueueAgeMs: &age}})
	if err != nil {
		t.Fatal(err)
	}
	var client ClientToServer
	if err := json.Unmarshal(raw, &client); err != nil {
		t.Fatal(err)
	}
	p, ok := client.Payload.(*SessionEnded)
	if !ok || client.Type != "session_ended" || p.Reason != "idle" || p.QueueAgeMs == nil || *p.QueueAgeMs != 42 {
		t.Fatalf("client message: %#v", client)
	}
	raw, err = json.Marshal(ServerToClient{Payload: SessionEndedResult{ControlPlaneSession: guestEndTestSession, Outcome: "refused"}})
	if err != nil {
		t.Fatal(err)
	}
	var server ServerToClient
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	if r, ok := server.Payload.(*SessionEndedResult); !ok || server.Type != "session_ended_result" || r.Outcome != "refused" {
		t.Fatalf("server message: %#v", server)
	}
}

// Codex review (signaling slice): a control plane at 3b47aac serves /ended and advertises
// session_ended_v1 but its strict decoder refuses queue_age_ms with 400. Against such a replica
// the report must still close the row, never be dropped as refused.
func TestSessionEndedQueueAgeCompatibility(t *testing.T) {
	strictPre37ac4ee := func(w http.ResponseWriter, req *http.Request) {
		dec := json.NewDecoder(req.Body)
		dec.DisallowUnknownFields()
		var body struct {
			DeviceID string `json:"device_id"`
			TenantID string `json:"tenant_id"`
			Reason   string `json:"reason"`
		}
		if dec.Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid session end"}`))
			return
		}
		_, _ = w.Write([]byte(`{"outcome":"ended"}`))
	}
	alwaysBad := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}
	age := int64(900)
	for _, tc := range []struct {
		name     string
		handler  http.HandlerFunc
		age      *int64
		outcome  string
		requests int32
		lastAge  bool
	}{
		{"pre-37ac4ee CP, age sent", strictPre37ac4ee, &age, "ended", 2, false},
		{"pre-37ac4ee CP, no age", strictPre37ac4ee, nil, "ended", 1, false},
		{"400 without age is terminal", alwaysBad, nil, "refused", 1, false},
		{"400 after the resend is terminal", alwaysBad, &age, "refused", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			var lastHadAge atomic.Bool
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				atomic.AddInt32(&calls, 1)
				raw := new(strings.Builder)
				_, _ = io.Copy(raw, req.Body)
				lastHadAge.Store(strings.Contains(raw.String(), "queue_age_ms"))
				req.Body = io.NopCloser(strings.NewReader(raw.String()))
				tc.handler(w, req)
			}))
			defer cp.Close()
			if got := guestEndTestReporter(t, cp.URL).reportEnded(context.Background(), guestEndTestSession, "d", "t", "idle", tc.age); got != tc.outcome {
				t.Fatalf("outcome = %q, want %q", got, tc.outcome)
			}
			if got := atomic.LoadInt32(&calls); got != tc.requests {
				t.Fatalf("requests = %d, want %d", got, tc.requests)
			}
			if lastHadAge.Load() != tc.lastAge {
				t.Fatalf("last request carried queue_age_ms = %v", lastHadAge.Load())
			}
		})
	}
}

// Parity with guest_ended_session: the two report kinds share one per-peer budget and one
// process-wide semaphore, and a saturated semaphore answers unavailable without reaching the CP.
func TestSessionEndedSharesGuestEndLimits(t *testing.T) {
	var calls int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"outcome":"ended"}`))
	}))
	defer cp.Close()
	authed := &Server{guestEnd: guestEndTestReporter(t, cp.URL), identity: guestEndStubResolver{}}
	p := &Peer{conn: &guestEndTestConn{sent: make(chan ServerToClient, 1)}, registered: true,
		DeviceId: "authenticated-device", Tenant: "authenticated-tenant"}
	// 30 guest-ended reports spend the budget the session_ended report then needs.
	for i := 0; i < 30; i++ {
		if !p.allowGuestEnd(time.Now()) {
			t.Fatalf("guest-end %d refused early", i)
		}
	}
	reply := sessionEndedDispatch(t, authed, p, map[string]any{"control_plane_session": guestEndTestSession, "reason": "idle"})
	if res, ok := reply.Payload.(SessionEndedResult); !ok || res.Outcome != "unavailable" {
		t.Fatalf("budget: %#v", reply)
	}
	p.guestEndTimes = nil
	for i := 0; i < cap(guestEndSlots); i++ {
		guestEndSlots <- struct{}{}
	}
	reply = sessionEndedDispatch(t, authed, p, map[string]any{"control_plane_session": guestEndTestSession, "reason": "idle"})
	for i := 0; i < cap(guestEndSlots); i++ {
		<-guestEndSlots
	}
	if res, ok := reply.Payload.(SessionEndedResult); !ok || res.Outcome != "unavailable" {
		t.Fatalf("saturation: %#v", reply)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("a limited report reached the control plane")
	}
	// An empty tenant (no control-plane identity) is refused like guest_ended.
	p.Tenant = ""
	reply = sessionEndedDispatch(t, authed, p, map[string]any{"control_plane_session": guestEndTestSession, "reason": "idle"})
	if res, ok := reply.Payload.(SessionEndedResult); !ok || res.Outcome != "refused" {
		t.Fatalf("empty tenant: %#v", reply)
	}
}

func withCapabilitySettledOnce(t *testing.T, v bool) {
	t.Helper()
	prev := capabilitySettledOnce.Load()
	capabilitySettledOnce.Store(v)
	t.Cleanup(func() { capabilitySettledOnce.Store(prev) })
}

// Until the first definitive answer since start, an unsettled probe retries fast: right after a
// deploy the fleet re-registers while the control plane may still be starting.
func TestCapabilityStartupRetry(t *testing.T) {
	withSessionEndedSupported(t, false)
	withCapabilitySettledOnce(t, false)
	if d := applyProbe(probeUnsettled); d != capabilityStartupRetry {
		t.Fatalf("unsettled before any answer: delay %v, want %v", d, capabilityStartupRetry)
	}
	if d := applyProbe(probeSupported); d != capabilityRefresh {
		t.Fatalf("settled: delay %v", d)
	}
	if d := applyProbe(probeUnsettled); d != capabilityRetry {
		t.Fatalf("unsettled after an answer: delay %v, want %v", d, capabilityRetry)
	}
}

// onSupported runs exactly once per flip to supported, never on a refresh or a transient failure.
func TestApplyProbeAndNotify(t *testing.T) {
	withSessionEndedSupported(t, false)
	withCapabilitySettledOnce(t, false)
	calls := 0
	on := func() { calls++ }
	for i, step := range []struct {
		o    probeOutcome
		want int
	}{
		{probeUnsettled, 0},
		{probeSupported, 1},
		{probeSupported, 1}, // a refresh is not a flip
		{probeUnsettled, 1},
		{probeUnsupported, 1}, // a rollback
		{probeSupported, 2},   // supported again
	} {
		applyProbeAndNotify(step.o, on)
		if calls != step.want {
			t.Fatalf("step %d (%v): onSupported ran %d times, want %d", i, step.o, calls, step.want)
		}
	}
}

func closeFrameReasons(c *fakeConn) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, f := range c.rawFrames {
		if len(f.data) >= 2 {
			out = append(out, string(f.data[2:]))
		}
	}
	return out
}

// Agents registered before the flip are reconnected; one told the feature is left alone, and one
// replaced before its timer fires is not closed again.
func TestBounceSessionEndedStale(t *testing.T) {
	withSessionEndedSupported(t, false)
	s, err := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	register := func(device string) (*Peer, *fakeConn) {
		c := &fakeConn{}
		p := &Peer{DeviceId: device, Tenant: "tenant-1", conn: c}
		s.reg.Register(p)
		_ = s.registeredMsg(p)
		return p, c
	}
	_, staleConn := register("dev-stale")
	_, laterConn := register("dev-replaced")
	sessionEndedSupported.Store(true)
	_, freshConn := register("dev-fresh")
	if len(s.reg.sessionEndedStalePeers()) != 2 {
		t.Fatalf("stale peers = %d, want 2", len(s.reg.sessionEndedStalePeers()))
	}

	s.bounceDelay = func() time.Duration { return 150 * time.Millisecond }
	n := s.bounceSessionEndedStale()
	if n != 2 {
		t.Fatalf("scheduled %d, want 2", n)
	}
	// dev-replaced reconnects on its own before its timer fires.
	_, replacementConn := register("dev-replaced")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		staleConn.mu.Lock()
		done := staleConn.closed
		staleConn.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // let every timer have fired

	if got := closeFrameReasons(staleConn); len(got) != 1 || got[0] != "capability changed; re-register" {
		t.Fatalf("stale peer close frames = %q", got)
	}
	if got := closeFrameReasons(freshConn); len(got) != 0 {
		t.Fatalf("a peer told the feature was closed: %q", got)
	}
	if got := closeFrameReasons(laterConn); len(got) != 1 || got[0] != "superseded by re-registration" {
		t.Fatalf("the replaced peer must only see its supersede close, got %q", got)
	}
	if got := closeFrameReasons(replacementConn); len(got) != 0 {
		t.Fatalf("the replacement (told the feature) was closed: %q", got)
	}
}

// Codex round 1: registeredMsg read "unsupported", then the probe flipped (its snapshot missing this
// peer, whose flag was not stored yet), then the flag was stored. The post-store re-read must
// schedule the peer's own bounce. Reproduced deterministically by storing after the flip.
func TestStaleRecordedAfterTheFlipStillBounces(t *testing.T) {
	withSessionEndedSupported(t, false)
	s, err := NewServer(time.Minute, "relay-1:4444", nil, guestEndStubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	s.bounceDelay = func() time.Duration { return 0 }
	c := &fakeConn{}
	p := &Peer{DeviceId: "dev-race", Tenant: "tenant-1", conn: c}
	s.reg.Register(p)
	// The flip happens first and its snapshot is empty (p's flag is not stored yet)...
	sessionEndedSupported.Store(true)
	if n := s.bounceSessionEndedStale(); n != 0 {
		t.Fatalf("snapshot saw %d peers, want 0 (the interleaving under test)", n)
	}
	// ...then the registration that read "unsupported" stores its flag.
	s.recordSessionEndedStale(p, true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := closeFrameReasons(c); len(got) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := closeFrameReasons(c); len(got) != 1 || got[0] != "capability changed; re-register" {
		t.Fatalf("the late-recorded stale peer was not bounced: %q", got)
	}
}
