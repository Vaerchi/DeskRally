package main

// docs/64: guest help requests. An enrolled agent that holds an AUTHENTICATED socket sends help_request /
// help_cancel / help_status; this file forwards them to the control plane with the identity the connection
// already proved (the same hop and authorization as sessionended.go -> /internal/sessions/{id}/ended:
// device-identity service token, tenant from the connection, never from the body). The control plane owns
// every durable rule (one open per machine, op_id dedup, budgets, authorization); signaling only bounds
// what it will carry: frame size, note length, a per-peer message budget and a bounded worker queue.
import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	helpRequestFeature = "help_request_v1"
	// maxHelpFrameBytes bounds a help frame (H-C2): the 64 KiB read cap is for registration payloads.
	maxHelpFrameBytes = 1024
	maxHelpNoteRunes  = 200
	maxHelpOpLen      = 64
	// helpPeerPerMinute is a courtesy ceiling on one DEVICE's help messages (keyed by tenant+device in the
	// Registry, so it survives reconnects); the DURABLE limits (30 calls/hour, 3 creations/hour, 10/day per
	// device, 200/hour per tenant) live in the control plane.
	helpPeerPerMinute = 12
	helpPeerWindow    = time.Minute
	// helpInflightPerDevice caps one device's jobs in the worker queue (queued + running).
	helpInflightPerDevice = 2
	// helpGateMaxKeys bounds the device table of the gate; entries lapse helpPeerWindow after last use.
	helpGateMaxKeys = 20000
	helpWorkerCount = 4
	helpQueueDepth  = 32
	helpTimeout     = 5 * time.Second
)

// helpRequestSupported is the last DEFINITIVE answer to "does the control plane list help_request_v1".
// Set by probeCapabilities from the same response as session_ended_v1; transient failures keep it.
var helpRequestSupported atomic.Bool

// helpFlippedUp is raised when a probe flips helpRequestSupported to true; RunCapabilityProbe consumes it
// to reconnect the peers registered without the feature.
var helpFlippedUp atomic.Bool

func setHelpRequestSupported(v bool) {
	if helpRequestSupported.Swap(v) != v {
		log.Printf("capability probe: help_request_v1 advertised = %v", v)
		if v {
			helpFlippedUp.Store(true)
		}
	}
}

// helpJob is one forwarded message. run is invoked on a worker and returns the reply.
type helpJob struct {
	run   func(ctx context.Context) HelpRequestResult
	reply func(HelpRequestResult)
}

var (
	helpJobs     = make(chan helpJob, helpQueueDepth)
	helpWorkOnce sync.Once
)

func startHelpWorkers() {
	helpWorkOnce.Do(func() {
		for i := 0; i < helpWorkerCount; i++ {
			go func() {
				for j := range helpJobs {
					j.reply(j.run(context.Background()))
				}
			}()
		}
	})
}

// enqueueHelp admits a job without ever waiting: a full queue is an overload, logged and answered
// "unavailable" (H-C2).
func enqueueHelp(j helpJob) bool {
	startHelpWorkers()
	select {
	case helpJobs <- j:
		return true
	default:
		log.Printf("help request forwarding overloaded: queue of %d full, dropping", helpQueueDepth)
		return false
	}
}

// helpGate is the DEVICE-keyed admission control in front of the forwarding queue. It is held by the Registry
// (not the Peer), so a device that reconnects keeps its budget, and it is bounded: at most helpGateMaxKeys
// devices are tracked, each for at most helpPeerWindow after its last admitted message, and a NEW device is
// refused (fail closed) while the table is full of live entries. It also caps the jobs one device may have in
// flight in the worker queue, so a few devices cannot occupy every worker slot.
type helpGate struct {
	mu       sync.Mutex
	times    map[string][]time.Time
	inflight map[string]int
	maxKeys  int
}

func newHelpGate() *helpGate {
	return &helpGate{times: map[string][]time.Time{}, inflight: map[string]int{}, maxKeys: helpGateMaxKeys}
}

// helpGateKey identifies a device: the tenant AND the device id, both from the authenticated connection.
func helpGateKey(tenant, device string) string { return tenant + "/" + device }

// admit spends one message of the device's budget and takes an in-flight slot; the caller MUST release the
// slot exactly once when the job's reply has been produced (or the job was never queued).
func (g *helpGate) admit(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	ts, tracked := g.times[key]
	first := 0
	for first < len(ts) && !ts[first].After(now.Add(-helpPeerWindow)) {
		first++
	}
	ts = ts[first:]
	if len(ts) >= helpPeerPerMinute || g.inflight[key] >= helpInflightPerDevice {
		if len(ts) == 0 {
			delete(g.times, key)
		} else {
			g.times[key] = ts
		}
		return false
	}
	if !tracked && len(g.times) >= g.maxKeys {
		g.pruneLocked(now)
		if len(g.times) >= g.maxKeys {
			return false
		}
	}
	g.times[key] = append(ts, now)
	g.inflight[key]++
	return true
}

// release gives back the in-flight slot admit took.
func (g *helpGate) release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inflight[key] <= 1 {
		delete(g.inflight, key)
	} else {
		g.inflight[key]--
	}
}

// pruneLocked drops every device whose whole window has lapsed and that has nothing in flight.
func (g *helpGate) pruneLocked(now time.Time) {
	for k, ts := range g.times {
		if g.inflight[k] == 0 && (len(ts) == 0 || !ts[len(ts)-1].After(now.Add(-helpPeerWindow))) {
			delete(g.times, k)
		}
	}
}

// fallbackHelpGate serves a Server built without a Registry (tests); production servers always have one.
var fallbackHelpGate = newHelpGate()

func (s *Server) helpGate() *helpGate {
	if s.reg != nil && s.reg.help != nil {
		return s.reg.help
	}
	return fallbackHelpGate
}

// validHelpOp mirrors the control plane's op_id rule: 1..64 bytes of [A-Za-z0-9._:-].
func validHelpOp(op string) bool {
	if op == "" || len(op) > maxHelpOpLen {
		return false
	}
	for i := 0; i < len(op); i++ {
		c := op[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

// isHelpMessage says whether a decoded client message is one of the three help messages (frame bound).
func isHelpMessage(msg ClientToServer) bool {
	switch msg.Payload.(type) {
	case *HelpRequest, *HelpCancel, *HelpStatus:
		return true
	}
	return false
}

// helpRefusal is what a connection that may not use help gets: a terminal outcome. A dev-mode or
// unauthenticated connection must never reach a route that creates technician work.
func (s *Server) helpAdmitted(self *Peer, op, opID string) (HelpRequestResult, bool) {
	res := func(outcome string) (HelpRequestResult, bool) {
		return HelpRequestResult{Op: op, OpID: opID, Outcome: outcome}, false
	}
	if s.identity == nil || self.Tenant == "" || !helpRequestSupported.Load() {
		return res("refused")
	}
	if !s.helpGate().admit(helpGateKey(self.Tenant, self.DeviceId), time.Now()) {
		return res("unavailable")
	}
	return HelpRequestResult{}, true
}

// forwardHelp queues an ADMITTED job (helpAdmitted returned true) and gives the device's in-flight slot
// back once the reply has been produced, or at once when the queue refuses the job.
func (s *Server) forwardHelp(self *Peer, op, opID string, run func(ctx context.Context) HelpRequestResult) {
	gate, key := s.helpGate(), helpGateKey(self.Tenant, self.DeviceId)
	reply := func(r HelpRequestResult) {
		gate.release(key)
		r.Op, r.OpID = op, opID
		_ = self.Send(r)
	}
	if !enqueueHelp(helpJob{run: run, reply: reply}) {
		reply(HelpRequestResult{Outcome: "unavailable"})
	}
}

func (s *Server) handleHelpRequest(self *Peer, p *HelpRequest) {
	if !self.registered {
		_ = self.Send(Rejected{Reason: "help request for unregistered device"})
		return
	}
	// opID is echoed only when well formed: a hostile value must not be reflected into the reply.
	echo := ""
	if validHelpOp(p.OpID) {
		echo = p.OpID
	}
	if !validHelpOp(p.OpID) || utf8.RuneCountInString(p.Note) > maxHelpNoteRunes {
		_ = self.Send(HelpRequestResult{Op: "help_request", OpID: echo, Outcome: "refused"})
		return
	}
	if res, ok := s.helpAdmitted(self, "help_request", echo); !ok {
		_ = self.Send(res)
		return
	}
	// Snapshot identity on the read goroutine: later registration must not change this request.
	deviceID, tenantID, r := self.DeviceId, self.Tenant, s.guestEnd
	opID, note := p.OpID, p.Note
	s.forwardHelp(self, "help_request", echo, func(ctx context.Context) HelpRequestResult {
		return r.helpCall(ctx, "help-request", deviceID, struct {
			TenantID string `json:"tenant_id"`
			OpID     string `json:"op_id"`
			Note     string `json:"note"`
		}{tenantID, opID, note})
	})
}

func (s *Server) handleHelpCancel(self *Peer, p *HelpCancel) {
	if !self.registered {
		_ = self.Send(Rejected{Reason: "help cancel for unregistered device"})
		return
	}
	if !validGuestEndSessionID(p.RequestID) {
		_ = self.Send(HelpRequestResult{Op: "help_cancel", Outcome: "refused"})
		return
	}
	if res, ok := s.helpAdmitted(self, "help_cancel", ""); !ok {
		res.CancelOf = p.RequestID
		_ = self.Send(res)
		return
	}
	deviceID, tenantID, r := self.DeviceId, self.Tenant, s.guestEnd
	id := p.RequestID
	s.forwardHelp(self, "help_cancel", "", func(ctx context.Context) HelpRequestResult {
		res := r.helpCall(ctx, "help-cancel", deviceID, struct {
			TenantID  string `json:"tenant_id"`
			RequestID string `json:"request_id"`
		}{tenantID, id})
		res.CancelOf = id
		return res
	})
}

func (s *Server) handleHelpStatus(self *Peer, _ *HelpStatus) {
	if !self.registered {
		_ = self.Send(Rejected{Reason: "help status for unregistered device"})
		return
	}
	if res, ok := s.helpAdmitted(self, "help_status", ""); !ok {
		_ = self.Send(res)
		return
	}
	deviceID, tenantID, r := self.DeviceId, self.Tenant, s.guestEnd
	s.forwardHelp(self, "help_status", "", func(ctx context.Context) HelpRequestResult {
		return r.helpCall(ctx, "help-status", deviceID, struct {
			TenantID string `json:"tenant_id"`
		}{tenantID})
	})
}

// helpCall POSTs one help message to /internal/devices/{device}/{route}. Transport errors and 5xx are
// retried (create is idempotent on op_id, cancel on its state machine, status is a read); everything
// else maps to a terminal outcome the agent can act on.
func (r *GuestEndReporter) helpCall(ctx context.Context, route, deviceID string, body any) HelpRequestResult {
	if r == nil || r.baseURL == "" || r.token == "" {
		return HelpRequestResult{Outcome: "unavailable"}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return HelpRequestResult{Outcome: "unavailable"}
	}
	endpoint := r.baseURL + "/internal/devices/" + url.PathEscape(deviceID) + "/" + route
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := 200 * time.Millisecond
			if attempt == 2 {
				delay = 800 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return HelpRequestResult{Outcome: "unavailable"}
			case <-timer.C:
			}
		}
		res, retry := r.helpAttempt(ctx, endpoint, raw)
		if !retry {
			return res
		}
	}
	return HelpRequestResult{Outcome: "unavailable"}
}

func (r *GuestEndReporter) helpAttempt(ctx context.Context, endpoint string, body []byte) (HelpRequestResult, bool) {
	ctx, cancel := context.WithTimeout(ctx, helpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return HelpRequestResult{Outcome: "unavailable"}, false
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return HelpRequestResult{Outcome: "unavailable"}, true
	}
	defer func() { _ = resp.Body.Close() }()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if rerr != nil || len(raw) > 8192 {
		return HelpRequestResult{Outcome: "unavailable"}, false
	}
	var parsed struct {
		Request           *HelpRequestInfo `json:"request"`
		RetryAfterSeconds int              `json:"retry_after_seconds"`
	}
	_ = json.Unmarshal(raw, &parsed)
	info := parsed.Request
	if info != nil {
		// The note is the guest machine's own text: bounded again before it reaches the agent's UI.
		info.Note = strings.ToValidUTF8(info.Note, "�")
	}
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		return HelpRequestResult{Outcome: "ok", Request: info}, false
	case resp.StatusCode == http.StatusConflict && info != nil:
		// accept / expiry won the race against a cancel: the current state, so the agent resets its UI.
		return HelpRequestResult{Outcome: "conflict", Request: info}, false
	case resp.StatusCode == http.StatusTooManyRequests:
		secs := parsed.RetryAfterSeconds
		if secs < 1 {
			secs = 60
		}
		return HelpRequestResult{Outcome: "limited", RetryAfterSeconds: secs}, false
	case resp.StatusCode == http.StatusNotFound && notFoundHelpRequest(raw):
		return HelpRequestResult{Outcome: "not_found"}, false
	case resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusBadRequest:
		return HelpRequestResult{Outcome: "refused"}, false
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound:
		// An unmounted internal route falls through to session auth (401) or 404: a rolled-back control
		// plane or a bad token is never a terminal answer for the guest.
		log.Printf("help request forwarding: control plane returned %d (route absent or bad SIGNALING_DEVICE_IDENTITY_TOKEN)", resp.StatusCode)
		return HelpRequestResult{Outcome: "unavailable"}, false
	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		return HelpRequestResult{Outcome: "unavailable"}, true
	default:
		return HelpRequestResult{Outcome: "unavailable"}, false
	}
}

// notFoundHelpRequest says whether a 404 body is the cancel handler's own "help request not found" (as
// opposed to "unknown device" or a missing route).
func notFoundHelpRequest(raw []byte) bool {
	var e struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(raw, &e) == nil && e.Error == "help request not found"
}
