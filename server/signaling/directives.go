package main

// Fleet agent directives (docs/65): signaling is a RELAY, never an authority.
//
// The control plane signs a directive (reinstall / uninstall) and the AGENT verifies it. Signaling
//
//   - asks the control plane for a device's pending directives when that device authenticates
//     (GET /internal/devices/{id}/directives/pending), and again when the control plane says one was
//     issued (POST /internal/devices/{id}/directive-pending, served here);
//   - relays each to the connection that just authenticated as that device, and only if the agent
//     advertised "directive_v1" at register_agent;
//   - reports delivery, and forwards the agent's signed acknowledgement VERBATIM
//     (POST /internal/directives/{id}/ack), with the device id taken from the authenticated
//     connection and never from the message.
//
// A RETIRED machine registers in RESTRICTED mode (registry.go RegisterRestricted): it is never
// brokerable or present, and this file's relay and ack paths are the only things it may use.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// maxPendingDirectives is how many directives one fetch may deliver (the control plane sends at
	// most this many; surplus entries are ignored).
	maxPendingDirectives = 4
	// maxPendingBodyBytes bounds the pending-list response: 4 artifacts of at most 4096 bytes plus
	// JSON overhead fit with room to spare.
	maxPendingBodyBytes = 32 << 10
	// maxDirectivesPerConnection bounds the per-connection "already sent" ledger.
	maxDirectivesPerConnection = 256
	// directiveNotifyWindow is the minimum spacing of control-plane fetches per device when the
	// control plane notifies signaling; a notification inside the window is coalesced into one
	// trailing fetch.
	directiveNotifyWindow = 2 * time.Second
	// directiveRegistrationWait is how long a registration-time relay waits for a control-plane slot.
	directiveRegistrationWait = 10 * time.Second
	// directiveAckPerMinute is the per-connection ceiling on directive_ack.
	directiveAckPerMinute = 20
	// maxNotifyBodyBytes bounds the (ignored) body of the notify route.
	maxNotifyBodyBytes = 4096
)

// directiveSlots bounds concurrent directive calls to the control plane (fetch, delivered, ack), so
// neither a fleet re-registering nor the notify route can amplify into unbounded control-plane load.
var directiveSlots = make(chan struct{}, 8)

// acquireDirectiveSlot takes a slot, waiting up to wait (0 = do not wait).
func acquireDirectiveSlot(wait time.Duration) bool {
	select {
	case directiveSlots <- struct{}{}:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case directiveSlots <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func releaseDirectiveSlot() { <-directiveSlots }

// pendingDirective is one entry of the control plane's pending list.
type pendingDirective struct {
	DirectiveID string `json:"directive_id"`
	Artifact    string `json:"artifact"`
}

// configured reports whether the reporter can reach a control plane.
func (r *GuestEndReporter) configured() bool {
	return r != nil && r.baseURL != "" && r.token != ""
}

// fetchPending asks the control plane for a device's pending directives. Entries that are not
// well-formed (id not a canonical UUID, artifact empty or oversized) are skipped; at most
// maxPendingDirectives are returned. Any non-200 answer is an error: nothing is delivered.
func (r *GuestEndReporter) fetchPending(ctx context.Context, deviceID string) ([]pendingDirective, error) {
	ctx, cancel := context.WithTimeout(ctx, guestEndTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.baseURL+"/internal/devices/"+url.PathEscape(deviceID)+"/directives/pending", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &directiveHTTPError{status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPendingBodyBytes+1))
	if err != nil || len(raw) > maxPendingBodyBytes {
		return nil, errBadDirectiveBody
	}
	var body struct {
		Directives []pendingDirective `json:"directives"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil, errBadDirectiveBody
	}
	var out []pendingDirective
	for _, d := range body.Directives {
		if len(out) == maxPendingDirectives {
			break
		}
		if !validGuestEndSessionID(d.DirectiveID) || d.Artifact == "" || len(d.Artifact) > maxDirectiveArtifactBytes {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

type directiveHTTPError struct{ status int }

func (e *directiveHTTPError) Error() string {
	return "control plane returned " + http.StatusText(e.status)
}

var errBadDirectiveBody = &directiveHTTPError{status: http.StatusBadGateway}

// postJSON sends one best-effort POST and returns the status and (bounded) body.
func (r *GuestEndReporter) postJSON(ctx context.Context, endpoint string, payload any) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, guestEndTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return resp.StatusCode, nil, errBadDirectiveBody
	}
	return resp.StatusCode, raw, nil
}

// reportDelivered tells the control plane a directive was written to the device's connection.
// Best effort: a failure is logged and never retried here.
func (r *GuestEndReporter) reportDelivered(ctx context.Context, directiveID, deviceID string) {
	status, _, err := r.postJSON(ctx, r.baseURL+"/internal/directives/"+url.PathEscape(directiveID)+"/delivered",
		struct {
			DeviceID string `json:"device_id"`
		}{deviceID})
	if err != nil || status != http.StatusOK {
		log.Printf("directive delivered report for %s failed (status %d, err %v)", clipForLog(directiveID), status, err)
	}
}

// forwardAck sends the agent's acknowledgement to the control plane exactly as received, adding only
// the authenticated device id, and maps the answer to the outcome the agent is told.
func (r *GuestEndReporter) forwardAck(ctx context.Context, deviceID string, a *DirectiveAck) string {
	status, raw, err := r.postJSON(ctx, r.baseURL+"/internal/directives/"+url.PathEscape(a.DirectiveID)+"/ack",
		struct {
			DeviceID string `json:"device_id"`
			From     string `json:"from"`
			To       string `json:"to"`
			TsMs     int64  `json:"ts_ms"`
			Detail   string `json:"detail"`
			Sig      string `json:"sig"`
		}{deviceID, a.From, a.To, a.TsMs, a.Detail, a.Sig})
	if err != nil {
		return "unavailable"
	}
	switch status {
	case http.StatusOK:
		var res struct {
			Outcome string `json:"outcome"`
		}
		if json.Unmarshal(raw, &res) == nil && (res.Outcome == "applied" || res.Outcome == "replay") {
			return res.Outcome
		}
		return "unavailable"
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict:
		return "refused"
	case http.StatusUnauthorized:
		log.Printf("directive ack: control plane returned 401; check SIGNALING_DEVICE_IDENTITY_TOKEN")
		return "unavailable"
	default:
		return "unavailable"
	}
}

// markDirectiveSent records that id is being relayed on this connection. It returns false when it
// already was (or the per-connection ledger is full), so a directive is relayed at most once.
func (p *Peer) markDirectiveSent(id string) bool {
	p.directiveMu.Lock()
	defer p.directiveMu.Unlock()
	if _, dup := p.directiveSent[id]; dup {
		return false
	}
	if len(p.directiveSent) >= maxDirectivesPerConnection {
		return false
	}
	if p.directiveSent == nil {
		p.directiveSent = make(map[string]struct{})
	}
	p.directiveSent[id] = struct{}{}
	return true
}

func (p *Peer) unmarkDirectiveSent(id string) {
	p.directiveMu.Lock()
	delete(p.directiveSent, id)
	p.directiveMu.Unlock()
}

// directiveEligible says whether p may be sent directives: control-plane-authenticated with a
// tenant (never dev mode), the agent advertised directive_v1, and the control plane's directive
// routes are confirmed. Normal and restricted connections are treated alike.
func (s *Server) directiveEligible(p *Peer) bool {
	return p != nil && p.conn != nil && p.directiveV1 && s.identity != nil && p.Tenant != "" &&
		p.DeviceId != "" && directiveSupported.Load()
}

// startDirectiveRelay runs right after a successful authenticated registration. It relays to p
// itself (the peer object that just authenticated), never to a peer looked up by a caller-supplied id.
func (s *Server) startDirectiveRelay(p *Peer) {
	if !s.directiveEligible(p) {
		return
	}
	go s.relayPending(p, directiveRegistrationWait)
}

// relayPending fetches p's device's pending directives and relays each to p.
func (s *Server) relayPending(p *Peer, wait time.Duration) {
	r := s.guestEnd
	if !r.configured() {
		return
	}
	if !acquireDirectiveSlot(wait) {
		log.Printf("directive relay for %s skipped: control-plane call capacity exhausted", clipForLog(p.DeviceId))
		return
	}
	list, err := r.fetchPending(context.Background(), p.DeviceId)
	releaseDirectiveSlot()
	if err != nil {
		// Never fails the registration: nothing is delivered until the next registration or notify.
		log.Printf("directive fetch for %s failed: %v", clipForLog(p.DeviceId), err)
		return
	}
	for _, d := range list {
		if !s.reg.isCurrent(p) {
			return // superseded or gone while we were fetching
		}
		if !p.markDirectiveSent(d.DirectiveID) {
			continue
		}
		if err := p.Send(Directive{DirectiveID: d.DirectiveID, Artifact: d.Artifact}); err != nil {
			p.unmarkDirectiveSent(d.DirectiveID)
			log.Printf("directive relay to %s failed: %v", clipForLog(p.DeviceId), err)
			return
		}
		if acquireDirectiveSlot(2 * time.Second) {
			r.reportDelivered(context.Background(), d.DirectiveID, p.DeviceId)
			releaseDirectiveSlot()
		}
	}
}

// directiveThrottle coalesces notifications per device.
type directiveThrottle struct {
	mu    sync.Mutex
	state map[string]*throttleEntry
}

type throttleEntry struct {
	last     time.Time
	trailing bool
}

// notifyDirectivePending is the control plane's "a directive was issued for this device". It does
// nothing unless a directive-capable connection for the device is registered (normal or restricted),
// and fetches at most once per window per device (a notification inside the window schedules one
// trailing fetch, so the latest issuance is still picked up).
func (s *Server) notifyDirectivePending(device string) {
	if s.reg == nil || len(device) == 0 || len(device) > 128 {
		return
	}
	eligible := false
	for _, p := range s.reg.directivePeers(device) {
		if s.directiveEligible(p) {
			eligible = true
			break
		}
	}
	if !eligible {
		return
	}
	window := s.directiveNotifyWindow
	if window <= 0 {
		window = directiveNotifyWindow
	}
	t := &s.directiveThrottle
	t.mu.Lock()
	if t.state == nil {
		t.state = make(map[string]*throttleEntry)
	}
	now := time.Now()
	e := t.state[device]
	if e == nil {
		if len(t.state) >= 1024 {
			for k, v := range t.state {
				if !v.trailing && now.Sub(v.last) > time.Minute {
					delete(t.state, k)
				}
			}
		}
		e = &throttleEntry{}
		t.state[device] = e
	}
	since := now.Sub(e.last)
	if !e.last.IsZero() && since < window {
		if !e.trailing {
			e.trailing = true
			time.AfterFunc(window-since, func() {
				t.mu.Lock()
				e.trailing = false
				e.last = time.Now()
				t.mu.Unlock()
				s.runDirectiveRelay(device)
			})
		}
		t.mu.Unlock()
		return
	}
	e.last = now
	t.mu.Unlock()
	go s.runDirectiveRelay(device)
}

// runDirectiveRelay relays to whichever directive-capable connections the device has right now.
func (s *Server) runDirectiveRelay(device string) {
	for _, p := range s.reg.directivePeers(device) {
		if s.directiveEligible(p) {
			s.relayPending(p, 0)
		}
	}
}

// directivePendingHandler serves POST /internal/devices/{device_id}/directive-pending. It answers 204
// whether or not the device is connected, so it is not a presence oracle; the body is ignored.
func (s *Server) directivePendingHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !directiveNotifyAuthorized(r, token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxNotifyBodyBytes))
		s.notifyDirectivePending(r.PathValue("device_id"))
		w.WriteHeader(http.StatusNoContent)
	}
}

// directiveNotifyAuthorized is a constant-time bearer check against the same service token the
// control plane's internal routes use (SIGNALING_DEVICE_IDENTITY_TOKEN).
func directiveNotifyAuthorized(r *http.Request, want string) bool {
	if len(want) < presenceTokenMinLen {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}

// mountDirectiveNotify attaches the notify route. Without a token of at least presenceTokenMinLen
// characters the route is NOT mounted at all (404): there is no unauthenticated mode.
func (s *Server) mountDirectiveNotify(mux *http.ServeMux, token string) {
	if len(token) < presenceTokenMinLen {
		log.Printf("SIGNALING_DEVICE_IDENTITY_TOKEN is not set (or too short) — POST /internal/devices/{id}/directive-pending is NOT mounted")
		return
	}
	mux.HandleFunc("POST /internal/devices/{device_id}/directive-pending", s.directivePendingHandler(token))
	log.Printf("directive notify route mounted at POST /internal/devices/{device_id}/directive-pending (service-token gated)")
}

// allowDirectiveAck is a rolling-window limiter for directive_ack, owned by the read goroutine.
func (p *Peer) allowDirectiveAck(now time.Time) bool {
	first := 0
	for first < len(p.directiveAckTimes) && !p.directiveAckTimes[first].After(now.Add(-time.Minute)) {
		first++
	}
	p.directiveAckTimes = p.directiveAckTimes[first:]
	if len(p.directiveAckTimes) >= directiveAckPerMinute {
		return false
	}
	p.directiveAckTimes = append(p.directiveAckTimes, now)
	return true
}

// handleDirectiveAck forwards an agent's signed acknowledgement. Accepted only from a registered
// (normal or restricted) connection that advertised directive_v1; the device id is the
// connection's, never the message's.
func (s *Server) handleDirectiveAck(self *Peer, a *DirectiveAck) {
	if !self.registered {
		_ = self.Send(Rejected{Reason: "directive ack for unregistered device"})
		return
	}
	if !self.directiveV1 {
		_ = self.Send(Rejected{Reason: "directive ack without directive_v1"})
		return
	}
	id := a.DirectiveID
	echo := DirectiveAckResult{DirectiveID: id}
	reply := func(outcome string) {
		r := echo
		r.Outcome = outcome
		_ = self.Send(r)
	}
	if a.validate() != nil {
		reply("refused") // unvalidated fields are not echoed
		return
	}
	echo.From, echo.To, echo.TsMs = a.From, a.To, a.TsMs
	// Only a control-plane-vouched connection may speak for a device (no dev mode).
	if s.identity == nil || self.Tenant == "" {
		reply("refused")
		return
	}
	if !self.allowDirectiveAck(time.Now()) {
		reply("unavailable")
		return
	}
	r := s.guestEnd
	if !directiveSupported.Load() || !r.configured() {
		reply("unavailable")
		return
	}
	deviceID := self.DeviceId // snapshot on the read goroutine
	// Acks are forwarded by ONE worker per connection, in the order they were received: a goroutine per ack
	// let a later transition overtake an earlier one at the control plane, which then answered a conflict
	// the agent treats as terminal (stranding a successful uninstall as removal_unconfirmed). The queue is
	// bounded; a full queue is "unavailable" (the agent retries). The worker is started here, on the read
	// goroutine, and stopped by cleanup closing the queue.
	self.directiveAckOnce.Do(func() {
		self.directiveAcks = make(chan DirectiveAck, directiveAckQueueMax)
		go func() {
			for ack := range self.directiveAcks {
				ack := ack
				outcome := "unavailable"
				if acquireDirectiveSlot(directiveAckSlotWait) {
					outcome = func() string {
						defer releaseDirectiveSlot()
						return r.forwardAck(context.Background(), deviceID, &ack)
					}()
				}
				_ = self.Send(DirectiveAckResult{DirectiveID: ack.DirectiveID, Outcome: outcome, From: ack.From, To: ack.To, TsMs: ack.TsMs})
			}
		}()
	})
	select {
	case self.directiveAcks <- *a:
	default:
		reply("unavailable")
	}
}

// directiveAckQueueMax bounds one connection's queue of acknowledgements waiting to be forwarded;
// directiveAckSlotWait is how long the worker waits for a global forwarding slot before telling the agent
// "unavailable".
const (
	directiveAckQueueMax = 8
	directiveAckSlotWait = 2 * time.Second
)
