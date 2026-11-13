package main

// docs/49: the generalised agent session-end report. The agent sends session_ended only on a
// connection whose Registered advertised session_ended_v1, and signaling advertises it only after
// the control plane's capability probe said /internal/sessions/{id}/ended exists.
import (
	"context"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const (
	sessionEndedFeature = "session_ended_v1"
	// capabilityRefresh is how often a settled probe is repeated; capabilityRetry follows an
	// answer that settled nothing (network error, 5xx, unexpected status).
	capabilityRefresh = 5 * time.Minute
	capabilityRetry   = 30 * time.Second
	// capabilityStartupRetry applies until the FIRST settled answer since start. Agents learn
	// features only from their first Registered, and right after a deploy the fleet re-registers
	// while the control plane may still be starting: a 30 s retry left that whole window unadvertised.
	capabilityStartupRetry = 2 * time.Second
	// capabilityBounceSpread spreads the reconnects of agents registered without the feature, so a
	// flip does not send the whole fleet through registration (and its control-plane lookups) at once.
	capabilityBounceSpread = 30 * time.Second
	// maxQueueAgeMs mirrors the control plane's bound (30 days); a larger age is clamped, not
	// refused, so a long-offline agent's report still closes its row.
	maxQueueAgeMs = 30 * 24 * 60 * 60 * 1000
)

// Bits of Peer.featuresTold.
const (
	featEnded uint32 = 1 << iota
	featHelp
)

// sessionEndedSupported is the last DEFINITIVE capability answer. Transient failures keep it.
var sessionEndedSupported atomic.Bool

// capabilitySettledOnce records that some probe since start gave a definitive answer.
var capabilitySettledOnce atomic.Bool

// probeOutcome is what one capability probe established.
type probeOutcome int

const (
	probeUnsettled probeOutcome = iota // transient: keep the previous answer, retry soon
	probeSupported
	probeUnsupported
)

// probeCapabilities asks the control plane which internal features it serves and reports the
// session_ended_v1 answer (see probeCapabilitySet for the directive_v1 one).
func (r *GuestEndReporter) probeCapabilities(ctx context.Context) probeOutcome {
	o, _ := r.probeCapabilitySet(ctx)
	return o
}

// probeCapabilitySet is one probe. The outcome is the session_ended_v1 answer; the bool says whether
// the same response also listed directive_v1, and is meaningful only when the outcome is settled
// (supported or unsupported): an unsettled probe keeps the previous answer for both features.
func (r *GuestEndReporter) probeCapabilitySet(ctx context.Context) (probeOutcome, bool) {
	if r == nil || r.baseURL == "" || r.token == "" {
		return probeUnsupported, false
	}
	ctx, cancel := context.WithTimeout(ctx, guestEndTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/internal/capabilities", nil)
	if err != nil {
		return probeUnsettled, false
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return probeUnsettled, false
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
		if err != nil || len(raw) > 4096 {
			return probeUnsettled, false
		}
		var caps struct {
			Features []string `json:"features"`
		}
		if json.Unmarshal(raw, &caps) != nil {
			return probeUnsettled, false
		}
		// One definitive answer carries all three features; help_request_v1 (docs/64) is tracked beside
		// session_ended_v1 and directive_v1 and never changes this probe's outcome.
		outcome, directive, help := probeUnsupported, false, false
		for _, f := range caps.Features {
			switch f {
			case sessionEndedFeature:
				outcome = probeSupported
			case directiveFeature:
				directive = true
			case helpRequestFeature:
				help = true
			}
		}
		setHelpRequestSupported(help)
		return outcome, directive
	case http.StatusNotFound:
		setHelpRequestSupported(false)
		return probeUnsupported, false
	case http.StatusUnauthorized, http.StatusForbidden:
		// An older control plane answers 401 here too (the route falls through to session auth).
		log.Printf("capability probe: control plane returned %d (an older control plane, or a bad SIGNALING_DEVICE_IDENTITY_TOKEN); session_ended_v1, directive_v1 and help_request_v1 not advertised", resp.StatusCode)
		setHelpRequestSupported(false)
		return probeUnsupported, false
	default:
		return probeUnsettled, false
	}
}

// directiveSupported is the last DEFINITIVE answer on whether the control plane serves its directive
// routes (feature "directive_v1"); transient failures keep it.
var directiveSupported atomic.Bool

// applyDirectiveProbe records the directive_v1 half of a probe and reports whether it just flipped
// from unsupported to supported. An unsettled probe changes nothing.
func applyDirectiveProbe(o probeOutcome, directive bool) (flippedSupported bool) {
	if o == probeUnsettled {
		return false
	}
	was := directiveSupported.Swap(directive)
	if was != directive {
		log.Printf("capability probe: directive_v1 advertised = %v", directive)
	}
	return !was && directive
}

// applyProbe records a probe's answer and returns the delay before the next one.
func applyProbe(o probeOutcome) time.Duration {
	switch o {
	case probeSupported, probeUnsupported:
		capabilitySettledOnce.Store(true)
		now := o == probeSupported
		if sessionEndedSupported.Swap(now) != now {
			log.Printf("capability probe: session_ended_v1 advertised = %v", now)
		}
		return capabilityRefresh
	default:
		if !capabilitySettledOnce.Load() {
			return capabilityStartupRetry
		}
		return capabilityRetry
	}
}

// applyProbeAndNotify is applyProbe plus the transition hook: onSupported runs once each time the
// answer flips from unsupported to supported.
func applyProbeAndNotify(o probeOutcome, onSupported func()) time.Duration {
	before := sessionEndedSupported.Load()
	delay := applyProbe(o)
	if !before && sessionEndedSupported.Load() && onSupported != nil {
		onSupported()
	}
	return delay
}

// RunCapabilityProbe probes now and then on a schedule until ctx ends. onSupported (may be nil)
// runs on each flip to supported; main wires it to Server.bounceSessionEndedStale.
func (r *GuestEndReporter) RunCapabilityProbe(ctx context.Context, onSupported func()) {
	for {
		o, directive := r.probeCapabilitySet(ctx)
		fired := false
		once := func() {
			if !fired && onSupported != nil {
				fired = true
				onSupported()
			}
		}
		// directive_v1 flipping to supported also reconnects the agents that asked for it but were
		// not told (the same bounce as session_ended_v1; it is idempotent and per-peer).
		if applyDirectiveProbe(o, directive) {
			once()
		}
		// help_request_v1 flipped to supported: agents registered without it reconnect to learn it.
		if helpFlippedUp.Swap(false) {
			once()
		}
		delay := applyProbeAndNotify(o, once)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// registeredMsg is the registration acknowledgement. The feature is advertised only where a
// report could succeed: agent authentication enforced and a control-plane tenant on the
// connection (handleSessionEnded refuses every report otherwise) and the control plane's route
// confirmed.
func (s *Server) registeredMsg(self *Peer) Registered {
	msg := Registered{ServerPubkey: s.serverPubkey()}
	qualifies := s.identity != nil && self.Tenant != ""
	// A restricted (retired) connection can never report session ends or send help requests: both would
	// be refused anyway (help requests come from ACTIVE machines only), so neither feature is advertised
	// to it (docs/65 D-C1).
	activeQualifies := qualifies && !self.restricted
	endedOn := activeQualifies && sessionEndedSupported.Load()
	helpOn := activeQualifies && helpRequestSupported.Load()
	if endedOn {
		msg.Features = append(msg.Features, sessionEndedFeature)
	}
	if helpOn {
		msg.Features = append(msg.Features, helpRequestFeature)
	}
	var mask uint32
	if endedOn {
		mask |= featEnded
	}
	if helpOn {
		mask |= featHelp
	}
	self.featuresTold.Store(mask)
	// directive_v1 only where a directive could be delivered: enforced auth, a control-plane tenant,
	// the agent asked for it, and the control plane confirmed its directive routes.
	directiveQualifies := qualifies && self.directiveV1
	directiveAdvertised := directiveQualifies && directiveSupported.Load()
	if directiveAdvertised {
		msg.Features = append(msg.Features, directiveFeature)
	}
	// Stale = told less than the control plane may later confirm. The agent re-reads features only from
	// its first Registered, so a flip reconnects it (bounce).
	s.recordSessionEndedStale(self, activeQualifies && (!endedOn || !helpOn))
	s.recordDirectiveStale(self, directiveQualifies && !directiveAdvertised)
	return msg
}

// recordDirectiveStale is recordSessionEndedStale for directive_v1, with the same post-store re-read
// that closes the race against the probe's flip.
func (s *Server) recordDirectiveStale(p *Peer, stale bool) {
	p.directiveStale.Store(stale)
	if stale && directiveSupported.Load() {
		s.scheduleSessionEndedBounce(p)
	}
}

// bounceWorthwhile: the peer was told less than the control plane confirms NOW. A peer stale only because
// the control plane lacks help_request_v1 must not reconnect in a loop while session_ended_v1 is on.
func (p *Peer) bounceWorthwhile() bool {
	if !p.sessionEndedStale.Load() {
		return false
	}
	told := p.featuresTold.Load()
	return (told&featEnded == 0 && sessionEndedSupported.Load()) || (told&featHelp == 0 && helpRequestSupported.Load())
}

// recordSessionEndedStale remembers that p was NOT told the feature, so a later flip to supported
// reconnects it (bounceSessionEndedStale). The re-read closes a race (Codex): if the probe flipped
// after registeredMsg read the capability but before this store, the flip's snapshot missed p, so
// p schedules its own bounce. Go atomics are sequentially consistent, so in every interleaving
// either the flip's snapshot sees the flag or this re-read sees the flip (or both; a second bounce
// finds the peer no longer current and does nothing).
func (s *Server) recordSessionEndedStale(p *Peer, stale bool) {
	p.sessionEndedStale.Store(stale)
	if p.bounceWorthwhile() {
		s.scheduleSessionEndedBounce(p)
	}
}

// bounceDelayFor is the per-peer reconnect delay: random over capabilityBounceSpread, or the test
// override.
func (s *Server) bounceDelayFor() time.Duration {
	if s.bounceDelay != nil {
		return s.bounceDelay()
	}
	return time.Duration(rand.Int63n(int64(capabilityBounceSpread)))
}

// scheduleSessionEndedBounce closes p's connection after a delay, unless by then p re-registered,
// was replaced, or stopped being stale.
func (s *Server) scheduleSessionEndedBounce(p *Peer) {
	time.AfterFunc(s.bounceDelayFor(), func() {
		if p.conn == nil || !(p.sessionEndedStale.Load() || p.directiveStale.Load()) || !s.reg.isCurrent(p) {
			return
		}
		closePeer(p, "capability changed; re-register")
	})
}

// bounceSessionEndedStale reconnects every agent that registered while session_ended_v1 was not
// yet confirmed, so it re-registers and learns the feature. Agents read features only from their
// first Registered, so a re-sent Registered would be ignored; a clean close (code 1000) is the
// signal every agent version already handles, exactly like a signaling restart: it reconnects at
// once, and established sessions are unaffected (their media and data channels are peer to peer).
// Returns how many peers were scheduled.
func (s *Server) bounceSessionEndedStale() int {
	peers := s.reg.sessionEndedStalePeers()
	// Peers that asked for directive_v1 but were not told it (a peer may be on both lists).
	seen := make(map[*Peer]struct{}, len(peers))
	for _, p := range peers {
		seen[p] = struct{}{}
	}
	for _, p := range s.reg.directiveStalePeers() {
		if _, dup := seen[p]; !dup {
			peers = append(peers, p)
		}
	}
	if len(peers) > 0 {
		log.Printf("capability: session_ended_v1 now supported; reconnecting %d agent(s) registered without it", len(peers))
	}
	for _, p := range peers {
		s.scheduleSessionEndedBounce(p)
	}
	return len(peers)
}

// notFoundFromHandler says whether a 404 body is the /ended handler's own "session not found".
func notFoundFromHandler(body io.Reader) bool {
	raw, err := io.ReadAll(io.LimitReader(body, 4097))
	if err != nil || len(raw) > 4096 {
		return false
	}
	var e struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(raw, &e) == nil && e.Error == "session not found"
}

// validEndReason accepts a short snake_case reason; anything else is forwarded as "other" (the
// control plane normalises unknown reasons the same way).
func validEndReason(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c == '_') {
			return false
		}
	}
	return true
}

// endedBadRequest is attempt's internal answer to a 400 from /ended; reportEnded turns it into
// "refused" after any compatibility resend. It never reaches an agent.
const endedBadRequest = "bad_request"

// reportEnded requires a slot already held by the dispatch worker.
//
// queue_age_ms is newer than the /ended route itself: a control plane that serves session_ended_v1
// without it (3b47aac) refuses the unknown field with 400. A mixed or rolled-back replica must not
// turn that into a dropped report, so a 400 for a report that carried an age is resent once
// without it. A 400 without the optional field is the terminal refusal it always was.
func (r *GuestEndReporter) reportEnded(ctx context.Context, sessionID, deviceID, tenantID, reason string, queueAgeMs *int64) string {
	endpoint := r.baseURL + "/internal/sessions/" + url.PathEscape(sessionID) + "/ended"
	post := func(age *int64) string {
		body, err := json.Marshal(struct {
			DeviceID   string `json:"device_id"`
			TenantID   string `json:"tenant_id"`
			Reason     string `json:"reason"`
			QueueAgeMs *int64 `json:"queue_age_ms,omitempty"`
		}{deviceID, tenantID, reason, age})
		if err != nil {
			return "unavailable"
		}
		return r.send(ctx, endpoint, body, true)
	}
	outcome := post(queueAgeMs)
	if outcome == endedBadRequest && queueAgeMs != nil {
		log.Printf("session end reporting: control plane refused queue_age_ms; resending without it")
		outcome = post(nil)
	}
	if outcome == endedBadRequest {
		return "refused"
	}
	return outcome
}

func (s *Server) handleSessionEnded(self *Peer, p *SessionEnded) {
	if !self.registered {
		_ = self.Send(Rejected{Reason: "session end for unregistered device"})
		return
	}
	id := p.ControlPlaneSession
	reply := func(outcome string) {
		_ = self.Send(SessionEndedResult{ControlPlaneSession: id, Outcome: outcome})
	}
	if !validGuestEndSessionID(id) {
		reply("refused")
		return
	}
	// Same authority rule as guest_ended_session: only a control-plane-vouched connection.
	if s.identity == nil || self.Tenant == "" {
		reply("refused")
		return
	}
	// One budget for both report kinds: a peer cannot double its rate by alternating them.
	if !self.allowGuestEnd(time.Now()) {
		reply("unavailable")
		return
	}
	reason := p.Reason
	if !validEndReason(reason) {
		reason = "other"
	}
	var age *int64
	if p.QueueAgeMs != nil && *p.QueueAgeMs >= 0 {
		a := *p.QueueAgeMs
		if a > maxQueueAgeMs {
			a = maxQueueAgeMs
		}
		age = &a
	}
	r := s.guestEnd
	if !r.acquire() {
		reply("unavailable")
		return
	}
	deviceID, tenantID := self.DeviceId, self.Tenant
	go func() {
		outcome := func() string {
			defer func() { <-guestEndSlots }()
			return r.reportEnded(context.Background(), id, deviceID, tenantID, reason, age)
		}()
		reply(outcome)
	}()
}
