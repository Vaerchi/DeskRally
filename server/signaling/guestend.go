package main

// Guest ends are idempotent at the control plane, so transport failures may be retried.
// Admission happens before spawning a worker: an outage must not accumulate waiting goroutines.
import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const guestEndTimeout = 5 * time.Second

var guestEndSlots = make(chan struct{}, 8)
var guestEndUnconfigured sync.Once

// GuestEndReporter shares ticket redemption's configuration and HTTP client conventions.
// Fields are immutable after construction; reports may run concurrently.
type GuestEndReporter struct {
	baseURL string
	token   string
	client  *http.Client
}

func newHTTPGuestEndReporter(baseURL, token string) (*GuestEndReporter, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	token = strings.TrimSpace(token)
	if baseURL == "" || token == "" {
		return &GuestEndReporter{}, nil
	}
	// Reuse the existing validation so both clients accept precisely the same configuration.
	r, err := newHTTPTicketRedeemer(baseURL, token)
	if err != nil {
		return nil, err
	}
	return &GuestEndReporter{
		baseURL: r.baseURL,
		token:   r.token,
		client: &http.Client{Timeout: guestEndTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			// A redirect must not turn one attempt into additional requests or forward identity.
			return http.ErrUseLastResponse
		}},
	}, nil
}

func guestEndReporterFromEnv() (*GuestEndReporter, error) {
	return newHTTPGuestEndReporter(os.Getenv("SIGNALING_DEVICE_IDENTITY_URL"), os.Getenv("SIGNALING_DEVICE_IDENTITY_TOKEN"))
}

func (r *GuestEndReporter) acquire() bool {
	if r == nil || r.baseURL == "" || r.token == "" {
		guestEndUnconfigured.Do(func() {
			log.Printf("guest end reporting unavailable: SIGNALING_DEVICE_IDENTITY_URL/SIGNALING_DEVICE_IDENTITY_TOKEN are not configured")
		})
		return false
	}
	select {
	case guestEndSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

// Report never waits for capacity. A slot covers the entire report, including retry backoff.
func (r *GuestEndReporter) Report(ctx context.Context, sessionID, deviceID, tenantID string) string {
	if !r.acquire() {
		return "unavailable"
	}
	defer func() { <-guestEndSlots }()
	return r.report(ctx, sessionID, deviceID, tenantID)
}

// report requires a slot already held by Report or the dispatch worker.
func (r *GuestEndReporter) report(ctx context.Context, sessionID, deviceID, tenantID string) string {
	body, err := json.Marshal(struct {
		DeviceID string `json:"device_id"`
		TenantID string `json:"tenant_id"`
	}{deviceID, tenantID})
	if err != nil {
		return "unavailable"
	}
	return r.send(ctx, r.baseURL+"/internal/sessions/"+url.PathEscape(sessionID)+"/guest-ended", body, false)
}

// send POSTs one end report, retrying only transport errors and 5xx. ended selects the docs/49
// /ended status mapping, where a missing route must never read as a terminal answer.
func (r *GuestEndReporter) send(ctx context.Context, endpoint string, body []byte, ended bool) string {
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return "unavailable"
		}
		if attempt > 0 {
			delay := 200 * time.Millisecond
			if attempt == 2 {
				delay = 800 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "unavailable"
			case <-timer.C:
			}
		}
		outcome, retry := r.attempt(ctx, endpoint, body, ended)
		if !retry {
			return outcome
		}
	}
	return "unavailable"
}

func (r *GuestEndReporter) attempt(ctx context.Context, endpoint string, body []byte, ended bool) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, guestEndTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "unavailable", false
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return "unavailable", true
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
		// Bound the response too: this service needs only one small outcome object.
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
		if err != nil || len(raw) > 4096 {
			return "unavailable", false
		}
		var result struct {
			Outcome string `json:"outcome"`
		}
		if json.Unmarshal(raw, &result) == nil && (result.Outcome == "ended" || result.Outcome == "already_ended") {
			return result.Outcome, false
		}
		return "unavailable", false
	case ended && resp.StatusCode == http.StatusNotFound:
		// Terminal only when the handler itself says the session does not exist. Any other 404 is
		// a control plane without the route (a rollback or mixed replica): the agent keeps it.
		if notFoundFromHandler(resp.Body) {
			return "refused", false
		}
		log.Printf("session end reporting: control plane has no /ended route; the agent will retry")
		return "unavailable", false
	case ended && resp.StatusCode == http.StatusBadRequest:
		// Terminal, but reportEnded may first resend without its optional fields (docs/49).
		return endedBadRequest, false
	case ended && resp.StatusCode == http.StatusUnauthorized:
		// An unmounted internal route falls through to session auth and answers 401 (docs/49 v4),
		// so this is as likely a rolled-back control plane as a bad token. Never terminal.
		log.Printf("session end reporting: control plane returned 401 for /ended (route absent or bad SIGNALING_DEVICE_IDENTITY_TOKEN); the agent will retry")
		return "unavailable", false
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		return "refused", false
	case resp.StatusCode == http.StatusUnauthorized:
		log.Printf("guest end reporting: control plane returned 401; check SIGNALING_DEVICE_IDENTITY_TOKEN")
		return "unavailable", false
	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		return "unavailable", true
	default:
		return "unavailable", false
	}
}

// Accept the canonical UUID wire form without depending on an unseen UUID package.
func validGuestEndSessionID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if id[i] != '-' {
				return false
			}
			continue
		}
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (p *Peer) allowGuestEnd(now time.Time) bool {
	first := 0
	for first < len(p.guestEndTimes) && !p.guestEndTimes[first].After(now.Add(-time.Minute)) {
		first++
	}
	p.guestEndTimes = p.guestEndTimes[first:]
	if len(p.guestEndTimes) >= 30 {
		return false
	}
	p.guestEndTimes = append(p.guestEndTimes, now)
	return true
}

func (s *Server) handleGuestEndedSession(self *Peer, p *GuestEndedSession) {
	if !self.registered {
		_ = self.Send(Rejected{Reason: "guest end for unregistered device"})
		return
	}
	id := p.ControlPlaneSession
	reply := func(outcome string) {
		_ = self.Send(GuestEndedResult{ControlPlaneSession: id, Outcome: outcome})
	}
	if !validGuestEndSessionID(id) {
		reply("refused")
		return
	}
	// Only a connection whose device and tenant the CONTROL PLANE vouched for may end a record. In
	// dev mode (-insecure-no-agent-auth, no identity resolver) "registered" means "asserted", and an
	// asserted device id must never reach a route that ends sessions. Refused, not unavailable: no
	// retry can make this connection authenticated.
	if s.identity == nil || self.Tenant == "" {
		reply("refused")
		return
	}
	if !self.allowGuestEnd(time.Now()) {
		reply("unavailable")
		return
	}
	r := s.guestEnd
	if !r.acquire() {
		reply("unavailable")
		return
	}
	// Snapshot identity on the read goroutine: later registration must not change this report.
	deviceID, tenantID := self.DeviceId, self.Tenant
	go func() {
		// Release before Send, whose socket deadline can otherwise consume scarce CP capacity.
		outcome := func() string {
			defer func() { <-guestEndSlots }()
			return r.report(context.Background(), id, deviceID, tenantID)
		}()
		reply(outcome)
	}()
}
