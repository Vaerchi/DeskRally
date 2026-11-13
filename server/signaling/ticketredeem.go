package main

// Session-ticket redemption — the SHARED half of single-use enforcement.
//
// ticket.go's `spentTickets` map makes a verified ticket single-use WITHIN THIS PROCESS. That is
// not the same as single-use: two signaling replicas behind a load balancer keep two maps, and a
// restart empties the one map there was, so a captured ticket brokers again — once per replica, and
// again after every restart — for the remainder of its ~2-minute TTL. Single use is a property of
// the TICKET, so the ledger lives with the issuer:
//
//	POST <SIGNALING_DEVICE_IDENTITY_URL>/internal/session-tickets/redeem
//	Authorization: Bearer <SIGNALING_DEVICE_IDENTITY_TOKEN>
//
// Deliberately the SAME endpoint configuration as the device-identity lookup: same host, same
// service token, no new secret to distribute, rotate, or get wrong.
//
// =====================================================================================
// THIS LOOKUP FAILS OPEN. THAT IS THE OPPOSITE OF deviceidentity.go, AND IT IS DELIBERATE.
// =====================================================================================
// Device-identity resolution fails CLOSED because it AUTHENTICATES A NEW PRINCIPAL: without an
// answer there is no basis on which to believe a connection is the agent it claims to be, so the
// only safe verdict is refusal.
//
// Redemption authenticates nothing. By the time it is called, the ticket has ALREADY been proven
// to be:
//
//   - signed by the control plane's grant-issuer key (Ed25519, over the canonical v1 preimage),
//   - version 1, unexpired, and issued within the clock-skew allowance — a ~2-minute credential,
//   - bound to a tenant, and to a tenant that matches the target agent's,
//   - bound to the specific device the connect_request names.
//
// All redemption adds is DE-DUPLICATION of that already-verified credential. So when the control
// plane cannot answer — timeout, connection refused, 5xx, 401, a route that does not exist because
// the control plane predates it — the broker proceeds on the LOCAL verdict alone and logs loudly.
//
// Refusing instead would mean that a control-plane restart, a rolling deploy, or one slow query
// stops the WHOLE FLEET from brokering any session at all. That outage is both far worse and far
// more likely than the replay this defends against, and it would convert a routine maintenance
// window into a total loss of remote access. The local map still stands during the blip: it is the
// first line of defence and the only one that works with the control plane unreachable.
//
// ONLY a definitive "already redeemed" (HTTP 409) refuses a broker.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// ticketRedeemTimeout bounds one redemption call. Much shorter than deviceIdentityTimeout on
	// purpose: this call sits on the INTERACTIVE path (a technician waiting for a session to open)
	// and its answer is advisory, so a control plane that is merely slow must not add seconds to
	// every session setup. Exceeding it is a transport failure like any other — we proceed.
	ticketRedeemTimeout = 2 * time.Second
)

// ErrTicketAlreadyRedeemed is the ONE definitive answer: this ticket's single use is already spent
// somewhere in the deployment. It is the only redemption error that refuses a broker; every other
// error means "the ledger could not answer", which is not a verdict.
var ErrTicketAlreadyRedeemed = errors.New("session ticket already redeemed")

// TicketRedeemer records a verified ticket's single use in the control plane's shared ledger.
//
// Implementations MUST return ErrTicketAlreadyRedeemed only for a definitive replay answer. Any
// other error is treated as "unavailable" and does not refuse the broker, so returning it for a
// suspected replay would silently disable the defence.
type TicketRedeemer interface {
	Redeem(ctx context.Context, claims TicketClaims) error
}

// httpTicketRedeemer is the TicketRedeemer backed by the control plane's redemption endpoint.
//
// No cache, unlike httpIdentityResolver: a cache would answer "already redeemed" for a ticket this
// process itself redeemed, which the local map already covers, and would answer stale for every
// other case. Every redemption is one request, exactly once per brokered session.
type httpTicketRedeemer struct {
	baseURL string
	token   string
	client  *http.Client
}

// ticketRedeemRequest is the wire body, matching the control plane's sessionTicketRedeemRequest.
type ticketRedeemRequest struct {
	TenantID    string `json:"tenant_id"`
	SessionID   string `json:"session_id"`
	DeviceID    string `json:"device_id"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
}

// newHTTPTicketRedeemer validates the endpoint configuration up front, mirroring
// newHTTPIdentityResolver, so a misconfigured deployment is a startup error rather than a surprise
// at the first brokered session.
func newHTTPTicketRedeemer(baseURL, token string) (*httpTicketRedeemer, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("SIGNALING_DEVICE_IDENTITY_URL must be an http(s) base URL, e.g. https://cp.example:8443")
	}
	if len(token) < deviceIdentityTokenMinLen {
		return nil, fmt.Errorf("SIGNALING_DEVICE_IDENTITY_TOKEN must be at least %d characters", deviceIdentityTokenMinLen)
	}
	return &httpTicketRedeemer{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: ticketRedeemTimeout},
	}, nil
}

// Redeem records the ticket's one use. nil means "first use, proceed"; ErrTicketAlreadyRedeemed
// means "replay, refuse"; anything else means the ledger could not answer (see the file header for
// what the caller does with that, and why).
func (r *httpTicketRedeemer) Redeem(ctx context.Context, claims TicketClaims) error {
	body, err := json.Marshal(ticketRedeemRequest{
		TenantID:    claims.TenantID,
		SessionID:   claims.SessionID,
		DeviceID:    claims.DeviceID,
		ExpiresAtMs: claims.ExpiresAtMs,
	})
	if err != nil {
		return fmt.Errorf("ticket redemption: encode request: %w", err)
	}
	endpoint := r.baseURL + "/internal/session-tickets/redeem"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ticket redemption request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("ticket redemption: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Recorded here for the first time. The body says {"redeemed": true} and is not read: the
		// status IS the answer, and parsing a body would add a way to fail that changes nothing.
		return nil
	case http.StatusConflict:
		return ErrTicketAlreadyRedeemed
	default:
		// Everything else — 401 (token mismatch), 404 (a control plane without this route), 429, 5xx
		// — is "could not answer". Named individually in the log so an operator can tell a
		// misconfiguration from an outage, since both otherwise look like sessions that keep working.
		return fmt.Errorf("ticket redemption: control plane returned %d", resp.StatusCode)
	}
}

// ticketRedeemerFromEnv builds the redeemer from the SAME pair the device-identity resolver uses:
// SIGNALING_DEVICE_IDENTITY_URL and SIGNALING_DEVICE_IDENTITY_TOKEN. Returns (nil, nil) when either
// is unset — the caller then runs on the local map alone and says so, loudly, once at startup.
//
// Note the return type: (TicketRedeemer, error), never a typed nil, so `redeemer == nil` at the
// call site means what it reads as.
func ticketRedeemerFromEnv() (TicketRedeemer, error) {
	base := strings.TrimSpace(os.Getenv("SIGNALING_DEVICE_IDENTITY_URL"))
	token := strings.TrimSpace(os.Getenv("SIGNALING_DEVICE_IDENTITY_TOKEN"))
	if base == "" || token == "" {
		return nil, nil
	}
	redeemer, err := newHTTPTicketRedeemer(base, token)
	if err != nil {
		return nil, err
	}
	return redeemer, nil
}
