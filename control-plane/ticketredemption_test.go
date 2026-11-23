package controlplane

// The shared single-use ledger for session tickets, at the HTTP surface and over the in-memory
// store. The pgx twin — real SQL, real RLS, real concurrency — lives in
// ticketredemption_pgstore_test.go (DB-gated).
//
// What this file is FOR: the endpoint must answer a replay DISTINGUISHABLY. Its caller
// (server/signaling) proceeds on its local verdict for every non-definitive answer, so an
// "already redeemed" that arrived as a 500 — or as a 200 — would be silently ignored and the whole
// ledger would be decorative.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	redeemTenantID  = "8b0e2f7c-3a4d-4c1e-9f22-6d5b1a7c4e30"
	redeemSessionID = "1f9a6c55-7d21-4bb0-8e3a-2c4f6d9b0a11"
	redeemDeviceID  = "c9d3e1a7-05b4-4f68-9a2c-7e1b3d5f8c40"
)

// ticketRedeemServer wires the in-memory ledger plus the service token, throttling off so a test
// can drive many attempts without tripping the limiter (metering has its own test below).
func ticketRedeemServer(t *testing.T) (*Server, *InMemoryTicketRedemptionStore) {
	t.Helper()
	store := NewInMemoryTicketRedemptionStore()
	srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
	srv.TicketRedemptions = store
	// Wired only so the sibling device-identity route mounts too — this endpoint does not use it,
	// and the pair sharing one service token is the arrangement under test.
	srv.Machines = NewInMemoryMachineStore()
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.DisableThrottle = true
	return srv, store
}

// postTicketRedeem issues POST /internal/session-tickets/redeem with the given raw body and
// Authorization header value ("" ⇒ no header).
func postTicketRedeem(t *testing.T, srv *Server, body []byte, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/internal/session-tickets/redeem", bytes.NewReader(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// redeemBody marshals a redeem request body.
func redeemBody(t *testing.T, tenantID, sessionID, deviceID string, expiresAtMs int64) []byte {
	t.Helper()
	raw, err := json.Marshal(sessionTicketRedeemRequest{
		TenantID:    tenantID,
		SessionID:   sessionID,
		DeviceID:    deviceID,
		ExpiresAtMs: expiresAtMs,
	})
	if err != nil {
		t.Fatalf("marshal redeem body: %v", err)
	}
	return raw
}

// The contract in one test: the first use is recorded and reported new; the second is refused with
// a status the caller can act on; and the ledger is keyed on (tenant, session), so the same session
// id in another tenant is a different ticket.
func TestSessionTicketRedeemFirstUseThenReplay(t *testing.T) {
	srv, store := ticketRedeemServer(t)
	exp := time.Now().Add(2 * time.Minute).UnixMilli()
	body := redeemBody(t, redeemTenantID, redeemSessionID, redeemDeviceID, exp)

	first := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken)
	if first.Code != http.StatusOK {
		t.Fatalf("first redemption = %d (body %s), want 200", first.Code, first.Body.String())
	}
	var payload struct {
		Redeemed bool `json:"redeemed"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &payload); err != nil || !payload.Redeemed {
		t.Fatalf("first redemption payload (err %v): %s", err, first.Body.String())
	}

	replay := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay = %d (body %s), want 409 — a replay MUST be distinguishable from an outage",
			replay.Code, replay.Body.String())
	}

	// Same session id, different tenant: a different ticket, and not a replay of this one.
	other := redeemBody(t, "3c7e5d91-2b46-4a08-b1f3-9e6c0a4d8b25", redeemSessionID, redeemDeviceID, exp)
	if rec := postTicketRedeem(t, srv, other, "Bearer "+deviceIdentityToken); rec.Code != http.StatusOK {
		t.Fatalf("same session id in another tenant = %d (body %s), want 200", rec.Code, rec.Body.String())
	}

	// The device the ticket named is recorded, so a refused replay can be traced to a machine.
	rec, err := store.RedeemTicket(t.Context(), redeemTenantID, redeemSessionID, redeemDeviceID, time.Now())
	if err != ErrTicketAlreadyRedeemed || rec != nil {
		t.Fatalf("store.RedeemTicket after use = (%v, %v), want (nil, ErrTicketAlreadyRedeemed)", rec, err)
	}
}

// The endpoint is service-token gated exactly like its device-identity sibling, and refuses with
// the same opaque 401.
func TestSessionTicketRedeemRequiresServiceToken(t *testing.T) {
	srv, _ := ticketRedeemServer(t)
	body := redeemBody(t, redeemTenantID, redeemSessionID, redeemDeviceID, time.Now().Add(time.Minute).UnixMilli())

	for name, header := range map[string]string{
		"missing":     "",
		"wrong token": "Bearer " + deviceIdentityToken[:31] + "X",
		"not bearer":  deviceIdentityToken,
		"empty token": "Bearer ",
	} {
		if rec := postTicketRedeem(t, srv, body, header); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s auth = %d, want 401", name, rec.Code)
		}
	}
	// …and none of those attempts recorded anything, so a valid one still reads as the FIRST use.
	if rec := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken); rec.Code != http.StatusOK {
		t.Fatalf("authorized redemption after failed auth attempts = %d, want 200", rec.Code)
	}
}

// The route EXISTS only when the service token is long enough AND a ledger is wired. Both absences
// degrade to "no route", which the signaling server reads as "cannot answer" and survives — the
// same behaviour it gets from a control plane predating this endpoint.
func TestSessionTicketRedeemRouteRequiresTokenAndStore(t *testing.T) {
	body := redeemBody(t, redeemTenantID, redeemSessionID, redeemDeviceID, time.Now().Add(time.Minute).UnixMilli())

	cases := map[string]func(*Server){
		"token unset":     func(s *Server) { s.DeviceIdentityToken = "" },
		"token too short": func(s *Server) { s.DeviceIdentityToken = deviceIdentityToken[:DeviceIdentityTokenMinLen-1] },
		"no ledger wired": func(s *Server) { s.TicketRedemptions = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			srv, _ := ticketRedeemServer(t)
			mutate(srv)
			// Unmounted: the request falls through to the protected "/" catch-all, whose stub
			// authenticator has a nil principal → 401, never a 200 recording a redemption.
			rec := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken)
			if rec.Code == http.StatusOK || rec.Code == http.StatusConflict {
				t.Fatalf("%s served the ledger (%d %s); the route must not be mounted",
					name, rec.Code, rec.Body.String())
			}
			// For the missing-STORE case that assertion is not enough on its own: the handler's own
			// defensive nil check would answer 500 and still satisfy it, so an unconditionally
			// mounted route would slip past. The handler's 500 is a distinguishable string, so
			// require that the handler did not run AT ALL.
			if name == "no ledger wired" && strings.Contains(rec.Body.String(), "ticket redemption store not configured") {
				t.Fatalf("the route was mounted without a ledger (body %s); the mount must be gated "+
					"on the store, not merely survived by the handler", rec.Body.String())
			}
		})
	}
}

// THE METERING EXCEPTION, and it is the whole reason this endpoint can be trusted under attack.
// Failed AUTH is metered like every other service-token route; a 409 REPLAY is deliberately not.
// Metering the replay would let an attacker who captured ONE ticket lock out the signaling server's
// source address by replaying it in a loop — after which every redemption returns 429, signaling
// falls open by design, and the defence has been switched off by the traffic it was built for.
func TestSessionTicketRedeemDoesNotMeterReplays(t *testing.T) {
	srv, _ := ticketRedeemServer(t)
	srv.DisableThrottle = false
	srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 2})
	body := redeemBody(t, redeemTenantID, redeemSessionID, redeemDeviceID, time.Now().Add(time.Minute).UnixMilli())

	if rec := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken); rec.Code != http.StatusOK {
		t.Fatalf("first redemption = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// Far past the free allowance: every one of these must still be answered 409, not 429.
	for i := 0; i < 10; i++ {
		if rec := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken); rec.Code != http.StatusConflict {
			t.Fatalf("replay %d = %d (body %s), want 409 — a replay must not consume the source's budget",
				i, rec.Code, rec.Body.String())
		}
	}
	// A FRESH ticket from the same source is still served, i.e. the source was never locked out.
	fresh := redeemBody(t, redeemTenantID, "6d2b8f10-4c93-4a57-9e01-3b7d5a2c8f64", redeemDeviceID,
		time.Now().Add(time.Minute).UnixMilli())
	if rec := postTicketRedeem(t, srv, fresh, "Bearer "+deviceIdentityToken); rec.Code != http.StatusOK {
		t.Fatalf("fresh ticket after 10 replays = %d, want 200 — replays locked the source out", rec.Code)
	}
	// Bad AUTH, by contrast, IS metered: the free allowance is spent by failures and the lockout
	// begins once one lands beyond it.
	for i := 0; i < 3; i++ {
		if rec := postTicketRedeem(t, srv, fresh, "Bearer wrong-token-wrong-token-wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad-auth attempt %d = %d, want 401", i, rec.Code)
		}
	}
	if rec := postTicketRedeem(t, srv, fresh, "Bearer wrong-token-wrong-token-wrong"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("bad auth past the free allowance = %d, want 429", rec.Code)
	}
}

// The row's expiry is clamped, not trusted. The caller is authenticated by a shared service token
// alone, so a compromised or buggy one must not be able to date rows years out and pin them past
// every reap.
func TestSessionTicketRedeemClampsExpiry(t *testing.T) {
	srv, store := ticketRedeemServer(t)
	farFuture := time.Now().Add(50 * 365 * 24 * time.Hour).UnixMilli()
	body := redeemBody(t, redeemTenantID, redeemSessionID, redeemDeviceID, farFuture)
	if rec := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken); rec.Code != http.StatusOK {
		t.Fatalf("redeem = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	store.mu.Lock()
	got := store.redeemed[redeemTenantID+"\x00"+redeemSessionID]
	store.mu.Unlock()
	ceiling := time.Now().Add(sessionTicketRedemptionMaxTTL + time.Minute)
	if got.ExpiresAt.After(ceiling) {
		t.Fatalf("recorded expiry %s exceeds the clamp (%s)", got.ExpiresAt, ceiling)
	}

	// An HONEST expiry inside the ceiling is kept as-is: the row means "this ticket cannot verify
	// after this instant", and rounding every entry up to the ceiling would keep dead tickets
	// remembered for an hour apiece.
	honest := time.Now().Add(2 * time.Minute).Truncate(time.Millisecond)
	body2 := redeemBody(t, redeemTenantID, "0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d", redeemDeviceID, honest.UnixMilli())
	if rec := postTicketRedeem(t, srv, body2, "Bearer "+deviceIdentityToken); rec.Code != http.StatusOK {
		t.Fatalf("redeem 2 = %d, want 200", rec.Code)
	}
	store.mu.Lock()
	got2 := store.redeemed[redeemTenantID+"\x000a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"]
	store.mu.Unlock()
	if !got2.ExpiresAt.Equal(honest) {
		t.Fatalf("recorded expiry = %s, want the ticket's own %s", got2.ExpiresAt, honest)
	}
}

// A malformed or incomplete body is a 400, never a silent 200 — a caller whose request never
// reached the ledger must not be told the ticket was recorded.
func TestSessionTicketRedeemRejectsBadBodies(t *testing.T) {
	srv, _ := ticketRedeemServer(t)
	for name, body := range map[string][]byte{
		"not json":       []byte("{"),
		"empty object":   []byte(`{}`),
		"no tenant":      redeemBody(t, "", redeemSessionID, redeemDeviceID, 0),
		"no session":     redeemBody(t, redeemTenantID, "", redeemDeviceID, 0),
		"wrong shape":    []byte(`{"tenant_id":123}`),
		"empty document": nil,
	} {
		if rec := postTicketRedeem(t, srv, body, "Bearer "+deviceIdentityToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d (body %s), want 400", name, rec.Code, rec.Body.String())
		}
	}
}

// The in-memory twin of the durable redeemed_at marker: WasRedeemed survives the ledger prune.
func TestInMemoryWasRedeemedSurvivesThePrune(t *testing.T) {
	now := time.Now()
	s := NewInMemoryTicketRedemptionStore()
	s.Now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := s.RedeemTicket(ctx, "t1", "s1", "dev", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour) // the ticket has expired
	if _, err := s.RedeemTicket(ctx, "t1", "s2", "dev", now.Add(time.Minute)); err != nil {
		t.Fatal(err) // any redemption prunes the expired s1 entry
	}
	if ok, _ := s.WasRedeemed(ctx, "t1", "s1"); !ok {
		t.Fatal("WasRedeemed forgot s1 after the prune")
	}
	if ok, _ := s.WasRedeemed(ctx, "t1", "never"); ok {
		t.Fatal("a never-redeemed session reads as redeemed")
	}
}
