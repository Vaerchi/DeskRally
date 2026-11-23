package main

import (
	"errors"
	"log"
	"strings"
	"testing"
)

// Signed ticket claims are issuer-authenticated but carry no length bound, and every diagnostic
// below is logged. Each leg mints a VALID signed ticket with an oversized claim, drives the real
// broker path, and checks the diagnostic is bounded, with a short-value positive control.

func requireBoundedDiag(t *testing.T, what, text, huge, mustContain string) {
	t.Helper()
	if !strings.Contains(text, mustContain) {
		t.Fatalf("%s: wrong diagnostic (want %q): %q", what, mustContain, clipForLog(text))
	}
	if len(text) >= 1024 || strings.Contains(text, huge) {
		t.Fatalf("%s: diagnostic is %d bytes / carries the full claim", what, len(text))
	}
}

func hugeSessionClaims() (TicketClaims, string) {
	claims := ticketGoldenClaims()
	huge := strings.Repeat("s", 60*1024)
	claims.SessionID = huge
	return claims, huge
}

func TestLocalReplayErrorClipsSessionID(t *testing.T) {
	claims, huge := hugeSessionClaims()
	broker, controller, _ := ticketBroker(t, claims.DeviceID)
	ticket := mintTicket(t, claims)
	if _, err := broker.ConnectRequest(controller, claims.DeviceID, ticket); err != nil {
		t.Fatalf("premise not met: first use of the oversized-session ticket was refused: %v", err)
	}
	_, err := broker.ConnectRequest(controller, claims.DeviceID, ticket)
	if err == nil || !errors.Is(err, errTicketInvalid) {
		t.Fatalf("replay: err = %v, want errTicketInvalid", err)
	}
	requireBoundedDiag(t, "local replay", err.Error(), huge, "was already used")

	// Positive control: the golden (short) session id is reported in full.
	short := ticketGoldenClaims()
	b2, c2, _ := ticketBroker(t, short.DeviceID)
	st := mintTicket(t, short)
	_, _ = b2.ConnectRequest(c2, short.DeviceID, st)
	if _, err := b2.ConnectRequest(c2, short.DeviceID, st); err == nil || !strings.Contains(err.Error(), short.SessionID) {
		t.Fatalf("short session id not reported in full: %v", err)
	}
}

func TestRedeemedElsewhereErrorClipsSessionID(t *testing.T) {
	claims, huge := hugeSessionClaims()
	ledger := newFakeRedeemer()
	a, ca, _ := redeemingBroker(t, claims.DeviceID, ledger)
	b, cb, _ := redeemingBroker(t, claims.DeviceID, ledger.sharing())
	if _, err := a.ConnectRequest(ca, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("premise not met: instance A refused the ticket: %v", err)
	}
	_, err := b.ConnectRequest(cb, claims.DeviceID, mintTicket(t, claims))
	if err == nil || !errors.Is(err, errTicketInvalid) {
		t.Fatalf("replay at instance B: err = %v, want errTicketInvalid", err)
	}
	requireBoundedDiag(t, "redeemed elsewhere", err.Error(), huge, "already redeemed elsewhere")
}

func TestLedgerOutageLogsClipSessionID(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := map[bool]string{false: "fail-open", true: "strict"}[strict]
		t.Run(name, func(t *testing.T) {
			sink := make(reviewLogSink, 32)
			old := log.Writer()
			log.SetOutput(sink)
			t.Cleanup(func() { log.SetOutput(old) })

			claims, huge := hugeSessionClaims()
			ledger := newFakeRedeemer()
			ledger.err = errors.New("synthetic ledger outage")
			broker, controller, _ := redeemingBroker(t, claims.DeviceID, ledger)
			if strict {
				broker = broker.WithStrictTicketRedemption()
			}
			_, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims))
			if strict != (err != nil) {
				t.Fatalf("%s: ConnectRequest err = %v", name, err)
			}
			want := map[bool]string{false: "WARNING: session-ticket ledger unavailable", true: "ERROR: session-ticket ledger unavailable"}[strict]
			for {
				select {
				case record := <-sink:
					if !strings.Contains(record, "ledger unavailable") {
						continue
					}
					requireBoundedDiag(t, name+" log", record, huge, want)
					if !strings.Contains(record, "...(61440 bytes)") {
						t.Fatalf("%s: clipped session id lacks its length marker", name)
					}
					return
				default:
					t.Fatalf("%s: no ledger-outage log line was written", name)
				}
			}
		})
	}
}

func TestTenantMismatchErrorClipsBothTenants(t *testing.T) {
	claims := ticketGoldenClaims()
	huge := strings.Repeat("t", 60*1024)
	claims.TenantID = huge
	broker, controller, _ := ticketBrokerTenant(t, claims.DeviceID, "agent-tenant")
	_, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims))
	if err == nil || !errors.Is(err, errTicketInvalid) {
		t.Fatalf("tenant mismatch: err = %v, want errTicketInvalid", err)
	}
	requireBoundedDiag(t, "ticket tenant", err.Error(), huge, "ticket for tenant")

	// The agent-declared tenant is the other operand (a register_agent field in dev mode).
	short := ticketGoldenClaims()
	b2, c2, _ := ticketBrokerTenant(t, short.DeviceID, huge)
	_, err = b2.ConnectRequest(c2, short.DeviceID, mintTicket(t, short))
	if err == nil {
		t.Fatal("agent tenant mismatch was accepted")
	}
	requireBoundedDiag(t, "agent tenant", err.Error(), huge, "target agent registered under tenant")

	// Positive control: short tenants are reported in full.
	b3, c3, _ := ticketBrokerTenant(t, short.DeviceID, "agent-tenant")
	other := short
	other.TenantID = "ticket-tenant"
	_, err = b3.ConnectRequest(c3, short.DeviceID, mintTicket(t, other))
	if err == nil || !strings.Contains(err.Error(), `ticket for tenant "ticket-tenant", target agent registered under tenant "agent-tenant"`) {
		t.Fatalf("short tenants not reported in full: %v", err)
	}
}
