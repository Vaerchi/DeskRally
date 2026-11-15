package controlplane

import "testing"

// Audit 2026-11-01 #2: a THROTTLED anonymous OIDC request must not append a tenant audit row.
// MUTATION: restore the s.oidcAuditFailure(..., "ip_throttled") call in oidcPublic -> this fails.
func TestB2bHTTPThrottledRequestsWriteNoAuditRows(t *testing.T) {
	f := b2bFixture(t)
	f.remoteAddr = "198.51.100.77:4000"
	throttled := 0
	// Trip the per-IP throttle with real failures (each is audited, and bounded by the budget).
	for i := 0; i < 30 && throttled == 0; i++ {
		if w := f.request("GET", "/auth/oidc/callback?state=x", ""); w.Code == 429 {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatal("per-IP OIDC throttle never engaged")
	}
	before := f.auditCount("auth.login_failed")
	for i := 0; i < 200; i++ {
		if w := f.request("GET", "/auth/oidc/callback?state=x", ""); w.Code != 429 {
			t.Fatalf("request %d: status %d, want 429 while throttled", i, w.Code)
		}
	}
	if after := f.auditCount("auth.login_failed"); after != before {
		t.Fatalf("200 throttled requests wrote %d audit rows", after-before)
	}
}
