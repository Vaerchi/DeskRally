package controlplane

// Tests for SSRF protection in the webhook delivery path.
//
// The 08:43 UTC checkpoint noted that scheme-only validation (https:// only at registration time)
// does not prevent connections to loopback (127.x.x.x / ::1), private networks
// (10.x / 172.16-31.x / 192.168.x / fc00::/7), or link-local addresses (169.254.x.x including
// cloud IMDS, fe80::/10), nor does it cover DNS-rebinding or redirects.
//
// These tests cover:
//   - webhookIsForbiddenIP: unit test for all IP categories
//   - checkWebhookRedirect: unit test for redirect scheme enforcement
//   - TestWebhookSSRFBlocksLoopback: integration — delivery to 127.0.0.1 fails when Client=nil
//   - TestWebhookSSRFMutations: explicit mutation guards

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWebhookIsForbiddenIP covers all IP categories that the SSRF filter must block.
func TestWebhookIsForbiddenIP(t *testing.T) {
	cases := []struct {
		addr    string
		blocked bool
		note    string
	}{
		// --- must block ---
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.255.255.255", true, "IPv4 loopback (last)"},
		{"::1", true, "IPv6 loopback"},
		{"10.0.0.1", true, "RFC 1918 class A"},
		{"10.255.255.255", true, "RFC 1918 class A last"},
		{"172.16.0.1", true, "RFC 1918 class B start"},
		{"172.31.255.255", true, "RFC 1918 class B end"},
		{"192.168.0.1", true, "RFC 1918 class C"},
		{"192.168.255.255", true, "RFC 1918 class C last"},
		{"fc00::1", true, "RFC 4193 ULA"},
		{"fd00::1", true, "RFC 4193 ULA fd00::/8"},
		{"169.254.0.1", true, "IPv4 link-local"},
		{"169.254.169.254", true, "AWS/GCP/Azure IMDS"},
		{"169.254.255.255", true, "IPv4 link-local last"},
		{"fe80::1", true, "IPv6 link-local"},
		{"224.0.0.1", true, "IPv4 link-local multicast"},
		{"239.255.255.255", true, "IPv4 global multicast (last)"},
		{"ff02::1", true, "IPv6 link-local multicast"},
		{"ff0e::1", true, "IPv6 global multicast"},
		{"100.64.0.1", true, "RFC 6598 CGNAT start"},
		{"100.127.255.255", true, "RFC 6598 CGNAT last"},
		{"0.0.0.0", true, "IPv4 unspecified"},
		{"::", true, "IPv6 unspecified"},
		// --- must allow ---
		{"8.8.8.8", false, "Google public DNS"},
		{"1.1.1.1", false, "Cloudflare public DNS"},
		{"93.184.216.34", false, "example.com (IANA)"},
		{"2606:4700:4700::1111", false, "Cloudflare IPv6"},
		{"172.15.255.255", false, "just below RFC 1918 class B"},
		{"172.32.0.0", false, "just above RFC 1918 class B"},
		{"100.63.255.255", false, "just below CGNAT block"},
		{"100.128.0.0", false, "just above CGNAT block"},
	}
	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			ip := net.ParseIP(tc.addr)
			if ip == nil {
				t.Fatalf("ParseIP(%q) failed", tc.addr)
			}
			got := webhookIsForbiddenIP(ip)
			if got != tc.blocked {
				t.Errorf("webhookIsForbiddenIP(%s) = %v, want %v (%s)", tc.addr, got, tc.blocked, tc.note)
			}
		})
	}
}

// TestWebhookCheckRedirect tests the redirect policy in isolation.
func TestWebhookCheckRedirect(t *testing.T) {
	via := []*http.Request{{}} // one hop already in chain

	// http:// redirect must be blocked regardless of destination.
	httpReq, _ := http.NewRequest("GET", "http://external.example/path", nil)
	if err := checkWebhookRedirect(httpReq, via); err == nil {
		t.Error("redirect to http:// must be blocked; got nil error")
	}

	// https:// redirect is allowed (destination IP checked separately by DialContext).
	httpsReq, _ := http.NewRequest("GET", "https://external.example/path", nil)
	if err := checkWebhookRedirect(httpsReq, via); err != nil {
		t.Errorf("redirect to https:// must be allowed; got error: %v", err)
	}

	// Redirect chain cap: 2+ prior hops blocked (i.e., would be 3rd request total).
	longVia := []*http.Request{{}, {}}
	if err := checkWebhookRedirect(httpsReq, longVia); err == nil {
		t.Error("redirect chain of 2+ prior hops must be blocked; got nil error")
	}
	// Exactly 1 prior hop is still allowed (would be 2nd request total).
	oneHop := []*http.Request{{}}
	if err := checkWebhookRedirect(httpsReq, oneHop); err != nil {
		t.Errorf("redirect with 1 prior hop must be allowed; got error: %v", err)
	}
}

// TestWebhookSSRFBlocksLoopback verifies that a delivery to 127.0.0.1 (httptest.Server)
// fails when WebhookDispatcher.Client is nil — i.e., the SSRF-safe transport is used.
// httptest.NewServer always binds to 127.0.0.1, which is a loopback address.
//
// This test does NOT probe production or internal services. It verifies that our code
// refuses to connect to the same loopback interface it is running on.
func TestWebhookSSRFBlocksLoopback(t *testing.T) {
	// Start a server that would succeed if it receives any request.
	contacted := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	store := NewInMemoryWebhookStore()
	wh := &TenantWebhook{ID: "wh-ssrf", URL: ts.URL, Events: []string{"test.event"}}
	if err := store.Create(context.Background(), "tenant-ssrf", wh, "secret-ssrf", 10); err != nil {
		t.Fatal(err)
	}

	// Client is nil → webhookSafeClient() used → loopback blocked.
	d := &WebhookDispatcher{Store: store}
	event := &MgmtAuditEvent{Action: "test.event"}
	// dispatchSync returns an error only on store failure; delivery errors are recorded per-webhook.
	if err := d.dispatchSync("tenant-ssrf", event); err != nil {
		t.Fatalf("dispatchSync store error: %v", err)
	}

	if contacted {
		t.Error("SSRF protection failed: the loopback server was contacted")
	}

	recs := d.RecentDeliveries("wh-ssrf")
	if len(recs) == 0 {
		t.Fatal("expected delivery records (even failed ones); got none")
	}
	for _, rec := range recs {
		if rec.Success {
			t.Errorf("attempt %d reported Success=true for a loopback target", rec.Attempt)
		}
		if !strings.Contains(rec.Error, "SSRF") && !strings.Contains(rec.Error, "loopback") && !strings.Contains(rec.Error, "private") {
			t.Errorf("attempt %d error %q does not mention SSRF/loopback/private", rec.Attempt, rec.Error)
		}
	}
}

// TestWebhookSSRFMutations documents explicit mutation guards for the SSRF code path.
//
// M1: Remove ip.IsLoopback() from webhookIsForbiddenIP → 127.0.0.1 passes → TestWebhookSSRFBlocksLoopback fails
// M2: Remove ip.IsPrivate() → 192.168.x.x passes → "RFC 1918 class C" case fails
// M3: Remove ip.IsLinkLocalUnicast() → 169.254.169.254 passes → "AWS/GCP/Azure IMDS" case fails
// M4: Remove ip.IsMulticast() → 239.x.x.x passes → "IPv4 global multicast" case fails
// M5: Remove cgnatBlock.Contains() → 100.64.x.x passes → "RFC 6598 CGNAT start" case fails
// M6: Remove http:// check in checkWebhookRedirect → TestWebhookCheckRedirect fails
// M7: Remove webhookSafeClient() (always use default client) → TestWebhookSSRFBlocksLoopback contacted=true → fails
func TestWebhookSSRFMutations(t *testing.T) {
	loopback := net.ParseIP("127.0.0.1")            // M1
	privateC := net.ParseIP("192.168.1.100")         // M2
	linkLocalIMDS := net.ParseIP("169.254.169.254")  // M3
	globalMulticast := net.ParseIP("239.255.255.255") // M4
	cgnat := net.ParseIP("100.64.0.1")               // M5

	if !webhookIsForbiddenIP(loopback) {
		t.Error("M1: 127.0.0.1 must be blocked (loopback); removing IsLoopback() would pass this through")
	}
	if !webhookIsForbiddenIP(privateC) {
		t.Error("M2: 192.168.1.100 must be blocked (private); removing IsPrivate() would pass this through")
	}
	if !webhookIsForbiddenIP(linkLocalIMDS) {
		t.Error("M3: 169.254.169.254 must be blocked (link-local); removing IsLinkLocalUnicast() would pass this through")
	}
	if !webhookIsForbiddenIP(globalMulticast) {
		t.Error("M4: 239.255.255.255 must be blocked (multicast); removing IsMulticast() would pass this through")
	}
	if !webhookIsForbiddenIP(cgnat) {
		t.Error("M5: 100.64.0.1 must be blocked (CGNAT); removing cgnatBlock.Contains() would pass this through")
	}
	// M6: http redirect blocked (TestWebhookCheckRedirect).
	// M7: loopback server not contacted (TestWebhookSSRFBlocksLoopback).
}
