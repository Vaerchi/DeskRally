package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdmissionRefusesWithNoOriginPolicy(t *testing.T) {
	t.Parallel()
	for _, in := range []admissionInput{
		{},
		{siteAddress: "  ,  "},
		{allowedOrigins: " , ", tenantHostSuffix: ".example.com"}, // a suffix alone is not a policy
		{production: true},
	} {
		_, err := decideAdmission(in)
		if err == nil || !strings.Contains(err.Error(), "SIGNALING_ALLOWED_ORIGINS") || !strings.Contains(err.Error(), "SIGNALING_SITE_ADDRESS") {
			t.Fatalf("%+v: want a refusal naming both variables, got %v", in, err)
		}
	}
}

func TestAdmissionAllowsExplicitAndDerivedOrigins(t *testing.T) {
	t.Parallel()
	d, err := decideAdmission(admissionInput{allowedOrigins: "https://a.example.com,https://b.example.com", trustedProxies: "172.18.0.0/16"})
	if err != nil || !d.origins.enforcing() || d.origins.originCount() != 2 {
		t.Fatalf("explicit: %+v %v", d, err)
	}
	d, err = decideAdmission(admissionInput{siteAddress: "console.example.com, tenant-a.example.com, tenant-b.example.com", tenantHostSuffix: ".example.com"})
	if err != nil || !d.origins.enforcing() || len(d.origins.allowed) != 3 || len(d.origins.wild) != 1 {
		t.Fatalf("derived: %+v %v", d, err)
	}
	// An explicit value wins over the site address (production: explicit list + site address).
	d, err = decideAdmission(admissionInput{allowedOrigins: "https://x.example.com", siteAddress: "y.example.com"})
	if err != nil || len(d.origins.allowed) != 1 || d.origins.allowed[0] != "https://x.example.com" {
		t.Fatalf("explicit must win: %+v %v", d, err)
	}
	// A malformed site address is still an error, not an open policy.
	if _, err = decideAdmission(admissionInput{siteAddress: "https://x.example.com"}); err == nil {
		t.Fatal("scheme in SITE_ADDRESS must be refused")
	}
}

func TestAdmissionOptOutIsOnlyTheExactStar(t *testing.T) {
	t.Parallel()
	d, err := decideAdmission(admissionInput{allowedOrigins: "*"})
	if err != nil || !d.origins.any || d.origins.enforcing() {
		t.Fatalf("exact *: %+v %v", d, err)
	}
	d, err = decideAdmission(admissionInput{allowedOrigins: " * "})
	if err != nil || !d.origins.any {
		t.Fatalf("trimmed *: %+v %v", d, err)
	}
	for _, v := range []string{"**", "*,https://a.example.com", "any", "true", "i-understand", "0", "off"} {
		if _, err := decideAdmission(admissionInput{allowedOrigins: v}); err == nil {
			t.Fatalf("%q must not open the policy", v)
		}
	}
}

func TestAdmissionPerIPDefaultAndExplicit(t *testing.T) {
	t.Parallel()
	base := admissionInput{allowedOrigins: "https://a.example.com"}
	d, err := decideAdmission(base)
	if err != nil || d.maxPerIP != defaultMaxConnectionsPerIP || d.maxPerIPSource != "default" || defaultMaxConnectionsPerIP != 64 {
		t.Fatalf("default: %+v %v", d, err)
	}
	for raw, want := range map[string]int{"0": 0, "5": 5, " 100 ": 100} {
		in := base
		in.maxPerIP = raw
		d, err = decideAdmission(in)
		if err != nil || d.maxPerIP != want || d.maxPerIPSource != "env" {
			t.Fatalf("%q: %+v %v", raw, d, err)
		}
	}
	for _, raw := range []string{"-1", "x", "1.5"} {
		in := base
		in.maxPerIP = raw
		if _, err = decideAdmission(in); err == nil {
			t.Fatalf("%q must be refused", raw)
		}
	}
}

func TestAdmissionTrustedProxyRule(t *testing.T) {
	t.Parallel()
	base := admissionInput{allowedOrigins: "https://a.example.com"}
	// Not production, no proxies: socket address, one INFO note saying so (never a silent bucket).
	d, err := decideAdmission(base)
	if err != nil || len(d.notes) != 1 || !strings.Contains(d.notes[0], "TCP peer address") {
		t.Fatalf("bare: %+v %v", d, err)
	}
	// Production, cap in force (default or explicit), no proxies: refused.
	for _, cap := range []string{"", "64"} {
		in := base
		in.production, in.maxPerIP = true, cap
		if _, err = decideAdmission(in); err == nil || !strings.Contains(err.Error(), "SIGNALING_TRUSTED_PROXIES") {
			t.Fatalf("production cap %q without proxies must refuse, got %v", cap, err)
		}
	}
	// Production with the cap explicitly off, or with trusted proxies: starts, no note.
	for _, in := range []admissionInput{
		{allowedOrigins: base.allowedOrigins, production: true, maxPerIP: "0"},
		{allowedOrigins: base.allowedOrigins, production: true, maxPerIP: "64", trustedProxies: "172.18.0.0/16"},
		{allowedOrigins: base.allowedOrigins, trustedProxies: "10.0.0.0/8,192.168.0.0/16"},
	} {
		d, err = decideAdmission(in)
		if err != nil || len(d.notes) != 0 {
			t.Fatalf("%+v: %+v %v", in, d, err)
		}
	}
	if _, err = decideAdmission(admissionInput{allowedOrigins: "https://a.example.com", trustedProxies: "nope"}); err == nil {
		t.Fatal("bad proxy list must be refused")
	}
}

// The live production environment, verbatim: must start and keep its posture.
func TestAdmissionLiveProductionConfigStillStarts(t *testing.T) {
	t.Parallel()
	d, err := decideAdmission(admissionInput{
		allowedOrigins:   "https://console.example.com,https://tenant-a.example.com,https://tenant-b.example.com",
		siteAddress:      "console.example.com, tenant-a.example.com, tenant-b.example.com",
		tenantHostSuffix: ".example.com",
		trustedProxies:   "172.18.0.0/16",
		maxPerIP:         "64",
		production:       true,
	})
	if err != nil || len(d.origins.allowed) != 3 || d.maxPerIP != 64 || len(d.trustedProxies) != 1 || len(d.notes) != 0 {
		t.Fatalf("%+v %v", d, err)
	}
	// Same, with the explicit list blank: the comma+SPACE site address alone yields the same 3 origins.
	d, err = decideAdmission(admissionInput{siteAddress: "console.example.com, tenant-a.example.com, tenant-b.example.com", trustedProxies: "172.18.0.0/16", production: true})
	if err != nil || len(d.origins.allowed) != 3 {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestPostureLineCarriesOriginCountAndCapSource(t *testing.T) {
	t.Parallel()
	line, _, err := signalingPosture{production: true, originEnforcing: true, originCount: 3, trustedProxies: 1, maxPerIP: 64, perIPSource: "env"}.evaluate()
	if err != nil || !strings.Contains(line, "origin_count=3") || !strings.Contains(line, "per_ip_cap_source=env") {
		t.Fatalf("%v %s", err, line)
	}
}

func TestUntrustedForwardedWarnsOnceAndNeverChangesBehaviour(t *testing.T) {
	t.Parallel()
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	s.noteUntrustedForwarded(r)
	s.noteUntrustedForwarded(r) // second call: Once, no panic, no second line
	if got := signalingClientIP(r, nil); got != "192.0.2.1" {
		t.Fatalf("without trusted proxies the TCP peer must be the bucket, got %q", got)
	}
}
