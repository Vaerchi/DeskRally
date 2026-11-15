package main

// Both edge configurations must send the same browser security headers. The native Caddyfile (Linux and Windows native
// installs) shipped without the anti-framing headers the Docker Caddyfile enforces, so a native console could be framed:
// a clickjacked frame is a clickjacked mouse on a customer's machine. These read the files as text.

import (
	"regexp"
	"strings"
	"testing"
)

var caddyHeaderFiles = []string{composeDir + "Caddyfile", composeDir + "native/Caddyfile"}

func TestEveryCaddyfileForbidsFraming(t *testing.T) {
	for _, f := range caddyHeaderFiles {
		cf := readDeployFile(t, f)
		m := regexp.MustCompile(`(?m)^\s*Content-Security-Policy\s+"([^"]+)"`).FindStringSubmatch(cf)
		if m == nil || !strings.Contains(m[1], "frame-ancestors 'none'") {
			t.Errorf("%s: no ENFORCED Content-Security-Policy carrying frame-ancestors 'none'", f)
		}
		if !regexp.MustCompile(`(?m)^\s*X-Frame-Options\s+"?DENY"?\s*$`).MatchString(cf) {
			t.Errorf("%s: no X-Frame-Options DENY", f)
		}
	}
}

// The content policy is ENFORCED (promoted 2026-11-14 on measured evidence; see deploy/Caddyfile). Each file sends it as
// ONE header: the shape that was measured. Two Content-Security-Policy headers would both be enforced (their
// intersection), and a leftover Report-Only copy would let the two drift apart unnoticed.
func TestCaddyfilesShareOneEnforcedPolicy(t *testing.T) {
	enforced := regexp.MustCompile(`(?m)^\s*(?:header\s+)?Content-Security-Policy\s+"([^"]+)"`)
	var policies []string
	for _, f := range caddyHeaderFiles {
		cf := readDeployFile(t, f)
		all := enforced.FindAllStringSubmatch(cf, -1)
		if len(all) != 1 {
			t.Fatalf("%s: %d enforced Content-Security-Policy headers, want exactly 1", f, len(all))
		}
		if regexp.MustCompile(`(?m)^\s*(?:header\s+)?Content-Security-Policy-Report-Only\s`).MatchString(cf) {
			t.Errorf("%s: still sends a Content-Security-Policy-Report-Only header", f)
		}
		policies = append(policies, all[0][1])
	}
	if policies[0] != policies[1] {
		t.Errorf("the Docker and native policies differ: docker=%q native=%q", policies[0], policies[1])
	}
	for _, want := range []string{"script-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "report-uri /cp/csp-report"} {
		if !strings.Contains(policies[0], want) {
			t.Errorf("the enforced policy lost %q", want)
		}
	}
}
