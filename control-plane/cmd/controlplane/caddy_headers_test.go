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
		if !regexp.MustCompile(`(?m)^\s*Content-Security-Policy\s+"frame-ancestors 'none'"\s*$`).MatchString(cf) {
			t.Errorf("%s: no ENFORCED Content-Security-Policy \"frame-ancestors 'none'\"", f)
		}
		if !regexp.MustCompile(`(?m)^\s*X-Frame-Options\s+"?DENY"?\s*$`).MatchString(cf) {
			t.Errorf("%s: no X-Frame-Options DENY", f)
		}
	}
}

func TestCaddyfilesShareOneReportOnlyPolicy(t *testing.T) {
	re := regexp.MustCompile(`(?m)Content-Security-Policy-Report-Only\s+"([^"]+)"`)
	var policies []string
	for _, f := range caddyHeaderFiles {
		m := re.FindStringSubmatch(readDeployFile(t, f))
		if m == nil {
			t.Fatalf("%s: no Content-Security-Policy-Report-Only header", f)
		}
		policies = append(policies, m[1])
	}
	if policies[0] != policies[1] {
		t.Errorf("the Docker and native report-only policies differ: docker=%q native=%q", policies[0], policies[1])
	}
	if !strings.Contains(policies[0], "frame-ancestors 'none'") {
		t.Errorf("the report-only policy dropped frame-ancestors 'none'")
	}
}
