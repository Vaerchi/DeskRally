package controlplane

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Security audit 2026-10-18: a failed login records at most a bounded, valid-UTF-8 email.
func TestAuditEmailFieldBoundsTheRecordedEmail(t *testing.T) {
	if got := auditEmailField("tech@acme.test"); got != "tech@acme.test" {
		t.Fatalf("ordinary email changed: %q", got)
	}
	exact := strings.Repeat("a", 254)
	if got := auditEmailField(exact); got != exact {
		t.Fatal("a 254-byte email must be kept whole")
	}
	long := strings.Repeat("é", 40_000) // 80 000 bytes, multi-byte runes straddle the cut
	got := auditEmailField(long)
	if len(got) > 254+len("…(truncated)") || !strings.HasSuffix(got, "…(truncated)") {
		t.Fatalf("long email not bounded: %d bytes", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation split a rune")
	}
}
