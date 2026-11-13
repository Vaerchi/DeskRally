package main

import (
	"strings"
	"testing"
)

func TestOriginsFromSiteAddress(t *testing.T) {
	t.Parallel()
	good := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"main.example.com", "https://main.example.com"},
		{"main.example.com, loam.example.com, vc.example.com", "https://main.example.com,https://loam.example.com,https://vc.example.com"},
		{"a.example.com b.example.com", "https://a.example.com,https://b.example.com"},
		{"a.example.com,\tb.example.com\n", "https://a.example.com,https://b.example.com"},
		{"A.Example.COM, a.example.com", "https://a.example.com"},
		{"localhost", "https://localhost"},
		{"a-b.example.com", "https://a-b.example.com"},
		{strings.Repeat("a", 63) + ".example.com", "https://" + strings.Repeat("a", 63) + ".example.com"},
		{"xn--bcher-kva.example.com", "https://xn--bcher-kva.example.com"},
		{"host1.example.com", "https://host1.example.com"},
		{"0xdead.example.com", "https://0xdead.example.com"},
		{"123.example.com", "https://123.example.com"},
		{"a.0xg", "https://a.0xg"},
	}
	for _, c := range good {
		got, err := OriginsFromSiteAddress(c.in)
		if err != nil || got != c.want {
			t.Errorf("OriginsFromSiteAddress(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		// Whatever is derived must be accepted by the real origin parser.
		if _, err := ParseOriginPolicy(got); err != nil {
			t.Errorf("derived %q rejected by ParseOriginPolicy: %v", got, err)
		}
	}
	bad := []string{
		"https://main.example.com",
		"http://main.example.com",
		"main.example.com:8443",
		":80",
		"*.example.com",
		"main.example.com, *.example.com",
		"main.example.com/path",
		"[::1]",
		"::1",
		"1.2.3.4:80",
		"user@host.example.com",
		"bad host!.example.com",
		"under_score.example.com",
		".example.com",
		"example.com.",
		"a..example.com",
		"127.0.0.1",
		"2130706433",
		"0x7f000001",
		"0X7F000001",
		"0x7f.0x1",
		"0x",
		"a.0x",
		"0177.0.0.1",
		"example.123",
		"10.0.0.5",
		"1.2.3",
		"-bad.example.com",
		"bad-.example.com",
		"ok.-bad.example.com",
		"ok.bad-.example.com",
		strings.Repeat("a", 64) + ".example.com",
	}
	for _, in := range bad {
		if got, err := OriginsFromSiteAddress(in); err == nil {
			t.Errorf("OriginsFromSiteAddress(%q) = %q, want an error", in, got)
		} else if !strings.Contains(err.Error(), "SIGNALING_SITE_ADDRESS") {
			t.Errorf("error for %q does not name the variable: %v", in, err)
		}
	}
}

func TestEffectiveAllowedOriginsExplicitWins(t *testing.T) {
	t.Parallel()
	got, err := effectiveAllowedOrigins("https://only.example.com", "a.example.com, b.example.com")
	if err != nil || got != "https://only.example.com" {
		t.Fatalf("explicit must win: %q %v", got, err)
	}
	// An explicit value wins even when the site address is garbage (it is never parsed).
	if got, err = effectiveAllowedOrigins("*", "https://garbage:1"); err != nil || got != "*" {
		t.Fatalf("explicit * must win: %q %v", got, err)
	}
	got, err = effectiveAllowedOrigins("  ", "a.example.com, b.example.com")
	if err != nil || got != "https://a.example.com,https://b.example.com" {
		t.Fatalf("blank explicit must derive: %q %v", got, err)
	}
	if _, err = effectiveAllowedOrigins("", "https://x"); err == nil {
		t.Fatal("a malformed site address must be a startup error when deriving")
	}
}

// Production still refuses an empty effective list: neither variable set -> not enforcing.
func TestDerivedOriginsFeedProductionPosture(t *testing.T) {
	t.Parallel()
	raw, err := effectiveAllowedOrigins("", "")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := ParseOriginPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (signalingPosture{production: true, originEnforcing: pol.enforcing(), originAny: pol.any, trustedProxies: 1}).evaluate(); err == nil {
		t.Fatal("production must refuse when neither variable yields an origin")
	}
	raw, _ = effectiveAllowedOrigins("", "main.example.com, loam.example.com")
	pol, _ = ParseOriginPolicy(raw)
	if !pol.enforcing() || len(pol.allowed) != 2 {
		t.Fatalf("list must yield 2 enforcing origins, got %+v", pol)
	}
}
