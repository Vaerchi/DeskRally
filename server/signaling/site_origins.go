package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// OriginsFromSiteAddress derives the SIGNALING_ALLOWED_ORIGINS value from SIGNALING_SITE_ADDRESS,
// the same list the Caddyfile site block uses (SITE_ADDRESS): hostnames separated by commas
// and/or whitespace, e.g. "main.example.com, loam.example.com". Each host becomes https://host.
//
// Only plain DNS hostnames are accepted. A scheme, port, path, wildcard, IP literal or any other
// character is a startup error rather than a silently malformed origin (the previous compose
// interpolation produced exactly such a string for a list). An empty input yields "" (no derived
// allowlist). Duplicates are collapsed; hosts are lowercased (browsers send a lowercase Origin).
func OriginsFromSiteAddress(raw string) (string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		if err := validateSiteHost(f); err != nil {
			return "", fmt.Errorf("SIGNALING_SITE_ADDRESS: %q %v (want bare hostnames separated by commas or spaces, "+
				"e.g. \"console.example.com, other.example.com\"; set SIGNALING_ALLOWED_ORIGINS explicitly for anything else)", f, err)
		}
		o := "https://" + strings.ToLower(f)
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return strings.Join(out, ","), nil
}

func validateSiteHost(h string) error {
	switch {
	case strings.Contains(h, "://"):
		return fmt.Errorf("carries a scheme")
	case strings.Contains(h, "*"):
		return fmt.Errorf("is a wildcard")
	case strings.Contains(h, ":"):
		return fmt.Errorf("carries a port or is an IPv6 literal")
	case strings.ContainsAny(h, "/?#@[]"):
		return fmt.Errorf("is not a bare hostname")
	}
	if len(h) > 253 {
		return fmt.Errorf("is longer than 253 bytes")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return fmt.Errorf("is an IP literal (Origins for IP hosts must be set explicitly)")
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("has an empty label")
		}
		if len(l) > 63 {
			return fmt.Errorf("has a label longer than 63 bytes")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("has a label starting or ending with a hyphen")
		}
		for _, r := range l {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-'
			if !ok {
				return fmt.Errorf("has an invalid character %q", r)
			}
		}
	}
	// WHATWG URL "ends in a number" rule: if the LAST label is all decimal digits, or 0x/0X followed by
	// hex digits (or nothing), browsers parse the whole host as an IPv4 address (2130706433, 0x7f000001,
	// 0x7f.0x1, 0177.0.0.1, 1.2.3 ...). Such a host is never a DNS name: reject it.
	if endsInNumber(labels[len(labels)-1]) {
		return fmt.Errorf("is (or is parsed by browsers as) an IPv4 address")
	}
	return nil
}

// effectiveAllowedOrigins picks the raw allowlist: an explicit SIGNALING_ALLOWED_ORIGINS always
// wins (even "*"); only when it is blank is the list derived from SIGNALING_SITE_ADDRESS.
func effectiveAllowedOrigins(explicit, siteAddress string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return explicit, nil
	}
	return OriginsFromSiteAddress(siteAddress)
}

func endsInNumber(l string) bool {
	if l == "" {
		return false
	}
	allIn := func(x, set string) bool {
		for _, r := range x {
			if !strings.ContainsRune(set, r) {
				return false
			}
		}
		return true
	}
	if allIn(l, "0123456789") {
		return true
	}
	if strings.HasPrefix(l, "0x") || strings.HasPrefix(l, "0X") {
		return allIn(l[2:], "0123456789abcdefABCDEF")
	}
	return false
}
