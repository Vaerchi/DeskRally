package main

// Startup ADMISSION decision (external review, operator-approved): the signaling server
// fails CLOSED. Two defaults used to be open:
//
//  1. An empty origin allow list admitted EVERY browser Origin to /ws (warn-only). The bare binary,
//     and any install whose config set neither SIGNALING_ALLOWED_ORIGINS nor SIGNALING_SITE_ADDRESS,
//     therefore let any web page drive a visitor's browser at /ws. It now refuses to start.
//  2. SIGNALING_MAX_CONNECTIONS_PER_IP defaulted to unlimited. It now defaults to
//     defaultMaxConnectionsPerIP (the value the shipped production overlay already used).
//
// The rules live in one pure function so the truth table is unit-testable; main() only reads the
// environment and calls it.
//
// THE ONE OPT-OUT, for laboratory/dev use: SIGNALING_ALLOWED_ORIGINS=* (exactly "*", the existing
// documented spelling; no new variable). It is logged as UNSAFE at startup and in the POSTURE block.
//
// PER-IP CAP AND PROXIES. A proxy cannot be detected at startup, so the rule is stated over what
// can be known:
//   - SIGNALING_TRUSTED_PROXIES set: the rightmost X-Forwarded-For hop is used for peers inside
//     those ranges (existing behaviour).
//   - unset: the TCP peer address is the bucket, and one INFO line says so. If a request later
//     arrives from an untrusted peer carrying X-Forwarded-For (i.e. there IS a proxy in front), a
//     WARNING is logged once (see Server.noteUntrustedForwarded).
//   - SIGNALING_PRODUCTION set (the production Compose overlay): a cap with no trusted proxies is a
//     startup error, as before (every client would share the proxy's bucket).
//   - SIGNALING_MAX_CONNECTIONS_PER_IP=0 is the explicit way to turn the cap off.

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// defaultMaxConnectionsPerIP is the per-source cap on UNAUTHENTICATED sockets when
// SIGNALING_MAX_CONNECTIONS_PER_IP is unset. It matches docker-compose.prod.yml.
const defaultMaxConnectionsPerIP = 64

// admissionInput is the raw environment the decision depends on.
type admissionInput struct {
	allowedOrigins   string // SIGNALING_ALLOWED_ORIGINS
	siteAddress      string // SIGNALING_SITE_ADDRESS
	tenantHostSuffix string // SIGNALING_ALLOWED_TENANT_HOST_SUFFIX
	trustedProxies   string // SIGNALING_TRUSTED_PROXIES
	maxPerIP         string // SIGNALING_MAX_CONNECTIONS_PER_IP
	production       bool   // SIGNALING_PRODUCTION
}

type admissionDecision struct {
	origins        *originPolicy
	trustedProxies []*net.IPNet
	maxPerIP       int
	maxPerIPSource string   // "default", "env"
	notes          []string // INFO lines to log
}

func decideAdmission(in admissionInput) (admissionDecision, error) {
	var d admissionDecision

	rawOrigins, err := effectiveAllowedOrigins(in.allowedOrigins, in.siteAddress)
	if err != nil {
		return d, err
	}
	pol, err := ParseOriginPolicy(rawOrigins)
	if err != nil {
		return d, err
	}
	pol = pol.WithTenantSuffix(in.tenantHostSuffix)
	if !pol.enforcing() && !pol.any {
		return d, fmt.Errorf("no browser-origin policy: neither SIGNALING_ALLOWED_ORIGINS nor SIGNALING_SITE_ADDRESS is set, " +
			"so any web page could drive visitors' browsers to open /ws. Set SIGNALING_ALLOWED_ORIGINS to the console " +
			"origin(s), e.g. https://console.example.com (or SIGNALING_SITE_ADDRESS to the console hostname(s)). For a " +
			"laboratory or development run ONLY, SIGNALING_ALLOWED_ORIGINS=* knowingly allows any origin (UNSAFE). " +
			"Native agents send no Origin header and are always admitted")
	}
	d.origins = pol

	d.trustedProxies, err = ParseSignalingTrustedProxies(in.trustedProxies)
	if err != nil {
		return d, err
	}

	d.maxPerIP, d.maxPerIPSource = defaultMaxConnectionsPerIP, "default"
	if raw := strings.TrimSpace(in.maxPerIP); raw != "" {
		n, perr := strconv.Atoi(raw)
		if perr != nil || n < 0 {
			return d, fmt.Errorf("SIGNALING_MAX_CONNECTIONS_PER_IP=%q is not a non-negative integer", raw)
		}
		d.maxPerIP, d.maxPerIPSource = n, "env"
	}

	if d.maxPerIP > 0 && len(d.trustedProxies) == 0 {
		if in.production {
			return d, fmt.Errorf("SIGNALING_PRODUCTION is set and the per-IP cap is %d (%s), but SIGNALING_TRUSTED_PROXIES "+
				"is empty: every client behind the reverse proxy would share the proxy's single quota bucket, so the cap "+
				"would lock out the whole fleet. Set SIGNALING_TRUSTED_PROXIES to the proxy's CIDR, or set "+
				"SIGNALING_MAX_CONNECTIONS_PER_IP=0 to turn the cap off", d.maxPerIP, d.maxPerIPSource)
		}
		d.notes = append(d.notes, fmt.Sprintf("INFO: per-IP cap %d (%s) keys on the TCP peer address because SIGNALING_TRUSTED_PROXIES "+
			"is not set; behind a reverse proxy that is the proxy's address, so set SIGNALING_TRUSTED_PROXIES to its CIDR "+
			"(a warning is logged if a forwarded request is seen)", d.maxPerIP, d.maxPerIPSource))
	}
	return d, nil
}

// originCount is the number of allow-list entries (exact plus wildcard), 0 for none/any.
func (p *originPolicy) originCount() int { return len(p.allowed) + len(p.wild) }

// noteUntrustedForwarded logs ONE warning when a request carries X-Forwarded-For but no trusted
// proxy is configured: a reverse proxy is evidently in front, so the per-source buckets key on the
// proxy's address and the whole fleet shares one. It never changes behaviour.
func (s *Server) noteUntrustedForwarded(r *http.Request) {
	if len(s.trustedProxyNets) != 0 || r.Header.Get("X-Forwarded-For") == "" {
		return
	}
	s.fwdWarnOnce.Do(func() {
		log.Printf("WARNING: a request carrying X-Forwarded-For arrived from %q but SIGNALING_TRUSTED_PROXIES is not set: "+
			"per-source limits key on that peer address, so every client behind the proxy shares one bucket. "+
			"Set SIGNALING_TRUSTED_PROXIES to the proxy's CIDR.", r.RemoteAddr)
	})
}
