package main

// Startup security POSTURE (audit 2026-11-01 #6/#7).
//
// Several anonymous-surface protections default to OFF so an upgrade changes nothing, which meant
// a production box could run with all of them off and nothing said so in one place. This file
// turns the effective configuration into one greppable line plus per-item warnings, and refuses
// the one combination that is actively harmful: a per-IP cap with no trusted proxies in
// production mode (behind Caddy every client then lands in Caddy's single bucket, so the cap
// becomes a fleet-wide outage switch instead of a flood defence).

import (
	"fmt"
	"os"
	"strings"
)

type signalingPosture struct {
	production       bool // SIGNALING_PRODUCTION=1 (set by deploy/docker-compose.prod.yml)
	originEnforcing  bool
	originAny        bool // SIGNALING_ALLOWED_ORIGINS=* (explicit, unsafe)
	trustedProxies   int
	maxPerIP         int
	connectRate      int
	pendingPerSource int
	strictTickets    bool
	messageRate      int
	maxPendingAuth   int
}

// evaluate returns the single POSTURE line, the list of protections that are off (each a
// human-readable warning), and a non-nil error when the configuration must not start.
func (p signalingPosture) evaluate() (line string, warnings []string, err error) {
	if p.production && p.maxPerIP > 0 && p.trustedProxies == 0 {
		return "", nil, fmt.Errorf("SIGNALING_PRODUCTION is set and SIGNALING_MAX_CONNECTIONS_PER_IP=%d, but "+
			"SIGNALING_TRUSTED_PROXIES is empty: every client behind the reverse proxy would share the "+
			"proxy's single quota bucket, so the cap would lock out the whole fleet. Set "+
			"SIGNALING_TRUSTED_PROXIES to the proxy's CIDR (or unset the cap).", p.maxPerIP)
	}
	if p.production && !p.originEnforcing && !p.originAny {
		return "", nil, fmt.Errorf("SIGNALING_PRODUCTION is set but SIGNALING_ALLOWED_ORIGINS is empty: any web page " +
			"could drive visitors' browsers to open /ws. Set it to the console origin (the production overlay " +
			"derives it from SITE_ADDRESS), or set SIGNALING_ALLOWED_ORIGINS=* to knowingly allow any origin (UNSAFE).")
	}
	onOff := func(on bool) string {
		if on {
			return "on"
		}
		return "OFF"
	}
	if p.originAny {
		warnings = append(warnings, "SIGNALING_ALLOWED_ORIGINS=* : ANY web page can drive visitors' browsers to open /ws (explicitly chosen, UNSAFE)")
	} else if !p.originEnforcing {
		warnings = append(warnings, "SIGNALING_ALLOWED_ORIGINS is empty: any web page can drive visitors' browsers to open /ws")
	}
	if p.trustedProxies == 0 {
		warnings = append(warnings, "SIGNALING_TRUSTED_PROXIES is empty: per-source limits key on the TCP peer (behind a reverse proxy that is the proxy's address)")
	}
	if p.maxPerIP == 0 {
		warnings = append(warnings, "SIGNALING_MAX_CONNECTIONS_PER_IP is 0: one source may hold every socket up to the global cap")
	}
	if p.connectRate == 0 {
		warnings = append(warnings, "SIGNALING_MAX_CONNECTS_PER_SECOND_PER_IP is 0: no per-source connection-rate limit")
	}
	if p.pendingPerSource == 0 {
		warnings = append(warnings, "SIGNALING_MAX_PENDING_PER_SOURCE is 0: one source may hold the whole pre-auth pool")
	}
	if !p.strictTickets {
		warnings = append(warnings, "SIGNALING_STRICT_TICKET_REDEMPTION is unset: tickets are brokered when the replay ledger is unreachable (fail-open)")
	}
	if p.messageRate == 0 {
		warnings = append(warnings, "SIGNALING_MAX_MESSAGES_PER_SECOND is 0: no per-connection message-rate limit")
	}
	originState := onOff(p.originEnforcing)
	if p.originAny {
		originState = "ANY(unsafe)"
	}
	line = fmt.Sprintf("POSTURE production=%v origin_allowlist=%s trusted_proxies=%d per_ip_cap=%d connect_rate_per_ip=%d "+
		"pending_per_source=%d strict_ticket_redemption=%s msg_rate=%d protections_off=%d",
		p.production, originState, p.trustedProxies, p.maxPerIP, p.connectRate,
		p.pendingPerSource, onOff(p.strictTickets), p.messageRate, len(warnings))
	return line, warnings, nil
}

// logPosture logs the posture; in production mode the warnings are loud (WARNING-level lines
// prefixed PRODUCTION), otherwise they are informational. Returns the error from evaluate.
func logPosture(p signalingPosture, logf func(string, ...any)) error {
	line, warnings, err := p.evaluate()
	if err != nil {
		return err
	}
	logf("%s", line)
	for _, w := range warnings {
		if p.production {
			logf("WARNING: PRODUCTION posture: %s", w)
		} else {
			logf("INFO: posture: %s", w)
		}
	}
	return nil
}

// envFlagOn reports whether an env var is switched on. Empty and the explicit "off" spellings
// ("0", "false", "no", "off") are OFF, so an operator can opt out of a flag the production overlay
// defaults to on without the value "0" accidentally meaning "on".
func envFlagOn(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
