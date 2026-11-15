package controlplane

import (
	"fmt"
	"net"
	"strings"
)

// Startup mode selection (docs/25 F13).
//
// # Why the mode is DECLARED and no longer inferred
//
// `main()` used to pick its operating mode from the ABSENCE of `DATABASE_URL`: no DSN meant a
// `StubAuthenticator` that answers every request as a full-capability owner of every group. That is
// a reasonable local demo and an catastrophic production accident, and nothing distinguished the
// two — a misconfigured or hand-started process served anonymous management on `:8081` (all
// interfaces, the default) and signed grants with whatever `GRANT_ISSUER_SEED` was in the
// environment.
//
// Measured before it was changed, at HEAD, with no DSN: `GET /users` with no cookie and no token
// answered `200` with the user list, and a supplied seed produced a DETERMINISTIC issuer key
// (the same seed twice gave the same public key; no seed gave a different key each run — so the
// production seed was genuinely in use, not merely present).
//
// So the mode is now an explicit declaration, and the three things that made the accident dangerous
// are each refused unless separately declared:
//
//  1. Production is the DEFAULT. No `CP_INSECURE_DEV` and no DSN is a fatal misconfiguration
//     rather than a silent downgrade to anonymous owner.
//  2. An insecure dev server binds LOOPBACK. A bare `:port` is rewritten to `127.0.0.1:port`
//     rather than refused, because that is the harmless default everyone actually types; an
//     explicitly routable bind needs `CP_INSECURE_DEV_LISTEN_ANY`.
//  3. The PRODUCTION signing variable is refused outright in dev mode. Dev reads its own
//     `CP_INSECURE_DEV_GRANT_SEED`, so a retained production `.env` cannot sign anything a
//     production agent would accept, while a lab that needs a stable pinned key still gets one.
//
// This is a pure function so the truth table is unit-testable. The equivalent logic inside `main()`
// was reachable only by starting a process, which is why it went unexamined for so long.

// Environment variable names, in one place so a test and the operator docs cannot drift from the
// code that reads them.
const (
	EnvInsecureDev          = "CP_INSECURE_DEV"
	EnvInsecureDevListenAny = "CP_INSECURE_DEV_LISTEN_ANY"
	EnvInsecureDevGrantSeed = "CP_INSECURE_DEV_GRANT_SEED"
	EnvGrantIssuerSeed      = "GRANT_ISSUER_SEED"
	EnvAllowPrivilegedDB    = "CP_INSECURE_ALLOW_PRIVILEGED_DB"
)

// StartupMode is which of the two authenticators the process will serve with.
type StartupMode int

const (
	// ModeProduction is Postgres-backed auth. The default, and the only mode that needs no flag.
	ModeProduction StartupMode = iota
	// ModeInsecureDev is the stub full-owner authenticator. Must be declared.
	ModeInsecureDev
)

func (m StartupMode) String() string {
	if m == ModeInsecureDev {
		return "insecure-dev"
	}
	return "production"
}

// StartupConfig is the raw environment, already read, so deciding needs no globals.
type StartupConfig struct {
	InsecureDev      bool   // CP_INSECURE_DEV
	AllowNonLoopback bool   // CP_INSECURE_DEV_LISTEN_ANY
	DatabaseURL      string // DATABASE_URL
	Listen           string // CP_LISTEN
	GrantIssuerSeed  string // GRANT_ISSUER_SEED — the PRODUCTION variable
	DevGrantSeed     string // CP_INSECURE_DEV_GRANT_SEED — the dev-only variable
}

// StartupDecision is what main() should actually do.
type StartupDecision struct {
	Mode StartupMode
	// Listen is the address to bind, which in dev mode may have been narrowed to loopback.
	Listen string
	// GrantSeed is the seed to build the issuer from; empty means generate an ephemeral key.
	GrantSeed string
	// Warnings are operator-facing lines main() should log. Never fatal, always worth saying.
	Warnings []string
}

// DecideStartup resolves the declared environment into a mode, a bind address and a signing seed,
// or refuses to start.
func DecideStartup(cfg StartupConfig) (StartupDecision, error) {
	if !cfg.InsecureDev {
		if strings.TrimSpace(cfg.DatabaseURL) == "" {
			return StartupDecision{}, fmt.Errorf(
				"DATABASE_URL is not set. Production startup requires it: without a database there "+
					"is no authenticator, and this server used to fall back to a stub that answers "+
					"EVERY request as a full-capability owner. If that is genuinely what you want "+
					"for a local demo, declare it with %s=1 — which also confines the listener to "+
					"loopback and refuses the production %s",
				EnvInsecureDev, EnvGrantIssuerSeed)
		}
		// Production: the environment is taken exactly as given.
		return StartupDecision{Mode: ModeProduction, Listen: cfg.Listen, GrantSeed: cfg.GrantIssuerSeed}, nil
	}

	// --- insecure dev mode, explicitly declared from here down ---

	if strings.TrimSpace(cfg.DatabaseURL) != "" {
		return StartupDecision{}, fmt.Errorf(
			"%s=1 was set AND DATABASE_URL is non-empty. These are contradictory: dev mode ignores "+
				"the database and serves a full-owner stub, so continuing would silently discard a "+
				"real DSN and every account in it. Unset one",
			EnvInsecureDev)
	}

	// The production signing variable is REFUSED here rather than ignored. Ignoring it would be
	// safe for signing but would leave an operator who set it believing their pinned
	// grant_issuer_pubkey was in force, and agents would then reject every grant with no clue why.
	if strings.TrimSpace(cfg.GrantIssuerSeed) != "" {
		return StartupDecision{}, fmt.Errorf(
			"%s is set while %s=1. Refusing: that seed signs backstage grants, elevation grants, "+
				"session policies and session tickets that PRODUCTION agents accept, and this mode "+
				"serves anonymous full-owner access to anyone who can reach the port — so a "+
				"retained production seed here is a grant-minting oracle. Use %s for a dev key",
			EnvGrantIssuerSeed, EnvInsecureDev, EnvInsecureDevGrantSeed)
	}

	dec := StartupDecision{Mode: ModeInsecureDev, GrantSeed: cfg.DevGrantSeed}

	listen, rewritten, err := confineListenToLoopback(cfg.Listen, cfg.AllowNonLoopback)
	if err != nil {
		return StartupDecision{}, err
	}
	dec.Listen = listen
	if rewritten {
		dec.Warnings = append(dec.Warnings, fmt.Sprintf(
			"%s=1: narrowed the listen address from %q to %q. An all-interfaces bind would expose "+
				"anonymous owner access to the network; set %s=1 if a bind you can reach from "+
				"another host is genuinely what you want (a VM lab, for instance)",
			EnvInsecureDev, cfg.Listen, listen, EnvInsecureDevListenAny))
	}
	if cfg.AllowNonLoopback && !isLoopbackHost(hostOf(listen)) {
		dec.Warnings = append(dec.Warnings, fmt.Sprintf(
			"DANGER: %s=1 with %s=1 on %q — every request to this address is answered as a "+
				"full-capability owner with NO authentication. Anyone who can route to it "+
				"administers this deployment. Never do this on a network you do not control",
			EnvInsecureDev, EnvInsecureDevListenAny, listen))
	}
	if strings.TrimSpace(cfg.DevGrantSeed) == "" {
		dec.Warnings = append(dec.Warnings, fmt.Sprintf(
			"%s not set — generating an ephemeral grant issuer key, so its public key changes on "+
				"every restart and agents pinned to grant_issuer_pubkey will reject grants after "+
				"one. Set it (64 hex chars) if you need a stable dev key",
			EnvInsecureDevGrantSeed))
	}
	return dec, nil
}

// confineListenToLoopback narrows a bind address for dev mode. It reports whether it rewrote the
// address, and refuses an explicitly routable one unless allowed.
//
// A bare `:8081` — the default, and what nearly every harness passes — means ALL INTERFACES to Go,
// so it is rewritten rather than accepted. It is not an error: refusing the value everyone types by
// default would make the safe path the annoying one, and an annoying safe path gets switched off.
func confineListenToLoopback(listen string, allowNonLoopback bool) (string, bool, error) {
	trimmed := strings.TrimSpace(listen)
	if trimmed == "" {
		// Go treats "" as ":0"; give dev an explicit loopback address instead of a wildcard.
		return "127.0.0.1:8081", true, nil
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		// Not host:port at all (e.g. "8081"). Do not guess — an unparseable bind address in a mode
		// whose whole job is confinement should stop, not be interpreted.
		return "", false, fmt.Errorf(
			"CP_LISTEN=%q is not a host:port address, so it cannot be confined to loopback for "+
				"%s=1: %w", listen, EnvInsecureDev, err)
	}
	if host == "" {
		return net.JoinHostPort("127.0.0.1", port), true, nil
	}
	if isLoopbackHost(host) {
		return trimmed, false, nil
	}
	if allowNonLoopback {
		return trimmed, false, nil
	}
	return "", false, fmt.Errorf(
		"CP_LISTEN=%q binds a non-loopback address while %s=1. That would serve anonymous "+
			"full-owner management to the network. Bind 127.0.0.1, or set %s=1 to declare that you "+
			"mean it", listen, EnvInsecureDev, EnvInsecureDevListenAny)
}

// hostOf returns the host half of a host:port, or "" if it does not parse.
func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// isLoopbackHost reports whether a bind host reaches only this machine.
//
// A NAME other than localhost is treated as non-loopback even if it happens to resolve to
// 127.0.0.1 today: resolution is not ours to depend on, and a confinement check that trusts DNS
// confines nothing.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false // all interfaces
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
