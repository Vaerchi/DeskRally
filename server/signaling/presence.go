package main

// Agent presence feed — the source of truth for "is this machine online right now".
//
// The control plane's `machine` table records who is ENROLLED; it has never known who is
// CONNECTED, because agents hold their live WebSocket here, not there. This endpoint closes that
// gap by exposing the registry the broker already consults: a device is online exactly when the
// broker could reach it, so presence is the real thing rather than a heartbeat approximation
// derived after the fact.
//
// SECURITY POSTURE — deliberately the mirror image of the control plane's
// GET /internal/devices/{device_id}/identity (docs/11 §4.1), and for the same reasons:
//
//   - Service-token auth (constant-time), never a tenant principal. The registry is cross-tenant by
//     construction — signaling belongs to no tenant — so there is no principal to scope it by.
//   - The route is NOT MOUNTED without a token of at least presenceTokenMinLen characters. There is
//     no unauthenticated mode: an open presence endpoint is a fleet-enumeration oracle that would
//     hand any caller the full list of live device ids across every tenant.
//   - The response carries ONLY device ids, freshness, and two pieces of agent-asserted, bounded
//     inventory: the `os` description (which refreshes the otherwise write-once `machine.os`) and
//     the `agent_version` build identity (which refreshes `machine.agent_version`, migrations/0039).
//     No pubkey, no tenant, no NAT type, no addressing information — nothing that helps anyone
//     reach an agent. Even with the token, the endpoint answers "which of these ids are up, what
//     they claim to run and what build they claim to be", not "how do I get to them".
//
//     THIS LIST IS AN ALLOWLIST, NOT A DESCRIPTION. Adding a field here is a deliberate amendment
//     to the posture, and TestPresenceEndpointReturnsDeviceIdsOnly asserts the excluded values
//     never appear in a response body. A build version is inventory a human reads, on exactly the
//     same footing as `os`; anything that helps REACH an agent is not, and does not belong here.
//   - The CALLER is responsible for tenant scoping. The control plane intersects this list with its
//     own RLS-scoped machine rows and never echoes an id it does not already own. That
//     intersection, not this endpoint, is what keeps one tenant from learning another's fleet.
//
// SCOPE LIMIT, stated rather than discovered: the registry is per-INSTANCE and in-memory. A
// single-instance deployment (self-hosted, dev, the test harness) gets exact presence. A
// multi-instance SaaS fleet needs shared presence state (the Redis presence store named in
// docs/02 "Deployment topologies"); until that exists, this endpoint reports only the agents
// connected to THIS instance.

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// presenceTokenMinLen is the shortest service token the presence route will mount behind. It is a
// machine-to-machine shared secret with no second factor, so anything shorter is a configuration
// mistake, not a policy choice. Matches the control plane's DeviceIdentityTokenMinLen.
const presenceTokenMinLen = 32

// PresenceEntry is one online agent: its device id, how long it has been continuously
// registered, and its asserted os. Deliberately minimal — see the security note above.
type PresenceEntry struct {
	DeviceID string `json:"device_id"`
	// LastSeenUnixMs is the registry's last heartbeat stamp for this agent.
	LastSeenUnixMs int64 `json:"last_seen_unix_ms"`
	// OS is the agent-asserted os description from register_agent (bounded at receipt; empty when
	// the agent sent none). Omitted from the JSON when empty so pre-os consumers see the exact
	// shape they always did.
	OS string `json:"os,omitempty"`
	// RequireSessionPolicy is the agent-asserted floor flag from register_agent, or nil when this
	// agent asserted none. NIL IS NOT FALSE: the control plane writes machine.require_session_policy
	// only for agents that actually reported, so an older agent's silence never clears a flag an
	// operator set. Omitted from the JSON when nil so pre-loop-86 consumers see the exact shape they
	// always did.
	RequireSessionPolicy *bool `json:"require_session_policy,omitempty"`
	// GrantKeyPinned is the agent-asserted posture (audit #9): whether a grant issuer key is pinned, so
	// signed policy / lease / grants are enforceable. Nil = agent reported no posture (unknown, NOT false).
	GrantKeyPinned *bool `json:"grant_key_pinned,omitempty"`
	// SessionPolicyRequired: agent-asserted require_session_policy posture; nil = not reported (unknown).
	SessionPolicyRequired *bool `json:"session_policy_required,omitempty"`
	// AgentVersion is the agent-asserted build identity from register_agent (bounded at receipt;
	// empty when the agent sent none). Omitted from the JSON when empty so pre-loop-96 consumers
	// see the exact shape they always did — and, more importantly, so a silent agent is
	// distinguishable from one reporting an empty version: the control plane must never let
	// silence blank a version it already recorded.
	AgentVersion string `json:"agent_version,omitempty"`
	// LoggedInUser is the interactive Windows session user announced at register_agent (e.g.
	// "CORP\alice"; bounded at receipt). Omitted from the JSON when empty so an older agent's
	// absence is distinguishable from a reported empty value — the control plane must never let
	// silence blank a user name it already recorded (migrations/0048).
	LoggedInUser string `json:"logged_in_user,omitempty"`
	// MultiSessionCapable is the advisory capability flag from register_agent. Nil when the agent
	// did not declare a value (older agents), so the control plane and viewer can distinguish
	// "said false" from "said nothing". Omitted from JSON when nil so pre-multi-session consumers
	// see the exact shape they always did.
	MultiSessionCapable *bool `json:"multi_session_capable,omitempty"`
}

// PresenceResponse is the body of GET /internal/presence.
type PresenceResponse struct {
	Devices []PresenceEntry `json:"devices"`
	// AsOfUnixMs is the server's clock when the snapshot was taken, so a caller can reason about
	// staleness without trusting its own clock to agree with signaling's.
	AsOfUnixMs int64 `json:"as_of_unix_ms"`
}

// Snapshot returns every FRESH peer in the registry (heartbeat within the TTL), as presence
// entries. Expired peers are skipped but — unlike Lookup — are NOT evicted here: a read-only
// observability call must not mutate the registry the broker depends on, and eviction already
// happens on the paths that matter (Lookup, Remove).
func (r *Registry) Snapshot() []PresenceEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PresenceEntry, 0, len(r.peers))
	for _, p := range r.peers {
		if r.expired(p) {
			continue
		}
		// An EMPTY device id is never a real machine. It is reachable today only on the dev-only
		// -insecure-no-agent-auth path, where the connection asserts its own identity and a
		// malformed register_agent decodes to a zero-valued RegisterAgent — so the peer registers
		// under "". Such an entry can match no enrolled machine, so emitting it would only add a
		// meaningless row for every consumer to filter. Dropped here, at the source.
		if p.DeviceId == "" {
			continue
		}
		out = append(out, PresenceEntry{
			DeviceID:              p.DeviceId,
			LastSeenUnixMs:        p.LastSeen.UnixMilli(),
			OS:                    p.OS,
			RequireSessionPolicy:  p.RequireSessionPolicy,
			GrantKeyPinned:        p.GrantKeyPinned,
			SessionPolicyRequired: p.SessionPolicyRequired,
			AgentVersion:          p.AgentVersion,
			LoggedInUser:          p.LoggedInUser,
			MultiSessionCapable:   p.MultiSessionCapable,
		})
	}
	return out
}

// presenceAuthorized reports whether the request carries the configured service token.
// Constant-time, so the token cannot be recovered a byte at a time from response latency.
func presenceAuthorized(r *http.Request, want string) bool {
	if len(want) < presenceTokenMinLen {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}

// presenceHandler builds the GET /internal/presence handler for a registry and service token.
func presenceHandler(reg *Registry, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !presenceAuthorized(r, token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		resp := PresenceResponse{
			Devices:    reg.Snapshot(),
			AsOfUnixMs: time.Now().UnixMilli(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// mountPresence attaches GET /internal/presence when SIGNALING_PRESENCE_TOKEN is configured long
// enough to be a secret. A missing token is NOT fatal — presence is a console nicety, not a
// security control, and an operator who has not configured it should get a control plane that
// reports "presence unavailable" rather than a signaling server that refuses to start. A token
// that is present but TOO SHORT is loud, because that is a misconfiguration rather than a choice.
func mountPresence(mux *http.ServeMux, reg *Registry, token string) {
	switch {
	case token == "":
		log.Printf("SIGNALING_PRESENCE_TOKEN is not set — GET /internal/presence is NOT mounted; " +
			"the control plane will report machine presence as unknown")
	case len(token) < presenceTokenMinLen:
		log.Printf("WARNING: SIGNALING_PRESENCE_TOKEN is shorter than %d characters — "+
			"GET /internal/presence is NOT mounted", presenceTokenMinLen)
	default:
		mux.HandleFunc("GET /internal/presence", presenceHandler(reg, token))
		log.Printf("presence feed mounted at GET /internal/presence (service-token gated)")
	}
}
