package controlplane

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

var (
	errWakeChanged          = errors.New("changed")
	errWakeAuditUnavailable = errors.New("audit_unavailable")
)

type wakeFact struct {
	MAC, Network, Gateway string
	ReceivedAt            time.Time
}

func (f wakeFact) segment() [2]string {
	return [2]string{f.Network, f.Gateway}
}

type wakeCandidate struct {
	Machine Machine
	Facts   []wakeFact
	Latest  time.Time
}

type wakeIssuance struct {
	Target, Relay wakeCandidate
	Dispatch      WakeContext
	RequestID     string
}

type WakeStore interface {
	wakeFacts(context.Context, string, []string) (map[string][]wakeFact, error)
	issueWake(context.Context, *Principal, wakeIssuance) (WakeClaims, error)
}

type WakeThrottle interface {
	ReserveWake(context.Context, string, string) (time.Duration, error)
}

func wakeMatch(target, relay []wakeFact) (wakeFact, bool) {
	for _, t := range target {
		for _, r := range relay {
			if t.Gateway != "" && t.segment() == r.segment() {
				return t, true
			}
		}
	}
	return wakeFact{}, false
}

func wakeRelays(p *Principal, presence *Presence, machines []Machine) []wakeCandidate {
	var candidates []wakeCandidate
	for _, m := range machines {
		if m.TenantID == p.TenantID && m.Status == MachineStatusActive && !m.Ephemeral && presence.IsOnline(m.DeviceID) &&
			presence.WakeCapableByDevice[m.DeviceID] && p.Grant.RequireMachine(CapWakeMachine, m.GroupID) == nil {
			candidates = append(candidates, wakeCandidate{Machine: m})
		}
	}
	return candidates
}

func (s *Server) loadWakeFacts(ctx context.Context, p *Principal, targets []Machine, relays []wakeCandidate) (map[string][]wakeFact, error) {
	ids := make([]string, 0, len(targets)+len(relays))
	for _, m := range targets {
		ids = append(ids, m.ID)
	}
	for _, relay := range relays {
		ids = append(ids, relay.Machine.ID)
	}
	facts, err := s.WakeStore.wakeFacts(ctx, p.TenantID, ids)
	if err != nil {
		return nil, err
	}
	for i := range relays {
		relays[i].Facts = facts[relays[i].Machine.ID]
		for _, fact := range relays[i].Facts {
			if fact.ReceivedAt.After(relays[i].Latest) {
				relays[i].Latest = fact.ReceivedAt
			}
		}
	}
	return facts, nil
}

func wakeReadiness(target []wakeFact, relaySegments map[[2]string]struct{}) string {
	if len(target) == 0 {
		return "no_lan_facts"
	}
	for _, fact := range target {
		if _, ok := relaySegments[fact.segment()]; fact.Gateway != "" && ok {
			return "ready"
		}
	}
	return "no_relay"
}

func (s *Server) annotateWake(r *http.Request, visible, owned []Machine, presence *Presence) {
	if !s.WakeOnLAN || s.WakeStore == nil {
		return
	}
	var targets []Machine
	for _, m := range visible {
		if !presence.IsOnline(m.DeviceID) {
			targets = append(targets, m)
		}
	}
	if len(targets) == 0 {
		return
	}
	p := principalFrom(r.Context())
	relays := wakeRelays(p, presence, owned)
	facts, err := s.loadWakeFacts(r.Context(), p, targets, relays)
	if err != nil {
		return
	}
	segments := make(map[[2]string]struct{})
	for _, relay := range relays {
		for _, fact := range relay.Facts {
			segments[fact.segment()] = struct{}{}
		}
	}
	for i := range visible {
		if !presence.IsOnline(visible[i].DeviceID) {
			visible[i].Wake = wakeReadiness(facts[visible[i].ID], segments)
		}
	}
}

func (s *Server) handleWake(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principalFrom(ctx)
	if s.Machines == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	target, err := s.Machines.GetMachineByID(ctx, p.TenantID, r.PathValue("id"))
	if errors.Is(err, ErrMachineNotFound) || (err == nil && target.TenantID != p.TenantID) {
		writeError(w, http.StatusNotFound, "unknown machine")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := p.Grant.RequireMachine(CapWakeMachine, target.GroupID); err != nil {
		if p.Grant.RequireMachine(CapViewMachines, target.GroupID) != nil {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeDenied(w, err)
		return
	}
	if s.Presence == nil {
		writeError(w, http.StatusServiceUnavailable, "presence_unknown")
		return
	}
	presence, err := s.Presence.FetchPresence(ctx)
	if err != nil || presence == nil {
		writeError(w, http.StatusServiceUnavailable, "presence_unknown")
		return
	}
	if presence.IsOnline(target.DeviceID) {
		writeError(w, http.StatusConflict, "machine_online")
		return
	}
	if s.WakeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	machines, err := s.Machines.ListMachines(ctx, p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	relays := wakeRelays(p, presence, machines)
	facts, err := s.loadWakeFacts(ctx, p, []Machine{*target}, relays)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	targetFacts := facts[target.ID]
	if len(targetFacts) == 0 {
		writeError(w, http.StatusConflict, "no_lan_facts")
		return
	}
	relays = slices.DeleteFunc(relays, func(relay wakeCandidate) bool {
		_, match := wakeMatch(targetFacts, relay.Facts)
		return relay.Machine.ID == target.ID || !match
	})
	if len(relays) == 0 {
		writeError(w, http.StatusConflict, "no_relay")
		return
	}
	slices.SortFunc(relays, func(a, b wakeCandidate) int {
		if newer := b.Latest.Compare(a.Latest); newer != 0 {
			return newer
		}
		return strings.Compare(a.Machine.ID, b.Machine.ID)
	})
	if s.WakeThrottle == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if retry, err := s.WakeThrottle.ReserveWake(ctx, p.TenantID, target.ID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	} else if retry > 0 {
		writeThrottled(w, retry)
		return
	}
	if s.WakeDispatcher == nil || s.DirectiveIssuer == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	requestID := newUUID()
	for _, relay := range relays[:min(3, len(relays))] {
		dispatch, outcome := s.WakeDispatcher.WakeContext(ctx, relay.Machine.DeviceID)
		if outcome != WakeContextReady {
			continue
		}
		claims, err := s.WakeStore.issueWake(ctx, p, wakeIssuance{
			Target: wakeCandidate{Machine: *target, Facts: targetFacts},
			Relay:  relay, Dispatch: dispatch, RequestID: requestID,
		})
		switch {
		case errors.Is(err, errWakeChanged):
			writeError(w, http.StatusConflict, "changed")
			return
		case errors.Is(err, errWakeAuditUnavailable):
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable")
			return
		case err != nil:
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		claims.IssuedAtMs = time.Now().UnixMilli()
		claims.ExpiresAtMs = claims.IssuedAtMs + wakeMaxTTL
		artifact, err := SignWake(s.DirectiveIssuer.priv, claims)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		switch s.WakeDispatcher.Forward(ctx, relay.Machine.DeviceID, dispatch.ConnRef, artifact) {
		case WakeNotWritten:
			continue
		case WakeWritten:
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "requested"})
		default:
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "uncertain"})
		}
		return
	}
	writeError(w, http.StatusConflict, "unavailable")
}
