package controlplane

// Machines: listing and presence, per-machine settings (status, alias, note, group, properties), bulk edits, enrollment. Split out of http.go (routing and middleware stay there).

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	all, err := s.Machines.ListMachines(r.Context(), p.TenantID)
	if err != nil {
		writeListError(w, err, "could not list machines")
		return
	}
	// RLS already scoped the query to the tenant; now filter to the groups the caller's
	// memberships actually cover, so a group-scoped viewer only sees their machines.
	visible := visibleMachines(p, all)
	// Optional custom-property filter (docs/01 §4): `?property_key=site[&property_value=HQ]` narrows
	// the listing to machines carrying that property. The matching-id set is INTERSECTED with what the
	// caller can already see (never unioned), so the filter can only narrow a listing — it can never
	// reveal a machine outside the caller's group scope, and an empty `property_value` matches any
	// value. `all` (below) is left untouched so presence history is still recorded fleet-wide.
	if key := strings.TrimSpace(r.URL.Query().Get("property_key")); key != "" {
		if s.MachineProperties == nil {
			writeError(w, http.StatusInternalServerError, "machine property store not configured")
			return
		}
		ids, err := s.MachineProperties.MachineIDsWithProperty(r.Context(), p.TenantID, key, r.URL.Query().Get("property_value"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not filter machines by property")
			return
		}
		filtered := make([]Machine, 0, len(visible))
		for _, m := range visible {
			if _, ok := ids[m.ID]; ok {
				filtered = append(filtered, m)
			}
		}
		visible = filtered
	}
	presenceKnown := s.annotatePresence(r, p.TenantID, visible, all)
	stampDerived(visible)
	var rows any = visible
	if r.URL.Query().Get("include") == "properties" {
		if s.MachineProperties == nil {
			writeError(w, http.StatusInternalServerError, "machine property store not configured")
			return
		}
		ids := make([]string, 0, len(visible))
		for _, m := range visible {
			ids = append(ids, m.ID)
		}
		properties, err := s.MachineProperties.ListPropertiesForMachines(r.Context(), p.TenantID, ids)
		if err != nil {
			writeListError(w, err, "could not list machine properties")
			return
		}
		type machineWithProperties struct {
			Machine
			Properties map[string]string `json:"properties"`
		}
		enriched := make([]machineWithProperties, 0, len(visible))
		for _, m := range visible {
			bag := properties[m.ID]
			if bag == nil {
				bag = map[string]string{}
			}
			enriched = append(enriched, machineWithProperties{Machine: m, Properties: bag})
		}
		rows = enriched
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"machines": rows,
		// Explicit so the console can say "presence unavailable" instead of silently rendering
		// every machine as offline when the feed is down (see presence.go's fail-soft note).
		"presence_known": presenceKnown,
	})
}

func visibleMachines(p *Principal, all []Machine) []Machine {
	visible := make([]Machine, 0, len(all))
	for _, m := range all {
		if p.Grant.AllowsInGroup(CapViewMachines, m.GroupID) {
			visible = append(visible, m)
		}
	}
	return visible
}

// annotatePresence stamps Online/LastSeen onto the caller's OWN machines from the signaling
// presence feed, and persists last_seen for the ones reported up. Returns whether presence could be
// determined at all.
//
// It takes TWO slices on purpose:
//
//   - `visible` — the machines this caller may see (RLS ∩ their group scope). Only these are
//     ANNOTATED, because only these appear in the response.
//   - `owned` — every machine RLS scoped to the tenant. The last_seen HISTORY is recorded across
//     all of them, because a sighting is a fact about the tenant's fleet, not about who happened to
//     be browsing. Stamping only `visible` meant a group-scoped viewer's page loads recorded
//     nothing for the rest of the tenant, so "offline since 14:32" silently depended on which
//     technician had last opened the console. The write reveals nothing to the caller — they cannot
//     read those rows back — and RLS still confines it to their own tenant.
//
// The tenant-scoping rule (presence.go): the feed is cross-tenant, so this only ever READS it by
// asking "is THIS machine's device id in the set" for machines the tenant already owns. Ids in the
// feed that do not match are never surfaced, counted, or distinguished from ids that do not exist,
// so a shared signaling server cannot leak one MSP's fleet to another.
//
// The result is NOT conditioned on len(visible): "the feed answered and you own nothing here" and
// "the feed is down" are different facts, and collapsing them made an empty fleet indistinguishable
// from an outage in the console.
//
// Everything here is best-effort. A missing source, an unreachable signaling server, or a failed
// last_seen write all degrade the listing to "presence unknown" and never fail the request:
// nothing is authorized on presence, so failing closed would cost availability and buy nothing.
func (s *Server) annotatePresence(r *http.Request, tenantID string, visible, owned []Machine) bool {
	if s.Presence == nil {
		return false
	}
	snapshot, err := s.Presence.FetchPresence(r.Context())
	if err != nil || snapshot == nil {
		if err != nil && !errors.Is(err, ErrPresenceUnavailable) {
			log.Printf("presence lookup for tenant %s failed: %v", tenantID, err)
		}
		return false
	}
	s.annotateWake(r, visible, owned, snapshot)
	for i := range visible {
		// Take the address of a per-iteration copy, not of the loop variable.
		online := snapshot.IsOnline(visible[i].DeviceID)
		flag := online
		visible[i].Online = &flag
		if !online {
			continue
		}
		if seen, ok := snapshot.LastSeen(visible[i].DeviceID); ok {
			stamp := seen
			visible[i].LastSeen = &stamp
		}
		if pinned, ok := snapshot.GrantKeyPinned(visible[i].DeviceID); ok {
			p := pinned
			visible[i].GrantKeyPinned = &p
		}
		if req, ok := snapshot.SessionPolicyRequired(visible[i].DeviceID); ok {
			r := req
			visible[i].SessionPolicyRequired = &r
		}
	}
	onlineIDs := make([]string, 0, len(owned))
	for i := range owned {
		if snapshot.IsOnline(owned[i].DeviceID) {
			onlineIDs = append(onlineIDs, owned[i].DeviceID)
		}
	}
	// Persist the sighting so "offline for 3h" stays answerable after the agent disconnects and
	// after signaling restarts. Failure is logged, never surfaced — the response above is already
	// correct without it.
	//
	// The stamp is the SNAPSHOT's timestamp, not this process's clock: last_seen means "the last
	// moment we observed this device online", and the observation happened on signaling's clock at
	// snapshot time. Using time.Now() here would mix two clocks into one column, so the value read
	// back for an offline machine would sit slightly after the live value shown while it was up.
	if len(onlineIDs) > 0 {
		at := snapshot.AsOf
		if at.IsZero() {
			at = time.Now().UTC()
		}
		if _, err := s.Machines.TouchLastSeen(r.Context(), tenantID, onlineIDs, at); err != nil {
			log.Printf("could not record last_seen for tenant %s: %v", tenantID, err)
		}
	}
	// Refresh machine.os from the agent-asserted values in the same feed — the column is otherwise
	// write-once at enrollment, so an OS upgrade never reached it. Keyed off the STORED rows
	// (`owned` carries each machine's current os), so the steady state — nothing changed — does not
	// call the store at all. Same scoping rationale as last_seen: `owned`, not `visible`, because
	// an OS upgrade is a fact about the fleet, not about who happened to be browsing. Write-behind
	// on purpose: this response still shows the value this request READ; the next poll shows the
	// refreshed one.
	osUpdates := make(map[string]string)
	for i := range owned {
		if observed, ok := snapshot.ObservedOS(owned[i].DeviceID); ok && observed != owned[i].OS {
			osUpdates[owned[i].DeviceID] = observed
		}
	}
	if len(osUpdates) > 0 {
		if _, err := s.Machines.RecordObservedOS(r.Context(), tenantID, osUpdates); err != nil {
			log.Printf("could not refresh machine.os for tenant %s: %v", tenantID, err)
		}
	}
	// Refresh machine.require_session_policy the same way, and for a sharper reason than inventory:
	// this one CHANGES BEHAVIOUR. handleStartSession mints a session policy for a machine flagged
	// here, and an agent whose operator set the flag AFTER enrollment would otherwise be stranded
	// view-only forever with the control plane never knowing why (migrations/0037). Enrollment ran
	// once, long ago; register_agent runs on every reconnect, which is what makes this the channel
	// that self-heals.
	//
	// ONLY devices that actually REPORTED produce an update — the two-value read is the guard. A
	// silent agent (older build, or one that never registered this session) must leave the stored
	// value alone: writing false for silence would clear a flag an operator deliberately set, which
	// is the exact stranding this feature exists to prevent, only sneakier.
	// Refresh machine.agent_version on exactly the same terms (migrations/0039). This is the hop
	// that makes "what is actually deployed out there" answerable, which every part of agent
	// auto-update depends on (docs/21 §2) — a rollout that cannot be observed cannot be staged,
	// canaried, soaked or rolled back.
	//
	// The two-value read is the same guard as the floor flag's, for the same reason: only a device
	// that actually REPORTED may cause a write, so an older agent's silence never blanks a version
	// already recorded. `owned` and not `visible`, because a deployed build is a fact about the
	// fleet rather than about who is browsing. Diffed against the stored value so the steady state
	// does not call the store at all — which is what keeps agent_version_seen_at meaning "first
	// observed" rather than degenerating into a second copy of last_seen.
	versionUpdates := make(map[string]string)
	for i := range owned {
		if reported, ok := snapshot.ObservedAgentVersion(owned[i].DeviceID); ok && reported != owned[i].AgentVersion {
			versionUpdates[owned[i].DeviceID] = reported
		}
	}
	if len(versionUpdates) > 0 {
		if _, err := s.Machines.RecordAgentVersion(r.Context(), tenantID, versionUpdates); err != nil {
			log.Printf("could not refresh machine.agent_version for tenant %s: %v", tenantID, err)
		}
	}
	floorUpdates := make(map[string]bool)
	for i := range owned {
		if reported, ok := snapshot.RequiresSessionPolicy(owned[i].DeviceID); ok && reported != owned[i].RequireSessionPolicy {
			floorUpdates[owned[i].DeviceID] = reported
		}
	}
	if len(floorUpdates) > 0 {
		if _, err := s.Machines.RecordRequireSessionPolicy(r.Context(), tenantID, floorUpdates); err != nil {
			log.Printf("could not refresh machine.require_session_policy for tenant %s: %v", tenantID, err)
		}
	}
	// Refresh machine.logged_in_user from the agent-asserted interactive-session user in the
	// presence feed (migrations/0048). This is purely display inventory — nothing authorizes on it.
	// The two-value read guards against a silent agent blanking a user already recorded, same as
	// ObservedAgentVersion and ObservedOS. `owned`, not `visible`, for the same scoping reason.
	userUpdates := make(map[string]string)
	for i := range owned {
		if reported, ok := snapshot.ObservedLoggedInUser(owned[i].DeviceID); ok && reported != owned[i].LoggedInUser {
			userUpdates[owned[i].DeviceID] = reported
		}
	}
	if len(userUpdates) > 0 {
		if _, err := s.Machines.RecordLoggedInUser(r.Context(), tenantID, userUpdates); err != nil {
			log.Printf("could not refresh machine.logged_in_user for tenant %s: %v", tenantID, err)
		}
	}
	return true
}

func (s *Server) handleGetMachine(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	// REST read path: `{id}` is the machine's PRIMARY KEY (as returned by GET /machines), so it
	// resolves by PK via GetMachineByID — NOT the device-id resolution the grant/session path uses.
	// The machine's REAL group is resolved from the store (never trusted from the caller), then
	// ViewMachines is gated on THAT group.
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapViewMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	one := []Machine{*m}
	stampDerived(one)
	writeJSON(w, http.StatusOK, map[string]any{"machine": one[0]})
}

// resolveMachineForProperties resolves `{id}` to its stored machine and enforces `cap` against the
// machine's REAL group (resolved from the store, never trusted from the caller) — the exact pattern
// handleGetMachine uses, and the D1 hole it closes. On any failure it has already written the
// response and returns ok=false. It also fails closed when either store is unwired.
// setMachineStatusRequest is the body of POST /machines/{id}/status.
type setMachineStatusRequest struct {
	Status string `json:"status"`
}

// handleSetMachineStatus backs POST /machines/{id}/status: quarantine / retire / reactivate a machine.
// It resolves the machine BY PRIMARY KEY (so authorization scopes on its REAL group, never a body
// claim), gates on CapManageMachines for that group, validates the status against the CHECK set, and
// records a machine.status_set audit event. A quarantined or retired machine is subsequently refused a
// new session by handleStartSession.
func (s *Server) handleSetMachineStatus(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineStatusRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if !IsValidMachineStatus(req.Status) {
		writeError(w, http.StatusBadRequest, "status must be active, quarantined, or retired")
		return
	}
	if err := s.Machines.SetMachineStatus(r.Context(), p.TenantID, m.ID, req.Status); err != nil {
		switch {
		case errors.Is(err, ErrMachineNotFound):
			writeError(w, http.StatusNotFound, "unknown machine")
		case errors.Is(err, ErrInvalidMachineStatus):
			writeError(w, http.StatusBadRequest, "status must be active, quarantined, or retired")
		case errors.Is(err, ErrMachineHasActiveDirective), errors.Is(err, ErrMachineRemoved):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not set machine status")
		}
		return
	}
	// Help requests follow the status IMMEDIATELY (H-C5), before any step that can return early: a failed
	// audit or session reap below must not leave an open request on a machine that is out of service.
	s.cancelHelpForMachine(r, p.TenantID, m.ID, m.Status, req.Status)
	if err := s.recordMgmtAudit(r, "machine.status_set", "machine", m.ID, map[string]any{"status": req.Status}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// Quarantine and retire end live sessions immediately so the concurrency seat is freed and the
	// operator's intent is immediate — new sessions are blocked by refuseOutOfServiceMachine; ending
	// the existing one closes the gap. Best-effort: the machine IS quarantined even if this fails.
	if req.Status != MachineStatusActive && s.SessionRecords != nil {
		if reaped, err := s.SessionRecords.EndSessionsForMachine(r.Context(), p.TenantID, m.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not end live sessions")
			return
		} else if reaped > 0 {
			if aerr := s.recordMgmtAudit(r, "session.reaped", "machine", m.ID,
				map[string]any{"count": reaped, "reason": "machine_" + req.Status}); aerr != nil {
				log.Printf("machine %s quarantined/retired but session.reaped audit failed: %v", m.ID, aerr)
			}
		}
	}
	m.Status = req.Status
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// maxMachineAliasRunes bounds a machine's tenant-set friendly name. Short — it is a display label, not
// free text — and rune-counted so multi-byte names are not mis-measured.
const maxMachineAliasRunes = 100

// setMachineAliasRequest is the body of PATCH /machines/{id}/alias. An absent/empty alias CLEARS the
// alias, reverting the console display to the agent-reported hostname.
type setMachineAliasRequest struct {
	Alias string `json:"alias"`
}

// normalizeMachineAlias validates a tenant-set machine friendly name: it trims surrounding whitespace,
// caps the length at maxMachineAliasRunes RUNES, and rejects control characters (which would garble the
// console table and — for NUL — cannot live in a Postgres text column). An EMPTY alias is valid: it
// clears the override so the hostname shows again.
func normalizeMachineAlias(alias string) (string, error) {
	a := strings.TrimSpace(alias)
	if len([]rune(a)) > maxMachineAliasRunes {
		return "", errors.New("alias must be at most 100 characters")
	}
	if strings.ContainsFunc(a, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("alias contains a control character")
	}
	return a, nil
}

// handleSetMachineAlias backs PATCH /machines/{id}/alias: SET (or clear) a machine's tenant-chosen
// friendly name (docs/01 §4). The agent-reported hostname (Machine.Name) is immutable from the console;
// the alias is a separate, tenant-owned display label the console prefers when non-empty. Resolved BY PK
// and gated on RequireMachine(CapManageMachines, m.GroupID) — the machine's REAL group, never the request
// body — so a group-scoped operator can only rename machines they manage. Audited machine.alias_set.
func (s *Server) handleSetMachineAlias(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineAliasRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	alias, err := normalizeMachineAlias(req.Alias)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Machines.SetMachineAlias(r.Context(), p.TenantID, m.ID, alias); err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set machine alias")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.alias_set", "machine", m.ID, map[string]any{"alias": alias}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	m.Alias = alias
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// maxMachineNoteRunes bounds a machine's free-text operator note. Generous for handoff prose yet small
// enough to keep the column and the fleet listing (the note is in the projection) sane; rune-counted.
const maxMachineNoteRunes = 2000

// setMachineNoteRequest is the body of PATCH /machines/{id}/note. An absent/empty note CLEARS it.
type setMachineNoteRequest struct {
	Note string `json:"note"`
}

// normalizeMachineNote validates a free-text machine note: it caps the length at maxMachineNoteRunes RUNES
// and rejects control characters OTHER than tab / newline / carriage-return (a note is multi-line prose, so
// those are kept; NUL cannot live in a Postgres text column and the other C0 controls would garble a render).
// The note is returned VERBATIM (no trimming) so it round-trips exactly as typed. An EMPTY note is valid: it
// clears the annotation.
func normalizeMachineNote(note string) (string, error) {
	if len([]rune(note)) > maxMachineNoteRunes {
		return "", errors.New("note must be at most 2000 characters")
	}
	for _, r := range note {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", errors.New("note contains a control character")
		}
	}
	return note, nil
}

// handleSetMachineNote backs PATCH /machines/{id}/note: SET (or clear) a machine's free-text operator note
// (docs/01 §4) — unstructured context, distinct from the short alias and from structured properties. Resolved
// BY PK and gated on RequireMachine(CapManageMachines, m.GroupID) — the machine's REAL group, never the request
// body — so a group-scoped operator can only annotate machines they manage. The note CONTENT is NOT put in the
// audit metadata (it may be sensitive); the event records only that a note was set.
func (s *Server) handleSetMachineNote(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineNoteRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	note, err := normalizeMachineNote(req.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Machines.SetMachineNote(r.Context(), p.TenantID, m.ID, note); err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set machine note")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.note_set", "machine", m.ID, map[string]any{}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	m.Note = note
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// setMachineGroupRequest is the body of POST /machines/{id}/group.
type setMachineGroupRequest struct {
	GroupID string `json:"group_id"`
}

// handleSetMachineGroup backs POST /machines/{id}/group: REASSIGN a machine to a different group (§4 fleet
// reorganization). Authorization is TWO-WAY, like role assignment (loop 48): the caller must hold
// CapManageMachines for the machine's CURRENT group (to move it OUT) AND for the TARGET group (to move it
// IN), so a group-scoped operator can only move machines BETWEEN groups they manage — never grab a machine
// from, or dump one into, a group they do not. The target group must resolve within the tenant (a clean 404,
// not the composite-FK 500); the change is audited machine.group_changed with from/to.
func (s *Server) handleSetMachineGroup(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil || s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	// Move OUT: manage the machine where it currently lives.
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setMachineGroupRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// Move IN: manage the destination group too (the no-escalation half).
	if err := p.Grant.RequireMachine(CapManageMachines, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// The target group must be a real group in this tenant (a clean 404 before the store's FK backstop).
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine groups")
		return
	}
	found := false
	var targetName string
	for _, g := range groups {
		if g.ID == req.GroupID {
			found = true
			targetName = g.Name
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "unknown machine group")
		return
	}
	from := m.GroupID
	if err := s.moveMachineToGroup(r.Context(), p, m.ID, req.GroupID); err != nil {
		switch {
		case errors.Is(err, ErrGroupTreeChanged):
			writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
		case errors.Is(err, ErrMachineNotFound):
			writeError(w, http.StatusNotFound, "unknown machine")
		case errors.Is(err, ErrInvalidMachineGroup):
			writeError(w, http.StatusNotFound, "unknown machine group")
		case errors.Is(err, ErrMachineHasActiveDirective), errors.Is(err, ErrMachineRemoved):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not reassign machine group")
		}
		return
	}
	if err := s.recordMgmtAudit(r, "machine.group_changed", "machine", m.ID,
		map[string]any{"from": from, "to": req.GroupID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// Reflect the move in the echoed record: GroupName was joined from the OLD group by GetMachineByID, so
	// recompute it from the resolved TARGET group — otherwise the response's group_id and group_name disagree.
	m.GroupID = req.GroupID
	m.GroupName = targetName
	writeJSON(w, http.StatusOK, map[string]any{"machine": m})
}

// moveMachineToGroup reassigns a machine, conditional on the group tree still being at the version the
// caller's grant was read at (docs/62 R2): whether this principal may move this machine depends on the tree,
// so a reparent between the grant read and this write must refuse the move (409 "groups changed, retry")
// rather than apply it on stale authorization. A static grant (an API token) has no version and writes
// unconditionally — it is tenant-wide, which no tree change can narrow.
func (s *Server) moveMachineToGroup(ctx context.Context, p *Principal, machineID, groupID string) error {
	if v := expectTreeVersion(p.Grant); v != nil {
		return s.Machines.SetMachineGroupIfTree(ctx, p.TenantID, machineID, groupID, *v)
	}
	return s.Machines.SetMachineGroup(ctx, p.TenantID, machineID, groupID)
}

// maxBulkStatusMachines bounds one bulk request so a single call cannot fan out into an unbounded number
// of per-machine resolves + audit-chain appends.
const maxBulkStatusMachines = 200

// bulkSetMachineStatusRequest is the body of POST /machines/bulk-status.
type bulkSetMachineStatusRequest struct {
	MachineIDs []string `json:"machine_ids"` // machine PRIMARY KEYs
	Status     string   `json:"status"`
}

// bulkStatusResult is the per-machine outcome of a bulk status change. Error is a short reason on failure
// (unknown machine, denied for its group, …) so the console can show WHICH machines were skipped and why.
type bulkStatusResult struct {
	MachineID string `json:"machine_id"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// handleBulkSetMachineStatus backs POST /machines/bulk-status: apply one status to MANY machines at once
// (§4 fleet management — quarantine a compromised batch, retire a decommissioned rack). Each machine is
// resolved BY PRIMARY KEY and INDEPENDENTLY gated on CapManageMachines for ITS OWN group, exactly like the
// single-machine handler, so a group-scoped caller can only change machines in the groups they manage —
// out-of-group ids come back as a per-machine `denied`, never a blanket success. The status is validated
// ONCE up front. Partial success is normal: the response is 200 with a per-machine results array; a machine
// that fails resolution/authz/write is skipped, not fatal. An up-front tenant-wide Require gate rejects a
// caller who manages NO machines at all (they cannot reach even the per-machine loop).
func (s *Server) handleBulkSetMachineStatus(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	// The caller must manage machines SOMEWHERE (any group); the per-machine RequireMachine below then
	// narrows to each machine's own group (loop-52 "a tenant-wide Require still owes per-group narrowing").
	if err := p.Grant.Require(CapManageMachines); err != nil {
		writeDenied(w, err)
		return
	}
	var req bulkSetMachineStatusRequest
	// The bulk tier (1 MiB, unchanged): this body carries a LIST of machine ids, capped at 200
	// downstream. See maxBulkJSONBodyBytes.
	if err := decodeJSONBody(w, r, maxBulkJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if !IsValidMachineStatus(req.Status) {
		writeError(w, http.StatusBadRequest, "status must be active, quarantined, or retired")
		return
	}
	if len(req.MachineIDs) == 0 {
		writeError(w, http.StatusBadRequest, "machine_ids must not be empty")
		return
	}
	if len(req.MachineIDs) > maxBulkStatusMachines {
		writeError(w, http.StatusBadRequest, "at most 200 machines per request")
		return
	}
	results := make([]bulkStatusResult, 0, len(req.MachineIDs))
	for _, id := range req.MachineIDs {
		results = append(results, s.applyBulkStatusOne(r, p, id, req.Status))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// applyBulkStatusOne resolves ONE machine, group-scopes CapManageMachines on its real group, sets the status,
// and audits it (machine.status_set with a bulk marker) — mirroring handleSetMachineStatus so a bulk change
// is indistinguishable, per machine, from a single one in the audit trail. Every failure is captured in the
// returned result rather than aborting the batch.
func (s *Server) applyBulkStatusOne(r *http.Request, p *Principal, id, status string) bulkStatusResult {
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, id)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return bulkStatusResult{MachineID: id, OK: false, Error: "unknown machine"}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not resolve machine"}
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "denied"}
	}
	if err := s.Machines.SetMachineStatus(r.Context(), p.TenantID, m.ID, status); err != nil {
		if errors.Is(err, ErrMachineHasActiveDirective) || errors.Is(err, ErrMachineRemoved) {
			return bulkStatusResult{MachineID: id, OK: false, Error: err.Error()}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not set status"}
	}
	// Immediately after the status write, before any early return (see handleSetMachineStatus).
	s.cancelHelpForMachine(r, p.TenantID, m.ID, m.Status, status)
	if err := s.recordMgmtAudit(r, "machine.status_set", "machine", m.ID,
		map[string]any{"status": status, "bulk": true}); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not record audit"}
	}
	// Mirror the single-machine handler: quarantine/retire end any live session immediately.
	if status != MachineStatusActive && s.SessionRecords != nil {
		if reaped, err := s.SessionRecords.EndSessionsForMachine(r.Context(), p.TenantID, m.ID); err != nil {
			return bulkStatusResult{MachineID: id, OK: false, Error: "could not end live sessions"}
		} else if reaped > 0 {
			if aerr := s.recordMgmtAudit(r, "session.reaped", "machine", m.ID,
				map[string]any{"count": reaped, "reason": "machine_" + status, "bulk": true}); aerr != nil {
				log.Printf("machine %s quarantined/retired (bulk) but session.reaped audit failed: %v", m.ID, aerr)
			}
		}
	}
	return bulkStatusResult{MachineID: id, OK: true}
}

// bulkSetMachineGroupRequest is the body of POST /machines/bulk-group.
type bulkSetMachineGroupRequest struct {
	MachineIDs []string `json:"machine_ids"` // machine PRIMARY KEYs
	GroupID    string   `json:"group_id"`    // the shared TARGET group
}

// handleBulkSetMachineGroup backs POST /machines/bulk-group: reassign MANY machines to ONE target group at
// once (§4 fleet — re-org a batch of machines into a group). The single handler's TWO-WAY authz is split for
// the SHARED target: the MOVE-IN half — the caller must manage the TARGET group AND the target must exist — is
// a PRECONDITION checked ONCE up front (it is identical for every machine, so a caller who cannot manage the
// target, or a non-existent target, fails the WHOLE request: 403 / 404). The MOVE-OUT half — manage each
// machine's CURRENT group — is per-machine, so a group-scoped caller only moves machines OUT of groups they
// manage; out-of-scope or unknown ids come back per-machine (`denied` / `unknown machine`), never a blanket
// success. Partial success is normal (200 + per-machine `results`); capped at 200. An up-front tenant-wide
// Require gate rejects a caller who manages NO machines at all.
func (s *Server) handleBulkSetMachineGroup(w http.ResponseWriter, r *http.Request) {
	if s.Machines == nil || s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageMachines); err != nil {
		writeDenied(w, err)
		return
	}
	var req bulkSetMachineGroupRequest
	// The bulk tier (1 MiB, unchanged): this body carries a LIST of machine ids, capped at 200
	// downstream. See maxBulkJSONBodyBytes.
	if err := decodeJSONBody(w, r, maxBulkJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	if len(req.MachineIDs) == 0 {
		writeError(w, http.StatusBadRequest, "machine_ids must not be empty")
		return
	}
	if len(req.MachineIDs) > maxBulkStatusMachines {
		writeError(w, http.StatusBadRequest, "at most 200 machines per request")
		return
	}
	// MOVE-IN (shared target), checked ONCE: the caller must manage the target group...
	if err := p.Grant.RequireMachine(CapManageMachines, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// ...and the target must be a real group in this tenant (a clean 404 before the per-machine FK backstop).
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine groups")
		return
	}
	found := false
	for _, g := range groups {
		if g.ID == req.GroupID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "unknown machine group")
		return
	}
	results := make([]bulkStatusResult, 0, len(req.MachineIDs))
	for _, id := range req.MachineIDs {
		results = append(results, s.applyBulkGroupOne(r, p, id, req.GroupID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// applyBulkGroupOne resolves ONE machine, group-scopes CapManageMachines on its CURRENT group (the move-OUT
// half — the move-IN half was checked once up front), reassigns it to groupID, and audits machine.group_changed
// with a bulk marker (so a bulk move is indistinguishable, per machine, from a single one). Every failure is
// captured in the returned result rather than aborting the batch.
func (s *Server) applyBulkGroupOne(r *http.Request, p *Principal, id, groupID string) bulkStatusResult {
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, id)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return bulkStatusResult{MachineID: id, OK: false, Error: "unknown machine"}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not resolve machine"}
	}
	if err := p.Grant.RequireMachine(CapManageMachines, m.GroupID); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "denied"}
	}
	from := m.GroupID
	if err := s.moveMachineToGroup(r.Context(), p, m.ID, groupID); err != nil {
		if errors.Is(err, ErrGroupTreeChanged) {
			return bulkStatusResult{MachineID: id, OK: false, Error: ErrGroupTreeChanged.Error()}
		}
		if errors.Is(err, ErrInvalidMachineGroup) {
			return bulkStatusResult{MachineID: id, OK: false, Error: "unknown machine group"}
		}
		if errors.Is(err, ErrMachineHasActiveDirective) || errors.Is(err, ErrMachineRemoved) {
			return bulkStatusResult{MachineID: id, OK: false, Error: err.Error()}
		}
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not reassign group"}
	}
	if err := s.recordMgmtAudit(r, "machine.group_changed", "machine", m.ID,
		map[string]any{"from": from, "to": groupID, "bulk": true}); err != nil {
		return bulkStatusResult{MachineID: id, OK: false, Error: "could not record audit"}
	}
	return bulkStatusResult{MachineID: id, OK: true}
}

func (s *Server) resolveMachineForProperties(w http.ResponseWriter, r *http.Request, cap Capability) (*Machine, bool) {
	if s.Machines == nil || s.MachineProperties == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return nil, false
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return nil, false
	}
	if err := p.Grant.RequireMachine(cap, m.GroupID); err != nil {
		writeDenied(w, err)
		return nil, false
	}
	return m, true
}

// handleListMachineProperties backs GET /machines/{id}/properties: every custom property on the
// machine, gated on CapViewMachines for the machine's group. Returns {"properties": [...]}.
func (s *Server) handleListMachineProperties(w http.ResponseWriter, r *http.Request) {
	m, ok := s.resolveMachineForProperties(w, r, CapViewMachines)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	props, err := s.MachineProperties.ListProperties(r.Context(), p.TenantID, m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list machine properties")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"properties": props})
}

// setMachinePropertyRequest is the body of PUT /machines/{id}/properties/{key}. The key is the path
// segment; only the value travels in the body.
type setMachinePropertyRequest struct {
	Value          string `json:"value"`
	invalidUnicode bool
}

// machinePropertyJSONValue retains the raw value's Unicode validity while
// preserving encoding/json's string and null handling.
type machinePropertyJSONValue struct {
	value             string
	unpairedSurrogate bool
}

func (v *machinePropertyJSONValue) UnmarshalJSON(data []byte) error {
	if data[0] == '"' {
		v.unpairedSurrogate = hasUnpairedJSONSurrogate(data)
	}
	return json.Unmarshal(data, &v.value)
}

func (req *setMachinePropertyRequest) UnmarshalJSON(data []byte) error {
	raw := struct {
		Value machinePropertyJSONValue `json:"value"`
	}{Value: machinePropertyJSONValue{value: req.Value}}
	err := json.Unmarshal(data, &raw)
	req.Value = raw.Value.value
	req.invalidUnicode = !utf8.Valid(data) || raw.Value.unpairedSurrogate
	return err
}

func (s *Server) handleSetMachineProperty(w http.ResponseWriter, r *http.Request) {
	s.handleSingleMachinePropertyEdit(w, r, false)
}

func (s *Server) handleDeleteMachineProperty(w http.ResponseWriter, r *http.Request) {
	s.handleSingleMachinePropertyEdit(w, r, true)
}

func (s *Server) handleSingleMachinePropertyEdit(w http.ResponseWriter, r *http.Request, remove bool) {
	// As on origin/main: resolve and authorize the target first (group-specific 403 / 404 unknown machine),
	// with no earlier capability check; the transaction re-checks scope on the locked row.
	machine, ok := s.resolveMachineForProperties(w, r, CapManageMachines)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	store := s.fieldStore(w)
	if store == nil {
		return
	}
	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	if !remove {
		if err := validateMachinePropertyKey(key); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var req setMachinePropertyRequest
	if !remove {
		if decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed set-property request body") != nil {
			return
		}
		if len(req.Value) > maxMachinePropertyValueLen {
			writeError(w, http.StatusBadRequest, "value is too long")
			return
		}
	}
	edit := machinePropertyEdit{key: key, value: req.Value, remove: remove, invalidUnicode: req.invalidUnicode}
	_, isMemory := s.Machines.(*InMemoryMachineStore)
	_ = edit.prepare([]string{machine.ID}, isMemory)
	events, err := store.editProperties(r.Context(), p, s.Machines, s.MgmtAudit, &edit)
	if err != nil {
		if IsDenied(err) {
			writeDenied(w, err)
		} else {
			writeMachineFieldError(w, err)
		}
		return
	}
	switch edit.results[0].Error {
	case "unknown machine":
		writeError(w, http.StatusNotFound, "unknown machine")
		return
	case "not set":
		writeError(w, http.StatusNotFound, "unknown property")
		return
	}
	s.dispatchMachineFieldEvents(p, events)
	if remove {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "key": key})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"property": MachineProperty{Key: key, Value: edit.value}})
}

type bulkSetMachinePropertyRequest struct {
	MachineIDs     []string `json:"machine_ids"`
	Key            string   `json:"key"`
	Value          string   `json:"value"`
	Delete         bool     `json:"delete"`
	invalidUnicode bool
}

func (req *bulkSetMachinePropertyRequest) UnmarshalJSON(data []byte) error {
	type request bulkSetMachinePropertyRequest
	raw := struct {
		*request
		Value machinePropertyJSONValue `json:"value"`
	}{request: (*request)(req), Value: machinePropertyJSONValue{value: req.Value}}
	err := json.Unmarshal(data, &raw)
	req.Value = raw.Value.value
	req.invalidUnicode = !utf8.Valid(data) || raw.Value.unpairedSurrogate
	return err
}

func (s *Server) handleBulkSetMachineProperty(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Machines == nil || s.MachineProperties == nil {
		writeError(w, http.StatusInternalServerError, "machine or property store not configured")
		return
	}
	var req bulkSetMachinePropertyRequest
	if err := decodeJSONBody(w, r, maxBulkJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if err := validateMachinePropertyKey(req.Key); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case !req.Delete && len(req.Value) > maxMachinePropertyValueLen:
		writeError(w, http.StatusBadRequest, "value is too long")
		return
	case len(req.MachineIDs) == 0:
		writeError(w, http.StatusBadRequest, "machine_ids must not be empty")
		return
	case len(req.MachineIDs) > maxBulkStatusMachines:
		writeError(w, http.StatusBadRequest, "at most 200 machines per request")
		return
	}
	edit := machinePropertyEdit{key: req.Key, value: req.Value, remove: req.Delete, bulk: true, invalidUnicode: req.invalidUnicode}
	if err := edit.prepare(req.MachineIDs, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	store := s.fieldStore(w)
	if store == nil {
		return
	}
	events, err := store.editProperties(r.Context(), p, s.Machines, s.MgmtAudit, &edit)
	if err != nil {
		writeMachineFieldError(w, err)
		return
	}
	s.dispatchMachineFieldEvents(p, events)
	writeJSON(w, http.StatusOK, map[string]any{"results": edit.results})
}

// enrollRequest is the body of POST /enroll: the target group plus optional identity fields. The
// group is what RBAC scopes against, so it is required.
//
// machine_id here is the agent's DEVICE ID (the stable agent identity), the same identifier the
// mint/start-session paths carry — NOT the database primary key, which the store assigns.
type enrollRequest struct {
	MachineID string `json:"machine_id"` // device id; optional — a fresh one is minted when empty
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
	// OS mirrors redeemEnrollmentRequest.OS: the agent's self-reported OS description, stored as
	// machine.os for the console's inventory column. Display-only, never interpreted.
	OS string `json:"os"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapEnrollMachine); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	var req enrollRequest
	// docs/25 F05. The capability check above already runs first, so an unauthorized caller never
	// reaches this decode at all; the cap bounds what an AUTHORIZED one can make the handler buffer
	// while it holds the pinned tenant connection.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed enroll request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// The capability check above is the tenant-wide form: it proves the caller may enroll SOMEWHERE.
	// The group the machine actually lands in is chosen by the CALLER, so it has to be authorized on
	// its own — otherwise an admin scoped to one group can plant machines into any other group in the
	// tenant (measured before this check existed: 201, row written with the foreign group_id).
	//
	// This is the same check handlePromoteAttended already makes for this very capability
	// (`RequireMachine(CapEnrollMachine, sess.GroupID)`), and that GET /machines/{id} makes against a
	// machine's resolved group. It must run AFTER decoding, because the group is in the body.
	if err := p.Grant.RequireMachine(CapEnrollMachine, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// Same free-text bounds as POST /enroll/redeem. This path is authenticated and capability-gated,
	// so the risk is far lower — but both write the same unbounded `text` columns and are echoed
	// into the same listings, and an asymmetry here is exactly the kind of gap that gets found later
	// and assumed to be deliberate. (`name` was unbounded here before `os` existed.)
	if len(req.Name) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if len(req.OS) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "os is too long")
		return
	}
	deviceID := req.MachineID
	if deviceID == "" {
		deviceID = newUUID()
	}
	// The machine is created into the CALLER'S tenant (RLS/the store pin it); the group comes
	// from the request. The store assigns the primary-key id (populated into m.ID on return);
	// device_id is the agent's stable identity. This legacy authenticated path enrolls WITHOUT
	// a pinned pubkey; installers use POST /enroll/redeem (token + pubkey) instead.
	//
	// A caller-supplied device_id is safe here only because device ids are GLOBALLY unique
	// (migrations/0008): claiming one another tenant already owns conflicts instead of minting a
	// second machine that this tenant could then issue session tickets for.
	m := &Machine{TenantID: p.TenantID, DeviceID: deviceID, GroupID: req.GroupID, Name: req.Name, OS: req.OS}
	if err := s.Machines.EnrollMachine(r.Context(), p.TenantID, m); err != nil {
		if errors.Is(err, ErrMachineDeviceIDTaken) {
			writeError(w, http.StatusConflict, "device_id already enrolled")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not enroll machine")
		return
	}
	if err := s.recordMgmtAudit(r, "machine.enroll", "machine", m.ID,
		map[string]any{"device_id": m.DeviceID, "group_id": m.GroupID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"machine": m})
}
