package controlplane

// Per-machine-group session-policy handlers (docs/01 §5 seat metering, loop 78): GET/PUT
// /machine-groups/{id}/session-policy read and set a single group's concurrent-session cap. All three
// endpoints need CapManageGroups — a cap is an availability control (setting it low throttles the group),
// so it is gated like MANAGING the group, not merely viewing it.
//
// Group scoping (docs/62 R3): a policy is admin knowledge about ONE group, so GET/PUT on a group need
// CapManageGroups whose scope COVERS that group (a scope on a parent covers its subgroups), the same rule
// rename and delete apply — the whole machine-group family moved to it at once. The list endpoint is
// narrowed to the groups the caller manages. A tenant-wide manager is unaffected.
//
// The row returned/stored is the group's OWN settings. Because a policy is the STRICTEST MERGE along the
// ancestor chain (D4), the GET also carries `effective`: the merged values this group is actually admitted
// under, so an editor can show why a child is stricter than its own row says.
// Since loop 80 the row carries more than a seat cap: enforce_view_only (every session on a machine in this
// group is admitted VIEW-ONLY, enforced by the agent via a signed session policy) and, since migration 0040,
// allow_backstage_under_view_only (the explicit opt-out that lets a view-only group still be issued backstage
// grants, for deliberate unattended maintenance). ALL of them are written together by the PUT.
//
// Enforcement of neither is here — the cap is applied at POST /sessions (handleStartSession), atomically, alongside
// the tenant-wide cap. The group must exist within the tenant (404 otherwise), so the fake and pg agree and
// a set never reaches the composite-FK backstop for a bad id.

import (
	"errors"
	"net/http"
)

// groupSessionPolicyRequest is the body of PUT /machine-groups/{id}/session-policy.
//
// Every field is a FULL overwrite of the group's policy, not a patch: an omitted field decodes to its
// zero value and is written as such. That is deliberate and matches the console, which always submits all
// of them — a partial-update semantic would need an explicit tri-state per field, and silently preserving an
// unsent enforce_view_only would make "turn this off" impossible to express.
//
// THAT SEMANTIC IS WHY AllowBackstageUnderViewOnly IS NAMED FOR THE PERMISSION rather than the protection.
// A client that predates migration 0040 — an older console bundle, an operator's script, a curl — will PUT a
// body without the field, and the field will be written as false. False therefore has to be the PROTECTED
// state, or every such caller would silently switch the protection off on whichever group it edited. See the
// field comment on GroupSessionPolicy and migration 0040's header; do not "fix" the name (docs/14 §0.1).
type groupSessionPolicyRequest struct {
	MaxConcurrentSessions       int  `json:"max_concurrent_sessions"`
	EnforceViewOnly             bool `json:"enforce_view_only"`
	AllowBackstageUnderViewOnly bool `json:"allow_backstage_under_view_only"`
	ProhibitRecording           bool `json:"prohibit_recording"`
	RequireRecording            bool `json:"require_recording"`
	MaxSessionDurationSeconds   int  `json:"max_session_duration_seconds"`
	MaxIdleSeconds              int  `json:"max_idle_seconds"`
}

// groupManageAuthorized checks the caller may MANAGE machine groups (CapManageGroups), matching the
// rename/delete handlers exactly — a CapManageGroups holder can already rename or delete any group in the
// tenant, so setting a cap is no more powerful and is gated the same way. Returns false after writing the
// denial, true to proceed.
func (s *Server) groupManageAuthorized(w http.ResponseWriter, r *http.Request, groupID string) bool {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return false
	}
	if groupID != "" {
		if err := authorizeGroupManage(p.Grant, groupID); err != nil {
			writeDenied(w, err)
			return false
		}
	}
	return true
}

// groupExistsInTenant reports whether a static machine group with this id exists in the tenant (RLS-scoped),
// so both handlers 404 identically on an unknown/out-of-tenant id — matching the delete handler's up-front
// membership check and keeping the fake in step with the pg composite-FK backstop.
func (s *Server) groupExistsInTenant(r *http.Request, tenantID, id string) (bool, error) {
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), tenantID)
	if err != nil {
		return false, err
	}
	for _, g := range groups {
		if g.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// handleListGroupSessionPolicies (GET /machine-groups/session-policies) returns every group in the tenant
// that has a cap set, so the console can render current caps in one fetch (the load-groups-and-caps-then-
// intersect-by-id pattern). CapManageGroups, like the per-group GET/PUT.
func (s *Server) handleListGroupSessionPolicies(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.GroupSessionPolicies == nil {
		writeError(w, http.StatusInternalServerError, "group session policy store not configured")
		return
	}
	if !s.groupManageAuthorized(w, r, "") {
		return
	}
	policies, err := s.GroupSessionPolicies.List(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list group session policies")
		return
	}
	// Narrow to the groups the caller manages (R3): a policy of a group outside their scope is not theirs to see.
	visible := make([]GroupSessionPolicy, 0, len(policies))
	for _, pol := range policies {
		if p.Grant.AllowsInGroup(CapManageGroups, pol.GroupID) {
			visible = append(visible, pol)
		}
	}
	body := map[string]any{"policies": visible}
	// The effective (own + inherited) policy of every group the caller manages, computed HERE because the
	// browser cannot: the rows above are narrowed to the caller's groups and a hidden ancestor's row is
	// absent, so a client-side merge would read "no restrictions" under a restricted parent. Hidden
	// ancestors' seat-cap ids are blanked. Any failure is a 500 (fail closed, never a partial map).
	if s.MachineGroups != nil {
		groups, gerr := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "could not list group session policies")
			return
		}
		effective := make(map[string]EffectiveGroupPolicy, len(groups))
		for _, g := range groups {
			if !p.Grant.AllowsInGroup(CapManageGroups, g.ID) {
				continue
			}
			eff, eerr := s.EffectivePolicy(r.Context(), p.TenantID, g.ID)
			if eerr != nil {
				writeError(w, http.StatusInternalServerError, "could not list group session policies")
				return
			}
			effective[g.ID] = effectivePolicyForCaller(p, eff)
		}
		body["effective"] = effective
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleGetGroupSessionPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.GroupSessionPolicies == nil || s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "group session policy store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "group id is required")
		return
	}
	if !s.groupManageAuthorized(w, r, id) {
		return
	}
	ok, err := s.groupExistsInTenant(r, p.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine group")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such machine group")
		return
	}
	policy, err := s.GroupSessionPolicies.Get(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read group session policy")
		return
	}
	eff, err := s.EffectivePolicy(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read group session policy")
		return
	}
	eff = effectivePolicyForCaller(p, eff)
	writeJSON(w, http.StatusOK, groupSessionPolicyView{GroupSessionPolicy: policy, Effective: &eff})
}

// effectivePolicyForCaller keeps the merged values (an admin needs them to see why a group is stricter than
// its own row) but blanks the group id of every seat cap set on a group the caller cannot see, by the same
// visibility rule as groupForCaller (R9): a child-scoped manager must not learn an ancestor's id.
func effectivePolicyForCaller(p *Principal, eff EffectiveGroupPolicy) EffectiveGroupPolicy {
	if len(eff.SeatCaps) == 0 {
		return eff
	}
	caps := make([]GroupSeatCap, len(eff.SeatCaps))
	for i, c := range eff.SeatCaps {
		if !p.Grant.AllowsInGroup(CapViewMachines, c.GroupID) && !p.Grant.AllowsInGroup(CapManageGroups, c.GroupID) {
			c.GroupID = ""
		}
		caps[i] = c
	}
	eff.SeatCaps = caps
	return eff
}

// groupSessionPolicyView is the GET body: the group's own row (every existing key unchanged, at the top
// level) plus the inherited effective merge (docs/62 D4).
type groupSessionPolicyView struct {
	GroupSessionPolicy
	Effective *EffectiveGroupPolicy `json:"effective,omitempty"`
}

func (s *Server) handleSetGroupSessionPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.GroupSessionPolicies == nil || s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "group session policy store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "group id is required")
		return
	}
	if !s.groupManageAuthorized(w, r, id) {
		return
	}
	var req groupSessionPolicyRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	policy, valid := NormalizeGroupSessionPolicy(GroupSessionPolicy{
		GroupID:                     id,
		MaxConcurrentSessions:       req.MaxConcurrentSessions,
		EnforceViewOnly:             req.EnforceViewOnly,
		AllowBackstageUnderViewOnly: req.AllowBackstageUnderViewOnly,
		ProhibitRecording:           req.ProhibitRecording,
		RequireRecording:            req.RequireRecording,
		MaxSessionDurationSeconds:   req.MaxSessionDurationSeconds,
		MaxIdleSeconds:              req.MaxIdleSeconds,
	})
	if !valid {
		if req.ProhibitRecording && req.RequireRecording {
			writeError(w, http.StatusBadRequest,
				"invalid group session policy: prohibit_recording and require_recording cannot both be true")
		} else if req.MaxSessionDurationSeconds < 0 || req.MaxSessionDurationSeconds > MaxGroupSessionDurationSeconds {
			writeError(w, http.StatusBadRequest,
				"invalid group session policy: max_session_duration_seconds must be 0 (unlimited) to 86400 (24 hours)")
		} else if req.MaxIdleSeconds < 0 || req.MaxIdleSeconds > MaxGroupIdleSeconds {
			writeError(w, http.StatusBadRequest,
				"invalid group session policy: max_idle_seconds must be 0 (disabled) to 3600 (1 hour)")
		} else if req.MaxConcurrentSessions > 0 && req.MaxSessionDurationSeconds == 0 {
			writeError(w, http.StatusBadRequest,
				"invalid group session policy: max_session_duration_seconds is required when max_concurrent_sessions > 0")
		} else {
			writeError(w, http.StatusBadRequest,
				"invalid group session policy: max_concurrent_sessions must be 0 (unlimited) to 100000")
		}
		return
	}
	// Existence check BEFORE the write so an unknown id 404s (not a 500 from the composite-FK 23503) and the
	// fake matches. A cap of 0 clears the row; both paths still require the group to exist.
	ok, err := s.groupExistsInTenant(r, p.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine group")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such machine group")
		return
	}
	// R4: refuse an edit that would leave this group or any descendant with an unsatisfiable merged policy
	// (require_recording at one level, prohibit_recording at another). The runtime denial in admission and
	// grant minting stays as the fail-closed backstop for anything this cannot see.
	if status, msg := s.policyEditConflict(r, p.TenantID, id, policy); msg != "" {
		writeError(w, status, msg)
		return
	}
	// Authorized on the grant's view of the tree, so the write is conditional on the tree still being at that
	// version (R2): a reparent that moved this group out of the manager's subtree in between is a 409.
	var setErr error
	if v := expectTreeVersion(p.Grant); v != nil {
		setErr = s.GroupSessionPolicies.SetIfTree(r.Context(), p.TenantID, id, policy, *v)
	} else {
		setErr = s.GroupSessionPolicies.Set(r.Context(), p.TenantID, id, policy)
	}
	if err := setErr; err != nil {
		if errors.Is(err, ErrGroupTreeChanged) {
			writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
			return
		}
		if isForeignKeyViolation(err) {
			// Backstop for a group deleted between the check and the write (TOCTOU) — the composite FK.
			writeError(w, http.StatusNotFound, "no such machine group")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not save group session policy")
		return
	}
	// The WHOLE policy goes into the trail, not only what changed — the PUT is a full overwrite, so what
	// was written IS the new state, and an auditor asking "was backstage open on this view-only group, and
	// from when" must be able to answer it from the events alone rather than by diffing live rows.
	if err := s.recordMgmtAudit(r, "machine_group.session_policy.set", "machine_group", id,
		map[string]any{
			"max_concurrent_sessions":         policy.MaxConcurrentSessions,
			"enforce_view_only":               policy.EnforceViewOnly,
			"allow_backstage_under_view_only": policy.AllowBackstageUnderViewOnly,
			"prohibit_recording":              policy.ProhibitRecording,
			"require_recording":               policy.RequireRecording,
			"max_session_duration_seconds":    policy.MaxSessionDurationSeconds,
			"max_idle_seconds":                policy.MaxIdleSeconds,
		}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

// policyEditConflict returns a refusal (status + message) when writing `policy` as group id's own row would
// give id or any of its descendants an unsatisfiable merged policy, else ("" message). A read failure refuses
// the edit with a 500 rather than writing past an unchecked hierarchy.
func (s *Server) policyEditConflict(r *http.Request, tenantID, id string, policy GroupSessionPolicy) (int, string) {
	tree, _, err := s.MachineGroups.GroupTree(r.Context(), tenantID)
	if err != nil {
		return http.StatusInternalServerError, "could not check the group hierarchy for policy conflicts"
	}
	policies, err := s.GroupSessionPolicies.List(r.Context(), tenantID)
	if err != nil {
		return http.StatusInternalServerError, "could not check the group hierarchy for policy conflicts"
	}
	byGroup := make(map[string]GroupSessionPolicy, len(policies)+1)
	for _, pol := range policies {
		byGroup[pol.GroupID] = pol
	}
	byGroup[id] = policy
	affected := make([]string, 0)
	for g := range subtreeOf(tree, []string{id}) {
		affected = append(affected, g)
	}
	if len(affected) == 0 {
		affected = []string{id}
	}
	if bad := wouldConflict(tree, byGroup, affected); len(bad) > 0 {
		return http.StatusConflict, "this policy would combine require_recording and prohibit_recording from different levels of the group hierarchy; resolve the conflicting group policies first"
	}
	return 0, ""
}
