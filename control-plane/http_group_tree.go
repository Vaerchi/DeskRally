package controlplane

// The machine-group HTTP handlers (docs/62 stage B): list, create (optionally under a parent), rename,
// move, delete. Hierarchy mutations authorize INSIDE the store's tree-locked transaction against the
// current tree (R2); the request-time check here is only an early, cheap refusal. Authorization rules are
// authorizeGroupCreate / Reparent / Manage in group_tree.go (D5 + R3).

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// groupActor is the identity a hierarchy mutation reloads inside its transaction.
func groupActor(p *Principal) GroupActor { return GroupActor{UserID: p.UserID, Grant: p.Grant} }

// writeGroupMutationError maps a hierarchy-mutation failure to its HTTP answer. fallback is the 500 text.
func writeGroupMutationError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case IsDenied(err):
		writeDenied(w, err)
	case errors.Is(err, ErrMachineGroupNotFound):
		writeError(w, http.StatusNotFound, "no such machine group")
	case errors.Is(err, ErrMachineGroupParentInvalid):
		writeError(w, http.StatusConflict, "parent group not found in this tenant")
	case errors.Is(err, ErrMachineGroupCycle):
		writeError(w, http.StatusConflict, "would create a cycle")
	case errors.Is(err, ErrMachineGroupTooDeep):
		writeError(w, http.StatusConflict, "subgroups nest at most 4 levels")
	case errors.Is(err, ErrMachineGroupHasChildren):
		writeError(w, http.StatusConflict, "group still has subgroups; move or delete them first")
	case errors.Is(err, ErrMachineGroupInUse):
		writeError(w, http.StatusConflict, "group is in use; remove its dependents (e.g. enrollment tokens) first")
	case errors.Is(err, ErrGroupTreeChanged):
		writeError(w, http.StatusConflict, "groups changed, retry")
	default:
		writeError(w, http.StatusInternalServerError, fallback)
	}
}

// groupForCaller returns g with parent_id blanked unless the parent is itself visible to the caller (R9):
// a child-scoped technician must not learn that an ancestor exists, let alone its id. Visible means what the
// list endpoint means by it (view_machines covering the group) or, for a caller that holds no view
// capability but manages the group (an API token with only manage_groups), manage_groups covering it — a
// manager of the parent already knows it exists, since moving a group under it required naming it.
func groupForCaller(p *Principal, g MachineGroup) MachineGroup {
	if g.ParentID != nil && !p.Grant.AllowsInGroup(CapViewMachines, *g.ParentID) &&
		!p.Grant.AllowsInGroup(CapManageGroups, *g.ParentID) {
		g.ParentID = nil
	}
	return g
}

// handleListMachineGroups (GET /machine-groups) lists the tenant's STATIC machine groups (the RBAC
// scope unit). Gated on CapViewMachines, then NARROWED to the groups the caller may actually view with
// the SAME AllowsInGroup filter GET /machines applies (separate-stores-intersect-in-handler): a
// group-scoped viewer must not learn the id/name of groups outside their scope. A tenant-wide membership
// (every preset) covers all groups, so this is a no-op for them. A scope on a parent covers its subtree, so
// the caller sees their groups AND the descendants; parent_id is returned only when the parent is itself
// visible (R9), so a child-scoped viewer's subtree root reads as a top-level group.
func (s *Server) handleListMachineGroups(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine group store not configured")
		return
	}
	all, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list machine groups")
		return
	}
	groups := make([]MachineGroup, 0, len(all))
	for _, g := range all {
		if p.Grant.AllowsInGroup(CapViewMachines, g.ID) {
			groups = append(groups, groupForCaller(p, g))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"machine_groups": groups})
}

// createMachineGroupRequest is the body of POST /machine-groups. ParentID is optional: absent or null makes
// a root group.
type createMachineGroupRequest struct {
	Name     string  `json:"name"`
	ParentID *string `json:"parent_id"`
}

// handleCreateMachineGroup (POST /machine-groups) creates a static machine group, a root or, with parent_id,
// a subgroup. Managing groups needs CapManageGroups (Owner/Admin); beyond that (D5/R3) a ROOT group needs a
// tenant-wide grant and a group under P needs manage_groups covering P — a scoped manager cannot mint a
// group outside their subtree. Records a machine_group.created audit event (carrying parent_id).
func (s *Server) handleCreateMachineGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine group store not configured")
		return
	}
	var req createMachineGroupRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	name, ok := validateMachineGroupName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "name must be 1 to 128 characters with no control characters")
		return
	}
	parent := ""
	if req.ParentID != nil {
		if !isUUID(*req.ParentID) {
			writeError(w, http.StatusBadRequest, "parent_id must be a machine group uuid or null")
			return
		}
		parent = *req.ParentID
	}
	// Early refusal on the request-time grant; the authoritative check re-runs inside the store's
	// tree-locked transaction against the current tree and a freshly reloaded grant (R2).
	if err := authorizeGroupCreate(p.Grant, parent); err != nil {
		writeDenied(w, err)
		return
	}
	g := &MachineGroup{Name: name}
	if parent != "" {
		g.ParentID = &parent
	}
	authz := func(grant *Grant, _ GroupTree) error { return authorizeGroupCreate(grant, parent) }
	if err := s.MachineGroups.CreateMachineGroupAs(r.Context(), p.TenantID, groupActor(p), g, authz); err != nil {
		writeGroupMutationError(w, err, "could not create machine group")
		return
	}
	var parentMeta any
	if g.ParentID != nil {
		parentMeta = *g.ParentID
	}
	if err := s.recordMgmtAudit(r, "machine_group.created", "machine_group", g.ID,
		map[string]any{"name": g.Name, "parent_id": parentMeta}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"machine_group": groupForCaller(p, *g)})
}

// renameMachineGroupRequest is the body of PATCH /machine-groups/{id}.
type renameMachineGroupRequest struct {
	Name string `json:"name"`
}

// handleRenameMachineGroup (PATCH /machine-groups/{id}) renames a static machine group. CapManageGroups,
// covering THAT group (R3: a scoped holder cannot rename a group outside their subtree). Audits
// machine_group.renamed. 404 if the id does not resolve within the tenant.
func (s *Server) handleRenameMachineGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine group store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "group id is required")
		return
	}
	if err := authorizeGroupManage(p.Grant, id); err != nil {
		writeDenied(w, err)
		return
	}
	var req renameMachineGroupRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	name, ok := validateMachineGroupName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "name must be 1 to 128 characters with no control characters")
		return
	}
	// The authorization above rests on the grant's view of the tree: the write is conditional on the tree
	// still being at that version (R2), so a reparent in between cannot let a former manager rename.
	var err error
	if v := expectTreeVersion(p.Grant); v != nil {
		err = s.MachineGroups.RenameMachineGroupIfTree(r.Context(), p.TenantID, id, name, *v)
	} else {
		err = s.MachineGroups.RenameMachineGroup(r.Context(), p.TenantID, id, name)
	}
	if err != nil {
		if errors.Is(err, ErrMachineGroupNotFound) {
			writeError(w, http.StatusNotFound, "no such machine group")
			return
		}
		if errors.Is(err, ErrGroupTreeChanged) {
			writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not rename machine group")
		return
	}
	if err := s.recordMgmtAudit(r, "machine_group.renamed", "machine_group", id, map[string]any{"name": name}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	out := MachineGroup{ID: id, Name: name}
	// The rename answer carries the group as it now stands, including its parent when the caller may see it.
	if s.MachineGroups != nil {
		if tree, _, err := s.MachineGroups.GroupTree(r.Context(), p.TenantID); err == nil {
			if par := tree[id]; par != "" {
				out.ParentID = &par
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"machine_group": groupForCaller(p, out)})
}

// moveMachineGroupRequest is the body of POST /machine-groups/{id}/move. ParentID is REQUIRED to be present:
// a uuid reparents, an explicit null makes the group a root. (RawMessage keeps absent and null distinct.)
type moveMachineGroupRequest struct {
	ParentID json.RawMessage `json:"parent_id"`
}

// handleMoveMachineGroup (POST /machine-groups/{id}/move) reparents a group (docs/62 §3). Authorization
// (D5/R3): manage_groups covering the moved group, its old parent and the new parent; making a group a root
// needs a tenant-wide grant. 404 unknown group; 409 for a cycle, a depth over 4, an unknown/foreign parent,
// a tree that changed under the request, or a move that would leave a descendant with an unsatisfiable
// recording policy. Audits machine_group.reparented with the old and new parent.
func (s *Server) handleMoveMachineGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine group store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "group id is required")
		return
	}
	var req moveMachineGroupRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if req.ParentID == nil {
		writeError(w, http.StatusBadRequest, "parent_id is required (a group uuid, or null to make a root group)")
		return
	}
	var newParent *string
	if string(req.ParentID) != "null" {
		var v string
		if err := json.Unmarshal(req.ParentID, &v); err != nil || !isUUID(v) {
			writeError(w, http.StatusBadRequest, "parent_id must be a machine group uuid or null")
			return
		}
		newParent = &v
	}
	np := strOrEmpty(newParent)
	// Early refusal on the request-time grant against the tree as it was when the grant was read; the
	// authoritative check re-runs inside the store transaction (R2). The tree read here also feeds the
	// policy-conflict pre-check below.
	tree, _, err := s.MachineGroups.GroupTree(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine groups")
		return
	}
	if _, exists := tree[id]; !exists {
		// An unknown group answers 404 only to a caller who could have managed it; everyone else gets the
		// same 403 an existing out-of-scope group would, so existence is not an oracle.
		if err := authorizeGroupManage(p.Grant, id); err != nil {
			writeDenied(w, err)
			return
		}
		writeError(w, http.StatusNotFound, "no such machine group")
		return
	}
	if err := authorizeGroupReparent(p.Grant, tree, id, np); err != nil {
		writeDenied(w, err)
		return
	}
	// R4: refuse a reparent that would give this group or any descendant an unsatisfiable merged policy.
	if refused, msg := s.reparentPolicyConflict(r, p.TenantID, tree, id, np); refused {
		writeError(w, http.StatusConflict, msg)
		return
	}
	authz := func(grant *Grant, current GroupTree) error { return authorizeGroupReparent(grant, current, id, np) }
	moved, oldParent, err := s.MachineGroups.MoveMachineGroup(r.Context(), p.TenantID, groupActor(p), id, newParent, authz)
	if err != nil {
		writeGroupMutationError(w, err, "could not move machine group")
		return
	}
	var from, to any
	if oldParent != nil {
		from = *oldParent
	}
	if moved.ParentID != nil {
		to = *moved.ParentID
	}
	if err := s.recordMgmtAudit(r, "machine_group.reparented", "machine_group", id,
		map[string]any{"from_parent_id": from, "to_parent_id": to}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"machine_group": groupForCaller(p, *moved)})
}

// reparentPolicyConflict reports whether moving group id under newParent ("" = root) would leave the group
// or any descendant with an unsatisfiable (require AND prohibit recording) merged policy. Best effort by
// design (R4): it reads the policies outside the store transaction, and the runtime denial in admission and
// grant minting is the fail-closed backstop.
func (s *Server) reparentPolicyConflict(r *http.Request, tenantID string, tree GroupTree, id, newParent string) (bool, string) {
	if s.GroupSessionPolicies == nil {
		return false, ""
	}
	policies, err := s.GroupSessionPolicies.List(r.Context(), tenantID)
	if err != nil {
		log.Printf("machine group %s move: could not read policies for the conflict pre-check: %v", id, err)
		return false, ""
	}
	byGroup := make(map[string]GroupSessionPolicy, len(policies))
	for _, pol := range policies {
		byGroup[pol.GroupID] = pol
	}
	next := make(GroupTree, len(tree))
	for k, v := range tree {
		next[k] = v
	}
	next[id] = newParent
	affected := make([]string, 0)
	for g := range subtreeOf(next, []string{id}) {
		affected = append(affected, g)
	}
	if bad := wouldConflict(next, byGroup, affected); len(bad) > 0 {
		return true, "this move would combine require_recording and prohibit_recording from different levels for a group in the moved subtree; resolve the group policies first"
	}
	return false, ""
}

// handleDeleteMachineGroup (DELETE /machine-groups/{id}) deletes a static machine group. CapManageGroups,
// covering THAT group (R3). Refused (409) while the group still has SUBGROUPS (D7) or MACHINES — checked up
// front so the fake and pg agree and the message is clear — and the pg FK backstops a group an enrollment
// token still references. Audits machine_group.deleted. 404 if the id does not resolve.
func (s *Server) handleDeleteMachineGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.MachineGroups == nil || s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "group id is required")
		return
	}
	// Early refusal, before the 409 checks below can reveal anything about a group outside the caller's
	// scope; the authoritative check re-runs inside the store transaction (R2).
	if err := authorizeGroupManage(p.Grant, id); err != nil {
		writeDenied(w, err)
		return
	}
	// A group that still contains machines must not be deleted out from under them (the machine.group_id
	// FK would block it anyway; checking here gives a clear 409 and keeps the fake in step with pg).
	machines, err := s.Machines.ListMachines(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check group membership")
		return
	}
	for _, m := range machines {
		if m.GroupID == id {
			writeError(w, http.StatusConflict, "group still has machines; move or remove them first")
			return
		}
	}
	authz := func(grant *Grant, _ GroupTree) error { return authorizeGroupManage(grant, id) }
	if err := s.MachineGroups.DeleteMachineGroupAs(r.Context(), p.TenantID, groupActor(p), id, authz); err != nil {
		writeGroupMutationError(w, err, "could not delete machine group")
		return
	}
	// Drop the group's per-group session cap along with it. Postgres has already done this via the
	// 0034 composite FK's ON DELETE CASCADE, so there this is a no-op; the in-memory store has no
	// cascade and would otherwise keep an orphan cap that GET /machine-groups/session-policies would
	// report for a group that no longer exists. Calling it for both keeps the two stores on ONE
	// observable contract. Deliberately AFTER the delete succeeded: a refused delete (409, the group
	// still has machines or subgroups) must leave the cap untouched.
	//
	// Best-effort: the group IS gone, so failing the request now would be a lie. Logged loudly instead
	// -- an orphan cap is inert (nothing counts sessions against a group that cannot be referenced).
	if s.GroupSessionPolicies != nil {
		if err := s.GroupSessionPolicies.DeleteForGroup(r.Context(), p.TenantID, id); err != nil {
			log.Printf("machine group %s deleted but its session cap could not be removed: %v", id, err)
		}
	}
	if err := s.recordMgmtAudit(r, "machine_group.deleted", "machine_group", id, map[string]any{}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}
