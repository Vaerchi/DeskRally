package controlplane

// Tenant administration: management audit, tenants, the tenant IP allowlist and dynamic groups. Split out of http.go (routing and middleware stay there).

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// -------------------------------------------------------------------------------------
// Handlers. Data access runs against the repository stores; RLS (pinned by the binder /
// withTenant) already scopes every query to the caller's tenant, so none of them carries an
// explicit tenant filter.
// -------------------------------------------------------------------------------------

// recordMgmtAudit appends a management-plane audit event for a handler action. When no
// MgmtAuditStore is wired (pure-RBAC skeleton tests) recording is skipped. A recording FAILURE
// is returned so the handler fails the request: a mutation that cannot be audited must be loud,
// not silent (the mutation itself may already be committed — its own transaction — but the
// caller sees a 500 instead of a success it could assume was recorded).
func (s *Server) recordMgmtAudit(r *http.Request, action, targetKind, targetID string, meta map[string]any) error {
	if s.MgmtAudit == nil {
		return nil
	}
	p := principalFrom(r.Context())
	var raw json.RawMessage
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		raw = b
	}
	e := &MgmtAuditEvent{
		ActorUserID: p.UserID,
		Action:      action,
		TargetKind:  targetKind,
		TargetID:    targetID,
		Metadata:    raw,
	}
	if err := s.MgmtAudit.RecordEvent(r.Context(), p.TenantID, e); err != nil {
		return err
	}
	// After a successful audit write, fire registered webhook endpoints asynchronously.
	// The dispatch is best-effort (fire-and-forget, one retry); audit failure is still
	// reported to the caller and blocks the mutation — webhooks never do.
	if s.Dispatcher != nil {
		s.Dispatcher.Dispatch(p.TenantID, e)
	}
	return nil
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	// RLS confines a normal caller to their own tenant row; the listing is still gated on
	// ManageTenant because tenant settings are a management surface, not technician data.
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Tenants == nil {
		writeError(w, http.StatusInternalServerError, "tenant store not configured")
		return
	}
	tenants, err := s.Tenants.ListTenants(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list tenants")
		return
	}
	// Provisioning moved to POST /platform/tenants (operators only); the console's Platform area
	// owns it, so this listing never offers it.
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants, "can_create": false})
}

// createTenantRequest is the body of POST /tenants (SaaS provisioning surface).
type createTenantRequest struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	DeploymentMode string `json:"deployment_mode"` // optional; defaults to "saas"
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	// Tenant provisioning is a platform-operator action: POST /platform/tenants, which requires the
	// per-user operator grant and a recent second-factor verification, and audits both chains.
	// Every tenant's Owner holds CapManageTenant, so this route could never be the gate.
	writeError(w, http.StatusGone, "tenant provisioning moved to POST /platform/tenants (platform operators only)")
}

// requireTenantIPAllowlist is the shared preamble for the three /tenant/ip-allowlist handlers: gate on
// CapManageTenant (tenant security settings, like the tenant surface) and confirm the store is wired.
// Returns the principal, or writes the error response and returns nil.
func (s *Server) requireTenantIPAllowlist(w http.ResponseWriter, r *http.Request) *Principal {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return nil
	}
	if s.TenantIPAllowlist == nil {
		writeError(w, http.StatusInternalServerError, "tenant ip allow-list store not configured")
		return nil
	}
	return p
}

// handleGetTenantIPAllowlist (GET /tenant/ip-allowlist) returns the tenant's allow-list CIDRs plus the
// caller's CURRENT source IP, so the console can show "your IP is X" beside the list — the signal an
// admin needs to avoid locking themselves out.
func (s *Server) handleGetTenantIPAllowlist(w http.ResponseWriter, r *http.Request) {
	p := s.requireTenantIPAllowlist(w, r)
	if p == nil {
		return
	}
	cidrs, err := s.TenantIPAllowlist.ListCIDRs(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list ip allow-list")
		return
	}
	if cidrs == nil {
		cidrs = []string{} // a tenant with no entries serializes as [], never null
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs, "your_ip": s.callerIPString(r)})
}

// callerIPString is the caller's source IP as the enforcement sees it (RemoteAddr or trusted XFF),
// or "" when it cannot be determined. Echoed to the console and used in the anti-lockout message.
func (s *Server) callerIPString(r *http.Request) string {
	if ip := resolveClientIP(r, s.trustProxyIP, s.trustedProxyNets); ip != nil {
		return ip.String()
	}
	return ""
}

// wouldLockOutCaller reports whether enforcing `resulting` as the tenant's allow-list would refuse the
// CALLER's own current request — i.e. the list is non-empty AND does not cover the caller's source IP.
// An empty resulting list is "open" (never a lockout). Reuses the exact enforcement matcher, so the
// safeguard and the middleware can never disagree. A parse error fails closed (treated as a lockout).
func (s *Server) wouldLockOutCaller(r *http.Request, resulting []string) bool {
	allow, err := ParseIPAllowlist(strings.Join(resulting, " "), s.trustProxyIP)
	if err != nil {
		return true
	}
	if allow != nil {
		allow.trustedProxyNets = s.trustedProxyNets
	}
	return !allow.Allows(r)
}

// handleAddTenantIPAllowlistEntry (POST /tenant/ip-allowlist, body {cidr}) adds one CIDR. It refuses
// (400) any add whose RESULTING list would exclude the caller's own current source IP — the
// anti-lockout safeguard, so an admin cannot fence themselves out of the very API that manages the list.
func (s *Server) handleAddTenantIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	p := s.requireTenantIPAllowlist(w, r)
	if p == nil {
		return
	}
	var body struct {
		CIDR string `json:"cidr"`
	}
	// docs/25 F05: one CIDR string; capped so the decode cannot hold the pinned tenant connection
	// open on a body the client keeps extending.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &body, "malformed request body"); err != nil {
		return
	}
	cidr, err := normalizeCIDR(body.CIDR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Anti-lockout is enforced ATOMICALLY inside the store (advisory-locked read-check-write), so two
	// concurrent mutations cannot each validate against a stale snapshot and jointly lock the caller out
	// (a TOCTOU a handler-side check leaves open). `safe` is the caller-coverage predicate; the store
	// runs it under the per-tenant lock against the true committed state.
	safe := func(resulting []string) bool { return !s.wouldLockOutCaller(r, resulting) }
	if err := s.TenantIPAllowlist.AddCIDRGuarded(r.Context(), p.TenantID, cidr, safe); err != nil {
		if errors.Is(err, ErrWouldLockOut) {
			writeError(w, http.StatusBadRequest, "this would lock you out: your current IP "+s.callerIPString(r)+" is not covered by the resulting allow-list")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not add ip allow-list entry")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.ip_allowlist.add", "tenant", p.TenantID, map[string]any{"cidr": cidr}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidr": cidr})
}

// handleDeleteTenantIPAllowlistEntry (DELETE /tenant/ip-allowlist?cidr=<cidr>) removes one CIDR. The
// CIDR is a query param, not a path segment, because it contains a '/'. It applies the same
// anti-lockout safeguard: removing an entry must not leave a non-empty list that excludes the caller.
func (s *Server) handleDeleteTenantIPAllowlistEntry(w http.ResponseWriter, r *http.Request) {
	p := s.requireTenantIPAllowlist(w, r)
	if p == nil {
		return
	}
	cidr, err := normalizeCIDR(r.URL.Query().Get("cidr"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Same ATOMIC anti-lockout as the add: the store removes and re-checks caller coverage under the
	// per-tenant advisory lock, so two concurrent deletes of overlapping-coverage entries cannot each
	// see the other's stale snapshot and jointly strand the caller. Removing to an empty (open) list is
	// always safe.
	safe := func(resulting []string) bool { return !s.wouldLockOutCaller(r, resulting) }
	if err := s.TenantIPAllowlist.RemoveCIDRGuarded(r.Context(), p.TenantID, cidr, safe); err != nil {
		if errors.Is(err, ErrWouldLockOut) {
			writeError(w, http.StatusBadRequest, "this would lock you out: your current IP "+s.callerIPString(r)+" would no longer be covered by the allow-list")
			return
		}
		if errors.Is(err, ErrTenantIPAllowlistEntryNotFound) {
			writeError(w, http.StatusNotFound, "no such allow-list entry")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not remove ip allow-list entry")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.ip_allowlist.remove", "tenant", p.TenantID, map[string]any{"cidr": cidr}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "cidr": cidr})
}

// handleListDynamicGroups (GET /dynamic-groups) lists the tenant's saved predicates. A read, gated on
// CapViewMachines (a technician benefits from resolving groups; managing them needs CapManageGroups).
func (s *Server) handleListDynamicGroups(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil {
		writeError(w, http.StatusInternalServerError, "dynamic group store not configured")
		return
	}
	groups, err := s.DynamicGroups.ListDynamicGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list dynamic groups")
		return
	}
	if groups == nil {
		groups = []DynamicGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// createDynamicGroupRequest is the body of POST /dynamic-groups.
type createDynamicGroupRequest struct {
	Name          string `json:"name"`
	PropertyKey   string `json:"property_key"`
	PropertyValue string `json:"property_value"` // optional; "" = "any value" (see MachineIDsWithProperty)
}

// handleCreateDynamicGroup (POST /dynamic-groups) creates a saved predicate. Managing groups needs
// CapManageGroups (Owner/Admin) — CapManageGroups' first consumer.
func (s *Server) handleCreateDynamicGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil {
		writeError(w, http.StatusInternalServerError, "dynamic group store not configured")
		return
	}
	var req createDynamicGroupRequest
	// docs/25 F05: three short strings, each length-checked below; capped so the decode cannot hold
	// the pinned tenant connection open.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.PropertyKey = strings.TrimSpace(req.PropertyKey)
	if req.Name == "" || req.PropertyKey == "" {
		writeError(w, http.StatusBadRequest, "name and property_key are required")
		return
	}
	if len(req.Name) > maxDynamicGroupNameLen || len(req.PropertyKey) > maxDynamicGroupKeyLen ||
		len(req.PropertyValue) > maxDynamicGroupValLen {
		writeError(w, http.StatusBadRequest, "name/property_key/property_value too long")
		return
	}
	g := &DynamicGroup{Name: req.Name, PropertyKey: req.PropertyKey, PropertyValue: req.PropertyValue}
	if err := s.DynamicGroups.CreateDynamicGroup(r.Context(), p.TenantID, g); err != nil {
		if errors.Is(err, ErrDynamicGroupNameTaken) {
			writeError(w, http.StatusConflict, "a dynamic group with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create dynamic group")
		return
	}
	if err := s.recordMgmtAudit(r, "group.create", "group", g.ID, map[string]any{"name": g.Name, "property_key": g.PropertyKey}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"group": g})
}

// handleDeleteDynamicGroup (DELETE /dynamic-groups/{id}) removes a saved predicate. CapManageGroups.
func (s *Server) handleDeleteDynamicGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageGroups); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil {
		writeError(w, http.StatusInternalServerError, "dynamic group store not configured")
		return
	}
	id := r.PathValue("id")
	if err := s.DynamicGroups.DeleteDynamicGroup(r.Context(), p.TenantID, id); err != nil {
		if errors.Is(err, ErrDynamicGroupNotFound) {
			writeError(w, http.StatusNotFound, "dynamic group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete dynamic group")
		return
	}
	if err := s.recordMgmtAudit(r, "group.delete", "group", id, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// handleResolveDynamicGroup (GET /dynamic-groups/{id}/machines) resolves a group's members LIVE. It
// reuses the SAME "narrow-only" resolution as GET /machines: list the tenant's machines, keep only those
// the caller may see (AllowsInGroup), then INTERSECT with the machines carrying the group's property —
// so a dynamic group can never reveal a machine the caller could not already list, nor widen their reach.
func (s *Server) handleResolveDynamicGroup(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewMachines); err != nil {
		writeDenied(w, err)
		return
	}
	if s.DynamicGroups == nil || s.Machines == nil || s.MachineProperties == nil {
		writeError(w, http.StatusInternalServerError, "machine or dynamic group store not configured")
		return
	}
	g, err := s.DynamicGroups.GetDynamicGroup(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrDynamicGroupNotFound) {
			writeError(w, http.StatusNotFound, "dynamic group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not read dynamic group")
		return
	}
	all, err := s.Machines.ListMachines(r.Context(), p.TenantID)
	if err != nil {
		writeListError(w, err, "could not list machines")
		return
	}
	ids, err := s.MachineProperties.MachineIDsWithProperty(r.Context(), p.TenantID, g.PropertyKey, g.PropertyValue)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve dynamic group members")
		return
	}
	members := make([]Machine, 0)
	for _, m := range all {
		// Narrow to the caller's visible machines AND intersect with the predicate (never widen).
		if p.Grant.AllowsInGroup(CapViewMachines, m.GroupID) {
			if _, ok := ids[m.ID]; ok {
				members = append(members, m)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": g, "machines": members})
}
