// Package controlplane is the multi-tenant management API (docs/02-architecture.md
// ADR-003): tenants, users, RBAC roles scoped to machine/session groups, machines,
// enrollment tokens, and audit.
//
// This file is the authorization model. It mirrors the agent's per-capability approach
// (agent/src/backstage/rbac.rs): every protected action maps to exactly one Capability,
// roles are presets that expand to a set of capabilities, and the single choke point is a
// per-capability check that additionally scopes machine access by group. The console UI
// hiding a button is never trusted — the check is re-run server-side on every request.
//
// The capability keys here are the source of truth mirrored by migrations/0001_core.sql's
// preset-role seed rows; the two MUST stay in sync (TestPresetsMatchExpectedCapabilities
// guards the shape).
package controlplane

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Capability is a single, indivisible management-plane permission. New capabilities MUST be
// added here explicitly (never inferred) so a capability the server doesn't know about can
// never be granted implicitly — same discipline as the agent's backstage Capability enum.
type Capability string

const (
	// --- tenant administration ---
	CapManageTenant Capability = "manage_tenant" // billing, deployment settings, delete tenant
	CapManageUsers  Capability = "manage_users"  // invite/disable users
	CapManageRoles  Capability = "manage_roles"  // create custom roles, assign memberships
	CapManageGroups Capability = "manage_groups" // create/rename/nest machine groups

	// --- fleet ---
	CapViewMachines     Capability = "view_machines"
	CapManageMachines   Capability = "manage_machines"   // rename, retire, quarantine, reassign group
	CapDeployAgent      Capability = "deploy_agent"      // push/trigger agent install
	CapEnrollMachine    Capability = "enroll_machine"    // redeem an enrollment token
	CapManageEnrollment Capability = "manage_enrollment" // mint/revoke enrollment tokens

	// --- sessions ---
	CapStartSession Capability = "start_session"
	// Observe supplements StartSession; it never authorizes a watch-only principal by itself.
	CapObserveSession Capability = "observe_session"
	CapEndSession     Capability = "end_session"
	CapBackstageShell Capability = "backstage_shell" // gates the backstage grant issued to the agent
	CapTransferFiles  Capability = "transfer_files"
	CapViewSessions   Capability = "view_sessions"
	// CapElevateSession gates POST /sessions/{id}/elevation — minting a signed, single-use grant
	// that lets ONE command on a live session run with the guest's LINKED ELEVATED token instead of
	// their ordinary filtered one (docs/01 §3, loop 87).
	//
	// Its OWN capability rather than a reuse of CapManageMachines (the existing "admin tier" gate in
	// grant.go's BackstageCapsFor), for one concrete reason: CapManageMachines is on
	// apiTokenGrantableCaps, so reusing it would let an API TOKEN — a principal with no user row and
	// no interactive session — mint an elevation. This one is deliberately absent from that
	// whitelist, so no token can ever hold it. A plain Technician does not get it either: they can
	// run commands, but taking the guest's admin identity is an administrator's decision.
	CapElevateSession Capability = "elevate_session"

	// --- audit ---
	CapViewAudit Capability = "view_audit"

	// CapViewRecordings gates watching and downloading central session recordings (docs/63 D6, C8).
	// Viewing a screen is more sensitive than reading an audit list, so it is its OWN capability, held
	// by Owner (everything), Admin and Auditor — NOT Technician (the technician who ran a session does
	// not get to replay it by default), NOT ReadOnly, and deliberately absent from apiTokenGrantableCaps
	// so no API token can ever hold it. Group scope applies exactly as for backstage audit.
	CapViewRecordings Capability = "view_recordings"

	// CapManageToolbox: create/edit/delete the tenant's SHARED toolbox items (docs/design-shared-
	// toolbox.md). Using the toolbox (listing, personal items, run requests) rides CapStartSession.
	CapManageToolbox Capability = "manage_toolbox"

	// CapRemoveAgent gates the per-machine fleet directives (docs/65): reinstalling an agent and, above
	// all, REMOVING one (uninstall + config and identity-key deletion) without opening a session.
	//
	// OWNER PRESET ONLY, and deliberately absent from apiTokenGrantableCaps (pinned by
	// TestRemoveAgentIsNeverTokenGrantable): the uninstall flow's gates - a TOTP step-up inside an
	// interactive session, a typed confirmation, an optional second approver - all assume a person, and
	// CapManageMachines, which an API token CAN hold, must never be enough to wipe a fleet. Group scope
	// applies (AllowsInGroup on the machine's CURRENT group, docs/62 sec. 2a).
	CapRemoveAgent Capability = "remove_agent"
)

// AllCapabilities is every capability the system defines, in a stable order. Used to expand
// the Owner preset and to validate seeds/tests.
var AllCapabilities = []Capability{
	CapManageTenant, CapManageUsers, CapManageRoles, CapManageGroups,
	CapViewMachines, CapManageMachines, CapDeployAgent, CapEnrollMachine, CapManageEnrollment,
	CapStartSession, CapObserveSession, CapEndSession, CapBackstageShell, CapTransferFiles, CapViewSessions,
	CapElevateSession,
	CapViewAudit,
	CapViewRecordings,
	CapManageToolbox,
	CapRemoveAgent,
}

// Role is a named capability preset. Keys match the preset `role.key` rows in
// migrations/0001_core.sql.
type Role string

const (
	RoleOwner      Role = "owner"
	RoleAdmin      Role = "admin"
	RoleTechnician Role = "technician"
	RoleReadOnly   Role = "readonly"
	RoleAuditor    Role = "auditor"
)

// rolePresets is the authoritative expansion of each preset role to its capabilities. This
// mirrors the seed INSERT in migrations/0001_core.sql — keep both in sync.
var rolePresets = map[Role][]Capability{
	// Owner holds everything, including tenant-level administration.
	RoleOwner: AllCapabilities,

	// Admin runs the tenant day-to-day but cannot touch tenant billing/deletion.
	RoleAdmin: {
		CapManageUsers, CapManageRoles, CapManageGroups,
		CapViewMachines, CapManageMachines, CapDeployAgent, CapEnrollMachine, CapManageEnrollment,
		CapStartSession, CapObserveSession, CapEndSession, CapBackstageShell, CapTransferFiles,
		CapViewSessions, CapElevateSession, CapViewAudit, CapViewRecordings, CapManageToolbox,
	},

	// Technician does the actual remote-support work but administers nothing.
	RoleTechnician: {
		CapViewMachines, CapDeployAgent,
		CapStartSession, CapObserveSession, CapEndSession, CapBackstageShell, CapTransferFiles,
		CapViewSessions,
	},

	// ReadOnly can look but not act.
	RoleReadOnly: {
		CapViewMachines, CapViewSessions,
	},

	// Auditor is ReadOnly plus the audit trail — for compliance reviewers.
	RoleAuditor: {
		CapViewMachines, CapViewSessions, CapViewAudit, CapViewRecordings,
	},
}

// assignableRoles is the set of preset roles the console may assign to a user, in a stable display
// order (highest authority first). Only presets are assignable today — custom per-tenant roles are a
// future feature — and the server-side gate is IsAssignableRole, never the UI list. Every entry MUST
// be a key of rolePresets (TestAssignableRolesMatchPresets guards the two do not drift).
var assignableRoles = []Role{RoleOwner, RoleAdmin, RoleTechnician, RoleReadOnly, RoleAuditor}

// AssignableRoles returns a copy of the assignable preset roles (so callers cannot mutate the source).
func AssignableRoles() []Role {
	out := make([]Role, len(assignableRoles))
	copy(out, assignableRoles)
	return out
}

// IsAssignableRole reports whether r is a known assignable preset. The role-assignment handler and the
// stores both gate on this so an unknown/empty role can never be written as a membership.
func IsAssignableRole(r Role) bool {
	for _, a := range assignableRoles {
		if a == r {
			return true
		}
	}
	return false
}

// capabilitySet is an efficient membership set built once per role/membership.
type capabilitySet map[Capability]struct{}

func newCapabilitySet(caps []Capability) capabilitySet {
	s := make(capabilitySet, len(caps))
	for _, c := range caps {
		s[c] = struct{}{}
	}
	return s
}

// Capabilities returns the preset capabilities for a role. Unknown roles return nil (deny
// by default).
func (r Role) Capabilities() []Capability {
	caps, ok := rolePresets[r]
	if !ok {
		return nil
	}
	// Return a copy so callers can't mutate the preset.
	out := make([]Capability, len(caps))
	copy(out, caps)
	return out
}

// Has reports whether the role's preset includes the capability.
func (r Role) Has(c Capability) bool {
	for _, rc := range rolePresets[r] {
		if rc == c {
			return true
		}
	}
	return false
}

// GroupScope describes which machine/session groups a membership applies to. A membership
// with All == true (equivalently, an empty Groups set persisted as `scoped_group_ids = {}`)
// covers every group in the tenant; otherwise only the listed group IDs AND their descendants.
//
// A group-limited scope carries TWO sets (docs/62 D3):
//
//   - assigned: exactly what is stored (the ids an admin chose). Persistence (GroupIDs,
//     AssignmentScope), homogeneity (sameScope) and the escalation comparison's TARGET side read it. It
//     is never rewritten by inheritance logic, so a reparent can never leave a stale expansion behind and
//     can never empty an array (empty = tenant-wide = a silent widen).
//   - covered: assigned plus every descendant, resolved once at grant load (GrantFor / StoredGrantFor,
//     pg and fake). Covers, Includes (actor side) and ScopeFor read it. It is downward-closed.
//
// A scope built by Groups() directly has no tree to consult, so covered == assigned (no inheritance).
// All is NEVER derived from an empty covered set: a scope whose roots all dangle is scoped and covers
// nothing (docs/62 R1d).
type GroupScope struct {
	All      bool
	assigned capabilitySetGroups
	covered  capabilitySetGroups
}

type capabilitySetGroups map[string]struct{}

// AllGroups returns a tenant-wide scope.
func AllGroups() GroupScope { return GroupScope{All: true} }

// Groups returns a scope limited to the given group IDs. An empty list is treated as
// tenant-wide (matching the DB convention where `{}` means all groups).
func Groups(ids ...string) GroupScope {
	if len(ids) == 0 {
		return GroupScope{All: true}
	}
	g := make(capabilitySetGroups, len(ids))
	for _, id := range ids {
		g[id] = struct{}{}
	}
	return GroupScope{assigned: g, covered: cloneGroupSet(g)}
}

func cloneGroupSet(in capabilitySetGroups) capabilitySetGroups {
	out := make(capabilitySetGroups, len(in))
	for id := range in {
		out[id] = struct{}{}
	}
	return out
}

// withCovered returns the scope with a FRESHLY ALLOCATED covered set (never shared with the assigned set
// or with another scope). An All scope is returned unchanged. A group-limited scope stays group-limited
// even when covered is empty (R1d): the result never becomes tenant-wide.
func (s GroupScope) withCovered(covered map[string]struct{}) GroupScope {
	if s.All {
		return s
	}
	return GroupScope{assigned: cloneGroupSet(s.assigned), covered: cloneGroupSet(covered)}
}

// expandedScope resolves a stored scope against a tree snapshot (parentOf: id -> parent id, "" = root,
// absent = no such group): covered = the assigned ids that exist, plus their descendants. A dangling
// assigned id contributes nothing. An All scope is unchanged.
func expandedScope(s GroupScope, parentOf map[string]string) GroupScope {
	if s.All {
		return s
	}
	roots := make([]string, 0, len(s.assigned))
	for id := range s.assigned {
		roots = append(roots, id)
	}
	return s.withCovered(subtreeOf(parentOf, roots))
}

// Covers reports whether this scope includes the given machine group, directly or by inheritance.
func (s GroupScope) Covers(groupID string) bool {
	if s.All {
		return true
	}
	_, ok := s.covered[groupID]
	return ok
}

// CoveredIDs returns the explicit covered group ids of a group-limited scope (assigned plus
// descendants), sorted, or nil for a tenant-wide scope. Unlike GroupIDs it is NOT for persistence: an
// empty result for a group-limited scope means "covers nothing", never "tenant-wide".
func (s GroupScope) CoveredIDs() []string {
	if s.All {
		return nil
	}
	out := make([]string, 0, len(s.covered))
	for id := range s.covered {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// GroupIDs returns the explicit group ids of a group-limited scope, sorted for determinism, or nil
// for a tenant-wide (All) scope. It is the inverse of Groups(): persisting GroupIDs() of a scope and
// reading it back through Groups() round-trips. nil is the signal "tenant-wide", matching the DB's
// empty scoped_group_ids convention — callers persisting this must write nil/empty as '{}' and must
// never let a non-empty scope collapse to empty by accident (that would silently widen to tenant-wide).
func (s GroupScope) GroupIDs() []string {
	if s.All || len(s.assigned) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.assigned))
	for id := range s.assigned {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Membership binds one role to a group scope for a user within a tenant. A user may hold
// several memberships (e.g. Technician over group A, ReadOnly tenant-wide).
type Membership struct {
	Role  Role
	Scope GroupScope
	// ExpiresAt is when the membership stops granting (docs/56); nil = never. Capability checks do NOT
	// read it: GrantFor drops expired memberships before a Grant is built, so an effective Grant only
	// ever holds live ones. It is populated on STORED grants (StoredGrantFor), which the admin paths use.
	ExpiresAt *time.Time
	// Window limits the membership to set hours (docs/57); nil = any time. Like ExpiresAt it is applied by
	// GrantFor, never by capability checks, and populated on stored grants.
	Window *AccessWindow

	// caps is the role's expanded capability set, cached for repeated checks.
	caps capabilitySet
}

// WithExpiry returns the membership with its expiry set (nil = never).
func (m Membership) WithExpiry(at *time.Time) Membership {
	m.ExpiresAt = at
	return m
}

// WithWindow returns the membership with its access window set (nil = any time).
func (m Membership) WithWindow(w *AccessWindow) Membership {
	m.Window = w
	return m
}

// grantsAt reports whether the membership grants at now: unexpired AND inside its window (docs/57 sec. 2).
func (m Membership) grantsAt(now time.Time) bool {
	return !m.expiredAt(now) && m.Window.OpenAt(now)
}

// expiredAt reports whether the membership has stopped granting at now (an expiry AT now counts:
// the predicate is `expires_at > now`, matching the pg filter).
func (m Membership) expiredAt(now time.Time) bool {
	return m.ExpiresAt != nil && !m.ExpiresAt.After(now)
}

// Effective returns a copy of the grant holding only the memberships that grant at now: unexpired and
// inside their window (the in-memory store's GrantFor; pg filters in SQL).
func (g *Grant) Effective(now time.Time) *Grant {
	if g == nil {
		return nil
	}
	out := &Grant{UserID: g.UserID, TenantID: g.TenantID, TreeVersion: g.TreeVersion, reloadable: g.reloadable}
	for _, m := range g.Members {
		if m.grantsAt(now) {
			out.Members = append(out.Members, m)
		}
	}
	return out
}

// AccessExpiry is the aggregate expiry of a STORED grant (docs/56 sec. 5): nil when the grant has no
// memberships or ANY membership never expires; otherwise the LATEST expiry (when the last access ends).
func (g *Grant) AccessExpiry() *time.Time {
	if g == nil || len(g.Members) == 0 {
		return nil
	}
	var latest *time.Time
	for _, m := range g.Members {
		if m.ExpiresAt == nil {
			return nil
		}
		if latest == nil || m.ExpiresAt.After(*latest) {
			t := *m.ExpiresAt
			latest = &t
		}
	}
	return latest
}

// AccessExpired reports whether a STORED grant has memberships and every one of them has expired.
func (g *Grant) AccessExpired(now time.Time) bool {
	if g == nil || len(g.Members) == 0 {
		return false
	}
	for _, m := range g.Members {
		if !m.expiredAt(now) {
			return false
		}
	}
	return true
}

// Homogeneous reports whether every membership of a STORED grant has the same scope, the same expiry
// and the same window, so preserving "the" scope, expiry or window is well-defined (docs/56 sec. 4 r3,
// docs/57 sec. 4). Zero or one membership is trivially homogeneous.
func (g *Grant) Homogeneous() bool {
	if g == nil || len(g.Members) < 2 {
		return true
	}
	first := g.Members[0]
	for _, m := range g.Members[1:] {
		if !sameScope(first.Scope, m.Scope) || !sameExpiry(first.ExpiresAt, m.ExpiresAt) || !sameWindow(first.Window, m.Window) {
			return false
		}
	}
	return true
}

// AccessWindowSummary is the aggregate window of a STORED grant (docs/57 sec. 5): the window when every
// membership carries the same one, else nil. varies: the memberships do not all carry the same window,
// counting "no window" as a value (so a windowed + unrestricted mix varies, and nil + !varies is
// genuinely "any time").
func (g *Grant) AccessWindowSummary() (window *AccessWindow, varies bool) {
	if g == nil || len(g.Members) == 0 {
		return nil, false
	}
	first := g.Members[0].Window
	for _, m := range g.Members[1:] {
		if !sameWindow(first, m.Window) {
			return nil, true
		}
	}
	return first, false
}

// OutsideWindow reports whether a STORED grant has an unexpired membership and every unexpired one is
// outside its window at now (docs/57 sec. 5). A current predicate only: it promises nothing about later.
func (g *Grant) OutsideWindow(now time.Time) bool {
	if g == nil {
		return false
	}
	live := false
	for _, m := range g.Members {
		if m.expiredAt(now) {
			continue
		}
		live = true
		if m.Window.OpenAt(now) {
			return false
		}
	}
	return live
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func sameScope(a, b GroupScope) bool {
	if a.All || b.All {
		return a.All == b.All
	}
	x, y := a.GroupIDs(), b.GroupIDs()
	if len(x) != len(y) {
		return false
	}
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// NewMembership builds a membership and pre-expands its role capabilities.
func NewMembership(role Role, scope GroupScope) Membership {
	return Membership{
		Role:  role,
		Scope: scope,
		caps:  newCapabilitySet(rolePresets[role]),
	}
}

// NewCapabilityMembership builds a membership from an EXPLICIT capability set rather than a role
// preset, for principals that carry capabilities directly (an API token, apitoken_auth.go). The
// Role is left empty on purpose: allows() consults m.caps first (it is non-nil here), so the
// empty Role is never read, and there is no preset to expand. The caps are copied so a later
// mutation of the caller's slice cannot widen a live grant.
func NewCapabilityMembership(caps []Capability, scope GroupScope) Membership {
	return Membership{
		Scope: scope,
		caps:  newCapabilitySet(caps),
	}
}

func (m Membership) allows(c Capability) bool {
	if m.caps == nil {
		// Membership built without NewMembership (e.g. a zero value) — expand lazily.
		return Role(m.Role).Has(c)
	}
	_, ok := m.caps[c]
	return ok
}

// Grant is a user's effective authorization within one tenant: the set of memberships
// resolved from the DB. It is the control plane's single authorization choke point, the
// analogue of the agent's signed backstage Grant.
type Grant struct {
	UserID   string
	TenantID string
	Members  []Membership

	// TreeVersion is the tenant's group_tree_version this grant's coverage was computed at (docs/62 R2).
	// A write whose authorization depends on the tree (an assignment edit, a machine move) is made
	// conditional on the tree still being at this version, else 409 "groups changed, retry". Zero for a
	// grant not loaded from a store (an API token, a hand-built grant).
	TreeVersion int64
	// reloadable marks a grant that was loaded from stored memberships (GrantFor / StoredGrantFor), so a
	// hierarchy mutation can re-read the actor's memberships INSIDE its tree-locked transaction (R2). A
	// token or hand-built grant is static: it is tenant-wide, which no tree change can narrow.
	reloadable bool
}

// Reloadable reports whether the grant came from stored memberships (see the field).
func (g *Grant) Reloadable() bool { return g != nil && g.reloadable }

// NewGrant assembles a grant from memberships.
func NewGrant(userID, tenantID string, members ...Membership) *Grant {
	return &Grant{UserID: userID, TenantID: tenantID, Members: members}
}

// Allows reports whether ANY membership grants the capability, ignoring group scope. Use
// this for tenant-wide capabilities that are not tied to a specific machine (ManageUsers,
// ViewAudit, ManageTenant, etc.).
func (g *Grant) Allows(c Capability) bool {
	for _, m := range g.Members {
		if m.allows(c) {
			return true
		}
	}
	return false
}

// AllowsInGroup reports whether the SAME membership both grants the capability and is scoped
// to the given machine group. Cross-membership mixing is deliberately not allowed here: a
// Technician scoped to group A must not borrow a capability from an Auditor membership
// scoped to group B when acting on a group-A machine.
func (g *Grant) AllowsInGroup(c Capability, groupID string) bool {
	for _, m := range g.Members {
		if m.allows(c) && m.Scope.Covers(groupID) {
			return true
		}
	}
	return false
}

// ScopeFor returns the union of group scopes across every membership that grants c, and whether c
// is granted at all. It answers "where may this grant use c", which neither Allows (which discards
// the scope) nor AllowsInGroup (which needs a group to ask about) can express.
//
// It exists for comparing two grants against each other — see canAdministerUser. Authorization
// decisions on a REQUEST should keep using Require/RequireMachine: those ask about the one group
// the request names, which is both cheaper and harder to get wrong.
//
// The union across memberships is the right aggregate here because a grant may legitimately hold c
// from several memberships (Technician over group A, ReadOnly tenant-wide), and its authority is
// then everything they add up to. Note this is NOT the cross-membership mixing AllowsInGroup
// deliberately forbids: the union is taken per capability, so a capability from one membership can
// never borrow the scope of a membership that does not grant it.
func (g *Grant) ScopeFor(c Capability) (GroupScope, bool) {
	if g == nil {
		return GroupScope{}, false
	}
	out := GroupScope{}
	found := false
	for _, m := range g.Members {
		if !m.allows(c) {
			continue
		}
		found = true
		if m.Scope.All {
			return GroupScope{All: true}, true
		}
		if out.assigned == nil {
			out.assigned = capabilitySetGroups{}
			out.covered = capabilitySetGroups{}
		}
		for id := range m.Scope.assigned {
			out.assigned[id] = struct{}{}
		}
		for id := range m.Scope.covered {
			out.covered[id] = struct{}{}
		}
	}
	return out, found
}

// AssignmentScope summarises a user's CURRENT membership scope as a single scope, for the
// "preserve the existing scope when a role change does not restate it" rule (so an update that omits
// the scope cannot silently widen a scoped user to tenant-wide). Semantics:
//   - ANY current membership that is tenant-wide (AllGroups) → the preserved scope is tenant-wide.
//   - otherwise → the union of every current membership's group ids.
//   - no memberships → tenant-wide (there is nothing to narrow; a first role grant defaults open).
//
// The result plugs straight into Groups(ids...) (empty/nil → AllGroups), and GroupIDs() of it is what
// a persister writes. This collapses a multi-membership grant conservatively (widest of what they
// hold), which is the safe direction for "don't accidentally narrow someone on an unrelated edit" —
// while the no-escalation guard still independently bounds what the ACTOR may assign.
func (g *Grant) AssignmentScope() GroupScope {
	if g == nil || len(g.Members) == 0 {
		return AllGroups()
	}
	union := capabilitySetGroups{}
	for _, m := range g.Members {
		if m.Scope.All {
			return AllGroups()
		}
		for id := range m.Scope.assigned {
			union[id] = struct{}{}
		}
	}
	if len(union) == 0 {
		return AllGroups()
	}
	// The preserved scope is the ASSIGNED ids only (docs/62 D3): persisting it must never write an
	// expansion back. covered mirrors assigned here because no tree is consulted.
	return GroupScope{assigned: union, covered: cloneGroupSet(union)}
}

// Includes reports whether s covers everything other covers — a subset test between two scopes.
//
// A tenant-wide scope includes everything. A group-limited scope never includes a tenant-wide one,
// even when it happens to name every group that exists today: "all groups" is a standing claim over
// groups not yet created, so treating it as satisfiable by an enumeration would silently widen the
// moment somebody adds one.
//
// Inheritance (docs/62 D3, R1): other.assigned must be a subset of s.covered. Assigned ids are validated
// to exist when submitted and covered is downward-closed, so this covers their whole subtrees: an actor on
// {P} includes a target on {C}; one on {C} never includes {P} or a sibling {S}. The TARGET side reads its
// ASSIGNED ids, never its covered set: a dangling id expands to nothing, so comparing covered sets would
// let any scoped actor "include" {missing-id}, and a later group created with that id would activate it.
// A dangling assigned id is not in the actor's covered set, so only a tenant-wide actor includes it.
func (s GroupScope) Includes(other GroupScope) bool {
	if s.All {
		return true
	}
	if other.All {
		return false
	}
	for id := range other.assigned {
		if _, ok := s.covered[id]; !ok {
			return false
		}
	}
	return true
}

// Require is the choke point for tenant-wide capabilities. Returns nil only if granted.
func (g *Grant) Require(c Capability) error {
	if g.Allows(c) {
		return nil
	}
	return &DeniedError{Capability: c}
}

// RequireAny is the choke point for a route that serves more than one legitimate principal: it
// returns nil if the grant holds ANY of `cs`, and a DeniedError naming the FIRST one otherwise.
//
// Added for POST /audit/ingest (loop 91), and deliberately narrow. Most routes correspond to one
// action and one capability, and a multi-capability gate is usually a sign the route is doing two
// things. Ingest is the exception because of what it carries: the forwarded batch is ONE hash-linked
// sequence per session, mixing backstage, file-transfer and session-recording events in seq order.
// It cannot be split per event kind — the chain would gap, and a gap is rejected forever — so the
// gate cannot ask "may you do X?" about individual events. It can only ask "are you a principal who
// legitimately runs sessions on this tenant?", which is what the two capabilities below jointly say.
//
// The denial names the first capability rather than the whole set on purpose: a DeniedError is
// rendered to a caller, and listing alternatives tells an unauthorized principal which capability to
// go and acquire.
func (g *Grant) RequireAny(cs ...Capability) error {
	for _, c := range cs {
		if g.Allows(c) {
			return nil
		}
	}
	if len(cs) == 0 {
		return &DeniedError{}
	}
	return &DeniedError{Capability: cs[0]}
}

// RequireMachine is the choke point for machine-scoped actions: the capability must be
// granted by a membership whose scope covers the machine's group. This is the group-scoping
// rule that mirrors "roles resolved server-side, scoped to session groups" in ADR / backstage.
func (g *Grant) RequireMachine(c Capability, machineGroupID string) error {
	if g.AllowsInGroup(c, machineGroupID) {
		return nil
	}
	return &DeniedError{Capability: c, GroupID: machineGroupID}
}

// DeniedError is returned by the Require* checks when authorization fails.
type DeniedError struct {
	Capability Capability
	GroupID    string // set when the denial was group-scoped
}

func (e *DeniedError) Error() string {
	if e.GroupID != "" {
		return fmt.Sprintf("capability %q not granted for machine group %q", e.Capability, e.GroupID)
	}
	return fmt.Sprintf("capability %q not granted", e.Capability)
}

// IsDenied reports whether err is (or wraps) a DeniedError.
func IsDenied(err error) bool {
	var d *DeniedError
	return errors.As(err, &d)
}
