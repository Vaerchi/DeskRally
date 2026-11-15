package controlplane

// Nested machine groups (docs/62): the tree helpers, the errors the hierarchy mutations share, the actor
// and authorizer types those mutations take, and the strictest-merge session policy resolver.
//
// Division of labour (docs/62 §1): the tree's STRUCTURE (no cross-tenant parent, no cycle, depth <= 4, no
// delete of a parent with children) is enforced in the database by migration 0065; the ACCESS decision
// stays in Go (GroupScope.Covers over the coverage GrantFor resolves). The in-memory fakes model the same
// rules with the same helpers so a test written against one cannot prove behaviour the other lacks.

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// maxGroupDepth is the deepest a group may sit: a root is level 1. Mirrors machine_group_check_structure.
const maxGroupDepth = 4

var (
	// ErrMachineGroupHasChildren: delete of a group that still has subgroups (docs/62 D7). Never an
	// auto-move and never a silent re-root.
	ErrMachineGroupHasChildren = errors.New("machine group still has subgroups")
	// ErrMachineGroupCycle: a move would make a group its own ancestor (pg: SQLSTATE GT001).
	ErrMachineGroupCycle = errors.New("this move would create a cycle")
	// ErrMachineGroupTooDeep: the result would nest deeper than maxGroupDepth (pg: SQLSTATE GT002).
	ErrMachineGroupTooDeep = errors.New("subgroups nest at most 4 levels")
	// ErrMachineGroupParentInvalid: the named parent does not exist in the tenant. A parent belonging to
	// another tenant is indistinguishable from a missing one (RLS hides it; the composite FK refuses it).
	ErrMachineGroupParentInvalid = errors.New("parent group not found in this tenant")
	// ErrGroupTreeChanged: the group tree changed after the caller's grant was read, so a tree-dependent
	// write is refused rather than applied on stale authorization (docs/62 R2). 409 "groups changed, retry".
	ErrGroupTreeChanged = errors.New("groups changed, retry")
)

// GroupTree is an immutable snapshot of one tenant's group structure: group id -> parent id, "" for a root.
// A group absent from the map does not exist.
type GroupTree map[string]string

// subtreeOf returns the roots that exist in parentOf plus every descendant of them. A root that is not a
// key of parentOf (dangling, deleted, another tenant's) contributes nothing, not even itself. The result is
// a freshly allocated set. It is the one shared helper the fake and the unit tests use; the pg path computes
// the same thing in cp_group_subtree.
func subtreeOf(parentOf map[string]string, roots []string) map[string]struct{} {
	out := make(map[string]struct{}, len(roots))
	if len(roots) == 0 || len(parentOf) == 0 {
		return out
	}
	children := make(map[string][]string, len(parentOf))
	for id, p := range parentOf {
		if p != "" {
			children[p] = append(children[p], id)
		}
	}
	queue := make([]string, 0, len(roots))
	for _, r := range roots {
		if _, ok := parentOf[r]; !ok {
			continue
		}
		if _, dup := out[r]; dup {
			continue
		}
		out[r] = struct{}{}
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if _, seen := out[c]; seen {
				continue
			}
			out[c] = struct{}{}
			queue = append(queue, c)
		}
	}
	return out
}

// ancestorsOf returns id and its ancestors, nearest first (id, parent, ..., root); nil when id is not in
// the tree. A malformed (cyclic) map terminates rather than looping.
func ancestorsOf(parentOf map[string]string, id string) []string {
	if _, ok := parentOf[id]; !ok {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for cur := id; cur != ""; cur = parentOf[cur] {
		if _, dup := seen[cur]; dup {
			break
		}
		if _, ok := parentOf[cur]; !ok {
			break
		}
		seen[cur] = struct{}{}
		out = append(out, cur)
	}
	return out
}

// treeLevel is the group's level (a root is 1); 0 for a group not in the tree.
func treeLevel(parentOf map[string]string, id string) int { return len(ancestorsOf(parentOf, id)) }

// treeHeight is the height of the subtree rooted at id counting id itself (a leaf is 1); 0 if absent.
func treeHeight(parentOf map[string]string, id string) int {
	if _, ok := parentOf[id]; !ok {
		return 0
	}
	children := make(map[string][]string, len(parentOf))
	for c, p := range parentOf {
		if p != "" {
			children[p] = append(children[p], c)
		}
	}
	var walk func(cur string, depth int, seen map[string]struct{}) int
	walk = func(cur string, depth int, seen map[string]struct{}) int {
		if _, dup := seen[cur]; dup {
			return depth - 1
		}
		seen[cur] = struct{}{}
		best := depth
		for _, c := range children[cur] {
			if h := walk(c, depth+1, seen); h > best {
				best = h
			}
		}
		return best
	}
	return walk(id, 1, map[string]struct{}{})
}

// checkReparent applies the structural rules the database trigger enforces, to an in-memory tree: the new
// parent must exist, must not be inside the moved subtree (cycle), and the moved subtree must still fit
// within maxGroupDepth. newParent "" makes the group a root. The pg store does NOT call this: it lets the
// trigger decide, so the trigger is what the pg tests exercise.
func checkReparent(parentOf map[string]string, id, newParent string) error {
	if newParent == "" {
		return nil
	}
	if _, ok := parentOf[newParent]; !ok {
		return ErrMachineGroupParentInvalid
	}
	for _, a := range ancestorsOf(parentOf, newParent) {
		if a == id {
			return ErrMachineGroupCycle
		}
	}
	if treeLevel(parentOf, newParent)+treeHeight(parentOf, id) > maxGroupDepth {
		return ErrMachineGroupTooDeep
	}
	return nil
}

// groupPathLabel is the "A > B > C" label of a group for messages and audit; falls back to the id.
func groupPathLabel(names map[string]string, parentOf map[string]string, id string) string {
	chain := ancestorsOf(parentOf, id)
	if len(chain) == 0 {
		return id
	}
	parts := make([]string, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		n := names[chain[i]]
		if n == "" {
			n = chain[i]
		}
		parts = append(parts, n)
	}
	return strings.Join(parts, " > ")
}

// GroupActor identifies who is mutating the hierarchy, so the store can re-read their memberships INSIDE
// its tree-locked transaction (docs/62 R2). Grant is the request-time grant: it is used as-is when it is
// not reloadable (an API token, a hand-built grant — tenant-wide or static) and as the fallback otherwise.
type GroupActor struct {
	UserID string
	Grant  *Grant
}

// GroupAuthorizer is called by a hierarchy mutation INSIDE the store's tree-locked transaction, after the
// tenant tree lock is held and the actor's memberships were reloaded against the CURRENT tree, and before
// anything is written. tree is the structure BEFORE the mutation. A non-nil error aborts the mutation and
// is returned to the caller unchanged (a *DeniedError becomes a 403).
type GroupAuthorizer func(grant *Grant, tree GroupTree) error

// groupTreeSource is what the in-memory user, machine and session stores need from the in-memory group
// store: a snapshot (taken, and the group lock RELEASED, before the caller takes its own lock — lock order
// is group store before every other store) and a callback form that holds the group lock across fn (used
// by tree-conditional writes; fn may then take the caller's own lock, never the reverse).
type groupTreeSource interface {
	snapshotTree(tenantID string) (GroupTree, int64)
	withTree(tenantID string, fn func(tree GroupTree, version int64) error) error
}

// LinkGroupStores connects the in-memory group store to the in-memory user store (and optionally the
// machine store) so grants expand through the tree, hierarchy mutations reload the actor's memberships, and
// tree-conditional writes know the version — the fake's twin of the database doing it all. Unlinked stores
// behave as before (no inheritance), which is what the many pre-docs/62 tests rely on.
func LinkGroupStores(groups *InMemoryMachineGroupStore, users *InMemoryUserStore, machines *InMemoryMachineStore) {
	if users != nil {
		users.setTreeSource(groups)
	}
	if machines != nil {
		machines.setTreeSource(groups)
	}
	if groups != nil && users != nil {
		groups.setGrantSource(users)
	}
}

// ---------------------------------------------------------------------------------------------------
// Authorization of hierarchy mutations (docs/62 D5 + R3). Every rule is a pure function of a grant and
// the tree so the handler, the stores' in-transaction callback and the tests share one definition.
// ---------------------------------------------------------------------------------------------------

// manageGroupsEverywhere reports whether the grant holds CapManageGroups tenant-wide (All scope).
func manageGroupsEverywhere(g *Grant) bool {
	scope, ok := g.ScopeFor(CapManageGroups)
	return ok && scope.All
}

// authorizeGroupCreate: a ROOT group needs a tenant-wide manage_groups; a group under P needs manage_groups
// whose scope covers P.
func authorizeGroupCreate(g *Grant, parentID string) error {
	if g == nil {
		return &DeniedError{Capability: CapManageGroups}
	}
	if parentID == "" {
		if manageGroupsEverywhere(g) {
			return nil
		}
		return &DeniedError{Capability: CapManageGroups}
	}
	return g.RequireMachine(CapManageGroups, parentID)
}

// authorizeGroupReparent: the actor must manage the moved group, its OLD parent (if any) and the NEW parent;
// making a group a root needs a tenant-wide grant.
func authorizeGroupReparent(g *Grant, tree GroupTree, id, newParent string) error {
	if g == nil {
		return &DeniedError{Capability: CapManageGroups}
	}
	if err := g.RequireMachine(CapManageGroups, id); err != nil {
		return err
	}
	if old := tree[id]; old != "" {
		if err := g.RequireMachine(CapManageGroups, old); err != nil {
			return err
		}
	}
	if newParent == "" {
		if !manageGroupsEverywhere(g) {
			return &DeniedError{Capability: CapManageGroups}
		}
		return nil
	}
	return g.RequireMachine(CapManageGroups, newParent)
}

// authorizeGroupManage: rename, delete and policy edits need manage_groups covering that group.
func authorizeGroupManage(g *Grant, id string) error {
	if g == nil {
		return &DeniedError{Capability: CapManageGroups}
	}
	return g.RequireMachine(CapManageGroups, id)
}

// expectTreeVersion is the tree version a tree-dependent write must still find (docs/62 R2): the one the
// request grant was read at, when that grant came from stored memberships. A static grant (an API token, a
// hand-built grant) has no version to hold the write to, so nil.
func expectTreeVersion(g *Grant) *int64 {
	if !g.Reloadable() {
		return nil
	}
	v := g.TreeVersion
	return &v
}

// mapGroupStructureErr translates a pg structure-trigger / FK failure to the shared errors; nil = not one.
func mapGroupStructureErr(err error) error {
	switch pgErrCode(err) {
	case "GT001":
		return ErrMachineGroupCycle
	case "GT002":
		return ErrMachineGroupTooDeep
	case "GT003":
		return ErrMachineGroupParentInvalid
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------
// Effective session policy (docs/62 D4 + R4 + R7).
// ---------------------------------------------------------------------------------------------------

// GroupSeatCap is one ancestor-or-self's seat cap. It counts the admitted sessions of the group's WHOLE
// subtree (R7).
type GroupSeatCap struct {
	GroupID string `json:"group_id"`
	Cap     int    `json:"cap"`
}

// EffectiveGroupPolicy is the strictest merge of a group's policy with its ancestors' (a child may tighten
// and never loosen). The embedded GroupSessionPolicy carries the merged values; MaxConcurrentSessions is the
// displayed effective cap (the minimum POSITIVE value, 0 = unlimited) while enforcement uses SeatCaps.
type EffectiveGroupPolicy struct {
	GroupSessionPolicy
	// Conflict is non-empty when the merge is unsatisfiable (require_recording AND prohibit_recording).
	// Admission and grant minting DENY with this reason; policy edits and reparents that would create one
	// are refused where detectable (R4).
	Conflict string `json:"conflict,omitempty"`
	// SeatCaps lists every ancestor-or-self that has a positive cap, nearest first.
	SeatCaps []GroupSeatCap `json:"seat_caps,omitempty"`
}

const policyConflictMsg = "the group hierarchy requires session recording at one level and prohibits it at another; " +
	"an administrator must resolve the conflicting group policies"

// mergeGroupPolicies merges a chain of policies, chain[0] being the group itself and the rest its ancestors
// nearest first. Rules (D4 + R4):
//
//   - enforce_view_only, prohibit_recording, require_recording: OR.
//   - max_session_duration_seconds, max_idle_seconds: the minimum non-zero value.
//   - allow_backstage_under_view_only (an opt-OUT of a restriction): when view-only is enforced it is true
//     only if EVERY level that enforces view-only allows it; levels that do not enforce view-only carry a
//     dormant value that never becomes a restriction. When nothing enforces view-only the value is the
//     group's own (dormant) one, so a flat tree reads back exactly what was stored.
//   - seat cap: SeatCaps holds every positive cap; MaxConcurrentSessions is the minimum positive.
func mergeGroupPolicies(groupID string, chain []GroupSessionPolicy, chainIDs []string) EffectiveGroupPolicy {
	out := EffectiveGroupPolicy{GroupSessionPolicy: GroupSessionPolicy{GroupID: groupID}}
	if len(chain) == 0 {
		return out
	}
	allowAll := true
	for i, p := range chain {
		if p.EnforceViewOnly {
			out.EnforceViewOnly = true
			if !p.AllowBackstageUnderViewOnly {
				allowAll = false
			}
		}
		out.ProhibitRecording = out.ProhibitRecording || p.ProhibitRecording
		out.RequireRecording = out.RequireRecording || p.RequireRecording
		out.MaxSessionDurationSeconds = minPositive(out.MaxSessionDurationSeconds, p.MaxSessionDurationSeconds)
		out.MaxIdleSeconds = minPositive(out.MaxIdleSeconds, p.MaxIdleSeconds)
		if p.MaxConcurrentSessions > 0 {
			out.MaxConcurrentSessions = minPositive(out.MaxConcurrentSessions, p.MaxConcurrentSessions)
			id := ""
			if i < len(chainIDs) {
				id = chainIDs[i]
			}
			out.SeatCaps = append(out.SeatCaps, GroupSeatCap{GroupID: id, Cap: p.MaxConcurrentSessions})
		}
	}
	if out.EnforceViewOnly {
		out.AllowBackstageUnderViewOnly = allowAll
	} else {
		out.AllowBackstageUnderViewOnly = chain[0].AllowBackstageUnderViewOnly
	}
	if out.ProhibitRecording && out.RequireRecording {
		out.Conflict = policyConflictMsg
	}
	return out
}

// minPositive: the smaller of two limits where 0 means "no limit".
func minPositive(a, b int) int {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case b < a:
		return b
	}
	return a
}

// EffectivePolicy resolves the strictest-merge policy for a group, replacing the exact-group read at every
// session-policy call site (docs/62 D4). With no group store wired it degrades to the group's own row.
func (s *Server) EffectivePolicy(ctx context.Context, tenantID, groupID string) (EffectiveGroupPolicy, error) {
	own, err := s.GroupSessionPolicies.Get(ctx, tenantID, groupID)
	if err != nil {
		return EffectiveGroupPolicy{}, err
	}
	chain := []GroupSessionPolicy{own}
	ids := []string{groupID}
	if s.MachineGroups != nil {
		tree, _, terr := s.MachineGroups.GroupTree(ctx, tenantID)
		if terr != nil {
			return EffectiveGroupPolicy{}, terr
		}
		for _, anc := range ancestorsOf(tree, groupID) {
			if anc == groupID {
				continue
			}
			p, perr := s.GroupSessionPolicies.Get(ctx, tenantID, anc)
			if perr != nil {
				return EffectiveGroupPolicy{}, perr
			}
			chain = append(chain, p)
			ids = append(ids, anc)
		}
	}
	return mergeGroupPolicies(groupID, chain, ids), nil
}

// wouldConflict reports the ids of groups whose effective policy would be unsatisfiable if the tree were
// `tree` and the stored policies were `policies` (group id -> policy). Used to refuse a policy edit or a
// reparent that would create a conflict for the group or any descendant (R4); the runtime denial remains
// the fail-closed backstop for anything this cannot see.
func wouldConflict(tree GroupTree, policies map[string]GroupSessionPolicy, among []string) []string {
	var bad []string
	for _, id := range among {
		var chain []GroupSessionPolicy
		var ids []string
		for _, a := range ancestorsOf(tree, id) {
			chain = append(chain, policies[a])
			ids = append(ids, a)
		}
		if len(chain) == 0 {
			continue
		}
		if mergeGroupPolicies(id, chain, ids).Conflict != "" {
			bad = append(bad, id)
		}
	}
	sort.Strings(bad)
	return bad
}
