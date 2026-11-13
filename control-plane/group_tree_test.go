package controlplane

// Pure (no database, no HTTP) proofs for nested machine groups (docs/62): the tree helpers, the
// assigned/covered split of GroupScope with its asymmetric P / C / S cases, the strictest-merge session
// policy, and the fake's per-ancestor seat counting. The store- and handler-level proofs that run the same
// scenarios against the in-memory and Postgres stores are in group_tree_store_test.go.
//
// FIXTURE SHAPE. Every scope case uses a deliberately ASYMMETRIC tree so a test that swapped two arguments
// (assigned vs covered, actor vs target, parent vs child) could not pass by accident:
//
//	R ── P ── C ── G        (R root; P parent; C child of P; G grandchild)
//	  └─ S                  (S: a sibling of P, under R)
//	X                       (an unrelated root)
//
// Scopes under test: {P}, {C}, {S}, {R}, {dangling}, tenant-wide.

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
)

func asymTree() GroupTree {
	return GroupTree{"R": "", "P": "R", "C": "P", "G": "C", "S": "R", "X": ""}
}

func setKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSubtreeOfAndAncestors(t *testing.T) {
	tree := asymTree()
	for _, tc := range []struct {
		name  string
		roots []string
		want  []string
	}{
		{"P covers itself, C and G", []string{"P"}, []string{"C", "G", "P"}},
		{"C covers itself and G but never P", []string{"C"}, []string{"C", "G"}},
		{"S is a leaf and covers neither P nor C", []string{"S"}, []string{"S"}},
		{"a dangling root contributes nothing, not even itself", []string{"nope"}, []string{}},
		{"dangling beside a real root keeps only the real one", []string{"nope", "S"}, []string{"S"}},
		{"R covers everything under it but not X", []string{"R"}, []string{"C", "G", "P", "R", "S"}},
		{"no roots", nil, []string{}},
	} {
		got := setKeys(subtreeOf(tree, tc.roots))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: subtreeOf(%v) = %v, want %v", tc.name, tc.roots, got, tc.want)
		}
	}
	// A fresh map each call: mutating one result must not leak into the next.
	a := subtreeOf(tree, []string{"S"})
	a["intruder"] = struct{}{}
	if _, leaked := subtreeOf(tree, []string{"S"})["intruder"]; leaked {
		t.Fatal("subtreeOf shares state between calls")
	}

	if got := ancestorsOf(tree, "G"); !reflect.DeepEqual(got, []string{"G", "C", "P", "R"}) {
		t.Errorf("ancestorsOf(G) = %v, want [G C P R] (nearest first)", got)
	}
	if got := ancestorsOf(tree, "nope"); got != nil {
		t.Errorf("ancestorsOf(dangling) = %v, want nil", got)
	}
	if treeLevel(tree, "G") != 4 || treeLevel(tree, "R") != 1 || treeLevel(tree, "nope") != 0 {
		t.Errorf("levels G=%d R=%d nope=%d, want 4 1 0", treeLevel(tree, "G"), treeLevel(tree, "R"), treeLevel(tree, "nope"))
	}
	if treeHeight(tree, "R") != 4 || treeHeight(tree, "P") != 3 || treeHeight(tree, "S") != 1 || treeHeight(tree, "nope") != 0 {
		t.Errorf("heights R=%d P=%d S=%d, want 4 3 1", treeHeight(tree, "R"), treeHeight(tree, "P"), treeHeight(tree, "S"))
	}
	// A malformed cyclic map must terminate (the database forbids it; the helper must not hang if it
	// ever saw one).
	cyc := GroupTree{"A": "B", "B": "A"}
	if got := ancestorsOf(cyc, "A"); len(got) != 2 {
		t.Errorf("ancestorsOf on a cycle = %v, want it to stop after 2", got)
	}
	_ = subtreeOf(cyc, []string{"A"})
	_ = treeHeight(cyc, "A")
}

func TestCheckReparentRules(t *testing.T) {
	tree := asymTree()
	if err := checkReparent(tree, "S", "P"); err != nil {
		t.Errorf("S under P (level 3) should be allowed, got %v", err)
	}
	if err := checkReparent(tree, "P", ""); err != nil {
		t.Errorf("P to root should be allowed, got %v", err)
	}
	if err := checkReparent(tree, "P", "G"); !errors.Is(err, ErrMachineGroupCycle) {
		t.Errorf("P under its own grandchild = %v, want a cycle", err)
	}
	if err := checkReparent(tree, "P", "P"); !errors.Is(err, ErrMachineGroupCycle) {
		t.Errorf("P under itself = %v, want a cycle", err)
	}
	if err := checkReparent(tree, "S", "nope"); !errors.Is(err, ErrMachineGroupParentInvalid) {
		t.Errorf("S under a missing parent = %v, want ErrMachineGroupParentInvalid", err)
	}
	// Depth: X (a root with no children) under G (level 4) would be level 5.
	if err := checkReparent(tree, "X", "G"); !errors.Is(err, ErrMachineGroupTooDeep) {
		t.Errorf("X under G (level 4) = %v, want too deep", err)
	}
	// A TALL SUBTREE brought under a deep parent: P has height 3 (P, C, G); under S (level 2) it would
	// reach level 2+3 = 5. Its own level is irrelevant; the subtree's height is the point.
	if err := checkReparent(tree, "P", "S"); !errors.Is(err, ErrMachineGroupTooDeep) {
		t.Errorf("tall subtree P under S = %v, want too deep", err)
	}
	// ...while the same subtree under a root-level parent still fits (1+3 = 4).
	if err := checkReparent(tree, "P", "X"); err != nil {
		t.Errorf("P under X (level 1+3=4) should fit, got %v", err)
	}
}

// --- GroupScope: assigned vs covered ----------------------------------------------------------

func scopeOver(tree GroupTree, ids ...string) GroupScope {
	return expandedScope(Groups(ids...), tree)
}

func TestGroupScopeCoversAsymmetric(t *testing.T) {
	tree := asymTree()
	for _, tc := range []struct {
		name   string
		scope  GroupScope
		covers map[string]bool
	}{
		{"{P} covers P, C, G; not S, R, X", scopeOver(tree, "P"),
			map[string]bool{"P": true, "C": true, "G": true, "S": false, "R": false, "X": false}},
		{"{C} covers C, G; NOT its parent P, nor the sibling S", scopeOver(tree, "C"),
			map[string]bool{"C": true, "G": true, "P": false, "S": false, "R": false}},
		{"{S} covers only S: neither P nor C", scopeOver(tree, "S"),
			map[string]bool{"S": true, "P": false, "C": false, "G": false}},
		{"a dangling id covers nothing, not even itself", scopeOver(tree, "ghost"),
			map[string]bool{"ghost": false, "P": false, "C": false, "S": false, "X": false}},
		{"tenant-wide covers everything, including groups not yet created", AllGroups(),
			map[string]bool{"P": true, "C": true, "S": true, "X": true, "brand-new": true}},
	} {
		for g, want := range tc.covers {
			if got := tc.scope.Covers(g); got != want {
				t.Errorf("%s: Covers(%s) = %v, want %v", tc.name, g, got, want)
			}
		}
	}
}

func TestIncludesIsAssignedSubsetOfCovered(t *testing.T) {
	tree := asymTree()
	P, C, S := scopeOver(tree, "P"), scopeOver(tree, "C"), scopeOver(tree, "S")
	ghost := scopeOver(tree, "ghost")
	all := AllGroups()
	for _, tc := range []struct {
		name          string
		actor, target GroupScope
		want          bool
	}{
		{"actor {P} includes target {C} (a child of its scope)", P, Groups("C"), true},
		{"actor {P} includes target {G} (a grandchild)", P, Groups("G"), true},
		{"actor {P} includes target {P}", P, Groups("P"), true},
		{"actor {C} does NOT include target {P} (its parent)", C, Groups("P"), false},
		{"actor {C} does NOT include target {S} (a sibling of the parent)", C, Groups("S"), false},
		{"actor {P} does NOT include target {S}", P, Groups("S"), false},
		{"actor {S} includes neither {P} nor {C}", S, Groups("P", "C"), false},
		{"actor {P} includes {C, G} together", P, Groups("C", "G"), true},
		{"actor {P} does not include {C, S} (one stray id sinks it)", P, Groups("C", "S"), false},
		{"a group-limited actor never includes a tenant-wide target", P, AllGroups(), false},
		{"a tenant-wide actor includes everything", all, Groups("P"), true},
		{"a tenant-wide actor includes a tenant-wide target", all, AllGroups(), true},
		// R1: a dangling id expands to nothing, so comparing COVERED sets would let any scoped actor
		// include {missing}. The target side reads ASSIGNED ids, so only a tenant-wide actor does.
		{"actor {P} does NOT include a target whose only id dangles", P, Groups("ghost"), false},
		{"actor {C} does NOT include a dangling target", C, Groups("ghost"), false},
		{"a tenant-wide actor DOES include a dangling target", all, Groups("ghost"), true},
		{"an actor whose own roots all dangle includes nothing real", ghost, Groups("C"), false},
		// The same hazard with the target EXPANDED the way a StoredGrantFor target is: its covered set
		// is EMPTY, so comparing covered sets would be vacuously true. Only the assigned ids tell.
		{"actor {P} does NOT include an EXPANDED dangling target", P, ghost, false},
		{"actor {C} does NOT include an EXPANDED dangling target", C, ghost, false},
		{"a tenant-wide actor includes an EXPANDED dangling target", all, ghost, true},
	} {
		if got := tc.actor.Includes(tc.target); got != tc.want {
			t.Errorf("%s: Includes = %v, want %v", tc.name, got, tc.want)
		}
	}
	// The TARGET side must be read through its ASSIGNED ids: a target scope that has been expanded (as a
	// StoredGrantFor target is) still includes-or-not by what was assigned, never by what it covers.
	// {C} expanded covers {C, G}; an actor {G} must not include it just because G is in its covered set.
	if scopeOver(tree, "G").Includes(scopeOver(tree, "C")) {
		t.Error("actor {G} includes expanded target {C}: the target's covered set leaked into the comparison")
	}
	if !scopeOver(tree, "P").Includes(scopeOver(tree, "C")) {
		t.Error("actor {P} must include expanded target {C}")
	}
}

func TestAllIsNeverDerivedFromAnEmptyCoveredSet(t *testing.T) {
	tree := asymTree()
	ghost := scopeOver(tree, "ghost")
	if ghost.All {
		t.Fatal("a scope whose roots all dangle became tenant-wide")
	}
	if len(ghost.CoveredIDs()) != 0 {
		t.Fatalf("dangling scope covers %v, want nothing", ghost.CoveredIDs())
	}
	if ids := ghost.GroupIDs(); len(ids) != 1 || ids[0] != "ghost" {
		t.Fatalf("the stored (assigned) ids were rewritten: %v, want [ghost]", ids)
	}
	// Through a grant: ScopeFor and AssignmentScope must not collapse it either.
	g := NewGrant("u", "t", NewMembership(RoleTechnician, ghost))
	sc, ok := g.ScopeFor(CapViewMachines)
	if !ok || sc.All || sc.Covers("anything") {
		t.Fatalf("ScopeFor(dangling) = %+v ok=%v, want group-limited covering nothing", sc, ok)
	}
	if as := g.AssignmentScope(); as.All || len(as.GroupIDs()) != 1 {
		t.Fatalf("AssignmentScope collapsed a dangling scope: %+v", as)
	}
	if g.AllowsInGroup(CapViewMachines, "ghost") {
		t.Fatal("a dangling scope allowed an action in its own (deleted) group")
	}
	// withCovered on an All scope is a no-op and never narrows it.
	if !AllGroups().withCovered(map[string]struct{}{}).All {
		t.Fatal("withCovered narrowed a tenant-wide scope")
	}
}

func TestAssignedIsNeverRewrittenByInheritance(t *testing.T) {
	tree := asymTree()
	base := Groups("P")
	exp := expandedScope(base, tree)
	if ids := exp.GroupIDs(); !reflect.DeepEqual(ids, []string{"P"}) {
		t.Fatalf("expanded scope's assigned ids = %v, want [P]", ids)
	}
	if ids := exp.CoveredIDs(); !reflect.DeepEqual(ids, []string{"C", "G", "P"}) {
		t.Fatalf("expanded scope covers %v, want [C G P]", ids)
	}
	// The AssignmentScope of a grant holding the EXPANDED scope persists assigned ids only.
	g := NewGrant("u", "t", NewMembership(RoleAdmin, exp))
	if ids := g.AssignmentScope().GroupIDs(); !reflect.DeepEqual(ids, []string{"P"}) {
		t.Fatalf("AssignmentScope persisted %v, want [P] (the expansion must never be written back)", ids)
	}
	// sameScope compares assigned: {P} expanded equals {P} plain, and differs from {P, C} even though
	// both cover the same machines.
	if !sameScope(exp, Groups("P")) {
		t.Error("sameScope: expanded {P} != plain {P}")
	}
	if sameScope(exp, Groups("P", "C")) {
		t.Error("sameScope compared covered sets: {P} == {P, C}")
	}
	// A reparent (a new tree) re-resolves coverage without touching the assigned set.
	moved := GroupTree{"R": "", "P": "R", "C": "S", "G": "C", "S": "R", "X": ""} // C moved under S
	exp2 := expandedScope(base, moved)
	if exp2.Covers("C") || !reflect.DeepEqual(exp2.GroupIDs(), []string{"P"}) {
		t.Errorf("after C moved out, {P} covers C=%v assigned=%v", exp2.Covers("C"), exp2.GroupIDs())
	}
}

func TestExpandedScopeAllocatesFreshMaps(t *testing.T) {
	tree := asymTree()
	base := Groups("P")
	a := expandedScope(base, tree)
	b := expandedScope(base, tree)
	a.covered["intruder"] = struct{}{}
	a.assigned["intruder"] = struct{}{}
	if b.Covers("intruder") || len(b.GroupIDs()) != 1 {
		t.Fatal("two expansions share a map")
	}
	if base.Covers("intruder") || len(base.GroupIDs()) != 1 {
		t.Fatal("expansion shares a map with the persisted assignment")
	}
}

func TestCanAdministerUserWithInheritedScopes(t *testing.T) {
	tree := asymTree()
	mk := func(ids ...string) *Grant {
		return NewGrant("u", "t", NewMembership(RoleAdmin, scopeOver(tree, ids...)))
	}
	if err := canAdministerUser(mk("P"), mk("C")); err != nil {
		t.Errorf("actor {P} administering target {C}: %v", err)
	}
	if err := canAdministerUser(mk("C"), mk("P")); err == nil {
		t.Error("actor {C} administering target {P} must be an escalation")
	}
	if err := canAdministerUser(mk("C"), mk("S")); err == nil {
		t.Error("actor {C} administering target {S} must be an escalation")
	}
	if err := canAdministerUser(mk("P"), mk("ghost")); err == nil {
		t.Error("a scoped actor administering a dangling-scope target must be an escalation (R1c)")
	}
	tenantWide := NewGrant("u", "t", NewMembership(RoleAdmin, AllGroups()))
	if err := canAdministerUser(tenantWide, mk("ghost")); err != nil {
		t.Errorf("a tenant-wide actor must be able to administer a dangling-scope target: %v", err)
	}
	// A NEWLY ASSIGNED scope is a plain Groups(): assigned {C} against actor {P}'s covered set.
	newGrant := NewGrant("x", "t", NewMembership(RoleAdmin, Groups("C")))
	if err := canAdministerUser(mk("P"), newGrant); err != nil {
		t.Errorf("actor {P} assigning {C}: %v", err)
	}
	newGrant = NewGrant("x", "t", NewMembership(RoleAdmin, Groups("P")))
	if err := canAdministerUser(mk("C"), newGrant); err == nil {
		t.Error("actor {C} assigning {P} must be an escalation")
	}
}

// --- D5 / R3 pure authorization rules ----------------------------------------------------------

func TestGroupAuthorizationRules(t *testing.T) {
	tree := asymTree()
	mk := func(scope GroupScope) *Grant {
		return NewGrant("u", "t", NewMembership(RoleAdmin, scope))
	}
	wide := mk(AllGroups())
	onP := mk(scopeOver(tree, "P"))
	onC := mk(scopeOver(tree, "C"))

	// create: a ROOT needs a tenant-wide manage_groups; under P needs coverage of P.
	if authorizeGroupCreate(wide, "") != nil || authorizeGroupCreate(onP, "") == nil {
		t.Error("creating a root group must need a tenant-wide grant")
	}
	if authorizeGroupCreate(onP, "P") != nil || authorizeGroupCreate(onP, "C") != nil {
		t.Error("{P} must be able to create under P and under its child C")
	}
	if authorizeGroupCreate(onC, "P") == nil || authorizeGroupCreate(onP, "S") == nil {
		t.Error("{C} creating under its parent P, or {P} under a sibling S, must be denied")
	}
	// reparent: must cover the group, its old parent AND the new parent.
	if err := authorizeGroupReparent(onP, tree, "G", "P"); err != nil { // G: C -> P, all inside {P}
		t.Errorf("{P} moving G from C to P: %v", err)
	}
	if err := authorizeGroupReparent(onC, tree, "G", "C"); err != nil { // no-op parent but covered
		t.Errorf("{C} moving G under C: %v", err)
	}
	if authorizeGroupReparent(onC, tree, "C", "") == nil {
		t.Error("{C} making C a root must need a tenant-wide grant")
	}
	if authorizeGroupReparent(onC, tree, "C", "S") == nil {
		t.Error("{C} moving C under S (not covered) must be denied")
	}
	// old parent not covered: {C} moving C (old parent P is NOT in {C}'s coverage) is denied even to a
	// covered destination.
	if authorizeGroupReparent(onC, tree, "C", "G") == nil {
		t.Error("{C} reparenting C must need its OLD parent P covered")
	}
	if authorizeGroupReparent(onP, tree, "S", "C") == nil {
		t.Error("{P} moving S (outside its scope) must be denied")
	}
	if authorizeGroupReparent(wide, tree, "C", "") != nil {
		t.Error("a tenant-wide manager must be able to make C a root")
	}
	// manage: rename / delete / policy need coverage of THAT group.
	if authorizeGroupManage(onP, "C") != nil || authorizeGroupManage(onC, "P") == nil || authorizeGroupManage(onP, "S") == nil {
		t.Error("manage must follow coverage: {P} manages C; {C} does not manage P; {P} does not manage S")
	}
	// A grant that holds the capability only through ANOTHER membership must not borrow its scope.
	mixed := NewGrant("u", "t",
		NewMembership(RoleTechnician, AllGroups()),     // no manage_groups
		NewMembership(RoleAdmin, scopeOver(tree, "C"))) // manage_groups over {C} only
	if authorizeGroupCreate(mixed, "") == nil {
		t.Error("a tenant-wide technician membership lent its scope to a scoped admin's capability")
	}
	if authorizeGroupManage(nilGrant(), "C") == nil || authorizeGroupCreate(nilGrant(), "P") == nil {
		t.Error("a nil grant must deny")
	}
}

func nilGrant() *Grant { return nil }

// --- strictest-merge session policy ------------------------------------------------------------

func TestMergeGroupPolicies(t *testing.T) {
	merge := func(chain ...GroupSessionPolicy) EffectiveGroupPolicy {
		ids := make([]string, len(chain))
		for i := range chain {
			ids[i] = string(rune('A' + i))
		}
		return mergeGroupPolicies("A", chain, ids)
	}
	// parent require_recording + child none => required.
	if e := merge(GroupSessionPolicy{}, GroupSessionPolicy{RequireRecording: true}); !e.RequireRecording {
		t.Error("a child under a require_recording parent must inherit it")
	}
	// the child cannot clear the parent's view-only.
	if e := merge(GroupSessionPolicy{EnforceViewOnly: false}, GroupSessionPolicy{EnforceViewOnly: true}); !e.EnforceViewOnly {
		t.Error("a child cleared its parent's view-only mandate")
	}
	// a child can tighten (view-only child, loose parent).
	if e := merge(GroupSessionPolicy{EnforceViewOnly: true}, GroupSessionPolicy{}); !e.EnforceViewOnly {
		t.Error("a child could not tighten")
	}
	// durations: the minimum non-zero; zero = unlimited never wins.
	e := merge(GroupSessionPolicy{MaxSessionDurationSeconds: 7200, MaxIdleSeconds: 0},
		GroupSessionPolicy{MaxSessionDurationSeconds: 3600, MaxIdleSeconds: 300})
	if e.MaxSessionDurationSeconds != 3600 || e.MaxIdleSeconds != 300 {
		t.Errorf("durations = %d / %d, want min non-zero 3600 / 300", e.MaxSessionDurationSeconds, e.MaxIdleSeconds)
	}
	if e := merge(GroupSessionPolicy{}, GroupSessionPolicy{MaxSessionDurationSeconds: 60}); e.MaxSessionDurationSeconds != 60 {
		t.Error("a zero (unlimited) child must not beat a parent's limit")
	}
	// backstage opt-out (AND over view-only levels): a child that opts out cannot widen a parent that
	// enforces view-only WITHOUT the opt-out.
	e = merge(GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: true},
		GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: false})
	if !e.EnforceViewOnly || e.AllowBackstageUnderViewOnly {
		t.Errorf("child widened its parent's backstage restriction: %+v", e.GroupSessionPolicy)
	}
	// ...and when EVERY enforcing level allows it, it is allowed.
	e = merge(GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: true},
		GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: true})
	if !e.AllowBackstageUnderViewOnly {
		t.Error("every enforcing level allows backstage, yet the merge denied it")
	}
	// R4: a DORMANT opt-out=false on a level that does not enforce view-only never becomes a restriction.
	e = merge(GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: true},
		GroupSessionPolicy{EnforceViewOnly: false, AllowBackstageUnderViewOnly: false, MaxIdleSeconds: 60})
	if !e.AllowBackstageUnderViewOnly {
		t.Error("a dormant allow_backstage=false on a non-view-only ancestor became a restriction")
	}
	// A flat tree reads back exactly the stored value, including a dormant opt-out.
	if e := merge(GroupSessionPolicy{AllowBackstageUnderViewOnly: true}); !e.AllowBackstageUnderViewOnly {
		t.Error("a lone group's dormant opt-out must read back unchanged")
	}
	// R4 conflict: require at one level, prohibit at another.
	e = merge(GroupSessionPolicy{ProhibitRecording: true}, GroupSessionPolicy{RequireRecording: true})
	if e.Conflict == "" {
		t.Error("require + prohibit across levels must report a conflict")
	}
	if merge(GroupSessionPolicy{RequireRecording: true}, GroupSessionPolicy{RequireRecording: true}).Conflict != "" {
		t.Error("require at both levels is not a conflict")
	}
	// seat caps: every positive cap is listed (nearest first), the displayed cap is the minimum positive.
	e = mergeGroupPolicies("C", []GroupSessionPolicy{
		{MaxConcurrentSessions: 5}, {}, {MaxConcurrentSessions: 2}}, []string{"C", "P", "R"})
	if e.MaxConcurrentSessions != 2 || len(e.SeatCaps) != 2 ||
		e.SeatCaps[0] != (GroupSeatCap{"C", 5}) || e.SeatCaps[1] != (GroupSeatCap{"R", 2}) {
		t.Errorf("seat caps = %+v (displayed %d), want [C:5 R:2] displayed 2", e.SeatCaps, e.MaxConcurrentSessions)
	}
	if e := merge(); e.GroupID != "A" {
		t.Error("an empty chain must still carry the group id")
	}
}

func TestWouldConflictFindsDescendants(t *testing.T) {
	tree := asymTree()
	pol := map[string]GroupSessionPolicy{
		"P": {RequireRecording: true},
		"G": {ProhibitRecording: true}, // a grandchild that prohibits what its grandparent requires
	}
	if bad := wouldConflict(tree, pol, []string{"P", "C", "G", "S"}); !reflect.DeepEqual(bad, []string{"G"}) {
		t.Errorf("conflicting groups = %v, want [G] only (P, C, S are fine)", bad)
	}
	if bad := wouldConflict(tree, map[string]GroupSessionPolicy{"P": {RequireRecording: true}}, []string{"P", "C", "G"}); len(bad) != 0 {
		t.Errorf("no conflict expected, got %v", bad)
	}
}

// --- fake seat counting: per-ancestor, subtree ---------------------------------------------------

func TestFakeSeatCapsCountTheWholeSubtreeOfEveryCappedAncestor(t *testing.T) {
	ctx := context.Background()
	tree := asymTree()
	s := NewInMemorySessionRecordStore()
	start := func(group string, caps ...GroupSeatCap) error {
		rec := &SessionRecord{TenantID: "t", MachineID: "m-" + group + newUUID(), TechnicianID: "u", MachineGroupID: group, Access: "control"}
		return s.StartSessionWithinLimit(ctx, "t", rec, SessionStartLimits{GroupID: group, GroupCaps: caps, Tree: tree})
	}
	// P is capped at 2, counting P's whole subtree (P, C, G). C is uncapped itself.
	capP := GroupSeatCap{GroupID: "P", Cap: 2}
	if err := start("C", capP); err != nil {
		t.Fatalf("first session in C: %v", err)
	}
	if err := start("G", capP); err != nil {
		t.Fatalf("second session in G (grandchild): %v", err)
	}
	if err := start("C", capP); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
		t.Fatalf("third session in C under P's cap of 2 = %v, want the group limit", err)
	}
	// A session in the SIBLING S is outside P's subtree: it neither counts against P nor is blocked by it.
	if err := start("S"); err != nil {
		t.Fatalf("a session in sibling S must not be counted against P's cap: %v", err)
	}
	// Per-ANCESTOR: C's own cap of 1 AND P's cap of 5 are BOTH enforced; the tighter one trips first even
	// though P still has room.
	s2 := NewInMemorySessionRecordStore()
	start2 := func(group string, caps ...GroupSeatCap) error {
		rec := &SessionRecord{TenantID: "t", MachineID: "m2-" + group + newUUID(), TechnicianID: "u", MachineGroupID: group, Access: "control"}
		return s2.StartSessionWithinLimit(ctx, "t", rec, SessionStartLimits{GroupID: group, GroupCaps: caps, Tree: tree})
	}
	caps := []GroupSeatCap{{GroupID: "C", Cap: 1}, {GroupID: "P", Cap: 5}}
	if err := start2("C", caps...); err != nil {
		t.Fatal(err)
	}
	if err := start2("C", caps...); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
		t.Fatalf("second session under C's own cap of 1 = %v (P has room)", err)
	}
	// ...and the looser descendant cap does not mask a tighter ancestor: P capped at 1 while C allows 9.
	s3 := NewInMemorySessionRecordStore()
	rec := func(group string) *SessionRecord {
		return &SessionRecord{TenantID: "t", MachineID: "m3-" + group + newUUID(), TechnicianID: "u", MachineGroupID: group, Access: "control"}
	}
	loose := []GroupSeatCap{{GroupID: "C", Cap: 9}, {GroupID: "P", Cap: 1}}
	if err := s3.StartSessionWithinLimit(ctx, "t", rec("G"), SessionStartLimits{GroupID: "G", GroupCaps: loose, Tree: tree}); err != nil {
		t.Fatal(err)
	}
	if err := s3.StartSessionWithinLimit(ctx, "t", rec("C"), SessionStartLimits{GroupID: "C", GroupCaps: loose, Tree: tree}); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
		t.Fatalf("P's cap of 1 must hold even though C's own cap is 9, got %v", err)
	}
	// The legacy (Group, GroupID) pair still means "this exact group's cap".
	s4 := NewInMemorySessionRecordStore()
	if err := s4.StartSessionWithinLimit(ctx, "t", rec("S"), SessionStartLimits{GroupID: "S", Group: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s4.StartSessionWithinLimit(ctx, "t", rec("S"), SessionStartLimits{GroupID: "S", Group: 1}); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
		t.Fatalf("legacy Group/GroupID cap = %v, want the group limit", err)
	}
	// An ENDED session frees its seat in the subtree count.
	open, _ := s.ListSessions(ctx, "t", SessionSummaryFilter{})
	for _, r := range open {
		if r.MachineGroupID == "C" {
			if _, err := s.EndSession(ctx, "t", r.ID, r.StartedAt); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if err := start("G", capP); err != nil {
		t.Fatalf("after one session in P's subtree ended, a new one must fit: %v", err)
	}
}
