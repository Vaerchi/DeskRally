package controlplane

// Store-level proofs for nested machine groups (docs/62 stages A + B), run against BOTH the in-memory
// stores and Postgres through one scenario list ("fake and pg must agree"): coverage through GrantFor and
// StoredGrantFor, structure rules, in-transaction authorization of hierarchy mutations (R2), the tree-version
// guard on assignment edits and machine moves, per-ancestor seat caps (R7) and the attended list. The pg-only
// half (the trigger under two real connections, tenant deletion with a tree, the migration's existing-data
// assertion, the SQL helpers, RLS on group_tree_version) is group_tree_pg_test.go. Every pg subtest needs
// TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a skip as a failure.
//
// THE TREE every scenario shares (asymmetric on purpose — see group_tree_test.go):
//
//	R ── P ── C ── G
//	  └─ S
//	X

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type treeEnv struct {
	t        *testing.T
	ctx      context.Context
	pg       bool
	tid      string
	otherTid string
	groups   MachineGroupStore
	users    UserStore
	machines MachineStore
	sessions SessionRecordStore
	policies GroupSessionPolicyStore
	attended AttendedStore
	su       *pgxpool.Pool // superuser pool (pg only)
	app      *pgxpool.Pool // rmt_app pool (pg only)
	tech     string        // an existing user, the technician of seeded sessions
	seq      int
}

func newFakeTreeEnv(t *testing.T) *treeEnv {
	t.Helper()
	users := NewInMemoryUserStore()
	groups := NewInMemoryMachineGroupStore()
	machines := NewInMemoryMachineStore()
	LinkGroupStores(groups, users, machines)
	sessions := NewInMemorySessionRecordStore()
	policies := NewInMemoryGroupSessionPolicyStore()
	LinkGroupPolicyStores(groups, policies, sessions)
	env := &treeEnv{t: t, ctx: context.Background(), tid: "tenant-a", otherTid: "tenant-b",
		groups: groups, users: users, machines: machines, policies: policies,
		sessions: sessions, attended: NewInMemoryAttendedStore(machines)}
	env.tech = env.newUser("tech", RoleTechnician)
	return env
}

func newPgTreeEnv(t *testing.T) *treeEnv {
	t.Helper()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyMachineDeviceUniqueMigration(t, su)
	applyDeviceIdentityMigration(t, su)
	applyAttendedMigration(t, su)
	tid, tech := provisionUser(t, su, "gt-a", "a@gt-a.test", "password-1234")
	otherTid, _ := provisionUser(t, su, "gt-b", "b@gt-b.test", "password-1234")
	ctx := context.Background()
	app := newAppRolePool(t, ctx)
	return &treeEnv{t: t, ctx: ctx, pg: true, tid: tid, otherTid: otherTid, su: su, app: app, tech: tech,
		groups: NewPgMachineGroupStore(app), users: newPgUserStoreT(app), machines: NewPgMachineStore(app),
		sessions: NewPgSessionRecordStore(app), policies: NewPgGroupSessionPolicyStore(app), attended: NewPgAttendedStore(app)}
}

// forEachTreeEnv runs fn once against the fake and once against Postgres.
func forEachTreeEnv(t *testing.T, fn func(t *testing.T, env *treeEnv)) {
	t.Helper()
	t.Run("fake", func(t *testing.T) { fn(t, newFakeTreeEnv(t)) })
	t.Run("pg", func(t *testing.T) { fn(t, newPgTreeEnv(t)) })
}

func (e *treeEnv) next(prefix string) string {
	e.seq++
	return prefix + "-" + strconv.Itoa(e.seq) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// newUser creates a user with ONE membership of role over scope (none = tenant-wide) and returns its id.
func (e *treeEnv) newUser(label string, role Role, scope ...string) string {
	return e.newUserExpiring(label, role, nil, scope...)
}

func (e *treeEnv) newUserExpiring(label string, role Role, expires *time.Time, scope ...string) string {
	e.t.Helper()
	id := newUUID()
	if err := e.users.CreateUserAssignment(e.ctx, e.tid, id, e.next(label)+"@x.test", label,
		Assignment{Role: role, ScopedGroupIDs: scope, ExpiresAt: expires}); err != nil {
		e.t.Fatalf("create user %s: %v", label, err)
	}
	return id
}

func (e *treeEnv) mkGroup(name, parent string) string {
	e.t.Helper()
	g := &MachineGroup{Name: name}
	if parent != "" {
		g.ParentID = &parent
	}
	if err := e.groups.CreateMachineGroup(e.ctx, e.tid, g); err != nil {
		e.t.Fatalf("create group %s under %q: %v", name, parent, err)
	}
	return g.ID
}

func (e *treeEnv) newMachine(group string) string {
	e.t.Helper()
	dev := newUUID()
	if e.pg {
		return seedNamedMachine(e.t, e.su, e.tid, group, dev, "host-"+dev[:8])
	}
	m := &Machine{DeviceID: dev, GroupID: group, Name: "host"}
	if err := e.machines.EnrollMachine(e.ctx, e.tid, m); err != nil {
		e.t.Fatalf("enroll machine: %v", err)
	}
	return m.ID
}

type tree5 struct{ R, P, C, G, S, X string }

func (e *treeEnv) standardTree() tree5 {
	e.t.Helper()
	var tr tree5
	tr.R = e.mkGroup("R", "")
	tr.P = e.mkGroup("P", tr.R)
	tr.C = e.mkGroup("C", tr.P)
	tr.G = e.mkGroup("G", tr.C)
	tr.S = e.mkGroup("S", tr.R)
	tr.X = e.mkGroup("X", "")
	return tr
}

func (e *treeEnv) wide() GroupActor {
	return GroupActor{UserID: "", Grant: NewGrant("admin", e.tid, NewMembership(RoleOwner, AllGroups()))}
}

func (e *treeEnv) grant(uid string) *Grant {
	e.t.Helper()
	g, err := e.users.GrantFor(e.ctx, e.tid, uid)
	if err != nil {
		e.t.Fatalf("GrantFor: %v", err)
	}
	return g
}

func (e *treeEnv) stored(uid string) *Grant {
	e.t.Helper()
	g, err := e.users.StoredGrantFor(e.ctx, e.tid, uid)
	if err != nil {
		e.t.Fatalf("StoredGrantFor: %v", err)
	}
	return g
}

func (e *treeEnv) parentOf(id string) string {
	e.t.Helper()
	tree, _, err := e.groups.GroupTree(e.ctx, e.tid)
	if err != nil {
		e.t.Fatalf("GroupTree: %v", err)
	}
	return tree[id]
}

func (e *treeEnv) version() int64 {
	e.t.Helper()
	_, v, err := e.groups.GroupTree(e.ctx, e.tid)
	if err != nil {
		e.t.Fatalf("GroupTree: %v", err)
	}
	return v
}

func covers(g *Grant, cap Capability, ids map[string]string) map[string]bool {
	out := map[string]bool{}
	for name, id := range ids {
		out[name] = g.AllowsInGroup(cap, id)
	}
	return out
}

func (t5 tree5) ids() map[string]string {
	return map[string]string{"R": t5.R, "P": t5.P, "C": t5.C, "G": t5.G, "S": t5.S, "X": t5.X}
}

func wantCovers(names ...string) map[string]bool {
	out := map[string]bool{"R": false, "P": false, "C": false, "G": false, "S": false, "X": false}
	for _, n := range names {
		out[n] = true
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------------------------------

func TestTreeCoverageThroughGrants(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		tr := env.standardTree()
		ids := tr.ids()
		uP := env.newUser("uP", RoleTechnician, tr.P)
		uC := env.newUser("uC", RoleTechnician, tr.C)
		uS := env.newUser("uS", RoleTechnician, tr.S)
		ghost := newUUID()
		uGhost := env.newUser("uGhost", RoleTechnician, ghost)
		uAll := env.newUser("uAll", RoleTechnician)

		for _, tc := range []struct {
			name string
			uid  string
			want map[string]bool
		}{
			{"{P} covers P, C, G", uP, wantCovers("P", "C", "G")},
			{"{C} covers C, G, never its parent P nor sibling S", uC, wantCovers("C", "G")},
			{"{S} covers S only", uS, wantCovers("S")},
			{"{dangling} covers nothing", uGhost, wantCovers()},
			{"tenant-wide covers all", uAll, wantCovers("R", "P", "C", "G", "S", "X")},
		} {
			// EFFECTIVE grant and STORED grant must agree on coverage (R1: admin containment needs it).
			if got := covers(env.grant(tc.uid), CapViewMachines, ids); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s: GrantFor coverage = %v, want %v", tc.name, got, tc.want)
			}
			if got := covers(env.stored(tc.uid), CapViewMachines, ids); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s: StoredGrantFor coverage = %v, want %v", tc.name, got, tc.want)
			}
		}
		// A dangling-only scope is group-limited, not tenant-wide, and stores what was assigned.
		gg := env.grant(uGhost)
		if sc, _ := gg.ScopeFor(CapViewMachines); sc.All {
			t.Fatal("dangling-only scope became tenant-wide")
		}
		if got := env.stored(uGhost).AssignmentScope().GroupIDs(); !reflect.DeepEqual(got, []string{ghost}) {
			t.Fatalf("stored assigned ids = %v, want [%s]", got, ghost)
		}

		// Both grants carry the tenant's tree version.
		if v := env.version(); v == 0 || env.grant(uP).TreeVersion != v || env.stored(uP).TreeVersion != v {
			t.Fatalf("grant versions %d/%d, tree version %d (must match and be non-zero)",
				env.grant(uP).TreeVersion, env.stored(uP).TreeVersion, v)
		}

		// EXPIRED memberships: GrantFor drops them, StoredGrantFor keeps them AND expands their scope.
		past := time.Now().Add(-time.Hour)
		uExp := env.newUserExpiring("uExp", RoleTechnician, &past, tr.P)
		if got := covers(env.grant(uExp), CapViewMachines, ids); !reflect.DeepEqual(got, wantCovers()) {
			t.Errorf("an expired membership authorized %v", got)
		}
		st := env.stored(uExp)
		if len(st.Members) != 1 || st.Members[0].ExpiresAt == nil || !st.Members[0].Scope.Covers(tr.C) {
			t.Errorf("StoredGrantFor must keep the expired membership with its expanded scope: %+v", st.Members)
		}

		// A REPARENT re-resolves coverage on the next read and never touches the stored array.
		v0 := env.version()
		if _, _, err := env.groups.MoveMachineGroup(env.ctx, env.tid, env.wide(), tr.C, &tr.S, nil); err != nil {
			t.Fatalf("move C under S: %v", err)
		}
		if env.version() <= v0 {
			t.Error("a reparent must bump the tree version")
		}
		if got := covers(env.grant(uP), CapViewMachines, ids); !reflect.DeepEqual(got, wantCovers("P")) {
			t.Errorf("after C moved under S, {P} covers %v, want only P", got)
		}
		if got := covers(env.grant(uS), CapViewMachines, ids); !reflect.DeepEqual(got, wantCovers("S", "C", "G")) {
			t.Errorf("after C moved under S, {S} covers %v, want S, C, G", got)
		}
		if got := covers(env.grant(uC), CapViewMachines, ids); !reflect.DeepEqual(got, wantCovers("C", "G")) {
			t.Errorf("a move must not change what {C} covers (its own subtree moves with it): %v", got)
		}
		for _, uid := range []string{uP, uC, uS} {
			if ids := env.stored(uid).AssignmentScope().GroupIDs(); len(ids) != 1 {
				t.Errorf("the stored scope of %s changed after a reparent: %v", uid, ids)
			}
		}
		// ListUsers is an ASSIGNED-scope summary: exactly the ids chosen, never the expansion.
		users, err := env.users.ListUsers(env.ctx, env.tid)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range users {
			switch u.ID {
			case uP:
				if !reflect.DeepEqual(u.ScopedGroupIDs, []string{tr.P}) {
					t.Errorf("ListUsers scope of {P} = %v (an expansion leaked into the summary)", u.ScopedGroupIDs)
				}
			case uAll:
				if len(u.ScopedGroupIDs) != 0 {
					t.Errorf("ListUsers scope of tenant-wide = %v", u.ScopedGroupIDs)
				}
			}
		}

		// Deleting a group leaves its id DANGLING in the stored array: safe deny, never a widen.
		if err := env.groups.DeleteMachineGroup(env.ctx, env.tid, tr.P); err != nil {
			t.Fatalf("delete P (now childless): %v", err)
		}
		gp := env.grant(uP)
		if sc, _ := gp.ScopeFor(CapViewMachines); sc.All || sc.Covers(tr.P) || sc.Covers(tr.S) {
			t.Fatalf("after P was deleted, {P} must cover nothing and stay group-limited: %+v", sc)
		}
		if got := env.stored(uP).AssignmentScope().GroupIDs(); !reflect.DeepEqual(got, []string{tr.P}) {
			t.Fatalf("stored scope after P's deletion = %v, want the dangling [%s]", got, tr.P)
		}
	})
}

func TestTreeStructureRulesAgreeAcrossStores(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		tr := env.standardTree()
		move := func(id string, parent *string) error {
			_, _, err := env.groups.MoveMachineGroup(env.ctx, env.tid, env.wide(), id, parent, nil)
			return err
		}
		ptr := func(s string) *string { return &s }

		// CYCLES: under its own descendant, and under itself.
		if err := move(tr.R, ptr(tr.G)); !errors.Is(err, ErrMachineGroupCycle) {
			t.Errorf("R under its grandchild G = %v, want a cycle", err)
		}
		if err := move(tr.P, ptr(tr.P)); !errors.Is(err, ErrMachineGroupCycle) {
			t.Errorf("P under itself = %v, want a cycle", err)
		}
		// DEPTH: a 5th level on create, and a tall subtree moved under a deep parent.
		g5 := &MachineGroup{Name: "level5", ParentID: &tr.G}
		if err := env.groups.CreateMachineGroup(env.ctx, env.tid, g5); !errors.Is(err, ErrMachineGroupTooDeep) {
			t.Errorf("create at level 5 = %v, want too deep", err)
		}
		if err := move(tr.X, ptr(tr.G)); !errors.Is(err, ErrMachineGroupTooDeep) {
			t.Errorf("X under level-4 G = %v, want too deep", err)
		}
		if err := move(tr.P, ptr(tr.S)); !errors.Is(err, ErrMachineGroupTooDeep) {
			t.Errorf("tall subtree P (height 3) under S (level 2) = %v, want too deep", err)
		}
		if err := move(tr.P, ptr(tr.X)); err != nil { // 1 + 3 = 4: fits
			t.Errorf("P (height 3) under root X must fit: %v", err)
		}
		if env.parentOf(tr.P) != tr.X {
			t.Errorf("P's parent = %q, want X", env.parentOf(tr.P))
		}
		// UNKNOWN / FOREIGN parent.
		if err := move(tr.S, ptr(newUUID())); !errors.Is(err, ErrMachineGroupParentInvalid) {
			t.Errorf("move under a missing parent = %v, want ErrMachineGroupParentInvalid", err)
		}
		foreign := &MachineGroup{Name: "other tenant's"}
		if err := env.groups.CreateMachineGroup(env.ctx, env.otherTid, foreign); err != nil {
			t.Fatalf("create foreign group: %v", err)
		}
		if err := move(tr.S, &foreign.ID); !errors.Is(err, ErrMachineGroupParentInvalid) {
			t.Errorf("move under ANOTHER tenant's group = %v, want ErrMachineGroupParentInvalid", err)
		}
		child := &MachineGroup{Name: "under foreign", ParentID: &foreign.ID}
		if err := env.groups.CreateMachineGroup(env.ctx, env.tid, child); !errors.Is(err, ErrMachineGroupParentInvalid) {
			t.Errorf("create under ANOTHER tenant's group = %v, want ErrMachineGroupParentInvalid", err)
		}
		missing := &MachineGroup{Name: "under nothing", ParentID: ptr(newUUID())}
		if err := env.groups.CreateMachineGroup(env.ctx, env.tid, missing); !errors.Is(err, ErrMachineGroupParentInvalid) {
			t.Errorf("create under a missing parent = %v, want ErrMachineGroupParentInvalid", err)
		}
		// MOVE TO ROOT clears the parent; an unknown group is not-found.
		if err := move(tr.S, nil); err != nil {
			t.Errorf("S to root: %v", err)
		}
		if env.parentOf(tr.S) != "" {
			t.Error("S still has a parent after being made a root")
		}
		if err := move(newUUID(), nil); !errors.Is(err, ErrMachineGroupNotFound) {
			t.Errorf("move of an unknown group = %v, want not-found", err)
		}
		// DELETE with children is refused, never re-roots; a leaf deletes.
		if err := env.groups.DeleteMachineGroup(env.ctx, env.tid, tr.C); !errors.Is(err, ErrMachineGroupHasChildren) {
			t.Errorf("delete C (has child G) = %v, want ErrMachineGroupHasChildren", err)
		}
		if env.parentOf(tr.G) != tr.C {
			t.Error("G was re-rooted by a refused delete")
		}
		if err := env.groups.DeleteMachineGroup(env.ctx, env.tid, tr.G); err != nil {
			t.Errorf("delete leaf G: %v", err)
		}
		if err := env.groups.DeleteMachineGroup(env.ctx, env.tid, tr.C); err != nil {
			t.Errorf("delete C once childless: %v", err)
		}
		// LIST carries parent_id.
		list, err := env.groups.ListMachineGroups(env.ctx, env.tid)
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]MachineGroup{}
		for _, g := range list {
			byID[g.ID] = g
		}
		if p := byID[tr.P].ParentID; p == nil || *p != tr.X {
			t.Errorf("listed parent of P = %v, want X", p)
		}
		if byID[tr.R].ParentID != nil {
			t.Errorf("a root must list a nil parent, got %v", *byID[tr.R].ParentID)
		}
	})
}

func TestHierarchyMutationAuthorizesAgainstTheCurrentTree(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		tr := env.standardTree()
		uA := env.newUser("actor", RoleAdmin, tr.P)

		reparent := func(actor GroupActor, id, np string) error {
			authz := func(g *Grant, current GroupTree) error { return authorizeGroupReparent(g, current, id, np) }
			_, _, err := env.groups.MoveMachineGroup(env.ctx, env.tid, actor, id, &np, authz)
			return err
		}
		stale := env.grant(uA) // request time: {P} covers P, C, G
		if !stale.AllowsInGroup(CapManageGroups, tr.G) {
			t.Fatal("precondition: the actor's request grant covers G")
		}

		// (a) the actor's SCOPE changes between the request-time grant and the mutation: the stale grant
		// would allow the move, the reloaded one must not.
		if err := env.users.SetUserAssignment(env.ctx, env.tid, uA, Assignment{Role: RoleAdmin, ScopedGroupIDs: []string{tr.S}}); err != nil {
			t.Fatal(err)
		}
		if err := reparent(GroupActor{UserID: uA, Grant: stale}, tr.G, tr.P); !IsDenied(err) {
			t.Fatalf("a move authorized on a STALE scope = %v, want denied (the grant must be reloaded in the transaction)", err)
		}
		if env.parentOf(tr.G) != tr.C {
			t.Fatal("the denied move changed the tree")
		}

		// (b) the TREE changes: restore the actor to {P}, then another admin moves C out from under P.
		if err := env.users.SetUserAssignment(env.ctx, env.tid, uA, Assignment{Role: RoleAdmin, ScopedGroupIDs: []string{tr.P}}); err != nil {
			t.Fatal(err)
		}
		stale = env.grant(uA)
		if _, _, err := env.groups.MoveMachineGroup(env.ctx, env.tid, env.wide(), tr.C, &tr.S, nil); err != nil {
			t.Fatal(err)
		}
		actor := GroupActor{UserID: uA, Grant: stale}
		if !stale.AllowsInGroup(CapManageGroups, tr.C) {
			t.Fatal("precondition: the stale grant still covers C")
		}
		newKid := &MachineGroup{Name: "kid", ParentID: &tr.C}
		err := env.groups.CreateMachineGroupAs(env.ctx, env.tid, actor, newKid,
			func(g *Grant, _ GroupTree) error { return authorizeGroupCreate(g, tr.C) })
		if !IsDenied(err) {
			t.Errorf("create under C after C left P's subtree = %v, want denied", err)
		}
		err = env.groups.DeleteMachineGroupAs(env.ctx, env.tid, actor, tr.G,
			func(g *Grant, _ GroupTree) error { return authorizeGroupManage(g, tr.G) })
		if !IsDenied(err) {
			t.Errorf("delete of G after its subtree left P = %v, want denied", err)
		}
		if err := reparent(actor, tr.C, tr.P); !IsDenied(err) {
			t.Errorf("move of C (no longer in the actor's subtree) = %v, want denied", err)
		}
		if env.parentOf(tr.C) != tr.S {
			t.Error("a denied move changed C's parent")
		}

		// (c) the positive path: a group the actor still covers.
		fresh := GroupActor{UserID: uA, Grant: env.grant(uA)}
		ok := &MachineGroup{Name: "inside P", ParentID: &tr.P}
		if err := env.groups.CreateMachineGroupAs(env.ctx, env.tid, fresh, ok,
			func(g *Grant, _ GroupTree) error { return authorizeGroupCreate(g, tr.P) }); err != nil {
			t.Errorf("create under P by an actor covering P: %v", err)
		}
		// (d) a STATIC grant (an API token) is tenant-wide and not reloaded.
		static := GroupActor{UserID: "token-id", Grant: NewGrant("token-id", env.tid, NewMembership(RoleAdmin, AllGroups()))}
		if err := reparent(static, tr.X, tr.R); err != nil {
			t.Errorf("a tenant-wide static grant must be able to reparent: %v", err)
		}
		// (e) the authorizer sees the tree BEFORE the mutation.
		var seen GroupTree
		_, _, err = env.groups.MoveMachineGroup(env.ctx, env.tid, static, tr.X, nil,
			func(_ *Grant, current GroupTree) error { seen = current; return nil })
		if err != nil || seen[tr.X] != tr.R {
			t.Errorf("authorizer saw X's parent %q (err %v), want the pre-move parent R", seen[tr.X], err)
		}
	})
}

func TestTreeVersionGuardsAssignmentsAndMachineMoves(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		tr := env.standardTree()
		uV := env.newUser("v", RoleAdmin, tr.P)
		g := env.grant(uV)
		ver := g.TreeVersion
		if ver == 0 {
			t.Fatal("precondition: the grant carries a non-zero tree version")
		}
		env.mkGroup("late", "") // any hierarchy change bumps the version
		if env.version() <= ver {
			t.Fatal("a created group must bump the tree version")
		}

		// ASSIGNMENT EDIT: stale version refused, nothing written.
		err := env.users.SetUserAssignment(env.ctx, env.tid, uV, Assignment{Role: RoleAdmin, ScopedGroupIDs: []string{tr.S}, ExpectTreeVersion: &ver})
		if !errors.Is(err, ErrGroupTreeChanged) {
			t.Fatalf("assignment on a stale tree = %v, want ErrGroupTreeChanged", err)
		}
		if got := env.stored(uV).AssignmentScope().GroupIDs(); !reflect.DeepEqual(got, []string{tr.P}) {
			t.Fatalf("the refused assignment changed the scope to %v", got)
		}
		cur := env.version()
		if err := env.users.SetUserAssignment(env.ctx, env.tid, uV, Assignment{Role: RoleAdmin, ScopedGroupIDs: []string{tr.S}, ExpectTreeVersion: &cur}); err != nil {
			t.Fatalf("assignment on the current tree: %v", err)
		}
		// CREATE USER with a stale version: refused, and no user left behind.
		newID := newUUID()
		err = env.users.CreateUserAssignment(env.ctx, env.tid, newID, env.next("late")+"@x.test", "late",
			Assignment{Role: RoleTechnician, ScopedGroupIDs: []string{tr.P}, ExpectTreeVersion: &ver})
		if !errors.Is(err, ErrGroupTreeChanged) {
			t.Fatalf("create user on a stale tree = %v, want ErrGroupTreeChanged", err)
		}
		if _, err := env.users.FindUserByID(env.ctx, env.tid, newID); !errors.Is(err, ErrNoUser) {
			t.Fatalf("the refused create left a user behind: %v", err)
		}

		// MACHINE MOVE: stale refused, machine stays; fresh moves it.
		mid := env.newMachine(tr.P)
		if err := env.machines.SetMachineGroupIfTree(env.ctx, env.tid, mid, tr.S, ver); !errors.Is(err, ErrGroupTreeChanged) {
			t.Fatalf("machine move on a stale tree = %v, want ErrGroupTreeChanged", err)
		}
		m, err := env.machines.GetMachineByID(env.ctx, env.tid, mid)
		if err != nil || m.GroupID != tr.P {
			t.Fatalf("the refused move changed the machine's group: %+v (err %v)", m, err)
		}
		if err := env.machines.SetMachineGroupIfTree(env.ctx, env.tid, mid, tr.S, env.version()); err != nil {
			t.Fatalf("machine move on the current tree: %v", err)
		}
		if m, _ := env.machines.GetMachineByID(env.ctx, env.tid, mid); m.GroupID != tr.S {
			t.Fatalf("machine group = %s, want S", m.GroupID)
		}
		// A reparent bumps it too.
		before := env.version()
		if _, _, err := env.groups.MoveMachineGroup(env.ctx, env.tid, env.wide(), tr.S, &tr.X, nil); err != nil {
			t.Fatal(err)
		}
		if env.version() <= before {
			t.Error("a reparent must bump the tree version")
		}
		// Deleting a group bumps it as well.
		before = env.version()
		if err := env.groups.DeleteMachineGroup(env.ctx, env.tid, tr.G); err != nil {
			t.Fatal(err)
		}
		if env.version() <= before {
			t.Error("a delete must bump the tree version")
		}
	})
}

func (e *treeEnv) startSession(group string, caps ...GroupSeatCap) error {
	e.t.Helper()
	tree, _, err := e.groups.GroupTree(e.ctx, e.tid)
	if err != nil {
		e.t.Fatal(err)
	}
	rec := &SessionRecord{TenantID: e.tid, MachineID: e.newMachine(group), TechnicianID: e.tech,
		Access: "control", MachineGroupID: group}
	return e.sessions.StartSessionWithinLimit(e.ctx, e.tid, rec,
		SessionStartLimits{GroupID: group, GroupCaps: caps, Tree: tree})
}

func (e *treeEnv) openSessions() []SessionRecord {
	e.t.Helper()
	all, err := e.sessions.ListSessions(e.ctx, e.tid, SessionSummaryFilter{})
	if err != nil {
		e.t.Fatal(err)
	}
	var open []SessionRecord
	for _, r := range all {
		if r.EndedAt == nil {
			open = append(open, r)
		}
	}
	return open
}

func TestSeatCapsCountSubtreesPerAncestor(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		tr := env.standardTree()
		capP := GroupSeatCap{GroupID: tr.P, Cap: 2}
		// P is capped at 2 and counts P's whole subtree: P, C, G.
		if err := env.startSession(tr.C, capP); err != nil {
			t.Fatalf("session 1 in C: %v", err)
		}
		if err := env.startSession(tr.G, capP); err != nil {
			t.Fatalf("session 2 in G: %v", err)
		}
		if err := env.startSession(tr.C, capP); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
			t.Fatalf("session 3 under P's cap of 2 = %v, want the group limit", err)
		}
		// The sibling S is outside P's subtree: not counted, not blocked.
		if err := env.startSession(tr.S); err != nil {
			t.Fatalf("a session in sibling S must not be counted against P: %v", err)
		}

		// PER ANCESTOR: every capped ancestor-or-self is enforced against ITS OWN subtree. A session in G
		// answers to C's cap and to P's cap and to R's cap, and the tightest one that is full refuses it
		// even when the others have room — a looser descendant cap never masks a tighter ancestor.
		capC1 := GroupSeatCap{GroupID: tr.C, Cap: 1}
		capC100 := GroupSeatCap{GroupID: tr.C, Cap: 100}
		capR := GroupSeatCap{GroupID: tr.R, Cap: 100}
		if err := env.startSession(tr.X, GroupSeatCap{GroupID: tr.X, Cap: 1}); err != nil {
			t.Fatalf("first session in X: %v", err)
		}
		if err := env.startSession(tr.X, GroupSeatCap{GroupID: tr.X, Cap: 1}); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
			t.Fatalf("X's cap of 1 = %v, want the group limit", err)
		}
		// C's subtree (C, G) already holds 2 open sessions, so C's cap of 1 refuses a session in G while
		// R's cap of 100 has plenty of room.
		if err := env.startSession(tr.G, capC1, capR); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
			t.Fatalf("a session in G under C's cap of 1 = %v, want the group limit", err)
		}
		// The reverse: C's own cap is loose (100) but P (2, full: C+G) is tight — the ancestor still holds.
		if err := env.startSession(tr.G, capC100, capP, capR); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
			t.Fatalf("P's full cap of 2 must refuse even though C's cap is 100: %v", err)
		}

		// A MOVE that puts a subtree over a cap ends nothing; admissions stay refused until under cap.
		// The caps are chosen so that ONLY counting S's session after the move can refuse: P's subtree holds
		// C and G (2); a cap of 3 admits a third (in P itself) BEFORE the move, and a cap of 4 then refuses
		// only if the moved S session is charged to P (3 without it, 4 with it).
		cap1 := GroupSeatCap{GroupID: tr.P, Cap: 1}
		cap3 := GroupSeatCap{GroupID: tr.P, Cap: 3}
		cap4 := GroupSeatCap{GroupID: tr.P, Cap: 4}
		if err := env.startSession(tr.P, cap3); err != nil {
			t.Fatalf("before the move P's subtree holds 2 sessions; a cap of 3 must admit: %v", err)
		}
		openBefore := len(env.openSessions())
		if _, _, err := env.groups.MoveMachineGroup(env.ctx, env.tid, env.wide(), tr.S, &tr.P, nil); err != nil {
			t.Fatal(err)
		}
		if got := len(env.openSessions()); got != openBefore {
			t.Fatalf("the move ended sessions: %d open, was %d", got, openBefore)
		}
		if err := env.startSession(tr.P, cap4); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
			t.Fatalf("after S moved under P its open session must count against P (C, G, P, S = 4 >= cap 4): %v", err)
		}
		// End everything in P's subtree; admissions resume.
		inP := map[string]bool{tr.P: true, tr.C: true, tr.G: true, tr.S: true}
		for _, r := range env.openSessions() {
			if inP[r.MachineGroupID] {
				if _, err := env.sessions.EndSession(env.ctx, env.tid, r.ID, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := env.startSession(tr.P, cap1); err != nil {
			t.Fatalf("admission after the subtree drained = %v, want admitted", err)
		}
	})
}

func TestAttendedListInheritsScope(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		tr := env.standardTree()
		uP := env.newUser("uP", RoleTechnician, tr.P)
		uC := env.newUser("uC", RoleTechnician, tr.C)
		uS := env.newUser("uS", RoleTechnician, tr.S)
		uAll := env.newUser("uAll", RoleTechnician)
		for _, gid := range []string{tr.P, tr.C, tr.G, tr.S} {
			if _, err := env.attended.Create(env.ctx, env.tid, &AttendedSession{GroupID: gid, TechnicianID: env.tech}); err != nil {
				t.Fatalf("create attended in %s: %v", gid, err)
			}
		}
		listGroups := func(uid string) []string {
			scope, ok := env.grant(uid).ScopeFor(CapViewSessions)
			if !ok {
				t.Fatalf("%s has no view_sessions", uid)
			}
			rows, err := env.attended.List(env.ctx, env.tid, scope, 50, 0)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			var gs []string
			for _, r := range rows {
				gs = append(gs, r.GroupID)
			}
			return sortedCopy(gs)
		}
		if got, want := listGroups(uP), sortedCopy([]string{tr.P, tr.C, tr.G}); !reflect.DeepEqual(got, want) {
			t.Errorf("{P} lists %v, want P, C and G sessions %v", got, want)
		}
		if got, want := listGroups(uC), sortedCopy([]string{tr.C, tr.G}); !reflect.DeepEqual(got, want) {
			t.Errorf("{C} lists %v, want C and G only (never its parent P) %v", got, want)
		}
		if got, want := listGroups(uS), []string{tr.S}; !reflect.DeepEqual(got, want) {
			t.Errorf("{S} lists %v, want S only", got)
		}
		if got := listGroups(uAll); len(got) != 4 {
			t.Errorf("tenant-wide lists %v, want all 4", got)
		}
		// A dangling scope lists NOTHING (an empty covered set must never degrade to "no filter").
		uGhost := env.newUser("uGhost", RoleTechnician, newUUID())
		if got := listGroups(uGhost); len(got) != 0 {
			t.Errorf("a dangling-scope user lists %v, want nothing", got)
		}
	})
}
