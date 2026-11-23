package controlplane

// Regression proofs for the three confirmed Codex implementation-review findings on docs/62:
//
//  1. seat-cap admission must be decided by the STORE from the CURRENT tree and policies, never from the
//     caller's pre-admission resolution (a concurrent reparent can put the admitted group under a capped
//     ancestor, and a group with no capped ancestors at resolve time may have one now);
//  2. the structure trigger's "an inserted row has no children" assumption must hold: a multi-row INSERT in
//     leaf-to-root order may not build a chain whose parents arrive after their children (GT003);
//  3. policy PUT and rename are conditional on the grant's tree version (ErrGroupTreeChanged, 409).

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (e *treeEnv) admit(group string, limits SessionStartLimits) error {
	e.t.Helper()
	rec := &SessionRecord{TenantID: e.tid, MachineID: e.newMachine(group), TechnicianID: e.tech,
		Access: "control", MachineGroupID: group}
	return e.sessions.StartSessionWithinLimit(e.ctx, e.tid, rec, limits)
}

func (e *treeEnv) setCap(group string, n int) {
	e.t.Helper()
	if err := e.policies.Set(e.ctx, e.tid, group, GroupSessionPolicy{MaxConcurrentSessions: n, MaxSessionDurationSeconds: 60}); err != nil {
		e.t.Fatalf("set cap on %s: %v", group, err)
	}
}

func (e *treeEnv) reparent(id, newParent string) {
	e.t.Helper()
	np := newParent
	if _, _, err := e.groups.MoveMachineGroup(e.ctx, e.tid, e.wide(), id, &np, nil); err != nil {
		e.t.Fatalf("reparent %s under %s: %v", id, newParent, err)
	}
}

// FINDING 1 (a) and (b): the caps the caller resolved BEFORE admission are stale by the time the store
// admits; the store must refuse on the ancestor that is capped NOW.
func TestSeatCapAdmissionIsDecidedFromTheCurrentTree(t *testing.T) {
	cases := []struct {
		name string
		// start puts S where the caller resolved it (and returns the hint it would pass).
		start func(env *treeEnv, s, q string) []GroupSeatCap
	}{
		{"stale resolution found another capped ancestor", func(env *treeEnv, s, q string) []GroupSeatCap {
			env.reparent(s, q) // S under Q (cap 5, plenty of room): the caller's hint is [Q:5]
			return []GroupSeatCap{{GroupID: q, Cap: 5}}
		}},
		{"stale resolution found no caps at all (the unconditional fast path)", func(env *treeEnv, s, q string) []GroupSeatCap {
			return nil // S is a root with no capped ancestor: the caller passes no caps
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
				p := env.mkGroup("P", "")
				q := env.mkGroup("Q", "")
				s := env.mkGroup("S", "")
				env.setCap(p, 2)
				env.setCap(q, 5)
				capP := GroupSeatCap{GroupID: p, Cap: 2}
				// Fill P's subtree: two sessions in P itself.
				for i := 0; i < 2; i++ {
					if err := env.startSession(p, capP); err != nil {
						t.Fatalf("seed session %d in P: %v", i, err)
					}
				}
				hint := tc.start(env, s, q)
				staleTree, _, err := env.groups.GroupTree(env.ctx, env.tid) // what the handler read before the race
				if err != nil {
					t.Fatal(err)
				}
				// CONTROL: before the reparent S is not under P, so it is admitted when the hint is right.
				if err := env.admit(s, SessionStartLimits{GroupID: s, GroupCaps: hint, Tree: staleTree}); err != nil {
					t.Fatalf("control admission into S before the reparent: %v", err)
				}
				// The concurrent reparent lands AFTER the caller resolved its caps.
				env.reparent(s, p)
				err = env.admit(s, SessionStartLimits{GroupID: s, GroupCaps: hint, Tree: staleTree})
				if !errors.Is(err, ErrGroupConcurrentSessionLimit) {
					t.Fatalf("admission into S after it moved under full P (stale hint %v) = %v, want ErrGroupConcurrentSessionLimit", hint, err)
				}
				// No hint, no tree at all: the store decides alone.
				if err := env.admit(s, SessionStartLimits{GroupID: s}); !errors.Is(err, ErrGroupConcurrentSessionLimit) {
					t.Fatalf("hint-less admission into S under full P = %v, want ErrGroupConcurrentSessionLimit", err)
				}
				// A group outside P is not blocked, and P's cap lifted later admits again.
				if err := env.admit(q, SessionStartLimits{GroupID: q}); err != nil {
					t.Fatalf("admission into unrelated Q: %v", err)
				}
				env.setCap(p, 0)
				if err := env.admit(s, SessionStartLimits{GroupID: s}); err != nil {
					t.Fatalf("admission into S once P's cap is lifted: %v", err)
				}
			})
		})
	}
}

// Postgres, with a real second connection: a reparent that is in flight (uncommitted, holding the tree lock
// exclusively) must make a concurrent admission WAIT, and the admission must then see the committed tree.
func TestPgAdmissionWaitsForAnInFlightReparentAndSeesItsResult(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	p := env.mkGroup("P", "")
	s := env.mkGroup("S", "")
	env.setCap(p, 1)
	if err := env.startSession(p, GroupSeatCap{GroupID: p, Cap: 1}); err != nil {
		t.Fatalf("seed session in P: %v", err)
	}

	tx := beginTenantTx(t, env.app, env.tid)
	if _, err := tx.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, s, p); err != nil { // S under P, uncommitted
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- env.admit(s, SessionStartLimits{GroupID: s}) }() // the caller resolved S as an uncapped root
	if !waitBlocked(done, 400*time.Millisecond) {
		t.Fatal("the admission did not wait for the in-flight reparent's tree lock")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrGroupConcurrentSessionLimit) {
		t.Fatalf("admission after the reparent committed = %v, want ErrGroupConcurrentSessionLimit", err)
	}
	if got := len(env.openSessions()); got != 1 {
		t.Fatalf("%d sessions open, want only the seeded one (P's cap of 1 must hold)", got)
	}
}

// FINDING 3 at the store: the policy write and the rename are conditional on the tree version.
func TestPolicyAndRenameWritesAreConditionalOnTheTreeVersion(t *testing.T) {
	forEachTreeEnv(t, func(t *testing.T, env *treeEnv) {
		g := env.mkGroup("G1", "")
		stale := env.version()
		env.mkGroup("bump", "") // any hierarchy change bumps the version

		pol := GroupSessionPolicy{EnforceViewOnly: true}
		if err := env.policies.SetIfTree(env.ctx, env.tid, g, pol, stale); !errors.Is(err, ErrGroupTreeChanged) {
			t.Fatalf("SetIfTree on a stale tree = %v, want ErrGroupTreeChanged", err)
		}
		if got, _ := env.policies.Get(env.ctx, env.tid, g); got.EnforceViewOnly {
			t.Fatal("the refused policy write changed the policy")
		}
		if err := env.groups.RenameMachineGroupIfTree(env.ctx, env.tid, g, "renamed", stale); !errors.Is(err, ErrGroupTreeChanged) {
			t.Fatalf("RenameMachineGroupIfTree on a stale tree = %v, want ErrGroupTreeChanged", err)
		}
		if name := groupName(t, env, g); name != "G1" {
			t.Fatalf("the refused rename changed the name to %q", name)
		}

		cur := env.version()
		if err := env.policies.SetIfTree(env.ctx, env.tid, g, pol, cur); err != nil {
			t.Fatalf("SetIfTree on the current tree: %v", err)
		}
		if got, _ := env.policies.Get(env.ctx, env.tid, g); !got.EnforceViewOnly {
			t.Fatal("the policy write on the current tree did not land")
		}
		if err := env.groups.RenameMachineGroupIfTree(env.ctx, env.tid, g, "renamed", cur); err != nil {
			t.Fatalf("RenameMachineGroupIfTree on the current tree: %v", err)
		}
		if name := groupName(t, env, g); name != "renamed" {
			t.Fatalf("name = %q, want renamed", name)
		}
		if err := env.groups.RenameMachineGroupIfTree(env.ctx, env.tid, newUUID(), "x", cur); !errors.Is(err, ErrMachineGroupNotFound) {
			t.Fatalf("rename of an unknown group = %v, want ErrMachineGroupNotFound", err)
		}
	})
}

func groupName(t *testing.T, env *treeEnv, id string) string {
	t.Helper()
	all, err := env.groups.ListMachineGroups(env.ctx, env.tid)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range all {
		if g.ID == id {
			return g.Name
		}
	}
	t.Fatalf("group %s not found", id)
	return ""
}

// Postgres: a policy write / rename that captured the OLD version parks on an in-flight reparent and then
// refuses (the shared tree lock orders it after the mutation, whichever side arrives first).
func TestPgPolicyAndRenameWaitForAnInFlightReparent(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	p := env.mkGroup("P", "")
	q := env.mkGroup("Q", "")
	ver := env.version()

	tx := beginTenantTx(t, env.app, env.tid)
	if _, err := tx.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, q, p); err != nil {
		t.Fatal(err)
	}
	doneP := make(chan error, 1)
	doneR := make(chan error, 1)
	go func() {
		doneP <- env.policies.SetIfTree(ctx, env.tid, q, GroupSessionPolicy{EnforceViewOnly: true}, ver)
	}()
	go func() { doneR <- env.groups.RenameMachineGroupIfTree(ctx, env.tid, q, "nope", ver) }()
	if !waitBlocked(doneP, 400*time.Millisecond) || !waitBlocked(doneR, 100*time.Millisecond) {
		t.Fatal("a tree-conditional policy write / rename did not wait for the in-flight reparent")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-doneP; !errors.Is(err, ErrGroupTreeChanged) {
		t.Fatalf("policy write after the reparent = %v, want ErrGroupTreeChanged", err)
	}
	if err := <-doneR; !errors.Is(err, ErrGroupTreeChanged) {
		t.Fatalf("rename after the reparent = %v, want ErrGroupTreeChanged", err)
	}
	if got, _ := env.policies.Get(ctx, env.tid, q); got.EnforceViewOnly {
		t.Fatal("the refused policy write landed")
	}
	if name := groupName(t, env, q); name != "Q" {
		t.Fatalf("the refused rename landed: %q", name)
	}
}

// FINDING 3 through the handlers: authorize on the request-time grant, then a reparent moves the target out
// of the manager's covered subtree before the write. Both writes must be refused with 409 and change nothing;
// the same calls with no race are 200.
func TestPolicyPutAndRenameRefusedWhenReparentedOutOfScopeAfterAuthorization(t *testing.T) {
	var racer *racingToggle
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":  {RoleOwner, nil},
		"adminP": {RoleAdmin, []string{"P"}},
	}, nameScope, func(next Authenticator) Authenticator {
		racer = &racingToggle{next: next}
		return racer
	})
	tr := x.tr
	ctx := context.Background()
	mk := func(name string) string {
		g := &MachineGroup{Name: name, ParentID: &tr.P}
		if err := x.groups.CreateMachineGroup(ctx, treeTenant, g); err != nil {
			t.Fatal(err)
		}
		return g.ID
	}
	ok, policyRace, renameRace := mk("ok"), mk("policy-race"), mk("rename-race")
	moveOut := func(id string) func() { // the concurrent reparent: out of P's subtree, under S
		return func() {
			to := tr.S
			if _, _, err := x.groups.MoveMachineGroup(ctx, treeTenant, GroupActor{Grant: NewGrant("owner", treeTenant, NewMembership(RoleOwner, AllGroups()))}, id, &to, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	policyURL := func(id string) string { return "/machine-groups/" + id + "/session-policy" }
	body := map[string]any{"max_concurrent_sessions": 0, "enforce_view_only": true}

	// CONTROL: no race.
	x.want("adminP", "PUT", policyURL(ok), body, http.StatusOK, "control: policy PUT, no race")
	x.want("adminP", "PATCH", "/machine-groups/"+ok, map[string]any{"name": "ok2"}, http.StatusOK, "control: rename, no race")

	// RACE: policy PUT.
	racer.set(moveOut(policyRace))
	rec := x.call("adminP", "PUT", policyURL(policyRace), body)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "groups changed") {
		t.Fatalf("policy PUT after a reparent out of scope = %d %s, want 409 groups changed", rec.Code, rec.Body.String())
	}
	if got, _ := x.policies.Get(ctx, treeTenant, policyRace); got.EnforceViewOnly {
		t.Fatal("the refused policy PUT changed the policy")
	}

	// RACE: rename.
	racer.set(moveOut(renameRace))
	rec = x.call("adminP", "PATCH", "/machine-groups/"+renameRace, map[string]any{"name": "stolen"})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "groups changed") {
		t.Fatalf("rename after a reparent out of scope = %d %s, want 409 groups changed", rec.Code, rec.Body.String())
	}
	all, _ := x.groups.ListMachineGroups(ctx, treeTenant)
	for _, g := range all {
		if g.ID == renameRace && g.Name != "rename-race" {
			t.Fatalf("the refused rename changed the name to %q", g.Name)
		}
	}
	// And once the tree has settled the former manager is simply out of scope.
	x.want("adminP", "PUT", policyURL(policyRace), body, http.StatusForbidden, "retry after the reparent: out of scope")
	x.want("adminP", "PATCH", "/machine-groups/"+renameRace, map[string]any{"name": "stolen"}, http.StatusForbidden, "retry after the reparent: out of scope")
}

// FINDING 2: a new row's parent must already exist at row time (GT003); root-first multi-row inserts work
// because earlier rows of the same statement are visible to the trigger; the depth cap still applies.
func TestPgMultiRowInsertCannotBuildAChainLeafToRoot(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = newUUID()
		}
		return out
	}
	// insert issues ONE multi-row INSERT of the chain ids[0] (root) .. ids[n-1] (leaf), rows in the given
	// order of indexes.
	insert := func(chain []string, order []int) error {
		var sb strings.Builder
		args := []any{env.tid}
		sb.WriteString(`INSERT INTO machine_group (id, tenant_id, name, parent_id) VALUES `)
		for k, i := range order {
			if k > 0 {
				sb.WriteString(", ")
			}
			args = append(args, chain[i])
			idArg := len(args)
			sb.WriteString("($" + strconv.Itoa(idArg) + "::uuid, $1::uuid, 'n" + strconv.Itoa(i) + "', ")
			if i == 0 {
				sb.WriteString("NULL)")
			} else {
				args = append(args, chain[i-1])
				sb.WriteString("$" + strconv.Itoa(len(args)) + "::uuid)")
			}
		}
		_, err := env.su.Exec(ctx, sb.String(), args...)
		return err
	}
	count := func(chain []string) int {
		var n int
		for _, id := range chain {
			var c int
			if err := env.su.QueryRow(ctx, `SELECT count(*) FROM machine_group WHERE id = $1::uuid`, id).Scan(&c); err != nil {
				t.Fatal(err)
			}
			n += c
		}
		return n
	}

	// leaf-to-root, 5 levels: refused (the parent is not there yet), nothing inserted.
	c5 := ids(5)
	if err := insert(c5, []int{4, 3, 2, 1, 0}); sqlState(err) != "GT003" {
		t.Fatalf("leaf-to-root 5-level insert = %v (SQLSTATE %q), want GT003", err, sqlState(err))
	}
	if n := count(c5); n != 0 {
		t.Fatalf("%d rows of the refused chain were inserted", n)
	}
	// leaf-to-root, 2 levels: refused too.
	c2 := ids(2)
	if err := insert(c2, []int{1, 0}); sqlState(err) != "GT003" {
		t.Fatalf("leaf-to-root 2-level insert = %v (SQLSTATE %q), want GT003", err, sqlState(err))
	}
	if n := count(c2); n != 0 {
		t.Fatalf("%d rows of the refused 2-level chain were inserted", n)
	}
	// root-first, 4 levels: ONE statement, earlier rows visible to the trigger: ok.
	c4 := ids(4)
	if err := insert(c4, []int{0, 1, 2, 3}); err != nil {
		t.Fatalf("root-first 4-level insert: %v", err)
	}
	if n := count(c4); n != 4 {
		t.Fatalf("%d of 4 rows inserted", n)
	}
	// root-first, 5 levels: the depth cap (GT002), not the parent rule.
	c5b := ids(5)
	if err := insert(c5b, []int{0, 1, 2, 3, 4}); sqlState(err) != "GT002" {
		t.Fatalf("root-first 5-level insert = %v (SQLSTATE %q), want GT002", err, sqlState(err))
	}
	if n := count(c5b); n != 0 {
		t.Fatalf("%d rows of the too-deep chain were inserted", n)
	}
	// The store maps GT003 to the shared 409 error (a parent id that names nothing in this tenant).
	g := &MachineGroup{Name: "orphan"}
	missing := newUUID()
	g.ParentID = &missing
	if err := env.groups.CreateMachineGroup(ctx, env.tid, g); !errors.Is(err, ErrMachineGroupParentInvalid) {
		t.Fatalf("create under a missing parent = %v, want ErrMachineGroupParentInvalid", err)
	}
}
