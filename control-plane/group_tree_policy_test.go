package controlplane

// Session policy over a group tree (docs/62 D4, R4, R7) through the real handlers: the effective merge a
// policy editor reads, the refusals of a policy edit or a reparent that would leave an unsatisfiable merge,
// the runtime denial that backstops them at admission, and seat caps counted over a subtree at POST
// /sessions. The pure merge table is TestMergeGroupPolicies in group_tree_test.go. Tree as in
// group_tree_http_test.go (R -> P -> C -> G, R -> S, X).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func (x *treeHTTP) machineIn(group string) *Machine {
	x.t.Helper()
	m := &Machine{DeviceID: newUUID(), GroupID: group, Name: "m"}
	if err := x.machines.EnrollMachine(context.Background(), treeTenant, m); err != nil {
		x.t.Fatal(err)
	}
	return m
}

func (x *treeHTTP) setPolicy(group string, p GroupSessionPolicy) {
	x.t.Helper()
	if err := x.policies.Set(context.Background(), treeTenant, group, p); err != nil {
		x.t.Fatal(err)
	}
}

func TestEffectivePolicyIsServedBesideTheGroupsOwnRow(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{"owner": {RoleOwner, nil}}, nameScope, nil)
	tr := x.tr
	x.setPolicy(tr.P, GroupSessionPolicy{EnforceViewOnly: true, MaxSessionDurationSeconds: 1200, MaxConcurrentSessions: 4})
	x.setPolicy(tr.G, GroupSessionPolicy{MaxIdleSeconds: 300, MaxSessionDurationSeconds: 3600})
	rec := x.want("owner", "GET", "/machine-groups/"+tr.G+"/session-policy", nil, http.StatusOK, "GET G's policy")
	var out struct {
		GroupSessionPolicy
		Effective *EffectiveGroupPolicy `json:"effective"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// G's OWN row is unchanged at the top level (every pre-docs/62 key keeps its meaning)...
	if out.EnforceViewOnly || out.MaxSessionDurationSeconds != 3600 || out.MaxIdleSeconds != 300 {
		t.Errorf("own row = %+v, want G's stored values untouched", out.GroupSessionPolicy)
	}
	// ...and the effective merge shows what G is actually admitted under.
	e := out.Effective
	if e == nil || !e.EnforceViewOnly || e.MaxSessionDurationSeconds != 1200 || e.MaxIdleSeconds != 300 || e.MaxConcurrentSessions != 4 {
		t.Fatalf("effective = %+v, want view-only, duration 1200 (the parent's, tighter), idle 300, cap 4", e)
	}
	if len(e.SeatCaps) != 1 || e.SeatCaps[0].GroupID != tr.P || e.SeatCaps[0].Cap != 4 {
		t.Errorf("effective seat caps = %+v, want P's cap of 4", e.SeatCaps)
	}
	// The effective policy a SESSION is admitted under is the merge too (not G's exact row). G's own row is
	// rewritten with NO duration or idle limit, so the PASS4 duration refusal can only come from P's
	// inherited limit: an admission path that read G's exact row would admit.
	x.setPolicy(tr.G, GroupSessionPolicy{AllowBackstageUnderViewOnly: true})
	grant, _ := x.f.users.GrantFor(context.Background(), treeTenant, treeUID("owner"))
	m := x.machineIn(tr.G)
	_, ref := x.f.srv.resolveSessionAdmission(context.Background(), treeTenant, treeUID("owner"), grant, m, "control")
	if ref == nil || ref.Status != http.StatusForbidden || !strings.Contains(ref.Msg, "max_session_duration_seconds") {
		t.Fatalf("admission refusal = %+v, want the PASS4 duration refusal driven by the INHERITED limit", ref)
	}
}

func TestRecordingPolicyConflictsAreRefusedAndDeniedAtAdmission(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{"owner": {RoleOwner, nil}, "tech": {RoleTechnician, nil}}, nameScope, nil)
	tr := x.tr
	ctx := context.Background()
	put := func(group string, p map[string]any) int {
		return x.call("owner", "PUT", "/machine-groups/"+group+"/session-policy", p).Code
	}
	// A parent that REQUIRES recording: a child that PROHIBITS it is refused (409), not stored.
	x.setPolicy(tr.P, GroupSessionPolicy{RequireRecording: true})
	if code := put(tr.C, map[string]any{"prohibit_recording": true}); code != http.StatusConflict {
		t.Errorf("child prohibiting what its parent requires = %d, want 409", code)
	}
	if got, _ := x.policies.Get(ctx, treeTenant, tr.C); !got.IsDefault() {
		t.Errorf("the refused edit was stored: %+v", got)
	}
	// ...and so is a descendant FURTHER down (the check covers the whole subtree, not the direct child).
	if code := put(tr.G, map[string]any{"prohibit_recording": true}); code != http.StatusConflict {
		t.Errorf("grandchild prohibiting what its grandparent requires = %d, want 409", code)
	}
	// A compatible edit passes (require at both levels is not a conflict).
	if code := put(tr.C, map[string]any{"require_recording": true}); code != http.StatusOK {
		t.Errorf("child also requiring recording = %d, want 200", code)
	}
	// The REVERSE direction: requiring at a parent while a descendant prohibits.
	x.setPolicy(tr.P, GroupSessionPolicy{})
	x.setPolicy(tr.C, GroupSessionPolicy{})
	x.setPolicy(tr.G, GroupSessionPolicy{ProhibitRecording: true})
	if code := put(tr.P, map[string]any{"require_recording": true}); code != http.StatusConflict {
		t.Errorf("parent requiring recording over a prohibiting descendant = %d, want 409", code)
	}
	// A REPARENT that would combine them is refused too, and moves nothing.
	x.setPolicy(tr.G, GroupSessionPolicy{})
	x.setPolicy(tr.P, GroupSessionPolicy{RequireRecording: true})
	rec := x.want("owner", "POST", "/machine-groups", map[string]any{"name": "Z"}, http.StatusCreated, "create Z")
	z := decodeGroup(t, rec).ID
	x.setPolicy(z, GroupSessionPolicy{ProhibitRecording: true})
	x.want("owner", "POST", "/machine-groups/"+z+"/move", map[string]any{"parent_id": tr.P}, http.StatusConflict, "reparent that would conflict")
	if x.parentOf(z) != "" {
		t.Error("the refused reparent moved Z")
	}
	// ...while a policy-neutral group moves fine under the same parent.
	x.setPolicy(z, GroupSessionPolicy{})
	x.want("owner", "POST", "/machine-groups/"+z+"/move", map[string]any{"parent_id": tr.P}, http.StatusOK, "neutral reparent")

	// RUNTIME BACKSTOP: a conflict that got into the store anyway (a direct write, a pre-check race) DENIES
	// admission and grant minting with the reason; groups outside the conflicted chain are unaffected.
	x.setPolicy(tr.P, GroupSessionPolicy{RequireRecording: true})
	x.setPolicy(tr.C, GroupSessionPolicy{ProhibitRecording: true})
	for name, group := range map[string]string{"C": tr.C, "G (descendant of C)": tr.G} {
		m := x.machineIn(group)
		rec := x.call("tech", "POST", "/sessions", startSessionRequest{MachineID: m.DeviceID})
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "requires session recording at one level and prohibits it") {
			t.Errorf("admission into %s under an unsatisfiable merge = %d %s, want 409 with the conflict reason", name, rec.Code, rec.Body.String())
		}
	}
	mS := x.machineIn(tr.S)
	if rec := x.call("tech", "POST", "/sessions", startSessionRequest{MachineID: mS.DeviceID}); rec.Code != http.StatusCreated {
		t.Errorf("a machine outside the conflicted chain = %d %s, want 201", rec.Code, rec.Body.String())
	}
}

func TestSeatCapAtSessionStartCountsTheWholeSubtree(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{"owner": {RoleOwner, nil}, "tech": {RoleTechnician, nil}}, nameScope, nil)
	tr := x.tr
	ctx := context.Background()
	// P: ONE seat for its whole subtree. Written WITHOUT a duration, straight to the store (the legacy shape
	// the handler log calls "only reachable via direct store write"): a duration limit anywhere in the chain
	// is refused for unattended sessions by the PASS4 gate, which would mask the cap under test.
	x.setPolicy(tr.P, GroupSessionPolicy{MaxConcurrentSessions: 1})
	p2 := &MachineGroup{Name: "P2", ParentID: &tr.P}
	if err := x.groups.CreateMachineGroup(ctx, treeTenant, p2); err != nil {
		t.Fatal(err)
	}
	mC, mP2, mS := x.machineIn(tr.C), x.machineIn(p2.ID), x.machineIn(tr.S)
	start := func(m *Machine) (int, string) {
		rec := x.call("tech", "POST", "/sessions", startSessionRequest{MachineID: m.DeviceID})
		var out struct {
			Session SessionRecord `json:"session"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Session.ID
	}
	code, first := start(mC)
	if code != http.StatusCreated {
		t.Fatalf("first session under P's cap (in C) = %d, want 201", code)
	}
	// A session in the SIBLING subtree P2 shares P's seat: refused with the GROUP message.
	rec := x.call("tech", "POST", "/sessions", startSessionRequest{MachineID: mP2.DeviceID})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "machine group") {
		t.Fatalf("sibling session over P's shared cap = %d %s, want 409 group limit", rec.Code, rec.Body.String())
	}
	// S (outside P's subtree) is not counted.
	if code, _ := start(mS); code != http.StatusCreated {
		t.Fatalf("a session outside P's subtree = %d, want 201", code)
	}
	// Ending the first frees the seat for the sibling.
	x.want("tech", "POST", "/sessions/"+first+"/end", nil, http.StatusOK, "end the first session")
	if code, _ := start(mP2); code != http.StatusCreated {
		t.Fatalf("sibling session after the seat freed = %d, want 201", code)
	}
}
