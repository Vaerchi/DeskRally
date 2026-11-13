package controlplane

// "Forget this machine" (docs/65 sec. 8): an Owner's deliberate, irreversible end of a RETIRED machine whose
// removal will never be confirmed. Every scenario runs against the in-memory stores AND real Postgres ("fake and
// pg must agree"), through the real HTTP handlers; the only seams are the ones production has no HTTP route for
// (time passing, the step-up the console does through TOTP, a guard bypass that builds a state the guard forbids).
// Each test here fails without the behaviour it names.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---- helpers ------------------------------------------------------------------------------------------------

func (h *dirHarness) forgetPath(m dirMachine) string { return "/machines/" + m.ID + "/forget" }

// forgetBodyFor types the machine's current name, as the console's dialog makes the person do.
func (h *dirHarness) forgetBodyFor(m dirMachine) string {
	raw, _ := json.Marshal(map[string]string{"confirm": h.machine(m.ID).Name})
	return string(raw)
}

// forget posts the request as user with whatever step-up the caller already arranged.
func (h *dirHarness) forget(user string, m dirMachine) (int, map[string]any) {
	h.t.Helper()
	return h.do(user, "POST", h.forgetPath(m), h.forgetBodyFor(m))
}

// mustForget: a fresh step-up, then forget (what the dialog does); the answer must be 200 "forgotten".
func (h *dirHarness) mustForget(user string, m dirMachine) map[string]any {
	h.t.Helper()
	h.stepUp(user)
	code, out := h.forget(user, m)
	if code != http.StatusOK || str(out, "outcome") != "forgotten" {
		h.t.Fatalf("forget as %s = %d %v, want 200 forgotten", user, code, out)
	}
	return out
}

// newestAudit returns the newest audit event with the action, with its decoded metadata (nil when absent).
func (h *dirHarness) newestAudit(action string) (*MgmtAuditEvent, map[string]any) {
	h.t.Helper()
	ev, err := h.audit.ListEvents(context.Background(), h.tenant, 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	for i := range ev {
		if ev[i].Action == action {
			var meta map[string]any
			_ = json.Unmarshal(ev[i].Metadata, &meta)
			return &ev[i], meta
		}
	}
	return nil, nil
}

// removalAt builds an uninstall on a fresh RETIRED machine that is in `state` (every ACTIVE state a forget may meet).
func (h *dirHarness) removalAt(state DirectiveState) (dirMachine, string) {
	h.t.Helper()
	m := h.addMachineFn(h.group, MachineStatusRetired)
	id := h.mustRequestUninstall(h.owner, m)
	if state != DirectiveRequested {
		h.issueNow(id)
		switch state {
		case DirectiveIssued:
		case DirectiveAccepted:
			h.drive(id, m, "accepted")
		case DirectiveExecuting:
			h.drive(id, m, "accepted", "executing")
		case DirectiveRebootPending:
			h.drive(id, m, "accepted", "executing", "reboot_pending")
		case DirectiveRemovalUnconfirmed:
			h.drive(id, m, "accepted", "executing")
			h.advance(directiveUnconfirmedAfter + time.Minute)
			h.sweep()
		default:
			h.t.Fatalf("no builder for state %s", state)
		}
	}
	if got := h.row(id).State; got != state {
		h.t.Fatalf("built state %s, want %s", got, state)
	}
	return m, id
}

func machineJSON(out map[string]any) map[string]any {
	m, _ := out["machine"].(map[string]any)
	return m
}

func closedIDs(out map[string]any) []string {
	var ids []string
	list, _ := out["closed_directives"].([]any)
	for _, x := range list {
		ids = append(ids, str(x.(map[string]any), "id"))
	}
	return ids
}

// The route exists only where the directive feature is configured (DIRECTIVE_SIGNING_SEED wires the store, the issuer and
// the signaling notifier together): a control plane without it has no directive ledger to close and nothing to forget through.
func TestForgetIsNotMountedWithoutDirectives(t *testing.T) {
	h := newMemDirHarness(t)
	srv := NewServer(dirAuth{users: h.users, tenant: h.tenant, user: h.owner, sid: h.sessionFor(h.owner).ID}, NoopBinder{})
	srv.Machines = h.machines
	h.stepUp(h.owner)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", h.forgetPath(h.m), strings.NewReader(h.forgetBodyFor(h.m))))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unconfigured control plane answers %d to the forget route, want 404 (not mounted)", rec.Code)
	}
	if got := h.machine(h.m.ID).Status; got != MachineStatusRetired {
		t.Fatalf("machine %s", got)
	}
}

// ---- the happy path and its evidence ------------------------------------------------------------------------

// TestForgetClosesAnUnconfirmedRemoval is the feature: a removal that stayed removal_unconfirmed is ended by an
// Owner. The machine is the D-C9 tombstone, the directive stops being active (so the pending-removals panel
// stops listing it), and nothing says the agent confirmed anything.
func TestForgetClosesAnUnconfirmedRemoval(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		if _, ids, _ := h.activeList(h.owner, "?state=active"); len(ids) != 1 || ids[0] != id {
			t.Fatalf("before: the pending list = %v, want just the unconfirmed removal", ids)
		}
		ackedBefore := h.row(id).AckedAt
		auditBefore := h.auditActions()

		out := h.mustForget(h.owner, m)

		if got := str(machineJSON(out), "status"); got != MachineStatusRemoved {
			t.Fatalf("answer's machine status = %q, want removed", got)
		}
		if ids := closedIDs(out); len(ids) != 1 || ids[0] != id {
			t.Fatalf("closed_directives = %v, want [%s]", ids, id)
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine status = %s, want removed", got)
		}
		d := h.row(id)
		if d.State != DirectiveForgotten || d.StateDetail != forgottenDetail {
			t.Fatalf("directive = %s %q, want forgotten with the control plane's own words", d.State, d.StateDetail)
		}
		if d.State.active() {
			t.Fatal("a forgotten directive is still active")
		}
		// What the AGENT last reported is untouched: forgetting claims nothing on its behalf.
		if d.AgentState != DirectiveExecuting || !reflect.DeepEqual(d.AckedAt, ackedBefore) {
			t.Fatalf("agent_state=%s acked_at=%v (was %v): a forget rewrote what the agent reported", d.AgentState, d.AckedAt, ackedBefore)
		}
		if _, ids, _ := h.activeList(h.owner, "?state=active"); len(ids) != 0 {
			t.Fatalf("after: the pending list = %v, want it empty", ids)
		}
		// The machine's history still has it, now as forgotten.
		code, hist := h.do(h.owner, "GET", "/machines/"+m.ID+"/directives", "")
		rows, _ := hist["directives"].([]any)
		if code != http.StatusOK || len(rows) != 1 || str(rows[0].(map[string]any), "state") != "forgotten" {
			t.Fatalf("history = %d %v", code, hist)
		}

		// Audit: exactly these two rows, in this order, and NOTHING that reads as a confirmed removal.
		after := h.auditActions()
		if got := after[len(auditBefore):]; !reflect.DeepEqual(got, []string{"machine.forgotten", "directive.forgotten"}) {
			t.Fatalf("audit rows written = %v, want [machine.forgotten directive.forgotten]", got)
		}
		if h.auditCount("machine.removed") != 0 || h.auditCount("directive.complete") != 0 {
			t.Fatalf("a forget wrote a confirmed-removal row: %v", after)
		}
		ev, meta := h.newestAudit("machine.forgotten")
		if ev.ActorUserID != h.owner || ev.TargetKind != "machine" || ev.TargetID != m.ID {
			t.Fatalf("machine.forgotten = actor %q target %s/%s, want the owner and the machine", ev.ActorUserID, ev.TargetKind, ev.TargetID)
		}
		wantKey := fingerprintOf(m.Pub)
		if meta["agent_confirmed"] != false || str(meta, "previous_status") != "retired" || str(meta, "machine_id") != m.ID ||
			str(meta, "device_id") != m.Device || str(meta, "group_id") != h.group || str(meta, "key_fp") != wantKey {
			t.Fatalf("machine.forgotten metadata = %v", meta)
		}
		closed, _ := meta["closed_directives"].([]any)
		if len(closed) != 1 {
			t.Fatalf("machine.forgotten closed_directives = %v, want the one removal", meta["closed_directives"])
		}
		c := closed[0].(map[string]any)
		if str(c, "directive_id") != id || str(c, "kind") != "uninstall" || str(c, "state") != "removal_unconfirmed" {
			t.Fatalf("closed directive = %v, want the unconfirmed uninstall", c)
		}
		dev, dmeta := h.newestAudit("directive.forgotten")
		if dev.ActorUserID != h.owner || dev.TargetKind != "agent_directive" || dev.TargetID != id {
			t.Fatalf("directive.forgotten = actor %q target %s/%s", dev.ActorUserID, dev.TargetKind, dev.TargetID)
		}
		if str(dmeta, "from") != "removal_unconfirmed" || str(dmeta, "state") != "forgotten" || dmeta["agent_confirmed"] != false ||
			str(dmeta, "reason") != "machine_forgotten" || dmeta["actor_kind"] != nil {
			t.Fatalf("directive.forgotten metadata = %v", dmeta)
		}
	})
}

// A retired machine with no directive at all (it was retired and is simply gone) is forgotten too.
func TestForgetAMachineWithNoDirective(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		before := h.auditActions()
		out := h.mustForget(h.owner, h.m)
		if ids := closedIDs(out); len(ids) != 0 {
			t.Fatalf("closed_directives = %v, want none", ids)
		}
		if _, isList := out["closed_directives"].([]any); !isList {
			t.Fatalf("closed_directives must be a list even when empty: %v", out["closed_directives"])
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("status = %s", got)
		}
		if got := h.auditActions()[len(before):]; !reflect.DeepEqual(got, []string{"machine.forgotten"}) {
			t.Fatalf("audit rows written = %v, want [machine.forgotten]", got)
		}
		_, meta := h.newestAudit("machine.forgotten")
		if _, has := meta["closed_directives"]; has {
			t.Fatalf("machine.forgotten lists closed directives for a machine with none: %v", meta)
		}
	})
}

// Every ACTIVE directive state ends as forgotten in the same transaction as the tombstone (the pg trigger
// machine_directive_guard would refuse the tombstone while any of them is still active).
func TestForgetClosesEveryActiveDirectiveState(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		for _, st := range []DirectiveState{DirectiveRequested, DirectiveIssued, DirectiveAccepted, DirectiveExecuting,
			DirectiveRebootPending, DirectiveRemovalUnconfirmed} {
			m, id := h.removalAt(st)
			h.mustForget(h.owner, m)
			if d := h.row(id); d.State != DirectiveForgotten {
				t.Fatalf("%s: directive ended as %s, want forgotten", st, d.State)
			}
			if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
				t.Fatalf("%s: machine %s, want removed", st, got)
			}
			_, meta := h.newestAudit("directive.forgotten")
			if str(meta, "from") != string(st) {
				t.Fatalf("%s: directive.forgotten says from=%q", st, str(meta, "from"))
			}
		}
		if _, ids, _ := h.activeList(h.owner, "?state=active"); len(ids) != 0 {
			t.Fatalf("directives still active after every forget: %v", ids)
		}
		// A pending REINSTALL too (the machine guard forbids retiring a machine with an active directive, so
		// build the state the guard would refuse: the closure must not depend on it never happening).
		m := h.addMachineFn(h.group, MachineStatusActive)
		code, out := h.request(h.owner, "reinstall", m)
		if code != http.StatusCreated {
			t.Fatalf("reinstall request = %d %v", code, out)
		}
		rid := dirIDOf(out)
		h.bypassGuard(func() {
			if h.pg {
				h.rawSQL(`UPDATE machine SET status = 'retired' WHERE id = $1`, m.ID)
			} else if err := h.machines.SetMachineStatus(context.Background(), h.tenant, m.ID, MachineStatusRetired); err != nil {
				t.Fatal(err)
			}
		})
		h.mustForget(h.owner, m)
		if d := h.row(rid); d.State != DirectiveForgotten || d.Kind != DirectiveReinstall {
			t.Fatalf("reinstall ended as %s/%s, want a forgotten reinstall", d.Kind, d.State)
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s", got)
		}
	})
}

// ---- who may, when, and with what proof ---------------------------------------------------------------------

func TestForgetPermissionMatrix(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		active := h.addMachineFn(h.group, MachineStatusActive)
		quarantined := h.addMachineFn(h.group, MachineStatusQuarantined)
		elsewhere := h.scopedOwner("elsewhere", h.otherGroup)
		auditBefore := h.auditActions()
		refused := func(what string, code int, out map[string]any, want int) {
			t.Helper()
			if code != want {
				t.Fatalf("%s = %d %v, want %d", what, code, out, want)
			}
		}
		step := func(u string) { h.stepUp(u) }

		// Roles without remove_agent: a fresh second factor does not substitute for the capability.
		for name, u := range map[string]string{"admin": h.admin, "technician": h.tech, "readonly": h.ro} {
			step(u)
			code, out := h.forget(u, h.m)
			refused(name, code, out, http.StatusForbidden)
		}
		// An Owner scoped to a DIFFERENT group has no authority over this machine's group.
		step(elsewhere)
		code, out := h.forget(elsewhere, h.m)
		refused("owner scoped to another group", code, out, http.StatusForbidden)
		// API-token principals: one holding every grantable capability, and one somehow carrying remove_agent
		// (no session, so not interactive).
		all := h.newServer(tokenAuth{tenant: h.tenant, caps: APITokenGrantableCapabilities()})
		code, out = h.doOn(all, "POST", h.forgetPath(h.m), h.forgetBodyFor(h.m), "")
		refused("token with every grantable capability", code, out, http.StatusForbidden)
		withCap := h.newServer(tokenAuth{tenant: h.tenant, caps: []Capability{CapRemoveAgent, CapViewMachines}})
		code, out = h.doOn(withCap, "POST", h.forgetPath(h.m), h.forgetBodyFor(h.m), "")
		refused("token carrying remove_agent", code, out, http.StatusForbidden)
		if !strings.Contains(strings.ToLower(str(out, "error")), "interactive") {
			t.Fatalf("token carrying remove_agent: %v, want the interactive-session refusal", out)
		}
		// Another tenant's Owner: the id answers exactly like a missing one.
		step(h.erin)
		code, out = h.forget(h.erin, h.m)
		refused("another tenant's owner", code, out, http.StatusNotFound)
		crossTenant := out
		code, out = h.do(h.owner, "POST", "/machines/"+newUUID()+"/forget", `{"confirm":"x"}`)
		refused("unknown machine id", code, out, http.StatusNotFound)
		if !reflect.DeepEqual(out, crossTenant) {
			t.Fatalf("a cross-tenant id answers %v, a missing one %v: they must be identical", crossTenant, out)
		}
		code, out = h.do(h.owner, "POST", "/machines/not-a-uuid/forget", `{"confirm":"x"}`)
		refused("non-uuid machine id", code, out, http.StatusNotFound)

		// Step-up: absent, then stale (and just inside the bound is fine, below).
		code, out = h.forget(h.owner2, h.m)
		if code != http.StatusForbidden || str(out, "code") != "step_up_required" {
			t.Fatalf("no step-up = %d %v, want 403 step_up_required", code, out)
		}
		step(h.owner)
		h.ageStepUp(h.owner, directiveStepUpMaxAge+time.Minute)
		code, out = h.forget(h.owner, h.m)
		if code != http.StatusForbidden || str(out, "code") != "step_up_required" {
			t.Fatalf("stale step-up = %d %v, want 403 step_up_required", code, out)
		}

		// The typed confirmation: empty, wrong, a prefix, another machine's name.
		step(h.owner)
		for _, confirm := range []string{"", "   ", "nope", h.machine(h.m.ID).Name[:3], h.machine(active.ID).Name} {
			raw, _ := json.Marshal(map[string]string{"confirm": confirm})
			code, out := h.do(h.owner, "POST", h.forgetPath(h.m), string(raw))
			refused("confirm "+confirm, code, out, http.StatusUnprocessableEntity)
		}
		// A malformed body.
		code, out = h.do(h.owner, "POST", h.forgetPath(h.m), `{"confirm":`)
		refused("malformed body", code, out, http.StatusBadRequest)

		// Only a RETIRED machine: active and quarantined are still in service (retire first, then forget).
		for name, m := range map[string]dirMachine{"active": active, "quarantined": quarantined} {
			code, out := h.forget(h.owner, m)
			refused(name+" machine", code, out, http.StatusConflict)
			if !strings.Contains(str(out, "error"), "retired") {
				t.Fatalf("%s machine: %v, want the retire-first reason", name, out)
			}
			if got := h.machine(m.ID).Status; got == MachineStatusRemoved {
				t.Fatalf("%s machine was removed", name)
			}
		}

		// NOTHING above changed anything: the machine is still retired and no audit row was written.
		if got := h.machine(h.m.ID); got.Status != MachineStatusRetired {
			t.Fatalf("a refused forget changed the machine: %s", got.Status)
		}
		if after := h.auditActions(); !reflect.DeepEqual(after, auditBefore) {
			t.Fatalf("refused forgets wrote audit rows: %v", after[len(auditBefore):])
		}

		// Just inside the step-up bound, with the machine's name, an Owner may.
		step(h.owner)
		h.ageStepUp(h.owner, directiveStepUpMaxAge-time.Minute)
		if code, out := h.forget(h.owner, h.m); code != http.StatusOK || str(out, "outcome") != "forgotten" {
			t.Fatalf("owner with a step-up just inside the bound = %d %v, want 200", code, out)
		}
	})
}

// An Owner whose scope covers the machine's group (own or inherited from a parent) may; the alias also confirms.
func TestForgetAllowsAScopedOwnerAndTheAlias(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		own := h.scopedOwner("own", h.group)
		h.stepUp(own)
		if code, out := h.forget(own, h.m); code != http.StatusOK || str(out, "outcome") != "forgotten" {
			t.Fatalf("owner scoped to the machine's group = %d %v, want 200", code, out)
		}
		// The tenant's alias is accepted exactly like the hostname (the uninstall dialog's rule).
		m2 := h.addMachineFn(h.group, MachineStatusRetired)
		if err := h.machines.SetMachineAlias(context.Background(), h.tenant, m2.ID, "Old reception"); err != nil {
			t.Fatal(err)
		}
		h.stepUp(h.owner)
		raw, _ := json.Marshal(map[string]string{"confirm": "  Old reception "})
		if code, out := h.do(h.owner, "POST", h.forgetPath(m2), string(raw)); code != http.StatusOK || str(out, "outcome") != "forgotten" {
			t.Fatalf("alias confirmation = %d %v, want 200", code, out)
		}
		// A different case is a different name.
		m3 := h.addMachineFn(h.group, MachineStatusRetired)
		raw, _ = json.Marshal(map[string]string{"confirm": strings.ToUpper(h.machine(m3.ID).Name)})
		if code, out := h.do(h.owner, "POST", h.forgetPath(m3), string(raw)); code != http.StatusUnprocessableEntity {
			t.Fatalf("a name in the wrong case = %d %v, want 422", code, out)
		}
	})
}

// Group scope follows the machine's CURRENT group: a machine moved out of the caller's scope after they authorized
// is refused by the store under its lock (a retry shows the 403).
func TestForgetRefusesAMachineThatMovedGroupsSinceTheCallerAuthorized(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		ctx := context.Background()
		if err := h.machines.SetMachineGroup(ctx, h.tenant, h.m.ID, h.otherGroup); err != nil {
			t.Fatal(err)
		}
		_, err := h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{MachineID: h.m.ID, ActorID: h.owner, ExpectGroupID: h.group})
		if !errors.Is(err, ErrDirectiveMachineChanged) {
			t.Fatalf("ForgetMachine for a machine that moved = %v, want ErrDirectiveMachineChanged", err)
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRetired {
			t.Fatalf("a refused forget changed the machine: %s", got)
		}
		// Scope is judged on the CURRENT group by the handler: an Owner scoped to the OLD group is now refused.
		old := h.scopedOwner("old", h.group)
		h.stepUp(old)
		if code, out := h.forget(old, h.m); code != http.StatusForbidden {
			t.Fatalf("owner scoped to the machine's OLD group = %d %v, want 403", code, out)
		}
	})
}

// ---- idempotency --------------------------------------------------------------------------------------------

func TestForgetIsIdempotent(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		h.mustForget(h.owner, m)
		before := h.auditActions()
		dirBefore := *h.row(id)

		// A retry (the first answer was lost): the current state, no second audit row, nothing rewritten - with
		// the same proof, with NO step-up left, and even with a wrong typed name (nothing is being changed).
		h.ageStepUp(h.owner, 24*time.Hour)
		for _, body := range []string{h.forgetBodyFor(m), `{"confirm":"not the name"}`} {
			code, out := h.do(h.owner, "POST", h.forgetPath(m), body)
			if code != http.StatusOK || str(out, "outcome") != "already_removed" || str(machineJSON(out), "status") != MachineStatusRemoved {
				t.Fatalf("second forget = %d %v, want 200 already_removed", code, out)
			}
			if ids := closedIDs(out); len(ids) != 0 {
				t.Fatalf("a second forget reports closed directives %v", ids)
			}
		}
		if after := h.auditActions(); !reflect.DeepEqual(after, before) {
			t.Fatalf("a second forget wrote audit rows: %v", after[len(before):])
		}
		if d := h.row(id); !reflect.DeepEqual(*d, dirBefore) {
			t.Fatalf("a second forget rewrote the directive: %+v -> %+v", dirBefore, *d)
		}
		// It tells nothing to a caller who may not act on the machine.
		h.stepUp(h.admin)
		if code, out := h.forget(h.admin, m); code != http.StatusForbidden {
			t.Fatalf("admin on a removed machine = %d %v, want 403", code, out)
		}
		// The store itself is idempotent too.
		res, err := h.dirs.ForgetMachine(context.Background(), h.tenant, ForgetMachineInput{MachineID: m.ID, ActorID: h.owner, ExpectGroupID: h.group})
		if err != nil || !res.AlreadyRemoved || len(res.Closed) != 0 {
			t.Fatalf("store ForgetMachine on a removed machine = %+v %v", res, err)
		}
	})
}

// A machine already removed by a CONFIRMED removal is "already removed" too, and stays confirmed: the directive
// is still `complete`, never rewritten to forgotten.
func TestForgetAfterAConfirmedRemovalChangesNothing(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		if code, out := h.finalAck(id, h.m.Priv, "executing", "complete"); code != 200 || str(out, "outcome") != "applied" {
			t.Fatalf("confirmed removal = %d %v", code, out)
		}
		before := h.auditActions()
		h.stepUp(h.owner)
		code, out := h.forget(h.owner, h.m)
		if code != http.StatusOK || str(out, "outcome") != "already_removed" {
			t.Fatalf("forget after a confirmed removal = %d %v, want 200 already_removed", code, out)
		}
		if h.row(id).State != DirectiveComplete {
			t.Fatalf("the confirmed directive became %s", h.row(id).State)
		}
		if after := h.auditActions(); !reflect.DeepEqual(after, before) {
			t.Fatalf("audit rows written: %v", after[len(before):])
		}
	})
}

// ---- the tombstone is EXACTLY the confirmed removal's ----------------------------------------------------------

func TestForgetAppliesTheTombstoneAMachineRemovalDoes(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		ctx := context.Background()
		id, m := h.unconfirmedRemoval()
		h.mustForget(h.owner, m)

		// Registration: the identity lookup signaling asks refuses the device (ordinary and restricted mode alike),
		// and nothing can be fetched or acknowledged for it.
		for _, restricted := range []bool{false, true} {
			if code, _ := h.identity(m.Device, restricted); code != http.StatusNotFound {
				t.Fatalf("identity of a forgotten machine (restricted=%v) = %d, want 404", restricted, code)
			}
		}
		if _, err := h.machines.LookupDeviceIdentity(ctx, m.Device); !errors.Is(err, ErrMachineNotFound) {
			t.Fatalf("LookupDeviceIdentity = %v, want ErrMachineNotFound", err)
		}
		if code, _ := h.internal("GET", "/internal/devices/"+m.Device+"/directives/pending", ""); code != http.StatusNotFound {
			t.Fatalf("pending directives of a forgotten machine = %d, want 404", code)
		}
		if code, _ := h.internal("POST", "/internal/directives/"+id+"/ack", h.ackJSON(id, m, m.Priv, "executing", "complete", "", h.nextAckTime())); code != http.StatusNotFound {
			t.Fatalf("a signaling ack for a forgotten machine = %d, want 404", code)
		}
		// Enrollment of the key, and attended redeem with it.
		if code, _ := h.redeemEnrollment(m.Pub); code != http.StatusForbidden {
			t.Fatalf("enrollment with the forgotten machine's key = %d, want 403", code)
		}
		if tomb, err := h.machines.KeyTombstoned(ctx, m.Pub); err != nil || !tomb {
			t.Fatalf("KeyTombstoned = %v %v, want true", tomb, err)
		}
		rec := &recAttendedRedeem{}
		srv := h.srv(h.owner)
		srv.Attended = rec
		body := `{"code":"ABCD-EFGH","pubkey":"` + m.Pub + `","name":"guest"}`
		if code, out := h.doOn(srv, "POST", "/attended-sessions/redeem", body, ""); code != http.StatusForbidden || rec.calls != 0 {
			t.Fatalf("attended redeem with the forgotten key = %d %v (store calls %d), want 403", code, out, rec.calls)
		}
		// A reinstall enrolls ONLY as a NEW machine, through a fresh token and a new key.
		_, freshPub := newDirKey(t)
		code, out := h.redeemEnrollment(freshPub)
		if code != http.StatusCreated {
			t.Fatalf("enrollment with a fresh key = %d %v, want 201", code, out)
		}
		fresh := machineJSON(out)
		if str(fresh, "id") == m.ID || str(fresh, "device_id") == m.Device {
			t.Fatalf("a reinstall enrolled as the forgotten machine: %v", fresh)
		}
		// Terminal: nothing brings it back, and no directive can be requested on it.
		for _, st := range []string{MachineStatusActive, MachineStatusQuarantined, MachineStatusRetired} {
			if err := h.machines.SetMachineStatus(ctx, h.tenant, m.ID, st); !errors.Is(err, ErrMachineRemoved) {
				t.Fatalf("SetMachineStatus(%s) on a forgotten machine = %v, want ErrMachineRemoved", st, err)
			}
		}
		if code, out := h.do(h.owner, "POST", "/machines/"+m.ID+"/status", `{"status":"active"}`); code != http.StatusConflict {
			t.Fatalf("un-retire through the API = %d %v, want 409", code, out)
		}
		for _, kind := range []string{"uninstall", "reinstall"} {
			if code, out := h.request(h.owner, kind, m); code != http.StatusConflict {
				t.Fatalf("%s request on a forgotten machine = %d %v, want 409", kind, code, out)
			}
		}
		// The device id and the key stay on the row (that is what makes the tombstone a tombstone).
		if got := h.machine(m.ID); got.DeviceID != m.Device || got.Pubkey != m.Pub {
			t.Fatalf("the tombstone lost the device id or key: %+v", got)
		}
	})
}

// A cancel or an approval aimed at the closed directive is refused like any finished directive.
func TestForgottenDirectivesAreFinished(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.mustForget(h.owner, h.m)
		if code, out := h.do(h.owner, "POST", "/directives/"+id+"/cancel", ""); code != http.StatusConflict {
			t.Fatalf("cancel of a forgotten directive = %d %v, want 409", code, out)
		}
		h.stepUp(h.owner2)
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", ""); code != http.StatusConflict {
			t.Fatalf("approve of a forgotten directive = %d %v, want 409", code, out)
		}
		h.advance(2 * directiveRequestTTL)
		h.sweep()
		if d := h.row(id); d.State != DirectiveForgotten || d.Artifact != "" {
			t.Fatalf("the sweeper moved a forgotten directive: %+v", d)
		}
		code, out := h.do(h.owner, "GET", "/directives/"+id, "")
		if code != http.StatusOK || dirStateOf(out) != "forgotten" {
			t.Fatalf("GET /directives/{id} = %d %v", code, out)
		}
	})
}

// ---- atomicity ----------------------------------------------------------------------------------------------

// Audit first: with the audit store down the forget fails, and the machine and its directive are exactly as they
// were (the audit rows, the directive closure and the tombstone commit together or not at all).
func TestForgetIsAtomicWhenTheAuditStoreFails(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		before := *h.row(id)
		h.stepUp(h.owner)
		h.failAudit(true)
		code, out := h.forget(h.owner, m)
		h.failAudit(false)
		if code != http.StatusInternalServerError {
			t.Fatalf("forget with a failing audit store = %d %v, want 500", code, out)
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRetired {
			t.Fatalf("machine %s after a failed forget, want retired", got)
		}
		if d := h.row(id); !reflect.DeepEqual(*d, before) {
			t.Fatalf("the directive changed under a failed forget: %+v -> %+v", before, *d)
		}
		if _, ids, _ := h.activeList(h.owner, "?state=active"); len(ids) != 1 {
			t.Fatalf("the removal left the pending list: %v", ids)
		}
		// Nothing half-written: the retry works and writes exactly one set of rows.
		h.mustForget(h.owner, m)
		if h.auditCount("machine.forgotten") != 1 || h.auditCount("directive.forgotten") != 1 {
			t.Fatalf("audit = %v", h.auditActions())
		}
	})
}

// The audit rows of one forget are all-or-nothing: with the SECOND append (directive.forgotten, after
// machine.forgotten already went in) refused, no audit row survives, the machine is not tombstoned, the
// directive is untouched, and the retry writes exactly one set of rows. Both backends (the fake must roll back
// the rows it already appended, as the pg transaction does).
func TestForgetIsAtomicWhenALaterAuditAppendFails(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		before := *h.row(id)
		auditBefore := h.auditActions()
		h.stepUp(h.owner)
		h.failAuditAction("directive.forgotten")
		code, out := h.forget(h.owner, m)
		h.failAuditAction("")
		if code != http.StatusInternalServerError {
			t.Fatalf("forget with the 2nd audit append failing = %d %v, want 500", code, out)
		}
		if got := h.auditActions(); !reflect.DeepEqual(got, auditBefore) {
			t.Fatalf("audit rows survived a failed forget: %v -> %v", auditBefore, got)
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRetired {
			t.Fatalf("machine %s after a failed forget, want retired", got)
		}
		if d := h.row(id); !reflect.DeepEqual(*d, before) {
			t.Fatalf("the directive changed under a failed forget: %+v -> %+v", before, *d)
		}
		h.mustForget(h.owner, m)
		if h.auditCount("machine.forgotten") != 1 || h.auditCount("directive.forgotten") != 1 {
			t.Fatalf("retry audit = %v", h.auditActions())
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s after the retry, want removed", got)
		}
	})
}

// ---- the store contract (both backends, no HTTP) -----------------------------------------------------------

func TestForgetMachineStoreContract(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		ctx := context.Background()
		baseline := len(h.auditActions())
		in := func(m dirMachine) ForgetMachineInput {
			return ForgetMachineInput{MachineID: m.ID, ActorID: h.owner, ExpectGroupID: h.group}
		}
		// Unknown, malformed and another tenant's id are all "not found".
		for name, mid := range map[string]string{"unknown": newUUID(), "malformed": "not-a-uuid", "empty": ""} {
			if _, err := h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{MachineID: mid, ActorID: h.owner, ExpectGroupID: h.group}); !errors.Is(err, ErrMachineNotFound) {
				t.Fatalf("%s machine id = %v, want ErrMachineNotFound", name, err)
			}
		}
		if _, err := h.dirs.ForgetMachine(ctx, h.alien, in(h.m)); !errors.Is(err, ErrMachineNotFound) {
			t.Fatalf("another tenant's machine = %v, want ErrMachineNotFound", err)
		}
		// Active and quarantined machines are refused, and nothing is written.
		for _, st := range []string{MachineStatusActive, MachineStatusQuarantined} {
			m := h.addMachineFn(h.group, st)
			if _, err := h.dirs.ForgetMachine(ctx, h.tenant, in(m)); !errors.Is(err, ErrForgetNotRetired) {
				t.Fatalf("%s machine = %v, want ErrForgetNotRetired", st, err)
			}
			if got := h.machine(m.ID).Status; got != st {
				t.Fatalf("a refused forget moved a %s machine to %s", st, got)
			}
		}
		if n := len(h.auditActions()); n != baseline {
			t.Fatalf("refusals wrote %d audit rows", n-baseline)
		}
		// A retired machine moved to another group since the caller authorized.
		if _, err := h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{MachineID: h.m.ID, ActorID: h.owner, ExpectGroupID: h.otherGroup}); !errors.Is(err, ErrDirectiveMachineChanged) {
			t.Fatalf("wrong expected group = %v, want ErrDirectiveMachineChanged", err)
		}
		// The real thing, with an active directive: it is closed and returned as it is now.
		id := h.mustRequestUninstall(h.owner, h.m)
		res, err := h.dirs.ForgetMachine(ctx, h.tenant, in(h.m))
		if err != nil || res.AlreadyRemoved || len(res.Closed) != 1 {
			t.Fatalf("ForgetMachine = %+v %v", res, err)
		}
		if c := res.Closed[0]; c.ID != id || c.State != DirectiveForgotten || c.StateDetail != forgottenDetail || c.Artifact != "" {
			t.Fatalf("closed directive = %+v", c)
		}
		if got := h.row(id); got.State != DirectiveForgotten || got.StateDetail != forgottenDetail {
			t.Fatalf("stored directive = %+v", got)
		}
	})
}

// ---- no agent can reach or leave `forgotten` ---------------------------------------------------------------

// forgotten is the control plane's own state, like removal_unconfirmed: it is neither a source nor a target of any
// acknowledgement an agent may send, so a directive can never be moved into it or back out of it by a report.
func TestNoAcknowledgementCanReachOrLeaveForgotten(t *testing.T) {
	all := []DirectiveState{DirectiveRequested, DirectiveIssued, DirectiveAccepted, DirectiveExecuting, DirectiveRebootPending,
		DirectiveComplete, DirectiveFailed, DirectiveRemovalUnconfirmed, DirectiveCancelled, DirectiveExpired, DirectiveForgotten}
	for _, s := range all {
		if directiveTransitionAllowed(DirectiveForgotten, s) {
			t.Fatalf("forgotten -> %s is an allowed transition", s)
		}
		if directiveTransitionAllowed(s, DirectiveForgotten) {
			t.Fatalf("%s -> forgotten is an allowed transition", s)
		}
	}
	if DirectiveForgotten.active() {
		t.Fatal("forgotten counts as active")
	}
	if finalAckWindowOpen(DirectiveForgotten, time.Now(), time.Now()) {
		t.Fatal("the final-ack window is open for a forgotten directive")
	}
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		// An agent that names forgotten as the target of an issued directive is refused (and moves nothing)...
		if code, out := h.ack(id, h.m, "issued", "forgotten"); code != http.StatusConflict {
			t.Fatalf("issued -> forgotten = %d %v, want 409", code, out)
		}
		if h.row(id).State != DirectiveIssued {
			t.Fatalf("state %s", h.row(id).State)
		}
		h.mustForget(h.owner, h.m)
		// ...and one that names it as the source of a revival is refused too.
		for _, to := range []string{"accepted", "executing", "complete", "failed"} {
			if code, out := h.ack(id, h.m, "forgotten", to); code != http.StatusNotFound {
				t.Fatalf("forgotten -> %s = %d %v, want 404 (the device no longer resolves)", to, code, out)
			}
		}
		// Straight at the store, bypassing the handler's device lookup: refused, nothing applied.
		d := h.row(id)
		for _, c := range [][2]string{{"forgotten", "executing"}, {"issued", "forgotten"}, {"forgotten", "complete"}} {
			ack, err := SignDirectiveAck(h.m.Priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, c[0], c[1], h.nextAckTime().UnixMilli(), "")
			if err != nil {
				t.Fatal(err)
			}
			if _, applied, err := h.dirs.ApplyAck(context.Background(), h.tenant, id, h.m.Device, ack); applied || !errors.Is(err, ErrDirectiveBadTransition) {
				t.Fatalf("store ApplyAck %v = applied %v err %v, want ErrDirectiveBadTransition", c, applied, err)
			}
		}
		if got := h.row(id); got.State != DirectiveForgotten {
			t.Fatalf("state %s after the refused acknowledgements", got.State)
		}
	})
}

// An agent never RECEIVES `forgotten` either. A directive reaches a device only as its signed artifact, relayed from
// PendingForDevice, and only while it is issued (unexpired), accepted, executing or reboot_pending. A directive closed by a
// forget KEEPS its artifact (the evidence of what was signed, and when), so it is the STATE that keeps it from the device:
// the store itself must stop serving it, whatever the device lookup in front of the route says (that lookup now refuses the
// machine too, which is why this asks the store directly).
func TestAForgottenDirectiveIsNeverServedToADevice(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		ctx := context.Background()
		for _, st := range []DirectiveState{DirectiveIssued, DirectiveAccepted, DirectiveExecuting, DirectiveRebootPending} {
			m, id := h.removalAt(st)
			keyFP := h.row(id).KeyFP
			// The control: until the forget the device IS served this directive, so the empty answer below means something.
			if served, err := h.dirs.PendingForDevice(ctx, h.tenant, m.Device, keyFP); err != nil || len(served) != 1 || served[0].ID != id || served[0].Artifact == "" {
				t.Fatalf("%s: before the forget PendingForDevice = %+v %v, want the one directive with its artifact", st, served, err)
			}
			if got := h.pending(m.Device); len(got) != 1 || str(got[0], "directive_id") != id {
				t.Fatalf("%s: before the forget the pending route serves %v, want the directive", st, got)
			}
			h.mustForget(h.owner, m)
			if d := h.row(id); d.State != DirectiveForgotten || d.Artifact == "" {
				t.Fatalf("%s: directive = %s with artifact %v, want forgotten with its artifact kept as evidence", st, d.State, d.Artifact != "")
			}
			if served, err := h.dirs.PendingForDevice(ctx, h.tenant, m.Device, keyFP); err != nil || len(served) != 0 {
				t.Fatalf("%s: a forgotten directive is still served to the device: %+v %v", st, served, err)
			}
			// Delivery bookkeeping cannot bring it back or touch it either.
			updatedBefore := h.row(id).UpdatedAt
			if err := h.dirs.MarkDelivered(ctx, h.tenant, id, m.Device); err != nil {
				t.Fatalf("%s: MarkDelivered on a forgotten directive = %v", st, err)
			}
			if d := h.row(id); d.State != DirectiveForgotten || !d.UpdatedAt.Equal(updatedBefore) {
				t.Fatalf("%s: MarkDelivered rewrote a forgotten directive: %+v", st, d)
			}
		}
	})
}

// ---- the agent's LATE final acknowledgement ----------------------------------------------------------------

// The agent really did finish the removal, and its signed final ack arrives AFTER an Owner forgot the machine. It
// must not resurrect anything (the directive stays forgotten, the machine stays removed, no row is written) and
// must not be told it was confirmed: 410, a terminal "not confirmed" to the agent.
func TestLateFinalAckAfterForgetIsSafeAndTruthful(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		h.mustForget(h.owner, m)
		before := h.auditActions()
		dirBefore := *h.row(id)
		const closedWords = "closed when an owner forgot the machine"
		for _, c := range [][2]string{{"executing", "complete"}, {"executing", "failed"}, {"accepted", "complete"},
			{"executing", "reboot_pending"}, {"executing", "bogus"}} {
			code, out := h.finalAck(id, m.Priv, c[0], c[1])
			if code != http.StatusGone || !strings.Contains(str(out, "error"), closedWords) || out["outcome"] != nil || out["state"] != nil {
				t.Fatalf("late final ack %v = %d %v, want 410 naming the forget and no outcome/state", c, code, out)
			}
		}
		// An exact resend of the body the agent persists: still 410 (never a replay, which would read as confirmed).
		same := h.faBody(id, m.Priv, "executing", "complete", "msi exit 0", h.nextAckTime())
		for i := 0; i < 2; i++ {
			if code, out := finalAckOn(t, h.srv(h.owner), id, same); code != http.StatusGone || out["outcome"] != nil {
				t.Fatalf("resend %d = %d %v", i, code, out)
			}
		}
		// A caller that has NOT proven the device key still gets the one generic answer.
		stranger, _ := newDirKey(t)
		if code, out := h.finalAck(id, stranger, "executing", "complete"); code != http.StatusNotFound || str(out, "error") != "unknown directive" || len(out) != 1 {
			t.Fatalf("a stranger's ack = %d %v, want the generic 404", code, out)
		}
		// Nothing moved, nothing was written, and the tombstone is untouched.
		if d := h.row(id); !reflect.DeepEqual(*d, dirBefore) {
			t.Fatalf("a late ack changed the directive: %+v -> %+v", dirBefore, *d)
		}
		if after := h.auditActions(); !reflect.DeepEqual(after, before) {
			t.Fatalf("a late ack wrote audit rows: %v", after[len(before):])
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s", got)
		}
		for _, restricted := range []bool{false, true} {
			if code, _ := h.identity(m.Device, restricted); code != http.StatusNotFound {
				t.Fatalf("identity resolves after a late ack (restricted=%v) = %d", restricted, code)
			}
		}
		if code, _ := h.redeemEnrollment(m.Pub); code != http.StatusForbidden {
			t.Fatalf("enrollment with the key after a late ack = %d, want 403", code)
		}
		// The store refuses on BOTH channels, so no future route can resurrect it by accident.
		d := h.row(id)
		ack, err := SignDirectiveAck(m.Priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, "executing", "complete", h.nextAckTime().UnixMilli(), "")
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if _, applied, err := h.dirs.ApplyAck(ctx, h.tenant, id, m.Device, ack); applied || !errors.Is(err, ErrDirectiveBadTransition) {
			t.Fatalf("ApplyAck (signaling path) = applied %v err %v, want ErrDirectiveBadTransition", applied, err)
		}
		if _, applied, err := h.dirs.ApplyAckVia(ctx, h.tenant, id, m.Device, ack, directiveFinalAckChannel); applied || !errors.Is(err, ErrDirectiveFinalAckWindowClosed) {
			t.Fatalf("ApplyAckVia (final-ack) = applied %v err %v, want ErrDirectiveFinalAckWindowClosed", applied, err)
		}
		if h.auditCount("directive.complete") != 0 || h.auditCount("machine.removed") != 0 {
			t.Fatalf("audit = %v", h.auditActions())
		}
	})
}

// A forget that lands BETWEEN the final-ack route's lookup (which saw the removal still active) and its apply:
// the apply re-reads the LOCKED row, so the answer is the same 410 and nothing is applied.
func TestForgetBetweenTheFinalAckLookupAndApply(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		h.stepUp(h.owner)
		srv := h.newServer(h.srv(h.owner).Auth)
		srv.Directives = &rotatingStore{DirectiveStore: h.dirs, afterLookup: func() {
			if _, err := h.dirs.ForgetMachine(context.Background(), h.tenant, ForgetMachineInput{MachineID: m.ID, ActorID: h.owner, ExpectGroupID: h.group}); err != nil {
				t.Errorf("forget between the lookup and the apply: %v", err)
			}
		}}
		code, out := finalAckOn(t, srv, id, h.faBody(id, m.Priv, "executing", "complete", "msi exit 0", h.nextAckTime()))
		if code != http.StatusGone || !strings.Contains(str(out, "error"), "owner forgot the machine") {
			t.Fatalf("ack after a forget that landed between lookup and apply = %d %v, want 410 naming the forget", code, out)
		}
		if got := h.row(id).State; got != DirectiveForgotten {
			t.Fatalf("directive %s, want forgotten", got)
		}
		if h.auditCount("directive.complete") != 0 || h.auditCount("machine.removed") != 0 || h.auditCount("machine.forgotten") != 1 {
			t.Fatalf("audit = %v", h.auditActions())
		}
	})
}

// The audit rows of a confirmed removal are all-or-nothing: with the SECOND append (machine.removed, after
// directive.complete already went in) refused on the final-ack route, the call errors, no audit row survives,
// the directive keeps its state and the machine is not tombstoned; the retry writes exactly one set of rows.
// Both backends (the fake must discard the directive.complete row it already appended, as pg rolls back).
func TestFinalAckRemovalIsAtomicWhenTheRemovedAppendFails(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		before := *h.row(id)
		machBefore := *h.machine(h.m.ID)
		auditBefore := h.auditActions()
		h.failAuditAction("machine.removed")
		code, out := h.finalAck(id, h.m.Priv, "executing", "complete")
		h.failAuditAction("")
		if code == http.StatusOK {
			t.Fatalf("final-ack with the machine.removed append failing = %d %v, want an error", code, out)
		}
		if got := h.auditActions(); !reflect.DeepEqual(got, auditBefore) {
			t.Fatalf("audit rows survived a failed removal: %v -> %v", auditBefore, got)
		}
		if d := h.row(id); !reflect.DeepEqual(*d, before) {
			t.Fatalf("the directive changed under a failed removal: %+v -> %+v", before, *d)
		}
		if got := *h.machine(h.m.ID); !reflect.DeepEqual(got, machBefore) {
			t.Fatalf("the machine changed under a failed removal: %+v -> %+v", machBefore, got)
		}
		if code, out := h.finalAck(id, h.m.Priv, "executing", "complete"); code != 200 || str(out, "outcome") != "applied" {
			t.Fatalf("retry = %d %v", code, out)
		}
		if h.auditCount("directive.complete") != 1 || h.auditCount("machine.removed") != 1 {
			t.Fatalf("retry audit = %v", h.auditActions())
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s after the retry, want removed", got)
		}
	})
}
