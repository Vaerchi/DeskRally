package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------------------------------
// Capability model
// ---------------------------------------------------------------------------------------------------

// TestRemoveAgentIsNeverTokenGrantable pins the Owner-only, not-token-grantable posture of CapRemoveAgent
// (docs/65 F1): CapManageMachines, which a token CAN hold, must never be enough to wipe a fleet.
func TestRemoveAgentIsNeverTokenGrantable(t *testing.T) {
	if IsAPITokenGrantableCapability(CapRemoveAgent) {
		t.Fatal("CapRemoveAgent must not be API-token grantable")
	}
	for _, c := range APITokenGrantableCapabilities() {
		if c == CapRemoveAgent {
			t.Fatal("grantable list contains remove_agent")
		}
	}
	if _, err := parseAPITokenCapabilities([]string{string(CapRemoveAgent)}); err == nil {
		t.Fatal("minting a token with remove_agent was accepted")
	}
	if !RoleOwner.Has(CapRemoveAgent) {
		t.Fatal("Owner must hold remove_agent")
	}
	for _, r := range []Role{RoleAdmin, RoleTechnician, RoleReadOnly, RoleAuditor} {
		if r.Has(CapRemoveAgent) {
			t.Fatalf("%s must NOT hold remove_agent", r)
		}
	}
}

// ---------------------------------------------------------------------------------------------------
// F1: the request gates
// ---------------------------------------------------------------------------------------------------

func TestDirectiveCapabilityMatrix(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		for name, u := range map[string]string{"admin": h.admin, "technician": h.tech, "readonly": h.ro} {
			h.stepUp(u) // a fresh second factor does not substitute for the capability
			for _, kind := range []string{"uninstall", "reinstall"} {
				if code, out := h.request(u, kind, h.m); code != http.StatusForbidden {
					t.Fatalf("%s %s = %d %v, want 403", name, kind, code, out)
				}
			}
		}
		// An API-token principal holding EVERY grantable capability (including manage_machines).
		tok := h.newServer(tokenAuth{tenant: h.tenant, caps: APITokenGrantableCapabilities()})
		if code, out := h.doOn(tok, "POST", "/machines/"+h.m.ID+"/directives", h.body("uninstall", h.m), ""); code != http.StatusForbidden {
			t.Fatalf("token principal = %d %v, want 403", code, out)
		}
		// A token somehow carrying remove_agent still has no session: refused as non-interactive.
		tok2 := h.newServer(tokenAuth{tenant: h.tenant, caps: []Capability{CapRemoveAgent, CapViewMachines}})
		code, out := h.doOn(tok2, "POST", "/machines/"+h.m.ID+"/directives", h.body("uninstall", h.m), "")
		if code != http.StatusForbidden || !strings.Contains(strings.ToLower(str(out, "error")), "interactive") {
			t.Fatalf("token principal with the capability = %d %v, want 403 interactive", code, out)
		}
		// The Owner is allowed.
		h.stepUp(h.owner)
		if code, out := h.request(h.owner, "uninstall", h.m); code != http.StatusCreated || dirStateOf(out) != "requested" {
			t.Fatalf("owner = %d %v, want 201 requested", code, out)
		}
		// There is no bulk or id-list route.
		for _, p := range []string{"/machines/bulk-directives", "/directives/bulk", "/directives"} {
			if code, _ := h.do(h.owner, "POST", p, `{"machine_ids":["`+h.m.ID+`"],"kind":"uninstall"}`); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
				t.Fatalf("POST %s = %d, want 404/405 (no bulk route)", p, code)
			}
		}
	})
}

func TestUninstallRequestGates(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		active := h.addMachineFn(h.group, MachineStatusActive)
		h.stepUp(h.owner)
		// Retired precondition.
		if code, out := h.request(h.owner, "uninstall", active); code != http.StatusConflict {
			t.Fatalf("uninstall of an ACTIVE machine = %d %v, want 409", code, out)
		}
		// Typed confirmation: absent, wrong, and another machine's name.
		for _, confirm := range []string{"", "nope", h.machine(active.ID).Name} {
			raw, _ := json.Marshal(map[string]string{"kind": "uninstall", "confirm": confirm})
			if code, out := h.do(h.owner, "POST", "/machines/"+h.m.ID+"/directives", string(raw)); code != http.StatusUnprocessableEntity {
				t.Fatalf("confirm %q = %d %v, want 422", confirm, code, out)
			}
		}
		// Step-up: absent (a user who never verified)...
		if code, out := h.request(h.owner2, "uninstall", h.m); code != http.StatusForbidden || str(out, "code") != "step_up_required" {
			t.Fatalf("no step-up = %d %v, want 403 step_up_required", code, out)
		}
		// ...stale...
		h.stepUp(h.owner)
		h.ageStepUp(h.owner, directiveStepUpMaxAge+time.Minute)
		if code, out := h.request(h.owner, "uninstall", h.m); code != http.StatusForbidden || str(out, "code") != "step_up_required" {
			t.Fatalf("stale step-up = %d %v, want 403 step_up_required", code, out)
		}
		// ...and just inside the bound is fine.
		h.stepUp(h.owner)
		h.ageStepUp(h.owner, directiveStepUpMaxAge-time.Minute)
		if code, out := h.request(h.owner, "uninstall", h.m); code != http.StatusCreated {
			t.Fatalf("fresh step-up = %d %v, want 201", code, out)
		}
		// One active directive per device.
		if code, out := h.request(h.owner, "uninstall", h.m); code != http.StatusConflict {
			t.Fatalf("second request while one is active = %d %v, want 409", code, out)
		}
		// Reinstall needs no step-up (a repair), but only for a machine that is NOT retired.
		other := h.addMachineFn(h.group, MachineStatusActive)
		if code, out := h.request(h.owner2, "reinstall", other); code != http.StatusCreated || dirStateOf(out) != "issued" {
			t.Fatalf("reinstall = %d %v, want 201 issued (no cancel window, no step-up)", code, out)
		}
	})
}

func TestUninstallTenantCap(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.setCaps(2, DefaultReinstallDailyCap)
		h.stepUp(h.owner)
		var ids []string
		for i := 0; i < 2; i++ {
			m := h.addMachineFn(h.group, MachineStatusRetired)
			code, out := h.request(h.owner, "uninstall", m)
			if code != http.StatusCreated {
				t.Fatalf("request %d = %d %v", i, code, out)
			}
			ids = append(ids, dirIDOf(out))
		}
		third := h.addMachineFn(h.group, MachineStatusRetired)
		if code, out := h.request(h.owner, "uninstall", third); code != http.StatusTooManyRequests {
			t.Fatalf("third request = %d %v, want 429", code, out)
		}
		// A cancelled request gives its slot back.
		if code, out := h.do(h.owner, "POST", "/directives/"+ids[0]+"/cancel", `{"reason":"oops"}`); code != http.StatusOK {
			t.Fatalf("cancel = %d %v", code, out)
		}
		if code, out := h.request(h.owner, "uninstall", third); code != http.StatusCreated {
			t.Fatalf("after cancel = %d %v, want 201", code, out)
		}
	})
}

func TestReinstallDeviceDailyCap(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		dev := h.addMachineFn(h.group, MachineStatusActive)
		for i := 0; i < DefaultReinstallDailyCap; i++ {
			code, out := h.request(h.owner, "reinstall", dev)
			if code != http.StatusCreated {
				t.Fatalf("reinstall %d = %d %v", i, code, out)
			}
			id := dirIDOf(out)
			h.drive(id, dev, "accepted", "executing", "complete")
		}
		if code, out := h.request(h.owner, "reinstall", dev); code != http.StatusTooManyRequests {
			t.Fatalf("reinstall beyond the daily cap = %d %v, want 429", code, out)
		}
		// Another device is unaffected: the cap is per device.
		other := h.addMachineFn(h.group, MachineStatusActive)
		if code, out := h.request(h.owner, "reinstall", other); code != http.StatusCreated {
			t.Fatalf("other device = %d %v, want 201", code, out)
		}
	})
}

func TestSecondApproverPolicy(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		// The policy itself: Owner-only, needs a fresh step-up.
		if code, _ := h.do(h.admin, "PUT", "/tenant/directive-policy", `{"require_second_approver":true}`); code != http.StatusForbidden {
			t.Fatalf("admin set policy = %d, want 403", code)
		}
		if code, out := h.do(h.owner, "PUT", "/tenant/directive-policy", `{"require_second_approver":true}`); code != http.StatusForbidden || str(out, "code") != "step_up_required" {
			t.Fatalf("policy without step-up = %d %v", code, out)
		}
		h.stepUp(h.owner)
		if code, out := h.do(h.owner, "PUT", "/tenant/directive-policy", `{"require_second_approver":true}`); code != http.StatusOK {
			t.Fatalf("set policy = %d %v", code, out)
		}
		id := h.mustRequestUninstall(h.owner, h.m)
		if !h.row(id).RequireApproval {
			t.Fatal("request did not snapshot the policy")
		}
		// Self-approval is refused.
		if code, out := h.do(h.owner, "POST", "/directives/"+id+"/approve", ""); code != http.StatusForbidden {
			t.Fatalf("self-approval = %d %v, want 403", code, out)
		}
		// The cancel window passes but nothing is issued without the second approver.
		h.advance(directiveCancelWindow + time.Minute)
		h.sweep()
		if d := h.row(id); d.State != DirectiveRequested || d.Artifact != "" {
			t.Fatalf("issued without approval: %+v", d)
		}
		if code, out := h.do(h.admin, "POST", "/directives/"+id+"/approve", ""); code != http.StatusNotFound && code != http.StatusForbidden {
			t.Fatalf("admin approve = %d %v, want 403/404", code, out)
		}
		// A different Owner approves (with their own step-up); approval restarts the cancel window, so it
		// does NOT issue at once - it issues when the new window ends.
		h.stepUp(h.owner2)
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", ""); code != http.StatusOK || dirStateOf(out) != "requested" {
			t.Fatalf("approve = %d %v, want 200 still requested", code, out)
		}
		if got := h.row(id); got.ApprovedBy != h.owner2 || got.Artifact != "" {
			t.Fatalf("row after approval: %+v", got)
		}
		if d := h.issueNow(id); d.State != DirectiveIssued || d.Artifact == "" {
			t.Fatalf("after the restarted window: %+v", d)
		}
		// Approval of a request that never needed it, and a repeat, are refused.
		h.stepUp(h.owner)
		if code, out := h.do(h.owner, "PUT", "/tenant/directive-policy", `{"require_second_approver":false}`); code != http.StatusOK {
			t.Fatalf("policy off = %d %v", code, out)
		}
		m2 := h.addMachineFn(h.group, MachineStatusRetired)
		id2 := dirIDOf(mustJSON(t)(h.request(h.owner, "uninstall", m2)))
		if code, _ := h.do(h.owner2, "POST", "/directives/"+id2+"/approve", ""); code != http.StatusConflict {
			t.Fatalf("approve of a request that needs none = %d, want 409", code)
		}
	})
}

func mustJSON(t *testing.T) func(int, map[string]any) map[string]any {
	return func(code int, out map[string]any) map[string]any {
		t.Helper()
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("unexpected status %d %v", code, out)
		}
		return out
	}
}

func TestCancelWindowAndLateCancel(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		// Inside the window: not issued by the sweeper, cancellable by ANY remove_agent holder.
		h.sweep()
		if d := h.row(id); d.State != DirectiveRequested {
			t.Fatalf("issued inside the cancel window: %s", d.State)
		}
		if code, out := h.do(h.tech, "POST", "/directives/"+id+"/cancel", ""); code != http.StatusNotFound {
			t.Fatalf("technician cancel = %d %v, want 404", code, out)
		}
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/cancel", `{"reason":"wrong box"}`); code != http.StatusOK || dirStateOf(out) != "cancelled" {
			t.Fatalf("cancel = %d %v", code, out)
		}
		if d := h.row(id); d.CancelledBy != h.owner2 || d.CancelReason != "wrong box" || d.Artifact != "" {
			t.Fatalf("cancelled row: %+v", d)
		}
		// A cancelled request is never issued, however late the sweeper runs.
		h.advance(2 * directiveCancelWindow)
		h.sweep()
		if d := h.row(id); d.State != DirectiveCancelled || d.Artifact != "" {
			t.Fatalf("cancelled directive moved: %+v", d)
		}
		// After issuance cancellation is refused.
		id2 := h.mustRequestUninstall(h.owner, h.m)
		if d := h.issueNow(id2); d.State != DirectiveIssued {
			t.Fatalf("not issued after the window: %s", d.State)
		}
		if code, out := h.do(h.owner, "POST", "/directives/"+id2+"/cancel", ""); code != http.StatusConflict {
			t.Fatalf("cancel after issuance = %d %v, want 409", code, out)
		}
	})
}

// TestCancelIssueRace: at the end of the window a cancel and the issuance race. Exactly one wins, and the
// invariant "a cancelled directive has no artifact; an issued one cannot be cancelled" always holds.
func TestCancelIssueRace(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		deps := DirectiveIssueDeps{Authority: h.srv(h.owner).directiveAuthority(h.tenant), Issuer: h.issuer}
		for i := 0; i < 12; i++ {
			m := h.addMachineFn(h.group, MachineStatusRetired)
			id := h.mustRequestUninstall(h.owner, m)
			h.advance(directiveCancelWindow + time.Minute)
			var wg sync.WaitGroup
			var issueErr, cancelErr error
			wg.Add(2)
			go func() { defer wg.Done(); _, issueErr = h.dirs.Issue(context.Background(), h.tenant, id, deps) }()
			go func() {
				defer wg.Done()
				_, cancelErr = h.dirs.Cancel(context.Background(), h.tenant, id, h.owner2, "race")
			}()
			wg.Wait()
			d := h.row(id)
			switch d.State {
			case DirectiveIssued:
				if issueErr != nil || !errors.Is(cancelErr, ErrDirectiveNotCancellable) || d.Artifact == "" {
					t.Fatalf("iter %d: issued but issueErr=%v cancelErr=%v artifact=%v", i, issueErr, cancelErr, d.Artifact != "")
				}
			case DirectiveCancelled:
				if cancelErr != nil || !errors.Is(issueErr, ErrDirectiveNotIssuable) || d.Artifact != "" {
					t.Fatalf("iter %d: cancelled but issueErr=%v cancelErr=%v artifact=%v", i, issueErr, cancelErr, d.Artifact != "")
				}
			default:
				t.Fatalf("iter %d: unexpected state %s", i, d.State)
			}
		}
	})
}

// ---------------------------------------------------------------------------------------------------
// D-C4: issuance re-checks everything
// ---------------------------------------------------------------------------------------------------

func TestIssuanceRechecks(t *testing.T) {
	type tc struct {
		name   string
		setup  func(h *dirHarness, id string, m dirMachine) // after the request, before the window ends
		reason string                                       // substring of the cancel reason
	}
	cases := []tc{
		{"requester demoted", func(h *dirHarness, _ string, _ dirMachine) { h.setRole(h.owner, RoleAdmin) }, "no longer holds"},
		{"machine un-retired (guard bypassed)", func(h *dirHarness, _ string, m dirMachine) {
			h.bypassGuard(func() {
				if err := h.machines.SetMachineStatus(context.Background(), h.tenant, m.ID, MachineStatusActive); err != nil {
					h.t.Fatal(err)
				}
			})
		}, "no longer retired"},
		{"agent re-enrolled with another key", func(h *dirHarness, _ string, m dirMachine) {
			_, other := newDirKey(h.t)
			h.setPubkey(m.ID, other)
		}, "re-enrolled"},
		{"policy changed", func(h *dirHarness, _ string, _ dirMachine) {
			h.stepUp(h.owner)
			if code, out := h.do(h.owner, "PUT", "/tenant/directive-policy", `{"require_second_approver":true}`); code != http.StatusOK {
				h.t.Fatalf("policy = %d %v", code, out)
			}
		}, "policy changed"},
		{"quota lowered", func(h *dirHarness, _ string, _ dirMachine) { h.setCaps(0, DefaultReinstallDailyCap) }, "quota"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
				id := h.mustRequestUninstall(h.owner, h.m)
				c.setup(h, id, h.m)
				h.advance(directiveCancelWindow + time.Minute)
				h.sweep()
				d := h.row(id)
				if d.State != DirectiveCancelled || d.Artifact != "" || d.IssuedAt != nil {
					t.Fatalf("directive not cancelled at issuance: %+v", d)
				}
				if !strings.Contains(d.CancelReason, c.reason) {
					t.Fatalf("cancel reason %q does not mention %q", d.CancelReason, c.reason)
				}
				if h.auditCount("directive.issued") != 0 {
					t.Fatal("a directive.issued audit row exists for a refused issuance")
				}
				if len(h.notes.got) != 0 {
					t.Fatalf("signaling was notified for a refused issuance: %v", h.notes.got)
				}
			})
		})
	}
}

func TestIssuanceApproverDemoted(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.stepUp(h.owner)
		h.do(h.owner, "PUT", "/tenant/directive-policy", `{"require_second_approver":true}`)
		id := h.mustRequestUninstall(h.owner, h.m)
		h.stepUp(h.owner2)
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", ""); code != http.StatusOK {
			t.Fatalf("approve = %d %v", code, out)
		}
		h.setRole(h.owner2, RoleAdmin) // the approver loses the capability before issuance
		h.advance(directiveCancelWindow + time.Minute)
		h.sweep()
		if d := h.row(id); d.State != DirectiveCancelled || d.Artifact != "" {
			t.Fatalf("issued on a demoted approver's approval: %+v", d)
		}
	})
}

func TestIssuanceTenantSuspendedAndExpiry(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(directiveCancelWindow + time.Minute)
		h.setSuspended(true)
		h.sweep()
		if d := h.row(id); d.State != DirectiveRequested || d.Artifact != "" {
			t.Fatalf("issued for a suspended tenant: %+v", d)
		}
		h.setSuspended(false)
		// A request nobody issued in time expires instead of issuing late.
		h.advance(directiveRequestTTL)
		h.sweep()
		if d := h.row(id); d.State != DirectiveExpired || d.Artifact != "" {
			t.Fatalf("a lapsed request was not expired: %+v", d)
		}
	})
}

// TestIssuanceTooEarlyAndNeedsApprovalDirect drives the store the way a buggy caller could: Issue before the
// window ends must refuse without a state change.
func TestIssueBeforeWindowRefused(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		deps := DirectiveIssueDeps{Authority: h.srv(h.owner).directiveAuthority(h.tenant), Issuer: h.issuer}
		if _, err := h.dirs.Issue(context.Background(), h.tenant, id, deps); !errors.Is(err, ErrDirectiveTooEarly) {
			t.Fatalf("Issue inside the window = %v, want ErrDirectiveTooEarly", err)
		}
		if d := h.row(id); d.State != DirectiveRequested || d.Artifact != "" {
			t.Fatalf("state moved: %+v", d)
		}
	})
}

// TestIssueAfterRequestExpiryRefused drives Issue directly (the sweeper would Expire first): a request past its
// lifetime must never be signed.
func TestIssueAfterRequestExpiryRefused(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(directiveRequestTTL + time.Minute)
		deps := DirectiveIssueDeps{Authority: h.srv(h.owner).directiveAuthority(h.tenant), Issuer: h.issuer}
		if _, err := h.dirs.Issue(context.Background(), h.tenant, id, deps); !errors.Is(err, ErrDirectiveExpired) {
			t.Fatalf("Issue of a lapsed request = %v, want ErrDirectiveExpired", err)
		}
		if d := h.row(id); d.State != DirectiveExpired || d.Artifact != "" {
			t.Fatalf("lapsed request was signed or left open: %+v", d)
		}
	})
}

// ---------------------------------------------------------------------------------------------------
// Audit first
// ---------------------------------------------------------------------------------------------------

func TestAuditFirstLeavesNothingWhenTheAuditStoreFails(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.stepUp(h.owner)
		h.failAudit(true)
		code, out := h.request(h.owner, "uninstall", h.m)
		h.failAudit(false)
		if code != http.StatusInternalServerError {
			t.Fatalf("request with a failing audit store = %d %v, want 500", code, out)
		}
		if ds, _ := h.dirs.List(context.Background(), h.tenant, h.m.ID); len(ds) != 0 {
			t.Fatalf("a directive exists although its audit row could not be written: %+v", ds)
		}
		// Issuance: the request is fine, the issuance's audit fails -> still requested, no artifact, no notice.
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(directiveCancelWindow + time.Minute)
		h.failAudit(true)
		h.sweep()
		h.failAudit(false)
		if d := h.row(id); d.State != DirectiveRequested || d.Artifact != "" {
			t.Fatalf("issued although the audit write failed: %+v", d)
		}
		if len(h.notes.got) != 0 {
			t.Fatalf("delivery notified without an issuance: %v", h.notes.got)
		}
		// And once the audit store is back it issues.
		h.sweep()
		if d := h.row(id); d.State != DirectiveIssued {
			t.Fatalf("not issued after the audit store recovered: %s", d.State)
		}
		if h.auditCount("directive.requested") != 1 || h.auditCount("directive.issued") != 1 {
			t.Fatalf("audit trail: %v", h.auditActions())
		}
	})
}

// ---------------------------------------------------------------------------------------------------
// F2: the signed artifact and its dedicated key
// ---------------------------------------------------------------------------------------------------

func TestIssuedArtifactVerifiesUnderTheDedicatedKeyOnly(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		d := h.issueNow(id)
		if d.State != DirectiveIssued || d.Artifact == "" {
			t.Fatalf("not issued: %+v", d)
		}
		pub, _ := hex.DecodeString(h.issuer.PublicKeyHex())
		exp := DirectiveExpectation{DeviceID: h.m.Device, TenantID: h.tenant, KeyFP: fingerprintOf(h.m.Pub), NowMs: d.IssuedAt.UnixMilli() + 1000}
		c, err := VerifyDirective(ed25519.PublicKey(pub), d.Artifact, exp)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if c.Kind != "uninstall" || c.DirectiveID != canonicalUUIDish(id) || c.ExpiresAtMs-c.IssuedAtMs != int64(directiveUninstallTTL/time.Millisecond) {
			t.Fatalf("claims: %+v", c)
		}
		// NOT the grant issuer: same artifact under the grant issuer's key is a signature failure, and the two
		// public keys differ.
		if h.issuer.PublicKeyHex() == h.grants.PublicKeyHex() {
			t.Fatal("directive key equals the grant issuer key")
		}
		gpub, _ := hex.DecodeString(h.grants.PublicKeyHex())
		if _, err := VerifyDirective(ed25519.PublicKey(gpub), d.Artifact, exp); verifyCode(err) != DirectiveRefusedSignature {
			t.Fatalf("grant issuer key verified a directive: %v", err)
		}
		// The artifact is single-purpose: wrong device / tenant / key generation are refused.
		for name, bad := range map[string]DirectiveExpectation{
			"device": {DeviceID: "other", TenantID: h.tenant, KeyFP: exp.KeyFP, NowMs: exp.NowMs},
			"tenant": {DeviceID: exp.DeviceID, TenantID: newUUID(), KeyFP: exp.KeyFP, NowMs: exp.NowMs},
			"key":    {DeviceID: exp.DeviceID, TenantID: h.tenant, KeyFP: fingerprintOf(testPubkeyHex(t)), NowMs: exp.NowMs},
		} {
			if _, err := VerifyDirective(ed25519.PublicKey(pub), d.Artifact, bad); err == nil {
				t.Fatalf("%s mismatch verified", name)
			}
		}
		// The enroll response hands out THIS key.
		code, out := h.redeemEnrollment(testPubkeyHex(t))
		if code != http.StatusCreated || str(out, "directive_pubkey") != h.issuer.PublicKeyHex() {
			t.Fatalf("enroll response = %d %v, want directive_pubkey %s", code, out, h.issuer.PublicKeyHex())
		}
	})
}

func verifyCode(err error) string {
	var ve *DirectiveVerifyError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

func (h *dirHarness) redeemEnrollment(pubHex string) (int, map[string]any) {
	h.t.Helper()
	tok := &EnrollmentToken{GroupID: h.group, ExpiresAt: time.Now().Add(time.Hour), MaxUses: 5}
	plain, err := h.enroll.MintToken(context.Background(), h.tenant, tok)
	if err != nil {
		h.t.Fatalf("mint enrollment token: %v", err)
	}
	raw, _ := json.Marshal(map[string]string{"token": plain, "pubkey": pubHex, "name": "new-box"})
	return h.doOn(h.srv(h.owner), "POST", "/enroll/redeem", string(raw), "")
}

// ---------------------------------------------------------------------------------------------------
// F3 / D-C1: restricted mode, pending fetch, delivery, acknowledgements
// ---------------------------------------------------------------------------------------------------

func TestRetiredMachineIdentityIsRestrictedOnly(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		active := h.addMachineFn(h.group, MachineStatusActive)
		// Active: resolves either way, status reported.
		for _, restricted := range []bool{false, true} {
			if code, out := h.identity(active.Device, restricted); code != http.StatusOK || str(out, "status") != "active" {
				t.Fatalf("active (restricted=%v) = %d %v", restricted, code, out)
			}
		}
		// Retired: 404 for an ordinary lookup (an older signaling keeps refusing it), 200+status when restricted.
		if code, _ := h.identity(h.m.Device, false); code != http.StatusNotFound {
			t.Fatalf("retired without restricted = %d, want 404", code)
		}
		if code, out := h.identity(h.m.Device, true); code != http.StatusOK || str(out, "status") != "retired" {
			t.Fatalf("retired restricted = %d %v, want 200 retired", code, out)
		}
		// Quarantined keeps today's semantics: it resolves as before.
		q := h.addMachineFn(h.group, MachineStatusQuarantined)
		if code, out := h.identity(q.Device, false); code != http.StatusOK || str(out, "status") != "quarantined" {
			t.Fatalf("quarantined = %d %v, want 200", code, out)
		}
		// Un-retiring restores ordinary registration on the next lookup.
		if err := h.machines.SetMachineStatus(context.Background(), h.tenant, h.m.ID, MachineStatusActive); err != nil {
			t.Fatal(err)
		}
		if code, out := h.identity(h.m.Device, false); code != http.StatusOK || str(out, "status") != "active" {
			t.Fatalf("re-activated = %d %v", code, out)
		}
	})
}

func TestPendingDeliveryAndAcks(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		if len(h.pending(h.m.Device)) != 0 {
			t.Fatal("a REQUESTED directive is pending for the device")
		}
		d := h.issueNow(id)
		if !h.notes.waitFor(h.m.Device, 1) {
			t.Fatal("signaling was not notified at issuance")
		}
		// Pending: only the matching device, with the artifact; another device sees nothing.
		p := h.pending(h.m.Device)
		if len(p) != 1 || p[0]["directive_id"] != id || p[0]["artifact"] != d.Artifact {
			t.Fatalf("pending = %v", p)
		}
		other := h.addMachineFn(h.group, MachineStatusRetired)
		if len(h.pending(other.Device)) != 0 {
			t.Fatal("another device was handed the directive")
		}
		// Routing token required.
		if code, _ := h.doOn(h.srv(h.owner), "GET", "/internal/devices/"+h.m.Device+"/directives/pending", "", ""); code != http.StatusUnauthorized {
			t.Fatalf("pending without the service token = %d, want 401", code)
		}
		// Delivery report: by the right device only, audited once.
		body := `{"device_id":"` + h.m.Device + `"}`
		for i := 0; i < 2; i++ {
			if code, out := h.internal("POST", "/internal/directives/"+id+"/delivered", body); code != http.StatusOK {
				t.Fatalf("delivered = %d %v", code, out)
			}
		}
		if h.auditCount("directive.delivered") != 1 || h.row(id).DeliveredAt == nil {
			t.Fatalf("delivery not recorded exactly once: %v", h.auditActions())
		}
		if code, _ := h.internal("POST", "/internal/directives/"+id+"/delivered", `{"device_id":"`+other.Device+`"}`); code != http.StatusNotFound {
			t.Fatalf("delivered by another device = %d, want 404", code)
		}
		// The agent's acknowledgements, in order.
		h.drive(id, h.m, "accepted", "executing", "reboot_pending", "executing")
		if code, out := h.ack(id, h.m, "executing", "complete"); code != http.StatusOK || str(out, "outcome") != "applied" {
			t.Fatalf("complete = %d %v", code, out)
		}
		if h.row(id).State != DirectiveComplete {
			t.Fatalf("state = %s", h.row(id).State)
		}
		// D-C9: the machine is a tombstone: removed, never resolvable, enrollment of its key refused.
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine status = %s, want removed", got)
		}
		for _, restricted := range []bool{false, true} {
			if code, _ := h.identity(h.m.Device, restricted); code != http.StatusNotFound {
				t.Fatalf("removed machine resolves (restricted=%v) = %d, want 404", restricted, code)
			}
		}
		if code, out := h.redeemEnrollment(h.m.Pub); code != http.StatusForbidden {
			t.Fatalf("enrollment with a removed device's key = %d %v, want 403", code, out)
		}
		if code, out := h.redeemEnrollment(testPubkeyHex(t)); code != http.StatusCreated {
			t.Fatalf("enrollment with a fresh key = %d %v, want 201", code, out)
		}
		// A removed machine never changes status again.
		if err := h.machines.SetMachineStatus(context.Background(), h.tenant, h.m.ID, MachineStatusActive); !errors.Is(err, ErrMachineRemoved) {
			t.Fatalf("un-removing = %v, want ErrMachineRemoved", err)
		}
		// Audit trail of the whole life.
		for _, a := range []string{"directive.requested", "directive.issued", "directive.accepted", "directive.executing", "directive.reboot_pending", "directive.complete", "machine.removed"} {
			if h.auditCount(a) == 0 {
				t.Fatalf("audit action %s missing: %v", a, h.auditActions())
			}
		}
	})
}

func TestAckBinding(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		path := "/internal/directives/" + id + "/ack"
		now := time.Now()
		row := h.row(id)
		_, wrongPriv := func() (string, ed25519.PrivateKey) { p, _ := newDirKey(t); return "", p }()
		other := h.addMachineFn(h.group, MachineStatusRetired)

		sign := func(priv ed25519.PrivateKey, tenant, device, dir, fp, from, to string) string {
			a, err := SignDirectiveAck(priv, tenant, device, dir, fp, from, to, now.UnixMilli(), "")
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(map[string]any{"device_id": h.m.Device, "from": from, "to": to, "ts_ms": a.TsMs, "detail": "", "sig": a.Sig})
			return string(raw)
		}
		good := func(from, to string) string {
			return sign(h.m.Priv, row.TenantID, row.DeviceID, row.ID, row.KeyFP, from, to)
		}
		// Each must be refused, and the row must not move.
		refused := map[string]struct {
			body string
			want int
		}{
			"signed by another key":                          {sign(wrongPriv, row.TenantID, row.DeviceID, row.ID, row.KeyFP, "issued", "accepted"), 403},
			"signature for other dir":                        {sign(h.m.Priv, row.TenantID, row.DeviceID, newUUID(), row.KeyFP, "issued", "accepted"), 403},
			"signature for other tenant":                     {sign(h.m.Priv, newUUID(), row.DeviceID, row.ID, row.KeyFP, "issued", "accepted"), 403},
			"signature for other device":                     {sign(h.m.Priv, row.TenantID, other.Device, row.ID, row.KeyFP, "issued", "accepted"), 403},
			"signature for other generation":                 {sign(h.m.Priv, row.TenantID, row.DeviceID, row.ID, strings.Repeat("ab", 32), "issued", "accepted"), 403},
			"signed transition differs from the claimed one": {strings.Replace(good("issued", "accepted"), `"to":"accepted"`, `"to":"executing"`, 1), 403},
			"not a legal transition":                         {good("issued", "complete"), 409},
			"wrong from state":                               {good("accepted", "executing"), 409},
			"unknown target":                                 {good("issued", "removal_unconfirmed"), 409},
		}
		for name, c := range refused {
			if code, out := h.internal("POST", path, c.body); code != c.want {
				t.Fatalf("%s = %d %v, want %d", name, code, out, c.want)
			}
			if h.row(id).State != DirectiveIssued {
				t.Fatalf("%s moved the row to %s", name, h.row(id).State)
			}
		}
		// A future timestamp is refused.
		future := h.ackJSON(id, h.m, h.m.Priv, "issued", "accepted", "", time.Now().Add(time.Hour))
		if code, _ := h.internal("POST", path, future); code != http.StatusConflict {
			t.Fatalf("future ts = %d, want 409", code)
		}
		// The device id comes from the authenticated device: another device's id cannot ack this directive.
		foreign := strings.Replace(good("issued", "accepted"), h.m.Device, other.Device, 1)
		if code, _ := h.internal("POST", path, foreign); code != http.StatusNotFound {
			t.Fatalf("ack from another device = %d, want 404", code)
		}
		// Unknown fields are refused (strict decode).
		if code, _ := h.internal("POST", path, strings.Replace(good("issued", "accepted"), `{`, `{"tenant_id":"x",`, 1)); code != http.StatusBadRequest {
			t.Fatalf("unknown field = %d, want 400", code)
		}
		// The good one applies; the exact replay is a no-op; an older transition replayed after progress is 409.
		if code, out := h.internal("POST", path, good("issued", "accepted")); code != http.StatusOK || str(out, "outcome") != "applied" {
			t.Fatalf("good ack = %d %v", code, out)
		}
		if code, out := h.internal("POST", path, good("issued", "accepted")); code != http.StatusOK || str(out, "outcome") != "replay" {
			t.Fatalf("replay = %d %v, want 200 replay", code, out)
		}
		if h.auditCount("directive.accepted") != 1 {
			t.Fatalf("a replay wrote another audit row: %v", h.auditActions())
		}
		h.drive(id, h.m, "executing")
		if code, _ := h.internal("POST", path, good("issued", "accepted")); code != http.StatusConflict {
			t.Fatalf("stale replay after progress = %d, want 409", code)
		}
		// A rotated device key voids the generation: even a correctly signed ack under the NEW key is refused.
		_, newPub := newDirKey(t)
		h.setPubkey(h.m.ID, newPub)
		if code, out := h.ack(id, h.m, "executing", "complete"); code != http.StatusConflict {
			t.Fatalf("ack after a key change = %d %v, want 409", code, out)
		}
		if h.row(id).State != DirectiveExecuting {
			t.Fatalf("state moved after a key change: %s", h.row(id).State)
		}
		if code, out := h.internal("GET", "/internal/devices/"+h.m.Device+"/directives/pending", ""); code != http.StatusOK || len(out["directives"].([]any)) != 0 {
			t.Fatalf("a directive for a stale key generation is still pending: %v", out)
		}
	})
}

func TestUnconfirmedAndExpiredSweeps(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		// An uninstall that started and never reported: removal_unconfirmed, machine stays retired.
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		h.drive(id, h.m, "accepted", "executing")
		h.advance(directiveUnconfirmedAfter + time.Minute)
		h.sweep()
		if d := h.row(id); d.State != DirectiveRemovalUnconfirmed {
			t.Fatalf("state = %s, want removal_unconfirmed", d.State)
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRetired {
			t.Fatalf("machine %s after an unconfirmed removal, want retired (never silently complete)", got)
		}
		// A late authenticated report resolves it.
		if code, out := h.ack(id, h.m, "removal_unconfirmed", "complete"); code != http.StatusOK {
			t.Fatalf("late complete = %d %v", code, out)
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s after the late report, want removed", got)
		}
		// A directive nobody accepted expires.
		m2 := h.addMachineFn(h.group, MachineStatusRetired)
		id2 := h.mustRequestUninstall(h.owner, m2)
		h.issueNow(id2)
		h.advance(directiveUninstallTTL + time.Minute)
		h.sweep()
		if d := h.row(id2); d.State != DirectiveExpired {
			t.Fatalf("state = %s, want expired", d.State)
		}
		if len(h.pending(m2.Device)) != 0 {
			t.Fatal("an expired directive is still pending")
		}
		// An ack for an expired directive is refused.
		if code, _ := h.ack(id2, m2, "issued", "accepted"); code != http.StatusConflict {
			t.Fatalf("ack of an expired directive = %d, want 409", code)
		}
	})
}

func TestRenotifyAndNotifierFailure(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.notes.fail = true // signaling down: issuance must still succeed
		id := h.mustRequestUninstall(h.owner, h.m)
		if d := h.issueNow(id); d.State != DirectiveIssued {
			t.Fatalf("issuance depends on the notifier: %s", d.State)
		}
		h.notes.waitFor(h.m.Device, 1) // the issuance's own notification
		before := h.notes.count(h.m.Device)
		h.advance(2 * time.Minute) // renotify waits a minute after issuance
		h.sweep()                  // undelivered: renotify
		if !h.notes.waitFor(h.m.Device, before+1) {
			t.Fatal("an undelivered directive was not renotified")
		}
		// Once delivered, no more renotify.
		h.internal("POST", "/internal/directives/"+id+"/delivered", `{"device_id":"`+h.m.Device+`"}`)
		before = h.notes.count(h.m.Device)
		h.sweep()
		time.Sleep(50 * time.Millisecond)
		if h.notes.count(h.m.Device) != before {
			t.Fatal("a delivered directive was renotified")
		}
	})
}

// ---------------------------------------------------------------------------------------------------
// Machine guards, isolation, scope
// ---------------------------------------------------------------------------------------------------

func TestMachineGuardsDuringADirective(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		// Un-retire, quarantine and a group move are refused while the directive is active.
		if code, out := h.do(h.owner, "POST", "/machines/"+h.m.ID+"/status", `{"status":"active"}`); code != http.StatusConflict {
			t.Fatalf("un-retire = %d %v, want 409", code, out)
		}
		if err := h.machines.SetMachineGroup(context.Background(), h.tenant, h.m.ID, h.otherGroup); !errors.Is(err, ErrMachineHasActiveDirective) {
			t.Fatalf("group move = %v, want ErrMachineHasActiveDirective", err)
		}
		if code, out := h.do(h.owner, "POST", "/machines/bulk-status", `{"status":"active","machine_ids":["`+h.m.ID+`"]}`); code != http.StatusOK ||
			!strings.Contains(string(mustMarshal(out)), "active directive") {
			t.Fatalf("bulk un-retire = %d %v, want a per-machine refusal", code, out)
		}
		if got := h.machine(h.m.ID); got.Status != MachineStatusRetired || got.GroupID != h.group {
			t.Fatalf("machine changed during a directive: %+v", got)
		}
		// Cancelling frees it.
		if code, out := h.do(h.owner, "POST", "/directives/"+id+"/cancel", ""); code != http.StatusOK {
			t.Fatalf("cancel = %d %v", code, out)
		}
		if code, out := h.do(h.owner, "POST", "/machines/"+h.m.ID+"/status", `{"status":"active"}`); code != http.StatusOK {
			t.Fatalf("un-retire after cancel = %d %v", code, out)
		}
		// And the removed status cannot be set through the API at all.
		if code, _ := h.do(h.owner, "POST", "/machines/"+h.m.ID+"/status", `{"status":"removed"}`); code != http.StatusBadRequest {
			t.Fatalf("set status removed = %d, want 400", code)
		}
	})
}

func mustMarshal(v any) []byte { b, _ := json.Marshal(v); return b }

func TestDirectiveTenantIsolation(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		// Erin (owner of ANOTHER tenant) sees and changes nothing.
		h.stepUp(h.erin)
		for _, c := range []struct{ method, path, body string }{
			{"GET", "/directives/" + id, ""},
			{"POST", "/directives/" + id + "/cancel", ""},
			{"POST", "/directives/" + id + "/approve", ""},
			{"GET", "/machines/" + h.m.ID + "/directives", ""},
			{"POST", "/machines/" + h.m.ID + "/directives", `{"kind":"reinstall"}`},
		} {
			if code, out := h.do(h.erin, c.method, c.path, c.body); code != http.StatusNotFound {
				t.Fatalf("%s %s as the other tenant = %d %v, want 404", c.method, c.path, code, out)
			}
		}
		if h.row(id).State != DirectiveRequested {
			t.Fatal("the other tenant changed the directive")
		}
		// A viewer of the tenant can read it but not act.
		if code, out := h.do(h.ro, "GET", "/directives/"+id, ""); code != http.StatusOK || str(out["directive"].(map[string]any), "id") != id {
			t.Fatalf("read-only get = %d %v", code, out)
		}
		h.issueNow(id)
		d := string(mustMarshal(h.mustGetDirectiveJSON(id)))
		if strings.Contains(d, "artifact") || strings.Contains(d, "nonce") || strings.Contains(d, "RMTDIRECTIVE") {
			t.Fatalf("a console view leaks the artifact/nonce: %s", d)
		}
	})
}

func (h *dirHarness) mustGetDirectiveJSON(id string) map[string]any {
	_, out := h.do(h.owner, "GET", "/directives/"+id, "")
	return out
}

func TestDirectiveGroupScopeFollowsTheCurrentGroup(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		// An Owner scoped to a DIFFERENT group has no authority over this machine.
		if !h.pg {
			mem := h.users.(*InMemoryUserStore)
			scoped := newUUID()
			mem.AddUser(&AuthUser{ID: scoped, TenantID: h.tenant, Email: "scoped@test.example"},
				NewGrant(scoped, h.tenant, NewMembership(RoleOwner, Groups(h.otherGroup))))
			h.stepUp(scoped)
			if code, out := h.request(scoped, "uninstall", h.m); code != http.StatusForbidden {
				t.Fatalf("owner scoped to another group = %d %v, want 403", code, out)
			}
			ownScope := newUUID()
			mem.AddUser(&AuthUser{ID: ownScope, TenantID: h.tenant, Email: "own@test.example"},
				NewGrant(ownScope, h.tenant, NewMembership(RoleOwner, Groups(h.group))))
			h.stepUp(ownScope)
			if code, out := h.request(ownScope, "uninstall", h.m); code != http.StatusCreated {
				t.Fatalf("owner scoped to the machine's group = %d %v, want 201", code, out)
			}
			return
		}
		var scoped string
		if err := h.su.QueryRow(context.Background(), "SELECT gen_random_uuid()::text").Scan(&scoped); err != nil {
			t.Fatal(err)
		}
		h.rawSQL(`INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, 'scoped@acme.test')`, scoped, h.tenant)
		h.rawSQL(`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
			VALUES ($1, $2, (SELECT id FROM role WHERE key='owner' AND tenant_id IS NULL), ARRAY[$3]::uuid[])`, h.tenant, scoped, h.otherGroup)
		h.stepUp(scoped)
		if code, out := h.request(scoped, "uninstall", h.m); code != http.StatusForbidden {
			t.Fatalf("owner scoped to another group = %d %v, want 403", code, out)
		}
		// docs/62 sec. 2a: scope is inherited DOWNWARD. Re-parent the machine's group under the scoped group.
		h.rawSQL(`UPDATE machine_group SET parent_id = $2 WHERE id = $1`, h.group, h.otherGroup)
		code, out := h.request(scoped, "uninstall", h.m)
		if code != http.StatusCreated {
			t.Fatalf("owner scoped to the PARENT group = %d %v, want 201 (inherited)", code, out)
		}
	})
}

func TestRemovedMachineIsOutOfService(t *testing.T) {
	m := &Machine{Status: MachineStatusRemoved}
	if outOfServiceMachineMsg(m, "start a session") == "" {
		t.Fatal("a removed machine accepts sessions")
	}
	if IsValidMachineStatus(MachineStatusRemoved) {
		t.Fatal("removed must not be a settable status")
	}
}
