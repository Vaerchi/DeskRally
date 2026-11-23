package controlplane

// Review round 3 of docs/65 (fleet directives): each test here fails without the fix it names.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ---- 1. a policy change serializes with issuance on one tenant lock --------------------------------

// TestPolicyChangeCannotSlipBetweenIssuancesPolicyReadAndCommit pauses an issuance exactly after it read the
// policy (no policy row exists yet - the absent-row case) and starts "require a second approver". The change
// must wait for the issuance to commit; before the fix it used a different lock, completed at once, and the
// issuance then signed an uninstall under a policy that no longer applied.
func TestPolicyChangeCannotSlipBetweenIssuancesPolicyReadAndCommit(t *testing.T) {
	h := newPgDirHarness(t)
	pg := h.dirs.(*PgDirectiveStore)
	id := h.mustRequestUninstall(h.owner, h.m)
	h.advance(directiveCancelWindow + time.Minute)

	paused, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	releaseIssuance := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseIssuance() // a failed assertion must not leave the paused issuance holding its connection
	pg.testAfterPolicyRead = func() {
		once.Do(func() { close(paused) })
		<-release
	}
	type result struct {
		d   *AgentDirective
		err error
	}
	issued := make(chan result, 1)
	go func() {
		d, err := h.srv(h.owner).issueDirective(context.Background(), h.tenant, id)
		issued <- result{d, err}
	}()
	select {
	case <-paused:
	case <-time.After(10 * time.Second):
		t.Fatal("issuance never reached the policy read")
	}
	policyDone := make(chan error, 1)
	go func() {
		_, err := h.dirs.SetPolicy(context.Background(), h.tenant, h.owner, true)
		policyDone <- err
	}()
	select {
	case err := <-policyDone:
		t.Fatalf("the policy change completed (%v) while an issuance was between its policy read and its commit", err)
	case <-time.After(500 * time.Millisecond):
	}
	releaseIssuance()
	r := <-issued
	if r.err != nil || r.d == nil || r.d.State != DirectiveIssued {
		t.Fatalf("issuance = %+v %v", r.d, r.err)
	}
	select {
	case err := <-policyDone:
		if err != nil {
			t.Fatalf("policy change: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the policy change never completed after the issuance committed")
	}
	if pol, _ := h.dirs.Policy(context.Background(), h.tenant); !pol.RequireSecondApprover {
		t.Fatal("the policy change was lost")
	}
	// A request made after the change snapshots the new policy.
	m2 := h.addMachineFn(h.group, MachineStatusRetired)
	h.stepUp(h.owner)
	code, out := h.request(h.owner, "uninstall", m2)
	if code != http.StatusCreated || !h.row(dirIDOf(out)).RequireApproval {
		t.Fatalf("a request after the policy change = %d %v, want 201 requiring approval", code, out)
	}
}

// ---- 2. an unconfirmed removal stays exclusive and accepts its genuine late completion -------------

func (h *dirHarness) unconfirmedRemoval() (string, dirMachine) {
	h.t.Helper()
	id := h.mustRequestUninstall(h.owner, h.m)
	h.issueNow(id)
	h.drive(id, h.m, "accepted", "executing")
	h.advance(directiveUnconfirmedAfter + time.Minute)
	h.sweep()
	if d := h.row(id); d.State != DirectiveRemovalUnconfirmed || d.AgentState != DirectiveExecuting {
		h.t.Fatalf("state = %s agent_state = %s, want removal_unconfirmed / executing", d.State, d.AgentState)
	}
	return id, h.m
}

func TestUnconfirmedRemovalKeepsTheMachineGuardedAndExclusive(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		_, m := h.unconfirmedRemoval()
		ctx := context.Background()
		if err := h.machines.SetMachineStatus(ctx, h.tenant, m.ID, MachineStatusActive); !errors.Is(err, ErrMachineHasActiveDirective) {
			t.Fatalf("reactivating a machine with an unresolved removal = %v, want ErrMachineHasActiveDirective", err)
		}
		if err := h.machines.SetMachineGroup(ctx, h.tenant, m.ID, h.otherGroup); !errors.Is(err, ErrMachineHasActiveDirective) {
			t.Fatalf("moving a machine with an unresolved removal = %v, want ErrMachineHasActiveDirective", err)
		}
		if got := h.machine(m.ID); got.Status != MachineStatusRetired || got.GroupID != h.group {
			t.Fatalf("machine changed: %s in %s", got.Status, got.GroupID)
		}
		h.stepUp(h.owner)
		if code, out := h.request(h.owner, "uninstall", m); code != http.StatusConflict {
			t.Fatalf("a second removal while one is unresolved = %d %v, want 409", code, out)
		}
	})
}

func TestLateGenuineCompletionOfAnUnconfirmedRemovalIsAccepted(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		// The agent never learned the control plane's own outcome: its ack names the state IT was in.
		if code, out := h.ack(id, m, "executing", "complete"); code != http.StatusOK || str(out, "outcome") != "applied" {
			t.Fatalf("late executing->complete = %d %v, want 200 applied", code, out)
		}
		if got := h.row(id).State; got != DirectiveComplete {
			t.Fatalf("state = %s, want complete", got)
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s, want removed", got)
		}
	})
}

func TestLateAckMustNameTheAgentsLastState(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		// accepted -> complete is not what the agent was doing; and the agent cannot move an unconfirmed
		// removal anywhere but to its end.
		if code, out := h.ack(id, m, "accepted", "complete"); code != http.StatusConflict {
			t.Fatalf("complete claimed from the wrong state = %d %v, want 409", code, out)
		}
		// reboot_pending -> complete is a legal transition in general, but not from where this agent was.
		if code, out := h.ack(id, m, "reboot_pending", "complete"); code != http.StatusConflict {
			t.Fatalf("complete claimed from a state the agent was never in = %d %v, want 409", code, out)
		}
		if code, out := h.ack(id, m, "executing", "reboot_pending"); code != http.StatusConflict {
			t.Fatalf("reboot_pending from an unconfirmed removal = %d %v, want 409", code, out)
		}
		if got := h.machine(m.ID).Status; got != MachineStatusRetired {
			t.Fatalf("machine %s", got)
		}
	})
}

func TestLateCompletionIsRefusedForARekeyedMachine(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id, m := h.unconfirmedRemoval()
		d := h.row(id)
		ack, err := SignDirectiveAck(m.Priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, "executing", "complete", h.nextAckTime().UnixMilli(), "")
		if err != nil {
			t.Fatal(err)
		}
		// The machine was re-enrolled under a new key after the directive was issued (the store-level
		// defence: the handler's own device-key check would normally stop this earlier).
		_, newPub := newDirKey(t)
		h.setPubkey(m.ID, newPub)
		if _, applied, err := h.dirs.ApplyAck(context.Background(), h.tenant, id, m.Device, ack); !errors.Is(err, ErrDirectiveKeyChanged) || applied {
			t.Fatalf("completion for a re-keyed machine = applied %v err %v, want ErrDirectiveKeyChanged", applied, err)
		}
		if got := h.machine(m.ID).Status; got == MachineStatusRemoved {
			t.Fatal("a re-keyed machine was tombstoned by an old directive")
		}
	})
}

// ---- 3. quotas count issuance time ------------------------------------------------------------------

func TestUninstallQuotaCountsIssuanceTimeNotRequestTime(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.setCaps(1, DefaultReinstallDailyCap)
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(50 * time.Minute) // the sweeper is late: issuance happens near the end of the request's hour
		h.sweep()
		if got := h.row(id).State; got != DirectiveIssued {
			t.Fatalf("first removal state = %s, want issued", got)
		}
		h.advance(15 * time.Minute) // its REQUEST is now 65 minutes old, its ISSUANCE only 15
		m2 := h.addMachineFn(h.group, MachineStatusRetired)
		h.stepUp(h.owner)
		if code, out := h.request(h.owner, "uninstall", m2); code != http.StatusTooManyRequests {
			t.Fatalf("second removal inside the issuance hour = %d %v, want 429", code, out)
		}
	})
}

func TestIssuanceQuotaCountsIssuancesNotReservations(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.setCaps(3, DefaultReinstallDailyCap)
		h.stepUp(h.owner)
		machines := []dirMachine{h.m, h.addMachineFn(h.group, MachineStatusRetired), h.addMachineFn(h.group, MachineStatusRetired)}
		var ids []string
		for _, m := range machines {
			code, out := h.request(h.owner, "uninstall", m)
			if code != http.StatusCreated {
				t.Fatalf("request = %d %v", code, out)
			}
			ids = append(ids, dirIDOf(out))
			// Make "oldest" real: with the fake clock frozen all three would share one due time and the
			// sweep's tie-break (directive id, a random UUID) would decide the order.
			h.advance(time.Second)
		}
		h.setCaps(2, DefaultReinstallDailyCap) // the cap drops while all three wait
		h.advance(directiveCancelWindow + time.Minute)
		h.sweep()
		// Oldest due first: two are issued, the last is refused. Counting the two OTHER reservations
		// against each issuance would have cancelled the FIRST one instead.
		want := []DirectiveState{DirectiveIssued, DirectiveIssued, DirectiveCancelled}
		for i, id := range ids {
			if got := h.row(id).State; got != want[i] {
				t.Fatalf("directive %d state = %s, want %s (reservations are not issuances)", i, got, want[i])
			}
		}
	})
}

// ---- 4. the step-up snapshot is one read --------------------------------------------------------------

func TestRequestRecordsTheGenerationTheStepUpWasVerifiedAgainst(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.stepUp(h.owner)
		srv := h.srv(h.owner)
		// The user's MFA is reset exactly between the step-up read and the rest of the request.
		srv.testAfterStepUp = func() { h.bumpMFA(h.owner) }
		code, out := h.request(h.owner, "uninstall", h.m)
		srv.testAfterStepUp = nil
		if code != http.StatusCreated {
			t.Fatalf("request = %d %v", code, out)
		}
		id := dirIDOf(out)
		h.issueNow(id)
		if d := h.row(id); d.State != DirectiveCancelled || d.Artifact != "" {
			t.Fatalf("issued under a step-up whose factor was reset after it was verified: %+v", d)
		}
	})
}

func TestApprovalRecordsTheGenerationTheStepUpWasVerifiedAgainst(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.policyOn()
		id := h.mustRequestUninstall(h.owner, h.m)
		h.stepUp(h.owner2)
		srv := h.srv(h.owner2)
		srv.testAfterStepUp = func() { h.bumpMFA(h.owner2) }
		code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", "")
		srv.testAfterStepUp = nil
		if code != http.StatusOK {
			t.Fatalf("approve = %d %v", code, out)
		}
		h.issueNow(id)
		if d := h.row(id); d.State != DirectiveCancelled || d.Artifact != "" {
			t.Fatalf("issued on an approval whose factor was reset after it was verified: %+v", d)
		}
	})
}

// ---- 5. the fake's guard is check-and-act ------------------------------------------------------------

// TestMachineMutationCannotInterleaveWithADirectiveReservation holds a reservation open right after the
// machine was validated and shows that a status change and a group move cannot run until it is made - and
// are then refused. (The pg store gets this from the machine row lock; the fake needs the shared lock.)
func TestMachineMutationCannotInterleaveWithADirectiveReservation(t *testing.T) {
	h := newMemDirHarness(t)
	dirs := h.dirs.(*InMemoryDirectiveStore)
	paused, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	releaseReservation := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseReservation()
	dirs.testAfterMachineRead = func() {
		once.Do(func() { close(paused) })
		<-release
	}
	ctx := context.Background()
	reserved := make(chan error, 1)
	go func() {
		_, err := dirs.Request(ctx, h.tenant, DirectiveRequestInput{MachineID: h.m.ID, Kind: DirectiveUninstall,
			RequestedBy: h.owner, ExpectGroupID: h.group, RequestedSession: "s"})
		reserved <- err
	}()
	select {
	case <-paused:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the reservation")
	}
	statusDone, groupDone := make(chan error, 1), make(chan error, 1)
	go func() { statusDone <- h.machines.SetMachineStatus(ctx, h.tenant, h.m.ID, MachineStatusActive) }()
	go func() { groupDone <- h.machines.SetMachineGroup(ctx, h.tenant, h.m.ID, h.otherGroup) }()
	for name, ch := range map[string]chan error{"status change": statusDone, "group move": groupDone} {
		select {
		case err := <-ch:
			t.Fatalf("a %s completed (%v) between the machine validation and the reservation", name, err)
		case <-time.After(300 * time.Millisecond):
		}
	}
	releaseReservation()
	if err := <-reserved; err != nil {
		t.Fatalf("reservation: %v", err)
	}
	for name, ch := range map[string]chan error{"status change": statusDone, "group move": groupDone} {
		if err := <-ch; !errors.Is(err, ErrMachineHasActiveDirective) {
			t.Fatalf("the %s after the reservation = %v, want ErrMachineHasActiveDirective", name, err)
		}
	}
	if got := h.machine(h.m.ID); got.Status != MachineStatusRetired || got.GroupID != h.group {
		t.Fatalf("machine changed under a live reservation: %s in %s", got.Status, got.GroupID)
	}
}
