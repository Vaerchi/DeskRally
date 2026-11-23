package controlplane

// "Forget this machine" against its concurrent neighbours (docs/65 sec. 8). An uninstall ISSUANCE and an agent's
// final-ack COMPLETE both lock the machine row the forget locks FOR UPDATE, so each pair must end consistent in
// either order: the machine removed exactly once, the directive either complete (the agent's confirmed removal won)
// or forgotten (the Owner's decision won), never both, never neither, and an audit trail that tells the same story.
// The orders are made deterministic with the stores' test hooks (one side is held open while the other starts, and
// must wait for its commit) on two real Postgres connections and, where the fake has the hook, in memory; a
// randomized hammer then lets the scheduler pick.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// holdOpen returns a test hook that closes `paused` the first time it runs and then blocks until release() (safe to
// call more than once; also called at cleanup so a failed assertion cannot leave a held transaction behind).
func holdOpen(t *testing.T) (hook func(), paused <-chan struct{}, release func()) {
	t.Helper()
	p, r := make(chan struct{}), make(chan struct{})
	var once, rel sync.Once
	release = func() { rel.Do(func() { close(r) }) }
	t.Cleanup(release)
	hook = func() {
		once.Do(func() { close(p) })
		<-r
	}
	return hook, p, release
}

func waitPaused(t *testing.T, paused <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-paused:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s never reached its hold", what)
	}
}

// mustStayBlocked fails when done delivers inside the grace period: the operation was supposed to be waiting on a
// lock the held side owns.
func mustStayBlocked[T any](t *testing.T, done <-chan T, what string) {
	t.Helper()
	select {
	case v := <-done:
		t.Fatalf("%s finished (%v) while the other side still held the machine", what, v)
	case <-time.After(500 * time.Millisecond):
	}
}

func (h *dirHarness) setForgetHook(f func()) {
	switch d := h.dirs.(type) {
	case *InMemoryDirectiveStore:
		d.testAfterForgetLock = f
	case *PgDirectiveStore:
		d.testAfterForgetLock = f
	}
}

func (h *dirHarness) setAckHook(f func()) {
	switch d := h.dirs.(type) {
	case *InMemoryDirectiveStore:
		d.testAfterAckLock = f
	case *PgDirectiveStore:
		d.testAfterAckLock = f
	}
}

type httpResult struct {
	code int
	out  map[string]any
}

// ---- forget versus the agent's final-ack complete --------------------------------------------------------------

// The final-ack apply is held open mid-transaction (it holds the machine and the directive): the forget must wait
// for it, then find the machine already removed by the CONFIRMED completion and do nothing at all.
func TestForgetWaitsForAFinalAckCompleteInFlight(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		hook, paused, release := holdOpen(t)
		h.setAckHook(hook)
		defer h.setAckHook(nil)
		ackBody := h.faBody(id, h.m.Priv, "executing", "complete", "msi exit 0", h.nextAckTime())
		ackDone := make(chan httpResult, 1)
		go func() {
			code, out := finalAckOn(t, h.srv(h.owner), id, ackBody)
			ackDone <- httpResult{code, out}
		}()
		waitPaused(t, paused, "the final-ack apply")

		type forgetResult struct {
			res *ForgetResult
			err error
		}
		forgetDone := make(chan forgetResult, 1)
		go func() {
			res, err := h.dirs.ForgetMachine(context.Background(), h.tenant, ForgetMachineInput{MachineID: h.m.ID, ActorID: h.owner, ExpectGroupID: h.group})
			forgetDone <- forgetResult{res, err}
		}()
		mustStayBlocked(t, forgetDone, "the forget")
		release()

		if a := <-ackDone; a.code != http.StatusOK || str(a.out, "outcome") != "applied" || str(a.out, "state") != "complete" {
			t.Fatalf("the held final ack = %d %v, want 200 applied complete", a.code, a.out)
		}
		f := <-forgetDone
		if f.err != nil || !f.res.AlreadyRemoved || len(f.res.Closed) != 0 {
			t.Fatalf("the forget that waited = %+v %v, want AlreadyRemoved with nothing closed", f.res, f.err)
		}
		if got := h.row(id).State; got != DirectiveComplete {
			t.Fatalf("directive %s, want complete (the agent's confirmed removal won)", got)
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s", got)
		}
		if h.auditCount("directive.complete") != 1 || h.auditCount("machine.removed") != 1 ||
			h.auditCount("machine.forgotten") != 0 || h.auditCount("directive.forgotten") != 0 {
			t.Fatalf("audit = %v, want the confirmed removal ONLY", h.auditActions())
		}
	})
}

// The forget holds the machine mid-transaction: the final-ack apply must wait for it, then find the directive
// forgotten and answer 410 - applying nothing, writing nothing, confirming nothing.
func TestAFinalAckCompleteWaitsForAForgetInFlight(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.executingUninstall()
		h.stepUp(h.owner)
		forgetBody := h.forgetBodyFor(h.m)
		ackBody := h.faBody(id, h.m.Priv, "executing", "complete", "msi exit 0", h.nextAckTime())
		hook, paused, release := holdOpen(t)
		h.setForgetHook(hook)
		defer h.setForgetHook(nil)
		forgetDone := make(chan httpResult, 1)
		go func() {
			code, out := h.do(h.owner, "POST", h.forgetPath(h.m), forgetBody)
			forgetDone <- httpResult{code, out}
		}()
		waitPaused(t, paused, "the forget")

		ackDone := make(chan httpResult, 1)
		go func() {
			code, out := finalAckOn(t, h.srv(h.owner), id, ackBody)
			ackDone <- httpResult{code, out}
		}()
		mustStayBlocked(t, ackDone, "the final-ack apply")
		release()

		if f := <-forgetDone; f.code != http.StatusOK || str(f.out, "outcome") != "forgotten" {
			t.Fatalf("the held forget = %d %v, want 200 forgotten", f.code, f.out)
		}
		a := <-ackDone
		if a.code != http.StatusGone || !strings.Contains(str(a.out, "error"), "owner forgot the machine") || a.out["outcome"] != nil {
			t.Fatalf("the final ack that waited = %d %v, want 410 naming the forget", a.code, a.out)
		}
		if got := h.row(id).State; got != DirectiveForgotten {
			t.Fatalf("directive %s, want forgotten (the Owner's decision won)", got)
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s", got)
		}
		if h.auditCount("machine.forgotten") != 1 || h.auditCount("directive.forgotten") != 1 ||
			h.auditCount("directive.complete") != 0 || h.auditCount("machine.removed") != 0 {
			t.Fatalf("audit = %v, want the forget ONLY", h.auditActions())
		}
	})
}

// Whichever of the two wins, the pair ends consistent (the scheduler picks; the invariants do not care).
func TestForgetAndAFinalAckCompleteRaceEndsConsistent(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		ctx := context.Background()
		completed, forgotten := 0, 0
		for i := 0; i < 16; i++ {
			m, id := h.removalAt(DirectiveExecuting)
			d := h.row(id)
			ack, err := SignDirectiveAck(m.Priv, d.TenantID, d.DeviceID, d.ID, d.KeyFP, "executing", "complete", h.nextAckTime().UnixMilli(), "msi exit 0")
			if err != nil {
				t.Fatal(err)
			}
			var (
				wg      sync.WaitGroup
				fres    *ForgetResult
				ferr    error
				applied bool
				aerr    error
			)
			start := make(chan struct{})
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				fres, ferr = h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{MachineID: m.ID, ActorID: h.owner, ExpectGroupID: h.group})
			}()
			go func() {
				defer wg.Done()
				<-start
				_, applied, aerr = h.dirs.ApplyAckVia(ctx, h.tenant, id, m.Device, ack, directiveFinalAckChannel)
			}()
			close(start)
			wg.Wait()

			if got := h.machine(m.ID).Status; got != MachineStatusRemoved {
				t.Fatalf("iter %d: machine %s, want removed", i, got)
			}
			switch st := h.row(id).State; st {
			case DirectiveComplete:
				completed++
				if ferr != nil || !fres.AlreadyRemoved || aerr != nil || !applied {
					t.Fatalf("iter %d: complete, but forget=%+v/%v ack=%v/%v", i, fres, ferr, applied, aerr)
				}
			case DirectiveForgotten:
				forgotten++
				if ferr != nil || fres.AlreadyRemoved || len(fres.Closed) != 1 || applied || !errors.Is(aerr, ErrDirectiveFinalAckWindowClosed) {
					t.Fatalf("iter %d: forgotten, but forget=%+v/%v ack=%v/%v", i, fres, ferr, applied, aerr)
				}
			default:
				t.Fatalf("iter %d: directive ended as %s, want complete or forgotten", i, st)
			}
		}
		// The trail tells the same story as the rows: one removal record per iteration, never both kinds for one.
		if h.auditCount("directive.complete") != completed || h.auditCount("machine.removed") != completed ||
			h.auditCount("machine.forgotten") != forgotten || h.auditCount("directive.forgotten") != forgotten {
			t.Fatalf("audit (complete=%d forgotten=%d): %v", completed, forgotten, h.auditActions())
		}
		t.Logf("%d confirmed first, %d forgotten first", completed, forgotten)
	})
}

// ---- forget versus an uninstall ISSUANCE -----------------------------------------------------------------------

// Postgres: the issuance is held open after it read the policy (it holds the machine FOR SHARE and the directive):
// the forget must wait for its commit, then close the now-ISSUED directive. Both are in the trail, in that order.
func TestForgetWaitsForAnIssuanceInFlight(t *testing.T) {
	h := newPgDirHarness(t)
	pg := h.dirs.(*PgDirectiveStore)
	id := h.mustRequestUninstall(h.owner, h.m)
	h.advance(directiveCancelWindow + time.Minute)
	// The forgetter is the OTHER owner: a step-up moves the requester's MFA generation, which would (rightly)
	// cancel the issuance the requester's session is still paying for.
	h.stepUp(h.owner2)
	forgetBody := h.forgetBodyFor(h.m)
	hook, paused, release := holdOpen(t)
	pg.testAfterPolicyRead = hook
	defer func() { pg.testAfterPolicyRead = nil }()

	type issued struct {
		d   *AgentDirective
		err error
	}
	issueDone := make(chan issued, 1)
	go func() {
		d, err := h.srv(h.owner).issueDirective(context.Background(), h.tenant, id)
		issueDone <- issued{d, err}
	}()
	waitPaused(t, paused, "the issuance")
	forgetDone := make(chan httpResult, 1)
	go func() {
		code, out := h.do(h.owner2, "POST", h.forgetPath(h.m), forgetBody)
		forgetDone <- httpResult{code, out}
	}()
	mustStayBlocked(t, forgetDone, "the forget")
	release()

	if r := <-issueDone; r.err != nil || r.d == nil || r.d.State != DirectiveIssued {
		t.Fatalf("the held issuance = %+v %v, want issued", r.d, r.err)
	}
	f := <-forgetDone
	if f.code != http.StatusOK || str(f.out, "outcome") != "forgotten" || len(closedIDs(f.out)) != 1 || closedIDs(f.out)[0] != id {
		t.Fatalf("the forget that waited = %d %v, want 200 forgotten with the issued directive closed", f.code, f.out)
	}
	d := h.row(id)
	if d.State != DirectiveForgotten || d.IssuedAt == nil || d.Artifact == "" {
		t.Fatalf("directive = %s issued_at=%v artifact=%v, want forgotten (its issuance kept as evidence)", d.State, d.IssuedAt, d.Artifact != "")
	}
	if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
		t.Fatalf("machine %s", got)
	}
	// The directive was signed, but the device can neither register nor fetch it any more.
	if code, _ := h.internal("GET", "/internal/devices/"+h.m.Device+"/directives/pending", ""); code != http.StatusNotFound {
		t.Fatalf("pending fetch for a forgotten machine = %d, want 404", code)
	}
	acts := h.auditActions()
	issuedAt, forgottenAt := indexOf(acts, "directive.issued"), indexOf(acts, "machine.forgotten")
	if issuedAt < 0 || forgottenAt < issuedAt || h.auditCount("directive.issued") != 1 || h.auditCount("directive.forgotten") != 1 {
		t.Fatalf("audit = %v, want directive.issued before machine.forgotten", acts)
	}
}

// Both backends: the forget is held open after it locked the machine: the issuance must wait for it, then find the
// directive forgotten - never signing it, never notifying signaling, never writing directive.issued.
func TestAnIssuanceWaitsForAForgetInFlight(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(directiveCancelWindow + time.Minute)
		h.stepUp(h.owner2)
		forgetBody := h.forgetBodyFor(h.m)
		hook, paused, release := holdOpen(t)
		h.setForgetHook(hook)
		defer h.setForgetHook(nil)
		forgetDone := make(chan httpResult, 1)
		go func() {
			code, out := h.do(h.owner2, "POST", h.forgetPath(h.m), forgetBody)
			forgetDone <- httpResult{code, out}
		}()
		waitPaused(t, paused, "the forget")

		type issued struct {
			d   *AgentDirective
			err error
		}
		issueDone := make(chan issued, 1)
		go func() {
			d, err := h.srv(h.owner).issueDirective(context.Background(), h.tenant, id)
			issueDone <- issued{d, err}
		}()
		mustStayBlocked(t, issueDone, "the issuance")
		release()

		if f := <-forgetDone; f.code != http.StatusOK || str(f.out, "outcome") != "forgotten" {
			t.Fatalf("the held forget = %d %v, want 200 forgotten", f.code, f.out)
		}
		r := <-issueDone
		if !errors.Is(r.err, ErrDirectiveNotIssuable) {
			t.Fatalf("the issuance that waited = %+v %v, want ErrDirectiveNotIssuable", r.d, r.err)
		}
		d := h.row(id)
		if d.State != DirectiveForgotten || d.Artifact != "" || d.IssuedAt != nil {
			t.Fatalf("directive = %s issued_at=%v artifact=%v, want forgotten and NEVER signed", d.State, d.IssuedAt, d.Artifact != "")
		}
		if h.auditCount("directive.issued") != 0 || h.notes.count(h.m.Device) != 0 {
			t.Fatalf("audit = %v, notifications = %d: the forgotten request was issued", h.auditActions(), h.notes.count(h.m.Device))
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s", got)
		}
	})
}

// ---- forget versus a status change and versus another forget -----------------------------------------------------

// An un-retire that arrives while a forget holds the machine must wait, and then find the machine removed (the
// terminal tombstone: never un-retired, never reactivated).
func TestAnUnRetireWaitsForAForgetInFlight(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		hook, paused, release := holdOpen(t)
		h.setForgetHook(hook)
		defer h.setForgetHook(nil)
		type forgetResult struct {
			res *ForgetResult
			err error
		}
		forgetDone := make(chan forgetResult, 1)
		go func() {
			res, err := h.dirs.ForgetMachine(context.Background(), h.tenant, ForgetMachineInput{MachineID: h.m.ID, ActorID: h.owner, ExpectGroupID: h.group})
			forgetDone <- forgetResult{res, err}
		}()
		waitPaused(t, paused, "the forget")
		statusDone := make(chan error, 1)
		go func() {
			statusDone <- h.machines.SetMachineStatus(context.Background(), h.tenant, h.m.ID, MachineStatusActive)
		}()
		mustStayBlocked(t, statusDone, "the un-retire")
		release()
		if f := <-forgetDone; f.err != nil || f.res.AlreadyRemoved {
			t.Fatalf("the held forget = %+v %v", f.res, f.err)
		}
		if err := <-statusDone; !errors.Is(err, ErrMachineRemoved) {
			t.Fatalf("the un-retire that waited = %v, want ErrMachineRemoved", err)
		}
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s", got)
		}
	})
}

// Two Owners forget the same machine at the same moment: exactly one forgets it, the other is told it is already
// removed, and the trail has ONE set of rows.
func TestTwoForgetsOfOneMachineEndWithOneSetOfRows(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		ctx := context.Background()
		for i := 0; i < 8; i++ {
			m, id := h.removalAt(DirectiveExecuting)
			var wg sync.WaitGroup
			results := make([]*ForgetResult, 2)
			errs := make([]error, 2)
			start := make(chan struct{})
			for k, actor := range []string{h.owner, h.owner2} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					results[k], errs[k] = h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{MachineID: m.ID, ActorID: actor, ExpectGroupID: h.group})
				}()
			}
			close(start)
			wg.Wait()
			if errs[0] != nil || errs[1] != nil {
				t.Fatalf("iter %d: errors %v %v", i, errs[0], errs[1])
			}
			if results[0].AlreadyRemoved == results[1].AlreadyRemoved {
				t.Fatalf("iter %d: AlreadyRemoved = %v and %v, want exactly one winner", i, results[0].AlreadyRemoved, results[1].AlreadyRemoved)
			}
			if h.row(id).State != DirectiveForgotten || h.machine(m.ID).Status != MachineStatusRemoved {
				t.Fatalf("iter %d: directive %s machine %s", i, h.row(id).State, h.machine(m.ID).Status)
			}
		}
		if h.auditCount("machine.forgotten") != 8 || h.auditCount("directive.forgotten") != 8 {
			t.Fatalf("audit = %v, want exactly one set of rows per machine", h.auditActions())
		}
	})
}

func indexOf(list []string, want string) int {
	for i, s := range list {
		if s == want {
			return i
		}
	}
	return -1
}
