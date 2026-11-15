package controlplane

// Session transfer / escalation (docs/51 §6-§9). Every test here runs against BOTH backends through
// forEachBackend: the in-memory stores and real Postgres as rmt_app. The Postgres-only properties
// (constraints, RLS, composite FKs, lock order under load) are in session_transfer_pgstore_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func wantCode(t *testing.T, what string, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %d %v, want %d", what, got, body, want)
	}
}

func TestTransferOfferCancelSupersede(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		code, out := h.offer(h.alice, s1, h.bob, "please take this")
		wantCode(t, "offer to bob", code, http.StatusCreated, out)
		tr := transferOf(out)
		first := str(tr, "id")
		if str(tr, "state") != "pending" || str(tr, "session_id") != s1 || str(tr, "to_user_id") != h.bob ||
			str(tr, "from_user_id") != h.alice || str(tr, "to_name") != "Bob" || str(tr, "note") != "please take this" {
			t.Fatalf("offer = %v", tr)
		}
		// machine_id and group_id are DERIVED from S1 (the machine PK and its group), never the request.
		if str(tr, "machine_id") != h.machine || str(tr, "group_id") != h.group {
			t.Fatalf("derived fields = %v, want machine %s group %s", tr, h.machine, h.group)
		}
		if _, out := h.do(h.alice, "GET", "/session-transfers/outgoing", ""); len(out["transfers"].([]any)) != 1 {
			t.Fatalf("outgoing = %v", out)
		}
		if _, out := h.do(h.bob, "GET", "/session-transfers/incoming", ""); len(out["transfers"].([]any)) != 1 {
			t.Fatalf("incoming for bob = %v", out)
		}

		// A new offer supersedes the pending one: exactly one live offer per session.
		code, out = h.offer(h.alice, s1, h.carol, "")
		wantCode(t, "second offer", code, http.StatusCreated, out)
		second := str(transferOf(out), "id")
		if got := h.transfer(first).State; got != TransferSuperseded {
			t.Fatalf("older offer = %s, want superseded", got)
		}
		if got := h.transfer(second).State; got != TransferPending {
			t.Fatalf("newer offer = %s", got)
		}
		if _, out := h.do(h.bob, "GET", "/session-transfers/incoming", ""); len(out["transfers"].([]any)) != 0 {
			t.Fatalf("a superseded offer is still incoming for bob: %v", out)
		}

		// Only the sender cancels; a cancelled offer is terminal.
		code, out = h.do(h.carol, "DELETE", "/session-transfers/"+second, "")
		wantCode(t, "carol cancelling alice's offer", code, http.StatusForbidden, out)
		code, out = h.do(h.alice, "DELETE", "/session-transfers/"+second, "")
		wantCode(t, "alice cancelling", code, http.StatusOK, out)
		if str(transferOf(out), "state") != "cancelled" {
			t.Fatalf("cancel = %v", out)
		}
		code, out = h.do(h.alice, "DELETE", "/session-transfers/"+second, "")
		wantCode(t, "cancelling twice", code, http.StatusConflict, out)
		code, out = h.accept(h.carol, second)
		wantCode(t, "accepting a cancelled offer", code, http.StatusConflict, out)

		// Audit: offered x2, superseded, cancelled, each attributed to its actor.
		if n := h.auditCount("session.transfer_offered"); n != 2 {
			t.Fatalf("offered rows = %d, want 2", n)
		}
		sup := h.auditFor("session.transfer_superseded", first)
		can := h.auditFor("session.transfer_cancelled", second)
		if len(sup) != 1 || sup[0].ActorUserID != h.alice || len(can) != 1 || can[0].ActorUserID != h.alice {
			t.Fatalf("superseded %+v / cancelled %+v", sup, can)
		}
		if h.auditFor("session.transfer_offered", first)[0].ActorUserID != h.alice {
			t.Fatal("the offer row must name the sender")
		}
	})
}

func TestTransferOnlyTheHolderCanOffer(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		// Carol is a technician in every group and Frank an Admin: both hold start_session on this machine,
		// and neither holds S1.
		for _, who := range []string{h.carol, h.frank} {
			code, out := h.offer(who, s1, h.bob, "")
			wantCode(t, "offer by a non-holder", code, http.StatusForbidden, out)
		}
		if _, out := h.do(h.carol, "GET", "/sessions/"+s1+"/transfer-candidates", ""); out["candidates"] != nil {
			t.Fatalf("a non-holder received the candidate list: %v", out)
		}
		// No offer row exists, and nothing was audited as offered.
		if n := h.auditCount("session.transfer_offered"); n != 0 {
			t.Fatalf("offered rows = %d, want 0", n)
		}
		// An ended session cannot be offered.
		h.do(h.alice, "POST", "/sessions/"+s1+"/end", "")
		code, out := h.offer(h.alice, s1, h.bob, "")
		wantCode(t, "offer on an ended session", code, http.StatusConflict, out)
	})
}

func TestTransferIneligibleRecipientIs422(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		other := newUUID() // not a user of this tenant
		for name, to := range map[string]string{
			"read-only user (no start_session)": h.dave,
			"the sender themselves":             h.alice,
			"a user of another tenant":          h.erin,
			"an unknown user":                   other,
		} {
			code, out := h.offer(h.alice, s1, to, "")
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("%s: offer = %d %v, want 422", name, code, out)
			}
		}
		// Scoped away from this machine's group: Bob is scoped to `group`; after the machine moves to a group
		// he cannot reach he is no longer a valid recipient (the CURRENT group decides).
		if err := h.machines.SetMachineGroup(context.Background(), h.tenant, h.machine, h.otherGroup); err != nil {
			t.Fatal(err)
		}
		code, out := h.offer(h.alice, s1, h.bob, "")
		wantCode(t, "offer to a user scoped away from the machine's current group", code, http.StatusUnprocessableEntity, out)
		if err := h.machines.SetMachineGroup(context.Background(), h.tenant, h.machine, h.group); err != nil {
			t.Fatal(err)
		}
		// A disabled user is not a recipient either.
		if err := h.users.SetUserDisabled(context.Background(), h.tenant, h.carol, true); err != nil {
			t.Fatal(err)
		}
		code, out = h.offer(h.alice, s1, h.carol, "")
		wantCode(t, "offer to a disabled user", code, http.StatusUnprocessableEntity, out)
		// The candidates list applies the same rule.
		_, out = h.do(h.alice, "GET", "/sessions/"+s1+"/transfer-candidates", "")
		var ids []string
		for _, c := range out["candidates"].([]any) {
			ids = append(ids, str(c.(map[string]any), "id"))
		}
		if len(ids) != 2 || !(ids[0] == h.bob && ids[1] == h.frank || ids[0] == h.frank && ids[1] == h.bob) {
			t.Fatalf("candidates = %v, want exactly bob and frank (not alice, carol(disabled), dave(read-only))", ids)
		}
		if g := out["group"].(map[string]any); str(g, "id") != h.group {
			t.Fatalf("candidate group = %v", g)
		}
		// An overlong note is a 400.
		long := make([]byte, 501)
		for i := range long {
			long[i] = 'x'
		}
		code, out = h.offer(h.alice, s1, h.bob, string(long))
		wantCode(t, "a 501-character note", code, http.StatusBadRequest, out)
	})
}

func TestTransferAgentAndVouchGates(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		h.setAgent(transferTestAgentOld)
		code, out := h.offer(h.alice, s1, h.bob, "")
		wantCode(t, "offer on an agent older than 0.1.6", code, http.StatusUnprocessableEntity, out)
		if want := "update this machine's agent to hand off a live session"; str(out, "error") != want {
			t.Fatalf("error = %q, want %q", str(out, "error"), want)
		}
		for _, bad := range []string{"garbage", "0.1.6-rc1", "0.1.5+x", "0.0.99"} {
			h.setAgent(bad)
			code, _ = h.offer(h.alice, s1, h.bob, "")
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("agent %q: offer = %d, want 422", bad, code)
			}
		}
		for _, good := range []string{"0.1.6", "0.1.6+abc", "0.2.0+x", "1.0.0"} {
			h.setAgent(good)
			code, out = h.offer(h.alice, s1, h.bob, "")
			if code != http.StatusCreated {
				t.Fatalf("agent %q: offer = %d %v, want 201", good, code, out)
			}
		}
		// A session signaling never vouched for (no redemption row) is refused: the agent's end report,
		// which releases it, only arrives for a brokered session.
		unvouched := h.start(h.carol)
		code, out = h.offer(h.carol, unvouched, h.bob, "")
		wantCode(t, "offer on an unvouched session", code, http.StatusUnprocessableEntity, out)
	})
}

func TestTransferAcceptAuthorizationAndStatusReads(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)

		code, out := h.accept(h.alice, id)
		wantCode(t, "the sender accepting their own offer", code, http.StatusForbidden, out)
		code, out = h.accept(h.carol, id)
		wantCode(t, "a user the offer is not addressed to", code, http.StatusForbidden, out)
		code, out = h.accept(h.dave, id)
		wantCode(t, "a read-only user", code, http.StatusForbidden, out)
		code, out = h.accept(h.erin, id)
		wantCode(t, "a user of another tenant", code, http.StatusNotFound, out)
		if got := h.transfer(id).State; got != TransferPending {
			t.Fatalf("a refused accept moved the offer to %s", got)
		}

		code, out = h.accept(h.bob, id)
		wantCode(t, "bob accepting", code, http.StatusOK, out)
		if str(transferOf(out), "state") != "releasing" || str(transferOf(out), "accepted_by") != h.bob {
			t.Fatalf("accept = %v", out)
		}
		// S1 stays OPEN and keeps its seat; no S2 yet.
		if rec := h.session(s1); rec.EndedAt != nil {
			t.Fatal("accept ended S1; it must stay open until the agent reports it gone")
		}
		if n := len(h.openSessions()); n != 1 {
			t.Fatalf("open sessions after accept = %d, want 1 (S1 only)", n)
		}
		// A repeated accept by the recorded acceptor is a status read: same state, no new audit row.
		for i := 0; i < 2; i++ {
			code, out = h.accept(h.bob, id)
			wantCode(t, "repeat accept", code, http.StatusOK, out)
			if str(transferOf(out), "state") != "releasing" {
				t.Fatalf("repeat accept = %v", out)
			}
		}
		if n := h.auditCount("session.transfer_accepted"); n != 1 {
			t.Fatalf("accepted audit rows = %d, want exactly 1", n)
		}
		// Anyone else is now told the offer is taken, and cannot read it.
		code, _ = h.accept(h.carol, id)
		if code != http.StatusForbidden {
			t.Fatalf("carol on an addressed offer = %d", code)
		}
		code, out = h.get(h.carol, id)
		wantCode(t, "a stranger reading the offer", code, http.StatusNotFound, out)
		code, out = h.get(h.bob, id)
		wantCode(t, "the acceptor reading it", code, http.StatusOK, out)
		code, out = h.get(h.alice, id)
		wantCode(t, "the sender reading it", code, http.StatusOK, out)
	})
}

func TestTransferFinalizesOnlyAfterTheAgentReports(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)

		// The acceptor's poll before the agent has reported: still releasing, no S2.
		for i := 0; i < 2; i++ {
			code, out := h.get(h.bob, id)
			wantCode(t, "poll", code, http.StatusOK, out)
			if str(transferOf(out), "state") != "releasing" {
				t.Fatalf("poll before the report = %v", out)
			}
		}
		if n := len(h.openSessions()); n != 1 {
			t.Fatalf("an S2 exists before the agent confirmed S1 gone: %d open sessions", n)
		}
		// The ticket endpoint refuses until the transfer is accepted.
		code, out := h.do(h.bob, "POST", "/session-transfers/"+id+"/ticket", "")
		wantCode(t, "ticket while releasing", code, http.StatusConflict, out)

		// S1's holder is told why, within one renewal: 409 session transferred, naming Bob.
		code, out = h.do(h.alice, "POST", "/sessions/"+s1+"/policy", "")
		wantCode(t, "S1 renewal while releasing", code, http.StatusConflict, out)
		if str(out, "error") != "session transferred" || str(out, "transferred_to") != "Bob" {
			t.Fatalf("renewal body = %v", out)
		}

		// The agent's authenticated end report arrives: S1 closes and the offer finalizes in one step.
		if code := h.agentEnd(s1); code != http.StatusOK {
			t.Fatalf("end report = %d", code)
		}
		tr := h.transfer(id)
		if tr.State != TransferAccepted || tr.NewSessionID == "" {
			t.Fatalf("after the report: %+v", tr)
		}
		s2 := h.session(tr.NewSessionID)
		if s2.TechnicianID != h.bob || s2.TransferredFrom != s1 || s2.EndedAt != nil || s2.Access != "control" || s2.MachineID != h.machine {
			t.Fatalf("S2 = %+v", s2)
		}
		old := h.session(s1)
		if old.EndedAt == nil || old.EndReason != "transferred" || old.AgentEndedAt == nil || old.TechnicianID != h.alice {
			t.Fatalf("S1 = %+v", old)
		}
		// Audit: S2's session.start links S1 and the offer; S1 keeps Alice as its technician.
		st := h.auditFor("session.start", tr.NewSessionID)
		if len(st) != 1 || st[0].ActorUserID != h.bob {
			t.Fatalf("session.start rows for S2 = %+v", st)
		}
		if meta := string(st[0].Metadata); !strings.Contains(meta, s1) || !strings.Contains(meta, id) {
			t.Fatalf("session.start metadata %s must link S1 %s and the offer %s", meta, s1, id)
		}
		// The holder's renewal after the end still says transferred (S1 is now ended); a non-holder does not.
		code, out = h.do(h.alice, "POST", "/sessions/"+s1+"/policy", "")
		if code != http.StatusConflict || str(out, "error") != "session transferred" || str(out, "transferred_to") != "Bob" {
			t.Fatalf("renewal after finalize = %d %v", code, out)
		}
		code, out = h.do(h.carol, "POST", "/sessions/"+s1+"/policy", "")
		if code != http.StatusConflict || str(out, "error") != "session has ended" || out["transferred_to"] != nil {
			t.Fatalf("a non-holder learned of the transfer: %d %v", code, out)
		}
		// A repeat accept after finalize is a status read of the accepted offer.
		code, out = h.accept(h.bob, id)
		wantCode(t, "repeat accept after finalize", code, http.StatusOK, out)
		if str(transferOf(out), "state") != "accepted" || str(transferOf(out), "new_session_id") != tr.NewSessionID {
			t.Fatalf("repeat accept after finalize = %v", out)
		}
	})
}

func TestTransferDuplicateEndReportDoesNotRefinalize(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.agentEnd(s1)
		tr := h.transfer(id)
		first := h.session(s1).AgentEndedAt
		if tr.State != TransferAccepted || first == nil {
			t.Fatalf("after the first report: %+v / %v", tr, first)
		}
		starts := h.auditCount("session.start")
		open := len(h.openSessions())
		time.Sleep(20 * time.Millisecond)
		for i := 0; i < 3; i++ {
			if code := h.agentEnd(s1); code != http.StatusOK {
				t.Fatalf("duplicate end report = %d", code)
			}
		}
		if got := h.transfer(id); got.NewSessionID != tr.NewSessionID || got.State != TransferAccepted {
			t.Fatalf("a duplicate report changed the offer: %+v", got)
		}
		if h.auditCount("session.start") != starts || len(h.openSessions()) != open {
			t.Fatalf("a duplicate report admitted another session or re-audited (starts %d->%d, open %d->%d)",
				starts, h.auditCount("session.start"), open, len(h.openSessions()))
		}
		if again := h.session(s1).AgentEndedAt; again == nil || !again.Equal(*first) {
			t.Fatalf("agent_ended_at moved from %v to %v: the FIRST report must win", first, again)
		}
	})
}

func TestTransferReleaseTimeoutAndLateReport(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.advance(59 * time.Second)
		if code, out := h.get(h.bob, id); code != http.StatusOK || str(transferOf(out), "state") != "releasing" {
			t.Fatalf("at 59 s the offer must still be releasing: %d %v", code, out)
		}
		h.advance(2 * time.Second) // 61 s with no end report
		code, out := h.get(h.bob, id)
		wantCode(t, "poll after the timeout", code, http.StatusOK, out)
		tr := transferOf(out)
		if str(tr, "state") != "failed" || str(tr, "failure_reason") != "the machine did not confirm the previous session closed" {
			t.Fatalf("after 61 s: %v", tr)
		}
		// Nothing is worse than before the offer: S1 is untouched, S1's renewals stay refused.
		if h.session(s1).EndedAt != nil {
			t.Fatal("the timeout ended S1")
		}
		// The failure was audited with the SYSTEM as actor.
		if f := h.auditFor("session.transfer_failed", id); len(f) != 1 || f[0].ActorUserID != "" {
			t.Fatalf("failed audit rows = %+v", f)
		}
		// A late report after failed may close S1 but never revives the offer or admits an S2.
		h.agentEnd(s1)
		if got := h.transfer(id); got.State != TransferFailed || got.NewSessionID != "" {
			t.Fatalf("a late report revived a failed offer: %+v", got)
		}
		if h.session(s1).EndedAt == nil {
			t.Fatal("the late report should still close S1 (the agent says it is gone)")
		}
		if n := len(h.openSessions()); n != 0 {
			t.Fatalf("a late report after failure admitted a session: %d open", n)
		}
		// A repeat accept by the recorded acceptor reads the failure, with no mutation.
		code, out = h.accept(h.bob, id)
		wantCode(t, "repeat accept after failure", code, http.StatusOK, out)
		if str(transferOf(out), "state") != "failed" {
			t.Fatalf("repeat accept after failure = %v", out)
		}
		// Terminal states are terminal: the failed offer cannot be cancelled and nobody else can take it.
		code, _ = h.do(h.alice, "DELETE", "/session-transfers/"+id, "")
		if code != http.StatusConflict {
			t.Fatalf("cancelling a failed offer = %d", code)
		}
	})
}

func TestTransferFinalizeRederivesAuthority(t *testing.T) {
	cases := []struct {
		name   string
		change func(h *transferHarness)
		undo   func(h *transferHarness)
	}{
		{"the acceptor's role is revoked",
			func(h *transferHarness) { h.setRole(h.bob, RoleReadOnly) },
			func(h *transferHarness) { h.setRole(h.bob, RoleTechnician) }},
		{"the acceptor is disabled",
			func(h *transferHarness) {
				if err := h.users.SetUserDisabled(context.Background(), h.tenant, h.bob, true); err != nil {
					h.t.Fatal(err)
				}
			},
			func(h *transferHarness) {
				if err := h.users.SetUserDisabled(context.Background(), h.tenant, h.bob, false); err != nil {
					h.t.Fatal(err)
				}
			}},
		{"the machine moves to a group the acceptor cannot reach",
			func(h *transferHarness) {
				if err := h.machines.SetMachineGroup(context.Background(), h.tenant, h.machine, h.otherGroup); err != nil {
					h.t.Fatal(err)
				}
			},
			func(h *transferHarness) {
				if err := h.machines.SetMachineGroup(context.Background(), h.tenant, h.machine, h.group); err != nil {
					h.t.Fatal(err)
				}
			}},
		{"the machine is quarantined",
			func(h *transferHarness) {
				if err := h.machines.SetMachineStatus(context.Background(), h.tenant, h.machine, MachineStatusQuarantined); err != nil {
					h.t.Fatal(err)
				}
			},
			func(h *transferHarness) {
				if err := h.machines.SetMachineStatus(context.Background(), h.tenant, h.machine, MachineStatusActive); err != nil {
					h.t.Fatal(err)
				}
			}},
		{"the machine's agent is downgraded below 0.1.6",
			func(h *transferHarness) { h.setAgent(transferTestAgentOld) },
			func(h *transferHarness) { h.setAgent(transferTestAgentOK) }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			forEachBackend(t, func(t *testing.T, h *transferHarness) {
				s1 := h.startVouched(h.alice)
				id := h.mustOffer(h.alice, s1, h.bob)
				h.mustAccept(h.bob, id)
				c.change(h)
				// Quarantine ends the machine's sessions at the control plane, as the admin handler does.
				if c.name == "the machine is quarantined" {
					if _, err := h.records.EndSessionsForMachine(context.Background(), h.tenant, h.machine); err != nil {
						t.Fatal(err)
					}
				}
				h.agentEnd(s1)
				tr := h.transfer(id)
				if tr.State != TransferFailed || tr.FailureReason == "" || tr.NewSessionID != "" {
					t.Fatalf("%s: offer = %+v, want failed with a reason and no S2", c.name, tr)
				}
				if n := len(h.openSessions()); n != 0 {
					t.Fatalf("%s: %d open sessions; a failed finalize must create no S2", c.name, n)
				}
				if h.session(s1).EndedAt == nil {
					t.Fatalf("%s: the agent confirmed S1 gone, so it must be closed", c.name)
				}
				if f := h.auditFor("session.transfer_failed", id); len(f) != 1 {
					t.Fatalf("%s: failed audit rows = %d", c.name, len(f))
				}
				// The acceptor is told why, by status read.
				if code, out := h.accept(h.bob, id); code != http.StatusOK && code != http.StatusForbidden {
					t.Fatalf("%s: repeat accept = %d %v", c.name, code, out)
				}
				c.undo(h)
			})
		})
	}
}

func TestTransferSeatCapDoesNotBlockTheTransfer(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		h.setCap(1) // a FULL tenant: S1 holds the only seat
		s1 := h.startVouched(h.alice)
		if code, _ := h.do(h.carol, "POST", "/sessions", `{"machine_id":"`+transferTestDevice+`"}`); code != http.StatusConflict {
			t.Fatalf("a second start under cap 1 = %d, want 409 (precondition)", code)
		}
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		// Finalize with S1 still OPEN in the control plane: S1 must end in the SAME transaction that admits
		// S2, so the counts see S1's seat freed. (Via the store, so S1 is not closed by the report handler.)
		admit := h.srv(h.bob).transferAdmitter(h.tenant)
		if err := h.transfers.RecordAgentEnded(context.Background(), h.tenant, s1, time.Now().UTC(), admit); err != nil {
			t.Fatal(err)
		}
		tr := h.transfer(id)
		if tr.State != TransferAccepted {
			t.Fatalf("a full tenant blocked the transfer: %+v", tr)
		}
		open := h.openSessions()
		if len(open) != 1 || open[0].ID != tr.NewSessionID || open[0].TechnicianID != h.bob {
			t.Fatalf("open sessions = %+v, want only bob's S2", open)
		}
		if h.session(s1).EndedAt == nil || h.session(s1).EndReason != "transferred" {
			t.Fatalf("S1 = %+v", h.session(s1))
		}
		// The end S1 row is audited by the transfer (the report handler did not run).
		if e := h.auditFor("session.end", s1); len(e) != 1 || !strings.Contains(string(e[0].Metadata), "transferred") {
			t.Fatalf("S1 session.end rows = %+v", e)
		}
	})
}

func TestTransferFailsWhenS2WouldExceedTheCap(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		h.start(h.carol) // a second open session (cap not yet set)
		h.setCap(1)      // now S1 + carol's session exceed the cap: freeing S1 still leaves it full
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		admit := h.srv(h.bob).transferAdmitter(h.tenant)
		if err := h.transfers.RecordAgentEnded(context.Background(), h.tenant, s1, time.Now().UTC(), admit); err != nil {
			t.Fatal(err)
		}
		tr := h.transfer(id)
		if tr.State != TransferFailed || tr.FailureReason != "concurrent session limit reached for this tenant" {
			t.Fatalf("offer = %+v, want failed on the tenant cap", tr)
		}
		// S1's end stands (the agent said it is gone); no S2 was admitted over the cap.
		if h.session(s1).EndedAt == nil {
			t.Fatal("S1 must end even though S2 could not be admitted")
		}
		if n := len(h.openSessions()); n != 1 {
			t.Fatalf("open sessions = %d, want only carol's", n)
		}
	})
}

func TestTransferConcurrentDoubleAcceptExactlyOneWins(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, "") // escalation: Bob and Carol may both accept
		var wg sync.WaitGroup
		codes := make([]int, 2)
		start := make(chan struct{})
		for i, who := range []string{h.bob, h.carol} {
			wg.Add(1)
			go func(i int, who string) {
				defer wg.Done()
				<-start
				codes[i], _ = h.accept(who, id)
			}(i, who)
		}
		close(start)
		wg.Wait()
		wins, conflicts := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusOK:
				wins++
			case http.StatusConflict:
				conflicts++
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("concurrent accepts = %v, want exactly one 200 and one 409", codes)
		}
		tr := h.transfer(id)
		if tr.State != TransferReleasing || (tr.AcceptedBy != h.bob && tr.AcceptedBy != h.carol) {
			t.Fatalf("offer = %+v", tr)
		}
		if n := h.auditCount("session.transfer_accepted"); n != 1 {
			t.Fatalf("accepted audit rows = %d, want 1", n)
		}
		// Finalizing admits exactly one S2, for the winner.
		h.agentEnd(s1)
		open := h.openSessions()
		if len(open) != 1 || open[0].TechnicianID != tr.AcceptedBy {
			t.Fatalf("open sessions after finalize = %+v", open)
		}
	})
}

func TestTransferOfferDuringReleasingIsRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, "")
		h.mustAccept(h.bob, id)
		code, out := h.offer(h.alice, s1, h.carol, "")
		wantCode(t, "a second offer while one is releasing", code, http.StatusConflict, out)
		if got := h.transfer(id).State; got != TransferReleasing {
			t.Fatalf("the releasing offer changed to %s", got)
		}
		if n := h.auditCount("session.transfer_offered"); n != 1 {
			t.Fatalf("offered rows = %d, want 1", n)
		}
	})
}

func TestTransferConcurrentOfferAndAccept(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		for round := 0; round < 4; round++ {
			s1 := h.startVouched(h.alice)
			first := h.mustOffer(h.alice, s1, "")
			var offerCode, acceptCode int
			var secondID string
			var wg sync.WaitGroup
			start := make(chan struct{})
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				var out map[string]any
				offerCode, out = h.offer(h.alice, s1, "", "again")
				secondID = str(transferOf(out), "id")
			}()
			go func() {
				defer wg.Done()
				<-start
				acceptCode, _ = h.accept(h.bob, first)
			}()
			close(start)
			wg.Wait()
			firstState := h.transfer(first).State
			switch {
			case acceptCode == http.StatusOK && offerCode == http.StatusConflict:
				if firstState != TransferReleasing {
					t.Fatalf("accept won but the offer is %s", firstState)
				}
			case offerCode == http.StatusCreated && acceptCode == http.StatusConflict:
				if firstState != TransferSuperseded || h.transfer(secondID).State != TransferPending {
					t.Fatalf("offer won but first=%s second=%s", firstState, h.transfer(secondID).State)
				}
			default:
				t.Fatalf("round %d: offer=%d accept=%d is not one of the two serial outcomes", round, offerCode, acceptCode)
			}
			h.do(h.alice, "POST", "/sessions/"+s1+"/end", "")
		}
	})
}

func TestTransferAcceptAfterExpiryOrAfterS1Ended(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.advance(4*time.Minute + 55*time.Second)
		if code, out := h.do(h.bob, "GET", "/session-transfers/incoming", ""); code != http.StatusOK || len(out["transfers"].([]any)) != 1 {
			t.Fatalf("a 4:59 offer must still be listed: %d %v", code, out)
		}
		h.advance(10 * time.Second)
		if _, out := h.do(h.bob, "GET", "/session-transfers/incoming", ""); len(out["transfers"].([]any)) != 0 {
			t.Fatalf("an expired offer is still listed: %v", out)
		}
		code, out := h.accept(h.bob, id)
		wantCode(t, "accept after 5 minutes", code, http.StatusConflict, out)
		if got := h.transfer(id).State; got != TransferExpired {
			t.Fatalf("offer = %s, want expired", got)
		}
		if e := h.auditFor("session.transfer_expired", id); len(e) != 1 || e[0].ActorUserID != "" {
			t.Fatalf("expired audit rows = %+v (the actor must be the system)", e)
		}
		if h.session(s1).EndedAt != nil {
			t.Fatal("an expired offer must not touch S1")
		}
		// Expired is terminal: even the sender's cancel and a fresh accept both refuse.
		code, _ = h.do(h.alice, "DELETE", "/session-transfers/"+id, "")
		if code != http.StatusConflict {
			t.Fatalf("cancelling an expired offer = %d", code)
		}

		// After S1 ended: accept is refused.
		id2 := h.mustOffer(h.alice, s1, h.bob)
		h.do(h.alice, "POST", "/sessions/"+s1+"/end", "")
		code, out = h.accept(h.bob, id2)
		wantCode(t, "accept after S1 ended", code, http.StatusConflict, out)
		if got := h.transfer(id2).State; got != TransferPending {
			t.Fatalf("offer = %s; an accept that cannot proceed must not move it", got)
		}
		if _, out := h.do(h.bob, "GET", "/session-transfers/incoming", ""); len(out["transfers"].([]any)) != 0 {
			t.Fatalf("an offer on an ended session is still listed: %v", out)
		}
		// A report committed BEFORE the accept closes S1, so the accept refuses (agent-side end).
		s3 := h.startVouched(h.alice)
		id3 := h.mustOffer(h.alice, s3, h.bob)
		h.agentEnd(s3)
		code, out = h.accept(h.bob, id3)
		wantCode(t, "accept after the agent's end report", code, http.StatusConflict, out)
	})
}

func TestTransferTenantIsolation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, "")
		// Erin owns ANOTHER tenant: she sees nothing, and every route says 404 as if it never existed.
		if code, out := h.do(h.erin, "GET", "/session-transfers/incoming", ""); code != http.StatusOK || len(out["transfers"].([]any)) != 0 {
			t.Fatalf("incoming across tenants = %d %v", code, out)
		}
		if code, out := h.do(h.erin, "GET", "/session-transfers/outgoing", ""); code != http.StatusOK || len(out["transfers"].([]any)) != 0 {
			t.Fatalf("outgoing across tenants = %d %v", code, out)
		}
		for _, c := range []struct{ method, path string }{
			{"GET", "/session-transfers/" + id}, {"POST", "/session-transfers/" + id + "/accept"},
			{"DELETE", "/session-transfers/" + id}, {"POST", "/session-transfers/" + id + "/ticket"},
		} {
			if code, out := h.do(h.erin, c.method, c.path, ""); code != http.StatusNotFound {
				t.Fatalf("%s %s across tenants = %d %v, want 404", c.method, c.path, code, out)
			}
		}
		code, out := h.offer(h.erin, s1, h.alice, "")
		if code != http.StatusNotFound {
			t.Fatalf("offering another tenant's session = %d %v, want 404", code, out)
		}
		// The store itself is tenant-scoped too.
		if _, err := h.transfers.Get(context.Background(), h.alienTenant, id); err == nil {
			t.Fatal("the store resolved another tenant's offer")
		}
		if got := h.transfer(id).State; got != TransferPending {
			t.Fatalf("cross-tenant calls moved the offer to %s", got)
		}
	})
}

func TestTransferGroupEscalationVisibility(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, "")
		list := func(user string) int {
			code, out := h.do(user, "GET", "/session-transfers/incoming", "")
			wantCode(t, "incoming", code, http.StatusOK, out)
			return len(out["transfers"].([]any))
		}
		if list(h.bob) != 1 || list(h.carol) != 1 || list(h.frank) != 1 {
			t.Fatal("holders of start_session on the machine's group must see a group escalation")
		}
		if list(h.dave) != 0 {
			t.Fatal("a read-only user saw a group escalation")
		}
		if list(h.alice) != 0 {
			t.Fatal("the sender saw their own offer as incoming")
		}
		// Re-derived per listing against the CURRENT group: when the machine moves out of Bob's scope he
		// stops seeing the machine's name and note.
		if err := h.machines.SetMachineGroup(context.Background(), h.tenant, h.machine, h.otherGroup); err != nil {
			t.Fatal(err)
		}
		if list(h.bob) != 0 {
			t.Fatal("a user scoped away from the machine's CURRENT group still saw the offer")
		}
		if list(h.carol) != 1 {
			t.Fatal("a tenant-wide technician lost the offer")
		}
		if code, _ := h.accept(h.bob, id); code != http.StatusForbidden {
			t.Fatalf("accept by a user scoped away = %d, want 403", code)
		}
		if code, _ := h.get(h.bob, id); code != http.StatusNotFound {
			t.Fatalf("reading an escalation scoped away = %d, want 404", code)
		}
	})
}

func TestTransferTicketIdempotentBeforeRedemptionAnd409After(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		code, out := h.do(h.bob, "POST", "/session-transfers/"+id+"/ticket", "")
		wantCode(t, "ticket while releasing", code, http.StatusConflict, out)
		h.agentEnd(s1)
		s2 := h.transfer(id).NewSessionID
		if s2 == "" {
			t.Fatal("no S2")
		}

		// Only the acceptor may fetch it.
		for _, who := range []string{h.alice, h.carol} {
			if code, _ := h.do(who, "POST", "/session-transfers/"+id+"/ticket", ""); code != http.StatusForbidden {
				t.Fatalf("ticket for a non-acceptor = %d, want 403", code)
			}
		}
		// Before redemption: idempotent. A lost response is retried and yields the same S2 and a fresh ticket.
		for i := 0; i < 3; i++ {
			code, out := h.do(h.bob, "POST", "/session-transfers/"+id+"/ticket", "")
			wantCode(t, "ticket before redemption", code, http.StatusOK, out)
			if sid := str(out["session"].(map[string]any), "id"); sid != s2 {
				t.Fatalf("ticket names session %s, want S2 %s", sid, s2)
			}
			sig := out["signaling"].(map[string]any)
			if str(sig, "session_id") != s2 || str(sig, "device_id") != transferTestDevice || str(sig, "url") != "ws://signal.example/ws" {
				t.Fatalf("signaling = %v", sig)
			}
			if _, ok := sig["ticket"].(map[string]any); !ok {
				t.Fatalf("no ticket in %v", sig)
			}
		}
		// S2's brokering is the same as POST /sessions': the plain control path mints no policy for a group
		// that asks for nothing (see brokerSessionStart), exactly as a fresh start.
		// After redemption: complete. The old connection is the live one; recovery is POST /sessions.
		h.redeem(s2)
		code, out = h.do(h.bob, "POST", "/session-transfers/"+id+"/ticket", "")
		wantCode(t, "ticket after redemption", code, http.StatusConflict, out)
		if str(out, "error") != "already connected; reconnect" {
			t.Fatalf("error = %q", str(out, "error"))
		}
		// And a reconnect through the ordinary path works for the new holder.
		h.do(h.bob, "POST", "/sessions/"+s2+"/end", "")
		if _, out := h.do(h.bob, "POST", "/sessions", `{"machine_id":"`+transferTestDevice+`"}`); out["session"] == nil {
			t.Fatalf("recovery through POST /sessions failed: %v", out)
		}
	})
}

func TestTransferTicketMintsThePolicyAGroupMandateRequires(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		// A view-only mandate: POST /sessions mints a signed policy for it; the ticket endpoint must too.
		gp := h.srv(h.alice).GroupSessionPolicies
		if err := gp.Set(context.Background(), h.tenant, h.group, GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
			t.Fatal(err)
		}
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.agentEnd(s1)
		code, out := h.do(h.bob, "POST", "/session-transfers/"+id+"/ticket", "")
		wantCode(t, "ticket", code, http.StatusOK, out)
		pol, ok := out["session_policy"].(map[string]any)
		if !ok || pol["view_only"] != true || str(pol, "signed") == "" {
			t.Fatalf("session_policy = %v, want a signed view_only policy like POST /sessions mints", out["session_policy"])
		}
	})
}

func TestTransferRenewIsRefusedWithTransferredTo(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		// Before any transfer a renewal is granted.
		if code, out := h.do(h.alice, "POST", "/sessions/"+s1+"/policy", ""); code != http.StatusOK || out["session_policy"] == nil {
			t.Fatalf("an ordinary renewal = %d %v", code, out)
		}
		id := h.mustOffer(h.alice, s1, h.bob)
		// A PENDING offer does not stop renewals: nothing has been handed over yet.
		if code, _ := h.do(h.alice, "POST", "/sessions/"+s1+"/policy", ""); code != http.StatusOK {
			t.Fatalf("renewal with a pending offer = %d", code)
		}
		h.mustAccept(h.bob, id)
		code, out := h.do(h.alice, "POST", "/sessions/"+s1+"/policy", "")
		wantCode(t, "renewal while releasing", code, http.StatusConflict, out)
		if str(out, "error") != "session transferred" || str(out, "transferred_to") != "Bob" {
			t.Fatalf("body = %v", out)
		}
		// A failed transfer keeps the refusal while S1 lives (docs/51 §8.4: S1's renewals stay refused).
		h.advance(2 * time.Minute)
		h.get(h.bob, id)
		if h.transfer(id).State != TransferFailed {
			t.Fatal("precondition: the offer should have failed on the timeout")
		}
		// Codex review: once a hand-off reached releasing, S1 NEVER renews again, even after it failed,
		// or a viewer that keeps renewing keeps S1 alive indefinitely (docs/51 §8.4). Repeatedly.
		for i := 0; i < 2; i++ {
			code, out = h.do(h.alice, "POST", "/sessions/"+s1+"/policy", "")
			wantCode(t, "renewal after a failed transfer", code, http.StatusConflict, out)
			if str(out, "error") != "session handed off; the transfer did not complete" {
				t.Fatalf("renewal after a failed transfer: body = %v", out)
			}
		}
	})
}

func TestTransferAuditRowsAreWrittenWithTheTransition(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.agentEnd(s1)
		tr := h.transfer(id)
		acc := h.auditFor("session.transfer_accepted", id)
		if len(acc) != 1 || acc[0].ActorUserID != h.bob || acc[0].TargetKind != "session_transfer" {
			t.Fatalf("accepted rows = %+v", acc)
		}
		for _, want := range []string{s1, h.alice, h.bob, h.machine, id} {
			if !strings.Contains(string(acc[0].Metadata), want) {
				t.Fatalf("accepted metadata %s lacks %s", acc[0].Metadata, want)
			}
		}
		st := h.auditFor("session.start", tr.NewSessionID)
		if len(st) != 1 {
			t.Fatalf("session.start rows = %+v", st)
		}
		var startMeta map[string]any // jsonb re-spaces the metadata, so compare decoded, not as text
		if err := json.Unmarshal(st[0].Metadata, &startMeta); err != nil || startMeta["transferred_from"] != s1 || startMeta["transfer_id"] != id {
			t.Fatalf("session.start metadata = %s", st[0].Metadata)
		}
		// S1's session.end exists exactly once (the agent's report; the pg store records it, the in-memory
		// fake's guest-end stand-in does not model audit).
		if h.pg {
			if e := h.auditFor("session.end", s1); len(e) != 1 {
				t.Fatalf("S1 session.end rows = %d, want 1 (one end, one row)", len(e))
			}
		}
	})
}

func TestTransferCandidatesRequireTheHolder(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		code, out := h.do(h.bob, "GET", "/sessions/"+s1+"/transfer-candidates", "")
		wantCode(t, "candidates for a non-holder", code, http.StatusForbidden, out)
		code, out = h.do(h.alice, "GET", "/sessions/"+s1+"/transfer-candidates", "")
		wantCode(t, "candidates for the holder", code, http.StatusOK, out)
		if code, _ := h.do(h.erin, "GET", "/sessions/"+s1+"/transfer-candidates", ""); code != http.StatusNotFound {
			t.Fatalf("candidates across tenants = %d, want 404", code)
		}
	})
}

// Codex review: the deadline is judged by when the agent's report FIRST arrived, not by whether a poll or
// sweep happened to run. No poll here between the deadline and the report.
func TestTransferFirstReportAfterTheDeadlineFails(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.advance(61 * time.Second) // past the deadline, and nothing reconciles meanwhile
		h.agentEnd(s1)              // the first report arrives late
		if got := h.transfer(id); got.State != TransferFailed || got.NewSessionID != "" {
			t.Fatalf("a first report after the deadline finalized: %+v", got)
		}
		if n := len(h.openSessions()); n != 0 {
			t.Fatalf("a late first report admitted a session: %d open", n)
		}
		code, out := h.get(h.bob, id)
		wantCode(t, "poll after a late report", code, http.StatusOK, out)
		if str(transferOf(out), "state") != "failed" {
			t.Fatalf("poll after a late report: %v", out)
		}
	})
}

// The other side of the same rule: a TIMELY report still finalizes even when the reconcile only runs
// after the deadline (a delayed retry must not turn an on-time hand-off into a failure).
func TestTransferTimelyReportFinalizesOnALateRetry(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.advance(10 * time.Second)
		h.agentEnd(s1) // on time
		h.advance(2 * time.Minute)
		code, out := h.get(h.bob, id)
		wantCode(t, "late poll after a timely report", code, http.StatusOK, out)
		if str(transferOf(out), "state") != "accepted" {
			t.Fatalf("a timely report did not finalize on a late retry: %v", out)
		}
	})
}

// Codex impl round 3: the S2 ticket endpoint re-runs the full start-time admission. A restriction that an
// ordinary unattended start refuses (here require_recording, a PASS4 absolute gate), enabled between
// finalize and the ticket fetch, refuses the ticket too.
func TestTransferTicketRefusedWhenAStartRestrictionAppearsAfterFinalize(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		h.agentEnd(s1)
		if got := h.transfer(id); got.State != TransferAccepted {
			t.Fatalf("precondition: finalized, got %+v", got)
		}
		if err := h.srv(h.bob).GroupSessionPolicies.Set(context.Background(), h.tenant, h.group,
			GroupSessionPolicy{GroupID: h.group, RequireRecording: true}); err != nil {
			t.Fatal(err)
		}
		code, out := h.do(h.bob, "POST", "/session-transfers/"+id+"/ticket", "")
		wantCode(t, "ticket after a start restriction appeared", code, http.StatusForbidden, out)
		if !strings.Contains(str(out, "error"), "require_recording") {
			t.Fatalf("refusal = %v", out)
		}
	})
}

// Fake/pg parity of the finalize transaction (backlog "session_transfer.go fakes append session-end/start
// without discard"): a finalize error that is not a business refusal rolls EVERYTHING back in pg (S1's
// end, the session.end audit row, the offer) and the offer stays releasing for a retry; the fake used to
// keep S1's end and its audit row and fail the offer. A business refusal (seat cap) keeps S1's end, writes
// exactly one session.end and one transfer_failed, and no session.start.
func TestTransferFinalizeDiscardsOnInfrastructureErrorAndKeepsS1OnRefusal(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		ctx := context.Background()
		s1 := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		real := h.srv(h.bob).transferAdmitter(h.tenant)
		// An admission whose S2 record is invalid: not a business refusal, so the finalize must roll back.
		bad := func(c context.Context, tr *SessionTransfer) (*TransferAdmission, error) {
			adm, err := real(c, tr)
			if err == nil {
				adm.Rec.Access = "bogus"
			}
			return adm, err
		}
		if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(), bad); err == nil {
			t.Fatal("an invalid S2 must surface as an error, not fail the offer")
		}
		if tr := h.transfer(id); tr.State != TransferReleasing || tr.FailureReason != "" {
			t.Fatalf("offer = %+v, want still releasing", tr)
		}
		if rec := h.session(s1); rec.EndedAt != nil || rec.EndReason != "" {
			t.Fatalf("S1 changed by a discarded finalize: %+v", rec)
		}
		if n := h.auditCount("session.end") + h.auditCount("session.transfer_failed"); n != 0 {
			t.Fatalf("a discarded finalize left %d session.end / transfer_failed audit rows", n)
		}
		for _, e := range h.auditEvents() {
			if e.Action == "session.start" && strings.Contains(string(e.Metadata), "transferred_from") {
				t.Fatalf("a discarded finalize left a transfer session.start row: %s", e.Metadata)
			}
		}
		// The retry with the real admitter completes it, with exactly one end and one start.
		if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(), real); err != nil {
			t.Fatal(err)
		}
		tr := h.transfer(id)
		if tr.State != TransferAccepted {
			t.Fatalf("after the retry: %+v", tr)
		}
		if n := len(h.auditFor("session.end", s1)); n != 1 {
			t.Fatalf("session.end rows for S1 = %d, want 1", n)
		}
		if n := len(h.auditFor("session.start", tr.NewSessionID)); n != 1 {
			t.Fatalf("session.start rows for S2 = %d, want 1", n)
		}
	})
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		s1 := h.startVouched(h.alice)
		h.start(h.carol)
		h.setCap(1)
		id := h.mustOffer(h.alice, s1, h.bob)
		h.mustAccept(h.bob, id)
		if err := h.transfers.RecordAgentEnded(context.Background(), h.tenant, s1, time.Now().UTC(), h.srv(h.bob).transferAdmitter(h.tenant)); err != nil {
			t.Fatal(err)
		}
		if tr := h.transfer(id); tr.State != TransferFailed {
			t.Fatalf("offer = %+v", tr)
		}
		if rec := h.session(s1); rec.EndedAt == nil || rec.EndReason != "transferred" {
			t.Fatalf("a refused S2 must keep S1's end: %+v", rec)
		}
		if n := len(h.auditFor("session.end", s1)); n != 1 {
			t.Fatalf("session.end rows for S1 = %d, want 1", n)
		}
		if n := h.auditCount("session.transfer_failed"); n != 1 {
			t.Fatalf("transfer_failed rows = %d, want 1", n)
		}
		for _, e := range h.auditEvents() {
			if e.Action == "session.start" && strings.Contains(string(e.Metadata), "transferred_from") {
				t.Fatalf("a refused S2 left a transfer session.start row: %s", e.Metadata)
			}
		}
	})
}

// failTreeSource is a group-tree source whose lock can never be taken (pg: a tree-lock timeout behind a group
// move, ErrGroupTreeChanged).
type failTreeSource struct{ groupTreeSource }

func (failTreeSource) withTree(string, func(GroupTree, int64) error) error {
	return ErrGroupTreeChanged
}

// The pg finalizeTx takes the group-tree lock only inside admitSessionTx, so a TransferRefusedError (no S2
// to admit) never touches it: the offer fails and S1's end stands even while the tree lock is unavailable.
// The fake used to take the lock on the refusal path too and would have returned the lock error instead.
// In-memory only: the tree lock cannot be held against the pg store from here.
func TestTransferRefusalDoesNotTakeTheTreeLock(t *testing.T) {
	h := newMemTransferHarness(t)
	ctx := context.Background()
	s1 := h.startVouched(h.alice)
	id := h.mustOffer(h.alice, s1, h.bob)
	h.mustAccept(h.bob, id)
	rs := h.records.(*InMemorySessionRecordStore)
	rs.tree = failTreeSource{rs.tree}
	refuse := func(context.Context, *SessionTransfer) (*TransferAdmission, error) {
		return nil, &TransferRefusedError{Reason: "the acceptor can no longer start sessions"}
	}
	if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(), refuse); err != nil {
		t.Fatalf("a refusal must not need the tree lock: %v", err)
	}
	if tr := h.transfer(id); tr.State != TransferFailed {
		t.Fatalf("offer = %+v", tr)
	}
	if rec := h.session(s1); rec.EndedAt == nil {
		t.Fatalf("S1 must be ended: %+v", rec)
	}
}

// The pg finalize is one transaction, so a failing audit write (the session.end row, or the session.start row
// after S2 was inserted) rolls back S1's end, S2, the offer and every audit row. The fake commits the offer and
// its audit batch inside the session store's critical section and undoes S1/S2 on a failure. The audit failure
// is injected through a wrapper on the fake only; a pg audit failure would need a trigger on mgmt_audit.
func TestTransferFinalizeIsAtomicUnderAuditFailure(t *testing.T) {
	for _, action := range []string{"session.end", "session.start", "session.transfer_failed"} {
		t.Run(action, func(t *testing.T) {
			h := newMemTransferHarness(t)
			ctx := context.Background()
			s1 := h.startVouched(h.alice)
			if action == "session.transfer_failed" {
				h.start(h.carol)
				h.setCap(1) // S2 is refused for a full cap: finalize fails the offer, so its failure row is the one to break
			}
			id := h.mustOffer(h.alice, s1, h.bob)
			h.mustAccept(h.bob, id)
			ts := h.transfers.(*InMemorySessionTransferStore)
			fa := &faultyAudit{InMemoryMgmtAuditStore: h.audit.(*InMemoryMgmtAuditStore)}
			ts.audit = fa
			before := len(h.auditEvents())
			opens := len(h.openSessions())
			real := h.srv(h.bob).transferAdmitter(h.tenant)
			fa.arm(action)
			if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(), real); err == nil {
				t.Fatal("an audit failure must surface as an error")
			}
			if tr := h.transfer(id); tr.State != TransferReleasing || tr.FailureReason != "" || tr.NewSessionID != "" {
				t.Fatalf("offer = %+v, want still releasing", tr)
			}
			if rec := h.session(s1); rec.EndedAt != nil || rec.EndReason != "" {
				t.Fatalf("S1 changed by a rolled-back finalize: %+v", rec)
			}
			if n := len(h.openSessions()); n != opens {
				t.Fatalf("open sessions = %d, want %d (no S2)", n, opens)
			}
			if n := len(h.auditEvents()); n != before {
				t.Fatalf("a rolled-back finalize left %d audit rows", n-before)
			}
			// Disarmed, the retry completes exactly once.
			fa.arm("")
			if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(), real); err != nil {
				t.Fatal(err)
			}
			want := TransferAccepted
			if action == "session.transfer_failed" {
				want = TransferFailed
			}
			if tr := h.transfer(id); tr.State != want {
				t.Fatalf("after the retry: %+v, want %s", tr, want)
			}
			if n := len(h.auditFor("session.end", s1)); n != 1 {
				t.Fatalf("session.end rows for S1 = %d, want 1", n)
			}
		})
	}
}
