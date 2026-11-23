package controlplane

// Review round 2 of docs/65 (fleet directives): each test here fails without the fix it names.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- seams (memory and pg) ----------------------------------------------------------------------

func (h *dirHarness) bumpMFA(user string) {
	h.t.Helper()
	if h.pg {
		mustExec(h.t, h.su, `UPDATE app_user SET mfa_generation = nextval('mfa_generation_seq') WHERE id = $1`, user)
		return
	}
	us := h.users.(*InMemoryUserStore)
	us.mu.Lock()
	defer us.mu.Unlock()
	us.bumpMFAGeneration(us.users[userKey(h.tenant, user)])
}

func (h *dirHarness) bumpCredential(user string) {
	h.t.Helper()
	if h.pg {
		mustExec(h.t, h.su, `UPDATE user_credential SET updated_at = now() + interval '5 seconds' WHERE user_id = $1`, user)
		return
	}
	us := h.users.(*InMemoryUserStore)
	us.mu.Lock()
	defer us.mu.Unlock()
	us.users[userKey(h.tenant, user)].CredentialUpdatedAt = time.Now().Add(5 * time.Second)
}

func (h *dirHarness) revokeSessions(user string) {
	h.t.Helper()
	if _, err := h.sessions.Store.RevokeAllForUser(context.Background(), h.tenant, user, nil); err != nil {
		h.t.Fatal(err)
	}
}

func (h *dirHarness) setReinstallHourly(n int) {
	switch d := h.dirs.(type) {
	case *InMemoryDirectiveStore:
		d.ReinstallHourlyCap = n
	case *PgDirectiveStore:
		d.ReinstallHourlyCap = n
	}
}

func (h *dirHarness) policyOn() {
	h.t.Helper()
	h.stepUp(h.owner)
	if code, out := h.do(h.owner, "PUT", "/tenant/directive-policy", `{"require_second_approver":true}`); code != http.StatusOK {
		h.t.Fatalf("policy on = %d %v", code, out)
	}
}

func (h *dirHarness) sweepActions(id string) []string {
	h.t.Helper()
	items, err := h.dirs.SweepCandidates(context.Background(), 100)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, it := range items {
		if id == "" || it.DirectiveID == id {
			out = append(out, it.Action)
		}
	}
	return out
}

// ---- 1. directive key must be dedicated ----------------------------------------------------------

func TestCheckDirectiveKeyDistinct(t *testing.T) {
	grant := NamedSigningKey{Name: "grant issuer", PublicHex: strings.Repeat("ab", 32)}
	if err := CheckDirectiveKeyDistinct(strings.Repeat("AB", 32), grant); err == nil || !strings.Contains(err.Error(), "grant issuer") {
		t.Fatalf("same key (any case) = %v, want a refusal naming the grant issuer", err)
	}
	other := NamedSigningKey{Name: "another signer", PublicHex: strings.Repeat("cd", 32)}
	if err := CheckDirectiveKeyDistinct(strings.Repeat("ab", 32), other, grant); err == nil {
		t.Fatal("a clash with the SECOND signer was not refused")
	}
	if err := CheckDirectiveKeyDistinct(strings.Repeat("ef", 32), grant, other, NamedSigningKey{Name: "unset"}); err != nil {
		t.Fatalf("distinct keys refused: %v", err)
	}
	if err := CheckDirectiveKeyDistinct("", grant); err == nil {
		t.Fatal("an empty directive key was accepted")
	}
	// And through the real constructors: the seed that produced the grant issuer must not be usable.
	gi, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	di, err := NewDirectiveIssuerFromHex(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectiveKeyDistinct(di.PublicKeyHex(), NamedSigningKey{Name: "grant issuer", PublicHex: gi.PublicKeyHex()}); err == nil {
		t.Fatal("DIRECTIVE_SIGNING_SEED == GRANT_ISSUER_SEED was not refused")
	}
}

// ---- 2. approval: step-up, restarted window, short TTL --------------------------------------------

func TestApprovalNeedsStepUpAndRestartsTheWindow(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.policyOn()
		id := h.mustRequestUninstall(h.owner, h.m)
		if d := h.row(id); d.RequestExpiresAt.Sub(d.RequestedAt) > time.Hour {
			t.Fatalf("an approval-required request lives %v, want <= 1h", d.RequestExpiresAt.Sub(d.RequestedAt))
		}
		// The approver proves the second factor too.
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", ""); code != http.StatusForbidden || str(out, "code") != "step_up_required" {
			t.Fatalf("approve without step-up = %d %v, want 403 step_up_required", code, out)
		}
		if h.row(id).ApprovedBy != "" {
			t.Fatal("approved without a step-up")
		}
		// The original window passes; approval must NOT issue immediately: it restarts the window.
		h.advance(directiveCancelWindow + time.Minute)
		h.stepUp(h.owner2)
		code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", "")
		if code != http.StatusOK || dirStateOf(out) != "requested" {
			t.Fatalf("approve = %d %v, want 200 and still requested (new cancel window)", code, out)
		}
		if d := h.row(id); d.Artifact != "" || d.ApprovedBy != h.owner2 {
			t.Fatalf("approval issued at once: %+v", d)
		}
		h.sweep()
		if h.row(id).State != DirectiveRequested {
			t.Fatal("the sweeper issued inside the restarted window")
		}
		// Inside the new window anyone covering the machine can still cancel.
		h.advance(directiveCancelWindow + time.Minute)
		h.sweep()
		if d := h.row(id); d.State != DirectiveIssued {
			t.Fatalf("after the restarted window state = %s, want issued", d.State)
		}
	})
}

func TestLateApprovalIsRefusedNotExtended(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.policyOn()
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(directiveRequestTTL - 5*time.Minute) // too late to leave a full cancel window
		h.stepUp(h.owner2)
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", ""); code != http.StatusGone {
			t.Fatalf("late approve = %d %v, want 410", code, out)
		}
		if h.row(id).ApprovedBy != "" {
			t.Fatal("a too-late approval was recorded")
		}
	})
}

// ---- 3. reinstall: tenant-wide hourly cap, never on a retired machine ------------------------------

func TestReinstallTenantHourlyCap(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		if DefaultReinstallHourlyCap != 20 {
			t.Fatalf("documented default changed: %d", DefaultReinstallHourlyCap)
		}
		h.setReinstallHourly(2)
		for i := 0; i < 2; i++ {
			m := h.addMachineFn(h.group, MachineStatusActive)
			if code, out := h.request(h.owner, "reinstall", m); code != http.StatusCreated {
				t.Fatalf("reinstall %d = %d %v", i, code, out)
			}
		}
		third := h.addMachineFn(h.group, MachineStatusActive)
		if code, out := h.request(h.owner, "reinstall", third); code != http.StatusTooManyRequests {
			t.Fatalf("third reinstall in the hour = %d %v, want 429", code, out)
		}
		// Uninstall quota is separate: it is not consumed by reinstalls.
		h.stepUp(h.owner)
		if code, out := h.request(h.owner, "uninstall", h.m); code != http.StatusCreated {
			t.Fatalf("uninstall after reinstalls = %d %v", code, out)
		}
	})
}

func TestReinstallRefusedOnRetiredAndRemovedMachines(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		if code, out := h.request(h.owner, "reinstall", h.m); code != http.StatusConflict {
			t.Fatalf("reinstall of a retired machine = %d %v, want 409", code, out)
		}
		if h.auditCount("directive.requested") != 0 {
			t.Fatal("a refused reinstall left a directive")
		}
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		h.drive(id, h.m, "accepted", "executing", "complete")
		if code, out := h.request(h.owner, "reinstall", h.m); code != http.StatusConflict {
			t.Fatalf("reinstall of a removed machine = %d %v, want 409", code, out)
		}
	})
}

// ---- 4. issuance re-checks the credentials the humans acted under ---------------------------------

func TestIssuanceRefusesWhenTheRequestersCredentialsChanged(t *testing.T) {
	cases := []struct {
		name   string
		change func(h *dirHarness)
	}{
		{"sessions revoked", func(h *dirHarness) { h.revokeSessions(h.owner) }},
		{"mfa reset", func(h *dirHarness) { h.bumpMFA(h.owner) }},
		{"password changed", func(h *dirHarness) { h.bumpCredential(h.owner) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
				id := h.mustRequestUninstall(h.owner, h.m)
				c.change(h)
				h.issueNow(id)
				if d := h.row(id); d.State != DirectiveCancelled || d.Artifact != "" {
					t.Fatalf("issued although the requester's %s since the request: %+v", c.name, d)
				}
			})
		})
	}
}

func TestIssuanceRefusesWhenTheApproversSessionWasRevoked(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.policyOn()
		id := h.mustRequestUninstall(h.owner, h.m)
		h.stepUp(h.owner2)
		if code, out := h.do(h.owner2, "POST", "/directives/"+id+"/approve", ""); code != http.StatusOK {
			t.Fatalf("approve = %d %v", code, out)
		}
		h.revokeSessions(h.owner2)
		h.issueNow(id)
		if d := h.row(id); d.State != DirectiveCancelled || d.Artifact != "" {
			t.Fatalf("issued although the approver's session was revoked: %+v", d)
		}
	})
}

func TestIssuanceStillWorksWhenNothingChanged(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		if d := h.issueNow(id); d.State != DirectiveIssued {
			t.Fatalf("state = %s, want issued (negative control)", d.State)
		}
	})
}

// ---- 5. an old signed ack cannot rewind the state --------------------------------------------------

func TestStaleAckReplayCannotRewindState(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		h.drive(id, h.m, "accepted", "executing")
		stale := h.ackJSON(id, h.m, h.m.Priv, "executing", "reboot_pending", "", h.nextAckTime())
		if code, out := h.internal("POST", "/internal/directives/"+id+"/ack", stale); code != http.StatusOK {
			t.Fatalf("first reboot_pending = %d %v", code, out)
		}
		if code, out := h.ack(id, h.m, "reboot_pending", "executing"); code != http.StatusOK {
			t.Fatalf("resume = %d %v", code, out)
		}
		// The captured, validly signed executing->reboot_pending ack is replayed: it must not rewind.
		if code, out := h.internal("POST", "/internal/directives/"+id+"/ack", stale); code != http.StatusConflict {
			t.Fatalf("replayed stale ack = %d %v, want 409", code, out)
		}
		if got := h.row(id).State; got != DirectiveExecuting {
			t.Fatalf("state rewound to %s", got)
		}
		// The same timestamp as the last accepted ack is not newer either.
		last := h.nextAckTime()
		if code, out := h.internal("POST", "/internal/directives/"+id+"/ack", h.ackJSON(id, h.m, h.m.Priv, "executing", "reboot_pending", "", last)); code != http.StatusOK {
			t.Fatalf("fresh ack = %d %v", code, out)
		}
		if code, out := h.internal("POST", "/internal/directives/"+id+"/ack", h.ackJSON(id, h.m, h.m.Priv, "reboot_pending", "executing", "", last)); code != http.StatusConflict {
			t.Fatalf("equal ts_ms = %d %v, want 409", code, out)
		}
	})
}

func TestAckOlderThanTheWindowIsRefused(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		old := time.Now().Add(-directiveAckMaxAge - 10*time.Minute)
		if code, out := h.internal("POST", "/internal/directives/"+id+"/ack", h.ackJSON(id, h.m, h.m.Priv, "issued", "accepted", "", old)); code != http.StatusConflict {
			t.Fatalf("an ack from %v ago = %d %v, want 409", directiveAckMaxAge+10*time.Minute, code, out)
		}
		if got := h.row(id).State; got != DirectiveIssued {
			t.Fatalf("state = %s", got)
		}
	})
}

// ---- 6. sweep candidates ---------------------------------------------------------------------------

func TestSweepSkipsRequestsAwaitingApproval(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		h.policyOn()
		id := h.mustRequestUninstall(h.owner, h.m)
		h.advance(directiveCancelWindow + time.Minute)
		for _, a := range h.sweepActions(id) {
			if a == "issue" {
				t.Fatalf("an unapproved request is an issue candidate: %v", h.sweepActions(id))
			}
		}
		h.stepUp(h.owner2)
		h.do(h.owner2, "POST", "/directives/"+id+"/approve", "")
		h.advance(directiveCancelWindow + time.Minute)
		if got := h.sweepActions(id); len(got) != 1 || got[0] != "issue" {
			t.Fatalf("an approved, due request = %v, want [issue]", got)
		}
	})
}

func TestSweepRanksActionsAndRateLimitsRenotify(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		// C: a started removal that went silent -> 'unconfirmed'.
		c := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(c)
		h.drive(c, h.m, "accepted", "executing")
		h.advance(directiveUnconfirmedAfter + time.Minute)
		// B: an issued, never delivered directive.
		m2 := h.addMachineFn(h.group, MachineStatusRetired)
		b := h.mustRequestUninstall(h.owner, m2)
		h.advance(directiveCancelWindow + time.Minute)
		// Issue B directly: the sweeper would also resolve C and take it out of the candidate list.
		if _, err := h.srv(h.owner).issueDirective(context.Background(), h.tenant, b); err != nil {
			t.Fatal(err)
		}
		if got := h.sweepActions(b); len(got) != 0 {
			t.Fatalf("a directive issued a moment ago is a sweep candidate: %v (renotify must wait a minute)", got)
		}
		h.advance(2 * time.Minute)
		if got := h.sweepActions(b); len(got) != 1 || got[0] != "renotify" {
			t.Fatalf("undelivered after 2 minutes = %v, want [renotify]", got)
		}
		items, err := h.dirs.SweepCandidates(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		var order []string
		for _, it := range items {
			if it.DirectiveID == b || it.DirectiveID == c {
				order = append(order, it.Action)
			}
		}
		if len(order) != 2 || order[0] != "unconfirmed" || order[1] != "renotify" {
			t.Fatalf("sweep order = %v, want [unconfirmed renotify] (explicit rank, not alphabetical)", order)
		}
	})
}

// ---- 7. the attended redeem path honours the removal tombstone -------------------------------------

type recAttendedRedeem struct {
	AttendedStore
	calls int
}

func (r *recAttendedRedeem) Redeem(context.Context, string, string, string) (*AttendedRedeem, error) {
	r.calls++
	return nil, ErrAttendedInvalid
}

// The handler redeems through RedeemScoped (docs/66); the stub counts both entry points.
func (r *recAttendedRedeem) RedeemScoped(context.Context, string, string, string, RedeemScope) (*AttendedRedeem, error) {
	r.calls++
	return nil, ErrAttendedInvalid
}

func TestAttendedRedeemRefusesARemovedMachinesKey(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		h.issueNow(id)
		h.drive(id, h.m, "accepted", "executing", "complete")
		if got := h.machine(h.m.ID).Status; got != MachineStatusRemoved {
			t.Fatalf("machine %s, want removed", got)
		}
		rec := &recAttendedRedeem{}
		srv := h.srv(h.owner)
		srv.Attended = rec
		body := func(pub string) string { return `{"code":"ABCD-EFGH","pubkey":"` + pub + `","name":"guest"}` }
		if code, out := h.doOn(srv, "POST", "/attended-sessions/redeem", body(h.m.Pub), ""); code != http.StatusForbidden {
			t.Fatalf("attended redeem with a removed device's key = %d %v, want 403", code, out)
		}
		if rec.calls != 0 {
			t.Fatal("the removed key reached the attended store")
		}
		// Control: a fresh key passes the tombstone check and reaches the store.
		h.doOn(srv, "POST", "/attended-sessions/redeem", body(testPubkeyHex(t)), "")
		if rec.calls != 1 {
			t.Fatalf("a fresh key did not reach the attended store (calls=%d)", rec.calls)
		}
	})
}
