package controlplane

import (
	"net/http"
	"testing"
)

func TestObserverRenewPGImmutableAdmissionMode(t *testing.T) {
	f := newObserverPGFixture(t)
	code, observer := observerStart(t, f.ownerSrv, "view_only")
	if code != http.StatusCreated {
		t.Fatalf("observer start = %d", code)
	}
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	if control.Session.Access != "control" || control.Signaling.Ticket.Claims.V != 1 || control.Signaling.Ticket.Claims.Access != "" {
		t.Fatalf("control admission changed: %+v", control)
	}
	// Tightening applies to both sessions. Clearing the group mandate may
	// restore control only to the session originally admitted as control.
	for _, enforce := range []bool{true, false} {
		if err := f.ownerSrv.GroupSessionPolicies.Set(t.Context(), f.tenant, f.groupID, GroupSessionPolicy{EnforceViewOnly: enforce}); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name    string
			started observerStartResponse
			want    string
		}{
			{"observer", observer, "view_only"},
			{"control", control, func() string {
				if enforce {
					return "view_only"
				}
				return "control"
			}()},
		} {
			var renewed observerStartResponse
			code := apiJSON(t, f.ownerSrv, "POST", "/sessions/"+tc.started.Session.ID+"/policy", `{}`, &renewed)
			if code != http.StatusOK {
				t.Fatalf("%s renewal (enforce=%v) = %d", tc.name, enforce, code)
			}
			// Renewal returns only the policy; supply the original id for the
			// shared policy-binding assertion.
			renewed.Session.ID = tc.started.Session.ID
			observerRequirePolicy(t, renewed, tc.want)
		}
	}
	for _, started := range []observerStartResponse{observer, control} {
		var access string
		if err := f.su.QueryRow(t.Context(), `SELECT access FROM session_record WHERE tenant_id = $1 AND id = $2`, f.tenant, started.Session.ID).Scan(&access); err != nil {
			t.Fatal(err)
		}
		if access != started.Session.Access {
			t.Fatalf("renewal mutated admission access: got %q, originally %q", access, started.Session.Access)
		}
	}
	// Observe permission remains additional to Connect on every renewal.
	withoutObserve := f.serverFor(observerCustomPrincipal(f.owner, f.tenant,
		CapViewMachines, CapStartSession, CapViewSessions, CapEndSession))
	if code := apiJSON(t, withoutObserve, "POST", "/sessions/"+observer.Session.ID+"/policy", `{}`, nil); code != http.StatusForbidden {
		t.Fatalf("observer renewal after losing observe_session = %d, want 403", code)
	}
}
