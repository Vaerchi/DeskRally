package controlplane

// POST /enroll must scope to the GROUP the machine is being planted into, not merely to the tenant.
//
// PREMISE, declared locally so this test cannot pass for the wrong reason: `enrollRequest.GroupID`
// is chosen by the CALLER, and the comment on that struct already says "The group is what RBAC
// scopes against, so it is required." The handler nevertheless checked `Require(CapEnrollMachine)`
// — the tenant-wide form — and then wrote the machine into whatever group the body named.
//
// This is an UNAPPLIED defence, not a missing one. The check exists and its own sibling uses it:
// handlePromoteAttended does `RequireMachine(CapEnrollMachine, sess.GroupID)` for the very same
// capability (http_attended.go), and GET /machines/{id} resolves the machine and gates on
// `m.GroupID`. Only this route skipped it.
//
// Why it matters: a group is the unit every downstream check scopes against. A technician confined
// to group A that can create machines in group B has written outside its scope — the machine shows
// up in B's inventory, and its `name`/`os` free text is echoed to everyone who can view B.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestEnrollIsScopedToTheTargetGroup(t *testing.T) {
	// An admin scoped to groupG ONLY — the realistic actor, since RoleTechnician does not hold
	// CapEnrollMachine at all (rbac.go rolePresets) and would be denied for the wrong reason. Because
	// RoleAdmin DOES hold it, a denial below is provably the GROUP check rather than a missing
	// capability, and the assertion on the error text pins that distinction rather than trusting the
	// status code alone.
	scoped := &Principal{
		UserID:   techUserUUID,
		TenantID: "tenant-123",
		Grant:    NewGrant(techUserUUID, "tenant-123", NewMembership(RoleAdmin, Groups(groupG))),
	}
	store := NewInMemoryMachineStore()
	srv := strictGrantServer(scoped, store)

	// Negative control FIRST: enrolling into its OWN group must succeed. Without this leg a handler
	// that denied every enroll would satisfy the assertion below.
	rec := postJSON(t, srv, "POST", "/enroll", map[string]any{
		"machine_id": machineInGroupG, "group_id": groupG, "name": "in-scope",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("premise not met: enroll into the caller's OWN group = %d, want 201 (body %s)",
			rec.Code, rec.Body.String())
	}

	// The measurement: enroll into a group the caller holds nothing in.
	const foreignDevice = "99999999-9999-4999-8999-999999999999"
	rec = postJSON(t, srv, "POST", "/enroll", map[string]any{
		"machine_id": foreignDevice, "group_id": groupG2, "name": "planted",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: enroll into foreign group %s = %d, want 403 (body %s)",
			groupG2, rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, groupG2) {
		t.Fatalf("denial should name the group it was scoped against, got %s", body)
	}

	// And it must not have been written. A 403 that still created the row would be the worse bug.
	if m, err := store.GetMachine(context.Background(), scoped.TenantID, foreignDevice); err == nil {
		t.Fatalf("SECURITY: denied enroll still created machine %+v in group %s", m, m.GroupID)
	}
}
