package controlplane

import "testing"

// Preset role → capability expectations. Mirrors both rolePresets and the seed INSERT in
// migrations/0001_core.sql; if any of the three drift, these tests fail.
func TestRoleHasCapability(t *testing.T) {
	cases := []struct {
		name string
		role Role
		cap  Capability
		want bool
	}{
		// Owner holds everything.
		{"owner manage tenant", RoleOwner, CapManageTenant, true},
		{"owner backstage", RoleOwner, CapBackstageShell, true},
		{"owner audit", RoleOwner, CapViewAudit, true},

		// Admin: full day-to-day, but NOT tenant administration.
		{"admin manage users", RoleAdmin, CapManageUsers, true},
		{"admin deploy agent", RoleAdmin, CapDeployAgent, true},
		{"admin audit", RoleAdmin, CapViewAudit, true},
		{"admin NOT manage tenant", RoleAdmin, CapManageTenant, false},

		// Owner and Admin may elevate a session to the guest's admin token; nobody else can.
		// Loop 87: the whole point of a separate capability is that a Technician — who runs the
		// commands — does not hold it.
		{"owner elevate session", RoleOwner, CapElevateSession, true},
		{"admin elevate session", RoleAdmin, CapElevateSession, true},

		// Technician: works sessions, administers nothing.
		{"tech start session", RoleTechnician, CapStartSession, true},
		{"tech NOT elevate session", RoleTechnician, CapElevateSession, false},
		{"tech backstage", RoleTechnician, CapBackstageShell, true},
		{"tech deploy agent", RoleTechnician, CapDeployAgent, true},
		{"tech NOT manage users", RoleTechnician, CapManageUsers, false},
		{"tech NOT audit", RoleTechnician, CapViewAudit, false},
		{"tech NOT enroll mgmt", RoleTechnician, CapManageEnrollment, false},

		// ReadOnly: look, don't touch.
		{"readonly view machines", RoleReadOnly, CapViewMachines, true},
		{"readonly view sessions", RoleReadOnly, CapViewSessions, true},
		{"readonly NOT start session", RoleReadOnly, CapStartSession, false},
		{"readonly NOT audit", RoleReadOnly, CapViewAudit, false},
		{"readonly NOT elevate session", RoleReadOnly, CapElevateSession, false},

		// Auditor: ReadOnly + audit, still cannot act.
		{"auditor audit", RoleAuditor, CapViewAudit, true},
		{"auditor view machines", RoleAuditor, CapViewMachines, true},
		{"auditor NOT start session", RoleAuditor, CapStartSession, false},
		{"auditor NOT backstage", RoleAuditor, CapBackstageShell, false},
		{"auditor NOT elevate session", RoleAuditor, CapElevateSession, false},

		// Unknown role denies everything.
		{"unknown role denies", Role("nope"), CapViewMachines, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.role.Has(tc.cap); got != tc.want {
				t.Fatalf("Role(%q).Has(%q) = %v, want %v", tc.role, tc.cap, got, tc.want)
			}
		})
	}
}

// Owner's preset must be exactly the full capability set.
func TestOwnerHoldsEveryCapability(t *testing.T) {
	for _, c := range AllCapabilities {
		if !RoleOwner.Has(c) {
			t.Errorf("Owner is missing capability %q", c)
		}
	}
	if len(RoleOwner.Capabilities()) != len(AllCapabilities) {
		t.Errorf("Owner has %d caps, want %d", len(RoleOwner.Capabilities()), len(AllCapabilities))
	}
}

// Capabilities() must hand back a copy — mutating it must not corrupt the preset.
func TestCapabilitiesReturnsCopy(t *testing.T) {
	caps := RoleTechnician.Capabilities()
	if len(caps) == 0 {
		t.Fatal("technician has no capabilities")
	}
	caps[0] = Capability("mutated")
	if RoleTechnician.Capabilities()[0] == "mutated" {
		t.Fatal("mutating the returned slice corrupted the preset")
	}
}

// Grant.Require (tenant-wide, ignores group scope).
func TestGrantRequire(t *testing.T) {
	g := NewGrant("u1", "t1",
		NewMembership(RoleAuditor, AllGroups()),
	)

	cases := []struct {
		name       string
		cap        Capability
		wantDenied bool
	}{
		{"auditor gets audit", CapViewAudit, false},
		{"auditor gets view machines", CapViewMachines, false},
		{"auditor denied start session", CapStartSession, true},
		{"auditor denied manage users", CapManageUsers, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.Require(tc.cap)
			if tc.wantDenied {
				if err == nil {
					t.Fatalf("Require(%q) = nil, want denied", tc.cap)
				}
				if !IsDenied(err) {
					t.Fatalf("Require(%q) err = %v, want *DeniedError", tc.cap, err)
				}
			} else if err != nil {
				t.Fatalf("Require(%q) = %v, want nil", tc.cap, err)
			}
		})
	}
}

// Group-scoping: RequireMachine must honor the SAME-membership rule and the group scope.
func TestGrantRequireMachineGroupScoping(t *testing.T) {
	const (
		groupA = "group-a"
		groupB = "group-b"
		groupC = "group-c"
	)

	// A user who is a Technician over group A only, and an Auditor tenant-wide.
	g := NewGrant("u1", "t1",
		NewMembership(RoleTechnician, Groups(groupA)),
		NewMembership(RoleAuditor, AllGroups()),
	)

	cases := []struct {
		name       string
		cap        Capability
		group      string
		wantDenied bool
	}{
		// Technician membership covers group A → can start a session there.
		{"start session in scoped group A", CapStartSession, groupA, false},
		// Technician is NOT scoped to group B → denied there even though it holds the cap.
		{"start session in unscoped group B", CapStartSession, groupB, true},
		{"start session in unscoped group C", CapStartSession, groupC, true},
		// Auditor is tenant-wide → view machines anywhere.
		{"view machines in group A", CapViewMachines, groupA, false},
		{"view machines in group B", CapViewMachines, groupB, false},
		// Cross-membership must NOT combine: the Auditor (all groups) does not lend
		// StartSession; the Technician (has StartSession) is not scoped to B.
		{"no cross-membership borrow in B", CapStartSession, groupB, true},
		// A capability nobody holds is denied everywhere.
		{"nobody has manage tenant", CapManageTenant, groupA, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.RequireMachine(tc.cap, tc.group)
			if tc.wantDenied {
				if err == nil {
					t.Fatalf("RequireMachine(%q,%q) = nil, want denied", tc.cap, tc.group)
				}
				var de *DeniedError
				if !IsDenied(err) {
					t.Fatalf("RequireMachine err = %v, want *DeniedError", err)
				}
				_ = de
			} else if err != nil {
				t.Fatalf("RequireMachine(%q,%q) = %v, want nil", tc.cap, tc.group, err)
			}
		})
	}
}

// A membership scoped to explicit groups must not be treated as tenant-wide.
func TestScopedMembershipIsNotTenantWide(t *testing.T) {
	g := NewGrant("u1", "t1", NewMembership(RoleTechnician, Groups("group-a")))

	// Tenant-wide Allows still reports true (it holds the cap *somewhere*)...
	if !g.Allows(CapStartSession) {
		t.Fatal("Allows(StartSession) = false, want true")
	}
	// ...but the machine-scoped check must reject a group it isn't scoped to.
	if g.AllowsInGroup(CapStartSession, "group-z") {
		t.Fatal("AllowsInGroup(StartSession, group-z) = true, want false")
	}
	if !g.AllowsInGroup(CapStartSession, "group-a") {
		t.Fatal("AllowsInGroup(StartSession, group-a) = false, want true")
	}
}

// Groups() with no ids means tenant-wide (matches the DB '{}' convention).
func TestEmptyGroupsIsTenantWide(t *testing.T) {
	s := Groups()
	if !s.All {
		t.Fatal("Groups() with no ids should be tenant-wide")
	}
	if !s.Covers("anything") {
		t.Fatal("tenant-wide scope must cover any group")
	}
}

// A zero-value Membership (built without NewMembership) must still resolve capabilities via
// the lazy fallback path rather than silently granting/denying incorrectly.
func TestZeroValueMembershipLazyResolves(t *testing.T) {
	m := Membership{Role: RoleReadOnly, Scope: AllGroups()}
	g := &Grant{UserID: "u", TenantID: "t", Members: []Membership{m}}
	if !g.Allows(CapViewMachines) {
		t.Fatal("zero-value ReadOnly membership should allow ViewMachines")
	}
	if g.Allows(CapStartSession) {
		t.Fatal("zero-value ReadOnly membership should not allow StartSession")
	}
}

// DeniedError message includes the group only when group-scoped.
func TestDeniedErrorMessage(t *testing.T) {
	tenantWide := (&DeniedError{Capability: CapViewAudit}).Error()
	if want := `capability "view_audit" not granted`; tenantWide != want {
		t.Fatalf("tenant-wide message = %q, want %q", tenantWide, want)
	}
	scoped := (&DeniedError{Capability: CapStartSession, GroupID: "g1"}).Error()
	if want := `capability "start_session" not granted for machine group "g1"`; scoped != want {
		t.Fatalf("scoped message = %q, want %q", scoped, want)
	}
}
