package controlplane

import "testing"

// docs/63 D6: CapViewRecordings is held by Owner, Admin and Auditor — and by nobody else — and no API
// token can ever carry it. Asymmetric on purpose: the roles that must NOT have it are asserted as hard
// as the ones that must.
func TestCapViewRecordingsPresetsAndTokenExclusion(t *testing.T) {
	has := func(r Role) bool { return r.Has(CapViewRecordings) }
	for role, want := range map[Role]bool{
		RoleOwner: true, RoleAdmin: true, RoleAuditor: true, RoleTechnician: false, RoleReadOnly: false,
	} {
		if has(role) != want {
			t.Errorf("role %s holds view_recordings = %v, want %v", role, has(role), want)
		}
	}
	// The technician who ran a session does not get to replay it by default, even though the same role
	// can read sessions and run commands on them.
	if !RoleTechnician.Has(CapViewSessions) || RoleTechnician.Has(CapViewRecordings) {
		t.Error("technician must view sessions but not recordings")
	}
	if !RoleAuditor.Has(CapViewAudit) || !RoleAuditor.Has(CapViewRecordings) {
		t.Error("auditor must hold both audit and recordings")
	}
	if IsAPITokenGrantableCapability(CapViewRecordings) {
		t.Error("view_recordings is API-token grantable")
	}
	for _, c := range APITokenGrantableCapabilities() {
		if c == CapViewRecordings {
			t.Error("view_recordings is in the grantable list")
		}
	}
	if _, err := parseAPITokenCapabilities([]string{"view_audit", "view_recordings"}); err == nil {
		t.Error("a token mint naming view_recordings was accepted")
	}
	found := false
	for _, c := range AllCapabilities {
		found = found || c == CapViewRecordings
	}
	if !found {
		t.Error("view_recordings is not in AllCapabilities (Owner would not hold it)")
	}
}
