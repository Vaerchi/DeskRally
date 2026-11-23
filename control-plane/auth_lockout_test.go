package controlplane

// Proofs for admin "clear user lockout" (DELETE /users/{id}/lockout): an admin CLEARS the per-account
// login-throttle counters for a locked-out user, gated on CapManageUsers + canAdministerUser hierarchy,
// through the real fixture flow.

import (
	"net/http"
	"testing"
	"time"
)

func TestHandleClearUserLockout(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "admin", "admin@acme.test", uaPw, RoleAdmin)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()

	ownerCookie, ownerCSRF, ownerTok := loginFor(t, f, "owner@acme.test", uaPw)
	adminCookie, adminCSRF, adminTok := loginFor(t, f, "admin@acme.test", uaPw)
	techCookie, techCSRF, techTok := loginFor(t, f, "tech@acme.test", uaPw)

	// --- CAPABILITY GATE ---
	// A Technician holds no CapManageUsers → 403.
	if rec := doJSONWith(t, h, "DELETE", "/users/tech/lockout", nil, techTok, techCookie, techCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("technician clearing lockout = %d, want 403", rec.Code)
	}

	// --- HIERARCHY GATE ---
	// An Admin CANNOT clear the Owner's lockout (Admin lacks CapManageTenant the Owner holds) → 403.
	if rec := doJSONWith(t, h, "DELETE", "/users/owner/lockout", nil, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("admin clearing owner lockout = %d, want 403", rec.Code)
	}
	// But CAN clear a Technician's lockout (within Admin's authority) → 204.
	if rec := doJSONWith(t, h, "DELETE", "/users/tech/lockout", nil, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusNoContent {
		t.Fatalf("admin clearing tech lockout = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	// --- NOT FOUND ---
	if rec := doJSONWith(t, h, "DELETE", "/users/nobody/lockout", nil, ownerTok, ownerCookie, ownerCSRF); rec.Code != http.StatusNotFound {
		t.Fatalf("clear lockout for unknown user = %d, want 404", rec.Code)
	}

	// --- SUCCESS + AUDIT ---
	rec := doJSONWith(t, h, "DELETE", "/users/tech/lockout", nil, ownerTok, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("owner clearing tech lockout = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	// Audit trail records the event.
	events, _ := f.auth.MgmtAudit.ListEvents(t.Context(), "tenant-1", 10)
	found := false
	for _, e := range events {
		if e.Action == "user.lockout_cleared" && e.TargetID == "tech" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("user.lockout_cleared audit event not recorded (got %d events)", len(events))
	}

	_ = techCookie // used implicitly by loginFor above
}

// TestHandleClearUserLockoutSelfAllowed verifies that a user CAN clear their own lockout (unlike
// self-disable, which is refused). An owner clearing their own lockout is the regression case.
func TestHandleClearUserLockoutSelfAllowed(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	h := f.srv.Handler()
	ownerCookie, ownerCSRF, ownerTok := loginFor(t, f, "owner@acme.test", uaPw)
	if rec := doJSONWith(t, h, "DELETE", "/users/owner/lockout", nil, ownerTok, ownerCookie, ownerCSRF); rec.Code != http.StatusNoContent {
		t.Fatalf("self clear lockout = %d, want 204: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleClearUserLockoutActuallyClearsThrottle is the mutation-sensitive proof: the handler must
// call th.Reset for the TOTP keys, not just audit and return 204.
//
// HandleClearUserLockout clears:
//   - accountKey("login-totp", tenantID, userID) — TOTP step-up during login (pure per-user-ID)
//   - accountKey("totp", tenantID, userID)       — TOTP enrollment step-up (pure per-user-ID)
//
// The login-source key (accountKey("login-source", …) + ":" + clientIP) is NOT cleared: it is a
// compound account+IP key and the admin cannot know the user's source IP.
//
// Mutation M1 — remove the th.Reset call from HandleClearUserLockout:
//
//	Allow() for both TOTP keys still returns (>0, false) after the handler → both sub-asserts FAIL.
func TestHandleClearUserLockoutActuallyClearsThrottle(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)

	// Wire a throttle with 1 free attempt so 2 Fail calls lock the account (FreeAttempts=0 falls
	// back to the default 5, so use 1 as the minimum meaningful value). Two calls: failures=2,
	// over = 2-1 = 1 > 0 → lockedUntil = now + BaseDelay (60s).
	th := NewThrottle(ThrottleConfig{
		FreeAttempts: 1,
		BaseDelay:    60 * time.Second,
		MaxDelay:     60 * time.Minute,
		Reset:        60 * time.Minute,
	})
	f.auth.Throttle = th

	h := f.srv.Handler()

	// Arm BOTH per-user-ID keys that HandleClearUserLockout actually clears.
	loginTOTPKey := accountKey("login-totp", "tenant-1", "tech")
	totpKey := accountKey("totp", "tenant-1", "tech")
	for _, k := range []string{loginTOTPKey, totpKey} {
		th.Fail(k)
		th.Fail(k) // second failure exceeds FreeAttempts=1 → locks
		if _, ok := th.Allow(k); ok {
			t.Fatalf("key %q must be armed before the test (Allow returned ok=true)", k)
		}
	}

	// Owner calls the lockout-clear endpoint.
	ownerCookie, ownerCSRF, ownerTok := loginFor(t, f, "owner@acme.test", uaPw)
	rec := doJSONWith(t, h, "DELETE", "/users/tech/lockout", nil, ownerTok, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clear lockout = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	// After the clear, Allow must succeed for BOTH keys — both lockouts are gone.
	for _, k := range []string{loginTOTPKey, totpKey} {
		if _, ok := th.Allow(k); !ok {
			t.Fatalf("key %q not cleared: Allow still returns ok=false after HandleClearUserLockout", k)
		}
	}
}
