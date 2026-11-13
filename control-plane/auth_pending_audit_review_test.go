package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The actual HTTP route must preserve the two-step login flow even while its audit sample is full.
func TestPendingAuditReviewLoginStillNeedsSecondFactor(t *testing.T) {
	f := newAuthFixture(t)
	const password = "synthetic-pending-review-password"
	u := f.addUser(t, "tenant-1", "pending-review", "pending@example.test", password, RoleTechnician)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatal(err)
	}
	audit := NewInMemoryMgmtAuditStore()
	f.auth.MgmtAudit = audit
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }
	h := f.srv.Handler()
	request := loginRequest{Tenant: u.TenantID, Email: u.Email, Password: password}
	for i := 0; i < 8; i++ {
		rec := doJSON(t, h, "POST", "/auth/login", request, nil)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
			t.Fatalf("pending attempt %d: status %d body %s", i, rec.Code, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("pending login issued cookies")
		}
	}
	events, err := audit.ListEvents(context.Background(), u.TenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "auth.second_factor_pending" {
		t.Fatalf("pending events: %#v", events)
	}
	if events[0].ActorUserID != "" || events[0].TargetID != "" {
		t.Fatal("pending event impersonates authenticated user")
	}
	var meta map[string]any
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["email"] != u.Email || meta["sampled"] != true {
		t.Fatalf("pending metadata: %s", events[0].Metadata)
	}
	for _, value := range []string{password, secret, u.PasswordHash} {
		if value != "" && strings.Contains(string(events[0].Metadata), value) {
			t.Fatal("secret in audit metadata")
		}
	}
	code, err := TOTPCode(secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatal(err)
	}
	request.TOTPCode = code
	rec := doJSON(t, h, "POST", "/auth/login", request, nil)
	if rec.Code != http.StatusOK || sessionCookieFrom(rec) == nil {
		t.Fatalf("valid second factor after pending requests: %d %s", rec.Code, rec.Body.String())
	}
	events, err = audit.ListEvents(context.Background(), u.TenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Action]++
	}
	if counts["auth.login"] != 1 || counts["auth.second_factor_pending"] != 1 || counts["auth.login_failed"] != 0 {
		t.Fatalf("auth event separation: %#v", counts)
	}
}
