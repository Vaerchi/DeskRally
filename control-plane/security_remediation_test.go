package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSecurityLoginFailureDoesNotLockAnotherSource(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "the-real-password", RoleTechnician)
	f.auth.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 1, BaseDelay: time.Minute, MaxDelay: time.Minute})
	h := f.srv.Handler()
	login := func(ip, password string) int {
		body, _ := json.Marshal(loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: password})
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(string(body)))
		req.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 2; i++ {
		if got := login("192.0.2.1", "wrong"); got != 401 {
			t.Fatalf("failure = %d", got)
		}
	}
	if got := login("192.0.2.1", "wrong"); got != 429 {
		t.Fatalf("attacker source = %d", got)
	}
	if got := login("192.0.2.2", "the-real-password"); got != 200 {
		t.Fatalf("legitimate source = %d", got)
	}
}

func TestSecurityProductionCookieNames(t *testing.T) {
	auth := &AuthService{SecureCookie: true}
	for _, cookie := range []*http.Cookie{auth.sessionCookie("session", time.Now()), auth.csrfCookie("csrf", time.Now())} {
		if !strings.HasPrefix(cookie.Name, "__Host-") || cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure {
			t.Fatalf("unsafe production cookie: %+v", cookie)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookie, Value: "tossed"})
	if got := bearerToken(req, auth.cookieName()); got != "" {
		t.Fatal("legacy cookie was accepted in secure mode")
	}
}

type securityBodyReader struct {
	io.Reader
	bound *bool
	t     *testing.T
}

func (r securityBodyReader) Read(p []byte) (int, error) {
	if *r.bound {
		r.t.Fatal("network body read while tenant connection is bound")
	}
	return r.Reader.Read(p)
}

type securityBinder struct{ bound *bool }

func (b securityBinder) BindTenant(ctx context.Context, _ string) (context.Context, func(), error) {
	*b.bound = true
	return ctx, func() {}, nil
}
func TestSecurityBodyReadPrecedesTenantBinding(t *testing.T) {
	srv := newBodyLimitServer(t, RoleOwner)
	bound := false
	srv.Binder = securityBinder{&bound}
	req := httptest.NewRequest("POST", "/sessions", securityBodyReader{strings.NewReader(`{"machine_id":"` + blMachineID + `"}`), &bound, t})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if !bound {
		t.Fatalf("valid body did not reach binder: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityConcurrencyLimitRequiresExpiry(t *testing.T) {
	srv := newBodyLimitServer(t, RoleOwner)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"max_concurrent_sessions":2}`, http.StatusBadRequest},
		{`{"max_concurrent_sessions":2,"max_session_seconds":3600}`, http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("PUT", "/tenant/session-policy", strings.NewReader(tc.body)))
		if rec.Code != tc.status {
			t.Fatalf("policy %s = %d: %s", tc.body, rec.Code, rec.Body.String())
		}
	}
}

func TestSecurityAuditLimitIsClamped(t *testing.T) {
	srv := newBodyLimitServer(t, RoleOwner)
	for i := 0; i < 1005; i++ {
		if err := srv.MgmtAudit.RecordEvent(context.Background(), blTenantID, &MgmtAuditEvent{Action: "test.security"}); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit?limit=2147483647", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 1000 {
		t.Fatalf("audit rows = %d, want 1000", len(body.Events))
	}
}

func TestSecurityOversizeFleetReturnsNoPartialResult(t *testing.T) {
	store := NewInMemoryMachineStore()
	for i := 0; i <= maxListRows; i++ {
		id := strconv.Itoa(i)
		store.machines[id] = &Machine{ID: id, TenantID: "tenant"}
	}
	rows, err := store.ListMachines(context.Background(), "tenant")
	if !errors.Is(err, ErrQueryTooBroad) || rows != nil {
		t.Fatalf("oversize result returned %d rows: %v", len(rows), err)
	}
	delete(store.machines, strconv.Itoa(maxListRows))
	rows, err = store.ListMachines(context.Background(), "tenant")
	if err != nil || len(rows) != maxListRows {
		t.Fatalf("at-limit fleet: %d rows, %v", len(rows), err)
	}
}
