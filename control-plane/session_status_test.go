package controlplane

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestSessionStatusDoesNotExtendIdleTimeout(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant", "user", "user@example.test", "test-password", RoleOwner)
	now := time.Unix(1700000000, 0)
	f.sessions.Now = func() time.Time { return now }
	f.sessions.IdleTTL = time.Minute
	token := issueSessionFor(t, context.Background(), f.users, f.sessions, "tenant", "user")
	cookie := &http.Cookie{Name: DefaultSessionCookie, Value: token}
	h := f.srv.Handler()
	for _, seconds := range []int{20, 20, 20} {
		now = now.Add(time.Duration(seconds) * time.Second)
		rec := doJSON(t, h, "GET", "/auth/session", nil, cookie)
		want := http.StatusNoContent
		if now.Unix() == 1700000060 {
			want = http.StatusUnauthorized
		}
		if rec.Code != want {
			t.Fatalf("status at %v = %d, want %d: %s", now, rec.Code, want, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("session status must not be cached")
		}
	}
}

func TestSessionStatusRequiresAuthentication(t *testing.T) {
	f := newAuthFixture(t)
	rec := doJSON(t, f.srv.Handler(), "GET", "/auth/session", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", rec.Code)
	}
}

func TestNormalActivityStillExtendsIdleTimeout(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant", "user", "user@example.test", "test-password", RoleOwner)
	now := time.Unix(1700000000, 0)
	f.sessions.Now = func() time.Time { return now }
	f.sessions.IdleTTL = time.Minute
	token := issueSessionFor(t, context.Background(), f.users, f.sessions, "tenant", "user")
	cookie := &http.Cookie{Name: DefaultSessionCookie, Value: token}
	h := f.srv.Handler()
	now = now.Add(40 * time.Second)
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("activity: %d %s", rec.Code, rec.Body.String())
	}
	now = now.Add(40 * time.Second)
	if rec := doJSON(t, h, "GET", "/auth/session", nil, cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("status after activity: %d %s", rec.Code, rec.Body.String())
	}
}
