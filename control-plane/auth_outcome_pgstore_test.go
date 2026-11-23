package controlplane

// The REAL pgx stores with a pool that cannot answer: authentication is 503, not 401. Skips without
// TEST_DATABASE_URL like every pgx test here; verify-all treats a skip as a failure.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthStoreFault_Pg_ClosedPoolIs503(t *testing.T) {
	f := newPass13PgFixture(t)
	alice, _, _ := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	if got := f.listSessions(t, alice); got != http.StatusOK {
		t.Fatalf("before the fault = %d, want 200", got)
	}
	f.appPool.Close() // every later query fails: the database "went away"
	r := httptest.NewRequest("GET", "/sessions", nil)
	r.AddCookie(alice)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	requireUnavailable(t, w, "GET /sessions on a closed pool")
}
