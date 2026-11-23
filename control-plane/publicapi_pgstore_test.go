package controlplane

// DB-gated proof for the public API WRITE surface (docs/59 §4, last bullet): ONE write driven end to
// end as a REAL Bearer token — minted into Postgres, resolved by APITokenAuthenticator on the pool
// (the auth-time path), the stores RLS-pinned as rmt_app, the mutation AND its audit row landing in
// Postgres with the TOKEN as the actor — plus the no-capability denial leaving no rows, and a
// malformed rmt_api_ credential failing closed instead of falling through to the session path. The
// in-memory behavioral suite (publicapi_test.go) covers every write route; this pins the credential
// chain and the database once. Needs TEST_DATABASE_URL; verify-all.ps1 treats a skip as a failure.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recordingFallbackAuth is the Next authenticator behind APITokenAuthenticator in the test. It
// RETURNS AN AUTHORIZED OWNER, so if a malformed rmt_api_ credential ever fell through to the
// session path the request would SUCCEED (201) - making the 401 assertion prove the fail-closed
// property instead of being satisfied by a nil fallback that also 401s (review f8e839aa F2).
type recordingFallbackAuth struct {
	p      *Principal
	called bool
}

func (a *recordingFallbackAuth) Authenticate(_ *http.Request) (*Principal, error) {
	a.called = true
	return a.p, nil
}

func TestPgPublicAPIWriteAsBearerToken(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTenantProvisionMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool)
	applyAPITokenMigration(t, suPool)
	ctx := context.Background()

	tid, uid := provisionUser(t, suPool, "pub-api", "owner@pub-api.test", "password-1234")
	appPool := newAppRolePool(t, ctx)
	tokens := NewPgAPITokenStore(appPool)

	fallback := &recordingFallbackAuth{p: &Principal{UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups()))}}
	srvFor := func() *Server {
		srv := NewServer(&APITokenAuthenticator{Tokens: tokens, Next: fallback},
			NewPgBinder(appPool))
		srv.MachineGroups = NewPgMachineGroupStore(appPool)
		srv.MgmtAudit = NewPgMgmtAuditStore(appPool)
		return srv
	}
	createGroup := func(bearer, name string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", publicAPIBasePath+"/machine-groups", strings.NewReader(`{"name":"`+name+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		srvFor().Handler().ServeHTTP(rec, req)
		return rec
	}
	countGroups := func(name string) int {
		var n int
		if err := suPool.QueryRow(ctx,
			`SELECT count(*) FROM machine_group WHERE tenant_id = $1::uuid AND name = $2`, tid, name).Scan(&n); err != nil {
			t.Fatalf("count groups: %v", err)
		}
		return n
	}

	// A token holding manage_groups performs the write; row + audit land in pg, actor = the token id.
	plainW, tokW, err := tokens.Mint(ctx, tid, "writer", []Capability{CapManageGroups}, uid, nil)
	if err != nil {
		t.Fatalf("mint writer token: %v", err)
	}
	rec := createGroup(plainW, "API PG Group")
	if rec.Code != http.StatusCreated {
		t.Fatalf("bearer create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		MachineGroup MachineGroup `json:"machine_group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.MachineGroup.ID == "" {
		t.Fatalf("create envelope = %s (err %v)", rec.Body.String(), err)
	}
	if n := countGroups("API PG Group"); n != 1 {
		t.Fatalf("persisted groups named 'API PG Group' = %d, want 1", n)
	}
	var actor, target string
	if err := suPool.QueryRow(ctx,
		`SELECT actor_user_id::text, target_id FROM audit_event
		 WHERE tenant_id = $1::uuid AND action = 'machine_group.created'`, tid).Scan(&actor, &target); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if actor != tokW.ID || target != out.MachineGroup.ID {
		t.Fatalf("audit actor/target = %s/%s, want the token %s and group %s", actor, target, tokW.ID, out.MachineGroup.ID)
	}

	// A read-only token is refused, and nothing landed — neither the row nor an audit event.
	plainR, _, err := tokens.Mint(ctx, tid, "reader", []Capability{CapViewMachines}, uid, nil)
	if err != nil {
		t.Fatalf("mint reader token: %v", err)
	}
	if rec := createGroup(plainR, "Denied Group"); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only bearer create = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if n := countGroups("Denied Group"); n != 0 {
		t.Fatalf("denied create persisted a row")
	}
	var audits int
	if err := suPool.QueryRow(ctx,
		`SELECT count(*) FROM audit_event WHERE tenant_id = $1::uuid AND action = 'machine_group.created'`, tid).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("machine_group.created audit rows = %d (%v), want exactly 1", audits, err)
	}

	// A malformed rmt_api_ credential fails CLOSED (401) — it is never re-interpreted as a session.
	if rec := createGroup(APITokenPrefix+"garbage", "Ghost"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage bearer create = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if n := countGroups("Ghost"); n != 0 {
		t.Fatalf("unauthenticated create persisted a row")
	}
	// No request in this test may ever reach the session path: every credential sent carried the
	// rmt_api_ prefix, which the token authenticator must consume - resolve or fail closed.
	if fallback.called {
		t.Fatalf("a rmt_api_-prefixed credential fell through to the session authenticator")
	}
}
