package controlplane

// Handler-level proofs for POST/GET/DELETE /api-tokens over newTestServer (StubAuthenticator +
// in-memory stores). These pin the HTTP surface: the CapManageTenant gate, capability validation,
// the one-time plaintext, and the mint→list→revoke lifecycle. RLS / SQL properties are in
// apitoken_pgstore_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doAPITokenReq runs one request as the given role and returns the recorder.
func doAPITokenReq(t *testing.T, role Role, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(role, AllGroups())),
	}
	srv, _ := newTestServer(p)
	rec := httptest.NewRecorder()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

func TestAPITokenMintRequiresManageTenant(t *testing.T) {
	body := `{"name":"bot","capabilities":["view_machines"]}`
	cases := []struct {
		role Role
		want int
	}{
		{RoleOwner, http.StatusCreated},   // Owner holds CapManageTenant
		{RoleAdmin, http.StatusForbidden}, // Admin deliberately lacks CapManageTenant
		{RoleReadOnly, http.StatusForbidden},
		{RoleTechnician, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(string(tc.role), func(t *testing.T) {
			rec := doAPITokenReq(t, tc.role, "POST", "/api-tokens", body)
			if rec.Code != tc.want {
				t.Fatalf("mint as %s = %d, want %d (body %s)", tc.role, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestAPITokenListRevokeRequireManageTenant(t *testing.T) {
	if rec := doAPITokenReq(t, RoleAdmin, "GET", "/api-tokens", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("list as Admin = %d, want 403", rec.Code)
	}
	if rec := doAPITokenReq(t, RoleOwner, "GET", "/api-tokens", ""); rec.Code != http.StatusOK {
		t.Fatalf("list as Owner = %d, want 200", rec.Code)
	}
	// Revoke gate: Admin denied even for a (non-existent) id — the capability check precedes lookup.
	if rec := doAPITokenReq(t, RoleAdmin, "DELETE", "/api-tokens/whatever", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("revoke as Admin = %d, want 403", rec.Code)
	}
}

func TestAPITokenMintRejectsBadCapabilities(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty caps", `{"name":"bot","capabilities":[]}`},
		{"unknown cap", `{"name":"bot","capabilities":["teleport"]}`},
		{"non-grantable: manage_tenant", `{"name":"bot","capabilities":["manage_tenant"]}`},
		{"non-grantable: start_session", `{"name":"bot","capabilities":["view_machines","start_session"]}`},
		{"missing name", `{"capabilities":["view_machines"]}`},
		{"negative expiry", `{"name":"bot","capabilities":["view_machines"],"expires_in_days":-1}`},
		{"over-long expiry", `{"name":"bot","capabilities":["view_machines"],"expires_in_days":100000}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAPITokenReq(t, RoleOwner, "POST", "/api-tokens", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("mint %q = %d, want 400 (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAPITokenLifecycle mints, lists, and revokes over ONE server instance, proving the plaintext
// is shown once and the row reflects each step.
func TestAPITokenLifecycle(t *testing.T) {
	p := &Principal{
		UserID:   "owner-1",
		TenantID: "tenant-123",
		Grant:    NewGrant("owner-1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)

	// --- MINT
	mintRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(mintRec, httptest.NewRequest("POST", "/api-tokens",
		strings.NewReader(`{"name":"ci-bot","capabilities":["view_machines","view_audit"]}`)))
	if mintRec.Code != http.StatusCreated {
		t.Fatalf("mint = %d, want 201 (body %s)", mintRec.Code, mintRec.Body.String())
	}
	var mintResp struct {
		Token    string   `json:"token"`
		APIToken APIToken `json:"api_token"`
	}
	if err := json.Unmarshal(mintRec.Body.Bytes(), &mintResp); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	if !strings.HasPrefix(mintResp.Token, APITokenPrefix) {
		t.Fatalf("returned token %q lacks prefix", mintResp.Token)
	}
	if mintResp.APIToken.ID == "" || mintResp.APIToken.Name != "ci-bot" {
		t.Fatalf("mint metadata wrong: %+v", mintResp.APIToken)
	}
	if mintResp.APIToken.CreatedBy != "owner-1" {
		t.Fatalf("created_by = %q, want owner-1", mintResp.APIToken.CreatedBy)
	}
	if len(mintResp.APIToken.Capabilities) != 2 {
		t.Fatalf("mint caps = %v, want 2", mintResp.APIToken.Capabilities)
	}
	id := mintResp.APIToken.ID

	// --- LIST shows it, active (no revoked_at).
	list := listAPITokens(t, srv)
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("list = %+v, want the one minted token %s", list, id)
	}
	if list[0].RevokedAt != nil {
		t.Fatalf("freshly minted token should not be revoked")
	}

	// --- REVOKE
	revRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(revRec, httptest.NewRequest("DELETE", "/api-tokens/"+id, nil))
	if revRec.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200 (body %s)", revRec.Code, revRec.Body.String())
	}

	// --- LIST now shows it revoked.
	list = listAPITokens(t, srv)
	if len(list) != 1 || list[0].RevokedAt == nil {
		t.Fatalf("after revoke, token should carry revoked_at: %+v", list)
	}

	// --- REVOKE unknown id → 404.
	nf := httptest.NewRecorder()
	srv.Handler().ServeHTTP(nf, httptest.NewRequest("DELETE", "/api-tokens/00000000-0000-0000-0000-000000000000", nil))
	if nf.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown = %d, want 404", nf.Code)
	}
}

func listAPITokens(t *testing.T, srv *Server) []APIToken {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api-tokens", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		APITokens []APIToken `json:"api_tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return resp.APITokens
}
