package controlplane

// DB-gated proof for the path-id gate (pathid.go): a malformed `{id}` must answer 404, not 500.
//
// This test is pg-backed BY NECESSITY, not by preference. The defect it pins is a PostgreSQL
// behaviour: every `{id}` in this service is a database primary key in a `uuid` column, and a
// malformed literal is rejected at cast time with SQLSTATE 22P02, which reaches the handler as an
// opaque driver error and falls into its "could not resolve …" 500 branch. The in-memory stores
// compare Go strings and simply miss, so they return not-found for a malformed id all by
// themselves — a fake CANNOT reproduce this, and an in-memory version of this test would have
// passed before the fix and proved nothing. (Same division of labour as the machine.os work: a
// fake pins a handler, only the database pins what the database does.)
//
// Every case asserts the 404 came from the HANDLER, not from the router: a mistyped path would
// give ServeMux's own 404 and pass this test vacuously. The handler answers JSON `{"error":…}`
// with a known message; ServeMux answers "404 page not found" in text/plain. Checking the message
// is what makes the premise real.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// malformedPathIDs are values PostgreSQL's uuid_in REJECTS, so each one reaches a `::uuid` cast and
// raises 22P02. The last two are the interesting ones: near-misses that look like ids.
var malformedPathIDs = []string{
	"not-a-uuid",
	"1",
	"%20",
	"11111111-1111-4111-8111-11111111111",   // 31 hex digits — one short
	"11111111-1111-4111-8111-1111111111111", // 33 hex digits — one long
	"11111111-1111-4111-8111-11111111111g",  // non-hex digit
}

// errorMessage extracts the JSON `error` field, or "" when the body is not the handler's JSON
// shape (ServeMux's own 404 is text/plain, which is exactly what this distinguishes).
func errorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		return ""
	}
	return body.Error
}

// TestPgMalformedPathIDIsNotFoundNotServerError drives the real handlers over real pg stores.
//
// Measured with the gate REMOVED, every case here returns 500 "could not resolve …" — that is the
// defect, and it is the reason this file exists.
func TestPgMalformedPathIDIsNotFoundNotServerError(t *testing.T) {
	pool := newTestPool(t)                     // skips when no TEST_DATABASE_URL
	applyAppRoleMigration(t, pool)             // 0005
	applyMachineDeviceUniqueMigration(t, pool) // 0008
	applyDeviceIdentityMigration(t, pool)      // 0010
	applyAttendedMigration(t, pool)            // 0013 — PgMachineStore projects machine.ephemeral
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()

	machines := NewPgMachineStore(pool)

	// Owner over every group, so a capability check can never be what produces a non-200 below —
	// otherwise a 403 would masquerade as "the gate works".
	p := &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.Machines = machines
	srv.SessionRecords = NewPgSessionRecordStore(pool)
	srv.Attended = NewPgAttendedStore(pool)
	// handlePromoteAttended checks this store BEFORE resolving the id, so leaving it nil makes that
	// case 500 for an unrelated reason and hides what is being tested.
	srv.EnrollmentTokens = NewPgEnrollmentTokenStore(pool)
	h := srv.Handler()

	// PREMISE: a real machine resolves 200 through this exact route. Without this, every assertion
	// below could be satisfied by a route that does not exist.
	real := &Machine{DeviceID: "pathid-device-1", GroupID: gid, Name: "host-1"}
	if err := machines.EnrollMachine(ctx, tid, real); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/machines/"+real.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("premise not met: GET /machines/{real id} = %d (body %s), want 200 — the rest of "+
			"this test cannot distinguish a working gate from a broken route",
			rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		name    string
		method  string
		path    string // %s ← the id under test
		wantMsg string
	}{
		{"get machine", "GET", "/machines/%s", "unknown machine"},
		{"end session", "POST", "/sessions/%s/end", "unknown session"},
		{"get attended", "GET", "/attended-sessions/%s", "unknown attended session"},
		{"connect attended", "POST", "/attended-sessions/%s/connect", "unknown attended session"},
		{"promote attended", "POST", "/attended-sessions/%s/promote", "unknown attended session"},
		{"end attended", "POST", "/attended-sessions/%s/end", "unknown attended session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The CONTROL: a well-formed uuid that names no row. It reaches the store, misses, and
			// takes the handler's not-found branch — so it fixes the message the malformed cases
			// must match, and proves the route reaches this handler at all.
			var wellFormed string
			if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&wellFormed); err != nil {
				t.Fatalf("gen uuid: %v", err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, strings.Replace(tc.path, "%s", wellFormed, 1), nil))
			if rec.Code != http.StatusNotFound || errorMessage(t, rec) != tc.wantMsg {
				t.Fatalf("premise not met: a well-formed unknown id gave %d %q, want 404 %q — the "+
					"route or its not-found branch is not what this test assumes",
					rec.Code, errorMessage(t, rec), tc.wantMsg)
			}

			for _, id := range malformedPathIDs {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(tc.method, strings.Replace(tc.path, "%s", id, 1), nil))
				if rec.Code == http.StatusInternalServerError {
					t.Errorf("%s %q → 500 (%s); a malformed id names a resource that cannot exist, "+
						"so it must be 404, not a server fault",
						tc.method, id, strings.TrimSpace(rec.Body.String()))
					continue
				}
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s %q → %d, want 404", tc.method, id, rec.Code)
					continue
				}
				// Same message as the well-formed miss: the gate must be indistinguishable from an
				// ordinary not-found, so it never reports whether an id was merely mistyped.
				if got := errorMessage(t, rec); got != tc.wantMsg {
					t.Errorf("%s %q → 404 %q, want the ordinary not-found message %q",
						tc.method, id, got, tc.wantMsg)
				}
			}
		})
	}
}

// TestPgMalformedPathIDOnPasswordResetRoutes covers the two `/users/{id}/password-reset` handlers,
// which the table above cannot reach: they sit behind a real login + CSRF double-submit + a
// password step-up, so they need the full HTTP chain (the same fixture shape as
// TestPgPasswordResetChainAsAppRole) rather than a StubAuthenticator.
//
// The two endpoints answer a malformed id DIFFERENTLY, and that is deliberate — each keeps the
// answer it already gives for a well-formed id naming no user, because the store-level check
// (pathid.go) makes the two cases identical rather than inventing a new outcome for one of them:
//
// Both answer 404 "no such user", because both now RESOLVE the target first and FindUserByID
// reports ErrNoUser for an id no `uuid` column could hold (pathid.go).
//
// Measured with the store check disabled, BOTH return 500 "could not resolve user" — both now
// reach FindUserByID first, so that is the cast they die on.
//
// The revoke path only reaches a user lookup at all because this work added one. Before, it
// revoked and AUDITED against the raw path value; a `{"revoked":0}` no-op for a malformed id was
// the first attempt at this fix, and it was measured returning 500 "could not record audit event"
// — the id flowed on into audit_event.target_id, a SECOND uuid cast. Resolving the target is what
// makes the endpoint answer before either cast.
func TestPgMalformedPathIDOnPasswordResetRoutes(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyCredentialTokenMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool)
	ctx := context.Background()

	tid, adminID := provisionUser(t, suPool, "pathid", "admin@pathid.test", "Admin-Passw0rd!")
	grantRole(t, suPool, tid, adminID, RoleAdmin)
	targetID := seedCredentiallessUser(t, suPool, tid, "dana@pathid.test")
	grantRole(t, suPool, tid, targetID, RoleTechnician)

	appPool := newAppRolePool(t, ctx)
	users := newPgUserStoreT(appPool)
	sessions := NewSessionManager(NewPgSessionStore(appPool))
	mgmtAudit := NewPgMgmtAuditStore(appPool)
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(appPool))
	srv.AuthAPI = &AuthService{
		Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(appPool),
		Issuer: "RMT", MgmtAudit: mgmtAudit,
		CredentialTokens: NewPgCredentialTokenStore(appPool),
	}
	srv.MgmtAudit = mgmtAudit
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	h := srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "pathid", Email: "admin@pathid.test", Password: "Admin-Passw0rd!"}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("admin login = %d: %s", login.Code, login.Body.String())
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)
	body := map[string]any{"password": "Admin-Passw0rd!"}

	// PREMISE: the same call with the REAL target id succeeds, so a 404 below is the gate and not a
	// broken route, a rejected step-up, or a CSRF failure.
	if rec := doJSONWith(t, h, "POST", "/users/"+targetID+"/password-reset", body,
		csrfToken, cookie, csrfCookie); rec.Code != http.StatusCreated {
		t.Fatalf("premise not met: mint for the real target = %d (%s), want 201",
			rec.Code, rec.Body.String())
	}

	for _, id := range malformedPathIDs {
		mint := doJSONWith(t, h, "POST", "/users/"+id+"/password-reset", body, csrfToken, cookie, csrfCookie)
		if mint.Code != http.StatusNotFound {
			t.Errorf("POST /users/%s/password-reset = %d (%s), want 404",
				id, mint.Code, strings.TrimSpace(mint.Body.String()))
		}
		revoke := doJSONWith(t, h, "DELETE", "/users/"+id+"/password-reset", nil, csrfToken, cookie, csrfCookie)
		if revoke.Code != http.StatusNotFound {
			t.Errorf("DELETE /users/%s/password-reset = %d (%s), want 404",
				id, revoke.Code, strings.TrimSpace(revoke.Body.String()))
		}
	}

	if _, err := suPool.Exec(ctx, "DELETE FROM tenant WHERE id = $1", tid); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestPgMalformedPathIDStillResolvesEveryFormPostgresAccepts is the OTHER direction, and the reason
// the gate parses with parsePgUUID (which matches uuid_in) rather than the stricter canonical-only
// isUUID: a spelling PostgreSQL accepts must keep resolving to the row it always resolved to.
// Rejecting one would turn a working lookup into a 404 — a regression dressed up as a fix, and one
// no test in this tree would otherwise catch, since every id the console handles is canonical.
func TestPgMalformedPathIDStillResolvesEveryFormPostgresAccepts(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()

	machines := NewPgMachineStore(pool)
	p := &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.Machines = machines
	h := srv.Handler()

	m := &Machine{DeviceID: "pathid-device-2", GroupID: gid, Name: "host-2"}
	if err := machines.EnrollMachine(ctx, tid, m); err != nil {
		t.Fatalf("seed machine: %v", err)
	}

	// Each spelling is confirmed against the LIVE server first, so the test asserts what Postgres
	// actually accepts rather than what this file believes it accepts.
	for _, id := range []string{
		m.ID,
		strings.ReplaceAll(m.ID, "-", ""), // dashless
		strings.ToUpper(m.ID),             // uppercase
		"{" + m.ID + "}",                  // brace-wrapped
		strings.Replace(m.ID, "-", "", 1), // one hyphen dropped
		"{" + strings.ReplaceAll(m.ID, "-", "") + "}", // both at once
	} {
		var accepted bool
		if err := pool.QueryRow(ctx,
			"SELECT $1::uuid = $2::uuid", id, m.ID).Scan(&accepted); err != nil || !accepted {
			t.Fatalf("premise not met: Postgres does not accept %q as %s (%v) — this case is "+
				"testing the wrong thing", id, m.ID, err)
		}
		// The brace/dashless forms must be percent-safe in a URL path; braces are legal in a path
		// segment for httptest's parser, so this drives them verbatim.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/machines/"+id, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET /machines/%s = %d (%s), want 200 — the gate must not reject a spelling "+
				"Postgres resolves", id, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}
