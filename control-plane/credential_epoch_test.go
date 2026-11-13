package controlplane

// The credential epoch (migrations/0018) — the fix for the password-change TOCTOU.
//
// The race, restated: a login and a password change are separate transactions, so a login that read
// the OLD password hash can insert its session AFTER the change's mass revocation has committed.
// That session is revoked by nothing and lives its full 12 hours, authorized by the password the
// account owner was rotating precisely because they believed it compromised.
//
// Nothing about instants can fix it — a revocation happens at SOME instant and the racing INSERT
// can always land after it — so sessions are compared by CREDENTIAL VERSION instead. These tests
// therefore drive the race in the order that actually produces the vulnerable session, rather than
// asserting on the comparison function alone: a unit test of CredentialEpochMatches would have
// passed against the vulnerable code too, because the vulnerable code never called it.
//
// The DB-backed half — that the epoch really round-trips through user_session.credential_epoch as
// the least-privilege rmt_app role, and that Postgres's own now() supplies the version — is
// TestPgCredentialEpochUnderRLS in password_pgstore_test.go.

import (
	"net/http"
	"testing"
	"time"
)

// THE RACE ITSELF, in the order that produces the vulnerable session:
//
//  1. a login reads the credential (hash + epoch) — the read that authorizes it
//  2. the password change commits AND revokes every existing session
//  3. only THEN does the login insert its session
//
// Step 3 lands after the revocation, so revocation cannot touch it. The session must still be
// refused, because the version it names is no longer the current one.
func TestCredentialEpochRefusesASessionThatRacedThePasswordChange(t *testing.T) {
	f := newPwFixture(t)

	// (1) The racing login's credential read. This is the value HandleLogin would carry into
	// Issue: the epoch that accompanied the hash it verified.
	racer, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if racer.CredentialUpdatedAt.IsZero() {
		t.Fatal("test premise: the user must have a credential epoch to race against")
	}

	// (2) The password change: new credential, every existing session revoked.
	if rec := f.change(t, pwOld, pwNew); rec.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
	}

	// (3) The racing login finally inserts its session — AFTER the revocation, so nothing revoked
	// it. This is exactly the session the old code handed out and could not evict.
	raced, _, err := f.sessions.Issue(t.Context(), "tenant-1", "u1", racer.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue (racing login): %v", err)
	}

	// It exists, it is unrevoked, it is unexpired — and it must still not authenticate.
	stored, err := f.sessions.Store.GetByTokenHash(t.Context(), HashToken(raced))
	if err != nil {
		t.Fatalf("the raced session was not stored at all: %v", err)
	}
	if stored.RevokedAt != nil {
		t.Fatal("test premise: the raced session must be UNREVOKED — otherwise revocation, not the " +
			"epoch, is what this test is measuring")
	}
	if code := apiJSONAuth(t, f.srv, "GET", "/machines", raced, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("a session authorized by the RETIRED password authenticated (%d); the credential "+
			"epoch must refuse it", code)
	}
}

// The same refusal at the authenticator seam, stated as the property rather than the scenario: a
// session whose epoch predates the credential's is refused with the typed error, and one carrying
// the current epoch is admitted.
func TestCredentialEpochRefusesASessionOlderThanTheCredential(t *testing.T) {
	f := newPwFixture(t)
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}

	stale, _, err := f.sessions.Issue(t.Context(), "tenant-1", "u1", u.CredentialUpdatedAt.Add(-time.Second))
	if err != nil {
		t.Fatalf("Issue stale: %v", err)
	}
	current, _, err := f.sessions.Issue(t.Context(), "tenant-1", "u1", u.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue current: %v", err)
	}

	sa := &SessionAuthenticator{Sessions: f.sessions, Users: f.users}
	if _, err := sa.Authenticate(bearerRequest(stale)); err != ErrSessionCredentialStale {
		t.Fatalf("stale-epoch Authenticate = %v, want ErrSessionCredentialStale", err)
	}
	p, err := sa.Authenticate(bearerRequest(current))
	if err != nil {
		t.Fatalf("current-epoch Authenticate = %v, want success", err)
	}
	if p.UserID != "u1" {
		t.Fatalf("principal user = %s, want u1", p.UserID)
	}

	// A session issued with a NEWER epoch than the credential is not signed out: that can only come
	// from a clock or backfill anomaly, never from the race, and the sessions that matter after a
	// password change were revoked outright.
	ahead, _, err := f.sessions.Issue(t.Context(), "tenant-1", "u1", u.CredentialUpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatalf("Issue ahead: %v", err)
	}
	if _, err := sa.Authenticate(bearerRequest(ahead)); err != nil {
		t.Fatalf("newer-epoch Authenticate = %v, want success", err)
	}
}

// The replacement session a successful change hands back must carry the NEW epoch. If it carried
// the pre-change one, the endpoint would answer 200 with a Set-Cookie the very next request
// rejects — a password change that silently signs the user out of the tab they did it in.
func TestChangePasswordIssuesASessionOnTheNewEpoch(t *testing.T) {
	f := newPwFixture(t)
	rec := f.change(t, pwOld, pwNew)
	if rec.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
	}
	rotated := sessionCookieFrom(rec)
	if rotated == nil || rotated.Value == "" {
		t.Fatal("the change did not return a replacement session cookie")
	}
	csrfCookie, csrfTok := csrfFrom(t, rec)
	if got := doJSONWith(t, f.handler, "GET", "/machines", nil, csrfTok, rotated, csrfCookie); got.Code != http.StatusOK {
		t.Fatalf("the rotated session is already stale (%d) — it must carry the epoch SetPassword "+
			"just wrote: %s", got.Code, got.Body.String())
	}
}

// A user with NO local credential has no version to be stale against, so a zero epoch on both sides
// compares equal and the session works. This is the federated/OIDC shape, and getting it wrong
// would lock out every user who has no password at all.
func TestCredentialEpochAdmitsAUserWithNoCredential(t *testing.T) {
	f := newAuthFixture(t)
	// Added WITHOUT going through addUser, which always hashes something: this account has no
	// user_credential row at all, so both PasswordHash and the epoch are genuinely absent.
	f.users.AddUser(
		&AuthUser{ID: "nopw", TenantID: "tenant-1", Email: "federated@acme.test"},
		NewGrant("nopw", "tenant-1", NewMembership(RoleTechnician, AllGroups())),
	)
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "nopw")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if !u.CredentialUpdatedAt.IsZero() {
		t.Fatalf("a user with no credential has epoch %v, want zero", u.CredentialUpdatedAt)
	}
	token, _, err := f.sessions.Issue(t.Context(), "tenant-1", "nopw", u.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sa := &SessionAuthenticator{Sessions: f.sessions, Users: f.users}
	if _, err := sa.Authenticate(bearerRequest(token)); err != nil {
		t.Fatalf("Authenticate for a credential-less user = %v, want success", err)
	}
}

// The comparison itself, including the fail-CLOSED direction that a pre-0018 session row (no epoch
// recorded ⇒ zero) is refused against a user who DOES have a credential. That is the one case where
// "unknown" must not mean "fine".
func TestCredentialEpochMatches(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name           string
		session, cred  time.Time
		wantAuthorized bool
	}{
		{"equal — the normal case", now, now, true},
		{"session older — the race", now.Add(-time.Millisecond), now, false},
		{"session newer — clock/backfill anomaly, not the race", now.Add(time.Millisecond), now, true},
		{"no credential at all", time.Time{}, time.Time{}, true},
		{"unrecorded epoch vs a real credential — fail CLOSED", time.Time{}, now, false},
		{"recorded epoch, credential removed", now, time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CredentialEpochMatches(tc.session, tc.cred); got != tc.wantAuthorized {
				t.Fatalf("CredentialEpochMatches(%v, %v) = %v, want %v",
					tc.session, tc.cred, got, tc.wantAuthorized)
			}
		})
	}
}

// bearerRequest builds a request carrying a session token as a Bearer credential.
func bearerRequest(token string) *http.Request {
	req, _ := http.NewRequest("GET", "/machines", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}
