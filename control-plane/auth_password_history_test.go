package controlplane

// Tests for password-reuse prevention (auth_password_history.go).
//
// Structure:
//   - InMemory store unit tests: RecordPassword trims correctly, RecentHashes retrieves correctly.
//   - checkPasswordHistory unit test: matched hash returns ErrPasswordReused; no match returns nil.
//   - Handler integration tests (POST /me/password): reuse of a recently retired password is
//     rejected; a new password that is not in history is accepted.
//
// Mutation guards:
//   M1 — removing the checkPasswordHistory call from HandleChangePassword:
//        a reuse that should be 400 becomes 200.
//   M2 — removing the RecordPassword call from HandleChangePassword:
//        history stays empty, so the check sees nothing and the reuse returns 200.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// -------------------------------------------------------------------------------------
// InMemoryPasswordHistoryStore unit tests
// -------------------------------------------------------------------------------------

func TestPasswordHistoryStoreTrimToDepth(t *testing.T) {
	s := &InMemoryPasswordHistoryStore{}
	tenant, user := "t1", "u1"

	// Insert passwordHistoryDepth + 2 entries; only the most recent depth must survive.
	for i := 0; i < passwordHistoryDepth+2; i++ {
		if err := s.RecordPassword(t.Context(), tenant, user, fakeHistHash(i)); err != nil {
			t.Fatalf("RecordPassword[%d]: %v", i, err)
		}
	}
	got, err := s.RecentHashes(t.Context(), tenant, user, passwordHistoryDepth+2)
	if err != nil {
		t.Fatalf("RecentHashes: %v", err)
	}
	if len(got) != passwordHistoryDepth {
		t.Fatalf("after %d inserts got %d hashes, want %d (depth)",
			passwordHistoryDepth+2, len(got), passwordHistoryDepth)
	}
	// Newest first — the last inserted hash is i=passwordHistoryDepth+1.
	if got[0] != fakeHistHash(passwordHistoryDepth+1) {
		t.Fatalf("newest entry = %q, want fakeHistHash(%d)", got[0], passwordHistoryDepth+1)
	}
}

func TestPasswordHistoryStoreDoesNotCrossTenants(t *testing.T) {
	s := &InMemoryPasswordHistoryStore{}
	if err := s.RecordPassword(t.Context(), "tenant-A", "u1", "hashA"); err != nil {
		t.Fatalf("RecordPassword tenantA: %v", err)
	}
	got, err := s.RecentHashes(t.Context(), "tenant-B", "u1", passwordHistoryDepth)
	if err != nil {
		t.Fatalf("RecentHashes tenantB: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d hashes for a different tenant, want 0", len(got))
	}
}

func TestPasswordHistoryStoreDoesNotCrossUsers(t *testing.T) {
	s := &InMemoryPasswordHistoryStore{}
	if err := s.RecordPassword(t.Context(), "t1", "userA", "hashA"); err != nil {
		t.Fatalf("RecordPassword userA: %v", err)
	}
	got, err := s.RecentHashes(t.Context(), "t1", "userB", passwordHistoryDepth)
	if err != nil {
		t.Fatalf("RecentHashes userB: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d hashes for a different user, want 0", len(got))
	}
}

// fakeHistHash produces a deterministic non-PHC string for InMemory-only store tests where
// argon2 verification is never called.
func fakeHistHash(i int) string { return "fake-hist-hash-" + string(rune('A'+i)) }

// -------------------------------------------------------------------------------------
// checkPasswordHistory unit tests (uses cheap argon2 via HashPasswordWith)
// -------------------------------------------------------------------------------------

func TestCheckPasswordHistoryNilStoreIsNoop(t *testing.T) {
	if err := checkPasswordHistory(t.Context(), nil, "t1", "u1", "anything"); err != nil {
		t.Fatalf("nil store: got %v, want nil", err)
	}
}

func TestCheckPasswordHistoryRejectsMatchingHash(t *testing.T) {
	s := &InMemoryPasswordHistoryStore{}
	const candidate = "OldPassword1!"
	hash, err := HashPasswordWith(candidate, cheapArgon2Params)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if err := s.RecordPassword(t.Context(), "t1", "u1", hash); err != nil {
		t.Fatalf("RecordPassword: %v", err)
	}
	if got := checkPasswordHistory(t.Context(), s, "t1", "u1", candidate); got != ErrPasswordReused {
		t.Fatalf("matching hash: got %v, want ErrPasswordReused", got)
	}
}

func TestCheckPasswordHistoryAllowsNonMatch(t *testing.T) {
	s := &InMemoryPasswordHistoryStore{}
	hash, err := HashPasswordWith("OldPassword1!", cheapArgon2Params)
	if err != nil {
		t.Fatalf("HashPasswordWith: %v", err)
	}
	if err := s.RecordPassword(t.Context(), "t1", "u1", hash); err != nil {
		t.Fatalf("RecordPassword: %v", err)
	}
	if err := checkPasswordHistory(t.Context(), s, "t1", "u1", "TotallyDifferentPw2!"); err != nil {
		t.Fatalf("different candidate: got %v, want nil", err)
	}
}

// -------------------------------------------------------------------------------------
// Handler integration: POST /me/password with history
// -------------------------------------------------------------------------------------

// newPwHistFixture builds the same wiring as newPwFixture but attaches an InMemory history store.
func newPwHistFixture(t *testing.T) *pwFixture {
	t.Helper()
	f := newPwFixture(t)
	f.auth.PasswordHistory = &InMemoryPasswordHistoryStore{}
	return f
}

// changeWithNewSession issues a POST /me/password and returns a new pwFixture updated with the
// rotated cookie and CSRF token from the response. The password change endpoint rotates the session
// on success, so subsequent requests need the new cookie.
func changeWithNewSession(t *testing.T, f *pwFixture, current, next string) (*pwFixture, *httptest.ResponseRecorder) {
	t.Helper()
	rec := doJSONWith(t, f.handler, "POST", "/me/password", map[string]string{
		"current_password": current, "new_password": next,
	}, f.token, f.cookie, f.csrf)
	if rec.Code == http.StatusOK {
		newCookie := sessionCookieFrom(rec)
		csrfCookie, csrfTok := csrfFrom(t, rec)
		f = &pwFixture{
			authFixture: f.authFixture,
			handler:     f.handler,
			audit:       f.audit,
			cookie:      newCookie,
			csrf:        csrfCookie,
			token:       csrfTok,
		}
	}
	return f, rec
}

// TestPasswordHistoryBlocksReuseOnChange — M1/M2 mutation guard.
//
// With the fix in place:
//   - P0 → P1 succeeds and records P0 in history.
//   - P1 → P0 is rejected with 400 (checkPasswordHistory finds P0 in history).
//
// M1 (remove checkPasswordHistory call): step 2 returns 200 — test fails.
// M2 (remove RecordPassword call): history is empty at step 2; checkPasswordHistory
//
//	finds nothing → step 2 returns 200 — test fails.
func TestPasswordHistoryBlocksReuseOnChange(t *testing.T) {
	f := newPwHistFixture(t)

	// P0 → P1: records P0 in history.
	f, rec := changeWithNewSession(t, f, pwOld, pwNew)
	if rec.Code != http.StatusOK {
		t.Fatalf("P0→P1 change = %d: %s", rec.Code, rec.Body.String())
	}

	// P1 → P0: must be rejected because P0 is in history.
	_, attempt := changeWithNewSession(t, f, pwNew, pwOld)
	if attempt.Code != http.StatusBadRequest {
		t.Fatalf("P1→P0 reuse = %d, want 400 (ErrPasswordReused): %s",
			attempt.Code, attempt.Body.String())
	}
}

// TestPasswordHistoryAllowsNewPassword — positive control: a genuinely new password is not blocked.
func TestPasswordHistoryAllowsNewPassword(t *testing.T) {
	const pwThird = "ThirdPassword-456!"
	f := newPwHistFixture(t)

	// P0 → P1: records P0 in history.
	f, rec := changeWithNewSession(t, f, pwOld, pwNew)
	if rec.Code != http.StatusOK {
		t.Fatalf("P0→P1 = %d: %s", rec.Code, rec.Body.String())
	}

	// P1 → pwThird: pwThird is not in history, must succeed.
	_, rec2 := changeWithNewSession(t, f, pwNew, pwThird)
	if rec2.Code != http.StatusOK {
		t.Fatalf("P1→new = %d, want 200: %s", rec2.Code, rec2.Body.String())
	}
}
