package controlplane

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type emailResetRacingStore struct {
	UserStore
	hash string
}

func (s emailResetRacingStore) SetEmail(ctx context.Context, tenantID, userID, email string, epoch time.Time) (time.Time, error) {
	// Commit a reset after step-up verification but before the email write.
	if _, err := s.UserStore.SetPassword(ctx, tenantID, userID, s.hash); err != nil {
		return time.Time{}, err
	}
	return s.UserStore.SetEmail(ctx, tenantID, userID, email, epoch)
}

func TestEmailChangeRefusesResetAfterPasswordVerification(t *testing.T) {
	f := newPwFixture(t)
	hash, err := HashPassword(pwNew)
	if err != nil {
		t.Fatal(err)
	}
	f.auth.Users = emailResetRacingStore{UserStore: f.users, hash: hash}
	rec := doJSONWith(t, f.handler, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: pwOld, NewEmail: "renamed@acme.test",
	}, f.token, f.cookie, f.csrf)
	if rec.Code != http.StatusConflict {
		t.Fatalf("racing reset: %d %s", rec.Code, rec.Body.String())
	}
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil || u.Email != "dana@acme.test" || u.PasswordHash != hash {
		t.Fatalf("stale change overwrote account: userPresent=%v err=%v", u != nil, err)
	}
}

func TestPgEmailEpochCannotMoveBackwardOnPasswordReset(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	tid, uid := provisionUser(t, pool, "email-epoch", "user@epoch.test", pwOld)
	// A newer stored epoch can be encountered by an older transaction. Password
	// reset must still advance it, not roll back the email change's version.
	var before time.Time
	err := pool.QueryRow(t.Context(), `UPDATE user_credential
		SET updated_at = clock_timestamp() + interval '1 minute'
		WHERE user_id = $1 RETURNING updated_at`, uid).Scan(&before)
	if err != nil {
		t.Fatal(err)
	}
	store := newPgUserStoreT(newAppRolePool(t, t.Context()))
	hash, err := HashPassword(pwNew)
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.SetPassword(t.Context(), tid, uid, hash)
	if err != nil || !after.After(before) {
		t.Fatalf("reset epoch did not advance: before=%v after=%v err=%v", before, after, err)
	}
	if CredentialEpochMatches(before, after) {
		t.Fatal("a session issued before reset still matches the credential")
	}
}

func TestEmailChangeRejectsLateLoginUsingOldEmailEpoch(t *testing.T) {
	f := newPwFixture(t)
	before, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	rec := doJSONWith(t, f.handler, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: pwOld, NewEmail: "renamed@acme.test",
	}, f.token, f.cookie, f.csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("change: %d %s", rec.Code, rec.Body.String())
	}
	// The old-email lookup happened before the rename, but its login session
	// arrives after revocation. Credential epoch, not revocation time, rejects it.
	token, _, err := f.auth.Sessions.Issue(t.Context(), "tenant-1", "u1", before.CredentialUpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	late := doJSON(t, f.handler, "GET", "/machines", nil, &http.Cookie{Name: DefaultSessionCookie, Value: token})
	if late.Code != http.StatusUnauthorized {
		t.Fatalf("old-email racing login still authorized: %d", late.Code)
	}
}

func TestEmailChangeStoreRefusesSuspendedTenant(t *testing.T) {
	f := newPwFixture(t)
	u, _ := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	f.users.SetTenantSuspended("tenant-1", true)
	if _, err := f.users.SetEmail(t.Context(), "tenant-1", "u1", "renamed@acme.test", u.CredentialUpdatedAt); err != ErrNoUser {
		t.Fatalf("suspended tenant: %v", err)
	}
	after, _ := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if after.Email != u.Email || !after.CredentialUpdatedAt.Equal(u.CredentialUpdatedAt) {
		t.Fatal("suspended account changed")
	}
}

func TestPgEmailChangeStoreRefusesSuspendedTenant(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	tid, uid := provisionUser(t, pool, "email-suspended", "user@suspended.test", pwOld)
	store := newPgUserStoreT(newAppRolePool(t, t.Context()))
	u, err := store.FindUserByID(t.Context(), tid, uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE tenant SET disabled_at=now() WHERE id=$1`, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetEmail(t.Context(), tid, uid, "renamed@suspended.test", u.CredentialUpdatedAt); err != ErrNoUser {
		t.Fatalf("suspended tenant: %v", err)
	}
	after, err := store.FindUserByID(t.Context(), tid, uid)
	if err != nil || after.Email != u.Email || !after.CredentialUpdatedAt.Equal(u.CredentialUpdatedAt) {
		t.Fatalf("suspended account changed: %v", err)
	}
}
