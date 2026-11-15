package controlplane

import (
	"context"
	"testing"
	"time"
)

// Security audit 2026-10-18 (Codex p06): two password changes that verified the SAME old password
// must not both write. The second, holding the pre-change epoch, is refused and changes nothing —
// against real Postgres as rmt_app, and against the in-memory fake the handler tests use.
func TestPgChangePasswordRefusesAStaleVerification(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()
	tid, uid := provisionUser(t, suPool, "cp-epoch", "ana@cp-epoch.test", "Original-Passw0rd!")
	store := newPgUserStoreT(newAppRolePool(t, ctx))
	assertChangePasswordEpoch(t, ctx, store, tid, uid)
}

func TestMemChangePasswordRefusesAStaleVerification(t *testing.T) {
	store := NewInMemoryUserStore()
	hash, err := HashPassword("Original-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	u := &AuthUser{ID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222", Email: "ana@cp-epoch.test", PasswordHash: hash}
	store.AddUser(u, nil)
	assertChangePasswordEpoch(t, context.Background(), store, u.TenantID, u.ID)
}

func assertChangePasswordEpoch(t *testing.T, ctx context.Context, store UserStore, tid, uid string) {
	t.Helper()
	before, err := store.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatal(err)
	}
	verified := before.CredentialUpdatedAt // both "requests" verified the old password at this epoch
	epoch, err := store.ChangePassword(ctx, tid, uid, "$owner-recovery-hash", verified)
	if err != nil {
		t.Fatalf("first change: %v", err)
	}
	if !epoch.After(verified) {
		t.Fatalf("epoch did not advance: %v -> %v", verified, epoch)
	}
	if _, err := store.ChangePassword(ctx, tid, uid, "$attacker-hash", verified); err != ErrStaleCredential {
		t.Fatalf("stale change = %v, want ErrStaleCredential", err)
	}
	after, err := store.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatal(err)
	}
	if after.PasswordHash != "$owner-recovery-hash" || !after.CredentialUpdatedAt.Equal(epoch) {
		t.Fatalf("stale change wrote: hash=%q epoch=%v want epoch %v", after.PasswordHash, after.CredentialUpdatedAt, epoch)
	}
	if _, err := store.ChangePassword(ctx, tid, uid, "$next-hash", time.Time{}); err != ErrStaleCredential {
		t.Fatalf("zero epoch = %v, want ErrStaleCredential", err)
	}
}
