package controlplane

// DB-backed integration tests for SetPromoteResult (migration 0052): confirms the promote-result
// columns are written and read back faithfully, and that a revoked/expired attend token and a
// session that has not yet had promote requested both return the correct sentinel errors.
//
// Like every pgx test these SKIP without TEST_DATABASE_URL. The in-memory path is covered by
// attended_promote_complete_test.go (no DB required).

import (
	"context"
	"errors"
	"testing"
	"time"
)

// pgPromoteNonce fetches the current PromoteAttemptNonce for sess.ID.  Call after SetPromoteToken
// to thread the minted nonce into SetPromoteResult.
func pgPromoteNonce(t *testing.T, store *PgAttendedStore, ctx context.Context, tid, sessID string) string {
	t.Helper()
	got, err := store.Get(ctx, tid, sessID)
	if err != nil {
		t.Fatalf("pgPromoteNonce Get: %v", err)
	}
	return got.PromoteAttemptNonce
}

func TestPgPromoteResultSuccessRoundtrip(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool) // 0008
	applyDeviceIdentityMigration(t, pool)      // 0010
	applyAttendedMigration(t, pool)            // 0013 + 0036 + 0042 + 0052
	tid, uid := provisionUser(t, pool, "pr-success", "tech-pr@success.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "promote success test"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-success"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)

	if err := store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{
		Success: true,
		At:      time.Now(),
	}); err != nil {
		t.Fatalf("SetPromoteResult success: %v", err)
	}

	got, err := store.Get(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PromoteResult == nil {
		t.Fatal("promote_result is nil after SetPromoteResult success")
	}
	if !got.PromoteResult.Success {
		t.Errorf("promote_result.success = false, want true")
	}
	if got.PromoteResult.Error != "" {
		t.Errorf("promote_result.error = %q, want empty", got.PromoteResult.Error)
	}
	if got.PromoteResult.At.IsZero() {
		t.Error("promote_result.at is zero")
	}
}

func TestPgPromoteResultFailureRoundtrip(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-failure", "tech-pr@failure.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-FAIL-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-failure"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)

	const errMsg = "installer exited with code 1"
	if err := store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{
		Success: false,
		Error:   errMsg,
		At:      time.Now(),
	}); err != nil {
		t.Fatalf("SetPromoteResult failure: %v", err)
	}

	got, err := store.Get(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PromoteResult == nil {
		t.Fatal("promote_result is nil after failure SetPromoteResult")
	}
	if got.PromoteResult.Success {
		t.Error("promote_result.success = true, want false")
	}
	if got.PromoteResult.Error != errMsg {
		t.Errorf("promote_result.error = %q, want %q", got.PromoteResult.Error, errMsg)
	}
}

func TestPgPromoteResultInvalidTokenReturnsInvalidError(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	// A token with no matching row simulates a revoked or expired bearer.
	fakeToken := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	err := store.SetPromoteResult(ctx, fakeToken, "", PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedInvalid) {
		t.Errorf("revoked/expired token: err = %v, want ErrAttendedInvalid", err)
	}
}

func TestPgPromoteResultConflictWhenSessionNotYetConsented(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-conflict", "tech-pr@conflict.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	// Create + redeem only (state = "redeemed") — no consent, so no promote was ever requested.
	sess := &AttendedSession{GroupID: gid, TechnicianID: uid}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-CONFLICT-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	err = store.SetPromoteResult(ctx, res.AttendToken, "", PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("redeemed (not consented) session: err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
}

func TestPgPromoteResultConflictWhenNoPromoteRequested(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-nopromote", "tech-pr@nopromote.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	// Create + redeem + consent — but no SetPromoteToken, so promote_requested_at IS NULL.
	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "no promote requested"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-NOPROMOTE-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}

	// Consented but promote_requested_at IS NULL → conflict.
	err = store.SetPromoteResult(ctx, res.AttendToken, "", PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("consented session with no promote token: err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
}

func TestPgPromoteResultAcceptedAfterSessionEnded(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-ended", "tech-pr@ended.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "ended before result"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-ENDED-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	// Stash promote token → stamps promote_requested_at and mints nonce.
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-ended"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)
	// End the session — clears promote_token but NOT promote_requested_at.
	if _, err := store.End(ctx, tid, sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}

	// An install completing after session end is valid: promote_requested_at IS NOT NULL and
	// state='ended' is not in ('pending','redeemed'), so the SQL function returns TRUE.
	err = store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{Success: true, At: time.Now()})
	if err != nil {
		t.Errorf("SetPromoteResult after session end: err = %v, want nil", err)
	}
}

func TestPgPromoteResultNotOverwrittenBySecondCall(t *testing.T) {
	// First completion wins: cp_attended_set_promote_result returns FALSE (→ conflict) on a second
	// call for the same session, preventing a stale duplicate from overwriting the recorded result.
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-nooverwrite", "tech-pr@nooverwrite.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "no overwrite test"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-NOW-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-nooverwrite"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)
	// First completion: success.
	if err := store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{
		Success: true,
		At:      time.Now(),
	}); err != nil {
		t.Fatalf("first SetPromoteResult: %v", err)
	}
	// Second call: promote_result_at IS NOT NULL → conflict (first completion wins).
	// Nonce still matches; the no-overwrite guard fires first.
	err = store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{
		Success: false,
		Error:   "stale retry",
		At:      time.Now(),
	})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("second SetPromoteResult: err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
	// GET must still show the first (success) result.
	got, err := store.Get(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PromoteResult == nil || !got.PromoteResult.Success {
		t.Errorf("promote_result.success = false after overwrite attempt — first result was not preserved")
	}
}

func TestPgPromoteResultClearedOnNewToken(t *testing.T) {
	// When the technician reissues a promote request (SetPromoteToken with a non-empty token),
	// the prior result columns are cleared so the new attempt's outcome is not masked by the old one.
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-clearretry", "tech-pr@clearretry.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-CLR-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-attempt1"); err != nil {
		t.Fatalf("SetPromoteToken attempt1: %v", err)
	}
	nonce1 := pgPromoteNonce(t, store, ctx, tid, sess.ID)
	// First attempt fails.
	if err := store.SetPromoteResult(ctx, res.AttendToken, nonce1, PromoteResult{
		Success: false,
		Error:   "first attempt failed",
		At:      time.Now(),
	}); err != nil {
		t.Fatalf("SetPromoteResult failure: %v", err)
	}
	// Technician reissues promote — must clear the prior failure result and mint a new nonce.
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-attempt2"); err != nil {
		t.Fatalf("SetPromoteToken attempt2: %v", err)
	}
	nonce2 := pgPromoteNonce(t, store, ctx, tid, sess.ID)
	if nonce2 == nonce1 {
		t.Error("SetPromoteToken retry must mint a new nonce; got the same nonce as attempt1")
	}
	// Verify result was cleared.
	got, err := store.Get(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("Get after retry SetPromoteToken: %v", err)
	}
	if got.PromoteResult != nil {
		t.Errorf("promote_result must be nil after SetPromoteToken retry, got %+v", got.PromoteResult)
	}
	// Second attempt succeeds with the new nonce — the no-overwrite guard must not block it.
	if err := store.SetPromoteResult(ctx, res.AttendToken, nonce2, PromoteResult{
		Success: true,
		At:      time.Now(),
	}); err != nil {
		t.Fatalf("SetPromoteResult success after retry: %v", err)
	}
	got, err = store.Get(ctx, tid, sess.ID)
	if err != nil {
		t.Fatalf("Get after retry success: %v", err)
	}
	if got.PromoteResult == nil || !got.PromoteResult.Success {
		t.Errorf("promote_result.success must be true after retry; got %+v", got.PromoteResult)
	}
}

func TestPgPromoteResultRejectedAfterRevocation(t *testing.T) {
	// When the promote token is explicitly revoked (SetPromoteToken("")) promote_requested_at is
	// cleared, so a subsequent promote-complete from the guest is rejected.
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-revoke", "tech-pr@revoke.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-REV-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	// Stash token → stamps promote_requested_at.
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-to-revoke"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	// Explicitly revoke (empty token) → must clear promote_requested_at and nonce.
	if err := store.SetPromoteToken(ctx, tid, sess.ID, ""); err != nil {
		t.Fatalf("SetPromoteToken revoke: %v", err)
	}
	// Late promote-complete from guest must be rejected (promote_requested_at IS NULL).
	err = store.SetPromoteResult(ctx, res.AttendToken, "", PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("revoked promote: err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
}

func TestPgPromoteResultConflictWhenSessionPending(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-pending", "tech-pr@pending.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	// Use pool (not appPool) to seed a token_hash directly so we can call SetPromoteResult
	// on a "pending" session without going through redeem.
	sess := &AttendedSession{GroupID: gid, TechnicianID: uid}
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)
	if _, err := store.Create(ctx, tid, sess); err != nil {
		t.Fatalf("create: %v", err)
	}
	// State is "pending" (not yet redeemed, so no token_hash in the row).
	// SetPromoteResult with any token against a pending session → NULL return (token not found
	// because token_hash IS NULL for pending rows). Correctly maps to ErrAttendedInvalid, since
	// the function's FOR UPDATE on token_hash = p_hash finds nothing.
	fakeToken := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	err := store.SetPromoteResult(ctx, fakeToken, "", PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedInvalid) {
		t.Errorf("pending session via fake token: err = %v, want ErrAttendedInvalid", err)
	}
}

func TestPgPromoteResultConflictOnNonceMismatch(t *testing.T) {
	// A guest sending the wrong nonce (e.g. a delayed old attempt) must be rejected even if all
	// other guards (state, promote_requested_at, no-overwrite, age) would pass.
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-noncemismatch", "tech-pr@noncemismatch.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "nonce mismatch test"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-NM-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-nonce"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	// Deliberately send the wrong nonce — simulates a delayed old attempt carrying stale state.
	err = store.SetPromoteResult(ctx, res.AttendToken, "0000000000000000000000000000000000000000000000000000000000000000", PromoteResult{
		Success: true,
		At:      time.Now(),
	})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("nonce mismatch: err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
	// Correct nonce must still work (the wrong nonce did not consume the slot).
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)
	if err := store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{
		Success: true,
		At:      time.Now(),
	}); err != nil {
		t.Errorf("correct nonce after mismatch rejection: %v", err)
	}
}

func TestPgPromoteResultConflictWhenAttemptStale(t *testing.T) {
	// An active session whose promote_requested_at is older than 24 hours must reject a result.
	// Simulated by backdating the column via the superuser pool after SetPromoteToken.
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-stale", "tech-pr@stale.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "stale attempt test"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-STALE-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-stale"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)

	// Backdate promote_requested_at to 25 hours ago using the superuser pool (bypasses RLS).
	if _, err := pool.Exec(ctx,
		`UPDATE attended_session SET promote_requested_at = now() - INTERVAL '25 hours' WHERE id = $1`,
		sess.ID); err != nil {
		t.Fatalf("backdate promote_requested_at: %v", err)
	}

	// Session is active (not ended), promote_requested_at > 24h ago → rejected.
	err = store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("stale attempt (25h): err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
}

func TestPgPromoteResultConflictAfterGraceExpiry(t *testing.T) {
	// An ended session whose ended_at is older than 30 minutes must reject a promote result.
	// This tests guard 4 in cp_attended_set_promote_result:
	//   state='ended' AND now() > ended_at + 30 minutes → FALSE
	// The within-grace case is covered by TestPgPromoteResultAcceptedAfterSessionEnded.
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "pr-grace-expired", "tech-pr@grace-expired.test", "p4ssword")
	gid := seedGroup(t, pool, tid)
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgAttendedStore(appPool)

	sess := &AttendedSession{GroupID: gid, TechnicianID: uid, Reason: "grace expiry test"}
	code, err := store.Create(ctx, tid, sess)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := store.Redeem(ctx, code, attendTestPubkey, "PR-GRACE-PC")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := store.Consent(ctx, res.AttendToken, true, "guest-user"); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if err := store.SetPromoteToken(ctx, tid, sess.ID, "tok-grace"); err != nil {
		t.Fatalf("SetPromoteToken: %v", err)
	}
	nonce := pgPromoteNonce(t, store, ctx, tid, sess.ID)
	// End the session — sets ended_at = now(), preserves promote_requested_at.
	if _, err := store.End(ctx, tid, sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}

	// Backdate ended_at to 31 minutes ago using the superuser pool (bypasses RLS).
	if _, err := pool.Exec(ctx,
		`UPDATE attended_session SET ended_at = now() - INTERVAL '31 minutes' WHERE id = $1`,
		sess.ID); err != nil {
		t.Fatalf("backdate ended_at: %v", err)
	}

	// Ended session with ended_at > 30 min ago → grace window closed → conflict.
	err = store.SetPromoteResult(ctx, res.AttendToken, nonce, PromoteResult{Success: true, At: time.Now()})
	if !errors.Is(err, ErrAttendedPromoteCompleteConflict) {
		t.Errorf("expired grace (31m after end): err = %v, want ErrAttendedPromoteCompleteConflict", err)
	}
}
