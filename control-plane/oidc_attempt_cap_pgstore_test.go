package controlplane

import "testing"

// Security audit 2026-10-18: at the 500-live-attempt cap a new Microsoft sign-in still starts; the
// OLDEST unfinished attempt is retired instead, so a flood cannot hold the tenant's SSO shut.
func TestPgOIDCAttemptCapRetiresTheOldestInsteadOfRefusing(t *testing.T) {
	f := newOIDCFixture(t)
	first := f.attempt(t, "first")
	// 499 more live attempts, created after `first`, filling the tenant to the cap.
	mustExec(t, f.su, `INSERT INTO oidc_login_attempt
	  (tenant_id,key_hash,state_hash,nonce,code_verifier_enc,mode,connection_version,profile,redirect_uri,return_path,created_at)
	  SELECT tenant_id, sha256(('k'||g)::bytea), sha256(('s'||g)::bytea), 'n'||g, code_verifier_enc, mode,
	         connection_version, profile, redirect_uri, return_path, created_at + make_interval(secs => g)
	    FROM oidc_login_attempt, generate_series(1,499) g WHERE id=$1`, first.ID)
	if n, err := f.store.CountLiveAttempts(f.ctx, f.tenant); err != nil || n != 500 {
		t.Fatalf("setup: live=%d err=%v, want 500", n, err)
	}

	f.attempt(t, "newest") // t.Fatal on ErrOIDCCap: the old behaviour

	if n, err := f.store.CountLiveAttempts(f.ctx, f.tenant); err != nil || n != 500 {
		t.Fatalf("live after the new start = %d err=%v, want 500 (bounded)", n, err)
	}
	_, err := f.store.ConsumeAttempt(f.ctx, f.tenant, first.StateHash, first.KeyHash)
	oidcWantError(t, err, ErrOIDCAttemptUsed)
}
