package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Stores run as rmt_app; the superuser connection only seeds and inspects persisted state.
// Aging rows in SQL makes expiration tests independent of sleeps and application clocks.
type oidcFixture struct {
	ctx                  context.Context
	su, app              *pgxpool.Pool
	store                *PgOIDCStore
	cipher               *TOTPCipher
	tenant, user, origin string
	write                OIDCConnectionWrite
	a                    OIDCIdentityAuthority
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	f := &oidcFixture{ctx: context.Background(), su: newTestPool(t)}
	applyAppRoleMigration(t, f.su)
	applyTenantProvisionMigration(t, f.su)
	applyMigrationFile(t, f.su, "migrations/0054_mfa_generation.sql")
	applyMigrationFile(t, f.su, "migrations/0056_toolbox.sql")
	applyMigrationFile(t, f.su, "migrations/0057_oidc_sso.sql")
	applyMigrationFile(t, f.su, "migrations/0080_oidc_remember.sql") // the remember choice on the attempt
	f.tenant, f.user = provisionUser(t, f.su, "acme", "owner@acme.test", "password-1234")
	f.app = newAppRolePool(t, f.ctx)
	var err error
	f.cipher, err = NewTOTPCipher(strings.Repeat("12", 32))
	if err != nil {
		t.Fatal(err)
	}
	f.store = NewPgOIDCStore(f.app, f.cipher)
	secret := "OIDC-client-secret-do-not-return"
	f.write = OIDCConnectionWrite{Profile: "entra", EntraTenantID: "11111111-1111-4111-8111-111111111111", ClientID: "22222222-2222-4222-8222-222222222222", Enabled: true, ClientSecret: &secret, UpdatedBy: &f.user}
	c, err := f.store.PutConnection(f.ctx, f.tenant, f.write)
	if err != nil {
		t.Fatal(err)
	}
	f.a = OIDCIdentityAuthority{TenantID: f.tenant, UserID: f.user, Issuer: "https://login.microsoftonline.com/" + f.write.EntraTenantID + "/v2.0", Subject: "subject-owner", ConnectionVersion: c.Version}
	if err := f.su.QueryRow(f.ctx, `SELECT updated_at FROM user_credential WHERE user_id=$1`, f.user).Scan(&f.a.EpochBaseline); err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.su, `UPDATE app_user SET mfa_generation=42 WHERE id=$1`, f.user)
	if err := f.su.QueryRow(f.ctx, `INSERT INTO user_session (tenant_id,user_id,token_hash,expires_at,credential_epoch,mfa_verified_at,mfa_generation)
		VALUES ($1,$2,$3,clock_timestamp()+interval '1 hour',$4,clock_timestamp(),42) RETURNING id::text`, f.tenant, f.user, HashToken("origin"), f.a.EpochBaseline).Scan(&f.origin); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPgOIDCCreateAttemptOrigin(t *testing.T) {
	for _, mode := range []string{"link", "test"} {
		for _, name := range []string{"success", "revoked", "expired", "other-user", "stale", "generation", "epoch", "disabled", "user-disabled"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				f := newOIDCFixture(t)
				a := &OIDCAttempt{TenantID: f.tenant, KeyHash: HashToken("start-key"), StateHash: HashToken("start-state"), Nonce: "nonce", CodeVerifier: "verifier", Mode: mode, UserID: &f.user, SessionID: &f.origin, EpochBaseline: f.a.EpochBaseline, ConnectionVersion: f.a.ConnectionVersion, Profile: "entra", RedirectURI: "https://acme.deskrally.com/cp/auth/oidc/callback", ReturnPath: "/console"}
				var want error
				switch name {
				case "revoked":
					mustExec(t, f.su, `UPDATE user_session SET revoked_at=clock_timestamp() WHERE id=$1`, f.origin)
					want = ErrOIDCSessionInvalid
				case "expired":
					mustExec(t, f.su, `UPDATE user_session SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.origin)
					want = ErrOIDCSessionInvalid
				case "other-user":
					var other string
					if err := f.su.QueryRow(f.ctx, `INSERT INTO app_user (tenant_id,email) VALUES ($1,'other@acme.test') RETURNING id::text`, f.tenant).Scan(&other); err != nil {
						t.Fatal(err)
					}
					mustExec(t, f.su, `UPDATE user_session SET user_id=$2 WHERE id=$1`, f.origin, other)
					want = ErrOIDCSessionInvalid
				case "stale":
					mustExec(t, f.su, `UPDATE user_session SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE id=$1`, f.origin)
					want = ErrOIDCStepUpStale
				case "generation":
					mustExec(t, f.su, `UPDATE user_session SET mfa_generation=41 WHERE id=$1`, f.origin)
					want = ErrOIDCStepUpStale
				case "epoch":
					a.EpochBaseline = a.EpochBaseline.Add(-time.Second)
					want = ErrOIDCEpoch
				case "disabled":
					mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=false WHERE tenant_id=$1`, f.tenant)
					want = ErrOIDCDisabled
				case "user-disabled":
					mustExec(t, f.su, `UPDATE app_user SET disabled_at=clock_timestamp() WHERE id=$1`, f.user)
					want = ErrOIDCUserDisabled
				}
				oidcWantError(t, f.store.CreateAttempt(f.ctx, a), want)
				var count int
				if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM oidc_login_attempt WHERE tenant_id=$1`, f.tenant).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if (count == 1) != (want == nil) {
					t.Fatalf("attempt count=%d, want error=%v", count, want)
				}
			})
		}
	}
}

func oidcWantError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func (f *oidcFixture) link(t *testing.T) {
	t.Helper()
	if err := f.store.LinkIdentity(f.ctx, f.a, f.origin); err != nil {
		t.Fatal(err)
	}
}

func (f *oidcFixture) attempt(t *testing.T, name string) *OIDCAttempt {
	t.Helper()
	a := &OIDCAttempt{TenantID: f.tenant, KeyHash: HashToken("key-" + name), StateHash: HashToken("state-" + name), Nonce: "nonce-" + name, CodeVerifier: "verifier-" + name, Mode: "login", ConnectionVersion: f.a.ConnectionVersion, Profile: "entra", RedirectURI: "https://acme.deskrally.com/cp/auth/oidc/callback", ReturnPath: "/console"}
	if err := f.store.CreateAttempt(f.ctx, a); err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *oidcFixture) pending(t *testing.T, name string) *OIDCPendingMFA {
	t.Helper()
	a := f.attempt(t, name)
	if _, err := f.store.ConsumeAttempt(f.ctx, f.tenant, a.StateHash, a.KeyHash); err != nil {
		t.Fatal(err)
	}
	p := &OIDCPendingMFA{TenantID: f.tenant, UserID: f.user, AttemptID: a.ID, Issuer: f.a.Issuer, Subject: f.a.Subject, EpochBaseline: f.a.EpochBaseline, ConnectionVersion: f.a.ConnectionVersion}
	if err := f.store.CreatePendingMFA(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *oidcFixture) issue(t *testing.T) *Session {
	t.Helper()
	token, s, err := f.store.IssueOIDCSession(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || s == nil || s.ID == "" || !bytes.Equal(HashToken(token), s.TokenHash) {
		t.Fatalf("invalid issued session: %+v", s)
	}
	stored, err := NewPgSessionStore(f.app).GetByTokenHash(f.ctx, HashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != s.ID || !stored.CredentialEpoch.Equal(f.a.EpochBaseline) || stored.RevokedAt != nil {
		t.Fatalf("persisted session = %+v", stored)
	}
	var method string
	var version int64
	if err := f.su.QueryRow(f.ctx, `SELECT login_method,oidc_connection_version FROM user_session WHERE id=$1`, s.ID).Scan(&method, &version); err != nil {
		t.Fatal(err)
	}
	if method != "oidc" || version != f.a.ConnectionVersion || s.ExpiresAt.Sub(s.CreatedAt) != DefaultSessionTTL || !s.LastSeen.Equal(s.CreatedAt) {
		t.Fatalf("session metadata = %s/%d %+v", method, version, s)
	}
	return s
}

func (f *oidcFixture) revoked(t *testing.T, id string, want bool) {
	t.Helper()
	var got bool
	if err := f.su.QueryRow(f.ctx, `SELECT revoked_at IS NOT NULL FROM user_session WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("session %s revoked=%v, want %v", id, got, want)
	}
}

func (f *oidcFixture) identity(t *testing.T, want bool) {
	t.Helper()
	var issuer, subject *string
	if err := f.su.QueryRow(f.ctx, `SELECT oidc_issuer,oidc_subject FROM app_user WHERE id=$1`, f.user).Scan(&issuer, &subject); err != nil {
		t.Fatal(err)
	}
	if want {
		if issuer == nil || subject == nil || *issuer != f.a.Issuer || *subject != f.a.Subject {
			t.Fatalf("link = %v/%v", issuer, subject)
		}
	} else if issuer != nil || subject != nil {
		t.Fatal("identity was not cleared")
	}
}

func TestPgOIDCConnection(t *testing.T) {
	for _, change := range []string{"secret", "disable", "client", "tenant"} {
		t.Run(change, func(t *testing.T) {
			f := newOIDCFixture(t)
			f.link(t)
			s := f.issue(t)
			f.pending(t, "pending")
			f.attempt(t, "live")
			if err := f.store.RecordTest(f.ctx, f.a, f.origin); err != nil {
				t.Fatal(err)
			}
			c, err := f.store.GetConnection(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if c.Version != 1 || !c.HasSecret || c.LastTestVersion == nil || *c.LastTestVersion != 1 || c.LastTestAt == nil {
				t.Fatalf("connection = %+v", c)
			}
			// Pin the public representation as well as its serialization: a new secret field
			// must not silently turn a settings read into credential disclosure.
			typ := reflect.TypeOf(*c)
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i).Name
				if strings.Contains(strings.ToLower(field), "secret") && field != "HasSecret" {
					t.Fatalf("secret-bearing public field %s", field)
				}
			}
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(b, []byte(*f.write.ClientSecret)) {
				t.Fatal("GET exposed secret")
			}
			var before []byte
			if err := f.su.QueryRow(f.ctx, `SELECT client_secret_enc FROM tenant_oidc WHERE tenant_id=$1`, f.tenant).Scan(&before); err != nil {
				t.Fatal(err)
			}
			plain, encrypted, err := f.cipher.Open(before)
			if err != nil || !encrypted || plain != *f.write.ClientSecret {
				t.Fatalf("secret encryption: encrypted=%v err=%v", encrypted, err)
			}
			w := f.write
			w.ClientSecret = nil
			switch change {
			case "secret":
				secret := "replacement-secret"
				w.ClientSecret = &secret
			case "disable":
				w.Enabled = false
			case "client":
				w.ClientID = "33333333-3333-4333-8333-333333333333"
			case "tenant":
				w.EntraTenantID = "44444444-4444-4444-8444-444444444444"
			}
			c, err = f.store.PutConnection(f.ctx, f.tenant, w)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.store.GetConnection(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c, got) || c.Version != 2 || c.Enabled != w.Enabled || c.ClientID != w.ClientID || c.EntraTenantID != w.EntraTenantID || c.LastTestAt != nil || c.LastTestVersion != nil {
				t.Fatalf("updated connection = %+v / %+v", c, got)
			}
			var after []byte
			if err := f.su.QueryRow(f.ctx, `SELECT client_secret_enc FROM tenant_oidc WHERE tenant_id=$1`, f.tenant).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if w.ClientSecret == nil && !bytes.Equal(before, after) {
				t.Fatal("nil secret changed ciphertext")
			}
			if w.ClientSecret != nil {
				plain, encrypted, err = f.cipher.Open(after)
				if err != nil || !encrypted || plain != *w.ClientSecret || bytes.Equal(before, after) {
					t.Fatal("replacement secret was not encrypted")
				}
			}
			f.identity(t, change != "client" && change != "tenant")
			f.revoked(t, s.ID, true)
			f.revoked(t, f.origin, false)
			for _, table := range []string{"oidc_login_attempt", "oidc_pending_mfa"} {
				var n int
				if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, f.tenant).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Fatalf("%s retains %d rows", table, n)
				}
			}
			c, err = f.store.PutConnection(f.ctx, f.tenant, w)
			if err != nil || c.Version != 3 {
				t.Fatalf("subsequent version: %+v, %v", c, err)
			}
		})
	}
}

func TestPgOIDCAttemptLifecycle(t *testing.T) {
	f := newOIDCFixture(t)
	a := f.attempt(t, "single")
	var sealed []byte
	if err := f.su.QueryRow(f.ctx, `SELECT code_verifier_enc FROM oidc_login_attempt WHERE id=$1`, a.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	plain, encrypted, err := f.cipher.Open(sealed)
	if err != nil || !encrypted || plain != a.CodeVerifier || bytes.Equal(sealed, []byte(a.CodeVerifier)) {
		t.Fatal("verifier was not encrypted")
	}
	_, err = f.store.ConsumeAttempt(f.ctx, f.tenant, a.StateHash, HashToken("wrong"))
	oidcWantError(t, err, ErrOIDCAttemptNotFound)
	got, err := f.store.ConsumeAttempt(f.ctx, f.tenant, a.StateHash, a.KeyHash)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != a.ID || got.CodeVerifier != a.CodeVerifier || got.Nonce != a.Nonce || got.UsedAt == nil || got.ConnectionVersion != a.ConnectionVersion || got.ReturnPath != a.ReturnPath || got.RedirectURI != a.RedirectURI || got.Mode != "login" || got.Profile != "entra" {
		t.Fatalf("consumed = %+v", got)
	}
	_, err = f.store.ConsumeAttempt(f.ctx, f.tenant, a.StateHash, a.KeyHash)
	oidcWantError(t, err, ErrOIDCAttemptUsed)
	expired := f.attempt(t, "expired")
	mustExec(t, f.su, `UPDATE oidc_login_attempt SET created_at=clock_timestamp()-interval '11 minutes' WHERE id=$1`, expired.ID)
	_, err = f.store.ConsumeAttempt(f.ctx, f.tenant, expired.StateHash, expired.KeyHash)
	oidcWantError(t, err, ErrOIDCAttemptExpired)
	f.attempt(t, "live")
	n, err := f.store.CountLiveAttempts(f.ctx, f.tenant)
	if err != nil || n != 1 {
		t.Fatalf("live count=%d, %v", n, err)
	}
	_, err = f.store.ConsumeAttempt(f.ctx, f.tenant, HashToken("missing"), a.KeyHash)
	oidcWantError(t, err, ErrOIDCAttemptNotFound)
	if err := f.store.SweepExpired(f.ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	_, err = f.store.ConsumeAttempt(f.ctx, f.tenant, expired.StateHash, expired.KeyHash)
	oidcWantError(t, err, ErrOIDCAttemptNotFound)
}

func TestPgOIDCPendingMFALifecycle(t *testing.T) {
	f := newOIDCFixture(t)
	p := f.pending(t, "single")
	duplicate := *p
	oidcWantError(t, f.store.CreatePendingMFA(f.ctx, &duplicate), ErrOIDCAttemptUsed)
	got, err := f.store.ConsumePendingMFA(f.ctx, f.tenant, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != p.ID || got.UserID != p.UserID || got.AttemptID != p.AttemptID || got.Issuer != p.Issuer || got.Subject != p.Subject || got.ConnectionVersion != p.ConnectionVersion || !got.EpochBaseline.Equal(p.EpochBaseline) || got.UsedAt == nil {
		t.Fatalf("pending = %+v", got)
	}
	_, err = f.store.ConsumePendingMFA(f.ctx, f.tenant, p.ID)
	oidcWantError(t, err, ErrOIDCAttemptUsed)
	expired := f.pending(t, "expired")
	mustExec(t, f.su, `UPDATE oidc_pending_mfa SET created_at=clock_timestamp()-interval '6 minutes' WHERE id=$1`, expired.ID)
	_, err = f.store.ConsumePendingMFA(f.ctx, f.tenant, expired.ID)
	oidcWantError(t, err, ErrOIDCAttemptExpired)
	unconsumed := f.attempt(t, "unconsumed")
	bad := *p
	bad.AttemptID = unconsumed.ID
	oidcWantError(t, f.store.CreatePendingMFA(f.ctx, &bad), ErrOIDCAttemptNotFound)
	// A callback baseline must survive the MFA round trip unchanged, even if a password
	// changes while the second-factor page is open.
	f.link(t)
	stale := f.pending(t, "stale-epoch")
	mustExec(t, f.su, `UPDATE user_credential SET updated_at=updated_at+interval '1 second' WHERE user_id=$1`, f.user)
	got, err = f.store.ConsumePendingMFA(f.ctx, f.tenant, stale.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := f.a
	a.EpochBaseline = got.EpochBaseline
	_, _, err = f.store.IssueOIDCSession(f.ctx, a)
	oidcWantError(t, err, ErrOIDCEpoch)
	if err := f.store.SweepExpired(f.ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	_, err = f.store.ConsumePendingMFA(f.ctx, f.tenant, expired.ID)
	oidcWantError(t, err, ErrOIDCAttemptNotFound)
}

func TestPgOIDCIssueSession(t *testing.T) {
	for _, name := range []string{"happy", "absent-credential", "invalid", "absent-connection", "disabled", "version", "tenant-disabled", "user-disabled", "user-absent", "unlinked", "issuer", "subject", "epoch", "zero-epoch"} {
		t.Run(name, func(t *testing.T) {
			f := newOIDCFixture(t)
			f.link(t)
			a := f.a
			var want error
			switch name {
			case "absent-credential":
				mustExec(t, f.su, `DELETE FROM user_credential WHERE user_id=$1`, f.user)
				a.EpochBaseline = time.Time{}
			case "invalid":
				a.Subject = ""
				want = ErrOIDCInvalid
			case "absent-connection":
				mustExec(t, f.su, `DELETE FROM tenant_oidc WHERE tenant_id=$1`, f.tenant)
				want = ErrOIDCDisabled
			case "disabled":
				mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=false WHERE tenant_id=$1`, f.tenant)
				want = ErrOIDCDisabled
			case "version":
				a.ConnectionVersion++
				want = ErrOIDCVersion
			case "tenant-disabled":
				mustExec(t, f.su, `UPDATE tenant SET disabled_at=clock_timestamp() WHERE id=$1`, f.tenant)
				want = ErrOIDCTenantDisabled
			case "user-disabled":
				mustExec(t, f.su, `UPDATE app_user SET disabled_at=clock_timestamp() WHERE id=$1`, f.user)
				want = ErrOIDCUserDisabled
			case "user-absent":
				a.UserID = "55555555-5555-4555-8555-555555555555"
				want = ErrOIDCUserDisabled
			case "unlinked":
				mustExec(t, f.su, `UPDATE app_user SET oidc_issuer=NULL,oidc_subject=NULL WHERE id=$1`, f.user)
				want = ErrOIDCNotLinked
			case "issuer":
				a.Issuer += "/wrong"
				want = ErrOIDCNotLinked
			case "subject":
				a.Subject += "wrong"
				want = ErrOIDCNotLinked
			case "epoch":
				a.EpochBaseline = a.EpochBaseline.Add(time.Second)
				want = ErrOIDCEpoch
			case "zero-epoch":
				a.EpochBaseline = time.Time{}
				want = ErrOIDCEpoch
			}
			if want == nil {
				f.a = a
				f.issue(t)
				return
			}
			token, sess, err := f.store.IssueOIDCSession(f.ctx, a)
			oidcWantError(t, err, want)
			if token != "" || sess != nil {
				t.Fatal("refusal returned session authority")
			}
			var n int
			if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session WHERE tenant_id=$1 AND login_method='oidc'`, f.tenant).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatal("refusal persisted a session")
			}
		})
	}
}

func TestPgOIDCLinkIdentity(t *testing.T) {
	for _, name := range []string{"happy", "same", "different", "unique", "stale", "future", "unverified", "generation", "revoked", "expired", "missing", "wrong-owner", "session-epoch", "epoch", "disabled", "version", "user-disabled"} {
		t.Run(name, func(t *testing.T) {
			f := newOIDCFixture(t)
			a, origin := f.a, f.origin
			var want error
			switch name {
			case "same":
				f.link(t)
			case "different":
				f.link(t)
				a.Subject = "replacement"
				want = ErrOIDCLinkConflict
			case "unique":
				mustExec(t, f.su, `INSERT INTO app_user (tenant_id,email,oidc_issuer,oidc_subject) VALUES ($1,'other@acme.test',$2,$3)`, f.tenant, a.Issuer, a.Subject)
				want = ErrOIDCLinkConflict
			case "stale":
				mustExec(t, f.su, `UPDATE user_session SET mfa_verified_at=clock_timestamp()-interval '11 minutes' WHERE id=$1`, origin)
				want = ErrOIDCStepUpStale
			case "future":
				mustExec(t, f.su, `UPDATE user_session SET mfa_verified_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, origin)
				want = ErrOIDCStepUpStale
			case "unverified":
				mustExec(t, f.su, `UPDATE user_session SET mfa_verified_at=NULL WHERE id=$1`, origin)
				want = ErrOIDCStepUpStale
			case "generation":
				mustExec(t, f.su, `UPDATE user_session SET mfa_generation=41 WHERE id=$1`, origin)
				want = ErrOIDCStepUpStale
			case "revoked":
				mustExec(t, f.su, `UPDATE user_session SET revoked_at=clock_timestamp() WHERE id=$1`, origin)
				want = ErrOIDCSessionInvalid
			case "expired":
				mustExec(t, f.su, `UPDATE user_session SET expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`, origin)
				want = ErrOIDCSessionInvalid
			case "missing":
				origin = "55555555-5555-4555-8555-555555555555"
				want = ErrOIDCSessionInvalid
			case "wrong-owner":
				var other string
				if err := f.su.QueryRow(f.ctx, `INSERT INTO app_user (tenant_id,email) VALUES ($1,'other@acme.test') RETURNING id::text`, f.tenant).Scan(&other); err != nil {
					t.Fatal(err)
				}
				mustExec(t, f.su, `UPDATE user_session SET user_id=$2 WHERE id=$1`, origin, other)
				want = ErrOIDCSessionInvalid
			case "session-epoch":
				mustExec(t, f.su, `UPDATE user_session SET credential_epoch=NULL WHERE id=$1`, origin)
				want = ErrOIDCSessionInvalid
			case "epoch":
				a.EpochBaseline = a.EpochBaseline.Add(time.Second)
				want = ErrOIDCEpoch
			case "disabled":
				mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=false WHERE tenant_id=$1`, f.tenant)
				want = ErrOIDCDisabled
			case "version":
				a.ConnectionVersion++
				want = ErrOIDCVersion
			case "user-disabled":
				mustExec(t, f.su, `UPDATE app_user SET disabled_at=clock_timestamp() WHERE id=$1`, f.user)
				want = ErrOIDCUserDisabled
			}
			oidcWantError(t, f.store.LinkIdentity(f.ctx, a, origin), want)
			f.identity(t, want == nil || name == "different")
			var n int
			if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session WHERE tenant_id=$1 AND login_method='oidc'`, f.tenant).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatal("link issued a session")
			}
		})
	}
}

func TestPgOIDCUnlink(t *testing.T) {
	f := newOIDCFixture(t)
	f.link(t)
	first, second := f.issue(t), f.issue(t)
	// Recovery must remain possible after the provider has been disabled.
	mustExec(t, f.su, `UPDATE tenant_oidc SET enabled=false WHERE tenant_id=$1`, f.tenant)
	if err := f.store.UnlinkIdentity(f.ctx, f.tenant, f.user); err != nil {
		t.Fatal(err)
	}
	f.identity(t, false)
	f.revoked(t, first.ID, true)
	f.revoked(t, second.ID, true)
	f.revoked(t, f.origin, false)
	if err := f.store.UnlinkIdentity(f.ctx, f.tenant, f.user); err != nil {
		t.Fatal(err)
	}
}

func TestPgOIDCTenantIsolation(t *testing.T) {
	f := newOIDCFixture(t)
	other, alien := provisionUser(t, f.su, "other", "owner@other.test", "password-1234")
	w := f.write
	w.UpdatedBy = &alien
	if _, err := f.store.PutConnection(f.ctx, other, w); err != nil {
		t.Fatal(err)
	}
	a := f.attempt(t, "private")
	p := f.pending(t, "private-mfa")
	_, err := f.store.ConsumeAttempt(f.ctx, other, a.StateHash, a.KeyHash)
	oidcWantError(t, err, ErrOIDCAttemptNotFound)
	_, err = f.store.ConsumePendingMFA(f.ctx, other, p.ID)
	oidcWantError(t, err, ErrOIDCAttemptNotFound)
	n, err := f.store.CountLiveAttempts(f.ctx, other)
	if err != nil || n != 0 {
		t.Fatalf("other tenant live count=%d: %v", n, err)
	}
	cross := f.a
	cross.TenantID = other
	_, _, err = f.store.IssueOIDCSession(f.ctx, cross)
	oidcWantError(t, err, ErrOIDCUserDisabled)
	oidcWantError(t, f.store.LinkIdentity(f.ctx, cross, f.origin), ErrOIDCUserDisabled)
	oidcWantError(t, f.store.UnlinkIdentity(f.ctx, other, f.user), ErrOIDCUserDisabled)
	if _, err := f.store.ConsumeAttempt(f.ctx, f.tenant, a.StateHash, a.KeyHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ConsumePendingMFA(f.ctx, f.tenant, p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPgOIDCRecordTest(t *testing.T) {
	f := newOIDCFixture(t)
	if err := f.store.RecordTest(f.ctx, f.a, f.origin); err != nil {
		t.Fatal(err)
	}
	f.identity(t, false)
	var n int
	if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session WHERE tenant_id=$1`, f.tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("test completion created session: count=%d", n)
	}
	for _, name := range []string{"version", "epoch", "revoked"} {
		t.Run(name, func(t *testing.T) {
			a := f.a
			want := ErrOIDCVersion
			switch name {
			case "version":
				a.ConnectionVersion++
			case "epoch":
				a.EpochBaseline = a.EpochBaseline.Add(time.Second)
				want = ErrOIDCEpoch
			case "revoked":
				mustExec(t, f.su, `UPDATE user_session SET revoked_at=clock_timestamp() WHERE id=$1`, f.origin)
				want = ErrOIDCSessionInvalid
			}
			before, err := f.store.GetConnection(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			oidcWantError(t, f.store.RecordTest(f.ctx, a, f.origin), want)
			after, err := f.store.GetConnection(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("refused test changed connection")
			}
		})
	}
}

func TestPgOIDCInvalidAttemptInput(t *testing.T) {
	f := newOIDCFixture(t)
	base := f.attempt(t, "base")
	for i, path := range []string{"https://evil.test/", "//evil.test/", "/\\evil", "/bad\npath"} {
		a := *base
		a.StateHash = HashToken(fmt.Sprint(i))
		a.ReturnPath = path
		oidcWantError(t, f.store.CreateAttempt(f.ctx, &a), ErrOIDCInvalid)
	}
}

// The settings change re-validates its ORIGINATING session inside the mutation transaction (Codex impl
// review B v1): a request that passed its step-up and then waited on the connection lock must not
// commit if, during the wait, its session was revoked or its step-up aged past 5 minutes.
func TestPgOIDCPutConnectionRevalidatesAuthorityAfterLockWait(t *testing.T) {
	for _, change := range []struct{ name, sql string }{
		{"revoked", `UPDATE user_session SET revoked_at=clock_timestamp() WHERE id=$1`},
		{"step-up expired", `UPDATE user_session SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE id=$1`},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := newOIDCFixture(t)
			before, err := f.store.GetConnection(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			// Hold the connection row so PutConnection blocks on its FOR UPDATE.
			holder, err := f.su.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = holder.Rollback(f.ctx) }()
			var blocker int32
			if err := holder.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
				t.Fatal(err)
			}
			if _, err := holder.Exec(f.ctx, `SELECT 1 FROM tenant_oidc WHERE tenant_id=$1 FOR SHARE`, f.tenant); err != nil {
				t.Fatal(err)
			}
			write := f.write
			write.ClientSecret = nil
			write.Authority = &OIDCSettingsAuthority{UserID: f.user, SessionID: f.origin, EpochBaseline: f.a.EpochBaseline}
			done := make(chan error, 1)
			go func() { _, err := f.store.PutConnection(f.ctx, f.tenant, write); done <- err }()
			deadline := time.Now().Add(10 * time.Second)
			for {
				var waiting bool
				if err := f.su.QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("PutConnection never blocked on the connection lock")
				}
				time.Sleep(5 * time.Millisecond)
			}
			mustExec(t, f.su, change.sql, f.origin) // the authority goes stale DURING the wait
			if err := holder.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("settings change committed after its authority went stale")
			}
			after, err := f.store.GetConnection(f.ctx, f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != before.Version {
				t.Fatalf("version moved %d -> %d despite the refusal", before.Version, after.Version)
			}
		})
	}
}

// Freshness is re-checked LAST, after statements that can block (Codex impl review B v2): the bulk
// revocation of the tenant's OIDC sessions waits while another transaction holds one of those rows,
// and a step-up that was fresh when checked can expire during that wait.
func TestPgOIDCPutConnectionRechecksFreshnessBeforeCommit(t *testing.T) {
	f := newOIDCFixture(t)
	before, err := f.store.GetConnection(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	// A second, OIDC-issued session of the tenant for the bulk revocation to wait on.
	var other string
	if err := f.su.QueryRow(f.ctx, `INSERT INTO user_session (tenant_id,user_id,token_hash,expires_at,credential_epoch,login_method,oidc_connection_version)
		VALUES ($1,$2,$3,clock_timestamp()+interval '1 hour',$4,'oidc',$5) RETURNING id::text`,
		f.tenant, f.user, HashToken("other-oidc"), f.a.EpochBaseline, before.Version).Scan(&other); err != nil {
		t.Fatal(err)
	}
	// The originating step-up is fresh by one second when PutConnection first checks it.
	mustExec(t, f.su, `UPDATE user_session SET mfa_verified_at=clock_timestamp()-interval '4 minutes 59 seconds' WHERE id=$1`, f.origin)
	holder, err := f.su.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()
	var blocker int32
	if err := holder.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(f.ctx, `SELECT 1 FROM user_session WHERE id=$1 FOR UPDATE`, other); err != nil {
		t.Fatal(err)
	}
	write := f.write
	write.ClientSecret = nil
	write.Authority = &OIDCSettingsAuthority{UserID: f.user, SessionID: f.origin, EpochBaseline: f.a.EpochBaseline}
	done := make(chan error, 1)
	go func() { _, err := f.store.PutConnection(f.ctx, f.tenant, write); done <- err }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err := f.su.QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the bulk revocation never blocked on the held session row")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(2 * time.Second) // the step-up crosses 5 minutes while the mutation waits
	if err := holder.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("settings change committed after its step-up expired during a lock wait")
	}
	after, err := f.store.GetConnection(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != before.Version {
		t.Fatalf("version moved %d -> %d despite the refusal", before.Version, after.Version)
	}
}

// LinkIdentity re-checks its originating authority LAST (Codex impl review B v3): its UPDATE waits on
// the unique index while another transaction holds an uncommitted claim to the same identity, and the
// step-up can expire during that wait. When the other claim rolls back, the link must still be refused.
func TestPgOIDCLinkRechecksFreshnessAfterUniqueWait(t *testing.T) {
	f := newOIDCFixture(t)
	var rival string
	if err := f.su.QueryRow(f.ctx, `INSERT INTO app_user (tenant_id,email) VALUES ($1,'rival@acme.test') RETURNING id::text`, f.tenant).Scan(&rival); err != nil {
		t.Fatal(err)
	}
	// Fresh by one second when LinkIdentity first checks it (10-minute completion window).
	mustExec(t, f.su, `UPDATE user_session SET mfa_verified_at=clock_timestamp()-interval '9 minutes 59 seconds' WHERE id=$1`, f.origin)
	holder, err := f.su.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(f.ctx) }()
	var blocker int32
	if err := holder.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	// The rival's uncommitted claim to the SAME identity: our UPDATE must wait on the unique index.
	if _, err := holder.Exec(f.ctx, `UPDATE app_user SET oidc_issuer=$2,oidc_subject=$3 WHERE id=$1`, rival, f.a.Issuer, f.a.Subject); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.store.LinkIdentity(f.ctx, f.a, f.origin) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err := f.su.QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("LinkIdentity never blocked on the rival's uncommitted identity claim")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(2 * time.Second) // the step-up crosses 10 minutes while the link waits
	if err := holder.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("link committed after its step-up expired during the unique-index wait")
	}
	var issuer *string
	if err := f.su.QueryRow(f.ctx, `SELECT oidc_issuer FROM app_user WHERE id=$1`, f.user).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	if issuer != nil {
		t.Fatalf("identity was linked despite the refusal: %q", *issuer)
	}
}
