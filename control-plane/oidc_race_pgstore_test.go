package controlplane

// These tests stop the first operation inside its transaction, after its write has acquired
// the fencing locks. The second operation must demonstrably wait before the barrier opens.
// Observing pg_blocking_pids avoids treating goroutine scheduling or a sleep as an interleaving.
import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type oidcRaceFixture struct {
	ctx                  context.Context
	su, left, right      *pgxpool.Pool
	tenant, user, origin string
	a                    OIDCIdentityAuthority
	write                OIDCConnectionWrite
	cipher               *TOTPCipher
}

func oidcRacePool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	base := newAppRolePool(t, ctx)
	cfg := base.Config().Copy()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func oidcRaceNew(t *testing.T, credential, linked bool) *oidcRaceFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyMigrationFile(t, su, "migrations/0054_mfa_generation.sql")
	applyMigrationFile(t, su, "migrations/0056_toolbox.sql")
	applyMigrationFile(t, su, "migrations/0057_oidc_sso.sql")
	applyMigrationFile(t, su, "migrations/0080_oidc_remember.sql") // the remember choice on the attempt
	f := &oidcRaceFixture{ctx: ctx, su: su}
	f.tenant, f.user = provisionUser(t, su, "acme", "race@acme.test", "password-1234")
	f.left = oidcRacePool(t, ctx)
	f.right = oidcRacePool(t, ctx)
	var err error
	f.cipher, err = NewTOTPCipher("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatal(err)
	}
	secret := "race-client-secret"
	f.write = OIDCConnectionWrite{
		Profile: "entra", EntraTenantID: "11111111-1111-4111-8111-111111111111",
		ClientID: "22222222-2222-4222-8222-222222222222", Enabled: true, ClientSecret: &secret,
	}
	c, err := NewPgOIDCStore(f.left, f.cipher).PutConnection(ctx, f.tenant, f.write)
	if err != nil {
		t.Fatal(err)
	}
	f.a = OIDCIdentityAuthority{
		TenantID: f.tenant, UserID: f.user,
		Issuer:  "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
		Subject: "race-subject", ConnectionVersion: c.Version,
	}
	if credential {
		if err := su.QueryRow(ctx, `SELECT updated_at FROM user_credential WHERE user_id=$1`, f.user).Scan(&f.a.EpochBaseline); err != nil {
			t.Fatal(err)
		}
	} else {
		mustExec(t, su, `DELETE FROM user_credential WHERE user_id=$1`, f.user)
	}
	mustExec(t, su, `UPDATE app_user SET mfa_generation=7 WHERE id=$1`, f.user)
	if linked {
		mustExec(t, su, `UPDATE app_user SET oidc_issuer=$2,oidc_subject=$3 WHERE id=$1`, f.user, f.a.Issuer, f.a.Subject)
	}
	if err := su.QueryRow(ctx, `INSERT INTO user_session
		(tenant_id,user_id,token_hash,expires_at,credential_epoch,mfa_verified_at,mfa_generation)
		VALUES ($1,$2,$3,clock_timestamp()+interval '1 hour',$4,clock_timestamp(),7)
		RETURNING id::text`, f.tenant, f.user, HashToken("race-origin"), oidcRaceEpoch(f.a.EpochBaseline)).Scan(&f.origin); err != nil {
		t.Fatal(err)
	}
	return f
}

func oidcRaceEpoch(epoch time.Time) *time.Time {
	if epoch.IsZero() {
		return nil
	}
	return &epoch
}

func oidcRacePID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int32 {
	t.Helper()
	var pid int32
	if err := pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func oidcRaceWait(t *testing.T, f *oidcRaceFixture, waiter, blocker int32) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.su.QueryRow(f.ctx, `SELECT $2::int = ANY(pg_blocking_pids($1::int))`, waiter, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-f.ctx.Done():
			t.Fatalf("backend %d never blocked on %d: %v", waiter, blocker, f.ctx.Err())
		case <-ticker.C:
		}
	}
}

// An AFTER trigger is important: the operation already holds the row locks whose lifetime
// is under test. The barrier is scoped to this fixture's principal/tenant and is removed
// before cleanup, so it cannot catch unrelated fixture provisioning.
func oidcRaceGate(t *testing.T, f *oidcRaceFixture, table, event, column, value string) (int32, func()) {
	t.Helper()
	name := "oidc_race_" + fmt.Sprintf("%x", HashToken(f.user)[:8])
	fn := pgx.Identifier{name}.Sanitize()
	tbl := pgx.Identifier{table}.Sanitize()
	col := pgx.Identifier{column}.Sanitize()
	conn, err := f.su.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := conn.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := conn.Exec(f.ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, f.user); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	// value and user are database-generated UUIDs, never caller-supplied SQL.
	ddl := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN
		PERFORM pg_advisory_xact_lock(hashtextextended('%s',0));
		RETURN NEW;
	END $$`, fn, f.user)
	mustExec(t, f.su, ddl)
	mustExec(t, f.su, fmt.Sprintf(`CREATE TRIGGER %s AFTER %s ON %s
		FOR EACH ROW WHEN (NEW.%s = '%s'::uuid) EXECUTE FUNCTION %s()`, fn, event, tbl, col, value, fn))
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := conn.Exec(cleanupCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, f.user)
		conn.Release()
		if err != nil {
			t.Errorf("release race barrier: %v", err)
		}
	}
	t.Cleanup(func() {
		release()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.su.Exec(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s`, fn, tbl)); err != nil {
			t.Errorf("drop race trigger: %v", err)
		}
		if _, err := f.su.Exec(cleanupCtx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn)); err != nil {
			t.Errorf("drop race function: %v", err)
		}
	})
	return pid, release
}

type oidcRaceResult struct {
	err     error
	session *Session
}

type oidcRaceCase struct {
	name                 string
	credential, link     bool
	table, event, column string
	refusal              error
}

func oidcRaceMutation(f *oidcRaceFixture, pool *pgxpool.Pool, name string) error {
	s := NewPgOIDCStore(pool, f.cipher)
	switch name {
	case "first_password", "password_change":
		_, err := NewPgUserStore(pool).SetPassword(f.ctx, f.tenant, f.user, "race-new-phc")
		return err
	case "email_epoch":
		_, err := NewPgUserStore(pool).SetEmail(f.ctx, f.tenant, f.user, "changed@acme.test", f.a.EpochBaseline)
		return err
	case "connection_disable":
		w := f.write
		w.Enabled = false
		_, err := s.PutConnection(f.ctx, f.tenant, w)
		return err
	case "connection_replace_issue", "connection_replace_link":
		w := f.write
		w.ClientID = "33333333-3333-4333-8333-333333333333"
		_, err := s.PutConnection(f.ctx, f.tenant, w)
		return err
	case "unlink":
		return s.UnlinkIdentity(f.ctx, f.tenant, f.user)
	case "user_disable_issue", "user_disable_link":
		return withTenant(f.ctx, pool, f.tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(f.ctx, `UPDATE app_user SET disabled_at=clock_timestamp() WHERE id=$1`, f.user); err != nil {
				return err
			}
			_, err := tx.Exec(f.ctx, `UPDATE user_session SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, f.user)
			return err
		})
	case "origin_revoke":
		return NewPgSessionStore(pool).Revoke(f.ctx, HashToken("race-origin"))
	}
	return fmt.Errorf("unknown race %s", name)
}

func oidcRaceOperation(f *oidcRaceFixture, pool *pgxpool.Pool, link bool) oidcRaceResult {
	s := NewPgOIDCStore(pool, f.cipher)
	if link {
		return oidcRaceResult{err: s.LinkIdentity(f.ctx, f.a, f.origin)}
	}
	_, session, err := s.IssueOIDCSession(f.ctx, f.a)
	return oidcRaceResult{err: err, session: session}
}

func oidcRaceReceive(t *testing.T, f *oidcRaceFixture, ch <-chan oidcRaceResult) oidcRaceResult {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
		return oidcRaceResult{}
	}
}

// A committed link is durable even when a later password change invalidates
// its originating authority. In the reverse order the old authority cannot link.
func TestPgOIDCPasswordVersusLink(t *testing.T) {
	for _, credential := range []bool{false, true} {
		for _, passwordFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("credential=%v/password-first=%v", credential, passwordFirst), func(t *testing.T) {
				f := oidcRaceNew(t, credential, false)
				table, event, column := "app_user", "UPDATE", "id"
				if passwordFirst {
					table, event, column = "user_credential", "INSERT OR UPDATE", "user_id"
				}
				gatePID, release := oidcRaceGate(t, f, table, event, column, f.user)
				leftPID := oidcRacePID(t, f.ctx, f.left)
				rightPID := oidcRacePID(t, f.ctx, f.right)
				password := func(pool *pgxpool.Pool) oidcRaceResult {
					_, err := NewPgUserStore(pool).SetPassword(f.ctx, f.tenant, f.user, "new-link-race-phc")
					return oidcRaceResult{err: err}
				}
				link := func(pool *pgxpool.Pool) oidcRaceResult { return oidcRaceOperation(f, pool, true) }
				first, second := link, password
				if passwordFirst {
					first, second = password, link
				}
				left, right := make(chan oidcRaceResult, 1), make(chan oidcRaceResult, 1)
				go func() { left <- first(f.left) }()
				oidcRaceWait(t, f, leftPID, gatePID)
				go func() { right <- second(f.right) }()
				oidcRaceWait(t, f, rightPID, leftPID)
				release()
				oidcWantError(t, oidcRaceReceive(t, f, left).err, nil)
				var want error
				if passwordFirst {
					want = ErrOIDCEpoch
				}
				oidcWantError(t, oidcRaceReceive(t, f, right).err, want)
				var linked bool
				if err := f.su.QueryRow(f.ctx, `SELECT coalesce(oidc_issuer=$2 AND oidc_subject=$3,false) FROM app_user WHERE id=$1`, f.user, f.a.Issuer, f.a.Subject).Scan(&linked); err != nil {
					t.Fatal(err)
				}
				if linked == passwordFirst {
					t.Fatalf("linked=%v, passwordFirst=%v", linked, passwordFirst)
				}
				if linked {
					_, _, err := NewPgOIDCStore(f.left, f.cipher).IssueOIDCSession(f.ctx, f.a)
					oidcWantError(t, err, ErrOIDCEpoch)
				}
			})
		}
	}
}

func TestPgOIDCCreateAttemptOriginLockWait(t *testing.T) {
	for _, mode := range []string{"link", "test"} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%v", mode, expired), func(t *testing.T) {
				f := oidcRaceNew(t, true, false)
				tx, err := f.su.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				var blocker int32
				if err := tx.QueryRow(f.ctx, `SELECT pg_backend_pid() FROM user_session WHERE id=$1 FOR UPDATE`, f.origin).Scan(&blocker); err != nil {
					t.Fatal(err)
				}
				waiter := oidcRacePID(t, f.ctx, f.left)
				a := &OIDCAttempt{TenantID: f.tenant, KeyHash: HashToken("wait-key"), StateHash: HashToken("wait-state"), Nonce: "nonce", CodeVerifier: "verifier", Mode: mode, UserID: &f.user, SessionID: &f.origin, EpochBaseline: f.a.EpochBaseline, ConnectionVersion: f.a.ConnectionVersion, Profile: "entra", ReturnPath: "/console", RedirectURI: "https://acme.deskrally.com/cp/auth/oidc/callback"}
				ch := make(chan oidcRaceResult, 1)
				go func() { ch <- oidcRaceResult{err: NewPgOIDCStore(f.left, f.cipher).CreateAttempt(f.ctx, a)} }()
				oidcRaceWait(t, f, waiter, blocker)
				// Commit newly stale authority while the real start operation waits.
				// Future verified_at also proves the clock read happened after its
				// transaction started, without a five-minute test sleep.
				_, err = tx.Exec(f.ctx, `UPDATE user_session SET mfa_verified_at=clock_timestamp() WHERE id=$1`, f.origin)
				if err != nil {
					t.Fatal(err)
				}
				if expired {
					_, err = tx.Exec(f.ctx, `UPDATE user_session SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.origin)
				} else {
					_, err = tx.Exec(f.ctx, `UPDATE user_session SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE id=$1`, f.origin)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				want := ErrOIDCStepUpStale
				if expired {
					want = ErrOIDCSessionInvalid
				}
				oidcWantError(t, oidcRaceReceive(t, f, ch).err, want)
			})
		}
	}
}

func TestPgOIDCFencingRaces(t *testing.T) {
	cases := []oidcRaceCase{
		{"first_password", false, false, "user_credential", "INSERT OR UPDATE", "user_id", ErrOIDCEpoch},
		{"password_change", true, false, "user_credential", "INSERT OR UPDATE", "user_id", ErrOIDCEpoch},
		{"email_epoch", true, false, "user_credential", "UPDATE", "user_id", ErrOIDCEpoch},
		{"connection_disable", true, false, "tenant_oidc", "UPDATE", "tenant_id", ErrOIDCDisabled},
		{"connection_replace_issue", true, false, "tenant_oidc", "UPDATE", "tenant_id", ErrOIDCVersion},
		{"connection_replace_link", true, true, "tenant_oidc", "UPDATE", "tenant_id", ErrOIDCVersion},
		{"unlink", true, false, "app_user", "UPDATE", "id", ErrOIDCNotLinked},
		{"user_disable_issue", true, false, "app_user", "UPDATE", "id", ErrOIDCUserDisabled},
		{"user_disable_link", true, true, "app_user", "UPDATE", "id", ErrOIDCUserDisabled},
		{"origin_revoke", true, true, "user_session", "UPDATE", "user_id", ErrOIDCSessionInvalid},
	}
	for _, tc := range cases {
		for _, mutationFirst := range []bool{true, false} {
			order := "oidc_first"
			if mutationFirst {
				order = "mutation_first"
			}
			t.Run(tc.name+"/"+order, func(t *testing.T) {
				f := oidcRaceNew(t, tc.credential, !tc.link)
				leftPID := oidcRacePID(t, f.ctx, f.left)
				rightPID := oidcRacePID(t, f.ctx, f.right)
				table, event, column, value := tc.table, tc.event, tc.column, f.user
				if column == "tenant_id" {
					value = f.tenant
				}
				if !mutationFirst {
					table, event, column, value = "user_session", "INSERT", "user_id", f.user
					if tc.link {
						table, event, column = "app_user", "UPDATE", "id"
					}
				}
				gatePID, release := oidcRaceGate(t, f, table, event, column, value)
				first := make(chan oidcRaceResult, 1)
				second := make(chan oidcRaceResult, 1)
				go func() {
					if mutationFirst {
						first <- oidcRaceResult{err: oidcRaceMutation(f, f.left, tc.name)}
					} else {
						first <- oidcRaceOperation(f, f.left, tc.link)
					}
				}()
				oidcRaceWait(t, f, leftPID, gatePID)
				go func() {
					if mutationFirst {
						second <- oidcRaceOperation(f, f.right, tc.link)
					} else {
						second <- oidcRaceResult{err: oidcRaceMutation(f, f.right, tc.name)}
					}
				}()
				oidcRaceWait(t, f, rightPID, leftPID)
				release()
				r1 := oidcRaceReceive(t, f, first)
				r2 := oidcRaceReceive(t, f, second)
				mutation, operation := r1, r2
				if !mutationFirst {
					mutation, operation = r2, r1
				}
				if mutation.err != nil {
					t.Fatalf("mutation: %v", mutation.err)
				}
				if mutationFirst {
					if !errors.Is(operation.err, tc.refusal) {
						t.Fatalf("OIDC operation = %v, want %v", operation.err, tc.refusal)
					}
				} else if operation.err != nil {
					t.Fatalf("OIDC operation committed first: %v", operation.err)
				}
				oidcRaceAssertState(t, f, tc, mutationFirst, operation.session)
			})
		}
	}
}

func oidcRaceAssertState(t *testing.T, f *oidcRaceFixture, tc oidcRaceCase, mutationFirst bool, issued *Session) {
	t.Helper()
	var live, usable int
	// Check both revocation and the persisted authentication predicates. An epoch mismatch
	// alone must not hide a missing required revocation by the credential writer.
	if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session
		WHERE tenant_id=$1 AND user_id=$2 AND login_method='oidc'
		AND revoked_at IS NULL AND expires_at>clock_timestamp()`, f.tenant, f.user).Scan(&live); err != nil {
		t.Fatal(err)
	}
	// Credential writers fence on app_user and leave revocation to the caller's RevokeOtherSessions
	// after commit, exactly as for password sessions; what makes a session issued just before the
	// credential change unusable AT ONCE is the per-request credential epoch (session.go
	// CredentialEpochMatches — the same defence TestCredentialEpochRefusesASessionThatRacedThePasswordChange
	// pins for password logins). So for those cases the `usable` check below is the assertion; every
	// other mutation revokes in its own transaction and must leave no live OIDC session.
	credentialCase := tc.table == "user_credential"
	if live != 0 && !credentialCase {
		t.Fatalf("%d unrevoked OIDC sessions survived %s", live, tc.name)
	}
	if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session s
		JOIN app_user u ON u.id=s.user_id AND u.tenant_id=s.tenant_id
		JOIN tenant t ON t.id=s.tenant_id
		JOIN tenant_oidc c ON c.tenant_id=s.tenant_id
		LEFT JOIN user_credential p ON p.user_id=u.id AND p.tenant_id=u.tenant_id
		WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.login_method='oidc'
		AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
		AND u.disabled_at IS NULL AND t.disabled_at IS NULL AND c.enabled
		AND c.version=s.oidc_connection_version
		AND u.oidc_issuer=$3 AND u.oidc_subject=$4
		AND s.credential_epoch IS NOT DISTINCT FROM p.updated_at`,
		f.tenant, f.user, f.a.Issuer, f.a.Subject).Scan(&usable); err != nil {
		t.Fatal(err)
	}
	if usable != 0 {
		t.Fatalf("%d usable sessions survived stale authority", usable)
	}
	var count int
	if err := f.su.QueryRow(f.ctx, `SELECT count(*) FROM user_session
		WHERE tenant_id=$1 AND user_id=$2 AND login_method='oidc'`, f.tenant, f.user).Scan(&count); err != nil {
		t.Fatal(err)
	}
	want := 0
	if !tc.link && !mutationFirst {
		want = 1
		if issued == nil || issued.ID == "" {
			t.Fatal("successful issuance returned no persisted session")
		}
	}
	if count != want {
		t.Fatalf("persisted OIDC sessions = %d, want %d", count, want)
	}
	if tc.link {
		var issuer, subject *string
		if err := f.su.QueryRow(f.ctx, `SELECT oidc_issuer,oidc_subject FROM app_user WHERE id=$1`, f.user).Scan(&issuer, &subject); err != nil {
			t.Fatal(err)
		}
		// Disabling a user or revoking the originating session after a successful link
		// does not undo that previously authorized link. Replacement always clears it.
		wantLink := !mutationFirst && tc.name != "connection_replace_link"
		if wantLink {
			if issuer == nil || subject == nil || *issuer != f.a.Issuer || *subject != f.a.Subject {
				t.Fatal("authorized link did not persist")
			}
		} else if issuer != nil || subject != nil {
			t.Fatal("stale link persisted")
		}
	}
}
