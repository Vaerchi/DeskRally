package controlplane

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPgOIDCSessionAuthenticateCredentialEpoch(t *testing.T) {
	for _, credential := range []bool{true, false} {
		name := "password"
		if !credential {
			name = "oidc-only"
		}
		t.Run(name, func(t *testing.T) {
			f := newOIDCFixture(t)
			if !credential {
				mustExec(t, f.su, `DELETE FROM user_credential WHERE user_id=$1`, f.user)
				f.a.EpochBaseline = time.Time{}
				mustExec(t, f.su, `UPDATE user_session SET credential_epoch=NULL WHERE id=$1`, f.origin)
			}
			f.link(t)
			token, issued, err := f.store.IssueOIDCSession(f.ctx, f.a)
			if err != nil {
				t.Fatal(err)
			}
			users := NewPgUserStore(f.app)
			sessions := NewPgSessionStore(f.app)
			auth := &SessionAuthenticator{Users: users, Sessions: NewSessionManager(sessions)}
			r := httptest.NewRequest("GET", "https://acme.deskrally.com/console", nil).WithContext(f.ctx)
			r.Header.Set("Authorization", "Bearer "+token)
			principal, err := auth.Authenticate(r)
			if err != nil {
				t.Fatal(err)
			}
			if principal.UserID != f.user || principal.SessionID != issued.ID {
				t.Fatalf("principal=%+v", principal)
			}
			// Exercise the actual writer. No revocation call masks a missing epoch
			// check; the same bearer token must fail on the next authenticated request.
			phc, err := HashPassword("replacement-password-1234")
			if err != nil {
				t.Fatal(err)
			}
			epoch, err := users.SetPassword(f.ctx, f.tenant, f.user, phc)
			if err != nil {
				t.Fatal(err)
			}
			if !epoch.After(f.a.EpochBaseline) {
				t.Fatalf("credential epoch did not advance: %v", epoch)
			}
			_, err = auth.Authenticate(r)
			if !errors.Is(err, ErrSessionCredentialStale) {
				t.Fatalf("Authenticate after password change=%v", err)
			}
			stored, err := sessions.GetByTokenHash(f.ctx, HashToken(token))
			if err != nil {
				t.Fatal(err)
			}
			if stored.RevokedAt != nil {
				t.Fatal("revocation masked credential epoch enforcement")
			}
		})
	}
}
