package controlplane

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type cancelledInstallerWriter struct {
	installerFailedWriter
	cancel context.CancelFunc
}

func (w *cancelledInstallerWriter) Write(b []byte) (int, error) {
	w.cancel()
	return w.installerFailedWriter.Write(b)
}

func TestPgManagedInstallerMintAndCancelledDownloadAsAppRole(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyEnrollmentMigration(t, pool)
	tid, uid := provisionUser(t, pool, "installer-tenant", "installer@example.test", "synthetic-password")
	group := seedGroup(t, pool, tid)
	app := newAppRolePool(t, context.Background())
	srv := NewServer(StubAuthenticator{Principal: &Principal{UserID: uid, TenantID: tid, Grant: NewGrant(uid, tid, NewMembership(RoleAdmin, Groups(group)))}}, NewPgBinder(app))
	srv.MachineGroups = NewPgMachineGroupStore(app)
	srv.EnrollmentTokens = NewPgEnrollmentTokenStore(app)
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	_, srv.ManagedInstaller = installerFixture(t)
	body := `{"group_id":"` + group + `"}`
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("download status%d", w.Code)
	}
	z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	secret := ""
	for _, f := range z.File {
		if f.Name == "enrollment.token" {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			secret = string(b)
		}
	}
	if len(secret) != 43 {
		t.Fatal("missing credential")
	}
	tok, err := srv.EnrollmentTokens.RedeemToken(context.Background(), secret)
	if err != nil || tok.GroupID != group || tok.TenantID != tid {
		t.Fatal("app-role redemption failed")
	}
	if _, err := srv.EnrollmentTokens.RedeemToken(context.Background(), secret); err == nil {
		t.Fatal("reused one-time credential")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := &cancelledInstallerWriter{installerFailedWriter{make(http.Header)}, cancel}
	srv.Handler().ServeHTTP(failed, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(body)).WithContext(ctx))
	if ctx.Err() == nil {
		t.Fatal("request was not cancelled")
	}
	tokens, err := srv.EnrollmentTokens.ListTokens(context.Background(), tid)
	if err != nil || len(tokens) != 2 {
		t.Fatal("expected two scoped mints")
	}
	revoked := 0
	for _, token := range tokens {
		if token.Revoked {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatal("cancelled response did not revoke through retained RLS-bound connection")
	}
}
