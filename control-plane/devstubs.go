//go:build cpdev

package controlplane

import (
	"context"
	"net/http"
)

// Dev-only stubs, compiled ONLY with `-tags cpdev` (outside review, 2026-11-23). A production build of
// cmd/controlplane (Dockerfile, native packages, build-release) has no tag, so it cannot contain an
// authenticator that answers every request as a fixed principal or a binder that skips tenant RLS.
// The package's own tests get identical copies from devstubs_test.go; CheckServingWiring
// (devstub_guard.go) refuses to serve with either one unless insecure dev mode was declared.

// StubAuthenticator returns the same Principal for every request. Dev and test fixtures only.
type StubAuthenticator struct {
	Principal *Principal
}

// Authenticate implements Authenticator.
func (a StubAuthenticator) Authenticate(_ *http.Request) (*Principal, error) {
	return a.Principal, nil
}

func (StubAuthenticator) insecureDevStub() {}

// NoopBinder is a TenantBinder that does nothing (no database). The real binder is PgBinder
// (binder.go), which pins app.current_tenant on a pooled connection.
type NoopBinder struct{}

// BindTenant implements TenantBinder.
func (NoopBinder) BindTenant(ctx context.Context, _ string) (context.Context, func(), error) {
	return ctx, nil, nil
}

func (NoopBinder) insecureDevStub() {}
