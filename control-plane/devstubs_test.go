//go:build !cpdev

package controlplane

import (
	"context"
	"net/http"
)

// Test copies of the dev-only stubs in devstubs.go, for `go test` without -tags cpdev. Keep the two in
// step: TestDevStubCopiesMatch compares them.

type StubAuthenticator struct {
	Principal *Principal
}

func (a StubAuthenticator) Authenticate(_ *http.Request) (*Principal, error) {
	return a.Principal, nil
}

func (StubAuthenticator) insecureDevStub() {}

type NoopBinder struct{}

func (NoopBinder) BindTenant(ctx context.Context, _ string) (context.Context, func(), error) {
	return ctx, nil, nil
}

func (NoopBinder) insecureDevStub() {}
