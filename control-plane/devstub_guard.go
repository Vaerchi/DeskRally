package controlplane

import "fmt"

// insecureDevStub marks the dev-only stubs (StubAuthenticator, NoopBinder). Only they implement it, and
// they exist only in -tags cpdev builds and in this package's tests.
type insecureDevStub interface{ insecureDevStub() }

// authWrapper is an Authenticator that delegates to another one, so the guard can see through it.
type authWrapper interface{ wrappedAuthenticator() Authenticator }

func (a *APITokenAuthenticator) wrappedAuthenticator() Authenticator { return a.Next }
func (a *GuardedAuthenticator) wrappedAuthenticator() Authenticator  { return a.Next }

// servesStubAuthenticator reports whether a dev-only authenticator answers somewhere in the chain.
func servesStubAuthenticator(a Authenticator) bool {
	for depth := 0; a != nil && depth < 16; depth++ {
		if _, ok := a.(insecureDevStub); ok {
			return true
		}
		w, ok := a.(authWrapper)
		if !ok {
			return false
		}
		a = w.wrappedAuthenticator()
	}
	return false
}

// CheckServingWiring is the last check before the control plane serves (outside review, 2026-11-23).
// DecideStartup judges the DECLARED environment; this judges what was actually WIRED, so a later edit
// that hands production a stub, or pairs a real database with the no-op binder (every query would then
// run without its tenant pinned, so row-level security would see no tenant), stops the process at boot
// instead of serving.
func CheckServingWiring(srv *Server, insecureDev bool, databaseURL string) error {
	if srv == nil {
		return fmt.Errorf("no server was wired")
	}
	stubAuth := servesStubAuthenticator(srv.Auth)
	_, noopBinder := srv.Binder.(insecureDevStub)
	if (stubAuth || noopBinder) && !insecureDev {
		return fmt.Errorf("refusing to serve: a dev-only stub (stub authenticator=%t, no-op tenant binder=%t) "+
			"is wired but %s is not set. These answer every request as a fixed principal and skip tenant "+
			"isolation; they exist for local demos and tests only", stubAuth, noopBinder, EnvInsecureDev)
	}
	if noopBinder && databaseURL != "" {
		return fmt.Errorf("refusing to serve: DATABASE_URL is set but the no-op tenant binder is wired, so " +
			"database queries would run without the tenant pinned and row-level security would not apply")
	}
	return nil
}
