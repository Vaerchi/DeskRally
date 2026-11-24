//go:build !cpdev

package main

import controlplane "rmt/controlplane"

// insecureDevCompiled: a production build (no -tags cpdev) contains no stub authenticator and no no-op
// binder, so CP_INSECURE_DEV=1 is refused at startup (main) before either function below is reached.
const insecureDevCompiled = false

func devStubAuthenticator(*controlplane.Principal) controlplane.Authenticator {
	panic("insecure dev mode is not compiled into this build (rebuild with -tags cpdev)")
}

func devNoopBinder() controlplane.TenantBinder {
	panic("insecure dev mode is not compiled into this build (rebuild with -tags cpdev)")
}
