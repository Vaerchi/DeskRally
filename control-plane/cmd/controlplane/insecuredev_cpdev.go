//go:build cpdev

package main

import controlplane "rmt/controlplane"

// insecureDevCompiled: this binary was built with -tags cpdev, so CP_INSECURE_DEV=1 can serve the stub.
const insecureDevCompiled = true

func devStubAuthenticator(p *controlplane.Principal) controlplane.Authenticator {
	return controlplane.StubAuthenticator{Principal: p}
}

func devNoopBinder() controlplane.TenantBinder { return controlplane.NoopBinder{} }
