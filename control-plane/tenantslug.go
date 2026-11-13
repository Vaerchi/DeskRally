package controlplane

// A tenant's slug is also its hostname, https://<slug>.deskrally.com: the console's login form
// reads the tenant from the first label (web/viewer/src/lib/tenant_from_host.ts), and the desktop
// client trusts exactly that origin for a tenant it is given (clients/windows/client_policy.h).
// So a slug must be one lowercase DNS label, and it must not be a name the deployment uses for
// infrastructure in the same zone, or a tenant could claim an origin that is not a console.
// The reserved list is mirrored in the client and in web/viewer/src/lib/desktop_launch.ts.
// "updater" is reserved because the desktop client keeps a tenant's settings in the registry key
// ...\DeskRally\Client\<slug>, and its updater already owns ...\Client\Updater.

var reservedTenantSlugs = map[string]bool{
	"www": true, "turn": true, "stun": true, "api": true, "app": true, "admin": true,
	"download": true, "downloads": true, "update": true, "updates": true, "updater": true, "mail": true,
	"status": true, "relay": true, "signal": true, "signaling": true,
}

// ValidTenantSlug reports whether s is 1-63 of [a-z0-9-], starting and ending alphanumeric,
// and not reserved. It does no case folding: an uppercase slug is refused, not normalised.
func ValidTenantSlug(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	return !reservedTenantSlugs[s]
}
