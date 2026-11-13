package controlplane

// SSRF protection for webhook delivery.
//
// Registration-time scheme validation (https-only in handleCreateWebhook) blocks the most obvious
// probing vectors, but it is insufficient on its own:
//   - A cloud IMDS address (169.254.169.254) is a valid https:// URL at the URL-parser level.
//   - A public hostname can resolve to a private IP via DNS rebinding or split-horizon DNS.
//   - A redirect from a legitimate HTTPS endpoint can lead to http:// or to a private destination.
//
// The safe client enforces destination constraints at connection time — after DNS resolution —
// so none of these bypass paths work.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// webhookSafeClientOnce ensures we allocate exactly one safe transport per process lifetime.
// The transport maintains its own connection pool; recreating it per dispatchSync call would
// prevent connection reuse across audit events to the same webhook host.
var webhookSafeClientOnce sync.Once
var webhookSafeClientSingleton *http.Client

// webhookSafeClient returns the shared SSRF-safe HTTP client for production webhook delivery.
// The client is created once (sync.Once) so its transport's connection pool is reused across
// fan-out calls. Tests bypass this by setting WebhookDispatcher.Client to their own client.
//
// The transport blocks connections to loopback, private, link-local, multicast, CGNAT, and
// unspecified addresses. The check runs at dial time — after DNS resolution — so DNS rebinding
// cannot bypass it. Because we dial the resolved IP directly (not the hostname), the OS cannot
// perform a second resolution for this connection, closing the classic TOCTOU window. TLS
// validation still uses the original URL hostname via http.Transport's ServerName mechanism.
// The same DialContext applies to redirect connections, so private-IP redirects are also blocked.
// Redirects that downgrade to http:// are blocked by CheckRedirect before DialContext runs.
func webhookSafeClient() *http.Client {
	webhookSafeClientOnce.Do(func() {
		dialer := &net.Dialer{}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("webhook: malformed dial addr %q: %w", addr, err)
				}
				// Resolve the host so we can check whether any resulting IP is private/reserved.
				// LookupIPAddr handles literal IPs (e.g., "127.0.0.1") by returning them unchanged.
				// Note: on Windows, net.DefaultResolver uses the WinDNS cache stub (typically
				// 127.0.0.53), but since we pass the literal resolved IP to dialer.DialContext below,
				// the OS cannot perform a second hostname resolution for this specific connection.
				resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("webhook: DNS resolution of %q failed: %w", host, err)
				}
				if len(resolved) == 0 {
					return nil, fmt.Errorf("webhook: DNS resolution of %q returned no addresses", host)
				}
				for _, a := range resolved {
					if webhookIsForbiddenIP(a.IP) {
						return nil, fmt.Errorf("webhook: SSRF protection blocked connection to %s (resolved %s is loopback/private/reserved)", host, a.IP)
					}
				}
				// Dial by the first resolved IP. Safety invariant: every address in `resolved`
				// has already passed webhookIsForbiddenIP above, so dialing resolved[0] cannot
				// reach a loopback/private/reserved host even if the set contains multiple
				// addresses — none survived the loop unless all of them are public. Dialing by
				// literal IP also closes the TOCTOU window: a second OS-level DNS lookup cannot
				// sneak in a different address between our check and the actual TCP SYN. TLS
				// still uses the URL hostname for SNI/certificate verification (http.Transport
				// sets ServerName from the request URL, not from the dialed address).
				return dialer.DialContext(ctx, network, net.JoinHostPort(resolved[0].IP.String(), port))
			},
		}
		webhookSafeClientSingleton = &http.Client{
			Timeout:       webhookDeliveryTimeout,
			Transport:     transport,
			CheckRedirect: checkWebhookRedirect,
		}
	})
	return webhookSafeClientSingleton
}

// checkWebhookRedirect is the CheckRedirect function for the SSRF-safe webhook client.
// It blocks redirects that downgrade to http:// (the destination IP check in DialContext
// already handles private-IP redirects for any scheme, but http:// is categorically blocked
// regardless of destination). Caps redirect chains at 2 hops (3 total requests including the
// original) to bound resource usage. The `via` slice holds previous requests, so
// `len(via) >= 2` fires when this would be the 3rd request (2nd redirect).
func checkWebhookRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("webhook: redirect to non-https scheme %q blocked (SSRF protection)", req.URL.Scheme)
	}
	if len(via) >= 2 {
		return fmt.Errorf("webhook: too many redirects (max 2 hops)")
	}
	return nil
}

// webhookCGNATBlock is the RFC 6598 shared address space (100.64.0.0/10) used by CGNAT.
// Cloud providers and ISPs route this space to internal infrastructure; it must not be
// dialable via the webhook path. net.IP.IsPrivate() does not cover this range (RFC 1918 only).
var webhookCGNATBlock = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// webhookIsForbiddenIP reports whether ip must not be contacted by the webhook dispatcher.
// Covers:
//   - Loopback:      127.0.0.0/8 (RFC 5735), ::1/128 (RFC 4291)
//   - Private:       10/8, 172.16/12, 192.168/16 (RFC 1918), fc00::/7 (RFC 4193)
//   - Link-local:    169.254/16 (RFC 3927, includes cloud IMDS at 169.254.169.254),
//                    fe80::/10 (RFC 4291)
//   - Multicast:     224.0.0.0/4 (RFC 1112), ff00::/8 (RFC 4291)
//   - CGNAT:         100.64.0.0/10 (RFC 6598 shared address space)
//   - Unspecified:   0.0.0.0, ::
//
// Not covered (explicit scope decision): IPv4 benchmarking 198.18.0.0/15 (RFC 2544),
// documentation 192.0.2.0/24 (RFC 5737), etc. — these are not routinely assigned to internal
// infrastructure so the risk is negligible.
func webhookIsForbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		webhookCGNATBlock.Contains(ip)
}
