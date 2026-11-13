/**
 * Guess the tenant slug from the hostname the console is served from.
 *
 * A deployment gives each tenant its own subdomain — `main.deskrally.com` is the
 * tenant `main` — so the slug is already on screen in the address bar and asking the operator to
 * retype it is friction with no purpose.
 *
 * **This is a PREFILL, not an authority.** The value goes into an editable field, and the server
 * resolves and authorizes whatever is actually submitted (`cp_resolve_tenant_by_slug`). That matters
 * for two reasons: a wrong guess must never lock anyone out, and the slug is a namespace selector
 * rather than a secret, so deriving it in the browser gives away nothing.
 *
 * Showing the derived value rather than hiding it is the point. A tenant whose slug does not match
 * its subdomain would otherwise fail login with the deliberately generic "invalid credentials" 401,
 * which is close to undebuggable from the outside. Prefilled and visible, the mismatch is obvious.
 */

/** True for an IPv4 literal or a bracketed/colon-bearing IPv6 host. */
function isIPLiteral(hostname: string): boolean {
  if (hostname.includes(":")) return true; // IPv6, with or without brackets
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

/**
 * Returns the leftmost DNS label when the hostname plausibly carries a tenant subdomain, else "".
 *
 * Requires at least THREE labels. Two (`example.com`) is an apex domain, and treating `example` as a
 * tenant would prefill a confident wrong answer on every single-domain deployment — worse than
 * prefilling nothing, because the operator has to notice it is wrong before it helps them.
 *
 * `localhost`, IP literals and `www.` all yield "" for the same reason: none of them names a tenant.
 */
export function tenantFromHostname(hostname: string): string {
  const host = hostname.trim().toLowerCase().replace(/\.$/, ""); // tolerate a trailing root dot
  if (host === "" || host === "localhost" || isIPLiteral(host)) return "";

  const labels = host.split(".");
  if (labels.length < 3) return "";

  const first = labels[0];
  if (first === "" || first === "www") return "";
  return first;
}
