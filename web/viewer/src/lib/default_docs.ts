/**
 * The default host's ORIGIN, and the documentation link built from it, for the join page's fixed attribution
 * (docs/66 2a.7, 2i).
 *
 * The attribution on a tenant-branded page must link to the DEFAULT host's `/docs`, never to the tenant's own
 * host. The viewer cannot learn the default host from the request (a tenant host is exactly where the page is
 * served from, and a Host-derived value would be attacker-influenced), so the origin is a deployment-configured,
 * build-time value: `VITE_DEFAULT_ORIGIN`, baked like `VITE_PRODUCT_NAME`. No existing build-time value fits
 * (`VITE_CONTROL_PLANE_URL` defaults to the relative `/cp`).
 *
 * The configuration is an ORIGIN and nothing else: `https://` + a dotted DNS host + an optional port. A path
 * (other than a bare `/`), query, fragment, userinfo, IP literal, control, space or quote character is invalid.
 * The link is always that origin + "/docs"; a configuration can never choose another path.
 *
 * `defaultOrigin` is fail-closed (a canonical origin or `null`). `JoinBrand` shows a tenant-branded page ONLY
 * when this yields a link, and renders the NEUTRAL page otherwise, so a branded page never lacks it. The same
 * function checks the value at build time (`vite.config.ts`).
 */
export function defaultOrigin(raw: string | undefined | null): string | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (s === "" || s.length > 300 || /[\u0000- \u007f-\u009f\\\"'`<>?#@]/.test(s)) return null;
  if (!s.toLowerCase().startsWith("https://")) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "") return null;
  if (u.pathname !== "/" || !(s.toLowerCase().endsWith(u.host) || s.toLowerCase().endsWith(`${u.host}/`))) return null;
  const host = u.hostname;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) return null;
  if (/^[0-9.]+$/.test(host)) return null; // an IPv4 literal
  return `https://${u.host}`;
}

/** The default host's documentation page: its configured origin + "/docs", or null when that is not valid. */
export function defaultDocsLink(raw: string | undefined | null): string | null {
  const origin = defaultOrigin(raw);
  return origin === null ? null : `${origin}/docs`;
}
