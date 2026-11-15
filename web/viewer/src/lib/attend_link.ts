/**
 * The `rmt-<fingerprint>://` launch link for the guest landing page (docs/01 §12, guest client
 * launch handoff).
 *
 * Pure and dependency-free so vitest can see it — `vite.config.ts` globs only `src/**\/*.test.ts`,
 * and logic left inside a `.tsx` render body gets no unit coverage at all.
 *
 * The agent registers a per-deployment scheme `rmt-<fingerprint>` at install time and re-parses the
 * whole URI in-process as ONE argument (`crates/agent-windows/src/uri.rs`). Three consequences bind
 * this file:
 *
 * 1. **The scheme is namespaced by the control-plane ORIGIN, and this file must derive the SAME one
 *    the agent does.** Registering the bare `rmt` scheme machine-wide meant two deployments' clients
 *    fought over one registry key — the last installer silently retargeted the first's links
 *    (docs/07 loop 18). Both sides therefore hash the canonical origin identically (see
 *    {@link deploymentScheme}); the golden vectors in the test suite here and in
 *    `crates/agent-windows/src/uri.rs` pin the agreement byte-for-byte.
 * 2. **Every value must be `encodeURIComponent`d.** The agent's parser deliberately REFUSES a raw
 *    space, a raw `#`, control characters, and `" < > \ ^ ` { } |` rather than guessing — so an
 *    un-encoded value does not degrade, it fails closed. In particular `+` is a literal plus to that
 *    parser, never a space.
 * 3. **This link cannot be the only affordance.** A machine that has never installed the client has
 *    no handler for our scheme, and browsers give no reliable signal that a scheme is unhandled — a
 *    failed navigation is silent. So the page always shows the copy-paste command too, and never
 *    auto-navigates.
 */

/** The action the agent's URI parser accepts, after the scheme. */
const ATTEND_ACTION = "attend";

/** Public URL fragments are untrusted, including when shown in a shell command. */
export function validatedAttendCode(raw: string): string {
  return /^(?:[0-9A-HJKMNP-TV-Z]{8}|[0-9A-HJKMNP-TV-Z]{13})$/i.test(raw)
    ? raw.toUpperCase()
    : "";
}

/**
 * Canonicalize a control-plane URL to its ORIGIN — `scheme://host[:port]` — exactly as
 * `window.location.origin` would (and as `crate::uri::canonical_origin` does in Rust): lower-case
 * scheme and host, drop userinfo, and drop a port that equals the scheme's default (443 for https,
 * 80 for http). Path, query and fragment are discarded.
 *
 * Hand-rolled rather than `new URL(u).origin` on purpose: this must match the Rust implementation
 * character-for-character, and `URL` has behaviours (IDNA/punycode, `blob:`/`file:` origins of
 * `"null"`) that Rust's simple splitter does not. For the http(s) control-plane origins this ever
 * sees, the two agree; keeping the algorithm explicit is what lets the golden vectors guarantee it.
 */
export function canonicalOrigin(url: string): string {
  const s = url.trim();
  let scheme = "";
  let rest = s;
  const sep = s.indexOf("://");
  if (sep >= 0) {
    scheme = s.slice(0, sep).toLowerCase();
    rest = s.slice(sep + 3);
  }
  const authority = rest.split(/[/?#]/, 1)[0] ?? "";
  // Userinfo is everything before the LAST '@' (RFC 3986).
  const at = authority.lastIndexOf("@");
  const hostPort = at >= 0 ? authority.slice(at + 1) : authority;
  // Split host from port, keeping an IPv6 literal's brackets intact.
  let host: string;
  let port: string | null = null;
  const close = hostPort.lastIndexOf("]");
  if (close >= 0) {
    host = hostPort.slice(0, close + 1);
    const tail = hostPort.slice(close + 1);
    port = tail.startsWith(":") ? tail.slice(1) : null;
  } else {
    const colon = hostPort.lastIndexOf(":");
    if (colon >= 0) {
      host = hostPort.slice(0, colon);
      port = hostPort.slice(colon + 1);
    } else {
      host = hostPort;
    }
  }
  host = host.toLowerCase();
  const defaultPort = scheme === "https" ? "443" : scheme === "http" ? "80" : null;
  const portPart = port && port.length > 0 && port !== defaultPort ? `:${port}` : "";
  return scheme ? `${scheme}://${host}${portPart}` : `${host}${portPart}`;
}

/**
 * FNV-1a (64-bit) over `s`'s UTF-8 bytes, as 16 lowercase hex digits — the byte-for-byte twin of
 * `crate::uri::fnv1a64_hex`. `BigInt` is used for the 64-bit arithmetic so the multiply never loses
 * precision the way a `number` would past 2^53.
 *
 * A NAMESPACING fingerprint, not a cryptographic one: its only job is that two different origins
 * almost never collide and one origin always maps to one value.
 */
export function fnv1a64Hex(s: string): string {
  const MASK = (1n << 64n) - 1n;
  const PRIME = 0x100000001b3n;
  let hash = 0xcbf29ce484222325n; // FNV offset basis
  for (const b of new TextEncoder().encode(s)) {
    hash ^= BigInt(b);
    hash = (hash * PRIME) & MASK;
  }
  return hash.toString(16).padStart(16, "0");
}

/**
 * The per-deployment URI scheme `rmt-<fingerprint>` for a control plane at `cpOrigin`. The agent
 * derives the identical value from its configured `control_plane_url`
 * (`crate::uri::deployment_scheme`); this is what routes a link to the right installed client and
 * keeps two deployments on one machine from colliding.
 */
export function deploymentScheme(cpOrigin: string): string {
  return `rmt-${fnv1a64Hex(canonicalOrigin(cpOrigin))}`;
}

/**
 * Build the `rmt-<fingerprint>://attend` launch URI, or `null` when there is no code to launch with.
 *
 * `null` rather than a link to `<CODE>`: a link that cannot work should not be offered, whereas the
 * copy-paste command is still useful as documentation with a placeholder in it.
 */
export function attendLaunchUri(code: string, cpOrigin: string): string | null {
  const trimmed = code.trim();
  if (!trimmed) return null;
  const scheme = deploymentScheme(cpOrigin);
  const cp = `${cpOrigin.replace(/\/+$/, "")}/cp`;
  return (
    `${scheme}://${ATTEND_ACTION}?code=${encodeURIComponent(trimmed)}` +
    `&cp=${encodeURIComponent(cp)}`
  );
}
