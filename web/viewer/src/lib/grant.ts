/**
 * Helpers for working with the `SignedGrant` JSON the control plane mints and the viewer
 * forwards verbatim to the agent via `InstallGrant`.
 *
 * The signature is NOT verified here — only the agent does that. These helpers parse the
 * plaintext `claims` section purely for UI state hints (e.g. show/hide the download button
 * when `file_download` is absent from the grant). The agent always enforces the real check.
 */

/**
 * Extract the capability strings from a `SignedGrant` JSON string.
 *
 * The expected shape is:
 *   `{ "claims": { "grant": { "capabilities": string[] }, … }, "sig": "…" }`
 *
 * Returns an empty set on any parse error so callers degrade gracefully.
 */
export function parseGrantCapabilities(signedGrantJson: string): ReadonlySet<string> {
  try {
    const parsed = JSON.parse(signedGrantJson) as unknown;
    if (!parsed || typeof parsed !== "object") return new Set();
    const claims = (parsed as Record<string, unknown>).claims;
    if (!claims || typeof claims !== "object") return new Set();
    const grant = (claims as Record<string, unknown>).grant;
    if (!grant || typeof grant !== "object") return new Set();
    const caps = (grant as Record<string, unknown>).capabilities;
    if (!Array.isArray(caps)) return new Set();
    return new Set(caps.filter((c): c is string => typeof c === "string"));
  } catch {
    return new Set();
  }
}
