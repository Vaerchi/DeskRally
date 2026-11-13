/**
 * Pure helpers for the attended-session support bundle download.
 *
 * The bundle endpoint (POST /attended-sessions/support-bundle) is unauthenticated — the code in
 * the request body is the guest's credential. The server returns a ZIP containing the unmodified
 * DeskRallySupport.exe and a session.code sidecar so the guest does not have to manually type the
 * code into the native client's prompt.
 *
 * Pure and dependency-free so vitest can cover it.
 */

/** Crockford base32 alphabet — uppercase only; I, L, O, U omitted. */
const CROCKFORD_RE = /^(?:[0-9A-HJKMNP-TV-Z]{8}|[0-9A-HJKMNP-TV-Z]{13})$/;

/**
 * Returns true when `code` has the exact format accepted by the support bundle endpoint:
 * 8 characters (or 13 for legacy codes) from the Crockford alphabet, uppercase only.
 *
 * This is a FORMAT check only — it does not validate that the code is live or unredeemed.
 * The same check runs server-side in `validAttendCodeShape` (managed_install.go).
 */
export function validAttendCodeForBundle(code: string): boolean {
  return CROCKFORD_RE.test(code);
}

/**
 * Returns the URL for the support bundle POST endpoint given the control-plane origin.
 * The caller should POST `{"code":"<ATTEND_CODE>"}` and expect a ZIP response.
 */
export function attendBundleEndpointUrl(cpOrigin: string): string {
  return `${cpOrigin.replace(/\/+$/, "")}/cp/attended-sessions/support-bundle`;
}

/** URL of the public GET that says whether the session bundle is the ONLY working download. */
export function attendSupportModeUrl(cpOrigin: string): string {
  return `${cpOrigin.replace(/\/+$/, "")}/cp/attended-sessions/support-mode`;
}

/**
 * True only for an explicit `{"bundle_only": true}`. In deployment-pass mode (docs/48 C) the plain
 * support exe is GENERIC and refuses to run without the pass that only the bundle carries, so the
 * join page must not offer it. Anything else (an older server, an error, junk) keeps today's page.
 */
export function parseSupportMode(body: unknown): boolean {
  return (body as { bundle_only?: unknown } | null)?.bundle_only === true;
}
