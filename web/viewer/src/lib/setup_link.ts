/**
 * The self-service password-setup link (docs/01 §5): the console mints a credential-setup token for a
 * user (POST /users/{id}/password-reset) and the administrator hands over a link to THIS page, where the
 * user sets their first password (or a reset one) against the public POST /auth/password/redeem.
 *
 * Pure and dependency-free so vitest can see it — `vite.config.ts` globs only `src/**\/*.test.ts`, and
 * logic left inside a `.tsx` render body gets no unit coverage at all (same rule as attend_link.ts).
 *
 * The token rides the URL FRAGMENT, never a query param — exactly like the /join code — so the secret
 * stays out of server logs, proxies, and the Referer header. The page reads it client-side only. The
 * token is a URL-safe base64 secret, but it is `encodeURIComponent`d on the way in and decoded on the
 * way out anyway, so the round-trip survives any future token alphabet without silently corrupting a `+`
 * or `/` the way a bare fragment would.
 */

/** The path the redemption page is served at (main.tsx routes it, like /join). */
export const SETUP_LINK_PATH = "/set-password";

/**
 * Build the full setup link a user opens to set their password: `<origin>/set-password#<token>`.
 *
 * Returns "" for an empty token — there is no usable link without a secret, and an empty string is a
 * falsy value the caller can guard on rather than a link to a bare `#` that would look real but do
 * nothing. A trailing slash on `origin` is normalised away so `https://host/` and `https://host` agree.
 */
export function setupLinkUrl(origin: string, token: string): string {
  if (!token) return "";
  const base = origin.replace(/\/+$/, "");
  return `${base}${SETUP_LINK_PATH}#${encodeURIComponent(token)}`;
}

/**
 * Recover the token from a location fragment (e.g. `window.location.hash`, "#<token>"). Strips the
 * leading '#' and decodes it. Returns "" when the fragment is empty (the link was opened bare).
 *
 * A malformed percent-encoding (a hand-mangled link) makes `decodeURIComponent` throw; rather than
 * crash the page, fall back to the raw stripped fragment — the redeem endpoint will reject a wrong
 * token cleanly, and a user who truly has a valid link is not blocked by our own decoder.
 */
export function parseSetupToken(hash: string): string {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!raw) return "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/**
 * Whether the /set-password form may be submitted: a non-empty new password that its confirmation
 * exactly matches. The SUBMIT BUTTON and the SUBMIT HANDLER both gate on this ONE function so they can
 * never disagree — the bug this replaces enabled the button on a lenient "mismatch" check (which is
 * false while confirm is still empty) while the handler used a strict `password === confirm`, so the
 * button was clickable but the click was a silent no-op with confirm empty.
 */
export function newPasswordsReady(password: string, confirm: string): boolean {
  return password !== "" && password === confirm;
}

/**
 * Whether to show the "passwords do not match" note: only once the user has typed something into the
 * confirm field AND it disagrees — an empty confirm is "not yet", not "wrong", so it shows nothing while
 * {@link newPasswordsReady} still (correctly) keeps the button disabled.
 */
export function showPasswordMismatch(password: string, confirm: string): boolean {
  return confirm !== "" && confirm !== password;
}
