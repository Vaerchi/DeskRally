/**
 * The guest JOIN page's HOST BRANDING (docs/66 stage 2): the tenant's operator-approved name, accent,
 * logo, message and contact, as the control plane publishes them for the HOSTNAME the guest opened.
 *
 * Pure and dependency-free so vitest can cover it (the React parts are `use_host_branding.ts` and
 * `components/JoinBrand.tsx`).
 *
 * # What this file is, and is not, trusted with
 *
 * The control plane already validates every field before it publishes it and re-validates on every public
 * read (control-plane/publicbranding.go `renderPublishedBranding`), so a well-behaved server never sends
 * anything this file refuses. It is here anyway because the strings are shown to ANONYMOUS guests on a page
 * whose lede warns about impersonation: whatever the response contains, the page must stay safe. So the
 * rule is ALL OR NOTHING. A response either passes every check below and is applied as ONE brand, or it is
 * the NEUTRAL brand (the page the deployment ships). There is no partially applied brand: not for a bad
 * contact, not for a bad logo hash, not for an unexpected shape, not for a timeout.
 *
 * The checks that matter for safety, in order of what they prevent:
 *
 *   - TYPES AND SHAPE. A JSON object with the five known fields. Unknown extra keys are ignored (a newer
 *     server may add some); a missing or mistyped known key is neutral.
 *   - NO URL IS EVER TAKEN FROM THE RESPONSE. The logo address is built here from a 64-hex hash
 *     (`publicBrandingLogoUrl`); the only `href`s a brand can produce are the three contact kinds below,
 *     each re-validated and each BUILT from the canonical value (`tel:` + digits, `https://` + a plain public
 *     DNS name). An email is shown as text and is never a link (docs/66 2a.7: the local part may legally
 *     contain `?`, `&` and `=`, which is how a `mailto:` grows a hidden Cc or Bcc).
 *   - NO SPOOFING CHARACTERS. Bidi overrides and isolates, zero-width and other format characters, controls,
 *     private use, lone surrogates, UNASSIGNED code points, line and paragraph separators and every space
 *     other than U+0020 are refused in the name and the message.
 *   - BOUNDED SIZE. 3 to 100 code points for the name, 280 and 4 lines for the message, 200 for a contact.
 *   - NO CSS INJECTION. The accent is exactly `#` and six lowercase hex digits; it reaches the page only as
 *     the value of one CSS custom property.
 *
 * The rendering side uses no HTML-insertion API of any kind (JoinBrand.test.tsx lists them and scans the
 * sources), so even a string that slipped past every check here is displayed as inert text.
 */

export type BrandContactKind = "phone" | "email" | "url";

export interface BrandContact {
  kind: BrandContactKind;
  value: string;
}

/** A validated brand. NEUTRAL_BRAND (every field empty) means "the page as the deployment ships it". */
export interface HostBrand {
  /** The tenant's product name; "" = neutral (the page uses its build-time product name). */
  name: string;
  /** "#rrggbb" or "" (the theme's own colour). */
  accent: string;
  /** The published logo's SHA-256 (64 lowercase hex), or "" for no logo. It is the ONLY input to the logo URL. */
  logoRev: string;
  /** Plain text, newlines allowed (at most 4 lines), or "". */
  supportText: string;
  /** The one support contact, or null. */
  contact: BrandContact | null;
}

export const NEUTRAL_BRAND: HostBrand = Object.freeze({
  name: "",
  accent: "",
  logoRev: "",
  supportText: "",
  contact: null,
});

// Bounds (control-plane/brandtext.go: BrandNameMinRunes, BrandNameMaxRunes, BrandTextMaxRunes,
// BrandTextMaxLines, BrandContactMaxLen).
export const BRAND_NAME_MIN = 3;
export const BRAND_NAME_MAX = 100;
export const BRAND_TEXT_MAX = 280;
export const BRAND_TEXT_MAX_LINES = 4;
export const BRAND_CONTACT_MAX = 200;

/** A public response is a few hundred bytes (JSON escapes can inflate it to a few KiB). Anything bigger is refused. */
export const HOST_BRANDING_MAX_BODY = 16 * 1024;

/** The whole lookup is given this long, body included. A guest is never kept waiting on a brand. */
export const HOST_BRANDING_TIMEOUT_MS = 1500;

// ---- text -----------------------------------------------------------------------------------------------

/** Code points, not UTF-16 units (a lone surrogate counts as one, like Go's rune count of the replacement). */
function codePointCount(s: string): number {
  return [...s].length;
}

// Unicode category C (Cc controls, Cf bidi and zero-width format characters, Cs surrogates, Co private use, Cn
// UNASSIGNED), the line and paragraph separators, and U+FFFD. brandtext.go refuses the same set.
const FORBIDDEN_CHAR = /[\p{C}\p{Zl}\p{Zp}�]/u;
const OTHER_SPACE = /\p{Zs}/u;
const LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;

/**
 * One line of brand text exactly as the server stores it: no forbidden character, U+0020 as the only space,
 * no leading or trailing space, no run of spaces. (The server TRIMS and COLLAPSES; a value that still
 * differs from its own trimmed, collapsed form was not produced by it, so it is refused rather than cleaned.)
 */
function plainLine(s: string): boolean {
  if (FORBIDDEN_CHAR.test(s)) return false;
  if (OTHER_SPACE.test(s.replace(/ /g, ""))) return false;
  return s === s.trim() && !s.includes("  ");
}

export function validBrandName(s: string): boolean {
  const n = codePointCount(s);
  return n >= BRAND_NAME_MIN && n <= BRAND_NAME_MAX && plainLine(s) && LETTER_OR_DIGIT.test(s);
}

/** "" or at most 280 code points over at most 4 lines. `\n` is the only line break; everything else is a plain line. */
export function validSupportText(s: string): boolean {
  if (s === "") return true;
  if (codePointCount(s) > BRAND_TEXT_MAX || s !== s.trim()) return false;
  const lines = s.split("\n");
  return lines.length <= BRAND_TEXT_MAX_LINES && lines.every(plainLine);
}

/** "" (the theme's colour) or exactly `#rrggbb` in lowercase. The only value that ever reaches a CSS property. */
export function validAccent(s: string): boolean {
  return s === "" || /^#[0-9a-f]{6}$/.test(s);
}

export function validLogoRev(s: string): boolean {
  return s === "" || /^[0-9a-f]{64}$/.test(s);
}

// ---- contacts -------------------------------------------------------------------------------------------

// A name as the control plane accepts it for a contact host (hostpolicy.go NormalizeAuthority): lowercase DNS
// labels, at least two, the last not purely numeric (so an IP literal can never pass).
const DNS_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

function publicDnsName(h: string): boolean {
  if (h.length > 253 || !DNS_NAME.test(h)) return false;
  return !/^[0-9]+$/.test(h.slice(h.lastIndexOf(".") + 1));
}

// brandtext.go emailLocalRE.
const EMAIL_LOCAL = /^[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+)*$/;

/** The stored phone form: exactly 5 to 15 ASCII digits (separators were dropped on input). */
export function validPhone(v: string): boolean {
  return /^[0-9]{5,15}$/.test(v);
}

export function validEmail(v: string): boolean {
  if (v.length > BRAND_CONTACT_MAX) return false;
  const at = v.lastIndexOf("@");
  if (at < 1 || at > 64) return false;
  return EMAIL_LOCAL.test(v.slice(0, at)) && publicDnsName(v.slice(at + 1));
}

/** An https URL, validated and split for display ("the host prominent"). */
export interface UrlContact {
  /** What the link navigates to: the browser's own normalised form of the validated value. */
  href: string;
  /** The host, for emphasis. */
  host: string;
  /** Everything after the host as the server stored it (path, query), shown verbatim. */
  rest: string;
}

/**
 * Validates a contact URL and splits it, or returns null. Accepted: `https://` + a lowercase public DNS name
 * (at least two labels, no IP literal, no port, no user-info) + an optional path/query, at most 200 printable
 * ASCII characters, no space, no backslash, no fragment. This is the server's canonical value (a Go
 * `url.URL.String()` of a validated URL), so a value the server stored always passes; anything else is refused.
 */
export function urlContact(value: string): UrlContact | null {
  if (value.length > BRAND_CONTACT_MAX || !/^https:\/\/[\x21-\x7e]+$/.test(value) || value.includes("\\") || value.includes("#")) {
    return null;
  }
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return null;
  }
  const afterScheme = value.slice("https://".length);
  const cut = afterScheme.search(/[/?]/);
  const host = cut < 0 ? afterScheme : afterScheme.slice(0, cut);
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.port !== "" || u.hash !== "") return null;
  // The authority as written must BE the host the browser will connect to (no user-info, no port, no odd spelling).
  if (!publicDnsName(host) || u.hostname !== host) return null;
  return { href: u.href, host, rest: cut < 0 ? "" : afterScheme.slice(cut) };
}

/** `tel:` + digits for a valid phone, else null. */
export function phoneHref(value: string): string | null {
  return validPhone(value) ? `tel:${value}` : null;
}

/** Re-validates a contact (kind and value together). The one place the three kinds are decided. */
export function validContact(kind: string, value: string): boolean {
  switch (kind) {
    case "phone":
      return validPhone(value);
    case "email":
      return validEmail(value);
    case "url":
      return urlContact(value) !== null;
  }
  return false;
}

// ---- the response ---------------------------------------------------------------------------------------

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Turns a parsed response body into a brand, or the NEUTRAL brand. Total: it never throws and never returns
 * a brand that did not pass every check. The control plane's own neutral object (every field "") is the
 * neutral brand; a body that claims a brand but is inconsistent (no name, an invalid anything) is neutral too.
 */
export function parseHostBranding(body: unknown): HostBrand {
  if (!isPlainObject(body)) return NEUTRAL_BRAND;
  const { product_name, accent_color, logo_rev, support_text, support_contact } = body;
  if (typeof product_name !== "string" || typeof accent_color !== "string" || typeof logo_rev !== "string" ||
    typeof support_text !== "string" || !isPlainObject(support_contact)) {
    return NEUTRAL_BRAND;
  }
  const { kind, value } = support_contact;
  if (typeof kind !== "string" || typeof value !== "string") return NEUTRAL_BRAND;
  if (product_name === "" && accent_color === "" && logo_rev === "" && support_text === "" && kind === "" && value === "") {
    return NEUTRAL_BRAND;
  }
  // From here the response CLAIMS a brand. A published brand always has a name; anything else, or anything
  // failing, means none of it is applied.
  if (!validBrandName(product_name) || !validAccent(accent_color) || !validLogoRev(logo_rev) || !validSupportText(support_text)) {
    return NEUTRAL_BRAND;
  }
  let contact: BrandContact | null = null;
  if (kind !== "" || value !== "") {
    if (!validContact(kind, value)) return NEUTRAL_BRAND;
    contact = { kind: kind as BrandContactKind, value };
  }
  return { name: product_name, accent: accent_color, logoRev: logo_rev, supportText: support_text, contact };
}

// ---- where to ask ---------------------------------------------------------------------------------------

/**
 * The public branding route on the PAGE'S OWN origin, through the viewer's `/cp` prefix (Caddy strips it in
 * production, the Vite proxy in development; the same convention as `attendSupportModeUrl`).
 *
 * It must be the page's own origin and NOT `VITE_CONTROL_PLANE_URL`: the answer is keyed by the HOST of the
 * request, and an absolute control-plane URL on another host would be asked about that other host's brand.
 */
export function publicBrandingUrl(origin: string): string {
  return `${origin.replace(/\/+$/, "")}/cp/public/branding`;
}

/**
 * The logo's address: the published-hash route, built here from a validated 64-hex hash and nothing else.
 * "" when there is no valid hash (no logo). The server serves bytes only for the hash of the PUBLISHED
 * revision and answers anything else with the neutral JSON, which an `<img>` cannot decode (its error event
 * is the viewer's cue to show the neutral mark).
 */
export function publicBrandingLogoUrl(origin: string, rev: string): string {
  return rev !== "" && validLogoRev(rev) ? `${publicBrandingUrl(origin)}/logo?rev=${rev}` : "";
}

/**
 * Where a logo image may be loaded from. The join page passes the published-hash route (`publicBrandingLogoUrl`); a
 * console preview passes its draft as a `blob:` URL or a raster `data:` URI (the same png/jpeg/gif/webp the console
 * accepts). Anything else (`javascript:`, `data:text/html`, an SVG, another path, another query, a protocol-relative
 * URL) is not a logo address, and the component then shows the neutral mark. The check lives in the component too, so
 * no caller can hand it an address that did not come from one of these three constructions.
 */
export function validLogoSrc(src: string | undefined): src is string {
  if (!src || src.length > 250_000) return false;
  if (/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(src)) return true;
  if (/^blob:https?:\/\/[^/?#\s]+\/[0-9a-f-]{36}$/.test(src)) return true;
  return /^(https?:\/\/[^/?#\s]+)?\/cp\/public\/branding\/logo\?rev=[0-9a-f]{64}$/.test(src);
}

// ---- the lookup -----------------------------------------------------------------------------------------

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface HostBrandingOptions {
  /** Injected in tests. Defaults to the global fetch. */
  fetchFn?: FetchLike;
  timeoutMs?: number;
  /** Aborting it abandons the lookup (the component unmounted). The result is then NEUTRAL and must be ignored. */
  signal?: AbortSignal;
}

/**
 * ONE lookup, never a retry, never a rejection. Resolves to the brand the host publishes, or to NEUTRAL_BRAND
 * on anything else: any network error, HTTP status other than 200 (429, 421, 5xx, a redirect), an unreadable
 * or oversized or malformed body, an unexpected shape, an abort, or no complete answer within the timeout.
 *
 * The request carries no cookies and no referrer and does not touch the HTTP cache (the server answers
 * `Cache-Control: no-store`, and a revoked brand must stop appearing on the next load). The timeout is a
 * RACE, not just an abort signal: it settles the lookup even if the fetch implementation ignores the signal
 * or the body stalls after the headers.
 */
export function fetchHostBranding(origin: string, opts: HostBrandingOptions = {}): Promise<HostBrand> {
  const fetchFn: FetchLike = opts.fetchFn ?? ((input, init) => fetch(input, init));
  const timeoutMs = opts.timeoutMs ?? HOST_BRANDING_TIMEOUT_MS;
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;

  const lookup = (async (): Promise<HostBrand> => {
    const res = await fetchFn(publicBrandingUrl(origin), {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    if (res.status !== 200) {
      // An answer we ignore must not be left holding the connection.
      void res.body?.cancel().catch(() => undefined);
      return NEUTRAL_BRAND;
    }
    const text = await res.text();
    if (text.length > HOST_BRANDING_MAX_BODY) return NEUTRAL_BRAND;
    return parseHostBranding(JSON.parse(text));
  })().catch((): HostBrand => NEUTRAL_BRAND);

  const settled = new Promise<HostBrand>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve(NEUTRAL_BRAND);
    }, timeoutMs);
    if (opts.signal) {
      if (opts.signal.aborted) {
        controller.abort();
        resolve(NEUTRAL_BRAND);
      } else {
        onAbort = () => {
          controller.abort();
          resolve(NEUTRAL_BRAND);
        };
        opts.signal.addEventListener("abort", onAbort);
      }
    }
  });

  return Promise.race([lookup, settled]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
    if (opts.signal && onAbort) opts.signal.removeEventListener("abort", onAbort);
  });
}
