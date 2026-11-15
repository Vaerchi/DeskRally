/**
 * Whether -- and to what -- the `/join` page may offer a one-click Windows download.
 *
 * This is the pure core of the download block (docs/27 step 16, docs/28 section 4). It lives in
 * `lib/` and not in `JoinPage.tsx` for the reason `attend_link.ts` already gives: vitest globs
 * `src/**\/*.test.ts` only, so logic left in a `.tsx` render body gets NO unit coverage -- and
 * `JoinPage` is the live counter-example this module exists to stop repeating.
 *
 * # The one security property
 *
 * {@link supportDownloadUrl} returns `null` unless the configured value is a **same-origin absolute
 * path** -- one leading `/`, never `//` (protocol-relative, i.e. another host), never a scheme. A
 * public page cannot verify a cross-origin binary and must never hand a guest a download link to a
 * host a fat-fingered (or tampered) deploy variable happened to name. Fail closed: a value that is
 * not unambiguously same-origin yields no download at all, which the page renders as "unavailable"
 * rather than as a link somewhere else.
 *
 * # What "ready" does and does not mean
 *
 * `ready` means the URL is well-shaped and same-origin and the platform can run it. It is NOT
 * evidence that the artifact EXISTS at that path, that it is signed, or that its hash matches -- that
 * is what `scripts/verify-download.ps1` (step 18) proves against the live deployment before
 * `VITE_SUPPORT_DOWNLOAD_URL` is ever set. Until that guard has passed, the variable stays unset,
 * this returns `unavailable`, and the block does not render -- so the shipped page offers no download
 * by default.
 */

/** Build-time download configuration, from `import.meta.env` (see `main.tsx`). */
export interface SupportDownloadConfig {
  /** `VITE_SUPPORT_DOWNLOAD_URL`: a SAME-ORIGIN absolute path, or unset. */
  url?: string;
  /**
   * `VITE_SUPPORT_DOWNLOAD_SHA256`: the SHA-256 `verify-download.ps1` baked from the artifact it
   * published. Shown for read-back ONLY when present -- the page must never show a hash it cannot
   * stand behind (docs/27 "what the page may NOT claim").
   */
  sha256?: string;
}

/** The visitor's OS, as far as the user-agent reveals it. */
export type Platform = "windows" | "other" | "unknown";

/** The resolved download decision the page renders. */
export type SupportDownloadState =
  | { kind: "ready"; url: string; sha256: string | null }
  | { kind: "unavailable" }
  | { kind: "unsupported-platform" };

/** True if the string contains any ASCII control character (C0 range or DEL). */
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x1f || c === 0x7f) return true;
  }
  return false;
}

/**
 * The validated same-origin download path, or `null`.
 *
 * Accepts ONLY an absolute same-origin path: exactly one leading `/`, no `//`, no scheme, no
 * backslash, no whitespace, no control characters. Everything else -- a full `https://...` URL, a
 * protocol-relative `//host/...`, a bare relative `download/x.exe`, anything with a `:` -- is
 * rejected.
 */
export function supportDownloadUrl(rawUrl: string | undefined): string | null {
  if (typeof rawUrl !== "string") return null;
  const url = rawUrl.trim();
  if (url === "") return null;
  // Must be an absolute path on THIS origin.
  if (!url.startsWith("/")) return null; // relative ('download/x') or schemed ('https://...')
  if (url.startsWith("//")) return null; // protocol-relative -> a different host
  // Defence in depth: a scheme separator, a Windows-style backslash, whitespace, or any control
  // character has no business in a same-origin path and is a sign the value is not what we think.
  if (url.includes(":")) return null;
  if (url.includes("\\")) return null;
  if (/\s/.test(url)) return null;
  if (hasControlChar(url)) return null;
  return url;
}

/**
 * The visitor's platform from a user-agent string. `unknown` when the UA is absent or unrecognised
 * -- treated as "might be Windows" by {@link resolveSupportDownload}, so an odd UA never hides a
 * real download; the copy still states the client is Windows-only.
 */
export function detectPlatform(userAgent: string | undefined): Platform {
  if (typeof userAgent !== "string" || userAgent.trim() === "") return "unknown";
  const ua = userAgent.toLowerCase();
  if (ua.includes("windows")) return "windows";
  if (/(mac os x|macintosh|iphone|ipad|android|linux|cros)/.test(ua)) return "other";
  return "unknown";
}

/**
 * Resolve the download state from build-time config and the visitor's platform.
 *
 * `unavailable` when no valid same-origin URL is configured (the default, and any rejected value).
 * `unsupported-platform` on a clearly non-Windows visitor. `ready` otherwise -- carrying the hash
 * for read-back only when one was baked.
 */
export function resolveSupportDownload(
  config: SupportDownloadConfig,
  platform: Platform,
): SupportDownloadState {
  const url = supportDownloadUrl(config.url);
  if (url === null) return { kind: "unavailable" };
  if (platform === "other") return { kind: "unsupported-platform" };
  const sha =
    typeof config.sha256 === "string" && config.sha256.trim() !== "" ? config.sha256.trim() : null;
  return { kind: "ready", url, sha256: sha };
}
