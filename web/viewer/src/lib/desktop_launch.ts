export type DesktopTarget = { kind: "connect" | "attended"; id: string };
export const DESKTOP_PREFERENCE_KEY = "deskrally.connect-target";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// One DNS label directly under the DeskRally zone, https on the default port only. The
// desktop client accepts the same grammar (clients/windows/client_policy.h), and the
// control plane refuses the same reserved names as tenant slugs (control-plane/tenantslug.go).
const TENANT_ORIGIN = /^https:\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.deskrally\.com$/;
const RESERVED_SLUGS = new Set([
  "www", "turn", "stun", "api", "app", "admin", "download", "downloads",
  "update", "updates", "updater", "mail", "status", "relay", "signal", "signaling",
]);
// Clients older than this reject tenant/<slug>/ links for any tenant other than main and loam.
export const DESKTOP_ANY_TENANT_VERSION = "0.6.0";
export function tenantFromOrigin(origin: string): string | null {
  const slug = TENANT_ORIGIN.exec(origin)?.[1];
  return slug && !RESERVED_SLUGS.has(slug) ? slug : null;
}
export function desktopLink(target: DesktopTarget, origin: string): string | null {
  // Pass only a tenant slug taken from this page's own origin and a validated ID, never an
  // arbitrary URL or credentials. The main tenant keeps the legacy form every client version accepts.
  const slug = tenantFromOrigin(origin);
  if (!slug) return null;
  if (target.kind !== "connect" && target.kind !== "attended") return null;
  if (target.id.length !== 36 || !UUID.test(target.id)) return null;
  const prefix = slug === "main" ? "" : `tenant/${slug}/`;
  return `deskrally-client://${prefix}${target.kind}/${target.id.toLowerCase()}`;
}
// The minimum app version to name when a launch from this origin may not open, or null.
export function desktopMinVersion(origin: string): string | null {
  const slug = tenantFromOrigin(origin);
  return slug && slug !== "main" ? DESKTOP_ANY_TENANT_VERSION : null;
}
export function isDesktopClient(userAgent: string): boolean {
  return /\bDeskRallyDesktop\/[0-9.]+\b/.test(userAgent);
}
/**
 * A desktop app that can NOT complete Microsoft sign-in in its own window: every desktop app before
 * 0.8.0. From 0.8.0 the app advertises `DeskRallySSO/1`, once its navigation policy admits the Entra
 * sign-in flow (client-sso design v2.1). A UI capability hint only, never an authorization signal.
 */
export function desktopClientLacksSso(userAgent: string): boolean {
  return isDesktopClient(userAgent) && !/(?:^|\s)DeskRallySSO\/1(?:\s|$)/.test(userAgent);
}
/**
 * A desktop app that shows its clipboard consent dialog on EVERY read: every app before 0.8.3. Those
 * apps never let WebView2 keep an answer, so automatic send (a read on each press into the remote
 * screen) would raise the dialog on every click. From 0.8.3 the app remembers the answer for the run
 * and advertises `DeskRallyClipAuto/1`. A UI capability hint only, never an authorization signal.
 */
export function desktopClientPromptsEveryClipboardRead(userAgent: string): boolean {
  return isDesktopClient(userAgent) && !/(?:^|\s)DeskRallyClipAuto\/1(?:\s|$)/.test(userAgent);
}
/**
 * Whether Connect should open the desktop app. A saved choice always wins. Without one, Windows defaults to the app
 * ONLY where a desktop link can exist: `origin` is this page's origin, and desktopLink accepts only a tenant origin
 * under the DeskRally zone. On any other server (a self-hosted domain) the default is the browser: defaulting there
 * to the app made every technician's first Connect fail with "cannot open in the desktop app" (server-install
 * acceptance, 2026-11-10). An explicit "Desktop app" choice on such a site still gets that message, never a launch.
 */
export function defaultDesktopPreference(saved: string | null, userAgent: string, origin: string): boolean {
  if (saved === "browser") return false;
  if (saved === "desktop") return true;
  if (!tenantFromOrigin(origin)) return false;
  return /Windows/i.test(userAgent) && !isDesktopClient(userAgent);
}
export function attendedLaunchId(search: string): string | null {
  const id = new URLSearchParams(search).get("attended");
  return id && id.length === 36 && UUID.test(id) ? id : null;
}
