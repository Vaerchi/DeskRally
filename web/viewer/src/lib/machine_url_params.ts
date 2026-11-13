/**
 * URL parameter helpers for multi-machine support.
 *
 * A technician can open a machine in a new browser tab by navigating to
 * `?device=<uuid>&name=<encoded-name>&signaling=<encoded-url>`. The new tab's
 * App reads these params on mount (after auth) and auto-connects.
 *
 * The signaling param is optional: the app derives it from the page origin when absent
 * (production), so a new-tab link on a same-origin deployment needs only `device` and `name`.
 *
 * Security: the `?signaling=` param is validated against the expected host derived from the
 * page location. An externally-crafted link cannot redirect the viewer's WebSocket connection
 * to a third-party server that could observe connection metadata or session ticket content.
 * Invalid values are silently replaced with the safe per-location default.
 */

import { defaultSignalingUrl } from "./default_signaling_url";

export interface MachineUrlParams {
  /** Raw UUID string for the machine's device id. */
  device: string;
  /** Human-readable label for the machine (alias or hostname). */
  name: string;
  /** WebSocket URL to use for signaling. */
  signalingUrl: string;
  /** `?observe=1`: join view-only (an invite to watch). The control plane still decides access. */
  observe: boolean;
}

/**
 * Validate that `raw` is a WebSocket URL whose host matches the host of `defaultUrl`.
 * Returns `raw` if valid, `null` if the URL is malformed, uses a non-WebSocket scheme, or
 * points to a different host than the derived default.
 *
 * This prevents an externally-crafted `?signaling=wss://evil.example.com/ws` from routing
 * the viewer's connection to an attacker-controlled server.
 */
function validateSignalingUrl(raw: string | null, defaultUrl: string): string | null {
  if (!raw) return null;
  try {
    const given = new URL(raw);
    const expected = new URL(defaultUrl);
    if (given.protocol !== "ws:" && given.protocol !== "wss:") return null;
    if (given.host !== expected.host) return null;
    return raw;
  } catch {
    return null;
  }
}

/**
 * Parse `?device=`, `?name=`, `?signaling=` from a query string.
 * Returns `null` when no `device` param is present.
 * `location` is used to derive a default signaling URL when the param is absent or invalid.
 * The `?signaling=` param is validated against the expected host; invalid values are ignored.
 */
export function parseMachineUrlParams(
  search: string,
  location: { protocol: string; hostname: string; host: string },
): MachineUrlParams | null {
  const params = new URLSearchParams(search);
  const device = params.get("device");
  // A device id is a UUID; anything else is not a link this app produced.
  if (!device || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(device)) return null;
  const name = params.get("name") ?? `agent ${device.slice(0, 8)}`;
  const defaultUrl = defaultSignalingUrl(location);
  const signalingUrl = validateSignalingUrl(params.get("signaling"), defaultUrl) ?? defaultUrl;
  return { device, name, signalingUrl, observe: params.get("observe") === "1" };
}

/**
 * Build a same-page URL that auto-connects to `device` when opened in a new tab.
 * `pageOrigin` is `window.location.origin` on the current page.
 * The signaling URL is always included so the new tab uses the same endpoint even if its
 * location would derive a different default (e.g. during local dev with Vite).
 */
export function machineNewTabUrl(
  device: string,
  name: string,
  signalingUrl: string,
  pageOrigin: string,
): string {
  // Target /console so that if auth is required the technician login form
  // renders (not the customer-facing JoinPage rendered at the root path).
  // Device params are preserved; after login the same auto-connect effect fires.
  const url = new URL("/console", pageOrigin);
  url.searchParams.set("device", device);
  url.searchParams.set("name", name);
  url.searchParams.set("signaling", signalingUrl);
  return url.toString();
}

/**
 * The link a technician copies to invite a colleague into the machine they are on (docs/01 §7 P1).
 *
 * It is a POINTER, not a credential: the colleague signs in as themselves and the control plane
 * applies THEIR access to this machine, exactly as if they had picked it from their own list. So the
 * link carries only the device and, for an invite to watch, `observe=1`. No name (the console never
 * trusts a link's name) and no signaling URL (the recipient's page derives its own).
 */
export function machineInviteUrl(device: string, pageOrigin: string, observe: boolean): string {
  const url = new URL("/console", pageOrigin);
  url.searchParams.set("device", device);
  if (observe) url.searchParams.set("observe", "1");
  return url.toString();
}
