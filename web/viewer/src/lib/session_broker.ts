/**
 * Brokered-session flow (M2 / ADR-002).
 *
 * The secured connect path: `POST /sessions` FIRST (via {@link ConsoleApi.startBrokeredSession}),
 * then dial the RETURNED `signaling.url` and present the signed session ticket in
 * `connect_request` — the signaling server verifies it against the control plane's issuer key
 * before brokering. On teardown, `POST /sessions/{id}/end` is fired best-effort.
 *
 * Fallback is deliberate: when the control plane is unreachable (or start is denied, or the
 * response carries no signaling envelope), {@link acquireBrokeredSession} resolves `null` and the
 * caller keeps today's direct-connect behavior (operator-entered signaling URL, no ticket) — the
 * dev flow and Playwright specs stay valid. A dev-mode signaling server (no
 * `SIGNALING_TICKET_PUBKEY`) accepts both shapes.
 */

import { ConsoleApiError } from "./console_api";
import type { ConsoleApi, SessionAccessPolicy, SessionSignaling } from "./console_api";

/** A control-plane-brokered session: the record id (for the end call) + signaling coordinates. */
export interface BrokeredSession {
  sessionId: string;
  signaling: SessionSignaling;
  /** The signed session ACCESS policy to install on the agent once the Control channel opens
   *  (loops 79/80). Absent when the control plane minted none. */
  sessionPolicy?: SessionAccessPolicy;
  /** An ordinary control-plane session this console already holds (a session transfer's S2, docs/51):
   *  owned exactly like one from `POST /sessions`, so it is renewed, ended on teardown and recovered.
   *  Absent = the ATTENDED hand-off, whose record the console deliberately does not own. */
  owned?: boolean;
}

/**
 * Start a control-plane session for `deviceId`. Resolves the brokered coordinates, or `null`
 * when the control plane is unreachable or carries no signaling envelope (dev/direct-connect
 * fallback). Throws {@link DeviceAccessDeniedError} when the control plane explicitly denies
 * access (403 Forbidden) — the caller must surface this as a visible refusal, not fall through
 * to direct-connect, because the user IS authenticated but NOT authorized for this device.
 *
 * `devMode` defaults to the Vite build flag (`import.meta.env.DEV`). Pass an explicit value in
 * unit tests to exercise the production path without a production build.
 */
export async function acquireBrokeredSession(
  api: Pick<ConsoleApi, "startBrokeredSession">,
  deviceId: string,
  devMode = import.meta.env.DEV,
  opts?: { access?: "view_only" },
): Promise<BrokeredSession | null> {
  try {
    const started = opts?.access
      ? await api.startBrokeredSession(deviceId, undefined, opts)
      : await api.startBrokeredSession(deviceId);
    if (!started.signaling) {
      // Dev/test: CP has no issuer configured — fall through to direct-connect.
      // Production: a missing signaling envelope is unexpected and must be surfaced immediately;
      // a silent ticketless fallback would fail at the signaling layer anyway.
      if (devMode && !opts?.access) return null;
      throw new ConsoleApiError(200, 'could not start session: CP returned no signaling envelope', 'server');
    }
    return {
      sessionId: started.session.id,
      signaling: started.signaling,
      sessionPolicy: started.session_policy,
    };
  } catch (e) {
    // 403 Forbidden: authenticated but NOT authorized for this specific device (cross-tenant,
    // group policy, RBAC). Propagate so the caller shows a visible device-refusal error rather
    // than silently falling back to a ticketless direct-connect — on a production signaling
    // server (SIGNALING_TICKET_PUBKEY set) the fallback would also fail at the signaling layer,
    // but the viewer must fail-closed and communicate the reason immediately.
    if (e instanceof ConsoleApiError && e.kind === "forbidden") throw e;
    // All other failures (network unreachable, 5xx, missing signaling envelope):
    // Dev/test: fall back to direct-connect so the local harness and Playwright specs keep working
    // (the local signaling server accepts ticketless connections with -insecure-no-ticket-verification).
    // Production: surface the failure immediately — a ticketless connect would be rejected by a
    // production signaling server anyway, so an explicit error is strictly better.
    if (devMode && !opts?.access) return null;
    throw e;
  }
}

/** Check whether an error is an explicit device-access denial (403 from POST /sessions). */
export function isDeviceAccessDenied(e: unknown): e is ConsoleApiError {
  return e instanceof ConsoleApiError && e.kind === "forbidden";
}

/**
 * Best-effort session end on teardown/disconnect: fire `POST /sessions/{id}/end` and swallow any
 * failure (the control plane may be gone; disconnecting must never throw). No-op without an id.
 */
export function releaseBrokeredSession(
  api: Pick<ConsoleApi, "endSession">,
  sessionId: string | null | undefined,
): void {
  if (!sessionId) return;
  void api.endSession(sessionId).catch(() => {});
}
