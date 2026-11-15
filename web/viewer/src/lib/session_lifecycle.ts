/**
 * What a TRANSPORT state change means for the control-plane session record.
 *
 * # Why this is a module and not three lines in `App.tsx`
 *
 * Because three lines in `App.tsx` is where the bug lived. `onStateChange` was `setState` and
 * nothing else, so a dead transport repainted a status label and left the session running in the
 * control plane — the console kept renewing its lease every 10 s against an agent that was gone,
 * and the next connect to that machine hung on "connecting" behind a session record that would
 * never end. Nothing in the suite could see that, because the decision was a closure over live
 * refs. It is a truth table, so it is written as one. Same reasoning as `SessionLeaseRenewer`.
 */

import type { ConnectionState } from "./transport";

/** The two things releasing a session actually does. Injected so the decision is testable. */
export interface SessionReleaseActions {
  /** Stop renewing the lease: there is no agent left to install a policy on. */
  stopRenewing: () => void;
  /** `POST /sessions/{id}/end` — so the machine is connectable again. */
  release: () => void;
}

/**
 * Is this connection state TERMINAL — the session is over and will not recover?
 *
 * **`disconnected` is not terminal, and that is the load-bearing half.** WebRTC uses it for a
 * transient loss of ICE connectivity, which recovers routinely on a laptop changing networks or a
 * momentary blip; releasing the session there would end a live session over nothing — a worse bug
 * than the zombie this exists to prevent. A connection that is genuinely dead is promoted to
 * `failed` by the browser itself, and that is what this keys on.
 */
export function isTerminalConnectionState(state: ConnectionState): boolean {
  return state === "failed";
}

/**
 * Release the control-plane session if — and only if — `state` is terminal.
 *
 * Returns whether it released, so a caller can tell the operator what happened.
 */
export function releaseSessionOnTerminalTransport(
  state: ConnectionState,
  actions: SessionReleaseActions,
): boolean {
  if (!isTerminalConnectionState(state)) return false;
  actions.stopRenewing();
  actions.release();
  return true;
}
