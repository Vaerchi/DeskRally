import { isInputControlError } from "./input_handoff";
import { isDisplayLayoutEnd } from "./layout_reconnect";

/**
 * Where a control-channel `Error` from the agent belongs. The agent has one `Error` reply for many
 * different situations, and the console must not treat them alike:
 *
 * - `input-control`: a refusal of a pending input hand-off (docs/61, stable "input control: " prefix).
 *   It changes no ownership state and is not a session error.
 * - `session-ended`: the agent ended the session (host.rs lease lapse and similar, exact
 *   "session ended:" prefix). `layoutChange` marks the display-layout end, which the console may
 *   reconnect from automatically (within its budget).
 * - `policy-rejected`: a signed session-policy install was in flight, so the error is its verdict:
 *   the agent could not verify the policy and has floored the session. That is a security fact the
 *   operator reads differently from "that command did not run", so it is not a command failure.
 * - `command`: everything else, the answer to whatever request was outstanding (a command, a
 *   screenshot, a recording start/stop, a directory listing).
 *
 * The order matters: a hand refusal and a session end are recognised by their text before the
 * pending policy install claims an error, so neither can be mistaken for the policy's verdict.
 */
export type AgentErrorRoute =
  | { kind: "input-control" }
  | { kind: "session-ended"; layoutChange: boolean }
  | { kind: "policy-rejected" }
  | { kind: "command" };

export function routeAgentError(message: string, policyInstallPending: boolean): AgentErrorRoute {
  if (isInputControlError(message)) return { kind: "input-control" };
  if (message.startsWith("session ended:")) return { kind: "session-ended", layoutChange: isDisplayLayoutEnd(message) };
  if (policyInstallPending) return { kind: "policy-rejected" };
  return { kind: "command" };
}

/** Allow only the agent's lease-lapse reason to enter background recovery. */
export function isRecoverableAgentEnd(message: string): boolean {
  return /^session ended: (?:the control-plane session lease expired and was not renewed|(?:the )?lease (?:lapsed|expired))[.!]?$/.test(message);
}
