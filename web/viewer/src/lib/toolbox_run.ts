/**
 * Running a saved toolbox script in a session (docs/design-shared-toolbox.md), as a pure step so its
 * ordering is unit-tested: the control plane authorizes the run against the held session and commits
 * the audit record FIRST, returning the exact command; only then, and only if the session is still the
 * one it was requested for, is that command sent as an ordinary RunCommand. Any refusal sends nothing.
 */

import type { ConsoleApi, ToolboxItem } from "./console_api";
import type { CommandShell } from "./control";

export interface ToolboxRunDeps {
  api: Pick<ConsoleApi, "requestToolboxRun">;
  /** The control-plane session id of the CURRENT connection, or null. Read again after the await. */
  currentSessionId: () => string | null;
  /** Send `RunCommand` to the current agent. */
  sendRunCommand: (command: string, shell: CommandShell, asUser: boolean) => void;
  /** Is THIS run still the command panel's current operation (no newer command, same connection)?
   *  Checked after the await: a superseded run neither sends nor reports, so it can never touch the
   *  pending state or error line of a later command or session. */
  isCurrent: () => boolean;
}

/** `stale`: superseded while in flight; the caller must leave the UI alone. */
export type ToolboxRunOutcome =
  | { sent: true; requestId: string }
  | { sent: false; stale: false; error: string }
  | { sent: false; stale: true };

export async function runToolboxScript(item: ToolboxItem, deps: ToolboxRunDeps): Promise<ToolboxRunOutcome> {
  const sessionId = deps.currentSessionId();
  if (!sessionId) {
    return { sent: false, stale: false, error: "This session has no control-plane record, so a saved script cannot run." };
  }
  let grant;
  try {
    grant = await deps.api.requestToolboxRun(item.id, sessionId, item.version);
  } catch (e) {
    if (!deps.isCurrent()) return { sent: false, stale: true };
    return { sent: false, stale: false, error: e instanceof Error ? e.message : String(e) };
  }
  if (!deps.isCurrent()) return { sent: false, stale: true };
  // The operator may have disconnected or moved to another machine while the request was in flight;
  // the script must never reach a different machine's agent.
  if (deps.currentSessionId() !== sessionId) {
    return { sent: false, stale: false, error: "The session changed while the script was being authorized; nothing ran." };
  }
  deps.sendRunCommand(grant.command, grant.shell === "cmd" ? "Cmd" : "PowerShell", grant.run_as === "user");
  return { sent: true, requestId: grant.request_id };
}
