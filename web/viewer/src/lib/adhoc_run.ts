/**
 * Running an AD-HOC command in a session — the sibling of toolbox_run.ts for a command the operator
 * typed rather than a saved item. The control plane authorizes the run against the held session and
 * commits the audit record FIRST (POST /sessions/{id}/command-run), returning the exact command text;
 * only then, and only if the session is still the one it was requested for, is that command sent as an
 * ordinary RunCommand. Any refusal sends nothing.
 *
 * Kept a pure step (like runToolboxScript) so its ORDERING is unit-tested: authorize-then-send, and a
 * superseded run neither sends nor reports.
 */

import type { ConsoleApi, ToolboxRunAs, ToolboxShell } from "./console_api";
import type { CommandShell } from "./control";
import type { ToolboxRunOutcome } from "./toolbox_run";

export interface AdhocCommandSpec {
  shell: ToolboxShell;
  runAs: ToolboxRunAs;
  /** The raw command the operator typed: a cmd line or a PowerShell script. */
  body: string;
}

export interface AdhocRunDeps {
  api: Pick<ConsoleApi, "requestCommandRun">;
  /** The control-plane session id of the CURRENT connection, or null. Read again after the await. */
  currentSessionId: () => string | null;
  /** Send `RunCommand` to the current agent. */
  sendRunCommand: (command: string, shell: CommandShell, asUser: boolean) => void;
  /** Is THIS run still the current operation (no newer command, same connection)? Checked after the
   *  await: a superseded run neither sends nor reports. */
  isCurrent: () => boolean;
}

export async function runAdhocCommand(spec: AdhocCommandSpec, deps: AdhocRunDeps): Promise<ToolboxRunOutcome> {
  const sessionId = deps.currentSessionId();
  if (!sessionId) {
    return { sent: false, stale: false, error: "This session has no control-plane record, so a command cannot run." };
  }
  let grant;
  try {
    grant = await deps.api.requestCommandRun(sessionId, spec.shell, spec.runAs, spec.body);
  } catch (e) {
    if (!deps.isCurrent()) return { sent: false, stale: true };
    return { sent: false, stale: false, error: e instanceof Error ? e.message : String(e) };
  }
  if (!deps.isCurrent()) return { sent: false, stale: true };
  // The operator may have disconnected or moved to another machine while the request was in flight;
  // the command must never reach a different machine's agent.
  if (deps.currentSessionId() !== sessionId) {
    return { sent: false, stale: false, error: "The session changed while the command was being authorized; nothing ran." };
  }
  deps.sendRunCommand(grant.command, grant.shell === "cmd" ? "Cmd" : "PowerShell", grant.run_as === "user");
  return { sent: true, requestId: grant.request_id };
}
