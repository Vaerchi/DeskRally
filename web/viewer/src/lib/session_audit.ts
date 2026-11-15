import { AuditForwarder } from "./audit_forward";
import type { ConsoleApi } from "./console_api";

/**
 * The session id the audit forwarder must be keyed on for a connection.
 *
 * Extracted and exported for ONE reason: `handleConnect` lives in a `.tsx`, which the vitest config
 * does not collect, and this decision is the single point where the whole trail can be silently
 * lost. It is `brokered?.sessionId` — the id signaling will vouch for and the agent will stamp into
 * every event — and NOT `brokeredSessionRef`, which is deliberately null on the attended path to
 * stop teardown ending a session record it does not own.
 *
 * `null` for a direct-connect/dev session, which has no control-plane session record: the agent
 * seals nothing there either, so both sides agree there is no central trail.
 */
export function auditSessionIdFor(brokered: { sessionId: string } | null | undefined): string | null {
  return brokered?.sessionId ?? null;
}

export function makeAuditForwarder(api: ConsoleApi, sessionId: string | null, onError?: (error: Error) => void): AuditForwarder | null {
  if (!sessionId) return null;
  return new AuditForwarder(null, async (_endpoint, body, opts) => {
    const res = await api.ingestAudit({ session_id: body.session_id, events: body.events }, opts);
    return { accepted: res.accepted, tail_seq: res.tail_seq, tail_hash: res.tail_hash };
  }, { onError });
}
