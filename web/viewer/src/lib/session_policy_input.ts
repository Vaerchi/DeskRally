/**
 * Client-side check of the tenant session-policy form, mirroring the server's NormalizeSessionPolicy
 * bounds (control-plane/tenant_session_policy.go) so an administrator gets a field-specific message
 * before any request is sent. The server stays the authority; this only rejects what it would refuse.
 * Pure: empty or malformed input is an error, never coerced to 0 (= unlimited).
 */

export const MAX_SESSION_LIMIT = 100000;
export const MIN_SESSION_SECONDS = 60;
export const MAX_SESSION_SECONDS_CEILING = 2592000;

export interface SessionPolicyInput {
  max_concurrent_sessions: number;
  max_session_seconds: number;
}

export type SessionPolicyParse = { ok: true; value: SessionPolicyInput } | { ok: false; error: string };

const LIMIT_FIELD = "max_concurrent_sessions";
const AGE_FIELD = "max_session_seconds";

/** Trimmed, ASCII-digit-only, safe-integer parse; null when the text is not such a number. */
function parseWhole(text: string): number | null {
  const t = text.trim();
  if (!/^[0-9]+$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}

export function parseSessionPolicyInput(limitText: string, maxAgeText: string): SessionPolicyParse {
  const limit = parseWhole(limitText);
  if (limit === null || limit > MAX_SESSION_LIMIT) {
    return {
      ok: false,
      error: `${LIMIT_FIELD} must be a whole number from 0 to ${MAX_SESSION_LIMIT} (0 = no limit)`,
    };
  }
  const age = parseWhole(maxAgeText);
  if (age === null || (age !== 0 && (age < MIN_SESSION_SECONDS || age > MAX_SESSION_SECONDS_CEILING))) {
    return {
      ok: false,
      error: `${AGE_FIELD} must be a whole number of seconds: 0 (no limit) or ${MIN_SESSION_SECONDS} to ${MAX_SESSION_SECONDS_CEILING}`,
    };
  }
  if (limit > 0 && age === 0) {
    return {
      ok: false,
      error: `Set ${AGE_FIELD} (${MIN_SESSION_SECONDS} to ${MAX_SESSION_SECONDS_CEILING}) before enabling a ${LIMIT_FIELD} limit, so abandoned sessions expire.`,
    };
  }
  return { ok: true, value: { max_concurrent_sessions: limit, max_session_seconds: age } };
}
