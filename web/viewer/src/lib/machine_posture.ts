export type PolicyPosture = "enforced" | "not_enforced" | "unknown";

export interface PostureInput {
  grant_key_pinned?: boolean;
  session_policy_required?: boolean;
}

/**
 * The agent's SELF-REPORTED enforcement posture (audit #9). Three states, never two:
 *  - "not_enforced": the agent reports no pinned grant issuer key, OR reports session policy is not
 *    required. A pinned key alone does not make policy mandatory.
 *  - "enforced": the agent reports BOTH a pinned key and require_session_policy.
 *  - "unknown": nothing (offline, or an older agent without posture reporting). Silence is not trust.
 * All of it is agent-asserted inventory: a compromised agent can lie, so nothing authorizes on it.
 */
export function policyPosture(m: PostureInput): PolicyPosture {
  if (m.grant_key_pinned === false || m.session_policy_required === false) return "not_enforced";
  if (m.grant_key_pinned === true && m.session_policy_required === true) return "enforced";
  return "unknown";
}

export interface PostureBadge {
  state: PolicyPosture;
  label: string;
  title: string;
}

export function policyPostureBadge(m: PostureInput): PostureBadge {
  const state = policyPosture(m);
  switch (state) {
    case "not_enforced":
      return {
        state,
        label: "policy not enforced",
        title:
          "Reported by the agent: no pinned grant issuer key, or session policy is not required. " +
          "The group's view-only mandate, session lease and signed grants are advisory on this machine. " +
          "Re-provision it with the grant issuer key and require_session_policy.",
      };
    case "enforced":
      return {
        state,
        label: "policy enforced",
        title:
          "Self-reported by the agent: grant issuer key pinned and session policy required. " +
          "Agent-asserted; not independently verified by the server.",
      };
    default:
      return {
        state,
        label: "policy unknown",
        title:
          "The agent has not reported its enforcement posture (offline, or an older agent). " +
          "Do not assume the group's view-only mandate is enforced on this machine.",
      };
  }
}
