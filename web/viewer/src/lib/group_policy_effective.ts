/**
 * The EFFECTIVE session policy of a nested group (docs/62 D4 + R4 + R7), computed for DISPLAY only: the
 * editor shows an admin why a child is stricter than its own row. The control plane's `EffectivePolicy`
 * remains the authority and the only thing admission trusts.
 *
 * The merge is the STRICTEST along the ancestor-or-self chain (a child can tighten, never loosen):
 *   - view-only, block-recording, require-recording: OR;
 *   - max session duration / max idle: the smallest NON-ZERO value (0 = unlimited);
 *   - max concurrent sessions (R7): the smallest POSITIVE value, 0 = unlimited. (Enforcement counts each
 *     ancestor's own subtree; the displayed effective cap is just the minimum.)
 *   - "Under the Hood on view-only" is an opt-OUT of a restriction (R4): effective-true only when EVERY
 *     ancestor-or-self that ENFORCES view-only has it true. A dormant value on a row that is not view-only
 *     never becomes a restriction. (Meaningless, and not reported, when nothing enforces view-only.)
 *   - Block + require recording both in force is a CONFLICT: the control plane DENIES admission for it.
 *
 * Built only from groups the caller can see (a hidden ancestor's policy is not known here, and the
 * server's answer is the truth), via the shared tree helper.
 */

import type { GroupEffectivePolicy, GroupSessionCap, MachineGroup } from "./console_api";
import { groupTree, pathsFromRows } from "./group_tree";

export interface EffectivePolicy {
  viewOnly: boolean;
  /** Effective only meaningful when `viewOnly`; true = Under the Hood tools stay allowed. */
  allowBackstageUnderViewOnly: boolean;
  prohibitRecording: boolean;
  requireRecording: boolean;
  /** Seconds; 0 = unlimited. */
  maxDurationSeconds: number;
  maxIdleSeconds: number;
  /** 0 = unlimited. */
  maxConcurrentSessions: number;
  /** Require AND prohibit recording are both in force: sessions in this group are refused. */
  conflict: boolean;
  /** Paths of the groups (self or ancestors) that set each recording flag, for the conflict message. */
  requireRecordingFrom: readonly string[];
  prohibitRecordingFrom: readonly string[];
  /** Which settings are stricter than this group's OWN row because an ancestor sets them. */
  inherited: readonly InheritedSetting[];
  /** The control plane's own conflict reason, when this came from the server (it names no groups). */
  serverConflict?: string;
}

export type InheritedSetting =
  | "viewOnly"
  | "prohibitRecording"
  | "requireRecording"
  | "maxDuration"
  | "maxIdle"
  | "maxSessions"
  | "backstageOptOut";

const smallestNonZero = (values: readonly number[]): number => {
  const positive = values.filter((v) => Number.isFinite(v) && v > 0);
  return positive.length === 0 ? 0 : Math.min(...positive);
};

/**
 * The effective policy for `groupId`, or null when the group is not in the list. `policies` are the SET
 * rows (a group with no row is the all-default policy, which cannot loosen anything).
 */
export function effectivePolicyFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[],
  groupId: string,
): EffectivePolicy | null {
  const rows = groupTree(groups);
  const self = rows.find((r) => r.group.id === groupId);
  if (!self) return null;
  const paths = pathsFromRows(rows);
  const byGroup = new Map(policies.map((p) => [p.group_id, p]));
  const chainIds = [...self.ancestorIds, groupId];
  const chain = chainIds.map((id) => ({ id, p: byGroup.get(id) }));

  const own = byGroup.get(groupId);
  const withPolicy = chain.filter((c): c is { id: string; p: GroupSessionCap } => c.p !== undefined);

  const viewOnlyLevels = withPolicy.filter((c) => c.p.enforce_view_only === true);
  const viewOnly = viewOnlyLevels.length > 0;
  // Opt-out is true only if EVERY view-only-enforcing level allows it.
  const allowBackstage = viewOnly && viewOnlyLevels.every((c) => c.p.allow_backstage_under_view_only === true);
  const prohibitFrom = withPolicy.filter((c) => c.p.prohibit_recording === true).map((c) => paths.get(c.id) ?? c.id);
  const requireFrom = withPolicy.filter((c) => c.p.require_recording === true).map((c) => paths.get(c.id) ?? c.id);

  const maxDurationSeconds = smallestNonZero(withPolicy.map((c) => c.p.max_session_duration_seconds));
  const maxIdleSeconds = smallestNonZero(withPolicy.map((c) => c.p.max_idle_seconds));
  const maxConcurrentSessions = smallestNonZero(withPolicy.map((c) => c.p.max_concurrent_sessions));

  const inherited: InheritedSetting[] = [];
  const ancestorPolicies = withPolicy.filter((c) => c.id !== groupId);
  const ownViewOnly = own?.enforce_view_only === true;
  if (viewOnly && !ownViewOnly) inherited.push("viewOnly");
  if (prohibitFrom.length > 0 && own?.prohibit_recording !== true) inherited.push("prohibitRecording");
  if (requireFrom.length > 0 && own?.require_recording !== true) inherited.push("requireRecording");
  if (maxDurationSeconds > 0 && maxDurationSeconds !== (own?.max_session_duration_seconds ?? 0)) inherited.push("maxDuration");
  if (maxIdleSeconds > 0 && maxIdleSeconds !== (own?.max_idle_seconds ?? 0)) inherited.push("maxIdle");
  if (maxConcurrentSessions > 0 && maxConcurrentSessions !== (own?.max_concurrent_sessions ?? 0)) inherited.push("maxSessions");
  if (
    viewOnly &&
    !allowBackstage &&
    own?.allow_backstage_under_view_only === true &&
    ancestorPolicies.some((c) => c.p.enforce_view_only === true && c.p.allow_backstage_under_view_only !== true)
  ) {
    inherited.push("backstageOptOut");
  }

  return {
    viewOnly,
    allowBackstageUnderViewOnly: allowBackstage,
    prohibitRecording: prohibitFrom.length > 0,
    requireRecording: requireFrom.length > 0,
    maxDurationSeconds,
    maxIdleSeconds,
    maxConcurrentSessions,
    conflict: prohibitFrom.length > 0 && requireFrom.length > 0,
    requireRecordingFrom: requireFrom,
    prohibitRecordingFrom: prohibitFrom,
    inherited,
  };
}

const humanSeconds = (s: number): string => {
  if (s % 3600 === 0) return `${s / 3600} h`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
};

/** The effective values as short chips for the table cell: [{text, inherited}]. Empty = no restriction. */
export function effectivePolicyChips(e: EffectivePolicy): { text: string; inherited: boolean }[] {
  const inh = (k: InheritedSetting) => e.inherited.includes(k);
  const chips: { text: string; inherited: boolean }[] = [];
  if (e.viewOnly) {
    chips.push({ text: "View only", inherited: inh("viewOnly") });
    chips.push({
      text: e.allowBackstageUnderViewOnly ? "Under the Hood allowed" : "Under the Hood refused",
      inherited: inh("backstageOptOut"),
    });
  }
  if (e.prohibitRecording) chips.push({ text: "Recording blocked", inherited: inh("prohibitRecording") });
  if (e.requireRecording) chips.push({ text: "Recording required", inherited: inh("requireRecording") });
  if (e.maxDurationSeconds > 0) chips.push({ text: `Max ${humanSeconds(e.maxDurationSeconds)}`, inherited: inh("maxDuration") });
  if (e.maxIdleSeconds > 0) chips.push({ text: `Idle ${humanSeconds(e.maxIdleSeconds)}`, inherited: inh("maxIdle") });
  if (e.maxConcurrentSessions > 0) chips.push({ text: `${e.maxConcurrentSessions} sessions`, inherited: inh("maxSessions") });
  return chips;
}

/** The explicit conflict warning, or null. Names the groups that set each side so the admin can fix one. */
export function policyConflictMessage(e: EffectivePolicy): string | null {
  if (!e.conflict) return null;
  if (e.serverConflict) return `Conflict: ${e.serverConflict}.`;
  return (
    `Conflict: recording is both required (${e.requireRecordingFrom.join(", ")}) and blocked ` +
    `(${e.prohibitRecordingFrom.join(", ")}) for this group. New sessions here are refused until one of them is cleared.`
  );
}

/**
 * The effective policy as the CONTROL PLANE computed it (it sees ancestors this caller cannot), shaped like
 * {@link effectivePolicyFor}. `own` is the group's saved row, used only to mark which values are inherited
 * (stricter than its own row).
 */
export function effectivePolicyFromServer(server: GroupEffectivePolicy, own: GroupSessionCap | undefined): EffectivePolicy {
  const viewOnly = server.enforce_view_only === true;
  const allowBackstage = viewOnly && server.allow_backstage_under_view_only === true;
  const prohibit = server.prohibit_recording === true;
  const require = server.require_recording === true;
  const dur = server.max_session_duration_seconds ?? 0;
  const idle = server.max_idle_seconds ?? 0;
  const seats = server.max_concurrent_sessions ?? 0;
  const inherited: InheritedSetting[] = [];
  if (viewOnly && own?.enforce_view_only !== true) inherited.push("viewOnly");
  if (prohibit && own?.prohibit_recording !== true) inherited.push("prohibitRecording");
  if (require && own?.require_recording !== true) inherited.push("requireRecording");
  if (dur > 0 && dur !== (own?.max_session_duration_seconds ?? 0)) inherited.push("maxDuration");
  if (idle > 0 && idle !== (own?.max_idle_seconds ?? 0)) inherited.push("maxIdle");
  if (seats > 0 && seats !== (own?.max_concurrent_sessions ?? 0)) inherited.push("maxSessions");
  if (viewOnly && !allowBackstage && own?.allow_backstage_under_view_only === true) inherited.push("backstageOptOut");
  const conflict = typeof server.conflict === "string" && server.conflict !== "";
  return {
    viewOnly,
    allowBackstageUnderViewOnly: allowBackstage,
    prohibitRecording: prohibit,
    requireRecording: require,
    maxDurationSeconds: dur,
    maxIdleSeconds: idle,
    maxConcurrentSessions: seats,
    conflict,
    requireRecordingFrom: [],
    prohibitRecordingFrom: [],
    inherited,
    ...(conflict ? { serverConflict: server.conflict as string } : {}),
  };
}
