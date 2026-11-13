/**
 * Static machine groups (docs/01 §4): create + list the `machine_group` rows that are the RBAC SCOPE
 * unit and the container a machine belongs to (its `group_id`). Labelled "Machine groups" in the console. Distinct from the "Smart groups" tab, which
 * manages DYNAMIC groups (saved property predicates).
 *
 * Creating needs CapManageGroups (Owner/Admin); listing needs CapViewMachines (the server gates both).
 * The listing shows each group's id so an operator can copy it into the Deploy tab when minting an
 * enrollment token for that group. Thin like the other console panels — load/refresh/in-flight state only.
 */

import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { ConsoleApi, GroupEffectivePolicy, GroupSessionCap, MachineGroup } from "../lib/console_api";
import {
  effectivePolicyChips,
  effectivePolicyFor,
  effectivePolicyFromServer,
  policyConflictMessage,
  type EffectivePolicy,
} from "../lib/group_policy_effective";
import { filterGroupTree, groupOptions, groupTree, moveTargetRows, optionsFromRows } from "../lib/group_tree";
import { machineGroupsToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";

/**
 * Seed each group's cap input from the SET policies. `policies === null` means the caps could not be
 * READ — a distinct answer from "no group is capped" — and yields NO drafts at all.
 *
 * That distinction is the whole point, and it is why this is a pure function with its own tests. Under
 * the column header "Max sessions (0 = unlimited)", seeding `0` for a group whose policy was never read
 * renders a read FAILURE identically to a genuinely-uncapped group; and because 0 is a writable value
 * that DELETES the row server-side, an operator confirming that fabricated 0 destroys a real cap. So an
 * unread cap must be absent here, never defaulted. (Same shape as AccessPanel's tri-state presence: the
 * feed being down is never rendered as "everything is off".)
 */
export function capDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, string> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.max_concurrent_sessions]));
  return Object.fromEntries(groups.map((g) => [g.id, String(byGroup.get(g.id) ?? 0)]));
}

/**
 * Seed each group's VIEW-ONLY checkbox from the SET policies, with the same unknown-vs-false discipline as
 * {@link capDraftsFor}: `policies === null` (the read failed) yields NO entries, so the column can render
 * "unknown" instead of an unchecked box that reads as "this group is not view-only".
 *
 * The stakes are the same as the cap's, in the opposite direction: showing an unread mandate as OFF invites
 * an admin to conclude a group is unprotected, and submitting that false would REMOVE a real view-only
 * mandate and hand control of those machines back to every technician.
 */
export function viewOnlyDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, boolean> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.enforce_view_only]));
  return Object.fromEntries(groups.map((g) => [g.id, byGroup.get(g.id) ?? false]));
}

/**
 * Seed each group's BACKSTAGE OPT-OUT checkbox from the SET policies (migration 0040) — the per-group
 * exception that lets a view-only group still be issued backstage grants (the remote shell and tool panels)
 * for deliberate unattended maintenance. Unchecked is the default and means the control plane REFUSES those
 * grants, which is what makes the "View only" column mean watch-only full stop.
 *
 * Same tri-state discipline as {@link capDraftsFor} and {@link viewOnlyDraftsFor}: `policies === null` (the
 * read failed) yields NO entries, so the column renders "unknown".
 *
 * WHICH WAY "UNKNOWN" MUST RENDER, because this field's hazard is the OTHER two mirrored and it is worth
 * being explicit rather than inheriting the branch by accident. Here the fabricated value would be
 * `false` = "backstage is refused on this group" — i.e. an unread policy would be drawn as the MORE
 * protected state. Submitting that is safe in itself, but the false BELIEF is not: an admin reading
 * "view-only, backstage refused" concludes the group is watch-only full stop and stops looking, when the
 * opt-out may in fact be set and technicians may in fact be running SYSTEM shells there. An unread security
 * setting must render as unread whichever direction its zero value happens to point; "the safe-looking value"
 * is not the same claim as "the value".
 */
export function allowBackstageDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, boolean> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.allow_backstage_under_view_only]));
  return Object.fromEntries(groups.map((g) => [g.id, byGroup.get(g.id) ?? false]));
}

/**
 * Seed each group's RECORDING BAN checkbox from the SET policies (migration 0043) — when true the control
 * plane mints `allow_recording: false` into signed session policies for this group, and the agent refuses
 * `StartRecording`. Unchecked, the default, means recording is permitted.
 *
 * Same tri-state discipline as {@link viewOnlyDraftsFor}: `policies === null` (the read failed) yields NO
 * entries, so the column renders "unknown".
 *
 * FABRICATED VALUE DIRECTION: false = "recording is allowed on this group" — the PERMISSIVE state. That
 * matches the zero-value and matches the cap/mandate direction (looks safe → stops looking → may be wrong).
 * Rendering as unknown is correct for the same reason it is correct for the mandate.
 */
export function prohibitRecordingDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, boolean> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.prohibit_recording]));
  return Object.fromEntries(groups.map((g) => [g.id, byGroup.get(g.id) ?? false]));
}

/** Initial `requireRecordingDraft` from the fetched policies (false when absent — optional baseline). */
export function requireRecordingDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, boolean> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.require_recording]));
  return Object.fromEntries(groups.map((g) => [g.id, byGroup.get(g.id) ?? false]));
}

/** Initial `maxDurationDraft` from the fetched policies (seconds → string; 0 = unlimited). */
export function maxDurationDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, string> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.max_session_duration_seconds]));
  return Object.fromEntries(groups.map((g) => [g.id, String(byGroup.get(g.id) ?? 0)]));
}

/** Initial `maxIdleDraft` from the fetched policies (seconds → string; 0 = unlimited). */
export function maxIdleDraftsFor(
  groups: readonly MachineGroup[],
  policies: readonly GroupSessionCap[] | null,
): Record<string, string> {
  if (policies === null) return {};
  const byGroup = new Map(policies.map((p) => [p.group_id, p.max_idle_seconds]));
  return Object.fromEntries(groups.map((g) => [g.id, String(byGroup.get(g.id) ?? 0)]));
}

/**
 * Why a cap edit must be refused, or null when it may be submitted. The cap-only part of
 * {@link groupPolicySubmission}, which is the guard the Set button actually runs.
 */
export function capSubmitRefusal(capError: string | null, raw: string): string | null {
  if (capError !== null) {
    return "session caps could not be loaded, so they cannot be changed — reload to retry";
  }
  if (wholeNumberIn(raw, GROUP_POLICY_LIMITS.maxConcurrentSessions) === null) {
    return `max sessions must be a whole number from 0 to ${GROUP_POLICY_LIMITS.maxConcurrentSessions} (0 = unlimited)`;
  }
  return null;
}

/**
 * The server's accepted ranges for a group policy (control-plane/group_session_policy.go:
 * MaxSessionLimit, MaxGroupSessionDurationSeconds, MaxGroupIdleSeconds). The server stays the authority —
 * it re-validates every PUT — these only let the console explain a refusal before sending it.
 */
export const GROUP_POLICY_LIMITS = {
  maxConcurrentSessions: 100_000,
  maxSessionDurationSeconds: 86_400,
  maxIdleSeconds: 3_600,
} as const;

/** `raw` as a whole number in 0..max, or null. Empty is NOT zero: "0 = unlimited" has to be typed. */
function wholeNumberIn(raw: string, max: number): number | null {
  const trimmed = raw.trim();
  const n = Number(trimmed);
  if (trimmed === "" || !Number.isInteger(n) || n < 0 || n > max) return null;
  return n;
}

/** Whether the group policies shown are a completed read of the current group list. */
export type PolicyRead = "loading" | "loaded" | "failed";

/** One group's editable policy, exactly as the inputs hold it. `undefined` means the draft was never seeded. */
export interface GroupPolicyDraft {
  cap: string | undefined;
  enforceViewOnly: boolean | undefined;
  allowBackstageUnderViewOnly: boolean | undefined;
  prohibitRecording: boolean | undefined;
  requireRecording: boolean | undefined;
  maxDuration: string | undefined;
  maxIdle: string | undefined;
}

export type GroupPolicyBody = Parameters<ConsoleApi["setGroupSessionPolicy"]>[1];

/**
 * Menu redesign wave 6: recording is ONE choice, not two checkboxes that could both be ticked. "conflict" only
 * describes a stored row with both flags set (the server refuses to write one, but the console must not hide
 * it if it ever reads one): it is shown, and groupPolicySubmission refuses it until another choice is made.
 */
export type RecordingChoice = "allowed" | "blocked" | "required" | "conflict";

export function recordingChoice(prohibit: boolean | undefined, require: boolean | undefined): RecordingChoice {
  if (prohibit && require) return "conflict";
  if (prohibit) return "blocked";
  if (require) return "required";
  return "allowed";
}

export function recordingFlags(choice: Exclude<RecordingChoice, "conflict">): { prohibit: boolean; require: boolean } {
  return { prohibit: choice === "blocked", require: choice === "required" };
}

/**
 * The group's policy exactly as the last read gave it, in draft form: what the editor's inputs are compared
 * with to decide "unsaved changes". Null while the read is missing (nothing can be dirty against an unread
 * policy, and the editor is not offered then).
 */
export function policyDraftFromRead(groupId: string, policies: readonly GroupSessionCap[] | null): GroupPolicyDraft | null {
  if (policies === null) return null;
  const p = policies.find((x) => x.group_id === groupId);
  return {
    cap: String(p?.max_concurrent_sessions ?? 0),
    enforceViewOnly: p?.enforce_view_only ?? false,
    allowBackstageUnderViewOnly: p?.allow_backstage_under_view_only ?? false,
    prohibitRecording: p?.prohibit_recording ?? false,
    requireRecording: p?.require_recording ?? false,
    maxDuration: String(p?.max_session_duration_seconds ?? 0),
    maxIdle: String(p?.max_idle_seconds ?? 0),
  };
}

/** Whether the editor holds anything the server does not have. Compared as typed: "0600" vs "600" counts. */
export function policyDraftDirty(saved: GroupPolicyDraft | null, draft: GroupPolicyDraft): boolean {
  if (saved === null) return false;
  return (Object.keys(saved) as (keyof GroupPolicyDraft)[]).some((k) => saved[k] !== draft[k]);
}

/** A seconds field said in words beside the input: "1 h 30 min", "unlimited", or "" for a value that is not a whole number. */
export function describeSeconds(raw: string | undefined): string {
  const t = (raw ?? "").trim();
  const n = Number(t);
  if (t === "" || !Number.isInteger(n) || n < 0) return "";
  if (n === 0) return "unlimited";
  const h = Math.floor(n / 3600);
  const m = Math.floor((n % 3600) / 60);
  const s = n % 60;
  return [h ? `${h} h` : "", m ? `${m} min` : "", s ? `${s} s` : ""].filter(Boolean).join(" ");
}

/**
 * The PUT body for one group's drafts, or why it must not be sent. This is the submit guard: every rule the
 * server would answer with a 400 is checked here first, in the server's terms, so the operator sees which
 * field to fix instead of an opaque "could not set group session policy: …".
 *
 * Two refusals are not about the values at all. While the policies are unread (`capError`), or for a group
 * whose drafts were never seeded from a read, nothing may be submitted: the PUT is a full overwrite, and a
 * draft that was never read would write each setting's zero value over whatever the group really has.
 *
 * Invalid numbers are REFUSED, never coerced. Coercing a mistyped duration to 0 silently means "unlimited".
 */
export function groupPolicySubmission(
  policyRead: PolicyRead,
  d: GroupPolicyDraft,
): { body: GroupPolicyBody; refusal: null } | { body: null; refusal: string } {
  const refuse = (refusal: string) => ({ body: null, refusal });
  if (policyRead === "failed") return refuse(capSubmitRefusal("failed", "")!);
  if (policyRead === "loading") return refuse("session policies are still loading — wait for them before changing this group");
  if (
    d.cap === undefined ||
    d.enforceViewOnly === undefined ||
    d.allowBackstageUnderViewOnly === undefined ||
    d.prohibitRecording === undefined ||
    d.requireRecording === undefined ||
    d.maxDuration === undefined ||
    d.maxIdle === undefined
  ) {
    return refuse("this group's policy has not been loaded, so it cannot be changed — reload to retry");
  }
  const capRefusal = capSubmitRefusal(null, d.cap);
  if (capRefusal !== null) return refuse(capRefusal);
  const cap = wholeNumberIn(d.cap, GROUP_POLICY_LIMITS.maxConcurrentSessions)!;
  const maxDuration = wholeNumberIn(d.maxDuration, GROUP_POLICY_LIMITS.maxSessionDurationSeconds);
  if (maxDuration === null) {
    return refuse(
      `max session duration must be a whole number of seconds from 0 to ${GROUP_POLICY_LIMITS.maxSessionDurationSeconds} (24 hours; 0 = unlimited)`,
    );
  }
  const maxIdle = wholeNumberIn(d.maxIdle, GROUP_POLICY_LIMITS.maxIdleSeconds);
  if (maxIdle === null) {
    return refuse(
      `max idle must be a whole number of seconds from 0 to ${GROUP_POLICY_LIMITS.maxIdleSeconds} (1 hour; 0 = unlimited)`,
    );
  }
  if (d.prohibitRecording && d.requireRecording) {
    return refuse("recording cannot be both blocked and required — choose Allowed, Blocked or Required");
  }
  if (cap > 0 && maxDuration === 0) {
    // The server's leaked-seat reaper uses the duration as its threshold, so a cap without one could be
    // starved forever by sessions that never closed (NormalizeGroupSessionPolicy).
    return refuse(
      `a group with a max sessions limit also needs a max session duration (1 to ${GROUP_POLICY_LIMITS.maxSessionDurationSeconds} seconds). Set a duration, or set max sessions to 0 (unlimited)`,
    );
  }
  return {
    refusal: null,
    body: {
      max_concurrent_sessions: cap,
      enforce_view_only: d.enforceViewOnly,
      allow_backstage_under_view_only: d.allowBackstageUnderViewOnly,
      prohibit_recording: d.prohibitRecording,
      require_recording: d.requireRecording,
      max_session_duration_seconds: maxDuration,
      max_idle_seconds: maxIdle,
    },
  };
}


/**
 * The inherited-policy cell next to a group's own row (docs/62 D4/R4): the EFFECTIVE values after merging
 * every visible ancestor (strictest wins), with "(inherited)" on what an ancestor imposes, and an explicit
 * warning when require + block recording are both in force (the control plane then refuses new sessions).
 */
function EffectiveCell({ effective, groupId }: { effective: EffectivePolicy; groupId: string }) {
  const chips = effectivePolicyChips(effective);
  const conflict = policyConflictMessage(effective);
  return (
    <>
      {chips.length === 0 ? (
        <span className="panel__muted" data-testid={`mgroup-effective-none-${groupId}`}>
          No restrictions
        </span>
      ) : (
        <span data-testid={`mgroup-effective-chips-${groupId}`}>
          {chips.map((c) => (c.inherited ? `${c.text} (inherited)` : c.text)).join(" · ")}
        </span>
      )}
      {conflict !== null && (
        <div className="panel__toolbar-error" role="alert" data-testid={`mgroup-conflict-${groupId}`}>
          {conflict}
        </div>
      )}
    </>
  );
}

interface PolicyEditorProps {
  group: MachineGroup;
  draft: GroupPolicyDraft;
  dirty: boolean;
  saved: boolean;
  saving: boolean;
  /** Another row is being renamed, or a save is in flight: every input is read-only. */
  locked: boolean;
  onChange: (patch: Partial<GroupPolicyDraft>) => void;
  onSave: () => void;
  onCancel: () => void;
}

/**
 * Menu redesign wave 6 (Codex menu review): the group's session policy in one labelled form with ONE "Save
 * policy". It used to be seven table columns saved by a "Set" button hidden in the Max sessions cell, with Block
 * and Require recording as two checkboxes that could both be ticked. The save is still a full overwrite of every
 * setting, guarded by groupPolicySubmission; Save is offered only when something changed.
 */
function PolicyEditor({ group: g, draft, dirty, saved, saving, locked, onChange, onSave, onCancel }: PolicyEditorProps) {
  const rec = recordingChoice(draft.prohibitRecording, draft.requireRecording);
  return (
    <fieldset className="mgroup-policy" disabled={locked}>
      <legend>Session policy for {g.name}</legend>
      <label className="mgroup-policy__check">
        <input
          type="checkbox"
          checked={draft.enforceViewOnly ?? false}
          onChange={(e) => onChange({ enforceViewOnly: e.target.checked })}
          aria-label={`Force view-only for ${g.name}`}
          data-testid={`mgroup-viewonly-${g.id}`}
        />
        View only <span className="panel__muted">— technicians can watch but not control</span>
      </label>
      <label className="mgroup-policy__check">
        {/* Deliberately NOT disabled when View only is off: the setting is inert without the mandate, and
            coupling the two would drop half an edit made in the other order. */}
        <input
          type="checkbox"
          checked={draft.allowBackstageUnderViewOnly ?? false}
          onChange={(e) => onChange({ allowBackstageUnderViewOnly: e.target.checked })}
          aria-label={`Allow Under the Hood tools on view-only sessions for ${g.name}`}
          data-testid={`mgroup-allowbackstage-${g.id}`}
        />
        Under the Hood allowed on view-only sessions
      </label>
      <label className="mgroup-policy__field">
        <span>Recording</span>
        <select
          className="panel__select"
          value={rec}
          onChange={(e) => {
            const f = recordingFlags(e.target.value as Exclude<RecordingChoice, "conflict">);
            onChange({ prohibitRecording: f.prohibit, requireRecording: f.require });
          }}
          aria-label={`Recording for ${g.name}`}
          data-testid={`mgroup-recording-${g.id}`}
        >
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked — sessions cannot be recorded</option>
          <option value="required">Required — every session is recorded</option>
          {rec === "conflict" && (
            <option value="conflict" disabled>
              Blocked and required (conflict) — choose one
            </option>
          )}
        </select>
      </label>
      <label className="mgroup-policy__field">
        <span>Max sessions at once</span>
        <input
          type="number"
          min={0}
          max={GROUP_POLICY_LIMITS.maxConcurrentSessions}
          value={draft.cap ?? ""}
          onChange={(e) => onChange({ cap: e.target.value })}
          aria-label={`Max concurrent sessions for ${g.name}`}
          data-testid={`mgroup-cap-${g.id}`}
        />
        <span className="panel__muted">{draft.cap?.trim() === "0" ? "unlimited" : "a limit also needs a max session length"}</span>
      </label>
      <label className="mgroup-policy__field">
        <span>Max session length (seconds)</span>
        <input
          type="number"
          min={0}
          max={GROUP_POLICY_LIMITS.maxSessionDurationSeconds}
          value={draft.maxDuration ?? "0"}
          onChange={(e) => onChange({ maxDuration: e.target.value })}
          aria-label={`Max session duration in seconds for ${g.name} (0 = unlimited)`}
          data-testid={`mgroup-maxduration-${g.id}`}
        />
        <span className="panel__muted" data-testid={`mgroup-maxduration-words-${g.id}`}>{describeSeconds(draft.maxDuration)}</span>
      </label>
      <label className="mgroup-policy__field">
        <span>Max idle time (seconds)</span>
        <input
          type="number"
          min={0}
          max={GROUP_POLICY_LIMITS.maxIdleSeconds}
          value={draft.maxIdle ?? "0"}
          onChange={(e) => onChange({ maxIdle: e.target.value })}
          aria-label={`Max idle seconds for ${g.name} (0 = unlimited)`}
          data-testid={`mgroup-maxidle-${g.id}`}
        />
        <span className="panel__muted">{describeSeconds(draft.maxIdle)}</span>
      </label>
      <div className="mgroup-policy__actions">
        <button className="panel__action" type="button" onClick={onSave} disabled={!dirty || saving} data-testid={`mgroup-cap-save-${g.id}`}>
          {saving ? "Saving…" : "Save policy"}
        </button>
        <button className="panel__action" type="button" onClick={onCancel} disabled={saving} data-testid={`mgroup-policy-cancel-${g.id}`}>
          Cancel
        </button>
        <span className="panel__muted" role="status" data-testid={`mgroup-policy-status-${g.id}`}>
          {dirty ? "Unsaved changes" : saved ? "Saved" : ""}
        </span>
      </div>
    </fieldset>
  );
}

export interface MachineGroupsPanelProps {
  api: ConsoleApi;
}

export function MachineGroupsPanel({ api }: MachineGroupsPanelProps) {
  const [groups, setGroups] = useState<readonly MachineGroup[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  // The parent for a new group ("" = top level). "New subgroup" on a row sets it; the select can change it.
  const [parentId, setParentId] = useState("");
  const nameInputRef = useRef<HTMLInputElement>(null);
  const [saving, setSaving] = useState(false);
  // Move…: the group whose parent is being chosen (null = none), the chosen new parent ("" = top level),
  // and whether the move is in flight. The server's 409 reason is shown verbatim in the toolbar error.
  const [moveFor, setMoveFor] = useState<string | null>(null);
  const [moveParent, setMoveParent] = useState("");
  // The picker's value when the move UI opened: "Move here" stays disabled while the selection equals it,
  // so an untouched picker can never send a request (a hidden parent preselects "Top level" = a detach).
  const [moveInitial, setMoveInitial] = useState("");
  const [movePending, setMovePending] = useState(false);
  // The SET policies as last read (null = unread), for the inherited/effective column.
  const [policyRows, setPolicyRows] = useState<readonly GroupSessionCap[] | null>(null);
  // The control plane's own effective (own + inherited) policy per managed group; null when it sent none
  // (an older server), in which case the column falls back to a browser-side merge of the visible rows.
  const [serverEffective, setServerEffective] = useState<Readonly<Record<string, GroupEffectivePolicy>> | null>(null);
  // Inline rename: editingId is the row being edited (null = none); editName is its draft. pending is the
  // row id with a rename/delete in flight (disables that row's controls).
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  // Per-group concurrent-session cap (docs/01 §5, loop 78). `capDraft` is each row's input value, seeded on
  // refresh from the SET caps (0/absent = unlimited by group); `capPending` is the row whose save is in flight.
  const [capDraft, setCapDraft] = useState<Record<string, string>>({});
  // The per-group VIEW-ONLY mandate (docs/01 §5, loops 79/80). Seeded from the same fetch as the cap and
  // submitted with it, because the server writes the whole policy in one PUT.
  const [viewOnlyDraft, setViewOnlyDraft] = useState<Record<string, boolean>>({});
  // The per-group BACKSTAGE OPT-OUT (migration 0040): unchecked — the default — means a view-only group also
  // refuses backstage grants, so the "View only" column means watch-only full stop. Same fetch, same PUT.
  const [allowBackstageDraft, setAllowBackstageDraft] = useState<Record<string, boolean>>({});
  // The per-group RECORDING BAN (migration 0043): checked means recording is prohibited on sessions in this
  // group; the agent refuses StartRecording and the viewer hides the record button. Same fetch, same PUT.
  const [prohibitRecordingDraft, setProhibitRecordingDraft] = useState<Record<string, boolean>>({});
  // The per-group MANDATORY RECORDING (migration 0044): checked means every session must be recorded;
  // the viewer auto-starts recording and the agent refuses StopRecording. Cannot be true at the same
  // time as prohibitRecording. Same fetch, same PUT.
  const [requireRecordingDraft, setRequireRecordingDraft] = useState<Record<string, boolean>>({});
  // The per-group MAX SESSION DURATION (migration 0045): seconds, 0 = unlimited. Stored in the input
  // as a string (same discipline as capDraft) so an empty input is "not yet set" rather than "zero".
  const [maxDurationDraft, setMaxDurationDraft] = useState<Record<string, string>>({});
  const [maxIdleDraft, setMaxIdleDraft] = useState<Record<string, string>>({});
  const [capPending, setCapPending] = useState<string | null>(null);
  // Wave 6: the group whose policy editor is open (one at a time), and the group whose policy was just saved
  // (cleared by the next edit), for the "Saved" line.
  const [policyFor, setPolicyFor] = useState<string | null>(null);
  const [savedFor, setSavedFor] = useState<string | null>(null);
  // Why the caps need their OWN error state rather than folding into `error`: the caps load is
  // best-effort (see `refresh`), so its failure must NOT blank the groups — but it must also not be
  // SILENT. Rendering an unread cap as `0` would be indistinguishable from a genuinely-uncapped
  // group under a "0 = unlimited" header, and because 0 is a writable value (the server DELETEs the
  // row on 0) an operator confirming that fabricated 0 would destroy a real cap. So: when this is
  // set, the cap column shows "unknown" and refuses to submit.
  const [capError, setCapError] = useState<string | null>(null);
  // False from the moment a refresh shows its groups until that SAME refresh has read their policies. The
  // groups render first (they need less privilege and must not wait on the policies), so without this a
  // row would sit there drawn from the previous read — or, for a group that is new to this list, from
  // nothing at all — with live inputs and a live Set button.
  const [policiesLoaded, setPoliciesLoaded] = useState(false);
  // Only the latest refresh may write state. Refreshes overlap (mount, the Refresh button, the reload after
  // every save), and an older one finishing last would put back groups and policies from before a save.
  const refreshSeq = useRef(0);
  const policyRead: PolicyRead = capError !== null ? "failed" : policiesLoaded ? "loaded" : "loading";
  // A row's policy inputs exist only for a completed read that seeded THIS group; otherwise the cells say
  // why there is no value instead of drawing a default that looks like one.
  const policyKnown = (groupId: string) => policyRead === "loaded" && capDraft[groupId] !== undefined;
  const unknownLabel = policyRead === "loading" ? "loading…" : "unknown";
  const draftOf = (groupId: string): GroupPolicyDraft => ({
    cap: capDraft[groupId],
    enforceViewOnly: viewOnlyDraft[groupId],
    allowBackstageUnderViewOnly: allowBackstageDraft[groupId],
    prohibitRecording: prohibitRecordingDraft[groupId],
    requireRecording: requireRecordingDraft[groupId],
    maxDuration: maxDurationDraft[groupId],
    maxIdle: maxIdleDraft[groupId],
  });
  const dirtyOf = (groupId: string) => policyDraftDirty(policyDraftFromRead(groupId, policyRows), draftOf(groupId));
  // While the open editor holds unsaved changes, no other editor may open (and it may not be hidden): an edit
  // must be saved or cancelled, never left behind out of sight.
  const openDirty = policyFor !== null && policyKnown(policyFor) && dirtyOf(policyFor);
  const [textQuery, setTextQuery] = useState("");

  // ONE tree helper (docs/62 §4): depth-first rows with indent + path, built from the groups this caller can see
  // (a group whose parent is hidden is a top-level row). The text filter keeps the ancestors of every match.
  const treeRows = useMemo(() => groupTree(groups), [groups]);
  const visibleRows = useMemo(() => filterGroupTree(treeRows, textQuery), [treeRows, textQuery]);
  const filteredGroups = useMemo(() => visibleRows.map((r) => r.group), [visibleRows]);
  const parentOptions = useMemo(() => groupOptions(groups), [groups]);
  // The chosen parent, or top level when that group is gone (deleted or moved out of view since it was chosen).
  const createParent = parentOptions.some((o) => o.id === parentId) ? parentId : "";
  // Effective (inherited) policy per group, from the saved policies. Null policies = unread: nothing computed.
  // The server's answer wins: it sees ancestors this caller cannot, which a browser merge cannot.
  const effectiveByGroup = useMemo(() => {
    if (policyRows === null) return new Map<string, EffectivePolicy | null>();
    if (serverEffective !== null) {
      const own = new Map(policyRows.map((p) => [p.group_id, p] as const));
      return new Map(
        groups.map((g) => {
          const s = serverEffective[g.id];
          return [g.id, s === undefined ? null : effectivePolicyFromServer(s, own.get(g.id))] as const;
        }),
      );
    }
    return new Map(groups.map((g) => [g.id, effectivePolicyFor(groups, policyRows, g.id)] as const));
  }, [groups, policyRows, serverEffective]);

  const handleExport = useCallback(() => {
    saveBytesAsFile("machine-groups.csv", new TextEncoder().encode(machineGroupsToCsv(filteredGroups)));
  }, [filteredGroups]);

  const refresh = useCallback(async () => {
    const seq = ++refreshSeq.current;
    const current = () => seq === refreshSeq.current;
    setBusy(true);
    setError(null);
    try {
      const gs = await api.listMachineGroups();
      if (!current()) return;
      setGroups(gs);
      setPoliciesLoaded(false);
      // Caps load SEPARATELY and best-effort: listing groups needs only CapViewMachines, but caps need
      // CapManageGroups — a viewer without it must still see the groups (loop-56 lesson: never let a policy
      // load failure blank the main data).
      //
      // "Best-effort" means the GROUPS survive a caps failure. It does NOT mean inventing a cap
      // value: on failure the drafts are left UNSEEDED and `capError` is set, so the column reads
      // "unknown" and cannot be submitted. Seeding `0` here would render a read failure exactly like
      // a genuinely-uncapped group, and submitting that 0 DELETES the group's real cap server-side.
      let policies: readonly GroupSessionCap[] | null = null;
      let effective: Readonly<Record<string, GroupEffectivePolicy>> | null = null;
      let policyError: string | null = null;
      try {
        if (api.listGroupSessionPolicyView) {
          const view = await api.listGroupSessionPolicyView();
          policies = view.policies;
          effective = view.effective;
        } else {
          policies = await api.listGroupSessionPolicies();
        }
      } catch (e) {
        policyError = e instanceof Error ? e.message : String(e);
      }
      if (!current()) return;
      setCapError(policyError);
      setPolicyRows(policies);
      setServerEffective(effective);
      setPoliciesLoaded(policies !== null);
      setCapDraft(capDraftsFor(gs, policies));
      setViewOnlyDraft(viewOnlyDraftsFor(gs, policies));
      setAllowBackstageDraft(allowBackstageDraftsFor(gs, policies));
      setProhibitRecordingDraft(prohibitRecordingDraftsFor(gs, policies));
      setRequireRecordingDraft(requireRecordingDraftsFor(gs, policies));
      setMaxDurationDraft(maxDurationDraftsFor(gs, policies));
      setMaxIdleDraft(maxIdleDraftsFor(gs, policies));
    } catch (e) {
      if (current()) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (current()) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
    return () => {
      // Orphan any refresh still in flight, so it cannot write after unmount or over a newer api's data.
      refreshSeq.current++;
    };
  }, [refresh]);

  const handleAdd = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const n = name.trim();
      if (n === "") {
        setError("a group needs a name");
        return;
      }
      setSaving(true);
      setError(null);
      try {
        await api.createMachineGroup({ name: n, parentId: createParent === "" ? null : createParent });
        setName("");
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [api, name, createParent, refresh],
  );

  const startEdit = useCallback((g: MachineGroup) => {
    setEditingId(g.id);
    setEditName(g.name);
    setError(null);
  }, []);

  const cancelEdit = useCallback(() => {
    setEditingId(null);
    setEditName("");
  }, []);

  const handleRename = useCallback(
    async (g: MachineGroup) => {
      const n = editName.trim();
      if (n === "") {
        setError("a group needs a name");
        return;
      }
      setPending(g.id);
      setError(null);
      try {
        await api.renameMachineGroup(g.id, n);
        cancelEdit();
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setPending(null);
      }
    },
    [api, editName, cancelEdit, refresh],
  );

  const startMove = useCallback(
    (g: MachineGroup) => {
      setMoveFor(g.id);
      // Start on the group's current VISIBLE parent, so "Move here" is a no-op until the admin picks another.
      const initial = treeRows.find((r) => r.group.id === g.id)?.parentId ?? "";
      setMoveParent(initial);
      setMoveInitial(initial);
      setError(null);
    },
    [treeRows],
  );

  const cancelMove = useCallback(() => {
    setMoveFor(null);
    setMoveParent("");
  }, []);

  const handleMove = useCallback(
    async (g: MachineGroup) => {
      if (moveParent === moveInitial) return; // an unchanged picker is never a request
      setMovePending(true);
      setError(null);
      try {
        await api.moveMachineGroup(g.id, moveParent === "" ? null : moveParent);
        cancelMove();
        await refresh();
      } catch (err) {
        // The server's reason (cycle, too deep, policy conflict, not allowed) is shown VERBATIM; the picker
        // stays open so the admin can choose another parent.
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setMovePending(false);
      }
    },
    [api, moveParent, moveInitial, cancelMove, refresh],
  );

  const handleSaveCap = useCallback(
    async (g: MachineGroup) => {
      // EVERY setting, always: the PUT is a full overwrite, so sending only the cap would clear the group's
      // view-only mandate as a side effect of editing an unrelated field. groupPolicySubmission refuses
      // unless every draft was seeded from a successful read of THIS group, and refuses rather than coerces
      // a value the server would reject.
      const { body, refusal } = groupPolicySubmission(policyRead, draftOf(g.id));
      if (body === null) {
        setError(`${g.name}: ${refusal}`);
        return;
      }
      setCapPending(g.id);
      setError(null);
      try {
        await api.setGroupSessionPolicy(g.id, body);
        await refresh();
        setSavedFor(g.id);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setCapPending(null);
      }
    },
    // draftOf reads exactly these drafts.
    [api, capDraft, policyRead, viewOnlyDraft, allowBackstageDraft, prohibitRecordingDraft, requireRecordingDraft, maxDurationDraft, maxIdleDraft, refresh],
  );

  const cancelPolicy = useCallback(
    (groupId: string) => {
      const saved = policyDraftFromRead(groupId, policyRows);
      if (saved !== null) {
        setCapDraft((d) => ({ ...d, [groupId]: saved.cap! }));
        setViewOnlyDraft((d) => ({ ...d, [groupId]: saved.enforceViewOnly! }));
        setAllowBackstageDraft((d) => ({ ...d, [groupId]: saved.allowBackstageUnderViewOnly! }));
        setProhibitRecordingDraft((d) => ({ ...d, [groupId]: saved.prohibitRecording! }));
        setRequireRecordingDraft((d) => ({ ...d, [groupId]: saved.requireRecording! }));
        setMaxDurationDraft((d) => ({ ...d, [groupId]: saved.maxDuration! }));
        setMaxIdleDraft((d) => ({ ...d, [groupId]: saved.maxIdle! }));
      }
      setPolicyFor(null);
      setSavedFor(null);
      setError(null);
    },
    [policyRows],
  );

  const handleDelete = useCallback(
    async (g: MachineGroup) => {
      setPending(g.id);
      setError(null);
      try {
        await api.deleteMachineGroup(g.id);
        await refresh();
      } catch (err) {
        // Surfaces the server's 409 ("group still has machines …") and any 404.
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setPending(null);
      }
    },
    [api, refresh],
  );

  return (
    <section className="panel panel--machinegroups" data-testid="machine-groups">
      <form className="panel__form" onSubmit={(e) => void handleAdd(e)}>
        <span className="panel__toolbar-title">Machine groups</span>
        <label className="panel__toolbar-field">
          Name
          <input
            ref={nameInputRef}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Front Office"
            data-testid="mgroup-name"
          />
        </label>
        <label className="panel__toolbar-field">
          Under
          <select
            className="panel__select"
            value={createParent}
            onChange={(e) => setParentId(e.target.value)}
            data-testid="mgroup-parent"
          >
            <option value="">Top level</option>
            {parentOptions.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <button className="panel__action" type="submit" disabled={saving} data-testid="mgroup-create">
          {saving ? "Creating…" : "Create group"}
        </button>
        <button className="panel__action" type="button" onClick={() => void refresh()} disabled={busy} data-testid="mgroup-refresh">
          {busy ? "Loading…" : "Refresh"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="mgroup-error">
            {error}
          </span>
        )}
      </form>
      <p className="panel__note" data-testid="machine-groups-help">
        Every machine belongs to exactly one access &amp; policy group. Roles, permissions, session limits and
        enrollment tokens are scoped to these groups, so moving a machine changes who can reach it.
        A maximum session duration is required when you limit concurrent sessions.
      </p>
      <p className="panel__note" data-testid="machine-groups-nesting-help">
        Groups can be nested up to 4 levels (&ldquo;New subgroup&rdquo;, or pick a parent under &ldquo;Under&rdquo;). Access given
        on a group covers all of its subgroups, and a subgroup can only tighten the session policy it inherits,
        never loosen it. Moving a group (&ldquo;Move&hellip;&rdquo;) changes who can reach everything inside it. You see paths
        like &ldquo;Acme &rsaquo; Site A&rdquo; built from the groups you can access, so a group whose parent is outside your
        access appears at the top level.
      </p>

      <div className="panel__toolbar">
        <input
          type="search"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          placeholder="Search name or group ID…"
          aria-label="Search machine groups"
          data-testid="mgroup-search"
        />
        <button
          className="panel__action"
          type="button"
          onClick={handleExport}
          disabled={filteredGroups.length === 0}
          data-testid="mgroup-export"
        >
          Export CSV
        </button>
      </div>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Group ID (use when minting an enrollment token)</th>
            <th>Effective policy (own + inherited)</th>
            <th>
              Session policy
              {capError !== null && (
                <span className="panel__toolbar-error" role="alert" data-testid="mgroup-cap-error">
                  {` — could not load: ${capError}`}
                </span>
              )}
            </th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredGroups.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={5} data-testid="mgroups-empty">
                {busy ? "Loading…" : textQuery ? "No machine groups match this search." : "No machine groups yet."}
              </td>
            </tr>
          )}
          {visibleRows.map(({ group: g, depth, path, matched }) => (
            <Fragment key={g.id}>
            <tr data-testid={`mgroup-row-${g.id}`} data-depth={depth} data-matched={matched ? "true" : "false"}>
              <td className="panel__name" style={{ paddingLeft: `${0.5 + depth * 1.25}rem` }} title={path}>
                {depth > 0 && editingId !== g.id && (
                  <span className="panel__muted" aria-hidden="true">
                    {"\u21b3 "}
                  </span>
                )}
                {editingId === g.id ? (
                  <input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    aria-label={`New name for ${g.name}`}
                    data-testid={`mgroup-edit-name-${g.id}`}
                  />
                ) : (
                  <span className={matched ? undefined : "panel__muted"}>{g.name}</span>
                )}
                {depth > 0 && editingId !== g.id && (
                  <div className="panel__muted" data-testid={`mgroup-path-${g.id}`}>
                    {path}
                  </div>
                )}
              </td>
              <td className="panel__mono" data-testid={`mgroup-id-${g.id}`}>{g.id}</td>
              <td data-testid={`mgroup-effective-${g.id}`}>
                {!policyKnown(g.id) || !effectiveByGroup.get(g.id) ? (
                  <span className="panel__muted">{unknownLabel}</span>
                ) : (
                  <EffectiveCell effective={effectiveByGroup.get(g.id)!} groupId={g.id} />
                )}
              </td>
              <td>
                {!policyKnown(g.id) ? (
                  // UNKNOWN, not "no restrictions": an unread policy offers no editor at all, so nothing that
                  // was never read can be shown as a value or written back (see capDraftsFor and its siblings).
                  <span className="panel__muted" data-testid={`mgroup-policy-unknown-${g.id}`}>
                    {unknownLabel}
                  </span>
                ) : (
                  <button
                    className="panel__action"
                    type="button"
                    aria-expanded={policyFor === g.id}
                    aria-controls={`mgroup-policy-editor-${g.id}`}
                    onClick={() => {
                      setPolicyFor(policyFor === g.id ? null : g.id);
                      setSavedFor(null);
                    }}
                    disabled={openDirty || editingId !== null}
                    title={openDirty ? "Save or cancel the policy you are editing first" : undefined}
                    data-testid={`mgroup-policy-edit-${g.id}`}
                  >
                    {policyFor === g.id ? "Hide policy" : "Edit policy"}
                  </button>
                )}
              </td>
              <td className="panel__col--action">
                {editingId === g.id ? (
                  <>
                    <button
                      className="panel__action"
                      onClick={() => void handleRename(g)}
                      disabled={pending !== null}
                      data-testid={`mgroup-save-${g.id}`}
                    >
                      {pending === g.id ? "Saving…" : "Save"}
                    </button>
                    <button className="panel__action" onClick={cancelEdit} data-testid={`mgroup-cancel-${g.id}`}>
                      Cancel
                    </button>
                  </>
                ) : moveFor === g.id ? (
                  <>
                    <label className="panel__toolbar-field">
                      Move under
                      <select
                        className="panel__select"
                        value={moveParent}
                        onChange={(e) => setMoveParent(e.target.value)}
                        disabled={movePending}
                        aria-label={`New parent for ${g.name}`}
                        data-testid={`mgroup-move-parent-${g.id}`}
                      >
                        <option value="">Top level</option>
                        {/* Excludes the group itself and its whole subtree: moving under either is a cycle. */}
                        {optionsFromRows(moveTargetRows(groups, g.id)).map((o) => (
                          <option key={o.id} value={o.id}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button
                      className="panel__action"
                      onClick={() => void handleMove(g)}
                      disabled={movePending || moveParent === moveInitial}
                      data-testid={`mgroup-move-apply-${g.id}`}
                    >
                      {movePending ? "Moving…" : "Move here"}
                    </button>
                    <button
                      className="panel__action"
                      onClick={cancelMove}
                      disabled={movePending}
                      data-testid={`mgroup-move-cancel-${g.id}`}
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      className="panel__action"
                      onClick={() => {
                        setParentId(g.id);
                        nameInputRef.current?.focus();
                      }}
                      disabled={pending !== null || editingId !== null || moveFor !== null}
                      data-testid={`mgroup-subgroup-${g.id}`}
                    >
                      New subgroup
                    </button>
                    <button
                      className="panel__action"
                      onClick={() => startMove(g)}
                      disabled={pending !== null || editingId !== null || moveFor !== null}
                      data-testid={`mgroup-move-${g.id}`}
                    >
                      Move…
                    </button>
                    <button
                      className="panel__action"
                      onClick={() => startEdit(g)}
                      disabled={pending !== null || editingId !== null || moveFor !== null}
                      data-testid={`mgroup-rename-${g.id}`}
                    >
                      Rename
                    </button>
                    <button
                      className="panel__action panel__action--danger"
                      onClick={() => void handleDelete(g)}
                      disabled={pending !== null || editingId !== null || moveFor !== null}
                      data-testid={`mgroup-delete-${g.id}`}
                    >
                      {pending === g.id ? "…" : "Delete"}
                    </button>
                  </>
                )}
              </td>
            </tr>
            {policyFor === g.id && policyKnown(g.id) && (
              <tr className="mgroup-policy__row" data-testid={`mgroup-policy-editor-${g.id}`} id={`mgroup-policy-editor-${g.id}`}>
                <td colSpan={5}>
                  <PolicyEditor
                    group={g}
                    draft={draftOf(g.id)}
                    dirty={dirtyOf(g.id)}
                    saved={savedFor === g.id}
                    saving={capPending === g.id}
                    locked={editingId !== null || capPending !== null}
                    onChange={(patch) => {
                      setSavedFor(null);
                      if (patch.cap !== undefined) setCapDraft((d) => ({ ...d, [g.id]: patch.cap! }));
                      if (patch.enforceViewOnly !== undefined) setViewOnlyDraft((d) => ({ ...d, [g.id]: patch.enforceViewOnly! }));
                      if (patch.allowBackstageUnderViewOnly !== undefined)
                        setAllowBackstageDraft((d) => ({ ...d, [g.id]: patch.allowBackstageUnderViewOnly! }));
                      if (patch.prohibitRecording !== undefined) setProhibitRecordingDraft((d) => ({ ...d, [g.id]: patch.prohibitRecording! }));
                      if (patch.requireRecording !== undefined) setRequireRecordingDraft((d) => ({ ...d, [g.id]: patch.requireRecording! }));
                      if (patch.maxDuration !== undefined) setMaxDurationDraft((d) => ({ ...d, [g.id]: patch.maxDuration! }));
                      if (patch.maxIdle !== undefined) setMaxIdleDraft((d) => ({ ...d, [g.id]: patch.maxIdle! }));
                    }}
                    onSave={() => void handleSaveCap(g)}
                    onCancel={() => cancelPolicy(g.id)}
                  />
                </td>
              </tr>
            )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </section>
  );
}
