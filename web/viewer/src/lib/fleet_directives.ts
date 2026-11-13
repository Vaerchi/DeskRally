/**
 * Fleet agent directives, console side (docs/65): reinstall or remove an agent WITHOUT opening a session.
 *
 * Pure logic only (no React, no fetch): the wire types as `control-plane/directive.go` serializes them, the
 * state model the panels render, the cancel-window countdown, the typed-confirmation guard and the friendly
 * wording of the server's refusals. The control plane owns every rule; nothing here authorizes anything. These
 * helpers only decide what to SHOW, so a refusal the server still issues (403 / 409 / 410 / 429) always wins.
 */

export type DirectiveKind = "reinstall" | "uninstall";

/** The control plane's own states (`DirectiveState`). */
export type DirectiveServerState =
  | "requested"
  | "issued"
  | "accepted"
  | "executing"
  | "reboot_pending"
  | "complete"
  | "failed"
  | "removal_unconfirmed"
  | "cancelled"
  | "expired"
  | "forgotten";

/** One directive row (`GET /machines/{id}/directives`, and the `directive` of every route that returns one). */
export interface AgentDirective {
  id: string;
  tenant_id?: string;
  machine_id: string;
  device_id?: string;
  group_id?: string;
  kind: DirectiveKind;
  state: DirectiveServerState;
  requested_by: string;
  requested_at: string;
  /** Earliest issuance. For an uninstall this is the end of the cancel window (approval RESTARTS it). */
  not_before: string;
  /** The request lapses (410) at this instant: 1 hour after it was made. */
  request_expires_at: string;
  require_approval: boolean;
  approved_by?: string;
  approved_at?: string | null;
  cancelled_by?: string;
  cancelled_at?: string | null;
  cancel_reason?: string;
  issued_at?: string | null;
  expires_at?: string | null;
  delivered_at?: string | null;
  acked_at?: string | null;
  state_detail?: string;
  updated_at?: string;
}

/** A directive from `GET /directives?state=active`: the row plus the machine's display facts. */
export interface ActiveDirective extends AgentDirective {
  machine_name: string;
  machine_alias?: string;
  machine_status: string;
}

/** One entry of `GET /me` capabilities: a capability the caller holds and WHERE. */
export interface MeCapability {
  capability: string;
  /** Held tenant-wide. */
  all_groups: boolean;
  /** Otherwise the groups it covers (assigned groups plus their descendants); empty when all_groups. */
  group_ids: string[];
}

/** Read `/me`'s untrusted capability list; anything malformed is dropped (an older server sends none). */
export function readMeCapabilities(raw: unknown): MeCapability[] {
  if (!Array.isArray(raw)) return [];
  const out: MeCapability[] = [];
  for (const e of raw) {
    const c = e as { capability?: unknown; all_groups?: unknown; group_ids?: unknown } | null;
    if (!c || typeof c.capability !== "string") continue;
    out.push({
      capability: c.capability,
      all_groups: c.all_groups === true,
      group_ids: Array.isArray(c.group_ids) ? c.group_ids.filter((g): g is string => typeof g === "string") : [],
    });
  }
  return out;
}

/** Does the caller hold `cap` for a machine in `groupId`? The question the server asks (AllowsInGroup). */
export function holdsCapabilityForGroup(caps: readonly MeCapability[], cap: string, groupId: string): boolean {
  return caps.some((c) => c.capability === cap && (c.all_groups || c.group_ids.includes(groupId)));
}

/** Does the caller hold `cap` anywhere at all? The question tenant-wide routes ask (Grant.Allows). */
export function holdsCapabilityAnywhere(caps: readonly MeCapability[], cap: string): boolean {
  return caps.some((c) => c.capability === cap);
}

/** `GET|PUT /tenant/directive-policy`. */
export interface DirectivePolicy {
  require_second_approver: boolean;
  version?: number;
}

/** The states the panels show: the server's, with "awaiting approval" and "delivered" told apart. */
export type DirectiveUiState =
  | "requested"
  | "awaiting_approval"
  | "issued"
  | "delivered"
  | "accepted"
  | "executing"
  | "reboot_pending"
  | "complete"
  | "failed"
  | "removal_unconfirmed"
  | "cancelled"
  | "expired"
  | "forgotten";

export interface DirectiveStateInfo {
  label: string;
  /** One plain sentence under the state. */
  explain: string;
  /** No further transition will happen (except a late genuine report for removal_unconfirmed, which is not terminal). */
  terminal: boolean;
  tone: "neutral" | "pending" | "ok" | "bad" | "warn";
}

export const DIRECTIVE_STATE_INFO: Readonly<Record<DirectiveUiState, DirectiveStateInfo>> = {
  requested: { label: "Requested", explain: "In the cancel window. Nothing is sent to the machine until it ends.", terminal: false, tone: "pending" },
  awaiting_approval: { label: "Awaiting approval", explain: "A second person must approve this removal. The cancel window starts again when they do.", terminal: false, tone: "pending" },
  issued: { label: "Issued", explain: "Signed and waiting for the agent to connect and collect it.", terminal: false, tone: "pending" },
  delivered: { label: "Delivered", explain: "The agent has received it and has not reported back yet.", terminal: false, tone: "pending" },
  accepted: { label: "Accepted", explain: "The agent verified the instruction and is about to start.", terminal: false, tone: "pending" },
  executing: { label: "Executing", explain: "The agent is carrying it out now.", terminal: false, tone: "pending" },
  reboot_pending: { label: "Reboot pending", explain: "The agent finished its part but Windows needs a restart to complete the change.", terminal: false, tone: "warn" },
  complete: { label: "Complete", explain: "Done and confirmed by the agent.", terminal: true, tone: "ok" },
  failed: { label: "Failed", explain: "The agent reported that it could not finish. The machine is unchanged unless the detail says otherwise.", terminal: true, tone: "bad" },
  removal_unconfirmed: {
    label: "Removal unconfirmed",
    explain: "The agent has not reported back; the machine stays retired and locked until it does, or until an owner forgets it.",
    terminal: false,
    tone: "warn",
  },
  cancelled: { label: "Cancelled", explain: "Cancelled before anything was sent to the machine.", terminal: true, tone: "neutral" },
  expired: { label: "Expired", explain: "The request lapsed (requests last 1 hour) before it was issued.", terminal: true, tone: "neutral" },
  // The control plane's own terminal state (docs/65 sec. 8): an Owner forgot the machine while this was active. It says
  // nothing about what the agent did, and it is never offered an action.
  forgotten: { label: "Forgotten", explain: "Closed when an owner forgot this machine. The agent never confirmed the removal.", terminal: true, tone: "neutral" },
};

/** Map a server row to the state the console shows. */
export function directiveUiState(d: Pick<AgentDirective, "state" | "require_approval" | "approved_at" | "approved_by" | "delivered_at">): DirectiveUiState {
  if (d.state === "requested" && d.require_approval && !d.approved_at && !d.approved_by) return "awaiting_approval";
  if (d.state === "issued" && d.delivered_at) return "delivered";
  return d.state;
}

/** Still in flight, i.e. the machine has an active directive (the server allows one per machine). */
export function isActiveDirective(d: Pick<AgentDirective, "state">): boolean {
  return !DIRECTIVE_STATE_INFO[d.state as DirectiveUiState]?.terminal;
}

/** Only a REQUESTED directive can be cancelled (anything later is a 409 from the server). */
export function canCancelDirective(d: Pick<AgentDirective, "state">): boolean {
  return d.state === "requested";
}

// --- who may be offered what -------------------------------------------------------------------------------

export interface MachineLike {
  id: string;
  name: string;
  alias?: string;
  status?: string;
}

/** The machine's lifecycle status; an absent one (an old server) is active. */
export function machineStatus(m: Pick<MachineLike, "status">): string {
  return m.status ?? "active";
}

/** "Reinstall agent": active machines only, and only to a holder of remove_agent. */
export function canOfferReinstall(m: Pick<MachineLike, "status">, hasRemoveAgent: boolean): boolean {
  return hasRemoveAgent && machineStatus(m) === "active";
}

/** "Remove agent...": RETIRED machines only, and only to a holder of remove_agent. */
export function canOfferRemove(m: Pick<MachineLike, "status">, hasRemoveAgent: boolean): boolean {
  return hasRemoveAgent && machineStatus(m) === "retired";
}

/**
 * "Forget this machine...": RETIRED machines only (retire first, then forget), and only to a holder of remove_agent
 * for the machine's group (docs/65 sec. 8). A removed machine has nothing left to forget.
 */
export function canOfferForget(m: Pick<MachineLike, "status">, hasRemoveAgent: boolean): boolean {
  return hasRemoveAgent && machineStatus(m) === "retired";
}

/**
 * The pending-removals row's "Forget this machine...": an UNCONFIRMED removal (the agent never reported back) on a
 * machine that is still retired. `GET /directives?state=active` lists only rows the caller may act on (remove_agent
 * for the machine's CURRENT group), so no capability check is needed here; the server still authorizes the call.
 */
export function canForgetFromRemoval(d: Pick<ActiveDirective, "kind" | "state" | "machine_status">): boolean {
  return d.kind === "uninstall" && d.state === "removal_unconfirmed" && d.machine_status === "retired";
}

/** The signed-in user's id (GET /me user_id); null when the server did not say. */
export type SelfUserId = string | null;

export function isRequester(d: Pick<AgentDirective, "requested_by">, selfUserId: SelfUserId): boolean {
  return selfUserId !== null && d.requested_by === selfUserId;
}

/**
 * Approve is offered for an uninstall awaiting a second approver, NEVER to the person who requested it. With an
 * unknown own id (an older server) it is offered and the server's 403 on self-approval is the backstop.
 */
export function canApproveDirective(d: AgentDirective, selfUserId: SelfUserId): boolean {
  return directiveUiState(d) === "awaiting_approval" && !isRequester(d, selfUserId);
}

// --- typed confirmation ------------------------------------------------------------------------------------

/**
 * The typed-confirmation guard. Mirrors the server (http_directive.go): the typed text, trimmed, must equal the
 * machine's name (hostname) or its alias EXACTLY (case-sensitive), and an empty entry never matches.
 */
export function removalConfirmationMatches(typed: string, m: Pick<MachineLike, "name" | "alias">): boolean {
  const t = typed.trim();
  if (t === "") return false;
  return t === m.name || (!!m.alias && t === m.alias);
}

// --- forget this machine (docs/65 sec. 8) ------------------------------------------------------------------

/** `POST /machines/{id}/forget`: what happened, the machine as it is now, and the directives that were closed. */
export interface ForgetMachineResult {
  /** "forgotten": done now. "already_removed": it was already removed (a confirmed removal or an earlier forget): nothing changed. */
  outcome: "forgotten" | "already_removed";
  machine: MachineLike;
  closed_directives: AgentDirective[];
}

/** The dialog's plain words. Pure so the wording is pinned by tests; the component only lays it out. */
export interface ForgetDialogCopy {
  title: string;
  /** What it does, permanently. */
  effect: string;
  /** When to use it. */
  when: string;
  /** What it does NOT do. */
  notice: string;
}

export function forgetDialogCopy(m: Pick<MachineLike, "name" | "alias">): ForgetDialogCopy {
  const label = m.alias || m.name;
  return {
    title: `Forget ${label}`,
    effect:
      `This permanently removes ${label} from DeskRally. The machine can never reconnect with its current identity, and this ` +
      `cannot be undone. Reinstalling the agent on it enrolls it as a new machine.`,
    when: "Use this when the machine is gone, or when its removal will never be confirmed by the agent.",
    notice: "It does not uninstall anything on the machine itself.",
  };
}

/** The sentence shown once the call returned. */
export function forgetOutcomeNote(outcome: ForgetMachineResult["outcome"], m: Pick<MachineLike, "name" | "alias">): string {
  const label = m.alias || m.name;
  return outcome === "forgotten"
    ? `${label} was forgotten. It can no longer connect; reinstalling the agent on it enrolls it as a new machine.`
    : `${label} was already removed. Nothing changed.`;
}

// --- cancel-window countdown -------------------------------------------------------------------------------

export type CancelWindow =
  | { kind: "counting"; msLeft: number }
  | { kind: "ended" } // the window is over; issuance happens at the next sweep
  | { kind: "needs_approval" } // not started: an approval restarts it
  | { kind: "none" }; // nothing to cancel

/** The state of a directive's cancel window at `nowMs`. */
export function cancelWindow(d: AgentDirective, nowMs: number): CancelWindow {
  if (d.state !== "requested") return { kind: "none" };
  if (directiveUiState(d) === "awaiting_approval") return { kind: "needs_approval" };
  const end = Date.parse(d.not_before);
  if (!Number.isFinite(end)) return { kind: "none" };
  const left = end - nowMs;
  return left > 0 ? { kind: "counting", msLeft: left } : { kind: "ended" };
}

/** m:ss for a remaining time, rounded UP so the display never reads 0:00 while cancelling still works. */
export function formatCountdown(msLeft: number): string {
  const total = Math.max(0, Math.ceil(msLeft / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${s < 10 ? "0" : ""}${s}`;
}

/** The request lifetime left (the 410 horizon), or 0 once past. */
export function requestLifetimeLeftMs(d: Pick<AgentDirective, "request_expires_at">, nowMs: number): number {
  const end = Date.parse(d.request_expires_at);
  return Number.isFinite(end) ? Math.max(0, end - nowMs) : 0;
}

/** One read of GET /directives?state=active: the rows fetched and whether the server still had more. */
export interface ActiveDirectiveList {
  rows: ActiveDirective[];
  hasMore: boolean;
}

// --- keeping the pending list fresh ---------------------------------------------------------------------------

/** How often the pending list is re-read, and how often while a removal is inside its cancel window. */
export const POLL_SLOW_MS = 15_000;
export const POLL_FAST_MS = 5_000;

/** The next poll delay: fast while any listed removal is inside (or just past) its cancel window, because its
 *  state is about to change under the operator; otherwise slow. */
export function pollIntervalMs(rows: readonly AgentDirective[], nowMs: number): number {
  for (const d of rows) {
    const w = cancelWindow(d, nowMs).kind;
    if (w === "counting" || w === "ended") return POLL_FAST_MS;
  }
  return POLL_SLOW_MS;
}

/** The visible stale indicator: null while the last refresh succeeded, else says when the data was last good. */
export function staleNotice(failed: boolean, lastOkMs: number | null): string | null {
  if (!failed) return null;
  if (lastOkMs === null) return "Could not refresh — nothing loaded yet";
  const t = new Date(lastOkMs);
  const p = (n: number) => (n < 10 ? "0" : "") + n;
  return `Could not refresh — last updated ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`;
}

// --- errors ------------------------------------------------------------------------------------------------

export interface DirectiveErrorLike {
  status: number;
  message: string;
  code?: string;
}

export type DirectiveAction = "reinstall" | "uninstall" | "approve" | "cancel" | "policy" | "forget";

/** The server's own words: ConsoleApiError messages read "could not <action>: <detail>". */
export function serverDetail(message: string): string {
  const i = message.indexOf(": ");
  return i >= 0 ? message.slice(i + 2) : message;
}

/** True for the 403 the control plane answers when no fresh second-factor verification exists. */
export function isStepUpRequired(e: DirectiveErrorLike): boolean {
  return e.status === 403 && (e.code === "step_up_required" || /second-factor verification is required/i.test(e.message));
}

/**
 * The refusal in plain words, keeping the server's reason: it is quoted for 403 and 409 (which carry the
 * specific rule), and rewritten only where the status alone says what to do.
 */
export function friendlyDirectiveError(e: DirectiveErrorLike, action: DirectiveAction): string {
  const detail = serverDetail(e.message);
  if (isStepUpRequired(e)) return "A recent authenticator code is needed for this. Enter the current 6-digit code and try again.";
  switch (e.status) {
    case 401:
      return "You have been signed out. Sign in again.";
    case 403:
      if (/own directive/i.test(detail)) return "You cannot approve your own request: a different person must approve it.";
      return `Not allowed: ${detail}`;
    case 404:
      return "That machine or request no longer exists (or you can no longer see it).";
    case 409:
      if (/active directive/i.test(detail)) return "This machine already has an agent action in progress. Cancel it or wait for it to finish.";
      if (/only be removed from a retired/i.test(detail)) return "Retire the machine first: an agent can only be removed from a retired machine.";
      if (/only be removed, not reinstalled/i.test(detail)) return "This machine is retired, so its agent can only be removed, not reinstalled.";
      if (/forgotten after it is retired/i.test(detail)) return "Retire the machine first: a machine can only be forgotten once it is retired.";
      if (/changed since it was authorized/i.test(detail)) return "This machine changed while you were working (it was moved to another group). Close this and try again.";
      if (/was removed/i.test(detail)) return "This machine has already been removed.";
      return `Conflict: ${detail}`;
    case 410:
      return "This request expired (requests last 1 hour). Start it again.";
    case 422:
      return /type the machine/i.test(detail) ? "Type the machine's name exactly to confirm." : `Not accepted: ${detail}`;
    case 429:
      if (action === "reinstall") {
        return "Reinstall limit reached: at most 20 reinstalls per hour for the whole organisation and 3 per machine per day. Try again later.";
      }
      if (action === "uninstall") return "Removal limit reached: at most 10 removals per hour for the organisation. Try again later.";
      return "Too many attempts. Wait a moment and try again.";
    default:
      return e.message;
  }
}
