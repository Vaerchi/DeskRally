import type { MgmtAuditEvent } from "./console_api";

/**
 * In-console operator notifications (docs/01 §7 P1 "Session policies … notifications": the genuinely
 * unbuilt half — an in-console real-time badge/banner for noteworthy events while the operator is on
 * a different panel). Out-of-band session webhooks already fire server-side; this is the IN-console
 * surface.
 *
 * This module is the PURE model — a classifier and a reducer over the management audit trail. It does
 * no fetching and no rendering, so every rule is unit-testable. A thin hook polls `GET /audit` and
 * feeds the batches through {@link primeNotificationState} (first load) then {@link ingestAuditEvents};
 * the bell renders {@link NotificationState} via {@link unseenCount}.
 *
 * Correctness notes that shaped this design (a review caught the earlier naive version):
 *  - Dedup is by a BOUNDED set of KNOWN ids ({@link NotificationState.knownIds}), not by the visible
 *    `items`. The `since` cursor is inclusive so a boundary event re-appears every poll, and a
 *    dismissed or capped-out event must still not reappear — neither is in `items`, so `items` is the
 *    wrong dedup source.
 *  - "unseen" is DERIVED from per-item `seen` flags ({@link unseenCount}), never an aggregate counter.
 *    An aggregate cannot stay correct when a single unseen item is dismissed.
 *  - The cursor is a PARSED instant (ms), not a lexical string compare: the server truncates
 *    occurred_at to milliseconds and JSON drops trailing-zero fractions, so "…:00Z" and "…:00.5Z"
 *    do not lexically order by time.
 *  - `primed` lives in the STATE (not a hook ref) so the prime→ingest transition is decided from
 *    React's authoritative previous state and cannot be skipped by a stale ref.
 */

export type NotificationSeverity = "info" | "security";

/**
 * The CURATED set of management-audit actions surfaced to an operator in real time, with a severity.
 * Deliberately small: notifying on every audit row (notes, aliases, installer downloads, automatic
 * session reaps) would be noise that trains operators to ignore the badge. Two families:
 *
 *  - session LIFECYCLE — someone is now on a machine (`session.start`, attended create/connect/promote);
 *  - SECURITY-relevant credential and policy changes an operator should notice even when a DIFFERENT
 *    admin made them (token/grant mint AND revoke, elevation, policy/security/SSO/IP-allowlist edits).
 *
 * Keys are the Go `recordMgmtAudit` literals; a test pins that every key is a real server action.
 */
const NOTABLE_ACTIONS: Readonly<Record<string, NotificationSeverity>> = {
  "session.start": "info",
  "attended.create": "info",
  "attended.connect": "info",
  "attended.promote": "info",
  "machine.enroll": "info",
  // docs/64: an enrolled machine asked for help, and a technician took it. Rendered by the bell for
  // tenant-wide auditors; the actionable queue is the separate "Help requests" list.
  "help.requested": "info",
  "help.accepted": "info",
  "api_token.mint": "security",
  "api_token.revoke": "security",
  "enrollment_token.mint": "security",
  "enrollment_token.revoke": "security",
  "grant.mint": "security",
  "session.elevation_minted": "security",
  "tenant.security_policy.set": "security",
  "tenant.session_policy.set": "security",
  "machine_group.session_policy.set": "security",
  "tenant.ip_allowlist.add": "security",
  "tenant.ip_allowlist.remove": "security",
  "tenant.sso_update": "security",
};

/** The severity of a notable action, or null when the action is not surfaced. */
export function notableSeverity(action: string): NotificationSeverity | null {
  return Object.prototype.hasOwnProperty.call(NOTABLE_ACTIONS, action) ? NOTABLE_ACTIONS[action] : null;
}

/** Whether an action is surfaced as an operator notification at all. */
export function isNotableAction(action: string): boolean {
  return notableSeverity(action) !== null;
}

/** The notable actions this model recognises (stable, sorted) — for tests and documentation. */
export function notableActions(): string[] {
  return Object.keys(NOTABLE_ACTIONS).sort();
}

/** One surfaced notification, derived from a notable {@link MgmtAuditEvent}. */
export interface AuditNotification {
  /** The audit event id — the dedupe key. */
  id: string;
  action: string;
  severity: NotificationSeverity;
  /** RFC3339 occurred_at as the server emitted it (display only; ordering uses the parsed instant). */
  occurredAt: string;
  targetKind?: string;
  targetId?: string;
  actorUserId?: string;
  /** Whether the operator has seen this one. The unseen count is derived from this flag. */
  seen: boolean;
}

export interface NotificationState {
  /** Notable notifications, most-recent-first, capped at {@link MAX_NOTIFICATIONS}. */
  items: AuditNotification[];
  /**
   * Ids of events already processed (notable or not, including ones since dismissed or capped out),
   * bounded to {@link MAX_KNOWN_IDS} most-recent. The dedup source — survives eviction and dismissal.
   */
  knownIds: string[];
  /** The newest occurred_at ingested, as epoch ms; the next poll's `since`. 0 until primed. */
  highWaterMs: number;
  /** True once the baseline has been established (so later ingests surface only genuinely new events). */
  primed: boolean;
}

/** The notification list is capped so a long-lived console cannot grow it without bound. */
export const MAX_NOTIFICATIONS = 50;
/** The dedup memory is bounded too; comfortably larger than one catch-up window. */
export const MAX_KNOWN_IDS = 2000;

export function emptyNotificationState(): NotificationState {
  return { items: [], knownIds: [], highWaterMs: 0, primed: false };
}

/** The number of unseen notifications — DERIVED, never stored. */
export function unseenCount(state: NotificationState): number {
  let n = 0;
  for (const it of state.items) if (!it.seen) n++;
  return n;
}

/** Parse an RFC3339 occurred_at to epoch ms; NaN (unparseable) becomes 0 so it never advances a cursor. */
function instantMs(occurredAt: string): number {
  const ms = Date.parse(occurredAt);
  return Number.isNaN(ms) ? 0 : ms;
}

/** The newest parsed instant (epoch ms) across a batch, or 0 for an empty batch. For the poll cursor. */
export function newestInstantMs(events: readonly MgmtAuditEvent[]): number {
  let max = 0;
  for (const ev of events) {
    const ms = instantMs(ev.occurred_at);
    if (ms > max) max = ms;
  }
  return max;
}

function toNotification(ev: MgmtAuditEvent, severity: NotificationSeverity): AuditNotification {
  return {
    id: ev.id,
    action: ev.action,
    severity,
    occurredAt: ev.occurred_at,
    targetKind: ev.target_kind,
    targetId: ev.target_id,
    actorUserId: ev.actor_user_id,
    seen: false,
  };
}

/** Append new ids and keep only the most-recent {@link MAX_KNOWN_IDS}. */
function rememberIds(knownIds: readonly string[], add: readonly string[]): string[] {
  if (add.length === 0) return knownIds as string[];
  const merged = [...knownIds, ...add];
  return merged.length > MAX_KNOWN_IDS ? merged.slice(merged.length - MAX_KNOWN_IDS) : merged;
}

/**
 * Establish the BASELINE on the first load WITHOUT raising the unseen count: opening the console must
 * not flash historical events as unread. It records the high-water instant AND remembers every fetched
 * id (so the inclusive-`since` boundary events are not re-surfaced as new on the next poll), sets
 * `primed`, and leaves `items` untouched. Only ever moves the high-water mark forward.
 */
export function primeNotificationState(state: NotificationState, fetched: readonly MgmtAuditEvent[]): NotificationState {
  const hw = newestInstantMs(fetched);
  return {
    ...state,
    knownIds: rememberIds(state.knownIds, fetched.map((e) => e.id)),
    highWaterMs: Math.max(state.highWaterMs, hw),
    primed: true,
  };
}

/**
 * Fold a freshly-fetched batch into the state. Only events whose id is NOT already known become
 * candidates; of those, only NOTABLE ones become notifications (unseen). Every processed id is
 * remembered, so the inclusive-`since` boundary event, a dismissed event, and a capped-out event all
 * stay deduped. The high-water instant advances across ALL fetched actions so the cursor does not
 * stall on a run of non-notable events. Items are kept most-recent-first and capped.
 */
export function ingestAuditEvents(state: NotificationState, fetched: readonly MgmtAuditEvent[]): NotificationState {
  const known = new Set(state.knownIds);
  const newIds: string[] = [];
  const added: AuditNotification[] = [];
  for (const ev of fetched) {
    if (known.has(ev.id)) continue;
    known.add(ev.id);
    newIds.push(ev.id);
    const severity = notableSeverity(ev.action);
    if (severity !== null) added.push(toNotification(ev, severity));
  }

  const nextHighWater = Math.max(state.highWaterMs, newestInstantMs(fetched));
  const knownIds = rememberIds(state.knownIds, newIds);
  if (added.length === 0) {
    return { ...state, knownIds, highWaterMs: nextHighWater };
  }

  const merged = [...added, ...state.items].sort((a, b) => {
    const am = instantMs(a.occurredAt);
    const bm = instantMs(b.occurredAt);
    if (am !== bm) return bm - am; // newest first
    return a.id < b.id ? 1 : a.id > b.id ? -1 : 0; // stable tiebreak
  });
  return {
    items: merged.slice(0, MAX_NOTIFICATIONS),
    knownIds,
    highWaterMs: nextHighWater,
    primed: state.primed,
  };
}

/** Mark every notification seen (the operator opened the panel); the derived unseen count becomes 0. */
export function markAllSeen(state: NotificationState): NotificationState {
  if (state.items.every((n) => n.seen)) return state;
  return { ...state, items: state.items.map((n) => (n.seen ? n : { ...n, seen: true })) };
}

/**
 * Remove one notification (operator dismissed it). The id STAYS in knownIds so a boundary re-fetch
 * cannot resurrect it. The unseen count is derived, so dismissing an unseen item lowers it correctly.
 */
export function dismissNotification(state: NotificationState, id: string): NotificationState {
  const items = state.items.filter((n) => n.id !== id);
  if (items.length === state.items.length) return state;
  return { ...state, items };
}
