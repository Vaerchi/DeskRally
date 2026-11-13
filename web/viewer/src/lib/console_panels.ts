/**
 * Management-console panel model + presentation helpers (Milestone M3).
 *
 * The pure logic behind the console panels (`../components/{SessionsPanel,AuditPanel,
 * PlatformPanel,MachinesPanel}.tsx`), following the backstage split (`../backstage/panels.ts` +
 * thin components): row derivation, sorting, badge tones, form validation, and the small
 * API-composition flows (end-and-refresh, create-tenant outcome mapping) — all testable without
 * a DOM. Timestamp rendering reuses `formatIsoUtc` from the backstage panel helpers so both
 * halves of the UI show the same "YYYY-MM-DD HH:MM:SS" UTC convention.
 */

import type { ChartRow } from "./report_chart";
import {
  ConsoleApiError,
  type APIToken,
  type AttendedPromoteResult,
  type AttendedSessionRecord,
  type AttendedState,
  type BulkStatusResult,
  type ConnectedAttendedSession,
  type ConsoleApi,
  type CreateTenantInput,
  type CreatedAttendedSession,
  type DeploymentMode,
  type MachineGroup,
  type MachineProperty,
  type MachineRecord,
  type MgmtAuditEvent,
  type SessionAccessPolicy,
  type SessionRecord,
  type UserSummary,
  type EnrollmentToken,
  type SessionReportFilter,
  type SessionSignaling,
  type Tenant,
  type TenantWebhook,
} from "./console_api";

import { groupPaths, pathLabelFor } from "./group_tree";

/** Sentinel shown for absent fields, matching the "—" convention across the UI. */
const DASH = "—";

/**
 * The display NAME for a machine-group id, resolved against a group list. Falls back to the id itself
 * when the group is not in the list — a group the caller cannot see (out of their narrowed scope) or,
 * defensively, one since removed — so the UI never renders a blank cell. Pure; used by the Deploy tab to
 * label enrollment tokens by group name instead of a raw uuid.
 */
export function groupNameFor(groups: readonly MachineGroup[], id: string): string {
  // The PATH label ("Acme › Site A"), built from the visible groups only (docs/62), so two groups with one
  // name stay distinguishable. A flat list yields the plain name, exactly as before.
  return pathLabelFor(groupPaths(groups), id);
}

/**
 * Best display label for a machine's group: prefer the fetched groups list (freshest names), then the
 * `group_name` the server already joined onto the machine record, and finally the raw id. So even if the
 * groups fetch fails (list empty), the row still shows a human name rather than a uuid. Pure so vitest pins it.
 */
export function groupLabel(
  groups: readonly MachineGroup[],
  groupId: string,
  joinedName: string | undefined,
): string {
  // Path label from the visible groups (docs/62); a group outside the list falls back to the joined name.
  return pathLabelFor(groupPaths(groups), groupId, joinedName);
}

/**
 * Resolve a technician id to a human label for the §5 "sessions by technician" report: the user's email if
 * the id is in the fetched user list, else the raw id (so a technician who has left — no longer in the list —
 * still shows identifiably rather than blank). Pure, so vitest covers it; mirrors {@link groupLabel}.
 */
/**
 * Menu redesign wave 9: ending a session is confirmed, naming the machine and who is disconnected, and saying
 * what it does NOT do (it is not a log off or a restart). An id that is not a readable name (a UUID) is not shown.
 */
export function endSessionConfirmText(machine: string, who: string): string {
  const person = !who || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(who) ? "The technician in it" : who;
  return `End the session on ${machine}? ${person} is disconnected at once. The computer keeps running and nothing on it is closed.`;
}

export function technicianLabel(users: readonly { id: string; email: string }[], technicianId: string): string {
  return users.find((u) => u.id === technicianId)?.email || technicianId;
}

/**
 * Map the CURRENT report's rows to chart rows ({key, label, value}), keying on the STABLE UNIQUE id the table
 * already keys on — machine_id for sessions, technician_id for technicians, the (naturally-unique) action for
 * the audit summary — NOT the display label. A display name (a hostname, a resolved technician label) is not
 * guaranteed unique, so keying the chart on it would duplicate React keys / data-testids when two rows share a
 * name; the id keeps the chart safe. Pure, so vitest pins the key choice; mirrors the table's row keys.
 */
export function reportChartRows(
  reportType: "actions" | "sessions" | "technicians",
  actionRows: readonly { action: string; count: number }[],
  sessionRows: readonly { machine_id: string; machine_name: string; count: number }[],
  techRows: readonly { technician_id: string; technician: string; count: number }[],
): ChartRow[] {
  if (reportType === "sessions") {
    return sessionRows.map((r) => ({ key: r.machine_id, label: r.machine_name, value: r.count }));
  }
  if (reportType === "technicians") {
    return techRows.map((r) => ({ key: r.technician_id, label: r.technician, value: r.count }));
  }
  return actionRows.map((r) => ({ key: r.action, label: r.action, value: r.count }));
}

/**
 * Humanize a capability KEY for the §5 Roles reference: `manage_tenant` → `manage tenant`. The server sends the
 * snake_case rbac keys verbatim (so they can never drift from what is enforced); this only makes them readable.
 * Pure, so vitest covers it.
 */
export function capabilityLabel(cap: string): string {
  return cap.replace(/_/g, " ");
}

// ---------------------------------------------------------------------------
// Tenant security (per-tenant IP allow-list, docs/01 §10)
// ---------------------------------------------------------------------------

/**
 * The message for the IP allow-list's empty-table cell. Distinguishes THREE states that must never be
 * conflated: still loading, a load FAILURE (the list is UNKNOWN — never assert "open"), and a genuinely
 * empty list on a successful load ("open"). The bug this closes: when the acting admin's own source IP
 * is outside a non-empty list, the GET /tenant/ip-allowlist route (itself behind the enforcement
 * middleware) 403s, `cidrs` stays `[]`, and a naive empty-state would claim "the API is open to any
 * network" — the exact opposite of reality (the API is restricting and actively blocking that admin).
 * Pure so it is unit-tested without a DOM.
 */
export function allowlistEmptyStateText(busy: boolean, hasError: boolean): string {
  if (busy) return "Loading…";
  if (hasError) return "Could not load the allow-list — its state is unknown.";
  return "No restriction — the API is open to any network.";
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/** A session is live until the server stamps `ended_at`. */
export type SessionStatus = "live" | "ended";

export function sessionStatus(rec: Pick<SessionRecord, "ended_at">): SessionStatus {
  return rec.ended_at ? "ended" : "live";
}

/** Badge tone for a session's status (live gets the green treatment; ended is neutral). */
export function sessionTone(rec: Pick<SessionRecord, "ended_at">): "good" | "neutral" {
  return sessionStatus(rec) === "live" ? "good" : "neutral";
}

/**
 * Newest-first by `started_at`. The server already returns this order, but the End flow re-lists
 * and the fake stores in tests don't guarantee it — sorting here makes the panel order a UI
 * invariant, not a server courtesy. Unparseable timestamps sink to the end.
 */
export function sortSessionsNewestFirst(rows: readonly SessionRecord[]): SessionRecord[] {
  const at = (r: SessionRecord) => {
    const t = Date.parse(r.started_at);
    return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
  };
  return [...rows].sort((a, b) => at(b) - at(a));
}

/** Human list of a session's backstage caps; "—" when it carried none (nil → JSON null). */
export function capsSummary(caps: readonly string[] | null | undefined): string {
  return caps && caps.length > 0 ? caps.join(", ") : DASH;
}

/**
 * Elapsed duration of a session in whole seconds. For an ended session this is
 * `ended_at − started_at`; for a live session it uses `now` (defaults to `Date.now()` so callers
 * do not need to pass it, but tests can pass a fixed value for determinism). Clamped to 0 for
 * invalid or negative inputs.
 */
export function sessionDurationSeconds(
  rec: Pick<SessionRecord, "started_at" | "ended_at">,
  now = Date.now(),
): number {
  const start = Date.parse(rec.started_at);
  const end = rec.ended_at ? Date.parse(rec.ended_at) : now;
  return Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, Math.floor((end - start) / 1000)) : 0;
}

/** Cell text for a session's machine column: alias if set, hostname, or "—". */
export function machineDisplayText(alias: string, name: string): string {
  return alias || name || DASH;
}

/** Tooltip for the machine cell: the hostname, but only when an alias is shown. */
export function machineDisplayTooltip(alias: string, name: string): string | undefined {
  return alias ? name : undefined;
}

/**
 * Client-side text filter for the fleet table: case-insensitive, across alias (friendly name),
 * hostname (`name`), device id, group name, OS label, logged-in user, and note. Empty or
 * whitespace-only query returns all rows unchanged so the caller does not need to guard for the
 * trivial case.
 */
export function filterMachinesByText(
  rows: readonly MachineRecord[],
  query: string,
): readonly MachineRecord[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (m) =>
      (m.alias ?? "").toLowerCase().includes(q) ||
      m.name.toLowerCase().includes(q) ||
      m.device_id.toLowerCase().includes(q) ||
      (m.group_name ?? "").toLowerCase().includes(q) ||
      (m.os ?? "").toLowerCase().includes(q) ||
      (m.logged_in_user ?? "").toLowerCase().includes(q) ||
      (m.note ?? "").toLowerCase().includes(q),
  );
}

/**
 * Client-side text filter for the sessions table: case-insensitive, across machine alias, machine
 * hostname, device id, technician id, and operator note. Empty or whitespace-only query returns
 * all rows unchanged so the caller does not need to guard for the trivial case.
 */
export function filterSessionsByText(
  rows: readonly SessionRecord[],
  query: string,
): readonly SessionRecord[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (s) =>
      s.machine_alias.toLowerCase().includes(q) ||
      s.machine_name.toLowerCase().includes(q) ||
      s.machine_device_id.toLowerCase().includes(q) ||
      s.technician_id.toLowerCase().includes(q) ||
      s.note.toLowerCase().includes(q),
  );
}

/**
 * Client-side text filter for the audit table: case-insensitive, across action, actor, target kind,
 * target id, and the JSON-stringified metadata details. Empty or whitespace-only query returns all
 * rows unchanged so the caller does not need to guard for the trivial case.
 */
export function filterAuditEventsByText(
  rows: readonly MgmtAuditEvent[],
  query: string,
): readonly MgmtAuditEvent[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (e) =>
      e.action.toLowerCase().includes(q) ||
      (e.actor_user_id ?? "").toLowerCase().includes(q) ||
      (e.target_kind ?? "").toLowerCase().includes(q) ||
      (e.target_id ?? "").toLowerCase().includes(q) ||
      (e.source_ip ?? "").toLowerCase().includes(q) ||
      metadataSummary(e.metadata).toLowerCase().includes(q),
  );
}

/**
 * Client-side text filter for the tenants table: case-insensitive, across slug, name, deployment
 * mode, and id. `disabled` is intentionally not searched — it is a boolean, not a text field.
 * `created_at` is also excluded — use the browser's built-in table sort for date queries. Empty or
 * whitespace-only query returns all rows unchanged so the caller does not need to guard for the
 * trivial case.
 */
export function filterTenantsByText(rows: readonly Tenant[], query: string): readonly Tenant[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (t) =>
      t.slug.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q) ||
      t.deployment_mode.toLowerCase().includes(q) ||
      t.id.toLowerCase().includes(q),
  );
}

/**
 * Client-side text filter for the users table: case-insensitive, across email, display name, and
 * roles (joined as space-separated text so "admin" or "technician" each match). Empty or
 * whitespace-only query returns all rows unchanged so the caller does not need to guard for the
 * trivial case.
 */
export function filterUsersByText(
  rows: readonly UserSummary[],
  query: string,
): readonly UserSummary[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (u) =>
      u.email.toLowerCase().includes(q) ||
      u.display_name.toLowerCase().includes(q) ||
      u.roles.join(" ").toLowerCase().includes(q),
  );
}

/**
 * Client-side text filter for the enrollment tokens table: case-insensitive, across id, group_id,
 * created_by, and the derived status string ("active" or "revoked") so operators can quickly find
 * all active tokens or all tokens for a particular group. `expires_at` is intentionally excluded
 * (a date string; use browser table-sort for date queries). Empty or whitespace-only query returns
 * all rows unchanged so the caller does not need to guard for the trivial case.
 */
export function filterEnrollmentTokensByText(
  rows: readonly EnrollmentToken[],
  query: string,
): readonly EnrollmentToken[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (t) =>
      t.id.toLowerCase().includes(q) ||
      t.group_id.toLowerCase().includes(q) ||
      (t.created_by ?? "").toLowerCase().includes(q) ||
      (t.revoked ? "revoked" : "active").includes(q),
  );
}

/**
 * Client-side text filter for the API tokens table: case-insensitive, across name, id, capabilities
 * (space-joined so "manage" matches any capability containing that substring), and the derived status
 * string ("active" or "revoked"). `expires_at` and `created_at` are intentionally excluded (date
 * fields; use browser table-sort for date queries). Empty or whitespace-only query returns all rows
 * unchanged so the caller does not need to guard for the trivial case.
 */
export function filterAPITokensByText(rows: readonly APIToken[], query: string): readonly APIToken[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (t) =>
      t.name.toLowerCase().includes(q) ||
      t.id.toLowerCase().includes(q) ||
      t.capabilities.join(" ").toLowerCase().includes(q) ||
      (t.revoked_at != null ? "revoked" : "active").includes(q),
  );
}

/**
 * Client-side text filter for the machine groups table: case-insensitive, across name and id.
 * There is no status or derived field on a MachineGroup row. Empty or whitespace-only query returns
 * all rows unchanged so the caller does not need to guard for the trivial case.
 */
export function filterMachineGroupsByText(
  rows: readonly MachineGroup[],
  query: string,
): readonly MachineGroup[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter((g) => g.name.toLowerCase().includes(q) || g.id.toLowerCase().includes(q));
}

/**
 * Client-side text filter for the webhooks table: case-insensitive, across url, id, and the events
 * list (space-joined, so "session" matches both "session.start" and "session.end"). An empty events
 * array is also matched by "all" — the display sentinel shown when a webhook subscribes to every
 * event. `created_at` is intentionally excluded (date field; use browser table-sort for date queries).
 * Empty or whitespace-only query returns all rows unchanged so the caller does not need to guard for
 * the trivial case.
 */
export function filterWebhooksByText(
  rows: readonly TenantWebhook[],
  query: string,
): readonly TenantWebhook[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (w) =>
      w.url.toLowerCase().includes(q) ||
      w.id.toLowerCase().includes(q) ||
      w.events.join(" ").toLowerCase().includes(q) ||
      (w.events.length === 0 && q === "all"),
  );
}

/**
 * Tooltip/title text for the presence dot in the fleet table. Three states:
 * - `presenceKnown && online === true`  → "online"
 * - `presenceKnown && online === false` → "offline"
 * - otherwise (presence feed unavailable, or individual record unknown) → "status unavailable"
 *
 * `presenceKnown` is the listing-level flag from `listMachinesWithPresence()`: when `false`, the
 * signaling feed was unreachable and EVERY record's `online` is absent — rendering them as offline
 * would be a lie. `presenceKnown && online === false` is the only safe "offline" signal.
 */
export function machineOnlineTitle(online: boolean | undefined, presenceKnown: boolean): string {
  if (presenceKnown && online === true) return "online";
  if (presenceKnown && online === false) return "offline";
  return "status unavailable";
}

/**
 * Index a list of LIVE sessions by `machine_device_id` for O(1) per-row badge lookup in the
 * fleet table. Sessions that already carry an `ended_at` are excluded defensively — callers should
 * pass only live sessions from {@link ConsoleApi.listLiveSessions}, but belt-and-suspenders. When
 * two open sessions share a device_id (a transient anomaly), the LAST one in iteration order wins.
 */
export function buildActiveSessionMap(
  sessions: readonly SessionRecord[],
): ReadonlyMap<string, SessionRecord> {
  const m = new Map<string, SessionRecord>();
  for (const s of sessions) {
    if (s.ended_at != null) continue;
    m.set(s.machine_device_id, s);
  }
  return m;
}

/**
 * Compact UTC "since" label for the machine-list session-active badge. Shows only `HH:MM` when
 * the session started on the same UTC calendar day as `now`; shows `Mon DD HH:MM` otherwise.
 * All values are UTC to match {@link formatIsoUtc}. Returns the raw string when it cannot be parsed.
 */
export function formatSessionSince(startedAt: string, now: Date = new Date()): string {
  const d = new Date(startedAt);
  if (Number.isNaN(d.getTime())) return startedAt;
  const pad = (n: number) => String(n).padStart(2, "0");
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  if (
    d.getUTCFullYear() === now.getUTCFullYear() &&
    d.getUTCMonth() === now.getUTCMonth() &&
    d.getUTCDate() === now.getUTCDate()
  ) {
    return time;
  }
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()} ${time}`;
}

/**
 * Full tooltip text for the machine-list session-active badge: "Active since HH:MM UTC · email"
 * (or "Active since Mon DD HH:MM UTC · email" for cross-day sessions). Composes
 * {@link formatSessionSince} and {@link technicianLabel}; pure so vitest covers the combined format.
 */
export function sessionBadgeTooltip(
  session: Pick<SessionRecord, "started_at" | "technician_id">,
  users: readonly { id: string; email: string }[],
  now?: Date,
): string {
  const when = formatSessionSince(session.started_at, now ?? new Date());
  const who = technicianLabel(users, session.technician_id);
  return `Active since ${when} UTC · ${who}`;
}

/**
 * Button label and disabled flag for the "End session" action in the Machines panel fleet table.
 * Extracted from JSX so vitest can cover the label/disabled logic without a DOM.
 *
 * `pendingId` is the session id currently being ended (null = none in flight). `disabled` is true
 * whenever ANY end-session call is in flight — not just this row — so a second click on a different
 * row cannot race the first.
 */
export function endSessionButtonProps(
  sessionId: string,
  pendingId: string | null,
): { label: string; disabled: boolean } {
  return {
    label: pendingId === sessionId ? "Ending\u2026" : "End session",
    disabled: pendingId !== null,
  };
}

/**
 * One-line outcome of a BULK machine-status change (docs/01 §4): "N updated" when all succeeded, else
 * "N updated, M failed" so the operator sees that some machines were skipped (out of their groups / gone).
 * Pure so vitest pins the count arithmetic.
 */
export function bulkStatusSummary(results: readonly BulkStatusResult[]): string {
  const ok = results.filter((r) => r.ok).length;
  const failed = results.length - ok;
  return failed === 0 ? `${ok} updated` : `${ok} updated, ${failed} failed`;
}

/** Human summary of a bulk GROUP reassignment: how many machines moved, and how many were skipped. */
export function bulkGroupSummary(results: readonly BulkStatusResult[]): string {
  const ok = results.filter((r) => r.ok).length;
  const failed = results.length - ok;
  return failed === 0 ? `${ok} moved` : `${ok} moved, ${failed} failed`;
}

/**
 * Confine a bulk selection to the machines actually VISIBLE in the current list: the intersection of the
 * selected ids with `visibleIds`. A bulk selection must never outlive the on-screen rows — when the list
 * re-fetches (a property filter applied/cleared, a Refresh), a machine that drops off screen has to drop out
 * of the selection too, or a destructive bulk action (quarantine/retire) could silently hit machines the
 * operator can no longer see, and the "N selected" count / select-all would misrepresent the view. Pure, so
 * vitest pins the intersection.
 */
export function prunedSelection(
  selected: ReadonlySet<string>,
  visibleIds: readonly string[],
): Set<string> {
  const visible = new Set(visibleIds);
  const next = new Set<string>();
  for (const id of selected) if (visible.has(id)) next.add(id);
  return next;
}

/**
 * Format a whole-second duration as a compact human string ("1h 2m 3s", "2m 3s", "45s", "0s") for the
 * §5 usage-hours report. Leading zero units are dropped but seconds always show; a negative/NaN input
 * clamps to "0s". Pure so vitest pins the formatting.
 */
export function formatDurationSeconds(total: number): string {
  const s = Number.isFinite(total) ? Math.max(0, Math.floor(total)) : 0;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts: string[] = [];
  if (h > 0) parts.push(`${h}h`);
  if (h > 0 || m > 0) parts.push(`${m}m`);
  parts.push(`${sec}s`);
  return parts.join(" ");
}

/**
 * End a session, then return the refreshed (newest-first) list — the SessionsPanel "End" flow as
 * one testable step. Errors from either call propagate to the caller's error surface. The re-list HONORS the
 * caller's applied date filter (if any) so a row action does not silently revert a filtered view to all-time.
 */
export async function endSessionAndRefresh(
  api: Pick<ConsoleApi, "endSession" | "listSessions">,
  sessionId: string,
  filter?: SessionReportFilter,
): Promise<SessionRecord[]> {
  await api.endSession(sessionId);
  return sortSessionsNewestFirst(await api.listSessions(filter));
}

/**
 * Save a session's free-text note (docs/01 §7), then return the refreshed, newest-first list — the
 * write-then-relist flow the Sessions panel drives, kept here (not in the .tsx) so it is unit-tested. The
 * re-list HONORS the caller's applied date filter (if any).
 */
export async function setSessionNoteAndRefresh(
  api: Pick<ConsoleApi, "setSessionNote" | "listSessions">,
  sessionId: string,
  note: string,
  filter?: SessionReportFilter,
): Promise<SessionRecord[]> {
  await api.setSessionNote(sessionId, note);
  return sortSessionsNewestFirst(await api.listSessions(filter));
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** The limit choices the AuditPanel's selector offers (server default is 200). */
export const AUDIT_LIMIT_CHOICES = [25, 50, 100, 200] as const;
export const DEFAULT_AUDIT_LIMIT = 50;

/** Actor column: the acting user, or "system" for server-initiated events (empty actor). */
export function formatActor(e: Pick<MgmtAuditEvent, "actor_user_id">): string {
  return e.actor_user_id || "system";
}

/** Target column: "kind:id" when both are present, the kind alone, else "—". */
export function formatAuditTarget(e: Pick<MgmtAuditEvent, "target_kind" | "target_id">): string {
  if (e.target_kind && e.target_id) return `${e.target_kind}:${e.target_id}`;
  return e.target_kind || DASH;
}

/** Compact one-line metadata rendering; empty string when there is none (keeps the cell blank). */
export function metadataSummary(metadata: unknown): string {
  if (metadata === undefined || metadata === null) return "";
  try {
    return JSON.stringify(metadata);
  } catch {
    return String(metadata);
  }
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

/** The deployment modes the create form offers (mirrors Go `ValidDeploymentMode`). */
export const DEPLOYMENT_MODES: readonly DeploymentMode[] = ["saas", "self_hosted"];

/** Status badge for a tenant row. */
export function tenantTone(t: Pick<Tenant, "disabled">): "good" | "bad" {
  return t.disabled ? "bad" : "good";
}

export interface TenantFormState {
  slug: string;
  name: string;
  mode: DeploymentMode;
}

export type TenantFormValidation =
  | { ok: true; input: CreateTenantInput }
  | { ok: false; message: string };

/**
 * Trim + validate the create-tenant form, mirroring the server's checks (slug and name required;
 * mode constrained by the select but re-checked here) so obvious misses never leave the browser.
 */
export function validateTenantForm(form: TenantFormState): TenantFormValidation {
  const slug = form.slug.trim();
  const name = form.name.trim();
  if (slug === "" || name === "") return { ok: false, message: "slug and name are required" };
  if (!DEPLOYMENT_MODES.includes(form.mode)) {
    return { ok: false, message: `unknown deployment mode "${form.mode}"` };
  }
  return { ok: true, input: { slug, name, deploymentMode: form.mode } };
}

// ---------------------------------------------------------------------------
// Attended sessions (docs/12 §9)
// ---------------------------------------------------------------------------

/**
 * DEV-mode default machine group (`DevDefaultMachineGroupID` server-side) — the panel's initial
 * group value so the flow works out of the box against a DEV control plane; production operators
 * paste a real group id (visible on the Machines panel).
 */
export const DEFAULT_ATTENDED_GROUP = "00000000-0000-0000-0000-000000000000";

/** How often the panel re-polls `GET /attended-sessions/{id}` while awaiting consent. */
export const ATTENDED_POLL_MS = 2000;

/** Badge tone per attended state (the consent-open states get the green treatment). */
export function attendedTone(state: AttendedState): "good" | "neutral" | "bad" {
  switch (state) {
    case "consented":
    case "active":
      return "good";
    case "declined":
    case "expired":
      return "bad";
    default:
      return "neutral";
  }
}

/**
 * Connect is enabled ONLY in the consent-open states. The panel keys this off the polled state
 * (never off probing `/connect`) — each successful connect writes an audit event and re-mints a
 * ticket, so the gate probe must not double as the poll.
 */
export function canConnectAttended(state: AttendedState): boolean {
  return state === "consented" || state === "active";
}

/** Terminal states — the consent poll stops here. */
export function attendedPollDone(state: AttendedState): boolean {
  return state === "declined" || state === "ended" || state === "expired";
}

/** One-line technician guidance per state, shown beside the badge. */
export function attendedStateHint(state: AttendedState): string {
  switch (state) {
    case "pending":
      return "Share the code or join link with the user.";
    case "redeemed":
      return "The user is looking at the consent prompt…";
    case "consented":
      return "Consent granted — you can connect.";
    case "active":
      return "Session active.";
    case "declined":
      return "The user declined the session.";
    case "ended":
      return "Session ended.";
    case "expired":
      return "The code or session expired.";
  }
}

/**
 * Derive the technician-visible promote result message from the latest session record.
 * Returns `{ pending: true }` when the technician clicked Promote but no result is back yet,
 * or `{ pending: false, text }` when the guest has reported an outcome.
 */
export function promoteResultMessage(
  promoted: boolean,
  result: AttendedPromoteResult | undefined,
): { pending: true } | { pending: false; text: string | null } {
  if (!promoted) return { pending: false, text: null };
  if (!result) return { pending: true };
  const err = result.error ?? "";
  const cancelled =
    err.includes("declined") || err.includes("cancelled") || err.includes("UAC");
  const text = result.success
    ? "Installation succeeded. The service will appear in the fleet when it connects."
    : cancelled
    ? "The guest cancelled the installation. You can request it again."
    : `Installation failed: ${err || "unknown error"}. Ask the guest to share the error message.`;
  return { pending: false, text };
}

/**
 * Group a raw attend code for display ("ABCDEF" → "ABCD-EF"), mirroring the Go `GroupAttendCode`
 * (groups of 4). The raw form stays the canonical value for the CLI/join link; redemption is
 * case/dash-insensitive server-side, so grouping is purely cosmetic.
 */
export function groupAttendCode(code: string): string {
  const groups: string[] = [];
  for (let i = 0; i < code.length; i += 4) groups.push(code.slice(i, i + 4));
  return groups.join("-");
}

export type StartAttendedOutcome =
  | { ok: true; created: CreatedAttendedSession }
  | { ok: false; message: string };

/**
 * The AttendedPanel "Start" flow as one testable step: validate the group id, create, and map
 * failures to the panel's error surface.
 */
export async function startAttendedFlow(
  api: Pick<ConsoleApi, "createAttendedSession">,
  groupId: string,
  reason: string,
): Promise<StartAttendedOutcome> {
  const group = groupId.trim();
  if (group === "") return { ok: false, message: "group id is required" };
  try {
    return { ok: true, created: await api.createAttendedSession(group, reason.trim()) };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

export type ConnectAttendedOutcome =
  | { ok: true; connected: ConnectedAttendedSession }
  | { ok: false; awaitingConsent: boolean; message: string };

/**
 * The AttendedPanel "Connect" flow: hit the consent gate and map a 409 (`kind === "conflict"`)
 * to `awaitingConsent` so the panel shows "still awaiting consent" instead of a raw error —
 * the gate can race the poll (consent can be withdrawn by expiry between poll and click).
 */
export async function connectAttendedFlow(
  api: Pick<ConsoleApi, "connectAttendedSession">,
  id: string,
): Promise<ConnectAttendedOutcome> {
  try {
    return { ok: true, connected: await api.connectAttendedSession(id) };
  } catch (e) {
    if (e instanceof ConsoleApiError) {
      return { ok: false, awaitingConsent: e.kind === "conflict", message: e.message };
    }
    return { ok: false, awaitingConsent: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * What an attended connect hands the live workspace: the same envelope an ordinary brokered start
 * produces, derived from the attended connect response.
 *
 * WHY THIS IS A FUNCTION AND NOT THREE ARGUMENTS. This mapping used to live inline across two
 * component hops — AttendedPanel spread the response into `onConnect(session, signaling, policy)`
 * and App.tsx reassembled it into a pre-acquired envelope — and neither hop had any test. That is
 * the shape loop 80's review found twice on the unattended path: a field that is only ever carried
 * by TYPES is not carried at all, and the failure is silent (the session simply runs unrestricted
 * while the console believes a mandate is in force).
 *
 * Passing the whole response through as ONE value removes the drop site rather than testing it: a
 * field nobody destructures cannot be forgotten. What remains is this pure mapping, which a test
 * can pin.
 */
export type AttendedHandoff = {
  deviceId: string;
  /** Workspace label — the guest's stated reason when there is one. */
  label: string;
  signalingUrl: string;
  /** The pre-acquired session envelope: the consent gate already minted the ticket. */
  preAcquired: {
    sessionId: string;
    signaling: SessionSignaling;
    sessionPolicy?: SessionAccessPolicy;
  };
};

export function attendedHandoff(connected: ConnectedAttendedSession): AttendedHandoff {
  const { session, signaling } = connected;
  return {
    // The DEVICE id comes from the signaling envelope, not the session record: it is the EPHEMERAL
    // device redemption minted, and it is what the agent binds its policy and its ticket to.
    deviceId: signaling.device_id,
    label: session.reason ? `Attended: ${session.reason}` : "Attended session",
    signalingUrl: signaling.url,
    preAcquired: {
      sessionId: session.id,
      signaling,
      // Forwarded, never dropped. An attended machine is ephemeral but NOT group-less — redemption
      // enrols it into the invite's group — so a per-group view-only mandate applies here exactly as
      // it does to an ordinary session.
      sessionPolicy: connected.session_policy,
    },
  };
}

/** Poll step: fetch the latest state, mapping failures to null (the poll silently retries). */
export async function pollAttendedSession(
  api: Pick<ConsoleApi, "getAttendedSession">,
  id: string,
): Promise<AttendedSessionRecord | null> {
  try {
    return await api.getAttendedSession(id);
  } catch {
    return null;
  }
}

export type CreateTenantOutcome =
  | { ok: true; tenant: Tenant }
  | { ok: false; slugTaken: boolean; message: string; status?: number };

/**
 * The PlatformPanel create flow as one testable step: validate, create, and map the failure shape —
 * a 409 (`kind === "conflict"`) becomes `slugTaken: true` so the panel can show the inline
 * "slug taken" error on the field rather than a generic banner.
 */
export async function submitCreateTenant(
  api: Pick<ConsoleApi, "createTenant">,
  form: TenantFormState,
): Promise<CreateTenantOutcome> {
  const validated = validateTenantForm(form);
  if (!validated.ok) return { ok: false, slugTaken: false, message: validated.message };
  try {
    return { ok: true, tenant: await api.createTenant(validated.input) };
  } catch (e) {
    if (e instanceof ConsoleApiError) {
      return { ok: false, slugTaken: e.kind === "conflict", message: e.message, status: e.status };
    }
    return { ok: false, slugTaken: false, message: e instanceof Error ? e.message : String(e) };
  }
}

// ---------------------------------------------------------------------------
// Machine custom properties (docs/01 §4)
// ---------------------------------------------------------------------------

export interface PropertyFormState {
  key: string;
  value: string;
}

export type PropertyFormValidation =
  | { ok: true; key: string; value: string }
  | { ok: false; message: string };

/**
 * Trim + require a key (an empty VALUE is allowed — it clears a field to blank), mirroring the
 * server's "key is required" check so the panel shows the error inline before a round trip.
 */
export function validatePropertyForm(form: PropertyFormState): PropertyFormValidation {
  const key = form.key.trim();
  if (key === "") return { ok: false, message: "key is required" };
  return { ok: true, key, value: form.value };
}

/**
 * Stable A→Z key order as a UI invariant. The server already sorts (ORDER BY key), but a test fake
 * or an older server need not, and the table renders whatever order it is handed — so sort here too.
 */
export function sortPropertiesByKey(rows: readonly MachineProperty[]): MachineProperty[] {
  return [...rows].sort((a, b) => a.key.localeCompare(b.key));
}

/** Upsert one property then return the refreshed, sorted list — the add flow as one testable step. */
export async function setPropertyAndRefresh(
  api: Pick<ConsoleApi, "setMachineProperty" | "listMachineProperties">,
  machineId: string,
  key: string,
  value: string,
): Promise<MachineProperty[]> {
  await api.setMachineProperty(machineId, key, value);
  return sortPropertiesByKey(await api.listMachineProperties(machineId));
}

/** Delete one property then return the refreshed, sorted list — the remove flow as one testable step. */
export async function deletePropertyAndRefresh(
  api: Pick<ConsoleApi, "deleteMachineProperty" | "listMachineProperties">,
  machineId: string,
  key: string,
): Promise<MachineProperty[]> {
  await api.deleteMachineProperty(machineId, key);
  return sortPropertiesByKey(await api.listMachineProperties(machineId));
}

/**
 * Convert a `datetime-local` input value (`"YYYY-MM-DDTHH:MM"`, optionally with `":SS"`, and never a
 * timezone) into an RFC3339 instant the audit API accepts. The value is interpreted as **UTC** — the
 * audit panel shows every timestamp in UTC, so the filter must read in UTC too, and treating the input
 * as UTC also makes this pure + deterministic (no dependence on the browser's local timezone). An empty
 * value yields `""` (no filter). Seconds are appended when the input omits them, then a `Z` suffix.
 */
export function datetimeLocalToUtcRfc3339(value: string): string {
  const v = value.trim();
  if (v === "") return "";
  const withSeconds = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(v) ? `${v}:00` : v;
  return `${withSeconds}Z`;
}

/**
 * Compact UTC timestamp for a webhook delivery attempt. Shows `HH:MM:SS` when the attempt
 * occurred on the same UTC calendar day as `now`; shows `YYYY-MM-DD HH:MM:SS` otherwise.
 * Returns the raw string when the value cannot be parsed as a date.
 *
 * `now` defaults to `new Date()` so callers pass nothing; tests inject a fixed date.
 */
export function formatDeliveryTime(iso: string, now: Date = new Date()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  const hms = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  if (
    d.getUTCFullYear() === now.getUTCFullYear() &&
    d.getUTCMonth() === now.getUTCMonth() &&
    d.getUTCDate() === now.getUTCDate()
  ) {
    return hms + " UTC";
  }
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${hms} UTC`;
}

/**
 * Returns true when a machine's self-reported agent version differs from the operator-designated
 * published version. "Differs" means any mismatch — older OR newer. The console shows a neutral
 * "⚠ mismatch" badge in both directions because the comparison is a string equality check, not
 * a semver parse; a canary/pre-production build ahead of the published string is equally
 * unexpected from an operator's fleet-uniformity perspective.
 *
 * Safe defaults: a missing publishedVersion ("not configured") or a missing machineVersion
 * ("never reported") both return false. An absent target cannot classify anything as a mismatch,
 * and an absent machine version cannot be compared — both are "unknown", not "different".
 *
 * Mutation targets:
 *   M1 — remove `!publishedVersion` guard → undefined target classifies every machine as matching
 *   M2 — remove `!machineVersion` guard → a machine that never reported shows the badge
 *   M3 — remove `!==` comparison → every machine shows the badge (including already-matching ones)
 */
export function isAgentVersionOutdated(
  machineVersion: string | undefined,
  publishedVersion: string | null | undefined,
): boolean {
  if (!publishedVersion) return false;
  if (!machineVersion) return false;
  return machineVersion !== publishedVersion;
}


