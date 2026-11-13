/**
 * CSV serialization for the §5 Reports export. Pure and dependency-free so vitest can see it (logic in a
 * `.tsx` render body gets no unit coverage — same rule as setup_link.ts / attend_link.ts).
 *
 * RFC 4180: fields are separated by commas and rows by CRLF; a field that contains a comma, a double
 * quote, or a line break is wrapped in double quotes with any internal quote doubled. Today's action
 * names are safe dotted identifiers, but escaping defensively keeps the export correct if the trail ever
 * carries a richer value, and it is what makes the serializer worth unit-testing.
 *
 * F17 — CSV formula-injection hardening: untrusted TEXT fields (machine names, aliases, OS strings,
 * group names, technician labels, audit action/actor/target/metadata) are checked for leading patterns
 * that a spreadsheet might evaluate as a formula. Risky values are prefixed with the visible literal
 * "[text] " before the entire original string; the prefix itself never starts with a formula character.
 * Number-typed fields (count, total_seconds) bypass this entirely and remain bare numerics.
 */

import type { APIToken, AuditActionCount, EnrollmentToken, MachineGroup, MachineRecord, MachineSessionCount, MgmtAuditEvent, SessionRecord, Tenant, TenantWebhook, UserSummary } from "./console_api";
import type { SiteRow } from "./sites";

import type { BulkRow } from "./bulk_types";

/**
 * Export a snapshot in caller order. All text uses the shared neutralizer; exit codes remain
 * numeric so negative exit codes keep their meaning in spreadsheets. Missing values stay empty.
 */
export function bulkResultsToCsv(rows: readonly BulkRow[]): string {
  const lines = [
    "device_id,machine,alias,state,exit_code,reason,output_head,agent_truncated,console_truncated",
    ...rows.map((r) => [
      csvTextField(r.deviceId),
      csvTextField(r.machineName),
      csvTextField(r.alias ?? ""),
      csvTextField(r.state),
      r.outcome?.exitCode === undefined ? "" : csvField(String(r.outcome.exitCode)),
      csvTextField(r.outcome?.reason ?? ""),
      csvTextField(r.outcome?.outputHead ?? ""),
      r.outcome?.agentTruncated === undefined ? "" : String(r.outcome.agentTruncated),
      r.outcome?.consoleTruncated === undefined ? "" : String(r.outcome.consoleTruncated),
    ].join(",")),
  ];
  return lines.join("\r\n") + "\r\n";
}

/** Quote a field iff RFC 4180 requires it (comma, quote, CR, or LF), doubling any internal quote. */
function csvField(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/**
 * Returns true when a text cell value starts with a pattern a spreadsheet might treat as a formula.
 *
 * Risky patterns:
 * - Leading ASCII formula-trigger characters: = + - @ and their fullwidth equivalents ＝ ＋ － ＠,
 *   even when preceded by whitespace (including regular space), BOM, or C0/DEL control characters.
 * - A bare leading tab, CR, LF, BOM, or other control character even without a subsequent operator
 *   (spreadsheets and CSV parsers may mishandle these regardless of what follows).
 *
 * Empty strings are never risky. Numeric string representations (e.g. "-5") that come from
 * number-typed fields never pass through this function.
 */
function isRiskyText(value: string): boolean {
  const leading = value.match(/^[\s\x00-\x1F\x7F]*/)?.[0] ?? "";
  // Inspect the whole leading run: ordinary spaces must not hide a later control character.
  return /[\x00-\x1F\x7F\uFEFF]/.test(leading) || /^[=+\-@＝＋－＠]/.test(value.slice(leading.length));
}

/**
 * Apply formula-injection hardening to a TEXT field, then RFC 4180-quote it.
 *
 * Risky values are prefixed with "[text] " (including a trailing space) before the ENTIRE original
 * string so the original bytes are preserved after the marker and a reader can distinguish altered
 * cells. The "[text] " prefix itself begins with "[", which is not a formula trigger.
 *
 * IMPORTANT: number-typed fields (count, total_seconds) must use csvField(String(n)) directly so
 * negative numbers and exponent notation survive unchanged.
 */
export function csvTextField(value: string): string {
  // Always quote altered text, including its original delimiters and control characters.
  return isRiskyText(value) ? `"[text] ${value.replace(/"/g, '""')}"` : csvField(value);
}

/** Tri-state presence as text: absent = unknown, NOT offline. */
function onlineLabel(v: boolean | undefined): string {
  return v === true ? "online" : v === false ? "offline" : "unknown";
}

/**
 * Serialize an audit-summary (action → count) to a CSV document: an `action,count` header followed by one
 * CRLF-terminated row per entry, in the order given. Always ends with a trailing CRLF so the last record
 * is terminated. An empty summary yields just the header row.
 */
export function auditSummaryToCsv(rows: readonly AuditActionCount[]): string {
  const lines = ["action,count", ...rows.map((r) => `${csvTextField(r.action)},${csvField(String(r.count))}`)];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize a sessions-by-machine report (machine → session count + total completed session time) to a CSV
 * document: a `machine,sessions,total_seconds` header followed by one CRLF-terminated row per machine, in
 * the order given. total_seconds stays RAW (whole seconds) so a spreadsheet can sum/pivot it — the human
 * "1m 30s" form is a display concern. Machine names can carry commas/quotes, so each field is RFC 4180-
 * escaped. An empty report yields just the header row.
 */
export function machineSessionsToCsv(rows: readonly MachineSessionCount[]): string {
  const lines = [
    "machine,sessions,total_seconds",
    ...rows.map(
      (r) => `${csvTextField(r.machine_name)},${csvField(String(r.count))},${csvField(String(r.total_seconds))}`,
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the (already filtered) management audit trail to a CSV document — an
 * `occurred_at,action,actor,target_kind,target_id,metadata` header followed by one CRLF-terminated row per
 * event, in the order given (the server's newest-first). Absent optional fields render as an empty cell;
 * `metadata` (arbitrary jsonb) is JSON-stringified so a spreadsheet keeps it in ONE cell — and since that JSON
 * is full of commas and quotes, EVERY field is RFC 4180-escaped (this is the whole reason the serializer is
 * worth unit-testing). This CSV is a human/offline analysis export — NOT the tamper-evident record; the
 * hash-chained NDJSON backstage-audit export is the verifiable one.
 */
/**
 * Serialize the fleet listing (docs/01 §4) to a CSV inventory export — a
 * `name,alias,device_id,group,status,os,online,last_seen,id` header followed by one CRLF-terminated row per
 * machine, in the order given. `name` is the agent-reported hostname and `alias` the tenant friendly name
 * (either can carry commas/quotes → every field is RFC 4180-escaped, the reason this is worth unit-testing);
 * `group` is the joined group NAME (empty when unresolved), `status` defaults to "active" for an old server
 * that omits it, and `online` renders the tri-state `*bool` as online/offline/unknown (absent = unknown, NOT
 * offline — a presence-feed hiccup must not read as down). An empty fleet yields just the header row.
 */
export function machinesToCsv(rows: readonly MachineRecord[]): string {
  const lines = [
    "name,alias,device_id,group,status,os,online,last_seen,id",
    ...rows.map((m) =>
      [
        m.name,
        m.alias ?? "",
        m.device_id,
        m.group_name ?? "",
        m.status ?? "active",
        m.os ?? "",
        onlineLabel(m.online),
        m.last_seen ?? "",
        m.id,
      ].map(csvTextField).join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the Sites view rows to a CSV document — a `site,site_state,name,alias,device_id,group,status,
 * online,id` header followed by one CRLF-terminated row per row, in the order given. `site` carries the
 * stored value ONLY for a `set` row (an empty stored value is still `set`, with an empty cell); `none` and
 * `unknown` rows leave it empty and say which in `site_state`, so an unreadable site is never exported as
 * "no site". Every text cell passes through formula-injection hardening (the site is user-entered).
 */
export function sitesToCsv(rows: readonly SiteRow[]): string {
  const lines = [
    "site,site_state,name,alias,device_id,group,status,online,id",
    ...rows.map(({ machine: m, site }) =>
      [
        site.kind === "set" ? site.value : "",
        site.kind,
        m.name,
        m.alias ?? "",
        m.device_id,
        m.group_name ?? "",
        m.status ?? "active",
        onlineLabel(m.online),
        m.id,
      ].map(csvTextField).join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize a sessions-by-technician report to a CSV document: a `technician,sessions,total_seconds` header
 * followed by one CRLF-terminated row per technician, in the order given. `technician` is the display label
 * the caller already resolved (an email, or a raw id for a departed user) — it can carry commas/quotes, so
 * each field is RFC 4180-escaped. total_seconds stays RAW (whole seconds) so a spreadsheet can sum/pivot it.
 * An empty report yields just the header row.
 */
export function technicianSessionsToCsv(
  rows: readonly { technician: string; count: number; total_seconds: number }[],
): string {
  const lines = [
    "technician,sessions,total_seconds",
    ...rows.map(
      (r) => `${csvTextField(r.technician)},${csvField(String(r.count))},${csvField(String(r.total_seconds))}`,
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the (already filtered) sessions listing to a CSV document — a
 * `status,started_at,ended_at,duration_seconds,machine,machine_alias,device_id,technician_id,note,id`
 * header followed by one CRLF-terminated row per session, in the order given (newest first from the
 * caller). An empty list yields just the header row.
 *
 * `duration_seconds` is a non-negative integer computed from `started_at`/`ended_at`; live sessions
 * use `now` (defaults to `Date.now()`) so the export instant is the snapshot time. `ended_at` is
 * empty for live sessions. Text fields pass through formula-injection hardening before RFC 4180
 * quoting; `duration_seconds` is numeric and bypasses the formula check (F17).
 */
export function sessionsToCsv(rows: readonly SessionRecord[], now = Date.now()): string {
  const lines = [
    "status,started_at,ended_at,duration_seconds,machine,machine_alias,device_id,technician_id,note,id",
    ...rows.map((s) => {
      const start = Date.parse(s.started_at);
      const end = s.ended_at ? Date.parse(s.ended_at) : now;
      const dur = Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, Math.floor((end - start) / 1000)) : 0;
      return [
        csvTextField(s.ended_at ? "ended" : "live"),
        csvTextField(s.started_at),
        csvTextField(s.ended_at ?? ""),
        csvField(String(dur)), // numeric — bypass F17 formula check
        csvTextField(s.machine_name),
        csvTextField(s.machine_alias),
        csvTextField(s.machine_device_id),
        csvTextField(s.technician_id),
        csvTextField(s.note),
        csvTextField(s.id),
      ].join(",");
    }),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the user listing to a CSV document — an `email,display_name,roles,status,id`
 * header followed by one CRLF-terminated row per user, in the order given. `roles` is
 * pipe-separated (`|`) so it cannot split the CSV column even when a user holds multiple
 * roles. Formula-injection hardening applies to all text fields. An empty list yields just
 * the header row.
 */
export function usersToCsv(rows: readonly UserSummary[]): string {
  const lines = [
    "email,display_name,roles,status,id",
    ...rows.map((u) =>
      [u.email, u.display_name, u.roles.join("|"), u.disabled ? "disabled" : "active", u.id].map(csvTextField).join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the tenant roster to a CSV document — a `status,slug,name,mode,created_at,id`
 * header followed by one CRLF-terminated row per tenant, in the order given. `status` is
 * "active" or "disabled" (derived from `disabled`). Formula-injection hardening applies to all
 * text fields. An empty list yields just the header row.
 */
export function tenantsToCsv(rows: readonly Tenant[]): string {
  const lines = [
    "status,slug,name,mode,created_at,id",
    ...rows.map((t) =>
      [t.disabled ? "disabled" : "active", t.slug, t.name, t.deployment_mode, t.created_at, t.id]
        .map(csvTextField)
        .join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the enrollment token roster to a CSV document — a
 * `group_id,expires_at,uses,max_uses,status,created_at,created_by,id` header followed by one
 * CRLF-terminated row per token, in the order given. `status` is "active" or "revoked" (derived
 * from `revoked`). `uses` and `max_uses` are bare numerics (no formula-injection risk). Formula-
 * injection hardening applies to all text fields. An empty list yields just the header row.
 */
export function enrollmentTokensToCsv(rows: readonly EnrollmentToken[]): string {
  const lines = [
    "group_id,expires_at,uses,max_uses,status,created_at,created_by,id",
    ...rows.map((t) =>
      [
        csvTextField(t.group_id),
        csvTextField(t.expires_at ?? ""),
        String(t.uses),
        String(t.max_uses),
        csvTextField(t.revoked ? "revoked" : "active"),
        csvTextField(t.created_at),
        csvTextField(t.created_by ?? ""),
        csvTextField(t.id),
      ].join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * Serialize the API token roster to a CSV document — a
 * `name,id,capabilities,expires_at,status,created_at` header followed by one CRLF-terminated row
 * per token, in the order given. `capabilities` are joined with `|` to avoid comma ambiguity in
 * spreadsheet tools. `status` is "active" or "revoked" (derived from `revoked_at`). Formula-
 * injection hardening applies to all text fields. An empty list yields just the header row.
 */
export function apiTokensToCsv(rows: readonly APIToken[]): string {
  const lines = [
    "name,id,capabilities,expires_at,status,created_at",
    ...rows.map((t) =>
      [
        csvTextField(t.name),
        csvTextField(t.id),
        csvTextField(t.capabilities.join("|")),
        csvTextField(t.expires_at ?? ""),
        csvTextField(t.revoked_at != null ? "revoked" : "active"),
        csvTextField(t.created_at),
      ].join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

export function auditEventsToCsv(events: readonly MgmtAuditEvent[]): string {
  const lines = [
    "occurred_at,action,actor,target_kind,target_id,metadata,source_ip",
    ...events.map((e) =>
      [
        e.occurred_at,
        e.action,
        e.actor_user_id ?? "",
        e.target_kind ?? "",
        e.target_id ?? "",
        e.metadata === undefined || e.metadata === null ? "" : JSON.stringify(e.metadata),
        e.source_ip ?? "",
      ].map(csvTextField).join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}

export function machineGroupsToCsv(rows: readonly MachineGroup[]): string {
  const lines = [
    "name,id",
    ...rows.map((g) => [csvTextField(g.name), csvTextField(g.id)].join(",")),
  ];
  return lines.join("\r\n") + "\r\n";
}

export function webhooksToCsv(rows: readonly TenantWebhook[]): string {
  const lines = [
    "id,url,events,created_at",
    ...rows.map((w) =>
      [
        csvTextField(w.id),
        csvTextField(w.url),
        csvTextField(w.events.length === 0 ? "all" : w.events.join("|")),
        csvTextField(w.created_at),
      ].join(","),
    ),
  ];
  return lines.join("\r\n") + "\r\n";
}
