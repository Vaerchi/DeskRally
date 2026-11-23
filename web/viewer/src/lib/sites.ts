/**
 * Sites (docs/01 §4): a machine's site is its existing `site` custom property — no new schema, no new
 * wire field. This module owns the pure Sites-view logic: load every visible machine with its site,
 * group by site, and set/clear ONE machine's site without touching its other properties.
 *
 * A site is display/organisation metadata only. Like every machine property it grants and restricts
 * nothing — authorization stays on the machine's access & policy group (`group_id`).
 *
 * Honesty rules the view depends on:
 *  - A machine whose properties could not be read is UNKNOWN, never "no site".
 *  - A save is reported only after the server confirms the exact key/value it stored.
 *  - A refresh that started before a save completed must not overwrite that save (`applyOverrides`).
 */

import type { ConsoleApi, MachineRecord } from "./console_api";

/** The property key the Sites view reads and writes. Existing data uses exactly this key. */
export const SITE_PROPERTY_KEY = "site";

/** Server-side cap on a property value, in UTF-8 bytes (control-plane maxMachinePropertyValueLen, compared with Go `len`). */
export const MAX_SITE_LEN = 4096;

export type SiteState =
  | { kind: "set"; value: string }
  | { kind: "none" }
  | { kind: "unknown"; error: string };

export interface SiteRow {
  machine: MachineRecord;
  site: SiteState;
}

export interface SitesLoad {
  rows: SiteRow[];
  /**
   * Set when the `property_key=site` listing failed and every machine's properties were read
   * individually instead. Informational: per-machine failures are already UNKNOWN rows.
   */
  filterError: string | null;
}

type SitesApi = Pick<ConsoleApi, "listMachines" | "listMachineProperties">;

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Read one machine's site from its property list. A read failure is UNKNOWN, not "none". */
async function readSite(api: SitesApi, machineId: string): Promise<SiteState> {
  try {
    const props = await api.listMachineProperties(machineId);
    const site = props.find((p) => p.key === SITE_PROPERTY_KEY);
    return site ? { kind: "set", value: site.value } : { kind: "none" };
  } catch (e) {
    return { kind: "unknown", error: message(e) };
  }
}

/** Run `fn` over `items` with at most `limit` in flight, preserving input order in the result. */
async function mapLimited<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/**
 * Load every machine the caller may see, with its site. The full listing failing rejects (there is
 * nothing to show). The server's `property_key=site` filter identifies which machines HAVE a site, so
 * only those need a per-machine property read; if that filter call fails, every machine is read
 * individually rather than guessing "no site" for all of them.
 */
export async function loadMachineSites(api: SitesApi, concurrency = 6): Promise<SitesLoad> {
  const machines = await api.listMachines();
  let withSite: Set<string> | null = null;
  let filterError: string | null = null;
  try {
    const filtered = await api.listMachines({ propertyKey: SITE_PROPERTY_KEY });
    withSite = new Set(filtered.map((m) => m.id));
  } catch (e) {
    filterError = message(e);
  }
  const rows = await mapLimited(machines, concurrency, async (machine): Promise<SiteRow> => {
    if (withSite !== null && !withSite.has(machine.id)) return { machine, site: { kind: "none" } };
    return { machine, site: await readSite(api, machine.id) };
  });
  return { rows, filterError };
}

export type SiteValidation = { ok: true; value: string } | { ok: false; message: string };

/** The limit as shown to the operator: it counts UTF-8 bytes, so non-ASCII characters use more than one. */
export const SITE_LIMIT_HINT = `Up to ${MAX_SITE_LEN} bytes in UTF-8 (ASCII characters use 1 byte each; accented, non-Latin and emoji characters use 2-4).`;

const utf8 = new TextEncoder();

/** UTF-8 byte length of `s`, as the Go server's `len(req.Value)` counts it. */
export function utf8ByteLength(s: string): number {
  return utf8.encode(s).length;
}

/**
 * Validate a site typed by the operator: trimmed, non-empty, and within the server's cap, which is
 * measured in UTF-8 BYTES (Go `len`), not UTF-16 code units. Never truncates; an over-long value is refused.
 */
export function validateSite(raw: string): SiteValidation {
  const value = raw.trim();
  if (value === "") return { ok: false, message: "enter a site name (use Remove site to clear it)" };
  const bytes = utf8ByteLength(value);
  if (bytes > MAX_SITE_LEN) {
    return {
      ok: false,
      message: `site is too long: ${bytes} bytes in UTF-8, max ${MAX_SITE_LEN} bytes (non-ASCII characters use 2-4 bytes each)`,
    };
  }
  return { ok: true, value };
}

/**
 * Set ONE machine's site. Only the `site` key is written (a single-key upsert), so the machine's other
 * properties are untouched. Resolves only when the server echoes back exactly what was asked for.
 */
export async function saveMachineSite(
  api: Pick<ConsoleApi, "setMachineProperty">,
  machineId: string,
  value: string,
): Promise<SiteState> {
  const stored = await api.setMachineProperty(machineId, SITE_PROPERTY_KEY, value);
  if (stored?.key !== SITE_PROPERTY_KEY || stored.value !== value) {
    throw new Error("could not set site: the server did not confirm the saved value");
  }
  return { kind: "set", value };
}

/** Remove ONE machine's site (deletes only the `site` key). Any failure rejects. */
export async function clearMachineSite(
  api: Pick<ConsoleApi, "deleteMachineProperty">,
  machineId: string,
): Promise<SiteState> {
  await api.deleteMachineProperty(machineId, SITE_PROPERTY_KEY);
  return { kind: "none" };
}

/** A site change the operator made and the server confirmed, stamped with a monotonic sequence. */
export interface SiteOverride {
  site: SiteState;
  seq: number;
}

/**
 * Apply confirmed changes that completed AFTER a load started (`seq > loadStartSeq`) on top of that
 * load's rows: the load may have read the server before the change landed, so its value is stale.
 */
export function applyOverrides(
  rows: readonly SiteRow[],
  overrides: ReadonlyMap<string, SiteOverride>,
  loadStartSeq: number,
): SiteRow[] {
  return rows.map((row) => {
    const o = overrides.get(row.machine.id);
    return o && o.seq > loadStartSeq ? { ...row, site: o.site } : row;
  });
}

/** Identifies one load: its generation (latest wins) and the change sequence when it started. */
export interface LoadTicket {
  gen: number;
  startSeq: number;
}

/**
 * The Sites view's ordering guard, kept out of the component so it is unit-testable as-is:
 *  - only the LATEST load may publish (`finishLoad` returns null for a superseded one);
 *  - a change confirmed after a load started is re-applied on top of that load's rows, so a stale
 *    refresh never reverts a successful save;
 *  - once a load that started AFTER a change finishes, the server's own answer is trusted again.
 */
export class SiteSync {
  private gen = 0;
  private seq = 0;
  private readonly overrides = new Map<string, SiteOverride>();

  beginLoad(): LoadTicket {
    return { gen: ++this.gen, startSeq: this.seq };
  }

  isCurrent(ticket: LoadTicket): boolean {
    return ticket.gen === this.gen;
  }

  /** The rows to publish for a finished load, or null when a newer load has started since. */
  finishLoad(ticket: LoadTicket, rows: readonly SiteRow[]): SiteRow[] | null {
    if (!this.isCurrent(ticket)) return null;
    const merged = applyOverrides(rows, this.overrides, ticket.startSeq);
    for (const [id, o] of this.overrides) if (o.seq <= ticket.startSeq) this.overrides.delete(id);
    return merged;
  }

  /** Record a change the server CONFIRMED (never call this for a failed or unverified write). */
  confirm(machineId: string, site: SiteState): void {
    this.overrides.set(machineId, { site, seq: ++this.seq });
  }
}

export interface SiteBucket {
  /** "set" buckets carry the site name; "none"/"unknown" collect the rest. */
  kind: SiteState["kind"];
  site: string | null;
  rows: SiteRow[];
}

export function machineLabel(m: MachineRecord): string {
  return m.alias || m.name || m.device_id;
}

/** Group rows by exact site value (A→Z), then "No site", then "Unknown". Empty buckets are omitted. */
export function groupBySite(rows: readonly SiteRow[]): SiteBucket[] {
  const named = new Map<string, SiteRow[]>();
  const none: SiteRow[] = [];
  const unknown: SiteRow[] = [];
  for (const row of rows) {
    if (row.site.kind === "set") {
      const list = named.get(row.site.value) ?? [];
      list.push(row);
      named.set(row.site.value, list);
    } else if (row.site.kind === "none") none.push(row);
    else unknown.push(row);
  }
  const byName = (a: SiteRow, b: SiteRow) => machineLabel(a.machine).localeCompare(machineLabel(b.machine));
  const buckets: SiteBucket[] = [...named.keys()]
    .sort((a, b) => a.localeCompare(b))
    .map((site) => ({ kind: "set" as const, site, rows: named.get(site)!.sort(byName) }));
  if (none.length > 0) buckets.push({ kind: "none", site: null, rows: none.sort(byName) });
  if (unknown.length > 0) buckets.push({ kind: "unknown", site: null, rows: unknown.sort(byName) });
  return buckets;
}

/**
 * Local search over ALREADY-LOADED rows: case-insensitive substring match of the trimmed query against
 * the site name (only a real `set` site), the machine alias and the machine hostname (`name`). A blank
 * query returns every row. A "none" or "unknown" row is never matched by a site name, so the
 * no-site/unknown distinction is preserved; it can only be found by machine alias/hostname.
 */
export function filterSiteRows(rows: readonly SiteRow[], query: string): SiteRow[] {
  const q = query.trim().toLowerCase();
  if (q === "") return [...rows];
  return rows.filter(({ machine: m, site }) => {
    const hay = [m.alias, m.name, site.kind === "set" ? site.value : ""];
    return hay.some((s) => (s ?? "").toLowerCase().includes(q));
  });
}

/** Assignment-status filter: every machine, or only one `SiteState` kind. */
export type SiteStateFilter = "all" | "assigned" | "none" | "unknown";

export const SITE_STATE_FILTERS: readonly { value: SiteStateFilter; label: string }[] = [
  { value: "all", label: "All machines" },
  { value: "assigned", label: "Assigned site" },
  { value: "none", label: "No site" },
  { value: "unknown", label: "Site unavailable" },
];

/** Narrow an untrusted string (e.g. a select value) to a filter; anything unrecognised is "all". */
export function parseSiteStateFilter(raw: string): SiteStateFilter {
  return SITE_STATE_FILTERS.some((f) => f.value === raw) ? (raw as SiteStateFilter) : "all";
}

/**
 * Filter loaded rows by assignment status. "assigned" is every `set` row, INCLUDING an empty stored
 * value (the property exists); "none" is only a CONFIRMED absence; "unknown" (site could not be read)
 * is never folded into either. "all" returns every row.
 */
export function filterSiteRowsByState(rows: readonly SiteRow[], state: SiteStateFilter): SiteRow[] {
  if (state === "all") return [...rows];
  const kind: SiteState["kind"] = state === "assigned" ? "set" : state;
  return rows.filter((r) => r.site.kind === kind);
}

/** Status filter AND text search, both local over already-loaded rows. */
export function applySiteFilters(rows: readonly SiteRow[], query: string, state: SiteStateFilter): SiteRow[] {
  return filterSiteRows(filterSiteRowsByState(rows, state), query);
}

/** Distinct existing site names, A→Z — the suggestions offered when assigning a site. */
export function siteNames(rows: readonly SiteRow[]): string[] {
  const names = new Set<string>();
  for (const r of rows) if (r.site.kind === "set") names.add(r.site.value);
  return [...names].sort((a, b) => a.localeCompare(b));
}
