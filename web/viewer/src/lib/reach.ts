/**
 * The private reach and adoption reports, console side (docs/68 stage 5). The pure model behind
 * `components/PlatformReach.tsx` (the operator's per-artifact request counts from the Caddy log) and
 * `components/AdoptionSection.tsx` (a tenant Owner's own device counts). No DOM, so vitest pins every rule.
 *
 * The wording is the contract. A raw request count is a REQUEST count: the word "downloads" never labels it
 * (it includes bots, retries and previews), and nothing here says "users" or "installs". Wire shapes are those of
 * control-plane/platform_reach.go.
 */

export type ReachWindow = 7 | 30 | 90;
export const REACH_WINDOWS: readonly ReachWindow[] = [7, 30, 90];
/** The report is fetched once for the widest window; the narrower ones are cut from it. */
export const REACH_FETCH_DAYS: ReachWindow = 90;

export interface ReachRow {
  day: string; // YYYY-MM-DD, UTC
  artifact: string;
  class: string; // human | update | other | noise (open set)
  requests: number;
  completed: number | null;
  uniqueIsh: number | null;
  bytes: number;
  partial: boolean;
}

export interface ReachReport {
  from: string;
  to: string;
  rows: ReachRow[];
  caveats: string[];
}

/** The docs/68 section 3 caveats, shown under the table. The server's own list wins when it sends one. */
export const REACH_CAVEATS: readonly string[] = [
  "Requests are not downloads: the human-artifact request count includes bots, retries and previews.",
  "Completed is approximate: a GET answered 200 whose logged size is within 1 KiB of the artifact's current size. Resumed (206) downloads are not stitched together. A dash means the artifact size was not known.",
  "Unique-ish clients are a salted per-day, per-artifact count of (address, browser) pairs. NAT merges people and mobile addresses split them. A restart or a missing salt makes the figure a lower bound (marked partial). Nothing links one day to the next.",
  "Update traffic (manifests and payloads) is machine traffic and never counts as a download.",
  "Registrations are the real adoption signal. A download cannot be linked to a registration and we do not try.",
];

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null);

/** Parse GET /platform/reach. A malformed row is dropped, not guessed at; a malformed body is null. */
export function parseReachReport(body: unknown): ReachReport | null {
  if (typeof body !== "object" || body === null) return null;
  const o = body as Record<string, unknown>;
  if (!Array.isArray(o.rows) || typeof o.from !== "string" || typeof o.to !== "string") return null;
  const rows: ReachRow[] = [];
  for (const r of o.rows) {
    if (typeof r !== "object" || r === null) continue;
    const x = r as Record<string, unknown>;
    const requests = num(x.requests);
    if (typeof x.day !== "string" || typeof x.artifact !== "string" || typeof x.class !== "string" || requests === null) continue;
    rows.push({
      day: x.day,
      artifact: x.artifact,
      class: x.class,
      requests,
      completed: num(x.completed_approx),
      uniqueIsh: num(x.unique_ish_clients),
      bytes: num(x.bytes) ?? 0,
      partial: x.unique_ish_partial === true,
    });
  }
  const caveats = Array.isArray(o.caveats) ? o.caveats.filter((c): c is string => typeof c === "string" && c !== "") : [];
  return { from: o.from, to: o.to, rows, caveats };
}

/** The caveats to print: the server's when it sent some, else the console's copy. */
export function caveatsToShow(report: ReachReport | null): readonly string[] {
  return report && report.caveats.length > 0 ? report.caveats : REACH_CAVEATS;
}

const DAY_MS = 86_400_000;
const dayMs = (d: string): number => Date.parse(`${d}T00:00:00Z`);
const dayStr = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** The `n` UTC days ending at `to`, oldest first. */
export function windowDays(to: string, n: number): string[] {
  const end = dayMs(to);
  if (!Number.isFinite(end)) return [];
  return Array.from({ length: n }, (_, i) => dayStr(end - (n - 1 - i) * DAY_MS));
}

/** The range to request: the last REACH_FETCH_DAYS days ending today (UTC). */
export function reachRange(now: Date): { from: string; to: string } {
  const to = dayStr(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  return { from: windowDays(to, REACH_FETCH_DAYS)[0], to };
}

export interface ArtifactSummary {
  artifact: string;
  requests: number;
  /** Sum of the known per-day completed figures; null when none was known. */
  completed: number | null;
  /** True when some day's figure was unknown, so `completed` is a lower bound. */
  completedLowerBound: boolean;
  /** The mean of the days with a usable unique-ish figure; null when no day has one. */
  uniquePerDay: number | null;
  /** Some day in the window carries a partial (lower-bound) or missing unique-ish figure. */
  uniquePartial: boolean;
  /** Requests per day across the window, oldest first, zero-filled. */
  daily: number[];
}

interface Acc extends ArtifactSummary {
  uSum: number;
  uDays: number;
}

/** Summarise one class of rows over the last `window` days ending at `to`, one entry per artifact, busiest first. */
export function summarize(rows: readonly ReachRow[], cls: "human" | "update", to: string, window: number): ArtifactSummary[] {
  const days = windowDays(to, window);
  const index = new Map(days.map((d, i) => [d, i]));
  const by = new Map<string, Acc>();
  for (const r of rows) {
    const i = index.get(r.day);
    if (r.class !== cls || i === undefined) continue;
    let s = by.get(r.artifact);
    if (!s) {
      s = {
        artifact: r.artifact, requests: 0, completed: null, completedLowerBound: false,
        uniquePerDay: null, uniquePartial: false, daily: days.map(() => 0), uSum: 0, uDays: 0,
      };
      by.set(r.artifact, s);
    }
    s.requests += r.requests;
    s.daily[i] += r.requests;
    if (r.completed === null) s.completedLowerBound = true;
    else s.completed = (s.completed ?? 0) + r.completed;
    // A flagged figure is a lower bound: it is never averaged in, and it marks the whole cell partial.
    if (r.uniqueIsh === null || r.partial) s.uniquePartial = true;
    else {
      s.uSum += r.uniqueIsh;
      s.uDays++;
    }
  }
  return [...by.values()]
    .map((a): ArtifactSummary => ({
      artifact: a.artifact, requests: a.requests, completed: a.completed, completedLowerBound: a.completedLowerBound,
      uniquePerDay: a.uDays > 0 ? a.uSum / a.uDays : null, uniquePartial: a.uniquePartial, daily: a.daily,
    }))
    .sort((a, b) => b.requests - a.requests || a.artifact.localeCompare(b.artifact));
}

// ---- cell text ------------------------------------------------------------------------------------------

export const DASH = "—";

export function fmtCount(n: number | null): string {
  return n === null ? DASH : Math.round(n).toLocaleString("en-US");
}

export function completedText(s: ArtifactSummary): string {
  if (s.completed === null) return DASH;
  return `${s.completedLowerBound ? "≥ " : ""}${fmtCount(s.completed)}`;
}

/** The unique-ish cell: a dash when no day has a usable figure, else the per-day mean (one decimal under 10). */
export function uniqueText(s: ArtifactSummary): string {
  if (s.uniquePerDay === null) return DASH;
  return s.uniquePerDay < 10 ? s.uniquePerDay.toFixed(1) : fmtCount(s.uniquePerDay);
}

// ---- sparkline ------------------------------------------------------------------------------------------

/** SVG polyline points for `values` in a `w` x `h` box with `pad` on every side. y grows downwards, so the largest
 *  value is at y = pad. A flat or all-zero series is a line along the bottom, never NaN; one point is centred. */
export function sparklinePoints(values: readonly number[], w: number, h: number, pad = 2): string {
  if (values.length === 0) return "";
  const max = Math.max(...values);
  const innerW = w - 2 * pad;
  const innerH = h - 2 * pad;
  return values
    .map((v, i) => {
      const x = values.length === 1 ? w / 2 : pad + (i * innerW) / (values.length - 1);
      const y = max <= 0 ? pad + innerH : pad + innerH - (Math.max(0, v) / max) * innerH;
      return `${+x.toFixed(2)},${+y.toFixed(2)}`;
    })
    .join(" ");
}

// ---- tenant adoption ------------------------------------------------------------------------------------

export interface Adoption {
  from: string;
  to: string;
  newDevicesPerWeek: Array<{ week: string; count: number }>;
  activeDevices30d: number;
  funnel: { issued: number; redeemed: number; consented: number; active: number };
  agentVersions: Array<{ version: string; count: number }>;
}

function pickList<T>(v: unknown, pick: (x: Record<string, unknown>) => T | null): T[] | null {
  if (v === null || v === undefined) return [];
  if (!Array.isArray(v)) return null;
  const out: T[] = [];
  for (const x of v) {
    const p = typeof x === "object" && x !== null ? pick(x as Record<string, unknown>) : null;
    if (p === null) return null;
    out.push(p);
  }
  return out;
}

/** Parse GET /adoption; null when the body is not that shape (the card then shows an error, never zeros). */
export function parseAdoption(body: unknown): Adoption | null {
  if (typeof body !== "object" || body === null) return null;
  const o = body as Record<string, unknown>;
  const f = o.attended_funnel;
  const active = num(o.active_devices_30d);
  if (typeof o.from !== "string" || typeof o.to !== "string" || active === null || typeof f !== "object" || f === null) return null;
  const fr = f as Record<string, unknown>;
  const issued = num(fr.issued);
  const redeemed = num(fr.redeemed);
  const consented = num(fr.consented);
  const fActive = num(fr.active);
  if (issued === null || redeemed === null || consented === null || fActive === null) return null;
  const weeks = pickList(o.new_devices_per_week, (x) => {
    const c = num(x.count);
    return typeof x.week === "string" && c !== null ? { week: x.week, count: c } : null;
  });
  const versions = pickList(o.agent_versions, (x) => {
    const c = num(x.count);
    return typeof x.version === "string" && c !== null ? { version: x.version, count: c } : null;
  });
  if (weeks === null || versions === null) return null;
  return {
    from: o.from, to: o.to, newDevicesPerWeek: weeks, activeDevices30d: active,
    funnel: { issued, redeemed, consented, active: fActive }, agentVersions: versions,
  };
}

export interface FunnelStep {
  label: string;
  count: number;
  /** Share of the first step, 0..1; null when the first step is zero. */
  share: number | null;
}

/** The attended-session funnel, in order, each step against the first. */
export function funnelSteps(f: Adoption["funnel"]): FunnelStep[] {
  const steps: Array<[string, number]> = [
    ["Codes issued", f.issued],
    ["Redeemed by a guest", f.redeemed],
    ["Guest consented", f.consented],
    ["Session reached active", f.active],
  ];
  return steps.map(([label, count]) => ({ label, count, share: f.issued > 0 ? count / f.issued : null }));
}

export function shareText(share: number | null): string {
  return share === null ? DASH : `${Math.round(share * 100)}%`;
}

/** "unknown" is a version a machine never reported; it is worded, not hidden. */
export function versionLabel(v: string): string {
  return v === "unknown" || v === "" ? "not reported" : v;
}
