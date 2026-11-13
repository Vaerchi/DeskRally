/**
 * Backstage tool-panel data model + presentation helpers.
 *
 * These are the *headless tool panels* from docs/04-backstage.md Part 1: the agent queries the
 * remote machine over a structured channel and the technician renders the results **natively**
 * in this browser UI (no remoted pixels). This module is the TS mirror of the agent-side row
 * shapes and holds only pure model + formatting/sorting logic — the React components in
 * `../components/*Panel.tsx` are the presentation layer on top of it.
 *
 * The interfaces below mirror the Rust serde output **exactly** (snake_case field names, the
 * same nullability). Keep them in lockstep with the agent's `panels::{process,service,file}`
 * row structs (docs/05-backstage-implementation.md). This is deliberately transport-agnostic:
 * it describes the row *shapes*, not how they arrive — the panel request/response protocol over
 * ChannelId.Backstage is not defined yet, so nothing here assumes a wire format.
 */

/** Sentinel shown for every absent/None field, matching the "—" convention across the UI. */
export const DASH = "—";

// ---------------------------------------------------------------------------
// Process panel (mirror of agent `panels::process::ProcessRow`)
// ---------------------------------------------------------------------------

/** One row of the process list. CPU% is a sampled instantaneous value (0..N·100 across cores). */
export interface ProcessRow {
  pid: number;
  /** Parent PID, or null when it couldn't be resolved (orphaned / access-denied). */
  parent_pid: number | null;
  name: string;
  cpu_percent: number;
  memory_bytes: number;
  /** Owning user (`DOMAIN\\user`), or null when the token couldn't be opened. */
  user: string | null;
  /** Full command line, or null when it couldn't be read (access-denied / SYSTEM-only). */
  command_line: string | null;
}

// ---------------------------------------------------------------------------
// Services panel (mirror of agent `panels::service::ServiceRow`)
// ---------------------------------------------------------------------------

/**
 * Service Control Manager state. Mirrors the `SERVICE_STATUS.dwCurrentState` values surfaced by
 * `EnumServicesStatusExW`, plus `unknown` for anything the agent couldn't map.
 */
export type ServiceState =
  | "stopped"
  | "start_pending"
  | "stop_pending"
  | "running"
  | "continue_pending"
  | "pause_pending"
  | "paused"
  | "unknown";

/** One row of the services list. */
export interface ServiceRow {
  /** Service key name (what `sc`/`ControlService` address). */
  name: string;
  /** Friendly name shown in services.msc. */
  display_name: string;
  state: ServiceState;
  /** Host process PID, or null when the service isn't running (no host process). */
  pid: number | null;
}

// ---------------------------------------------------------------------------
// File browser panel (mirror of agent `panels::file::{DirListing,FileEntry}`)
// ---------------------------------------------------------------------------

/** One directory entry. */
export interface FileEntry {
  name: string;
  is_dir: boolean;
  /** Reparse point / junction / symlink — the agent doesn't follow these in walks. */
  is_symlink: boolean;
  /** File size in bytes; null for directories (and entries the agent couldn't stat). */
  size_bytes: number | null;
  /** Last-modified time in Unix milliseconds, or null when unavailable. */
  modified_unix_ms: number | null;
}

/** A listing of one directory: the absolute path browsed and its entries. */
export interface DirListing {
  /** Absolute path of the listed directory. Empty string = the drive/root list. */
  path: string;
  entries: FileEntry[];
}

// ---------------------------------------------------------------------------
// Forthcoming panels — typed ahead so the UI is ready (NOT YET on the agent)
// ---------------------------------------------------------------------------
//
// These two panels are next in the roadmap (event log via `EvtQuery`, and a system-info summary)
// but the agent does NOT emit them yet. The shapes below are a reasonable first cut so components
// can be sketched against them; treat them as PROVISIONAL and re-confirm against the Rust structs
// before wiring anything real. Do not build wire code against these.

/**
 * Severity name of an event-log record, as the agent maps the numeric event Level. Matches the
 * strings emitted by the Rust `panels::eventlog::level_name` (capitalized; "Unknown" for codes
 * outside the schema).
 */
export type EventLevel =
  | "Critical"
  | "Error"
  | "Warning"
  | "Information"
  | "Verbose"
  | "Unknown";

/**
 * One Windows Event Log record. Mirrors the Rust `panels::eventlog::EventLogRow` serde shape
 * exactly (all headline fields are optional — the agent renders event XML and extracts what's
 * present; the fully-localized message is a later addition).
 */
export interface EventLogRow {
  /** Channel/log name, e.g. "System", "Application", "Security". */
  channel: string;
  /** Monotonic per-channel record id, or null when absent. */
  record_id: number | null;
  /** Publisher / event source, or null. */
  provider: string | null;
  event_id: number | null;
  /** Severity name, or null when the Level element is missing. */
  level: EventLevel | null;
  /** ISO-8601 UTC timestamp exactly as the log recorded it (parse/localize in the UI). */
  time_created: string | null;
}

/**
 * Machine identity + resource summary. Mirrors the Rust `panels::sysinfo::SystemInfo` serde
 * shape exactly. Fields the host can't report come back null (render "—").
 */
export interface SystemInfo {
  hostname: string | null;
  /** OS family, e.g. "Windows". */
  os_name: string | null;
  /** Long OS description, e.g. "Windows 11 Pro". */
  os_long_version: string | null;
  /** Kernel / build version string. */
  kernel_version: string | null;
  /** CPU architecture, e.g. "x86_64". */
  cpu_arch: string;
  /** CPU model string. */
  cpu_brand: string;
  /** Logical processor count (threads). */
  logical_cpus: number;
  /** Physical core count when the OS reports it. */
  physical_cores: number | null;
  total_memory_bytes: number;
  used_memory_bytes: number;
  total_swap_bytes: number;
  used_swap_bytes: number;
  /** Seconds since boot. */
  uptime_seconds: number;
  /** Boot time as a Unix timestamp (seconds). */
  boot_time_unix: number;
  /** User logged into the active console session (`DOMAIN\\user`), or null (login screen / unknown). */
  logged_in_user: string | null;
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure, unit-tested)
// ---------------------------------------------------------------------------

/** Present an optional string, falling back to the "—" sentinel for null/empty. */
export function formatOptional(value: string | null | undefined): string {
  return value == null || value === "" ? DASH : value;
}

/**
 * Human-readable byte size (base-1024, e.g. "4.0 MB"). Returns "—" for null/negative/non-finite.
 * Whole bytes render without a decimal; KB and up carry one decimal place.
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return DASH;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

/** CPU percentage with one decimal (e.g. "12.5%"). Returns "—" for non-finite input. */
export function formatCpuPercent(percent: number | null | undefined): string {
  if (percent == null || !Number.isFinite(percent)) return DASH;
  return `${percent.toFixed(1)}%`;
}

/**
 * Format a Unix-millisecond timestamp as "YYYY-MM-DD HH:mm" in **UTC** (deterministic across
 * hosts and test runners). Returns "—" for null/invalid input.
 */
export function formatTimestamp(unixMs: number | null | undefined): string {
  if (unixMs == null || !Number.isFinite(unixMs)) return DASH;
  const d = new Date(unixMs);
  if (Number.isNaN(d.getTime())) return DASH;
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` +
    ` ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  );
}

/**
 * Format an ISO-8601 timestamp string (as the event log records it) to "YYYY-MM-DD HH:mm:ss" in
 * UTC. Returns "—" for null/empty, and echoes the raw string back if it can't be parsed.
 */
export function formatIsoUtc(iso: string | null | undefined): string {
  if (iso == null || iso === "") return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}` +
    ` ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
  );
}

/** Format an uptime/duration in seconds as "4d 07h 29m" (days omitted below one day). "—" if invalid. */
export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return DASH;
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86_400);
  const hours = Math.floor((s % 86_400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const pad = (n: number) => String(n).padStart(2, "0");
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  parts.push(`${pad(hours)}h`, `${pad(mins)}m`);
  return parts.join(" ");
}

/** Status-badge tone for an event-log level, matching the CSS `--good/--pending/--bad/--neutral`. */
export function eventLevelTone(
  level: EventLevel | null,
): "good" | "pending" | "bad" | "neutral" {
  switch (level) {
    case "Critical":
    case "Error":
      return "bad";
    case "Warning":
      return "pending";
    case "Information":
      return "good";
    case "Verbose":
    case "Unknown":
    case null:
      return "neutral";
  }
}

// ---------------------------------------------------------------------------
// Process sorting
// ---------------------------------------------------------------------------

/** Columns the process table can sort by. */
export type ProcessSortKey = "name" | "cpu" | "memory";
export type SortDirection = "asc" | "desc";

/**
 * Return a new array sorted by the chosen column. `name` sorts case-insensitively; `cpu`/`memory`
 * sort numerically. Ties break by PID (ascending) so the order is stable and deterministic.
 * Does not mutate the input.
 */
export function sortProcesses(
  rows: readonly ProcessRow[],
  key: ProcessSortKey,
  direction: SortDirection,
): ProcessRow[] {
  const factor = direction === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    let cmp: number;
    switch (key) {
      case "name":
        cmp = a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
        break;
      case "cpu":
        cmp = a.cpu_percent - b.cpu_percent;
        break;
      case "memory":
        cmp = a.memory_bytes - b.memory_bytes;
        break;
    }
    if (cmp !== 0) return cmp * factor;
    return a.pid - b.pid; // stable tie-break, independent of direction
  });
}

// ---------------------------------------------------------------------------
// Service sorting + state presentation
// ---------------------------------------------------------------------------

/** Running-first ordering rank; lower sorts earlier. */
const SERVICE_STATE_RANK: Record<ServiceState, number> = {
  running: 0,
  start_pending: 1,
  continue_pending: 2,
  pause_pending: 3,
  stop_pending: 4,
  paused: 5,
  stopped: 6,
  unknown: 7,
};

/**
 * Return a new array with running services first (then pending, paused, stopped, unknown), each
 * tier ordered by display name. Does not mutate the input.
 */
export function sortServices(rows: readonly ServiceRow[]): ServiceRow[] {
  return [...rows].sort((a, b) => {
    const rank = SERVICE_STATE_RANK[a.state] - SERVICE_STATE_RANK[b.state];
    if (rank !== 0) return rank;
    return a.display_name.localeCompare(b.display_name, undefined, { sensitivity: "base" });
  });
}

/** Human-readable label for a service state (e.g. "start_pending" -> "Start pending"). */
export function serviceStateLabel(state: ServiceState): string {
  const words = state.split("_");
  const joined = words.join(" ");
  return joined.charAt(0).toUpperCase() + joined.slice(1);
}

/**
 * Status-badge tone for a service state, matching the `--good/--pending/--bad/--neutral` CSS
 * tokens used by the viewer status bar.
 */
export function serviceStateTone(state: ServiceState): "good" | "pending" | "bad" | "neutral" {
  switch (state) {
    case "running":
      return "good";
    case "start_pending":
    case "stop_pending":
    case "continue_pending":
    case "pause_pending":
      return "pending";
    case "paused":
      return "bad";
    case "stopped":
    case "unknown":
      return "neutral";
  }
}

// ---------------------------------------------------------------------------
// File browser sorting + path breadcrumb
// ---------------------------------------------------------------------------

/**
 * Return a new array with directories first, then files, each group ordered by name
 * (case-insensitive). Does not mutate the input.
 */
export function sortFileEntries(entries: readonly FileEntry[]): FileEntry[] {
  return [...entries].sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
  });
}

/** One breadcrumb hop: a label to show and the cumulative path it navigates to. */
export interface Breadcrumb {
  label: string;
  path: string;
}

/**
 * Split an absolute path into cumulative breadcrumb hops. Handles Windows (`C:\\Users\\foo`,
 * backslash-separated, drive-rooted) and POSIX (`/usr/local`, slash-separated) styles. An empty
 * path yields no crumbs (the drive/root list). Each crumb's `path` is the absolute path up to and
 * including that segment, suitable for a navigate callback.
 */
export function breadcrumbSegments(path: string): Breadcrumb[] {
  if (!path) return [];

  const isWindows = /^[A-Za-z]:/.test(path) || path.includes("\\");
  const sep = isWindows ? "\\" : "/";

  if (isWindows) {
    // e.g. "C:\Users\foo" -> ["C:", "Users", "foo"]; root crumb keeps the trailing separator.
    const parts = path.split(/[\\/]+/).filter((p) => p.length > 0);
    if (parts.length === 0) return [];
    const crumbs: Breadcrumb[] = [];
    const rootLabel = parts[0]; // "C:"
    crumbs.push({ label: rootLabel + sep, path: rootLabel + sep });
    let acc = rootLabel + sep;
    for (let i = 1; i < parts.length; i += 1) {
      acc = acc.endsWith(sep) ? acc + parts[i] : acc + sep + parts[i];
      crumbs.push({ label: parts[i], path: acc });
    }
    return crumbs;
  }

  // POSIX: leading "/" is the root crumb.
  const parts = path.split("/").filter((p) => p.length > 0);
  const crumbs: Breadcrumb[] = [{ label: "/", path: "/" }];
  let acc = "";
  for (const part of parts) {
    acc = `${acc}/${part}`;
    crumbs.push({ label: part, path: acc });
  }
  return crumbs;
}
