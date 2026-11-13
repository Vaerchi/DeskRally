/**
 * Sample backstage-panel data for previews, Storybook-less visual checks, and tests. These are
 * hand-authored rows shaped exactly like the agent's serde output — the components render these
 * until the panel request/response protocol over ChannelId.Backstage exists.
 *
 * Not a wire format and not exhaustive: just enough variety to exercise every formatting/sorting
 * branch (null fields, symlinks, each service state, mixed dirs/files).
 */

import type {
  DirListing,
  EventLogRow,
  ProcessRow,
  ServiceRow,
  SystemInfo,
} from "./panels";

/** A fixed epoch for deterministic timestamp formatting in tests: 2026-07-20 14:30 UTC. */
const T = Date.UTC(2026, 6, 20, 14, 30, 0);

export const SAMPLE_PROCESSES: ProcessRow[] = [
  {
    pid: 4,
    parent_pid: null,
    name: "System",
    cpu_percent: 0.1,
    memory_bytes: 143_360,
    user: "NT AUTHORITY\\SYSTEM",
    command_line: null,
  },
  {
    pid: 1284,
    parent_pid: 812,
    name: "svchost.exe",
    cpu_percent: 0.0,
    memory_bytes: 24_117_248,
    user: "NT AUTHORITY\\SYSTEM",
    command_line: "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
  },
  {
    pid: 6721,
    parent_pid: 3310,
    name: "chrome.exe",
    cpu_percent: 18.4,
    memory_bytes: 512_450_560,
    user: "ACME\\jdoe",
    command_line: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
  },
  {
    pid: 9002,
    parent_pid: 6721,
    name: "chrome.exe",
    cpu_percent: 3.2,
    memory_bytes: 268_435_456,
    user: "ACME\\jdoe",
    command_line: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
  },
  {
    pid: 512,
    parent_pid: 4,
    name: "lsass.exe",
    cpu_percent: 0.5,
    memory_bytes: 15_728_640,
    user: null, // token couldn't be opened
    command_line: null,
  },
  {
    pid: 7788,
    parent_pid: 1,
    name: "powershell.exe",
    cpu_percent: 42.7,
    memory_bytes: 98_566_144,
    user: "ACME\\admin",
    command_line: "powershell.exe -NoProfile -Command Get-Process",
  },
];

export const SAMPLE_SERVICES: ServiceRow[] = [
  { name: "Spooler", display_name: "Print Spooler", state: "running", pid: 2140 },
  { name: "wuauserv", display_name: "Windows Update", state: "stopped", pid: null },
  { name: "BITS", display_name: "Background Intelligent Transfer Service", state: "start_pending", pid: 3312 },
  { name: "Dnscache", display_name: "DNS Client", state: "running", pid: 1284 },
  { name: "TermService", display_name: "Remote Desktop Services", state: "paused", pid: 4501 },
  { name: "Fax", display_name: "Fax", state: "stop_pending", pid: 6620 },
  { name: "WSearch", display_name: "Windows Search", state: "unknown", pid: null },
];

export const SAMPLE_DIR_LISTING: DirListing = {
  path: "C:\\Users\\jdoe\\Documents",
  entries: [
    { name: "Projects", is_dir: true, is_symlink: false, size_bytes: null, modified_unix_ms: T },
    { name: "Archive", is_dir: true, is_symlink: false, size_bytes: null, modified_unix_ms: T - 86_400_000 },
    { name: "OneDrive", is_dir: true, is_symlink: true, size_bytes: null, modified_unix_ms: T - 3_600_000 },
    { name: "budget.xlsx", is_dir: false, is_symlink: false, size_bytes: 48_231, modified_unix_ms: T - 7_200_000 },
    { name: "notes.txt", is_dir: false, is_symlink: false, size_bytes: 1_024, modified_unix_ms: T - 600_000 },
    { name: "backup.iso", is_dir: false, is_symlink: false, size_bytes: 4_812_341_248, modified_unix_ms: T - 172_800_000 },
    { name: "locked.bin", is_dir: false, is_symlink: false, size_bytes: null, modified_unix_ms: null },
  ],
};

/** The special top-level listing: the drive list (empty path, directories only). */
export const SAMPLE_DRIVE_LISTING: DirListing = {
  path: "",
  entries: [
    { name: "C:\\", is_dir: true, is_symlink: false, size_bytes: null, modified_unix_ms: null },
    { name: "D:\\", is_dir: true, is_symlink: false, size_bytes: null, modified_unix_ms: null },
  ],
};

// --- Event log + system info (shapes mirror the implemented agent panels) ---

export const SAMPLE_EVENT_LOG: EventLogRow[] = [
  {
    channel: "System",
    record_id: 88213,
    provider: "Service Control Manager",
    event_id: 7036,
    level: "Information",
    time_created: "2026-07-26T14:03:21.1234567Z",
  },
  {
    channel: "System",
    record_id: 88240,
    provider: "Microsoft-Windows-Kernel-Power",
    event_id: 41,
    level: "Critical",
    time_created: "2026-07-26T14:18:21.0Z",
  },
  {
    // A sparse record: the agent renders what's present, leaving the rest null.
    channel: "Application",
    record_id: null,
    provider: null,
    event_id: null,
    level: null,
    time_created: null,
  },
];

export const SAMPLE_SYSTEM_INFO: SystemInfo = {
  hostname: "ACCT-WS-07",
  os_name: "Windows",
  os_long_version: "Windows 11 Pro",
  kernel_version: "26100",
  cpu_arch: "x86_64",
  cpu_brand: "Intel(R) Core(TM) i7-1265U",
  logical_cpus: 12,
  physical_cores: 10,
  total_memory_bytes: 17_179_869_184,
  used_memory_bytes: 10_737_418_240,
  total_swap_bytes: 4_294_967_296,
  used_swap_bytes: 1_073_741_824,
  uptime_seconds: 372_540,
  boot_time_unix: 1_753_000_000,
  logged_in_user: "ACCT\\jdoe",
};
