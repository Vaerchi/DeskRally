/**
 * Backstage panel tests: the pure formatting/sorting logic, plus a smoke test that each panel
 * component renders the fixtures without throwing. Rendering uses `react-dom/server`
 * (renderToStaticMarkup) so it works under vitest's `node` environment — no jsdom needed.
 */

import { describe, it, expect } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  DASH,
  breadcrumbSegments,
  formatBytes,
  formatCpuPercent,
  formatOptional,
  formatTimestamp,
  serviceStateLabel,
  serviceStateTone,
  sortFileEntries,
  sortProcesses,
  sortServices,
  type FileEntry,
  type ProcessRow,
  type ServiceState,
} from "./panels";
import {
  SAMPLE_DIR_LISTING,
  SAMPLE_DRIVE_LISTING,
  SAMPLE_PROCESSES,
  SAMPLE_SERVICES,
} from "./fixtures";
import { ProcessPanel } from "../components/ProcessPanel";
import { ServicesPanel } from "../components/ServicesPanel";
import { FileBrowserPanel } from "../components/FileBrowserPanel";

// --- Formatting ------------------------------------------------------------

describe("formatBytes", () => {
  it("renders '—' for null/negative/non-finite", () => {
    expect(formatBytes(null)).toBe(DASH);
    expect(formatBytes(-1)).toBe(DASH);
    expect(formatBytes(Number.NaN)).toBe(DASH);
    expect(formatBytes(Number.POSITIVE_INFINITY)).toBe(DASH);
  });

  it("shows whole bytes below 1 KiB without a decimal", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("scales base-1024 with one decimal", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(4 * 1024 * 1024 * 1024)).toBe("4.0 GB");
  });
});

describe("formatCpuPercent", () => {
  it("carries one decimal, '—' for non-finite", () => {
    expect(formatCpuPercent(0)).toBe("0.0%");
    expect(formatCpuPercent(18.44)).toBe("18.4%");
    expect(formatCpuPercent(null)).toBe(DASH);
  });
});

describe("formatOptional", () => {
  it("falls back to '—' for null/empty", () => {
    expect(formatOptional(null)).toBe(DASH);
    expect(formatOptional("")).toBe(DASH);
    expect(formatOptional("ACME\\jdoe")).toBe("ACME\\jdoe");
  });
});

describe("formatTimestamp", () => {
  it("formats Unix ms as UTC 'YYYY-MM-DD HH:mm'", () => {
    // 2026-07-20 14:30:00 UTC
    expect(formatTimestamp(Date.UTC(2026, 6, 20, 14, 30, 0))).toBe("2026-07-20 14:30");
  });

  it("renders '—' for null/invalid", () => {
    expect(formatTimestamp(null)).toBe(DASH);
    expect(formatTimestamp(Number.NaN)).toBe(DASH);
  });
});

// --- Process sorting -------------------------------------------------------

describe("sortProcesses", () => {
  it("sorts by CPU descending and does not mutate the input", () => {
    const input = SAMPLE_PROCESSES;
    const out = sortProcesses(input, "cpu", "desc");
    expect(out).not.toBe(input);
    expect(input[0].name).toBe("System"); // original order intact
    const cpus = out.map((p) => p.cpu_percent);
    expect(cpus).toEqual([...cpus].sort((a, b) => b - a));
    expect(out[0].name).toBe("powershell.exe"); // highest CPU
  });

  it("sorts by memory ascending", () => {
    const out = sortProcesses(SAMPLE_PROCESSES, "memory", "asc");
    const mem = out.map((p) => p.memory_bytes);
    expect(mem).toEqual([...mem].sort((a, b) => a - b));
  });

  it("sorts by name case-insensitively", () => {
    const out = sortProcesses(SAMPLE_PROCESSES, "name", "asc");
    expect(out[0].name.toLowerCase()).toBe("chrome.exe");
  });

  it("breaks ties by PID regardless of direction", () => {
    const tied: ProcessRow[] = [
      { pid: 30, parent_pid: null, name: "a", cpu_percent: 5, memory_bytes: 0, user: null, command_line: null },
      { pid: 10, parent_pid: null, name: "a", cpu_percent: 5, memory_bytes: 0, user: null, command_line: null },
      { pid: 20, parent_pid: null, name: "a", cpu_percent: 5, memory_bytes: 0, user: null, command_line: null },
    ];
    expect(sortProcesses(tied, "cpu", "desc").map((p) => p.pid)).toEqual([10, 20, 30]);
    expect(sortProcesses(tied, "cpu", "asc").map((p) => p.pid)).toEqual([10, 20, 30]);
  });
});

// --- Service sorting + state presentation ----------------------------------

describe("sortServices", () => {
  it("puts running first, then pending/paused/stopped/unknown, and doesn't mutate", () => {
    const input = SAMPLE_SERVICES;
    const out = sortServices(input);
    expect(out).not.toBe(input);
    const states = out.map((s) => s.state);
    // All running come before any non-running.
    const firstNonRunning = states.findIndex((s) => s !== "running");
    expect(states.slice(0, firstNonRunning).every((s) => s === "running")).toBe(true);
    expect(states.slice(firstNonRunning).some((s) => s === "running")).toBe(false);
  });

  it("orders running services by display name", () => {
    const out = sortServices(SAMPLE_SERVICES).filter((s) => s.state === "running");
    expect(out.map((s) => s.display_name)).toEqual(["DNS Client", "Print Spooler"]);
  });
});

describe("service state presentation", () => {
  it("humanizes state labels", () => {
    expect(serviceStateLabel("running")).toBe("Running");
    expect(serviceStateLabel("start_pending")).toBe("Start pending");
  });

  it("maps every state to a tone", () => {
    const all: ServiceState[] = [
      "stopped", "start_pending", "stop_pending", "running",
      "continue_pending", "pause_pending", "paused", "unknown",
    ];
    for (const s of all) {
      expect(["good", "pending", "bad", "neutral"]).toContain(serviceStateTone(s));
    }
    expect(serviceStateTone("running")).toBe("good");
    expect(serviceStateTone("stopped")).toBe("neutral");
  });
});

// --- File entry sorting + breadcrumb ---------------------------------------

describe("sortFileEntries", () => {
  it("lists directories before files, each group by name, without mutating", () => {
    const input = SAMPLE_DIR_LISTING.entries;
    const out = sortFileEntries(input);
    expect(out).not.toBe(input);
    const firstFile = out.findIndex((e) => !e.is_dir);
    expect(out.slice(0, firstFile).every((e) => e.is_dir)).toBe(true);
    expect(out.slice(firstFile).every((e) => !e.is_dir)).toBe(true);
    // Dir group alphabetical.
    expect(out.slice(0, firstFile).map((e) => e.name)).toEqual(["Archive", "OneDrive", "Projects"]);
  });

  it("handles an all-files or empty listing", () => {
    const files: FileEntry[] = [
      { name: "b.txt", is_dir: false, is_symlink: false, size_bytes: 1, modified_unix_ms: null },
      { name: "a.txt", is_dir: false, is_symlink: false, size_bytes: 1, modified_unix_ms: null },
    ];
    expect(sortFileEntries(files).map((e) => e.name)).toEqual(["a.txt", "b.txt"]);
    expect(sortFileEntries([])).toEqual([]);
  });
});

describe("breadcrumbSegments", () => {
  it("returns no crumbs for the empty (drive-list) path", () => {
    expect(breadcrumbSegments("")).toEqual([]);
  });

  it("splits a Windows path into cumulative hops", () => {
    expect(breadcrumbSegments("C:\\Users\\jdoe\\Documents")).toEqual([
      { label: "C:\\", path: "C:\\" },
      { label: "Users", path: "C:\\Users" },
      { label: "jdoe", path: "C:\\Users\\jdoe" },
      { label: "Documents", path: "C:\\Users\\jdoe\\Documents" },
    ]);
  });

  it("handles a bare Windows drive root", () => {
    expect(breadcrumbSegments("C:\\")).toEqual([{ label: "C:\\", path: "C:\\" }]);
  });

  it("splits a POSIX path with a root crumb", () => {
    expect(breadcrumbSegments("/usr/local/bin")).toEqual([
      { label: "/", path: "/" },
      { label: "usr", path: "/usr" },
      { label: "local", path: "/usr/local" },
      { label: "bin", path: "/usr/local/bin" },
    ]);
  });
});

// --- Component smoke tests (render fixtures without error) ------------------

describe("panel components render the fixtures", () => {
  it("ProcessPanel renders rows and humanized values", () => {
    const html = renderToStaticMarkup(createElement(ProcessPanel, { rows: SAMPLE_PROCESSES }));
    expect(html).toContain("powershell.exe");
    expect(html).toContain("42.7%");
    expect(html).toContain("MB");
    expect(html).toContain(DASH); // null user/command line
  });

  it("ProcessPanel renders empty state", () => {
    const html = renderToStaticMarkup(createElement(ProcessPanel, { rows: [] }));
    expect(html).toContain("No processes.");
  });

  it("ServicesPanel renders state badges and host PID / '—'", () => {
    const html = renderToStaticMarkup(createElement(ServicesPanel, { rows: SAMPLE_SERVICES }));
    expect(html).toContain("Print Spooler");
    expect(html).toContain("Running");
    expect(html).toContain('data-tone="good"');
    expect(html).toContain(DASH); // stopped service has null PID
  });

  it("FileBrowserPanel renders breadcrumb, entries, and dir/size formatting", () => {
    const html = renderToStaticMarkup(createElement(FileBrowserPanel, { listing: SAMPLE_DIR_LISTING }));
    expect(html).toContain("budget.xlsx");
    expect(html).toContain("Documents"); // breadcrumb hop
    expect(html).toContain("4.5 GB"); // backup.iso humanized
  });

  it("FileBrowserPanel renders the drive-list (empty path) listing", () => {
    const html = renderToStaticMarkup(
      createElement(FileBrowserPanel, { listing: SAMPLE_DRIVE_LISTING }),
    );
    expect(html).toContain("C:\\");
    expect(html).toContain("Drives");
  });
});
