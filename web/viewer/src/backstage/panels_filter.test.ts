import { describe, expect, it } from "vitest";
import { filterProcesses, filterServices, matchesFilter, type ProcessRow, type ServiceRow } from "./panels";

const procs: ProcessRow[] = [
  { pid: 4321, parent_pid: 1, name: "chrome.exe", cpu_percent: 1, memory_bytes: 1, user: "PC\\tech", command_line: "chrome --type=renderer" },
  { pid: 88, parent_pid: 1, name: "svchost.exe", cpu_percent: 0, memory_bytes: 1, user: null, command_line: null },
];
const svcs: ServiceRow[] = [
  { name: "Spooler", display_name: "Print Spooler", state: "running", pid: 10 },
  { name: "wuauserv", display_name: "Windows Update", state: "stopped", pid: null },
];

describe("Under the Hood filter", () => {
  it("an empty filter keeps everything", () => {
    expect(filterProcesses(procs, "  ")).toHaveLength(2);
  });
  it("matches name, pid, user and command line, case-insensitively", () => {
    expect(filterProcesses(procs, "CHROME").map((p) => p.pid)).toEqual([4321]);
    expect(filterProcesses(procs, "88").map((p) => p.pid)).toEqual([88]);
    expect(filterProcesses(procs, "tech").map((p) => p.pid)).toEqual([4321]);
    expect(filterProcesses(procs, "renderer").map((p) => p.pid)).toEqual([4321]);
  });
  it("every word must match somewhere (null fields never match)", () => {
    expect(filterServices(svcs, "windows stopped").map((s) => s.name)).toEqual(["wuauserv"]);
    expect(filterServices(svcs, "windows running")).toEqual([]);
    expect(matchesFilter("x", [null, undefined])).toBe(false);
  });
});