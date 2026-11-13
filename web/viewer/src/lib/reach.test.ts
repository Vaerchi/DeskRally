/**
 * docs/68 stage 5: the reach and adoption model. Wording rules (a raw request count is never "downloads"),
 * the window arithmetic, the unique-ish partial rule, the completed lower bound, and the sparkline geometry.
 */
import { describe, expect, it } from "vitest";
import {
  DASH,
  REACH_CAVEATS,
  caveatsToShow,
  completedText,
  funnelSteps,
  parseAdoption,
  parseReachReport,
  reachRange,
  shareText,
  sparklinePoints,
  summarize,
  uniqueText,
  versionLabel,
  windowDays,
  type ReachRow,
} from "./reach";

const row = (over: Partial<ReachRow>): ReachRow => ({
  day: "2026-11-05", artifact: "DeskRallySupport.exe", class: "human", requests: 10, completed: 4, uniqueIsh: 3, bytes: 0, partial: false, ...over,
});

describe("parseReachReport", () => {
  it("maps the wire names and keeps null as null (never 0)", () => {
    const r = parseReachReport({
      from: "2026-08-08", to: "2026-11-05", caveats: ["c1"],
      rows: [{ day: "2026-11-05", artifact: "a", class: "human", requests: 5, completed_approx: null, unique_ish_clients: null, bytes: 9, unique_ish_partial: true }],
    });
    expect(r?.rows[0]).toEqual({ day: "2026-11-05", artifact: "a", class: "human", requests: 5, completed: null, uniqueIsh: null, bytes: 9, partial: true });
    expect(r?.caveats).toEqual(["c1"]);
  });
  it("drops a malformed row and refuses a malformed body", () => {
    expect(parseReachReport({ from: "a", to: "b", rows: [{ day: 1 }, null, { day: "d", artifact: "x", class: "human", requests: -1 }] })?.rows).toEqual([]);
    expect(parseReachReport({ rows: [] })).toBeNull();
    expect(parseReachReport(null)).toBeNull();
  });
  it("prints the server's caveats when sent, else the console's copy", () => {
    expect(caveatsToShow(null)).toBe(REACH_CAVEATS);
    expect(caveatsToShow({ from: "", to: "", rows: [], caveats: [] })).toBe(REACH_CAVEATS);
    expect(caveatsToShow({ from: "", to: "", rows: [], caveats: ["x"] })).toEqual(["x"]);
  });
  it("says requests are not downloads, and never uses users or installs", () => {
    const all = REACH_CAVEATS.join(" ").toLowerCase();
    expect(all).toContain("requests are not downloads");
    expect(all).not.toMatch(/\busers?\b|\binstalls?\b/);
  });
});

describe("windows", () => {
  it("lists n UTC days ending at `to`, oldest first, across a month boundary", () => {
    expect(windowDays("2026-11-02", 4)).toEqual(["2026-10-30", "2026-10-31", "2026-11-01", "2026-11-02"]);
  });
  it("requests 90 days ending today (UTC)", () => {
    const r = reachRange(new Date("2026-11-06T23:59:00Z"));
    expect(r.to).toBe("2026-11-06");
    expect(r.from).toBe("2026-08-09");
  });
});

describe("summarize", () => {
  const to = "2026-11-06";
  it("cuts each window from the same rows", () => {
    const rows = [row({ day: "2026-11-06", requests: 1 }), row({ day: "2026-10-20", requests: 10 }), row({ day: "2026-09-01", requests: 100 })];
    expect(summarize(rows, "human", to, 7)[0].requests).toBe(1);
    expect(summarize(rows, "human", to, 30)[0].requests).toBe(11);
    expect(summarize(rows, "human", to, 90)[0].requests).toBe(111);
  });
  it("keeps human and update rows apart and ignores other and noise", () => {
    const rows = [row({}), row({ class: "update", artifact: "agent-manifest" }), row({ class: "other", artifact: "sidecar" }), row({ class: "noise", artifact: "-" })];
    expect(summarize(rows, "human", to, 7).map((s) => s.artifact)).toEqual(["DeskRallySupport.exe"]);
    expect(summarize(rows, "update", to, 7).map((s) => s.artifact)).toEqual(["agent-manifest"]);
  });
  it("zero-fills the daily series and orders busiest first", () => {
    const s = summarize([row({ day: "2026-11-04", requests: 3 }), row({ artifact: "b", day: "2026-11-06", requests: 9 })], "human", to, 7);
    expect(s.map((x) => x.artifact)).toEqual(["b", "DeskRallySupport.exe"]);
    expect(s[1].daily).toEqual([0, 0, 0, 0, 3, 0, 0]);
  });
  it("averages only usable unique-ish days and marks the cell partial when any day is flagged or missing", () => {
    const s = summarize([row({ day: "2026-11-05", uniqueIsh: 4 }), row({ day: "2026-11-06", uniqueIsh: 6 }), row({ day: "2026-11-04", uniqueIsh: 99, partial: true })], "human", to, 7)[0];
    expect(s.uniquePerDay).toBe(5);
    expect(s.uniquePartial).toBe(true);
    expect(uniqueText(s)).toBe("5.0");
  });
  it("shows a dash for unique-ish when every day is flagged or null", () => {
    const s = summarize([row({ partial: true }), row({ day: "2026-11-04", uniqueIsh: null })], "human", to, 7)[0];
    expect(uniqueText(s)).toBe(DASH);
    expect(s.uniquePartial).toBe(true);
  });
  it("a clean figure is not marked partial", () => {
    expect(summarize([row({})], "human", to, 7)[0].uniquePartial).toBe(false);
  });
  it("completed: dash when never known, a lower bound when some days are unknown", () => {
    expect(completedText(summarize([row({ completed: null })], "human", to, 7)[0])).toBe(DASH);
    expect(completedText(summarize([row({ completed: 1200 }), row({ day: "2026-11-04", completed: null })], "human", to, 7)[0])).toBe("≥ 1,200");
    expect(completedText(summarize([row({ completed: 0 })], "human", to, 7)[0])).toBe("0");
  });
});

describe("sparklinePoints", () => {
  it("puts the largest value at the top and zero at the bottom, inside the padding", () => {
    expect(sparklinePoints([0, 10], 100, 20, 2)).toBe("2,18 98,2");
  });
  it("is a flat line along the bottom for an all-zero series, never NaN", () => {
    const p = sparklinePoints([0, 0, 0], 100, 20, 2);
    expect(p).toBe("2,18 50,18 98,18");
    expect(p).not.toContain("NaN");
  });
  it("centres a single point and returns nothing for none", () => {
    expect(sparklinePoints([5], 100, 20, 2)).toBe("50,2");
    expect(sparklinePoints([], 100, 20)).toBe("");
  });
  it("spaces points evenly", () => {
    const xs = sparklinePoints([1, 2, 3, 4, 5], 90, 20, 5).split(" ").map((p) => Number(p.split(",")[0]));
    expect(xs).toEqual([5, 25, 45, 65, 85]);
  });
});

describe("adoption", () => {
  const body = {
    from: "2026-10-07", to: "2026-11-05", active_devices_30d: 7,
    new_devices_per_week: [{ week: "2026-10-26", count: 2 }],
    attended_funnel: { issued: 8, redeemed: 4, consented: 2, active: 1 },
    agent_versions: [{ version: "1.3.18", count: 5 }, { version: "unknown", count: 1 }],
  };
  it("parses the wire shape, and null lists as empty", () => {
    expect(parseAdoption(body)?.activeDevices30d).toBe(7);
    expect(parseAdoption({ ...body, new_devices_per_week: null, agent_versions: null })?.agentVersions).toEqual([]);
  });
  it("refuses a malformed body rather than showing zeros", () => {
    expect(parseAdoption({ ...body, attended_funnel: { issued: 1 } })).toBeNull();
    expect(parseAdoption({ ...body, active_devices_30d: "7" })).toBeNull();
    expect(parseAdoption({ ...body, agent_versions: [{ version: 1, count: 1 }] })).toBeNull();
    expect(parseAdoption(null)).toBeNull();
  });
  it("funnel steps are ordered and share is against the first step", () => {
    const steps = funnelSteps(parseAdoption(body)!.funnel);
    expect(steps.map((s) => s.count)).toEqual([8, 4, 2, 1]);
    expect(steps.map((s) => shareText(s.share))).toEqual(["100%", "50%", "25%", "13%"]);
  });
  it("an empty funnel has no share (a dash, not NaN%)", () => {
    expect(funnelSteps({ issued: 0, redeemed: 0, consented: 0, active: 0 }).map((s) => shareText(s.share))).toEqual([DASH, DASH, DASH, DASH]);
  });
  it("words a never-reported version", () => {
    expect(versionLabel("unknown")).toBe("not reported");
    expect(versionLabel("1.3.18")).toBe("1.3.18");
  });
});
