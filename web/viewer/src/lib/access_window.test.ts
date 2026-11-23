import { describe, expect, it } from "vitest";
import {
  crossesMidnight,
  daysLabel,
  draftFromWindow,
  draftToWindow,
  readWindow,
  timeZoneOptions,
  toggleDay,
  windowLabel,
} from "./access_window";

describe("window labels (docs/57)", () => {
  it("compresses runs of three or more days, Mon first", () => {
    expect(daysLabel(["fri", "mon", "tue", "wed", "thu"])).toBe("Mon–Fri");
    expect(daysLabel(["sat", "sun"])).toBe("Sat, Sun");
    expect(daysLabel(["mon", "wed"])).toBe("Mon, Wed");
    expect(daysLabel(["mon", "fri", "sat", "sun"])).toBe("Mon, Fri–Sun");
    expect(daysLabel(["sun", "mon", "tue", "wed", "thu", "fri", "sat"])).toBe("Every day");
  });
  it("labels a whole window", () => {
    expect(windowLabel({ days: ["mon", "tue", "wed", "thu", "fri"], start: "08:00", end: "18:00", time_zone: "Europe/London" })).toBe(
      "Mon–Fri 08:00–18:00 (Europe/London)",
    );
  });
  it("knows when a window runs past midnight", () => {
    expect(crossesMidnight("22:00", "06:00")).toBe(true);
    expect(crossesMidnight("08:00", "08:00")).toBe(true);
    expect(crossesMidnight("08:00", "18:00")).toBe(false);
    expect(crossesMidnight("00:00", "24:00")).toBe(false);
  });
});

describe("readWindow", () => {
  it("accepts the API shape and refuses anything else", () => {
    const w = { days: ["mon"], start: "08:00", end: "18:00", time_zone: "UTC" };
    expect(readWindow(w)).toEqual(w);
    expect(readWindow(null)).toBeNull();
    expect(readWindow(undefined)).toBeNull();
    expect(readWindow({ days: "mon", start: "08:00", end: "18:00", time_zone: "UTC" })).toBeNull();
    expect(readWindow({ days: [1], start: "08:00", end: "18:00", time_zone: "UTC" })).toBeNull();
    expect(readWindow({ days: ["mon"], start: 8, end: "18:00", time_zone: "UTC" })).toBeNull();
  });
});

describe("editor draft <-> API window", () => {
  it("defaults to off, weekdays 08:00-18:00 in the given zone", () => {
    const d = draftFromWindow(null, "Europe/Paris");
    expect(d.enabled).toBe(false);
    expect(draftToWindow(d)).toEqual({ window: null });
    expect(draftToWindow({ ...d, enabled: true })).toEqual({
      window: { days: ["mon", "tue", "wed", "thu", "fri"], start: "08:00", end: "18:00", time_zone: "Europe/Paris" },
    });
  });
  it("round-trips 24:00 through the end-of-day box (a time input cannot hold it)", () => {
    const w = { days: ["sun"], start: "00:00", end: "24:00", time_zone: "UTC" };
    const d = draftFromWindow(w, "Europe/London");
    expect(d.endOfDay).toBe(true);
    expect(d.zone).toBe("UTC"); // the STORED zone, not the browser's
    expect(draftToWindow(d)).toEqual({ window: w });
  });
  it("sends days in a stable order", () => {
    const d = { ...draftFromWindow(null, "UTC"), enabled: true, days: ["sun", "fri", "mon"] };
    expect(draftToWindow(d)).toMatchObject({ window: { days: ["mon", "fri", "sun"] } });
  });
  it("refuses an incomplete draft with a message", () => {
    const on = { ...draftFromWindow(null, "UTC"), enabled: true };
    expect(draftToWindow({ ...on, days: [] })).toHaveProperty("error");
    expect(draftToWindow({ ...on, start: "" })).toHaveProperty("error");
    expect(draftToWindow({ ...on, end: "" })).toHaveProperty("error");
    expect(draftToWindow({ ...on, end: "08:00" })).toHaveProperty("error"); // equal to start
    expect(draftToWindow({ ...on, zone: " " })).toHaveProperty("error");
    expect(draftToWindow({ ...on, end: "", endOfDay: true })).toMatchObject({ window: { end: "24:00" } });
  });
  it("toggles days without duplicates", () => {
    expect(toggleDay(["mon"], "tue")).toEqual(["mon", "tue"]);
    expect(toggleDay(["mon", "tue"], "mon")).toEqual(["tue"]);
  });
});

describe("timeZoneOptions", () => {
  it("always offers UTC and the stored zone, sorted and de-duplicated", () => {
    const zones = timeZoneOptions("Etc/GMT+5", "Etc/GMT+5", null);
    expect(zones).toContain("UTC");
    expect(zones).toContain("Etc/GMT+5");
    expect(new Set(zones).size).toBe(zones.length);
    expect([...zones].sort((a, b) => a.localeCompare(b))).toEqual(zones);
  });
});
