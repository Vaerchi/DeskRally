import { describe, expect, it } from "vitest";
import { accessLabel, isoToLocalInput, localInputToISO } from "./user_access";

describe("accessLabel (docs/56)", () => {
  it("is Never when the server says nothing (older server) or null", () => {
    expect(accessLabel({})).toBe("Never");
    expect(accessLabel({ access_expires_at: null, access_expired: false })).toBe("Never");
  });
  it("is Expired whenever access_expired, even with a date", () => {
    expect(accessLabel({ access_expires_at: "2026-11-05T17:00:00Z", access_expired: true })).toBe("Expired");
  });
  it("shows the expiry otherwise", () => {
    expect(accessLabel({ access_expires_at: "2026-11-05T17:00:00Z", access_expired: false })).toMatch(/^Expires .*2026/);
  });
  it("treats a garbage date as Never rather than rendering Invalid Date", () => {
    expect(accessLabel({ access_expires_at: "not a date" })).toBe("Never");
  });
});

describe("local datetime <-> RFC 3339", () => {
  it("round-trips a local value through UTC", () => {
    const iso = localInputToISO("2026-11-05T17:00");
    expect(iso).toMatch(/^2026-11-0[56]T\d{2}:00:00Z$/);
    expect(isoToLocalInput(iso)).toBe("2026-11-05T17:00");
  });
  it("sends no milliseconds (a stable RFC 3339 value)", () => {
    expect(localInputToISO("2026-11-05T17:00")).not.toMatch(/\.\d+Z$/);
  });
  it("refuses a calendar date the browser would normalize (31 Feb → 3 Mar)", () => {
    expect(localInputToISO("2026-02-31T10:00")).toBeNull();
    expect(localInputToISO("2026-13-01T10:00")).toBeNull();
    expect(localInputToISO("2026-11-05T24:30")).toBeNull();
  });
  it("refuses a local time inside a DST gap, wherever the test machine's zone has one", () => {
    // Find a spring-forward gap in the CURRENT zone (none in UTC zones: then nothing to assert).
    for (let day = 0; day < 366; day++) {
      const base = new Date(2026, 0, 1 + day);
      for (let h = 0; h < 24; h++) {
        const at = new Date(base.getFullYear(), base.getMonth(), base.getDate(), h, 30);
        if (at.getHours() !== h) {
          const pad = (n: number) => String(n).padStart(2, "0");
          const v = `${base.getFullYear()}-${pad(base.getMonth() + 1)}-${pad(base.getDate())}T${pad(h)}:30`;
          expect(localInputToISO(v)).toBeNull();
          return;
        }
      }
    }
  });
  it("refuses empty and malformed input", () => {
    expect(localInputToISO("")).toBeNull();
    expect(localInputToISO("2026-11-05")).toBeNull();
    expect(localInputToISO("tomorrow")).toBeNull();
    expect(isoToLocalInput(null)).toBe("");
    expect(isoToLocalInput("garbage")).toBe("");
  });
});
