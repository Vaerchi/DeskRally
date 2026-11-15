import { describe, expect, it } from "vitest";
import { connectState, inService } from "./connect_rule";

describe("the one connect rule (menu redesign wave 3)", () => {
  it("never lets presence disable Connect: offline and unknown keep it, with the reason", () => {
    for (const online of [true, false, undefined]) {
      const s = connectState({ online, current: false });
      expect(s.enabled, `online=${online}`).toBe(true);
      expect(s.label).toBe("Connect");
    }
    expect(connectState({ online: false, current: false }).hint).toMatch(/looked offline/);
    expect(connectState({ online: undefined, current: false }).hint).toMatch(/unavailable/);
  });

  it("disables Connect only for a machine out of service, whatever its presence", () => {
    for (const status of ["quarantined", "retired", "removed"]) {
      for (const online of [true, false, undefined]) {
        const s = connectState({ online, status, current: false });
        expect(s.enabled, `${status} online=${online}`).toBe(false);
        expect(s.hint).toContain(status);
      }
    }
    expect(connectState({ online: true, status: "active", current: false }).enabled).toBe(true);
    expect(connectState({ online: true, status: undefined, current: false }).enabled).toBe(true);
  });

  it("says Return to session for the machine already being viewed, and out of service still wins", () => {
    expect(connectState({ online: true, current: true })).toMatchObject({ enabled: true, label: "Return to session" });
    expect(connectState({ online: true, status: "quarantined", current: true }).enabled).toBe(false);
  });

  it("treats an absent status as active", () => {
    expect(inService(undefined)).toBe(true);
    expect(inService("active")).toBe(true);
    expect(inService("retired")).toBe(false);
  });
});
