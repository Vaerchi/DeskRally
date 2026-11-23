import { describe, expect, it } from "vitest";
import { AREA_CAPABILITIES, areaVisible, heldCapabilities } from "./area_visibility";

describe("console areas follow the user's capabilities (menu redesign wave 5)", () => {
  const technician = new Set(["view_machines", "start_session", "view_sessions", "transfer_files"]);

  it("hides the administration areas from a technician and keeps the work areas", () => {
    for (const a of ["users", "roles", "security", "apitokens", "webhooks", "enrollment", "audit"]) {
      expect(areaVisible(a, technician), a).toBe(false);
    }
    for (const a of ["live", "machines", "attended", "sessions", "reports", "toolbox", "machinegroups", "account", "help"]) {
      expect(areaVisible(a, technician), a).toBe(true);
    }
  });

  it("shows an area when ANY of its capabilities is held", () => {
    expect(areaVisible("enrollment", new Set(["deploy_agent"]))).toBe(true);
    expect(areaVisible("enrollment", new Set(["manage_enrollment"]))).toBe(true);
    expect(areaVisible("toolbox", new Set(["manage_toolbox"]))).toBe(true);
    expect(areaVisible("attended", new Set(["start_session"]))).toBe(true);
    expect(areaVisible("users", new Set(["manage_users"]))).toBe(true);
    expect(areaVisible("security", new Set(["manage_tenant"]))).toBe(true);
  });

  it("hides nothing while the capabilities are unknown, or when the server sends no list", () => {
    for (const a of Object.keys(AREA_CAPABILITIES)) expect(areaVisible(a, null), a).toBe(true);
    expect(heldCapabilities(undefined)).toBeNull();
    expect(heldCapabilities([])).toBeNull();
    expect(heldCapabilities([{ capability: "view_machines" }])).toEqual(new Set(["view_machines"]));
  });

  it("always shows the areas with no rule", () => {
    for (const a of ["live", "account", "help", "appearance"]) expect(areaVisible(a, new Set())).toBe(true);
  });
});
