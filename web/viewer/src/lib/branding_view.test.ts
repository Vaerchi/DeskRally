import { describe, expect, it } from "vitest";
import { brandingControlsDisabled, canManageTenant, publicJoinControlsDisabled } from "./branding_view";

describe("brandingControlsDisabled", () => {
  it("is disabled before the load has succeeded", () => {
    expect(brandingControlsDisabled(false, false)).toBe(true);
  });
  it("is disabled while busy even if the load had not succeeded", () => {
    expect(brandingControlsDisabled(false, true)).toBe(true);
  });
  it("is disabled while a save is in flight", () => {
    expect(brandingControlsDisabled(true, true)).toBe(true);
  });
  it("is enabled only when loaded and idle", () => {
    expect(brandingControlsDisabled(true, false)).toBe(false);
  });
});

describe("publicJoinControlsDisabled", () => {
  it("is enabled only for an Owner, loaded and idle", () => {
    expect(publicJoinControlsDisabled(true, false, true)).toBe(false);
  });
  it("a member never gets editable controls", () => {
    expect(publicJoinControlsDisabled(true, false, false)).toBe(true);
  });
  it("is disabled before the load and while submitting, even for an Owner", () => {
    expect(publicJoinControlsDisabled(false, false, true)).toBe(true);
    expect(publicJoinControlsDisabled(true, true, true)).toBe(true);
    expect(publicJoinControlsDisabled(false, true, true)).toBe(true);
  });
});

describe("canManageTenant", () => {
  it("is true only when manage_tenant is held", () => {
    expect(canManageTenant([{ capability: "view_audit" }, { capability: "manage_tenant" }])).toBe(true);
    expect(canManageTenant([{ capability: "manage_users" }])).toBe(false);
    expect(canManageTenant([])).toBe(false);
  });
});
