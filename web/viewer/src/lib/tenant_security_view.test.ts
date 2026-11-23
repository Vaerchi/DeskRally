/** Read-gating decisions for the tenant security panel: unknown is never shown as a default. */
import { describe, it, expect } from "vitest";
import { sessionLimitControlsDisabled, twoFactorControlState } from "./tenant_security_view";

describe("twoFactorControlState", () => {
  it("unknown while loading: disabled, unchecked, loading note", () => {
    const s = twoFactorControlState(null, true, false);
    expect(s.checked).toBe(false);
    expect(s.disabled).toBe(true);
    expect(s.note).toMatch(/loading/i);
  });

  it("unknown after a failed read: disabled, unchecked, unknown note", () => {
    const s = twoFactorControlState(null, false, false);
    expect(s.checked).toBe(false);
    expect(s.disabled).toBe(true);
    expect(s.note).toMatch(/unknown/i);
  });

  it("unknown stays disabled even if saving is false and busy flips", () => {
    expect(twoFactorControlState(null, false, true).disabled).toBe(true);
  });

  it("known true is checked and enabled, with no note", () => {
    expect(twoFactorControlState(true, false, false)).toEqual({ checked: true, disabled: false, note: null });
  });

  it("known false is unchecked and enabled, with no note", () => {
    expect(twoFactorControlState(false, false, false)).toEqual({ checked: false, disabled: false, note: null });
  });

  it("a known value stays enabled during a background refresh but disables while saving", () => {
    expect(twoFactorControlState(true, true, false).disabled).toBe(false);
    expect(twoFactorControlState(true, false, true).disabled).toBe(true);
    expect(twoFactorControlState(true, true, false).checked).toBe(true);
  });
});

describe("sessionLimitControlsDisabled", () => {
  it("is disabled until both stored values are known", () => {
    expect(sessionLimitControlsDisabled(null, null, false)).toBe(true);
    expect(sessionLimitControlsDisabled(0, null, false)).toBe(true);
    expect(sessionLimitControlsDisabled(null, 0, false)).toBe(true);
  });

  it("treats a known 0 (unlimited) as known, not unread", () => {
    expect(sessionLimitControlsDisabled(0, 0, false)).toBe(false);
  });

  it("is disabled while saving even when known", () => {
    expect(sessionLimitControlsDisabled(5, 3600, true)).toBe(true);
  });
});
