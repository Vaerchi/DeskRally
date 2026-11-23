import { describe, expect, it, vi } from "vitest";
import { isFullscreenBreakout, lockEscape, shouldShowFullscreenHint, unlockKeys } from "./fullscreen_keys";

describe("the Shift+Esc hint on entering full screen (11-23)", () => {
  it("shows only in full screen, while keys go to the remote, on a non-touch device", () => {
    expect(shouldShowFullscreenHint({ isFullscreen: true, inputActive: true, coarsePointer: false })).toBe(true);
    expect(shouldShowFullscreenHint({ isFullscreen: false, inputActive: true, coarsePointer: false })).toBe(false);
    expect(shouldShowFullscreenHint({ isFullscreen: true, inputActive: false, coarsePointer: false })).toBe(false); // plain Esc still exits
    expect(shouldShowFullscreenHint({ isFullscreen: true, inputActive: true, coarsePointer: true })).toBe(false); // phone: no Esc key
  });
});

const key = (k: string, mods: Partial<{ shiftKey: boolean; ctrlKey: boolean; altKey: boolean; metaKey: boolean }> = {}) =>
  ({ key: k, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, ...mods });

describe("full screen and Escape (11-18: Escape goes to the remote; Shift+Esc leaves)", () => {
  it("only Shift+Esc with no other modifier is the breakout", () => {
    expect(isFullscreenBreakout(key("Escape", { shiftKey: true }))).toBe(true);
    expect(isFullscreenBreakout(key("Escape"))).toBe(false);
    expect(isFullscreenBreakout(key("Escape", { shiftKey: true, ctrlKey: true }))).toBe(false); // Ctrl+Shift+Esc stays the OS's
    expect(isFullscreenBreakout(key("Escape", { shiftKey: true, altKey: true }))).toBe(false);
    expect(isFullscreenBreakout(key("Escape", { shiftKey: true, metaKey: true }))).toBe(false);
    expect(isFullscreenBreakout(key("Tab", { shiftKey: true }))).toBe(false);
  });

  it("locks exactly Escape, and unlocks", () => {
    const lock = vi.fn(async () => {});
    const unlock = vi.fn();
    const win = { navigator: { keyboard: { lock, unlock } } } as unknown as Window;
    lockEscape(win);
    expect(lock).toHaveBeenCalledWith(["Escape"]);
    unlockKeys(win);
    expect(unlock).toHaveBeenCalledOnce();
  });

  it("is a no-op where Keyboard Lock does not exist or refuses", () => {
    expect(() => lockEscape({ navigator: {} } as unknown as Window)).not.toThrow();
    expect(() => unlockKeys({ navigator: {} } as unknown as Window)).not.toThrow();
    expect(() => lockEscape(null)).not.toThrow();
    const refusing = { navigator: { keyboard: { lock: () => Promise.reject(new Error("not fullscreen")) } } } as unknown as Window;
    expect(() => lockEscape(refusing)).not.toThrow();
  });
});
