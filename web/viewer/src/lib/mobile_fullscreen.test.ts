import { describe, expect, it } from "vitest";
import { shouldUseMobileFullscreenBar as f } from "./mobile_fullscreen";
import { STACKED_MAX_WIDTH } from "./layout_breakpoints";

const base = { isFullscreen: true, coarsePointer: false, width: 1400, poppedOut: false };

describe("shouldUseMobileFullscreenBar", () => {
  it("is off outside full screen, whatever the device", () => {
    expect(f({ ...base, isFullscreen: false, coarsePointer: true, width: 400 })).toBe(false);
  });
  it("is off for a desktop (fine pointer, wide) in full screen", () => {
    expect(f(base)).toBe(false);
  });
  it("is on for a coarse pointer at any width (a tablet)", () => {
    expect(f({ ...base, coarsePointer: true })).toBe(true);
  });
  it("is on for a narrow viewport even with a fine pointer", () => {
    expect(f({ ...base, width: STACKED_MAX_WIDTH })).toBe(true);
    expect(f({ ...base, width: STACKED_MAX_WIDTH + 1 })).toBe(false);
  });
  it("keeps pop-out windows on their own chrome", () => {
    expect(f({ ...base, coarsePointer: true, width: 400, poppedOut: true })).toBe(false);
  });
  it("does not treat a nonsense width as narrow", () => {
    expect(f({ ...base, width: 0 })).toBe(false);
    expect(f({ ...base, width: NaN })).toBe(false);
    expect(f({ ...base, width: -5 })).toBe(false);
  });
});
