import { describe, it, expect } from "vitest";
import { shouldUseCompactBar, pickerAsButtons, MAX_PICKER_BUTTONS } from "./mobile_bar";
import { STACKED_MAX_WIDTH } from "./layout_breakpoints";

const phone = { isFullscreen: false, coarsePointer: true, width: 412, poppedOut: false };

describe("shouldUseCompactBar", () => {
  it("is on for a touch device at phone width outside full screen", () => {
    expect(shouldUseCompactBar(phone)).toBe(true);
    expect(shouldUseCompactBar({ ...phone, width: STACKED_MAX_WIDTH })).toBe(true);
  });
  it("needs BOTH a coarse pointer and a narrow viewport", () => {
    expect(shouldUseCompactBar({ ...phone, coarsePointer: false })).toBe(false); // narrow desktop window
    expect(shouldUseCompactBar({ ...phone, width: STACKED_MAX_WIDTH + 1 })).toBe(false); // tablet, laptop touch screen
    expect(shouldUseCompactBar({ ...phone, coarsePointer: false, width: 1440 })).toBe(false);
  });
  it("is off in full screen (which has its own bar) and in a pop-out", () => {
    expect(shouldUseCompactBar({ ...phone, isFullscreen: true })).toBe(false);
    expect(shouldUseCompactBar({ ...phone, poppedOut: true })).toBe(false);
  });
  it("never counts a nonsense width as narrow", () => {
    for (const width of [0, -5, NaN, Infinity]) expect(shouldUseCompactBar({ ...phone, width })).toBe(false);
  });
});

describe("pickerAsButtons", () => {
  it("is for 2..MAX choices only", () => {
    expect(pickerAsButtons(0)).toBe(false);
    expect(pickerAsButtons(1)).toBe(false);
    expect(pickerAsButtons(2)).toBe(true);
    expect(pickerAsButtons(MAX_PICKER_BUTTONS)).toBe(true);
    expect(pickerAsButtons(MAX_PICKER_BUTTONS + 1)).toBe(false);
  });
});
