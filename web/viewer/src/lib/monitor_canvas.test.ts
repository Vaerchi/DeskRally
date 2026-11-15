/**
 * Unit tests for monitor_canvas.ts — crop math for viewer-side independent monitor rendering.
 *
 * All tests are pure math on plain numbers. No DOM, no browser, no encoder.
 */

import { describe, it, expect } from "vitest";
import {
  monitorCrop,
  remapCroppedPointer,
  cropStyles,
  type MonitorCanvas,
  type NormalizedCrop,
} from "./monitor_canvas";

// ── Fixtures ─────────────────────────────────────────────────────────────────

/** Two 1920×1080 monitors side by side: total canvas 3840×1080. */
const sideBySide: MonitorCanvas = {
  width: 3840,
  height: 1080,
  monitors: [
    { id: 0, x: 0, y: 0, width: 1920, height: 1080 },
    { id: 1, x: 1920, y: 0, width: 1920, height: 1080 },
  ],
};

/** Two monitors stacked vertically: 1920×1080 on top, 1920×1080 below. */
const stacked: MonitorCanvas = {
  width: 1920,
  height: 2160,
  monitors: [
    { id: 0, x: 0, y: 0, width: 1920, height: 1080 },
    { id: 1, x: 0, y: 1080, width: 1920, height: 1080 },
  ],
};

/** Mixed resolutions: 2560×1440 primary + 1920×1080 secondary (different heights). */
const mixedRes: MonitorCanvas = {
  width: 4480,
  height: 1440,
  monitors: [
    { id: 0, x: 0, y: 0, width: 2560, height: 1440 },
    { id: 1, x: 2560, y: 180, width: 1920, height: 1080 }, // centred vertically next to primary
  ],
};

/** Three monitors: left secondary, primary centre, right secondary. */
const threeWide: MonitorCanvas = {
  width: 5760,
  height: 1080,
  monitors: [
    { id: 0, x: 1920, y: 0, width: 1920, height: 1080 }, // primary (centre)
    { id: 1, x: 0, y: 0, width: 1920, height: 1080 },    // left secondary
    { id: 2, x: 3840, y: 0, width: 1920, height: 1080 }, // right secondary
  ],
};

// ── monitorCrop ───────────────────────────────────────────────────────────────

describe("monitorCrop — normalized crop rectangle", () => {
  it("returns null for composite id (-1)", () => {
    expect(monitorCrop(sideBySide, -1)).toBeNull();
  });

  it("returns null for an unknown monitor id", () => {
    expect(monitorCrop(sideBySide, 99)).toBeNull();
  });

  it("left monitor: occupies the left half of the canvas", () => {
    const crop = monitorCrop(sideBySide, 0);
    expect(crop).not.toBeNull();
    expect(crop!.left).toBeCloseTo(0, 9);
    expect(crop!.top).toBeCloseTo(0, 9);
    expect(crop!.width).toBeCloseTo(0.5, 9);
    expect(crop!.height).toBeCloseTo(1, 9);
  });

  it("right monitor: occupies the right half of the canvas", () => {
    const crop = monitorCrop(sideBySide, 1);
    expect(crop).not.toBeNull();
    expect(crop!.left).toBeCloseTo(0.5, 9);
    expect(crop!.top).toBeCloseTo(0, 9);
    expect(crop!.width).toBeCloseTo(0.5, 9);
    expect(crop!.height).toBeCloseTo(1, 9);
  });

  it("stacked: bottom monitor has top offset 0.5", () => {
    const crop = monitorCrop(stacked, 1);
    expect(crop).not.toBeNull();
    expect(crop!.top).toBeCloseTo(0.5, 9);
    expect(crop!.left).toBeCloseTo(0, 9);
    expect(crop!.width).toBeCloseTo(1, 9);
    expect(crop!.height).toBeCloseTo(0.5, 9);
  });

  it("mixed resolution: secondary has non-zero top offset (vertical centering)", () => {
    const crop = monitorCrop(mixedRes, 1);
    expect(crop).not.toBeNull();
    // y=180/1440 = 0.125
    expect(crop!.top).toBeCloseTo(180 / 1440, 9);
    expect(crop!.left).toBeCloseTo(2560 / 4480, 9);
    expect(crop!.width).toBeCloseTo(1920 / 4480, 9);
    expect(crop!.height).toBeCloseTo(1080 / 1440, 9);
  });

  it("three monitors: centre (primary) has non-zero left offset", () => {
    const crop = monitorCrop(threeWide, 0);
    expect(crop).not.toBeNull();
    expect(crop!.left).toBeCloseTo(1920 / 5760, 9);
    expect(crop!.width).toBeCloseTo(1920 / 5760, 9);
  });

  it("returns null for a degenerate canvas (zero width)", () => {
    expect(monitorCrop({ width: 0, height: 1080, monitors: [{ id: 0, x: 0, y: 0, width: 1920, height: 1080 }] }, 0)).toBeNull();
  });

  it("returns null for a monitor with zero width", () => {
    expect(monitorCrop({ width: 3840, height: 1080, monitors: [{ id: 0, x: 0, y: 0, width: 0, height: 1080 }] }, 0)).toBeNull();
  });
});

// ── remapCroppedPointer ───────────────────────────────────────────────────────

describe("remapCroppedPointer — crop-local normalized → full-canvas normalized", () => {
  it("top-left of crop maps to the crop's own left/top in canvas coordinates", () => {
    const crop = monitorCrop(sideBySide, 1)!; // right half: left=0.5, top=0, w=0.5, h=1
    const r = remapCroppedPointer(0, 0, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(0.5, 9);
    expect(r!.ny).toBeCloseTo(0, 9);
  });

  it("bottom-right of crop maps to the crop's right/bottom in canvas coordinates", () => {
    const crop = monitorCrop(sideBySide, 1)!;
    const r = remapCroppedPointer(1, 1, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(1, 9);
    expect(r!.ny).toBeCloseTo(1, 9);
  });

  it("centre of left monitor maps to canvas quarter-point", () => {
    const crop = monitorCrop(sideBySide, 0)!; // left=0, top=0, w=0.5, h=1
    const r = remapCroppedPointer(0.5, 0.5, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(0.25, 9);
    expect(r!.ny).toBeCloseTo(0.5, 9);
  });

  it("stacked: centre of bottom monitor maps to canvas 3/4 down", () => {
    const crop = monitorCrop(stacked, 1)!; // top=0.5, h=0.5
    const r = remapCroppedPointer(0.5, 0.5, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(0.5, 9);
    expect(r!.ny).toBeCloseTo(0.75, 9);
  });

  it("mixed resolution: pointer in secondary maps through non-zero top offset", () => {
    const crop = monitorCrop(mixedRes, 1)!;
    const r = remapCroppedPointer(0, 0, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(2560 / 4480, 9);
    expect(r!.ny).toBeCloseTo(180 / 1440, 9);
  });

  it("returns null for out-of-range pointer (e.g. letterbox click)", () => {
    const crop = monitorCrop(sideBySide, 0)!;
    expect(remapCroppedPointer(-0.01, 0.5, crop)).toBeNull();
    expect(remapCroppedPointer(0.5, 1.01, crop)).toBeNull();
  });

  it("returns null for a zero-size crop", () => {
    const zeroCrop: NormalizedCrop = { left: 0, top: 0, width: 0, height: 1 };
    expect(remapCroppedPointer(0.5, 0.5, zeroCrop)).toBeNull();
  });
});

// ── cropStyles ────────────────────────────────────────────────────────────────

describe("cropStyles — CSS wrapper and video offset calculation", () => {
  it("fillSurface=true: wrapper covers 0/0/100%/100%", () => {
    const crop = monitorCrop(sideBySide, 0)!;
    const { wrapperStyle } = cropStyles(crop, true);
    expect(wrapperStyle.left).toBe("0%");
    expect(wrapperStyle.top).toBe("0%");
    expect(wrapperStyle.width).toBe("100%");
    expect(wrapperStyle.height).toBe("100%");
    expect(wrapperStyle.overflow).toBe("hidden");
  });

  it("fillSurface=true: video is 200% wide for a half-canvas crop (side-by-side, left)", () => {
    const crop = monitorCrop(sideBySide, 0)!; // width=0.5
    const { videoOffsetStyle } = cropStyles(crop, true);
    // 1/0.5 = 200%
    expect(videoOffsetStyle.width).toBe("200%");
    expect(videoOffsetStyle.height).toBe("100%"); // height fraction = 1
    expect(videoOffsetStyle.left).toBe("0%"); // no left offset for left monitor
    expect(videoOffsetStyle.top).toBe("0%");
  });

  it("fillSurface=true: right monitor video is offset left by -100% of wrapper", () => {
    const crop = monitorCrop(sideBySide, 1)!; // left=0.5, width=0.5
    const { videoOffsetStyle } = cropStyles(crop, true);
    // -(0.5/0.5)*100 = -100%
    expect(videoOffsetStyle.left).toBe("-100%");
    expect(videoOffsetStyle.width).toBe("200%");
  });

  it("fillSurface=true: stacked bottom monitor is offset top by -100%", () => {
    const crop = monitorCrop(stacked, 1)!; // top=0.5, height=0.5
    const { videoOffsetStyle } = cropStyles(crop, true);
    expect(videoOffsetStyle.top).toBe("-100%");
    expect(videoOffsetStyle.height).toBe("200%");
  });

  it("fillSurface=false: wrapper is at crop's proportional position", () => {
    const crop = monitorCrop(sideBySide, 1)!; // left=0.5, top=0, w=0.5, h=1
    const { wrapperStyle } = cropStyles(crop, false);
    expect(wrapperStyle.left).toBe("50%");
    expect(wrapperStyle.top).toBe("0%");
    expect(wrapperStyle.width).toBe("50%");
    expect(wrapperStyle.height).toBe("100%");
  });

  it("scaling: mixed-resolution secondary monitor has correct video scale", () => {
    const crop = monitorCrop(mixedRes, 1)!;
    const { videoOffsetStyle } = cropStyles(crop, true);
    const expectedW = (1 / crop.width) * 100;
    const expectedH = (1 / crop.height) * 100;
    expect(videoOffsetStyle.width).toBe(`${expectedW}%`);
    expect(videoOffsetStyle.height).toBe(`${expectedH}%`);
  });

  it("rounding: values are exact numbers (no floating-point string truncation issues for common sizes)", () => {
    // 1920/3840 = exactly 0.5 — no rounding needed, result must be exact.
    const crop = monitorCrop(sideBySide, 0)!;
    const { videoOffsetStyle } = cropStyles(crop, true);
    expect(videoOffsetStyle.width).toBe("200%");
  });
});

// ── Round-trip sanity: crop → remap covers edge cases ────────────────────────

describe("round-trip: pointer at crop edge maps to correct canvas boundary", () => {
  it("three-wide: right monitor right edge → canvas right edge (1.0)", () => {
    const crop = monitorCrop(threeWide, 2)!; // rightmost: x=3840, w=1920, canvas=5760
    const r = remapCroppedPointer(1, 0.5, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(1, 9);
  });

  it("three-wide: left monitor left edge → canvas left edge (0.0)", () => {
    const crop = monitorCrop(threeWide, 1)!; // leftmost: x=0
    const r = remapCroppedPointer(0, 0.5, crop);
    expect(r).not.toBeNull();
    expect(r!.nx).toBeCloseTo(0, 9);
  });
});
