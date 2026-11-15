/**
 * Tests for the viewport transform (zoom & pan) — the pointer→desktop mapping that must be correct at
 * any zoom/pan or a click lands in the wrong place on the customer's machine. All pure math, no DOM.
 *
 * The worked examples use round numbers so the expected absolute coordinates are exact, not fudged.
 */

import { describe, it, expect } from "vitest";
import {
  MIN_ZOOM,
  MAX_ZOOM,
  IDENTITY_VIEW,
  clampZoom,
  contentRect,
  mapPointerToAbs,
  clampPan,
  zoomAtPoint,
  zoomToCenter,
  zoomByWheel,
  panBy,
  actualZoom,
  displayScale,
  displayScalePct,
  isPannable,
  type Dims,
  type ViewTransform,
} from "./viewport";

// A square surface with a square desktop: base = 1, no letterbox. The simplest case.
const square: Dims = { surfaceW: 1000, surfaceH: 1000, contentW: 1000, contentH: 1000 };
// A square surface showing a 2:1 desktop: base = 0.5, so a top/bottom LETTERBOX at fit.
const wide: Dims = { surfaceW: 1000, surfaceH: 1000, contentW: 2000, contentH: 1000 };
// A viewport smaller than the desktop on both axes (base = 0.5) — the usual real case.
const small: Dims = { surfaceW: 800, surfaceH: 600, contentW: 1600, contentH: 1200 };

describe("clampZoom", () => {
  it("bounds into [MIN_ZOOM, MAX_ZOOM] and floors non-finite to MIN_ZOOM", () => {
    expect(clampZoom(0.1)).toBe(MIN_ZOOM);
    expect(clampZoom(1e9)).toBe(MAX_ZOOM);
    expect(clampZoom(3)).toBe(3);
    // Any non-finite value floors to the safe fit view, never to max magnification — a garbage zoom
    // should never leave the operator staring at an 16×-blown-up corner.
    expect(clampZoom(NaN)).toBe(MIN_ZOOM);
    expect(clampZoom(Infinity)).toBe(MIN_ZOOM);
    expect(clampZoom(-Infinity)).toBe(MIN_ZOOM);
  });
});

describe("contentRect", () => {
  it("fills the surface with no offset when the aspect ratios match (base = 1, fit)", () => {
    expect(contentRect(square, IDENTITY_VIEW)).toEqual({ ox: 0, oy: 0, cw: 1000, ch: 1000 });
  });

  it("letterboxes a wide desktop: the image is a centred horizontal band at fit", () => {
    // base = 0.5 → 1000×500 centred vertically: 250px bar top and bottom.
    expect(contentRect(wide, IDENTITY_VIEW)).toEqual({ ox: 0, oy: 250, cw: 1000, ch: 500 });
  });

  it("returns null for a degenerate (zero-size) surface", () => {
    expect(contentRect({ surfaceW: 0, surfaceH: 0, contentW: 100, contentH: 100 }, IDENTITY_VIEW)).toBeNull();
  });

  it("treats unknown content dims (0) as filling the surface", () => {
    const d: Dims = { surfaceW: 640, surfaceH: 480, contentW: 0, contentH: 0 };
    expect(contentRect(d, IDENTITY_VIEW)).toEqual({ ox: 0, oy: 0, cw: 640, ch: 480 });
  });
});

describe("mapPointerToAbs — the correctness core", () => {
  it("maps the surface centre to the desktop centre and the corners to the abs extremes (fit, no letterbox)", () => {
    expect(mapPointerToAbs(500, 500, square, IDENTITY_VIEW)).toEqual({ xAbs: 32768, yAbs: 32768 });
    expect(mapPointerToAbs(0, 0, square, IDENTITY_VIEW)).toEqual({ xAbs: 0, yAbs: 0 });
    expect(mapPointerToAbs(1000, 1000, square, IDENTITY_VIEW)).toEqual({ xAbs: 65535, yAbs: 65535 });
  });

  it("returns null over the letterbox rather than clamping to a bogus edge coordinate", () => {
    // (500,100) is 150px up into the top letterbox band of `wide` (image starts at oy=250).
    expect(mapPointerToAbs(500, 100, wide, IDENTITY_VIEW)).toBeNull();
  });

  it("maps within the letterboxed band using the BAND height, not the whole surface (the old bug)", () => {
    // The pre-feature code divided by the whole surface height: fy = 300/1000 = 0.30 → yAbs 19661.
    // The correct mapping divides by the 500px band starting at oy=250: fy = (300-250)/500 = 0.10.
    expect(mapPointerToAbs(500, 300, wide, IDENTITY_VIEW)).toEqual({ xAbs: 32768, yAbs: 6554 });
  });

  it("is correct when ZOOMED: at 2× centred, the surface top-left shows the desktop's 25% point", () => {
    const v = zoomToCenter(square, IDENTITY_VIEW, 2);
    expect(mapPointerToAbs(0, 0, square, v)).toEqual({ xAbs: 16384, yAbs: 16384 });
    // The centre still maps to the desktop centre.
    expect(mapPointerToAbs(500, 500, square, v)).toEqual({ xAbs: 32768, yAbs: 32768 });
  });
});

describe("zoomAtPoint — holds the point under the cursor fixed", () => {
  it("keeps the desktop coordinate under the cursor identical across a zoom change", () => {
    const cursorX = 600;
    const cursorY = 450;
    const before = mapPointerToAbs(cursorX, cursorY, small, IDENTITY_VIEW);
    const zoomed = zoomAtPoint(small, IDENTITY_VIEW, cursorX, cursorY, 2);
    const after = mapPointerToAbs(cursorX, cursorY, small, zoomed);
    expect(after).toEqual(before); // the pixel under the cursor did not move
    expect(zoomed.zoom).toBe(2);
  });

  it("clamps zoom and, on a no-op zoom, still returns a pan-clamped view", () => {
    const over = zoomAtPoint(square, IDENTITY_VIEW, 500, 500, 1e6);
    expect(over.zoom).toBe(MAX_ZOOM);
    // Same-zoom call: no change in zoom, pan clamped (here already centred → identity).
    expect(zoomAtPoint(square, IDENTITY_VIEW, 500, 500, 1)).toEqual(IDENTITY_VIEW);
  });
});

describe("clampPan", () => {
  it("re-centres and zeroes the pan at fit (zoom = 1 ⇒ pan = 0), even if asked to pan", () => {
    const nudged: ViewTransform = { zoom: 1, panX: 120, panY: -80 };
    expect(clampPan(square, nudged)).toEqual({ zoom: 1, panX: 0, panY: 0 });
  });

  it("keeps both edges covered when zoomed in — no black gap at any edge", () => {
    // 2× on the square desktop → content 2000 wide in a 1000 surface: ox must stay in [-1000, 0].
    const overRight = clampPan(square, { zoom: 2, panX: 500, panY: 0 });
    expect(contentRect(square, overRight)!.ox).toBe(0); // snapped to the left edge (ox ≤ 0)
    const overLeft = clampPan(square, { zoom: 2, panX: -5000, panY: 0 });
    const r = contentRect(square, overLeft)!;
    expect(r.ox).toBe(-1000); // right edge flush: ox + cw = -1000 + 2000 = 1000 = surfaceW
    expect(r.ox + r.cw).toBe(1000);
  });
});

describe("panBy", () => {
  it("translates then clamps (a drag past the edge is caught)", () => {
    const v = zoomToCenter(square, IDENTITY_VIEW, 2); // centred at 2×: ox = -500
    const panned = panBy(square, v, 200, 0); // drag right 200 → ox would be -300, still legal
    expect(contentRect(square, panned)!.ox).toBe(-300);
    const slammed = panBy(square, v, 100000, 0); // drag far right → snaps to left edge
    expect(contentRect(square, slammed)!.ox).toBe(0);
  });
});

describe("actualZoom / displayScale (1:1 semantics)", () => {
  it("actualZoom is 1/base, so displayScale there is exactly native (100%)", () => {
    expect(actualZoom(small)).toBe(2); // base 0.5 → native at 2× fit
    expect(displayScale(small, { zoom: actualZoom(small), panX: 0, panY: 0 })).toBeCloseTo(1, 10);
    expect(displayScalePct(small, { zoom: actualZoom(small), panX: 0, panY: 0 })).toBe(100);
  });

  it("reads the fit as its native-relative percent (a desktop bigger than the viewport shows < 100%)", () => {
    expect(displayScalePct(small, IDENTITY_VIEW)).toBe(50); // base 0.5 → fit is 50% of native
  });

  it("clamps 1:1 to fit when the desktop is SMALLER than the viewport (every pixel already visible)", () => {
    const big: Dims = { surfaceW: 2000, surfaceH: 2000, contentW: 1000, contentH: 1000 };
    expect(actualZoom(big)).toBe(MIN_ZOOM);
  });
});

describe("zoomByWheel", () => {
  it("scroll up (deltaY < 0) zooms in; scroll down zooms out; and it cannot go below fit", () => {
    const inOne = zoomByWheel(square, IDENTITY_VIEW, 500, 500, -100);
    expect(inOne.zoom).toBeGreaterThan(1);
    const back = zoomByWheel(square, inOne, 500, 500, +100);
    expect(back.zoom).toBeLessThan(inOne.zoom);
    // From fit, scrolling down stays at fit (clamped to MIN_ZOOM).
    expect(zoomByWheel(square, IDENTITY_VIEW, 500, 500, +100).zoom).toBe(MIN_ZOOM);
  });
});

describe("isPannable", () => {
  it("is false at fit (whole desktop visible) and true once the content overflows the surface", () => {
    expect(isPannable(square, IDENTITY_VIEW)).toBe(false);
    expect(isPannable(wide, IDENTITY_VIEW)).toBe(false); // letterboxed but fully visible → nothing to pan
    expect(isPannable(square, { zoom: 2, panX: 0, panY: 0 })).toBe(true);
    expect(isPannable(wide, { zoom: 1.5, panX: 0, panY: 0 })).toBe(true); // 1500 > 1000 wide now
  });
});
