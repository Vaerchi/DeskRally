import { describe, expect, it } from "vitest";
import { LOGO_MAX_HEIGHT, LOGO_MAX_UPLOAD_BYTES, LOGO_MAX_WIDTH, LOGO_PICK_TYPES, dataUriBytes, fitWithin } from "./brand_logo";

describe("fitWithin", () => {
  it("never enlarges", () => {
    expect(fitWithin(100, 50)).toEqual({ width: 100, height: 50 });
    expect(fitWithin(512, 256)).toEqual({ width: 512, height: 256 });
  });
  it("shrinks a wide image to the width, keeping proportions", () => {
    expect(fitWithin(2048, 512)).toEqual({ width: 512, height: 128 });
  });
  it("shrinks a tall image to the height", () => {
    expect(fitWithin(1000, 1000)).toEqual({ width: 256, height: 256 });
    expect(fitWithin(300, 1024)).toEqual({ width: 75, height: 256 });
  });
  it("never exceeds 512x256 and never returns a zero side", () => {
    for (const [w, h] of [[4000, 10], [10, 4000], [513, 257], [1, 1], [100000, 100000]] as const) {
      const f = fitWithin(w, h);
      expect(f.width).toBeLessThanOrEqual(LOGO_MAX_WIDTH);
      expect(f.height).toBeLessThanOrEqual(LOGO_MAX_HEIGHT);
      expect(f.width).toBeGreaterThanOrEqual(1);
      expect(f.height).toBeGreaterThanOrEqual(1);
    }
    expect(fitWithin(4000, 10)).toEqual({ width: 512, height: 1 });
  });
  it("an image with no size is a 1x1 canvas, not NaN", () => {
    expect(fitWithin(0, 0)).toEqual({ width: 1, height: 1 });
    expect(fitWithin(NaN, 5)).toEqual({ width: 1, height: 1 });
  });
});

describe("dataUriBytes", () => {
  it("counts decoded bytes, padding included", () => {
    expect(dataUriBytes("data:image/png;base64,QUJD")).toBe(3);
    expect(dataUriBytes("data:image/png;base64,QUI=")).toBe(2);
    expect(dataUriBytes("data:image/png;base64,QQ==")).toBe(1);
    expect(dataUriBytes("nonsense")).toBe(0);
  });
});

describe("limits", () => {
  it("match the server's 128 KiB input cap, and SVG is not a pickable type", () => {
    expect(LOGO_MAX_UPLOAD_BYTES).toBe(128 * 1024);
    expect(LOGO_PICK_TYPES.some((t) => t.includes("svg"))).toBe(false);
  });
});
