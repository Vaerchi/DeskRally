import { describe, expect, it } from "vitest";
import {
  CONTRAST_LABEL_BACKGROUND,
  CONTRAST_LABEL_MIN,
  CONTRAST_SURFACE,
  CONTRAST_SURFACE_MIN,
  checkAccentContrast,
  contrastRatio,
  floor2,
} from "./brand_contrast";
import { normalizeBrandAccent } from "./brand_text";
import vectors from "../../../../control-plane/testdata/brand_contrast_vectors.json";

// The SAME file control-plane/brandtext_golden_test.go reads: the two implementations cannot drift apart.
describe("shared golden vectors (control-plane/testdata/brand_contrast_vectors.json)", () => {
  it("the file is not empty", () => {
    expect(vectors.ratios.length).toBeGreaterThanOrEqual(10);
    expect(vectors.accents.length).toBeGreaterThanOrEqual(15);
  });

  it("uses the server's constants", () => {
    expect(vectors.constants.label_background).toBe(CONTRAST_LABEL_BACKGROUND);
    expect(vectors.constants.surface).toBe(CONTRAST_SURFACE);
    expect(vectors.constants.label_min).toBe(CONTRAST_LABEL_MIN);
    expect(vectors.constants.surface_min).toBe(CONTRAST_SURFACE_MIN);
  });

  it.each(vectors.ratios)("ratio $a against $b is $ratio", ({ a, b, ratio }) => {
    const got = contrastRatio(a, b);
    expect(got).not.toBeNull();
    expect(Math.abs(got! - ratio)).toBeLessThan(0.00005);
    expect(contrastRatio(b, a)).toBe(got);
  });

  it.each(vectors.accents)("accent %j is judged as the server judges it", (c) => {
    const got = normalizeBrandAccent(c.input);
    if (c.ok) expect(got).toEqual({ ok: true, value: c.normalized });
    else expect(got).toEqual({ ok: false, error: c.error });
  });
});

describe("contrast helpers", () => {
  it("is null for a value that is not #rrggbb", () => {
    expect(contrastRatio("red", "#ffffff")).toBeNull();
    expect(contrastRatio("#fff", "#ffffff")).toBeNull();
    expect(checkAccentContrast("#fff").failure).toBeNull();
    expect(checkAccentContrast("#fff").labelRatio).toBeNull();
  });
  it("floors to two decimals like the server, never rounds up across the threshold", () => {
    expect(floor2(4.4999)).toBe("4.49");
    expect(floor2(4.5)).toBe("4.50");
    expect(floor2(21)).toBe("21.00");
  });
  it("accepts case-insensitively and reports both ratios for a passing colour", () => {
    const c = checkAccentContrast("#35654A");
    expect(c.failure).toBeNull();
    expect(c.labelRatio!).toBeGreaterThan(6.7);
    expect(c.surfaceRatio!).toBeGreaterThan(5.9);
  });
  it("names the white label first when the colour is too light", () => {
    expect(checkAccentContrast("#3b82f6").failure).toBe("contrast 3.67:1 against the white button label, needs 4.5:1");
  });
});
