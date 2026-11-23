/**
 * The accent colour's contrast gate, as the control plane applies it (docs/66 2.2, 2.7; control-plane/brandtext.go
 * `NormalizeBrandAccent`). The Owner editor shows the readout while the colour is being chosen; the SERVER still decides.
 *
 * The constants and the formula are pinned to the server's by `control-plane/testdata/brand_contrast_vectors.json`, which
 * `brandtext_golden_test.go` and `brand_contrast.test.ts` both read: change one side and the other's test fails.
 */

/** White label text sits on the accent fill (the join page's primary button): WCAG AA normal text. */
export const CONTRAST_LABEL_BACKGROUND = "#ffffff";
export const CONTRAST_LABEL_MIN = 4.5;
/** The accent must also stand out from the page surface (--dr-paper): WCAG non-text UI. */
export const CONTRAST_SURFACE = "#f3f0e8";
export const CONTRAST_SURFACE_MIN = 3.0;

/** `#rrggbb`, either case: the shape the server accepts before it lowercases. */
export function parseHex6(s: string): [number, number, number] | null {
  if (!/^#[0-9a-fA-F]{6}$/.test(s)) return null;
  return [parseInt(s.slice(1, 3), 16), parseInt(s.slice(3, 5), 16), parseInt(s.slice(5, 7), 16)];
}

function srgbChannel(v: number): number {
  const c = v / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

function relativeLuminance(hex: string): number | null {
  const rgb = parseHex6(hex);
  if (rgb === null) return null;
  return 0.2126 * srgbChannel(rgb[0]) + 0.7152 * srgbChannel(rgb[1]) + 0.0722 * srgbChannel(rgb[2]);
}

/** WCAG 2.x contrast ratio (1 to 21) of two `#rrggbb` colours, or null when either is not one. */
export function contrastRatio(a: string, b: string): number | null {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  if (la === null || lb === null) return null;
  const hi = Math.max(la, lb);
  const lo = Math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}

/** The server rounds DOWN to two decimals in its refusal, so a 4.499 is never shown as "4.50:1, needs 4.5:1". */
export function floor2(f: number): string {
  return (Math.floor(f * 100) / 100).toFixed(2);
}

export interface AccentContrast {
  /** Ratio against the white label text, or null when the colour is not `#rrggbb`. */
  labelRatio: number | null;
  /** Ratio against the page surface. */
  surfaceRatio: number | null;
  /** The server's own refusal text when it would refuse, else null. */
  failure: string | null;
}

/** The measured ratios and, for a failing colour, the same sentence the server answers with. */
export function checkAccentContrast(accent: string): AccentContrast {
  const labelRatio = contrastRatio(accent, CONTRAST_LABEL_BACKGROUND);
  const surfaceRatio = contrastRatio(accent, CONTRAST_SURFACE);
  if (labelRatio === null || surfaceRatio === null) return { labelRatio, surfaceRatio, failure: null };
  const checks: [number, number, string][] = [
    [labelRatio, CONTRAST_LABEL_MIN, "white button label"],
    [surfaceRatio, CONTRAST_SURFACE_MIN, "page surface"],
  ];
  for (const [ratio, min, what] of checks) {
    if (ratio < min) return { labelRatio, surfaceRatio, failure: `contrast ${floor2(ratio)}:1 against the ${what}, needs ${min.toFixed(1)}:1` };
  }
  return { labelRatio, surfaceRatio, failure: null };
}
