/** Unit tests for the §5 Reports bar-chart layout — normalization to the largest value, key threading, edges. */
import { describe, it, expect } from "vitest";
import { barChart } from "./report_chart";

describe("barChart", () => {
  it("returns [] for no rows", () => {
    expect(barChart([])).toEqual([]);
  });

  it("scales each bar as a PERCENT of the largest value (largest = 100%), preserving order + value + key", () => {
    expect(
      barChart([
        { key: "a", label: "A", value: 10 },
        { key: "b", label: "B", value: 5 },
        { key: "c", label: "C", value: 0 },
      ]),
    ).toEqual([
      { key: "a", label: "A", value: 10, widthPct: 100 },
      { key: "b", label: "B", value: 5, widthPct: 50 },
      { key: "c", label: "C", value: 0, widthPct: 0 },
    ]);
  });

  it("keeps DISTINCT keys for rows that share a display label (so the render can't collide)", () => {
    const bars = barChart([
      { key: "m-1", label: "HOST", value: 3 },
      { key: "m-2", label: "HOST", value: 3 },
    ]);
    expect(bars.map((b) => b.key)).toEqual(["m-1", "m-2"]);
    expect(bars.every((b) => b.label === "HOST")).toBe(true);
  });

  it("makes ALL bars 0% when the largest value is 0 (no divide-by-zero / NaN)", () => {
    expect(barChart([{ key: "x", label: "x", value: 0 }, { key: "y", label: "y", value: 0 }])).toEqual([
      { key: "x", label: "x", value: 0, widthPct: 0 },
      { key: "y", label: "y", value: 0, widthPct: 0 },
    ]);
  });

  it("clamps a negative value to 0% (still counting the positive max)", () => {
    expect(barChart([{ key: "p", label: "p", value: 4 }, { key: "n", label: "n", value: -3 }])).toEqual([
      { key: "p", label: "p", value: 4, widthPct: 100 },
      { key: "n", label: "n", value: -3, widthPct: 0 },
    ]);
  });

  it("a single row fills the track (100%)", () => {
    expect(barChart([{ key: "only", label: "only", value: 7 }])).toEqual([
      { key: "only", label: "only", value: 7, widthPct: 100 },
    ]);
  });
});
