/**
 * Bar-chart layout for the §5 Reports view. Pure and dependency-free (self-contained inline SVG — no external
 * charting library, so it works under the console's strict CSP), so vitest can pin the math independently of
 * the SVG rendering.
 */

/**
 * One input row of a report chart: a STABLE UNIQUE `key` (used for the React key + the chart's data-testids)
 * kept SEPARATE from the human display `label`, because a display name is not necessarily unique — e.g. two
 * machines can share a hostname, so `machine_name` collides while `machine_id` does not. The table keys on the
 * unique id for the same reason; the chart must too, or same-named rows would duplicate React keys/testids.
 */
export interface ChartRow {
  key: string;
  label: string;
  value: number;
}

/** One horizontal bar of a report chart (a ChartRow plus its computed length). */
export interface ChartBar extends ChartRow {
  /** Bar length as a PERCENT (0..100) of the LARGEST value in the set — the biggest bar fills the track. */
  widthPct: number;
}

/**
 * Compute horizontal-bar lengths for a report chart: each bar's length is its value as a PERCENT of the
 * LARGEST value, so the biggest bar fills the track and the rest scale proportionally. An empty input yields
 * `[]`; if the largest value is <= 0 (an all-zero report), EVERY bar is 0% — no divide-by-zero, no NaN. A
 * negative value clamps to 0%. The row ORDER and each row's `key` are preserved (the server already sorted).
 */
export function barChart(rows: readonly ChartRow[]): ChartBar[] {
  const max = rows.reduce((m, r) => Math.max(m, r.value), 0);
  return rows.map((r) => ({
    key: r.key,
    label: r.label,
    value: r.value,
    widthPct: max > 0 ? (Math.max(0, r.value) / max) * 100 : 0,
  }));
}
