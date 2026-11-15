/**
 * A self-contained inline-SVG horizontal bar chart for the §5 Reports view (docs/01 §5). No external charting
 * library — just SVG the browser draws — so it works under the console's strict CSP. The layout math lives in
 * the pure `barChart` (report_chart.ts, unit-tested); this component only draws it. Bars use the tenant accent
 * (`--accent`, the loop-46 branding variable).
 */

import type { ChartBar } from "../lib/report_chart";

export interface ReportBarChartProps {
  bars: readonly ChartBar[];
}

const ROW_H = 22;
const GAP = 8;
const LABEL_W = 170;
const TRACK_W = 280;
const VALUE_W = 52;

export function ReportBarChart({ bars }: ReportBarChartProps) {
  if (bars.length === 0) return null;
  const width = LABEL_W + TRACK_W + VALUE_W;
  const height = bars.length * (ROW_H + GAP);
  return (
    <svg
      className="report-chart"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Report bar chart"
      data-testid="report-chart"
      style={{ maxWidth: "100%" }}
    >
      {bars.map((b, i) => {
        const y = i * (ROW_H + GAP);
        const barW = (b.widthPct / 100) * TRACK_W;
        const baseline = y + ROW_H * 0.72;
        return (
          <g key={b.key} data-testid={`chart-bar-${b.key}`}>
            <text x={0} y={baseline} style={{ fontSize: 12, fill: "currentColor" }}>
              {b.label}
            </text>
            {/* The full track (faint) makes an empty/short bar legible; the value bar overlays it. */}
            <rect x={LABEL_W} y={y} width={TRACK_W} height={ROW_H} rx={2} style={{ fill: "currentColor", opacity: 0.08 }} />
            <rect
              x={LABEL_W}
              y={y}
              width={barW}
              height={ROW_H}
              rx={2}
              style={{ fill: "var(--accent, #3b82f6)" }}
              data-testid={`chart-rect-${b.key}`}
            />
            <text x={LABEL_W + TRACK_W + 6} y={baseline} style={{ fontSize: 12, fill: "currentColor" }}>
              {b.value}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
