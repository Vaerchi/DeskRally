/**
 * Backstage event-log panel: a read-only table of Windows Event Log records, rendered natively in
 * the technician's browser (docs/04-backstage.md Part 1; agent `panels::eventlog` via `EvtQuery`).
 *
 * Presentational only: rows come in as props from a typed source. Every headline field can be null
 * (the agent extracts what the event XML has), so all render "—" when absent. A colored level badge
 * mirrors the service-state badge convention.
 */

import {
  eventLevelTone,
  formatIsoUtc,
  formatOptional,
  type EventLogRow,
} from "../backstage/panels";

export interface EventLogPanelProps {
  rows: readonly EventLogRow[];
}

export function EventLogPanel({ rows }: EventLogPanelProps) {
  return (
    <div className="panel panel--eventlog">
      <table className="panel__table">
        <thead>
          <tr>
            <th>Level</th>
            <th>Time (UTC)</th>
            <th className="panel__col--num">Event ID</th>
            <th>Provider</th>
            <th className="panel__col--num">Record</th>
            <th>Channel</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={6}>
                No events.
              </td>
            </tr>
          )}
          {rows.map((e, i) => (
            <tr key={e.record_id ?? `idx-${i}`}>
              <td>
                <span className="panel__badge" data-tone={eventLevelTone(e.level)}>
                  {e.level ?? "—"}
                </span>
              </td>
              <td className="panel__mono">{formatIsoUtc(e.time_created)}</td>
              <td className="panel__col--num">{e.event_id ?? "—"}</td>
              <td>{formatOptional(e.provider)}</td>
              <td className="panel__col--num">{e.record_id ?? "—"}</td>
              <td>{e.channel}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
