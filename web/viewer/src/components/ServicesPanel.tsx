/**
 * Backstage services panel: a read-only table of the remote machine's services, running-first,
 * with a colored state badge and the host PID (or "—" when not running). Rendered natively in the
 * technician's browser (docs/04-backstage.md Part 1).
 *
 * Presentational only: rows come in as props from a typed source. With `onControl` each row starts with its
 * Start / Stop / Restart buttons (confirmed by the container: type the machine name).
 */

import { useMemo } from "react";
import {
  serviceStartTypeLabel,
  serviceStateLabel,
  serviceStateTone,
  sortServices,
  type ServiceRow,
} from "../backstage/panels";
import type { ServiceVerb, SettableStartType } from "../backstage/client";

const SETTABLE: { value: SettableStartType; label: string }[] = [
  { value: "auto", label: "Automatic" },
  { value: "auto_delayed", label: "Automatic (delayed start)" },
  { value: "manual", label: "Manual" },
  { value: "disabled", label: "Disabled" },
];

export interface ServicesPanelProps {
  rows: readonly ServiceRow[];
  /**
   * When provided, start/stop/restart controls are shown per row (a mutating Tier-2 tool). The
   * container wires this to the confirm-gated `BackstageClient.controlService`. Omit for a
   * read-only table.
   */
  onControl?: (row: ServiceRow, verb: ServiceVerb) => void;
  /** 1.3.38: when provided (the agent advertised `service_start_type_v1`), Startup type is a choice per row. */
  onSetStartType?: (row: ServiceRow, to: SettableStartType) => void;
}

export function ServicesPanel({ rows, onControl, onSetStartType }: ServicesPanelProps) {
  const sorted = useMemo(() => sortServices(rows), [rows]);

  return (
    <div className="panel panel--services">
      <table className="panel__table">
        <thead>
          <tr>
            {onControl && <th className="panel__col--action">Action</th>}
            <th>State</th>
            <th>Display name</th>
            <th>Service</th>
            <th>Startup type</th>
            <th className="panel__col--num">PID</th>
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={onControl ? 6 : 5}>
                No services.
              </td>
            </tr>
          )}
          {sorted.map((s) => (
            <tr key={s.name}>
              {onControl && (
                <td className="panel__col--action">
                  {s.state === "running" ? (
                    <>
                      <button className="panel__action" onClick={() => onControl(s, "restart")}>
                        Restart
                      </button>
                      <button className="panel__action" onClick={() => onControl(s, "stop")}>
                        Stop
                      </button>
                    </>
                  ) : (
                    <button className="panel__action" onClick={() => onControl(s, "start")}>
                      Start
                    </button>
                  )}
                </td>
              )}
              <td>
                <span className="panel__badge" data-tone={serviceStateTone(s.state)}>
                  {serviceStateLabel(s.state)}
                </span>
              </td>
              <td className="panel__name">{s.display_name}</td>
              <td className="panel__mono">{s.name}</td>
              <td>
                {onSetStartType && s.start_type && SETTABLE.some((o) => o.value === s.start_type) ? (
                  <select
                    aria-label={`Startup type of ${s.display_name}`}
                    data-testid={`svc-start-type-${s.name}`}
                    value={s.start_type}
                    onChange={(e) => onSetStartType(s, e.target.value as SettableStartType)}
                  >
                    {SETTABLE.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                ) : (
                  serviceStartTypeLabel(s.start_type)
                )}
              </td>
              <td className="panel__col--num">{s.pid ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
