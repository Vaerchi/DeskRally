/**
 * Backstage services panel: a read-only table of the remote machine's services, running-first,
 * with a colored state badge and the host PID (or "—" when not running). Rendered natively in the
 * technician's browser (docs/04-backstage.md Part 1).
 *
 * Presentational only: rows come in as props from a typed source. Service control (start/stop/
 * restart) is a mutating Tier-2 tool that lands later behind RBAC, so there is no action here.
 */

import { useMemo } from "react";
import {
  serviceStateLabel,
  serviceStateTone,
  sortServices,
  type ServiceRow,
} from "../backstage/panels";
import type { ServiceVerb } from "../backstage/client";

export interface ServicesPanelProps {
  rows: readonly ServiceRow[];
  /**
   * When provided, start/stop/restart controls are shown per row (a mutating Tier-2 tool). The
   * container wires this to the confirm-gated `BackstageClient.controlService`. Omit for a
   * read-only table.
   */
  onControl?: (row: ServiceRow, verb: ServiceVerb) => void;
}

export function ServicesPanel({ rows, onControl }: ServicesPanelProps) {
  const sorted = useMemo(() => sortServices(rows), [rows]);

  return (
    <div className="panel panel--services">
      <table className="panel__table">
        <thead>
          <tr>
            <th>State</th>
            <th>Display name</th>
            <th>Service</th>
            <th className="panel__col--num">PID</th>
            {onControl && <th className="panel__col--action">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={onControl ? 5 : 4}>
                No services.
              </td>
            </tr>
          )}
          {sorted.map((s) => (
            <tr key={s.name}>
              <td>
                <span className="panel__badge" data-tone={serviceStateTone(s.state)}>
                  {serviceStateLabel(s.state)}
                </span>
              </td>
              <td className="panel__name">{s.display_name}</td>
              <td className="panel__mono">{s.name}</td>
              <td className="panel__col--num">{s.pid ?? "—"}</td>
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
