/**
 * Backstage process panel: a sortable, read-only table of the remote machine's processes,
 * rendered natively in the technician's browser (docs/04-backstage.md Part 1 — headless panels).
 *
 * Presentational only: it takes rows as props from a typed source and owns nothing but the local
 * sort selection. It does not fetch, and it intentionally has no kill/action affordance — the
 * mutating tools land later behind RBAC. Byte sizes are humanized and every null field renders
 * as "—".
 */

import { useMemo, useState } from "react";
import {
  formatBytes,
  formatCpuPercent,
  formatOptional,
  sortProcesses,
  type ProcessRow,
  type ProcessSortKey,
  type SortDirection,
} from "../backstage/panels";

export interface ProcessPanelProps {
  rows: readonly ProcessRow[];
  /** Initial sort column (default: CPU). */
  initialSortKey?: ProcessSortKey;
  /** Initial sort direction (default: descending). */
  initialSortDirection?: SortDirection;
  /**
   * When provided, a "Kill" action is shown per row (a mutating Tier-2 tool). The container wires
   * this to the confirm-gated `BackstageClient.killProcess`. Omit for a read-only table.
   */
  onKill?: (row: ProcessRow) => void;
}

const COLUMNS: { key: ProcessSortKey; label: string; numeric: boolean }[] = [
  { key: "name", label: "Name", numeric: false },
  { key: "cpu", label: "CPU", numeric: true },
  { key: "memory", label: "Memory", numeric: true },
];

export function ProcessPanel({
  rows,
  initialSortKey = "cpu",
  initialSortDirection = "desc",
  onKill,
}: ProcessPanelProps) {
  const [sortKey, setSortKey] = useState<ProcessSortKey>(initialSortKey);
  const [direction, setDirection] = useState<SortDirection>(initialSortDirection);

  const sorted = useMemo(() => sortProcesses(rows, sortKey, direction), [rows, sortKey, direction]);

  const toggleSort = (key: ProcessSortKey) => {
    if (key === sortKey) {
      setDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      // Names default A→Z; numeric columns default high→low.
      setDirection(key === "name" ? "asc" : "desc");
    }
  };

  return (
    <div className="panel panel--process">
      <table className="panel__table">
        <thead>
          <tr>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className={col.numeric ? "panel__col--num" : undefined}
                aria-sort={
                  sortKey === col.key ? (direction === "asc" ? "ascending" : "descending") : "none"
                }
              >
                <button className="panel__sort" onClick={() => toggleSort(col.key)}>
                  {col.label}
                  {sortKey === col.key && (
                    <span className="panel__caret">{direction === "asc" ? "▲" : "▼"}</span>
                  )}
                </button>
              </th>
            ))}
            <th className="panel__col--num">PID</th>
            <th>User</th>
            <th>Command line</th>
            {onKill && <th className="panel__col--action">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={onKill ? 7 : 6}>
                No processes.
              </td>
            </tr>
          )}
          {sorted.map((p) => (
            <tr key={p.pid}>
              <td className="panel__name">{p.name}</td>
              <td className="panel__col--num">{formatCpuPercent(p.cpu_percent)}</td>
              <td className="panel__col--num">{formatBytes(p.memory_bytes)}</td>
              <td className="panel__col--num">{p.pid}</td>
              <td>{formatOptional(p.user)}</td>
              <td className="panel__mono panel__ellipsis" title={p.command_line ?? undefined}>
                {formatOptional(p.command_line)}
              </td>
              {onKill && (
                <td className="panel__col--action">
                  <button className="panel__action panel__action--danger" onClick={() => onKill(p)}>
                    Kill
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
