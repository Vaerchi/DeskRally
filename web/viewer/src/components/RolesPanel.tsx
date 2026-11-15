/**
 * Roles reference (docs/01 §5): the assignable preset roles and the capabilities each grants, from
 * `GET /roles` (CapManageRoles). READ-ONLY — it closes the role-assignment loop (the Users tab assigns a role
 * by NAME; this shows what that name permits). Thin like the other console panels: fetching goes through the
 * injected `ConsoleApi`; the component owns only load/error state.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { ConsoleApi, RoleCatalogEntry } from "../lib/console_api";
import { createLatestWins, type LatestWins } from "../lib/latest_wins";
import { capabilityLabel } from "../lib/console_panels";

export interface RolesPanelProps {
  api: ConsoleApi;
}

export function RolesPanel({ api }: RolesPanelProps) {
  const [roles, setRoles] = useState<readonly RoleCatalogEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Latest-wins ordering: a slower OLDER listing (or failure) must never overwrite a newer outcome, and
  // only the newest request clears busy.
  const latest = useRef<LatestWins>(createLatestWins());

  const refresh = useCallback(async () => {
    const token = latest.current.begin();
    setBusy(true);
    setError(null);
    try {
      const list = await api.listRoles();
      if (!latest.current.isCurrent(token)) return;
      setRoles(list);
    } catch (e) {
      if (!latest.current.isCurrent(token)) return;
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (latest.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    const seq = latest.current;
    void refresh();
    return () => seq.invalidate();
  }, [refresh]);

  return (
    <section className="panel panel--roles" data-testid="roles">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Roles &amp; capabilities</span>
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="roles-error">
            {error}
          </span>
        )}
      </div>
      <table className="panel__table">
        <thead>
          <tr>
            <th>Role</th>
            <th>Capabilities</th>
          </tr>
        </thead>
        <tbody>
          {roles.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={2} data-testid="roles-empty">
                {busy ? "Loading…" : "No roles."}
              </td>
            </tr>
          )}
          {roles.map((r) => (
            <tr key={r.role} data-testid={`role-row-${r.role}`}>
              <td className="panel__name">{r.role}</td>
              <td data-testid={`role-caps-${r.role}`}>
                {r.capabilities.length === 0
                  ? "—"
                  : r.capabilities.map((c) => (
                      <span key={c} className="panel__chip">
                        {capabilityLabel(c)}
                      </span>
                    ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
