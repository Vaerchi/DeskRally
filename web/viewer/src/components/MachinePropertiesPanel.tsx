/**
 * Per-machine custom properties (docs/01 §4): list + add + remove key/value fields over
 * GET/PUT/DELETE /machines/{id}/properties. Thin like the other console panels — the flows live in
 * `lib/console_panels.ts` (validate, upsert-and-refresh, delete-and-refresh); this owns only
 * load/refresh/in-flight state and rendering.
 *
 * `machineId` is the machine PRIMARY KEY (`MachineRecord.id`), the same identity the routes address —
 * never the device id. The panel re-keys its load on `machineId`, so selecting a different machine
 * reloads its own properties (and the mount site remounts via `key={machineId}` as belt-and-braces).
 */

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import type { ConsoleApi, MachineProperty } from "../lib/console_api";
import { createLatestWins, type LatestWins } from "../lib/latest_wins";
import {
  deletePropertyAndRefresh,
  setPropertyAndRefresh,
  sortPropertiesByKey,
  validatePropertyForm,
} from "../lib/console_panels";

export interface MachinePropertiesPanelProps {
  api: ConsoleApi;
  /** Machine PRIMARY KEY (`MachineRecord.id`), not the device id. */
  machineId: string;
  machineName?: string;
}

export function MachinePropertiesPanel({ api, machineId, machineName }: MachinePropertiesPanelProps) {
  const [rows, setRows] = useState<readonly MachineProperty[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  // Latest-wins: refresh, add and remove all re-list this machine's properties, so they share one
  // token source. Only the newest outcome may touch rows/error/busy; a superseded listing (an older
  // refresh, or a response for a previously selected machine) is dropped, success or failure alike.
  const latest = useRef<LatestWins>(createLatestWins());

  const refresh = useCallback(async () => {
    const token = latest.current.begin();
    setBusy(true);
    setError(null);
    try {
      const list = sortPropertiesByKey(await api.listMachineProperties(machineId));
      if (latest.current.isCurrent(token)) setRows(list);
    } catch (e) {
      if (latest.current.isCurrent(token)) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (latest.current.isCurrent(token)) setBusy(false);
    }
  }, [api, machineId]);

  useEffect(() => {
    const lw = latest.current;
    void refresh();
    // machineId change / unmount: every outstanding token goes stale, so nothing from the old
    // machine lands after this point (this also covers StrictMode's replayed mount).
    return () => lw.invalidate();
  }, [refresh]);

  const handleAdd = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const v = validatePropertyForm({ key, value });
      if (!v.ok) {
        setError(v.message);
        return;
      }
      const token = latest.current.begin();
      setSaving(true);
      setError(null);
      try {
        const list = await setPropertyAndRefresh(api, machineId, v.key, v.value);
        if (latest.current.isCurrent(token)) {
          setRows(list);
          setKey("");
          setValue("");
        }
      } catch (err) {
        if (latest.current.isCurrent(token)) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (latest.current.isCurrent(token)) {
          setSaving(false);
          setBusy(false); // this write's re-list superseded any in-flight refresh
        }
      }
    },
    [api, machineId, key, value],
  );

  const handleRemove = useCallback(
    async (k: string) => {
      const token = latest.current.begin();
      setRemoving(k);
      setError(null);
      try {
        const list = await deletePropertyAndRefresh(api, machineId, k);
        if (latest.current.isCurrent(token)) setRows(list);
      } catch (err) {
        if (latest.current.isCurrent(token)) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (latest.current.isCurrent(token)) {
          setRemoving(null);
          setBusy(false);
        }
      }
    },
    [api, machineId],
  );

  return (
    <section className="panel panel--properties" data-testid="machine-properties">
      <form className="panel__form" onSubmit={(e) => void handleAdd(e)}>
        <span className="panel__toolbar-title">
          Properties{machineName ? ` — ${machineName}` : ""}
        </span>
        <label className="panel__toolbar-field">
          Key
          <input
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="site"
            data-testid="property-key"
          />
        </label>
        <label className="panel__toolbar-field">
          Value
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="HQ"
            data-testid="property-value"
          />
        </label>
        <button className="panel__action" type="submit" disabled={saving || removing !== null} data-testid="property-add">
          {saving ? "Saving…" : "Add"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="properties-error">
            {error}
          </span>
        )}
      </form>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Key</th>
            <th>Value</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={3} data-testid="properties-empty">
                {busy ? "Loading…" : "No properties set."}
              </td>
            </tr>
          )}
          {rows.map((p) => (
            <tr key={p.key} data-testid={`property-row-${p.key}`}>
              <td className="panel__name">{p.key}</td>
              <td className="panel__mono">{p.value || "—"}</td>
              <td className="panel__col--action">
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleRemove(p.key)}
                  disabled={removing !== null || saving}
                  data-testid={`property-remove-${p.key}`}
                >
                  {removing === p.key ? "Removing…" : "Remove"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
