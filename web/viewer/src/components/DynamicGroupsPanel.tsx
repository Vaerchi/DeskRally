import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { createLatestWins } from "../lib/latest_wins";
import type { ConsoleApi, DynamicGroup, DynamicGroupMatch, DynamicGroupOperator, MachineRecord } from "../lib/console_api";
import {
  conditionTakesValue, dynamicGroupFields, dynamicGroupOperatorLabels, dynamicGroupOperators,
  MAX_DYNAMIC_GROUP_CONDITIONS, summarizeDynamicGroup, validateDynamicGroup, type DynamicGroupField,
} from "../lib/dynamic_groups";

interface ConditionRow {
  id: number;
  field: DynamicGroupField;
  key: string;
  op: DynamicGroupOperator;
  value: string;
}

function newConditionRow(id: number): ConditionRow {
  return { id, field: "property", key: "", op: "equals", value: "" };
}

export interface DynamicGroupsPanelProps {
  api: ConsoleApi;
}

export function DynamicGroupsPanel({ api }: DynamicGroupsPanelProps) {
  const [groups, setGroups] = useState<readonly DynamicGroup[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [match, setMatch] = useState<DynamicGroupMatch>("all");
  const [rows, setRows] = useState(() => [newConditionRow(0)]);
  const nextRowId = useRef(1);
  function updateRow(id: number, patch: Partial<Omit<ConditionRow, "id">>) {
    setRows((current) => current.map((row) => row.id === id ? { ...row, ...patch } : row));
  }
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  // The currently-resolved group's members (id of the group + the machine rows), or null when none open.
  const [resolved, setResolved] = useState<{ groupId: string; machines: MachineRecord[] } | null>(null);

  // Latest-wins guards, one per section: only the newest group listing may touch the list/error/busy, and
  // only the newest resolve (not invalidated by a delete of its group) may touch the members card.
  const listGuard = useRef(createLatestWins());
  const resolveGuard = useRef(createLatestWins());
  // The group whose resolve is currently the newest in flight (null when none), so a delete can supersede it.
  const resolvingRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  useEffect(() => {
    const list = listGuard.current;
    const resolve = resolveGuard.current;
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      list.invalidate();
      resolve.invalidate();
    };
  }, []);

  const refresh = useCallback(async () => {
    if (!mountedRef.current) return;
    const token = listGuard.current.begin();
    setBusy(true);
    setError(null);
    try {
      const list = await api.listDynamicGroups();
      if (!listGuard.current.isCurrent(token)) return; // superseded: a newer listing owns the state
      setGroups(list);
    } catch (e) {
      if (!listGuard.current.isCurrent(token)) return; // a superseded failure must not show
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      // Only the newest listing clears busy (an older one finishing must not hide a newer load).
      if (listGuard.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleAdd = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const n = name.trim();
      const conditions = rows.map(({ field, key, op, value }) => ({
        field: field === "property" ? `property:${key.trim()}` : field, op, value,
      }));
      const validationError = validateDynamicGroup(n, match, conditions);
      if (validationError) {
        setError(validationError);
        return;
      }
      setSaving(true);
      setError(null);
      try {
        await api.createDynamicGroup({ name: n, match, conditions });
        setName("");
        setMatch("all");
        setRows([newConditionRow(nextRowId.current++)]);
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [api, name, match, rows, refresh],
  );

  const handleRemove = useCallback(
    async (g: DynamicGroup) => {
      setRemoving(g.id);
      setError(null);
      try {
        await api.deleteDynamicGroup(g.id);
        // The group is gone: a resolve of it still in flight must never reopen its members.
        if (resolvingRef.current === g.id) {
          resolveGuard.current.invalidate();
          resolvingRef.current = null;
        }
        setResolved((prev) => (prev?.groupId === g.id ? null : prev));
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setRemoving(null);
      }
    },
    [api, refresh],
  );

  const handleResolve = useCallback(
    async (g: DynamicGroup) => {
      const token = resolveGuard.current.begin(); // supersedes any earlier resolve
      resolvingRef.current = g.id;
      setError(null);
      try {
        const machines = await api.resolveDynamicGroup(g.id);
        if (!resolveGuard.current.isCurrent(token)) return; // superseded or group removed: drop it
        setResolved({ groupId: g.id, machines });
      } catch (err) {
        if (!resolveGuard.current.isCurrent(token)) return; // a superseded failure must not show
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (resolveGuard.current.isCurrent(token)) resolvingRef.current = null;
      }
    },
    [api],
  );

  return (
    <section className="panel panel--groups" data-testid="dynamic-groups">
      <form className="panel__form" onSubmit={(e) => void handleAdd(e)}>
        <span className="panel__toolbar-title">Smart groups</span>
        <label className="panel__toolbar-field">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="HQ machines" data-testid="group-name" />
        </label>
        <label className="panel__toolbar-field">
          Match
          <select value={match} onChange={(e) => setMatch(e.target.value as DynamicGroupMatch)} data-testid="group-match">
            <option value="all">Match all</option>
            <option value="any">Match any</option>
          </select>
        </label>
        <fieldset className="dynamic-groups__conditions" disabled={saving}>
          <legend>Conditions</legend>
          {rows.map(({ id, field, key, op, value }, index) => (
            <div key={id} className="dynamic-groups__condition" data-testid="group-condition">
              <label className="panel__toolbar-field">
                Field
                <select value={field} onChange={(e) => {
                  const next = e.target.value as DynamicGroupField;
                  updateRow(id, { field: next, key: "", op: "equals", value: next === "online" ? "true" : "" });
                }} data-testid="group-field">
                  {Object.entries(dynamicGroupFields).map(([fieldValue, label]) => (
                    <option key={fieldValue} value={fieldValue}>{label}</option>
                  ))}
                </select>
              </label>
              {field === "property" && (
                <label className="panel__toolbar-field">
                  Property key
                  <input value={key} onChange={(e) => updateRow(id, { key: e.target.value })} placeholder="site" data-testid="group-key" />
                </label>
              )}
              <label className="panel__toolbar-field">
                Operator
                <select value={op} onChange={(e) => {
                  const next = e.target.value as DynamicGroupOperator;
                  updateRow(id, { op: next, value: conditionTakesValue(next) ? value : "" });
                }} data-testid="group-op">
                  {dynamicGroupOperators[field].map((operator) => (
                    <option key={operator} value={operator}>{dynamicGroupOperatorLabels[operator]}</option>
                  ))}
                </select>
              </label>
              {conditionTakesValue(op) && (
                <label className="panel__toolbar-field">
                  Value
                  {field === "online" ? (
                    <select value={value} onChange={(e) => updateRow(id, { value: e.target.value })} data-testid="group-value">
                      <option value="true">True</option>
                      <option value="false">False</option>
                    </select>
                  ) : (
                    <input value={value} onChange={(e) => updateRow(id, { value: e.target.value })} data-testid="group-value" />
                  )}
                </label>
              )}
              <button className="panel__action" type="button" aria-label={`Remove condition ${index + 1}`}
                disabled={rows.length === 1} onClick={() => setRows((current) => current.filter((row) => row.id !== id))}>
                Remove
              </button>
            </div>
          ))}
          <button className="panel__action" type="button" disabled={rows.length >= MAX_DYNAMIC_GROUP_CONDITIONS}
            onClick={() => {
              const row = newConditionRow(nextRowId.current++);
              setRows((current) => [...current, row]);
            }} data-testid="group-add-condition">
            Add condition
          </button>
        </fieldset>
        <button className="panel__action" type="submit" disabled={saving} data-testid="group-add">
          {saving ? "Saving…" : "Add"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="group-error">
            {error}
          </span>
        )}
      </form>
      <p className="panel__note" data-testid="dynamic-groups-help">
        A smart group finds machines you can access that currently meet its conditions.
      </p>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Predicate</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {groups.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={3} data-testid="groups-empty">
                {busy ? "Loading…" : "No dynamic groups yet."}
              </td>
            </tr>
          )}
          {groups.map((g) => (
            <tr key={g.id} data-testid={`group-row-${g.name}`}>
              <td className="panel__name">{g.name}</td>
              <td className="panel__mono">{summarizeDynamicGroup(g)}</td>
              <td className="panel__col--action">
                <button
                  className="panel__action"
                  onClick={() => void handleResolve(g)}
                  data-testid={`group-resolve-${g.name}`}
                >
                  Members
                </button>
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleRemove(g)}
                  disabled={removing !== null}
                  data-testid={`group-delete-${g.name}`}
                >
                  {removing === g.id ? "Removing…" : "Delete"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {resolved && (
        <div className="panel__members" data-testid="group-members">
          <span className="panel__toolbar-title">Members ({resolved.machines.length})</span>
          {resolved.machines.length === 0 ? (
            <span className="panel__empty" data-testid="group-members-empty">
              No machines match this group.
            </span>
          ) : (
            <ul>
              {resolved.machines.map((m) => (
                <li key={m.id} data-testid={`group-member-${m.id}`}>
                  {m.alias || m.name || m.device_id}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
