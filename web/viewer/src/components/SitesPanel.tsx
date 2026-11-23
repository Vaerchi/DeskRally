/**
 * Sites (docs/01 §4): every visible machine grouped by its `site` property, with per-machine set /
 * change / remove. Built entirely on the existing machine + machine-property routes — a site is the
 * same `site=<value>` property the Machines tab's properties editor shows, nothing new on the wire.
 *
 * Sites are organisation only: they never grant or restrict access (that is Machine groups).
 * Thin like the other console panels — the flows and honesty rules live in `lib/sites.ts`; this owns
 * load/refresh/in-flight state and rendering. `SiteSync` supplies the ordering guards: only the latest
 * load publishes, and a confirmed save/remove is never reverted by a refresh that started before it.
 */

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ConsoleApi } from "../lib/console_api";
import { sitesToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";
import {
  SITE_LIMIT_HINT,
  SiteSync,
  clearMachineSite,
  SITE_STATE_FILTERS,
  applySiteFilters,
  groupBySite,
  parseSiteStateFilter,
  loadMachineSites,
  saveMachineSite,
  siteNames,
  validateSite,
  type SiteRow,
  type SiteState,
  type SiteStateFilter,
} from "../lib/sites";
import {
  BULK_CAP_HINT,
  BULK_SELECTION_CAP,
  apiContextKey,
  planBulkAssign,
  pruneSelection,
  runBulkAssign,
  selectVisible,
  selectionAfterBatch,
  summarizeBulk,
  toggleSelected,
  type BulkOutcome,
  type BulkTarget,
} from "../lib/sites_bulk";

interface BulkPending {
  value: string;
  targets: readonly BulkTarget[];
}

interface BulkResult {
  value: string;
  outcomes: readonly BulkOutcome[];
}

export interface SitesPanelProps {
  api: ConsoleApi;
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function siteLabel(site: SiteState): string {
  if (site.kind === "set") return site.value === "" ? "(empty)" : site.value;
  if (site.kind === "none") return "No site";
  return "Unknown";
}

/**
 * Every piece of state below (rows, drafts, SiteSync, selection, in-flight sets) belongs to ONE api
 * context. Keying the body by api identity makes a replaced api a full unmount + fresh mount: nothing the
 * old context loaded can be selected or submitted through the new one, and a new context whose load
 * fails shows no machines at all.
 */
export function SitesPanel({ api }: SitesPanelProps) {
  return <SitesPanelBody key={apiContextKey(api)} api={api} />;
}

function SitesPanelBody({ api }: SitesPanelProps) {
  const [rows, setRows] = useState<readonly SiteRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(true); // the mount effect starts the first load immediately
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [rowBusy, setRowBusy] = useState<Record<string, boolean>>({});
  const [rowError, setRowError] = useState<Record<string, string>>({});

  const sync = useRef(new SiteSync());

  // Bulk assignment. `batchActive` is the SYNCHRONOUS guard (state lags a render); `life.live` goes false
  // synchronously on unmount and on every api change (the body is re-keyed), so a batch started under an
  // old context stops and publishes nothing.
  const [selectedRaw, setSelectedRaw] = useState<ReadonlySet<string>>(new Set());
  const [bulkSite, setBulkSite] = useState("");
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bulkCapped, setBulkCapped] = useState(false);
  const [pending, setPending] = useState<BulkPending | null>(null);
  const [bulkRunning, setBulkRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [bulkResult, setBulkResult] = useState<BulkResult | null>(null);
  const batchActive = useRef(false);
  // `lock` is true from "review opened" until the batch ends or is cancelled (synchronous twin of `locked`).
  const lock = useRef(false);
  // The ONE live confirmation. Set when review opens; cleared synchronously by cancel, confirm, teardown and
  // a stale-view refusal. Confirm reads this (never the render-captured `pending`), so a Cancel followed by a
  // Confirm before React re-renders sends nothing.
  const confirmToken = useRef<BulkPending | null>(null);
  // Synchronous per-row in-flight set: a second submit/click before React re-renders the disabled
  // controls is dropped, so one row never has two writes racing.
  const inFlight = useRef(new Set<string>());
  const refreshing = useRef(0);
  const locked = pending !== null || bulkRunning;
  const rowWriting = Object.values(rowBusy).some(Boolean);

  // This mount's liveness. The layout-effect cleanup runs synchronously when the component unmounts or
  // its api (the key) changes, so a late response from this context is dropped before it can publish.
  const life = useRef({ live: true });
  useLayoutEffect(() => {
    const mine = life.current;
    mine.live = true;
    return () => {
      mine.live = false;
      batchActive.current = false;
      lock.current = false;
      confirmToken.current = null;
    };
  }, []);
  const alive = () => life.current.live;

  const refresh = useCallback(async () => {
    if (batchActive.current || lock.current) return; // a pending/running batch owns the rows
    const ticket = sync.current.beginLoad();
    refreshing.current += 1;
    setBusy(true);
    setError(null);
    try {
      const result = await loadMachineSites(api);
      if (!life.current.live) return;
      const merged = sync.current.finishLoad(ticket, result.rows);
      if (merged === null) return; // a newer load owns the view
      setRows(merged);
      setNotice(
        result.filterError
          ? `Site filter unavailable (${result.filterError}); each machine was checked individually.`
          : null,
      );
      setLoaded(true);
    } catch (e) {
      if (!life.current.live || !sync.current.isCurrent(ticket)) return;
      setError(errorText(e));
    } finally {
      refreshing.current -= 1;
      if (life.current.live && sync.current.isCurrent(ticket)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const applyConfirmed = useCallback((machineId: string, site: SiteState) => {
    sync.current.confirm(machineId, site);
    setRows((prev) => prev.map((r) => (r.machine.id === machineId ? { ...r, site } : r)));
    setDrafts((d) => ({ ...d, [machineId]: "" }));
  }, []);

  const runRow = useCallback(
    async (machineId: string, op: () => Promise<SiteState>) => {
      if (batchActive.current || lock.current || inFlight.current.has(machineId)) return;
      inFlight.current.add(machineId);
      setRowBusy((b) => ({ ...b, [machineId]: true }));
      setRowError((e) => ({ ...e, [machineId]: "" }));
      try {
        const site = await op();
        if (life.current.live) applyConfirmed(machineId, site); // a late old-context answer is dropped
      } catch (e) {
        if (life.current.live) setRowError((m) => ({ ...m, [machineId]: errorText(e) }));
      } finally {
        inFlight.current.delete(machineId);
        if (life.current.live) setRowBusy((b) => ({ ...b, [machineId]: false }));
      }
    },
    [applyConfirmed],
  );

  const handleSave = useCallback(
    (machineId: string) => {
      if (batchActive.current || lock.current || inFlight.current.has(machineId)) return;
      const v = validateSite(drafts[machineId] ?? "");
      if (!v.ok) {
        setRowError((m) => ({ ...m, [machineId]: v.message }));
        return;
      }
      void runRow(machineId, () => saveMachineSite(api, machineId, v.value));
    },
    [api, drafts, runRow],
  );

  const handleClear = useCallback(
    (machineId: string) => {
      if (batchActive.current || lock.current) return;
      void runRow(machineId, () => clearMachineSite(api, machineId));
    },
    [api, runRow],
  );

  // Search is local over rows already loaded (and already authorized); drafts/errors are keyed by
  // machine id, so a row hidden by the filter keeps them. Suggestions use ALL rows, not the filtered set.
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<SiteStateFilter>("all");
  const filtering = query.trim() !== "" || stateFilter !== "all";
  const stateLabel = SITE_STATE_FILTERS.find((f) => f.value === stateFilter)?.label ?? "";
  const clearFilters = () => {
    if (lock.current) return;
    setQuery("");
    setStateFilter("all");
  };
  const visible = useMemo(() => applySiteFilters(rows, query, stateFilter), [rows, query, stateFilter]);
  const buckets = useMemo(() => groupBySite(visible), [visible]);
  const names = useMemo(() => siteNames(rows), [rows]);
  const siteCount = buckets.filter((b) => b.kind === "set").length;
  const noMatch = loaded && rows.length > 0 && visible.length === 0;

  // Display-ordered visible rows, and the selection restricted to them AT RENDER TIME: a row hidden by a
  // filter or removed by a refresh is never selected, whatever the raw state still holds.
  const ordered = useMemo(() => buckets.flatMap((b) => b.rows), [buckets]);
  const selected = useMemo(() => pruneSelection(selectedRaw, ordered), [selectedRaw, ordered]);
  useEffect(() => {
    if (selected !== selectedRaw && !batchActive.current) setSelectedRaw(selected);
  }, [selected, selectedRaw]);
  const orderedRef = useRef(ordered);
  orderedRef.current = ordered;

  const handleToggle = (id: string, on: boolean) => {
    if (batchActive.current || lock.current) return;
    const change = toggleSelected(selected, ordered, id, on);
    setSelectedRaw(change.selected);
    setBulkCapped(change.capped);
    setBulkError(null);
  };
  const handleSelectAll = () => {
    if (batchActive.current || lock.current) return;
    const change = selectVisible(selected, ordered);
    setSelectedRaw(change.selected);
    setBulkCapped(change.capped);
    setBulkError(null);
  };
  const handleDeselectAll = () => {
    if (batchActive.current || lock.current) return;
    setSelectedRaw(new Set());
    setBulkCapped(false);
  };

  // Export exactly what is on screen (after search/state filters), from already-loaded state: no request.
  const handleExport = () => {
    if (batchActive.current || lock.current || panelBusy() || ordered.length === 0) return;
    saveBytesAsFile("deskrally-sites.csv", new TextEncoder().encode(sitesToCsv(ordered)));
    setNotice(`Exported ${ordered.length} of ${rows.length} machines`);
  };

  // One request at a time across the WHOLE panel: no review/confirmation while any row write or refresh
  // (even on an unselected machine) is outstanding.
  const panelBusy = () => inFlight.current.size > 0 || refreshing.current > 0;

  const handleReview = () => {
    if (batchActive.current || lock.current) return;
    if (panelBusy()) {
      setBulkError("Wait for the current save or refresh to finish, then review again.");
      return;
    }
    const plan = planBulkAssign(selected, ordered, bulkSite);
    if (!plan.ok) {
      setBulkError(plan.message);
      return;
    }
    setBulkError(null);
    setBulkResult(null);
    const next: BulkPending = { value: plan.value, targets: plan.targets };
    lock.current = true;
    confirmToken.current = next;
    setPending(next);
  };

  const handleCancel = () => {
    if (batchActive.current) return;
    lock.current = false;
    confirmToken.current = null;
    setPending(null);
  };

  const handleConfirm = () => {
    const snap = confirmToken.current;
    if (batchActive.current || !lock.current || snap === null) return;
    confirmToken.current = null; // consumed: a second Confirm before re-render is a no-op
    // Every snapshotted target must still be visible, and nothing else may be writing/refreshing;
    // otherwise nothing is sent.
    const shown = new Set(orderedRef.current.map((r) => r.machine.id));
    if (snap.targets.some((t) => !shown.has(t.id)) || panelBusy()) {
      lock.current = false;
      setPending(null);
      setBulkError("The visible machines changed or another save was running before confirmation; nothing was sent. Review the selection again.");
      return;
    }
    batchActive.current = true;
    for (const t of snap.targets) inFlight.current.add(t.id);
    setBulkRunning(true);
    setProgress(0);
    let done = 0;
    void (async () => {
      try {
        const run = await runBulkAssign(api, snap.targets, snap.value, {
          shouldContinue: alive,
          onOutcome: (o) => {
            if (!alive()) return;
            done += 1;
            setProgress(done);
            if (o.status === "saved") {
              sync.current.confirm(o.id, o.site); // exact echo only (saveMachineSite throws otherwise)
              setRows((prev) => prev.map((r) => (r.machine.id === o.id ? { ...r, site: o.site } : r)));
            }
          },
        });
        if (!alive()) return; // unmounted or api changed: publish nothing into the new context
        setSelectedRaw((s) => selectionAfterBatch(s, run.outcomes));
        setBulkResult({ value: snap.value, outcomes: run.outcomes });
      } finally {
        if (alive()) {
          for (const t of snap.targets) inFlight.current.delete(t.id);
          batchActive.current = false;
          lock.current = false;
          setPending(null);
          setBulkRunning(false);
        }
      }
    })();
  };

  const summary = bulkResult ? summarizeBulk(bulkResult.outcomes, bulkResult.value) : null;

  return (
    <section className="panel panel--sites" data-testid="sites">
      <div className="panel__form">
        <span className="panel__toolbar-title">Sites</span>
        <button className="panel__action" type="button" onClick={() => void refresh()} disabled={busy || locked} data-testid="sites-refresh">
          {busy ? "Loading…" : "Refresh"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="sites-error">
            {error}
          </span>
        )}
      </div>
      <p className="panel__note">
        A site records where a machine is (an office, branch or customer). It is the machine&apos;s{" "}
        <code>site</code> property, so Smart groups can match on it. Sites organise machines only; they do not
        grant or restrict access — use Machine groups for that. Other properties stay in Machines.
      </p>
      <p className="panel__note" data-testid="sites-limit-hint">
        {SITE_LIMIT_HINT} Longer names are refused, never shortened.
      </p>
      {notice && (
        <p className="panel__note" role="status" data-testid="sites-notice">
          {notice}
        </p>
      )}
      {loaded && (
        <div className="panel__toolbar sites__search">
          <input
            className="panel__search"
            type="search"
            aria-label="Search sites and machines"
            placeholder="Search site, machine name or alias…"
            value={query}
            onChange={(e) => {
              if (!lock.current) setQuery(e.target.value);
            }}
            disabled={locked}
            data-testid="sites-search"
          />
          <label className="sites__state">
            <span className="sites__state-label">Assignment</span>
            <select
              value={stateFilter}
              onChange={(e) => {
                if (!lock.current) setStateFilter(parseSiteStateFilter(e.target.value));
              }}
              disabled={locked}
              data-testid="sites-state-filter"
            >
              {SITE_STATE_FILTERS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
          {query.trim() !== "" && (
            <button className="panel__action" type="button" onClick={() => { if (!lock.current) setQuery(""); }} disabled={locked} data-testid="sites-search-clear">
              Clear search
            </button>
          )}
          <button
            className="panel__action"
            type="button"
            onClick={handleExport}
            disabled={ordered.length === 0 || locked || busy || rowWriting}
            data-testid="sites-export"
          >
            Export CSV
          </button>
        </div>
      )}
      {loaded && (
        <p className="panel__note" role="status" aria-live="polite" data-testid="sites-summary">
          {filtering
            ? `Showing ${visible.length} of ${rows.length} ${rows.length === 1 ? "machine" : "machines"}, ${siteCount} ${siteCount === 1 ? "site" : "sites"}`
            : `${siteCount} ${siteCount === 1 ? "site" : "sites"}, ${rows.length} ${rows.length === 1 ? "machine" : "machines"}`}
        </p>
      )}
      {loaded && rows.length > 0 && (
        <div className="sites__bulk" data-testid="sites-bulk">
          <div className="sites__bulk-row">
            <input
              className="sites__bulk-site"
              value={bulkSite}
              onChange={(e) => setBulkSite(e.target.value)}
              disabled={locked}
              placeholder="Site for selected machines"
              list="sites-known"
              aria-label="Site to assign to selected machines"
              data-testid="sites-bulk-site"
            />
            <button className="panel__action" type="button" onClick={handleReview} disabled={locked || busy || rowWriting || selected.size === 0} data-testid="sites-bulk-review">
              Review assignment
            </button>
          </div>
          <div className="sites__bulk-row">
            <span className="sites__bulk-count" role="status" aria-live="polite" data-testid="sites-bulk-count">
              {selected.size} selected (max {BULK_SELECTION_CAP})
            </span>
            <button className="panel__action" type="button" onClick={handleSelectAll} disabled={locked || ordered.length === 0} data-testid="sites-bulk-select-all">
              Select all visible (up to {BULK_SELECTION_CAP})
            </button>
            <button className="panel__action" type="button" onClick={handleDeselectAll} disabled={locked || selected.size === 0} data-testid="sites-bulk-deselect">
              Clear selection
            </button>
          </div>
          <p className="panel__note sites__bulk-note" data-testid="sites-bulk-hint">
            {BULK_CAP_HINT} Sets this site on the selected machines only; it never removes a site or changes other properties.
          </p>
          {bulkCapped && (
            <p className="panel__toolbar-error sites__bulk-note" role="status" data-testid="sites-bulk-cap">
              Selection limit reached: only {BULK_SELECTION_CAP} machines can be selected at once.
            </p>
          )}
          {bulkError && (
            <p className="panel__toolbar-error sites__bulk-note" role="alert" data-testid="sites-bulk-error">
              {bulkError}
            </p>
          )}
          {pending && (
            <div className="sites__confirm" role="group" aria-label="Confirm site assignment" data-testid="sites-bulk-confirm">
              <p className="sites__confirm-title" data-testid="sites-bulk-confirm-title">
                Set site &quot;{pending.value}&quot; on {pending.targets.length} {pending.targets.length === 1 ? "machine" : "machines"}?
              </p>
              <ul className="sites__confirm-list" data-testid="sites-bulk-confirm-list">
                {pending.targets.map((t) => (
                  <li key={t.id} data-testid={`sites-bulk-target-${t.id}`}>
                    {t.label}
                  </li>
                ))}
              </ul>
              {bulkRunning ? (
                <p role="status" aria-live="polite" data-testid="sites-bulk-progress">
                  Updating {Math.min(progress + 1, pending.targets.length)} of {pending.targets.length}…
                </p>
              ) : (
                <div className="sites__bulk-row">
                  <button className="panel__action" type="button" onClick={handleConfirm} disabled={busy || rowWriting} data-testid="sites-bulk-confirm-yes">
                    Set site on {pending.targets.length} {pending.targets.length === 1 ? "machine" : "machines"}
                  </button>
                  <button className="panel__action" type="button" onClick={handleCancel} data-testid="sites-bulk-confirm-cancel">
                    Cancel
                  </button>
                </div>
              )}
            </div>
          )}
          {summary && bulkResult && (
            <div className="sites__result" data-testid="sites-bulk-result">
              <p
                className={summary.allSaved ? "panel__note" : "panel__toolbar-error"}
                role={summary.allSaved ? "status" : "alert"}
                data-testid="sites-bulk-summary"
              >
                {summary.message}
              </p>
              <ul className="sites__confirm-list">
                {bulkResult.outcomes.map((o) => (
                  <li key={o.id} data-testid={`sites-bulk-result-${o.id}`} data-status={o.status}>
                    {o.label}:{" "}
                    {o.status === "saved" ? "saved" : o.status === "failed" ? `failed — ${o.error}` : "not attempted"}
                  </li>
                ))}
              </ul>
              <button className="panel__action" type="button" onClick={() => setBulkResult(null)} disabled={locked} data-testid="sites-bulk-result-dismiss">
                Dismiss
              </button>
            </div>
          )}
        </div>
      )}
      <datalist id="sites-known">
        {names.map((n) => (
          <option key={n} value={n} />
        ))}
      </datalist>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Machine</th>
            <th>Site</th>
            <th className="panel__col--action">Change site</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={3} data-testid="sites-empty">
                {busy ? (
                  "Loading…"
                ) : !loaded ? (
                  <>
                    Machines could not be loaded.{" "}
                    <button className="panel__action" type="button" onClick={() => void refresh()} data-testid="sites-retry">
                      Retry
                    </button>
                  </>
                ) : (
                  "No machines."
                )}
              </td>
            </tr>
          )}
          {noMatch && (
            <tr>
              <td className="panel__empty" colSpan={3} data-testid="sites-no-match">
                No machines match
                {query.trim() !== "" && <> &quot;{query.trim()}&quot;</>}
                {stateFilter !== "all" && <> with status &quot;{stateLabel}&quot;</>}.{" "}
                <button className="panel__action" type="button" onClick={clearFilters} data-testid="sites-no-match-reset">
                  Show all machines
                </button>
              </td>
            </tr>
          )}
          {buckets.map((b) => (
            <BucketRows
              key={`${b.kind}:${b.site ?? ""}`}
              title={b.kind === "set" ? siteLabel({ kind: "set", value: b.site ?? "" }) : b.kind === "none" ? "No site" : "Unknown — could not read properties"}
              testId={b.kind === "set" ? `site-bucket-${b.site}` : `site-bucket-${b.kind}`}
              rows={b.rows}
              drafts={drafts}
              rowBusy={rowBusy}
              rowError={rowError}
              selected={selected}
              locked={locked}
              atCap={selected.size >= BULK_SELECTION_CAP}
              onToggle={handleToggle}
              onDraft={(id, v) => setDrafts((d) => ({ ...d, [id]: v }))}
              onSave={handleSave}
              onClear={handleClear}
            />
          ))}
        </tbody>
      </table>
    </section>
  );
}

interface BucketRowsProps {
  title: string;
  testId: string;
  rows: readonly SiteRow[];
  drafts: Record<string, string>;
  rowBusy: Record<string, boolean>;
  rowError: Record<string, string>;
  selected: ReadonlySet<string>;
  /** A bulk confirmation or batch is open: every row control is disabled. */
  locked: boolean;
  atCap: boolean;
  onToggle: (machineId: string, on: boolean) => void;
  onDraft: (machineId: string, value: string) => void;
  onSave: (machineId: string) => void;
  onClear: (machineId: string) => void;
}

function BucketRows({ title, testId, rows, drafts, rowBusy, rowError, selected, locked, atCap, onToggle, onDraft, onSave, onClear }: BucketRowsProps) {
  return (
    <>
      <tr data-testid={testId}>
        <th colSpan={3} className="sites__bucket">
          {title} ({rows.length})
        </th>
      </tr>
      {rows.map(({ machine: m, site }) => {
        const id = m.id;
        const working = rowBusy[id] === true;
        const off = working || locked;
        const checked = selected.has(id);
        return (
          <tr key={id} data-testid={`site-row-${id}`}>
            <td className="sites__machine">
              <label className="sites__pick">
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={locked || (atCap && !checked)}
                  onChange={(e) => onToggle(id, e.target.checked)}
                  aria-label={`Select ${m.alias || m.name || m.device_id}`}
                  data-testid={`site-select-${id}`}
                />
                <span>{m.alias || m.name || m.device_id}</span>
              </label>
            </td>
            <td className="panel__mono" data-testid={`site-value-${id}`} title={site.kind === "unknown" ? site.error : undefined}>
              {siteLabel(site)}
            </td>
            <td className="panel__col--action">
              <form
                className="sites__edit"
                onSubmit={(e) => {
                  e.preventDefault();
                  onSave(id);
                }}
              >
                <input
                  value={drafts[id] ?? ""}
                  onChange={(e) => onDraft(id, e.target.value)}
                  disabled={off}
                  placeholder={site.kind === "set" ? "New site" : "Site"}
                  list="sites-known"
                  aria-label={`Site for ${m.alias || m.name || m.device_id}`}
                  data-testid={`site-input-${id}`}
                />
                <button className="panel__action" type="submit" disabled={off}data-testid={`site-save-${id}`}>
                  {working ? "Saving…" : site.kind === "set" ? "Change" : "Set site"}
                </button>
                {site.kind === "set" && (
                  <button
                    className="panel__action panel__action--danger"
                    type="button"
                    onClick={() => onClear(id)}
                    disabled={off}
                    data-testid={`site-clear-${id}`}
                  >
                    Remove site
                  </button>
                )}
                {rowError[id] && (
                  <span className="panel__toolbar-error" role="alert" data-testid={`site-error-${id}`}>
                    {rowError[id]}
                  </span>
                )}
              </form>
            </td>
          </tr>
        );
      })}
    </>
  );
}
