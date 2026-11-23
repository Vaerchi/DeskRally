/**
 * Management-console fleet view (Milestone M3): the tenant's enrolled machines from
 * `GET /machines`, rendered as a read-only table (name, device id, group, PK).
 *
 * Distinct from `AccessPanel`, which lists agents currently ONLINE at the signaling server —
 * this is the control plane's enrollment record, RBAC-filtered server-side to the groups the
 * caller can view. Thin by design: fetching goes through the injected `ConsoleApi`; the
 * component owns only load/refresh state.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createLatestWins } from "../lib/latest_wins";
import {
  MACHINE_STATUSES,
  ConsoleApiError,
  type AgentVersionInfo,
  type BulkStatusResult,
  type ConsoleApi,
  type MachineGroup,
  type MachinePropertyFilter,
  type MachineRecord,
  type SessionRecord,
  type UserSummary,
} from "../lib/console_api";
import {
  buildActiveSessionMap,
  bulkGroupSummary,
  bulkStatusSummary,
  endSessionButtonProps,
  endSessionConfirmText,
  technicianLabel,
  filterMachinesByText,
  isAgentVersionOutdated,
  machineOnlineTitle,
  prunedSelection,
  sessionBadgeTooltip,
} from "../lib/console_panels";
import { policyPostureBadge } from "../lib/machine_posture";
import { groupOptions, groupPaths, pathLabelFor } from "../lib/group_tree";
import { machinesToCsv } from "../lib/report_csv";
import { machinePropertyKeys, machinePropertyValue, togglePropertyColumn } from "../lib/machine_property_columns";
import { connectState, IN_SESSION_LABEL } from "../lib/connect_rule";
import { MachinePropertiesPanel } from "./MachinePropertiesPanel";
import { MachineFieldInput } from "./MachineFieldInput";
import { canonicalFieldValue, compareFieldValues, fieldFilterOperand, storedFieldValue } from "../lib/machine_fields";
import { useMachineFields } from "../lib/use_machine_fields";
import { ToolbarMenu } from "./ToolbarMenu";
import { saveBytesAsFile } from "./FileTransferPanel";
import { DirectivePolicyToggle, ForgetMachineDialog, PendingRemovalsPanel, RemoveAgentDialog, describeDirectiveError } from "./FleetDirectives";
import {
  canOfferForget,
  canOfferReinstall,
  canOfferRemove,
  forgetOutcomeNote,
  holdsCapabilityAnywhere,
  holdsCapabilityForGroup,
  type DirectivePolicy,
  type ForgetMachineResult,
  type MachineLike,
  type MeCapability,
} from "../lib/fleet_directives";
import { WAKE_GUIDE_PATH, wakeMenuState, wakeResultMessage } from "../lib/wake";

export interface MachinesPanelProps {
  api: ConsoleApi;
  onConnect?: (machine: MachineRecord) => void;
}

export function BulkPropertyResults({ results }: { results: readonly BulkStatusResult[] }) {
  return (
    <>
      {/* The summary keeps its own status element (its text is a stable contract); the per-machine
          outcomes (docs/74 §5c.6) are a separate list beside it. */}
      <div role="status" data-testid="bulk-property-result">{bulkStatusSummary(results)}</div>
      <ul data-testid="bulk-property-outcomes">{results.map((result) => (
        <li key={result.machine_id}>{result.machine_id} — {result.ok ? "Updated" : result.error || "Failed"}</li>
      ))}</ul>
    </>
  );
}

const PROPERTY_COLUMNS_STORAGE_KEY = "deskrally.machinePropertyColumns";

export function MachinesPanel({ api, onConnect }: MachinesPanelProps) {
  const [rows, setRows] = useState<readonly MachineRecord[]>([]);
  const [selectedPropertyKeys, setSelectedPropertyKeys] = useState<string[]>(() => {
    try {
      const saved: unknown = JSON.parse(window.localStorage.getItem(PROPERTY_COLUMNS_STORAGE_KEY) ?? "[]");
      if (Array.isArray(saved)) {
        return [...new Set(saved.filter((key): key is string => typeof key === "string"))];
      }
    } catch {
      // Column preferences are optional when storage is unavailable.
    }
    return [];
  });
  useEffect(() => {
    try {
      window.localStorage.setItem(PROPERTY_COLUMNS_STORAGE_KEY, JSON.stringify(selectedPropertyKeys));
    } catch {
      // The current table still reflects the selection.
    }
  }, [selectedPropertyKeys]);
  const { fields } = useMachineFields(api);
  const fieldsByKey = useMemo(() => new Map(fields.map((field) => [field.key, field])), [fields]);
  const propertyLabels = useMemo(() => new Map(fields.map((field) => [field.key, field.label])), [fields]);
  const propertyKeys = useMemo(
    () => [...fields.map((field) => field.key), ...machinePropertyKeys(rows).filter((key) => !fieldsByKey.has(key))],
    [fields, fieldsByKey, rows],
  );
  const [propertySort, setPropertySort] = useState<{ key: string; descending: boolean }>();
  const visiblePropertyKeys = useMemo(() => {
    const available = new Set(propertyKeys);
    return selectedPropertyKeys.filter((key) => available.has(key));
  }, [propertyKeys, selectedPropertyKeys]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The machine whose custom-property editor is open below the table (by PRIMARY KEY), or null.
  const [selected, setSelected] = useState<{ id: string; name: string } | null>(null);
  // The custom-property search form, and the filter currently APPLIED to the listing (undefined = all).
  const [filterKey, setFilterKey] = useState("");
  const [filterValue, setFilterValue] = useState("");
  const [rawFilter, setRawFilter] = useState(false);
  const [filterError, setFilterError] = useState("");
  const filterDefinition = fieldsByKey.get(filterKey);
  const filterField = rawFilter ? undefined : filterDefinition;
  const [applied, setApplied] = useState<MachinePropertyFilter | undefined>(undefined);
  // The machine (by PRIMARY KEY) whose status change is in flight, or null.
  const [statusPending, setStatusPending] = useState<string | null>(null);
  // The tenant's machine groups (for the per-row reassignment picker), and the machine whose group change
  // is in flight.
  const [groups, setGroups] = useState<readonly MachineGroup[]>([]);
  const [groupPending, setGroupPending] = useState<string | null>(null);
  // Group pickers and labels come from ONE tree helper (docs/62): path labels ("Acme › Site A") in tree order,
  // built from the groups this caller can see, so equal names never merge into one option.
  const groupPathMap = useMemo(() => groupPaths(groups), [groups]);
  const groupPickerOptions = useMemo(() => groupOptions(groups), [groups]);
  // BULK status change: the selected machine PKs, the status to apply, in-flight flag, last summary.
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState<string>("");
  const [bulkPending, setBulkPending] = useState(false);
  const [bulkResult, setBulkResult] = useState<string | null>(null);
  // BULK group reassignment: the shared TARGET group id, in-flight flag, last summary (operates on selectedIds).
  const [bulkGroupId, setBulkGroupId] = useState<string>("");
  const [bulkGroupPending, setBulkGroupPending] = useState(false);
  const [bulkGroupResult, setBulkGroupResult] = useState<string | null>(null);
  const [bulkPropertyAction, setBulkPropertyAction] = useState<"set" | "remove" | null>(null);
  const [bulkPropertyKey, setBulkPropertyKey] = useState("");
  const [bulkPropertyValue, setBulkPropertyValue] = useState("");
  const [bulkPropertyPending, setBulkPropertyPending] = useState(false);
  const [bulkPropertyResults, setBulkPropertyResults] = useState<BulkStatusResult[] | null>(null);
  const [bulkPropertyError, setBulkPropertyError] = useState("");
  const bulkField = fieldsByKey.get(bulkPropertyKey);
  // ALIAS (friendly-name) inline editor: the machine PK being edited (null = none), the draft text, and
  // the machine whose alias write is in flight.
  const [aliasEditId, setAliasEditId] = useState<string | null>(null);
  const [aliasDraft, setAliasDraft] = useState("");
  const [aliasPending, setAliasPending] = useState<string | null>(null);
  // NOTE (free-text) inline editor: the machine PK being edited (null = none), the draft, and the in-flight PK.
  const [noteEditId, setNoteEditId] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [notePending, setNotePending] = useState<string | null>(null);
  // Local text search (client-side, no extra fetch): filters the loaded rows by alias/name/device id/group/OS/note.
  const [textQuery, setTextQuery] = useState("");
  // Presence envelope: whether the signaling feed was reachable at the last listing. Used to distinguish
  // "offline" (presenceKnown=true, online=false) from "unknown" (feed unreachable).
  const [presenceKnown, setPresenceKnown] = useState(false);
  // Live sessions fetched alongside the machine list (requires CapViewSessions). On 403 or any
  // error the list stays empty and no badges appear — a graceful degradation, not an error state.
  const [liveSessions, setLiveSessions] = useState<readonly SessionRecord[]>([]);
  // Users fetched once on mount for badge "by whom" resolution (requires CapManageUsers). On 403
  // or any error the list stays empty and the badge tooltip falls back to the raw technician_id.
  const [users, setUsers] = useState<readonly UserSummary[]>([]);
  // The session id whose End call is in flight, or null. Disables ALL end-session buttons while set
  // so a second click on a different row cannot race the first.
  const [endSessionPending, setEndSessionPending] = useState<string | null>(null);
  // Operator-configured expected agent version. null = not configured (no outdated badges shown).
  // Fetched once on mount; failure degrades gracefully to null (no badges).
  const [publishedVersion, setPublishedVersion] = useState<AgentVersionInfo | null>(null);
  // Fleet directives (docs/65). What the caller holds and where comes from GET /me (the SAME coverage the server
  // checks per machine); the tenant policy is read only by someone who holds remove_agent somewhere.
  const [myCaps, setMyCaps] = useState<readonly MeCapability[]>([]);
  const [selfUserId, setSelfUserId] = useState<string | null>(null);
  const [directivePolicy, setDirectivePolicy] = useState<DirectivePolicy | null>(null);
  const holdsRemoveAgentAnywhere = holdsCapabilityAnywhere(myCaps, "remove_agent");
  const holdsRemoveAgentFor = useCallback((m: MachineRecord) => holdsCapabilityForGroup(myCaps, "remove_agent", m.group_id), [myCaps]);
  const [removeFor, setRemoveFor] = useState<MachineRecord | null>(null);
  // "Forget this machine..." (docs/65 sec. 8): opened from a retired machine's row or from a pending removal the agent
  // never confirmed, so it holds the minimal machine facts both can supply.
  const [forgetFor, setForgetFor] = useState<MachineLike | null>(null);
  const [directiveReload, setDirectiveReload] = useState(0);
  const [reinstallPending, setReinstallPending] = useState<string | null>(null);
  const wakeInFlight = useRef(new Set<string>());
  const [wakePending, setWakePending] = useState<ReadonlySet<string>>(new Set());
  const [directiveNote, setDirectiveNote] = useState<{ kind: "ok" | "error"; text: string; guide?: boolean } | null>(null);

  // Latest-wins guard for the listing: the filter, Refresh and every row action's re-list can overlap, and
  // only the newest request may touch the rows, badges, error or busy flag.
  const listGuard = useRef(createLatestWins());
  const mountedRef = useRef(true);
  // The filter CURRENTLY applied, readable by row actions whose mutation outlives the render that started them.
  const appliedRef = useRef<MachinePropertyFilter | undefined>(undefined);
  useEffect(() => {
    const guard = listGuard.current;
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      guard.invalidate();
    };
  }, []);
  const refresh = useCallback(
    async (filter?: MachinePropertyFilter) => {
      const token = listGuard.current.begin();
      setBusy(true);
      setError(null);
      try {
        const [listing, sessions] = await Promise.all([
          api.listMachinesWithPresence(filter, { includeProperties: true }),
          api.listLiveSessions().catch((): SessionRecord[] => []),
        ]);
        if (!listGuard.current.isCurrent(token)) return; // superseded: a newer request owns the state
        setRows(listing.machines);
        setPresenceKnown(listing.presenceKnown);
        setLiveSessions(sessions);
      } catch (e) {
        if (!listGuard.current.isCurrent(token)) return; // a superseded failure must not show
        setError(e instanceof Error ? e.message : String(e));
        // Clear session badges: the machine list is stale after a failure, so badge state from the
        // prior fetch would be inconsistent with whatever rows the component still shows.
        setLiveSessions([]);
      } finally {
        // Only the newest request clears busy (an older one finishing must not hide a newer load).
        if (listGuard.current.isCurrent(token)) setBusy(false);
      }
    },
    [api],
  );

  // Post-action re-list: resolves the filter applied NOW (not the one captured when the action started) and
  // never starts a request once the panel is unmounted.
  const relist = useCallback(async () => {
    if (!mountedRef.current) return;
    await refresh(appliedRef.current);
  }, [refresh]);

  // Re-list whenever the applied filter changes (and on mount) — the applied filter is the source of truth.
  useEffect(() => {
    void refresh(applied);
  }, [refresh, applied]);

  // Client-side text filter applied on top of the server-side property filter — no extra fetch.
  const filteredRows = useMemo(() => {
    const visible = filterMachinesByText(rows, textQuery);
    if (!propertySort || !visiblePropertyKeys.includes(propertySort.key)) return visible;
    const { key, descending } = propertySort;
    const field = fieldsByKey.get(key);
    if (!field) return visible;
    return [...visible].sort((a, b) => compareFieldValues(field, storedFieldValue(a, key), storedFieldValue(b, key), descending));
  }, [rows, textQuery, propertySort, visiblePropertyKeys, fieldsByKey]);

  // O(1) device_id → session lookup for per-row "active" badges. Recomputed only when the session
  // list changes (independent of the text filter — all rows get badges, not just the visible slice).
  const activeSessionMap = useMemo(() => buildActiveSessionMap(liveSessions), [liveSessions]);

  // Load the tenant's groups once (for the per-row reassignment picker). A groups-load failure is
  // non-fatal — the machine listing still works; the picker just falls back to showing the group id.
  useEffect(() => {
    void api
      .listMachineGroups()
      .then(setGroups)
      .catch(() => {});
  }, [api]);

  // Load users once for "by whom" badge tooltip resolution. Requires CapManageUsers; on 403 or
  // any error the list stays empty and the badge tooltip shows the raw technician_id instead.
  useEffect(() => {
    void api
      .listUsers()
      .then(setUsers)
      .catch(() => {});
  }, [api]);

  // Published agent version: fetched once on mount. On any error (including 403 if the user
  // lacks CapViewMachines — which should not occur here, since the panel gating already requires
  // it) degrades gracefully to null so no spurious outdated badges appear.
  useEffect(() => {
    void api
      .getPublishedAgentVersion()
      .then(setPublishedVersion)
      .catch(() => {});
  }, [api]);

  useEffect(() => {
    let live = true;
    void api.me().then((me) => {
      if (!live) return;
      setMyCaps(me.capabilities);
      setSelfUserId(me.userId);
    }, () => {});
    return () => { live = false; };
  }, [api]);

  useEffect(() => {
    if (!holdsRemoveAgentAnywhere) { setDirectivePolicy(null); return; }
    let live = true;
    void api.getDirectivePolicy().then((p) => { if (live) setDirectivePolicy(p); }, () => { if (live) setDirectivePolicy(null); });
    return () => { live = false; };
  }, [api, holdsRemoveAgentAnywhere]);

  const handleWake = async (id: string) => {
    if (wakeInFlight.current.has(id)) return;
    wakeInFlight.current.add(id);
    setWakePending(new Set(wakeInFlight.current));
    setDirectiveNote(null);
    try {
      const status = await api.requestWake(id);
      setDirectiveNote({ kind: "ok", text: wakeResultMessage(status), guide: true });
    } catch (e) {
      let outcome: string | number | undefined;
      if (e instanceof ConsoleApiError) {
        outcome = e.status === 404 || e.status === 429 ? e.status : e.code;
      }
      setDirectiveNote({ kind: "error", text: wakeResultMessage(outcome) });
    } finally {
      wakeInFlight.current.delete(id);
      setWakePending(new Set(wakeInFlight.current));
    }
  };

  const handleReinstall = useCallback(
    async (m: MachineRecord) => {
      if (reinstallPending !== null) return;
      if (!window.confirm(`Reinstall the agent on ${m.alias || m.name || m.device_id}? It is repaired to the current release; its identity and settings are kept.`)) return;
      setReinstallPending(m.id);
      setDirectiveNote(null);
      try {
        await api.requestDirective(m.id, "reinstall");
        setDirectiveNote({ kind: "ok", text: `Reinstall requested for ${m.alias || m.name}. The agent repairs itself the next time it connects.` });
      } catch (e) {
        setDirectiveNote({ kind: "error", text: describeDirectiveError(e, "reinstall") });
      } finally {
        setReinstallPending(null);
      }
    },
    [api, reinstallPending],
  );

  // The forget went through (or the machine was already removed): the machine list and the pending removals both changed.
  const handleForgotten = useCallback(
    (r: ForgetMachineResult) => {
      setDirectiveNote({ kind: "ok", text: forgetOutcomeNote(r.outcome, r.machine) });
      setDirectiveReload((n) => n + 1);
      void relist();
    },
    [relist],
  );

  const handleEndSession = useCallback(
    async (sessionId: string) => {
      if (endSessionPending !== null) return;
      setEndSessionPending(sessionId);
      setError(null);
      try {
        await api.endSession(sessionId);
        await relist();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setEndSessionPending(null);
      }
    },
    [api, endSessionPending, relist],
  );

  const handleSetGroup = useCallback(
    async (m: MachineRecord, groupId: string) => {
      if (groupId === m.group_id || groupPending !== null) return;
      setGroupPending(m.id);
      setError(null);
      try {
        await api.setMachineGroup(m.id, groupId);
        await relist();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setGroupPending(null);
      }
    },
    [api, groupPending, relist],
  );

  // Keep the bulk selection CONFINED to the currently-visible machines: whenever the list re-fetches
  // (property filter applied/cleared, Refresh, post-apply reload) OR the text query changes, drop
  // any selected id no longer on screen. Without this a bulk quarantine/retire could hit machines
  // the operator filtered away and can no longer see, and the "N selected" count / select-all would
  // misrepresent the view (review-caught). filteredRows is the visible set; the text filter is enforced here.
  useEffect(() => {
    setSelectedIds((prev) => {
      const next = prunedSelection(prev, filteredRows.map((m) => m.id));
      return next.size === prev.size ? prev : next; // next ⊆ prev, so equal size ⇒ unchanged
    });
  }, [filteredRows]);

  const handleFilter = useCallback((e: FormEvent) => {
    e.preventDefault();
    const key = filterDefinition?.key ?? filterKey.trim();
    const operand = fieldFilterOperand(filterField, filterValue);
    if (operand === undefined) {
      setFilterError(`Invalid value for field ${filterField?.label}`);
      return;
    }
    setFilterError("");
    const next = key === "" ? undefined : {
      propertyKey: key, propertyValue: operand, exactKey: filterDefinition !== undefined,
    };
    appliedRef.current = next;
    setApplied(next);
  }, [filterKey, filterValue, filterDefinition, filterField]);

  const handleClear = useCallback(() => {
    setFilterKey("");
    setFilterValue("");
    setFilterError("");
    appliedRef.current = undefined;
    setApplied(undefined);
  }, []);

  const handleSetStatus = useCallback(
    async (m: MachineRecord, status: string) => {
      if (status === (m.status ?? "active") || statusPending !== null) return;
      if (status !== "active" && !window.confirm(`Set ${m.alias || m.name || m.device_id} to ${status}? This prevents new remote sessions.`)) return;
      setStatusPending(m.id);
      setError(null);
      try {
        await api.setMachineStatus(m.id, status);
        await relist();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setStatusPending(null);
      }
    },
    [api, relist, statusPending],
  );

  const handleSetAlias = useCallback(
    async (m: MachineRecord) => {
      if (aliasPending !== null) return;
      setAliasPending(m.id);
      setError(null);
      try {
        // An empty draft CLEARS the alias (reverts to the hostname); the server trims + validates.
        await api.setMachineAlias(m.id, aliasDraft.trim());
        setAliasEditId(null);
        setAliasDraft("");
        await relist();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setAliasPending(null);
      }
    },
    [aliasDraft, aliasPending, api, relist],
  );

  const handleSetNote = useCallback(
    async (m: MachineRecord) => {
      if (notePending !== null) return;
      setNotePending(m.id);
      setError(null);
      try {
        // An empty draft CLEARS the note; the server validates (≤2000 runes, no control chars but newlines OK).
        // Sent verbatim (NOT trimmed) so a multi-line note round-trips as typed.
        await api.setMachineNote(m.id, noteDraft);
        setNoteEditId(null);
        setNoteDraft("");
        await relist();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setNotePending(null);
      }
    },
    [noteDraft, notePending, api, relist],
  );

  const handleExport = useCallback(() => {
    // Export the machines CURRENTLY SHOWN (honoring both the server-side property filter and the
    // client-side text search) as a CSV inventory the browser saves — a pure serialization, no extra fetch.
    saveBytesAsFile("machines.csv", new TextEncoder().encode(machinesToCsv(filteredRows, visiblePropertyKeys, propertyLabels)));
  }, [filteredRows, visiblePropertyKeys, propertyLabels]);

  const toggleOne = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const allSelected = filteredRows.length > 0 && filteredRows.every((m) => selectedIds.has(m.id));

  const toggleAll = useCallback(() => {
    setSelectedIds((prev) => {
      const everySelected = filteredRows.length > 0 && filteredRows.every((m) => prev.has(m.id));
      return everySelected ? new Set<string>() : new Set(filteredRows.map((m) => m.id));
    });
  }, [filteredRows]);

  const handleBulkApply = useCallback(async () => {
    if (selectedIds.size === 0 || bulkPending || !bulkStatus) return;
    if (bulkStatus !== "active" && !window.confirm(`Set ${selectedIds.size} selected machines to ${bulkStatus}? This prevents new remote sessions.`)) return;
    setBulkPending(true);
    setError(null);
    setBulkResult(null);
    try {
      const results = await api.bulkSetMachineStatus([...selectedIds], bulkStatus);
      setBulkResult(bulkStatusSummary(results));
      setSelectedIds(new Set());
      await relist();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBulkPending(false);
    }
  }, [api, bulkPending, bulkStatus, relist, selectedIds]);

  const handleBulkGroupApply = useCallback(async () => {
    if (selectedIds.size === 0 || bulkGroupId === "" || bulkGroupPending) return;
    setBulkGroupPending(true);
    setError(null);
    setBulkGroupResult(null);
    try {
      const results = await api.bulkSetMachineGroup([...selectedIds], bulkGroupId);
      setBulkGroupResult(bulkGroupSummary(results));
      setSelectedIds(new Set());
      await relist();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBulkGroupPending(false);
    }
  }, [api, bulkGroupId, bulkGroupPending, relist, selectedIds]);

  const handleBulkPropertyApply = async (event: FormEvent) => {
    event.preventDefault();
    if (selectedIds.size === 0 || bulkPropertyPending || !bulkPropertyAction || !bulkPropertyKey) return;
    const remove = bulkPropertyAction === "remove";
    setBulkPropertyError("");
    setBulkPropertyResults(null);
    if (!remove && bulkField && canonicalFieldValue(bulkField, bulkPropertyValue) === undefined) {
      setBulkPropertyError(`Invalid value for field ${bulkField.label}`);
      return;
    }
    setBulkPropertyPending(true);
    setError(null);
    try {
      const results = await api.bulkSetMachineProperty(
        [...selectedIds], bulkPropertyKey, remove ? "" : bulkPropertyValue, remove,
      );
      setBulkPropertyResults(results);
      setBulkPropertyAction(null);
      setBulkPropertyKey("");
      setBulkPropertyValue("");
      setSelectedIds(new Set());
      await relist();
    } catch (e) {
      setBulkPropertyError(e instanceof ConsoleApiError && e.status === 400 && e.code.startsWith("invalid value for field ")
        ? e.code : e instanceof Error ? e.message : String(e));
    } finally {
      setBulkPropertyPending(false);
    }
  };

  // AGENT VERSION SKEW (docs/21 §2). The question a rollout is judged by is "how many machines are
  // NOT on the newest build I can see" — and the honest answer has to separate machines that
  // reported an older version from machines that reported NOTHING. Lumping the two together is what
  // makes a rollout look complete when part of the fleet is simply not answering.
  //
  // "Newest" is the highest version PRESENT IN THE FLEET, not a value the console is told: the
  // control plane has no notion of a current release yet (that arrives with the manifest, docs/21
  // §3). So this reports skew relative to what is actually out there, which is exactly what step 1
  // can honestly support and no more.
  //
  // Compared as plain strings deliberately. AGENT_VERSION is `<semver>+<sha>`, and semver says build
  // metadata is IGNORED for precedence — so two builds of the same version from different commits
  // are the same version, and a lexical max would pick one arbitrarily. Grouping by the whole string
  // and counting distinct values sidesteps ordering entirely; real ordering waits for the manifest.
  const versionSkew = (() => {
    if (rows.length === 0) return null;
    const counts = new Map<string, number>();
    let unknown = 0;
    for (const m of rows) {
      const v = (m.agent_version ?? "").trim();
      if (v === "") { unknown += 1; continue; }
      counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    if (counts.size === 0 && unknown === 0) return null;
    // The most COMMON reported build is the reference point. Not the newest — nothing here can
    // order builds — but it is the one a rollout is moving the fleet toward or away from.
    let common = "";
    let commonN = 0;
    for (const [v, n] of counts) {
      if (n > commonN) { common = v; commonN = n; }
    }
    const reported = rows.length - unknown;
    const differing = reported - commonN;
    if (counts.size <= 1 && unknown === 0) {
      return { label: `all ${rows.length} on ${common}`, detail: `Every machine reports ${common}.` };
    }
    const parts: string[] = [];
    if (differing > 0) parts.push(`${differing} on another build`);
    if (unknown > 0) parts.push(`${unknown} unknown`);
    return {
      label: `agents: ${parts.join(", ")}`,
      detail:
        `${commonN} of ${rows.length} report ${common || "nothing"}. ` +
        (differing > 0 ? `${differing} report a different build. ` : "") +
        (unknown > 0
          ? `${unknown} have never reported a version — treat those as UNKNOWN, not up to date.`
          : ""),
    };
  })();

  return (
    <div className="panel panel--machines">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Machines</span>
        <button className="panel__action" onClick={() => void refresh(applied)} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={rows.length === 0}
          title="Download the shown machines as a CSV inventory"
          data-testid="machines-export"
        >
          Export CSV
        </button>
        <ToolbarMenu label="Columns" triggerClassName="panel__action">
          {propertyKeys.length === 0 && <span>No custom properties in this list</span>}
          {propertyKeys.map((key) => (
            <label className="panel__toolbar-field" key={key}>
              <input
                type="checkbox"
                checked={selectedPropertyKeys.includes(key)}
                onChange={() => setSelectedPropertyKeys((current) => togglePropertyColumn(current, key))}
              />
              {propertyLabels.get(key) ?? key}
            </label>
          ))}
        </ToolbarMenu>
        {versionSkew && (
          <span className="panel__toolbar-title" data-testid="machines-version-skew" title={versionSkew.detail}>
            {versionSkew.label}
          </span>
        )}
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="machines-error">
            {error}
          </span>
        )}
      </div>
      <div className="panel__toolbar">
        <input
          className="panel__search"
          type="search"
          aria-label="Search machines"
          placeholder="Search name, alias, device ID, group, OS, note…"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="machines-text-search"
        />
      </div>
      <form className="panel__form" onSubmit={handleFilter}>
        <span className="panel__toolbar-title">Search by property</span>
        <label className="panel__toolbar-field">
          Key
          <input
            value={filterKey}
            onChange={(e) => {
              if (!rawFilter && fieldsByKey.get(e.target.value)?.id !== filterField?.id) setFilterValue("");
              setFilterKey(e.target.value);
              setFilterError("");
            }}
            list="machine-field-filter-keys"
            placeholder="site"
            data-testid="machine-filter-key"
          />
        </label>
        <datalist id="machine-field-filter-keys">
          {fields.map((field) => <option key={field.key} value={field.key}>{field.label}</option>)}
        </datalist>
        {filterDefinition && (
          <label className="panel__toolbar-field">
            <input type="checkbox" checked={rawFilter} onChange={(e) => {
              setRawFilter(e.target.checked);
              setFilterError("");
            }} />
            Raw value
          </label>
        )}
        <label className="panel__toolbar-field">
          Value
          {filterField ? (
            <MachineFieldInput field={filterField} value={filterValue} onChange={(value) => {
              setFilterValue(value);
              setFilterError("");
            }} testId="machine-filter-value" emptyLabel="(any)" />
          ) : (
            <input value={filterValue} onChange={(e) => setFilterValue(e.target.value)}
              placeholder="(any)" data-testid="machine-filter-value" />
          )}
        </label>
        {filterError && <span role="alert">{filterError}</span>}
        <button className="panel__action" type="submit" disabled={busy} data-testid="machine-filter-apply">
          Filter
        </button>
        {applied && (
          <button
            className="panel__action"
            type="button"
            onClick={handleClear}
            data-testid="machine-filter-clear"
          >
            Clear
          </button>
        )}
        {applied && (
          <span className="panel__toolbar-title" data-testid="machine-filter-active">
            {applied.propertyValue
              ? `${applied.propertyKey} = ${applied.propertyValue}`
              : applied.propertyKey}
          </span>
        )}
      </form>
      <div className="panel__toolbar">
        <span className="panel__toolbar-title" data-testid="bulk-selected-count">
          {`${selectedIds.size} selected`}
        </span>
        <label className="panel__toolbar-field">
          Set status
          <select
            className="panel__select"
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value)}
            disabled={bulkPending}
            data-testid="bulk-status-select"
          >
            <option value="" disabled>Choose status…</option>
            {MACHINE_STATUSES.map((st) => (
              <option key={st} value={st}>
                {st}
              </option>
            ))}
          </select>
        </label>
        <button
          className="panel__action"
          onClick={() => void handleBulkApply()}
          disabled={selectedIds.size === 0 || bulkPending || !bulkStatus}
          data-testid="bulk-apply"
        >
          {bulkPending ? "Applying…" : `Apply to ${selectedIds.size} selected`}
        </button>
        {bulkResult && (
          <span className="panel__toolbar-title" data-testid="bulk-result">
            {bulkResult}
          </span>
        )}
        <label className="panel__toolbar-field">
          Move to group
          <select
            className="panel__select"
            value={bulkGroupId}
            onChange={(e) => setBulkGroupId(e.target.value)}
            disabled={bulkGroupPending || groups.length === 0}
            data-testid="bulk-group-select"
          >
            <option value="">(choose a group)</option>
            {groupPickerOptions.map((g) => (
              <option key={g.id} value={g.id}>
                {g.label}
              </option>
            ))}
          </select>
        </label>
        <button
          className="panel__action"
          onClick={() => void handleBulkGroupApply()}
          disabled={selectedIds.size === 0 || bulkGroupId === "" || bulkGroupPending}
          data-testid="bulk-group-apply"
        >
          {bulkGroupPending ? "Moving…" : `Move ${selectedIds.size} to group`}
        </button>
        {bulkGroupResult && (
          <span className="panel__toolbar-title" data-testid="bulk-group-result">
            {bulkGroupResult}
          </span>
        )}
        <button type="button" className="panel__action"
          disabled={selectedIds.size === 0 || bulkPropertyPending || busy}
          onClick={() => { setBulkPropertyError(""); setBulkPropertyAction("set"); }}>
          Set property…
        </button>
        <button type="button" className="panel__action"
          disabled={selectedIds.size === 0 || bulkPropertyPending || busy}
          onClick={() => { setBulkPropertyError(""); setBulkPropertyAction("remove"); }}>
          Remove property…
        </button>
        {bulkPropertyResults && <BulkPropertyResults results={bulkPropertyResults} />}
      </div>
      {bulkPropertyAction && (
        <form className="panel__toolbar" onSubmit={(event) => void handleBulkPropertyApply(event)}>
          <label className="panel__toolbar-field">
            Property key
            <input className="panel__input" value={bulkPropertyKey} required maxLength={128}
              list="machine-field-bulk-keys" disabled={bulkPropertyPending} onChange={(event) => {
                if (fieldsByKey.get(event.target.value)?.id !== bulkField?.id) setBulkPropertyValue("");
                setBulkPropertyKey(event.target.value);
                setBulkPropertyError("");
              }} />
            <datalist id="machine-field-bulk-keys">
              {fields.map((field) => <option key={field.key} value={field.key}>{field.label}</option>)}
            </datalist>
          </label>
          {bulkPropertyAction === "set" && (
            <label className="panel__toolbar-field">
              Property value
              <MachineFieldInput field={bulkField} value={bulkPropertyValue} disabled={bulkPropertyPending}
                maxLength={4096} onChange={(value) => { setBulkPropertyValue(value); setBulkPropertyError(""); }} />
            </label>
          )}
          {bulkPropertyError && <span role="alert">{bulkPropertyError}</span>}
          <button type="submit" className="panel__action" disabled={selectedIds.size === 0 || bulkPropertyPending || busy}>
            {bulkPropertyAction === "set" ? "Set on" : "Remove from"} {selectedIds.size} selected
          </button>
          <button type="button" className="panel__action" disabled={bulkPropertyPending}
            onClick={() => setBulkPropertyAction(null)}>
            Cancel
          </button>
        </form>
      )}
      <table className="panel__table">
        <thead>
          <tr>
            <th className="panel__col--check">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={toggleAll}
                aria-label="Select all machines"
                data-testid="bulk-select-all"
              />
            </th>
            <th>Name</th>
            <th>Device ID</th>
            <th>Group</th>
            <th>Machine ID</th>
            <th>Status</th>
            <th>Agent</th>
            <th>User</th>
            <th>Note</th>
            {visiblePropertyKeys.map((key) => {
              const field = fieldsByKey.get(key);
              const direction = propertySort?.key === key ? (propertySort.descending ? "descending" : "ascending") : undefined;
              return (
                <th key={key} aria-sort={direction}>
                  {field ? <button className="panel__action" onClick={() => setPropertySort({ key, descending: direction === "ascending" })}>
                    {field.label}{direction === "ascending" ? " ↑" : direction === "descending" ? " ↓" : ""}
                  </button> : key}
                </th>
              );
            })}
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredRows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={10 + visiblePropertyKeys.length} data-testid="machines-empty">
                {busy
                  ? "Loading…"
                  : textQuery.trim()
                    ? "No machines match this search."
                    : applied
                      ? "No machines match this property."
                      : "No machines enrolled."}
              </td>
            </tr>
          )}
          {filteredRows.map((m) => (
            <tr key={m.id}>
              <td className="panel__col--check">
                <input
                  type="checkbox"
                  checked={selectedIds.has(m.id)}
                  onChange={() => toggleOne(m.id)}
                  aria-label={`Select ${m.name || m.device_id}`}
                  data-testid={`bulk-check-${m.id}`}
                />
              </td>
              <td className="panel__name">
                <span
                  className="panel__dot"
                  data-online={presenceKnown ? String(m.online ?? "unknown") : "unknown"}
                  data-testid={`machine-online-${m.id}`}
                  title={machineOnlineTitle(m.online, presenceKnown)}
                />
                {activeSessionMap.has(m.device_id) && (
                  <span
                    className="panel__session-badge"
                    data-testid={`machine-session-active-${m.id}`}
                    title={sessionBadgeTooltip(activeSessionMap.get(m.device_id)!, users)}
                  >
                    {IN_SESSION_LABEL}
                  </span>
                )}
                {(() => {
                  const b = policyPostureBadge(m);
                  return (
                    <span
                      className={`panel__session-badge panel__posture-badge panel__posture-badge--${b.state}`}
                      data-testid={`machine-policy-posture-${m.id}`}
                      data-posture={b.state}
                      title={b.title}
                    >
                      {b.label}
                    </span>
                  );
                })()}
                {aliasEditId === m.id ? (
                  <span className="panel__inline-edit">
                    <input
                      className="panel__input"
                      value={aliasDraft}
                      onChange={(e) => setAliasDraft(e.target.value)}
                      placeholder={m.name || m.device_id}
                      maxLength={100}
                      aria-label={`Friendly name for ${m.name || m.device_id}`}
                      data-testid={`machine-alias-input-${m.id}`}
                    />
                    <button
                      className="panel__action"
                      onClick={() => void handleSetAlias(m)}
                      disabled={aliasPending !== null}
                      data-testid={`machine-alias-save-${m.id}`}
                    >
                      Save
                    </button>
                    <button
                      className="panel__action"
                      onClick={() => {
                        setAliasEditId(null);
                        setAliasDraft("");
                      }}
                      disabled={aliasPending !== null}
                      data-testid={`machine-alias-cancel-${m.id}`}
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <span className="panel__inline-edit">
                    {onConnect && (() => {
                      // The one connect rule (lib/connect_rule.ts), shared with the sidebar: presence never disables Connect.
                      const cs = connectState({ online: presenceKnown ? m.online === true : undefined, status: m.status, current: false });
                      return <button type="button" className="panel__action"
                        data-testid={`machine-connect-${m.id}`}
                        disabled={!cs.enabled}
                        title={cs.hint}
                        onClick={() => onConnect(m)}>{cs.label}</button>;
                    })()}
                    <span data-testid={`machine-name-${m.id}`}>{m.alias || m.name || "—"}</span>
                  </span>
                )}
              </td>
              <td className="panel__mono">{m.device_id}</td>
              <td>
                <span className="panel__mono" data-testid={`machine-group-${m.id}`}>
                  {pathLabelFor(groupPathMap, m.group_id, m.group_name)}
                </span>
                <select
                  className="panel__select"
                  value={m.group_id}
                  onChange={(e) => void handleSetGroup(m, e.target.value)}
                  disabled={groupPending !== null}
                  aria-label={`Group for ${m.name || m.device_id}`}
                  data-testid={`machine-group-select-${m.id}`}
                >
                  {/* The machine's current group is always an option even if it is outside the viewable list. */}
                  {!groups.some((g) => g.id === m.group_id) && (
                    <option value={m.group_id}>{pathLabelFor(groupPathMap, m.group_id, m.group_name)}</option>
                  )}
                  {groupPickerOptions.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label}
                    </option>
                  ))}
                </select>
              </td>
              <td className="panel__mono">{m.id}</td>
              <td>
                <span data-testid={`machine-status-${m.id}`}>{m.status ?? "active"}</span>
                {/* A REMOVED machine (a confirmed removal, or one an owner forgot: docs/65) is terminal: there is no
                    status to choose, and a select whose value matches none of its options would read "active". */}
                {m.status !== "removed" && (
                  <select
                    className="panel__select"
                    value={m.status ?? "active"}
                    onChange={(e) => void handleSetStatus(m, e.target.value)}
                    disabled={statusPending !== null}
                    aria-label={`Status for ${m.name || m.device_id}`}
                    data-testid={`machine-status-select-${m.id}`}
                  >
                    {MACHINE_STATUSES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>
                )}
              </td>
              {/* Agent build identity (migrations/0039). Empty is UNKNOWN and says so: a machine
                  that has never reported must never read as up to date, because a fleet that looks
                  current is a rollout nobody checks. `title` carries when the build was first seen,
                  which is the rollout question — a different column from last_seen.

                  AND last_seen IS NOT LIVENESS, which this comment used to assert. Measured
                  2026-09-06: it is the timestamp of the last AUTHENTICATED `/cp/machines` request
                  — a TECHNICIAN OPENING THIS PAGE — matching the access log to the second, and a
                  401 does not refresh it. It is wrong in BOTH directions: a healthy agent
                  registering every 22s read 11.5 h stale because nobody had loaded the console,
                  and a laptop that died at 01:43Z carried 22:12Z, under-reporting its life by 3.5
                  hours. Liveness is `Machine.Online`, the presence-feed tri-state AccessPanel gates
                  on `presenceKnown`. Two people have now reached for this field as a health signal;
                  the second had this comment encouraging them. */}
              <td className="panel__mono" data-testid={`machine-agent-version-${m.id}`}>
                {m.agent_version ? (
                  <span title={m.agent_version_seen_at ? `First seen ${m.agent_version_seen_at}` : undefined}>
                    {m.agent_version}
                    {isAgentVersionOutdated(m.agent_version, publishedVersion?.version) && (
                      <span
                        className="panel__version-outdated"
                        title={`Version mismatch — expected: ${publishedVersion?.version}`}
                        data-testid={`machine-version-outdated-${m.id}`}
                      >
                        {" "}⚠ mismatch
                      </span>
                    )}
                  </span>
                ) : (
                  <span className="panel__muted" title="This agent has never reported a version. It predates version reporting, or has not reconnected since.">
                    unknown
                  </span>
                )}
              </td>
              <td className="panel__mono" data-testid={`machine-user-${m.id}`}>
                {m.logged_in_user ? (
                  m.logged_in_user
                ) : (
                  <span className="panel__muted">—</span>
                )}
              </td>
              <td className="panel__note">
                {noteEditId === m.id ? (
                  <span className="panel__inline-edit">
                    <textarea
                      className="panel__input"
                      value={noteDraft}
                      onChange={(e) => setNoteDraft(e.target.value)}
                      rows={2}
                      maxLength={2000}
                      aria-label={`Note for ${m.name || m.device_id}`}
                      data-testid={`machine-note-input-${m.id}`}
                    />
                    <button
                      className="panel__action"
                      onClick={() => void handleSetNote(m)}
                      disabled={notePending !== null}
                      data-testid={`machine-note-save-${m.id}`}
                    >
                      Save
                    </button>
                    <button
                      className="panel__action"
                      onClick={() => {
                        setNoteEditId(null);
                        setNoteDraft("");
                      }}
                      disabled={notePending !== null}
                      data-testid={`machine-note-cancel-${m.id}`}
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <span className="panel__inline-edit">
                    <span data-testid={`machine-note-${m.id}`}>{m.note || "—"}</span>
                    <button
                      className="panel__action"
                      onClick={() => {
                        setNoteEditId(m.id);
                        setNoteDraft(m.note ?? "");
                      }}
                      disabled={notePending !== null}
                      title="Set a free-text operator note"
                      data-testid={`machine-note-edit-${m.id}`}
                    >
                      {m.note ? "Edit" : "Add note"}
                    </button>
                  </span>
                )}
              </td>
              {visiblePropertyKeys.map((key) => {
                const field = fieldsByKey.get(key);
                const value = storedFieldValue(m, key);
                return <td key={key}>{field
                  ? value === undefined ? "Unset" : canonicalFieldValue(field, value) !== value
                    ? <span title="Nonconforming value">{value || "Empty value"} ⚠</span>
                    : value === "" ? "Empty text" : value
                  : machinePropertyValue(m, key)}</td>;
              })}
              <td className="panel__col--action">
                {/* Menu redesign wave 8: Properties stays on the row; everything else is in its "⋯" menu, so a row
                    reads Connect … Properties ⋯ instead of up to six buttons. Same handlers and test ids. */}
                <span className="panel__row-actions">
                <button
                  className="panel__action"
                  data-testid={`machine-props-${m.id}`}
                  onClick={() =>
                    setSelected((s) =>
                      s?.id === m.id ? null : { id: m.id, name: m.name || m.device_id },
                    )
                  }
                >
                  {selected?.id === m.id ? "Hide" : "Properties"}
                </button>
                <ToolbarMenu label="More actions" ariaLabel={`More actions for ${m.alias || m.name || m.device_id}`}
                  trigger="⋯" triggerTestId={`machine-actions-${m.id}`} triggerClassName="panel__action panel__row-menu"
                  closeOnAction>
                <button
                  className="panel__action"
                  onClick={() => {
                    setAliasEditId(m.id);
                    setAliasDraft(m.alias ?? "");
                  }}
                  disabled={aliasPending !== null}
                  title="Set a friendly name (overrides the reported hostname)"
                  data-testid={`machine-alias-edit-${m.id}`}
                >
                  Rename
                </button>
                {(() => {
                  const sess = activeSessionMap.get(m.device_id);
                  if (!sess) return null;
                  const btn = endSessionButtonProps(sess.id, endSessionPending);
                  return (
                    <button
                      className="panel__action panel__action--danger"
                      data-testid={`machine-end-session-${m.id}`}
                      disabled={btn.disabled}
                      title={`End active session on ${m.alias || m.name || m.device_id}`}
                      onClick={() => {
                        if (!window.confirm(endSessionConfirmText(m.alias || m.name || m.device_id, technicianLabel(users, sess.technician_id)))) return;
                        void handleEndSession(sess.id);
                      }}
                    >
                      {btn.label}
                    </button>
                  );
                })()}
                {(() => {
                  const wake = wakeMenuState(m, myCaps, presenceKnown);
                  if (!wake.visible) return null;
                  return (
                    <button
                      type="button"
                      className="panel__action"
                      data-testid={`machine-wake-${m.id}`}
                      disabled={!wake.enabled || wakePending.has(m.id)}
                      title={wake.reason}
                      onClick={() => void handleWake(m.id)}
                    >
                      Wake
                    </button>
                  );
                })()}
                {canOfferReinstall(m, holdsRemoveAgentFor(m)) && (
                  <button
                    className="panel__action"
                    data-testid={`machine-reinstall-${m.id}`}
                    disabled={reinstallPending !== null}
                    title="Repair the agent to the current release without opening a session"
                    onClick={() => void handleReinstall(m)}
                  >
                    Reinstall agent
                  </button>
                )}
                {canOfferRemove(m, holdsRemoveAgentFor(m)) && (
                  <button
                    className="panel__action panel__action--danger"
                    data-testid={`machine-remove-agent-${m.id}`}
                    title="Uninstall the agent and delete its identity"
                    onClick={() => setRemoveFor(m)}
                  >
                    Remove agent…
                  </button>
                )}
                {canOfferForget(m, holdsRemoveAgentFor(m)) && (
                  <button
                    className="panel__action panel__action--danger"
                    data-testid={`machine-forget-${m.id}`}
                    title="Permanently remove this machine from DeskRally. It does not uninstall anything."
                    onClick={() => setForgetFor(m)}
                  >
                    Forget this machine…
                  </button>
                )}
                </ToolbarMenu>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {directiveNote && (
        <p role={directiveNote.kind === "error" ? "alert" : "status"} className={directiveNote.kind === "error" ? "panel__toolbar-error" : "panel__hint"} data-testid="directive-note">
          {directiveNote.text}
          {directiveNote.guide && (
            <> <a href={WAKE_GUIDE_PATH}>See which power states DeskRally has verified</a>.</>
          )}
        </p>
      )}
      {holdsRemoveAgentAnywhere && (
        <>
          {directivePolicy && <DirectivePolicyToggle api={api} policy={directivePolicy} onSaved={setDirectivePolicy} />}
          <PendingRemovalsPanel api={api} selfUserId={selfUserId} users={users}
            reloadToken={directiveReload} onChanged={() => setDirectiveReload((n) => n + 1)} onForget={setForgetFor} />
        </>
      )}
      {forgetFor && (
        <ForgetMachineDialog
          key={forgetFor.id}
          api={api}
          machine={forgetFor}
          onClose={() => setForgetFor(null)}
          onForgotten={handleForgotten}
        />
      )}
      {removeFor && (
        <RemoveAgentDialog
          key={removeFor.id}
          api={api}
          machine={removeFor}
          onClose={() => setRemoveFor(null)}
          onChanged={() => setDirectiveReload((n) => n + 1)}
        />
      )}
      {selected && (
        <MachinePropertiesPanel
          key={selected.id}
          api={api}
          machineId={selected.id}
          machineName={selected.name}
          onPropertiesChanged={relist}
        />
      )}
    </div>
  );
}
