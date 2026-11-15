/**
 * Access panel: the technician's list of controllable machines, grouped, with online/offline
 * status and one-click connect. Agents are addressed by stable DeviceId (ADR-002), never IP.
 *
 * REAL DATA (2026-08-01): {@link machinesFromRecords} maps the control plane's `GET /machines`
 * envelope — enriched with presence, OS and group name (control-plane migrations/0017) — into this
 * panel's view model. Presence is TRI-STATE end to end: the control plane reads it live from the
 * signaling registry and reports `presence_known: false` when that feed is unreachable, so the
 * panel can say "status unavailable" instead of rendering a healthy fleet as offline.
 *
 * THERE IS NO FALLBACK FLEET (2026-08-13). The panel renders the caller's data or says it has none;
 * see {@link fleetStatus} for what `undefined` means and why the demo list that used to sit at the
 * bottom of this file was a defect rather than a convenience.
 */

import { useMemo, useState } from "react";
import { asDeviceId, type DeviceId } from "../lib";
import type { MachineGroup, MachineListing, MachineRecord } from "../lib/console_api";
import { groupPaths } from "../lib/group_tree";

import { DEV_SIGNALING_URL, defaultSignalingUrl } from "../lib/default_signaling_url";
import { machineNewTabUrl } from "../lib/machine_url_params";
import { connectState, IN_SESSION_LABEL, VIEW_ONLY_LABEL } from "../lib/connect_rule";
import { ToolbarMenu } from "./ToolbarMenu";
import { endSessionConfirmText } from "../lib/console_panels";

export interface Machine {
  device: DeviceId;
  name: string;
  /** Tenant-chosen friendly name (machine.alias). When set, shown instead of `name`; `name` becomes a tooltip. */
  alias?: string;
  /**
   * The group heading: the PATH label ("Acme › Site A") when the group list was available, else the joined
   * group name. Display + search text only — never the bucket key (see `groupId`).
   */
  group: string;
  /**
   * The group's id, which is what machines are bucketed by: two groups may share a name (docs/62 — names are
   * not unique, paths disambiguate), and bucketing by name would merge their machines under one heading.
   * Absent only for a hand-built Machine, which then buckets by `group` as before.
   */
  groupId?: string;
  /** `undefined` = presence unknown (the feed could not be consulted), NOT offline. */
  online: boolean | undefined;
  os: string;
  /** ISO timestamp of last check-in; used for the "offline for…" hint. "" when never seen. */
  lastSeen: string;
  /** Whether unattended access is policy-permitted (ADR-005 consent/visibility). */
  unattended: boolean;
  /** Set when there is a currently open session on this machine. Absent when none or unknown. */
  liveSession?: { sessionId?: string; startedAt: string; technicianId: string };
  /**
   * Whether the agent advertises multi-tech capability (multiple concurrent controllers).
   * Tri-state: true = explicitly advertised, false = explicitly declined, absent = older agent
   * that never reported. Display-only; nothing authorizes on it.
   */
  multiSessionCapable?: boolean;
  /** Machine status from the control plane ("active", "quarantined", ...); absent = active. Drives the one connect rule. */
  status?: string;
}

/**
 * Map one control-plane `MachineRecord` into the panel's view model.
 *
 * The machine is addressed by `device_id` — the STABLE AGENT IDENTITY the connect path carries —
 * never by `id`, which is the database primary key (see the MachineRecord doc). Conflating them
 * would produce a panel whose Connect button targets a machine that does not exist.
 *
 * `presenceKnown` gates the online flag: when the control plane could not reach the presence feed
 * every record's `online` is absent, and forcing that to `false` here would be the lie the whole
 * tri-state exists to avoid.
 */
export function machineFromRecord(
  rec: MachineRecord,
  presenceKnown: boolean,
  liveSession?: { sessionId?: string; startedAt: string; technicianId: string },
  groupPathById?: ReadonlyMap<string, string>,
): Machine {
  return {
    device: asDeviceId(rec.device_id),
    name: rec.name || rec.device_id.slice(0, 8),
    alias: rec.alias || undefined,
    // Fall back to the raw group id only when the join found no name, so a machine is never
    // silently filed under a blank heading.
    // With the group list: the path label (docs/62), built from the groups the caller can see.
    group: groupPathById?.get(rec.group_id) || rec.group_name || rec.group_id || "Ungrouped",
    groupId: rec.group_id || undefined,
    online: presenceKnown ? rec.online === true : undefined,
    os: rec.os || "unknown OS",
    lastSeen: rec.last_seen ?? "",
    // Every enrolled (non-ephemeral) machine in the listing is an unattended endpoint; attended
    // guests are ephemeral and the control plane hides them from this listing entirely.
    unattended: true,
    liveSession,
    multiSessionCapable: rec.multi_session_capable,
    status: rec.status,
  };
}

/**
 * Map a whole `GET /machines` listing, optionally cross-referencing open sessions.
 *
 * `liveSessionsByDevice` is keyed by the agent's stable device id (matches `MachineRecord.device_id`).
 * When absent or when a machine has no entry, its `liveSession` is left undefined.
 */
export function machinesFromRecords(
  listing: MachineListing,
  liveSessionsByDevice?: ReadonlyMap<string, { sessionId?: string; startedAt: string; technicianId: string }>,
  groups?: readonly MachineGroup[],
): Machine[] {
  // One path map for the whole listing (not per machine). Without a group list the heading stays the joined name.
  const paths = groups && groups.length > 0 ? groupPaths(groups) : undefined;
  return listing.machines.map((m) =>
    machineFromRecord(m, listing.presenceKnown, liveSessionsByDevice?.get(m.device_id), paths),
  );
}

/**
 * Filter a machine list by a free-text query and an online-only flag.
 *
 * When `query` is empty/whitespace the original array is returned by reference (mutation-pin for
 * tests: removing this early return causes 2 reference-equality tests to fail).
 *
 * Matches are case-insensitive across: alias (friendly name), hostname (`name`), `group`, and `os`.
 * `onlineOnly` hides machines known to be offline; UNKNOWN presence is always shown (tri-state rule:
 * "status unavailable" must not silently drop the fleet from the panel).
 */
export function filterMachines(
  machines: readonly Machine[],
  query: string,
  onlineOnly: boolean,
): readonly Machine[] {
  const q = query.trim().toLowerCase();
  if (!q && !onlineOnly) return machines;
  return machines.filter((m) => {
    if (onlineOnly && m.online === false) return false;
    if (!q) return true;
    return (
      (m.alias ?? "").toLowerCase().includes(q) ||
      m.device.toLowerCase().includes(q) ||
      m.name.toLowerCase().includes(q) ||
      m.group.toLowerCase().includes(q) ||
      m.os.toLowerCase().includes(q)
    );
  });
}

/**
 * Bucket machines into group sections: `[bucketKey, heading, machines]`, headings alphabetical, each
 * section online-first then by name.
 *
 * The bucket key is the group ID, NEVER the heading text: names are not unique (docs/62), so two groups
 * that share a name must stay two sections (their headings differ by path, or by an id suffix when even
 * the path is equal). A hand-built Machine with no `groupId` still buckets by its heading, as before.
 */
export function bucketMachinesByGroup(machines: readonly Machine[]): (readonly [string, string, Machine[]])[] {
  const byGroup = new Map<string, { label: string; list: Machine[] }>();
  for (const m of machines) {
    const key = m.groupId ?? `name:${m.group}`;
    const bucket = byGroup.get(key) ?? { label: m.group, list: [] };
    bucket.list.push(m);
    byGroup.set(key, bucket);
  }
  // Online first, then alphabetical within each group (unknown sorts with offline).
  for (const { list } of byGroup.values()) {
    list.sort(
      (a, b) => Number(b.online === true) - Number(a.online === true) || (a.alias ?? a.name).localeCompare(b.alias ?? b.name),
    );
  }
  return [...byGroup.entries()]
    .map(([key, { label, list }]) => [key, label, list] as const)
    .sort(([, a], [, b]) => a.localeCompare(b));
}

/**
 * The status line under a machine's name — the panel's whole claim about what we know.
 *
 * Three distinct answers, and the third one is why this is a function rather than an inline
 * ternary. `lastSeen` is only written when a technician's page load catches the agent connected,
 * and enrollment does not seed it, so a machine that has been up and healthy since the day it was
 * enrolled carries NO stamp. Rendering that as "last seen never" turned "we have not observed it"
 * into a claim about the device — and it read as the strongest possible evidence of a dead machine
 * precisely when the machine was fine. "Not seen since enrollment" says what we actually know.
 *
 * `now` is injectable so the relative rendering is testable without freezing the clock.
 */
export function presenceHint(m: Machine, now: number = Date.now()): string {
  if (m.online === undefined) return "status unavailable";
  if (m.online) return "";
  return m.lastSeen ? `last seen ${relativeTime(m.lastSeen, now)}` : "not seen since enrollment";
}

/**
 * Short label shown on a machine row when a session is currently open on it.
 *
 * Returns an empty string (falsy) when there is no live session, so callers can guard with a
 * simple truthiness check. The time is extracted from the ISO string as "HH:MM UTC" — a
 * deterministic, locale-independent format that is unambiguous in a shared-tenant console.
 */
export function sessionHint(m: Machine): string {
  if (!m.liveSession) return "";
  const time = formatSessionTime(m.liveSession.startedAt);
  return `session active since ${time} by ${m.liveSession.technicianId}`;
}

/**
 * Tooltip for the Connect button. Connect is NEVER disabled (see {@link AccessPanel}), so when the
 * panel believes a machine is down this is where that belief is surfaced — as information, not as a
 * veto.
 */
export function connectHint(m: Machine): string {
  return connectState({ online: m.online, status: m.status, current: false }).hint;
}

/**
 * What the panel actually knows about the fleet — THREE states, not two.
 *
 * The distinction this type exists to force is between "the control plane says you have no
 * machines" and "we never got an answer". They look identical as an empty array and mean opposite
 * things to a technician, and collapsing them is how this panel came to render a fabricated fleet:
 * `machines` defaulted to a five-machine demo list whenever the prop was `undefined`, and
 * `undefined` is exactly what `App.tsx` leaves it as when the load fails (no control plane, or a
 * 401 because nobody is logged in). Measured in a real browser with the control plane down: the
 * header read "3/5 online" over RECEPTION-01 / ACCT-WS-07 / CEO-LAPTOP, each with a live Connect
 * button pointing at a UUID that exists nowhere.
 *
 * `undefined` now means UNLOADED and renders as unloaded. There is no demo fleet.
 */
export type FleetStatus =
  | { kind: "unloaded" }
  | { kind: "empty" }
  | { kind: "loaded"; total: number; online: number; presenceKnown: boolean };

/** Classify the `machines` prop. Pure, so the three-way distinction is unit-testable. */
export function fleetStatus(machines: Machine[] | undefined): FleetStatus {
  if (machines === undefined) return { kind: "unloaded" };
  if (machines.length === 0) return { kind: "empty" };
  // Presence is unknown for the WHOLE listing when the control plane could not consult the feed;
  // `machinesFromRecords` encodes that as `online === undefined` on every row. One known row is
  // enough to make the tally meaningful, so this is `every`, not `some`.
  const presenceKnown = !machines.every((m) => m.online === undefined);
  return {
    kind: "loaded",
    total: machines.length,
    online: machines.filter((m) => m.online === true).length,
    presenceKnown,
  };
}

/**
 * The header line. Never states a count the panel cannot stand behind: an unloaded fleet reports
 * itself unavailable rather than borrowing the shape of a real tally.
 */
export function fleetCountLabel(status: FleetStatus): string {
  switch (status.kind) {
    case "unloaded":
      return "machine list unavailable";
    case "empty":
      return "no machines enrolled";
    case "loaded":
      return status.presenceKnown
        ? `${status.online}/${status.total} online`
        : `${status.total} machines · status unavailable`;
  }
}

/**
 * Default rendezvous/signaling WebSocket.
 *
 * Derived from the page's own origin on a deployed console, because Caddy serves the console and
 * signaling from ONE origin with signaling at `/ws`. It used to be the hard-coded dev loopback,
 * which meant a production console displayed `ws://127.0.0.1:8080/ws` — reasonably read by an
 * operator as "this console is pointed at localhost". Only a default, and the brokered path ignores
 * it, but a control surface that describes itself wrongly is a bug regardless.
 */
export const DEFAULT_SIGNALING_URL =
  typeof window === "undefined" ? DEV_SIGNALING_URL : defaultSignalingUrl(window.location);

/** Loose UUID check so the manual-connect button is only enabled for a plausible DeviceId. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AccessPanelProps {
  machines?: Machine[];
  /**
   * Open a session with `device`, labelled `name`, reached through `signalingUrl`.
   * `alias` is the operator-chosen friendly name, when set; absent for manually-entered device IDs.
   */
  onConnect: (device: DeviceId, name: string, signalingUrl: string, alias?: string) => void;
  onObserve?: (device: DeviceId, name: string, signalingUrl: string, alias?: string) => void;
  /** DeviceId of the machine currently being controlled, if any. */
  activeDevice?: DeviceId | null;
  /**
   * End a live session by its id. When provided, an "End" button appears on each machine card
   * that has a live session with a known `sessionId`. The promise is awaited to track in-flight
   * state; the button is disabled until the call settles (success or failure).
   */
  onEndSession?: (sessionId: string) => Promise<void>;
  /** When the list was collapsed (compact) on a screen wide enough for it: put it back as a permanent
   *  pane. Shown only where that would change anything (CSS keys on data-natural-pane-mode). */
  onPin?: () => void;
}

export function AccessPanel({ machines, onConnect, onObserve, activeDevice = null, onEndSession, onPin }: AccessPanelProps) {
  const [query, setQuery] = useState("");
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [endingSessionIds, setEndingSessionIds] = useState<ReadonlySet<string>>(new Set());
  const [endSessionErrors, setEndSessionErrors] = useState<Map<string, string>>(new Map());

  function handleEndClick(sessionId: string) {
    setEndingSessionIds((prev) => new Set([...prev, sessionId]));
    // Clear any previous error for this session on a fresh attempt.
    setEndSessionErrors((prev) => {
      if (!prev.has(sessionId)) return prev;
      const next = new Map(prev);
      next.delete(sessionId);
      return next;
    });
    void onEndSession!(sessionId).catch((e: unknown) => {
      setEndSessionErrors((prev) => {
        const next = new Map(prev);
        next.set(sessionId, e instanceof Error ? e.message : "Failed to end session");
        return next;
      });
    }).finally(() => {
      setEndingSessionIds((prev) => {
        const next = new Set(prev);
        next.delete(sessionId);
        return next;
      });
    });
  }
  // Manual-connect affordance: reach a specific agent by DeviceId over a chosen signaling URL.
  // This is the path the operator (and the e2e test) use to reach a live agent directly, and it is
  // the reason an unloaded fleet is not treated as a page error: it must keep working with no
  // control plane at all. The signaling URL typed here applies to THIS form's Connect only: the
  // machine rows always use DEFAULT_SIGNALING_URL. Once the form is folded away, a value left in
  // it must not silently redirect every row's Connect, View only and new-tab link (Codex menu
  // review, 2026-11-07).
  const [signalingUrl, setSignalingUrl] = useState(DEFAULT_SIGNALING_URL);
  const [manualDevice, setManualDevice] = useState("");
  const manualValid = UUID_RE.test(manualDevice.trim());
  // Connecting by a raw device ID is the fallback for when the list cannot be loaded (no control plane, lab use), so it
  // stays folded behind one link and the machines get the panel (Ed, 2026-11-07). Always folded at first, never
  // opened by the list's state: the list is "unloaded" until its first fetch answers, so an automatic form would
  // flash open on every page load.
  const [manualOpen, setManualOpen] = useState(false);

  const status = fleetStatus(machines);
  const showManual = manualOpen;

  const grouped = useMemo(() => bucketMachinesByGroup(filterMachines(machines ?? [], query, onlineOnly)), [machines, query, onlineOnly]);

  return (
    // `id` is the target of the topbar drawer toggle's aria-controls in the stacked layout.
    <aside className="access" id="access-panel">
      <header className="access__header">
        <h2>Machines</h2>
        <span className="access__count" data-testid="access-count">
          {fleetCountLabel(status)}
        </span>
        {onPin && (
          <button type="button" className="access__pin" data-testid="access-pin" onClick={onPin}
            title="Keep the machine list open beside the session">
            Keep list open
          </button>
        )}
      </header>

      <div className="access__controls">
        <input
          className="access__search"
          type="search"
          aria-label="Search machines"
          placeholder="Search alias, name, device ID, group, OS…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <label className="access__filter">
          <input
            type="checkbox"
            checked={onlineOnly}
            onChange={(e) => setOnlineOnly(e.target.checked)}
          />
          Online only
        </label>
      </div>

      {!showManual && (
        <button type="button" className="access__manual-toggle" data-testid="manual-toggle" onClick={() => setManualOpen(true)}>
          Connect by device ID…
        </button>
      )}
      {showManual && (
      <form
        className="access__manual"
        onSubmit={(e) => {
          e.preventDefault();
          if (!manualValid) return;
          const id = manualDevice.trim();
          onConnect(asDeviceId(id), `agent ${id.slice(0, 8)}`, signalingUrl.trim());
        }}
      >
        <h3 className="access__group-title">Connect to a device</h3>
        <label className="access__manual-field">
          Signaling URL
          <input
            data-testid="signaling-url"
            type="text"
            value={signalingUrl}
            onChange={(e) => setSignalingUrl(e.target.value)}
            placeholder={DEFAULT_SIGNALING_URL}
          />
        </label>
        <label className="access__manual-field">
          Device ID
          <input
            data-testid="manual-device"
            type="text"
            value={manualDevice}
            onChange={(e) => setManualDevice(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <button data-testid="manual-connect" type="submit" disabled={!manualValid}>
          Connect
        </button>
        <button type="button" className="access__manual-close" data-testid="manual-close" onClick={() => setManualOpen(false)}>
          Hide
        </button>
      </form>
      )}

      <div className="access__list">
        {/*
          Three distinct empty states, because they are three different facts. Saying "No machines
          match." when the list was never loaded would tell a technician their fleet is gone at
          precisely the moment the console cannot see it.
        */}
        {status.kind === "unloaded" && (
          <p className="access__empty" data-testid="access-unloaded">
            The machine list could not be loaded — sign in to the control plane, or check that it is
            reachable. You can still{" "}
            <button type="button" className="access__manual-toggle access__manual-toggle--inline" onClick={() => setManualOpen(true)}>
              connect to a machine by its device ID
            </button>
            .
          </p>
        )}
        {status.kind === "empty" && (
          <p className="access__empty" data-testid="access-none-enrolled">
            No machines are enrolled in this tenant yet.
          </p>
        )}
        {status.kind === "loaded" && grouped.length === 0 && (
          <p className="access__empty">No machines match.</p>
        )}
        {grouped.map(([key, group, list]) => (
          <section key={key} className="access__group">
            <h3 className="access__group-title">{group}</h3>
            <ul>
              {list.map((m) => {
                // Computed once per row: `relativeTime` reads the clock, so calling it twice in one
                // render could produce two different strings for the same machine.
                const hint = presenceHint(m);
                return (
                <li
                  key={m.device}
                  className="access__machine"
                  data-active={m.device === activeDevice}
                >
                  <span
                    className="access__dot"
                    data-online={m.online ?? "unknown"}
                    title={m.online === undefined ? "status unavailable" : m.online ? "online" : "offline"}
                  />
                  <span className="access__meta">
                    <span className="access__name" title={m.alias ? m.name : undefined}>{m.alias ?? m.name}</span>
                    <span className="access__sub">
                      {m.os}
                      {m.unattended ? " · unattended" : " · attended"}
                      {m.multiSessionCapable === true && " · multi-session"}
                      {hint && ` · ${hint}`}
                    </span>
                  </span>
                  {/*
                    The badge and buttons are ONE cluster that wraps below the name when the
                    sidebar is narrow. As separate row items they kept their width while the name
                    shrank under its longest word, which then overflowed onto the ACTIVE badge.
                  */}
                  <span className="access__actions">
                  {m.liveSession && (
                    <span
                      className="access__session"
                      data-testid={`session-badge-${m.device}`}
                      title={sessionHint(m)}
                    >
                      {IN_SESSION_LABEL}
                    </span>
                  )}
                  {onEndSession && m.liveSession?.sessionId && (
                    <>
                      {endSessionErrors.has(m.liveSession.sessionId) && (
                        <span
                          className="access__session-end-error"
                          role="alert"
                          data-testid={`end-error-${m.device}`}
                        >
                          {endSessionErrors.get(m.liveSession.sessionId)}
                        </span>
                      )}
                    </>
                  )}
                  {/*
                    Presence never disables Connect (only an out-of-service status does, through the
                    shared rule in lib/connect_rule.ts) — including on a believed-OFFLINE machine, which is
                    the case this comment used to describe while the code did the opposite.
                    Presence is a 5s-cached read of a feed that can be stale, wrong, or unreachable,
                    and nothing is authorized on it; the session attempt itself is the
                    authoritative test. Disabling the button turned a soft signal into a hard veto
                    and left the technician no way to reach a machine the feed was wrong about.
                    The belief is surfaced in the dot, the status line, and the tooltip instead.
                  */}
                  {(() => {
                    // The one connect rule (lib/connect_rule.ts), shared with the Machines page. Only an out-of-service
                    // machine disables it; presence never does (see above).
                    const cs = connectState({ online: m.online, status: m.status, current: m.device === activeDevice });
                    return (
                      <button
                        className="access__connect"
                        data-testid={`connect-${m.device}`}
                        data-believed-offline={m.online === false}
                        disabled={!cs.enabled}
                        title={cs.hint}
                        onClick={() => onConnect(m.device, m.name, DEFAULT_SIGNALING_URL, m.alias)}
                      >
                        {cs.label}
                      </button>
                    );
                  })()}
                  {/* Menu redesign wave 8b: the row is Connect and "⋯"; View only, Open in new tab and End session
                      are in the menu (the same rules decide what it offers). */}
                  <ToolbarMenu label="More actions" ariaLabel={`More actions for ${m.alias ?? m.name}`}
                    trigger="⋯" triggerTestId={`access-actions-${m.device}`} triggerClassName="access__more"
                    closeOnAction>
                  {onObserve && m.multiSessionCapable === true && (
                    <button
                      className="panel__action"
                      data-testid={`observe-${m.device}`}
                      title="Watch without control"
                      disabled={!connectState({ online: m.online, status: m.status, current: false }).enabled}
                      onClick={() => onObserve(m.device, m.name, DEFAULT_SIGNALING_URL, m.alias)}
                    >
                      {VIEW_ONLY_LABEL}
                    </button>
                  )}
                  <a
                    className="panel__action access__new-tab"
                    href={machineNewTabUrl(m.device, m.alias ?? m.name, DEFAULT_SIGNALING_URL, window.location.origin)}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={`Open ${m.alias ?? m.name} in a new tab (for connecting to multiple machines simultaneously)`}
                    aria-label={`Open ${m.alias ?? m.name} in new tab`}
                    data-testid={`new-tab-${m.device}`}
                  >
                    ↗ Open in new tab
                  </a>
                  {onEndSession && m.liveSession?.sessionId && (
                    <button
                      className="panel__action panel__action--danger"
                      data-testid={`end-session-${m.device}`}
                      disabled={endingSessionIds.has(m.liveSession.sessionId)}
                      title="End this session"
                      onClick={() => {
                        if (!window.confirm(endSessionConfirmText(m.alias ?? m.name, m.liveSession!.technicianId))) return;
                        handleEndClick(m.liveSession!.sessionId!);
                      }}
                    >
                      End session
                    </button>
                  )}
                  </ToolbarMenu>
                  </span>
                </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>
    </aside>
  );
}

function formatSessionTime(iso: string): string {
  // Extract "HH:MM" from the ISO string's time component for deterministic, locale-independent
  // output — toLocaleTimeString() varies by OS and browser locale.
  const m = /T(\d{2}:\d{2})/.exec(iso);
  return m ? `${m[1]} UTC` : "unknown time";
}

function relativeTime(iso: string, now: number = Date.now()): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "unknown";
  const secs = Math.max(0, Math.round((now - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

// --- No fallback data ------------------------------------------------------
//
// There was a five-machine demo fleet here (RECEPTION-01, ACCT-WS-07, CEO-LAPTOP, DC-01,
// WAREHOUSE-KIOSK) serving as the default value of the `machines` prop. It is deliberately gone.
//
// It was introduced as a storybook/dev-shell convenience, but the prop it defaulted is the one
// `App.tsx` leaves `undefined` on EVERY control-plane load failure, so the demo fleet was what a
// real technician saw whenever they were logged out or the control plane was down: five plausible
// machine names, a `3/5 online` header, and a Connect button per row aimed at a UUID that exists
// nowhere. Measured in a browser against a control plane that was not running.
//
// A component that renders a caller's data must not manufacture data when the caller has none.
// `fleetStatus` now makes `undefined` mean unloaded, and the panel says so.
// e2e/fleet_fallback.spec.ts is the regression net.
