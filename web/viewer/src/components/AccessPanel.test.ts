/**
 * AccessPanel view-model tests — the mapping from the control plane's real `GET /machines`
 * envelope (enriched with presence/OS/group name by control-plane migrations/0017) into the
 * panel's `Machine` shape.
 *
 * The property under test throughout is that presence is TRI-STATE and stays that way: online,
 * offline, and UNKNOWN are three distinct answers, and "the presence feed is down" must never be
 * rendered as "the whole fleet is offline".
 */

import { describe, it, expect } from "vitest";
import {
  connectHint,
  filterMachines,
  machineFromRecord,
  machinesFromRecords,
  fleetStatus,
  fleetCountLabel,
  presenceHint,
  sessionHint,
  type Machine,
} from "./AccessPanel";
import type { MachineRecord } from "../lib/console_api";

const REC: MachineRecord = {
  id: "pk-1",
  tenant_id: "t-1",
  device_id: "11111111-1111-4111-8111-111111111111",
  group_id: "g-1",
  name: "RECEPTION-01",
  os: "Windows 11 Pro",
  group_name: "Acme / Front Office",
  online: true,
  last_seen: "2026-08-01T10:00:00Z",
};

describe("machineFromRecord", () => {
  it("addresses the machine by DEVICE id, never the primary key", () => {
    const m = machineFromRecord(REC, true);
    // Conflating the two would produce a Connect button aimed at a machine that does not exist.
    expect(m.device).toBe(REC.device_id);
    expect(m.device).not.toBe(REC.id);
  });

  it("carries the joined group name, OS and last-seen through", () => {
    const m = machineFromRecord(REC, true);
    expect(m.group).toBe("Acme / Front Office");
    expect(m.os).toBe("Windows 11 Pro");
    expect(m.lastSeen).toBe("2026-08-01T10:00:00Z");
    expect(m.online).toBe(true);
  });

  it("maps online=false to offline when presence IS known", () => {
    expect(machineFromRecord({ ...REC, online: false }, true).online).toBe(false);
  });

  it("maps an absent online flag to UNKNOWN, not offline, when presence is not known", () => {
    const { online: _drop, ...withoutPresence } = REC;
    const m = machineFromRecord(withoutPresence, false);
    expect(m.online).toBeUndefined();
  });

  it("refuses to assert online when the listing says presence is unknown", () => {
    // Even if a record somehow carries online:true, presenceKnown=false wins — the control plane
    // has told us it could not consult the feed, so nothing in that response is authoritative.
    expect(machineFromRecord(REC, false).online).toBeUndefined();
  });

  it("falls back to the raw group id rather than filing a machine under a blank heading", () => {
    const { group_name: _drop, ...noName } = REC;
    expect(machineFromRecord(noName, true).group).toBe("g-1");
    expect(machineFromRecord({ ...noName, group_id: "" }, true).group).toBe("Ungrouped");
  });

  it("falls back to a device-id prefix when the machine has no name", () => {
    expect(machineFromRecord({ ...REC, name: "" }, true).name).toBe("11111111");
  });

  it("reports an unknown OS and a never-seen machine without producing NaN or 'Invalid Date'", () => {
    const { os: _o, last_seen: _l, ...bare } = REC;
    const m = machineFromRecord(bare, true);
    expect(m.os).toBe("unknown OS");
    expect(m.lastSeen).toBe("");
  });
});

describe("machineFromRecord — alias", () => {
  it("carries alias through when the record has one", () => {
    const m = machineFromRecord({ ...REC, alias: "the operator's Workstation" }, true);
    expect(m.alias).toBe("the operator's Workstation");
  });

  it("leaves alias undefined when the record has no alias", () => {
    const m = machineFromRecord(REC, true);
    expect(m.alias).toBeUndefined();
  });

  it("leaves alias undefined when the record alias is an empty string", () => {
    const m = machineFromRecord({ ...REC, alias: "" }, true);
    expect(m.alias).toBeUndefined();
  });

  it("does not affect name when alias is absent — name still uses the hostname", () => {
    const m = machineFromRecord(REC, true);
    expect(m.name).toBe("RECEPTION-01");
  });
});

describe("machinesFromRecords", () => {
  it("applies the listing's presence flag to every row", () => {
    const listing = {
      machines: [REC, { ...REC, id: "pk-2", device_id: "22222222-2222-4222-8222-222222222222", online: false }],
      presenceKnown: false,
    };
    const out = machinesFromRecords(listing);
    expect(out).toHaveLength(2);
    expect(out.every((m) => m.online === undefined)).toBe(true);
  });

  it("preserves per-machine presence when the feed IS known", () => {
    const listing = {
      machines: [REC, { ...REC, id: "pk-2", device_id: "22222222-2222-4222-8222-222222222222", online: false }],
      presenceKnown: true,
    };
    expect(machinesFromRecords(listing).map((m) => m.online)).toEqual([true, false]);
  });

  it("maps an empty fleet to an empty list", () => {
    expect(machinesFromRecords({ machines: [], presenceKnown: true })).toEqual([]);
  });
});

/** A Machine for the rendering helpers, varied per test. */
function machine(over: Partial<Machine> = {}): Machine {
  return {
    device: machineFromRecord(REC, true).device,
    name: "RECEPTION-01",
    group: "Acme / Front Office",
    online: true,
    os: "Windows 11 Pro",
    lastSeen: "",
    unattended: true,
    ...over,
  };
}

describe("presenceHint", () => {
  const NOW = Date.parse("2026-08-02T12:00:00Z");

  it("says nothing for a machine that is online", () => {
    expect(presenceHint(machine({ online: true }), NOW)).toBe("");
  });

  it("distinguishes NEVER OBSERVED from a real last-seen stamp", () => {
    // The defect: last_seen is only written when a technician's page load catches the agent
    // connected, and enrollment never seeds it — so a machine that has been healthy since
    // enrollment rendered "last seen never", the strongest possible claim that it is dead.
    expect(presenceHint(machine({ online: false, lastSeen: "" }), NOW)).toBe(
      "not seen since enrollment",
    );
    expect(presenceHint(machine({ online: false, lastSeen: "" }), NOW)).not.toContain("never");
    expect(presenceHint(machine({ online: false, lastSeen: "2026-08-02T09:00:00Z" }), NOW)).toBe(
      "last seen 3h ago",
    );
  });

  it("reports unknown presence as unavailable, never as a last-seen claim", () => {
    expect(presenceHint(machine({ online: undefined, lastSeen: "" }), NOW)).toBe(
      "status unavailable",
    );
    // Even with a stamp on hand, "the feed is down" is what we know — not "offline since then".
    expect(presenceHint(machine({ online: undefined, lastSeen: "2026-08-02T09:00:00Z" }), NOW)).toBe(
      "status unavailable",
    );
  });

  it("does not render an unparseable stamp as a date", () => {
    expect(presenceHint(machine({ online: false, lastSeen: "not-a-date" }), NOW)).toBe(
      "last seen unknown",
    );
  });
});

describe("connectHint", () => {
  // Connect is never disabled — presence is a cached read of a feed that can be stale, wrong, or
  // unreachable, and the session attempt is the authoritative test. These strings are the only
  // place the panel's belief reaches the button, so they must actually differ per state.
  it("tells the technician the attempt will proceed regardless of the believed state", () => {
    const offline = connectHint(machine({ online: false }));
    const unknown = connectHint(machine({ online: undefined }));
    const online = connectHint(machine({ online: true }));
    expect(offline).toMatch(/offline/i);
    expect(offline).toMatch(/anyway/i);
    expect(unknown).toMatch(/unavailable/i);
    expect(unknown).toMatch(/anyway/i);
    expect(new Set([offline, unknown, online]).size).toBe(3);
  });
});

describe("fleetStatus / fleetCountLabel", () => {
  // The defect these pin: `machines` was an optional prop DEFAULTED to a five-machine demo fleet,
  // and `App.tsx` leaves it `undefined` on every control-plane load failure. A logged-out
  // technician therefore saw "3/5 online" over five fabricated machines, each with a Connect button
  // aimed at a UUID that exists nowhere. The panel is not permitted to invent a fleet, and it is
  // not permitted to report "no machines enrolled" when the truth is "we never got an answer".

  it("distinguishes NOT LOADED from a genuinely empty fleet", () => {
    expect(fleetStatus(undefined)).toEqual({ kind: "unloaded" });
    expect(fleetStatus([])).toEqual({ kind: "empty" });
    // The whole point: these two must not collapse into each other.
    expect(fleetStatus(undefined)).not.toEqual(fleetStatus([]));
    expect(fleetCountLabel(fleetStatus(undefined))).not.toBe(fleetCountLabel(fleetStatus([])));
  });

  it("never renders a numeric tally for a fleet it has not loaded", () => {
    // A label containing digits is the failure signature: "3/5 online" is exactly what an operator
    // reads as a real, populated fleet.
    expect(fleetCountLabel(fleetStatus(undefined))).not.toMatch(/\d/);
    expect(fleetCountLabel(fleetStatus(undefined))).toMatch(/unavailable/i);
  });

  it("counts only machines KNOWN to be online, and says so", () => {
    const s = fleetStatus([
      machine({ online: true }),
      machine({ online: true }),
      machine({ online: false }),
      machine({ online: undefined }),
    ]);
    expect(s).toEqual({ kind: "loaded", total: 4, online: 2, presenceKnown: true });
    expect(fleetCountLabel(s)).toBe("2/4 online");
  });

  it("reports the whole listing as status-unavailable only when EVERY row is unknown", () => {
    const allUnknown = fleetStatus([machine({ online: undefined }), machine({ online: undefined })]);
    expect(allUnknown).toMatchObject({ kind: "loaded", presenceKnown: false });
    expect(fleetCountLabel(allUnknown)).toBe("2 machines · status unavailable");

    // One known row is enough to make the tally meaningful — `every`, not `some`. Mutating that
    // predicate would make a single unknown machine suppress the count for the entire fleet.
    const oneKnown = fleetStatus([machine({ online: undefined }), machine({ online: true })]);
    expect(oneKnown).toMatchObject({ kind: "loaded", presenceKnown: true });
    expect(fleetCountLabel(oneKnown)).toBe("1/2 online");
  });
});

const LIVE_SESSION = { sessionId: "session-uuid-1", startedAt: "2026-09-26T14:32:00Z", technicianId: "tech@acme.com" };

describe("machineFromRecord — liveSession", () => {
  it("passes a live session through when provided", () => {
    const m = machineFromRecord(REC, true, LIVE_SESSION);
    expect(m.liveSession).toEqual(LIVE_SESSION);
  });

  it("leaves liveSession undefined when not provided", () => {
    const m = machineFromRecord(REC, true);
    expect(m.liveSession).toBeUndefined();
  });

  it("leaves liveSession undefined when explicitly passed undefined", () => {
    const m = machineFromRecord(REC, true, undefined);
    expect(m.liveSession).toBeUndefined();
  });
});

describe("machinesFromRecords — liveSessionsByDevice", () => {
  const DEVICE_A = "11111111-1111-4111-8111-111111111111";
  const DEVICE_B = "22222222-2222-4222-8222-222222222222";
  const REC_B: MachineRecord = { ...REC, id: "pk-2", device_id: DEVICE_B, online: false };

  it("attaches a live session to the matching machine by device id", () => {
    const listing = { machines: [REC, REC_B], presenceKnown: true };
    const byDevice = new Map([[DEVICE_A, LIVE_SESSION]]);
    const out = machinesFromRecords(listing, byDevice);
    expect(out[0].liveSession).toEqual(LIVE_SESSION);
    expect(out[1].liveSession).toBeUndefined();
  });

  it("leaves all sessions undefined when no map is supplied", () => {
    const listing = { machines: [REC, REC_B], presenceKnown: true };
    const out = machinesFromRecords(listing);
    expect(out.every((m) => m.liveSession === undefined)).toBe(true);
  });

  it("leaves all sessions undefined when an explicit empty Map is supplied", () => {
    const listing = { machines: [REC, REC_B], presenceKnown: true };
    const out = machinesFromRecords(listing, new Map());
    expect(out.every((m) => m.liveSession === undefined)).toBe(true);
  });

  it("leaves sessions undefined for machines absent from the map", () => {
    const listing = { machines: [REC, REC_B], presenceKnown: true };
    const byDevice = new Map([["99999999-9999-4999-8999-999999999999", LIVE_SESSION]]);
    const out = machinesFromRecords(listing, byDevice);
    expect(out.every((m) => m.liveSession === undefined)).toBe(true);
  });
});

describe("machineFromRecord — liveSession.sessionId", () => {
  it("carries sessionId through to the Machine view model", () => {
    const m = machineFromRecord(REC, true, { sessionId: "s-abc", startedAt: "2026-09-26T10:00:00Z", technicianId: "t@x.com" });
    expect(m.liveSession?.sessionId).toBe("s-abc");
  });

  it("accepts a liveSession without sessionId (backward-compat with pre-sessionId code)", () => {
    const m = machineFromRecord(REC, true, { startedAt: "2026-09-26T10:00:00Z", technicianId: "t@x.com" });
    expect(m.liveSession).toBeDefined();
    expect(m.liveSession?.sessionId).toBeUndefined();
  });

  it("machinesFromRecords propagates sessionId from the device map", () => {
    const DEVICE_A = "11111111-1111-4111-8111-111111111111";
    const listing = { machines: [REC], presenceKnown: true };
    const byDevice = new Map([[DEVICE_A, { sessionId: "s-xyz", startedAt: "2026-09-26T11:00:00Z", technicianId: "admin@x.com" }]]);
    const out = machinesFromRecords(listing, byDevice);
    expect(out[0].liveSession?.sessionId).toBe("s-xyz");
  });
});

describe("filterMachines", () => {
  const base = machine();
  const withAlias = machine({ alias: "the operator's Workstation", name: "DESKTOP-ABC" });
  const offline = machine({ online: false });
  const unknown = machine({ online: undefined });

  it("returns the same array reference when query is empty and onlineOnly is false", () => {
    const arr = [base, withAlias];
    expect(filterMachines(arr, "", false)).toBe(arr);
    expect(filterMachines(arr, "   ", false)).toBe(arr);
  });

  it("matches a device ID even when its display name differs", () => {
    const target = machine({ device: REC.device_id as Machine["device"], name: "Workstation" });
    expect(filterMachines([target, machine({ device: "other" as Machine["device"] })], "1111-4111", false)).toEqual([target]);
  });

  it("matches by alias (case-insensitive)", () => {
    const result = filterMachines([base, withAlias], "workstation", false);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(withAlias);
  });

  it("matches by hostname when alias is absent", () => {
    const result = filterMachines([base, withAlias], "reception", false);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(base);
  });

  it("does not match hostname when alias is present and only alias matches the query", () => {
    // Query matches alias of withAlias ("workstation"), but not alias of base (no alias).
    // base.name is RECEPTION-01 — "workstation" doesn't match it.
    const result = filterMachines([base, withAlias], "workstation", false);
    expect(result).not.toContain(base);
  });

  it("matches by group (case-insensitive)", () => {
    const inGroup = machine({ group: "Support Team" });
    const result = filterMachines([base, inGroup], "support", false);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(inGroup);
  });

  it("matches by OS (case-insensitive)", () => {
    const win10 = machine({ os: "Windows 10 Pro" });
    const result = filterMachines([base, win10], "windows 10", false);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(win10);
  });

  it("onlineOnly hides offline but keeps UNKNOWN presence machines (tri-state rule)", () => {
    const result = filterMachines([base, offline, unknown], "", true);
    expect(result).toContain(base);
    expect(result).not.toContain(offline);
    expect(result).toContain(unknown);
  });

  it("combines onlineOnly and text query", () => {
    const offlineWithAlias = machine({ online: false, alias: "the operator's Workstation" });
    const result = filterMachines([base, offlineWithAlias], "workstation", true);
    // offlineWithAlias matches query but is filtered by onlineOnly.
    expect(result).toHaveLength(0);
  });
});

describe("sessionHint", () => {
  it("returns empty string when there is no live session", () => {
    expect(sessionHint(machine())).toBe("");
  });

  it("includes the formatted start time and technician id", () => {
    const hint = sessionHint(machine({ liveSession: LIVE_SESSION }));
    expect(hint).toContain("14:32 UTC");
    expect(hint).toContain("tech@acme.com");
    expect(hint).toMatch(/active since/i);
  });

  it("handles a malformed ISO timestamp without throwing", () => {
    const hint = sessionHint(machine({ liveSession: { startedAt: "not-a-date", technicianId: "t@x.com" } }));
    expect(hint).toContain("unknown time");
    expect(hint).toContain("t@x.com");
  });

  it("produces different strings for sessions at different times", () => {
    const a = sessionHint(machine({ liveSession: { startedAt: "2026-09-26T09:00:00Z", technicianId: "t@x.com" } }));
    const b = sessionHint(machine({ liveSession: { startedAt: "2026-09-26T17:45:00Z", technicianId: "t@x.com" } }));
    expect(a).not.toBe(b);
    expect(a).toContain("09:00 UTC");
    expect(b).toContain("17:45 UTC");
  });
});
