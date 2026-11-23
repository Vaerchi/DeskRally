/**
 * Multi-tech (Multi-Tech) unit tests.
 *
 * Exercises:
 *  - decodeSignaling correctly parses session_participants messages
 *  - SessionParticipantEntry shape is correct
 *  - machineFromRecord propagates multi_session_capable through the view model
 *  - machinesFromRecords propagates multi_session_capable for each machine
 *  - Tri-state nil / false / true are all distinguishable after the round-trip
 *
 * All logic is in pure functions (no React, no DOM), so these run in the vitest
 * node environment without a renderer.
 */

import { describe, it, expect } from "vitest";
import { decodeSignaling, type SessionParticipantEntry } from "./lib/protocol";
import { machineFromRecord, machinesFromRecords } from "./components/AccessPanel";
import type { MachineRecord, MachineListing } from "./lib/console_api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRecord(overrides: Partial<MachineRecord> = {}): MachineRecord {
  return {
    id: "db-id-1",
    tenant_id: "tenant-1",
    device_id: "2b948dba-0000-4000-8000-000000000001",
    group_id: "group-1",
    name: "TEST-PC",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// decodeSignaling — session_participants
// ---------------------------------------------------------------------------

describe("decodeSignaling — session_participants", () => {
  it("decodes a session_participants message with one participant", () => {
    const json = JSON.stringify({
      type: "session_participants",
      device_id: "agent-1",
      participants: [{ session_id: "sess-a", technician_id: "tech-1" }],
    });
    const msg = decodeSignaling(json);
    expect(msg.type).toBe("session_participants");
    if (msg.type !== "session_participants") return;
    expect(msg.device_id).toBe("agent-1");
    expect(msg.participants).toHaveLength(1);
    expect(msg.participants[0].session_id).toBe("sess-a");
    expect(msg.participants[0].technician_id).toBe("tech-1");
  });

  it("decodes a session_participants message with two participants", () => {
    const json = JSON.stringify({
      type: "session_participants",
      device_id: "agent-1",
      participants: [
        { session_id: "sess-a", technician_id: "tech-1" },
        { session_id: "sess-b", technician_id: "tech-2" },
      ],
    });
    const msg = decodeSignaling(json);
    if (msg.type !== "session_participants") throw new Error("wrong type");
    expect(msg.participants).toHaveLength(2);
    expect(msg.participants[1].session_id).toBe("sess-b");
  });

  it("decodes a session_participants message with no participants (empty array)", () => {
    const json = JSON.stringify({
      type: "session_participants",
      device_id: "agent-1",
      participants: [],
    });
    const msg = decodeSignaling(json);
    if (msg.type !== "session_participants") throw new Error("wrong type");
    expect(msg.participants).toHaveLength(0);
  });

  it("decodes a participant with no technician_id (unauthenticated/dev path)", () => {
    const json = JSON.stringify({
      type: "session_participants",
      device_id: "agent-1",
      participants: [{ session_id: "sess-x" }],
    });
    const msg = decodeSignaling(json);
    if (msg.type !== "session_participants") throw new Error("wrong type");
    const entry: SessionParticipantEntry = msg.participants[0];
    expect(entry.session_id).toBe("sess-x");
    expect(entry.technician_id).toBeUndefined();
  });

  it("does not confuse session_participants with other message types", () => {
    const json = JSON.stringify({ type: "registered", server_pubkey: "abcdef" });
    const msg = decodeSignaling(json);
    expect(msg.type).toBe("registered");
    expect(msg.type).not.toBe("session_participants");
  });
});

// ---------------------------------------------------------------------------
// machineFromRecord — multi_session_capable tri-state
// ---------------------------------------------------------------------------

describe("machineFromRecord — multi_session_capable", () => {
  it("maps multi_session_capable: true to Machine.multiSessionCapable === true", () => {
    const rec = makeRecord({ multi_session_capable: true });
    const m = machineFromRecord(rec, true);
    expect(m.multiSessionCapable).toBe(true);
  });

  it("maps multi_session_capable: false to Machine.multiSessionCapable === false", () => {
    const rec = makeRecord({ multi_session_capable: false });
    const m = machineFromRecord(rec, true);
    expect(m.multiSessionCapable).toBe(false);
  });

  it("maps absent multi_session_capable to Machine.multiSessionCapable === undefined", () => {
    const rec = makeRecord(); // no multi_session_capable field
    const m = machineFromRecord(rec, true);
    expect(m.multiSessionCapable).toBeUndefined();
  });

  it("distinguishes false from undefined (nil vs false)", () => {
    const recFalse = makeRecord({ multi_session_capable: false });
    const recNil = makeRecord();
    const mFalse = machineFromRecord(recFalse, true);
    const mNil = machineFromRecord(recNil, true);
    expect(mFalse.multiSessionCapable).toBe(false);
    expect(mNil.multiSessionCapable).toBeUndefined();
    expect(mFalse.multiSessionCapable).not.toBe(mNil.multiSessionCapable);
  });
});

// ---------------------------------------------------------------------------
// machinesFromRecords — propagation through whole mapping
// ---------------------------------------------------------------------------

describe("machinesFromRecords — multi_session_capable propagation", () => {
  it("propagates multi_session_capable for each machine independently", () => {
    const listing: MachineListing = {
      presenceKnown: true,
      machines: [
        makeRecord({ device_id: "dev-a", name: "A", multi_session_capable: true }),
        makeRecord({ device_id: "dev-b", name: "B", multi_session_capable: false }),
        makeRecord({ device_id: "dev-c", name: "C" }),
      ],
    };
    const machines = machinesFromRecords(listing);
    // DeviceId is a branded string; cast to string to build a plain-string-keyed Map for lookup.
    const byDevice = new Map(machines.map((m) => [m.device as string, m]));
    expect(byDevice.get("dev-a")!.multiSessionCapable).toBe(true);
    expect(byDevice.get("dev-b")!.multiSessionCapable).toBe(false);
    expect(byDevice.get("dev-c")!.multiSessionCapable).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// decodeSignaling — brokered message (signaling session id)
// ---------------------------------------------------------------------------
//
// App.tsx reads msg.session from the "brokered" signaling message to capture the
// signaling-level session id that session_participants entries use. This is DISTINCT
// from the CP record id returned by POST /sessions (brokered.sessionId in session_broker.ts).

describe("decodeSignaling — brokered message", () => {
  it("decodes a brokered message and exposes the signaling session id", () => {
    const json = JSON.stringify({
      type: "brokered",
      session: "sig-sess-abc-123",
      peer_device: "device-peer",
      peer_pubkey: "ed25519:peer",
    });
    const msg = decodeSignaling(json);
    expect(msg.type).toBe("brokered");
    if (msg.type !== "brokered") return;
    // This is the id that appears in session_participants entries — NOT the CP record id.
    expect(msg.session).toBe("sig-sess-abc-123");
  });

  it("brokered session id is distinct from a hypothetical CP record id", () => {
    // The CP record id (from POST /sessions response) is "cp-record-id-999".
    // The signaling server independently generates "sig-sess-abc-123" at broker time.
    // Filtering participants by the CP record id would wrongly include self.
    const cpRecordId = "cp-record-id-999";
    const json = JSON.stringify({
      type: "brokered",
      session: "sig-sess-abc-123",
      peer_device: "device-peer",
      peer_pubkey: "ed25519:peer",
    });
    const msg = decodeSignaling(json);
    if (msg.type !== "brokered") throw new Error("wrong type");
    expect(msg.session).not.toBe(cpRecordId); // the two ids differ — self-filter must use msg.session
    expect(msg.session).toBe("sig-sess-abc-123");
  });
});

// ---------------------------------------------------------------------------
// Co-participant filtering (the logic App.tsx applies to session_participants)
// ---------------------------------------------------------------------------
//
// App.tsx filters msg.participants using the signaling session id captured from the
// "brokered" message — not the CP record id. These tests verify the filtering logic.
// The correct wire-up (signaling id used, not CP id) is proven by the e2e test
// "session_participants self-filter uses signaling session ID, not CP record ID" in
// multi_tab_lifecycle.spec.ts.

/** Mirror of App.tsx's participant filtering logic (pure, no React). */
function filterPeers(
  participants: SessionParticipantEntry[],
  ownSignalingSessionId: string | null,
): SessionParticipantEntry[] {
  return ownSignalingSessionId
    ? participants.filter((p) => p.session_id !== ownSignalingSessionId)
    : participants;
}

describe("co-participant filtering — own signaling session excluded", () => {
  it("filters own signaling session from a two-participant list leaving one co-tech", () => {
    const participants: SessionParticipantEntry[] = [
      { session_id: "sig-sess-own", technician_id: "tech-me" },
      { session_id: "sig-sess-peer", technician_id: "tech-peer" },
    ];
    const peers = filterPeers(participants, "sig-sess-own");
    expect(peers).toHaveLength(1);
    expect(peers[0].session_id).toBe("sig-sess-peer");
    expect(peers[0].technician_id).toBe("tech-peer");
  });

  it("returns empty array when only self is connected (no co-techs)", () => {
    const participants: SessionParticipantEntry[] = [{ session_id: "sig-sess-own" }];
    const peers = filterPeers(participants, "sig-sess-own");
    expect(peers).toHaveLength(0);
  });

  it("includes all participants when signaling session id is unknown (direct-connect path)", () => {
    const participants: SessionParticipantEntry[] = [
      { session_id: "sess-a" },
      { session_id: "sess-b" },
    ];
    const peers = filterPeers(participants, null);
    expect(peers).toHaveLength(2);
  });

  it("handles three participants: self + two co-techs", () => {
    const participants: SessionParticipantEntry[] = [
      { session_id: "sig-sess-own", technician_id: "me" },
      { session_id: "sig-sess-peer-1", technician_id: "alice" },
      { session_id: "sig-sess-peer-2", technician_id: "bob" },
    ];
    const peers = filterPeers(participants, "sig-sess-own");
    expect(peers).toHaveLength(2);
    expect(peers.map((p) => p.session_id)).toEqual(["sig-sess-peer-1", "sig-sess-peer-2"]);
  });

  it("does NOT filter when filtering by CP record id (the wrong id)", () => {
    // Demonstrates the bug the fix addresses: if we used the CP record id instead of the
    // signaling session id, self would not be filtered (the ids are distinct on the wire).
    const cpRecordId = "cp-record-id-999";
    const signalingSessionId = "sig-sess-abc-123";
    const participants: SessionParticipantEntry[] = [
      { session_id: signalingSessionId, technician_id: "tech-me" }, // self, using signaling id
      { session_id: "peer-sess", technician_id: "tech-peer" },
    ];
    // Wrong: filter by CP record id — self is NOT removed (wrong id)
    const wrongPeers = filterPeers(participants, cpRecordId);
    expect(wrongPeers).toHaveLength(2); // self is incorrectly included
    // Correct: filter by signaling session id — self IS removed
    const correctPeers = filterPeers(participants, signalingSessionId);
    expect(correctPeers).toHaveLength(1);
    expect(correctPeers[0].session_id).toBe("peer-sess");
  });
});

// ---------------------------------------------------------------------------
// device_id guard — session_participants from wrong device must be ignored
// ---------------------------------------------------------------------------
//
// App.tsx checks `msg.device_id !== device` before updating state.
// These tests verify the wire type carries device_id so the guard can work.

describe("session_participants — device_id guard", () => {
  it("carries device_id in the decoded message for the guard check", () => {
    const json = JSON.stringify({
      type: "session_participants",
      device_id: "device-connected",
      participants: [{ session_id: "sess-a" }],
    });
    const msg = decodeSignaling(json);
    if (msg.type !== "session_participants") throw new Error("wrong type");
    // The guard in App.tsx: if (msg.device_id !== device) return;
    expect(msg.device_id).toBe("device-connected");
    expect(msg.device_id).not.toBe("device-other");
  });

  it("a message for a different device has a distinct device_id", () => {
    const json = JSON.stringify({
      type: "session_participants",
      device_id: "device-other",
      participants: [{ session_id: "sess-b", technician_id: "intruder" }],
    });
    const msg = decodeSignaling(json);
    if (msg.type !== "session_participants") throw new Error("wrong type");
    const connectedDevice = "device-connected";
    // The guard must reject this message: device_id does not match connected device.
    expect(msg.device_id !== connectedDevice).toBe(true);
  });
});
