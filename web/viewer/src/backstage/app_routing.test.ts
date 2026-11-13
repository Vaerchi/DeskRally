/**
 * V2 App channel-routing contract.
 *
 * `App.tsx` builds a single `onMessage(channel, payload)` that must route `ChannelId.Control` frames
 * to the `ControlClient` and `ChannelId.Backstage` frames to the `ChannelBackstageTransport` —
 * without either channel consuming the other's frames (the Backstage FIFO correlation must not be
 * advanced by a Control frame, and vice-versa). App is `.tsx` and the vitest env is `node`, so rather
 * than render the component we exercise the exact routing rule over the real clients it composes.
 */

import { describe, it, expect } from "vitest";

import { ChannelId, ControlClient, encodeControl, type MonitorDesc } from "../lib";
import { BackstageClient, type Envelope } from "./client";
import { ChannelBackstageTransport } from "./channel";

const encoder = new TextEncoder();

/** Build the two live clients + the App-shaped router that fans inbound frames out by channel. */
function wire() {
  let monitors: MonitorDesc[] = [];
  const controlSent: Uint8Array[] = [];
  const control = new ControlClient((p) => controlSent.push(p), {
    onMonitors: (list) => (monitors = [...list]),
  });

  const backstageSent: Uint8Array[] = [];
  const backstage = new ChannelBackstageTransport((p) => backstageSent.push(p));
  const client = new BackstageClient(backstage.asBackstageTransport());

  // Byte-for-byte the routing in App.tsx's `onMessage`.
  const route = (channel: ChannelId, payload: Uint8Array) => {
    if (channel === ChannelId.Control) control.handleMessage(payload);
    else if (channel === ChannelId.Backstage) backstage.handleMessage(payload);
  };

  return { route, client, backstage, controlSent, backstageSent, monitors: () => monitors };
}

describe("App inbound-frame routing (Control vs Backstage)", () => {
  it("routes each channel to its own client without collision", async () => {
    const w = wire();

    // A backstage request is in flight, awaiting its reply frame.
    const pending = w.client.getSystemInfo();
    expect(w.backstageSent).toHaveLength(1);

    // A Control frame arrives first. It must update the monitor list AND must NOT resolve the
    // in-flight backstage request (no cross-channel correlation theft).
    const monitorList: MonitorDesc[] = [{ id: 1, width: 1920, height: 1080, primary: true }];
    w.route(ChannelId.Control, encodeControl({ t: "MonitorList", c: { monitors: monitorList } }));
    expect(w.monitors()).toEqual(monitorList);

    let settled = false;
    void pending.then(() => (settled = true));
    await Promise.resolve();
    expect(settled, "control frame must not resolve a backstage request").toBe(false);

    // Now the matching Backstage envelope arrives and resolves the request.
    const env: Envelope = {
      ok: true,
      response: { type: "SystemInfo", data: { hostname: "ROUTED-HOST" } as never },
      audit: { hash: "deadbeefcafef00d", outcome: "authorized", action: "GetSystemInfo" },
    };
    w.route(ChannelId.Backstage, encoder.encode(JSON.stringify(env)));

    const result = await pending;
    expect(result.response?.type).toBe("SystemInfo");
    expect(result.audit?.hash).toBe("deadbeefcafef00d");
  });

  it("ignores channels it does not handle (input/clipboard/file) — no throw, no consume", async () => {
    const w = wire();
    const pending = w.client.listProcesses();

    // A frame on an unrelated channel must be dropped, not routed to backstage's FIFO.
    w.route(ChannelId.FileTransfer, encoder.encode("garbage"));

    let settled = false;
    void pending.then(() => (settled = true));
    await Promise.resolve();
    expect(settled).toBe(false);

    w.route(
      ChannelId.Backstage,
      encoder.encode(JSON.stringify({ ok: true, response: { type: "ProcessList", data: [] } })),
    );
    expect((await pending).response?.type).toBe("ProcessList");
  });
});
