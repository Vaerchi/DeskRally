/**
 * M2 brokered-connect wiring: `App.tsx` starts a control-plane session first
 * (`acquireBrokeredSession`), dials the RETURNED signaling URL, presents the signed session
 * ticket in `connect_request`, and ends the session best-effort on teardown
 * (`releaseBrokeredSession`). Following `m3_wiring.test.ts` / `grant_flow.test.ts`, we drive the
 * exact flows through the REAL `ConsoleApiClient` (fake fetch mirroring the control plane's
 * `POST /sessions` wire shape) and the REAL `SignalingClient` (stubbed global WebSocket), proving
 * the ticket flows verbatim from the HTTP response into the connect_request JSON — and that the
 * direct-connect fallback stays ticketless when the control plane is unreachable.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { ConsoleApiClient, type SessionSignaling, type SessionRecord } from "./lib/console_api";
import { acquireBrokeredSession, releaseBrokeredSession } from "./lib/session_broker";
import { SignalingClient } from "./lib/transport";
import { asDeviceId, type SignedSessionTicket } from "./lib/protocol";

const DEVICE = "33333333-3333-4333-8333-333333333333";

const TICKET: SignedSessionTicket = {
  claims: {
    v: 1,
    session_id: "s-1",
    technician_id: "u-1",
    tenant_id: "t-1",
    device_id: DEVICE,
    iat_ms: 1730000000000,
    exp_ms: 1730000120000,
  },
  sig: "ab".repeat(64),
};

const RECORD: SessionRecord = {
  id: "s-1",
  tenant_id: "t-1",
  machine_id: "pk-1",
  technician_id: "u-1",
  started_at: "2026-07-28T12:00:00Z",
  consent_policy: "none",
  granted_caps: null,
  machine_group_id: "g-1",
  machine_device_id: DEVICE,
  machine_name: "M",
  machine_alias: "",
  note: "",
};

const SIGNALING: SessionSignaling = {
  url: "ws://cp-signal.example:8080/ws",
  device_id: DEVICE,
  session_id: "s-1",
  ticket: TICKET,
};

/** Minimal WebSocket stand-in: opens on a microtask, records every sent payload. */
class FakeWebSocket {
  static OPEN = 1;
  static instances: FakeWebSocket[] = [];
  readyState = FakeWebSocket.OPEN;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((ev: unknown) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => this.onopen?.());
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {}
}

afterEach(() => {
  FakeWebSocket.instances = [];
  vi.unstubAllGlobals();
});

describe("M2 brokered connect wiring", () => {
  it("start → returned signaling URL → connect_request carries the ticket verbatim", async () => {
    const posts: { url: string; body: unknown }[] = [];
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: (url, init) => {
        posts.push({ url, body: init?.body });
        return Promise.resolve(
          new Response(JSON.stringify({ session: RECORD, signaling: SIGNALING }), { status: 201 }),
        );
      },
    });

    const brokered = await acquireBrokeredSession(api, DEVICE);
    expect(posts[0].url).toBe("/cp/sessions");
    expect(JSON.parse(posts[0].body as string)).toEqual({ machine_id: DEVICE });
    expect(brokered).not.toBeNull();
    expect(brokered!.sessionId).toBe("s-1");
    expect(brokered!.signaling.url).toBe(SIGNALING.url);

    // Mirror App.handleConnect: dial the RETURNED url, present the ticket in connect_request.
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const signaling = new SignalingClient(brokered!.signaling.url);
    await signaling.open();
    signaling.requestConnect(asDeviceId(DEVICE), brokered!.signaling.ticket);

    const ws = FakeWebSocket.instances[0];
    expect(ws.url).toBe(SIGNALING.url);
    expect(JSON.parse(ws.sent[0])).toEqual({ type: "connect_request", target: DEVICE, ticket: TICKET });
  });

  it("control plane unreachable → null, and the fallback connect_request stays ticketless", async () => {
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: () => Promise.reject(new Error("connection refused")),
    });
    const brokered = await acquireBrokeredSession(api, DEVICE);
    expect(brokered).toBeNull();

    // Mirror the fallback: operator-entered URL, no ticket field on the wire at all.
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const signaling = new SignalingClient("ws://127.0.0.1:8080/ws");
    await signaling.open();
    signaling.requestConnect(asDeviceId(DEVICE), brokered?.signaling.ticket);
    const sent = JSON.parse(FakeWebSocket.instances[0].sent[0]) as Record<string, unknown>;
    expect(sent).toEqual({ type: "connect_request", target: DEVICE });
    expect("ticket" in sent).toBe(false);
  });

  it("a session without a signaling envelope (no issuer wired) falls back to direct connect", async () => {
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: () =>
        Promise.resolve(new Response(JSON.stringify({ session: RECORD }), { status: 201 })),
    });
    expect(await acquireBrokeredSession(api, DEVICE)).toBeNull();
  });

  it("a denied start (403) throws DeviceAccessDeniedError (fail-closed, not null fallback)", async () => {
    // 403 Forbidden: authenticated but not authorized for this device. The viewer must fail-closed
    // and show a device-refusal error rather than silently falling back to ticketless direct-connect.
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: () =>
        Promise.resolve(new Response(JSON.stringify({ error: "denied" }), { status: 403 })),
    });
    // acquireBrokeredSession now re-throws the ConsoleApiError for 403 (kind="forbidden").
    await expect(acquireBrokeredSession(api, DEVICE)).rejects.toMatchObject({
      name: "ConsoleApiError",
      kind: "forbidden",
      status: 403,
    });
  });

  it("a 5xx / unreachable start still falls back to null (dev direct-connect path preserved)", async () => {
    // 503 / network error: CP is not reachable. acquireBrokeredSession returns null so the
    // dev/direct-connect path proceeds (as tested in the existing unreachable case above, which
    // uses a rejected promise; this verifies the HTTP-error variant).
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: () =>
        Promise.resolve(new Response(JSON.stringify({ error: "no broker" }), { status: 503 })),
    });
    expect(await acquireBrokeredSession(api, DEVICE)).toBeNull();
  });

  it("releaseBrokeredSession fires POST /sessions/{id}/end best-effort on disconnect", async () => {
    const calls: string[] = [];
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: (url) => {
        calls.push(url);
        return Promise.resolve(
          new Response(JSON.stringify({ session: { ...RECORD, ended_at: "2026-07-28T12:30:00Z" } }), {
            status: 200,
          }),
        );
      },
    });

    releaseBrokeredSession(api, "s-1");
    await Promise.resolve(); // let the fire-and-forget request run
    expect(calls).toEqual(["/cp/sessions/s-1/end"]);

    // No brokered session → no call; a failing end is swallowed (disconnect must never throw).
    releaseBrokeredSession(api, null);
    expect(calls).toHaveLength(1);
    const failing = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: () => Promise.reject(new Error("gone")),
    });
    expect(() => releaseBrokeredSession(failing, "s-1")).not.toThrow();
    await new Promise((r) => setTimeout(r, 0)); // surface an unhandled rejection if any
  });
});

describe("the signed session policy reaches the connect path", () => {
  it("acquireBrokeredSession carries session_policy through as sessionPolicy", async () => {
    // The second half of the loop-80 regression: even once startBrokeredSession plucks the field, the
    // broker has to hand it on, or App.tsx never sees it. Both hops are asserted so a future refactor
    // cannot quietly drop either.
    const api = {
      startBrokeredSession: async () => ({
        session: { id: "s-9" } as never,
        signaling: { url: "ws://x/ws", device_id: "d-9", session_id: "s-9", ticket: {} } as never,
        session_policy: { access: "view_only", signed: '{"claims":{},"sig":"ab"}' },
      }),
    };
    const brokered = await acquireBrokeredSession(api as never, "d-9");
    expect(brokered?.sessionPolicy).toEqual({
      access: "view_only",
      signed: '{"claims":{},"sig":"ab"}',
    });
  });

  it("leaves sessionPolicy undefined when the control plane minted none", async () => {
    const api = {
      startBrokeredSession: async () => ({
        session: { id: "s-9" } as never,
        signaling: { url: "ws://x/ws", device_id: "d-9", session_id: "s-9", ticket: {} } as never,
      }),
    };
    const brokered = await acquireBrokeredSession(api as never, "d-9");
    expect(brokered?.sessionPolicy).toBeUndefined();
  });
});
