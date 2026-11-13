/**
 * Observer design v2, the transport's own fail-closed check: an OBSERVE connection whose `brokered`
 * reply does not say `access: "view_only"`, `access_version: 1` fails BEFORE any offer is created,
 * so nothing is negotiated with a server that would broker a controlling session. The App also
 * disconnects on that reply; this test pins the transport layer by itself, which the browser spec
 * cannot separate from the App's check.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OBSERVE_UNSUPPORTED, SignalingClient, WebRTCTransport } from "./transport";
import type { ServerToClient } from "./protocol";

class FakeSignaling {
  handlers = new Set<(msg: ServerToClient) => void>();
  sent: string[] = [];
  onMessage(h: (msg: ServerToClient) => void) {
    this.handlers.add(h);
    return () => this.handlers.delete(h);
  }
  requestConnect() { this.sent.push("connect_request"); }
  sendSdp() { this.sent.push("sdp"); }
  trickle() { this.sent.push("candidate"); }
  emit(msg: ServerToClient) { for (const h of this.handlers) h(msg); }
}

let offers = 0;
class FakePeer {
  connectionState = "new";
  onconnectionstatechange: (() => void) | null = null;
  ontrack: unknown = null;
  onicecandidate: unknown = null;
  createDataChannel() { return { readyState: "connecting", send() {}, close() {} }; }
  addTransceiver() {}
  createOffer() { offers++; return Promise.resolve({ type: "offer", sdp: "v=0" }); }
  setLocalDescription() { return Promise.resolve(); }
  close() { this.connectionState = "closed"; }
}

const brokered = (extra: Record<string, unknown>) =>
  ({ type: "brokered", session: "s", peer_device: "d", peer_pubkey: "k", ...extra }) as unknown as ServerToClient;

async function run(requireViewOnlyBrokered: boolean, extra: Record<string, unknown>) {
  const signaling = new FakeSignaling();
  const errors: string[] = [];
  const t = new WebRTCTransport(
    { signaling: signaling as unknown as SignalingClient, requireViewOnlyBrokered },
    { onError: (e) => errors.push(e.message) },
  );
  void t.connect("d" as never).catch(() => {});
  signaling.emit(brokered(extra));
  await new Promise((r) => setTimeout(r, 0));
  t.close();
  return { signaling, errors, state: t.state };
}

describe("observe: the transport refuses a non-view-only brokered reply before negotiating", () => {
  beforeEach(() => {
    offers = 0;
    vi.stubGlobal("RTCPeerConnection", FakePeer);
  });
  afterEach(() => vi.unstubAllGlobals());

  for (const [name, extra] of [
    ["no access (older signaling)", {}],
    ["control", { access: "control", access_version: 1 }],
    ["view_only without the marker", { access: "view_only" }],
    ["unknown marker", { access: "view_only", access_version: 2 }],
  ] as const) {
    it(`refuses ${name}`, async () => {
      const { signaling, errors } = await run(true, extra);
      expect(offers, "no offer may be created").toBe(0);
      expect(signaling.sent).not.toContain("sdp");
      expect(errors).toContain(OBSERVE_UNSUPPORTED);
    });
  }

  it("negotiates a view_only brokered reply for an observe", async () => {
    const { signaling, errors } = await run(true, { access: "view_only", access_version: 1 });
    expect(offers).toBe(1);
    expect(signaling.sent).toContain("sdp");
    expect(errors).not.toContain(OBSERVE_UNSUPPORTED);
  });

  it("a normal connect ignores access entirely (unchanged behaviour)", async () => {
    const { signaling } = await run(false, {});
    expect(offers).toBe(1);
    expect(signaling.sent).toContain("sdp");
  });
});
