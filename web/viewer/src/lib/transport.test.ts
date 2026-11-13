/**
 * WebRTCTransport framing tests (Milestone M4).
 *
 * The browser transport was unified onto the Rust peer's model: ONE ordered `"frames"` data
 * channel carrying length-prefixed `Frame`s (`[channel:u8][len:u32 BE][payload]`), instead of six
 * separate unframed `RTCDataChannel`s. These tests pin that behavior against the shared
 * `encodeFrame`/`FrameDecoder` codec (which already interops with the Rust relay via the WS
 * transport), so browser→agent input/backstage bytes are no longer silently dropped.
 *
 * The vitest environment is "node" (no WebRTC), so we install minimal fakes for
 * `RTCPeerConnection`/`RTCDataChannel` that record what the transport does.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { WebRTCTransport, candidateKind, type SignalingClient, type TransportEvents } from "./transport";
import {
  ChannelId,
  encodeFrame,
  frame as makeFrame,
  decodeFrame,
  asDeviceId,
  toRTCIceServers,
  type ServerToClient,
} from "./protocol";
import { RELAY_LIMIT_CAUSE, withRelayLimitCause } from "./relay_notice";

// --- Minimal WebRTC fakes -------------------------------------------------

class FakeDataChannel {
  binaryType = "blob";
  readyState: "connecting" | "open" | "closing" | "closed" = "connecting";
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  readonly sent: ArrayBuffer[] = [];

  constructor(
    readonly label: string,
    readonly options: RTCDataChannelInit | undefined,
  ) {}

  send(data: ArrayBuffer): void {
    if (this.readyState !== "open") throw new Error(`send on ${this.readyState} channel`);
    this.sent.push(data);
  }
  close(): void {
    this.readyState = "closed";
  }

  /** Test helper: transition to open and fire onopen (flushes the transport's send queue). */
  open(): void {
    this.readyState = "open";
    this.onopen?.();
  }
  /** Test helper: deliver an inbound SCTP message (an ArrayBuffer) to the transport. */
  deliver(bytes: Uint8Array): void {
    const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    this.onmessage?.({ data: buf });
  }
}

class FakePeerConnection {
  static last: FakePeerConnection | null = null;
  readonly channels: FakeDataChannel[] = [];
  ontrack: unknown = null;
  onconnectionstatechange: unknown = null;
  onicecandidate: unknown = null;
  connectionState = "new";

  /**
   * What the transport passed to `new RTCPeerConnection(...)`.
   *
   * Recorded rather than discarded because the "no public STUN default" assertion reads it — and
   * without this field that assertion passed VACUOUSLY (`undefined ?? []` is empty whatever the
   * transport did), which is exactly the shape of test that proves nothing.
   */
  constructedWith?: RTCConfiguration;
  constructor(config?: RTCConfiguration) {
    this.constructedWith = config;
    FakePeerConnection.last = this;
  }
  createDataChannel(label: string, options?: RTCDataChannelInit): FakeDataChannel {
    const dc = new FakeDataChannel(label, options);
    this.channels.push(dc);
    return dc;
  }
  addTransceiver(): void {}
  /**
   * The applied configuration, recorded. A no-op `setConfiguration` would let the ICE-server
   * plumbing be entirely absent and still pass every test in this file — the fake has to remember.
   */
  config: RTCConfiguration = {};
  getConfiguration(): RTCConfiguration {
    return { ...this.config };
  }
  setConfiguration(cfg: RTCConfiguration): void {
    this.config = cfg;
  }
  async getStats(): Promise<Map<string, unknown>> {
    return new Map();
  }
  close(): void {}
}

/** A no-op signaling client: connect() only subscribes + requestConnect; we drive nothing. */
function fakeSignaling(): SignalingClient {
  return {
    onMessage: (_h: (m: ServerToClient) => void) => () => {},
    requestConnect: () => {},
    trickle: () => {},
    sendSdp: () => {},
  } as unknown as SignalingClient;
}

/**
 * A signaling client that captures the transport's handler so a test can PUSH server messages, and
 * records what was trickled back.
 */
function drivableSignaling(): {
  client: SignalingClient;
  push: (m: ServerToClient) => void;
  trickled: { addr: string; kind: string }[];
} {
  let handler: ((m: ServerToClient) => void) | null = null;
  const trickled: { addr: string; kind: string }[] = [];
  const client = {
    onMessage: (h: (m: ServerToClient) => void) => {
      handler = h;
      return () => {};
    },
    requestConnect: () => {},
    trickle: (_s: unknown, c: { addr: string; kind: string }) => trickled.push(c),
    sendSdp: () => {},
  } as unknown as SignalingClient;
  return { client, push: (m) => handler?.(m), trickled };
}

// -------------------------------------------------------------------------

const origRTC = (globalThis as Record<string, unknown>).RTCPeerConnection;

beforeEach(() => {
  FakePeerConnection.last = null;
  (globalThis as Record<string, unknown>).RTCPeerConnection = FakePeerConnection;
});
afterEach(() => {
  vi.useRealTimers();
  (globalThis as Record<string, unknown>).RTCPeerConnection = origRTC;
});

async function connected(): Promise<{ transport: WebRTCTransport; dc: FakeDataChannel }> {
  const transport = new WebRTCTransport({ signaling: fakeSignaling(), iceServers: [] });
  await transport.connect(asDeviceId("11111111-1111-1111-1111-111111111111"));
  const pc = FakePeerConnection.last!;
  return { transport, dc: pc.channels[0] };
}

describe("ICE server issuance and candidate classification (WAN/TURN)", () => {
  it("candidateKind reads the `typ` token, so a relay candidate is reported as relayed", () => {
    // Every trickled candidate used to be labelled "host" unconditionally, which made the
    // signaling server's view of connectivity fiction and hid whether TURN ever worked.
    expect(candidateKind("candidate:1 1 udp 2113937151 192.168.1.5 54321 typ host generation 0")).toBe("host");
    expect(candidateKind("candidate:2 1 udp 1677729535 203.0.113.9 54321 typ srflx raddr 192.168.1.5 rport 54321")).toBe("server_reflexive");
    expect(candidateKind("candidate:3 1 udp 41885439 198.51.100.7 3478 typ relay raddr 0.0.0.0 rport 0")).toBe("relayed");
    expect(candidateKind("candidate:4 1 udp 1 10.0.0.1 1 typ prflx")).toBe("server_reflexive");
    // Unparseable degrades to host rather than inventing a relay that was never gathered.
    expect(candidateKind("garbage")).toBe("host");
    expect(candidateKind("")).toBe("host");
    // `typ` must be a whole token: a candidate whose FOUNDATION happens to contain "relay" is not
    // a relay candidate.
    expect(candidateKind("candidate:relay1 1 udp 1 10.0.0.1 1 typ host")).toBe("host");
  });

  it("toRTCIceServers leaves a STUN entry without credentials", () => {
    // An empty-string username is NOT the same as an absent one: RTCIceServer treats it as a
    // credential that was supplied and is wrong, which fails against coturn instead of being
    // ignored.
    const out = toRTCIceServers([
      { urls: ["stun:stun.example:3478"] },
      { urls: ["turn:turn.example:3478?transport=udp"], username: "1700:rmt", credential: "pw" },
      { urls: [] }, // dropped: an entry with no URLs is not a server
      // A half-credential is not usable and must not be forwarded as one.
      { urls: ["turn:half.example:3478"], username: "only-a-name" },
    ]);
    expect(out).toHaveLength(3);
    expect(out[0]).toEqual({ urls: ["stun:stun.example:3478"] });
    expect("username" in out[0]).toBe(false);
    expect(out[1]).toEqual({
      urls: ["turn:turn.example:3478?transport=udp"],
      username: "1700:rmt",
      credential: "pw",
    });
    expect("username" in out[2]).toBe(false);
  });

  it("applies server-issued ICE servers to the peer connection before gathering", async () => {
    const { client, push } = drivableSignaling();
    const transport = new WebRTCTransport({ signaling: client, iceServers: [] });
    await transport.connect(asDeviceId("11111111-1111-1111-1111-111111111111"));
    const pc = FakePeerConnection.last!;

    push({
      type: "ice_servers",
      session: "s-1",
      servers: [
        { urls: ["stun:stun.example:3478"] },
        { urls: ["turn:turn.example:3478?transport=udp"], username: "u", credential: "p" },
      ],
    } as unknown as ServerToClient);

    const applied = pc.getConfiguration().iceServers ?? [];
    expect(applied).toHaveLength(2);
    expect(applied[1]).toMatchObject({ username: "u", credential: "p" });
    transport.close();
  });

  it("does NOT synthesise a TURN server from a relay assignment", async () => {
    // The relay is an application-layer byte-splicer, not a TURN server. Folding
    // `turn:<relay_addr>` with the session token as a credential into the ICE config produced an
    // entry that could never authenticate — pure gathering latency, and it made TURN look wired
    // when it was not.
    const { client, push } = drivableSignaling();
    const transport = new WebRTCTransport({ signaling: client, iceServers: [] });
    await transport.connect(asDeviceId("11111111-1111-1111-1111-111111111111"));
    const pc = FakePeerConnection.last!;

    push({
      type: "relay_assignment",
      session: "s-1",
      relay_addr: "relay-1.example:4444",
      token: "22222222-2222-2222-2222-222222222222",
    } as unknown as ServerToClient);

    const applied = pc.getConfiguration().iceServers ?? [];
    expect(applied).toHaveLength(0);
    transport.close();
  });

  it("adds no public STUN of its own when the caller supplies none", async () => {
    // A hardcoded third-party STUN default sends every session's connectivity checks to someone
    // the operator never chose, and masks a missing deployment configuration as a working one.
    const transport = new WebRTCTransport({ signaling: fakeSignaling() });
    await transport.connect(asDeviceId("11111111-1111-1111-1111-111111111111"));
    expect(FakePeerConnection.last!.constructedWith?.iceServers ?? []).toHaveLength(0);
    transport.close();
  });
});

describe("WebRTCTransport unified framing (M4)", () => {
  it("opens exactly ONE ordered 'frames' data channel", async () => {
    const { transport } = await connected();
    const pc = FakePeerConnection.last!;
    expect(pc.channels).toHaveLength(1);
    expect(pc.channels[0].label).toBe("frames");
    expect(pc.channels[0].options).toEqual({ ordered: true });
    transport.close();
  });

  it("send(Input, payload) writes encodeFrame(frame(Input, payload)) on the one channel", async () => {
    const { transport, dc } = await connected();
    dc.open();

    const payload = new TextEncoder().encode('{"t":"MouseMove","c":{"x":12345,"y":6789}}');
    transport.send(ChannelId.Input, payload);

    expect(dc.sent).toHaveLength(1);
    const expected = encodeFrame(makeFrame(ChannelId.Input, payload));
    expect(new Uint8Array(dc.sent[0])).toEqual(expected);

    // And the bytes decode back to exactly the Input frame we sent.
    const { frame: decoded } = decodeFrame(new Uint8Array(dc.sent[0]));
    expect(decoded.channel).toBe(ChannelId.Input);
    expect(decoded.payload).toEqual(payload);
    transport.close();
  });

  it("buffers sends issued before the channel opens, then flushes in order on open", async () => {
    const { transport, dc } = await connected();
    // Channel still "connecting": these must be queued, not dropped or thrown.
    transport.send(ChannelId.Input, new Uint8Array([1]));
    transport.send(ChannelId.Backstage, new Uint8Array([2, 3]));
    expect(dc.sent).toHaveLength(0);

    dc.open();
    expect(dc.sent).toHaveLength(2);
    expect(new Uint8Array(dc.sent[0])).toEqual(encodeFrame(makeFrame(ChannelId.Input, new Uint8Array([1]))));
    expect(new Uint8Array(dc.sent[1])).toEqual(
      encodeFrame(makeFrame(ChannelId.Backstage, new Uint8Array([2, 3]))),
    );
    transport.close();
  });

  it("rejects sending on the Video channel (media track, not framed)", async () => {
    const { transport, dc } = await connected();
    dc.open();
    expect(() => transport.send(ChannelId.Video, new Uint8Array([0]))).toThrow(/video/i);
    transport.close();
  });

  it("routes inbound framed bytes through FrameDecoder to onMessage by channel", async () => {
    const got: Array<{ channel: ChannelId; payload: Uint8Array }> = [];
    const transport = new WebRTCTransport(
      { signaling: fakeSignaling(), iceServers: [] },
      { onMessage: (channel, payload) => got.push({ channel, payload }) },
    );
    await transport.connect(asDeviceId("11111111-1111-1111-1111-111111111111"));
    const dc = FakePeerConnection.last!.channels[0];
    dc.open();

    // Two frames coalesced into one SCTP message: the decoder must split them.
    const a = encodeFrame(makeFrame(ChannelId.Control, new Uint8Array([9])));
    const b = encodeFrame(makeFrame(ChannelId.Clipboard, new Uint8Array([7, 7])));
    const both = new Uint8Array(a.length + b.length);
    both.set(a, 0);
    both.set(b, a.length);
    dc.deliver(both);

    expect(got).toHaveLength(2);
    expect(got[0].channel).toBe(ChannelId.Control);
    expect(got[0].payload).toEqual(new Uint8Array([9]));
    expect(got[1].channel).toBe(ChannelId.Clipboard);
    expect(got[1].payload).toEqual(new Uint8Array([7, 7]));
    transport.close();
  });
});

describe("transport liveness",()=> {
 it("a connection that never establishes fails within a bounded time",async()=> {
  vi.useFakeTimers();const {transport}=await connected();
  await vi.advanceTimersByTimeAsync(30000);expect(transport.state).toBe("failed");transport.close();
 });
 it("closing the control data channel reports failure instead of keeping a live label",async()=> {
  const {transport,dc}=await connected();
  (dc as unknown as {onclose:()=>void}).onclose();expect(transport.state).toBe("failed");transport.close();
 });
 it("a frozen media pipeline fails even though peer connection remains connected",async()=> {
  vi.useFakeTimers();const {transport}=await connected();const pc=FakePeerConnection.last!;
  Object.assign(pc,{getStats:async()=>new Map([["video",{type:"inbound-rtp",kind:"video",framesDecoded:7}]])});
  pc.connectionState="connected";(pc.onconnectionstatechange as ()=>void)();
  await vi.advanceTimersByTimeAsync(24000);expect(transport.state).toBe("failed");transport.close();
 });
 it("a stuck stats request cannot keep a frozen screen marked connected indefinitely",async()=> {
  vi.useFakeTimers();const {transport}=await connected();const pc=FakePeerConnection.last!;
  Object.assign(pc,{getStats:()=>new Promise(()=>{})});
  pc.connectionState="connected";(pc.onconnectionstatechange as ()=>void)();
  await vi.advanceTimersByTimeAsync(12000);expect(transport.state).toBe("failed");transport.close();
 });
});

// Security batch 3 caps the TURN credentials OUTSTANDING per technician and tenant. At the cap signaling still
// brokers the session but issues no relay credential and says so in `ice_servers.relay_notice`. The transport
// reports that to the UI (`onRelayNotice`) and, when the connection then never comes up, words the failure so it
// names the relay limit as the likely cause. An older server never sends the field and nothing may change.
describe("relay notice (signaling withheld a relay credential)", () => {
  const DEVICE = asDeviceId("11111111-1111-1111-1111-111111111111");
  const NOTICE = "relay capacity exhausted for your account; direct connection only";
  const iceServers = (extra: Record<string, unknown> = {}) =>
    ({ type: "ice_servers", session: "s-1", servers: [{ urls: ["stun:stun.example:3478"] }], ...extra }) as unknown as ServerToClient;

  // The transport logs the notice for developers; keep that line out of the test output (and assertable).
  let warn: { mockRestore(): void; mock: { calls: unknown[][] } };
  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => warn.mockRestore());

  async function connectWith(events: TransportEvents = {}) {
    const { client, push } = drivableSignaling();
    const transport = new WebRTCTransport({ signaling: client, iceServers: [] }, events);
    await transport.connect(DEVICE);
    return { transport, push, pc: FakePeerConnection.last! };
  }
  const reportState = (pc: FakePeerConnection, state: string) => {
    pc.connectionState = state;
    (pc.onconnectionstatechange as () => void)();
  };

  it("sets the state and announces the notice exactly once, with the server's own text", async () => {
    const heard: Array<{ notice: string; stateAtCall: string | null }> = [];
    const holder: { transport?: WebRTCTransport } = {};
    const { transport, push, pc } = await connectWith({
      onRelayNotice: (notice) => heard.push({ notice, stateAtCall: holder.transport?.relayNotice ?? null }),
    });
    holder.transport = transport;
    expect(transport.relayNotice).toBeNull();

    push(iceServers({ relay_notice: NOTICE }));

    expect(transport.relayNotice).toBe(NOTICE);
    // One announcement, and the state was already set when it fired: a consumer may read it from the callback.
    expect(heard).toEqual([{ notice: NOTICE, stateAtCall: NOTICE }]);
    // The notice changes what the technician is TOLD, not what ICE gets: the STUN entry is still applied.
    expect(pc.getConfiguration().iceServers).toEqual([{ urls: ["stun:stun.example:3478"] }]);
    // The developer log line is kept, once.
    expect(warn.mock.calls).toEqual([["[webrtc] " + NOTICE]]);
    transport.close();
  });

  it("an `ice_servers` without a notice (an older server, or an account under its cap) leaves it null and fires nothing", async () => {
    const heard: string[] = [];
    const { transport, push, pc } = await connectWith({ onRelayNotice: (notice) => heard.push(notice) });

    push(iceServers());

    expect(transport.relayNotice).toBeNull();
    expect(heard).toEqual([]);
    expect(warn.mock.calls).toEqual([]);
    expect(transport.relayLimitCause()).toBeNull();
    expect(pc.getConfiguration().iceServers).toEqual([{ urls: ["stun:stun.example:3478"] }]);
    transport.close();
  });

  it("announces a repeat of the same text once, and a changed text as news", async () => {
    const heard: string[] = [];
    const { transport, push } = await connectWith({ onRelayNotice: (notice) => heard.push(notice) });

    push(iceServers({ relay_notice: NOTICE }));
    push(iceServers({ relay_notice: NOTICE }));
    expect(heard).toEqual([NOTICE]);

    push(iceServers({ relay_notice: "relay disabled for this tenant" }));
    expect(heard).toEqual([NOTICE, "relay disabled for this tenant"]);
    expect(transport.relayNotice).toBe("relay disabled for this tenant");
    transport.close();
  });

  it("treats anything that is not a non-empty string as absent (the wire type is not enforced)", async () => {
    const heard: unknown[] = [];
    const { transport, push } = await connectWith({ onRelayNotice: (notice) => heard.push(notice) });

    // An object stored here and handed to React as a child would throw at render time.
    for (const hostile of ["", "   ", "\n\t", 0, 1, true, null, {}, ["x"], { toString: () => "x" }]) {
      push(iceServers({ relay_notice: hostile }));
    }

    expect(transport.relayNotice).toBeNull();
    expect(heard).toEqual([]);
    expect(transport.relayLimitCause()).toBeNull();
    transport.close();
  });

  it("follows the connection lifecycle: a new transport starts clean, a reconnect clears and re-announces", async () => {
    const heard: string[] = [];
    const events = { onRelayNotice: (notice: string) => heard.push(notice) };
    const first = await connectWith(events);
    first.push(iceServers({ relay_notice: NOTICE }));
    expect(first.transport.relayNotice).toBe(NOTICE);
    expect(heard).toEqual([NOTICE]);

    // A NEW session is a new transport (what App builds per session): nothing is inherited.
    const second = await connectWith(events);
    expect(second.transport.relayNotice).toBeNull();
    expect(second.transport.relayLimitCause()).toBeNull();

    // A second connect() on the SAME transport is a new attempt, brokered afresh: the old notice must not
    // leak into its failure message, and a notice on the new attempt is announced again.
    await first.transport.connect(DEVICE);
    expect(first.transport.relayNotice).toBeNull();
    expect(first.transport.relayLimitCause()).toBeNull();
    first.push(iceServers({ relay_notice: NOTICE }));
    expect(first.transport.relayNotice).toBe(NOTICE);
    expect(heard).toEqual([NOTICE, NOTICE]);
    first.transport.close();
    second.transport.close();
  });

  describe("failures while the notice is active", () => {
    it("a connection that never establishes times out naming the relay limit as the likely cause", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const { transport, push } = await connectWith({ onError: (e) => errors.push(e.message) });
      push(iceServers({ relay_notice: NOTICE }));

      await vi.advanceTimersByTimeAsync(30000);

      expect(transport.state).toBe("failed");
      expect(errors).toEqual([withRelayLimitCause("Connection timed out", RELAY_LIMIT_CAUSE)]);
      // The wording itself, not just the shared constant: what the technician reads.
      expect(errors[0]).toMatch(/^Connection timed out \(likely cause: .*limit of relay credentials.*\)$/);
      transport.close();
    });

    it("without a notice the same timeout is exactly the old message (nothing changes)", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const { transport, push } = await connectWith({ onError: (e) => errors.push(e.message) });
      push(iceServers());

      await vi.advanceTimersByTimeAsync(30000);

      expect(errors).toEqual(["Connection timed out"]);
      transport.close();
    });

    it("a control channel that closes or errors before the connection came up names it too", async () => {
      for (const event of ["onclose", "onerror"] as const) {
        const errors: string[] = [];
        const { transport, push, pc } = await connectWith({ onError: (e) => errors.push(e.message) });
        push(iceServers({ relay_notice: NOTICE }));

        (pc.channels[0] as unknown as Record<string, () => void>)[event]();

        const base = event === "onclose" ? "Control connection closed" : "Control connection failed";
        expect(errors).toEqual([withRelayLimitCause(base, RELAY_LIMIT_CAUSE)]);
        transport.close();
      }
    });

    it("ICE failure is reported as state only: the consumer words its message from relayLimitCause()", async () => {
      // What App does: ask the transport for its cause from inside the state callback, when it says `failed`.
      const asked: Array<string | null> = [];
      const holder: { transport?: WebRTCTransport } = {};
      const { transport, push, pc } = await connectWith({
        onStateChange: (s) => { if (s === "failed") asked.push(holder.transport!.relayLimitCause()); },
      });
      holder.transport = transport;
      push(iceServers({ relay_notice: NOTICE }));
      expect(transport.relayLimitCause()).toBe(RELAY_LIMIT_CAUSE);

      reportState(pc, "failed");

      expect(transport.state).toBe("failed");
      expect(asked).toEqual([RELAY_LIMIT_CAUSE]);
      transport.close();
    });

    it("once the connection has come up, an ICE failure is not blamed on the relay", async () => {
      const { transport, push, pc } = await connectWith();
      push(iceServers({ relay_notice: NOTICE }));
      expect(transport.relayLimitCause()).toBe(RELAY_LIMIT_CAUSE);

      reportState(pc, "connected");
      expect(transport.relayLimitCause()).toBeNull();
      reportState(pc, "failed");

      // The state really did change to failed (not an ignored event), and there is no cause to append.
      expect(transport.state).toBe("failed");
      expect(transport.relayLimitCause()).toBeNull();
      transport.close();
    });

    it("once the connection has come up, a frozen picture is a stall, not a missing relay", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const { transport, push, pc } = await connectWith({ onError: (e) => errors.push(e.message) });
      push(iceServers({ relay_notice: NOTICE }));
      Object.assign(pc, { getStats: async () => new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 7 }]]) });

      reportState(pc, "connected");
      await vi.advanceTimersByTimeAsync(24000);

      expect(errors).toEqual(["Video stopped responding"]);
      transport.close();
    });

    // 2026-11-09: a hidden console over an idle (displays-off) screen got no frames, by design (background
    // mode has no keep-alive), and the stall check reconnected it every ~33 s.
    it("in background mode a silent picture is not a stall; back in front, the full 20 s counts from the return", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const { transport, pc } = await connectWith({ onError: (e) => errors.push(e.message) });
      Object.assign(pc, { getStats: async () => new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 7 }]]) });

      reportState(pc, "connected");
      transport.setBackground(true);
      await vi.advanceTimersByTimeAsync(120000);
      expect(errors).toEqual([]);

      transport.setBackground(false);
      await vi.advanceTimersByTimeAsync(15000);
      expect(errors).toEqual([]);
      await vi.advanceTimersByTimeAsync(9000);
      expect(errors).toEqual(["Video stopped responding"]);
      transport.close();
    });

    it("a refusal or a negotiation error is not a connectivity failure: no cause in the error, none for the state callback", async () => {
      // The error banner AND the recovery notice are worded from these, so both must stay quiet.
      const asked: Array<string | null> = [];
      const holder: { transport?: WebRTCTransport } = {};
      const onStateChange = (s: string) => { if (s === "failed") asked.push(holder.transport!.relayLimitCause()); };

      const refused: string[] = [];
      const first = await connectWith({ onError: (e) => refused.push(e.message), onStateChange });
      holder.transport = first.transport;
      first.push(iceServers({ relay_notice: NOTICE }));
      first.push({ type: "rejected", reason: "device is not registered or offline" } as ServerToClient);
      expect(first.transport.state).toBe("failed");
      expect(refused).toEqual(["connect rejected: device is not registered or offline"]);
      expect(asked).toEqual([null]);
      expect(first.transport.relayLimitCause()).toBeNull();
      first.transport.close();

      asked.length = 0;
      const negotiation: string[] = [];
      const second = await connectWith({ onError: (e) => negotiation.push(e.message), onStateChange });
      holder.transport = second.transport;
      Object.assign(second.pc, { createOffer: async () => { throw new Error("offer failed"); } });
      second.push(iceServers({ relay_notice: NOTICE }));
      second.push({ type: "brokered", session: "s-1", peer_device: "d", peer_pubkey: "k" } as unknown as ServerToClient);
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(negotiation).toEqual(["Connection negotiation failed: offer failed"]);
      expect(asked).toEqual([null]);
      expect(second.transport.relayLimitCause()).toBeNull();
      second.transport.close();
    });

    it("a refusal is terminal: the connect timer is cancelled, so 30 s later nothing fails again or blames the relay", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const states: string[] = [];
      const asked: Array<string | null> = [];
      const holder: { transport?: WebRTCTransport } = {};
      const { transport, push, pc } = await connectWith({
        onError: (e) => errors.push(e.message),
        onStateChange: (s) => { states.push(s); if (s === "failed") asked.push(holder.transport!.relayLimitCause()); },
      });
      holder.transport = transport;
      push(iceServers({ relay_notice: NOTICE }));
      push({ type: "rejected", reason: "device is not registered or offline" } as ServerToClient);
      expect(errors).toEqual(["connect rejected: device is not registered or offline"]);

      await vi.advanceTimersByTimeAsync(60000);
      // A late control-channel event is also ignored: the failure is latched.
      (pc.channels[0] as unknown as Record<string, () => void>).onclose();

      expect(errors).toEqual(["connect rejected: device is not registered or offline"]);
      expect(states.filter((s) => s === "failed")).toHaveLength(1);
      expect(asked).toEqual([null]);
      expect(transport.relayLimitCause()).toBeNull();
      transport.close();
    });

    it("a negotiation error is terminal too: no second failure or relay attribution after 30 s", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const { transport, push, pc } = await connectWith({ onError: (e) => errors.push(e.message) });
      Object.assign(pc, { createOffer: async () => { throw new Error("offer failed"); } });
      push(iceServers({ relay_notice: NOTICE }));
      push({ type: "brokered", session: "s-1", peer_device: "d", peer_pubkey: "k" } as unknown as ServerToClient);
      await vi.advanceTimersByTimeAsync(60000);

      expect(errors).toEqual(["Connection negotiation failed: offer failed"]);
      expect(transport.relayLimitCause()).toBeNull();
      transport.close();
    });

    it("close() cancels the connect timer: no failure after a deliberate close", async () => {
      vi.useFakeTimers();
      const errors: string[] = [];
      const { transport, push } = await connectWith({ onError: (e) => errors.push(e.message) });
      push(iceServers({ relay_notice: NOTICE }));
      transport.close();
      await vi.advanceTimersByTimeAsync(60000);
      expect(errors).toEqual([]);
      expect(transport.state).toBe("disconnected");
    });

    it("a reconnect after a refusal is judged on its own: the refusal does not silence the next attempt's cause", async () => {
      const { transport, push } = await connectWith();
      push({ type: "rejected", reason: "peer became unreachable" } as ServerToClient);
      expect(transport.relayLimitCause()).toBeNull();

      await transport.connect(DEVICE);
      push(iceServers({ relay_notice: NOTICE }));

      expect(transport.relayLimitCause()).toBe(RELAY_LIMIT_CAUSE);
      transport.close();
    });

    it("a reconnect on the same transport starts with no cause until its own notice arrives", async () => {
      const { transport, push, pc } = await connectWith();
      push(iceServers({ relay_notice: NOTICE }));
      reportState(pc, "failed");
      expect(transport.relayLimitCause()).toBe(RELAY_LIMIT_CAUSE);

      await transport.connect(DEVICE);

      expect(transport.relayLimitCause()).toBeNull();
      transport.close();
    });

    it("a reconnect after an attempt that DID connect is judged on its own: no connection yet, so the cause is back", async () => {
      const { transport, push, pc } = await connectWith();
      reportState(pc, "connected");

      // The same transport reconnects (a new attempt, brokered afresh) and signaling again withholds the relay.
      await transport.connect(DEVICE);
      push(iceServers({ relay_notice: NOTICE }));

      // This attempt has not connected, whatever the previous one did.
      expect(transport.relayLimitCause()).toBe(RELAY_LIMIT_CAUSE);
      transport.close();
    });
  });
});
