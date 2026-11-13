/**
 * Automated browser↔agent e2e harness (Milestone M3).
 *
 * This page instantiates the REAL viewer transport — `WebRTCTransport` + `SignalingClient` from
 * `src/lib` — exactly as the product would, reaches a Rust streaming agent through the Go signaling
 * server, attaches the received `MediaStream` to a `<video>`, and exposes connection state plus
 * `getStats()` on `window.rmt` so a Playwright test can assert media actually arrives. No signaling
 * is reimplemented here; the harness only drives the existing transport.
 *
 * Query params:
 *   ?device=<uuid>   target agent DeviceId to reach (required)
 *   ?url=<ws-url>    signaling WebSocket (default ws://127.0.0.1:8080/ws)
 *   ?ticket=<b64url> base64url-encoded JSON `SignedSessionTicket` from POST /sessions, presented in
 *                    `connect_request`. REQUIRED against a signaling server started WITHOUT
 *                    `-insecure-no-ticket-verification` (secure_posture.spec.ts); omitted by the
 *                    dev-mode specs, which then take the ticketless direct-connect path unchanged.
 */
import { WebRTCTransport, SignalingClient } from "../src/lib/transport";
import { asDeviceId, ChannelId, type SignedSessionTicket } from "../src/lib/protocol";
import { encodeInput, type InputEvent } from "../src/lib/input";
import { encodeControl, decodeControl } from "../src/lib/control";

interface StatEntry {
  type: string;
  [k: string]: unknown;
}

interface RmtHarness {
  state: string;
  error: string | null;
  gotVideoTrack: boolean;
  /** Resolves once the peer connection reaches "connected"; rejects on "failed". */
  connected: Promise<void>;
  /** Flattened RTCStatsReport entries (each a plain object) for the test to inspect. */
  stats(): Promise<StatEntry[]>;
  /** Convenience: just the inbound-rtp video entry (or null if none yet). */
  inboundVideo(): Promise<StatEntry | null>;
  /**
   * Send one controller→agent input event UP over the unified "frames" data channel
   * (`transport.send(ChannelId.Input, encodeInput(ev))`). Proves the browser is a full
   * controller, not just a viewer. Throws before `connect()` wires the transport.
   */
  sendInput(ev: InputEvent): void;
  /** All decoded ControlMessages received from the agent (appended as they arrive). Field `t` is the message type. */
  controlReceived: { t: string; [k: string]: unknown }[];
  /** Raw UTF-8 backstage response payloads received from the agent. */
  backstageResponses: string[];
  /** Send a CP-minted signed grant to the agent via ChannelId.Control / InstallGrant. */
  installGrant(signedGrant: string): void;
  /**
   * Forward a CP-minted signed session-policy blob to the agent via ChannelId.Control /
   * InstallSessionPolicy. The agent replies with SessionPolicyInstalled on success or Error
   * on rejection (wrong session, tampered signature, expired, etc.). Pass the raw `signed`
   * string from `POST /sessions/{id}/policy` response — do not re-encode it.
   */
  installSessionPolicy(signedPolicy: string): void;
  /** Send a raw JSON backstage Request to the agent via ChannelId.Backstage. */
  sendBackstageRequest(json: string): void;
}

// The harness object is created first so the transport event callbacks (which fire during/after
// `connect`) can mutate it without a temporal-dead-zone hazard.
const harness: RmtHarness = {
  state: "idle",
  error: null,
  gotVideoTrack: false,
  connected: Promise.resolve(),
  async stats() {
    return [];
  },
  async inboundVideo() {
    return null;
  },
  sendInput() {
    throw new Error("harness: transport not connected yet");
  },
  controlReceived: [] as { t: string; [k: string]: unknown }[],
  backstageResponses: [],
  installGrant() {
    throw new Error("harness: transport not connected yet");
  },
  installSessionPolicy() {
    throw new Error("harness: transport not connected yet");
  },
  sendBackstageRequest() {
    throw new Error("harness: transport not connected yet");
  },
};
(window as unknown as { rmt: RmtHarness }).rmt = harness;

async function main(): Promise<void> {
  const params = new URLSearchParams(location.search);
  const url = params.get("url") ?? "ws://127.0.0.1:8080/ws";
  const device = params.get("device");
  if (!device) throw new Error("harness: missing ?device=<uuid>");

  const video = document.getElementById("v") as HTMLVideoElement;

  // Decoded once, up front: a malformed ?ticket must be a loud harness error, not a silent
  // ticketless connect that then fails with an opaque "connect request not authorized".
  const ticketParam = params.get("ticket");
  let ticket: SignedSessionTicket | undefined;
  if (ticketParam) {
    ticket = JSON.parse(atob(ticketParam.replace(/-/g, "+").replace(/_/g, "/"))) as SignedSessionTicket;
  }

  // Open the signaling socket and register a controller identity BEFORE connect_request, so the
  // broker has a non-empty `Brokered.peer_device` to echo to the agent in DEV mode.
  //
  // Against an ENFORCING server (docs/11-agent-identity-contract.md §2.6) a controller never
  // answers the agent-auth challenge and so never enters the registry: the echoed peer_device is
  // empty there, by design. The agent must tolerate that — see the `peer_device` doc comment in
  // crates/protocol/src/signaling.rs.
  const signaling = new SignalingClient(url);
  await signaling.open();
  const selfId = crypto.randomUUID();
  signaling.send({
    type: "register_agent",
    device: asDeviceId(selfId),
    pubkey: "ed25519:browser-controller",
    nat: "unknown",
    enrollment_token: null,
  });

  let resolveConnected!: () => void;
  let rejectConnected!: (e: Error) => void;
  harness.connected = new Promise<void>((res, rej) => {
    resolveConnected = res;
    rejectConnected = rej;
  });

  // No ICE servers: loopback host candidates only (matches the Rust agent, keeps the test offline).
  const transport = new WebRTCTransport(
    { signaling, iceServers: [] },
    {
      onStateChange: (s) => {
        harness.state = s;
        if (s === "connected") resolveConnected();
        if (s === "failed") rejectConnected(new Error("connection failed"));
      },
      onVideoTrack: (stream) => {
        harness.gotVideoTrack = true;
        video.srcObject = stream;
        void video.play().catch(() => {
          /* autoplay may be blocked; getStats still works without playback */
        });
      },
      onError: (e) => {
        harness.error = e.message;
      },
      onMessage: (channel, payload) => {
        if (channel === ChannelId.Control) {
          try {
            const msg = decodeControl(payload);
            harness.controlReceived.push(msg as { t: string; [k: string]: unknown });
          } catch {
            /* ignore undecodable control frames */
          }
        } else if (channel === ChannelId.Backstage) {
          harness.backstageResponses.push(new TextDecoder().decode(payload));
        }
      },
    },
  );

  harness.stats = async () => {
    const report = await transport.getStats();
    const out: StatEntry[] = [];
    report?.forEach((r) => out.push(r as unknown as StatEntry));
    return out;
  };
  harness.inboundVideo = async () => {
    const all = await harness.stats();
    return (
      all.find(
        (r) => r.type === "inbound-rtp" && (r as { kind?: string }).kind === "video",
      ) ?? null
    );
  };
  // Browser → agent input: frame the encoded event onto ChannelId.Input over the one "frames"
  // channel. `send` buffers until the channel opens, so calling it right after connect is safe.
  harness.sendInput = (ev: InputEvent) => {
    transport.send(ChannelId.Input, encodeInput(ev));
  };
  harness.installGrant = (signedGrant: string) => {
    transport.send(ChannelId.Control, encodeControl({ t: "InstallGrant", c: { signed_grant: signedGrant } }));
  };
  harness.installSessionPolicy = (signedPolicy: string) => {
    transport.send(ChannelId.Control, encodeControl({ t: "InstallSessionPolicy", c: { signed_policy: signedPolicy } }));
  };
  harness.sendBackstageRequest = (json: string) => {
    transport.send(ChannelId.Backstage, new TextEncoder().encode(json));
  };

  await transport.connect(asDeviceId(device), ticket);
}

main().catch((e: unknown) => {
  harness.error = String(e);
  (window as unknown as { rmtFatal: string }).rmtFatal = String(e);
});
