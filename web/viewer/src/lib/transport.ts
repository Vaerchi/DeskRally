import { MediaProgress, withDeadline } from "./session_recovery";
import { RELAY_LIMIT_CAUSE, isRelayNotice, withRelayLimitCause } from "./relay_notice";
/**
 * Transport abstraction (ADR-001 / ADR-007).
 *
 * The architecture makes one thing load-bearing: a `Transport` with explicit named channels
 * and per-channel reliability/priority policy, so QUIC can be swapped in later without
 * rippling through the app. This file defines that interface plus two implementations:
 *
 *  - `WebRTCTransport` â€” v1 primary. A single ordered `"frames"` `RTCDataChannel` carrying
 *    length-prefixed `Frame`s (`[channel:u8][len:u32][payload]`) â€” exactly the mux the Rust
 *    agent/controller speak â€” plus an inbound media track for Video. Every logical channel
 *    (Control, Input, Clipboard, Chat, FileTransfer, Backstage) multiplexes onto that one
 *    data channel via the frame header; the agent routes by `frame.channel`.
 *  - `WebSocketTransport` â€” UDP-hostile-network fallback. A single ordered byte stream that
 *    carries every channel via the length-prefixed `Frame` mux.
 *
 * Both are skeletons: the signaling handshake wiring is sketched but not connected to a live
 * agent yet. The shapes are real so the UI and tests can build against them.
 */

import {
  ChannelId,
  channelName,
  encodeFrame,
  encodeSignaling,
  decodeSignaling,
  frame as makeFrame,
  FrameDecoder,
  toRTCIceServers,
  type Candidate,
  type ClientToServer,
  type DeviceId,
  type Frame,
  type ServerToClient,
  type SessionId,
  type SignedSessionTicket,
} from "./protocol";

// ---------------------------------------------------------------------------
// Transport interface
// ---------------------------------------------------------------------------

export type ConnectionState =
  | "idle"
  | "signaling"
  | "connecting"
  | "connected"
  | "disconnected"
  | "failed";

/** A payload received on a data (non-video) channel. */
export type ChannelMessageHandler = (channel: ChannelId, payload: Uint8Array) => void;

/** Called when the remote video MediaStreamTrack becomes available (WebRTC only). */
export type VideoTrackHandler = (stream: MediaStream) => void;

/**
 * Called when the remote AUDIO track becomes available â€” the guest machine's own output.
 *
 * Separate from {@link VideoTrackHandler} even though both tracks arrive in the SAME MediaStream,
 * because the UI needs to know whether there is anything to un-mute. An agent that predates audio
 * passthrough answers the audio m-line as inactive, so this simply never fires and the speaker
 * control stays disabled rather than lying about what is available.
 */
export type AudioTrackHandler = (stream: MediaStream) => void;

export type StateChangeHandler = (state: ConnectionState) => void;

export interface TransportEvents {
  /** The framed data channel is open and ready to send. */
  onChannelOpen?: () => void;
  onMessage?: ChannelMessageHandler;
  onVideoTrack?: VideoTrackHandler;
  onAudioTrack?: AudioTrackHandler;
  onStateChange?: StateChangeHandler;
  onError?: (err: Error) => void;
  /**
   * Signaling brokered this session WITHOUT a relay credential because the account is at its cap on
   * outstanding ones (`ice_servers.relay_notice`, see lib/relay_notice.ts). Only a direct connection can
   * succeed, so the UI says so up front rather than leave a failure unexplained. `notice` is the server's
   * own text: untrusted, to be shown as text only.
   *
   * Fires at most once per `connect()`: a repeat of the same text is not news. An absent notice (an older
   * server, or an account under its cap) fires nothing, and there is no event that clears one: a consumer
   * starts each session with none and resets it with its own per-session state. WebRTC only.
   */
  onRelayNotice?: (notice: string) => void;
}

/**
 * The one abstraction the rest of the app depends on. Send bytes on a named channel; the
 * transport applies that channel's reliability/priority policy. Video is receive-only here
 * (agent -> controller), surfaced out-of-band via `onVideoTrack`.
 */
export interface Transport {
  readonly kind: "webrtc" | "websocket";
  readonly state: ConnectionState;

  /**
   * Establish the session (runs signaling + connectivity). Resolves once connected. `ticket` is
   * the control-plane session ticket presented in `connect_request` (M2); omitted on the
   * direct-connect dev path.
   */
  connect(target: DeviceId, ticket?: SignedSessionTicket): Promise<void>;

  /** Send a payload on a logical channel. May buffer until the channel is open. */
  send(channel: ChannelId, payload: Uint8Array): void;

  /** Convenience: send a pre-built protocol Frame. */
  sendFrame(frame: Frame): void;

  /** Tear everything down. */
  close(): void;
}

// ---------------------------------------------------------------------------
// Signaling client
// ---------------------------------------------------------------------------

/**
 * Speaks the `ClientToServer` / `ServerToClient` message set over a WebSocket to the
 * rendezvous server (ADR-002). Authoritative + authenticated; brokers sessions and issues
 * relay assignments. Peers never self-dial â€” offer/answer candidates route through here.
 */
export class SignalingClient {
  private ws: WebSocket | null = null;
  private readonly url: string;
  private handlers = new Set<(msg: ServerToClient) => void>();

  constructor(url: string) {
    this.url = url;
  }

  async open(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(this.url);
      const timer = setTimeout(() => { ws.close(); reject(new Error("Signaling connection timed out")); }, 15000);
      ws.onopen = () => { clearTimeout(timer); resolve(); };
      ws.onerror = () => { clearTimeout(timer); reject(new Error(`signaling connection failed: ${this.url}`)); };
      ws.onmessage = (ev) => {
        try {
          const msg = decodeSignaling(typeof ev.data === "string" ? ev.data : "");
          for (const h of this.handlers) h(msg);
        } catch (err) {
          console.error("[signaling] failed to decode message", err);
        }
      };
      ws.onclose = () => {
        clearTimeout(timer); reject(new Error("Signaling connection closed"));
        if (this.ws === ws) this.ws = null;
      };
      this.ws = ws;
    });
  }

  /** Subscribe to server messages. Returns an unsubscribe fn. */
  onMessage(handler: (msg: ServerToClient) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  send(msg: ClientToServer): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("signaling socket not open");
    }
    this.ws.send(encodeSignaling(msg));
  }

  /**
   * Controller asks the server to broker a session with an agent. `ticket` (from the control
   * plane's `POST /sessions`) authorizes the rendezvous; a secured signaling server rejects the
   * request without it, dev-mode servers accept either way.
   */
  requestConnect(target: DeviceId, ticket?: SignedSessionTicket): void {
    this.send(ticket ? { type: "connect_request", target, ticket } : { type: "connect_request", target });
  }

  /** Trickle a locally-gathered ICE candidate to the peer via the server. */
  trickle(session: SessionId, candidate: Candidate): void {
    this.send({ type: "candidate", session, candidate });
  }

  /** Deliver an SDP offer/answer to the peer via the server (relayed opaquely). */
  sendSdp(session: SessionId, sdp: string, kind: "offer" | "answer"): void {
    this.send({ type: "sdp", session, sdp, kind });
  }

  close(): void {
    this.ws?.close();
    this.ws = null;
    this.handlers.clear();
  }
}

// ---------------------------------------------------------------------------
// WebRTC transport (v1 primary)
// ---------------------------------------------------------------------------

/** The single data-channel name both peers agree on (mirrors the Rust `create_data_channel("frames")`). */
const FRAMES_CHANNEL = "frames";

/**
 * Classify an ICE candidate line by its `typ` token (RFC 5245 Â§15.1).
 *
 * Exported and pure because it is the instrument for the question a WAN deployment actually needs
 * answered: **did we ever gather a relay candidate?** Previously every trickled candidate was
 * labelled `"host"` unconditionally, which made the signaling server's view of connectivity
 * fiction â€” and left "TURN is misconfigured" and "TURN was not needed" indistinguishable.
 *
 * `srflx` (server-reflexive, via STUN) and `prflx` (peer-reflexive) both report as
 * `server_reflexive`; the protocol's `CandidateKind` has no separate peer-reflexive value and the
 * distinction does not change what an operator would do.
 */
export function candidateKind(candidate: string): Candidate["kind"] {
  const m = /(?:^|\s)typ\s+(host|srflx|prflx|relay)(?:\s|$)/.exec(candidate);
  switch (m?.[1]) {
    case "relay":
      return "relayed";
    case "srflx":
    case "prflx":
      return "server_reflexive";
    default:
      // Unparseable or genuinely host. Defaulting to `host` keeps the previous behaviour for
      // anything unrecognised rather than inventing a relay that was never gathered.
      return "host";
  }
}

export interface WebRTCTransportConfig {
  signaling: SignalingClient;
  /** ICE servers (STUN/TURN). TURN entries come from the server's RelayAssignment in v1. */
  iceServers?: RTCIceServer[];
  /**
   * An OBSERVE session (observer design v2): the `brokered` reply must say `access: "view_only"`,
   * `access_version: 1`, or the transport fails BEFORE creating an offer, so nothing is negotiated
   * with a server that would broker a controlling session instead.
   */
  requireViewOnlyBrokered?: boolean;
}

/** The message an observe shows when the server cannot broker a view-only session. */
export const OBSERVE_UNSUPPORTED = "This server cannot observe yet; nothing was shown";

export class WebRTCTransport implements Transport {
  /**
   * Set when signaling withheld a relay credential (capacity), so the UI can explain a failed WAN path.
   * The server's own text, kept as received (display cleaning is `relayNoticeDetail`'s job). Per
   * `connect()`: each attempt is brokered afresh, so a new one starts with none and a reused transport
   * can never carry the previous attempt's notice into its failure message.
   */
  relayNotice: string | null = null;
  readonly kind = "webrtc" as const;
  state: ConnectionState = "idle";

  private pc: RTCPeerConnection | null = null;
  /** The single "frames" data channel carrying every logical channel as framed bytes. */
  private channel: RTCDataChannel | null = null;
  /** Reassembles inbound `Frame`s (SCTP preserves message boundaries, but be robust anyway). */
  private readonly decoder = new FrameDecoder();
  /** Encoded frames queued while the data channel is not yet "open"; flushed on open. */
  private sendQueue: Uint8Array[] = [];
  private session: SessionId | null = null;
  /**
   * Which ICE candidate types this peer actually gathered. Readable via
   * {@link gatheredCandidateKinds} so a WAN deployment can be diagnosed from the console: no
   * `relayed` entry means TURN never produced a candidate, which is a configuration answer rather
   * than a connectivity mystery.
   */
  private readonly gathered = new Set<Candidate["kind"]>();
  private readonly signaling: SignalingClient;
  private readonly iceServers: RTCIceServer[];
  private readonly events: TransportEvents;
  private unsubscribe: (() => void) | null = null;
  private healthTimer: ReturnType<typeof setInterval> | undefined;
  private connectTimer: ReturnType<typeof setTimeout> | undefined;
  private statsPending = false;
  private healthFailed = false;
  /** This attempt's peer connection reached "connected" at least once. Per `connect()`, like `relayNotice`. */
  private everConnected = false;
  /**
   * Why this attempt failed, once it has. Only a CONNECTIVITY failure (the connection never established, or
   * its control channel closed under it) can be put down to a missing relay; a refusal, a negotiation error or
   * a protocol fault says nothing about one, and {@link relayLimitCause} stays quiet after them. Per `connect()`.
   */
  private failureKind: "connectivity" | "other" | null = null;
  private readonly requireViewOnlyBrokered: boolean;
  /** The session is in background mode: the agent sends no keep-alive, so the video-stall check pauses. */
  private background = false;

  /**
   * Tell the transport the session entered or left background mode (see `ControlClient.setBackground`). While
   * in it, an idle screen legitimately sends no frames, so "Video stopped responding" must not fire.
   */
  setBackground(hidden: boolean): void {
    this.background = hidden;
  }

  private failHealth(message: string, kind: "connectivity" | "other" = "other"): void {
    if (this.healthFailed || !this.pc) return;
    this.healthFailed = true;
    // Before the state is reported: the consumer asks `relayLimitCause()` from its state callback.
    this.failureKind = kind;
    clearInterval(this.healthTimer); clearTimeout(this.connectTimer);
    this.events.onError?.(new Error(message));
    this.setState("failed");
  }

  /**
   * The clause to put on the failure of a connection that never came up, or null when the relay is not the
   * suspect: signaling withheld the relay credential (the account is at its cap), this attempt never reached
   * "connected", and it did not fail for a reason that has nothing to do with connectivity. Once a direct
   * connection has worked, a later failure is not a missing relay, so it is not blamed on one.
   */
  relayLimitCause(): string | null {
    return this.relayNotice !== null && !this.everConnected && this.failureKind !== "other" ? RELAY_LIMIT_CAUSE : null;
  }

  /**
   * `failHealth` for a failure that is about CONNECTIVITY, as opposed to a refusal or a negotiation error,
   * where a missing relay says nothing. Adds the relay-limit cause when {@link relayLimitCause} holds, and is
   * otherwise exactly `failHealth` apart from recording the kind.
   */
  private failConnectivity(message: string): void {
    this.failHealth(withRelayLimitCause(message, this.relayLimitCause()), "connectivity");
  }

  constructor(config: WebRTCTransportConfig, events: TransportEvents = {}) {
    this.signaling = config.signaling;
    // No hardcoded public STUN default. A self-hosted deployment issues its own via `ice_servers`,
    // and silently sending every session's connectivity checks to a third party is not a default
    // worth having. A caller that wants one still passes it.
    this.iceServers = config.iceServers ?? [];
    this.requireViewOnlyBrokered = config.requireViewOnlyBrokered === true;
    this.events = events;
  }

  /** The ICE candidate types gathered so far â€” see {@link gathered}. */
  gatheredCandidateKinds(): Candidate["kind"][] {
    return [...this.gathered];
  }

  async connect(target: DeviceId, ticket?: SignedSessionTicket): Promise<void> {
    this.setState("signaling");

    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    this.pc = pc;
    this.healthFailed = false;
    // A new attempt is brokered afresh and gets its own `ice_servers`: what the last one said about the
    // relay says nothing about this one.
    this.relayNotice = null;
    this.everConnected = false;
    this.failureKind = null;
    this.connectTimer=setTimeout(()=> {if(this.pc === pc) this.failConnectivity("Connection timed out");},30000);

    // ONE ordered/reliable data channel carrying every logical channel as length-prefixed
    // `Frame`s â€” the exact mux the Rust peer speaks (`create_data_channel("frames")`). The
    // controller (this side) creates it; the agent receives it via on_data_channel.
    const dc = pc.createDataChannel(FRAMES_CHANNEL, { ordered: true });
    this.wireDataChannel(dc);
    this.channel = dc;

    // Media is receive-only: agent -> controller.
    pc.addTransceiver("video", { direction: "recvonly" });
    // An AUDIO m-line must be offered or the agent's Opus track has nowhere to go â€” it would be
    // negotiated away and the session would work, look right and be silent, with no error anywhere.
    // Safe against older agents: one with no audio track answers this m-line as inactive, so
    // `onAudioTrack` never fires and the UI keeps its speaker control disabled.
    pc.addTransceiver("audio", { direction: "recvonly" });
    pc.ontrack = (ev) => {
      const [stream] = ev.streams;
      if (!stream) return;
      // `ontrack` fires once PER TRACK, and both tracks share one stream, so this runs twice with
      // the same object. Routed by kind: the <video> element gets the stream either way, but only
      // an actual audio track may enable un-muting.
      if (ev.track.kind === "audio") this.events.onAudioTrack?.(stream);
      else this.events.onVideoTrack?.(stream);
    };

    pc.onconnectionstatechange = () => {
      if(this.pc !== pc || this.healthFailed) return;
      switch (pc.connectionState) {
        case "connected":
          clearTimeout(this.connectTimer);
          this.everConnected = true;
          if(this.healthTimer === undefined) {
            const progress=new MediaProgress(Date.now());
            this.healthTimer=setInterval(()=> {
              if(this.statsPending || this.pc !== pc || this.state !== "connected" || typeof pc.getStats !== "function") return;
              this.statsPending=true;
              void withDeadline(pc.getStats(),8000).then(report=> {
                if(this.pc === pc && progress.stalled(report,Date.now(),!this.background)) this.failHealth("Video stopped responding");
              }).catch(()=>{if(this.pc === pc) this.failHealth("Unable to verify the video connection");}).finally(()=>{this.statsPending=false;});
            },3000);
          }
          this.setState("connected");
          break;
        case "disconnected":
          this.setState("disconnected");
          break;
        case "failed":
          // ICE gave up: connectivity, unless something else already failed this attempt.
          this.failureKind ??= "connectivity";
          this.setState("failed");
          break;
      }
    };

    // Trickle ICE candidates to the peer through the signaling server.
    pc.onicecandidate = (ev) => {
      if (ev.candidate && this.session) {
        const kind = candidateKind(ev.candidate.candidate);
        this.gathered.add(kind);
        this.signaling.trickle(this.session, {
          addr: ev.candidate.candidate,
          kind,
        });
      }
    };

    // React to brokering / relay assignment / peer candidates.
    this.unsubscribe = this.signaling.onMessage((msg) => {
      void this.onSignal(pc,msg).catch(error=> {
        if(this.pc === pc) this.failHealth(`Connection negotiation failed: ${(error as Error).message}`);
      });
    });

    // Kick off: ask the server to broker (presenting the session ticket when brokered). The
    // `brokered` reply carries the SessionId and we create the SDP offer then.
    this.setState("connecting");
    this.signaling.requestConnect(target, ticket);
  }

  private async onSignal(pc: RTCPeerConnection, msg: ServerToClient): Promise<void> {
    if(this.pc !== pc) return;
    switch (msg.type) {
      case "brokered": {
        // Checked before ANYTHING is negotiated: no offer, no candidates, no media.
        if (this.requireViewOnlyBrokered && (msg.access !== "view_only" || msg.access_version !== 1)) {
          this.failHealth(OBSERVE_UNSUPPORTED);
          pc.close();
          return;
        }
        this.session = msg.session;
        // Controller is the offerer: create the offer, set it locally, and deliver it to the
        // agent through the signaling server (peers never self-dial).
        const offer = await pc.createOffer();
        if(this.pc !== pc) return;
        await pc.setLocalDescription(offer);
        if(this.pc !== pc) return;
        this.signaling.sendSdp(msg.session, offer.sdp ?? "", "offer");
        break;
      }
      case "sdp": {
        if (this.session !== msg.session) break;
        if (msg.kind === "answer") {
          // The agent answered our offer â€” apply it and let ICE finish connecting.
          await pc.setRemoteDescription({ type: "answer", sdp: msg.sdp });
        } else {
          // Defensive: if we ever receive an offer (agent-initiated), answer it.
          await pc.setRemoteDescription({ type: "offer", sdp: msg.sdp });
          if(this.pc !== pc) return;
          const answer = await pc.createAnswer();
          if(this.pc !== pc) return;
          await pc.setLocalDescription(answer);
          if(this.pc !== pc) return;
          this.signaling.sendSdp(msg.session, answer.sdp ?? "", "answer");
        }
        break;
      }
      case "ice_servers": {
        // The session's STUN/TURN, issued by the signaling server (short-lived TURN credentials).
        //
        // `setConfiguration` rather than construction because the peer connection already exists by
        // the time this arrives â€” but it lands in time, and not by luck: the server sends
        // `ice_servers` BEFORE `brokered` (asserted in server/signaling/broker_test.go), and ICE
        // gathering does not begin until `setLocalDescription` in the `brokered` case above. So the
        // servers are always in place before a single candidate is gathered.
        //
        // Merged with, not replacing, whatever the caller configured: the static list is how a
        // LAN/dev caller supplies servers when the deployment issues none.
        if (isRelayNotice(msg.relay_notice) && msg.relay_notice !== this.relayNotice) {
          // The server brokered this session WITHOUT a relay credential (the account is at its cap).
          // Say so rather than degrade silently: only a direct connection is possible.
          //
          // `isRelayNotice`, not a truthiness test: the wire type says string but nothing enforces it, and
          // a non-string stored here would be rendered by the UI. The state is set BEFORE the event
          // fires, so a consumer reading `relayNotice` from the callback sees it; the comparison makes a
          // repeat of the same text silent (the event is "at most once per connect").
          this.relayNotice = msg.relay_notice;
          console.warn("[webrtc] " + msg.relay_notice);
          this.events.onRelayNotice?.(msg.relay_notice);
        }
        if (msg.servers.length === 0) break;
        const cfg = pc.getConfiguration();
        cfg.iceServers = [...toRTCIceServers(msg.servers), ...(cfg.iceServers ?? [])];
        pc.setConfiguration(cfg);
        break;
      }
      case "relay_assignment": {
        // Deliberately IGNORED for ICE.
        //
        // This used to synthesise `{ urls: "turn:" + relay_addr, username: token, credential: token }`
        // and fold it into the ICE configuration. That was wrong in a way that looked right: the
        // project's relay is an application-layer BYTE-SPLICER, not a TURN server (see the Rust
        // `ServerToClient::RelayAssignment` doc), so the entry pointed ICE at a service that speaks
        // no STUN/TURN, using a session UUID as a credential. Every such candidate necessarily
        // failed; all it did was add gathering latency and make it look as though TURN was wired
        // when it was not â€” which is exactly what docs/10 Â§6 came to claim.
        //
        // Real TURN arrives in `ice_servers` above. The relay assignment remains meaningful for the
        // non-ICE fallback transport (`agent-core/src/relay_transport.rs`), which this browser
        // client does not implement.
        break;
      }
      case "candidate": {
        if (this.session === msg.session) {
          try {
            await pc.addIceCandidate({ candidate: msg.candidate.addr, sdpMid: "0" });
          } catch (err) {
            this.events.onError?.(err as Error);
          }
        }
        break;
      }
      case "rejected": {
        // An authoritative refusal: nothing about the relay explains it, and it is terminal. failHealth latches
        // the failure and cancels the connect timer, so 30 s later nothing fails again as "connectivity".
        this.failHealth(`connect rejected: ${msg.reason}`, "other");
        break;
      }
      case "registered":
        break;
    }
  }

  private wireDataChannel(dc: RTCDataChannel): void {
    dc.binaryType = "arraybuffer";
    dc.onopen = () => {
      this.flushQueue();
      this.events.onChannelOpen?.();
    };
    dc.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return;
      let frames: Frame[];
      try {
        // SCTP preserves message boundaries so each message is normally one whole frame, but
        // the FrameDecoder also tolerates coalesced/partial delivery robustly.
        frames = this.decoder.push(new Uint8Array(ev.data));
      } catch (err) {
        // too_long / unknown_channel are hard protocol errors â€” surface and tear down.
        this.events.onError?.(err as Error);
        this.close();
        return;
      }
      for (const f of frames) this.events.onMessage?.(f.channel, f.payload);
    };
    dc.onerror = () => { if(this.channel === dc) this.failConnectivity("Control connection failed"); };
    dc.onclose = () => { if(this.channel === dc) this.failConnectivity("Control connection closed"); };
  }

  /** Flush any frames buffered while the channel was still opening. */
  private flushQueue(): void {
    const dc = this.channel;
    if (!dc || dc.readyState !== "open") return;
    const queued = this.sendQueue;
    this.sendQueue = [];
    for (const bytes of queued) this.rawSend(dc, bytes);
  }

  /** Send already-encoded frame bytes, or queue them until the channel opens. */
  private enqueue(bytes: Uint8Array): void {
    const dc = this.channel;
    if (!dc) {
      throw new Error("transport not connected (no 'frames' data channel)");
    }
    if (dc.readyState === "open") {
      this.rawSend(dc, bytes);
    } else {
      // Callers may send right after connect(), before the SCTP channel finishes opening.
      // Buffer rather than drop; flushed in onopen.
      this.sendQueue.push(bytes);
    }
  }

  private rawSend(dc: RTCDataChannel, bytes: Uint8Array): void {
    // Copy into a fresh (non-shared) ArrayBuffer so it matches RTCDataChannel.send's overload
    // under strict TS (a Uint8Array may be backed by a SharedArrayBuffer otherwise).
    const buf = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(buf).set(bytes);
    dc.send(buf);
  }

  send(channel: ChannelId, payload: Uint8Array): void {
    if (channel === ChannelId.Video) {
      throw new Error(`cannot send on ${channelName(channel)} (video is a media track, not framed)`);
    }
    // Mirror the Rust peer exactly: frame the payload and send it on the one "frames" channel.
    this.enqueue(encodeFrame(makeFrame(channel, payload)));
  }

  sendFrame(frame: Frame): void {
    if (frame.channel === ChannelId.Video) {
      throw new Error("cannot send a Video frame (video is a media track, not framed)");
    }
    this.enqueue(encodeFrame(frame));
  }

  /**
   * Diagnostic: the peer connection's current `RTCStatsReport` (inbound-rtp, candidate-pair, â€¦).
   * Used by the automated browserâ†”agent e2e test to prove media is actually arriving
   * (inbound-rtp video `bytesReceived`/`packetsReceived`). Returns `undefined` before `connect`.
   */
  async getStats(): Promise<RTCStatsReport | undefined> {
    return this.pc ? await this.pc.getStats() : undefined;
  }

  close(): void {
    clearInterval(this.healthTimer); this.healthTimer=undefined;
    clearTimeout(this.connectTimer);
    this.unsubscribe?.();
    this.unsubscribe = null;
    const dc=this.channel; this.channel=null; dc?.close();
    this.sendQueue = [];
    this.pc?.close();
    this.pc = null;
    this.setState("disconnected");
  }

  private setState(state: ConnectionState): void {
    this.state = state;
    this.events.onStateChange?.(state);
  }
}

// ---------------------------------------------------------------------------
// WebSocket transport (fallback)
// ---------------------------------------------------------------------------

/**
 * Fallback for UDP-hostile networks. A single ordered byte stream carries every channel via
 * the length-prefixed `Frame` mux (matching the Rust `frame.rs` layout), so the same
 * Control/Input/Clipboard/etc. payloads flow without WebRTC. Video arrives as framed,
 * chunked bytes on the Video channel (WASM/JS decode) rather than a hardware media track â€”
 * the WASM decode fallback path from ADR-001.
 */
export interface WebSocketTransportConfig {
  /** The relay/agent data-plane URL that speaks framed bytes. */
  url: string;
}

export class WebSocketTransport implements Transport {
  readonly kind = "websocket" as const;
  state: ConnectionState = "idle";

  private ws: WebSocket | null = null;
  private readonly url: string;
  private readonly events: TransportEvents;
  private readonly decoder = new FrameDecoder();

  constructor(config: WebSocketTransportConfig, events: TransportEvents = {}) {
    this.url = config.url;
    this.events = events;
  }

  async connect(_target: DeviceId, _ticket?: SignedSessionTicket): Promise<void> {
    this.setState("connecting");
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(this.url);
      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        this.setState("connected");
        this.events.onChannelOpen?.();
        resolve();
      };
      ws.onerror = () => {
        this.setState("failed");
        reject(new Error(`websocket transport failed: ${this.url}`));
      };
      ws.onclose = () => this.setState("disconnected");
      ws.onmessage = (ev) => this.onData(ev);
      this.ws = ws;
    });
  }

  private onData(ev: MessageEvent): void {
    if (!(ev.data instanceof ArrayBuffer)) return;
    let frames: Frame[];
    try {
      frames = this.decoder.push(new Uint8Array(ev.data));
    } catch (err) {
      // too_long / unknown_channel are hard protocol errors â€” surface and bail.
      this.events.onError?.(err as Error);
      this.close();
      return;
    }
    for (const f of frames) {
      if (f.channel === ChannelId.Video) {
        // No media track here; the caller feeds these bytes to a WASM/JS decoder.
        this.events.onMessage?.(f.channel, f.payload);
      } else {
        this.events.onMessage?.(f.channel, f.payload);
      }
    }
  }

  send(channel: ChannelId, payload: Uint8Array): void {
    this.sendFrame(makeFrame(channel, payload));
  }

  sendFrame(frame: Frame): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn("[websocket] not open; frame dropped");
      return;
    }
    this.ws.send(encodeFrame(frame));
  }

  close(): void {
    this.ws?.close();
    this.ws = null;
    this.setState("disconnected");
  }

  private setState(state: ConnectionState): void {
    this.state = state;
    this.events.onStateChange?.(state);
  }
}
