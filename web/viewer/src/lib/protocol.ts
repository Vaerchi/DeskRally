/**
 * TypeScript mirror of the shared Rust wire protocol (`crates/protocol`).
 *
 * This is the contract every component builds on — agent, relay, signaling, and this
 * browser viewer. It is deliberately transport-agnostic: it describes *what* is exchanged,
 * not *how* bytes move (WebRTC in v1, QUIC later — docs/02-architecture.md ADR-001).
 *
 * Keep this in lockstep with `crates/protocol/src/{channel,frame,signaling}.rs` and
 * `lib.rs`. The Frame layout and ChannelId tags are wire-compatible with Rust; the
 * signaling messages match the serde `#[serde(tag = "type", rename_all = "snake_case")]`
 * JSON representation.
 */

/** Wire protocol version, negotiated at connect (`PROTOCOL_VERSION` in lib.rs). */
export const PROTOCOL_VERSION = 1;

// ---------------------------------------------------------------------------
// Channels (mirror of crates/protocol/src/channel.rs)
// ---------------------------------------------------------------------------

/**
 * Well-known channel identities. Stable u8 tags — do NOT renumber (wire-compatibility).
 * On QUIC these map to streams/datagrams; on WebRTC to media tracks + data channels;
 * over the TCP/WS fallback we emulate the mux with length-prefixed frames.
 */
export enum ChannelId {
  /** Control/handshake: capability negotiation, session lifecycle. Reliable, tiny. */
  Control = 0,
  /** Mouse/keyboard, controller -> agent. Reliable, ordered, HIGHEST priority, tiny. */
  Input = 1,
  /** Screen video, agent -> controller. Partial reliability (drop stale frames). */
  Video = 2,
  /** Clipboard sync, bidirectional. Reliable, small. */
  Clipboard = 3,
  /** In-session chat, bidirectional. Reliable, tiny. */
  Chat = 4,
  /** File transfer, bidirectional. Reliable, LOWEST priority (yields to video+input). */
  FileTransfer = 5,
  /** Backstage tool RPC (shell, panels), bidirectional. Reliable. */
  Backstage = 6,
}

const CHANNEL_VALUES: ReadonlySet<number> = new Set([0, 1, 2, 3, 4, 5, 6]);

/** Narrow a raw u8 to a ChannelId, or `undefined` if unknown (mirror of `from_u8`). */
export function channelFromU8(v: number): ChannelId | undefined {
  return CHANNEL_VALUES.has(v) ? (v as ChannelId) : undefined;
}

/**
 * Scheduling priority — higher wins when the transport must choose what to send next.
 * Input beats control beats video beats file transfer. Mirror of `ChannelId::priority`.
 */
export function channelPriority(c: ChannelId): number {
  switch (c) {
    case ChannelId.Input:
      return 250;
    case ChannelId.Control:
      return 200;
    case ChannelId.Clipboard:
      return 150;
    case ChannelId.Chat:
      return 150;
    case ChannelId.Backstage:
      return 140;
    case ChannelId.Video:
      return 100;
    case ChannelId.FileTransfer:
      return 10;
  }
}

/**
 * Whether every byte must be delivered reliably. Video tolerates loss (request a keyframe
 * instead of stalling); everything else is reliable. Mirror of `ChannelId::reliable`.
 */
export function channelReliable(c: ChannelId): boolean {
  return c !== ChannelId.Video;
}

/** Human-readable channel name, for logs and the debug UI. */
export function channelName(c: ChannelId): string {
  return ChannelId[c] ?? `Unknown(${c})`;
}

// ---------------------------------------------------------------------------
// Frame codec (mirror of crates/protocol/src/frame.rs)
// ---------------------------------------------------------------------------
//
// Layout: [channel: u8][len: u32 big-endian][payload: len bytes].
// Header is 5 bytes. Used on the multiplexed-over-one-stream fallback (WS/TCP) where the
// transport doesn't give us native streams like QUIC/WebRTC data channels do.

/** Fixed frame header size in bytes: u8 channel + u32 length. */
export const FRAME_HEADER_LEN = 5;

/**
 * Guard against a malicious/corrupt length header allocating unbounded memory. 64 MiB is
 * far above any legitimate single frame. Must match Rust `MAX_FRAME_LEN`.
 */
export const MAX_FRAME_LEN = 64 * 1024 * 1024;

/** A decoded frame: which channel, and its payload bytes. */
export interface Frame {
  channel: ChannelId;
  payload: Uint8Array;
}

export type FrameErrorKind = "unknown_channel" | "too_long" | "incomplete";

export class FrameError extends Error {
  readonly kind: FrameErrorKind;
  /** Present for `unknown_channel` (the offending byte) and `too_long` (the length). */
  readonly value?: number;

  constructor(kind: FrameErrorKind, message: string, value?: number) {
    super(message);
    this.name = "FrameError";
    this.kind = kind;
    this.value = value;
  }

  static unknownChannel(byte: number): FrameError {
    return new FrameError("unknown_channel", `unknown channel id ${byte}`, byte);
  }
  static tooLong(len: number): FrameError {
    return new FrameError("too_long", `frame length ${len} exceeds maximum ${MAX_FRAME_LEN}`, len);
  }
  static incomplete(): FrameError {
    return new FrameError("incomplete", "incomplete frame: need more bytes");
  }
}

/** Construct a frame. */
export function frame(channel: ChannelId, payload: Uint8Array): Frame {
  return { channel, payload };
}

/**
 * Encode a single frame to a fresh `Uint8Array` (header + payload). Equivalent to Rust
 * `Frame::to_bytes`.
 */
export function encodeFrame(f: Frame): Uint8Array {
  const out = new Uint8Array(FRAME_HEADER_LEN + f.payload.length);
  const view = new DataView(out.buffer);
  view.setUint8(0, f.channel);
  view.setUint32(1, f.payload.length, /* littleEndian */ false); // big-endian
  out.set(f.payload, FRAME_HEADER_LEN);
  return out;
}

/** Result of a streaming decode: the frame, plus how many bytes were consumed. */
export interface DecodedFrame {
  frame: Frame;
  /** Total bytes consumed from the front of the buffer (header + payload). */
  consumed: number;
}

/**
 * Try to decode one frame from the front of `src` (starting at `offset`).
 *
 * Mirrors the Rust streaming-decoder contract: throws `FrameError("incomplete")` when more
 * bytes are needed (leaving the caller to read more and retry), `too_long` for an oversized
 * length header, and `unknown_channel` for an unrecognized channel tag. On success returns
 * the decoded frame and the number of bytes consumed — the caller advances its cursor.
 */
export function decodeFrame(src: Uint8Array, offset = 0): DecodedFrame {
  const available = src.length - offset;
  if (available < FRAME_HEADER_LEN) {
    throw FrameError.incomplete();
  }

  const view = new DataView(src.buffer, src.byteOffset + offset, available);
  const channelByte = view.getUint8(0);
  const len = view.getUint32(1, /* littleEndian */ false); // big-endian

  if (len > MAX_FRAME_LEN) {
    throw FrameError.tooLong(len);
  }
  // Validate the channel from the HEADER, before waiting for the payload — both facts are known
  // as soon as the 5 header bytes are present. Reporting "incomplete" for a frame whose channel
  // can never be valid makes a receiver accumulate toward a payload it was always going to
  // reject. Kept in lockstep with the Rust decoder (crates/protocol/src/frame.rs, docs/25 F02).
  const channel = channelFromU8(channelByte);
  if (channel === undefined) {
    throw FrameError.unknownChannel(channelByte);
  }
  if (available < FRAME_HEADER_LEN + len) {
    throw FrameError.incomplete();
  }

  const start = offset + FRAME_HEADER_LEN;
  // Copy the payload out so it is independent of the (possibly reused) input buffer.
  const payload = src.slice(start, start + len);
  return { frame: { channel, payload }, consumed: FRAME_HEADER_LEN + len };
}

/**
 * A small stateful accumulator for the byte-stream (WS/TCP) transport. Feed it arriving
 * chunks; it yields every complete frame and retains the trailing partial frame.
 */
export class FrameDecoder {
  private chunks: Uint8Array[] = [];
  private head = 0;
  private offset = 0;
  private total = 0;
  private header?: { channel: ChannelId; len: number };

  /** Append a chunk and return all newly-complete frames (in order). */
  push(chunk: Uint8Array): Frame[] {
    if (chunk.length > 0) {
      // Own pending bytes because the transport may reuse its input buffer after push().
      this.chunks.push(chunk.slice());
      this.total += chunk.length;
    }
    const frames: Frame[] = [];
    for (;;) {
      if (this.header === undefined) {
        if (this.total < FRAME_HEADER_LEN) break;
        const header = new Uint8Array(FRAME_HEADER_LEN);
        let copied = 0;
        for (let i = this.head; copied < FRAME_HEADER_LEN; i++) {
          const part = this.chunks[i];
          const start = i === this.head ? this.offset : 0;
          const count = Math.min(part.length - start, FRAME_HEADER_LEN - copied);
          header.set(part.subarray(start, start + count), copied);
          copied += count;
        }
        const len = new DataView(header.buffer).getUint32(1, false);
        // Reject impossible frames immediately, in the same order as decodeFrame().
        if (len > MAX_FRAME_LEN) throw FrameError.tooLong(len);
        const channel = channelFromU8(header[0]);
        if (channel === undefined) throw FrameError.unknownChannel(header[0]);
        this.header = { channel, len };
      }
      const { channel, len } = this.header;
      if (this.total < FRAME_HEADER_LEN + len) break;
      this.consume(FRAME_HEADER_LEN);
      const payload = new Uint8Array(len);
      this.consume(len, payload);
      frames.push({ channel, payload });
      this.header = undefined;
    }
    // Amortize queue maintenance instead of shifting every remaining chunk per frame.
    if (this.head > 0 && this.head * 2 >= this.chunks.length) {
      this.chunks = this.chunks.slice(this.head);
      this.head = 0;
    }
    return frames;
  }

  private consume(count: number, out?: Uint8Array): void {
    let written = 0;
    while (written < count) {
      const part = this.chunks[this.head];
      const take = Math.min(count - written, part.length - this.offset);
      if (out) out.set(part.subarray(this.offset, this.offset + take), written);
      written += take;
      this.offset += take;
      if (this.offset === part.length) {
        this.head++;
        this.offset = 0;
      }
    }
    this.total -= count;
  }

  /** Number of buffered-but-not-yet-decodable bytes (a partial frame). */
  get pending(): number {
    return this.total;
  }
}

// ---------------------------------------------------------------------------
// Stable identities (mirror of crates/protocol/src/lib.rs)
// ---------------------------------------------------------------------------
//
// In Rust these are newtype-wrapped UUIDs (`DeviceId(Uuid)` etc.) that serialize as the
// bare UUID string. On the wire (JSON) they are plain strings, so we model them as branded
// string aliases for a little extra type-safety without runtime cost.

type Brand<T, B> = T & { readonly __brand: B };

/** Stable, permanent identifier for an agent (a controlled machine). UUID string. */
export type DeviceId = Brand<string, "DeviceId">;
/** Identifies one live control session between a controller and an agent. UUID string. */
export type SessionId = Brand<string, "SessionId">;
/** Relay-assigned token both half-connections present so the dumb relay can pair them. */
export type RelayToken = Brand<string, "RelayToken">;

export const asDeviceId = (s: string): DeviceId => s as DeviceId;
export const asSessionId = (s: string): SessionId => s as SessionId;
export const asRelayToken = (s: string): RelayToken => s as RelayToken;

// ---------------------------------------------------------------------------
// Signaling messages (mirror of crates/protocol/src/signaling.rs)
// ---------------------------------------------------------------------------
//
// JSON over the signaling WebSocket. Serde uses an internally-tagged enum
// (`{"type": "...", ...fields}`) with snake_case, so these discriminated unions match
// byte-for-byte.

export type CandidateKind = "host" | "server_reflexive" | "relayed";

/** Distinguishes an SDP offer from an answer. */
export type SdpKind = "offer" | "answer";

/** ICE-style connectivity candidate; the server relays these, it never dials them. */
export interface Candidate {
  /** Opaque transport-specific address string (e.g. an ICE candidate line). */
  addr: string;
  kind: CandidateKind;
}

/** NAT classification — symmetric-to-symmetric essentially always requires a relay. */
export type NatType =
  | "unknown"
  | "open"
  | "full_cone"
  | "restricted_cone"
  | "port_restricted"
  | "symmetric";

/**
 * Claims of a control-plane-signed session ticket (Go `TicketClaims`, control-plane/ticket.go).
 * Minted by `POST /sessions`; the signaling server verifies the signature over these before
 * brokering, so a `connect_request` without a valid ticket is rejected in secured deployments.
 */
export interface SessionTicketClaims {
  v: number;
  session_id: string;
  technician_id: string;
  tenant_id: string;
  device_id: string;
  iat_ms: number;
  exp_ms: number;
}

/** Signed session-ticket envelope (Go `SignedSessionTicket`): claims + hex Ed25519 signature. */
export interface SignedSessionTicket {
  claims: SessionTicketClaims;
  sig: string;
}

/** Controller/agent -> signaling server. Internally tagged by `type`. */
export type ClientToServer =
  | {
      type: "register_agent";
      device: DeviceId;
      /** Long-term Ed25519 identity (hex). The server pins this against silent swaps. */
      pubkey: string;
      nat: NatType;
      /** Optional enrollment token proving this agent may join this tenant. */
      enrollment_token: string | null;
    }
  | { type: "heartbeat"; device: DeviceId }
  | {
      type: "connect_request";
      target: DeviceId;
      /** Session ticket from `POST /sessions` (M2). Omitted on the direct-connect dev path. */
      ticket?: SignedSessionTicket;
    }
  | { type: "candidate"; session: SessionId; candidate: Candidate }
  | { type: "sdp"; session: SessionId; sdp: string; kind: SdpKind };

/**
 * One ICE server issued by the signaling server for this session. Mirror of the Rust
 * `IceServerSpec` and the Go `IceServerSpec`.
 *
 * `username`/`credential` are absent for STUN and present for TURN. They are optional rather than
 * empty-string-defaulted on purpose: `RTCIceServer` treats an empty username as a credential that
 * was supplied and is wrong, which fails authentication against coturn instead of being ignored.
 */
export interface IceServerSpec {
  urls: string[];
  username?: string;
  credential?: string;
}

/**
 * Convert the wire form into the browser's `RTCIceServer`, dropping entries with no URLs.
 *
 * Exported and pure so the mapping can be unit-tested without a peer connection — including the
 * property that matters most and is easiest to get wrong: a STUN entry must NOT acquire an empty
 * `username`/`credential` on the way through.
 */
export function toRTCIceServers(specs: IceServerSpec[]): RTCIceServer[] {
  return specs
    .filter((s) => Array.isArray(s.urls) && s.urls.length > 0)
    .map((s) => {
      const out: RTCIceServer = { urls: s.urls };
      // Only set them when BOTH are present. A half-credential is not a usable TURN entry, and
      // passing `username` with no `credential` throws in some browsers rather than degrading.
      if (s.username !== undefined && s.credential !== undefined) {
        out.username = s.username;
        out.credential = s.credential;
      }
      return out;
    });
}

/**
 * One concurrent controller in a session, as announced by the signaling server.
 * Mirror of the Go `SessionParticipantEntry` in server/signaling/messages.go.
 */
export interface SessionParticipantEntry {
  /** The session id that distinguishes this controller's slot. */
  session_id: string;
  /** Technician id extracted from the session ticket, if any. Empty for unauthenticated paths. */
  technician_id?: string;
  access?: string;
}

/** Signaling server -> controller/agent. Internally tagged by `type`. */
export type ServerToClient =
  | { type: "registered"; server_pubkey: string }
  | {
      type: "brokered";
      session: SessionId;
      peer_device: DeviceId;
      peer_pubkey: string;
      access?: string;
      access_version?: number;
    }
  | {
      type: "relay_assignment";
      session: SessionId;
      relay_addr: string;
      token: RelayToken;
    }
  | { type: "ice_servers"; session: SessionId; servers: IceServerSpec[]; relay_notice?: string }
  | { type: "candidate"; session: SessionId; candidate: Candidate }
  | { type: "sdp"; session: SessionId; sdp: string; kind: SdpKind }
  | { type: "rejected"; reason: string }
  | {
      type: "session_participants";
      /** The device id this participant list belongs to. */
      device_id: string;
      /** All currently-connected controllers for this device, including the receiver. */
      participants: SessionParticipantEntry[];
    };

/** Serialize a client message to the exact JSON the Rust signaling server expects. */
export function encodeSignaling(msg: ClientToServer): string {
  return JSON.stringify(msg);
}

/** Parse a server message. Does a light structural check on the tag. */
export function decodeSignaling(text: string): ServerToClient {
  const value = JSON.parse(text) as ServerToClient;
  if (typeof value !== "object" || value === null || typeof (value as { type?: unknown }).type !== "string") {
    throw new Error("malformed signaling message: missing 'type' tag");
  }
  return value;
}
