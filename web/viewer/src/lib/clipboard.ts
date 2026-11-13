/**
 * Canonical bidirectional text-clipboard codec + minimal client (browser side, M9 + docs/25 F08).
 *
 * Byte-for-byte mirror of the Rust `crates/agent-core/src/clipboard.rs`. Messages ride as the payload
 * of a `Frame` tagged `ChannelId.Clipboard` on the single "frames" data channel (see transport.ts).
 * The wire shape is **adjacently-tagged** JSON — `{"t":<variant>,"c":<content>}` — exactly like
 * input.ts. Only a `Text` variant exists in v1; the shape is kept a discriminated union so future
 * formats (image/HTML/file) can be added without a breaking change.
 *
 * Keep this in lockstep with the Rust unit tests: the exact JSON strings here are the same literals
 * the Rust `round_trip` asserts (`{"t":"Text","c":"…"}`, incl. the empty string).
 *
 * ## Browser constraints (important)
 *
 * The async Clipboard API is gated by the browser: `navigator.clipboard.readText()` requires the
 * page to be focused AND a **user gesture** (a click/keypress) plus the `clipboard-read` permission;
 * `writeText()` similarly needs a secure context (https/localhost) and usually focus. There is **no**
 * reliable "clipboard changed" event, so the controller can only push its clipboard opportunistically
 * (e.g. on focus/paste/copy events behind a gesture) — this client exposes {@link sendText} for that.
 *
 * ## Inbound consent (docs/25 F08)
 *
 * Inbound remote text is NOT applied by default. A new {@link ClipboardClient} starts with receive
 * disabled and callers must invoke {@link ClipboardClient.setReceiveEnabled} with `true` from an
 * explicit UI gesture to accept remote writes. The opt-in is per-instance and never persisted; a
 * fresh session gets a fresh disabled client. Frames that arrive while disabled are dropped before
 * any parse/decode or OS call. When enabled, writes are size-bounded, rate-bounded, and serialized:
 * one native write at a time, no queue, excess dropped.
 */

import { ChannelId } from "./protocol";

/** A single clipboard message. Mirror of the Rust `ClipboardMessage` enum. */
export type ClipboardMessage = { t: "Text"; c: string };

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });

/**
 * Encode one {@link ClipboardMessage} to its canonical JSON wire bytes (UTF-8), byte-compatible with
 * Rust `clipboard::decode`. This is the clipboard **payload** only — the caller wraps it in a `Frame`
 * tagged {@link ChannelId.Clipboard}.
 */
export function encodeMessage(msg: ClipboardMessage): Uint8Array {
  // Pin the field order to serde's output (`t` then `c`) so the JSON is byte-identical to Rust.
  return encoder.encode(JSON.stringify({ t: msg.t, c: msg.c }));
}

/** Decode one {@link ClipboardMessage} from canonical JSON wire bytes. */
export function decodeMessage(bytes: Uint8Array): ClipboardMessage {
  if (bytes.length === 0) throw new Error("empty clipboard payload");
  const obj = JSON.parse(decoder.decode(bytes)) as ClipboardMessage;
  if (!obj || obj.t !== "Text" || typeof obj.c !== "string") {
    throw new Error("malformed clipboard message");
  }
  return obj;
}

/** Convenience constructor for a text message. */
export const text = (s: string): ClipboardMessage => ({ t: "Text", c: s });

// --- minimal client ----------------------------------------------------------------------------

/**
 * The subset of `navigator.clipboard` this client needs. Declared as a seam so tests can inject a
 * fake without a DOM (the real one is `navigator.clipboard`, available only in a secure context).
 */
export interface ClipboardApi {
  readText(): Promise<string>;
  writeText(text: string): Promise<void>;
}

/** Use the document that owns the clicked control, including a separate pop-out window. */
export function clipboardForWindow(win: Window | null): ClipboardApi {
  return {
    readText: () => win?.navigator.clipboard?.readText()
      ?? Promise.reject(new Error("clipboard API unavailable")),
    writeText: text => win?.navigator.clipboard?.writeText(text)
      ?? Promise.reject(new Error("clipboard API unavailable")),
  };
}

/** Kinds of own-side notices this client emits — content is NEVER included, only a byte count. */
export type ClipboardNoticeKind =
  | "written"
  | "too-large"
  | "rate-limited"
  | "malformed"
  | "permission-failed";

export interface ClipboardNotice {
  kind: ClipboardNoticeKind;
  /** UTF-8 byte size when meaningful (accepted write / oversized reject). Undefined otherwise. */
  bytes?: number;
}

/** Maximum outbound UTF-8 byte length, matching the agent's 1 MiB inbound clipboard limit. */
export const MAX_CLIPBOARD_SEND_BYTES = 1024 * 1024;

/** Optional tuning + wiring for a {@link ClipboardClient}. Never persisted; strictly per-instance. */
export interface ClipboardClientOptions {
  /** Cap on decoded UTF-8 byte length (default 64 KiB). Must be a positive safe integer. */
  maxTextBytes?: number;
  /** Minimum gap between accepted writes, in the same units as `now()` (default 250 ms). */
  minWriteIntervalMs?: number;
  /** Monotonic clock. Defaults to `performance.now` — tests inject a controllable source. */
  now?: () => number;
  /** Own-status callback (rate-bounded/coalesced). Content of remote text is never passed. */
  onNotice?: (n: ClipboardNotice) => void;
}

/**
 * Absolute ceiling on inbound pre-decode byte size, derived from `maxTextBytes`. Six bytes per source
 * byte covers the worst-case JSON string escape (a lone control char → `\u00XX`), plus 64 bytes for
 * the `{"t":"Text","c":""}` frame. Computed at construction after `maxTextBytes` is validated so the
 * arithmetic cannot overflow a safe integer.
 */
function derivePreDecodeCap(maxTextBytes: number): number {
  // maxTextBytes <= 2^30 is enforced below; 6*x + 64 stays well within Number.MAX_SAFE_INTEGER.
  return 6 * maxTextBytes + 64;
}

function assertPositiveSafeInt(name: string, v: number, max: number): number {
  if (!Number.isFinite(v) || !Number.isInteger(v) || v <= 0 || v > max) {
    throw new RangeError(`ClipboardClient: ${name} must be a positive safe integer <= ${max}`);
  }
  return v;
}

/**
 * Minimal bidirectional clipboard client over the session data channel.
 *
 * Inbound receive is DEFAULT OFF (docs/25 F08). Enable it with {@link setReceiveEnabled}. Outbound
 * push is gesture-driven via {@link sendText}. Dispose the client on session teardown; a disposed
 * client drops all late frames and refuses new sends.
 */
export class ClipboardClient {
  private readonly send: (payload: Uint8Array) => void;
  private readonly clipboard: ClipboardApi;
  private receiveClipboard: ClipboardApi;
  private readonly maxTextBytes: number;
  private readonly preDecodeCap: number;
  private readonly minWriteIntervalMs: number;
  private readonly now: () => number;
  private onNotice: ((n: ClipboardNotice) => void) | undefined;

  /** Last text we sent or successfully applied, to avoid re-pushing an unchanged value. */
  private lastSeen: string | null = null;
  private receiveEnabled = false;
  private disposed = false;
  private writeInFlight = false;
  /** Last admitted parsing attempt, including malformed or oversized frames. */
  private lastProcessedAt = Number.NEGATIVE_INFINITY;
  /** Coalescing state so an attacker cannot amplify onNotice via one call per frame. */
  private lastNoticeAt = Number.NEGATIVE_INFINITY;
  /**
   * Bumped whenever receive-enabled changes or dispose runs; a native write in flight when the
   * generation moves MUST NOT commit `lastSeen` on completion, because the session it belonged to is
   * no longer the live one.
   */
  private stateGen = 0;

  constructor(
    send: (payload: Uint8Array) => void,
    clipboard: ClipboardApi,
    options: ClipboardClientOptions = {},
  ) {
    this.send = send;
    this.clipboard = clipboard;
    this.receiveClipboard = clipboard;
    // Cap maxTextBytes at 2^30 so 6*x + 64 stays a safe integer without special-casing.
    this.maxTextBytes = assertPositiveSafeInt(
      "maxTextBytes",
      options.maxTextBytes ?? 64 * 1024,
      1 << 30,
    );
    this.minWriteIntervalMs = assertPositiveSafeInt(
      "minWriteIntervalMs",
      options.minWriteIntervalMs ?? 250,
      24 * 60 * 60 * 1000,
    );
    this.preDecodeCap = derivePreDecodeCap(this.maxTextBytes);
    this.now = options.now ?? (() => performance.now());
    this.onNotice = options.onNotice;
  }

  /** Whether inbound remote text is currently being applied. */
  isReceiveEnabled(): boolean {
    return this.receiveEnabled && !this.disposed;
  }

  /**
   * Toggle inbound application. `true` requires an explicit UI gesture in the caller — this seam does
   * not attempt to prove one. Turning off is immediate: any frame arriving after this call is dropped
   * before parse. A native write already handed to the OS cannot be cancelled — see class docs.
   */
  setReceiveEnabled(enabled: boolean, clipboard: ClipboardApi = this.clipboard): void {
    if (this.disposed) return;
    const target = enabled ? clipboard : this.clipboard;
    if (this.receiveEnabled === enabled && this.receiveClipboard === target) return;
    this.receiveEnabled = enabled;
    this.receiveClipboard = target;
    this.stateGen++;
  }

  /**
   * Idempotently release the client. Blocks future inbound writes and outbound sends, drops the
   * notice callback so a stale UI cannot be re-entered, and ignores any late frames. An in-flight
   * native write started before dispose will settle in the background; its completion is discarded.
   */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.receiveEnabled = false;
    this.receiveClipboard = this.clipboard;
    this.onNotice = undefined;
    this.lastSeen = null;
    this.stateGen++;
  }

  /**
   * Read the local clipboard and, if it changed since we last saw it, send it to the agent. Must be
   * called from within a user gesture (browser requirement for `readText`). Resolves to the text that
   * was sent, or `null` if unchanged / unreadable / too large / disposed. A rejected send does not throw.
   */
  /**
   * Why the last `sendText` sent nothing (or that it sent). `sendText` returns `null` for every
   * no-send case; a control that tells the technician what happened reads this to say WHICH one —
   * "could not read your clipboard" and "already sent" call for different actions (Ed, 2026-10-24:
   * one message for both hid which was happening).
   */
  lastSendOutcome: "sent" | "unchanged" | "unreadable" | "too-large" | "failed" | "disposed" | null = null;

  async sendText(clipboard: ClipboardApi = this.clipboard): Promise<string | null> {
    if (this.disposed) { this.lastSendOutcome = "disposed"; return null; }
    let current: string;
    try {
      current = await clipboard.readText();
    } catch {
      this.lastSendOutcome = "unreadable";
      return null; // no permission / not focused — best-effort
    }
    // The client may have been disposed while we awaited readText; do not send through a stale
    // transport seam. The caller may have already wired a new session onto the same App-level ref.
    if (this.disposed) { this.lastSendOutcome = "disposed"; return null; }
    if (current === this.lastSeen) { this.lastSendOutcome = "unchanged"; return null; } // nothing to push
    // Every UTF-16 unit is at least one UTF-8 byte, so a long string is rejected before it is encoded
    // (Codex clip r1: a multi-MB clipboard would otherwise be encoded on every focus).
    if (current.length > MAX_CLIPBOARD_SEND_BYTES || new TextEncoder().encode(current).length > MAX_CLIPBOARD_SEND_BYTES) {
      this.lastSendOutcome = "too-large";
      return null;
    }
    try {
      this.send(encodeMessage(text(current)));
    } catch {
      // A failed send is retryable; do not claim success or suppress the next explicit attempt.
      this.lastSendOutcome = "failed";
      return null;
    }
    if (!this.disposed) this.lastSeen = current;
    this.lastSendOutcome = "sent";
    return current;
  }

  /**
   * Route one inbound `ChannelId.Clipboard` payload.
   *
   * Drops silently when disposed or receive-disabled — WITHOUT parsing, decoding or retaining any
   * bytes of remote text. When enabled, bounds parsing attempts, raw frame size, decoded text size
   * and simultaneous native writes. All notice kinds share one notification rate budget.
   */
  async handleMessage(payload: Uint8Array): Promise<void> {
    // Default-off short-circuit: no parse, no OS call, no retained buffer, no notice per drop.
    if (this.disposed || !this.receiveEnabled) return;

    // Charge attempts BEFORE decode or validation, so malformed traffic cannot bypass the limit.
    const t = this.now();
    if (t - this.lastProcessedAt < this.minWriteIntervalMs) {
      this.notice({ kind: "rate-limited" });
      return;
    }

    // One native write at a time, no queue. Toggling receive does not free this slot early.
    if (this.writeInFlight) {
      this.notice({ kind: "rate-limited" });
      return;
    }
    this.lastProcessedAt = t;

    if (payload.length > this.preDecodeCap) {
      this.notice({ kind: "too-large", bytes: payload.length });
      return;
    }

    // 4. Decode + validate variant.
    let msg: ClipboardMessage;
    try {
      msg = decodeMessage(payload);
    } catch {
      this.notice({ kind: "malformed" });
      return;
    }

    // 5. Post-decode UTF-8 byte cap on the accepted text. Encoding once here also gives us the exact
    //    byte count the notice reports — no measure/mismatch drift.
    if (msg.c.length > this.maxTextBytes) {
      this.notice({ kind: "too-large" });
      return;
    }
    const encoded = encoder.encode(msg.c);
    if (encoded.length > this.maxTextBytes) {
      this.notice({ kind: "too-large", bytes: encoded.length });
      return;
    }

    this.writeInFlight = true;
    const genAtStart = this.stateGen;
    try {
      await this.receiveClipboard.writeText(msg.c);
      // Commit echo-suppression ONLY on success AND only if the session is still the same — a toggle
      // off, dispose, or re-enable during the await moves stateGen and invalidates our commit.
      if (!this.disposed && this.receiveEnabled && this.stateGen === genAtStart) {
        this.lastSeen = msg.c;
        this.notice({ kind: "written", bytes: encoded.length });
      }
    } catch {
      // Failed writes must NOT update lastSeen: if the operator later copies the same string
      // locally, we still owe the agent an outbound push (otherwise a failed inbound silently
      // suppresses a legitimate outbound gesture).
      if (!this.disposed && this.stateGen === genAtStart) {
        this.notice({ kind: "permission-failed" });
      }
    } finally {
      // Always release the in-flight slot — even after dispose — so the counter cannot leak.
      this.writeInFlight = false;
    }
  }

  /** All kinds share one budget: alternating error kinds must not amplify UI notifications. */
  private notice(n: ClipboardNotice): void {
    const cb = this.onNotice;
    if (!cb) return;
    const t = this.now();
    if (t - this.lastNoticeAt < this.minWriteIntervalMs) {
      return;
    }
    this.lastNoticeAt = t;
    try {
      cb(n);
    } catch {
      // A throwing observer must not break cleanup or subsequent frames.
    }
  }
}

/** The `ChannelId` this client's frames ride on (re-exported for callers wiring the transport). */
export const CLIPBOARD_CHANNEL = ChannelId.Clipboard;
