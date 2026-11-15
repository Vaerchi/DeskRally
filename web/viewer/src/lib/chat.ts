/**
 * Canonical in-session chat codec + transcript client (browser side, M12).
 *
 * Byte-for-byte mirror of the Rust `crates/agent-core/src/chat.rs`, which is the authoritative
 * contract — its unit tests and `chat.test.ts` pin the SAME JSON literals, and each file names the
 * other. Messages ride as the payload of a `Frame` tagged `ChannelId.Chat` on the single "frames"
 * data channel (see transport.ts). The wire shape is **adjacently-tagged** JSON —
 * `{"t":<variant>,"c":<content>}` — exactly like clipboard.ts / control.ts / file_transfer.ts.
 *
 * ## The flow
 *
 * 1. either side → other: `Send` — a line of text someone typed.
 * 2. agent → controller: `Posted` — the message as **recorded**, carrying the sequence number and
 *    timestamp the agent's transcript assigned it.
 * 3. controller → agent: `RequestHistory { since_seq }` — "replay what I missed".
 * 4. agent → controller: `History { entries, truncated }` — the backlog.
 *
 * ## Why the AGENT assigns the sequence numbers (and what that buys this file)
 *
 * The agent is the only party present for every session with its machine, so it is the only one that
 * can order a transcript spanning several technicians and several connections. That is what makes
 * `since_seq` a resumable **cursor** instead of a guess: {@link ChatClient.requestHistory} asks for
 * everything after the highest sequence it already holds and receives exactly the gap — not a
 * duplicate of the whole conversation, which is what a timestamp cursor yields the moment two
 * messages share a millisecond.
 *
 * It also means this client never invents an entry. A message the operator types appears in the log
 * only once the agent echoes it back as `Posted`, so what the technician reads is the recorded
 * transcript rather than a local optimistic guess that may not have survived the trip.
 */

import { ChannelId } from "./protocol";

/**
 * Who wrote a message. Mirror of the Rust `ChatFrom`, a unit-only enum, so it serializes as a **bare
 * string** (`"Technician"` / `"Guest"`), not an object.
 *
 * Deliberately a role and not a name: the agent cannot authenticate a display name — it receives
 * whatever the controller sends — so a transcript recording "Alice" would be recording a claim as if
 * it were a fact. The role is something the agent knows: one side of the connection is the remote
 * technician, the other is the person at the machine.
 */
export type ChatFrom = "Technician" | "Guest";

/**
 * One recorded chat line. Mirror of the Rust `ChatEntry` (serde field order: seq, from, body,
 * at_unix_ms).
 *
 * `seq` is a `u64` in Rust and a `number` here; `at_unix_ms` is an `i64`. Both are safe rather than
 * lucky: `seq` counts messages a human typed on ONE machine, and `at_unix_ms` does not reach
 * `Number.MAX_SAFE_INTEGER` until the year 275760.
 */
export interface ChatEntry {
  /** Monotonic per-machine sequence number, assigned by the agent. Starts at 1. */
  seq: number;
  /** Which side wrote it. */
  from: ChatFrom;
  /** The text, already truncated to {@link MAX_BODY_CHARS} by the agent. */
  body: string;
  /** Unix milliseconds when the agent recorded it. */
  at_unix_ms: number;
}

/** A single chat message. Mirror of the Rust `ChatMessage` enum (adjacently tagged). */
export type ChatMessage =
  // Either side → the other: a line someone typed. The sender does NOT assign a sequence number or
  // timestamp; the agent's transcript does, and echoes them back in `Posted`.
  | { t: "Send"; c: { from: ChatFrom; body: string } }
  // agent → controller: a message as recorded. Sent for EVERY message the transcript accepts,
  // including this controller's own — so our view of the transcript is the agent's, not a guess.
  | { t: "Posted"; c: { entry: ChatEntry } }
  // controller → agent: replay everything after `since_seq`. `0` means "everything you have".
  | { t: "RequestHistory"; c: { since_seq: number } }
  // agent → controller: the requested backlog, oldest first. `truncated` says entries were omitted.
  | { t: "History"; c: { entries: ChatEntry[]; truncated: boolean } };

/**
 * Longest accepted message body, in **characters** (code points, not UTF-16 units and not bytes).
 * Mirror of the Rust `MAX_BODY_CHARS`.
 */
export const MAX_BODY_CHARS = 4000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * The nested `entry` object, rebuilt in serde declaration order.
 *
 * `JSON.stringify` emits string keys in insertion order, so the ONLY thing keeping our bytes equal to
 * serde's is the order the properties are written here. Two variants carry entries (`Posted` and
 * `History`), and duplicating the literal would mean a field reorder could be fixed in one and missed
 * in the other — so the order lives here, once, and both arms call it (the technique control.ts uses
 * for `QualitySettings`).
 */
function entryJson(e: ChatEntry) {
  return { seq: e.seq, from: e.from, body: e.body, at_unix_ms: e.at_unix_ms };
}

/**
 * Encode one {@link ChatMessage} to its canonical JSON wire bytes (UTF-8), byte-compatible with Rust
 * `chat::decode`. This is the chat **payload** only — the caller wraps it in a `Frame` tagged
 * {@link ChannelId.Chat}. Field order is pinned to serde's output so the bytes are identical.
 */
export function encodeChat(msg: ChatMessage): Uint8Array {
  let obj: unknown;
  switch (msg.t) {
    case "Send":
      obj = { t: msg.t, c: { from: msg.c.from, body: msg.c.body } };
      break;
    case "Posted":
      obj = { t: msg.t, c: { entry: entryJson(msg.c.entry) } };
      break;
    case "RequestHistory":
      obj = { t: msg.t, c: { since_seq: msg.c.since_seq } };
      break;
    case "History":
      // The controller never sends this, but pinning the encoder keeps the golden vectors symmetric
      // with Rust's own round-trip test — a field reorder here fails a test instead of shipping.
      obj = { t: msg.t, c: { entries: msg.c.entries.map(entryJson), truncated: msg.c.truncated } };
      break;
  }
  return encoder.encode(JSON.stringify(obj));
}

/**
 * Validate + rebuild one {@link ChatEntry}. Throws on any missing or wrongly-typed field.
 *
 * Strict, and `from` most of all: defaulting an unparseable role would attribute a line to the wrong
 * side of the conversation, and a support transcript that says the technician wrote what the customer
 * wrote is worse than no transcript at all. A missing field is rejected, never defaulted — a `seq` of
 * 0 invented here would collide with the "I have nothing" cursor value and poison the resume logic.
 */
function decodeEntry(v: unknown): ChatEntry {
  const e = v as Partial<ChatEntry> | undefined;
  if (
    !e ||
    typeof e.seq !== "number" || !Number.isSafeInteger(e.seq) || e.seq <= 0 ||
    (e.from !== "Technician" && e.from !== "Guest") ||
    typeof e.body !== "string" || e.body.length > MAX_BODY_CHARS * 2 || Array.from(e.body).length > MAX_BODY_CHARS ||
    typeof e.at_unix_ms !== "number" || !Number.isSafeInteger(e.at_unix_ms)
  ) {
    throw new Error("malformed ChatEntry");
  }
  return { seq: e.seq, from: e.from, body: e.body, at_unix_ms: e.at_unix_ms };
}

/** Decode one {@link ChatMessage} from canonical JSON wire bytes. Throws on a malformed shape. */
export function decodeChat(bytes: Uint8Array): ChatMessage {
  if (bytes.length > 4 * 1024 * 1024) throw new Error("chat payload exceeds limit");
  if (bytes.length === 0) throw new Error("empty chat payload");
  const obj = JSON.parse(decoder.decode(bytes)) as { t?: string; c?: unknown };
  switch (obj.t) {
    case "Send": {
      const c = obj.c as { from?: unknown; body?: unknown } | undefined;
      if (!c || (c.from !== "Technician" && c.from !== "Guest") || typeof c.body !== "string") {
        throw new Error("malformed Send");
      }
      return { t: "Send", c: { from: c.from, body: c.body } };
    }
    case "Posted": {
      const c = obj.c as { entry?: unknown } | undefined;
      if (!c) throw new Error("malformed Posted");
      return { t: "Posted", c: { entry: decodeEntry(c.entry) } };
    }
    case "RequestHistory": {
      const c = obj.c as { since_seq?: unknown } | undefined;
      if (!c || typeof c.since_seq !== "number") throw new Error("malformed RequestHistory");
      return { t: "RequestHistory", c: { since_seq: c.since_seq } };
    }
    case "History": {
      const c = obj.c as { entries?: unknown; truncated?: unknown } | undefined;
      if (!c || !Array.isArray(c.entries) || c.entries.length > 200 || typeof c.truncated !== "boolean") {
        throw new Error("malformed History");
      }
      return { t: "History", c: { entries: c.entries.map(decodeEntry), truncated: c.truncated } };
    }
    default:
      throw new Error(`unknown chat variant ${String(obj.t)}`);
  }
}

// Convenience constructors — keep call sites terse and the tag/content shape in one place.

/** A line typed by this controller's operator. */
export const chatSend = (body: string, from: ChatFrom = "Technician"): ChatMessage => ({
  t: "Send",
  c: { from, body },
});

/** Ask the agent to replay everything after `sinceSeq` (`0` = the whole retained transcript). */
export const chatRequestHistory = (sinceSeq: number): ChatMessage => ({
  t: "RequestHistory",
  c: { since_seq: sinceSeq },
});

/**
 * Cut `body` to at most {@link MAX_BODY_CHARS} **code points**, the same rule the agent applies.
 *
 * `String.prototype.slice` would count UTF-16 units and could cut a surrogate pair in half, putting a
 * lone surrogate on the wire; `Array.from` iterates code points, so the cut always lands on a
 * character boundary — the browser mirror of Rust's `chars().take(MAX_BODY_CHARS)`.
 */
export function truncateChatBody(body: string): string {
  const chars = Array.from(body);
  return chars.length <= MAX_BODY_CHARS ? body : chars.slice(0, MAX_BODY_CHARS).join("");
}

// --- minimal client ----------------------------------------------------------------------------

/**
 * Minimal in-session chat client over the session data channel: sends what the operator types and
 * maintains the local view of the agent's transcript.
 *
 * Construct with a `send` bound to `transport.send(ChannelId.Chat, …)`. Call {@link send} to post a
 * line and {@link requestHistory} once the channel is up; feed every inbound `ChannelId.Chat` payload
 * to {@link handleMessage}. The accumulated transcript is readable via {@link messages} and pushed to
 * `onMessages` whenever it changes.
 */
export class ChatClient {
  private readonly sendPayload: (payload: Uint8Array) => void;
  /**
   * The transcript, keyed by the agent-assigned sequence. A Map rather than an array because
   * de-duplication by `seq` is the whole point — see {@link handleMessage}.
   */
  private readonly bySeq = new Map<number, ChatEntry>();
  /** {@link bySeq} sorted by sequence, rebuilt on change so `messages` is O(1) to read. */
  private ordered: ChatEntry[] = [];
  /** Sticky: set once the agent reports a `History` that omitted entries. */
  private hasHole = false;
  /** Fired with the whole ordered transcript whenever it gains an entry. */
  private readonly onMessages?: (messages: readonly ChatEntry[]) => void;
  /** Fired when the agent reports that a `History` reply omitted entries. */
  private readonly onTruncated?: () => void;
  /** Where an undecodable inbound frame goes. See {@link handleMessage}. */
  private readonly onError: (err: Error) => void;

  constructor(
    send: (payload: Uint8Array) => void,
    handlers: {
      onMessages?: (messages: readonly ChatEntry[]) => void;
      onTruncated?: () => void;
      onError?: (err: Error) => void;
    } = {},
  ) {
    this.sendPayload = send;
    this.onMessages = handlers.onMessages;
    this.onTruncated = handlers.onTruncated;
    // Default to `console.debug`, not `console.warn`: a frame from a newer agent is an expected
    // condition on a mixed-version fleet, not an operator-visible fault (as in control.ts).
    this.onError =
      handlers.onError ?? ((err) => console.debug("chat: dropping undecodable frame:", err.message));
  }

  /**
   * Post a line as the technician.
   *
   * Nothing appears in {@link messages} yet: the agent assigns the sequence and timestamp and echoes
   * the recorded entry back as `Posted`, which is what the operator ends up reading. Showing a local
   * copy immediately would show a message that may never have been recorded.
   *
   * The body is cut to {@link MAX_BODY_CHARS} here as well as on the agent. The agent truncates
   * rather than rejects, so this changes no outcome — it keeps a multi-megabyte paste off a channel
   * documented as "tiny", and because both sides cut at the same CHARACTER count the operator's
   * message and the recorded one agree exactly.
   */
  send(body: string): void {
    this.sendPayload(encodeChat(chatSend(truncateChatBody(body))));
  }

  /**
   * Ask the agent to replay everything after the highest sequence we already hold.
   *
   * NOT `0` — that is the point of the cursor. Asking from 0 on a reconnect would pull the entire
   * retained transcript back down and, before the dedupe in {@link handleMessage} existed, show the
   * operator every message twice. Asking from the high-water mark fetches exactly the gap. A fresh
   * client holds nothing, so its first call naturally asks for everything.
   */
  requestHistory(): void {
    this.sendPayload(encodeChat(chatRequestHistory(this.lastSeq)));
  }

  /** The transcript so far, oldest first. */
  get messages(): readonly ChatEntry[] {
    return this.ordered;
  }

  /**
   * The highest sequence held (`0` when empty — which is why the agent's sequences start at 1: it
   * makes "I have nothing" unambiguous rather than colliding with a real entry).
   */
  get lastSeq(): number {
    return this.ordered.length === 0 ? 0 : this.ordered[this.ordered.length - 1].seq;
  }

  /**
   * Whether the agent has reported that a `History` reply omitted entries, i.e. the transcript has a
   * hole. Sticky: a later complete reply does not heal a gap in the OLDER messages, and telling the
   * operator the conversation is complete when it is not is the failure `truncated` exists to prevent.
   */
  get truncated(): boolean {
    return this.hasHole;
  }

  /**
   * Route one inbound `ChannelId.Chat` payload (a `Posted` echo or a `History` reply).
   *
   * TOLERANT BY DESIGN, unlike {@link decodeChat}. This is called with no try/catch of its own from
   * `App.tsx`'s `onMessage`, which runs inside `transport.ts`'s `for (const f of frames)` loop over
   * every frame coalesced into a single SCTP message. A throw escaping here therefore abandons that
   * loop and discards the INNOCENT SIBLING frames behind the bad one — one unparseable line from a
   * newer agent could cost the operator the rest of the conversation that decoded fine.
   *
   * So the split is the same as control.ts's: the codec stays strict (it must never invent a value it
   * could not parse), and the client absorbs the failure, reports it to `onError`, and moves on.
   */
  handleMessage(payload: Uint8Array): void {
    let msg: ChatMessage;
    try {
      msg = decodeChat(payload);
    } catch (err) {
      this.onError(err as Error);
      return;
    }
    switch (msg.t) {
      case "Posted":
        this.merge([msg.c.entry]);
        break;
      case "History":
        this.merge(msg.c.entries);
        if (msg.c.truncated && !this.hasHole) {
          this.hasHole = true;
          this.onTruncated?.();
        }
        break;
      // Send / RequestHistory are controller→agent; never received here.
      default:
        break;
    }
  }

  /**
   * Merge entries into the transcript, de-duplicated by sequence and kept in sequence order.
   *
   * DE-DUPLICATION IS LOAD-BEARING, not tidiness. The same entry legitimately arrives twice: the
   * agent echoes every accepted message as `Posted`, and a subsequent `History` (after a reconnect,
   * or any second {@link requestHistory}) replays the retained window, which contains that same
   * entry. A naive append would show the operator the whole conversation twice.
   *
   * Sorting is likewise not cosmetic: `Posted` echoes and a `History` reply are separate frames and a
   * reply can land after an echo of a LATER message, so arrival order is not sequence order. The
   * operator reading a support conversation out of order would misread who answered what.
   *
   * First write wins for a repeated sequence — the agent assigns each sequence exactly once, so two
   * copies are the same entry, and keeping the first avoids re-rendering identical content.
   */
  private merge(entries: readonly ChatEntry[]): void {
    let added = false;
    for (const e of entries) {
      if (this.bySeq.has(e.seq)) continue;
      this.bySeq.set(e.seq, e);
      added = true;
    }
    if (!added) return;
    this.ordered = [...this.bySeq.values()].sort((a, b) => a.seq - b.seq);
    if (this.ordered.length > 500) {
      for (const e of this.ordered.splice(0, this.ordered.length - 500)) this.bySeq.delete(e.seq);
      if (!this.hasHole) { this.hasHole = true; this.onTruncated?.(); }
    }
    this.onMessages?.(this.ordered);
  }
}

/** The `ChannelId` this client's frames ride on (re-exported for callers wiring the transport). */
export const CHAT_CHANNEL = ChannelId.Chat;
