/**
 * Backstage over the session data channel (M5).
 *
 * Historically the {@link BackstageClient} spoke HTTP `POST /backstage/exec` via an injectable
 * {@link BackstageTransport} seam `(path, body) => Promise<string>`. M5 carries the exact same
 * `Request`/`Envelope` JSON over the WebRTC session transport instead: the browser sends a request
 * as `transport.send(ChannelId.Backstage, encodeBackstageRequest(req))` and the agent replies with
 * an `Envelope` frame on the same channel, delivered to `onMessage(ChannelId.Backstage, payload)`.
 *
 * {@link ChannelBackstageTransport} adapts that message-passing shape back onto the request/response
 * `BackstageTransport` seam so the existing typed `BackstageClient` works unchanged over the data
 * channel. Correlation is a FIFO queue: the agent dispatches backstage frames serially and replies
 * in order on one reliable, ordered channel, so the Nth reply answers the Nth request.
 *
 * Confirmation (docs/58 §3): there is no query string on the wire, so a confirmed retry carries the
 * agent's `confirm_token` inside the request body as a top-level `confirm` (BackstageClient.exec).
 *
 * Correlation is by ORDER, so a reply that never comes would pair every later reply with the wrong
 * request (docs/58 §2). The transport therefore CLOSES, for good, when a reply is overdue or a send
 * throws: every pending request is rejected and every later one refused. It is never reopened on
 * the same session channel, because the overdue reply could still arrive; a new session (a new data
 * channel and a new transport) is the only way back.
 */

import { parseEnvelope, type BackstageTransport, type Envelope, type Request } from "./client";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encode a backstage {@link Request} to the bytes sent on `ChannelId.Backstage`. */
export function encodeBackstageRequest(request: Request): Uint8Array {
  return encoder.encode(JSON.stringify(request));
}

/** Decode an `Envelope`-frame payload received on `ChannelId.Backstage`. */
export function decodeBackstageEnvelope(payload: Uint8Array): Envelope {
  return parseEnvelope(decoder.decode(payload));
}

/**
 * Adapts a raw send/receive backstage channel onto the request/response {@link BackstageTransport}
 * seam. Construct with a `send` bound to `transport.send(ChannelId.Backstage, …)`, feed inbound
 * `ChannelId.Backstage` payloads to {@link handleMessage}, and hand {@link asBackstageTransport} to
 * a {@link BackstageClient}.
 */
export class ChannelBackstageTransport {
  private readonly send: (payload: Uint8Array) => void;
  /** Resolvers/rejecters for in-flight requests, oldest first — answered in receive order. */
  private readonly pending: {
    resolve: (text: string) => void;
    reject: (err: Error) => void;
  }[] = [];
  /** Set once {@link close} runs so late sends fail fast instead of hanging forever. */
  private closed = false;
  /** Why the transport closed; the message every later request is rejected with. */
  private closedReason = "Under the Hood connection closed";
  /** How long a request may wait for its reply before the transport closes (docs/58 §2). */
  private readonly replyTimeoutMs: number;
  /** The overdue-reply timer for the OLDEST pending request, if any. */
  private timer: ReturnType<typeof setTimeout> | null = null;
  /** Optional observer of every inbound envelope — see the constructor. */
  private readonly onEnvelope?: (envelope: Envelope) => void;

  /**
   * `onEnvelope`, when given, is called with EVERY inbound envelope — including one that answers no
   * pending request, which `handleMessage` otherwise drops.
   *
   * It exists for audit forwarding (H2/ADR-008). Each envelope carries the agent's hash-chained
   * `audit` event for the action it answers, and the chain is only complete if every event reaches
   * the control plane; reading them off the individual panel call sites would mean every present
   * and future panel had to remember to forward, and one that forgot would break the chain's
   * linkage rather than merely omitting a row. Observing the transport is the one place all of them
   * necessarily pass through.
   *
   * A throwing observer is swallowed: it is a side-channel, and it must never cost a panel its
   * reply.
   */
  constructor(
    send: (payload: Uint8Array) => void,
    onEnvelope?: (envelope: Envelope) => void,
    replyTimeoutMs = 60_000,
  ) {
    this.send = send;
    this.onEnvelope = onEnvelope;
    this.replyTimeoutMs = replyTimeoutMs;
  }

  /** (Re)arm the overdue-reply timer for whatever request is now oldest. */
  private armTimer(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    if (this.closed || this.pending.length === 0) return;
    this.timer = setTimeout(
      () => this.close("Under the Hood stopped responding. Reconnect the session to use it again."),
      this.replyTimeoutMs,
    );
  }

  /**
   * Route one inbound `ChannelId.Backstage` payload (raw `Envelope` JSON bytes) to the oldest
   * in-flight request. Extra/unsolicited frames are ignored (but still reach `onEnvelope`).
   */
  handleMessage(payload: Uint8Array): void {
    const text = decoder.decode(payload);
    if (this.onEnvelope) {
      try {
        this.onEnvelope(parseEnvelope(text));
      } catch {
        // A malformed frame, or an observer that threw. Neither may cost the caller its reply.
      }
    }
    if (this.closed) return; // a reply after the close answers nothing (it may be the overdue one)
    const next = this.pending.shift();
    if (next) next.resolve(text);
    this.armTimer();
  }

  /**
   * Cancel the transport on session teardown: reject every in-flight request (so the panels show a
   * clean error rather than a promise that never settles) and refuse further sends. Idempotent.
   */
  close(reason = "Under the Hood connection closed"): void {
    if (!this.closed) this.closedReason = reason;
    this.closed = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    const err = new Error(this.closedReason);
    let next = this.pending.shift();
    while (next) {
      next.reject(err);
      next = this.pending.shift();
    }
  }

  /**
   * The {@link BackstageTransport} view: send the body on the channel and resolve with the next
   * envelope text. `path` is accepted for seam compatibility but unused (see the confirm-flow note
   * above — no query string travels over the channel).
   */
  asBackstageTransport(): BackstageTransport {
    return (_path: string, body: string): Promise<string> => {
      if (this.closed) return Promise.reject(new Error(this.closedReason));
      const text = new Promise<string>((resolve, reject) => {
        this.pending.push({ resolve, reject });
      });
      try {
        this.send(encoder.encode(body));
      } catch {
        // The request is queued but was never sent: leaving it queued would let the NEXT reply
        // answer it. Close, which rejects it and everything behind it.
        this.close("Under the Hood could not send to this machine. Reconnect the session to use it again.");
        return text;
      }
      if (this.pending.length === 1) this.armTimer();
      return text;
    };
  }
}
