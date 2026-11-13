/**
 * Backstage audit-chain forwarding client (Milestone H2, browser side).
 *
 * The agent builds a SHA-256 hash-chained audit trail per backstage session
 * (agent/src/backstage/audit.rs) and returns each event to the controller inside the backstage
 * `Envelope` (agent/src/transport/backstage_api.rs, field `audit`). This client batches those
 * events and POSTs them to the control plane's `POST /audit/ingest` for central, tamper-evident
 * storage. The request/response shapes mirror the Go contract in `control-plane/audit.go`
 * (`auditIngestRequest` / `auditIngestResponse`) exactly.
 *
 * WHO FORWARDS: the CONTROLLER — the authenticated technician session that already receives the
 * backstage envelopes — is the authenticated forwarder. `POST /audit/ingest` sits behind the same
 * auth → tenant (RLS) middleware as every other control-plane route and is gated on
 * `backstage_shell`. The agent needs no new emission for H2: it already delivers each `AuditEvent`
 * in the envelope; this client simply extracts and forwards them.
 *
 * SEAM NOTE: a backstage client + `Envelope` DO exist (`web/viewer/src/backstage/client.ts`), and
 * every `BackstageClient` method returns the full envelope. However, that module's `AuditEvent`
 * interface is a lenient UI projection: it declares only `hash` / `outcome` / a few optional fields
 * and OMITS the identity fields the control plane requires (`session_id`, `technician_id`,
 * `machine_id`, `id`, `occurred_at_unix_ms`). At runtime the full agent event is present (the
 * Rust envelope serializes the whole struct and `parseEnvelope` passes the object through untyped),
 * so forwarding works — but the fully-typed path is the seam: the backstage client should surface
 * the complete audit-event type. Until then this forwarder defines the authoritative wire contract
 * ({@link AuditEvent}) and {@link envelopeAudit} reads the minimal `{ ok, audit }` surface both
 * envelope shapes share. The batching/ordering/dedupe logic and exact wire shape are what H2 pins.
 */

/** One audit event — field-for-field mirror of the Rust `AuditEvent` / Go `AuditEvent`. */
export interface AuditEvent {
  id: string;
  seq: number;
  session_id: string;
  technician_id: string;
  machine_id: string;
  occurred_at_unix_ms: number;
  /** Internally-tagged Rust `AuditAction` (`{"kind":...}`) — opaque to the forwarder. */
  action: unknown;
  /** Internally-tagged Rust `Outcome` (`{"result":...}`) — opaque to the forwarder. */
  outcome: unknown;
  /** Hex SHA-256 of the predecessor; "" for the first event (seq 0). */
  prev_hash: string;
  /** Hex SHA-256 of this event. */
  hash: string;
  /** Agent origin proof; absent on legacy records. Forward unchanged. */
  agent_pubkey?: string;
  agent_signature?: string;
}

/** Body of `POST /audit/ingest` — mirror of Go `auditIngestRequest`. */
export interface AuditIngestRequest {
  session_id: string;
  events: AuditEvent[];
}

/** Response of `POST /audit/ingest` — mirror of Go `auditIngestResponse`. */
export interface AuditIngestResponse {
  accepted: number;
  tail_seq: number;
  tail_hash: string;
}

/** The minimal backstage-envelope surface this forwarder reads: the optional `audit` event. */
export interface BackstageEnvelopeLike {
  ok: boolean;
  audit?: AuditEvent | null;
}

/**
 * Extract the audit event from a backstage envelope, if present. The dispatcher records even
 * denials, so `audit` is present whenever the request reached the chain; a "no grant installed"
 * denial carries none (returns null).
 */
export function envelopeAudit(env: BackstageEnvelopeLike): AuditEvent | null {
  return env.audit ?? null;
}

/** Injected POST transport, so tests pin the request shape with no real network. */
export type PostJson = (
  url: string,
  body: AuditIngestRequest,
  opts?: { keepalive?: boolean },
) => Promise<AuditIngestResponse>;

/** Default endpoint + batch size. A session's chain is forwarded in bounded batches. */
const DEFAULT_ENDPOINT = "/audit/ingest";
const DEFAULT_BATCH_SIZE = 256;
/**
 * Request-body budget for a `keepalive` batch. Browsers cap the bodies of ALL in-flight keepalive
 * requests from a page at 64 KiB, and reject (not truncate) one that would exceed it, so the unload
 * batch stays well under that with room for the session id and JSON framing.
 */
export const KEEPALIVE_BODY_BUDGET = 60 * 1024;
/**
 * How long a flush holds back events past a seq gap before sending them anyway. The agent seals
 * events on more than one thread (the session loop, the Backstage worker, the upload writer) and
 * they reach the console on different channels, so seq N+1 can arrive just before N. Posting across
 * that gap is a batch the control plane rejects; waiting a moment lets N arrive and close it. A gap
 * that outlives this is not reordering, and the old behaviour (post, and surface the rejection)
 * applies.
 */
export const GAP_HOLD_MS = 5_000;

/**
 * Buffers backstage audit events for one session and forwards them to the control plane in
 * seq-ordered batches. De-duplicates by `seq` (so a re-delivered event is never double-sent) and
 * ignores events from a different session (defensive — a forwarder is per-session). {@link flush}
 * sends pending events oldest-first so the chain linkage the control plane verifies is preserved
 * on the wire; batches are sent sequentially (each awaited) so the stored tail advances in order.
 */
export class AuditForwarder {
  private readonly pending: AuditEvent[] = [];
  private readonly seen = new Set<number>();
  private acknowledgedSeq = -1;
  private pendingBytes = 0;
  private failure: Error | null = null;
  private flushing: Promise<AuditIngestResponse[]> | null = null;
  private readonly onError?: (error: Error) => void;
  /** When the current seq gap was first seen by a flush (null: no gap). */
  private gapSince: number | null = null;
  private readonly now: () => number;

  private fail(message: string): void {
    if (!this.failure) {
      this.failure = new Error(message);
      this.onError?.(this.failure);
    }
  }
  private readonly endpoint: string;
  private readonly batchSize: number;
  /** The chain this forwarder is bound to. `null` until the first event ADOPTS one — see below. */
  private sessionId: string | null;

  /**
   * `sessionId` is a HINT, not a decision. Pass `null` to bind to whatever the agent's first event
   * says its chain is.
   *
   * **Why adoption, and not the console deciding (loop 91).** The agent chains under the session id
   * SIGNALING vouched for, and on a deployment that verifies no session tickets signaling vouches
   * for nothing — so the agent falls back to the id inside the installed backstage grant. The
   * console cannot know in advance which of those two happened, and if it guesses wrong every event
   * is silently dropped by the filter below and the entire trail vanishes with no error anywhere
   * (flush failures are swallowed by design). Binding to what the agent actually chained under makes
   * the two definitionally equal.
   *
   * This weakens nothing. The id was never an authorization input: `POST /audit/ingest` authorizes
   * on the CALLER's capability and refuses any event whose `technician_id` is not the authenticated
   * forwarder, and it already required every event in a batch to carry the request's session id —
   * which is exactly what this preserves, one chain per forwarder, no mixing.
   */
  constructor(
    sessionId: string | null,
    private readonly postJson: PostJson,
    opts: { endpoint?: string; batchSize?: number; onError?: (error: Error) => void; now?: () => number } = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.sessionId = sessionId;
    this.endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
    this.batchSize = Math.max(1, Math.min(DEFAULT_BATCH_SIZE, Math.floor(opts.batchSize || DEFAULT_BATCH_SIZE)));
    this.onError = opts.onError;
  }

  /** The chain this forwarder is bound to, or `null` if no event has arrived to bind it. */
  get boundSessionId(): string | null {
    return this.sessionId;
  }

  /** Number of buffered events not yet flushed. */
  get pendingCount(): number {
    return this.pending.length;
  }

  /**
   * Buffer one or more audit events for forwarding. Events for a different session or an already
   * seen `seq` are ignored. Accepts either raw {@link AuditEvent}s or `null` (e.g. the result of
   * {@link envelopeAudit} on a no-audit denial), which is skipped.
   */
  enqueue(events: AuditEvent | AuditEvent[] | null): void {
    if (events == null || this.failure) return;
    const arr = Array.isArray(events) ? events : [events];
    for (const e of arr) {
      if (e == null) continue;
      if (!Number.isSafeInteger(e.seq) || e.seq < 0 || typeof e.session_id !== "string" || e.session_id.length > 128) {
        this.fail("Audit forwarding stopped: malformed event; the audit trail may be incomplete.");
        return;
      }
      // Bind on the FIRST event. From then on the filter is exactly as strict as before: a second
      // chain's events are dropped rather than mixed into this one's batch, which is what the
      // control plane's per-session linkage check requires.
      if (this.sessionId === null) this.sessionId = e.session_id;
      if (e.session_id !== this.sessionId) continue;
      if (e.seq <= this.acknowledgedSeq || this.seen.has(e.seq)) continue;
      let encoded: string;
      try { encoded = JSON.stringify(e); } catch {
        this.fail("Audit forwarding stopped: malformed event; the audit trail may be incomplete."); return;
      }
      if (encoded.length > 64 * 1024 || this.pending.length >= 1024 || this.pendingBytes + encoded.length * 2 > 4 * 1024 * 1024) {
        this.fail("Audit forwarding stopped: buffer limit reached; the audit trail is incomplete."); return;
      }
      this.pendingBytes += encoded.length * 2;
      this.seen.add(e.seq);
      this.pending.push(JSON.parse(encoded) as AuditEvent);
    }
  }

  /** Convenience: pull the audit event out of a backstage envelope and buffer it. */
  enqueueEnvelope(env: BackstageEnvelopeLike): void {
    this.enqueue(envelopeAudit(env));
  }

  /**
   * Forward all buffered events, oldest-first, in batches. Returns one response per batch. On a
   * rejected batch the underlying POST rejects; already-sent batches are not rolled back here (the
   * control plane verified and stored each accepted batch atomically), and the un-sent remainder
   * stays buffered for a retry.
   */
  flush(opts: { keepaliveFirstBatch?: boolean } = {}): Promise<AuditIngestResponse[]> {
    if (this.failure) return Promise.reject(this.failure);
    // A flush already in flight is joined, not doubled. Its requests are ordinary ones, so on an
    // unload that coincides with an interval flush the keepalive variant does not apply; the
    // window is the one batch that interval flush is sending.
    if (!this.flushing) this.flushing = this.flushPending(!!opts.keepaliveFirstBatch).finally(() => { this.flushing = null; });
    return this.flushing;
  }

  /**
   * `keepaliveFirst`: the TEARDOWN flush. Teardown runs from `pagehide`, and an ordinary `fetch`
   * started there is abandoned when the page goes away, which lost up to a flush interval of the
   * session's last events. So the first batch is cut to {@link KEEPALIVE_BODY_BUDGET} and sent with
   * `keepalive`, which the browser completes after unload. Later batches go out normally: they reach
   * the server if the page survives (an in-app disconnect) and are abandoned only on a real unload.
   * A single event too large for the budget is sent without keepalive (a keepalive request over the
   * cap is rejected outright, which would lose it for certain).
   */
  private async flushPending(keepaliveFirst = false): Promise<AuditIngestResponse[]> {
    // Nothing bound means nothing buffered, and an unbound POST would be a 400 ("session_id is
    // required") that the caller swallows.
    if (this.sessionId === null) return [];
    this.pending.sort((a, b) => a.seq - b.seq);
    const responses: AuditIngestResponse[] = [];
    let sentCount = 0;
    while (this.pending.length > 0 && sentCount < 1024) {
      this.pending.sort((a, b) => a.seq - b.seq);
      // Only the contiguous run is sent while a gap is young (see GAP_HOLD_MS). The head may follow
      // the last acknowledged seq or, before anything was acknowledged, start anywhere (a chain the
      // server already holds a prefix of). The teardown flush holds nothing: it is the last chance.
      const run = this.contiguousRun();
      const hold = !keepaliveFirst && run < this.pending.length;
      if (hold) {
        if (this.gapSince === null) this.gapSince = this.now();
      } else {
        this.gapSince = null;
      }
      const gapExpired = hold && this.now() - (this.gapSince ?? 0) >= GAP_HOLD_MS;
      const sendable = hold && !gapExpired ? run : this.pending.length;
      if (sendable === 0) break;
      const batch: AuditEvent[] = [];
      let bytes = 0;
      for (const event of this.pending.slice(0, Math.min(this.batchSize, sendable))) {
        const size = new TextEncoder().encode(JSON.stringify(event)).length;
        if (batch.length && bytes + size > 512 * 1024) break;
        bytes += size;
        batch.push(event);
      }
      let keepalive = false;
      if (keepaliveFirst && responses.length === 0) {
        const bodyBytes = () => new TextEncoder().encode(JSON.stringify({ session_id: this.sessionId, events: batch })).length;
        while (batch.length > 1 && bodyBytes() > KEEPALIVE_BODY_BUDGET) batch.pop();
        keepalive = bodyBytes() <= KEEPALIVE_BODY_BUDGET;
      }
      const res = await this.postJson(
        this.endpoint,
        { session_id: this.sessionId, events: batch },
        keepalive ? { keepalive: true } : undefined,
      );
      if (res.accepted !== batch.length) throw new Error("Audit server did not acknowledge the complete batch");
      sentCount += batch.length;
      // Only drop the batch after a successful send, so a rejection leaves it buffered.
      const sent = new Set(batch.map((e) => e.seq));
      for (let i = this.pending.length - 1; i >= 0; i--) {
        const e = this.pending[i];
        if (!sent.has(e.seq)) continue;
        this.pendingBytes -= JSON.stringify(e).length * 2;
        this.seen.delete(e.seq);
        this.pending.splice(i, 1);
      }
      this.acknowledgedSeq = Math.max(this.acknowledgedSeq, ...batch.map((e) => e.seq));
      responses.push(res);
      if (this.contiguousRun() === this.pending.length) this.gapSince = null;
    }
    return responses;
  }

  /** How many of the (sorted) pending events form a gap-free run from the expected next seq. */
  private contiguousRun(): number {
    if (this.pending.length === 0) return 0;
    if (this.acknowledgedSeq >= 0 && this.pending[0].seq !== this.acknowledgedSeq + 1) return 0;
    let n = 1;
    while (n < this.pending.length && this.pending[n].seq === this.pending[n - 1].seq + 1) n++;
    return n;
  }
}
