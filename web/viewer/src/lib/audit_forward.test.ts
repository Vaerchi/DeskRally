/**
 * Audit-forward client tests — pins the `POST /audit/ingest` request shape (mirror of the Go
 * `auditIngestRequest` contract) and the batch / ordering / dedupe logic. No real network: the POST
 * transport is a recording stub.
 */

import { describe, it, expect, vi } from "vitest";
import {
  AuditForwarder,
  GAP_HOLD_MS,
  KEEPALIVE_BODY_BUDGET,
  envelopeAudit,
  type AuditEvent,
  type AuditIngestRequest,
  type AuditIngestResponse,
  type BackstageEnvelopeLike,
} from "./audit_forward";

const SESSION = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

function hex64(n: number): string {
  return n.toString(16).padStart(64, "0");
}

/** Structurally-valid linked event: hash(seq)=hex64(seq+1), prev=""@0 else hex64(seq). */
function ev(seq: number, sessionId = SESSION): AuditEvent {
  return {
    id: `00000000-0000-0000-0000-${String(seq).padStart(12, "0")}`,
    seq,
    session_id: sessionId,
    technician_id: "11111111-1111-1111-1111-111111111111",
    machine_id: "22222222-2222-2222-2222-222222222222",
    occurred_at_unix_ms: 1000 + seq,
    action: { kind: "service_control", service: "spooler", verb: "stop" },
    outcome: { result: "ok" },
    prev_hash: seq === 0 ? "" : hex64(seq),
    hash: hex64(seq + 1),
  };
}

/** A recording POST stub that echoes the tail of whatever batch it receives. */
function recordingPost() {
  const calls: AuditIngestRequest[] = [];
  const post = vi.fn(async (_url: string, body: AuditIngestRequest): Promise<AuditIngestResponse> => {
    calls.push(body);
    const last = body.events[body.events.length - 1];
    return { accepted: body.events.length, tail_seq: last.seq, tail_hash: last.hash };
  });
  return { calls, post };
}

describe("envelopeAudit", () => {
  it("extracts the audit event when present", () => {
    const env: BackstageEnvelopeLike = { ok: true, audit: ev(0) };
    expect(envelopeAudit(env)).toEqual(ev(0));
  });

  it("returns null for an envelope with no audit (e.g. no-grant denial)", () => {
    expect(envelopeAudit({ ok: false })).toBeNull();
    expect(envelopeAudit({ ok: false, audit: null })).toBeNull();
  });
});

describe("AuditForwarder", () => {
  it("forwards a single batch with the exact wire shape", async () => {
    const { calls, post } = recordingPost();
    const fwd = new AuditForwarder(SESSION, post);

    fwd.enqueue([ev(0), ev(1), ev(2)]);
    expect(fwd.pendingCount).toBe(3);

    const res = await fwd.flush();

    expect(post).toHaveBeenCalledTimes(1);
    expect(calls[0]).toEqual({ session_id: SESSION, events: [ev(0), ev(1), ev(2)] });
    expect(res).toEqual([{ accepted: 3, tail_seq: 2, tail_hash: hex64(3) }]);
    expect(fwd.pendingCount).toBe(0);
  });

  it("splits into batches of batchSize, oldest-first, preserving seq order", async () => {
    const { calls, post } = recordingPost();
    const fwd = new AuditForwarder(SESSION, post, { batchSize: 2 });

    // Enqueue out of order to prove flush sorts by seq.
    fwd.enqueue([ev(2), ev(0), ev(3), ev(1)]);
    await fwd.flush();

    expect(post).toHaveBeenCalledTimes(2);
    expect(calls[0].events.map((e) => e.seq)).toEqual([0, 1]);
    expect(calls[1].events.map((e) => e.seq)).toEqual([2, 3]);
  });

  it("de-duplicates by seq (re-delivered events are not double-sent)", async () => {
    const { calls, post } = recordingPost();
    const fwd = new AuditForwarder(SESSION, post);

    fwd.enqueue(ev(0));
    fwd.enqueue(ev(0)); // replay
    fwd.enqueue(ev(1));
    expect(fwd.pendingCount).toBe(2);

    await fwd.flush();
    expect(calls[0].events.map((e) => e.seq)).toEqual([0, 1]);
  });

  it("ignores events from a different session", () => {
    const { post } = recordingPost();
    const fwd = new AuditForwarder(SESSION, post);
    fwd.enqueue(ev(0, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
    expect(fwd.pendingCount).toBe(0);
  });

  it("enqueueEnvelope pulls the audit event out of an envelope", async () => {
    const { calls, post } = recordingPost();
    const fwd = new AuditForwarder(SESSION, post);

    fwd.enqueueEnvelope({ ok: true, audit: ev(0) });
    fwd.enqueueEnvelope({ ok: false }); // no audit → skipped
    expect(fwd.pendingCount).toBe(1);

    await fwd.flush();
    expect(calls[0].events.map((e) => e.seq)).toEqual([0]);
  });

  it("keeps the batch buffered when the POST rejects (retryable)", async () => {
    const post = vi.fn(async (): Promise<AuditIngestResponse> => {
      throw new Error("400 broken linkage");
    });
    const fwd = new AuditForwarder(SESSION, post);
    fwd.enqueue([ev(0), ev(1)]);

    await expect(fwd.flush()).rejects.toThrow("broken linkage");
    expect(fwd.pendingCount).toBe(2); // nothing dropped
  });

  it("rejects and keeps pending events when the server partially accepts the batch", async () => {
    const post = vi.fn(async (_url: string, body: AuditIngestRequest): Promise<AuditIngestResponse> => {
      return { accepted: body.events.length - 1, tail_seq: 0, tail_hash: hex64(1) };
    });
    const fwd = new AuditForwarder(SESSION, post);
    fwd.enqueue([ev(0), ev(1)]);

    await expect(fwd.flush()).rejects.toThrow("Audit server did not acknowledge the complete batch");
    expect(fwd.pendingCount).toBe(2);
  });
});


describe("hostile audit forwarding limits", () => {
  it("stops at a bounded backlog and reports an incomplete trail", async () => {
    const onError = vi.fn();
    const { post } = recordingPost();
    const forwarder = new AuditForwarder(SESSION, post, { onError });
    for (let seq = 0; seq < 3000; seq++) forwarder.enqueue(ev(seq));
    expect(forwarder.pendingCount).toBe(1024);
    expect(onError).toHaveBeenCalledTimes(1);
    await expect(forwarder.flush()).rejects.toThrow("incomplete");
    expect(post).not.toHaveBeenCalled();
  });
  it("rejects a giant event without retaining it", () => {
    const onError = vi.fn();
    const { post } = recordingPost();
    const forwarder = new AuditForwarder(SESSION, post, { onError });
    forwarder.enqueue({ ...ev(0), action: "x".repeat(65537) });
    expect(forwarder.pendingCount).toBe(0);
    expect(onError).toHaveBeenCalledTimes(1);
  });
  it("rejects an event with a NaN seq and does not retain it", () => {
    const onError = vi.fn();
    const { post } = recordingPost();
    const forwarder = new AuditForwarder(SESSION, post, { onError });
    forwarder.enqueue({ ...ev(0), seq: NaN });
    expect(onError).toHaveBeenCalledTimes(1);
    expect(forwarder.pendingCount).toBe(0);
  });
  it("shares one in-flight flush and preserves events enqueued during it", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const post = vi.fn(async (_url: string, body: AuditIngestRequest) => {
      await gate;
      const tail = body.events[body.events.length - 1];
      return { accepted: body.events.length, tail_seq: tail.seq, tail_hash: tail.hash };
    });
    const forwarder = new AuditForwarder(SESSION, post);
    forwarder.enqueue(ev(0));
    const first = forwarder.flush();
    expect(forwarder.flush()).toBe(first);
    forwarder.enqueue(ev(1));
    release();
    await first;
    expect(post).toHaveBeenCalledTimes(2);
    expect(forwarder.pendingCount).toBe(0);
    forwarder.enqueue(ev(0));
    expect(forwarder.pendingCount).toBe(0);
  });
});


it("forwards agent signatures unchanged", async () => {
  const { post, calls } = recordingPost();
  const forwarder = new AuditForwarder(SESSION, post);
  const event = { ...ev(0), agent_pubkey: "a".repeat(64), agent_signature: "b".repeat(128) };
  forwarder.enqueue(event);
  await forwarder.flush();
  expect(calls[0].events[0]).toEqual(event);
});


describe("AuditForwarder — null sessionId (late-binding adoption)", () => {
  it("(a) flush before any event returns [] and never POSTs", async () => {
    const { post } = recordingPost();
    const fwd = new AuditForwarder(null, post);
    const res = await fwd.flush();
    expect(res).toEqual([]);
    expect(post).not.toHaveBeenCalled();
  });

  it("(b) first enqueued event adopts its session_id as boundSessionId", () => {
    const { post } = recordingPost();
    const fwd = new AuditForwarder(null, post);
    expect(fwd.boundSessionId).toBeNull();
    fwd.enqueue(ev(0, SESSION));
    expect(fwd.boundSessionId).toBe(SESSION);
  });

  it("(c) events are forwarded normally after adoption", async () => {
    const { calls, post } = recordingPost();
    const fwd = new AuditForwarder(null, post);
    fwd.enqueue(ev(0, SESSION));
    fwd.enqueue(ev(1, SESSION));
    const res = await fwd.flush();
    expect(post).toHaveBeenCalledTimes(1);
    expect(calls[0]).toEqual({ session_id: SESSION, events: [ev(0, SESSION), ev(1, SESSION)] });
    expect(res).toEqual([{ accepted: 2, tail_seq: 1, tail_hash: hex64(2) }]);
    expect(fwd.pendingCount).toBe(0);
  });

  it("(d) events from a second session_id are filtered after the chain is bound", () => {
    const { post } = recordingPost();
    const OTHER = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const fwd = new AuditForwarder(null, post);
    fwd.enqueue(ev(0, SESSION));  // binds to SESSION
    fwd.enqueue(ev(1, OTHER));    // different session — must be dropped
    fwd.enqueue(ev(2, SESSION));  // same session — accepted
    expect(fwd.boundSessionId).toBe(SESSION);
    expect(fwd.pendingCount).toBe(2);
  });
});

it("keeps multi-byte audit batches below the server body limit", async () => {
  const { post, calls } = recordingPost();
  const forwarder = new AuditForwarder(SESSION, post);
  for (let i = 0; i < 50; i++) forwarder.enqueue({ ...ev(i), action: { kind: "test", text: "\u00e9".repeat(16000) } });
  await forwarder.flush();
  expect(calls.length).toBeGreaterThan(1);
  expect(calls.reduce((n, call) => n + call.events.length, 0)).toBe(50);
  for (const call of calls) expect(new TextEncoder().encode(JSON.stringify(call)).length).toBeLessThan(1024 * 1024);
});

describe("teardown flush (keepaliveFirstBatch)", () => {
  /** An event padded to roughly `bytes` so batches cross the keepalive budget deterministically. */
  function bigEv(seq: number, bytes: number): AuditEvent {
    return { ...ev(seq), action: { kind: "run_command", command: "x".repeat(bytes) } };
  }
  function keepalivePost() {
    const calls: { body: AuditIngestRequest; keepalive: boolean }[] = [];
    const post = vi.fn(async (_url: string, body: AuditIngestRequest, opts?: { keepalive?: boolean }) => {
      calls.push({ body, keepalive: !!opts?.keepalive });
      const last = body.events[body.events.length - 1];
      return { accepted: body.events.length, tail_seq: last.seq, tail_hash: last.hash };
    });
    return { calls, post };
  }

  it("sends the FIRST batch with keepalive, within the budget, then the rest normally, all in order", async () => {
    const { calls, post } = keepalivePost();
    const f = new AuditForwarder(SESSION, post);
    for (let i = 0; i < 10; i++) f.enqueue(bigEv(i, 15 * 1024)); // ~150 KiB in total
    await f.flush({ keepaliveFirstBatch: true });

    expect(calls.length).toBeGreaterThan(1);
    expect(calls[0].keepalive).toBe(true);
    expect(new TextEncoder().encode(JSON.stringify(calls[0].body)).length).toBeLessThanOrEqual(KEEPALIVE_BODY_BUDGET);
    expect(calls.slice(1).every((c) => !c.keepalive)).toBe(true);
    expect(calls.flatMap((c) => c.body.events.map((e) => e.seq))).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(f.pendingCount).toBe(0);
  });

  it("sends a single event too large for the budget WITHOUT keepalive (the browser would reject it)", async () => {
    const { calls, post } = keepalivePost();
    const f = new AuditForwarder(SESSION, post);
    f.enqueue(bigEv(0, 62 * 1024));
    await f.flush({ keepaliveFirstBatch: true });
    expect(calls).toHaveLength(1);
    expect(calls[0].keepalive).toBe(false);
    expect(calls[0].body.events.map((e) => e.seq)).toEqual([0]);
  });

  it("an ordinary flush never uses keepalive", async () => {
    const { calls, post } = keepalivePost();
    const f = new AuditForwarder(SESSION, post);
    f.enqueue([ev(0), ev(1)]);
    await f.flush();
    expect(calls.map((c) => c.keepalive)).toEqual([false]);
  });
});

describe("AuditForwarder holds back a seq gap (1.3.18 release review)", () => {
  it("sends only the contiguous run, then the rest once the late event arrives", async () => {
    const { calls, post } = recordingPost();
    const f = new AuditForwarder(SESSION, post, { now: () => 0 });
    f.enqueue(ev(0));
    await f.flush();
    f.enqueue(ev(2)); // seq 1 is still on its way (sealed on another thread)
    await f.flush();
    expect(calls.map((c) => c.events.map((e) => e.seq))).toEqual([[0]]);
    f.enqueue(ev(1));
    await f.flush();
    expect(calls.map((c) => c.events.map((e) => e.seq))).toEqual([[0], [1, 2]]);
  });

  it("holds an internal gap even before anything was acknowledged", async () => {
    const { calls, post } = recordingPost();
    const f = new AuditForwarder(SESSION, post, { now: () => 0 });
    f.enqueue([ev(5), ev(7)]);
    await f.flush();
    expect(calls.map((c) => c.events.map((e) => e.seq))).toEqual([[5]]);
    expect(f.pendingCount).toBe(1);
  });

  it("sends across a gap that outlives the hold, as before", async () => {
    const { calls, post } = recordingPost();
    let t = 0;
    const f = new AuditForwarder(SESSION, post, { now: () => t });
    f.enqueue(ev(0));
    await f.flush();
    f.enqueue(ev(2));
    await f.flush();
    t = GAP_HOLD_MS - 1;
    await f.flush();
    expect(calls).toHaveLength(1);
    t = GAP_HOLD_MS;
    await f.flush();
    expect(calls.map((c) => c.events.map((e) => e.seq))).toEqual([[0], [2]]);
  });

  it("the teardown flush holds nothing back", async () => {
    const { calls, post } = recordingPost();
    const f = new AuditForwarder(SESSION, post, { now: () => 0 });
    f.enqueue(ev(0));
    await f.flush();
    f.enqueue(ev(2));
    await f.flush({ keepaliveFirstBatch: true });
    expect(calls.map((c) => c.events.map((e) => e.seq))).toEqual([[0], [2]]);
  });
});
