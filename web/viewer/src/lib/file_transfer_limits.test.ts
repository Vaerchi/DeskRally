/**
 * Adversarial lifecycle + integrity tests for {@link FileTransferClient}: F07 memory/lifecycle
 * bounds and the F06 integrity portion (size/hash-invalid completion never reaches `onDownload`).
 *
 * These assert observable EFFECTS — messages sent, callbacks fired, pool counters — never the
 * private `downloads` map. Tests inject a small {@link DownloadMemoryBudget} per case so no case
 * needs to allocate a real 128 MiB.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import {
  FileTransferClient,
  DownloadMemoryBudget,
  encodeMessage,
  decodeMessage,
  chunkFile,
  sha256Hex,
  uuidToBytes,
  CHUNK_TAG,
  MAX_CHUNK_DATA,
  type Message,
} from "./file_transfer";

const ID_A = "11111111-2222-3333-4444-555555555555";
const ID_B = "22222222-3333-4444-5555-666666666666";
const ID_C = "33333333-4444-5555-6666-777777777777";
const ID_D = "44444444-5555-6666-7777-888888888888";
const ID_E = "55555555-6666-7777-8888-999999999999";

const ownedClients: FileTransferClient[] = [];
const clientErrors = new WeakMap<FileTransferClient, { id?: string; name?: string; reason: string }[]>();
/**
 * Wraps `new FileTransferClient` and — under the F06 explicit-approval contract — injects a
 * synchronous auto-approve observer when the caller has not supplied one. This preserves the
 * PRE-F06 delivery semantics these F07/legacy fixtures were written against: the client admits
 * the unsolicited Offer under UNCHANGED F07 bounds, verifies the hash, holds the bytes, emits a
 * pending snapshot, and this observer immediately calls `approveDownload(id)` to deliver via
 * `onDownload`. The CLIENT ITSELF has no insecure automatic mode — this is a per-test scaffold.
 */
function ownedClient(...args: ConstructorParameters<typeof FileTransferClient>): FileTransferClient {
  const [send, onDl, onAudit, options] = args;
  const merged = { ...(options ?? {}) };
  if (!merged.onPendingDownloadsChanged) {
    let ref: FileTransferClient;
    merged.onPendingDownloadsChanged = (pending) => {
      for (const p of pending) ref?.approveDownload(p.id);
    };
    const client = new FileTransferClient(send, onDl, onAudit, merged);
    ref = client;
    ownedClients.push(client);
    return client;
  }
  const client = new FileTransferClient(send, onDl, onAudit, merged);
  ownedClients.push(client);
  return client;
}

function collectSent(client?: FileTransferClient): { client: FileTransferClient; sent: Message[]; pool: DownloadMemoryBudget } {
  const sent: Message[] = [];
  const pool = new DownloadMemoryBudget(16 * 1024, 4); // 16 KiB, 4 leases — enough for a handful of tiny transfers
  const errors: { id?: string; name?: string; reason: string }[] = [];
  const c =
    client ??
    ownedClient(
      (p) => sent.push(decodeMessage(p)),
      () => {},
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => errors.push(e) },
    );
  clientErrors.set(c, errors);
  return { client: c, sent, pool };
}

function errorsOf(c: FileTransferClient): { id?: string; name?: string; reason: string }[] {
  return clientErrors.get(c)!;
}

async function pollFor<T>(fn: () => T | undefined, ms = 500): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    const v = fn();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error("pollFor timed out");
}

describe("Offer validation + per-file limits", () => {
  it("rejects an Offer over the aggregate budget without reserving a lease", () => {
    const { client, sent, pool } = collectSent();
    const before = pool.stats();
    client.handleMessage(
      encodeMessage({ t: "Offer", c: { id: ID_A, name: "big.bin", size: 5000, sha256: "a".repeat(64) } }),
    );
    // pool is 16 KiB × leases=4; 5000 × 4 = 20000 > 16384 → rejected
    expect(pool.stats().used).toBe(before.used);
    expect(pool.stats().leases).toBe(before.leases);
    const err = sent.find((m) => m.t === "Error");
    expect(err && err.t === "Error" && err.c.id).toBe(ID_A);
    expect(errorsOf(client).some((e) => /memory|too large/i.test(e.reason))).toBe(true);
  });

  it("rejects malformed offers (bad UUID, bad hex, bad size, oversized name)", () => {
    const { client, sent } = collectSent();
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: "not-a-uuid", name: "x", size: 1, sha256: "a".repeat(64) } }));
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 1, sha256: "zzz" } }));
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: -1, sha256: "a".repeat(64) } }));
    client.handleMessage(
      encodeMessage({ t: "Offer", c: { id: ID_A, name: "n".repeat(5000), size: 1, sha256: "a".repeat(64) } }),
    );
    expect(errorsOf(client).length).toBeGreaterThanOrEqual(3);
    // No Error wire message for the id-invalid one (there is no id to name); at least one for the rest.
    const withId = sent.filter((m) => m.t === "Error" && m.c.id === ID_A);
    expect(withId.length).toBeGreaterThan(0);
  });

  it("zero-byte transfer still consumes exactly one lease (aggregate protection)", async () => {
    const pool = new DownloadMemoryBudget(1024, 2);
    const client = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool });
    const sha = await sha256Hex(new Uint8Array(0));
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "e0.bin", size: 0, sha256: sha } }));
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_B, name: "e1.bin", size: 0, sha256: sha } }));
    // Third zero-byte offer must be rejected: leases exhausted.
    let saw: unknown;
    const c3 = ownedClient(
      () => {},
      () => {},
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => (saw = e) },
    );
    c3.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_C, name: "e2.bin", size: 0, sha256: sha } }));
    expect(saw).toBeDefined();
    expect(pool.stats().leases).toBe(2);
  });
});

describe("per-client active-transfer cap", () => {
  it("rejects the 5th offer when maxActiveTransfers=4", () => {
    const pool = new DownloadMemoryBudget(1 << 20, 16);
    const errs: { reason: string }[] = [];
    const client = ownedClient(
      () => {},
      () => {},
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => errs.push(e), limits: { maxActiveTransfers: 4 } },
    );
    const sha = "a".repeat(64);
    for (const id of [ID_A, ID_B, ID_C, ID_D]) {
      client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "x", size: 8, sha256: sha } }));
    }
    errs.length = 0;
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_E, name: "x", size: 8, sha256: sha } }));
    expect(errs.some((e) => /concurrent/.test(e.reason))).toBe(true);
  });
});

describe("chunk-path safety", () => {
  it("ignores a JSON message pretending to be a Chunk (does not route peer .data into binary state)", async () => {
    const sha = await sha256Hex(new Uint8Array([1, 2, 3]));
    // A control-tagged Chunk should be silently ignored — do not push into parts.
    const forged: Uint8Array = new TextEncoder().encode(
      `{"t":"Chunk","c":{"id":"${ID_A}","seq":0,"data":[1,2,3]}}`,
    );
    const captured: { verified: boolean }[] = [];
    const pool2 = new DownloadMemoryBudget(1024, 2);
    const c2 = ownedClient(
      () => {},
      (f) => captured.push({ verified: f.verified }),
      () => {},
      { memoryBudget: pool2 },
    );
    c2.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "j.bin", size: 3, sha256: sha } }));
    c2.handleMessage(forged);
    for (const c of chunkFile(ID_A, new Uint8Array([1, 2, 3]))) c2.handleMessage(encodeMessage({ t: "Chunk", c }));
    c2.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));
    await pollFor(() => (captured.length > 0 ? true : undefined));
    expect(captured[0].verified).toBe(true);
  });

  it("rejects an oversize binary chunk BEFORE copying its body", () => {
    const pool = new DownloadMemoryBudget(1 << 20, 4);
    const errs: { reason: string }[] = [];
    const sent: Message[] = [];
    const client = ownedClient(
      (p) => {
        try {
          sent.push(decodeMessage(p));
        } catch {
          /* corrupt frames are ok in a test */
        }
      },
      () => {},
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => errs.push(e) },
    );
    client.handleMessage(
      encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 10, sha256: "a".repeat(64) } }),
    );
    // Craft a binary chunk larger than MAX_CHUNK_DATA. We spy on Uint8Array.prototype.slice to prove
    // that the client did NOT copy the body — only the 16-byte id header slice is permitted.
    const bodyLen = MAX_CHUNK_DATA + 1024;
    const buf = new Uint8Array(1 + 16 + 4 + bodyLen);
    buf[0] = CHUNK_TAG;
    buf.set(uuidToBytes(ID_A), 1);
    // seq=0 big-endian is all zeros already.
    const original = Uint8Array.prototype.slice;
    const spy = vi.fn(function (this: Uint8Array, ...args: [number?, number?]) { return original.apply(this, args); });
    Uint8Array.prototype.slice = spy as unknown as typeof original;
    try {
      client.handleMessage(buf);
    } finally {
      Uint8Array.prototype.slice = original;
    }
    // The only permitted slice is the 16-byte id header (start=1, end=17). Prove no full-body copy.
    const bodySlices = spy.mock.calls.filter(
      (call) => call[0] !== 1 || call[1] !== 17,
    );
    expect(bodySlices.length).toBe(0);
    expect(errs.some((e) => /48KiB/.test(e.reason))).toBe(true);
  });

  it("aborts on empty, out-of-order, and beyond-size chunks; and enforces maxParts", async () => {
    const pool = new DownloadMemoryBudget(1 << 16, 8);
    const sha = "a".repeat(64);

    // (a) empty chunk
    {
      const errs: { reason: string }[] = [];
      const client = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool, onDownloadError: (e) => errs.push(e) });
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 4, sha256: sha } }));
      client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_A, seq: 0, data: new Uint8Array(0) } }));
      expect(errs.some((e) => /empty/.test(e.reason))).toBe(true);
    }
    // (b) out-of-order
    {
      const errs: { reason: string }[] = [];
      const client = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool, onDownloadError: (e) => errs.push(e) });
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_B, name: "x", size: 4, sha256: sha } }));
      client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_B, seq: 5, data: new Uint8Array([1, 2, 3, 4]) } }));
      expect(errs.some((e) => /out-of-order/.test(e.reason))).toBe(true);
    }
    // (c) beyond declared size
    {
      const errs: { reason: string }[] = [];
      const client = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool, onDownloadError: (e) => errs.push(e) });
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_C, name: "x", size: 4, sha256: sha } }));
      client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_C, seq: 0, data: new Uint8Array([1, 2, 3, 4, 5]) } }));
      expect(errs.some((e) => /declared size/i.test(e.reason))).toBe(true);
    }
    // (d) maxParts enforced when peer streams 1-byte chunks
    {
      const errs: { reason: string }[] = [];
      const client = ownedClient(
        () => {},
        () => {},
        () => {},
        {
          memoryBudget: pool,
          onDownloadError: (e) => errs.push(e),
          limits: { maxPartsPerTransfer: 8 },
        },
      );
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_D, name: "x", size: 100, sha256: sha } }));
      for (let i = 0; i < 12; i++) {
        client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_D, seq: i, data: new Uint8Array([1]) } }));
      }
      expect(errs.some((e) => /too many parts/.test(e.reason))).toBe(true);
    }
  });
});

describe("Done + integrity gating (F06 integrity portion)", () => {
  it("Done with declared-size mismatch does NOT deliver to onDownload", async () => {
    const pool = new DownloadMemoryBudget(1 << 16, 4);
    const delivered: unknown[] = [];
    const errs: { reason: string }[] = [];
    const client = ownedClient(
      () => {},
      (f) => delivered.push(f),
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => errs.push(e) },
    );
    const sha = "a".repeat(64);
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 10, sha256: sha } }));
    client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_A, seq: 0, data: new Uint8Array([1, 2, 3]) } }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));
    await new Promise((r) => setTimeout(r, 20));
    expect(delivered.length).toBe(0);
    expect(errs.some((e) => /declared size/i.test(e.reason))).toBe(true);
    expect(pool.stats().used).toBe(0);
    expect(pool.stats().leases).toBe(0);
  });

  it("Done with SHA mismatch is rejected — no onDownload, lease freed after digest settles", async () => {
    const pool = new DownloadMemoryBudget(1 << 16, 4);
    const delivered: unknown[] = [];
    const errs: { reason: string }[] = [];
    const client = ownedClient(
      () => {},
      (f) => delivered.push(f),
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => errs.push(e) },
    );
    const data = new Uint8Array([9, 8, 7]);
    client.handleMessage(
      encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: data.length, sha256: "0".repeat(64) } }),
    );
    client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_A, seq: 0, data } }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));
    await pollFor(() => (errs.some((e) => /sha256/.test(e.reason)) ? true : undefined));
    expect(delivered.length).toBe(0);
    expect(pool.stats().used).toBe(0);
    expect(pool.stats().leases).toBe(0);
  });

  it("valid requested download reaches onDownload and screenshot-shaped download works too", async () => {
    const pool = new DownloadMemoryBudget(1 << 16, 4);
    const delivered: { name: string; verified: boolean }[] = [];
    const client = ownedClient(
      () => {},
      (f) => delivered.push({ name: f.name, verified: f.verified }),
      () => {},
      { memoryBudget: pool },
    );
    const data = new Uint8Array(300).map((_, i) => (i * 7) % 256);
    const sha = await sha256Hex(data);
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "report.bin", size: data.length, sha256: sha } }));
    for (const c of chunkFile(ID_A, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));

    const shot = new Uint8Array([1, 2, 3, 4]);
    const shotSha = await sha256Hex(shot);
    client.handleMessage(
      encodeMessage({ t: "Offer", c: { id: ID_B, name: "screenshot-abc.png", size: shot.length, sha256: shotSha } }),
    );
    for (const c of chunkFile(ID_B, shot)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_B } }));

    await pollFor(() => (delivered.length === 2 ? true : undefined));
    expect(delivered.map((d) => d.name).sort()).toEqual(["report.bin", "screenshot-abc.png"]);
    expect(delivered.every((d) => d.verified)).toBe(true);
    expect(pool.stats().leases).toBe(0);
  });
});

describe("duplicate offer preserves the original", () => {
  it("a repeat Offer for an active id does not reset parts and does not send a wire Error", async () => {
    const pool = new DownloadMemoryBudget(1 << 16, 4);
    const sent: Message[] = [];
    const delivered: { verified: boolean }[] = [];
    const client = ownedClient(
      (p) => sent.push(decodeMessage(p)),
      (f) => delivered.push({ verified: f.verified }),
      () => {},
      { memoryBudget: pool },
    );
    const data = new Uint8Array(200).map((_, i) => i);
    const sha = await sha256Hex(data);
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: data.length, sha256: sha } }));
    // Feed the first chunk, then a duplicate Offer, then the rest — a reset would abandon seq state
    // and later chunks would be "out of order".
    const chunks = chunkFile(ID_A, data);
    client.handleMessage(encodeMessage({ t: "Chunk", c: chunks[0] }));
    client.handleMessage(
      encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: data.length, sha256: sha } }),
    );
    for (let i = 1; i < chunks.length; i++) client.handleMessage(encodeMessage({ t: "Chunk", c: chunks[i] }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));
    await pollFor(() => (delivered.length > 0 ? true : undefined));
    expect(delivered[0].verified).toBe(true);
    expect(sent.find((m) => m.t === "Error" && m.c.id === ID_A)).toBeUndefined();
  });
});

describe("expiry", () => {
  it("inactivity expires with NO further peer frames (fake timers + injected clock)", async () => {
    vi.useFakeTimers();
    try {
      let now = 1_000_000;
      const clock = () => now;
      const pool = new DownloadMemoryBudget(1 << 16, 4);
      const errs: { reason: string }[] = [];
      const client = ownedClient(
        () => {},
        () => {},
        () => {},
        { memoryBudget: pool, onDownloadError: (e) => errs.push(e), clock, limits: { inactivityMs: 1000, maxAgeMs: 60_000 } },
      );
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 100, sha256: "a".repeat(64) } }));
      expect(pool.stats().leases).toBe(1);
      now += 2000;
      vi.advanceTimersByTime(2000);
      expect(errs.some((e) => /expired/.test(e.reason))).toBe(true);
      expect(pool.stats().leases).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("absolute-age expiry fires despite steady progress", async () => {
    vi.useFakeTimers();
    try {
      let now = 5_000_000;
      const clock = () => now;
      const pool = new DownloadMemoryBudget(1 << 16, 4);
      const errs: { reason: string }[] = [];
      const client = ownedClient(
        () => {},
        () => {},
        () => {},
        {
          memoryBudget: pool,
          onDownloadError: (e) => errs.push(e),
          clock,
          limits: { inactivityMs: 60_000, maxAgeMs: 3000 },
        },
      );
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 100, sha256: "a".repeat(64) } }));
      // Steady 1-byte chunks — inactivity keeps resetting, but the absolute-age wall stands.
      for (let i = 0; i < 5; i++) {
        now += 400;
        vi.advanceTimersByTime(400);
        if (!errs.length) client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_A, seq: i, data: new Uint8Array([i + 1]) } }));
      }
      // Nudge past the age wall.
      now += 2000;
      vi.advanceTimersByTime(2000);
      expect(errs.some((e) => /expired/.test(e.reason))).toBe(true);
      expect(pool.stats().leases).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("recovery after each abort", () => {
  it("aborted transfer frees the lease; a fresh transfer proceeds", async () => {
    const pool = new DownloadMemoryBudget(1 << 16, 4);
    const delivered: unknown[] = [];
    const errs: { reason: string }[] = [];
    const client = ownedClient(
      () => {},
      (f) => delivered.push(f),
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => errs.push(e) },
    );
    const sha = "a".repeat(64);
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 4, sha256: sha } }));
    client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_A, seq: 9, data: new Uint8Array([1]) } })); // out of order
    expect(pool.stats().leases).toBe(0);

    const data = new Uint8Array([1, 2, 3]);
    const goodSha = await sha256Hex(data);
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_B, name: "y", size: data.length, sha256: goodSha } }));
    for (const c of chunkFile(ID_B, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_B } }));
    await pollFor(() => (delivered.length > 0 ? true : undefined));
    expect(pool.stats().leases).toBe(0);
  });
});

describe("delayed digest — reservation cannot be bypassed by Done/Error/timeout/dispose", () => {
  it("holds the lease until the async hash actually settles", async () => {
    // Replace crypto.subtle.digest with a deferrable stub — restore in finally.
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let releaseHash: (v: ArrayBuffer) => void = () => {};
    const deferred: Promise<ArrayBuffer>[] = [];
    (crypto.subtle as unknown as { digest: typeof crypto.subtle.digest }).digest = ((_algo: string, _data: ArrayBuffer) => {
      const p = new Promise<ArrayBuffer>((resolve) => (releaseHash = resolve));
      deferred.push(p);
      return p;
    }) as typeof crypto.subtle.digest;

    try {
      const pool = new DownloadMemoryBudget(64, 2); // A 16-byte reservation excludes a second 52-byte reservation.
      const client = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool });
      const data = new Uint8Array([1, 2, 3, 4]);
      const sha = "a".repeat(64); // stub digest returns anything; content match not the point here
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: data.length, sha256: sha } }));
      for (const c of chunkFile(ID_A, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
      client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));
      // Also try Error mid-hash and dispose — none of these may release the lease early.
      client.handleMessage(encodeMessage({ t: "Error", c: { id: ID_A, message: "peer" } }));
      // At this point the lease STILL must be held: finalizer's finally has not run.
      expect(pool.stats().leases).toBe(1);
      expect(pool.stats().used).toBe(16);

      // A new offer of matching size cannot be admitted — the reservation stands.
      const errs: { reason: string }[] = [];
      const c2 = ownedClient(
        () => {},
        () => {},
        () => {},
        { memoryBudget: pool, onDownloadError: (e) => errs.push(e) },
      );
      c2.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_B, name: "y", size: 13, sha256: sha } })); // 13*4=52 → 16+52=68 > 64
      expect(errs.some((e) => /memory|budget/.test(e.reason))).toBe(true);

      // Now settle the digest — the finalizer's finally releases the lease.
      const hash = new ArrayBuffer(32);
      releaseHash(hash);
      await Promise.all(deferred);
      await new Promise((r) => setTimeout(r, 10));
      expect(pool.stats().leases).toBe(0);
      expect(pool.stats().used).toBe(0);
    } finally {
      (crypto.subtle as unknown as { digest: typeof crypto.subtle.digest }).digest = originalDigest as typeof crypto.subtle.digest;
    }
  });
});

describe("cross-client pool protects reconnect", () => {
  it("two clients sharing a pool contend for one aggregate budget", () => {
    const pool = new DownloadMemoryBudget(32, 2); // 32 bytes, 2 leases
    const a = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool });
    const bErrs: { reason: string }[] = [];
    const b = ownedClient(
      () => {},
      () => {},
      () => {},
      { memoryBudget: pool, onDownloadError: (e) => bErrs.push(e) },
    );
    const sha = "a".repeat(64);
    a.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: 4, sha256: sha } })); // 16 used, 1 lease
    a.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_B, name: "x", size: 4, sha256: sha } })); // 32 used, 2 leases
    b.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_C, name: "z", size: 4, sha256: sha } }));
    expect(bErrs.some((e) => /memory|budget/.test(e.reason))).toBe(true);
  });
});

describe("dispose", () => {
  it("disposed finalizer produces no callback and clears state", async () => {
    // Deferred digest to keep a finalizer alive across dispose.
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let releaseHash: (v: ArrayBuffer) => void = () => {};
    (crypto.subtle as unknown as { digest: typeof crypto.subtle.digest }).digest = ((_algo: string, _data: ArrayBuffer) => {
      return new Promise<ArrayBuffer>((resolve) => (releaseHash = resolve));
    }) as typeof crypto.subtle.digest;

    try {
      const pool = new DownloadMemoryBudget(64, 2);
      const delivered: unknown[] = [];
      const client = ownedClient(
        () => {},
        (f) => delivered.push(f),
        () => {},
        { memoryBudget: pool },
      );
      const data = new Uint8Array([9, 9, 9]);
      client.handleMessage(
        encodeMessage({ t: "Offer", c: { id: ID_A, name: "x", size: data.length, sha256: "a".repeat(64) } }),
      );
      for (const c of chunkFile(ID_A, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
      client.handleMessage(encodeMessage({ t: "Done", c: { id: ID_A } }));

      client.dispose();
      client.dispose(); // idempotent
      releaseHash(new ArrayBuffer(32));
      await new Promise((r) => setTimeout(r, 20));
      expect(delivered.length).toBe(0);
      // Late inbound frames after dispose must be ignored.
      client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID_B, name: "y", size: 1, sha256: "a".repeat(64) } }));
      expect(pool.stats().leases).toBe(0);
    } finally {
      (crypto.subtle as unknown as { digest: typeof crypto.subtle.digest }).digest = originalDigest as typeof crypto.subtle.digest;
    }
  });

  it("dispose resolves pending upload acks with ok=false and does not send after await", async () => {
    // A slow digest keeps upload() awaiting when dispose() is called.
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let releaseHash: (v: ArrayBuffer) => void = () => {};
    (crypto.subtle as unknown as { digest: typeof crypto.subtle.digest }).digest = ((_algo: string, _data: ArrayBuffer) => {
      return new Promise<ArrayBuffer>((resolve) => (releaseHash = resolve));
    }) as typeof crypto.subtle.digest;

    try {
      const sent: Uint8Array[] = [];
      const client = ownedClient((p) => sent.push(p));
      const p = client.upload("a.bin", new Uint8Array([1, 2, 3]));
      client.dispose();
      // Now release the digest — the upload continuation sees `disposed` after await and must not send.
      releaseHash(new ArrayBuffer(32));
      await expect(p).resolves.toEqual({ ok: false, message: "client disposed" });
      expect(sent.length).toBe(0);
    } finally {
      (crypto.subtle as unknown as { digest: typeof crypto.subtle.digest }).digest = originalDigest as typeof crypto.subtle.digest;
    }
  });
});

describe("limit validation", () => {
  it("rejects non-positive or non-safe-integer limits", () => {
    expect(() => ownedClient(() => {}, () => {}, () => {}, { limits: { maxFileBytes: 0 } })).toThrow();
    expect(() => ownedClient(() => {}, () => {}, () => {}, { limits: { maxAgeMs: -1 } })).toThrow();
    expect(() => ownedClient(() => {}, () => {}, () => {}, { limits: { inactivityMs: 1.5 } })).toThrow();
    expect(() => ownedClient(() => {}, () => {}, () => {}, { limits: { maxPartsPerTransfer: Number.POSITIVE_INFINITY } })).toThrow();
  });
});

afterEach(() => {
  for (const client of ownedClients.splice(0)) client.dispose();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("independently challenged lifecycle boundaries", () => {
  const zeroHash = "00".repeat(32);
  function offer(client: FileTransferClient, id = ID_A, size = 4, sha256 = zeroHash) {
    client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "file.bin", size, sha256 } }));
  }
  function chunk(client: FileTransferClient, data = new Uint8Array([1, 2, 3, 4]), seq = 0) {
    client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID_A, seq, data } }));
  }
  function done(client: FileTransferClient, id = ID_A) {
    client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
  }
  function abort(client: FileTransferClient) {
    client.handleMessage(encodeMessage({ t: "Error", c: { id: ID_A, message: "untrusted" } }));
  }
  function deferredDigest() {
    let resolve!: (value: ArrayBuffer) => void;
    let reject!: (reason: Error) => void;
    const promise = new Promise<ArrayBuffer>((a, b) => { resolve = a; reject = b; });
    const spy = vi.spyOn(crypto.subtle, "digest").mockReturnValue(promise);
    return { resolve: () => resolve(new ArrayBuffer(32)), reject: () => reject(new Error("digest failure")), spy };
  }
  async function settle() { for (let i = 0; i < 6; i++) await Promise.resolve(); }

  it("enforces the file cap independently of aggregate capacity", () => {
    const pool = new DownloadMemoryBudget(1024, 8);
    const error = vi.fn();
    const client = ownedClient(() => {}, () => {}, () => {},
      { memoryBudget: pool, limits: { maxFileBytes: 4 }, onDownloadError: error });
    offer(client, ID_A, 5);
    expect(error).toHaveBeenCalledOnce();
    expect(error.mock.calls[0][0].reason).toContain("MiB limit");
    expect(pool.stats().leases).toBe(0);
    offer(client, ID_B, 4);
    expect(pool.stats().used).toBe(16);
  });

  it("reports the default 128 MiB cap without allocating the advertised file", () => {
    const pool = new DownloadMemoryBudget(1024 * 1024 * 1024, 8);
    const error = vi.fn();
    const client = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool, onDownloadError: error });
    offer(client, ID_A, 128 * 1024 * 1024 + 1);
    expect(error.mock.calls[0][0].reason).toContain("128 MiB");
    expect(pool.stats().leases).toBe(0);
    offer(client, ID_B, 128 * 1024 * 1024);
    expect(pool.stats().used).toBe(512 * 1024 * 1024);
    client.dispose();
    expect(pool.stats().used).toBe(0);
  });

  it.each(["Done", "Error", "timeout", "dispose"])("retains reservations through %s until the hash settles", async action => {
    vi.useFakeTimers();
    const hash = deferredDigest();
    const pool = new DownloadMemoryBudget(16, 1);
    const delivered = vi.fn();
    const error = vi.fn();
    const client = ownedClient(() => {}, delivered, () => {},
      { memoryBudget: pool, onDownloadError: error, clock: () => Date.now(), limits: { inactivityMs: 100 } });
    offer(client); chunk(client); done(client);
    expect(hash.spy).toHaveBeenCalledOnce();
    if (action === "Error") abort(client);
    if (action === "timeout") {
      vi.advanceTimersByTime(100);
      expect(error.mock.calls[0][0].reason).toContain("expired");
    }
    if (action === "dispose") { client.dispose(); client.dispose(); }
    expect(pool.stats()).toMatchObject({ used: 16, leases: 1 });
    const rejected = vi.fn();
    const next = ownedClient(() => {}, () => {}, () => {}, { memoryBudget: pool, onDownloadError: rejected });
    offer(next, ID_B);
    expect(rejected).toHaveBeenCalledOnce();
    hash.resolve(); await settle();
    // Matching digest means suppressing a cancelled callback cannot pass accidentally on a hash mismatch.
    expect(delivered).toHaveBeenCalledTimes(action === "Done" ? 1 : 0);
    if (action === "timeout") expect(error.mock.calls[0][0].reason).toContain("expired");
    expect(pool.stats()).toMatchObject({ used: 0, leases: 0 });
    offer(next, ID_B);
    expect(pool.stats().leases).toBe(1);
  });

  it("keeps cancelled finalizers counted and ignores malformed duplicates", async () => {
    const hash = deferredDigest();
    const pool = new DownloadMemoryBudget(1024, 8);
    const sent: Message[] = [];
    const error = vi.fn();
    const delivered = vi.fn();
    const client = ownedClient(p => sent.push(decodeMessage(p)), delivered, () => {},
      { memoryBudget: pool, onDownloadError: error, limits: { maxActiveTransfers: 1 } });
    offer(client); chunk(client); done(client); abort(client);
    const count = sent.length;
    offer(client, ID_A, -1);
    expect(sent.length).toBe(count);
    offer(client, ID_B);
    expect(error.mock.calls[error.mock.calls.length - 1][0].reason).toContain("concurrent");
    expect(pool.stats().leases).toBe(1);
    hash.resolve(); await settle();
    expect(delivered).not.toHaveBeenCalled();
    offer(client, ID_B);
    expect(pool.stats().leases).toBe(1);
  });

  it("preserves partial data and sequence across invalid duplicate offers", async () => {
    const hash = deferredDigest();
    const sent: Message[] = [];
    const delivered = vi.fn();
    const pool = new DownloadMemoryBudget(1024, 8);
    const client = ownedClient(p => sent.push(decodeMessage(p)), delivered, () => {}, { memoryBudget: pool });
    offer(client); chunk(client, new Uint8Array([1, 2]), 0);
    offer(client, ID_A, -1);
    chunk(client, new Uint8Array([3, 4]), 1); done(client);
    hash.resolve(); await settle();
    expect(sent.filter(m => m.t === "Error")).toEqual([]);
    expect(delivered).toHaveBeenCalledOnce();
  });

  it("rejects stale Done before digest even if the timer has not fired", () => {
    let now = 0;
    const digest = vi.spyOn(crypto.subtle, "digest");
    const pool = new DownloadMemoryBudget(1024, 8);
    const error = vi.fn();
    const client = ownedClient(() => {}, () => {}, () => {},
      { memoryBudget: pool, onDownloadError: error, clock: () => now, limits: { inactivityMs: 100 } });
    offer(client); chunk(client); now = 100; done(client);
    expect(digest).not.toHaveBeenCalled();
    expect(error.mock.calls[0][0].reason).toContain("expired");
    expect(pool.stats().leases).toBe(0);
  });

  it("releases reservations on rejected digest and throwing consumer", async () => {
    const hash = deferredDigest();
    const pool = new DownloadMemoryBudget(1024, 8);
    const error = vi.fn();
    const delivered = vi.fn(() => { throw new Error("consumer"); });
    const client = ownedClient(() => {}, delivered, () => {}, { memoryBudget: pool, onDownloadError: error });
    offer(client); chunk(client); done(client); hash.reject(); await settle();
    expect(error.mock.calls[0][0].reason).toContain("digest failed");
    expect(pool.stats().leases).toBe(0);
    hash.spy.mockResolvedValue(new ArrayBuffer(32));
    offer(client); chunk(client); done(client); await settle();
    expect(delivered).toHaveBeenCalledOnce();
    expect(pool.stats().leases).toBe(0);
  });

  it("uses a shared default pool even after reconnect disposal", async () => {
    const hash = deferredDigest();
    const a = ownedClient(() => {});
    const b = ownedClient(() => {});
    const error = vi.fn();
    const c = ownedClient(() => {}, () => {}, () => {}, { onDownloadError: error });
    for (let i = 0; i < 8; i++) {
      const id = `${String(i).padStart(8, "0")}-2222-3333-4444-555555555555`;
      const client = i < 4 ? a : b;
      offer(client, id, 0); done(client, id);
    }
    expect(hash.spy).toHaveBeenCalledTimes(8);
    a.dispose(); b.dispose(); offer(c, ID_C, 0);
    expect(error).toHaveBeenCalledOnce();
    hash.resolve(); await settle();
    offer(c, ID_C, 0); done(c, ID_C); await settle();
    expect(hash.spy).toHaveBeenCalledTimes(9);
    expect(error).toHaveBeenCalledOnce();
  });

  it("resolves an already pending upload acknowledgment on disposal", async () => {
    const hash = deferredDigest();
    const sent: Message[] = [];
    const client = ownedClient(p => sent.push(decodeMessage(p)));
    const result = client.upload("file.bin", new Uint8Array([1]));
    hash.resolve(); await settle();
    expect(sent[sent.length - 1]?.t).toBe("Done");
    client.dispose(); client.dispose();
    await expect(result).resolves.toMatchObject({ ok: false });
    await expect(client.upload("later", new Uint8Array())).resolves.toMatchObject({ ok: false });
    expect(hash.spy).toHaveBeenCalledOnce();
  });
});
