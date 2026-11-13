/**
 * F06 explicit-approval contract tests for {@link FileTransferClient}.
 *
 * These pin the pending-request map bounds, the requested-vs-approved routing, and the failure
 * modes of `approveDownload`. Positive delivery + hold semantics are covered by
 * `file_transfer_approval_review.test.ts`; this file focuses on the surrounding invariants.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DownloadMemoryBudget,
  FileTransferClient,
  encodeMessage,
  sha256Hex,
  DEFAULT_MAX_PENDING_REQUESTS,
} from "./file_transfer";

const owned: FileTransferClient[] = [];
afterEach(() => {
  for (const c of owned.splice(0)) c.dispose();
  vi.restoreAllMocks();
});

function mk(options: ConstructorParameters<typeof FileTransferClient>[3] = {}) {
  const sent: unknown[] = [];
  const send = vi.fn((p: Uint8Array) => {
    sent.push(p);
  });
  const delivered = vi.fn();
  const pool = new DownloadMemoryBudget(1 << 16, 8);
  let pending: readonly { id: string; name: string; size: number }[] = [];
  const client = new FileTransferClient(send, delivered, () => {}, {
    memoryBudget: pool,
    onPendingDownloadsChanged: (list) => {
      pending = list;
    },
    ...options,
  });
  owned.push(client);
  return { client, delivered, pool, send, pending: () => pending };
}

describe("request() — bounded outbound issuance", () => {
  it.each([
    ["empty path", ""],
    ["oversize path", "x".repeat(4097)],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ["non-string path", 5 as any],
  ])("throws synchronously on %s", (_label, bad) => {
    const s = mk();
    expect(() => s.client.request(bad as string)).toThrow();
    expect(s.send).not.toHaveBeenCalled();
  });

  it(`throws when the pending map hits the cap (default ${DEFAULT_MAX_PENDING_REQUESTS})`, () => {
    const s = mk({ maxPendingRequests: 3 });
    s.client.request("a");
    s.client.request("b");
    s.client.request("c");
    expect(() => s.client.request("d")).toThrow(/pending/);
    // The failed attempt did NOT send a wire frame.
    expect(s.send).toHaveBeenCalledTimes(3);
  });

  it("throws when disposed", () => {
    const s = mk();
    s.client.dispose();
    expect(() => s.client.request("x")).toThrow(/disposed/);
  });

  it("clears the pending entry when the transport send throws (does not leak a slot)", () => {
    let count = 0;
    const bad = new FileTransferClient(
      () => {
        throw new Error("transport gone");
      },
      () => {},
      () => {},
      { onPendingDownloadsChanged: () => {}, maxPendingRequests: 1 },
    );
    owned.push(bad);
    expect(() => bad.request("a")).toThrow(/transport/);
    count++;
    // The cap of 1 is still available — the failed request did not consume it.
    expect(() => bad.request("b")).toThrow(/transport/);
    expect(count).toBe(1);
  });

  it("survives a synchronously re-entrant Offer during send (insertion is before send)", async () => {
    // A transport that, while sending Request, calls handleMessage with the matching Offer.
    let client!: FileTransferClient;
    const data = new Uint8Array([1, 2, 3, 4]);
    const sha = await sha256Hex(data);
    let capturedId: string | undefined;
    const send = vi.fn((payload: Uint8Array) => {
      // Only re-enter on the first (Request) send.
      if (capturedId) return;
      // Decode the outgoing Request to extract id.
      const s = new TextDecoder().decode(payload);
      const m = /"id":"([^"]+)"/.exec(s);
      capturedId = m ? m[1] : undefined;
      if (!capturedId) return;
      client.handleMessage(
        encodeMessage({ t: "Offer", c: { id: capturedId, name: "rogue-name.png", size: data.length, sha256: sha } }),
      );
    });
    const delivered = vi.fn();
    client = new FileTransferClient(send, delivered, () => {}, {
      memoryBudget: new DownloadMemoryBudget(1 << 16, 8),
    });
    owned.push(client);
    const id = client.request("wanted.bin");
    expect(id).toBe(capturedId);
    // Chunks + Done arrive after send unwinds.
    client.handleMessage(encodeMessage({ t: "Chunk", c: { id, seq: 0, data } }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce());
    expect(delivered.mock.calls[0][0]).toMatchObject({ name: "wanted.bin", source: "requested" });
  });
});

describe("acceptOffer — pending-request correlation", () => {
  it("a late Offer after the deadline is treated as unsolicited (never delivered as requested)", async () => {
    let now = 0;
    const s = mk({ clock: () => now, requestDeadlineMs: 100 });
    const id = s.client.request("wanted.bin");
    now = 200;
    const data = new Uint8Array([1, 2, 3, 4]);
    const sha = await sha256Hex(data);
    s.client.handleMessage(
      encodeMessage({ t: "Offer", c: { id, name: "attacker.exe", size: data.length, sha256: sha } }),
    );
    s.client.handleMessage(encodeMessage({ t: "Chunk", c: { id, seq: 0, data } }));
    s.client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
    // Held for approval — NOT delivered as requested with the basename shortcut.
    expect(s.delivered).not.toHaveBeenCalled();
  });

  it("a requested download whose peer name starts with screenshot- still uses the request basename", async () => {
    const s = mk();
    const id = s.client.request("logs/report.bin");
    const data = new Uint8Array([1, 2, 3, 4]);
    const sha = await sha256Hex(data);
    s.client.handleMessage(
      encodeMessage({ t: "Offer", c: { id, name: "screenshot-attacker.png", size: data.length, sha256: sha } }),
    );
    s.client.handleMessage(encodeMessage({ t: "Chunk", c: { id, seq: 0, data } }));
    s.client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    await vi.waitFor(() => expect(s.delivered).toHaveBeenCalledOnce());
    expect(s.delivered.mock.calls[0][0]).toMatchObject({ name: "report.bin", source: "requested" });
  });

  it("a duplicate Offer for a held id neither resets nor releases", async () => {
    const s = mk();
    const data = new Uint8Array([1, 2, 3, 4]);
    const sha = await sha256Hex(data);
    const id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    s.client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "x.bin", size: data.length, sha256: sha } }));
    s.client.handleMessage(encodeMessage({ t: "Chunk", c: { id, seq: 0, data } }));
    s.client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
    const before = s.pool.stats();
    s.client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "x.bin", size: data.length, sha256: sha } }));
    expect(s.pool.stats()).toEqual(before);
    expect(s.pending()).toHaveLength(1);
  });
});

describe("approveDownload / dismissDownload — explicit-approval boundary", () => {
  async function feedUnsolicited() {
    const s = mk();
    const data = new Uint8Array([1, 2, 3, 4]);
    const sha = await sha256Hex(data);
    const id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    s.client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "x.bin", size: 4, sha256: sha } }));
    s.client.handleMessage(encodeMessage({ t: "Chunk", c: { id, seq: 0, data } }));
    s.client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    return { ...s, id };
  }

  it.each([
    ["unknown id", (c: FileTransferClient) => c.approveDownload("not-a-uuid")],
    ["already dismissed", async (c: FileTransferClient, id: string) => {
      c.dismissDownload(id);
      return c.approveDownload(id);
    }],
  ])("returns false and delivers nothing when %s", async (_label, act) => {
    const s = await feedUnsolicited();
    await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
    await act(s.client, s.id);
    expect(s.delivered).not.toHaveBeenCalled();
  });

  it("a second approve returns false and does not double-deliver", async () => {
    const s = await feedUnsolicited();
    await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
    expect(s.client.approveDownload(s.id)).toBe(true);
    expect(s.client.approveDownload(s.id)).toBe(false);
    expect(s.delivered).toHaveBeenCalledOnce();
  });

  it("approve before completion fails closed (still assembling)", () => {
    const s = mk();
    const id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    s.client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "x", size: 4, sha256: "a".repeat(64) } }));
    expect(s.client.approveDownload(id)).toBe(false);
    expect(s.delivered).not.toHaveBeenCalled();
  });

  it("a peer Error while held releases the lease and clears the prompt row", async () => {
    const s = await feedUnsolicited();
    await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
    expect(s.pool.stats().leases).toBe(1);
    s.client.handleMessage(encodeMessage({ t: "Error", c: { id: s.id, message: "peer" } }));
    expect(s.pool.stats().leases).toBe(0);
    expect(s.pending()).toHaveLength(0);
  });
});
