import { afterEach, expect, it, vi } from "vitest";
import { DownloadMemoryBudget, FileTransferClient, encodeMessage, sha256Hex, sanitizeDisplayName } from "./file_transfer";

const ID = "11111111-2222-3333-4444-555555555555";
const bytes = new Uint8Array([1, 2, 3, 4]);
const owned: FileTransferClient[] = [];
afterEach(() => {
  for (const client of owned.splice(0)) client.dispose();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function setup(options: ConstructorParameters<typeof FileTransferClient>[3] = {}) {
  const pool = new DownloadMemoryBudget(16, 1);
  const delivered = vi.fn();
  let pending: readonly { id: string; name: string; size: number }[] = [];
  const client = new FileTransferClient(() => {}, delivered, () => {}, {
    memoryBudget: pool,
    onPendingDownloadsChanged: list => { pending = list; },
    ...options,
  });
  owned.push(client);
  return { client, pool, delivered, pending: () => pending };
}

function feed(client: FileTransferClient, sha: string, id = ID, name = "received.bin") {
  client.handleMessage(encodeMessage({ t: "Offer", c: { id, name, size: bytes.length, sha256: sha } }));
  client.handleMessage(encodeMessage({ t: "Chunk", c: { id, seq: 0, data: bytes } }));
  client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
}

it("keeps verified unmatched bytes charged until a single explicit approval", async () => {
  const s = setup();
  feed(s.client, await sha256Hex(bytes));
  await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
  expect(s.delivered).not.toHaveBeenCalled();
  expect(s.pool.stats()).toMatchObject({ used: 16, leases: 1 });
  expect(Object.keys(s.pending()[0]).sort()).toEqual(["id", "name", "size"]);
  // A second Done/Chunk must not re-hash empty parts or release held memory.
  s.client.handleMessage(encodeMessage({ t: "Done", c: { id: ID } }));
  s.client.handleMessage(encodeMessage({ t: "Chunk", c: { id: ID, seq: 1, data: bytes } }));
  expect(s.pool.stats().leases).toBe(1);
  s.client.approveDownload(ID);
  s.client.approveDownload(ID);
  expect(s.delivered).toHaveBeenCalledOnce();
  expect(s.delivered.mock.calls[0][0]).toMatchObject({ source: "approved", bytes, verified: true });
  expect(s.pool.stats()).toMatchObject({ used: 0, leases: 0 });
  expect(s.pending()).toHaveLength(0);
});

it("does not approve after the monotonic deadline even before the timer runs", async () => {
  let now = 0;
  const s = setup({ clock: () => now });
  feed(s.client, await sha256Hex(bytes));
  await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
  now = 60_001;
  s.client.approveDownload(ID);
  expect(s.delivered).not.toHaveBeenCalled();
  expect(s.pool.stats().leases).toBe(0);
  expect(s.pending()).toHaveLength(0);
});

it("routes a requested file by local intent and basename, never the offered name", async () => {
  const s = setup();
  const id = s.client.request("C:\\reports\\report.txt");
  feed(s.client, await sha256Hex(bytes), id, "screenshot-attacker.exe");
  await vi.waitFor(() => expect(s.delivered).toHaveBeenCalledOnce());
  expect(s.delivered.mock.calls[0][0]).toMatchObject({ name: "report.txt", source: "requested" });
  expect(s.pending()).toHaveLength(0);
});

it.each(["dismiss", "dispose"])("allows reentrant %s from the metadata callback without a lease leak", async action => {
  let client: FileTransferClient;
  const s = setup({ onPendingDownloadsChanged: list => {
    if (list.length) {
      if (action === "dismiss") client.dismissDownload(list[0].id);
      else client.dispose();
    }
  } });
  client = s.client;
  feed(client, await sha256Hex(bytes));
  await vi.waitFor(() => expect(s.pool.stats().leases).toBe(0));
  expect(s.delivered).not.toHaveBeenCalled();
});

it.each(["inactivity", "absolute age"])("expires a held file at its %s deadline", async mode => {
  let now = 0;
  const s = setup({ clock: () => now, limits: mode === "inactivity"
    ? { inactivityMs: 50, maxAgeMs: 500 } : { inactivityMs: 500, maxAgeMs: 50 } });
  feed(s.client, await sha256Hex(bytes));
  await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
  expect(s.pool.stats().leases).toBe(1);
  now = 50;
  await vi.waitFor(() => expect(s.pending()).toHaveLength(0));
  expect(s.pool.stats()).toMatchObject({ used: 0, leases: 0 });
  expect(s.delivered).not.toHaveBeenCalled();
});

it("cancelling a request consumes its expectation without authorizing a late offer", async () => {
  const s = setup({ maxPendingRequests: 1 });
  const id = s.client.request("cancelled.txt");
  s.client.cancelRequest(id);
  expect(() => s.client.request("next.txt")).not.toThrow();
  feed(s.client, await sha256Hex(bytes), id);
  await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
  expect(s.delivered).not.toHaveBeenCalled();
});

it("keeps an unmatched in-flight digest charged after disposal and never emits a late prompt", async () => {
  const sha = await sha256Hex(bytes);
  let settle!: (result: ArrayBuffer) => void;
  vi.spyOn(crypto.subtle, "digest").mockImplementation(() => new Promise(resolve => { settle = resolve; }));
  const s = setup();
  feed(s.client, sha);
  expect(s.pool.stats().leases).toBe(1);
  s.client.dispose();
  expect(s.pool.stats().leases).toBe(1);
  settle(new Uint8Array(sha.match(/../g)!.map(h => parseInt(h, 16))).buffer);
  await vi.waitFor(() => expect(s.pool.stats().leases).toBe(0));
  expect(s.pending()).toHaveLength(0);
  expect(s.delivered).not.toHaveBeenCalled();
});

it("rejects unmatched offers before allocating when there is no approval consumer", () => {
  const s = setup({ onPendingDownloadsChanged: undefined });
  s.client.handleMessage(encodeMessage({ t: "Offer", c: { id: ID, name: "screenshot-1.png", size: 4, sha256: "00".repeat(32) } }));
  expect(s.pool.stats()).toMatchObject({ used: 0, leases: 0 });
  expect(s.delivered).not.toHaveBeenCalled();
});

it("shows the same safe basename that explicit approval will save", async () => {
  const s = setup();
  feed(s.client, await sha256Hex(bytes), ID, "fake/path\\invoice\u202E.pdf.exe");
  await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
  expect(s.pending()[0].name).toBe("invoice.pdf.exe");
  s.client.approveDownload(ID);
  expect(s.delivered.mock.calls[0][0].name).toBe("invoice.pdf.exe");
});

it("preserves normal Unicode joining while removing filename direction overrides", () => {
  const ordinary = "گزارش\u200cنامه 👩\u200d💻.txt";
  expect(sanitizeDisplayName(ordinary)).toBe(ordinary);
  expect(sanitizeDisplayName("invoice\u202E.pdf.exe\n")).toBe("invoice.pdf.exe");
});

it("rearms an early pending-request timer instead of permanently occupying its slot", async () => {
  vi.useFakeTimers();
  let now = 0;
  const s = setup({ clock: () => now, maxPendingRequests: 1, requestDeadlineMs: 50 });
  s.client.request("first.txt");
  await vi.advanceTimersByTimeAsync(50); // injected monotonic clock is still before the deadline
  now = 50;
  await vi.advanceTimersByTimeAsync(50);
  expect(() => s.client.request("second.txt")).not.toThrow();
});

it("retains the approval lease through the save callback, including reentrant disposal", async () => {
  const pool = new DownloadMemoryBudget(16, 1);
  const observed: number[] = [];
  let pending = 0;
  let client: FileTransferClient;
  client = new FileTransferClient(() => {}, () => {
    observed.push(pool.stats().leases);
    client.dispose();
    observed.push(pool.stats().leases);
  }, () => {}, { memoryBudget: pool, onPendingDownloadsChanged: rows => { pending = rows.length; } });
  owned.push(client);
  feed(client, await sha256Hex(bytes));
  await vi.waitFor(() => expect(pending).toBe(1));
  client.approveDownload(ID);
  expect(observed).toEqual([1, 1]);
  expect(pool.stats().leases).toBe(0);
});

it("clears a pending request on peer Error and requires approval for a later reply", async () => {
  const s = setup({ maxPendingRequests: 1 });
  const id = s.client.request("requested.txt");
  s.client.handleMessage(encodeMessage({ t: "Error", c: { id, message: "not found" } }));
  expect(() => s.client.request("next.txt")).not.toThrow();
  feed(s.client, await sha256Hex(bytes), id, "late.exe");
  await vi.waitFor(() => expect(s.pending()).toHaveLength(1));
  expect(s.delivered).not.toHaveBeenCalled();
});
