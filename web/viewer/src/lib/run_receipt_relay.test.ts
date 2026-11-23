import { afterEach, expect, it, vi } from "vitest";
import { ConsoleApiClient } from "./console_api";
import { RunReceiptQueue } from "./run_receipt_relay";

const receipt = { requestId: "request/1", receipt: { claims: { request_id: "request/1", exit_code: null }, sig: "fixture" } };

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

it("refuses the 101st outstanding receipt and admits more when an entry completes", async () => {
  const queue = new RunReceiptQueue();
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  let complete!: (status: number) => void;
  const waiting = new Promise<number>((resolve) => { complete = resolve; });
  const post = vi.fn(() => waiting);
  for (let i = 0; i < 101; i++) queue.enqueue(receipt, post);
  expect(post).toHaveBeenCalledTimes(100);
  expect(warn).toHaveBeenCalledOnce();
  complete(200);
  await waiting;
  queue.enqueue(receipt, post);
  expect(post).toHaveBeenCalledTimes(101);
});

it("backs off on network errors, 429 and 5xx, stopping on 200", async () => {
  vi.useFakeTimers();
  const post = vi.fn<() => Promise<number>>()
    .mockRejectedValueOnce(new TypeError("network"))
    .mockResolvedValueOnce(429).mockResolvedValueOnce(503).mockResolvedValue(200);
  new RunReceiptQueue().enqueue(receipt, post);
  await vi.advanceTimersByTimeAsync(999);
  expect(post).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(post).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(2000);
  expect(post).toHaveBeenCalledTimes(3);
  await vi.advanceTimersByTimeAsync(4000);
  expect(post).toHaveBeenCalledTimes(4);
  expect(vi.getTimerCount()).toBe(0);
});

it.each([400, 401, 403, 404, 409, 422])("logs and drops HTTP %s", async (status) => {
  vi.useFakeTimers();
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  const post = vi.fn().mockResolvedValue(status);
  new RunReceiptQueue().enqueue(receipt, post);
  await vi.advanceTimersByTimeAsync(600000);
  expect(post).toHaveBeenCalledOnce();
  expect(warn).toHaveBeenCalledWith("Run receipt refused", status);
});

it("stops retrying at ten minutes", async () => {
  vi.useFakeTimers();
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const post = vi.fn().mockResolvedValue(503);
  new RunReceiptQueue().enqueue(receipt, post);
  await vi.advanceTimersByTimeAsync(600000);
  expect(post.mock.calls.length).toBeGreaterThan(1);
  expect(vi.getTimerCount()).toBe(0);
});

it("posts the unmodified signed object and bypasses the session fetch on 401", async () => {
  const sessionFetch = vi.fn();
  const receiptFetch = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
  const api = new ConsoleApiClient({ baseUrl: "/cp", fetch: sessionFetch, receiptFetch, cookies: () => "" });
  const { signal } = new AbortController();
  await expect(api.postRunReceipt(receipt, signal)).resolves.toBe(401);
  expect(receiptFetch).toHaveBeenCalledWith("/cp/runs/request%2F1/result", expect.objectContaining({
    method: "POST", credentials: "include", signal, body: JSON.stringify({ receipt: receipt.receipt }),
  }));
  expect(sessionFetch).not.toHaveBeenCalled();
});
