import { afterEach, describe, expect, it, vi } from "vitest";
import { ClipboardClient, encodeMessage, type ClipboardApi, type ClipboardNotice } from "./clipboard";

const clients: ClipboardClient[] = [];
function setup(options: ConstructorParameters<typeof ClipboardClient>[2] = {}) {
  const api: ClipboardApi = { readText: vi.fn(async () => "local"), writeText: vi.fn(async () => {}) };
  const notices: ClipboardNotice[] = [];
  const client = new ClipboardClient(() => {}, api, { ...options, onNotice: value => notices.push(value) });
  clients.push(client);
  client.setReceiveEnabled(true);
  return { client, api, notices };
}
afterEach(() => {
  for (const client of clients.splice(0)) client.dispose();
  vi.restoreAllMocks();
});

describe("independent clipboard review regressions", () => {
  it("debits parsing attempts even when frames are malformed", async () => {
    let now = 0;
    const s = setup({ now: () => now, minWriteIntervalMs: 100 });
    const bad = new TextEncoder().encode('{"t":"Text","c":42}');
    const decode = vi.spyOn(TextDecoder.prototype, "decode");
    for (let i = 0; i < 100; i++) await s.client.handleMessage(bad);
    expect(decode).toHaveBeenCalledOnce();
    expect(s.api.writeText).not.toHaveBeenCalled();
    now = 100;
    await s.client.handleMessage(encodeMessage({ t: "Text", c: "valid" }));
    expect(s.api.writeText).toHaveBeenCalledOnce();
  });

  it("alternating rejection kinds cannot flood the notice callback", async () => {
    const s = setup({ now: () => 0, maxTextBytes: 4, minWriteIntervalMs: 100 });
    const oversized = new Uint8Array(89);
    const malformed = new TextEncoder().encode('{"t":"Text","c":42}');
    for (let i = 0; i < 50; i++) {
      await s.client.handleMessage(oversized);
      await s.client.handleMessage(malformed);
    }
    expect(s.notices).toHaveLength(1);
    expect(s.api.writeText).not.toHaveBeenCalled();
  });

  it("a failed outgoing send is not reported as sent or cached against retry", async () => {
    const send = vi.fn().mockImplementationOnce(() => { throw new Error("transport closed"); });
    const api: ClipboardApi = { readText: async () => "retry me", writeText: async () => {} };
    const client = new ClipboardClient(send, api);
    clients.push(client);
    expect(await client.sendText()).toBeNull();
    expect(await client.sendText()).toBe("retry me");
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("a native write completing after off/on cannot commit stale echo or notice state", async () => {
    let finish!: () => void;
    const notices: ClipboardNotice[] = [];
    const send = vi.fn();
    const client = new ClipboardClient(send, {
      readText: async () => "old value",
      writeText: () => new Promise<void>(resolve => { finish = resolve; }),
    }, { onNotice: value => notices.push(value) });
    clients.push(client);
    client.setReceiveEnabled(true);
    const writing = client.handleMessage(encodeMessage({ t: "Text", c: "old value" }));
    client.setReceiveEnabled(false); client.setReceiveEnabled(true);
    finish(); await writing;
    expect(notices).toEqual([]);
    expect(await client.sendText()).toBe("old value");
    expect(send).toHaveBeenCalledOnce();
  });
});
