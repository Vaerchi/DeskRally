import { describe, expect, it } from "vitest";
import { FileStreamClient, type FilesChannelLike, type StreamSink } from "./file_stream_client";
import { Sha256Stream } from "./sha256_stream";

// The fake agent's window: smaller than the real 8 MiB so the test is quick; the client does not know the window, it
// only credits what it has written, so a smaller one exercises the same waiting.
const WINDOW = 1024 * 1024;
const CHUNK = 32 * 1024;

/** A fake agent end of the files channel that follows the protocol: start, chunks within the credit window, done. */
class FakeAgent implements FilesChannelLike {
  readyState = "connecting";
  binaryType = "blob";
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  sentToAgent: Record<string, unknown>[] = [];
  maxAhead = 0;
  private sent = 0;
  private written = 0;
  private id = "";
  private cur: Uint8Array = new Uint8Array();
  constructor(
    private readonly files: Record<string, Uint8Array>,
    private readonly opts: { badDigest?: boolean; extraBytes?: boolean; errorAfter?: number; silent?: boolean; ignoreCredits?: boolean; claimSize?: number } = {},
  ) {
    queueMicrotask(() => {
      this.readyState = "open";
      this.onopen?.({});
    });
  }
  send(data: string): void {
    const m = JSON.parse(data);
    this.sentToAgent.push(m);
    if (this.opts.silent) return;
    if (m.t === "get") {
      const f = this.files[m.path];
      this.id = m.id;
      this.sent = 0;
      this.written = 0;
      if (!f) return this.reply({ t: "error", id: m.id, message: "file not found" });
      this.cur = f;
      const sha = this.opts.badDigest ? "0".repeat(64) : new Sha256Stream().update(f).digestHex();
      this.reply({ t: "start", id: m.id, name: m.path, size: this.opts.claimSize ?? f.length, sha256: sha });
      this.pump(f);
    } else if (m.t === "credit") {
      this.written = m.written;
      const file = this.cur;
      if (this.written === file.length && this.sent === file.length) this.reply({ t: "done", id: this.id, bytes: file.length });
      else this.pump(file);
    }
  }
  close(): void {
    this.readyState = "closed";
    this.onclose?.({});
  }
  private reply(m: object): void {
    queueMicrotask(() => this.onmessage?.({ data: JSON.stringify(m) }));
  }
  private pump(f: Uint8Array): void {
    while (this.sent < f.length && (this.opts.ignoreCredits || this.sent - this.written < WINDOW)) {
      if (this.opts.errorAfter !== undefined && this.sent >= this.opts.errorAfter) {
        this.reply({ t: "error", id: this.id, message: "the on-screen indicator was lost" });
        return;
      }
      const n = Math.min(CHUNK, f.length - this.sent);
      const chunk = f.slice(this.sent, this.sent + n);
      this.sent += n;
      this.maxAhead = Math.max(this.maxAhead, this.sent - this.written);
      queueMicrotask(() => this.onmessage?.({ data: chunk.buffer }));
    }
    if (this.opts.extraBytes && this.sent === f.length) {
      queueMicrotask(() => this.onmessage?.({ data: new Uint8Array(5).buffer }));
    }
  }
}

class MemSink implements StreamSink {
  parts: Uint8Array[] = [];
  closed = false;
  aborted = false;
  constructor(private readonly failAt?: number) {}
  async write(d: Uint8Array): Promise<void> {
    if (this.failAt !== undefined && this.parts.length === this.failAt) throw new Error("disk full");
    // A disk that yields (Node's setImmediate: not clamped like a 0 ms timer; the viewer tsconfig has no Node types).
    await new Promise<void>((r) => (globalThis as unknown as { setImmediate: (f: () => void) => void }).setImmediate(r));
    this.parts.push(d);
  }
  async close(): Promise<void> { this.closed = true; }
  async abort(): Promise<void> { this.aborted = true; }
  bytes(): Uint8Array {
    const out = new Uint8Array(this.parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of this.parts) { out.set(p, o); o += p.length; }
    return out;
  }
}

const data = (n: number) => { const d = new Uint8Array(n); for (let i = 0; i < n; i++) d[i] = (i * 7 + 3) & 0xff; return d; };

describe("FileStreamClient (docs/77 phase 3)", () => {
  it("streams a file into the sink in order, verified, never letting the agent run more than its window ahead", async () => {
    const file = data(1.5 * 1024 * 1024 + 123); // over one window: the agent must wait for credits
    const agent = new FakeAgent({ "dr-stage-1.bin": file });
    const client = new FileStreamClient(() => agent);
    const sink = new MemSink();
    let lastProgress = 0;
    const r = await client.get("dr-stage-1.bin", sink, (w) => { lastProgress = w; });
    expect(r.size).toBe(file.length);
    expect(sink.closed).toBe(true);
    expect(sink.aborted).toBe(false);
    expect(sink.bytes()).toEqual(file);
    expect(lastProgress).toBe(file.length);
    expect(agent.maxAhead).toBeLessThanOrEqual(WINDOW);
    const credits = agent.sentToAgent.filter((m) => m.t === "credit").map((m) => m.written as number);
    expect(credits[credits.length - 1]).toBe(file.length);
    expect([...credits].sort((a, b) => a - b)).toEqual(credits); // credits only move forward
  }, 60_000); // generous: the fake disk yields per chunk and a loaded machine slows it (seen 11-26)

  it("an empty file completes", async () => {
    const agent = new FakeAgent({ "e.txt": new Uint8Array(0) });
    const sink = new MemSink();
    const r = await new FileStreamClient(() => agent).get("e.txt", sink);
    expect(r.size).toBe(0);
    expect(sink.closed).toBe(true);
  });

  it("a digest mismatch saves nothing", async () => {
    const agent = new FakeAgent({ "a.bin": data(100_000) }, { badDigest: true });
    const sink = new MemSink();
    await expect(new FileStreamClient(() => agent).get("a.bin", sink)).rejects.toThrow(/changed while it was being copied/);
    expect(sink.aborted).toBe(true);
    expect(sink.closed).toBe(false);
  });

  it("an agent error mid-stream aborts the sink with the agent's reason", async () => {
    const agent = new FakeAgent({ "a.bin": data(1_000_000) }, { errorAfter: 200_000 });
    const sink = new MemSink();
    await expect(new FileStreamClient(() => agent).get("a.bin", sink)).rejects.toThrow(/indicator was lost/);
    expect(sink.aborted).toBe(true);
  });

  it("a failing disk cancels the download on the agent and aborts the sink", async () => {
    const agent = new FakeAgent({ "a.bin": data(500_000) });
    const sink = new MemSink(3);
    await expect(new FileStreamClient(() => agent).get("a.bin", sink)).rejects.toThrow(/disk full/);
    expect(sink.aborted).toBe(true);
    expect(agent.sentToAgent.some((m) => m.t === "cancel")).toBe(true);
  });

  it("more bytes than the announced size is refused", async () => {
    const agent = new FakeAgent({ "a.bin": data(70_000) }, { extraBytes: true });
    const sink = new MemSink();
    await expect(new FileStreamClient(() => agent).get("a.bin", sink)).rejects.toThrow(/more than the file's size/);
    expect(sink.aborted).toBe(true);
  });

  it("silence from the agent ends the download", async () => {
    const agent = new FakeAgent({ "a.bin": data(10) }, { silent: true });
    const sink = new MemSink();
    await expect(new FileStreamClient(() => agent, 30, undefined, 30).get("a.bin", sink)).rejects.toThrow(/did not start sending/);
    expect(sink.aborted).toBe(true);
  });

  it("a missing file is reported and the next get still works on the same channel", async () => {
    const agent = new FakeAgent({ "b.txt": data(10) });
    const client = new FileStreamClient(() => agent);
    await expect(client.get("nope.txt", new MemSink())).rejects.toThrow(/file not found/);
    const sink = new MemSink();
    await client.get("b.txt", sink);
    expect(sink.bytes()).toEqual(data(10));
  });

  it("no connection: the sink is aborted and the error says so", async () => {
    const sink = new MemSink();
    await expect(new FileStreamClient(() => null).get("a", sink)).rejects.toThrow(/not connected/);
    expect(sink.aborted).toBe(true);
  });

  it("refuses an announced size over its limit (never trusts the agent's size)", async () => {
    const agent = new FakeAgent({ "a.bin": data(10) }, { claimSize: 5 * 1024 * 1024 * 1024 });
    const sink = new MemSink();
    await expect(new FileStreamClient(() => agent).get("a.bin", sink)).rejects.toThrow(/larger than 4096 MiB/);
    expect(sink.aborted).toBe(true);
    expect(agent.sentToAgent.some((m) => m.t === "cancel")).toBe(true);
  });

  it("refuses an agent that ignores credits and runs ahead (no unbounded queue in the tab)", async () => {
    const big = data(12 * 1024 * 1024);
    const agent = new FakeAgent({ "a.bin": big }, { ignoreCredits: true });
    const sink = new MemSink();
    await expect(new FileStreamClient(() => agent).get("a.bin", sink)).rejects.toThrow(/faster than it was allowed/);
    expect(sink.aborted).toBe(true);
  }, 20_000);

  it("after a failed download the next one gets a fresh channel (late chunks are never read as its bytes)", async () => {
    let opened = 0;
    const files = { "a.bin": data(100_000), "b.txt": data(10) };
    const client = new FileStreamClient(() => { opened++; return new FakeAgent(files, opened === 1 ? { badDigest: true } : {}); });
    await expect(client.get("a.bin", new MemSink())).rejects.toThrow(/changed while it was being copied/);
    const sink = new MemSink();
    await client.get("b.txt", sink);
    expect(opened).toBe(2);
    expect(sink.bytes()).toEqual(data(10));
  });

  it("opens a sink given as a function inside the queue, one at a time", async () => {
    const agent = new FakeAgent({ "a": data(10), "b": data(20) });
    const client = new FileStreamClient(() => agent);
    const order: string[] = [];
    const open = (n: string) => async () => { order.push(`open ${n}`); return new MemSink(); };
    const pa = client.get("a", open("a")).then(() => order.push("done a"));
    const pb = client.get("b", open("b")).then(() => order.push("done b"));
    await Promise.all([pa, pb]);
    expect(order).toEqual(["open a", "done a", "open b", "done b"]);
  });
});
