import { describe, expect, it } from "vitest";
import { MAX_SHELL_INPUT_BYTES, ShellClient, type ShellChannelLike, type ShellState } from "./shell_client";

class FakeChannel implements ShellChannelLike {
  readyState: RTCDataChannelState = "connecting";
  binaryType: BinaryType = "blob";
  sent: (string | Uint8Array)[] = [];
  closed = false;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: Event) => void) | null = null;
  send(data: string | ArrayBuffer | ArrayBufferView): void {
    this.sent.push(typeof data === "string" ? data : new Uint8Array(data as ArrayBuffer));
  }
  close(): void {
    this.closed = true;
  }
  openNow(): void {
    this.readyState = "open";
    this.onopen?.(new Event("open"));
  }
  agent(msg: unknown): void {
    this.onmessage?.(new MessageEvent("message", { data: typeof msg === "string" ? msg : JSON.stringify(msg) }));
  }
  agentBytes(bytes: number[]): void {
    this.onmessage?.(new MessageEvent("message", { data: new Uint8Array(bytes).buffer }));
  }
}

function last<T>(xs: T[]): T {
  return xs[xs.length - 1];
}

function setup() {
  const dc = new FakeChannel();
  const states: ShellState[] = [];
  const output: number[][] = [];
  const client = new ShellClient(dc, { onState: (s) => states.push(s), onOutput: (b) => output.push([...b]) });
  return { dc, client, states, output };
}

describe("ShellClient (docs/76)", () => {
  it("sends open once the channel opens, answers the agent's token once, and reports open", () => {
    const { dc, client, states } = setup();
    expect(dc.binaryType).toBe("arraybuffer");
    client.open(120, 30);
    expect(dc.sent).toEqual([]); // not before the channel is open
    dc.openNow();
    expect(JSON.parse(dc.sent[0] as string)).toEqual({ t: "open", cols: 120, rows: 30 });
    dc.agent({ t: "needs_confirmation", reason: "x", token: "tok-1" });
    expect(JSON.parse(dc.sent[1] as string)).toEqual({ t: "open", cols: 120, rows: 30, token: "tok-1" });
    dc.agent({ t: "opened", shell_id: "s-1" });
    expect(last(states)).toEqual({ kind: "open", shellId: "s-1" });
  });

  it("does not loop on a second confirmation request", () => {
    const { dc, client, states } = setup();
    dc.openNow();
    client.open(80, 25);
    dc.agent({ t: "needs_confirmation", token: "a" });
    dc.agent({ t: "needs_confirmation", token: "b" });
    expect(dc.sent).toHaveLength(2);
    expect(last(states)).toEqual({ kind: "refused", reason: "the agent did not accept the confirmation" });
  });

  it("relays output and input only while open, chunking large input", () => {
    const { dc, client, output } = setup();
    dc.openNow();
    client.input("ignored before open");
    client.open(80, 25);
    dc.agent({ t: "opened", shell_id: "s" });
    dc.agentBytes([27, 91, 50, 74]);
    expect(output).toEqual([[27, 91, 50, 74]]);
    const big = "x".repeat(MAX_SHELL_INPUT_BYTES * 2 + 5);
    const before = dc.sent.length;
    client.input(big);
    const chunks = dc.sent.slice(before) as Uint8Array[];
    expect(chunks.map((c) => c.length)).toEqual([MAX_SHELL_INPUT_BYTES, MAX_SHELL_INPUT_BYTES, 5]);
  });

  it("reports refusals, closes with reasons, clamps resizes, and notices the channel closing", () => {
    const { dc, client, states } = setup();
    dc.openNow();
    client.open(80, 25);
    dc.agent({ t: "refused", reason: "a SYSTEM shell is not available in an attended session" });
    expect(last(states)).toEqual({ kind: "refused", reason: "a SYSTEM shell is not available in an attended session" });
    client.open(80, 25);
    dc.agent({ t: "opened", shell_id: "s" });
    client.resize(9999, 0);
    expect(JSON.parse(last(dc.sent) as string)).toEqual({ t: "resize", cols: 500, rows: 1 });
    dc.agent({ t: "closed", reason: "access expired", exit_code: null });
    expect(last(states)).toEqual({ kind: "closed", reason: "access expired", exitCode: null });
    dc.onclose?.(new Event("close"));
    expect(last(states)).toEqual({ kind: "disconnected" });
    client.dispose();
    expect(dc.closed).toBe(true);
  });
});
