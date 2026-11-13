/**
 * Clipboard codec + client tests — pins `encodeMessage` to the exact canonical JSON the Rust
 * `crates/agent-core/src/clipboard.rs` unit tests assert (byte-for-byte the same literals), plus a
 * minimal client exercise with a fake `navigator.clipboard`.
 *
 * docs/25 F08 flipped inbound to default-off: the older tests that asserted an auto-write on the
 * first inbound frame are gone. Explicit `setReceiveEnabled(true)` is now the only path to a native
 * write, and echo suppression is asserted through that same enabled path.
 */

import { describe, it, expect } from "vitest";
import {
  encodeMessage,
  decodeMessage,
  text,
  ClipboardClient,
  type ClipboardApi,
  type ClipboardMessage,
} from "./clipboard";

const dec = (u: Uint8Array) => new TextDecoder().decode(u);

describe("clipboard codec (wire-compat with Rust clipboard.rs)", () => {
  it("Text → adjacently-tagged JSON", () => {
    const bytes = encodeMessage({ t: "Text", c: "hi" });
    expect(dec(bytes)).toBe(`{"t":"Text","c":"hi"}`);
    expect(decodeMessage(bytes)).toEqual({ t: "Text", c: "hi" });
  });

  it("empty string round-trips (an empty clipboard is a valid state)", () => {
    const bytes = encodeMessage(text(""));
    expect(dec(bytes)).toBe(`{"t":"Text","c":""}`);
    expect(decodeMessage(bytes)).toEqual({ t: "Text", c: "" });
  });

  it("unicode + emoji round-trip exactly", () => {
    const s = "café — 日本語 — 🦀🎉";
    const bytes = encodeMessage(text(s));
    expect(dec(bytes)).toBe(`{"t":"Text","c":"${s}"}`);
    expect(decodeMessage(bytes)).toEqual({ t: "Text", c: s });
  });

  it("decode rejects garbage and unknown variants", () => {
    expect(() => decodeMessage(new Uint8Array(0))).toThrow();
    expect(() => decodeMessage(new TextEncoder().encode("not json"))).toThrow();
    expect(() => decodeMessage(new TextEncoder().encode(`{"t":"Image","c":"x"}`))).toThrow();
  });
});

/** An in-memory fake `navigator.clipboard` for the client tests. */
class FakeClipboard implements ClipboardApi {
  value = "";
  readonly writes: string[] = [];
  reads = 0;
  async readText(): Promise<string> {
    this.reads++;
    return this.value;
  }
  async writeText(t: string): Promise<void> {
    this.value = t;
    this.writes.push(t);
  }
}

describe("ClipboardClient outbound (unchanged by F08)", () => {
  it("sendText() reads the local clipboard and frames it out (once per change)", async () => {
    const fake = new FakeClipboard();
    const sent: ClipboardMessage[] = [];
    const client = new ClipboardClient((p) => sent.push(decodeMessage(p)), fake);

    fake.value = "hello agent";
    expect(await client.sendText()).toBe("hello agent");
    expect(sent).toEqual([{ t: "Text", c: "hello agent" }]);

    // Unchanged clipboard → nothing new is sent.
    expect(await client.sendText()).toBeNull();
    expect(sent.length).toBe(1);
  });

  it("sendText() returns null when readText rejects (no permission / not focused)", async () => {
    const denied: ClipboardApi = {
      readText: () => Promise.reject(new Error("NotAllowedError")),
      writeText: () => Promise.resolve(),
    };
    const sent: Uint8Array[] = [];
    const client = new ClipboardClient((p) => sent.push(p), denied);
    expect(await client.sendText()).toBeNull();
    expect(sent).toEqual([]);
  });
});

describe("ClipboardClient inbound consent (docs/25 F08)", () => {
  it("suppresses echo when receive is enabled and a write succeeded", async () => {
    const fake = new FakeClipboard();
    const sent: ClipboardMessage[] = [];
    const client = new ClipboardClient((p) => sent.push(decodeMessage(p)), fake);
    client.setReceiveEnabled(true);

    await client.handleMessage(encodeMessage(text("agent value")));
    expect(fake.writes).toEqual(["agent value"]);
    // A later opportunistic sendText() sees the SAME value → must not bounce it back.
    expect(await client.sendText()).toBeNull();
    expect(sent).toEqual([]);
  });
});
