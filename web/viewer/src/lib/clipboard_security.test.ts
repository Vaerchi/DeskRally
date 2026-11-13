/**
 * docs/25 F08 — inbound consent / bounds regression suite.
 *
 * Every case runs the REAL `ClipboardClient` against a tracking fake `ClipboardApi`; no real OS
 * clipboard, no navigator, no permissions API is ever touched. Small limits and a fake clock are
 * injected through the options seam so timing behaviour is deterministic and rate-limit and
 * in-flight assertions do not depend on wall-clock scheduling.
 */

import { afterEach, describe, it, expect, vi } from "vitest";
import {
  ClipboardClient,
  encodeMessage,
  text,
  type ClipboardApi,
  type ClipboardNotice,
} from "./clipboard";
afterEach(() => vi.restoreAllMocks());

/** Fake API that counts and records every call — the primary evidence surface for these tests. */
class TrackingClipboard implements ClipboardApi {
  reads = 0;
  writes: string[] = [];
  writeResult: () => Promise<void> = () => Promise.resolve();
  async readText(): Promise<string> {
    this.reads++;
    return "";
  }
  async writeText(t: string): Promise<void> {
    this.writes.push(t);
    return this.writeResult();
  }
}

/** A controllable monotonic clock; advanced explicitly in each timing-sensitive case. */
function fakeClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (dt: number) => {
      t += dt;
    },
  };
}

function makeClient(
  api: ClipboardApi,
  overrides: Partial<{
    maxTextBytes: number;
    minWriteIntervalMs: number;
    now: () => number;
    onNotice: (n: ClipboardNotice) => void;
  }> = {},
) {
  const sent: Uint8Array[] = [];
  const client = new ClipboardClient((p) => sent.push(p), api, {
    maxTextBytes: overrides.maxTextBytes ?? 32,
    minWriteIntervalMs: overrides.minWriteIntervalMs ?? 100,
    now: overrides.now,
    onNotice: overrides.onNotice,
  });
  return { client, sent };
}

describe("F08 default-off", () => {
  it("drops inbound frames without touching the OS or the decoder when disabled", async () => {
    const api = new TrackingClipboard();
    const notices: ClipboardNotice[] = [];
    const { client } = makeClient(api, { onNotice: (n) => notices.push(n) });
    const decode = vi.spyOn(TextDecoder.prototype, "decode");

    // Send several syntactically valid frames plus one obviously oversized one — every one MUST
    // be dropped WITHOUT decoding: a disabled client offers zero surface to a hostile peer.
    for (let i = 0; i < 5; i++) {
      await client.handleMessage(encodeMessage(text("payload " + i)));
    }
    await client.handleMessage(new Uint8Array(1024 * 1024)); // giant garbage

    expect(api.writes).toEqual([]);
    expect(api.reads).toBe(0);
    // No notice, either — the checkbox label already tells the operator receive is off.
    expect(notices).toEqual([]);
    expect(client.isReceiveEnabled()).toBe(false);
    expect(decode).not.toHaveBeenCalled();
  });

  it("configuration validation rejects non-positive / non-integer / non-finite tunings", () => {
    const api = new TrackingClipboard();
    const send = () => {};
    expect(() => new ClipboardClient(send, api, { maxTextBytes: 0 })).toThrow(RangeError);
    expect(() => new ClipboardClient(send, api, { maxTextBytes: -1 })).toThrow(RangeError);
    expect(() => new ClipboardClient(send, api, { maxTextBytes: 1.5 })).toThrow(RangeError);
    expect(() => new ClipboardClient(send, api, { maxTextBytes: Number.POSITIVE_INFINITY })).toThrow(
      RangeError,
    );
    expect(() => new ClipboardClient(send, api, { minWriteIntervalMs: 0 })).toThrow(RangeError);
    // The cap is deliberately far below Number.MAX_SAFE_INTEGER so 6*x + 64 never overflows.
    expect(() => new ClipboardClient(send, api, { maxTextBytes: Number.MAX_SAFE_INTEGER })).toThrow(
      RangeError,
    );
  });
});

describe("F08 enable/disable/dispose", () => {
  it("explicit enable writes exactly once; a later disable blocks all future writes", async () => {
    const api = new TrackingClipboard();
    const clock = fakeClock();
    const { client } = makeClient(api, { now: clock.now });

    client.setReceiveEnabled(true);
    await client.handleMessage(encodeMessage(text("first")));
    expect(api.writes).toEqual(["first"]);

    // Move past the rate window so a follow-up would otherwise succeed — the disable is what blocks.
    clock.advance(1000);
    client.setReceiveEnabled(false);
    await client.handleMessage(encodeMessage(text("blocked-1")));
    await client.handleMessage(encodeMessage(text("blocked-2")));
    expect(api.writes).toEqual(["first"]);
  });

  it("dispose() is idempotent, blocks late inbound frames and refuses async outbound sends", async () => {
    const api = new TrackingClipboard();
    // readText resolves later so we can dispose between the await and the send.
    let resolveRead: (v: string) => void = () => {};
    api.readText = () =>
      new Promise<string>((res) => {
        resolveRead = res;
      });
    const notices: ClipboardNotice[] = [];
    const { client, sent } = makeClient(api, {
      onNotice: (n) => notices.push(n),
    });
    client.setReceiveEnabled(true);

    const sendPromise = client.sendText();
    client.dispose();
    client.dispose(); // idempotent — no throw, no state change
    resolveRead("post-dispose");
    expect(await sendPromise).toBeNull();
    expect(sent).toEqual([]);

    // Late inbound frames after dispose do nothing — no writes, no notices (callback was cleared).
    await client.handleMessage(encodeMessage(text("late")));
    expect(api.writes).toEqual([]);
    expect(notices).toEqual([]);
    expect(client.isReceiveEnabled()).toBe(false);
  });

  it("a fresh client after a disposed one defaults off regardless of prior opt-in", async () => {
    const api1 = new TrackingClipboard();
    const { client: c1 } = makeClient(api1);
    c1.setReceiveEnabled(true);
    await c1.handleMessage(encodeMessage(text("session-1")));
    c1.dispose();

    const api2 = new TrackingClipboard();
    const { client: c2 } = makeClient(api2);
    expect(c2.isReceiveEnabled()).toBe(false);
    await c2.handleMessage(encodeMessage(text("session-2")));
    expect(api2.writes).toEqual([]);
  });
});

describe("F08 bounds + validation", () => {
  it("rejects malformed frames after decode without a native call", async () => {
    const api = new TrackingClipboard();
    const notices: ClipboardNotice[] = [];
    const clock = fakeClock();
    const { client } = makeClient(api, { now: clock.now, onNotice: (n) => notices.push(n) });
    client.setReceiveEnabled(true);

    await client.handleMessage(new TextEncoder().encode("not-json-at-all"));
    clock.advance(1000);
    await client.handleMessage(new TextEncoder().encode(`{"t":"Image","c":"x"}`));

    expect(api.writes).toEqual([]);
    expect(notices.map((n) => n.kind)).toEqual(["malformed", "malformed"]);
  });

  it("rejects oversized frames pre-decode AND post-decode without a native call", async () => {
    const api = new TrackingClipboard();
    const notices: ClipboardNotice[] = [];
    const clock = fakeClock();
    const { client } = makeClient(api, {
      maxTextBytes: 16,
      minWriteIntervalMs: 100,
      now: clock.now,
      onNotice: (n) => notices.push(n),
    });
    client.setReceiveEnabled(true);

    // 1. Pre-decode cap: 6 * 16 + 64 = 160. A 512-byte payload is dropped before parse.
    const big = new Uint8Array(512);
    big.fill(0x20);
    const decode = vi.spyOn(TextDecoder.prototype, "decode");
    await client.handleMessage(big);
    expect(decode).not.toHaveBeenCalled();
    expect(notices[notices.length - 1]?.kind).toBe("too-large");

    // 2. Post-decode cap: fits the pre-decode envelope, string looks OK char-count-wise, but 8 emoji
    //    (each 4 UTF-8 bytes) = 32 bytes, above 16. Ensure a well-formed but oversized text drops.
    clock.advance(1000);
    const long = "🦀".repeat(8);
    await client.handleMessage(encodeMessage(text(long)));
    expect(api.writes).toEqual([]);
    expect(notices[notices.length - 1]?.kind).toBe("too-large");
  });

  it("accepts a UTF-8 boundary that fits exactly, including escaped controls", async () => {
    const api = new TrackingClipboard();
    const clock = fakeClock();
    // 12 bytes: three 4-byte emoji fit exactly at maxTextBytes = 12.
    const { client } = makeClient(api, { maxTextBytes: 12, now: clock.now });
    client.setReceiveEnabled(true);

    const exact = "🦀🦀🦀";
    await client.handleMessage(encodeMessage(text(exact)));
    expect(api.writes).toEqual([exact]);

    // A control character encodes as `\u0007` on the wire (6 chars, but 1 UTF-8 byte after decode).
    // The pre-decode cap must permit the escaped form; the post-decode cap sees only 1 byte.
    clock.advance(1000);
    const controls = "\u0007".repeat(12);
    await client.handleMessage(encodeMessage(text(controls)));
    expect(api.writes[api.writes.length - 1]).toBe(controls);
  });
});

describe("F08 rate + in-flight discipline", () => {
  it("drops frames that arrive inside the rate window (no queue)", async () => {
    const api = new TrackingClipboard();
    const notices: ClipboardNotice[] = [];
    const clock = fakeClock();
    const { client } = makeClient(api, {
      minWriteIntervalMs: 100,
      now: clock.now,
      onNotice: (n) => notices.push(n),
    });
    client.setReceiveEnabled(true);

    await client.handleMessage(encodeMessage(text("a")));
    // Same tick — must be dropped.
    await client.handleMessage(encodeMessage(text("b")));
    // 50 ms later — still inside the window.
    clock.advance(50);
    await client.handleMessage(encodeMessage(text("c")));
    // 200 ms after the first accept — past the window.
    clock.advance(200);
    await client.handleMessage(encodeMessage(text("d")));

    expect(api.writes).toEqual(["a", "d"]);
    // Successful writes and rejected attempts share the notification budget.
    expect(notices.length).toBeLessThanOrEqual(2);
  });

  it("only one delayed write completes despite many messages and receive toggles", async () => {
    const api = new TrackingClipboard();
    // Hold the first write in flight until we say so.
    let resolveFirst: () => void = () => {};
    let call = 0;
    api.writeResult = () => {
      call++;
      if (call === 1) return new Promise<void>((res) => (resolveFirst = res));
      return Promise.resolve();
    };
    const clock = fakeClock();
    const { client } = makeClient(api, {
      minWriteIntervalMs: 10,
      now: clock.now,
    });
    client.setReceiveEnabled(true);

    // Kick off one write and DO NOT await — it stays in flight.
    const firstWrite = client.handleMessage(encodeMessage(text("first")));
    // Flood while the write is in flight; toggle receive between them.
    for (let i = 0; i < 10; i++) {
      clock.advance(50);
      await client.handleMessage(encodeMessage(text("burst-" + i)));
    }
    client.setReceiveEnabled(false);
    client.setReceiveEnabled(true);
    for (let i = 0; i < 10; i++) {
      clock.advance(50);
      await client.handleMessage(encodeMessage(text("more-" + i)));
    }
    // Only the first write's promise is issued — nothing queued behind it.
    expect(api.writes).toEqual(["first"]);
    resolveFirst();
    await firstWrite;
    // Even after the write settles, there is no post-settle burst: no queue accumulated.
    expect(api.writes).toEqual(["first"]);
    clock.advance(50);
    await client.handleMessage(encodeMessage(text("after settle")));
    expect(api.writes).toEqual(["first", "after settle"]);
  });

  it("write rejection leaves echo-suppression state unchanged and does not throw", async () => {
    const api = new TrackingClipboard();
    api.writeResult = () => Promise.reject(new Error("NotAllowedError"));
    const clock = fakeClock();
    const notices: ClipboardNotice[] = [];
    const { client, sent } = makeClient(api, {
      now: clock.now,
      onNotice: (n) => notices.push(n),
    });
    client.setReceiveEnabled(true);

    await expect(client.handleMessage(encodeMessage(text("would-echo")))).resolves.toBeUndefined();
    expect(api.writes).toEqual(["would-echo"]);
    expect(notices.map((n) => n.kind)).toContain("permission-failed");

    // A subsequent sendText() where the local clipboard has that same string MUST still push it —
    // a failed inbound write does not silently swallow a legitimate outbound gesture.
    api.readText = async () => "would-echo";
    clock.advance(1000);
    const out = await client.sendText();
    expect(out).toBe("would-echo");
    expect(sent.length).toBe(1);

  });

  it("an onNotice that throws cannot break subsequent frames or dispose()", async () => {
    const api = new TrackingClipboard();
    const clock = fakeClock();
    const { client } = makeClient(api, {
      now: clock.now,
      onNotice: () => {
        throw new Error("observer boom");
      },
    });
    client.setReceiveEnabled(true);

    await expect(
      client.handleMessage(encodeMessage(text("a"))),
    ).resolves.toBeUndefined();
    clock.advance(1000);
    await expect(
      client.handleMessage(encodeMessage(text("b"))),
    ).resolves.toBeUndefined();
    expect(api.writes).toEqual(["a", "b"]);
    // Dispose must still succeed — the callback is cleared, not called.
    expect(() => client.dispose()).not.toThrow();
  });
});
