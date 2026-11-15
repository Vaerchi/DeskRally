/**
 * Frame codec tests — asserts wire-compatibility with the Rust `crates/protocol/src/frame.rs`
 * layout: [channel: u8][len: u32 big-endian][payload]. These mirror the Rust unit tests so
 * both sides are pinned to the same bytes.
 */

import { describe, it, expect, vi } from "vitest";
import {
  ChannelId,
  FRAME_HEADER_LEN,
  MAX_FRAME_LEN,
  FrameError,
  FrameDecoder,
  channelFromU8,
  channelPriority,
  channelReliable,
  decodeFrame,
  encodeFrame,
  frame,
  encodeSignaling,
  decodeSignaling,
} from "./protocol";
import type { ClientToServer, ServerToClient } from "./protocol";

const bytes = (s: string) => new TextEncoder().encode(s);

describe("Frame codec (wire-compat with Rust frame.rs)", () => {
  it("produces the exact byte layout: u8 channel + u32 BE length + payload", () => {
    const encoded = encodeFrame(frame(ChannelId.Input, bytes("click")));
    // channel=1, len=5 (0x00000005), then "click"
    expect(Array.from(encoded)).toEqual([
      0x01, // Input
      0x00, 0x00, 0x00, 0x05, // length, big-endian
      0x63, 0x6c, 0x69, 0x63, 0x6b, // "click"
    ]);
    expect(encoded.length).toBe(FRAME_HEADER_LEN + 5);
  });

  it("round-trips a single frame and reports bytes consumed", () => {
    const f = frame(ChannelId.Input, bytes("click"));
    const encoded = encodeFrame(f);
    const { frame: decoded, consumed } = decodeFrame(encoded);
    expect(decoded.channel).toBe(ChannelId.Input);
    expect(new TextDecoder().decode(decoded.payload)).toBe("click");
    expect(consumed).toBe(encoded.length);
  });

  it("round-trips an empty payload", () => {
    const encoded = encodeFrame(frame(ChannelId.Control, new Uint8Array(0)));
    expect(encoded.length).toBe(FRAME_HEADER_LEN);
    const { frame: decoded, consumed } = decodeFrame(encoded);
    expect(decoded.channel).toBe(ChannelId.Control);
    expect(decoded.payload.length).toBe(0);
    expect(consumed).toBe(FRAME_HEADER_LEN);
  });

  it("round-trips every channel id", () => {
    for (const c of [
      ChannelId.Control,
      ChannelId.Input,
      ChannelId.Video,
      ChannelId.Clipboard,
      ChannelId.Chat,
      ChannelId.FileTransfer,
      ChannelId.Backstage,
    ]) {
      const { frame: decoded } = decodeFrame(encodeFrame(frame(c, bytes("x"))));
      expect(decoded.channel).toBe(c);
    }
  });

  it("decodes multiple frames from one buffer via offsets", () => {
    const a = encodeFrame(frame(ChannelId.Input, bytes("a")));
    const b = encodeFrame(frame(ChannelId.Video, bytes("bb")));
    const buf = new Uint8Array(a.length + b.length);
    buf.set(a, 0);
    buf.set(b, a.length);

    const first = decodeFrame(buf, 0);
    expect(first.frame.channel).toBe(ChannelId.Input);

    const second = decodeFrame(buf, first.consumed);
    expect(second.frame.channel).toBe(ChannelId.Video);
    expect(new TextDecoder().decode(second.frame.payload)).toBe("bb");
  });

  it("throws Incomplete when fewer than a full frame is present", () => {
    const full = encodeFrame(frame(ChannelId.Chat, bytes("hello")));
    const partial = full.slice(0, 7); // header + 2 of 5 payload bytes
    try {
      decodeFrame(partial);
      throw new Error("expected FrameError");
    } catch (e) {
      expect(e).toBeInstanceOf(FrameError);
      expect((e as FrameError).kind).toBe("incomplete");
    }
  });

  it("throws Incomplete when even the header is short", () => {
    expect(() => decodeFrame(new Uint8Array([0x01, 0x00]))).toThrowError(FrameError);
  });

  it("rejects an oversized length header (too_long)", () => {
    const buf = new Uint8Array(FRAME_HEADER_LEN);
    const view = new DataView(buf.buffer);
    view.setUint8(0, ChannelId.Video);
    view.setUint32(1, MAX_FRAME_LEN + 1, false);
    try {
      decodeFrame(buf);
      throw new Error("expected FrameError");
    } catch (e) {
      expect((e as FrameError).kind).toBe("too_long");
      expect((e as FrameError).value).toBe(MAX_FRAME_LEN + 1);
    }
  });

  it("rejects an unknown channel id", () => {
    const buf = new Uint8Array(FRAME_HEADER_LEN);
    const view = new DataView(buf.buffer);
    view.setUint8(0, 99);
    view.setUint32(1, 0, false);
    try {
      decodeFrame(buf);
      throw new Error("expected FrameError");
    } catch (e) {
      expect((e as FrameError).kind).toBe("unknown_channel");
      expect((e as FrameError).value).toBe(99);
    }
  });

  // docs/25 F02: the channel byte is validated from the HEADER, before the payload-
  // completeness check, and must stay that way (length -> channel -> completeness), in
  // lockstep with Rust `Frame::decode`. Checking the channel last turns a frame that can
  // never be accepted into "incomplete" — a recoverable "read more" — so the receiver
  // accumulates toward a payload it was always going to reject. The test above declares
  // length 0 and passes under either ordering; this one does not.
  it("rejects an unknown channel before waiting for the declared payload", () => {
    const declaredLen = 8 * 1024 * 1024; // large but legal: a receiver would wait for 8 MiB
    expect(declaredLen).toBeLessThan(MAX_FRAME_LEN);
    const buf = new Uint8Array(FRAME_HEADER_LEN); // header only — no payload supplied
    const view = new DataView(buf.buffer);
    view.setUint8(0, 99);
    view.setUint32(1, declaredLen, false);
    try {
      decodeFrame(buf);
      throw new Error("expected FrameError");
    } catch (e) {
      expect(e).toBeInstanceOf(FrameError);
      // NOT "incomplete": both facts are knowable from the 5 header bytes alone.
      expect((e as FrameError).kind).toBe("unknown_channel");
      expect((e as FrameError).value).toBe(99);
    }
  });
});

describe("FrameDecoder (streaming byte accumulator)", () => {
  it("decodes frames split into single bytes and owns its input", () => {
    const dec = new FrameDecoder();
    const expected = frame(ChannelId.Chat, bytes("hello"));
    const encoded = encodeFrame(expected);
    const out = [];
    const chunk = new Uint8Array(1);
    for (let i = 0; i < encoded.length; i++) {
      chunk[0] = encoded[i];
      out.push(...dec.push(chunk));
      chunk[0] = 255;
      expect(dec.pending).toBe(i === encoded.length - 1 ? 0 : i + 1);
    }
    expect(out).toEqual([decodeFrame(encoded).frame]);
    expect(out).toEqual([expected]);
  });

  it("rejects a split oversized header as soon as its fifth byte arrives", () => {
    const header = new Uint8Array(FRAME_HEADER_LEN);
    header[0] = 99;
    new DataView(header.buffer).setUint32(1, MAX_FRAME_LEN + 1, false);
    const dec = new FrameDecoder();
    for (let i = 0; i < FRAME_HEADER_LEN - 1; i++) {
      expect(dec.push(header.subarray(i, i + 1))).toEqual([]);
    }
    try {
      dec.push(header.subarray(4));
      throw new Error("expected FrameError");
    } catch (e) {
      expect(e).toBeInstanceOf(FrameError);
      expect((e as FrameError).kind).toBe("too_long");
      expect((e as FrameError).value).toBe(MAX_FRAME_LEN + 1);
    }
  });

  it("copies only linear bytes for a 4 MiB frame delivered in 1 KiB chunks", () => {
    const encoded = encodeFrame(frame(ChannelId.Video, new Uint8Array(4 * 1024 * 1024)));
    const dec = new FrameDecoder();
    const originalSet = Uint8Array.prototype.set;
    let copied = 0;
    // Counting bytes catches repeated partial-frame concatenation without timing assumptions.
    const spy = vi.spyOn(Uint8Array.prototype, "set").mockImplementation(function (
      this: Uint8Array, source: ArrayLike<number>, offset?: number,
    ) {
      copied += source.length;
      originalSet.call(this, source, offset);
    });
    let decoded;
    try {
      for (let i = 0; i < encoded.length; i += 1024) {
        const out = dec.push(encoded.subarray(i, i + 1024));
        if (out.length > 0) decoded = out[0];
      }
    } finally {
      spy.mockRestore();
    }
    // A plain loop, not toEqual: a deep equality over 4 MiB takes vitest ~20 s.
    const expected = decodeFrame(encoded).frame;
    expect(decoded?.channel).toBe(expected.channel);
    expect(decoded?.payload.length).toBe(expected.payload.length);
    let mismatches = 0;
    for (let i = 0; i < expected.payload.length; i++) if (decoded!.payload[i] !== expected.payload[i]) mismatches++;
    expect(mismatches).toBe(0);
    expect(dec.pending).toBe(0);
    expect(copied).toBeGreaterThanOrEqual(encoded.length - FRAME_HEADER_LEN);
    expect(copied).toBeLessThanOrEqual(3 * encoded.length);
  });

  it("decodes multiple empty frames in one chunk", () => {
    const dec = new FrameDecoder();
    const empty = frame(ChannelId.Control, new Uint8Array(0));
    const encoded = encodeFrame(empty);
    const stream = new Uint8Array(encoded.length * 2);
    stream.set(encoded);
    stream.set(encoded, encoded.length);
    expect(dec.push(stream)).toEqual([empty, empty]);
    expect(dec.pending).toBe(0);
  });
  it("yields complete frames and retains a trailing partial frame", () => {
    const dec = new FrameDecoder();
    const a = encodeFrame(frame(ChannelId.Input, bytes("aa")));
    const b = encodeFrame(frame(ChannelId.Clipboard, bytes("bbbb")));
    const stream = new Uint8Array(a.length + b.length);
    stream.set(a, 0);
    stream.set(b, a.length);

    // Feed in two arbitrary splits, one mid-frame.
    const cut = a.length + 3;
    const out1 = dec.push(stream.slice(0, cut));
    expect(out1.map((f) => f.channel)).toEqual([ChannelId.Input]);
    expect(dec.pending).toBe(cut - a.length);

    const out2 = dec.push(stream.slice(cut));
    expect(out2.map((f) => f.channel)).toEqual([ChannelId.Clipboard]);
    expect(dec.pending).toBe(0);
  });

  // docs/25 F02: push() must THROW on this header rather than swallowing it as "incomplete"
  // and accumulating — `too_long`/`unknown_channel` are hard protocol errors. Only a decoder
  // that validates the channel BEFORE the completeness check can raise one from a chunk that
  // is header-sized; keep the ordering in decodeFrame (and its Rust mirror) as it is.
  it("throws on an unknown channel with a large declared length instead of buffering", () => {
    const declaredLen = 8 * 1024 * 1024; // large but legal
    expect(declaredLen).toBeLessThan(MAX_FRAME_LEN);
    const header = new Uint8Array(FRAME_HEADER_LEN); // header only — no payload supplied
    const view = new DataView(header.buffer);
    view.setUint8(0, 99);
    view.setUint32(1, declaredLen, false);

    const dec = new FrameDecoder();
    let thrown: unknown;
    let returned: unknown;
    try {
      returned = dec.push(header);
    } catch (e) {
      thrown = e;
    }
    // Under the old ordering push() did not throw: it returned [] and kept the 5 bytes
    // buffered, waiting for a payload it would always reject.
    expect(thrown).toBeInstanceOf(FrameError);
    expect((thrown as FrameError).kind).toBe("unknown_channel");
    expect((thrown as FrameError).value).toBe(99);
    expect(returned).toBeUndefined();
  });
});

describe("ChannelId policy (mirror of channel.rs)", () => {
  it("round-trips ids through u8 and rejects unknown", () => {
    for (let v = 0; v <= 6; v++) expect(channelFromU8(v)).toBe(v);
    expect(channelFromU8(200)).toBeUndefined();
  });

  it("prioritizes input over video over file transfer", () => {
    expect(channelPriority(ChannelId.Input)).toBeGreaterThan(channelPriority(ChannelId.Video));
    expect(channelPriority(ChannelId.Video)).toBeGreaterThan(
      channelPriority(ChannelId.FileTransfer),
    );
  });

  it("marks only video as lossy", () => {
    expect(channelReliable(ChannelId.Video)).toBe(false);
    expect(channelReliable(ChannelId.Input)).toBe(true);
    expect(channelReliable(ChannelId.FileTransfer)).toBe(true);
  });
});

describe("signaling SDP message (mirrors Rust/Go wire format)", () => {
  it("encodes an offer with the snake_case type tag", () => {
    const msg: ClientToServer = {
      type: "sdp",
      session: "11111111-1111-1111-1111-111111111111" as never,
      sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n",
      kind: "offer",
    };
    const json = encodeSignaling(msg);
    expect(json).toContain('"type":"sdp"');
    expect(json).toContain('"kind":"offer"');
  });

  it("round-trips an answer through encode/decode", () => {
    const original: ServerToClient = {
      type: "sdp",
      session: "22222222-2222-2222-2222-222222222222" as never,
      sdp: "v=0\r\ns=-\r\n",
      kind: "answer",
    };
    const decoded = decodeSignaling(JSON.stringify(original)) as Extract<
      ServerToClient,
      { type: "sdp" }
    >;
    expect(decoded.kind).toBe("answer");
    expect(decoded.sdp).toBe("v=0\r\ns=-\r\n");
  });
});
