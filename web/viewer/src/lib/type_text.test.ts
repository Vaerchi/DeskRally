import { describe, expect, it } from "vitest";
import { key, text } from "./input";
import { TYPE_CHUNK_CHARS, VK_RETURN, VK_TAB, normalizeForTyping, typeBatches, typedLength, typingBatches } from "./type_text";

describe("paste by typing", () => {
  it("types ONE character per event by default (a burst garbles Windows 11 Notepad)", () => {
    expect(TYPE_CHUNK_CHARS).toBe(1);
    expect(typingBatches("hi😀")).toEqual([[text("h")], [text("i")], [text("😀")]]);
  });

  it("presses Enter and Tab as keys, not Unicode packets, for every line-ending style", () => {
    const enter = [key(VK_RETURN, true), key(VK_RETURN, false)];
    const tab = [key(VK_TAB, true), key(VK_TAB, false)];
    expect(typingBatches("a\r\nb\rc\nd\te")).toEqual([
      [text("a")], enter, [text("b")], enter, [text("c")], enter, [text("d")], tab, [text("e")],
    ]);
  });

  it("drops other control characters (ESC, backspace, NUL, DEL) but keeps the rest", () => {
    expect(normalizeForTyping("a\u001b[2Jb\u0008c\u0000d\u007fé")).toBe("a[2Jbcdé");
  });

  it("with a larger chunk, never splits a surrogate pair", () => {
    const s = "😀".repeat(32 + 3);
    const batches = typingBatches(s, 32);
    expect(batches).toHaveLength(2);
    expect(batches[0]).toEqual([text("😀".repeat(32))]);
    expect(batches[1]).toEqual([text("😀".repeat(3))]);
    for (const [ev] of batches) {
      const bytes = new TextEncoder().encode((ev as { c: string }).c).length;
      expect(bytes).toBeLessThanOrEqual(4096);
    }
  });

  it("counts characters after normalisation", () => {
    expect(typedLength("ab\r\n😀")).toBe(4);
    expect(typingBatches("")).toEqual([]);
  });

  it("sends batches in order with a pause between them, and stops on cancel or inactive input", async () => {
    const batches = typingBatches("ab\ncd", 1);
    const sent: unknown[] = [];
    const sleeps: number[] = [];
    const n = await typeBatches(batches, (b) => { sent.push(b); return true; },
      { delayMs: 7, sleep: async (ms) => { sleeps.push(ms); } });
    expect(n).toBe(batches.length);
    expect(sent).toEqual(batches);
    expect(sleeps).toEqual(Array(batches.length - 1).fill(7));

    let cancel = false;
    const got = await typeBatches(batches, () => { cancel = true; return true; },
      { cancelled: () => cancel, sleep: async () => {} });
    expect(got).toBe(1);

    const inactive = await typeBatches(batches, () => false, { sleep: async () => {} });
    expect(inactive).toBe(0);
  });
});
