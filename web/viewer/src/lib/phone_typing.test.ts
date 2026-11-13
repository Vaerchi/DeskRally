/**
 * Phone-typing tests: the diff that replays a soft keyboard's edits on the guest, the sentinel and
 * overflow rules of `typingEdit`, the reset rule, and the keys that bypass the field. No DOM — the
 * component only feeds field values in.
 */

import { describe, it, expect } from "vitest";
import {
  NAV_KEYS,
  STRIP_MODIFIERS,
  TEXT_CHUNK_CODEPOINTS,
  TYPING_MAX_EDIT,
  TYPING_RESEED_AT,
  TYPING_SENTINEL as S,
  navKeyEvents,
  shouldReseed,
  typingContent,
  typingDiff,
  typingEdit,
  typingFieldKey,
  codeForTypedChar,
  singleTypedChar,
} from "./phone_typing";
import { MODIFIER_ORDER, oskKeyEvents } from "./osk";
import { liveKeyEvent, vkForCode } from "./dom_input";
import { key, text, type InputEvent } from "./input";

const tap = (code: string): InputEvent[] => [key(vkForCode(code), true), key(vkForCode(code), false)];
const BS = tap("Backspace");
const ENTER = tap("Enter");

/** Replay a sequence of raw field values through `typingEdit`, as the component does. */
function replay(values: string[]): InputEvent[] {
  let content = "";
  const out: InputEvent[] = [];
  for (const v of values) {
    const e = typingEdit(content, v);
    out.push(...e.events);
    content = e.content;
  }
  return out;
}

describe("typingDiff (content to content)", () => {
  it("sends nothing when nothing changed", () => {
    expect(typingDiff("abc", "abc")).toEqual([]);
  });

  it("sends an appended letter as Text", () => {
    expect(typingDiff("", "h")).toEqual([text("h")]);
  });

  it("sends a whole committed word as ONE Text event", () => {
    expect(typingDiff("", "hello")).toEqual([text("hello")]);
  });

  it("turns a deletion at the end into Backspaces, one per character", () => {
    expect(typingDiff("abc", "a")).toEqual([...BS, ...BS]);
  });

  it("replays an autocorrect from the first differing character: teh -> the", () => {
    expect(typingDiff("teh", "the")).toEqual([...BS, ...BS, text("he")]);
  });

  it("an autocorrect that adds a trailing space keeps prefix and appends", () => {
    expect(typingDiff("teh", "the ")).toEqual([...BS, ...BS, text("he ")]);
  });

  it("turns a newline into an Enter tap, not Unicode text", () => {
    expect(typingDiff("dir", "dir\n")).toEqual(ENTER);
  });

  it("splits text around newlines and tabs, in order", () => {
    expect(typingDiff("", "a\nb\tc")).toEqual([text("a"), ...ENTER, text("b"), ...tap("Tab"), text("c")]);
  });

  it("collapses CRLF to ONE Enter", () => {
    expect(typingDiff("", "x\r\ny")).toEqual([text("x"), ...ENTER, text("y")]);
  });

  it("counts by code point: an emoji is one Backspace, and a prefix never splits a surrogate pair", () => {
    expect(typingDiff("a😀", "a")).toEqual(BS);
    // 😀 (U+1F600) and 😁 (U+1F601) share their HIGH surrogate; a UTF-16 prefix would keep half.
    expect(typingDiff("😀", "😁")).toEqual([...BS, text("😁")]);
  });

  it("chunks a long run so no Text event can exceed the agent's 4096-byte limit", () => {
    const run = "😀".repeat(TEXT_CHUNK_CODEPOINTS * 2 + 5); // 4 UTF-8 bytes each: the worst case
    const events = typingDiff("", run);
    expect(events).toHaveLength(3);
    for (const ev of events) {
      expect(ev.t).toBe("Text");
      expect(new TextEncoder().encode((ev as { c: string }).c).length).toBeLessThanOrEqual(4096);
    }
    expect(events.map((ev) => (ev as { c: string }).c).join("")).toBe(run);
  });

  it("a mid-field edit replays from the edit point, so the guest still ends with the field's text", () => {
    expect(typingDiff("abcd", "abXcd")).toEqual([...BS, ...BS, text("Xcd")]);
  });
});

describe("typingEdit (raw field value, sentinel, overflow)", () => {
  it("strips the sentinel: it was never sent, so it is never diffed as guest text", () => {
    expect(typingContent(S + "abc")).toBe("abc");
    expect(typingEdit("", S + "h")).toEqual({ events: [text("h")], content: "h", overflow: false });
  });

  it("a Backspace on an EMPTY field (the sentinel deleted) is one guest Backspace", () => {
    expect(typingEdit("", "", "deleteContentBackward")).toEqual({ events: BS, content: "", overflow: false });
  });

  it("select-all + replace sends exactly one Backspace per SENT character — not one for the sentinel", () => {
    // Codex v1 finding: ' abc' -> 'x' used to send FOUR Backspaces, deleting a guest character the
    // bar never typed.
    expect(typingEdit("abc", "x", "insertText").events).toEqual([...BS, ...BS, ...BS, text("x")]);
  });

  it("select-all + paste into a FRESH field sends no Backspace at all", () => {
    expect(typingEdit("", "pasted", "insertFromPaste").events).toEqual([text("pasted")]);
  });

  it("select-all + cut/delete of a fresh field sends nothing", () => {
    expect(typingEdit("", "", "deleteByCut").events).toEqual([]);
    expect(typingEdit("", "", "deleteContentForward").events).toEqual([]);
    expect(typingEdit("", "")).toEqual({ events: [], content: "", overflow: false });
  });

  it("composition updates replay live and end with the guest holding exactly the final text", () => {
    // Gboard's composing word: "w", "wo", "wor", then the prediction picks "world ".
    expect(replay([S + "w", S + "wo", S + "wor", S + "world "])).toEqual([text("w"), text("o"), text("r"), text("ld ")]);
  });

  it("refuses an oversized insertion whole: nothing sent, history unchanged, caller told to reset", () => {
    const big = "x".repeat(TYPING_MAX_EDIT + 1);
    expect(typingEdit("ab", S + "ab" + big)).toEqual({ events: [], content: "ab", overflow: true });
  });

  it("refuses an oversized deletion whole", () => {
    const long = "y".repeat(TYPING_MAX_EDIT + 1);
    expect(typingEdit(long, S).overflow).toBe(true);
  });

  it("accepts an edit of exactly the limit (newline-heavy: still bounded to 2 events per char)", () => {
    const nl = "\n".repeat(TYPING_MAX_EDIT);
    const e = typingEdit("", S + nl);
    expect(e.overflow).toBe(false);
    expect(e.events).toHaveLength(TYPING_MAX_EDIT * 2);
  });
});

describe("shouldReseed", () => {
  it("never resets under an active composition", () => {
    expect(shouldReseed("", true)).toBe(false);
    expect(shouldReseed(S + "a\n", true)).toBe(false);
    expect(shouldReseed(S + "x".repeat(TYPING_RESEED_AT * 2), true)).toBe(false);
  });

  it("resets once the sentinel is gone, so the next Backspace still registers", () => {
    expect(shouldReseed("", false)).toBe(true);
    expect(shouldReseed("abc", false)).toBe(true);
  });

  it("resets after a line break", () => {
    expect(shouldReseed(S + "dir\n", false)).toBe(true);
  });

  it("resets after a TAB: it moves guest focus, so nothing before it may be diffed against (Codex v2)", () => {
    expect(shouldReseed(S + "a\tb", false)).toBe(true);
    expect(shouldReseed(S + "a\t", false)).toBe(true);
  });

  it("resets long CONTENT, and only past the threshold (the sentinel does not count)", () => {
    const at = S + "x".repeat(TYPING_RESEED_AT);
    expect(shouldReseed(at, false)).toBe(false);
    expect(shouldReseed(at + "x", false)).toBe(true);
  });

  it("leaves an ordinary short line alone", () => {
    expect(shouldReseed(S + "hello", false)).toBe(false);
  });
});

describe("typingFieldKey", () => {
  const ev = (key: string, over: Partial<{ code: string; keyCode: number; isComposing: boolean }> = {}) => ({
    key,
    code: over.code ?? key,
    keyCode: over.keyCode ?? 1,
    isComposing: over.isComposing ?? false,
  });

  it("passes a hardware arrow, Escape, Delete and Tab straight to the guest", () => {
    expect(typingFieldKey(ev("ArrowLeft"))).toEqual(tap("ArrowLeft"));
    expect(typingFieldKey(ev("Escape"))).toEqual(tap("Escape"));
    expect(typingFieldKey(ev("Delete"))).toEqual(tap("Delete"));
    expect(typingFieldKey(ev("Tab"))).toEqual(tap("Tab"));
  });

  it("leaves text, Backspace and Enter to the field (they arrive via the diff, so never twice)", () => {
    expect(typingFieldKey(ev("a", { code: "KeyA" }))).toBeNull();
    expect(typingFieldKey(ev("Backspace"))).toBeNull();
    expect(typingFieldKey(ev("Enter"))).toBeNull();
  });

  it("ignores IME placeholders even when they claim a nav key", () => {
    expect(typingFieldKey(ev("ArrowLeft", { keyCode: 229 }))).toBeNull();
    expect(typingFieldKey(ev("ArrowLeft", { isComposing: true }))).toBeNull();
  });
});

describe("the key strip's modifiers and typed characters", () => {
  it("every strip modifier is a real modifier key the latch understands", () => {
    for (const k of STRIP_MODIFIERS) {
      expect(vkForCode(k.code), k.code).not.toBe(0);
      expect(MODIFIER_ORDER).toContain(k.code);
    }
    expect(STRIP_MODIFIERS.map((k) => k.label)).toEqual(["Ctrl", "Alt", "Win"]);
  });

  it("a typed letter or digit has a key a modifier can combine with; nothing else does", () => {
    expect(codeForTypedChar("c")).toBe("KeyC");
    expect(codeForTypedChar("C")).toBe("KeyC");
    expect(codeForTypedChar("7")).toBe("Digit7");
    for (const ch of ["@", " ", "é", "😀", "", "ab"]) expect(codeForTypedChar(ch), ch).toBeNull();
  });

  it("only a single inserted character counts as 'the next key'", () => {
    expect(singleTypedChar([{ t: "Text", c: "c" }])).toBe("c");
    expect(singleTypedChar([{ t: "Text", c: "😀" }])).toBe("😀");
    expect(singleTypedChar([{ t: "Text", c: "cat" }])).toBeNull(); // autocorrect / paste
    expect(singleTypedChar([])).toBeNull();
    expect(singleTypedChar([{ t: "Key", c: { code: 8, down: true } }, { t: "Key", c: { code: 8, down: false } }])).toBeNull();
  });

  it("Ctrl latched, then c typed, is exactly Ctrl down, C down, C up, Ctrl up", () => {
    const ctrl = vkForCode("ControlLeft");
    const c = vkForCode("KeyC");
    expect(oskKeyEvents(["ControlLeft"], codeForTypedChar("c")!)).toEqual([
      { t: "Key", c: { code: ctrl, down: true } },
      { t: "Key", c: { code: c, down: true } },
      { t: "Key", c: { code: c, down: false } },
      { t: "Key", c: { code: ctrl, down: false } },
    ]);
  });
});

describe("NAV_KEYS", () => {
  it("every nav key resolves to a real virtual key and taps it", () => {
    for (const k of NAV_KEYS) {
      expect(vkForCode(k.code), k.code).not.toBe(0);
      expect(navKeyEvents(k)).toEqual(tap(k.code));
    }
  });
});

describe("liveKeyEvent (the window-level keyboard path)", () => {
  it("drops the Android soft-keyboard placeholder instead of injecting VK 229", () => {
    expect(liveKeyEvent({ code: "", keyCode: 229 }, true)).toBeNull();
  });

  it("drops a keydown during an IME composition", () => {
    expect(liveKeyEvent({ code: "KeyA", keyCode: 65, isComposing: true }, true)).toBeNull();
  });

  it("drops a key that maps to no virtual key", () => {
    expect(liveKeyEvent({ code: "", keyCode: 0 }, true)).toBeNull();
  });

  it("keeps the keyCode fallback for a physical key whose code is unmapped", () => {
    expect(liveKeyEvent({ code: "SomeOemKey", keyCode: 0xe2 }, true)).toEqual(key(0xe2, true));
  });

  it("still sends an ordinary physical key, down and up", () => {
    expect(liveKeyEvent({ code: "KeyA", keyCode: 65 }, true)).toEqual(key(vkForCode("KeyA"), true));
    expect(liveKeyEvent({ code: "KeyA", keyCode: 65 }, false)).toEqual(key(vkForCode("KeyA"), false));
  });
});
