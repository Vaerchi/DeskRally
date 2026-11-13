/**
 * Phone typing — turn what a phone's own keyboard (Gboard, Samsung Keyboard, …) does to a text
 * field into input events for the remote machine.
 *
 * WHY NOT JUST CAPTURE keydown, like the physical-keyboard path. A soft keyboard does not send keys.
 * Chrome on Android reports almost every keystroke as `keyCode 229` with `key: "Unidentified"` and
 * an empty `code`, and the real change arrives later as an edit to a focused field — often a whole
 * word at once, rewritten again by autocorrect or a prediction tap. Forwarding those keydowns sends
 * VK 229 (VK_PROCESSKEY) to the guest: junk, not text. And with no focused field the keyboard does
 * not open at all, which is why the viewer used to offer only its own tap-a-cap keyboard.
 *
 * THE APPROACH: the operator types into a real (visible) text field, and every `input` event is a
 * DIFF between what the field held and what it holds now. Whatever the keyboard did — a letter, a
 * composed word, an autocorrect replacing "teh" with "the", a swipe-typed word, a paste — reduces
 * to "delete N characters from the end, then type this", which is exactly what the guest's caret
 * needs replayed: N Backspaces, then the new text as `Text` (the agent injects it with
 * KEYEVENTF_UNICODE, so it is layout-independent and covers any script).
 *
 * THE CONTRACT THAT MAKES THE DIFF SAFE: the field's CONTENT (everything after the sentinel) is
 * exactly what this bar has typed since the guest's caret was last somewhere we know — at the end of
 * that content. Anything that moves the guest caret behind our back (a nav key, a tap on the remote
 * screen, input being switched off) must RESET the content to empty, or a later Backspace or
 * autocorrect would delete characters the operator never meant. The component owns those resets;
 * this module only ever diffs content against content.
 *
 * THE SENTINEL. A Backspace on an EMPTY field changes nothing, so it fires no `input` event and the
 * guest would never see it. So the field always starts with {@link TYPING_SENTINEL}. The sentinel is
 * NOT content — it was never sent — so it is stripped before diffing; deleting it sends a Backspace
 * only when the operator's INTENT was a backspace on an empty field (`deleteContentBackward`), never
 * when it disappears as part of replacing a selection (select-all + paste).
 *
 * Pure and React-free, like `osk.ts`: vitest's include glob covers `.ts` only.
 */

import { vkForCode } from "./dom_input";
import { chord } from "./special_keys";
import { text, type InputEvent } from "./input";

/** What the typing field is reset to: one character a Backspace can delete. A plain space, not a
 *  zero-width character — some keyboards treat invisible characters oddly (one backspace that
 *  appears to do nothing, predictions anchored to nothing). */
export const TYPING_SENTINEL = " ";

/** Reset the field once its content holds more than this many characters (outside a composition).
 *  Bounds the cost of a mid-field edit and keeps the field from growing for a whole session. */
export const TYPING_RESEED_AT = 64;

/**
 * Largest single edit accepted, in code points, for EITHER side: characters deleted or characters
 * inserted. An edit past this (a huge paste, a runaway composition) is refused whole — nothing is
 * sent and the component resets the field — rather than flooding the input channel, since a
 * newline-heavy paste costs two key events per character.
 */
export const TYPING_MAX_EDIT = 1000;

/**
 * Longest `Text` event, in code points. The agent refuses a `Text` over 4096 UTF-8 BYTES, and one
 * code point is at most 4 bytes, so 1000 code points can never trip it.
 */
export const TEXT_CHUNK_CODEPOINTS = 1000;

const VK_BACKSPACE = vkForCode("Backspace");
const VK_ENTER = vkForCode("Enter");
const VK_TAB = vkForCode("Tab");

/** The edit from `prev` to `next`, by CODE POINT: how many trailing characters of `prev` go, and
 *  what replaces them. */
function splitEdit(prev: string, next: string): { deleted: number; inserted: string[] } {
  const a = Array.from(prev);
  const b = Array.from(next);
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) p++;
  return { deleted: a.length - p, inserted: b.slice(p) };
}

/**
 * The events that turn the guest's text from `prev` into `next`, assuming the guest's caret sits at
 * the end of `prev`. Both arguments are CONTENT (no sentinel).
 *
 * Compared by code point (`Array.from`), not UTF-16 unit, so an emoji is one Backspace rather than
 * two, and the common prefix can never split a surrogate pair. (A multi-code-point grapheme — a
 * flag, a ZWJ family — may still need its Backspaces counted differently by the guest app; that is
 * an edge the guest's own text control decides, and we do not try to model it.)
 *
 * Newlines become an Enter tap and tabs a Tab tap rather than Unicode text: `KEYEVENTF_UNICODE` with
 * U+000A is not an Enter key to most Windows apps. A `\r` (some keyboards send `\r\n`) is dropped so
 * one line break is one Enter.
 */
export function typingDiff(prev: string, next: string): InputEvent[] {
  const { deleted, inserted } = splitEdit(prev, next);
  const events: InputEvent[] = [];
  for (let i = 0; i < deleted; i++) events.push(...chord([], VK_BACKSPACE));

  let run: string[] = [];
  const flush = () => {
    for (let i = 0; i < run.length; i += TEXT_CHUNK_CODEPOINTS) {
      events.push(text(run.slice(i, i + TEXT_CHUNK_CODEPOINTS).join("")));
    }
    run = [];
  };
  for (const ch of inserted) {
    if (ch === "\n") {
      flush();
      events.push(...chord([], VK_ENTER));
    } else if (ch === "\t") {
      flush();
      events.push(...chord([], VK_TAB));
    } else if (ch !== "\r") {
      run.push(ch);
    }
  }
  flush();
  return events;
}

/** The field's content: its value minus the leading sentinel, if the sentinel is still there. */
export function typingContent(value: string): string {
  return value.startsWith(TYPING_SENTINEL) ? value.slice(TYPING_SENTINEL.length) : value;
}

/** What one `input` event on the typing field means for the guest. */
export interface TypingEdit {
  /** Events to send. Empty on overflow. */
  events: InputEvent[];
  /** The content the guest now holds, to diff the next edit against. */
  content: string;
  /** The edit exceeded {@link TYPING_MAX_EDIT}: nothing was sent, and the caller must reset. */
  overflow: boolean;
}

/**
 * Interpret one `input` event: `prevContent` is the content as of the last edit, `nextValue` the
 * field's raw value now, `inputType` the event's `InputEvent.inputType` when there is one.
 */
export function typingEdit(prevContent: string, nextValue: string, inputType?: string): TypingEdit {
  const content = typingContent(nextValue);
  // A backspace with nothing typed: the sentinel went and nothing else changed. That is the one
  // case where losing the sentinel IS a guest Backspace — the operator deleting into text the bar
  // did not type. Select-all + delete/cut/paste also removes it, with a different inputType.
  if (prevContent === "" && nextValue === "" && inputType === "deleteContentBackward") {
    return { events: chord([], VK_BACKSPACE), content: "", overflow: false };
  }
  const { deleted, inserted } = splitEdit(prevContent, content);
  if (deleted > TYPING_MAX_EDIT || inserted.length > TYPING_MAX_EDIT) {
    return { events: [], content: prevContent, overflow: true };
  }
  return { events: typingDiff(prevContent, content), content, overflow: false };
}

/**
 * Should the field be reset to the sentinel now? Never mid-composition — rewriting the value under
 * an active IME composition aborts or duplicates the word on most keyboards. Otherwise: once the
 * sentinel is gone (so the next Backspace still registers), once the content is long, or after a
 * line break or TAB. Both are sent as real keys that can move the guest's caret or focus — Enter may
 * submit a dialog, Tab moves to the next control — so text before them is no longer at the guest
 * caret, and a later select-all replace would send Backspaces into a control the bar never typed
 * into (Codex v2). Resetting forgets that history.
 */
export function shouldReseed(value: string, composing: boolean): boolean {
  if (composing) return false;
  if (!value.startsWith(TYPING_SENTINEL)) return true;
  if (value.includes("\n") || value.includes("\t")) return true;
  return Array.from(typingContent(value)).length > TYPING_RESEED_AT;
}

/** One navigation key on the phone-typing bar — the keys a soft keyboard does not have. */
export interface NavKey {
  /** DOM `code` of the physical key, resolved through `dom_input`'s one VK table. */
  code: string;
  label: string;
  title: string;
}

/**
 * Navigation keys a phone keyboard lacks. These inject the same `Key` event a physical arrow or
 * Delete key already sends through the live-keyboard path, so they behave exactly as that does on
 * the guest. Every one of them moves the guest caret or changes text the bar cannot see, so the
 * component resets the field's content before sending one.
 */
export const NAV_KEYS: NavKey[] = [
  { code: "Escape", label: "Esc", title: "Escape" },
  { code: "ArrowLeft", label: "←", title: "Left arrow" },
  { code: "ArrowRight", label: "→", title: "Right arrow" },
  { code: "ArrowUp", label: "↑", title: "Up arrow" },
  { code: "ArrowDown", label: "↓", title: "Down arrow" },
  { code: "Home", label: "Home", title: "Home" },
  { code: "End", label: "End", title: "End" },
  { code: "Tab", label: "Tab", title: "Tab" },
  { code: "Delete", label: "Del", title: "Delete (forward delete)" },
];

/**
 * The modifiers on the key strip above the phone's keyboard. Shift is not here: the phone keyboard
 * has its own. A tap LATCHES one locally and the next key (a strip key or one typed letter or digit)
 * goes as a chord, pressed and released in one burst (see `oskKeyEvents` in `osk.ts` for why a
 * modifier is never held down on the guest).
 */
export const STRIP_MODIFIERS: NavKey[] = [
  { code: "ControlLeft", label: "Ctrl", title: "Ctrl (applies to the next key)" },
  { code: "AltLeft", label: "Alt", title: "Alt (applies to the next key)" },
  { code: "MetaLeft", label: "Win", title: "Windows key (applies to the next key, or tap twice for Start)" },
];

/**
 * The key code for one typed character, when it has a key of its own a modifier can combine with:
 * a letter or a digit. Anything else (punctuation, accented letters, emoji) has no layout-free
 * key, so a latched modifier cannot apply to it.
 */
export function codeForTypedChar(ch: string): string | null {
  if (/^[a-zA-Z]$/.test(ch)) return `Key${ch.toUpperCase()}`;
  if (/^[0-9]$/.test(ch)) return `Digit${ch}`;
  return null;
}

/**
 * The single character an edit typed, if that is ALL it did (one `Text` event of one character);
 * otherwise `null` (a deletion, an autocorrect replacement, a paste).
 */
export function singleTypedChar(events: InputEvent[]): string | null {
  if (events.length !== 1) return null;
  const e = events[0];
  if (e.t !== "Text") return null;
  const chars = [...e.c];
  return chars.length === 1 ? chars[0] : null;
}

/** The events one nav-key tap sends: a plain down+up of its virtual key. */
export function navKeyEvents(k: NavKey): InputEvent[] {
  return chord([], vkForCode(k.code));
}

/**
 * A key pressed while the typing field has focus that should go straight to the guest instead of
 * editing the field — a hardware keyboard's arrows, Escape, Delete, … (a folding phone with a
 * Bluetooth keyboard, or a keyboard app that has arrow keys). Returns `null` for anything the field
 * should handle itself: printable text, Backspace and Enter (they reach the guest through the diff),
 * and every IME placeholder (`keyCode 229`, or a keydown during composition). Like a nav key, a
 * passthrough moves the guest caret, so the caller resets the field's content.
 */
export function typingFieldKey(e: { key: string; code: string; keyCode: number; isComposing: boolean }): InputEvent[] | null {
  if (e.isComposing || e.keyCode === 229) return null;
  const passthrough = ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End", "PageUp", "PageDown", "Delete", "Escape", "Tab"];
  if (!passthrough.includes(e.key)) return null;
  const vk = vkForCode(e.key);
  return vk === 0 ? null : chord([], vk);
}
