/**
 * DOM event → canonical `InputEvent` mapping (Milestone V1).
 *
 * Bridges browser DOM input events to the agent's canonical `InputEvent` wire shape (see
 * `input.ts`), which the Rust agent decodes (`input_codec`) and injects via `SendInput`. These are
 * pure functions taking plain objects (not live DOM events) so they are unit-testable without a DOM
 * — vitest here runs in a `node` environment. `Viewer.tsx` calls them, then
 * `transport.send(ChannelId.Input, encodeInput(ev))`.
 */

import {
  mouseMove,
  mouseButton,
  scroll,
  key,
  type InputButton,
  type InputEvent,
} from "./input";

/** Absolute coordinate space the agent maps onto the target monitor (0..=65535). */
export const ABS_MAX = 65535;

/** Normalize a `0..1` fraction to the agent's `0..=65535` absolute coordinate space. */
export function toAbs(fraction: number): number {
  return Math.max(0, Math.min(ABS_MAX, Math.round(fraction * ABS_MAX)));
}

/** `MouseMove` at already-normalized absolute coords. */
export function moveEvent(xAbs: number, yAbs: number): InputEvent {
  return mouseMove(xAbs, yAbs);
}

/**
 * Map a DOM `MouseEvent.button` to the agent's `InputButton`.
 *
 * DOM numbering (MDN `MouseEvent.button`): `0` = left/main, `1` = middle/wheel, `2` = right/
 * secondary, `3` = back, `4` = forward. (The old viewer encoded `1` as "right" — that was WRONG;
 * `1` is the middle button.) Returns `null` for a button we do not map.
 */
export function domButtonToInputButton(button: number): InputButton | null {
  switch (button) {
    case 0:
      return "Left";
    case 1:
      return "Middle";
    case 2:
      return "Right";
    case 3:
      return "Back";
    case 4:
      return "Forward";
    default:
      return null;
  }
}

/** `MouseButton` press/release, or `null` for an unmapped DOM button. */
export function buttonEvent(domButton: number, down: boolean): InputEvent | null {
  const button = domButtonToInputButton(domButton);
  return button ? mouseButton(button, down) : null;
}

/**
 * Map a DOM `wheel` event to a `Scroll` measured in wheel notches.
 *
 * Sign: the agent's `Scroll` treats `dy>0` as scrolling UP (it maps to `+WHEEL_DELTA`), whereas the
 * DOM `wheel` event reports `deltaY>0` when scrolling DOWN — so `dy` is the NEGATED, notch-scaled
 * `deltaY`. `dx` keeps the DOM sign (`deltaX>0` = right = agent `dx>0`).
 *
 * Scale: pixel-mode deltas (`deltaMode === 0`) are ~100px per notch on Windows, so we divide by 100
 * and round; line/page modes (`1`/`2`) are already in notch-like units (divide by 1). Any nonzero
 * delta yields at least one notch, so small trackpad movements are never silently dropped.
 */
export function wheelToScroll(e: {
  deltaX: number;
  deltaY: number;
  deltaMode?: number;
}): InputEvent {
  const perNotch = (e.deltaMode ?? 0) === 0 ? 100 : 1;
  const notches = (d: number): number =>
    d === 0 ? 0 : Math.round(d / perNotch) || Math.sign(d);
  const dy = -notches(e.deltaY); // flip: DOM down (+) → agent down (−)
  const dx = notches(e.deltaX); //  keep: DOM right (+) → agent right (+)
  return scroll(dx, dy);
}

/**
 * Normalize a wheel `deltaY` to a pixel-equivalent magnitude, so the viewer's zoom/pan respond
 * consistently across the DOM delta modes. `deltaMode` 0 is already pixels; mode 1 is LINES (~16px
 * each on Windows); mode 2 is PAGES (a viewport). Firefox reports line mode for a standard mouse,
 * where one notch is only a few line-units — without this the exponential zoom would barely move.
 *
 * Sibling to {@link wheelToScroll}, which speaks in scroll NOTCHES for the remote scroll wheel; this
 * speaks in PIXELS, which is the unit the zoom rate (`WHEEL_ZOOM_RATE`) is calibrated against.
 */
export function wheelPixels(deltaY: number, deltaMode?: number): number {
  switch (deltaMode) {
    case 1:
      return deltaY * 16; // lines → px
    case 2:
      return deltaY * 800; // pages → px (a nominal viewport height)
    default:
      return deltaY; // already pixels (mode 0 / undefined)
  }
}

/**
 * Complete `KeyboardEvent.code` → Windows virtual-key (VK) map (V3).
 *
 * We prefer this over the (deprecated but still-populated) `keyCode` for the keys it covers, because
 * `e.code` is layout-independent and stable (it names the PHYSICAL key, so `Digit1` is VK 0x31 whether
 * or not Shift is held — the shifted glyph "!" is produced by the agent's OS from the concurrent
 * Shift key event, not a different VK). This table now covers the full US-layout keyboard: letters,
 * digits, F1–F24, navigation/editing, whitespace, both-hand modifiers, US punctuation, the numpad
 * (digits + operators), and the lock/system keys. For anything still unmapped (exotic intl/media
 * keys) we fall back to `e.keyCode`, which on Windows Chrome already equals the VK code for most keys.
 */
const CODE_TO_VK: Record<string, number> = (() => {
  const m: Record<string, number> = {
    // Whitespace / editing.
    Enter: 0x0d,
    Escape: 0x1b,
    Backspace: 0x08,
    Tab: 0x09,
    Space: 0x20,
    // Navigation / editing cluster.
    ArrowLeft: 0x25,
    ArrowUp: 0x26,
    ArrowRight: 0x27,
    ArrowDown: 0x28,
    Delete: 0x2e,
    Insert: 0x2d,
    Home: 0x24,
    End: 0x23,
    PageUp: 0x21,
    PageDown: 0x22,
    // Lock / system keys.
    CapsLock: 0x14,
    NumLock: 0x90,
    ScrollLock: 0x91,
    PrintScreen: 0x2c,
    Pause: 0x13,
    ContextMenu: 0x5d, // "Apps"/Menu key
    // Modifiers, left + right (VK_L*/VK_R* distinguish the sides).
    ShiftLeft: 0xa0,
    ShiftRight: 0xa1,
    ControlLeft: 0xa2,
    ControlRight: 0xa3,
    AltLeft: 0xa4,
    AltRight: 0xa5,
    MetaLeft: 0x5b, // VK_LWIN
    MetaRight: 0x5c, // VK_RWIN
    // US-layout punctuation (OEM VK codes).
    Minus: 0xbd,
    Equal: 0xbb,
    BracketLeft: 0xdb,
    BracketRight: 0xdd,
    Backslash: 0xdc,
    Semicolon: 0xba,
    Quote: 0xde,
    Backquote: 0xc0,
    Comma: 0xbc,
    Period: 0xbe,
    Slash: 0xbf,
    IntlBackslash: 0xe2, // the extra <> key on ISO keyboards (VK_OEM_102)
    // Numpad operators + separators. NumpadEnter shares VK_RETURN with the main Enter (the
    // extended-key flag, which we do not model, is what distinguishes them at the OS level).
    NumpadDivide: 0x6f,
    NumpadMultiply: 0x6a,
    NumpadSubtract: 0x6d,
    NumpadAdd: 0x6b,
    NumpadDecimal: 0x6e,
    NumpadEnter: 0x0d,
    NumpadEqual: 0x92, // VK_OEM_NEC_EQUAL
    NumpadComma: 0x6c, // VK_SEPARATOR
  };
  // Letters KeyA..KeyZ → VK 0x41..0x5A; digits Digit0..Digit9 → VK 0x30..0x39.
  for (let i = 0; i < 26; i++) m[`Key${String.fromCharCode(65 + i)}`] = 0x41 + i;
  for (let i = 0; i <= 9; i++) m[`Digit${i}`] = 0x30 + i;
  // Function keys F1..F24 → VK 0x70..0x87 (VK_F1..VK_F24 are contiguous).
  for (let i = 1; i <= 24; i++) m[`F${i}`] = 0x70 + (i - 1);
  // Numpad digits Numpad0..Numpad9 → VK_NUMPAD0..VK_NUMPAD9 (0x60..0x69).
  for (let i = 0; i <= 9; i++) m[`Numpad${i}`] = 0x60 + i;
  return m;
})();

/**
 * Resolve a DOM `code` string to its Windows virtual-key code, or `0` when the table does not cover
 * it. **This is the single source of VK truth in the viewer** — `domKeyToVk` (live keyboard),
 * `special_keys.ts` (the toolbar chords) and `osk.ts` (the on-screen keyboard) all go through it.
 *
 * Exported for that reason. `special_keys.ts` used to re-type seven of these values by hand, with a
 * comment admitting the mirror; a second hand-typed table is a place for the two to disagree, and a
 * disagreement here injects the WRONG KEY on a customer's machine with nothing in either language
 * able to notice. Adding a third table for the OSK would have made that near-certain.
 *
 * `0` is unambiguous as "unmapped": `VK_LBUTTON` is 0x01 and no legal virtual-key code is 0, so no
 * entry of {@link CODE_TO_VK} can collide with the sentinel. Callers must not inject it.
 */
export function vkForCode(code: string): number {
  return Object.prototype.hasOwnProperty.call(CODE_TO_VK, code) ? CODE_TO_VK[code] : 0;
}

/**
 * Resolve a DOM keyboard event to a Windows virtual-key code. Prefers the layout-independent
 * `e.code` map; falls back to the pragmatic (deprecated) `e.keyCode` for anything the (now full
 * US-layout) map does not cover — exotic international/media keys. Returns `0` when neither is
 * available.
 */
export function domKeyToVk(e: { code?: string; keyCode?: number }): number {
  const fromCode = e.code ? vkForCode(e.code) : 0;
  return fromCode !== 0 ? fromCode : (e.keyCode ?? 0);
}

/** `Key` press/release, resolving the DOM event to a Windows virtual-key code. */
export function keyEvent(e: { code?: string; keyCode?: number }, down: boolean): InputEvent {
  return key(domKeyToVk(e), down);
}

/**
 * The live-keyboard path's event for one DOM keydown/keyup, or `null` when there is nothing real to
 * send. Two cases are not keys: an IME placeholder (`keyCode 229` — what Chrome on Android reports
 * for nearly every soft-keyboard keystroke — or any event during a composition), which resolved to
 * VK 229 (VK_PROCESSKEY) and injected that junk on the guest; and an event that maps to no virtual
 * key at all (`0`, which `vkForCode` documents callers must not inject). Soft-keyboard text reaches
 * the guest through `phone_typing.ts` instead.
 */
export function liveKeyEvent(
  e: { code?: string; keyCode?: number; isComposing?: boolean },
  down: boolean,
): InputEvent | null {
  if (e.isComposing || e.keyCode === 229) return null;
  const vk = domKeyToVk(e);
  return vk === 0 ? null : key(vk, down);
}
