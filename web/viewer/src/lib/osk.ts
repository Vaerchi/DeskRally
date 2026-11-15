/**
 * On-screen keyboard model — the caps, the modifier latch, and the events a tap produces.
 *
 * Pure and React-free, like `special_keys.ts` next to it: the component that renders this is
 * presentation only, so every rule that could be wrong lives here where vitest can see it (the
 * runner's `include` glob covers `src/**` + `.ts` only — logic inside a `.tsx` render body is
 * invisible to it).
 *
 * WHY AN ON-SCREEN KEYBOARD AT ALL, given the viewer already captures the physical keyboard. Three
 * cases the capture path cannot serve: a technician on a tablet or a touch screen with no keyboard;
 * a key the LOCAL OS eats before the page sees it (the same reason `special_keys.ts` exists); and a
 * keyboard whose layout differs from the guest's, where the operator wants to press the PHYSICAL key
 * they can see rather than whatever their own layout produces. Every cap here is named by its DOM
 * `code` — the physical key — for exactly that last reason.
 *
 * SCOPE (v1): the main alphanumeric block plus modifiers. Deliberately no arrow cluster, no numpad,
 * no Insert/Delete/Home/End/PageUp/PageDown. `dom_input.ts` does not model the extended-key flag
 * (`KEYEVENTF_EXTENDEDKEY`), and those are precisely the keys where Windows distinguishes the
 * extended scan code from its non-extended twin — a numpad-vs-arrow ambiguity that would inject a
 * key that behaves differently from the physical one. Offering them would look like parity while
 * quietly being wrong; the physical keyboard still sends them correctly through `keyEvent`.
 */

import { vkForCode } from "./dom_input";
import { chord } from "./special_keys";
import type { InputEvent } from "./input";

/** One cap on the on-screen keyboard. */
export interface OskKey {
  /** DOM `code` naming the PHYSICAL key; resolved to a VK through `dom_input`'s one table. */
  code: string;
  /** The legend on the cap. */
  label: string;
  /**
   * The shifted legend, where the key has one (`1` → `!`). Rendered as a hint, never as a separate
   * key: the shifted glyph is produced by the GUEST's OS from the concurrent Shift, not by a
   * different virtual-key code — the same reason `dom_input` keys off `e.code` and not `e.key`.
   */
  shift?: string;
  /** Latching modifier cap (see {@link toggleLatch}). */
  modifier?: boolean;
  /** Cap width relative to a letter key. Presentation only. */
  width?: number;
}

/**
 * The latching modifiers, in the order they are PRESSED.
 *
 * Fixed order, not click order, so the bytes on the wire are a function of the SET of latched
 * modifiers and nothing else: latching Ctrl-then-Shift and Shift-then-Ctrl must produce the same
 * injection, or the same visible key combination would sometimes work and sometimes not. Ctrl, Alt,
 * Shift, Win is the order Windows itself writes its shortcuts in (Ctrl+Alt+Del, Ctrl+Shift+Esc).
 */
export const MODIFIER_ORDER: readonly string[] = [
  "ControlLeft",
  "AltLeft",
  "ShiftLeft",
  "MetaLeft",
];

const letter = (c: string): OskKey => ({ code: `Key${c}`, label: c });
const digit = (d: number, shift: string): OskKey => ({ code: `Digit${d}`, label: String(d), shift });
const mod = (code: string, label: string, width: number): OskKey => ({
  code,
  label,
  modifier: true,
  width,
});

/**
 * The caps, row by row, in US-layout order.
 *
 * CapsLock is deliberately NOT a `modifier`. It is a toggle on the GUEST — tapping it flips a lock
 * state that persists there — so a tap is exactly right and a local latch would be a second, lying
 * model of a state this console does not own.
 */
export const OSK_ROWS: readonly (readonly OskKey[])[] = [
  [
    { code: "Backquote", label: "`", shift: "~" },
    digit(1, "!"),
    digit(2, "@"),
    digit(3, "#"),
    digit(4, "$"),
    digit(5, "%"),
    digit(6, "^"),
    digit(7, "&"),
    digit(8, "*"),
    digit(9, "("),
    digit(0, ")"),
    { code: "Minus", label: "-", shift: "_" },
    { code: "Equal", label: "=", shift: "+" },
    { code: "Backspace", label: "⌫", width: 2 },
  ],
  [
    { code: "Tab", label: "Tab", width: 1.5 },
    ...["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"].map(letter),
    { code: "BracketLeft", label: "[", shift: "{" },
    { code: "BracketRight", label: "]", shift: "}" },
    { code: "Backslash", label: "\\", shift: "|", width: 1.5 },
  ],
  [
    { code: "CapsLock", label: "Caps", width: 1.75 },
    ...["A", "S", "D", "F", "G", "H", "J", "K", "L"].map(letter),
    { code: "Semicolon", label: ";", shift: ":" },
    { code: "Quote", label: "'", shift: '"' },
    { code: "Enter", label: "Enter", width: 2.25 },
  ],
  [
    mod("ShiftLeft", "Shift", 2.25),
    ...["Z", "X", "C", "V", "B", "N", "M"].map(letter),
    { code: "Comma", label: ",", shift: "<" },
    { code: "Period", label: ".", shift: ">" },
    { code: "Slash", label: "/", shift: "?", width: 2.25 },
  ],
  [
    mod("ControlLeft", "Ctrl", 1.5),
    mod("MetaLeft", "⊞ Win", 1.5),
    mod("AltLeft", "Alt", 1.5),
    { code: "Space", label: "Space", width: 7 },
  ],
];

/**
 * Toggle one modifier in the latch set, returning it in {@link MODIFIER_ORDER}.
 *
 * A pure reducer over a canonicalised set: the output order never depends on the input's, so the
 * same latched modifiers always build the same chord. A `code` that is not a modifier latches
 * nothing — only the modifier caps hold, and every other cap is a tap.
 */
export function toggleLatch(latched: readonly string[], code: string): string[] {
  const next = latched.includes(code)
    ? latched.filter((c) => c !== code)
    : [...latched, code];
  return MODIFIER_ORDER.filter((c) => next.includes(c));
}

/**
 * The ordered events one cap tap sends: press the latched modifiers, tap `code`, release the
 * modifiers in reverse — {@link chord}, reused rather than re-derived.
 *
 * ## The latch AUTO-RELEASES; it is not a held key
 *
 * Clicking Shift then `A` injects Shift↓ A↓ A↑ Shift↑ and leaves nothing pressed on the guest. The
 * alternative — holding Shift down on the guest until the operator clicks it again — is the one a
 * physical keyboard models, and it is the wrong choice here because **this console has no reliable
 * release path**. If the technician disconnects, unchecks "Capture input", closes the tab, or simply
 * loses their network in the half-second after latching Ctrl, the agent is left with a modifier
 * physically held down: no autorepeat timeout releases it, nothing in the agent tracks controller
 * liveness against injected key state, and the guest's user is left on a machine where every
 * keystroke is a Ctrl chord until someone taps that key locally. A tap that presses and releases
 * inside ONE message burst cannot strand a key that way, and the operator loses nothing — a
 * multi-key chord (Ctrl+Shift+Esc) is still expressible by latching both before the tap.
 *
 * A `code` outside {@link vkForCode}'s table returns NO events rather than injecting VK 0, which is
 * not a key.
 */
export function oskKeyEvents(latched: readonly string[], code: string): InputEvent[] {
  const vk = vkForCode(code);
  if (vk === 0) return [];
  // A latched modifier that is ALSO the key being tapped would otherwise be pressed twice and
  // released twice around itself; the tap wins (clicking a latched Shift is handled by toggleLatch
  // long before this, so this only guards a caller that routed one wrongly).
  const mods = MODIFIER_ORDER.filter((m) => m !== code && latched.includes(m)).map(vkForCode);
  return chord(mods, vk);
}
