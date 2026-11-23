/**
 * Special-key sends for the viewer toolbar.
 *
 * Some keys and combinations never reach the page from the controller's browser — the local OS
 * eats them first. Ctrl+Alt+Del is intercepted by Windows before any application sees it; the
 * Windows key opens the *local* Start menu; Alt+Tab switches the *local* window. So the remote-
 * control product needs explicit buttons that synthesize these onto the agent, bypassing the local
 * keyboard entirely.
 *
 * Every entry produces an ordered list of canonical {@link InputEvent}s to hand to the transport in
 * sequence. Ctrl+Alt+Del is the one that cannot be expressed as ordinary key events (Windows drops
 * a synthetic Ctrl+Alt+Del) — it maps to the dedicated {@link sas} unit event, which the agent
 * routes to `SendSAS`. The rest are plain key chords the agent injects via `SendInput`.
 *
 * Pure and dependency-free so the sequences are unit-tested without a DOM or a live transport.
 */

import { key, sas, type InputEvent } from "./input";
import { vkForCode } from "./dom_input";

/**
 * Windows virtual-key codes for the keys used in the toolbar chords, RESOLVED THROUGH the one VK
 * table in {@link ./dom_input} rather than re-typed here. The agent injects `VIRTUAL_KEY(code)` for
 * a `Key` event.
 *
 * These seven were hand-typed literals whose own comment admitted they mirrored `CODE_TO_VK`. A
 * mirror is a place for two tables to disagree, and the failure mode is silent: the toolbar would
 * inject a plausible wrong key on a customer's machine and nothing on either side of the wire could
 * tell. Naming the physical keys (`MetaLeft`, `AltLeft`, …) also makes the mapping self-describing —
 * `0x5b` says nothing about which Windows key it is.
 */
export const VK = {
  LWIN: vkForCode("MetaLeft"),
  LALT: vkForCode("AltLeft"),
  TAB: vkForCode("Tab"),
  ESC: vkForCode("Escape"),
  D: vkForCode("KeyD"),
  E: vkForCode("KeyE"),
  F4: vkForCode("F4"),
} as const;

/**
 * A key chord: press each modifier in `mods` (in order), tap `main` (down then up), then release
 * the modifiers in reverse order — the standard press/release nesting a physical chord produces.
 * With no modifiers and just a `main`, this is a plain key tap (e.g. the Windows key alone).
 */
export function chord(mods: number[], main: number): InputEvent[] {
  const events: InputEvent[] = [];
  for (const m of mods) events.push(key(m, true));
  events.push(key(main, true));
  events.push(key(main, false));
  for (let i = mods.length - 1; i >= 0; i--) events.push(key(mods[i], false));
  return events;
}

/** One toolbar button: a stable id, its visible label, a tooltip, and the events it sends. */
export interface SpecialKey {
  id: string;
  label: string;
  title: string;
  /** Build the ordered event sequence to send when the button is pressed. */
  build: () => InputEvent[];
}

/**
 * The toolbar's special keys, in display order. Ctrl+Alt+Del leads because it is the marquee one
 * (and the P0 checklist item); the Windows key and the app-switch/close chords follow.
 */
export const SPECIAL_KEYS: SpecialKey[] = [
  {
    id: "cad",
    label: "Ctrl+Alt+Del",
    title: "Send the Secure Attention Sequence to the remote machine (SendSAS on the agent)",
    build: () => [sas()],
  },
  {
    id: "win",
    label: "⊞ Win",
    title: "Tap the Windows key on the remote machine (opens its Start menu)",
    build: () => chord([], VK.LWIN),
  },
  {
    id: "win-d",
    label: "⊞+D",
    title: "Show the remote desktop (Windows key + D)",
    build: () => chord([VK.LWIN], VK.D),
  },
  {
    id: "win-e",
    label: "⊞+E",
    title: "Open File Explorer on the remote machine (Windows key + E)",
    build: () => chord([VK.LWIN], VK.E),
  },
  {
    id: "alt-tab",
    label: "Alt+Tab",
    title: "Switch windows on the remote machine (Alt + Tab)",
    build: () => chord([VK.LALT], VK.TAB),
  },
  {
    id: "alt-f4",
    label: "Alt+F4",
    title: "Close the focused remote window (Alt + F4)",
    build: () => chord([VK.LALT], VK.F4),
  },
  {
    id: "esc",
    label: "Esc",
    title: "Send Escape to the remote machine",
    build: () => chord([], VK.ESC),
  },
];
