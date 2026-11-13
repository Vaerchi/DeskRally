/**
 * On-screen keyboard tests: the caps, the latch reducer, and the exact events a tap injects.
 *
 * No DOM and no React — `OnScreenKeyboard.tsx` is presentation only, so everything that could be
 * wrong is here. The `.tsx` file could not be tested anyway: vitest's `include` glob is `.ts`.
 */

import { describe, it, expect } from "vitest";
import { MODIFIER_ORDER, OSK_ROWS, oskKeyEvents, toggleLatch, type OskKey } from "./osk";
import { keyEvent, vkForCode } from "./dom_input";
import { key, type InputEvent } from "./input";

const CAPS: OskKey[] = OSK_ROWS.flatMap((r) => [...r]);
const codes = (): string[] => CAPS.map((k) => k.code);

/** Every subset of the latching modifiers, so a property can be asserted over all of them. */
const LATCH_SETS: string[][] = (() => {
  const out: string[][] = [];
  for (let mask = 0; mask < 1 << MODIFIER_ORDER.length; mask++) {
    out.push(MODIFIER_ORDER.filter((_, i) => mask & (1 << i)));
  }
  return out;
})();

describe("OSK layout", () => {
  it("resolves every cap through the one VK table — no dead keys", () => {
    // A typo'd `code` ("Semicolo") would render a perfectly normal-looking cap that injects nothing.
    // `vkForCode` returning 0 is the only signal, and it is silent at runtime by design.
    for (const k of CAPS) {
      expect(vkForCode(k.code), `${k.code} (${k.label}) resolves to no virtual key`).not.toBe(0);
    }
    expect(CAPS.length).toBeGreaterThan(50); // a full alphanumeric block, not a stub
  });

  it("has unique codes — they key the React list AND the latch set", () => {
    const codes = CAPS.map((k) => k.code);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it("covers the whole alphanumeric block", () => {
    for (let i = 0; i < 26; i++) {
      const code = `Key${String.fromCharCode(65 + i)}`;
      expect(codes(), `missing ${code}`).toContain(code);
    }
    for (let d = 0; d <= 9; d++) expect(codes()).toContain(`Digit${d}`);
    for (const c of ["Space", "Enter", "Backspace", "Tab", "CapsLock"]) {
      expect(codes()).toContain(c);
    }
  });

  it("offers NO extended-key caps, because dom_input does not model the extended flag", () => {
    // Arrows, the numpad and the Insert/Delete/Home/End/PageUp/PageDown cluster are exactly the keys
    // where Windows distinguishes the extended scan code from its non-extended twin. Injecting them
    // without KEYEVENTF_EXTENDEDKEY would send a key that can behave differently from the physical
    // one — parity-shaped, quietly wrong. v1 leaves them to the captured physical keyboard.
    for (const c of codes()) {
      expect(c, `${c} is an extended key`).not.toMatch(/^(Arrow|Numpad)/);
      expect(["Insert", "Delete", "Home", "End", "PageUp", "PageDown"]).not.toContain(c);
    }
  });

  it("latches only the four modifiers; CapsLock is a TAP", () => {
    const latching = CAPS.filter((k) => k.modifier).map((k) => k.code);
    expect(latching.sort()).toEqual([...MODIFIER_ORDER].sort());
    // CapsLock toggles a lock state on the GUEST. Latching it locally would be a second model of a
    // state this console does not own — and the tap already does the right thing.
    expect(CAPS.find((k) => k.code === "CapsLock")?.modifier).toBeUndefined();
  });
});

describe("toggleLatch", () => {
  it("toggles a modifier on and back off", () => {
    expect(toggleLatch([], "ShiftLeft")).toEqual(["ShiftLeft"]);
    expect(toggleLatch(["ShiftLeft"], "ShiftLeft")).toEqual([]);
  });

  it("canonicalises order, so click order cannot change the bytes on the wire", () => {
    // The property the fixed MODIFIER_ORDER exists for: the same visible combination must always
    // inject the same sequence, or a chord would work or not depending on which cap was clicked
    // first — an intermittent fault with no visible cause.
    const ctrlThenShift = toggleLatch(toggleLatch([], "ControlLeft"), "ShiftLeft");
    const shiftThenCtrl = toggleLatch(toggleLatch([], "ShiftLeft"), "ControlLeft");
    expect(ctrlThenShift).toEqual(shiftThenCtrl);
    expect(ctrlThenShift).toEqual(["ControlLeft", "ShiftLeft"]);
    expect(oskKeyEvents(ctrlThenShift, "KeyA")).toEqual(oskKeyEvents(shiftThenCtrl, "KeyA"));
  });

  it("latches nothing for a non-modifier cap", () => {
    expect(toggleLatch([], "KeyA")).toEqual([]);
    expect(toggleLatch(["AltLeft"], "KeyA")).toEqual(["AltLeft"]);
  });

  it("does not mutate the set it is handed", () => {
    const before = ["ControlLeft"];
    toggleLatch(before, "ShiftLeft");
    expect(before).toEqual(["ControlLeft"]);
  });
});

describe("oskKeyEvents", () => {
  it("taps an unmodified cap as down→up", () => {
    expect(oskKeyEvents([], "KeyA")).toEqual([key(0x41, true), key(0x41, false)]);
  });

  it("uses the SAME virtual keys as the captured physical keyboard", () => {
    // The one-table proof: a divergence between the OSK and `keyEvent` would mean clicking the
    // on-screen "A" and pressing the physical A injected different keys on the guest.
    for (const k of CAPS) {
      expect(oskKeyEvents([], k.code)).toEqual([
        keyEvent({ code: k.code }, true),
        keyEvent({ code: k.code }, false),
      ]);
    }
  });

  it("nests a latched modifier around the tap (Shift+A)", () => {
    expect(oskKeyEvents(["ShiftLeft"], "KeyA")).toEqual([
      key(0xa0, true),
      key(0x41, true),
      key(0x41, false),
      key(0xa0, false),
    ]);
  });

  it("presses every latched modifier in MODIFIER_ORDER and releases in reverse", () => {
    expect(oskKeyEvents([...MODIFIER_ORDER], "KeyS")).toEqual([
      key(0xa2, true), // Ctrl
      key(0xa4, true), // Alt
      key(0xa0, true), // Shift
      key(0x5b, true), // Win
      key(0x53, true), // S
      key(0x53, false),
      key(0x5b, false),
      key(0xa0, false),
      key(0xa4, false),
      key(0xa2, false),
    ]);
  });

  it("sends nothing for a code the VK table does not cover", () => {
    // VK 0 is not a key; injecting it would be a nonsense SendInput on the guest.
    expect(oskKeyEvents([], "MediaPlayPause")).toEqual([]);
    expect(oskKeyEvents(["ControlLeft"], "NoSuchCode")).toEqual([]);
  });

  /**
   * The safety property behind the auto-release decision (see `oskKeyEvents`'s doc): a tap can never
   * leave a key held on the guest. A held latch would — and this console has no path to release it
   * if the technician disconnects, unchecks capture, or closes the tab.
   */
  it("leaves NOTHING pressed on the guest, for every cap and every latch combination", () => {
    for (const latched of LATCH_SETS) {
      for (const k of CAPS) {
        const events = oskKeyEvents(latched, k.code);
        const held: number[] = [];
        for (const ev of events) {
          expect(ev.t).toBe("Key");
          if (ev.t !== "Key") continue;
          if (ev.c.down) {
            held.push(ev.c.code);
          } else {
            // Perfect nesting: a release must close the most recent press, exactly as a physical
            // chord does. A release in FORWARD order would still balance, so pop-and-compare is
            // what actually pins it.
            expect(held.pop(), `${k.code} with [${latched}] released out of order`).toBe(ev.c.code);
          }
        }
        expect(held, `${k.code} with [${latched}] left keys held down`).toEqual([]);
      }
    }
  });

  it("can NEVER emit the SAS unit event — Ctrl+Alt+Del stays the dedicated toolbar button", () => {
    // Two separate claims. First: nothing on this keyboard, under any latch, produces `{"t":"Sas"}`.
    for (const latched of LATCH_SETS) {
      for (const k of CAPS) {
        for (const ev of oskKeyEvents(latched, k.code)) expect(ev.t).toBe("Key");
      }
    }
    // Second: the composition an operator would reach for is not even offered, and would not work if
    // it were. Windows drops a SYNTHETIC Ctrl+Alt+Delete — only `SendSAS` from the session-0 service
    // raises the secure desktop (docs/07) — so an OSK that quietly mapped this triple to `sas()`
    // would claim the toolbar's capability while an honest raw injection is silently swallowed.
    // `Delete` IS in the shared VK table (the physical keyboard needs it), so the triple is
    // constructible here even though no cap offers it — and it comes out as six plain Key events.
    const triple: InputEvent[] = oskKeyEvents(["ControlLeft", "AltLeft"], "Delete");
    expect(triple.some((e) => e.t === "Sas")).toBe(false);
    expect(triple.every((e) => e.t === "Key")).toBe(true);
    expect(triple).toHaveLength(6);
    // …and no cap offers it, so the operator is never shown a Ctrl+Alt+Del that silently does
    // nothing next to a toolbar button that works.
    expect(CAPS.some((k) => k.code === "Delete")).toBe(false);
  });
});
