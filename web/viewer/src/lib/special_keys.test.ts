/**
 * Pure-logic tests for the toolbar's special-key sequences. No DOM, no transport — just the event
 * lists each button produces, plus the exact wire bytes for the marquee Ctrl+Alt+Del case.
 */

import { describe, it, expect } from "vitest";
import { chord, SPECIAL_KEYS, VK } from "./special_keys";
import { encodeInput, key, sas, type InputEvent } from "./input";

describe("VK", () => {
  it("still resolves to the exact codes the hand-typed table held", () => {
    // `VK` now reads through `dom_input`'s single `CODE_TO_VK` instead of re-typing seven literals.
    // That removes the mirror, but it also removes the independent statement of what the values ARE,
    // so the literals are pinned here: a wrong `code` string in `special_keys.ts` would otherwise
    // resolve to some OTHER real key and inject it on a customer's machine, and every symbolic
    // assertion below (`VK.LWIN`, `VK.D`, …) would happily follow it.
    expect(VK.LWIN).toBe(0x5b); // VK_LWIN — the e2e pins the same 91 in the agent's INJECTED line
    expect(VK.LALT).toBe(0xa4);
    expect(VK.TAB).toBe(0x09);
    expect(VK.ESC).toBe(0x1b);
    expect(VK.D).toBe(0x44); // 68
    expect(VK.E).toBe(0x45);
    expect(VK.F4).toBe(0x73);
  });
});

describe("chord()", () => {
  it("taps a lone key as down→up when there are no modifiers", () => {
    // The Windows key alone: press and release, nothing else.
    expect(chord([], VK.LWIN)).toEqual([key(VK.LWIN, true), key(VK.LWIN, false)]);
  });

  it("nests modifiers: press in order, tap main, release modifiers in REVERSE order", () => {
    // Two synthetic modifiers 0xAA then 0xBB around main 0xCC. Reverse-order release is what a real
    // physical chord does and what the OS expects; a mutant that released in forward order would be
    // caught here.
    expect(chord([0xaa, 0xbb], 0xcc)).toEqual([
      key(0xaa, true),
      key(0xbb, true),
      key(0xcc, true),
      key(0xcc, false),
      key(0xbb, false),
      key(0xaa, false),
    ]);
  });

  it("wraps a single modifier around the main key (Win+D)", () => {
    expect(chord([VK.LWIN], VK.D)).toEqual([
      key(VK.LWIN, true),
      key(VK.D, true),
      key(VK.D, false),
      key(VK.LWIN, false),
    ]);
  });
});

describe("SPECIAL_KEYS", () => {
  const byId = (id: string) => {
    const sk = SPECIAL_KEYS.find((k) => k.id === id);
    if (!sk) throw new Error(`no special key ${id}`);
    return sk;
  };

  it("maps Ctrl+Alt+Del to the single SAS unit event — NOT raw Ctrl/Alt/Del key events", () => {
    // The whole point: Windows drops a synthetic Ctrl+Alt+Del, so this must be the dedicated Sas
    // event, not `chord([LCTRL, LALT], DEL)`. Assert both the structure and the exact wire bytes.
    const events = byId("cad").build();
    expect(events).toEqual([sas()]);
    expect(events).toEqual([{ t: "Sas" }]);
    expect(new TextDecoder().decode(encodeInput(events[0]))).toBe('{"t":"Sas"}');
  });

  it("leads with Ctrl+Alt+Del and includes the Windows key", () => {
    expect(SPECIAL_KEYS[0].id).toBe("cad");
    expect(SPECIAL_KEYS.some((k) => k.id === "win")).toBe(true);
  });

  it("every non-SAS entry is a plain key chord (only Key events, never Sas)", () => {
    for (const sk of SPECIAL_KEYS) {
      if (sk.id === "cad") continue;
      const events: InputEvent[] = sk.build();
      expect(events.length).toBeGreaterThan(0);
      for (const ev of events) expect(ev.t).toBe("Key");
      // A chord is balanced: equal downs and ups.
      const downs = events.filter((e) => e.t === "Key" && e.c.down).length;
      const ups = events.filter((e) => e.t === "Key" && !e.c.down).length;
      expect(downs).toBe(ups);
    }
  });

  it("pins the EXACT event sequence of every entry (not just aggregate shape)", () => {
    // The aggregate check above passes even if a modifier and its main key are swapped (both stay
    // balanced Key events), so it would miss a wrong VK or a `chord([TAB],ALT)` transposition. These
    // deep-equal assertions pin the actual codes + ordering the agent will inject for each button.
    expect(byId("cad").build()).toEqual([sas()]);
    expect(byId("win").build()).toEqual([key(VK.LWIN, true), key(VK.LWIN, false)]);
    expect(byId("win-d").build()).toEqual([
      key(VK.LWIN, true), key(VK.D, true), key(VK.D, false), key(VK.LWIN, false),
    ]);
    expect(byId("win-e").build()).toEqual([
      key(VK.LWIN, true), key(VK.E, true), key(VK.E, false), key(VK.LWIN, false),
    ]);
    expect(byId("alt-tab").build()).toEqual([
      key(VK.LALT, true), key(VK.TAB, true), key(VK.TAB, false), key(VK.LALT, false),
    ]);
    expect(byId("alt-f4").build()).toEqual([
      key(VK.LALT, true), key(VK.F4, true), key(VK.F4, false), key(VK.LALT, false),
    ]);
    expect(byId("esc").build()).toEqual([key(VK.ESC, true), key(VK.ESC, false)]);
  });

  it("gives every entry a stable id, a label, and a tooltip", () => {
    const ids = new Set<string>();
    for (const sk of SPECIAL_KEYS) {
      expect(sk.id).toBeTruthy();
      expect(sk.label).toBeTruthy();
      expect(sk.title).toBeTruthy();
      expect(ids.has(sk.id)).toBe(false); // ids are unique (they key React list items)
      ids.add(sk.id);
    }
  });
});
