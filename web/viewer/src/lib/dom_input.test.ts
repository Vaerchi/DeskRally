/**
 * DOM → InputEvent mapping tests (Milestone V1).
 *
 * These pin the browser-side DOM→`InputEvent` mapping to the EXACT canonical bytes the Rust agent's
 * `input_codec::decode` accepts (the same wire shape `input.test.ts` locks). The mapping module is
 * what `Viewer.tsx` uses, so asserting `encodeInput(mapFn(domEvent))` proves a real mouse move /
 * button / wheel / key from the console reaches the agent decoded correctly.
 */

import { describe, it, expect } from "vitest";
import {
  toAbs,
  moveEvent,
  domButtonToInputButton,
  buttonEvent,
  wheelToScroll,
  wheelPixels,
  domKeyToVk,
  keyEvent,
  vkForCode,
} from "./dom_input";
import { encodeInput } from "./input";

const wire = (ev: ReturnType<typeof moveEvent>) => new TextDecoder().decode(encodeInput(ev));

describe("toAbs", () => {
  it("normalizes a 0..1 fraction to 0..=65535 (clamped, rounded)", () => {
    expect(toAbs(0)).toBe(0);
    expect(toAbs(1)).toBe(65535);
    expect(toAbs(0.5)).toBe(32768);
    expect(toAbs(-1)).toBe(0);
    expect(toAbs(2)).toBe(65535);
  });
});

describe("MouseMove mapping", () => {
  it("produces the exact MouseMove wire bytes the agent decodes", () => {
    expect(wire(moveEvent(12345, 6789))).toBe('{"t":"MouseMove","c":{"x":12345,"y":6789}}');
  });
});

describe("MouseButton mapping (DOM button number → InputButton)", () => {
  it("maps DOM 0/1/2/3/4 to Left/Middle/Right/Back/Forward (NOT the old 1=right)", () => {
    expect(domButtonToInputButton(0)).toBe("Left");
    expect(domButtonToInputButton(1)).toBe("Middle");
    expect(domButtonToInputButton(2)).toBe("Right");
    expect(domButtonToInputButton(3)).toBe("Back");
    expect(domButtonToInputButton(4)).toBe("Forward");
    expect(domButtonToInputButton(9)).toBeNull();
  });

  it("encodes a left-button down/up to the canonical bytes", () => {
    expect(wire(buttonEvent(0, true)!)).toBe(
      '{"t":"MouseButton","c":{"button":"Left","down":true}}',
    );
    expect(wire(buttonEvent(0, false)!)).toBe(
      '{"t":"MouseButton","c":{"button":"Left","down":false}}',
    );
  });

  it("encodes right button (DOM 2) as Right", () => {
    expect(wire(buttonEvent(2, true)!)).toBe(
      '{"t":"MouseButton","c":{"button":"Right","down":true}}',
    );
  });

  it("returns null for an unmapped button so the caller can skip it", () => {
    expect(buttonEvent(7, true)).toBeNull();
  });
});

describe("Wheel mapping (DOM deltaY → Scroll dy, sign flipped + notch-scaled)", () => {
  it("pixel-mode scroll DOWN (deltaY>0) becomes agent dy<0 (agent scrolls down)", () => {
    // One notch down on Windows pixel mode is ~+100 deltaY → dy = -1.
    expect(wire(wheelToScroll({ deltaX: 0, deltaY: 100, deltaMode: 0 }))).toBe(
      '{"t":"Scroll","c":{"dx":0,"dy":-1}}',
    );
  });

  it("pixel-mode scroll UP (deltaY<0) becomes agent dy>0 (agent scrolls up)", () => {
    expect(wire(wheelToScroll({ deltaX: 0, deltaY: -100, deltaMode: 0 }))).toBe(
      '{"t":"Scroll","c":{"dx":0,"dy":1}}',
    );
  });

  it("a small sub-notch pixel delta still yields one notch (never dropped)", () => {
    expect(wire(wheelToScroll({ deltaX: 0, deltaY: 30, deltaMode: 0 }))).toBe(
      '{"t":"Scroll","c":{"dx":0,"dy":-1}}',
    );
  });

  it("line-mode (deltaMode 1) deltas are already in notches (divide by 1)", () => {
    expect(wire(wheelToScroll({ deltaX: 0, deltaY: 3, deltaMode: 1 }))).toBe(
      '{"t":"Scroll","c":{"dx":0,"dy":-3}}',
    );
  });

  it("horizontal deltaX keeps its sign (right stays right)", () => {
    expect(wire(wheelToScroll({ deltaX: 100, deltaY: 0, deltaMode: 0 }))).toBe(
      '{"t":"Scroll","c":{"dx":1,"dy":0}}',
    );
  });
});

describe("wheelPixels (deltaMode → pixel-equivalent, for zoom/pan)", () => {
  it("passes pixel mode through and scales line/page modes up so they are not near-inert", () => {
    expect(wheelPixels(120, 0)).toBe(120); // already pixels
    expect(wheelPixels(5)).toBe(5); // undefined mode = pixels
    // Firefox line mode: a ~3-line notch must become a meaningful pixel magnitude, not ~3.
    expect(wheelPixels(3, 1)).toBe(48);
    expect(wheelPixels(-3, 1)).toBe(-48); // sign preserved
    expect(wheelPixels(1, 2)).toBe(800); // page mode
  });
});

describe("Key mapping (DOM → Windows virtual-key code)", () => {
  it("maps e.code letters to VK codes (KeyA → 65)", () => {
    expect(domKeyToVk({ code: "KeyA", keyCode: 65 })).toBe(65);
    expect(domKeyToVk({ code: "KeyZ" })).toBe(90);
    expect(domKeyToVk({ code: "Digit0" })).toBe(48);
    expect(domKeyToVk({ code: "Enter" })).toBe(13);
    expect(domKeyToVk({ code: "Escape" })).toBe(27);
    expect(domKeyToVk({ code: "F1" })).toBe(0x70);
  });

  it("maps the full US-layout spread (V3): letters, digits, nav, F-keys, modifiers, punctuation", () => {
    // Letters + digits (physical keys — Shift does not change the VK).
    expect(domKeyToVk({ code: "KeyA" })).toBe(0x41);
    expect(domKeyToVk({ code: "KeyM" })).toBe(0x4d);
    expect(domKeyToVk({ code: "Digit1" })).toBe(0x31); // "!" when shifted → same VK
    expect(domKeyToVk({ code: "Digit9" })).toBe(0x39);
    // Navigation / editing.
    expect(domKeyToVk({ code: "ArrowLeft" })).toBe(0x25);
    expect(domKeyToVk({ code: "Home" })).toBe(0x24);
    expect(domKeyToVk({ code: "PageDown" })).toBe(0x22);
    expect(domKeyToVk({ code: "Insert" })).toBe(0x2d);
    // Whitespace.
    expect(domKeyToVk({ code: "Space" })).toBe(0x20);
    expect(domKeyToVk({ code: "Tab" })).toBe(0x09);
    expect(domKeyToVk({ code: "Backspace" })).toBe(0x08);
    // Function keys, incl. the newly-added F13..F24.
    expect(domKeyToVk({ code: "F1" })).toBe(0x70);
    expect(domKeyToVk({ code: "F12" })).toBe(0x7b);
    expect(domKeyToVk({ code: "F24" })).toBe(0x87);
    // Modifiers, both hands.
    expect(domKeyToVk({ code: "ShiftLeft" })).toBe(0xa0);
    expect(domKeyToVk({ code: "ShiftRight" })).toBe(0xa1);
    expect(domKeyToVk({ code: "ControlRight" })).toBe(0xa3);
    expect(domKeyToVk({ code: "AltLeft" })).toBe(0xa4);
    expect(domKeyToVk({ code: "MetaRight" })).toBe(0x5c);
    // Punctuation (US OEM).
    expect(domKeyToVk({ code: "Semicolon" })).toBe(0xba);
    expect(domKeyToVk({ code: "Slash" })).toBe(0xbf);
    expect(domKeyToVk({ code: "Backquote" })).toBe(0xc0);
    // System / lock keys.
    expect(domKeyToVk({ code: "ContextMenu" })).toBe(0x5d);
    expect(domKeyToVk({ code: "NumLock" })).toBe(0x90);
    // Numpad digits + operators.
    expect(domKeyToVk({ code: "Numpad0" })).toBe(0x60);
    expect(domKeyToVk({ code: "Numpad9" })).toBe(0x69);
    expect(domKeyToVk({ code: "NumpadAdd" })).toBe(0x6b);
    expect(domKeyToVk({ code: "NumpadDivide" })).toBe(0x6f);
    expect(domKeyToVk({ code: "NumpadEnter" })).toBe(0x0d); // shares VK_RETURN
  });

  it("falls back to keyCode when e.code is not in the map (exotic intl/media keys)", () => {
    expect(domKeyToVk({ code: "MediaPlayPause", keyCode: 179 })).toBe(179);
    expect(domKeyToVk({ keyCode: 42 })).toBe(42);
    expect(domKeyToVk({})).toBe(0);
  });

  it("vkForCode is the ONE table every caller resolves through", () => {
    // Exported so `special_keys.ts` (toolbar chords) and `osk.ts` (on-screen keyboard) stop
    // hand-typing their own copies. `domKeyToVk` must agree with it on every code it covers, or the
    // live keyboard and the clicked keys would inject different keys for the same physical cap.
    for (const code of ["KeyA", "Digit1", "Enter", "ShiftLeft", "MetaLeft", "F4", "Slash"]) {
      expect(vkForCode(code)).toBe(domKeyToVk({ code }));
      expect(vkForCode(code)).not.toBe(0);
    }
    // 0 is the unmapped sentinel and cannot collide with a real key (no legal VK is 0 — VK_LBUTTON
    // is 0x01), which is what lets `oskKeyEvents` treat it as "send nothing".
    expect(vkForCode("NoSuchCode")).toBe(0);
    expect(vkForCode("MediaPlayPause")).toBe(0);
    // …and the keyCode fallback still applies on top of it for the LIVE keyboard only.
    expect(domKeyToVk({ code: "MediaPlayPause", keyCode: 179 })).toBe(179);
  });

  it("encodes a key down/up ('A' = VK 65) to the canonical bytes the agent decodes", () => {
    expect(wire(keyEvent({ code: "KeyA", keyCode: 65 }, true))).toBe(
      '{"t":"Key","c":{"code":65,"down":true}}',
    );
    expect(wire(keyEvent({ code: "KeyA", keyCode: 65 }, false))).toBe(
      '{"t":"Key","c":{"code":65,"down":false}}',
    );
  });
});
