import { describe, expect, it } from "vitest";
import {
  CLICK_WINDOW_MS,
  NO_PRESS,
  clickArrived,
  pressAbandoned,
  pressBegan,
  pressEnded,
} from "./press_activation";

const POINTER_CLICK = { detail: 1, pointerId: 7 };
const AT_CLICK = { detail: 0 };

describe("press activation (attribute a click by provenance)", () => {
  it("an independent click with nothing pending activates (Tab arrives, then a screen reader clicks)", () => {
    expect(clickArrived(NO_PRESS, 1000, AT_CLICK).activate).toBe(true);
    expect(clickArrived(NO_PRESS, 1000, POINTER_CLICK).activate).toBe(true);
  });

  it("pointer press and release: its detail>0 click is suppressed once, then the next activates", () => {
    const s = pressEnded(pressBegan(7), 100);
    const c = clickArrived(s, 110, POINTER_CLICK);
    expect(c.activate).toBe(false);
    expect(clickArrived(c.state, 120, POINTER_CLICK).activate).toBe(true);
  });

  it("a detail===0 click right after a pointer press activates, even with the press pending", () => {
    const s = pressEnded(pressBegan(7), 100);
    const at = clickArrived(s, 105, AT_CLICK);
    expect(at.activate).toBe(true);
    // ...and it does not eat the press's own click, which still arrives and is suppressed.
    expect(clickArrived(at.state, 110, POINTER_CLICK).activate).toBe(false);
  });

  it("a keyboard press never sets pending: an AT click within the window activates", () => {
    // The keyboard path does not call pressBegan at all, so the state stays NO_PRESS.
    expect(clickArrived(NO_PRESS, 300, AT_CLICK).activate).toBe(true);
  });

  it("pointer cancel clears the press, so an AT click (or any later click) activates", () => {
    const s = pressAbandoned();
    expect(clickArrived(s, 50, AT_CLICK).activate).toBe(true);
    expect(clickArrived(pressAbandoned(), 50, POINTER_CLICK).activate).toBe(true);
  });

  it("a click from a different pointer is not this press's click", () => {
    const s = pressEnded(pressBegan(7), 100);
    expect(clickArrived(s, 105, { detail: 1, pointerId: 9 }).activate).toBe(true);
  });

  it("unknown pointer ids still match on provenance (detail > 0 inside the window)", () => {
    const s = pressEnded(pressBegan(), 100);
    expect(clickArrived(s, 110, { detail: 1 }).activate).toBe(false);
  });

  it("a click while the press is still down is its own", () => {
    expect(clickArrived(pressBegan(7), 10, POINTER_CLICK).activate).toBe(false);
  });

  it("a press whose click never came expires", () => {
    const s = pressEnded(pressBegan(7), 100);
    expect(clickArrived(s, 100 + CLICK_WINDOW_MS + 1, POINTER_CLICK).activate).toBe(true);
  });

  it("ending something that never began does not invent a pending press", () => {
    expect(pressEnded(NO_PRESS, 5)).toBe(NO_PRESS);
  });
});
