/**
 * Tests for the touch gesture recogniser — what a finger means to the guest's desktop.
 *
 * All pure, no DOM, and time is arithmetic rather than a timer: a gesture test that sleeps is a
 * flaky gesture test, and these have to be trustworthy because the failure mode is *input landing
 * on a customer's machine that the operator did not give*.
 *
 * Two properties get the most attention, because they are the ones with consequences:
 *   1. A plain one-finger drag must NEVER reach the guest — it pans the view.
 *   2. A button that goes DOWN must always come back up, and one that never went down must never
 *      produce a spurious up.
 */

import { describe, it, expect } from "vitest";
import {
  INITIAL_GESTURE_STATE,
  reduceGesture,
  LONG_PRESS_MS,
  DOUBLE_TAP_MS,
  TAP_SLOP_PX,
  DOUBLE_TAP_SLOP_PX,
  PINCH_DEADZONE,
  SCROLL_LATCH_PX,
  type GestureAction,
  type GestureEvent,
  type GestureState,
} from "./touch_gestures";

/** Feed a sequence and collect everything it emitted, so a test reads as the gesture it describes. */
function run(events: GestureEvent[], from: GestureState = INITIAL_GESTURE_STATE) {
  let state = from;
  const actions: GestureAction[] = [];
  let lastDeadline: number | undefined;
  for (const e of events) {
    const r = reduceGesture(state, e);
    state = r.state;
    actions.push(...r.actions);
    lastDeadline = r.longPressDeadline;
  }
  return { state, actions, lastDeadline };
}

const p = (id: number, x: number, y: number) => ({ id, x, y });
const kinds = (a: GestureAction[]) => a.map((x) => x.kind);

describe("tap", () => {
  it("a tap is a left click where the finger landed", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 200)], t: 0 },
      { type: "end", points: [], t: 80 },
    ]);
    expect(actions).toEqual([{ kind: "click", x: 100, y: 200, button: "left" }]);
  });

  it("a tap that trembles within the slop is still a tap", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 200)], t: 0 },
      { type: "move", points: [p(1, 100 + (TAP_SLOP_PX - 1), 200)], t: 40 },
      { type: "end", points: [], t: 80 },
    ]);
    // The click is reported at the PRESS point, not where the finger drifted to.
    expect(actions).toEqual([{ kind: "click", x: 100, y: 200, button: "left" }]);
  });

  it("asks the caller to schedule the long-press deadline when a finger goes down", () => {
    const { lastDeadline } = run([{ type: "start", points: [p(1, 5, 5)], t: 1000 }]);
    expect(lastDeadline).toBe(1000 + LONG_PRESS_MS);
  });
});

describe("double tap", () => {
  it("two quick taps in the same place are a double click", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 50, 50)], t: 0 },
      { type: "end", points: [], t: 50 },
      { type: "start", points: [p(1, 52, 51)], t: 120 },
      { type: "end", points: [], t: 160 },
    ]);
    expect(actions).toEqual([
      { kind: "click", x: 50, y: 50, button: "left" },
      { kind: "doubleClick", x: 52, y: 51 },
    ]);
  });

  // NEGATIVE CONTROL on time. Without it, "double click" could just mean "two taps ever".
  it("two taps too far apart in TIME are two separate clicks", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 50, 50)], t: 0 },
      { type: "end", points: [], t: 50 },
      { type: "start", points: [p(1, 50, 50)], t: DOUBLE_TAP_MS + 60 },
      { type: "end", points: [], t: DOUBLE_TAP_MS + 100 },
    ]);
    expect(kinds(actions)).toEqual(["click", "click"]);
  });

  // NEGATIVE CONTROL on space.
  it("two quick taps too far apart in SPACE are two separate clicks", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 50, 50)], t: 0 },
      { type: "end", points: [], t: 50 },
      { type: "start", points: [p(1, 50 + DOUBLE_TAP_SLOP_PX + 5, 50)], t: 120 },
      { type: "end", points: [], t: 160 },
    ]);
    expect(kinds(actions)).toEqual(["click", "click"]);
  });

  it("a triple tap is a click, a double click, then a fresh click — not two double clicks", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 50, 50)], t: 0 },
      { type: "end", points: [], t: 40 },
      { type: "start", points: [p(1, 50, 50)], t: 100 },
      { type: "end", points: [], t: 140 },
      { type: "start", points: [p(1, 50, 50)], t: 200 },
      { type: "end", points: [], t: 240 },
    ]);
    expect(kinds(actions)).toEqual(["click", "doubleClick", "click"]);
  });
});

describe("long press", () => {
  it("a hold with no movement is a RIGHT click", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 70, 80)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "end", points: [], t: LONG_PRESS_MS + 50 },
    ]);
    expect(actions).toEqual([{ kind: "click", x: 70, y: 80, button: "right" }]);
  });

  it("a tick BEFORE the hold completes does nothing", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 70, 80)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS - 1 },
    ]);
    expect(actions).toEqual([]);
  });

  it("a hold then a lift produces the right click and NO button-up, because none went down", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 70, 80)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "end", points: [], t: 900 },
    ]);
    // Fabricating a dragEnd here would be inventing input the operator never gave.
    expect(kinds(actions)).toEqual(["click"]);
  });
});

describe("drag (long press, then move)", () => {
  it("opens at the PRESS point and then keeps moving", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 10, 10)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "move", points: [p(1, 40, 10)], t: 560 },
      { type: "move", points: [p(1, 80, 10)], t: 600 },
      { type: "move", points: [p(1, 120, 10)], t: 640 },
      { type: "end", points: [], t: 700 },
    ]);
    expect(actions).toEqual([
      { kind: "click", x: 10, y: 10, button: "right" },
      { kind: "dragStart", x: 10, y: 10 },
      { kind: "dragMove", x: 40, y: 10 },
      { kind: "dragMove", x: 80, y: 10 },
      { kind: "dragMove", x: 120, y: 10 },
      { kind: "dragEnd" },
    ]);
  });

  /**
   * THE REGRESSION FOR A BUG THIS FILE ALREADY HAD. The first version reused the long-press flag as
   * the "drag is open" marker, so the first move cleared it and every later move took the
   * not-yet-open branch and emitted NOTHING. The drag moved once and then froze while the finger
   * kept going — and the single-move test above passes perfectly against that bug, which is exactly
   * why this one counts the moves.
   */
  it("emits a dragMove for EVERY move, not just the first", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      ...[1, 2, 3, 4, 5].map(
        (i): GestureEvent => ({ type: "move", points: [p(1, i * 20, 0)], t: 500 + i * 20 }),
      ),
    ]);
    expect(actions.filter((a) => a.kind === "dragMove")).toHaveLength(5);
    expect(actions.filter((a) => a.kind === "dragStart")).toHaveLength(1);
  });
});

describe("one-finger drag pans the view and never touches the guest", () => {
  it("moving past the slop before the hold pans, and emits no remote input at all", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100)], t: 0 },
      { type: "move", points: [p(1, 100 + TAP_SLOP_PX + 5, 100)], t: 30 },
      { type: "move", points: [p(1, 100 + TAP_SLOP_PX + 25, 120)], t: 60 },
      { type: "end", points: [], t: 90 },
    ]);
    expect(kinds(actions)).toEqual(["pan", "pan"]);
    // The load-bearing assertion: nothing that could act on the customer's machine.
    for (const a of actions) {
      expect(["click", "doubleClick", "dragStart", "dragMove", "dragEnd"]).not.toContain(a.kind);
    }
  });

  it("a pan does not become a click when the finger lifts", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 200, 0)], t: 40 },
      { type: "end", points: [], t: 80 },
    ]);
    expect(kinds(actions)).toEqual(["pan"]);
  });

  it("a pan that started does not later turn into a drag when the deadline ticks", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 200, 0)], t: 40 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "move", points: [p(1, 260, 0)], t: 560 },
    ]);
    expect(kinds(actions)).toEqual(["pan", "pan"]);
  });
});

describe("two fingers", () => {
  it("changing separation is a pinch, reported as a per-move scale about the centroid", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      // Separation 100 -> 200: well past the deadzone.
      { type: "move", points: [p(1, 50, 100), p(2, 250, 100)], t: 40 },
    ]);
    expect(actions).toHaveLength(1);
    const a = actions[0];
    expect(a.kind).toBe("zoom");
    if (a.kind === "zoom") {
      expect(a.scale).toBeCloseTo(2, 5);
      expect(a.cx).toBeCloseTo(150, 5);
      expect(a.cy).toBeCloseTo(100, 5);
    }
  });

  it("moving together past the latch distance is a scroll, not a zoom", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "move", points: [p(1, 100, 100 + SCROLL_LATCH_PX + 5), p(2, 200, 100 + SCROLL_LATCH_PX + 5)], t: 40 },
    ]);
    expect(actions).toEqual([{ kind: "scroll", dx: 0, dy: SCROLL_LATCH_PX + 5 }]);
  });

  it("hand noise below both thresholds decides nothing and emits nothing", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      // 3px of separation change (3% < deadzone) and 3px of centroid travel (< latch).
      { type: "move", points: [p(1, 100, 103), p(2, 203, 103)], t: 40 },
    ]);
    expect(actions).toEqual([]);
  });

  /**
   * LATCHING. Without it a pinch that drifts, or a scroll whose fingers splay, flips modes
   * mid-gesture and the view lurches. Once decided, a gesture keeps its meaning until the fingers
   * lift.
   */
  it("a latched scroll stays a scroll even when the fingers then splay past the pinch deadzone", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "move", points: [p(1, 100, 140), p(2, 200, 140)], t: 40 },   // latches scroll
      { type: "move", points: [p(1, 40, 180), p(2, 260, 180)], t: 80 },    // separation 100 -> 220
    ]);
    expect(kinds(actions)).toEqual(["scroll", "scroll"]);
  });

  /**
   * The latch is about never becoming a SCROLL, not about emitting a zoom on every move. A pinch
   * whose separation is unchanged has no scale to apply, so a translating pinch correctly emits
   * nothing — the first version of this test asserted a second `zoom` there and was simply wrong
   * about what the code should do.
   */
  it("a latched pinch never becomes a scroll, however far the centroid travels", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "move", points: [p(1, 50, 100), p(2, 250, 100)], t: 40 },    // latches pinch, spread 100->200
      { type: "move", points: [p(1, 250, 300), p(2, 450, 300)], t: 80 },   // same spread, moved 200px
      { type: "move", points: [p(1, 300, 300), p(2, 400, 300)], t: 120 },  // spread 200->100
    ]);
    expect(kinds(actions)).toEqual(["zoom", "zoom"]);
    expect(actions.some((a) => a.kind === "scroll")).toBe(false);
    // The middle move — pure translation — contributed nothing, and the third zoomed back out.
    const scales = actions.flatMap((a) => (a.kind === "zoom" ? [a.scale] : []));
    expect(scales[0]).toBeCloseTo(2, 5);
    expect(scales[1]).toBeCloseTo(0.5, 5);
  });

  it("the pinch deadzone is expressed as a fraction of the starting separation", () => {
    // Just inside the deadzone: no zoom.
    const inside = run([
      { type: "start", points: [p(1, 0, 0), p(2, 100, 0)], t: 0 },
      { type: "move", points: [p(1, 0, 0), p(2, 100 + (PINCH_DEADZONE * 100 - 2), 0)], t: 40 },
    ]);
    expect(inside.actions).toEqual([]);
    // Just outside: a zoom.
    const outside = run([
      { type: "start", points: [p(1, 0, 0), p(2, 100, 0)], t: 0 },
      { type: "move", points: [p(1, 0, 0), p(2, 100 + (PINCH_DEADZONE * 100 + 2), 0)], t: 40 },
    ]);
    expect(kinds(outside.actions)).toEqual(["zoom"]);
  });
});

describe("a held button always comes back up", () => {
  it("a cancel mid-drag releases the button", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 10, 10)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "move", points: [p(1, 60, 10)], t: 540 },
      { type: "cancel", t: 560 },
    ]);
    expect(actions[actions.length - 1]).toEqual({ kind: "dragEnd" });
  });

  it("a cancel with nothing held invents no button-up", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 10, 10)], t: 0 },
      { type: "move", points: [p(1, 200, 10)], t: 40 },
      { type: "cancel", t: 60 },
    ]);
    expect(kinds(actions)).toEqual(["pan"]);
  });

  it("a second finger arriving mid-drag releases the button before pinching", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 10, 10)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "move", points: [p(1, 60, 10)], t: 540 },
      { type: "start", points: [p(1, 60, 10), p(2, 200, 10)], t: 560 },
    ]);
    expect(actions[actions.length - 1]).toEqual({ kind: "dragEnd" });
  });

  it("a third finger arriving mid-drag releases the button", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 10, 10)], t: 0 },
      { type: "tick", t: LONG_PRESS_MS },
      { type: "move", points: [p(1, 60, 10)], t: 540 },
      { type: "start", points: [p(1, 60, 10), p(2, 100, 10), p(3, 140, 10)], t: 560 },
    ]);
    expect(actions[actions.length - 1]).toEqual({ kind: "dragEnd" });
  });
});

describe("three fingers are not a gesture", () => {
  it("emits nothing, and is not re-read as a two-finger gesture as the fingers lift", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "start", points: [p(1, 0, 0), p(2, 100, 0)], t: 20 },
      { type: "start", points: [p(1, 0, 0), p(2, 100, 0), p(3, 200, 0)], t: 40 },
      { type: "move", points: [p(1, 0, 50), p(2, 100, 50), p(3, 200, 50)], t: 60 },
      { type: "end", points: [p(1, 0, 50), p(2, 100, 50)], t: 80 },
      // Two fingers remain and move — this must NOT become a scroll.
      { type: "move", points: [p(1, 0, 150), p(2, 100, 150)], t: 100 },
      { type: "end", points: [p(1, 0, 150)], t: 120 },
      { type: "move", points: [p(1, 0, 250)], t: 140 },
      { type: "end", points: [], t: 160 },
    ]);
    expect(actions).toEqual([]);
  });

  it("recovers once every finger is up", () => {
    const { state } = run([
      { type: "start", points: [p(1, 0, 0), p(2, 10, 0), p(3, 20, 0)], t: 0 },
      { type: "end", points: [], t: 40 },
    ]);
    // Asserted on the FIELDS the downstream branches are guarded on, rather than on a flag: a
    // three-finger touch must leave nothing behind that a later event could interpret.
    expect(state.press).toBeNull();
    expect(state.startSpread).toBeNull();
    expect(state.dragOpened).toBe(false);
    // And the next tap works normally.
    const { actions } = run(
      [
        { type: "start", points: [p(1, 5, 5)], t: 100 },
        { type: "end", points: [], t: 140 },
      ],
      state,
    );
    expect(kinds(actions)).toEqual(["click"]);
  });
});

describe("the reducer is pure", () => {
  it("does not mutate the state it is given", () => {
    const before: GestureState = { ...INITIAL_GESTURE_STATE };
    const snapshot = JSON.stringify(before);
    reduceGesture(before, { type: "start", points: [p(1, 1, 2)], t: 0 });
    expect(JSON.stringify(before)).toBe(snapshot);
  });

  it("gives the same answer twice for the same input", () => {
    const s: GestureState = { ...INITIAL_GESTURE_STATE };
    const e: GestureEvent = { type: "start", points: [p(1, 3, 4)], t: 7 };
    expect(reduceGesture(s, e)).toEqual(reduceGesture(s, e));
  });
});
