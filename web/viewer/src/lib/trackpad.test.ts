import { describe, expect, it } from "vitest";
import {
  ACCEL_MAX_BOOST,
  INITIAL_TRACKPAD_STATE,
  SCROLL_PX_PER_NOTCH,
  SENSITIVITY_GAIN,
  STRIP_PX_PER_NOTCH,
  TAP_MAX_MS,
  TOUCH_MOUSE_GUARD_MS,
  TWO_TAP_MAX_MS,
  accelGain,
  cursorMapPoint,
  cursorSurfacePoint,
  isTouchEchoMouse,
  isTouchEchoMouseUp,
  readTrackpadPrefs,
  reduceTrackpad,
  revealDelta,
  writeTrackpadPrefs,
  type Pt,
  type TrackpadAction,
  type TrackpadEvent,
  type TrackpadGeom,
  type TrackpadState,
} from "./trackpad";

const GEOM: TrackpadGeom = { cw: 1000, ch: 500 };
const p = (id: number, x: number, y: number): Pt => ({ id, x, y });

/** Feed a list of events, collecting every action and the final state. */
function run(events: TrackpadEvent[], from: TrackpadState = INITIAL_TRACKPAD_STATE, geom = GEOM) {
  let state = from;
  const actions: TrackpadAction[] = [];
  for (const e of events) {
    const r = reduceTrackpad(state, e, geom);
    state = r.state;
    actions.push(...r.actions);
  }
  return { state, actions };
}
const kinds = (a: TrackpadAction[]) => a.map((x) => x.kind);

describe("relative cursor movement", () => {
  it("moves the cursor by the finger's travel, not to the finger", () => {
    // Slow drag (well under the acceleration knee): 100 px right over 1 s = gain 1.
    const { state, actions } = run([
      { type: "start", points: [p(1, 700, 400)], t: 0 },
      { type: "move", points: [p(1, 750, 400)], t: 500 },
      { type: "move", points: [p(1, 800, 400)], t: 1000 },
    ]);
    // The finger is at x=800 on screen but the cursor started at the centre and moved 100/1000.
    expect(state.cursor.fx).toBeCloseTo(0.6, 5);
    expect(state.cursor.fy).toBeCloseTo(0.5, 5);
    expect(actions.every((a) => a.kind === "move")).toBe(true);
  });

  it("does not move for jitter inside the tap slop", () => {
    const { state, actions } = run([
      { type: "start", points: [p(1, 100, 100)], t: 0 },
      { type: "move", points: [p(1, 104, 103)], t: 30 },
    ]);
    expect(actions).toEqual([]);
    expect(state.cursor).toEqual({ fx: 0.5, fy: 0.5 });
  });

  it("accelerates: a fast flick travels farther than a slow drag of the same finger distance", () => {
    const slow = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 100, 0)], t: 1000 },
    ]).state.cursor.fx;
    const fast = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 100, 0)], t: 40 },
    ]).state.cursor.fx;
    expect(fast).toBeGreaterThan(slow);
    expect(slow - 0.5).toBeCloseTo(0.1, 5); // slow = exact 1:1
  });

  it("acceleration is bounded", () => {
    const g = accelGain(10_000, 1, "normal");
    expect(g).toBeCloseTo(SENSITIVITY_GAIN.normal * (1 + ACCEL_MAX_BOOST), 9);
  });

  it("sensitivity scales the slow gain low < normal < high", () => {
    const at = (value: "low" | "normal" | "high") => {
      const s = run([{ type: "sensitivity", value }]).state;
      return run(
        [
          { type: "start", points: [p(1, 0, 0)], t: 0 },
          { type: "move", points: [p(1, 100, 0)], t: 1000 },
        ],
        s,
      ).state.cursor.fx;
    };
    expect(at("low")).toBeLessThan(at("normal"));
    expect(at("normal")).toBeLessThan(at("high"));
  });

  it("clamps the cursor to the remote screen and stops reporting moves at the edge", () => {
    const first = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 5000, 5000)], t: 100 },
    ]);
    expect(first.state.cursor).toEqual({ fx: 1, fy: 1 });
    const again = run([{ type: "move", points: [p(1, 6000, 6000)], t: 200 }], first.state);
    expect(again.actions).toEqual([]); // pinned: nothing new to tell the guest
    const back = run(
      [
        { type: "start", points: [p(1, 0, 0)], t: 0 },
        { type: "move", points: [p(1, -9000, -9000)], t: 50 },
      ],
      first.state,
    );
    expect(back.state.cursor).toEqual({ fx: 0, fy: 0 });
  });

  it("a degenerate content size moves nothing rather than producing NaN", () => {
    const { state } = run(
      [
        { type: "start", points: [p(1, 0, 0)], t: 0 },
        { type: "move", points: [p(1, 50, 50)], t: 500 },
      ],
      INITIAL_TRACKPAD_STATE,
      { cw: 0, ch: 0 },
    );
    expect(state.cursor).toEqual({ fx: 0.5, fy: 0.5 });
  });
});

describe("tap and two-finger tap", () => {
  it("a tap is a left click AT THE CURSOR, not under the finger", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 900, 450)], t: 0 },
      { type: "end", points: [], t: 80 },
    ]);
    expect(actions).toEqual([{ kind: "click", button: "left", fx: 0.5, fy: 0.5 }]);
  });

  it("a tap after moving clicks at the moved cursor", () => {
    const moved = run([
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 100, 0)], t: 1000 },
      { type: "end", points: [], t: 1010 },
    ]);
    expect(kinds(moved.actions)).toEqual(["move"]); // the lift after a drag is not a tap
    const tap = run(
      [
        { type: "start", points: [p(1, 900, 400)], t: 0 },
        { type: "end", points: [], t: 60 },
      ],
      moved.state,
    );
    expect(tap.actions).toHaveLength(1);
    expect(tap.actions[0]).toMatchObject({ kind: "click", button: "left" });
    expect((tap.actions[0] as { fx: number }).fx).toBeCloseTo(0.6, 5);
  });

  it("a finger held too long is not a tap", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 5, 5)], t: 0 },
      { type: "end", points: [], t: TAP_MAX_MS + 1 },
    ]);
    expect(actions).toEqual([]);
  });

  it("a tap while the button is latched down sends no second click", () => {
    const held = run([{ type: "holdToggle" }]).state;
    const { actions } = run(
      [
        { type: "start", points: [p(1, 5, 5)], t: 0 },
        { type: "end", points: [], t: 50 },
      ],
      held,
    );
    expect(actions).toEqual([]);
  });

  it("a two-finger tap is a right click at the cursor, once", () => {
    const { actions, state } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "end", points: [p(2, 200, 100)], t: 90 },
      { type: "end", points: [], t: 110 },
    ]);
    expect(actions).toEqual([{ kind: "click", button: "right", fx: 0.5, fy: 0.5 }]);
    expect(state.pad.phase).toBe("idle");
  });

  it("two fingers resting too long are not a right click", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "end", points: [p(2, 200, 100)], t: TWO_TAP_MAX_MS + 1 },
      { type: "end", points: [], t: TWO_TAP_MAX_MS + 20 },
    ]);
    expect(actions).toEqual([]);
  });

  it("the finger left after a two-finger tap does not become a tap or a cursor move", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "end", points: [p(2, 200, 100)], t: 60 },
      { type: "move", points: [p(2, 400, 300)], t: 100 },
      { type: "end", points: [], t: 130 },
    ]);
    expect(kinds(actions)).toEqual(["click"]);
  });

  it("a second finger landing mid-drag cancels the one-finger tap (no left click)", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100)], t: 0 },
      { type: "start", points: [p(1, 100, 100), p(2, 160, 100)], t: 20 },
      { type: "end", points: [], t: 40 },
    ]);
    // Only the two-finger tap's right click; never a left click.
    expect(actions.map((a) => (a as { button?: string }).button)).toEqual(["right"]);
  });

  it("three fingers do nothing", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 0, 0), p(2, 50, 0), p(3, 100, 0)], t: 0 },
      { type: "move", points: [p(1, 0, 80), p(2, 50, 80), p(3, 100, 80)], t: 50 },
      { type: "end", points: [], t: 80 },
    ]);
    expect(actions).toEqual([]);
  });
});

describe("two-finger drag scrolls (natural direction) and pinch zooms", () => {
  const two = (y: number, t: number): TrackpadEvent => ({
    type: "move",
    points: [p(1, 100, y), p(2, 200, y)],
    t,
  });

  it("fingers moving UP scroll the page DOWN (positive DOM sign), in whole notches", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 400), p(2, 200, 400)], t: 0 },
      two(380, 20), // latches (>= 12 px travel), 20 px up
      two(380 - SCROLL_PX_PER_NOTCH * 2, 40),
    ]);
    const total = actions.filter((a) => a.kind === "wheel").reduce((s, a) => s + (a as { dy: number }).dy, 0);
    expect(total).toBeGreaterThan(0);
    expect(actions.every((a) => a.kind === "wheel" && (a as { dx: number }).dx === 0)).toBe(true);
  });

  it("fingers moving DOWN scroll the page UP", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      two(130, 20),
      two(200, 40),
    ]);
    const total = actions.filter((a) => a.kind === "wheel").reduce((s, a) => s + (a as { dy: number }).dy, 0);
    expect(total).toBeLessThan(0);
  });

  it("sub-notch travel accumulates instead of being lost", () => {
    const evs: TrackpadEvent[] = [{ type: "start", points: [p(1, 100, 500), p(2, 200, 500)], t: 0 }];
    // Latch, then 2 px steps: no single step is a notch, but 28 px of them is.
    evs.push(two(480, 10));
    for (let i = 1; i <= 20; i++) evs.push(two(480 - i * 2, 10 + i * 10));
    const { actions } = run(evs);
    const total = actions.reduce((s, a) => s + (a.kind === "wheel" ? a.dy : 0), 0);
    expect(total).toBe(Math.trunc((20 + 40) / SCROLL_PX_PER_NOTCH));
  });

  it("a scroll never also right-clicks on release", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 300), p(2, 200, 300)], t: 0 },
      two(250, 20),
      { type: "end", points: [p(2, 200, 250)], t: 60 },
      { type: "end", points: [], t: 80 },
    ]);
    expect(actions.some((a) => a.kind === "click")).toBe(false);
  });

  it("pinch reports a zoom ratio and no wheel", () => {
    const { actions } = run([
      { type: "start", points: [p(1, 100, 100), p(2, 200, 100)], t: 0 },
      { type: "move", points: [p(1, 70, 100), p(2, 230, 100)], t: 30 },
    ]);
    const z = actions.find((a) => a.kind === "zoom");
    expect(z).toMatchObject({ kind: "zoom", cx: 150, cy: 100 });
    expect((z as { scale: number }).scale).toBeCloseTo(1.6, 5);
    expect(actions.some((a) => a.kind === "wheel")).toBe(false);
  });
});

describe("Left button, Hold latch and the stuck-button invariant", () => {
  const downs = (a: TrackpadAction[]) => a.filter((x) => x.kind === "buttonDown").length;
  const ups = (a: TrackpadAction[]) => a.filter((x) => x.kind === "buttonUp").length;

  it("press-and-hold Left pairs one down with one up, at the cursor", () => {
    const { actions, state } = run([{ type: "leftDown" }, { type: "leftUp" }]);
    expect(actions).toEqual([
      { kind: "buttonDown", button: "left", fx: 0.5, fy: 0.5 },
      { kind: "buttonUp", button: "left" },
    ]);
    expect(state.leftDown).toBe(false);
  });

  it("dragging the cursor between down and up is a drag (moves while the button is down)", () => {
    const { actions } = run([
      { type: "leftDown" },
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 80, 0)], t: 800 },
      { type: "leftUp" },
    ]);
    expect(kinds(actions)).toEqual(["buttonDown", "move", "buttonUp"]);
  });

  it("repeated leftDown does not press twice; stray leftUp sends nothing", () => {
    const a = run([{ type: "leftDown" }, { type: "leftDown" }, { type: "leftUp" }, { type: "leftUp" }]).actions;
    expect(downs(a)).toBe(1);
    expect(ups(a)).toBe(1);
  });

  it("Hold latches down, a one-finger drag then drags, and Hold again releases", () => {
    const { actions, state } = run([
      { type: "holdToggle" },
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "move", points: [p(1, 60, 0)], t: 600 },
      { type: "end", points: [], t: 650 },
      { type: "holdToggle" },
    ]);
    expect(kinds(actions)).toEqual(["buttonDown", "move", "buttonUp"]);
    expect(state.held).toBe(false);
    expect(state.leftDown).toBe(false);
  });

  it("[Left] while Hold is latched neither re-presses nor releases the latch", () => {
    const { actions, state } = run([{ type: "holdToggle" }, { type: "leftDown" }, { type: "leftUp" }]);
    expect(downs(actions)).toBe(1);
    expect(ups(actions)).toBe(0);
    expect(state.leftDown).toBe(true);
  });

  it("Hold toggled off while a finger is still on [Left] keeps the button down until it lifts", () => {
    const { actions, state } = run([{ type: "leftDown" }, { type: "holdToggle" }, { type: "holdToggle" }]);
    expect(ups(actions)).toBe(0);
    expect(state.leftDown).toBe(true);
    const done = run([{ type: "leftUp" }], state);
    expect(ups(done.actions)).toBe(1);
  });

  it("release lets go of a latched button exactly once and clears the latch", () => {
    const { actions, state } = run([{ type: "holdToggle" }, { type: "release" }, { type: "release" }]);
    expect(downs(actions)).toBe(1);
    expect(ups(actions)).toBe(1);
    expect(state).toMatchObject({ held: false, leftDown: false, padButton: false });
  });

  it("release lets go of a pressed [Left] button (visibility change / mode switch / cancel)", () => {
    const { actions } = run([{ type: "leftDown" }, { type: "release" }]);
    expect(ups(actions)).toBe(1);
    // ...and a late pointer-up afterwards must not send a second up.
    const late = run([{ type: "leftDown" }, { type: "release" }, { type: "leftUp" }]).actions;
    expect(ups(late)).toBe(1);
  });

  it("release with nothing held sends nothing", () => {
    expect(run([{ type: "release" }]).actions).toEqual([]);
  });

  it("a touch cancel does not strand the pad and does not drop a deliberate latch", () => {
    const { state, actions } = run([
      { type: "holdToggle" },
      { type: "start", points: [p(1, 0, 0)], t: 0 },
      { type: "cancel" },
    ]);
    expect(state.pad.phase).toBe("idle");
    expect(state.held).toBe(true);
    expect(ups(actions)).toBe(0);
    // And the next touch works normally.
    const next = run(
      [
        { type: "start", points: [p(1, 0, 0)], t: 0 },
        { type: "move", points: [p(1, 50, 0)], t: 500 },
      ],
      state,
    );
    expect(kinds(next.actions)).toEqual(["move"]);
  });

  it("every down in a long random sequence is matched by an up once released", () => {
    // Deterministic pseudo-random walk over the button events; the invariant must hold throughout.
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const choices: TrackpadEvent[] = [
      { type: "leftDown" },
      { type: "leftUp" },
      { type: "holdToggle" },
      { type: "rightClick" },
      { type: "cancel" },
    ];
    let state = INITIAL_TRACKPAD_STATE;
    let open = 0;
    for (let i = 0; i < 500; i++) {
      const r = reduceTrackpad(state, choices[Math.floor(rnd() * choices.length)], GEOM);
      for (const a of r.actions) {
        if (a.kind === "buttonDown") open++;
        if (a.kind === "buttonUp") open--;
      }
      expect(open === 0 || open === 1).toBe(true); // never two downs, never an up without a down
      expect(state.leftDown === (open === 1) || r.state.leftDown === (open === 1)).toBe(true);
      state = r.state;
    }
    const end = reduceTrackpad(state, { type: "release" }, GEOM);
    for (const a of end.actions) {
      if (a.kind === "buttonUp") open--;
    }
    expect(open).toBe(0);
  });
});

describe("right button bar", () => {
  it("rightClick clicks at the cursor", () => {
    expect(run([{ type: "rightClick" }]).actions).toEqual([{ kind: "click", button: "right", fx: 0.5, fy: 0.5 }]);
  });
});

describe("scroll strip", () => {
  it("dragging up scrolls down in notches, dragging down scrolls up", () => {
    const up = run([
      { type: "stripStart", y: 150, h: 200 },
      { type: "stripMove", y: 150 - STRIP_PX_PER_NOTCH * 3 },
      { type: "stripEnd", y: 90 },
    ]);
    expect(up.actions.reduce((s, a) => s + (a.kind === "wheel" ? a.dy : 0), 0)).toBe(3);
    const dn = run([
      { type: "stripStart", y: 50, h: 200 },
      { type: "stripMove", y: 50 + STRIP_PX_PER_NOTCH * 2 },
      { type: "stripEnd", y: 90 },
    ]);
    expect(dn.actions.reduce((s, a) => s + (a.kind === "wheel" ? a.dy : 0), 0)).toBe(-2);
  });

  it("a drag does not also step on release", () => {
    const { actions } = run([
      { type: "stripStart", y: 100, h: 200 },
      { type: "stripMove", y: 60 },
      { type: "stripEnd", y: 60 },
    ]);
    expect(actions).toEqual([{ kind: "wheel", dx: 0, dy: 2 }]);
  });

  it("a tap steps one notch toward the tapped half", () => {
    expect(run([{ type: "stripStart", y: 20, h: 200 }, { type: "stripEnd", y: 20 }]).actions).toEqual([
      { kind: "wheel", dx: 0, dy: -1 },
    ]);
    expect(run([{ type: "stripStart", y: 180, h: 200 }, { type: "stripEnd", y: 180 }]).actions).toEqual([
      { kind: "wheel", dx: 0, dy: 1 },
    ]);
  });

  it("cancel and release drop the gesture without scrolling", () => {
    expect(run([{ type: "stripStart", y: 20, h: 200 }, { type: "stripCancel" }, { type: "stripEnd", y: 20 }]).actions).toEqual([]);
    expect(run([{ type: "stripStart", y: 20, h: 200 }, { type: "release" }, { type: "stripEnd", y: 20 }]).actions).toEqual([]);
  });
});

describe("geometry helpers", () => {
  const r = { ox: 100, oy: 50, cw: 400, ch: 200 };
  it("maps the cursor fraction to a surface point", () => {
    expect(cursorSurfacePoint(r, { fx: 0.5, fy: 0.25 })).toEqual({ x: 300, y: 100 });
  });
  it("the map point stays strictly inside the content even at the corners", () => {
    const a = cursorMapPoint(r, { fx: 0, fy: 0 });
    const b = cursorMapPoint(r, { fx: 1, fy: 1 });
    expect(a.x).toBeGreaterThan(r.ox);
    expect(a.y).toBeGreaterThan(r.oy);
    expect(b.x).toBeLessThan(r.ox + r.cw);
    expect(b.y).toBeLessThan(r.oy + r.ch);
  });
  it("revealDelta pans the cursor back into view and is zero when already visible", () => {
    expect(revealDelta({ x: 200, y: 200 }, 400, 400)).toEqual({ dx: 0, dy: 0 });
    expect(revealDelta({ x: -50, y: 200 }, 400, 400)).toEqual({ dx: 62, dy: 0 });
    expect(revealDelta({ x: 200, y: 900 }, 400, 400)).toEqual({ dx: 0, dy: -512 });
  });
});

describe("touch echo mouse guard", () => {
  it("ignores mouse events right after a touch and Chrome's firesTouchEvents, not a later real mouse", () => {
    expect(isTouchEchoMouse(1000, 1100)).toBe(true);
    expect(isTouchEchoMouse(1000, 1000 + TOUCH_MOUSE_GUARD_MS + 1)).toBe(false);
    expect(isTouchEchoMouse(0, 5)).toBe(false); // no touch yet
    expect(isTouchEchoMouse(0, 5, true)).toBe(true);
    // An explicit false is a physical mouse even right after a touch (hybrid device).
    expect(isTouchEchoMouse(1000, 1100, false)).toBe(false);
  });
});

describe("touch echo mouseup classifier", () => {
  it("ignores only a mouseup the browser positively says a touch generated", () => {
    expect(isTouchEchoMouseUp(true)).toBe(true);
  });
  it("honours an explicit false: a physical mouse release always goes through", () => {
    expect(isTouchEchoMouseUp(false)).toBe(false);
  });
  it("unknown capabilities: still released, never swallowed on timing (a stuck button is worse)", () => {
    expect(isTouchEchoMouseUp(undefined)).toBe(false);
  });
});

describe("per-device preference", () => {
  const mem = () => {
    const m = new Map<string, string>();
    return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
  };
  it("defaults to off / normal", () => {
    expect(readTrackpadPrefs(mem())).toEqual({ enabled: false, sensitivity: "normal" });
  });
  it("round-trips", () => {
    const s = mem();
    writeTrackpadPrefs({ enabled: true, sensitivity: "high" }, s);
    expect(readTrackpadPrefs(s)).toEqual({ enabled: true, sensitivity: "high" });
  });
  it("an unknown stored sensitivity falls back to normal", () => {
    const s = mem();
    s.setItem("deskrally.trackpad.sensitivity", "turbo");
    expect(readTrackpadPrefs(s).sensitivity).toBe("normal");
  });
  it("throwing storage is survived on both read and write", () => {
    const bad = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(readTrackpadPrefs(bad)).toEqual({ enabled: false, sensitivity: "normal" });
    expect(() => writeTrackpadPrefs({ enabled: true, sensitivity: "low" }, bad)).not.toThrow();
  });
});
