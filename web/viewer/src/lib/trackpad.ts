/**
 * Trackpad pointer mode for the remote canvas — a phone used like a laptop trackpad.
 *
 * Direct touch (`touch_gestures.ts`) puts a click where the finger is, which is exact but hides the
 * target under the fingertip and cannot do a precise hover, drag-select or scroll of a small control.
 * Trackpad mode instead keeps a visible CURSOR the operator steers RELATIVELY: dragging anywhere
 * moves it by the finger's travel (with acceleration), and a tap clicks AT THE CURSOR, never under
 * the finger.
 *
 * | gesture / control                  | meaning                                          |
 * |------------------------------------|--------------------------------------------------|
 * | one-finger drag                    | move the cursor (relative, accelerated)          |
 * | one-finger tap                     | left click at the cursor                         |
 * | two-finger tap                     | right click at the cursor                        |
 * | two-finger drag                    | scroll wheel, natural direction                  |
 * | pinch                              | zoom the LOCAL view (the viewer keeps the cursor in view) |
 * | [Left] press / release             | left button down / up at the cursor (hold = drag)|
 * | [Hold]                             | latch the left button down; tap again to release |
 * | [Right]                            | right click at the cursor                        |
 * | scroll strip drag / tap            | wheel / one notch (top half up, bottom half down)|
 *
 * Like `touch_gestures.ts` this is a PURE reducer: time is injected, nothing reads a clock or the
 * DOM, and vitest (which only globs `.ts`) can exercise all of it. The component turns the returned
 * actions into the SAME calls the mouse path makes (`mapPointer` / `moveEvent` / `buttonEvent` /
 * `wheelToScroll`), so this mode gains no privileges: it is gated by exactly the same
 * `pointerToRemote` as direct touch and the agent's view-only enforcement still applies.
 *
 * # The cursor is a FRACTION of the displayed desktop, not a pixel
 *
 * `cursor.fx/fy` is a position inside the desktop content rect in [0,1]. That makes clamping to the
 * remote screen trivial and exact, keeps the cursor on the same desktop point through pan, zoom and
 * resize, and lets the component reuse the existing pointer mapping unchanged (it converts the
 * fraction to a surface point and calls `mapPointer`, so crops and multi-monitor canvases work the
 * same as for the mouse).
 *
 * # The invariant that matters: never leave a button stuck down
 *
 * `leftDown` is "the guest holds the left button because of us". Every transition that sets it emits
 * a `buttonDown`, and every way out (button released, Hold toggled off, `release`) emits exactly one
 * `buttonUp`. `release` is what the component sends on cancel, visibility change, blur, mode switch,
 * monitor change and unmount.
 */

import type { ContentRect } from "./viewport";
import { PINCH_DEADZONE, SCROLL_LATCH_PX, TAP_SLOP_PX } from "./touch_gestures";

export type Sensitivity = "low" | "normal" | "high";
export const SENSITIVITIES: readonly Sensitivity[] = ["low", "normal", "high"];

/** Base cursor gain per sensitivity: cursor px moved on screen per finger px, at slow speed. */
export const SENSITIVITY_GAIN: Record<Sensitivity, number> = { low: 0.6, normal: 1, high: 1.7 };

/** Finger speed (px/ms) below which there is no acceleration — slow movement stays precise. */
export const ACCEL_KNEE = 0.35;
/** Extra gain per px/ms above the knee. */
export const ACCEL_SLOPE = 1.1;
/** Ceiling on the acceleration boost (gain tops out at base * (1 + MAX_BOOST)). */
export const ACCEL_MAX_BOOST = 2.5;
/** dt floor (ms) so two events stamped the same millisecond cannot divide by zero or spike. */
export const MIN_DT_MS = 4;

/** Longest a finger may stay down and still be a tap. */
export const TAP_MAX_MS = 500;
/** Longest both fingers may stay down and still be a two-finger tap (right click). */
export const TWO_TAP_MAX_MS = 350;

/** Two-finger travel (px) that is worth one wheel notch. */
export const SCROLL_PX_PER_NOTCH = 28;
/** Scroll-strip travel (px) that is worth one wheel notch. */
export const STRIP_PX_PER_NOTCH = 20;

export interface Pt {
  id: number;
  x: number;
  y: number;
}

export interface Cursor {
  fx: number;
  fy: number;
}

type PadPhase = "idle" | "one" | "two" | "dead";

interface PadTouch {
  phase: PadPhase;
  points: Pt[];
  /** One finger: where/when it went down. */
  press: { x: number; y: number; t: number } | null;
  last: { x: number; y: number } | null;
  lastT: number;
  /** Has the single finger left the tap slop (so it is a cursor move, not a tap)? */
  moved: boolean;
  /** Two fingers: when they went down, their spread and centroid then. */
  twoStart: { t: number; spread: number; cx: number; cy: number } | null;
  twoIntent: "undecided" | "pinch" | "scroll";
  scrollRem: { x: number; y: number };
  /** The right click for this two-finger touch has been sent (or the touch is no longer a tap). */
  twoDone: boolean;
}

interface Strip {
  startY: number;
  lastY: number;
  h: number;
  moved: boolean;
}

export interface TrackpadState {
  cursor: Cursor;
  sensitivity: Sensitivity;
  /** The Hold latch: the operator asked for the left button to stay down. */
  held: boolean;
  /** The [Left] bar button is physically pressed right now. */
  padButton: boolean;
  /** The guest holds the left button because of this mode (pad button and/or Hold). */
  leftDown: boolean;
  pad: PadTouch;
  strip: Strip | null;
  stripRem: number;
}

const IDLE_PAD: PadTouch = {
  phase: "idle",
  points: [],
  press: null,
  last: null,
  lastT: 0,
  moved: false,
  twoStart: null,
  twoIntent: "undecided",
  scrollRem: { x: 0, y: 0 },
  twoDone: false,
};

export const INITIAL_TRACKPAD_STATE: TrackpadState = {
  cursor: { fx: 0.5, fy: 0.5 },
  sensitivity: "normal",
  held: false,
  padButton: false,
  leftDown: false,
  pad: IDLE_PAD,
  strip: null,
  stripRem: 0,
};

/** The size of the desktop content on screen, which converts finger pixels to cursor fractions. */
export interface TrackpadGeom {
  cw: number;
  ch: number;
}

export type TrackpadEvent =
  | { type: "start"; points: Pt[]; t: number }
  | { type: "move"; points: Pt[]; t: number }
  | { type: "end"; points: Pt[]; t: number }
  | { type: "cancel" }
  | { type: "leftDown" }
  | { type: "leftUp" }
  | { type: "rightClick" }
  | { type: "holdToggle" }
  | { type: "stripStart"; y: number; h: number }
  | { type: "stripMove"; y: number }
  | { type: "stripEnd"; y: number }
  | { type: "stripCancel" }
  /** Let go of everything: a held button, the latch, any touch in flight. */
  | { type: "release" }
  | { type: "sensitivity"; value: Sensitivity };

/** What the component should do. Positions are the cursor fraction; the component maps them. */
export type TrackpadAction =
  | { kind: "move"; fx: number; fy: number }
  | { kind: "click"; button: "left" | "right"; fx: number; fy: number }
  | { kind: "buttonDown"; button: "left"; fx: number; fy: number }
  | { kind: "buttonUp"; button: "left" }
  /** Wheel NOTCHES with the DOM sign: dy > 0 scrolls the page DOWN (as a wheel event's deltaY). */
  | { kind: "wheel"; dx: number; dy: number }
  | { kind: "zoom"; scale: number; cx: number; cy: number };

export interface TrackpadResult {
  state: TrackpadState;
  actions: TrackpadAction[];
}

export const clamp01 = (v: number): number => (v < 0 ? 0 : v > 1 ? 1 : v);

/**
 * Cursor gain for one finger move: the sensitivity's base gain, boosted when the finger is fast so
 * a flick crosses the screen and a slow nudge stays pixel-precise (a laptop trackpad's curve).
 */
export function accelGain(distPx: number, dtMs: number, sens: Sensitivity): number {
  const base = SENSITIVITY_GAIN[sens];
  const speed = distPx / Math.max(dtMs, MIN_DT_MS);
  const boost = Math.min(ACCEL_MAX_BOOST, Math.max(0, speed - ACCEL_KNEE) * ACCEL_SLOPE);
  return base * (1 + boost);
}

function dist(a: { x: number; y: number }, b: { x: number; y: number }): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}
function centroid(ps: Pt[]): { x: number; y: number } {
  const n = ps.length || 1;
  return { x: ps.reduce((s, p) => s + p.x, 0) / n, y: ps.reduce((s, p) => s + p.y, 0) / n };
}

/** Whole notches out of an accumulating remainder (sign preserved), and what is left over. */
function takeNotches(rem: number, perNotch: number): { n: number; rem: number } {
  const n = Math.trunc(rem / perNotch);
  return { n, rem: rem - n * perNotch };
}

function down(s: TrackpadState, actions: TrackpadAction[]): TrackpadState {
  if (s.leftDown) return s;
  actions.push({ kind: "buttonDown", button: "left", fx: s.cursor.fx, fy: s.cursor.fy });
  return { ...s, leftDown: true };
}
function up(s: TrackpadState, actions: TrackpadAction[]): TrackpadState {
  if (!s.leftDown) return s;
  actions.push({ kind: "buttonUp", button: "left" });
  return { ...s, leftDown: false };
}

export function reduceTrackpad(state: TrackpadState, event: TrackpadEvent, geom: TrackpadGeom): TrackpadResult {
  const actions: TrackpadAction[] = [];
  let s = state;

  switch (event.type) {
    case "sensitivity":
      return { state: { ...s, sensitivity: event.value }, actions };

    case "release": {
      s = up(s, actions);
      return {
        state: { ...s, held: false, padButton: false, leftDown: false, pad: IDLE_PAD, strip: null, stripRem: 0 },
        actions,
      };
    }

    case "leftDown": {
      if (s.padButton) return { state: s, actions };
      s = { ...s, padButton: true };
      s = down(s, actions); // already down (Hold) → no second press
      return { state: s, actions };
    }
    case "leftUp": {
      if (!s.padButton) return { state: s, actions };
      s = { ...s, padButton: false };
      if (!s.held) s = up(s, actions); // the latch keeps it down
      return { state: s, actions };
    }
    case "holdToggle": {
      if (!s.held) {
        s = { ...s, held: true };
        s = down(s, actions);
      } else {
        s = { ...s, held: false };
        if (!s.padButton) s = up(s, actions); // a finger still on [Left] keeps it down until lifted
      }
      return { state: s, actions };
    }
    case "rightClick":
      actions.push({ kind: "click", button: "right", fx: s.cursor.fx, fy: s.cursor.fy });
      return { state: s, actions };

    case "stripStart":
      return { state: { ...s, strip: { startY: event.y, lastY: event.y, h: event.h, moved: false }, stripRem: 0 }, actions };
    case "stripMove": {
      const st = s.strip;
      if (!st) return { state: s, actions };
      const moved = st.moved || Math.abs(event.y - st.startY) >= TAP_SLOP_PX;
      if (!moved) return { state: s, actions };
      // Finger UP → page scrolls DOWN, like grabbing the page (same as two-finger scroll).
      const taken = takeNotches(s.stripRem + (st.lastY - event.y), STRIP_PX_PER_NOTCH);
      if (taken.n !== 0) actions.push({ kind: "wheel", dx: 0, dy: taken.n });
      return { state: { ...s, strip: { ...st, lastY: event.y, moved: true }, stripRem: taken.rem }, actions };
    }
    case "stripEnd": {
      const st = s.strip;
      if (st && !st.moved) {
        // A tap: one notch, toward whichever end was tapped.
        actions.push({ kind: "wheel", dx: 0, dy: event.y < st.h / 2 ? -1 : 1 });
      }
      return { state: { ...s, strip: null, stripRem: 0 }, actions };
    }
    case "stripCancel":
      return { state: { ...s, strip: null, stripRem: 0 }, actions };

    case "cancel":
      // The browser took the touch. The pad never owns a button, so there is nothing to release
      // here; the Hold latch is the operator's deliberate choice and survives a stray cancel.
      return { state: { ...s, pad: IDLE_PAD }, actions };
  }

  // --- pad touch events ---
  const pad = s.pad;

  if (event.type === "start") {
    const pts = event.points;
    if (pts.length > 2) return { state: { ...s, pad: { ...IDLE_PAD, phase: "dead", points: pts } }, actions };
    if (pts.length === 2) {
      const c = centroid(pts);
      return {
        state: {
          ...s,
          pad: {
            ...IDLE_PAD,
            phase: "two",
            points: pts,
            lastT: event.t,
            twoStart: { t: event.t, spread: dist(pts[0], pts[1]), cx: c.x, cy: c.y },
          },
        },
        actions,
      };
    }
    if (pts.length === 1) {
      const p = pts[0];
      return {
        state: { ...s, pad: { ...IDLE_PAD, phase: "one", points: pts, press: { x: p.x, y: p.y, t: event.t }, last: { x: p.x, y: p.y }, lastT: event.t } },
        actions,
      };
    }
    return { state: s, actions };
  }

  if (event.type === "move") {
    const pts = event.points;
    if (pad.phase === "one" && pts.length === 1 && pad.press && pad.last) {
      const p = pts[0];
      let moved = pad.moved;
      if (!moved && dist(p, pad.press) >= TAP_SLOP_PX) moved = true;
      if (!moved) return { state: { ...s, pad: { ...pad, points: pts } }, actions };
      const dx = p.x - pad.last.x;
      const dy = p.y - pad.last.y;
      const d = Math.hypot(dx, dy);
      let cursor = s.cursor;
      if (d > 0 && geom.cw > 0 && geom.ch > 0) {
        const g = accelGain(d, event.t - pad.lastT, s.sensitivity);
        cursor = { fx: clamp01(s.cursor.fx + (dx * g) / geom.cw), fy: clamp01(s.cursor.fy + (dy * g) / geom.ch) };
        // Pinned against an edge the cursor does not move; saying so would spam the guest.
        if (cursor.fx !== s.cursor.fx || cursor.fy !== s.cursor.fy) {
          actions.push({ kind: "move", fx: cursor.fx, fy: cursor.fy });
        }
      }
      return {
        state: { ...s, cursor, pad: { ...pad, points: pts, moved: true, last: { x: p.x, y: p.y }, lastT: event.t } },
        actions,
      };
    }
    if (pad.phase === "two" && pts.length === 2 && pad.twoStart) {
      const c = centroid(pts);
      const spread = dist(pts[0], pts[1]);
      const ratio = pad.twoStart.spread > 0 ? spread / pad.twoStart.spread : 1;
      const travel = Math.hypot(c.x - pad.twoStart.cx, c.y - pad.twoStart.cy);
      let intent = pad.twoIntent;
      if (intent === "undecided") {
        if (Math.abs(ratio - 1) >= PINCH_DEADZONE) intent = "pinch";
        else if (travel >= SCROLL_LATCH_PX) intent = "scroll";
      }
      let scrollRem = pad.scrollRem;
      const prev = pad.points;
      if (intent === "pinch" && prev.length === 2) {
        const prevSpread = dist(prev[0], prev[1]);
        const step = prevSpread > 0 ? spread / prevSpread : 1;
        if (step !== 1) actions.push({ kind: "zoom", scale: step, cx: c.x, cy: c.y });
      } else if (intent === "scroll" && prev.length === 2) {
        const pc = centroid(prev);
        // Fingers moving UP pull the page up, i.e. the wheel scrolls DOWN: DOM-sign delta = -movement.
        const ty = takeNotches(scrollRem.y + -(c.y - pc.y), SCROLL_PX_PER_NOTCH);
        const tx = takeNotches(scrollRem.x + -(c.x - pc.x), SCROLL_PX_PER_NOTCH);
        scrollRem = { x: tx.rem, y: ty.rem };
        if (tx.n !== 0 || ty.n !== 0) actions.push({ kind: "wheel", dx: tx.n, dy: ty.n });
      }
      const twoDone = pad.twoDone || intent !== "undecided";
      return { state: { ...s, pad: { ...pad, points: pts, twoIntent: intent, scrollRem, twoDone, lastT: event.t } }, actions };
    }
    return { state: { ...s, pad: { ...pad, points: pts } }, actions };
  }

  if (event.type === "end") {
    const remaining = event.points;

    if (pad.phase === "one" && remaining.length === 0) {
      const tap = !pad.moved && pad.press !== null && event.t - pad.press.t <= TAP_MAX_MS;
      // A tap while the button is latched down would be a second press on a held button: ignore it.
      if (tap && !s.leftDown) {
        actions.push({ kind: "click", button: "left", fx: s.cursor.fx, fy: s.cursor.fy });
      }
      return { state: { ...s, pad: IDLE_PAD }, actions };
    }

    if (pad.phase === "two") {
      const quick = pad.twoStart !== null && event.t - pad.twoStart.t <= TWO_TAP_MAX_MS;
      if (!pad.twoDone && quick) {
        actions.push({ kind: "click", button: "right", fx: s.cursor.fx, fy: s.cursor.fy });
      }
      // Whatever remains of this touch must not read as a fresh one-finger gesture.
      return {
        state: { ...s, pad: remaining.length === 0 ? IDLE_PAD : { ...IDLE_PAD, phase: "dead", points: remaining } },
        actions,
      };
    }

    return { state: { ...s, pad: remaining.length === 0 ? IDLE_PAD : { ...pad, points: remaining } }, actions };
  }

  return { state: s, actions };
}

// --- geometry helpers (pure; the component supplies the rects) ---------------------------------

/** Surface-local point of a cursor inside the desktop content rect. */
export function cursorSurfacePoint(r: ContentRect, c: Cursor): { x: number; y: number } {
  return { x: r.ox + c.fx * r.cw, y: r.oy + c.fy * r.ch };
}

/**
 * Surface point to hand to the existing pointer mapping. The mapping rejects anything outside the
 * content (`fx > 1`), and float rounding at the very edge can land a hair outside, so the cursor is
 * nudged a hundredth of a pixel inward.
 */
export function cursorMapPoint(r: ContentRect, c: Cursor): { x: number; y: number } {
  const eps = 0.01;
  const fx = Math.min(1 - eps / Math.max(r.cw, 1), Math.max(eps / Math.max(r.cw, 1), c.fx));
  const fy = Math.min(1 - eps / Math.max(r.ch, 1), Math.max(eps / Math.max(r.ch, 1), c.fy));
  return { x: r.ox + fx * r.cw, y: r.oy + fy * r.ch };
}

/** The pan that brings a point back inside the surface (with a margin); 0 on an axis already inside. */
export function revealDelta(
  p: { x: number; y: number },
  surfaceW: number,
  surfaceH: number,
  margin = 12,
): { dx: number; dy: number } {
  const m = Math.min(margin, surfaceW / 2, surfaceH / 2);
  const axis = (v: number, size: number): number => (v < m ? m - v : v > size - m ? size - m - v : 0);
  return { dx: axis(p.x, surfaceW), dy: axis(p.y, surfaceH) };
}

/**
 * A touch also makes the browser fire compatibility mouse events (move/down/up) shortly after. In
 * trackpad mode those would click under the finger, so mouse events this soon after a touch are ignored.
 */
export const TOUCH_MOUSE_GUARD_MS = 1000;
export function isTouchEchoMouse(lastTouchAt: number, now: number, firesTouchEvents?: boolean): boolean {
  // The browser's own answer wins in BOTH directions: an explicit false is a physical mouse however
  // recent the last touch was. Only a browser that does not say (Firefox, Safari) falls back to timing.
  if (firesTouchEvents === true) return true;
  if (firesTouchEvents === false) return false;
  return lastTouchAt > 0 && now - lastTouchAt < TOUCH_MOUSE_GUARD_MS;
}

/**
 * Should a MOUSEUP be ignored as the browser's compatibility echo of a touch?
 *
 * Only when the browser positively says so (`sourceCapabilities.firesTouchEvents === true`). An
 * explicit false is a physical mouse. When the platform gives no capabilities (Firefox, Safari) the
 * answer is still NO: a release for a physical press the viewer recorded is never swallowed on a
 * timer. That is a deliberate asymmetry: if a touch echo is mistaken for a release the worst case is
 * a physical drag that ends early, whereas swallowing a real release leaves the remote button stuck
 * down on the customer's machine. (Mouse-DOWN echoes keep the timing fallback in
 * {@link isTouchEchoMouse}: a swallowed down records nothing, so it cannot stick anything.)
 */
export function isTouchEchoMouseUp(firesTouchEvents?: boolean): boolean {
  return firesTouchEvents === true;
}

// --- per-device preference ---------------------------------------------------------------------

export const TRACKPAD_ENABLED_KEY = "deskrally.trackpad.enabled";
export const TRACKPAD_SENS_KEY = "deskrally.trackpad.sensitivity";

export interface TrackpadPrefs {
  enabled: boolean;
  sensitivity: Sensitivity;
}

const DEFAULT_PREFS: TrackpadPrefs = { enabled: false, sensitivity: "normal" };

/** Read the device's choice. Storage can be missing or throw (private window): fall back to the default (off). */
export function readTrackpadPrefs(storage?: Pick<Storage, "getItem">): TrackpadPrefs {
  try {
    const st = storage ?? window.localStorage;
    const sens = st.getItem(TRACKPAD_SENS_KEY);
    return {
      enabled: st.getItem(TRACKPAD_ENABLED_KEY) === "1",
      sensitivity: (SENSITIVITIES as readonly string[]).includes(sens ?? "") ? (sens as Sensitivity) : "normal",
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

export function writeTrackpadPrefs(prefs: TrackpadPrefs, storage?: Pick<Storage, "setItem">): void {
  try {
    const st = storage ?? window.localStorage;
    st.setItem(TRACKPAD_ENABLED_KEY, prefs.enabled ? "1" : "0");
    st.setItem(TRACKPAD_SENS_KEY, prefs.sensitivity);
  } catch {
    /* page-only: the choice still applies to this session */
  }
}
