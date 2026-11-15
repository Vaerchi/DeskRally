/**
 * Touch gestures for the remote canvas — what a finger on a phone means to the guest's desktop.
 *
 * # Why this is a pure reducer and not handlers in `Viewer.tsx`
 *
 * The viewer binds `onMouseDown` / `onMouseMove` and a native `wheel` listener and had **no touch
 * handling at all**, so on a phone the canvas was undrivable: browsers synthesise a delayed click
 * from a tap and nothing else, and there is no pinch, no pan, no right-click, no drag. Everything
 * below is the missing half.
 *
 * It lives here, beside `viewport.ts`, for the reason `osk.ts` gives next door: **vitest's `include`
 * glob covers `src/**` and `.ts` only, so logic inside a `.tsx` render body is invisible to it.** A
 * gesture recogniser is a state machine with timing, thresholds and latching — precisely the kind of
 * code that is wrong in ways only a test finds — so none of it belongs in a component.
 *
 * # The mapping, and why it is this one
 *
 * It follows the established mobile-RDP convention (Microsoft Remote Desktop's, which technicians
 * already have in their fingers) rather than inventing one:
 *
 * | gesture                     | meaning                                    |
 * |-----------------------------|--------------------------------------------|
 * | tap                         | left click there                           |
 * | double tap                  | double click there                         |
 * | long press, no movement     | right click there                          |
 * | long press **then** move    | drag with the left button held             |
 * | one finger dragged at once  | PAN THE VIEW — nothing reaches the guest   |
 * | two fingers, distance changes | pinch zoom                               |
 * | two fingers, moved together | scroll wheel                               |
 *
 * **A plain one-finger drag pans the view and never touches the guest**, and that asymmetry is
 * deliberate. A phone shows a 2560×1080 desktop at a size where panning is constant, so panning has
 * to be the cheap gesture; and a drag that reached the desktop by default would mean a stray thumb
 * can drag a file into another folder on a customer's machine. Dragging the guest therefore costs a
 * deliberate hold first. Same instinct as gating a button-DOWN by position while letting the UP
 * always through: the destructive direction is the one that needs the ceremony.
 *
 * # Time is injected, and long-press is a DEADLINE the caller schedules
 *
 * Every event carries `t`. A reducer cannot fire its own timer, so when a press could still become a
 * long press the result carries `longPressDeadline`; the caller sets one timeout and feeds back a
 * `tick`. That keeps the whole machine pure and lets a test advance time by arithmetic instead of
 * waiting — a gesture test that sleeps is a flaky gesture test.
 *
 * Coordinates are SURFACE-RELATIVE (already minus the canvas rect). Mapping to desktop absolutes
 * stays in `viewport.ts`'s `mapPointerToAbs`, which is where it is already tested; this module
 * decides *what happened*, never *where on the desktop*.
 */

/** One active touch, in surface coordinates. */
export interface GesturePoint {
  id: number;
  x: number;
  y: number;
}

/**
 * A touch event, normalised. `points` is the full set of ACTIVE touches after the event — so an
 * `end` that lifts the last finger carries an empty array.
 */
export type GestureEvent =
  | { type: "start"; points: GesturePoint[]; t: number }
  | { type: "move"; points: GesturePoint[]; t: number }
  | { type: "end"; points: GesturePoint[]; t: number }
  | { type: "cancel"; t: number }
  | { type: "tick"; t: number };

/** What the viewer should do. Surface coordinates; `viewport.ts` maps them to the desktop. */
export type GestureAction =
  | { kind: "click"; x: number; y: number; button: "left" | "right" }
  | { kind: "doubleClick"; x: number; y: number }
  | { kind: "dragStart"; x: number; y: number }
  | { kind: "dragMove"; x: number; y: number }
  | { kind: "dragEnd" }
  | { kind: "pan"; dx: number; dy: number }
  | { kind: "zoom"; scale: number; cx: number; cy: number }
  | { kind: "scroll"; dx: number; dy: number };

/**
 * Movement (px) a single touch may wander and still count as a tap rather than a pan.
 *
 * 10 px at a phone's device-pixel-ratio is about a millimetre of skin. Lower and a deliberate tap
 * becomes a 2 px pan that swallows the click; higher and a slow drag starts as a tap.
 */
export const TAP_SLOP_PX = 10;

/** How long a finger must stay down (and within {@link TAP_SLOP_PX}) to mean a right click. */
export const LONG_PRESS_MS = 500;

/** Maximum gap between two taps for the second to be a double click. */
export const DOUBLE_TAP_MS = 300;

/**
 * How far apart two taps may land and still be a double click.
 *
 * Looser than {@link TAP_SLOP_PX}: a finger lifts and returns rather than staying put, so the second
 * tap is reliably a few pixels off, and a double click that silently degrades into two single
 * clicks is a bug the operator cannot see — they just get no double click.
 */
export const DOUBLE_TAP_SLOP_PX = 24;

/**
 * Fractional change in finger separation before a two-finger gesture LATCHES as a pinch.
 *
 * Two fingers dragged down a screen never stay exactly parallel, so without a deadzone every scroll
 * would also zoom. 15 % is past ordinary hand noise and well inside a deliberate pinch.
 */
export const PINCH_DEADZONE = 0.15;

/** Two-finger centroid travel (px) before the gesture latches as a scroll. */
export const SCROLL_LATCH_PX = 12;

/** What a two-finger gesture has been decided to be. Latched, so it cannot flip mid-gesture. */
type TwoFingerIntent = "undecided" | "pinch" | "scroll";

/** What a single touch has been decided to be. */
type OneFingerIntent = "undecided" | "pan" | "drag";

export interface GestureState {
  /** Active touches, by id, as of the last event. */
  points: GesturePoint[];
  /** Where and when the current single touch went down; null when no single touch is tracked. */
  press: { x: number; y: number; t: number } | null;
  /** Last position a delta was measured from (pan, drag or two-finger centroid). */
  last: { x: number; y: number } | null;
  /** Finger separation when the two-finger gesture began, for the pinch ratio. */
  startSpread: number | null;
  oneFinger: OneFingerIntent;
  twoFinger: TwoFingerIntent;
  /** True once the long-press deadline has fired for the current press. */
  longPressFired: boolean;
  /**
   * True once a `dragStart` has been emitted — i.e. a button is DOWN on the guest.
   *
   * Separate from {@link longPressFired} on purpose. Reusing that flag as the "drag opened" marker
   * was the first version of this file, and it froze every drag after one move: the first move
   * cleared the flag, and the next move then took the not-yet-opened branch and emitted nothing. It
   * also decides whether a lift or a cancel owes the guest a button-UP.
   */
  dragOpened: boolean;
  /** The previous completed tap, for double-tap detection. */
  lastTap: { x: number; y: number; t: number } | null;
}

export const INITIAL_GESTURE_STATE: GestureState = {
  points: [],
  press: null,
  last: null,
  startSpread: null,
  oneFinger: "undecided",
  twoFinger: "undecided",
  longPressFired: false,
  dragOpened: false,
  lastTap: null,
};

export interface GestureResult {
  state: GestureState;
  actions: GestureAction[];
  /**
   * When set, the caller should schedule a `tick` at this timestamp: a press is pending that becomes
   * a right click if nothing else happens. Absent means no timer is needed.
   */
  longPressDeadline?: number;
}

function dist(a: GesturePoint, b: GesturePoint): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

function centroid(points: GesturePoint[]): { x: number; y: number } {
  const n = points.length || 1;
  return {
    x: points.reduce((s, p) => s + p.x, 0) / n,
    y: points.reduce((s, p) => s + p.y, 0) / n,
  };
}

/** Reset everything except the double-tap memory, which must survive between taps to work at all. */
function idle(s: GestureState): GestureState {
  return { ...INITIAL_GESTURE_STATE, lastTap: s.lastTap };
}

/**
 * Advance the recogniser by one event.
 *
 * Pure: same state and event always give the same result, and nothing here reads a clock or touches
 * the DOM.
 */
export function reduceGesture(state: GestureState, event: GestureEvent): GestureResult {
  const actions: GestureAction[] = [];

  if (event.type === "cancel") {
    // A cancel means the browser took the touch away (a system gesture, a call, scrolling stolen by
    // an ancestor). Any held button MUST be released — a drag abandoned with the button down would
    // leave the guest's mouse stuck down, which is the worst state to leave a customer's machine in.
    if (state.dragOpened) actions.push({ kind: "dragEnd" });
    return { state: idle(state), actions };
  }

  if (event.type === "tick") {
    // The long-press deadline. Only meaningful for a still-undecided single press.
    if (
      state.press &&
      state.points.length === 1 &&
      state.oneFinger === "undecided" &&
      !state.longPressFired &&
      event.t - state.press.t >= LONG_PRESS_MS
    ) {
      actions.push({ kind: "click", x: state.press.x, y: state.press.y, button: "right" });
      // Latched as a drag: a hold that then MOVES drags with the button held. The right click has
      // already been delivered, so a hold-and-release is a right click and nothing more.
      return {
        state: { ...state, longPressFired: true, oneFinger: "drag", last: { x: state.press.x, y: state.press.y } },
        actions,
      };
    }
    return { state, actions };
  }

  if (event.type === "start") {
    const points = event.points;

    if (points.length > 2) {
      // Three fingers: not a gesture. Release anything held and drop every accumulated
      // interpretation, so the two- and one-finger states this sequence passes through on the way
      // up cannot be read as a gesture the operator did not make.
      //
      // THE RESET IS THE MECHANISM, and that is worth stating because the first version also
      // carried a `poisoned` flag to suppress the rest of the sequence. Mutation testing showed
      // nothing could distinguish that flag from its absence: `idle()` already clears `press` and
      // `startSpread`, and every downstream branch is guarded on one of them, so the fingers that
      // remain can produce nothing until a fresh `start`. A flag that changes no behaviour is one a
      // later reader takes for load-bearing, so it is gone and the behaviour test below stands
      // guard instead — if `idle()` ever stops clearing those fields, that test fails.
      if (state.dragOpened) actions.push({ kind: "dragEnd" });
      return { state: { ...idle(state), points }, actions };
    }

    if (points.length === 2) {
      // A second finger arrived. Abandon any one-finger interpretation — including a held drag,
      // whose button must be released rather than left down while the view is pinched.
      if (state.dragOpened) actions.push({ kind: "dragEnd" });
      const [a, b] = points;
      return {
        state: {
          ...idle(state),
          points,
          startSpread: dist(a, b),
          last: centroid(points),
          twoFinger: "undecided",
        },
        actions,
      };
    }

    // One finger down. Undecided: it could still become a tap, a pan, a long press or a drag.
    const p = points[0];
    return {
      state: {
        ...idle(state),
        points,
        press: { x: p.x, y: p.y, t: event.t },
        last: { x: p.x, y: p.y },
        oneFinger: "undecided",
      },
      actions,
      longPressDeadline: event.t + LONG_PRESS_MS,
    };
  }

  if (event.type === "move") {
    // --- two fingers: pinch or scroll, latched once ---
    if (event.points.length === 2 && state.startSpread !== null && state.last) {
      const [a, b] = event.points;
      const spread = dist(a, b);
      const c = centroid(event.points);
      const ratio = state.startSpread > 0 ? spread / state.startSpread : 1;
      const travel = Math.hypot(c.x - state.last.x, c.y - state.last.y);

      let intent = state.twoFinger;
      if (intent === "undecided") {
        if (Math.abs(ratio - 1) >= PINCH_DEADZONE) intent = "pinch";
        else if (travel >= SCROLL_LATCH_PX) intent = "scroll";
      }

      if (intent === "pinch") {
        // The scale is reported RELATIVE to the last move, not to the gesture start, so the caller
        // can compose it with `zoomAtPoint` and stay clamped the whole way. Anchored on the current
        // centroid, which is what "pinch about the point between my fingers" means.
        const prevSpread = state.points.length === 2 ? dist(state.points[0], state.points[1]) : spread;
        const step = prevSpread > 0 ? spread / prevSpread : 1;
        if (step !== 1) actions.push({ kind: "zoom", scale: step, cx: c.x, cy: c.y });
      } else if (intent === "scroll") {
        actions.push({ kind: "scroll", dx: c.x - state.last.x, dy: c.y - state.last.y });
      }
      return {
        state: { ...state, points: event.points, twoFinger: intent, last: c },
        actions,
      };
    }

    // --- one finger ---
    if (event.points.length === 1 && state.press && state.last) {
      const p = event.points[0];
      const moved = Math.hypot(p.x - state.press.x, p.y - state.press.y);

      if (state.oneFinger === "undecided") {
        if (moved < TAP_SLOP_PX) {
          // Still within the slop: keep the long-press deadline alive and emit nothing, so a tap
          // that trembles is still a tap.
          return {
            state: { ...state, points: event.points },
            actions,
            longPressDeadline: state.press.t + LONG_PRESS_MS,
          };
        }
        // Moved before the hold completed → this is a PAN of the view. Nothing reaches the guest.
        actions.push({ kind: "pan", dx: p.x - state.last.x, dy: p.y - state.last.y });
        return {
          state: { ...state, points: event.points, oneFinger: "pan", last: { x: p.x, y: p.y } },
          actions,
        };
      }

      if (state.oneFinger === "pan") {
        actions.push({ kind: "pan", dx: p.x - state.last.x, dy: p.y - state.last.y });
        return { state: { ...state, points: event.points, last: { x: p.x, y: p.y } }, actions };
      }

      // Latched as a drag by a completed long press. The FIRST move opens it (button down at the
      // press point, so the drag starts where the finger actually landed rather than where it had
      // already travelled to); every later move is a plain move.
      if (state.oneFinger === "drag") {
        if (!state.dragOpened) {
          actions.push({ kind: "dragStart", x: state.press.x, y: state.press.y });
        }
        actions.push({ kind: "dragMove", x: p.x, y: p.y });
        return {
          state: { ...state, points: event.points, dragOpened: true, last: { x: p.x, y: p.y } },
          actions,
        };
      }
    }

    return { state: { ...state, points: event.points }, actions };
  }

  // --- end ---
  const remaining = event.points;

  if (state.oneFinger === "drag") {
    // Only owed a button-UP if a DOWN was actually sent. A long press that is held and then lifted
    // without moving already delivered its right click on the tick and opened nothing, so
    // fabricating an UP for it would be inventing input the operator never gave.
    //
    // This is narrower than "a button-up must always fire", and deliberately so: that rule is about
    // never DROPPING the up for a real down, which is still guaranteed here (dragOpened is only
    // cleared by going idle, and every path to idle from a drag emits the up first). The viewer also
    // keeps its own window-level release for buttons it believes are held, so a genuinely stuck
    // button has a second way out.
    if (state.dragOpened) actions.push({ kind: "dragEnd" });
    return { state: remaining.length === 0 ? idle(state) : { ...state, points: remaining }, actions };
  }

  if (state.oneFinger === "undecided" && state.press && state.points.length === 1) {
    // A finger that never moved far and never held long enough: a TAP, or the second of a pair.
    const p = state.press;
    const prev = state.lastTap;
    const isDouble =
      prev !== null &&
      event.t - prev.t <= DOUBLE_TAP_MS &&
      Math.hypot(p.x - prev.x, p.y - prev.y) <= DOUBLE_TAP_SLOP_PX;

    if (isDouble) {
      actions.push({ kind: "doubleClick", x: p.x, y: p.y });
      // Cleared, so a third tap starts a fresh pair rather than producing a second double click.
      return { state: { ...idle(state), lastTap: null }, actions };
    }
    actions.push({ kind: "click", x: p.x, y: p.y, button: "left" });
    return { state: { ...idle(state), lastTap: { x: p.x, y: p.y, t: event.t } }, actions };
  }

  // A pan, a pinch, a scroll, or a lift from a multi-finger gesture: nothing to emit on release.
  return { state: remaining.length === 0 ? idle(state) : { ...state, points: remaining }, actions };
}
