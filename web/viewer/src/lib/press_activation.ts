/**
 * Telling the click a POINTER press generated from an independent assistive-tech click.
 *
 * The trackpad's [Left] button acts on pointer-down and pointer-up. The browser then also fires a
 * `click` for that pointer press, which must not act a second time. A screen reader's "activate"
 * sends ONLY a click, and that must act (down then up). Attribution is by PROVENANCE, not by "the
 * next click":
 *
 * - only a POINTER press sets `pending` (with its pointerId). Space/Enter never do: the keyboard path
 *   does its own down/up and suppresses the native activation click with preventDefault, so there is
 *   no generated click to attribute;
 * - a click is the pending press's own only if it is pointer-generated (`detail > 0`), its pointerId
 *   matches where both are known, and it arrives before the press's up expires (`CLICK_WINDOW_MS`
 *   after the up, since touch clicks can lag it). It is suppressed once and consumes the press;
 * - a click with `detail === 0` (assistive tech, synthetic) is ALWAYS independent and activates, even
 *   with a pointer press pending, and leaves that pending press for its real click;
 * - a cancelled press generates no click, so `pressAbandoned` clears it (also used on blur).
 *
 * Pure, with time injected.
 */
export interface PressActivation {
  pending: boolean;
  /** The pointer that pressed; null when unknown. */
  pointerId: number | null;
  /** When the press's up arrived; null while it is still down. */
  upAt: number | null;
}

export const NO_PRESS: PressActivation = { pending: false, pointerId: null, upAt: null };

/** How long after a press's up its generated click may still arrive (touch clicks can lag the up). */
export const CLICK_WINDOW_MS = 400;

export const pressBegan = (pointerId?: number): PressActivation => ({
  pending: true,
  pointerId: typeof pointerId === "number" && pointerId >= 0 ? pointerId : null,
  upAt: null,
});

export function pressEnded(s: PressActivation, now: number): PressActivation {
  return s.pending ? { ...s, upAt: now } : s;
}

/** The press will produce no click (pointer cancelled) or focus left: forget it. */
export const pressAbandoned = (): PressActivation => NO_PRESS;

export interface ClickInfo {
  /** `MouseEvent.detail`: 0 for keyboard/assistive-tech/synthetic activation, >= 1 for a real pointer click. */
  detail: number;
  /** The click's `pointerId` where the browser provides one (a PointerEvent click). */
  pointerId?: number;
}

/** A click arrived. `activate` is true when it is independent and must be performed as a full click. */
export function clickArrived(
  s: PressActivation,
  now: number,
  click: ClickInfo,
): { state: PressActivation; activate: boolean } {
  if (click.detail <= 0) return { state: s, activate: true };
  const idKnown = typeof click.pointerId === "number" && click.pointerId >= 0 && s.pointerId !== null;
  const sameSource = !idKnown || click.pointerId === s.pointerId;
  const inWindow = s.upAt === null || now - s.upAt <= CLICK_WINDOW_MS;
  if (s.pending && sameSource && inWindow) return { state: NO_PRESS, activate: false };
  return { state: NO_PRESS, activate: true };
}
