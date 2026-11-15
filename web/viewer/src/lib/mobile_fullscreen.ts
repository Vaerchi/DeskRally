/**
 * When full screen on a phone swaps the whole toolbar for one compact floating bar.
 *
 * (Ed, 11-06: "can you give [me] a full screen version that just has [the monitor] selector,
 * trackpad selector and keyboard selector for mobile?") On a phone the inline toolbar plus the
 * special-key strip fill most of the screen in full screen, which defeats going full screen.
 *
 * Pure so it is testable; the viewer feeds it the live values. This is a class-name / CSS decision
 * (the viewer hides the old chrome rather than unmounting it) so toggling it never tears down the
 * `<video>` or the peer connection — see layout_breakpoints.ts for why the tree must not branch.
 */
import { STACKED_MAX_WIDTH } from "./layout_breakpoints";

export interface MobileFullscreenInput {
  isFullscreen: boolean;
  /** `(pointer: coarse)` in the viewer's owner window: a finger is the primary pointer. */
  coarsePointer: boolean;
  /** The owner window's inner width in CSS px. */
  width: number;
  /** The session lives in a pop-out window: it keeps its own chrome. */
  poppedOut: boolean;
}

export function shouldUseMobileFullscreenBar({ isFullscreen, coarsePointer, width, poppedOut }: MobileFullscreenInput): boolean {
  if (!isFullscreen || poppedOut) return false;
  // A nonsense width (0, NaN from a torn-down window) must not count as "narrow".
  const narrow = Number.isFinite(width) && width > 0 && width <= STACKED_MAX_WIDTH;
  return coarsePointer || narrow;
}
