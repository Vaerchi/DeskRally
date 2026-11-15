/**
 * The compact top bar for a phone OUTSIDE full screen.
 *
 * (Ed, 2026-11-13: "the top bar is very crowded on mobile and i have to slide over to change screens -
 * can we update it like the main site in full screen?") In full screen a phone already gets one small
 * bar (mobile_fullscreen.ts). Outside it the whole toolbar sat in the top row and scrolled sideways, so
 * changing screens meant sliding the row. Here the row keeps only the screen picker, always visible,
 * and ONE "More" button; everything else is behind More.
 *
 * "A phone" here is STRICTER than the full-screen rule (which is coarse OR narrow): a touch device AND a
 * narrow viewport. A narrow desktop window (a mouse, a resized browser) keeps the full toolbar, because
 * it has the pointer precision for it and a developer or operator shrinking a window should not lose it.
 *
 * Pure, and a class-name decision made by the viewer: the toolbar's contents change, the tree around
 * the video and the peer connection does not (see layout_breakpoints.ts).
 */
import { STACKED_MAX_WIDTH } from "./layout_breakpoints";

export interface CompactBarInput {
  isFullscreen: boolean;
  /** `(pointer: coarse)` in the viewer's owner window. */
  coarsePointer: boolean;
  /** The owner window's inner width in CSS px. */
  width: number;
  /** The session lives in a pop-out or a monitor window: it keeps its own chrome. */
  poppedOut: boolean;
}

export function shouldUseCompactBar({ isFullscreen, coarsePointer, width, poppedOut }: CompactBarInput): boolean {
  if (isFullscreen || poppedOut) return false; // full screen has its own bar
  const narrow = Number.isFinite(width) && width > 0 && width <= STACKED_MAX_WIDTH;
  return coarsePointer && narrow;
}

/** More than this many screen choices (including "All") will not fit side by side: use the select. */
export const MAX_PICKER_BUTTONS = 5;

/** Show the screen picker as one-tap buttons (true) or as the existing select (false). */
export function pickerAsButtons(optionCount: number): boolean {
  return optionCount >= 2 && optionCount <= MAX_PICKER_BUTTONS;
}
