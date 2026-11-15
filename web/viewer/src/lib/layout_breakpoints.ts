/**
 * How wide the console is, and what that means for its layout.
 *
 * # Why ranges, and not device metrics
 *
 * The console had **one** `@media` query in 1,911 lines of CSS and it covered only the sign-in page,
 * so the authenticated shell had never been laid out for anything but a desktop: `.access` is a hard
 * `width: 320px; flex-shrink: 0`, which on a 360 px phone leaves about 40 px for the session.
 *
 * The operator carries a Galaxy Z Fold 7, which is two devices in one — a narrow cover screen and a
 * near-square inner screen — and also wants ordinary Android to work. It would be easy to hard-code
 * that phone's numbers, and wrong: **no emulator profile is a real Fold 7**, a generic "fold-in with
 * outer display" AVD is a different panel, and a layout pinned to one device's metrics breaks on the
 * next one. So the bands below are chosen to BRACKET a class of devices, and a real device's numbers
 * are only ever used to confirm it lands in the band we expect.
 *
 * # The band that is really a correctness rule
 *
 * The fold transition is a **live resize**, not a reload: the page is mid-session when the screen
 * changes shape. So every layout decision here must be expressible in CSS, and the React tree must
 * NOT branch on width. Conditional rendering — `{isMobile ? <A/> : <B/>}` — unmounts a subtree on
 * resize, and unmounting the session pane would tear down the `<video>`, the peer connection and the
 * zoom/pan state, i.e. unfolding the phone would drop the call. This module therefore exists to name
 * the bands and to drive *class names and ARIA*, never to decide what gets rendered.
 */

/** What the shell does with its two panes at a given width. */
export type PaneMode =
  /** One pane at a time; the machine list is an off-canvas drawer. Phones, and a folded Fold. */
  | "stacked"
  /** Both panes, with a narrowed list. Unfolded foldables and small tablets. */
  | "split-narrow"
  /** Both panes at full width — the layout the console has always had. */
  | "split-wide";

/**
 * Below this, the two panes cannot coexist: a list plus a usable session does not fit.
 *
 * **Raised 599 → 767 on 2026-09-05, on the operator's report from the device this band was guessed
 * for.** The first cut put an unfolded foldable (high 600s to low 700s CSS px) in `split-narrow` and
 * narrowed the list to 240 px to make it fit; the test for that band said in as many words that the
 * exact number was "the operator's to report". They reported: *"the menu still takes up the majority
 * of the screen."* At ~700 px a 240 px list is a THIRD of the viewport before any padding — two
 * panes on a phone-shaped screen is a compromise that serves neither.
 *
 * 767 keeps the split for real tablets (768 is iPad portrait) and gives every phone-shaped device,
 * folded or unfolded, the drawer layout. Guessing a device's CSS px from its marketing name is what
 * produced the first number; this one is anchored to a reported symptom instead.
 */
export const STACKED_MAX_WIDTH = 767;

/**
 * At or above this, use the full desktop layout.
 *
 * Between {@link STACKED_MAX_WIDTH} and here sit real tablets in portrait, which have the room for a
 * permanent list; foldables no longer land in this band.
 */
export const SPLIT_WIDE_MIN_WIDTH = 960;

/**
 * The most of the viewport a permanent list may occupy in any split mode.
 *
 * Not consulted at runtime — {@link paneModeFor} is a plain threshold and easier to reason about
 * that way — but asserted over a width sweep in the tests, so that changing a breakpoint or a list
 * width can never quietly re-create the "the menu takes up most of the screen" complaint. Both
 * split modes sit exactly at this bound at their narrowest: 240/768 and 320/960.
 */
export const MAX_LIST_SHARE = 1 / 3;

/** The list pane's width in each split mode, kept here so CSS and tests cannot disagree. */
export const LIST_WIDTH_WIDE = 320;
export const LIST_WIDTH_NARROW = 240;

/**
 * Which layout a viewport width calls for.
 *
 * Total, including nonsense input: a zero or negative width happens in real browsers (a
 * background tab, a `resize` fired mid-teardown) and must not throw or produce a fourth answer.
 */
export function paneModeFor(width: number): PaneMode {
  if (!Number.isFinite(width) || width <= STACKED_MAX_WIDTH) return "stacked";
  if (width >= SPLIT_WIDE_MIN_WIDTH) return "split-wide";
  return "split-narrow";
}

/** True when the machine list is an off-canvas drawer rather than a permanent pane. */
export function listIsDrawer(width: number): boolean {
  return paneModeFor(width) === "stacked";
}

/**
 * Whether a drawer that is currently open should be forced shut in this mode.
 *
 * The drawer's open flag is deliberately kept as plain state that WIDE layouts simply ignore, so a
 * fold/unfold is a pure CSS reflow with no remount. But a drawer left open while the layout widens
 * would leave a stale backdrop over a two-pane view, so the shell closes it on the way out of
 * stacked mode. Returns false when already closed, so a caller can avoid a no-op state set (and the
 * re-render it would cause on every resize event).
 *
 * Takes the EFFECTIVE mode rather than a width, because the mode is no longer a function of width
 * alone — see {@link effectivePaneMode}. Passing a width here would have quietly ignored the
 * operator's compact override.
 */
export function shouldForceDrawerClosed(mode: PaneMode, drawerOpen: boolean): boolean {
  return drawerOpen && mode !== "stacked";
}

/**
 * The operator's layout choice.
 *
 * `"auto"` follows the viewport. `"compact"` forces the stacked, single-pane, drawer layout at ANY
 * width.
 *
 * # Why a manual override exists at all
 *
 * Because the automatic rule was right and still not what the operator wanted. They reported the
 * compact menu bar not appearing on their foldable — and it was working exactly as designed: the
 * unfolded inner screen is around 700 px, which is {@link PaneMode} `split-narrow`, so it correctly
 * kept two panes and the full bar. A width threshold cannot know that someone on a 700 px screen, or
 * on a 2560 px desktop, would rather have the screen back and reach the machine list from a drawer.
 *
 * That is a preference, not a measurement, so it is asked rather than inferred. It also means the
 * exact CSS pixel a given device reports — the thing no emulator profile can tell us for a real
 * Fold 7 — stops being load-bearing: if the automatic band is wrong for someone's hardware, they can
 * simply say so.
 */
export type PaneModePreference = "auto" | "compact";

/** `localStorage` key for {@link PaneModePreference}. Per-browser, which is the right scope. */
export const PANE_MODE_PREF_KEY = "deskrally.layout.paneMode";

/**
 * The band actually in force: the viewport's, unless the operator has asked for compact.
 *
 * This is the single source of truth for layout, and the shell publishes it as `data-pane-mode` for
 * the CSS to key on. Nothing keys on a media query any more, precisely so the automatic path and the
 * forced path cannot drift into two different layouts.
 */
export function effectivePaneMode(width: number, pref: PaneModePreference): PaneMode {
  return pref === "compact" ? "stacked" : paneModeFor(width);
}

/** Parse a stored preference, treating anything unrecognised as `"auto"`. */
export function parsePaneModePreference(raw: string | null | undefined): PaneModePreference {
  return raw === "compact" ? "compact" : "auto";
}

/**
 * A short label for the current band, for `data-pane-mode` on the shell.
 *
 * A data attribute rather than a conditional render, for the reason in the module note: the tree
 * must survive a resize. It also gives the Playwright mobile project something unambiguous to assert
 * against, instead of measuring pixels and hoping.
 */
export function paneModeAttr(width: number): PaneMode {
  return paneModeFor(width);
}
