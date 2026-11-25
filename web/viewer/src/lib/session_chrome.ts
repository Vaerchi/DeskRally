/**
 * Session "chrome" (the top bar) in the Chrome-Remote-Desktop style the operator asked for: during a
 * live session the whole top row collapses behind a small tab on the top edge, so the remote screen
 * gets the window. The tab keeps the monitor switcher one click away; ▾ drops the full bar down as an
 * overlay, and Pin restores the always-visible bar. Pure, so the rules are unit-tested.
 */

/** "minimal": collapsed behind the tab (the default). "pinned": the full bar is always shown. */
export type SessionChromePref = "minimal" | "pinned";

/** localStorage key for the per-browser preference (a viewer convenience, not shared state). */
export const SESSION_CHROME_KEY = "deskrally.sessionChrome";

/** Parse a stored preference; anything unknown (including absent) is the minimal default. */
export function parseSessionChrome(stored: string | null | undefined): SessionChromePref {
  return stored === "pinned" ? "pinned" : "minimal";
}

/**
 * How the top bar renders right now.
 * - "normal": no live session — the ordinary console bar.
 * - "pinned": a live session with the bar pinned — today's layout.
 * - "collapsed": a live session, minimal, bar hidden — only the tab shows.
 * - "overlay": a live session, minimal, bar dropped down over the screen.
 */
export type ChromeMode = "normal" | "pinned" | "collapsed" | "overlay";

/**
 * `screenShown` is false while the session shows Under the Hood, Files or Chat instead of the remote screen. The
 * overlay exists to give the SCREEN the whole window; over a tools view it only hides that view's own tab row
 * (2026-11-24: Processes/Services/Files/Event log were invisible until the bar was minimized). There an opened bar
 * takes its own row instead, as if pinned.
 */
export function chromeMode(sessionLive: boolean, pref: SessionChromePref, open: boolean, screenShown = true): ChromeMode {
  if (!sessionLive) return "normal";
  if (pref === "pinned") return "pinned";
  if (!open) return "collapsed";
  return screenShown ? "overlay" : "pinned";
}

/** A one-click monitor button for the tab. */
export interface TabMonitorButton {
  value: number;
  /** Short face: "1", "2", … or "All". */
  text: string;
  /** Full description for the tooltip / accessible name. */
  title: string;
  active: boolean;
}

/**
 * The tab's monitor buttons from the viewer's monitor options. A single monitor yields NO buttons —
 * there is nothing to switch to, so the tab stays as small as possible. Real monitors are numbered in
 * order; the composite option (if present) reads "All".
 */
export function tabMonitorButtons(
  options: readonly { value: number; label: string }[],
  active: number,
  compositeId: number,
): TabMonitorButton[] {
  const real = options.filter((o) => o.value !== compositeId);
  if (real.length < 2) return [];
  return options.map((o) => ({
    value: o.value,
    text: o.value === compositeId ? "All" : String(real.findIndex((r) => r.value === o.value) + 1),
    title: o.label,
    active: o.value === active,
  }));
}
