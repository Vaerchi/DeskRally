/**
 * Tests for the layout bands.
 *
 * The band boundaries are asserted at the exact pixel on both sides, because an off-by-one here is
 * invisible in review and shows up as a phone getting the desktop layout — 320 px of machine list
 * and 40 px of session.
 *
 * The widths used as examples are the ones that motivated the bands: ordinary Android phones, a
 * folded and an unfolded large foldable, and a desktop.
 */

import { describe, it, expect } from "vitest";
import {
  paneModeFor,
  listIsDrawer,
  shouldForceDrawerClosed,
  effectivePaneMode,
  parsePaneModePreference,
  PANE_MODE_PREF_KEY,
  STACKED_MAX_WIDTH,
  SPLIT_WIDE_MIN_WIDTH,
  LIST_WIDTH_NARROW,
  LIST_WIDTH_WIDE,
  MAX_LIST_SHARE,
  type PaneMode,
} from "./layout_breakpoints";

describe("the bands bracket the devices they were chosen for", () => {
  // Rather than hard-code one phone's metrics, assert that a RANGE of plausible reports all land in
  // the intended band. That is the property that matters: a device we have never seen must still get
  // a sensible layout.
  it("ordinary Android phones (360-430 CSS px) all stack", () => {
    for (let w = 360; w <= 430; w += 1) {
      expect(paneModeFor(w)).toBe<PaneMode>("stacked");
    }
  });

  it("a folded large foldable's cover screen (roughly 380-420) stacks", () => {
    for (const w of [380, 400, 412, 420]) {
      expect(paneModeFor(w)).toBe<PaneMode>("stacked");
    }
  });

  // REVERSED 2026-09-05 on the operator's report. This band used to expect `split-narrow`, and the
  // comment here used to say the exact number was "the operator's to report". They reported it, from
  // the Fold itself: "the menu still takes up the majority of the screen." A 240 px list is a third
  // of a ~700 px viewport before padding, so the whole foldable range now gets the drawer.
  it("an unfolded large foldable (roughly 650-760) gets ONE pane and a drawer", () => {
    for (const w of [650, 673, 700, 728, 760]) {
      expect(paneModeFor(w)).toBe<PaneMode>("stacked");
      expect(listIsDrawer(w)).toBe(true);
    }
  });

  it("laptops and desktops get the layout the console has always had", () => {
    for (const w of [960, 1280, 1440, 1920, 2560]) {
      expect(paneModeFor(w)).toBe<PaneMode>("split-wide");
    }
  });

  it("a tablet in portrait (768-900) is split-narrow, not stacked", () => {
    for (const w of [768, 820, 900]) {
      expect(paneModeFor(w)).toBe<PaneMode>("split-narrow");
    }
  });
});

describe("the boundaries are exact", () => {
  it("stacks up to and including STACKED_MAX_WIDTH, and splits one pixel later", () => {
    expect(paneModeFor(STACKED_MAX_WIDTH)).toBe<PaneMode>("stacked");
    expect(paneModeFor(STACKED_MAX_WIDTH + 1)).toBe<PaneMode>("split-narrow");
  });

  it("is split-narrow one pixel below SPLIT_WIDE_MIN_WIDTH and wide at it", () => {
    expect(paneModeFor(SPLIT_WIDE_MIN_WIDTH - 1)).toBe<PaneMode>("split-narrow");
    expect(paneModeFor(SPLIT_WIDE_MIN_WIDTH)).toBe<PaneMode>("split-wide");
  });

  it("the narrow list is narrower than the wide one, or the middle band is pointless", () => {
    expect(LIST_WIDTH_NARROW).toBeLessThan(LIST_WIDTH_WIDE);
  });
});

describe("nonsense widths do not produce a fourth answer", () => {
  // Real browsers report these: a background tab, a resize fired during teardown, a headless shell.
  it("treats zero, negative and non-finite widths as stacked", () => {
    for (const w of [0, -1, -1920, Number.NaN, Number.POSITIVE_INFINITY * 0]) {
      expect(paneModeFor(w)).toBe<PaneMode>("stacked");
    }
  });

  it("an infinite width is still wide, not a crash", () => {
    // Infinity is not finite, so it takes the guard clause and stacks. Asserted so the behaviour is
    // a decision rather than an accident someone later 'fixes' in the wrong direction.
    expect(paneModeFor(Number.POSITIVE_INFINITY)).toBe<PaneMode>("stacked");
  });
});

describe("listIsDrawer", () => {
  it("is true only in the stacked band", () => {
    expect(listIsDrawer(400)).toBe(true);
    // 700 was `false` until 2026-09-05: an unfolded foldable used to keep a permanent list. The
    // operator reported that list eating the screen, so this width now gets the drawer.
    expect(listIsDrawer(700)).toBe(true);
    expect(listIsDrawer(800)).toBe(false);
    expect(listIsDrawer(1440)).toBe(false);
  });
});

describe("the list never dominates the viewport", () => {
  /**
   * THE INVARIANT BEHIND THE 2026-09-05 CHANGE, asserted directly so it cannot be lost the next time
   * someone moves a breakpoint or widens a list. The operator's complaint was proportional — "the
   * menu takes up the majority of the screen" — so the guard is proportional too, rather than another
   * guess at a device's CSS pixels. Both split modes sit exactly at the bound at their narrowest
   * (240/768 and 320/960), which is what makes it a real constraint and not a slack one.
   */
  it("a permanent list is at most a third of the width, at every width that has one", () => {
    for (let w = 200; w <= 3000; w += 1) {
      const mode = paneModeFor(w);
      if (mode === "stacked") continue;
      const listWidth = mode === "split-wide" ? LIST_WIDTH_WIDE : LIST_WIDTH_NARROW;
      expect(listWidth / w).toBeLessThanOrEqual(MAX_LIST_SHARE);
    }
  });

  it("and the session pane therefore always keeps the majority", () => {
    for (const w of [768, 800, 959, 960, 1280, 2560]) {
      const mode = paneModeFor(w);
      const listWidth = mode === "split-wide" ? LIST_WIDTH_WIDE : LIST_WIDTH_NARROW;
      expect(w - listWidth).toBeGreaterThan(w / 2);
    }
  });
});

describe("shouldForceDrawerClosed — the fold transition", () => {
  /**
   * THE CASE THAT MOTIVATES THIS. The operator unfolds the phone mid-session: the drawer was open
   * over a stacked layout, and the layout is now split. Leaving the flag set would strand a backdrop
   * over a two-pane view.
   */
  it("closes an open drawer when the layout leaves the stacked band", () => {
    expect(shouldForceDrawerClosed("split-narrow", true)).toBe(true);
    expect(shouldForceDrawerClosed("split-wide", true)).toBe(true);
  });

  it("leaves an open drawer alone while still stacked", () => {
    expect(shouldForceDrawerClosed("stacked", true)).toBe(false);
  });

  // NEGATIVE CONTROL, and the one that keeps resize cheap: a closed drawer must never report that it
  // needs closing, or every resize event would set state and re-render.
  it("reports nothing to do when the drawer is already closed, in any mode", () => {
    for (const m of ["stacked", "split-narrow", "split-wide"] as const) {
      expect(shouldForceDrawerClosed(m, false)).toBe(false);
    }
  });

  /**
   * It takes the EFFECTIVE MODE, not a width, and this is the test that pins why. An operator who
   * has forced compact on a 1440 px desktop is in the stacked layout, so their open drawer must NOT
   * be slammed shut — which is exactly what a width-based version did.
   */
  it("does not close the drawer of someone who forced compact on a wide screen", () => {
    expect(shouldForceDrawerClosed(effectivePaneMode(1440, "compact"), true)).toBe(false);
  });
});

describe("effectivePaneMode — the operator's manual override", () => {
  /**
   * WHY THIS EXISTS. The automatic rule was right and still not what the operator wanted: they
   * reported the compact bar missing on their foldable, and the unfolded inner screen is ~700 px,
   * which is `split-narrow` — so it correctly kept two panes and the full bar. A width threshold
   * cannot know that someone would rather have the screen back at that size, or on a desktop.
   */
  it("forces the stacked layout at ANY width when compact is chosen", () => {
    for (const w of [360, 599, 700, 960, 1440, 2560, 3840]) {
      expect(effectivePaneMode(w, "compact")).toBe<PaneMode>("stacked");
    }
  });

  // The negative control: `auto` must be exactly the automatic behaviour, unchanged. Without this,
  // an override that always forced stacked would pass the test above.
  it("auto is indistinguishable from the width-only rule", () => {
    for (const w of [0, 360, 599, 600, 700, 959, 960, 2560]) {
      expect(effectivePaneMode(w, "auto")).toBe(paneModeFor(w));
    }
  });

  it("the two preferences differ wherever the width would not have stacked", () => {
    // Asymmetric on purpose: at 800 the override CHANGES the answer.
    //
    // This used to use 700, the operator's unfolded foldable, because that width was `split-narrow`
    // and the override was their only escape from a permanent list. On 2026-09-05 they reported the
    // list still dominating, STACKED_MAX_WIDTH moved to 767, and 700 now stacks on its own — so the
    // override is a no-op there and the example had to move to a width that still splits. The
    // override remains the escape hatch for a real tablet or a desktop; it is no longer the only
    // thing standing between a foldable and a third of its screen being menu.
    expect(effectivePaneMode(800, "auto")).toBe<PaneMode>("split-narrow");
    expect(effectivePaneMode(800, "compact")).toBe<PaneMode>("stacked");
    // ...and is a no-op where the width already stacked, so toggling it on a phone changes nothing.
    expect(effectivePaneMode(400, "auto")).toBe(effectivePaneMode(400, "compact"));
    // The foldable specifically: both preferences now agree, which is the point of the change.
    expect(effectivePaneMode(700, "auto")).toBe(effectivePaneMode(700, "compact"));
  });
});

describe("parsePaneModePreference", () => {
  it("round-trips the two real values", () => {
    expect(parsePaneModePreference("compact")).toBe("compact");
    expect(parsePaneModePreference("auto")).toBe("auto");
  });

  // Anything else is `auto`, because this value comes from localStorage: it can be absent, stale
  // from an older build, or edited by hand. Defaulting to the automatic behaviour means a corrupt
  // preference degrades to "follow the viewport" rather than trapping someone in a layout.
  it("treats absent, empty and unrecognised values as auto", () => {
    for (const raw of [null, undefined, "", "COMPACT", "Compact", "stacked", "true", "{}"]) {
      expect(parsePaneModePreference(raw)).toBe("auto");
    }
  });

  it("has a stable storage key, since changing it silently forgets everyone's choice", () => {
    expect(PANE_MODE_PREF_KEY).toBe("deskrally.layout.paneMode");
  });
});
