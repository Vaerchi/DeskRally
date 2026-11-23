/**
 * The console's colour theme: System (default), Light or Dark.
 *
 * A per-browser convenience stored in localStorage next to the layout preference
 * (`deskrally.layout.paneMode`), never shared state. The palette itself lives in `index.css` as
 * semantic tokens: the dark values under `:root[data-theme="dark"]` (also the no-JS default), the
 * light ones under `:root[data-theme="light"]`, and `@media (prefers-color-scheme: light)` for
 * `:root:not([data-theme])`. So "System" is the ABSENCE of the attribute and the browser keeps it
 * live when the operating system flips; only an explicit choice writes `data-theme`.
 *
 * `public/theme-init.js` repeats the read-and-apply below as a tiny blocking script in `<head>`,
 * so the first paint is already in the right theme (a module script runs too late). It is a
 * separate file, not an inline script, because the deployed CSP is `script-src 'self'`. A test
 * keeps the key and the values of the two copies identical.
 */

export type ThemePreference = "system" | "light" | "dark";

export const THEME_PREF_KEY = "deskrally.theme";

export const THEME_PREFERENCES: readonly ThemePreference[] = ["system", "light", "dark"];

/** What the browser chrome (`theme-color`) should be for each resolved theme: the `--bg` of each palette. */
export const THEME_COLOR = { dark: "#0e1116", light: "#f6f8fa" } as const;

/** Parse a stored preference; anything unrecognised (including absent) is `"system"`. */
export function parseThemePreference(raw: string | null | undefined): ThemePreference {
  return raw === "light" || raw === "dark" ? raw : "system";
}

/** The theme actually shown for a preference, given whether the OS prefers light. */
export function resolveTheme(pref: ThemePreference, systemPrefersLight: boolean): "light" | "dark" {
  if (pref === "system") return systemPrefersLight ? "light" : "dark";
  return pref;
}

function systemPrefersLight(win: Pick<Window, "matchMedia">): boolean {
  try {
    return win.matchMedia("(prefers-color-scheme: light)").matches;
  } catch {
    return false;
  }
}

/**
 * Apply a preference to a document: `data-theme` for an explicit choice, no attribute for System,
 * and the `theme-color` meta tags follow so the phone's status bar matches.
 */
export function applyThemePreference(
  pref: ThemePreference,
  doc: Document = document,
  win: Pick<Window, "matchMedia"> = window,
): void {
  const root = doc.documentElement;
  if (pref === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
  const color = THEME_COLOR[resolveTheme(pref, systemPrefersLight(win))];
  doc.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]').forEach((m) => {
    // Remember the shipped value so choosing System again can restore the media-split pair.
    if (m.dataset.defaultColor === undefined) m.dataset.defaultColor = m.content;
    m.content = pref === "system" ? (m.dataset.defaultColor ?? color) : color;
  });
}

export function readThemePreference(storage: Pick<Storage, "getItem"> | null = safeStorage()): ThemePreference {
  try {
    return parseThemePreference(storage?.getItem(THEME_PREF_KEY));
  } catch {
    return "system";
  }
}

/** Store and apply. Storage failure (private mode) still applies for this page view. */
export function saveThemePreference(
  pref: ThemePreference,
  storage: Pick<Storage, "setItem" | "removeItem"> | null = safeStorage(),
  doc: Document = document,
  win: Pick<Window, "matchMedia"> = window,
): void {
  try {
    if (pref === "system") storage?.removeItem(THEME_PREF_KEY);
    else storage?.setItem(THEME_PREF_KEY, pref);
  } catch { /* preference optional */ }
  applyThemePreference(pref, doc, win);
}

function safeStorage(): Storage | null {
  try { return window.localStorage; } catch { return null; }
}

/** The motion preference, for any JS-driven animation (CSS handles its own via the media query). */
export function prefersReducedMotion(win: Pick<Window, "matchMedia"> = window): boolean {
  try {
    return win.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}
