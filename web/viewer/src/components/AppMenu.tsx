import type { ReactNode } from "react";
import { DESKTOP_PREFERENCE_KEY } from "../lib/desktop_launch";
import type { PaneModePreference } from "../lib/layout_breakpoints";
import { CONSOLE_AREA_GROUPS, type ConsoleArea, type ConsoleAreaDef } from "../lib/console_areas";
import { parseThemePreference, THEME_PREFERENCES, type ThemePreference } from "../lib/theme";
import { RallyMark } from "./RallyIdentity";
import { ToolbarMenu } from "./ToolbarMenu";

/** The "DeskRally" app menu: downloads, desktop/browser choice, every console area, layout and theme, and (when the
 *  bar has no right end) the bells, identity and sign-out. Moved out of App.tsx unchanged. */
export function AppMenu(props: {
  onOpenChange: (open: boolean) => void;
  /** The help-request count shown on the trigger, or null. */
  badge: string | null;
  barChrome: boolean;
  desktopClient: boolean;
  preferDesktop: boolean;
  setPreferDesktop: (desktop: boolean) => void;
  visibleAreas: readonly ConsoleAreaDef[];
  area: ConsoleArea;
  setArea: (area: ConsoleArea) => void;
  layoutPref: PaneModePreference;
  toggleCompactLayout: () => void;
  themePref: ThemePreference;
  chooseTheme: (theme: ThemePreference) => void;
  bells: ReactNode;
  whoami: ReactNode;
  signOutButton: ReactNode;
}) {
  const { onOpenChange, badge, barChrome, desktopClient, preferDesktop, setPreferDesktop, visibleAreas, area, setArea,
    layoutPref, toggleCompactLayout, themePref, chooseTheme, bells, whoami, signOutButton } = props;
  return (
    <ToolbarMenu label="DeskRally" onOpenChange={onOpenChange} badge={badge} badgeNoun="help requests waiting">
    <span className="app__brand"><RallyMark />DeskRally</span>
    {!barChrome && <a href="/downloads" target="_blank" rel="noopener noreferrer">Downloads</a>}
    {!desktopClient && <label>Connect in <select aria-label="Connect in" value={preferDesktop ? "desktop" : "browser"}
      onChange={e => { const desktop = e.target.value === "desktop"; setPreferDesktop(desktop);
        try { localStorage.setItem(DESKTOP_PREFERENCE_KEY, desktop ? "desktop" : "browser"); } catch { /* preference optional */ }
      }}><option value="desktop">Desktop app</option><option value="browser">Browser</option></select></label>}
    {/* Console areas stay available in the app menu without taking a second row. */}
    <nav className="app__viewswitch app__consolenav" aria-label="Console area">
      {CONSOLE_AREA_GROUPS.map((g) => {
        const inGroup = visibleAreas.filter((a) => a.group === g);
        if (inGroup.length === 0) return null;
        return (
          <div key={g} className="app__navgroup" role="tablist" aria-label={g} data-testid={`nav-group-${g.toLowerCase()}`}>
            <span className="app__navgroup-title" aria-hidden="true">{g}</span>
            {inGroup.map((a) => (
              <button
                key={a.id}
                role="tab"
                aria-selected={area === a.id}
                data-active={area === a.id}
                onClick={() => setArea(a.id)}
              >
                {a.label}
              </button>
            ))}
          </div>
        );
      })}
    </nav>
    {/* Compact-layout toggle. Available at EVERY width, which is the point: the automatic band
        is right for a phone and still not what someone on a 700px foldable — or a wide desktop
        who wants the screen back — necessarily wants. `aria-pressed` rather than a checkbox,
        because it toggles the surrounding layout rather than submitting a value. */}
    <button
      type="button"
      className={`app__compact${layoutPref === "compact" ? " app__compact--on" : ""}`}
      data-testid="app-compact-toggle"
      aria-pressed={layoutPref === "compact"}
      title={
        layoutPref === "compact"
          ? "Compact layout is ON — the machine list is a drawer. Click to follow the window size instead."
          : "Compact layout: hide the machine list behind a menu button and give the session the whole window."
      }
      onClick={toggleCompactLayout}
    >
      {layoutPref === "compact" ? "Compact ✓" : "Compact"}
    </button>
    {/* Colour theme lives in the app menu with the other display preferences, never in the session top row. */}
    <label className="app__theme">
      <span>Theme</span>
      <select
        data-testid="app-theme-select"
        value={themePref}
        onChange={(e) => chooseTheme(parseThemePreference(e.target.value))}
        title="Colour theme for this browser. System follows the operating system."
      >
        {THEME_PREFERENCES.map((t) => <option key={t} value={t}>{t === "system" ? "System" : t === "light" ? "Light" : "Dark"}</option>)}
      </select>
    </label>
    {!barChrome && bells}
    {!barChrome && whoami}
    {!barChrome && signOutButton}
    </ToolbarMenu>
  );
}
