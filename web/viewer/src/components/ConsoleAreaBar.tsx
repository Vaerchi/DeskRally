import type { ReactNode } from "react";
import { areaBarItems } from "../lib/area_nav";
import type { ConsoleArea, ConsoleAreaDef } from "../lib/console_areas";
import { ToolbarMenu } from "./ToolbarMenu";

/**
 * The console's visible page bar and its right end (bells and the Account menu). Moved out of App.tsx unchanged.
 *
 * Menu redesign wave 10: outside a live session the console's pages are a VISIBLE bar (2026-11-07), built from the
 * same groups as the app menu. In a live session (chrome other than "normal") it is not drawn, so the CRD-style tab row
 * gains nothing; on a phone CSS hides it and the menu sheet is the drawer.
 */
export function ConsoleAreaBar(props: {
  chrome: string;
  /** Wide enough, outside a session, to draw the bar's right end instead of putting these in the app menu. */
  barChrome: boolean;
  visibleAreas: readonly ConsoleAreaDef[];
  area: ConsoleArea;
  setArea: (area: ConsoleArea) => void;
  bells: ReactNode;
  whoami: ReactNode;
  signOutButton: ReactNode;
}) {
  const { chrome, barChrome, visibleAreas, area, setArea, bells, whoami, signOutButton } = props;
  return (
    <>
      {chrome === "normal" && (
        <nav className="app__areabar" aria-label="Console" data-testid="area-bar">
          {areaBarItems(visibleAreas, area).map((it) => it.kind === "direct" ? (
            <button key={it.group} type="button" className="app__areabtn" data-testid={`area-bar-${it.group.toLowerCase()}`}
              aria-current={it.current ? "page" : undefined}
              onClick={() => { if (!it.current) setArea(it.target.id); }}>
              {it.group}
            </button>
          ) : (
            <ToolbarMenu key={it.group} label={it.group} triggerTestId={`area-bar-${it.group.toLowerCase()}`}
              triggerClassName={`app__areabtn${it.current ? " app__areabtn--current" : ""}`} closeOnAction>
              {it.items.map((a) => (
                <button key={a.id} type="button" className="app__areaitem" data-testid={`area-bar-item-${a.id}`}
                  aria-current={area === a.id ? "page" : undefined} onClick={() => setArea(a.id)}>
                  {a.label}
                </button>
              ))}
            </ToolbarMenu>
          ))}
        </nav>
      )}
      {/* Wave 10b: the right end of the bar. A sibling of the nav, never inside it: the nav scrolls sideways
          (overflow-x), which would clip the bells' drop-down panels. */}
      {barChrome && (
        <div className="app__barend" data-testid="area-bar-end">
          {bells}
          <ToolbarMenu label="Account" triggerTestId="area-bar-account" triggerClassName="app__areabtn" closeOnAction>
            {whoami}
            {visibleAreas.filter((a) => a.group === "Account").map((a) => (
              <button key={a.id} type="button" className="app__areaitem" data-testid={`area-bar-item-${a.id}`}
                aria-current={area === a.id ? "page" : undefined} onClick={() => setArea(a.id)}>
                {a.label}
              </button>
            ))}
            <a className="app__areaitem" href="/downloads" target="_blank" rel="noopener noreferrer">Downloads</a>
            {signOutButton}
          </ToolbarMenu>
        </div>
      )}
    </>
  );
}
