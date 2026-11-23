/**
 * The count badge on a menu trigger (docs/64 console: open help requests on the existing "DeskRally" menu
 * trigger, visible while the menu is closed). vitest here has no DOM, so the presentational pieces are called
 * as pure functions; the real trigger (portal, hooks) is covered by e2e/help_requests.spec.ts.
 */
import { describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MenuSection, ToolbarMenu, ToolbarMenuBadge, menuPanelPosition, toolbarMenuTitle } from "./ToolbarMenu";
import { helpBellView } from "../lib/help_requests";
import type { HelpRequest } from "../lib/console_api";

const req = (id: string, status = "open"): HelpRequest => ({
  id, machine_id: `m-${id}`, machine_name: `H-${id}`, group_id: "g", note: "", note_source: "guest_machine",
  requested_from: "machine", status, created_at: "2026-10-31T10:00:00Z", expires_at: "2026-10-31T10:30:00Z",
  online: true, can_accept: true,
} as HelpRequest);

describe("ToolbarMenuBadge", () => {
  it("renders nothing without a count", () => {
    expect(ToolbarMenuBadge({ badge: null })).toBeNull();
    expect(ToolbarMenuBadge({ badge: undefined })).toBeNull();
    expect(ToolbarMenuBadge({ badge: "" })).toBeNull();
  });

  it("renders the count as decorative text so the trigger keeps its exact accessible name", () => {
    const el = ToolbarMenuBadge({ badge: "3" }) as ReactElement<{ children: string; "aria-hidden": string; "data-testid": string }>;
    expect(el.props.children).toBe("3");
    expect(el.props["aria-hidden"]).toBe("true");
    expect(el.props["data-testid"]).toBe("toolbar-menu-badge");
  });
});

describe("toolbarMenuTitle", () => {
  it("is the label alone without a badge, and says what the count is with one", () => {
    expect(toolbarMenuTitle("DeskRally")).toBe("DeskRally");
    expect(toolbarMenuTitle("DeskRally", null, "help requests waiting")).toBe("DeskRally");
    expect(toolbarMenuTitle("DeskRally", "2", "help requests waiting")).toBe("DeskRally — 2 help requests waiting");
  });
});

describe("the DeskRally trigger's count follows OPEN help requests only", () => {
  it("counts open requests; none, or only closed ones, show no badge", () => {
    expect(helpBellView([]).badge).toBeNull();
    expect(helpBellView([req("a", "accepted"), req("b", "cancelled")]).badge).toBeNull();
    expect(helpBellView([req("a"), req("b"), req("c", "expired")]).badge).toBe("2");
  });
});

describe("MenuSection (menu redesign wave 7)", () => {
  it("is a named group with a decorative heading, its children unwrapped", () => {
    const html = renderToStaticMarkup(
      <MenuSection title="Collaboration" testId="sec"><button data-testid="child">Hand over session…</button></MenuSection>,
    );
    expect(html).toBe(
      '<div class="menu-section" role="group" aria-label="Collaboration" data-testid="sec">'
      + '<span class="menu-section__title" aria-hidden="true">Collaboration</span>'
      + '<button data-testid="child">Hand over session…</button></div>',
    );
  });

  it("holds only its heading when every child renders nothing (CSS then hides it)", () => {
    const html = renderToStaticMarkup(<MenuSection title="Clipboard">{false}{null}</MenuSection>);
    expect(html).toBe('<div class="menu-section" role="group" aria-label="Clipboard">'
      + '<span class="menu-section__title" aria-hidden="true">Clipboard</span></div>');
  });

  it("adds nothing inside a menu drawn inline (a pop-out window's toolbar row)", () => {
    // ToolbarMenu makes its (unused, when inline) portal container on mount; vitest has no DOM.
    vi.stubGlobal("document", { createElement: () => ({}) });
    try {
      const html = renderToStaticMarkup(
        <ToolbarMenu label="More" inline><MenuSection title="View"><button>Fit</button></MenuSection></ToolbarMenu>,
      );
      expect(html).toBe("<button>Fit</button>");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("menuPanelPosition (a row menu near the bottom opens upward)", () => {
  const win = { innerWidth: 1280, innerHeight: 800 };
  it("opens under its trigger when there is room", () => {
    expect(menuPanelPosition({ top: 100, bottom: 130, left: 500 }, win)).toEqual({ top: 134, left: 500 });
  });
  it("opens above a trigger near the bottom of the window", () => {
    expect(menuPanelPosition({ top: 700, bottom: 730, left: 500 }, win)).toEqual({ bottom: 104, left: 500 });
  });
  it("keeps the panel inside the window horizontally", () => {
    expect(menuPanelPosition({ top: 100, bottom: 130, left: 1200 }, win).left).toBe(1280 - 336);
    expect(menuPanelPosition({ top: 100, bottom: 130, left: -20 }, win).left).toBe(8);
  });
});
