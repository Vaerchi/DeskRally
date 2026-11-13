import { createContext, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

const MenuVisibility = createContext(true);
/** True inside a ToolbarMenu drawn INLINE (a pop-out window's row): there a section is no group at all. */
const MenuInline = createContext(false);
export const useToolbarMenuVisible = () => useContext(MenuVisibility);

/**
 * The small count on a menu trigger (e.g. open guest help requests on "DeskRally"). It is a child of the
 * EXISTING trigger, never a control of its own, so the single-row chrome gains no button. Decorative for
 * assistive tech: the trigger's accessible name stays exactly its label (the tab-bar tests and users find it
 * by that name); the count is carried by the trigger's `title` instead.
 */
export function ToolbarMenuBadge({ badge }: { badge?: string | null }) {
  if (!badge) return null;
  return <span className="toolbar-menu__badge" data-testid="toolbar-menu-badge" aria-hidden="true">{badge}</span>;
}

/** The trigger's tooltip: the label alone, or the label with what the badge counts. */
export function toolbarMenuTitle(label: string, badge?: string | null, badgeNoun?: string): string {
  return badge ? `${label} — ${badge} ${badgeNoun ?? "waiting"}` : label;
}

/** Where a panel opens: under its trigger, or above it when there is no room below (a row near the bottom). */
export function menuPanelPosition(rect: { top: number; bottom: number; left: number }, win: { innerWidth: number; innerHeight: number }):
  { top?: number; bottom?: number; left: number } {
  const left = Math.max(8, Math.min(rect.left, win.innerWidth - 336));
  const below = win.innerHeight - rect.bottom;
  return below < 240 && rect.top > below ? { bottom: win.innerHeight - rect.top + 4, left } : { top: rect.bottom + 4, left };
}

/**
 * Preserve stateful controls while an overflow panel is closed or fullscreen changes.
 *
 * Menu redesign wave 8 (a machine row's "⋯" menu) adds: `trigger` (what the button shows; default "label ▾"),
 * `ariaLabel` (its accessible name and the panel's; default `label`, so many rows can each name their machine),
 * `triggerTestId`, `triggerClassName`, and `closeOnAction` (choosing an item closes the menu).
 */
export function ToolbarMenu({ label, children, inline = false, onOpenChange, badge, badgeNoun, trigger: triggerContent, ariaLabel, triggerTestId, triggerClassName, closeOnAction = false }: { label: string; children: ReactNode; inline?: boolean; onOpenChange?: (open: boolean) => void; badge?: string | null; badgeNoun?: string; trigger?: ReactNode; ariaLabel?: string; triggerTestId?: string; triggerClassName?: string; closeOnAction?: boolean }) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const [container] = useState(() => document.createElement("div"));
  const [position, setPosition] = useState<{ top?: number; bottom?: number; left: number }>({ top: 48, left: 8 });
  const name = ariaLabel ?? label;
  useLayoutEffect(() => {
    if (inline) return;
    const doc = trigger.current!.ownerDocument;
    const place = () => { (doc.fullscreenElement ?? doc.body).appendChild(container); setOpen(false); };
    place();
    doc.addEventListener("fullscreenchange", place);
    return () => { doc.removeEventListener("fullscreenchange", place); container.remove(); };
  }, [container, inline]);
  useEffect(() => {
    if (!open || inline) return;
    const doc = trigger.current!.ownerDocument;
    const outside = (event: Event) => {
      if (!trigger.current?.contains(event.target as Node) && !panel.current?.contains(event.target as Node)) setOpen(false);
    };
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setOpen(false); trigger.current?.focus(); }
    };
    doc.addEventListener("pointerdown", outside);
    doc.addEventListener("focusin", outside);
    doc.addEventListener("keydown", key);
    panel.current?.focus();
    return () => {
      doc.removeEventListener("pointerdown", outside);
      doc.removeEventListener("focusin", outside);
      doc.removeEventListener("keydown", key);
    };
  }, [open, inline]);
  useLayoutEffect(() => { onOpenChange?.(open && !inline); return () => onOpenChange?.(false); }, [open, inline, onOpenChange]);
  if (inline) return <MenuInline.Provider value={true}>{children}</MenuInline.Provider>;
  return <>
    <button type="button" className={triggerClassName ?? "toolbar-menu__trigger"} ref={trigger} data-menu-label={label}
      data-testid={triggerTestId}
      aria-label={name} title={toolbarMenuTitle(name, badge, badgeNoun)} aria-expanded={open} aria-haspopup="dialog" onClick={() => {
        const rect = trigger.current!.getBoundingClientRect();
        const win = trigger.current!.ownerDocument.defaultView;
        setPosition(menuPanelPosition(rect, { innerWidth: win?.innerWidth ?? 400, innerHeight: win?.innerHeight ?? 800 }));
        setOpen(value => !value);
      }}>{triggerContent ?? <>{label} ▾</>}<ToolbarMenuBadge badge={badge} /></button>
    {createPortal(<MenuVisibility.Provider value={open}>
      <div ref={panel} className="toolbar-menu__panel" role="dialog" hidden={!open}
        aria-label={name} tabIndex={-1} style={position}
        onClick={event => {
          const target = event.target as Element;
          if (target.closest('[role="tab"]')) { setOpen(false); trigger.current?.focus(); }
          // An action that opens something of its own (a rename field, a dialog) keeps the focus it moves.
          else if (closeOnAction && target.closest("button, a[href]")) setOpen(false);
        }}>
        {children}
      </div>
    </MenuVisibility.Provider>, container)}
  </>;
}

/**
 * A labelled group inside a menu panel (menu redesign wave 7: Collaboration, Clipboard, View, Recording,
 * Connection...). It is a named `group` for assistive tech, and the heading is drawn for sighted users.
 * Children that render nothing (a control the session does not offer) leave the group empty, and CSS hides an
 * empty group, so an observer never sees a heading over nothing. Children are never wrapped or re-keyed, so
 * their state and test ids are unchanged. In a menu drawn inline (a pop-out window's toolbar row) it adds nothing.
 */
export function MenuSection({ title, testId, children }: { title: string; testId?: string; children: ReactNode }) {
  const inline = useContext(MenuInline);
  if (inline) return <>{children}</>;
  return (
    <div className="menu-section" role="group" aria-label={title} data-testid={testId}>
      <span className="menu-section__title" aria-hidden="true">{title}</span>
      {children}
    </div>
  );
}

/** Move a stable portal container, not its React subtree, when entering fullscreen. */
export function ToolbarDock({ target, children, inline = false }: { target?: HTMLElement | null; children: ReactNode; inline?: boolean }) {
  const anchor = useRef<HTMLDivElement>(null);
  const [container] = useState(() => { const el = document.createElement("div"); el.className = "toolbar-dock"; return el; });
  useLayoutEffect(() => {
    if (inline) return;
    (target ?? anchor.current)?.appendChild(container);
    return () => { container.remove(); };
  }, [target, container, inline]);
  if (inline) return <>{children}</>;
  return <><div ref={anchor} className="toolbar-dock" />{createPortal(children, container)}</>;
}
