/**
 * Navigation through the single-row App chrome.
 *
 * Console areas, "Connect in", Compact and Sign out live in the "DeskRally" menu, which stays mounted
 * but `hidden` while closed. Hidden elements are not in the accessibility tree, so a spec has to open
 * the menu before it can find them by role. Session views (Screen/Backstage/Files/Chat) are a select.
 * In the docked App, the "Session" menu holds clipboard, collaboration and connection details. The viewer's
 * View panel holds zoom, fullscreen, pan, pop-out and quality; its Tools panel holds Record.
 */
import type { Locator, Page } from "@playwright/test";

/** Menus of the docked App chrome. ("More" went in menu redesign wave 7b: its controls are in the Viewer's
 *  View and Tools panels.) */
export type ToolbarMenuLabel = "DeskRally" | "Session";

function menuTrigger(page: Page, label: ToolbarMenuLabel): Locator {
  return page.getByRole("button", { name: label, exact: true });
}

/** Open a menu. Idempotent: clicking an open trigger would close it again. */
export async function openMenu(page: Page, label: ToolbarMenuLabel): Promise<void> {
  const trigger = menuTrigger(page, label);
  if ((await trigger.getAttribute("aria-expanded")) !== "true") await trigger.click();
}

/** Close a menu if it is open, so its fixed panel cannot cover what the spec clicks next. Uses the
 *  trigger rather than Escape, so no key event reaches a focused remote surface. A trigger that is
 *  gone (the click popped the viewer out, or ended the session) has nothing left to close. */
export async function closeMenu(page: Page, label: ToolbarMenuLabel): Promise<void> {
  const trigger = menuTrigger(page, label);
  if ((await trigger.count()) === 0) return;
  if ((await trigger.getAttribute("aria-expanded")) === "true") await trigger.click();
}

/** Click a control that lives in a menu, then close the menu again. */
export async function clickInMenu(page: Page, label: ToolbarMenuLabel, target: Locator): Promise<void> {
  await openMenu(page, label);
  await target.click();
  await closeMenu(page, label);
}

export const openAppMenu = (page: Page) => openMenu(page, "DeskRally");
export const closeAppMenu = (page: Page) => closeMenu(page, "DeskRally");

/** Menu redesign wave 10b: "Signed in as", My account, Help, Downloads and Sign out are in the Account menu at the page
 *  bar's right end outside a live session on a screen wider than 600px, and in the DeskRally menu otherwise (in a
 *  session, or on a phone). Opens whichever of the two holds them right now. */
export async function openAccountControls(page: Page): Promise<void> {
  // Wait for the signed-in top bar first: right after a navigation neither trigger exists yet, and checking for the
  // Account trigger then would wrongly fall back to the DeskRally menu (the gate's one flaky run, 2026-11-09). The
  // bar's right end is drawn in the same render as the DeskRally trigger, so once that is visible the answer is final.
  await menuTrigger(page, "DeskRally").waitFor({ state: "visible" });
  const account = page.getByTestId("area-bar-account");
  if ((await account.count()) === 0) return openAppMenu(page);
  if ((await account.getAttribute("aria-expanded")) !== "true") await account.click();
}

/** A console-area tab, with the app menu opened first. Clicking a tab closes the menu. */
export async function consoleTab(page: Page, options: { name: string | RegExp; exact?: boolean }): Promise<Locator> {
  await openAppMenu(page);
  return page.getByRole("tab", options);
}

/** Choose "Connect in" (desktop or browser), then close the menu. */
export async function setConnectIn(page: Page, value: "desktop" | "browser"): Promise<void> {
  await openAppMenu(page);
  await page.getByRole("combobox", { name: "Connect in", exact: true }).selectOption(value);
  await closeAppMenu(page);
}

/** Open the Viewer's View/Input/Tools dropdown panel. These panels predate the single-row chrome and
 *  render their controls only while open (Files, Command and Screenshot live in Tools). */
export async function openViewerPanel(page: Page, panel: "view" | "input" | "tools"): Promise<void> {
  const trigger = page.getByTestId(`viewer-${panel}-menu`);
  if ((await trigger.getAttribute("aria-expanded")) !== "true") await trigger.click();
}

/** Close a View/Input/Tools panel if it is open (a trigger that is gone has nothing to close). */
export async function closeViewerPanel(page: Page, panel: "view" | "input" | "tools"): Promise<void> {
  const trigger = page.getByTestId(`viewer-${panel}-menu`);
  if ((await trigger.count()) === 0) return;
  if ((await trigger.getAttribute("aria-expanded")) === "true") await trigger.click();
}

/** Click a control in a View/Input/Tools panel, then close the panel again (some controls close it
 *  themselves: Pan when turned on, Pop out). Menu redesign wave 7b moved zoom, Fit, 1:1, Pan, Full screen,
 *  Pop out, monitor windows and the quality readout from "More" to View, and Record to Tools. */
export async function clickInViewerPanel(page: Page, panel: "view" | "input" | "tools", target: Locator): Promise<void> {
  await openViewerPanel(page, panel);
  await target.click();
  await closeViewerPanel(page, panel);
}

/** Click "Pop out", which is in the View panel since menu redesign wave 7b (it closes the panel itself). */
export async function clickPopOut(page: Page): Promise<void> {
  await openViewerPanel(page, "view");
  await page.getByTestId("viewer-popout").click();
}

/** Switch the live session view. */
export async function selectSessionView(page: Page, view: "Screen" | "Under the Hood" | "Files" | "Chat"): Promise<void> {
  await page.getByRole("combobox", { name: "Session view", exact: true }).selectOption({ label: view });
}
