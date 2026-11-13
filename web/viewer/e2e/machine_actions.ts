/**
 * A machine row's actions (menu redesign wave 8). Properties stays on the row; Rename, End session, Reinstall agent,
 * Remove agent… and Forget this machine… are in the row's "⋯" menu (`machine-actions-<id>`). The menu stays mounted
 * while closed, so `toHaveCount` still says whether an action is offered, but a spec must open the menu before it can
 * see or click one. Choosing an action closes the menu.
 */
import { expect, type Page } from "@playwright/test";

/** Open a machine row's "⋯" menu (idempotent). */
export async function openMachineActions(page: Page, machineId: string): Promise<void> {
  const trigger = page.getByTestId(`machine-actions-${machineId}`);
  if ((await trigger.getAttribute("aria-expanded")) !== "true") await trigger.click();
  await expect(trigger).toHaveAttribute("aria-expanded", "true");
}

/** Close a machine row's "⋯" menu if it is open. */
export async function closeMachineActions(page: Page, machineId: string): Promise<void> {
  const trigger = page.getByTestId(`machine-actions-${machineId}`);
  if ((await trigger.count()) === 0) return;
  if ((await trigger.getAttribute("aria-expanded")) === "true") await trigger.click();
}

/** Click one of a machine row's menu actions by its test id (e.g. `machine-reinstall-<id>`). */
export async function clickMachineAction(page: Page, machineId: string, testId: string): Promise<void> {
  await openMachineActions(page, machineId);
  await page.getByTestId(testId).click();
}

/**
 * The sidebar machine list (menu redesign wave 8b): a row is Connect and "⋯" (`access-actions-<device>`), whose menu
 * holds View only (`observe-<device>`), Open in new tab (`new-tab-<device>`) and End session (`end-session-<device>`).
 */
export async function openAccessActions(page: Page, device: string): Promise<void> {
  const trigger = page.getByTestId(`access-actions-${device}`);
  if ((await trigger.getAttribute("aria-expanded")) !== "true") await trigger.click();
  await expect(trigger).toHaveAttribute("aria-expanded", "true");
}

export async function clickAccessAction(page: Page, device: string, testId: string): Promise<void> {
  await openAccessActions(page, device);
  await page.getByTestId(testId).click();
}
