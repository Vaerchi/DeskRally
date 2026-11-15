import { expect, type Page } from "@playwright/test";

/**
 * The "Connect by device ID" form is folded behind one link in the machine panel (Ed, 2026-11-07). Specs that connect
 * through the form open it first. Idempotent: once open, the link is gone and this does nothing.
 *
 * It WAITS for either the link or the form before deciding: an instant isVisible() check right after page.goto can run
 * before the panel has rendered, find neither, and then wait on a link that was never going to be the right target.
 */
export async function openManualConnect(page: Page): Promise<void> {
  const form = page.getByTestId("manual-device");
  const toggle = page.getByTestId("manual-toggle");
  await expect(form.or(toggle)).toBeVisible();
  if (await form.isVisible()) return;
  await toggle.click();
  await expect(form).toBeVisible();
}
