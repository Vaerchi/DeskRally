import { expect, type Page } from "@playwright/test";

/**
 * Menu redesign wave 6: a machine group's policy lives in an editor opened by "Edit policy" under its row.
 * Opens it (a no-op when it is already open) and waits for it. Specs MUST call this before touching any
 * mgroup-viewonly / allowbackstage / recording / cap / maxduration / maxidle / cap-save control.
 */
export async function openGroupPolicy(page: Page, groupId: string) {
  const editor = page.getByTestId(`mgroup-policy-editor-${groupId}`);
  if (!(await editor.isVisible())) await page.getByTestId(`mgroup-policy-edit-${groupId}`).click();
  await expect(editor).toBeVisible();
}

/** Clicks Save policy and waits until the server's copy has been read back ("Saved"). */
export async function saveGroupPolicy(page: Page, groupId: string) {
  await page.getByTestId(`mgroup-cap-save-${groupId}`).click();
  await expect(page.getByTestId(`mgroup-policy-status-${groupId}`)).toHaveText("Saved");
}
