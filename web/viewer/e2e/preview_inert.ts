/**
 * Shared by the specs of both join-page previews (the Owner's editor and the operator's review, docs/66 2l): proves the
 * preview frame's OWN link handler cancels a click, which the iframe sandbox and a mock that aborts external requests
 * would otherwise hide (they stop a navigation even when the handler is gone).
 */
import { expect, type FrameLocator, type Page } from "@playwright/test";

/** `frame` and `frameSelector` name the same preview iframe; the link is the contact link of the join page in it. */
export async function expectInertLink(page: Page, frame: FrameLocator, frameSelector: string, destination: string): Promise<void> {
  const link = frame.getByTestId("join-brand-contact").locator("a");
  await expect(link).toHaveAttribute("href", destination);
  const origin = new URL(destination).origin;
  const requests: string[] = [];
  page.on("request", (r) => requests.push(r.url()));
  let popups = 0;
  page.on("popup", () => popups++);
  const before = page.url();
  // defaultPrevented is read from a bubble-phase listener on the same document, which runs after the frame's own
  // capture-phase handler: without that handler it reads false.
  const seen = await page.locator(frameSelector).evaluate((el) => {
    const doc = (el as HTMLIFrameElement).contentDocument!;
    const a = doc.querySelector('[data-testid="join-brand-contact"] a')!;
    const out: Record<string, boolean> = {};
    for (const type of ["click", "auxclick"]) {
      let prevented = false;
      const read = (e: Event) => {
        prevented = e.defaultPrevented;
      };
      doc.addEventListener(type, read);
      a.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, button: type === "auxclick" ? 1 : 0 }));
      doc.removeEventListener(type, read);
      out[type] = prevented;
    }
    return out;
  });
  expect(seen).toEqual({ click: true, auxclick: true });
  // A real click as well: nothing opens, nothing navigates, nothing is requested at the destination.
  await link.click();
  await page.waitForTimeout(300);
  expect(popups).toBe(0);
  expect(page.url()).toBe(before);
  expect(requests.filter((u) => u.startsWith(origin))).toEqual([]);
  // The preview document and its join root are still there.
  await expect(frame.getByTestId("join-root")).toBeVisible();
}
