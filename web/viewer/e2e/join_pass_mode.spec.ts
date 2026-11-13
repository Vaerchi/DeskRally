/**
 * docs/48 C (slice 4): in deployment-pass mode the standalone support exe is GENERIC and refuses
 * to run without the pass that only the session bundle carries, so the join page must offer the
 * bundle only. The server says so on GET /cp/attended-sessions/support-mode.
 *
 * Mutation evidence: rendering the plain-download block regardless of `bundleOnly` fails the first
 * test; treating any truthy value (or a fetch failure) as bundle-only fails the second.
 */
import { test, expect, type Page } from "@playwright/test";

const url = "http://127.0.0.1:5173/e2e/join_pass_mode.html";

async function mode(page: Page, body: string, status = 200) {
  await page.route("**/cp/attended-sessions/support-mode", (route) =>
    route.fulfill({ status, contentType: "application/json", body }));
}

test("pass mode: only the session bundle is offered", async ({ page }) => {
  await mode(page, `{"bundle_only":true}`);
  await page.goto(url);
  await expect(page.getByTestId("join-bundle-btn")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
  await expect(page.getByTestId("join-sha256")).toHaveCount(0);
  // A failed bundle download must not point at a download that is not there.
  await page.route("**/cp/attended-sessions/support-bundle", (route) => route.fulfill({ status: 500, body: "x" }));
  await page.getByTestId("join-bundle-btn").click();
  await expect(page.getByTestId("join-bundle-error")).toContainText("ask your technician");
  await expect(page.getByTestId("join-bundle-error")).not.toContainText("below");
});

test("baked, older server or an error: the page is unchanged", async ({ page }) => {
  for (const [body, status] of [[`{"bundle_only":false}`, 200], [`{"bundle_only":"true"}`, 200], [`{}`, 404], [`not json`, 200]] as const) {
    await page.unroute("**/cp/attended-sessions/support-mode");
    await mode(page, body, status);
    await page.goto(url);
    await expect(page.getByTestId("join-bundle-btn")).toBeVisible();
    await expect(page.getByTestId("join-download-link"), `${status} ${body}`).toBeVisible();
    await expect(page.getByTestId("join-sha256")).toBeVisible();
  }
});

test("pass mode without a code asks for the code instead of offering a download", async ({ page }) => {
  await mode(page, `{"bundle_only":true}`);
  await page.goto(url + "?nocode");
  await expect(page.getByTestId("join-bundle-needs-code")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
});

test("while the mode answer is pending, the standalone exe is not offered", async ({ page }) => {
  for (const answer of [`{"bundle_only":true}`, `{"bundle_only":false}`]) {
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    let asked = false;
    await page.unroute("**/cp/attended-sessions/support-mode");
    await page.route("**/cp/attended-sessions/support-mode", async (route) => {
      asked = true;
      await held;
      await route.fulfill({ status: 200, contentType: "application/json", body: answer });
    });
    await page.goto(url);
    await expect.poll(() => asked).toBe(true);
    await expect(page.getByTestId("join-bundle-btn")).toBeVisible();
    // Held open: the page has rendered, and the plain download must still be absent.
    await page.waitForTimeout(300);
    await expect(page.getByTestId("join-download-link")).toHaveCount(0);
    release();
    if (answer.includes("true")) {
      await page.waitForTimeout(300);
      await expect(page.getByTestId("join-download-link")).toHaveCount(0);
    } else {
      await expect(page.getByTestId("join-download-link")).toBeVisible();
    }
  }
});
