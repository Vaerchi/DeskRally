/**
 * The guest join flow for a first-time customer (operator report 2026-11-13: "when you enter the session code
 * then hit continue it just shows you again"). Continue must visibly move on to step 2; the primary action there is
 * the download (the session bundle when it exists, otherwise the plain download with the code to type), and the
 * custom-URI launch link is a quiet line, not the way in.
 *
 * The fixture (join_flow.tsx) takes the config from the query string so every combination is exercised:
 * bundle on/off x plain download on/off. Production today is bundle OFF, plain download ON.
 */
import { test, expect, type Page } from "@playwright/test";

const url = (q: string) => `http://127.0.0.1:5173/e2e/join_flow.html?${q}`;

async function supportMode(page: Page, bundleOnly = false) {
  await page.route("**/cp/attended-sessions/support-mode", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ bundle_only: bundleOnly }) }));
}

async function continueWith(page: Page, text: string) {
  await page.getByLabel("Session code from your technician").fill(text);
  await page.getByRole("button", { name: "Continue" }).click();
}

test("production shape (plain ON, bundle OFF): Continue moves on to a clear Download button and the code to type", async ({ page }) => {
  await page.goto(url("url=1"));
  const step2 = page.getByTestId("join-step-client");
  await expect(page.getByTestId("join-needs-code")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
  // Let the initial page activity (module loads, the brand lookup) settle, then watch EVERYTHING.
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(300);

  const requests: string[] = [];
  page.on("request", (r) => requests.push(r.url()));
  await continueWith(page, "abcd-2345");

  // Focus moved to the step 2 heading, which is a labelled heading.
  await expect(page.locator("#join-step2")).toBeFocused();
  await expect(page.getByRole("heading", { level: 2, name: /Get the DeskRally support client/ })).toBeVisible();
  await expect(step2).toHaveClass(/join__step--active/);
  await expect(page.getByTestId("join-download-link")).toBeInViewport();
  await expect(page.getByTestId("join-download-link")).toHaveText("Download support client");
  await expect(page.getByTestId("join-download-link")).toHaveAttribute("href", "/download/support/DeskRallySupport.exe");
  await expect(page.getByTestId("join-code")).toHaveText("ABCD-2345");
  await expect(page.getByTestId("join-codecard")).toContainText("When DeskRally Support opens, enter this code");
  await expect(page.getByTestId("join-sha256")).toContainText("ab".repeat(32));
  expect(page.url()).toContain("#ABCD2345");
  // No code-validity oracle: Continue made no network request of any kind (any URL, external included).
  await page.waitForTimeout(500);
  expect(requests).toEqual([]);
  await expect(page.getByTestId("join-bundle-btn")).toHaveCount(0);
});

test("Continue by keyboard: Enter in the field advances and moves focus", async ({ page }) => {
  await page.goto(url("url=1"));
  await page.getByLabel("Session code from your technician").fill("ABCD2345");
  await page.keyboard.press("Enter");
  await expect(page.locator("#join-step2")).toBeFocused();
  // Tab from the heading reaches the download link: the next stop is the action.
  await page.keyboard.press("Tab");
  await expect(page.getByTestId("join-download-link")).toBeFocused();
});

test("an invalid code shows the error, stays on step 1 and does not advance", async ({ page }) => {
  await page.goto(url("url=1"));
  await continueWith(page, "nope");
  await expect(page.getByRole("alert")).toContainText("8-character session code");
  await expect(page.getByLabel("Session code from your technician")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("join-needs-code")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
  await expect(page.locator("#join-step2")).not.toBeFocused();
  // Typing clears the error.
  await page.getByLabel("Session code from your technician").fill("A");
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("the code can be copied", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(url("url=1&code=ABCD2345"));
  await page.getByTestId("join-copy-code").click();
  await expect(page.getByTestId("join-copy-code")).toHaveText("Code copied");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("ABCD2345");
});

test("the launch link is a quiet text link, not the call to action", async ({ page }) => {
  await page.goto(url("url=1&code=ABCD2345"));
  const launch = page.getByTestId("join-launch");
  await expect(launch).toHaveText("Open it with this code");
  await expect(launch).toHaveAttribute("href", /^rmt-[0-9a-f]{16}:\/\/attend\?code=ABCD2345/);
  await expect(launch).not.toHaveClass(/join__action|join__downloadbtn/);
  await expect(page.getByTestId("join-launch-block")).toContainText("Already have DeskRally Support open or installed?");
  const dl = await page.getByTestId("join-download-link").boundingBox();
  const lk = await launch.boundingBox();
  expect(lk!.y).toBeGreaterThan(dl!.y + dl!.height);
  expect(lk!.height).toBeLessThan(dl!.height);
});

test("a code in the link goes straight to step 2 without stealing focus", async ({ page }) => {
  await page.goto(url("url=1&code=ABCD2345"));
  await expect(page.getByTestId("join-download-link")).toBeVisible();
  await expect(page.locator("#join-step2")).not.toBeFocused();
});

test("bundle ON, plain ON: the bundle is the primary button and the plain download is the secondary link", async ({ page }) => {
  await supportMode(page);
  await page.goto(url("bundle=1&url=1&code=ABCD2345"));
  await expect(page.getByTestId("join-bundle-btn")).toHaveText("Download support client");
  await expect(page.getByTestId("join-bundle-step")).toContainText("No code to type");
  await expect(page.getByTestId("join-download-link")).toContainText("Or download the client on its own");
  await expect(page.getByTestId("join-sha256")).toBeVisible();
  await expect(page.getByTestId("join-codecard")).toContainText("If the DeskRally client asks for a code");
  let body = "";
  await page.route("**/cp/attended-sessions/support-bundle", (route) => {
    body = route.request().postData() ?? "";
    return route.fulfill({ status: 200, contentType: "application/zip", body: "PK" });
  });
  const dl = page.waitForEvent("download");
  await page.getByTestId("join-bundle-btn").click();
  expect((await dl).suggestedFilename()).toBe("DeskRally-Support.zip");
  expect(JSON.parse(body)).toEqual({ code: "ABCD2345" });
});

test("bundle ON but the server has none (503): falls back to the plain download and says so", async ({ page }) => {
  await supportMode(page);
  await page.route("**/cp/attended-sessions/support-bundle", (route) => route.fulfill({ status: 503, body: "no" }));
  await page.goto(url("bundle=1&url=1&code=ABCD2345"));
  await page.getByTestId("join-bundle-btn").click();
  await expect(page.getByTestId("join-bundle-unavailable")).toBeVisible();
  await expect(page.getByTestId("join-bundle-btn")).toHaveCount(0);
  await expect(page.getByTestId("join-download-link")).toHaveText("Download support client");
  await expect(page.getByTestId("join-codecard")).toContainText("When DeskRally Support opens, enter this code");
});

test("bundle ON, plain OFF: the bundle button is offered on its own", async ({ page }) => {
  await supportMode(page);
  await page.goto(url("bundle=1&code=ABCD2345"));
  await expect(page.getByTestId("join-bundle-btn")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
  await expect(page.getByTestId("join-download-unavailable")).toHaveCount(0);
});

test("bundle OFF, plain OFF: no download is offered, the code and the command line path are", async ({ page }) => {
  await page.goto(url("code=ABCD2345"));
  await expect(page.getByTestId("join-download-unavailable")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
  await expect(page.getByTestId("join-bundle-btn")).toHaveCount(0);
  await expect(page.getByTestId("join-code")).toHaveText("ABCD-2345");
  await expect(page.getByTestId("join-launch")).toBeVisible();
  await page.getByTestId("join-advanced").locator("summary").click();
  await expect(page.getByTestId("join-command")).toContainText("--code ABCD2345");
});

test("a non-Windows visitor is told the client is for Windows", async ({ page }) => {
  await page.goto(url("url=1&platform=other&code=ABCD2345"));
  await expect(page.getByTestId("join-unsupported")).toBeVisible();
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
});

test("the technician warnings are still on the page next to the download", async ({ page }) => {
  await page.goto(url("url=1&code=ABCD2345"));
  await page.getByText("If Windows or your browser gets in the way").click();
  await expect(page.getByText("Do not bypass a security warning")).toBeVisible();
  await expect(page.getByText("We will never ask you to turn off your antivirus")).toBeVisible();
});

test("bundle ON, plain OFF, 503: no 'download below' is promised; the guest is told to ask their technician", async ({ page }) => {
  await supportMode(page);
  await page.route("**/cp/attended-sessions/support-bundle", (route) => route.fulfill({ status: 503, body: "no" }));
  await page.goto(url("bundle=1&code=ABCD2345"));
  await page.getByTestId("join-bundle-btn").click();
  const note = page.getByTestId("join-bundle-unavailable");
  await expect(note).toContainText("Ask your technician for help");
  await expect(note).not.toContainText("download below");
  await expect(page.getByTestId("join-download-link")).toHaveCount(0);
});

for (const bundle of ["bundle=1&", ""]) {
  test(`non-Windows visitor with plain download OFF (${bundle ? "bundle on" : "bundle off"}) still gets the Windows-only note`, async ({ page }) => {
    await supportMode(page);
    await page.goto(url(`${bundle}platform=other&code=ABCD2345`));
    await expect(page.getByTestId("join-unsupported")).toBeVisible();
    await expect(page.getByTestId("join-bundle-btn")).toHaveCount(0);
    await expect(page.getByTestId("join-download-link")).toHaveCount(0);
    await expect(page.getByTestId("join-download-unavailable")).toHaveCount(0);
  });
}
