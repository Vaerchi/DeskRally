import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/*", (route) => new URL(route.request().url()).origin === "http://127.0.0.1:5173"
    ? route.continue() : route.abort());
});

test("one group starts without copying IDs, and connection still waits for guest consent", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/e2e/support_flow.html");
  await expect(page.getByTestId("attended-group")).toHaveValue("test-group");
  await page.getByRole("button", { name: "Start support session" }).click();
  expect(await page.evaluate(() => (window as any).supportRequests)).toEqual(["test-group"]);
  await expect(page.getByTestId("attended-join-url")).toHaveAttribute("href", "/join#0123456789ABC");
  await expect(page.getByTestId("attended-connect")).toBeDisabled();
  await page.evaluate(() => (window as any).supportConsent());
  await expect(page.getByTestId("attended-connect")).toBeEnabled();
});

test("multiple groups require a deliberate selection by name", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/e2e/support_flow.html?mode=multiple");
  await expect(page.getByTestId("attended-start")).toBeDisabled();
  await page.getByTestId("attended-group").selectOption({ label: "Work computers" });
  await page.getByTestId("attended-start").click();
  expect(await page.evaluate(() => (window as any).supportRequests)).toEqual(["work-group"]);
});

for (const mode of ["empty", "error"]) {
  test(`missing groups cannot mint a session (${mode})`, async ({ page }) => {
    await page.goto(`http://127.0.0.1:5173/e2e/support_flow.html?mode=${mode}`);
    await expect(page.getByText(mode === "error" ? "Could not load machine groups." : "Create a machine group", { exact: false })).toBeVisible();
    await expect(page.getByTestId("attended-start")).toBeDisabled();
    expect(await page.evaluate(() => (window as any).supportRequests)).toEqual([]);
  });
}

test("guest steps follow the native code-before-consent sequence", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/e2e/support_flow.html?mode=join");
  const headings = await page.locator(".join__stephead").allTextContents();
  expect(headings).toEqual([
    "1 Get the DeskRally support client", "2 Open the client and enter your code", "3 Approve screen sharing",
  ]);
  await expect(page.getByTestId("join-code")).toHaveText("0123-4567-89AB-C");
  await expect(page.getByTestId("join-download-link")).toHaveAttribute("href", "/download/DeskRallySupport.exe");
});

test("preconfigured installer is minted only on click and saved without displaying a token", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/e2e/support_flow.html?mode=installer");
  expect(await page.evaluate(() => (window as any).supportRequests)).toEqual([]);
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download Windows installer" }).click();
  const file = await downloaded;
  expect(file.suggestedFilename()).toBe("DeskRally-Install.zip");
  expect(await page.evaluate(() => (window as any).supportRequests)).toEqual(["test-group"]);
  await expect(page.getByRole("status")).toContainText("Extract all files");
});
