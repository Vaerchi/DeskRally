import { test, expect } from "@playwright/test";

test.beforeEach(async ({page}) => {
  await page.route("**/*", async route => {
    const url = new URL(route.request().url());
    if (!["127.0.0.1", "localhost"].includes(url.hostname)) return route.abort();
    if (url.pathname.startsWith("/cp/")) return route.fulfill({status:401,json:{error:"unauthorized"}});
    return route.continue();
  });
});

test("signed-out home leads with download and code entry; sign-in is separate", async ({page}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", {name:"Get remote support"})).toBeVisible();
  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
  await page.screenshot({path:test.info().outputPath("support-home-desktop.png"),fullPage:true});
  const download = page.getByTestId("join-download-link");
  if (test.info().project.metadata.supportDownloadExpected || await download.count()) {
    await expect(download).toHaveAttribute("href", "/download/DeskRallySupport.exe");
  } else {
    await expect(page.getByTestId("join-download-unavailable")).toBeVisible();
  }
  await page.getByLabel("Session code", {exact:true}).fill("01234-56789-ABC");
  await page.getByRole("button", {name:"Continue", exact:true}).click();
  await expect(page).toHaveURL(/\/join#0123456789ABC$/);
  await expect(page.getByTestId("join-code")).toHaveAttribute("data-code", "0123456789ABC");
  await expect(page.getByTestId("join-launch")).toHaveAttribute("href", /code=0123456789ABC/);
  await page.getByRole("link", {name:"Technician sign in"}).click();
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
});

test("invalid codes cannot enter launch links or commands", async ({page}) => {
  await page.goto("/join#bad%3Bcommand");
  await expect(page.getByTestId("join-copy")).toBeDisabled();
  await page.getByLabel("Session code", {exact:true}).fill("abc; malicious");
  await page.getByRole("button", {name:"Continue", exact:true}).click();
  await expect(page.getByRole("alert")).toContainText("13-character");
  await expect(page.getByTestId("join-launch")).toHaveCount(0);
  await expect(page.getByTestId("join-command")).not.toContainText("malicious");
});

test("support links prefill code and mobile layout fits", async ({page}) => {
  await page.setViewportSize({width:390,height:844});
  await page.goto("/join#0123456789ABC");
  await expect(page.getByLabel("Session code", {exact:true})).toHaveValue("0123456789ABC");
  await expect(page.getByRole("heading", {name:"Approve screen sharing"})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({path:test.info().outputPath("support-home-mobile.png"),fullPage:true});
});
