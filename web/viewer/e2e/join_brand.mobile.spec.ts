/**
 * The branded guest join page on a phone and on an unfolded foldable (docs/66 stage 2, 2a.7: "at phone and desktop
 * widths").
 *
 * Runs under the `mobile-phone` (Pixel 7, 412 px, touch) and `mobile-foldable` (700 px) projects of
 * playwright.config.ts, which is why this file is named `*.mobile.spec.ts`; the `desktop` project ignores it. It uses
 * the `page` FIXTURE, never `chromium.launch()`, so the device profile (viewport, touch, mobile) really applies.
 *
 * The public branding route is answered by Playwright, so no Go binary is involved. The desktop half, the host-keyed
 * real-server half and the full set of failure modes are in join_brand.spec.ts and join_brand_host.spec.ts.
 */
import { test, expect, type Page } from "@playwright/test";

const JOIN = "/join#ABCD2345";

const BRAND = {
  product_name: "Acme IT Support and Remote Maintenance Services",
  accent_color: "#1d4ed8",
  logo_rev: "",
  support_text: "Call us first.\nWe are open 9 to 5, Monday to Friday.\nOut of hours: leave a message.",
  support_contact: { kind: "url", value: `https://help.example.com/${"abcdefghij".repeat(10)}` },
};

async function serve(page: Page, body: unknown) {
  await page.route((u) => u.pathname === "/cp/public/branding", async (route) => {
    try {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    } catch { /* abandoned by the page (StrictMode's first effect) */ }
  });
}

test("a branded page fits the screen, keeps the lede first and unobscured, and wraps tenant text", async ({ page }) => {
  await serve(page, BRAND);
  await page.goto(JOIN);
  await expect(page.getByTestId("join-root")).toHaveAttribute("data-brand-state", "branded");
  await expect(page.getByTestId("join-brand-name")).toHaveText(BRAND.product_name);

  const m = await page.evaluate(() => {
    const vw = window.innerWidth;
    const box = (sel: string) => {
      const el = document.querySelector(sel) as HTMLElement;
      el.scrollIntoView({ block: "center" });
      const r = el.getBoundingClientRect();
      const probe = document.elementFromPoint(r.left + Math.min(r.width / 2, 40), r.top + r.height / 2);
      return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, height: r.height, unobscured: !!probe && el.contains(probe) };
    };
    return {
      vw,
      overflowX: document.documentElement.scrollWidth - vw,
      lede: box(".join__lede"),
      message: box('[data-testid="join-brand-message"]'),
      contact: box('[data-testid="join-brand-contact"]'),
      attribution: box('[data-testid="join-attribution"]'),
    };
  });
  expect(m.overflowX, "no horizontal scroll").toBeLessThanOrEqual(0);
  for (const key of ["lede", "message", "contact", "attribution"] as const) {
    expect(m[key].left, `${key} left`).toBeGreaterThanOrEqual(0);
    expect(m[key].right, `${key} right`).toBeLessThanOrEqual(m.vw);
    expect(m[key].unobscured, `${key} is not covered by anything`).toBe(true);
  }

  // Document order is visual order here (one column): the lede, then the tenant's message, then the attribution.
  const order = await page.evaluate(() => {
    const y = (sel: string) => (document.querySelector(sel) as HTMLElement).getBoundingClientRect().top + window.scrollY;
    return [y(".join__lede"), y('[data-testid="join-brand-message"]'), y('[data-testid="join-attribution"]')];
  });
  expect(order[0]!).toBeLessThan(order[1]!);
  expect(order[1]!).toBeLessThan(order[2]!);

  // The long name stays on ONE line in the top bar (ellipsis), not a wall.
  const name = await page.getByTestId("join-brand-name").boundingBox();
  expect(name!.height).toBeLessThan(40);
});

test("a failed lookup leaves the ordinary join page on a phone", async ({ page }) => {
  await page.route((u) => u.pathname === "/cp/public/branding", (route) => route.abort("failed"));
  await page.goto(JOIN);
  await expect(page.getByTestId("join-root")).toHaveAttribute("data-brand-state", "neutral");
  await expect(page.getByTestId("join-brand-name")).toHaveText("DeskRally");
  await expect(page.getByTestId("join-brand-message")).toHaveCount(0);
  await expect(page.getByTestId("join-attribution")).toHaveCount(0);
  await expect(page.getByTestId("join-code")).toHaveAttribute("data-code", "ABCD2345");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("the worst case of every tenant string fits without horizontal scroll", async ({ page }) => {
  await serve(page, {
    product_name: "WWWW MMMM ".repeat(10).trim(), // the widest name the server accepts
    accent_color: "#000000",
    logo_rev: "",
    support_text: `${"abcdefghijklmnopqrstuvwxyz0123456789".repeat(8).slice(0, 280)}`,
    support_contact: { kind: "email", value: `${"a".repeat(30)}.${"b".repeat(30)}@${"c".repeat(40)}.example.com` },
  });
  await page.goto(JOIN);
  await expect(page.getByTestId("join-root")).toHaveAttribute("data-brand-state", "branded");
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
  await expect(page.locator(".join__lede")).toBeVisible();
  await expect(page.getByTestId("join-brand-contact")).toBeVisible();
});

// The server's real maximum: 100 runes (control-plane/brandtext.go BrandNameMaxRunes), no run of more than 4 identical
// characters, no spaces: one unbroken 100-character word. Both the top bar and the step 1 heading carry it.
const LONG_NAME = "abcdefghij".repeat(10);

test("a 100-character unbroken product name does not overflow the screen, in the top bar or the step heading", async ({ page }) => {
  expect(LONG_NAME).toHaveLength(100);
  await serve(page, { ...BRAND, product_name: LONG_NAME });
  await page.goto(JOIN);
  await expect(page.getByTestId("join-root")).toHaveAttribute("data-brand-state", "branded");
  const m = await page.evaluate(() => {
    document.querySelectorAll("details").forEach((d) => { d.open = true; }); // measure the hidden copies too
    const vw = document.documentElement.clientWidth;
    const rects = [...document.querySelectorAll("bdi")]
      .filter((el) => el.textContent === "abcdefghij".repeat(10))
      .map((el) => { const r = el.getBoundingClientRect(); return { left: r.left, right: r.right, inStep: !!el.closest(".join__stephead") }; });
    return { vw, scrollW: document.documentElement.scrollWidth, bodyScrollW: document.body.scrollWidth, rects };
  });
  expect(m.scrollW, "document scrollWidth <= clientWidth").toBeLessThanOrEqual(m.vw);
  expect(m.bodyScrollW).toBeLessThanOrEqual(m.vw);
  expect(m.rects.some((r) => r.inStep), "the step heading carries the name").toBe(true);
  for (const r of m.rects) {
    expect(r.left).toBeGreaterThanOrEqual(0);
    expect(r.right, `right edge of ${r.inStep ? "step" : "topbar"} name`).toBeLessThanOrEqual(m.vw);
  }
});
