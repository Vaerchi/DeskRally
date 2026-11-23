/**
 * Platform operator: the public join-page branding review (docs/66 2a.7, 2k), with the API mocked.
 *
 *   1. The review renders the draft in the REAL JoinBrand at phone and at desktop width (two documents of exactly
 *      those widths), with the hostname and the contact destination shown literally beside them; a link inside the
 *      preview goes nowhere.
 *   2. Approve is refused until every finding is acknowledged AND a reason is given; the request carries the ids,
 *      hash and generation the review returned plus the acknowledged codes and the reason.
 *   3. A 409 stale reads "the tenant changed something since you opened this review: reload", blocks Approve until
 *      the review is reloaded, and the next approval carries the NEW ids; a 409 findings lists the server's findings.
 *   4. Withdraw needs a reason. Every change goes through the second-factor check like suspend does.
 *
 * Mocked API, loopback only; named supervisor_* so the mocked profile runs it.
 */
import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { mountPlatform, ACME } from "./platform_mock";
import { expectInertLink } from "./preview_inert";

const REV1 = "11111111-1111-4111-8111-111111111111";
const REV2 = "44444444-4444-4444-8444-444444444444";
const ASG = "22222222-2222-4222-8222-222222222222";
const HASH1 = "ab".repeat(32);
const HASH2 = "cd".repeat(32);
// A real 1x1 PNG.
const PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

const FINDINGS = [
  { code: "mixed_script", message: "the name mixes scripts" },
  { code: "brand_denylist", message: "the name resembles a denylisted brand" },
];

function reviewBody(over: { rev?: string; hash?: string; gen?: number; findings?: typeof FINDINGS; contact?: { kind: string; value: string }; published?: boolean } = {}) {
  const rev = over.rev ?? REV1;
  return {
    review: {
      tenant_id: ACME.id,
      draft: {
        id: rev,
        seq: 3,
        product_name: "Acme IT",
        accent_color: "#1d4ed8",
        support_text: "Call us first.\nWe are open 9 to 5.",
        support_contact: over.contact ?? { kind: "email", value: "help@acme.example.test" },
        logo_sha256: "0".repeat(64),
        has_logo: true,
        normalized_hash: over.hash ?? HASH1,
        created_by: "owner@acme.example.test",
        created_at: "2026-11-05T10:00:00Z",
      },
      published_revision_id: over.published ? rev : "",
      published_revision_hash: over.published ? (over.hash ?? HASH1) : "",
      published_assignment_id: over.published ? ASG : "",
      assignment: { id: ASG, host: "acme.example.test", state: "active" },
      review_generation: over.gen ?? 7,
    },
    logo_png_base64: PNG_B64,
    findings: over.findings ?? [],
  };
}

interface State {
  review: ReturnType<typeof reviewBody>;
  /** What the next approve answers: ok, or a 409. */
  approve: "ok" | "stale" | "findings";
  approveBodies: unknown[];
  withdrawBodies: unknown[];
  reviewReads: number;
  /** When set, a review read that arrives while it is set waits for it. */
  gate?: Promise<void> | null;
}

async function open(page: Page, st: State, me?: Parameters<typeof mountPlatform>[2]) {
  const mock = await mountPlatform(
    page,
    async (url, method, route) => {
      if (url.pathname === `/cp/platform/tenants/${ACME.id}/branding/review` && method === "GET") {
        st.reviewReads++;
        const gate = st.gate;
        if (gate) await gate;
        await route.fulfill({ json: st.review });
        return true;
      }
      if (url.pathname === `/cp/platform/tenants/${ACME.id}/branding/approve` && method === "POST") {
        st.approveBodies.push(route.request().postDataJSON());
        if (st.approve === "stale") {
          await route.fulfill({ status: 409, json: { error: "review is stale: reload", code: "stale" } });
        } else if (st.approve === "findings") {
          await route.fulfill({
            status: 409,
            json: { error: "the review has findings", code: "findings", findings: [...FINDINGS, { code: "skeleton_collision", message: "new since the review" }] },
          });
        } else {
          await route.fulfill({ json: { published: { revision_id: REV1 } } });
        }
        return true;
      }
      if (url.pathname === `/cp/platform/tenants/${ACME.id}/branding/withdraw` && method === "POST") {
        st.withdrawBodies.push(route.request().postDataJSON());
        await route.fulfill({ json: { withdrawn: true } });
        return true;
      }
      return false;
    },
    me,
  );
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-row-acme")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("platform-branding-acme").click();
  await expect(page.getByTestId("review-root")).toBeVisible();
  return mock;
}

const fresh = (review: ReturnType<typeof reviewBody>, approve: State["approve"] = "ok"): State => ({
  review,
  approve,
  approveBodies: [],
  withdrawBodies: [],
  reviewReads: 0,
});

const phone = (page: Page) => page.frameLocator('iframe[title="Join page as a guest sees it, phone width"]');
const desktop = (page: Page) => page.frameLocator('iframe[title="Join page as a guest sees it, desktop width"]');

test("the review renders the real join page at phone and desktop width, with hostname and contact shown literally", async ({ page }) => {
  await open(page, fresh(reviewBody()));

  for (const [label, frame, width] of [
    ["phone", phone(page), 390],
    ["desktop", desktop(page), 1100],
  ] as const) {
    const root = frame.getByTestId("join-root");
    await expect(root, label).toHaveAttribute("data-brand-state", "branded");
    await expect(frame.getByTestId("join-brand-name"), label).toHaveText("Acme IT");
    await expect(frame.getByTestId("join-brand-text"), label).toContainText("Call us first.");
    // An email is shown as text and is never a link (docs/66 2a.7).
    await expect(frame.getByTestId("join-brand-contact"), label).toContainText("help@acme.example.test");
    await expect(frame.getByTestId("join-brand-contact").locator("a"), label).toHaveCount(0);
    // The fixed attribution links to the DEFAULT host, whatever the tenant's own.
    await expect(frame.getByTestId("join-attribution").locator("a"), label).toHaveAttribute("href", "https://default.example.test/docs");
    // The logo is the draft's own bytes, decoded.
    await expect(frame.getByTestId("join-brand-logo"), label).toHaveAttribute("data-state", "ok");
    // The frame IS a document of that width.
    expect(await page.locator(`iframe[title*="${label} width"]`).evaluate((el) => (el as HTMLIFrameElement).contentWindow!.innerWidth), label).toBe(width);
  }
  // The fixed lede is on the page the operator reviews, as for a guest.
  await expect(phone(page).locator(".join__lede")).toContainText("Do this only if YOU called your IT provider");

  await expect(page.getByTestId("review-hostname")).toContainText("acme.example.test");
  await expect(page.getByTestId("review-hostname")).toContainText("active");
  await expect(page.getByTestId("review-contact")).toContainText("help@acme.example.test");
  await expect(page.getByTestId("review-contact")).toContainText("email");
  await expect(page.getByTestId("review-no-findings")).toBeVisible();
  await expect(page.getByTestId("review-approve")).toBeEnabled();
});

test("a link in the preview goes nowhere", async ({ page }) => {
  const contact = "https://help.acme.example.test/support";
  await open(page, fresh(reviewBody({ contact: { kind: "url", value: contact } })));
  await expectInertLink(page, phone(page), 'iframe[title="Join page as a guest sees it, phone width"]', contact);
  await expect(page.getByTestId("review-contact")).toContainText(contact);
  await expect(page.getByTestId("review-root")).toBeVisible();
});

test("approve is refused until every finding is acknowledged and a reason is given", async ({ page }) => {
  const st = fresh(reviewBody({ findings: FINDINGS, gen: 9 }));
  await open(page, st);
  const approve = page.getByTestId("review-approve");
  await expect(page.getByTestId("review-findings")).toContainText("mixed_script");
  await expect(approve).toBeDisabled();
  await expect(page.getByTestId("review-block")).toContainText("Acknowledge every finding");

  await page.getByTestId("review-ack-mixed_script").check();
  await expect(approve).toBeDisabled(); // one of two
  await page.getByTestId("review-ack-brand_denylist").check();
  await expect(approve).toBeDisabled(); // acknowledged, but no reason
  await expect(page.getByTestId("review-block")).toContainText("override reason");
  await page.getByTestId("review-reason").fill("   ");
  await expect(approve).toBeDisabled(); // a blank reason is not a reason
  await page.getByTestId("review-reason").fill("customer verified by phone");
  await expect(approve).toBeEnabled();
  expect(st.approveBodies).toHaveLength(0);

  await approve.click();
  await expect(page.getByTestId("review-notice")).toContainText("Approved");
  expect(st.approveBodies).toEqual([
    {
      revision_id: REV1,
      normalized_hash: HASH1,
      assignment_id: ASG,
      review_generation: 9,
      acknowledge: ["mixed_script", "brand_denylist"],
      override_reason: "customer verified by phone",
    },
  ]);
});

test("409 stale says to reload, blocks approve, and the next approval carries the new review", async ({ page }) => {
  const st = fresh(reviewBody({ gen: 7 }), "stale");
  await open(page, st);
  await page.getByTestId("review-approve").click();
  await expect(page.getByTestId("review-error")).toContainText("The tenant changed something since you opened this review: reload");
  await expect(page.getByTestId("review-approve")).toBeDisabled();
  expect(st.approveBodies).toHaveLength(1);

  // The tenant saved a newer draft; reloading shows it and approving it sends ITS ids.
  st.review = reviewBody({ rev: REV2, hash: HASH2, gen: 8 });
  st.approve = "ok";
  await page.getByTestId("review-stale-reload").click();
  await expect(page.getByTestId("review-error")).toHaveCount(0);
  await expect(page.getByTestId("review-approve")).toBeEnabled();
  await page.getByTestId("review-approve").click();
  await expect(page.getByTestId("review-notice")).toContainText("Approved");
  expect(st.approveBodies[1]).toMatchObject({ revision_id: REV2, normalized_hash: HASH2, review_generation: 8 });
});

test("409 findings lists the findings the server returned and resets the acknowledgements", async ({ page }) => {
  const st = fresh(reviewBody({ findings: FINDINGS }), "findings");
  await open(page, st);
  await page.getByTestId("review-ack-mixed_script").check();
  await page.getByTestId("review-ack-brand_denylist").check();
  await page.getByTestId("review-reason").fill("checked");
  await page.getByTestId("review-approve").click();
  await expect(page.getByTestId("review-error")).toHaveAttribute("data-kind", "findings");
  await expect(page.getByTestId("review-error-findings")).toContainText("skeleton_collision");
  // The new finding is acknowledgeable and nothing stays acknowledged from before.
  await expect(page.getByTestId("review-ack-skeleton_collision")).not.toBeChecked();
  await expect(page.getByTestId("review-ack-mixed_script")).not.toBeChecked();
  await expect(page.getByTestId("review-approve")).toBeDisabled();
});

test("withdraw needs a reason and sends it", async ({ page }) => {
  const st = fresh(reviewBody({ published: true }));
  await open(page, st);
  await expect(page.getByTestId("review-published")).toContainText("this revision");
  await expect(page.getByTestId("review-approve")).toBeDisabled(); // already published for this hostname
  await page.getByTestId("review-withdraw-open").click();
  await expect(page.getByTestId("review-withdraw")).toContainText("neutral");
  const submit = page.getByTestId("review-withdraw-submit");
  await expect(submit).toBeDisabled();
  await page.getByTestId("review-withdraw-reason").fill("  ");
  await expect(submit).toBeDisabled();
  await page.getByTestId("review-withdraw-reason").fill("impersonation report");
  await expect(submit).toBeEnabled();
  st.review = reviewBody({ published: false });
  await submit.click();
  await expect(page.getByTestId("review-notice")).toContainText("Withdrawn");
  expect(st.withdrawBodies).toEqual([{ reason: "impersonation report" }]);
  await expect(page.getByTestId("review-withdraw-open")).toHaveCount(0);
});

test("approve asks for the second-factor code first, like suspend, and is then sent once", async ({ page }) => {
  const st = fresh(reviewBody());
  const mock = await open(page, st, { operator: true, mfa_ok: true, mfa_fresh: false });
  await page.getByTestId("review-approve").click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  expect(st.approveBodies).toHaveLength(0);
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => st.approveBodies.length).toBe(1);
  await expect(page.getByTestId("review-notice")).toContainText("Approved");
  expect(mock.stepUps).toEqual(["123456"]);
});

test("access that expires while a review is open removes it, and a read still in flight cannot bring it back", async ({ page }) => {
  const st = fresh(reviewBody());
  const mock = await open(page, st);
  await expect(phone(page).getByTestId("join-root")).toBeVisible();
  let release!: () => void;
  st.gate = new Promise<void>((r) => (release = r));
  const reads = st.reviewReads;
  await page.getByTestId("review-reload").click();
  await expect.poll(() => st.reviewReads).toBe(reads + 1);
  mock.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).last().click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(page.getByTestId("review-root")).toHaveCount(0);
  await expect(page.getByTestId("platform-row-acme")).toHaveCount(0);
  st.gate = null;
  release();
  await page.waitForTimeout(300);
  await expect(page.getByTestId("review-root")).toHaveCount(0);
  await expect(page.locator("iframe")).toHaveCount(0);
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("platform-row-acme")).toBeVisible();
  await expect(page.getByTestId("review-root")).toHaveCount(0);
});

test("access that is revoked while a review is open removes it", async ({ page }) => {
  const mock = await open(page, fresh(reviewBody()));
  mock.me = { operator: false, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).last().click();
  await expect(page.getByTestId("platform-not-operator")).toBeVisible();
  await expect(page.getByTestId("review-root")).toHaveCount(0);
});
