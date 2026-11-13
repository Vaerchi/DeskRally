/**
 * The console's preview of the join page (docs/66 2j, 2l). Its whole point is that it IS the join page's component, shown
 * through the one frame the operator's review uses, so the tests render the page the frame holds and look for what only
 * `JoinBrand` produces, and scan the sources for a copy or a second mechanism.
 */

import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { JoinPreview, type JoinPreviewProps } from "./JoinPreview";
import { PREVIEW_WIDTHS, PreviewJoinPage, previewFrameTitle, type PreviewJoinPageProps } from "./JoinPreviewPage";
import { NEUTRAL_BRAND, type HostBrand } from "../lib/host_branding";
import joinPreviewSource from "./JoinPreview.tsx?raw";
import previewPageSource from "./JoinPreviewPage.tsx?raw";
import reviewSource from "./PlatformBrandingReview.tsx?raw";
import joinPageSource from "./JoinPage.tsx?raw";
import publicJoinSource from "./PublicJoinSection.tsx?raw";
import appearanceSource from "./AppearancePanel.tsx?raw";
import joinBrandSource from "./JoinBrand.tsx?raw";

const ORIGIN = "https://main.deskrally.com";
const BRAND: HostBrand = {
  name: "Acme IT",
  accent: "#1d4ed8",
  logoRev: "",
  supportText: "Call us first.",
  contact: { kind: "phone", value: "442079460958" },
};

// The page the preview frame holds. (The frame's content arrives through a portal after mount, which a server render does
// not run, so the page is rendered directly; the frame's use is pinned by the source checks below.)
const page = (over: Partial<PreviewJoinPageProps> = {}) =>
  renderToStaticMarkup(createElement(PreviewJoinPage, { brand: BRAND, defaultOrigin: ORIGIN, width: "phone", ...over }));
const preview = (over: Partial<JoinPreviewProps> = {}) =>
  renderToStaticMarkup(createElement(JoinPreview, { brand: BRAND, defaultOrigin: ORIGIN, width: "phone", ...over }));

describe("the preview renders JoinBrand", () => {
  it("shows the real page's frame: the root, the fixed lede, the tenant message and the fixed attribution", () => {
    const html = page();
    expect(html).toContain('data-testid="join-root"');
    expect(html).toContain('data-brand-state="branded"');
    expect(html).toContain("Get remote support");
    expect(html).toContain("Do this only if YOU called your IT provider");
    expect(html).toContain("Message from");
    expect(html).toContain("Call us first.");
    expect(html).toContain(`href="${ORIGIN}/docs"`);
    expect(html).toContain("--join-accent:#1d4ed8");
  });
  it("the shared page source imports JoinBrand and renders it, and carries no copy of the page's own text", () => {
    expect(previewPageSource).toContain('import { JoinBrand } from "./JoinBrand"');
    expect(previewPageSource).toContain("<JoinBrand");
    for (const src of [previewPageSource, joinPreviewSource]) {
      expect(src).not.toContain("Get remote support");
      expect(src).not.toContain("Do this only if YOU called");
      expect(src).not.toContain("join-brand__message");
      expect(src).not.toContain("Remote support software by");
    }
  });
  it("the page component still owns that text (so the checks above can tell a copy from the real thing)", () => {
    expect(joinBrandSource).toContain("Get remote support");
    expect(joinBrandSource).toContain("Remote support software by");
  });
});

describe("one preview mechanism for the Owner and the operator (docs/66 2l)", () => {
  it("both previews render PreviewJoinPage inside JoinBrandFrame at the shared widths and title", () => {
    for (const src of [joinPreviewSource, reviewSource]) {
      expect(src).toContain('import { JoinBrandFrame } from "./JoinBrandFrame"');
      expect(src).toContain("<JoinBrandFrame");
      expect(src).toContain("<PreviewJoinPage");
      expect(src).toContain("PREVIEW_WIDTHS[");
      expect(src).toContain("previewFrameTitle(");
      expect(src).toContain('from "./JoinPreviewPage"');
      expect(src).toContain("fallbackName={");
      // no second width table, no bare JoinBrand
      expect(src).not.toMatch(/<JoinBrand[ \n]/);
      expect(src).not.toMatch(/\b(390|1100|375|760)\b/);
    }
    expect(joinPreviewSource).not.toContain("join-preview__frame");
  });
  it("the widths are written once, in the shared module", () => {
    expect(PREVIEW_WIDTHS).toEqual({ phone: 390, desktop: 1100 });
    expect(previewPageSource).toContain("{ phone: 390, desktop: 1100 }");
    expect(reviewSource).not.toMatch(/(^|[^P])REVIEW_WIDTHS/);
  });
  it("the shared frame carries the width and the title as the iframe's size and name", () => {
    for (const w of ["phone", "desktop"] as const) {
      const html = preview({ width: w });
      expect(html).toContain("<iframe");
      expect(html).toContain(`width:${PREVIEW_WIDTHS[w]}px`);
      expect(html).toContain(`title="${previewFrameTitle(w)}"`);
    }
  });
  it("the neutral name is passed as the join page passes it: the build's product name", () => {
    expect(reviewSource).toContain("fallbackName={import.meta.env.VITE_PRODUCT_NAME}");
    expect(publicJoinSource).toContain("fallbackName={import.meta.env.VITE_PRODUCT_NAME}");
    expect(joinPageSource).toContain("fallbackName={productName}");
  });
  it("the page passes the guest page's top-bar links as INERT text and the welcome panel on desktop", () => {
    const html = page({ width: "desktop" });
    for (const t of ["Downloads", "Documentation", "Technician sign in"]) expect(html).toContain(t);
    expect(html).not.toContain('href="/downloads"');
    expect(html).not.toContain('href="/console"');
    expect(html).not.toContain('href="/docs"');
    expect(html).toContain("rally-welcome");
    expect(html).not.toContain("join__welcome-layout--single");
    // the same words the guest page's own nav uses
    for (const t of [">Downloads<", ">Documentation<", ">Technician sign in<"]) expect(joinPageSource).toContain(t);
    expect(joinPageSource).toContain("<RallyWelcome />");
  });
  it("on a phone the welcome panel is left out: the single column the guest page shows there", () => {
    const html = page({ width: "phone" });
    expect(html).not.toContain("rally-welcome");
    expect(html).toContain("Technician sign in");
  });
  it("the neutral page uses the product name through the shared page too", () => {
    expect(page({ brand: NEUTRAL_BRAND, fallbackName: "Contoso Help" })).toContain("Contoso Help");
  });
});

describe("width and the neutral toggle", () => {
  it("the preview records its width and neutral state", () => {
    expect(preview({ width: "phone" })).toContain('data-width="phone"');
    expect(preview({ width: "desktop" })).toContain('data-width="desktop"');
    expect(preview({ neutral: true })).toContain('data-neutral="true"');
    expect(preview()).toContain('data-neutral="false"');
  });
  it("show as neutral default swaps the brand and the logo for the neutral ones", () => {
    expect(joinPreviewSource).toContain("neutral ? NEUTRAL_BRAND : brand");
    expect(joinPreviewSource).toContain("neutral ? undefined : logoSrc");
  });
  it("the neutral page renders unbranded: no name, message, attribution or accent", () => {
    const html = page({ brand: NEUTRAL_BRAND });
    expect(html).toContain('data-brand-state="neutral"');
    expect(html).not.toContain("Acme IT");
    expect(html).not.toContain("Call us first.");
    expect(html).not.toContain("join-attribution");
    expect(html).not.toContain("--join-accent");
  });
});

describe("the default origin", () => {
  it("an unset or invalid origin renders the neutral page, exactly as production would", () => {
    for (const o of [undefined, "", "none", "http://main.deskrally.com", "https://main.deskrally.com/docs"]) {
      const html = page({ defaultOrigin: o });
      expect(html).toContain('data-brand-state="neutral"');
      expect(html).not.toContain("Acme IT");
      expect(html).not.toContain("join-attribution");
    }
  });
  it("the sections hand the preview the join page's own build value, not a copy of its rule", () => {
    expect(appearanceSource).toContain("defaultOrigin={import.meta.env.VITE_DEFAULT_ORIGIN}");
    expect(publicJoinSource).toContain("<JoinPreview");
    expect(publicJoinSource).toContain("defaultOrigin={defaultOrigin}");
    expect(publicJoinSource).toContain("previewOriginUsable(defaultOrigin)");
    expect(reviewSource).toContain("const origin = import.meta.env.VITE_DEFAULT_ORIGIN");
    expect(reviewSource).toContain("defaultOrigin={origin}");
  });
});

describe("the new sources use no HTML-insertion API", () => {
  const apis = ["dangerously" + "SetInnerHTML", ".inner" + "HTML", ".outer" + "HTML", "insertAdjacent" + "HTML", "document." + "write"];
  it.each([
    ["JoinPreview.tsx", joinPreviewSource],
    ["JoinPreviewPage.tsx", previewPageSource],
    ["PublicJoinSection.tsx", publicJoinSource],
  ])("%s", (_name, source) => {
    for (const api of apis) expect(source).not.toContain(api);
  });
});

describe("the editor section", () => {
  it("renders the logo field only when the server said it can convert logos", () => {
    expect(publicJoinSource).toContain("{logoSupported && (");
    expect(publicJoinSource).toContain('data-testid="pub-logo-field"');
  });
  it("lives under the console form in the Appearance panel, which keeps its own heading", () => {
    expect(appearanceSource).toContain("<PublicJoinSection");
    expect(appearanceSource).toContain("Console appearance");
  });
});
