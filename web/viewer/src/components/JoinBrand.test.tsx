/**
 * The join page's brand surface (docs/66 stage 2), rendered to static markup (vitest here has no DOM; the
 * browser behaviour, the logo's load and error events and the computed styles are covered by
 * e2e/join_brand.spec.ts and e2e/join_brand_host.spec.ts).
 *
 * What these tests hold in place:
 *   - the page that renders while the brand is loading IS the neutral page, byte for byte;
 *   - every tenant string is escaped text, whatever it looks like;
 *   - the only hrefs a brand can produce are the validated contact kinds, and an email is never a link;
 *   - the fixed lede is identical for every brand, and the accent reaches only a custom property;
 *   - none of the sources uses an HTML-insertion API.
 */

import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { JoinBrand, brandDisplayName, effectiveBrand, DEFAULT_PRODUCT_NAME, type JoinBrandProps } from "./JoinBrand";
import { JoinPage } from "./JoinPage";
import { NEUTRAL_BRAND, type HostBrand } from "../lib/host_branding";
import { defaultDocsLink, defaultOrigin } from "../lib/default_docs";
import joinBrandSource from "./JoinBrand.tsx?raw";
import joinPageSource from "./JoinPage.tsx?raw";
import mainSource from "../main.tsx?raw";
import appSource from "../App.tsx?raw";
import hostBrandingSource from "../lib/host_branding.ts?raw";
import useHostBrandingSource from "../lib/use_host_branding.ts?raw";

const ORIGIN = "https://main.deskrally.com";
const HASH = "0123456789abcdef".repeat(4);

const BRAND: HostBrand = {
  name: "Acme IT",
  accent: "#1d4ed8",
  logoRev: HASH,
  supportText: "Call us first.\nWe are open 9 to 5.",
  contact: { kind: "phone", value: "442079460958" },
};

/** The deployment value every branded page needs (VITE_DEFAULT_ORIGIN); a test overrides it explicitly, even with undefined. */
const render = (props: Partial<JoinBrandProps> & { brand: HostBrand }, kids?: ReactElement) =>
  renderToStaticMarkup(createElement(JoinBrand, { defaultOrigin: ORIGIN, ...props }, kids));

/** Every href in the markup, in order. */
const allHrefs = (html: string) => [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]!.replace(/&amp;/g, "&"));
/** The hrefs a BRAND can produce: every href except the fixed attribution link to the default host's /docs. */
const hrefs = (html: string) => allHrefs(html).filter((h) => h !== `${ORIGIN}/docs`);

const lede = (html: string) => /<p class="join__lede">[\s\S]*?<\/p>/.exec(html)?.[0];

describe("the neutral page and the loading skeleton", () => {
  it("a neutral brand is the deployment's own page: its name, no message, no attribution, no accent, no logo", () => {
    const html = render({ brand: NEUTRAL_BRAND });
    expect(html).toContain('data-brand-state="neutral"');
    expect(html).toContain('data-testid="join-brand-name">DeskRally</bdi>');
    expect(html).not.toContain("join-brand-message");
    expect(html).not.toContain("join-attribution");
    expect(html).not.toContain("join-brand__logo");
    expect(html).not.toContain("style=");
    expect(html).toContain("rally-mark");
  });

  it("while the lookup is pending the page IS the neutral page (only the state flag differs)", () => {
    const neutral = render({ brand: NEUTRAL_BRAND, fallbackName: "Acme Self-Host" });
    const loading = render({ brand: NEUTRAL_BRAND, fallbackName: "Acme Self-Host", loading: true });
    expect(loading).toContain('data-brand-state="loading"');
    expect(loading.replace('data-brand-state="loading"', 'data-brand-state="neutral"')).toBe(neutral);
  });

  it("a brand's logo address is ignored while the page is neutral", () => {
    expect(render({ brand: NEUTRAL_BRAND, logoSrc: "/cp/public/branding/logo?rev=" + HASH })).not.toContain("join-brand__logo");
  });

  it("a logo address that is not one of the three allowed constructions never reaches an <img> (the neutral mark shows)", () => {
    for (const logoSrc of ["javascript:alert(1)", "data:image/svg+xml;base64,PHN2Zz4=", "data:text/html;base64,PHNjcmlwdD4=", "https://evil.example/x.png",
      `//evil.example/cp/public/branding/logo?rev=${HASH}`, "/cp/public/branding/logo?rev=short", ""]) {
      const html = render({ brand: BRAND, logoSrc });
      expect(html, logoSrc).not.toContain("join-brand__logo");
      expect(html.slice(0, html.indexOf("</header>")), logoSrc).toContain("rally-mark");
    }
    // A draft preview may hand a blob: URL or a raster data: URI.
    expect(render({ brand: BRAND, logoSrc: "blob:https://acme.deskrally.com/3f1c2a9e-5b7d-4f0a-9c3e-0d1e2f3a4b5c" })).toContain("<img");
    expect(render({ brand: BRAND, logoSrc: "data:image/png;base64,iVBORw0KGgo=" })).toContain("<img");
  });

  it("the deployment's build-time name is the fallback; a brand's own name wins over it", () => {
    expect(render({ brand: NEUTRAL_BRAND, fallbackName: "Acme Self-Host" })).toContain('data-testid="join-brand-name">Acme Self-Host</bdi>');
    expect(render({ brand: NEUTRAL_BRAND, fallbackName: "  " })).toContain(">DeskRally</bdi>");
    expect(render({ brand: BRAND, fallbackName: "Acme Self-Host" })).toContain('data-testid="join-brand-name">Acme IT</bdi>');
    expect(brandDisplayName(NEUTRAL_BRAND)).toBe(DEFAULT_PRODUCT_NAME);
    expect(brandDisplayName(NEUTRAL_BRAND, " Self-Host ")).toBe("Self-Host");
    expect(brandDisplayName(BRAND, "Self-Host")).toBe("Acme IT");
  });

  it("the page renders the neutral skeleton before the lookup answers, with the build-time name in its steps", () => {
    const html = renderToStaticMarkup(createElement(JoinPage, { code: "0123456789ABC", origin: "https://acme.example", platform: "windows", productName: "Acme Self-Host" }));
    expect(html).toContain('data-brand-state="loading"');
    expect(html).toContain('data-testid="join-brand-name">Acme Self-Host</bdi>');
    expect(html).toContain('Get the <bdi dir="auto">Acme Self-Host</bdi> support client');
    expect(html).not.toContain("join-attribution");
  });
});

describe("a branded page", () => {
  it("shows the name, the message from it and the fixed attribution", () => {
    const html = render({ brand: BRAND });
    expect(html).toContain('data-brand-state="branded"');
    expect(html).toContain('data-testid="join-brand-name">Acme IT</bdi>');
    expect(html).toContain('Message from <bdi dir="auto">Acme IT</bdi>');
    expect(html).toContain('data-testid="join-brand-text" dir="auto">Call us first.\nWe are open 9 to 5.</p>');
    expect(html).toContain(`Remote support software by <a href="${ORIGIN}/docs">DeskRally</a></span>`);
  });

  it("carries the accent as ONE custom property on the root, and nowhere else", () => {
    const html = render({ brand: BRAND });
    expect(html).toContain('style="--join-accent:#1d4ed8"');
    expect([...html.matchAll(/style="/g)]).toHaveLength(1);
    expect(html).not.toContain("#1d4ed8;");
  });

  it("does not let an invalid accent reach the style attribute (a draft is handed straight in)", () => {
    for (const accent of ["red", "#FFF", "#1d4ed8; background:url(//evil.example/x)", "url(x)", "var(--x)", "#12345g"]) {
      const html = render({ brand: { ...BRAND, accent } });
      expect(html, accent).not.toContain("style=");
      expect(html, accent).not.toContain("evil");
    }
  });

  it("with a logo address: a hidden-until-loaded image with an empty alt; without one: the neutral mark", () => {
    const withLogo = render({ brand: BRAND, logoSrc: `/cp/public/branding/logo?rev=${HASH}` });
    expect(withLogo).toContain(`<img class="join-brand__logo" data-testid="join-brand-logo" data-state="loading" src="/cp/public/branding/logo?rev=${HASH}" alt=""/>`);
    // The top bar shows the logo INSTEAD of the neutral mark (the attribution below keeps its own small mark).
    expect(withLogo.slice(0, withLogo.indexOf("</header>"))).not.toContain("rally-mark");
    const without = render({ brand: BRAND });
    expect(without).not.toContain("join-brand__logo");
    expect(without.slice(0, without.indexOf("</header>"))).toContain("rally-mark");
  });

  it("renders only the message when there is no contact, and only the contact when there is no message", () => {
    const textOnly = render({ brand: { ...BRAND, contact: null } });
    expect(textOnly).toContain("Message from");
    expect(textOnly).not.toContain("join-brand-contact");
    const contactOnly = render({ brand: { ...BRAND, supportText: "" } });
    expect(contactOnly).not.toContain("Message from");
    expect(contactOnly).toContain('aria-label="Support contact"');
    expect(contactOnly).toContain("join-brand-contact");
    const neither = render({ brand: { ...BRAND, supportText: "", contact: null } });
    expect(neither).not.toContain("join-brand-message");
    expect(neither).toContain("join-attribution");
  });

  it("puts the page's own content after the brand, in the slots the page gives it", () => {
    const html = render({ brand: BRAND, nav: createElement("a", { href: "/downloads" }, "Downloads"), welcome: createElement("p", null, "art") },
      createElement("section", { "data-testid": "steps" }, "steps"));
    expect(html.indexOf("join-attribution")).toBeLessThan(html.indexOf('data-testid="steps"'));
    expect(html).toContain('href="/downloads"');
    expect(html).toContain('<aside class="join__welcome" aria-label="Welcome to DeskRally support"><p>art</p></aside>');
    expect(html).toContain('class="join__welcome-layout"');
    const preview = render({ brand: BRAND });
    expect(preview).toContain("join__welcome-layout--single");
    expect(preview).not.toContain("join__welcome\"");
  });
});

describe("the fixed lede", () => {
  const ledeText = "Do this only if YOU called your IT provider for help";
  it("is first after the heading and byte-identical for every brand, hostile or not", () => {
    const hostile: HostBrand = {
      name: '<img src=x onerror=alert(1)>',
      accent: "#000000",
      logoRev: HASH,
      supportText: '"><script>alert(1)</script>\n<b>trusted</b> verified safe',
      contact: { kind: "url", value: "https://help.example.com/x" },
    };
    const neutral = lede(render({ brand: NEUTRAL_BRAND }));
    expect(neutral).toContain(ledeText);
    for (const brand of [BRAND, hostile, { ...BRAND, accent: "" }]) {
      const html = render({ brand });
      expect(lede(html)).toBe(neutral);
      expect(html.indexOf("join__title")).toBeLessThan(html.indexOf("join__lede"));
      expect(html.indexOf("join__lede")).toBeLessThan(html.indexOf("join-brand-message"));
    }
  });
});

describe("hostile strings are text", () => {
  const hostile: HostBrand = {
    name: '<img src=x onerror=alert(1)>',
    accent: "#1d4ed8",
    logoRev: "",
    supportText: '"><script>window.__pwned=1</script>\n<b>bold</b> [link](javascript:alert(1)) &lt;already&gt;',
    contact: { kind: "email", value: "a'b&c=d?e@example.com" },
  };

  it("escapes every tenant string and creates no element from any of them", () => {
    const html = render({ brand: hostile });
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&quot;&gt;&lt;script&gt;window.__pwned=1&lt;/script&gt;");
    expect(html).toContain("&lt;b&gt;bold&lt;/b&gt;");
    expect(html).toContain("&amp;lt;already&amp;gt;");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<b>");
    expect(html).not.toMatch(/<img[^>]*onerror/i);
    expect(html).not.toMatch(/<[^>]*\sonerror=/i);
  });

  it("produces no href from any of them (no default docs URL configured: the attribution is plain text)", () => {
    expect(hrefs(render({ brand: hostile }))).toEqual([]);
  });

  it("shows an email as literal text, never as a link, whatever the local part contains", () => {
    const html = render({ brand: hostile });
    expect(html).toContain('<span class="join-brand__contactvalue" dir="ltr">a&#x27;b&amp;c=d?e@example.com</span>');
    expect(html.toLowerCase()).not.toContain("mailto");
  });
});

describe("contacts", () => {
  it("phone: tel: plus the digits", () => {
    const html = render({ brand: BRAND });
    expect(html).toContain('data-kind="phone"');
    expect(html).toContain('<a href="tel:442079460958">442079460958</a>');
    expect(hrefs(html)).toEqual(["tel:442079460958"]);
  });

  it("url: the host on screen before the click, https only, no opener, no referrer", () => {
    const html = render({ brand: { ...BRAND, contact: { kind: "url", value: "https://help.example.com/support?x=1&y=2" } } });
    expect(html).toContain('<a href="https://help.example.com/support?x=1&amp;y=2" target="_blank" rel="noopener noreferrer nofollow">https://<strong>help.example.com</strong>/support?x=1&amp;y=2</a>');
    expect(hrefs(html)).toEqual(["https://help.example.com/support?x=1&y=2"]);
    // The visible text of the link is the whole stored value: nothing hidden, nothing rewritten.
    const link = /<a href="https:[^>]*>([\s\S]*?)<\/a>/.exec(html)![1]!;
    expect(link.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&")).toBe("https://help.example.com/support?x=1&y=2");
  });

  it("email: text only", () => {
    const html = render({ brand: { ...BRAND, contact: { kind: "email", value: "help@example.com" } } });
    expect(html).toContain('data-kind="email"');
    expect(html).toContain(">help@example.com</span>");
    expect(hrefs(html)).toEqual([]);
  });

  it("re-validates at render: a contact that is not valid is not shown and produces no href", () => {
    const bad: Array<{ kind: "phone" | "email" | "url"; value: string }> = [
      { kind: "url", value: "javascript:alert(1)" },
      { kind: "url", value: "http://help.example.com" },
      { kind: "url", value: "https://user@help.example.com" },
      { kind: "url", value: "https://1.2.3.4/" },
      { kind: "phone", value: "+442079460958" },
      { kind: "phone", value: "5551234;rm -rf" },
      { kind: "email", value: "mailto:a@example.com" },
      { kind: "email", value: "a@b" },
    ];
    for (const contact of bad) {
      const html = render({ brand: { ...BRAND, supportText: "", contact } });
      expect(html, `${contact.kind} ${contact.value}`).not.toContain("join-brand-contact");
      expect(html, `${contact.kind} ${contact.value}`).not.toContain("join-brand-message");
      expect(hrefs(html)).toEqual([]);
    }
    // A kind that is not one of the three never renders either.
    const html = render({ brand: { ...BRAND, supportText: "", contact: { kind: "sms" as "phone", value: "442079460958" } } });
    expect(html).not.toContain("join-brand-contact");
  });
});

describe("the sources", () => {
  const files: Array<[string, string]> = [
    ["components/JoinBrand.tsx", joinBrandSource],
    ["components/JoinPage.tsx", joinPageSource],
    ["lib/host_branding.ts", hostBrandingSource],
    ["lib/use_host_branding.ts", useHostBrandingSource],
  ];

  // Needles are split so this file cannot match itself, and none of them is written out in the sources.
  const forbidden = [
    "dangerously" + "SetInnerHTML",
    "inner" + "HTML",
    "outer" + "HTML",
    "insertAdjacent" + "HTML",
    "document." + "write",
    "createContextual" + "Fragment",
    "DOM" + "Parser",
    "ev" + "al(",
    "new Func" + "tion",
    "set" + "Attribute",
    "src" + "doc",
  ];

  for (const [name, source] of files) {
    it(`${name} uses no HTML-insertion or code-evaluation API`, () => {
      for (const needle of forbidden) expect(source, `${name}: ${needle}`).not.toContain(needle);
    });
  }

  it("JoinBrand.tsx can build an href in exactly three places: tel:, the validated website, and the default-host docs link (built from the validated origin and passed to the attribution)", () => {
    const found = [...joinBrandSource.matchAll(/\bhref=(\{[^}]*\}|"[^"]*")/g)].map((m) => m[1]);
    expect(found).toEqual(["{tel}", "{web.href}", "{href}", "{docsHref}"]);
  });

  it("JoinBrand.tsx loads exactly one image, and its address is the caller's logoSrc", () => {
    const images = [...joinBrandSource.matchAll(/<img\s[\s\S]*?\/>/g)].map((m) => m[0]);
    expect(images).toHaveLength(1);
    expect(images[0]).toContain("src={src}");
  });

  it("the join page's guest-facing text never interpolates a tenant string outside BrandName", () => {
    // Every {name} in running text is wrapped; a bare one would lose the direction isolation.
    expect(joinPageSource).not.toMatch(/[A-Za-z] \{name\} [A-Za-z]/);
    // Step 1's heading, the unsupported-platform line and step 2's launch link (menu wave 11 removed the second launch link under Advanced).
    expect([...joinPageSource.matchAll(/<BrandName text=\{name\} \/>/g)]).toHaveLength(3);
  });
});

describe("the attribution link (docs/66 2a.7, 2i: always the DEFAULT host's origin + /docs)", () => {
  const DOCS = "https://main.deskrally.com/docs";

  it("links the default origin's /docs, and nothing else on the page is a link to it", () => {
    const html = render({ brand: BRAND, defaultOrigin: ORIGIN });
    expect(html).toContain(`Remote support software by <a href="${DOCS}">DeskRally</a>`);
    expect(allHrefs(html)).toEqual(["tel:442079460958", DOCS]);
  });

  it("accepts the origin with a trailing slash or a port, and always links origin + /docs", () => {
    expect(allHrefs(render({ brand: BRAND, defaultOrigin: `${ORIGIN}/` }))).toContain(DOCS);
    expect(allHrefs(render({ brand: BRAND, defaultOrigin: "https://main.deskrally.com:8443" }))).toContain("https://main.deskrally.com:8443/docs");
  });

  it("is the NEUTRAL page, never branded without the link, when the origin is unset or empty", () => {
    for (const v of [undefined, "", "   "]) {
      const html = render({ brand: BRAND, defaultOrigin: v });
      expect(html, String(v)).toContain('data-brand-state="neutral"');
      expect(html).not.toContain("join-attribution");
      expect(html).not.toContain("Acme IT");
      expect(html).not.toContain("join-brand-message");
      expect(html).not.toContain("--join-accent");
      expect(allHrefs(html)).toEqual([]);
      expect(html).toBe(render({ brand: NEUTRAL_BRAND, defaultOrigin: v }));
    }
  });

  it("is the neutral page for any invalid value: a path, query, fragment, userinfo, wrong scheme, relative or tenant-like value", () => {
    for (const v of ["https://main.deskrally.com/docs", "https://main.deskrally.com/other", "https://main.deskrally.com//evil.example",
      "https://main.deskrally.com?a=1", "https://main.deskrally.com/?a=1", "https://main.deskrally.com#x", "https://main.deskrally.com/#x",
      "/docs", "//evil.example", "http://main.deskrally.com", "javascript:alert(1)",
      "https://user:pw@main.deskrally.com", "https://main.deskrally.com@evil.example", "https://127.0.0.1", "https://localhost",
      "https://main.deskrally.com\"onmouseover=\"x", "https://exa mple.com", "https://main.deskrally.com\@evil.example"]) {
      const html = render({ brand: BRAND, defaultOrigin: v });
      expect(html, v).toContain('data-brand-state="neutral"');
      expect(html, v).not.toContain("join-attribution");
      expect(html, v).not.toContain("Acme IT");
      expect(allHrefs(html), v).toEqual([]);
    }
  });

  it("defaultOrigin / defaultDocsLink: canonical origin or null, link is exactly origin + /docs", () => {
    expect(defaultOrigin(ORIGIN)).toBe(ORIGIN);
    expect(defaultOrigin(` ${ORIGIN}/ `)).toBe(ORIGIN);
    expect(defaultOrigin("HTTPS://Main.DeskRally.com")).toBe(ORIGIN);
    expect(defaultOrigin(`${ORIGIN}/docs`)).toBeNull();
    expect(defaultDocsLink(ORIGIN)).toBe(`${ORIGIN}/docs`);
    expect(defaultDocsLink(`${ORIGIN}/docs`)).toBeNull();
    expect(defaultDocsLink(undefined)).toBeNull();
  });

  it("effectiveBrand keeps the brand only with a valid origin", () => {
    expect(effectiveBrand(BRAND, ORIGIN)).toBe(BRAND);
    expect(effectiveBrand(BRAND, undefined)).toBe(NEUTRAL_BRAND);
    expect(effectiveBrand(BRAND, "https://main.deskrally.com/docs")).toBe(NEUTRAL_BRAND);
  });

  it("every route that renders JoinPage passes the build-time origin (main.tsx is the real /join entry)", () => {
    expect(mainSource).toContain("defaultOrigin={import.meta.env.VITE_DEFAULT_ORIGIN}");
    expect(appSource).toContain("defaultOrigin={import.meta.env.VITE_DEFAULT_ORIGIN}");
  });

  it("JoinPage derives its brand through effectiveBrand and passes the origin on (title, step names and logo follow the neutral page too)", () => {
    expect(joinPageSource).toContain("effectiveBrand(hostBranding.brand, defaultOrigin)");
    expect(joinPageSource).toContain("defaultOrigin={defaultOrigin}");
  });
});
