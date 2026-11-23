import { describe, expect, it } from "vitest";
import { PREVIEW_ORIGIN_NOTICE, draftToHostBrand, previewLogoSrc, previewOriginUsable } from "./brand_preview";
import { checkBrandForm } from "./brand_text";
import { NEUTRAL_BRAND } from "./host_branding";

const good = { productName: "Acme Support", accent: "#35654a", supportText: "Call us", contactKind: "email" as const, contactValue: "Help@Example.com" };

describe("draftToHostBrand", () => {
  it("is the draft as the page would receive it (canonical values)", () => {
    expect(draftToHostBrand(checkBrandForm(good))).toEqual({
      name: "Acme Support",
      accent: "#35654a",
      logoRev: "",
      supportText: "Call us",
      contact: { kind: "email", value: "Help@example.com" },
    });
  });
  it("a refused name is the neutral brand", () => {
    expect(draftToHostBrand(checkBrandForm({ ...good, productName: "Ab" }))).toBe(NEUTRAL_BRAND);
    expect(draftToHostBrand(checkBrandForm({ ...good, productName: "" }))).toBe(NEUTRAL_BRAND);
  });
  it("any other refused field is left out, the rest still shows", () => {
    const b = draftToHostBrand(checkBrandForm({ ...good, accent: "#ffffff", contactValue: "nope" }));
    expect(b.name).toBe("Acme Support");
    expect(b.accent).toBe("");
    expect(b.contact).toBeNull();
    expect(b.supportText).toBe("Call us");
  });
  it("no contact kind is no contact", () => {
    expect(draftToHostBrand(checkBrandForm({ ...good, contactKind: "", contactValue: "" })).contact).toBeNull();
  });
});

describe("previewLogoSrc", () => {
  it("only a logo the browser holds can be shown", () => {
    expect(previewLogoSrc({ kind: "new", dataUri: "data:image/png;base64,AA" })).toBe("data:image/png;base64,AA");
    expect(previewLogoSrc({ kind: "kept", sha256: "x" })).toBeUndefined();
    expect(previewLogoSrc({ kind: "none" })).toBeUndefined();
    expect(previewLogoSrc({ kind: "console", dataUri: "data:image/png;base64,AA" })).toBeUndefined();
  });
});

describe("previewOriginUsable", () => {
  it("is the join page's own rule", () => {
    expect(previewOriginUsable("https://main.deskrally.com")).toBe(true);
    expect(previewOriginUsable(undefined)).toBe(false);
    expect(previewOriginUsable("")).toBe(false);
    expect(previewOriginUsable("http://main.deskrally.com")).toBe(false);
    expect(previewOriginUsable("https://main.deskrally.com/docs")).toBe(false);
  });
  it("the notice says plainly that the live page is neutral until the deployment sets it", () => {
    expect(PREVIEW_ORIGIN_NOTICE).toContain("neutral");
    expect(PREVIEW_ORIGIN_NOTICE).toContain("VITE_DEFAULT_ORIGIN");
  });
});
