import { describe, expect, it } from "vitest";
import {
  checkBrandForm,
  normalizeBrandAccent,
  normalizeBrandContact,
  normalizeBrandName,
  normalizeBrandSupportText,
  supportTextCounts,
  type BrandFormValues,
} from "./brand_text";
import vectors from "../../../../control-plane/testdata/brand_text_vectors.json";

// The SAME file control-plane/brandtext_golden_test.go reads. Expected values come from the SERVER.
describe("shared golden vectors (control-plane/testdata/brand_text_vectors.json)", () => {
  it("the file is not empty", () => {
    expect(vectors.names.length).toBeGreaterThanOrEqual(20);
    expect(vectors.texts.length).toBeGreaterThanOrEqual(10);
    expect(vectors.contacts.length).toBeGreaterThanOrEqual(20);
  });
  it.each(vectors.names)("name %j", (c) => {
    expect(normalizeBrandName(c.input)).toEqual(c.ok ? { ok: true, value: c.normalized } : { ok: false, error: c.error });
  });
  it.each(vectors.texts)("support text %j", (c) => {
    expect(normalizeBrandSupportText(c.input)).toEqual(c.ok ? { ok: true, value: c.normalized } : { ok: false, error: c.error });
  });
  it.each(vectors.contacts)("contact $kind $value", (c) => {
    const got = normalizeBrandContact({ kind: c.kind as "phone", value: c.value });
    expect(got).toEqual(c.ok ? { ok: true, value: c.normalized } : { ok: false, error: c.error });
  });
});

describe("support text counter", () => {
  it("counts code points, not UTF-16 units, and a CRLF as one line break", () => {
    expect(supportTextCounts("")).toEqual({ runes: 0, lines: 0 });
    expect(supportTextCounts("ab")).toEqual({ runes: 2, lines: 1 });
    expect(supportTextCounts("\u{1F600}\u{1F600}")).toEqual({ runes: 2, lines: 1 });
    expect(supportTextCounts("a\r\nb\rc\nd")).toEqual({ runes: 7, lines: 4 });
  });
});

describe("accent", () => {
  it("empty is the theme default and is not trimmed into an error", () => {
    expect(normalizeBrandAccent("")).toEqual({ ok: true, value: "" });
    expect(normalizeBrandAccent("   ")).toEqual({ ok: true, value: "" });
  });
});

describe("a lone surrogate", () => {
  it("is refused like invalid UTF-8", () => {
    expect(normalizeBrandName("Acme\ud800 Support")).toEqual({ ok: false, error: "must be valid UTF-8 text" });
  });
});

const good: BrandFormValues = { productName: "Acme Support", accent: "#35654a", supportText: "Call us", contactKind: "phone", contactValue: "+1 555 010 0199" };

describe("checkBrandForm", () => {
  it("passes a good form and returns the canonical values", () => {
    const c = checkBrandForm(good);
    expect(c.valid).toBe(true);
    expect(c.errors).toEqual({});
    expect(c.normalized).toEqual({ productName: "Acme Support", accent: "#35654a", supportText: "Call us", contact: { kind: "phone", value: "15550100199" } });
  });
  it("reports every refused field at once, each with the server's wording, and keeps the ones that passed", () => {
    const c = checkBrandForm({ ...good, productName: "Ab", accent: "#ffffff", contactKind: "url", contactValue: "http://x.com" });
    expect(c.valid).toBe(false);
    expect(c.errors.productName).toBe("must be 3 to 100 characters");
    expect(c.errors.accent).toBe("contrast 1.00:1 against the white button label, needs 4.5:1");
    expect(c.errors.contact).toBe("a URL must start with https://");
    expect(c.errors.supportText).toBeUndefined();
    expect(c.normalized.productName).toBeUndefined();
    expect(c.normalized.supportText).toBe("Call us");
  });
  it("a contact kind without a value is refused, and neither is fine", () => {
    expect(checkBrandForm({ ...good, contactValue: "" }).errors.contact).toBe("needs both a kind and a value");
    expect(checkBrandForm({ ...good, contactKind: "", contactValue: "" }).valid).toBe(true);
  });
});
