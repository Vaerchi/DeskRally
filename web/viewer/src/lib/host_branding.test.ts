/**
 * Host branding for the guest join page (docs/66 stage 2): what a response must look like to be applied, and
 * what the lookup does when anything is wrong. The rule under test is ALL OR NOTHING: a response is applied as
 * one brand or not at all, and every kind of trouble (network, status, body, shape, a single bad field, time)
 * yields the NEUTRAL brand with no retry.
 *
 * The neutral bytes below are control-plane/publicbranding.go's `NeutralBrandingBody()`; the full brand is the
 * shape its `publicBrandingBody` marshals.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  HOST_BRANDING_MAX_BODY,
  HOST_BRANDING_TIMEOUT_MS,
  NEUTRAL_BRAND,
  fetchHostBranding,
  parseHostBranding,
  phoneHref,
  publicBrandingLogoUrl,
  publicBrandingUrl,
  urlContact,
  validAccent,
  validBrandName,
  validContact,
  validEmail,
  validLogoRev,
  validLogoSrc,
  validPhone,
  validSupportText,
} from "./host_branding";

const HASH = "0123456789abcdef".repeat(4);

const NEUTRAL_BYTES = '{"product_name":"","accent_color":"","logo_rev":"","support_text":"","support_contact":{"kind":"","value":""}}';

function body(over: Record<string, unknown> = {}) {
  return {
    product_name: "Acme IT Support",
    accent_color: "#1d4ed8",
    logo_rev: HASH,
    support_text: "Call us first.\nWe are open 9 to 5.",
    support_contact: { kind: "phone", value: "442079460958" },
    ...over,
  };
}

function contactBody(kind: string, value: string) {
  return body({ support_contact: { kind, value } });
}

describe("parseHostBranding: the neutral object", () => {
  it("is the neutral brand for the control plane's own neutral bytes", () => {
    expect(parseHostBranding(JSON.parse(NEUTRAL_BYTES))).toBe(NEUTRAL_BRAND);
  });

  it("applies a complete valid brand as one brand", () => {
    expect(parseHostBranding(body())).toEqual({
      name: "Acme IT Support",
      accent: "#1d4ed8",
      logoRev: HASH,
      supportText: "Call us first.\nWe are open 9 to 5.",
      contact: { kind: "phone", value: "442079460958" },
    });
  });

  it("accepts a brand with only a name (every optional field empty)", () => {
    expect(parseHostBranding(body({ accent_color: "", logo_rev: "", support_text: "", support_contact: { kind: "", value: "" } }))).toEqual({
      name: "Acme IT Support", accent: "", logoRev: "", supportText: "", contact: null,
    });
  });

  it("ignores unknown extra keys (a newer server may add some) but never reads a URL from them", () => {
    const b = parseHostBranding({ ...body(), logo_url: "https://evil.example/x.png", href: "javascript:alert(1)", scope: "tenant" });
    expect(b.name).toBe("Acme IT Support");
    expect(JSON.stringify(b)).not.toContain("evil.example");
    expect(JSON.stringify(b)).not.toContain("javascript");
  });
});

describe("parseHostBranding: unexpected shapes are neutral", () => {
  const cases: Array<[string, unknown]> = [
    ["null", null],
    ["undefined", undefined],
    ["an array", [body()]],
    ["a string", "Acme"],
    ["a number", 42],
    ["a boolean", true],
    ["an empty object", {}],
    ["an old shape with logo_url and scope", { scope: "tenant", product_name: "Acme IT", accent_color: "", logo_url: "/x", support_text: "", support_contact: { kind: "", value: "" } }],
    ["a missing product_name", (() => { const b: Record<string, unknown> = body(); delete b.product_name; return b; })()],
    ["a missing logo_rev", (() => { const b: Record<string, unknown> = body(); delete b.logo_rev; return b; })()],
    ["a numeric product_name", body({ product_name: 12345 })],
    ["a null accent_color", body({ accent_color: null })],
    ["an object support_text", body({ support_text: { text: "x" } })],
    ["a missing support_contact", (() => { const b: Record<string, unknown> = body(); delete b.support_contact; return b; })()],
    ["a null support_contact", body({ support_contact: null })],
    ["a string support_contact", body({ support_contact: "phone:123" })],
    ["an array support_contact", body({ support_contact: ["phone", "123"] })],
    ["a numeric contact kind", body({ support_contact: { kind: 1, value: "442079460958" } })],
    ["a missing contact value", body({ support_contact: { kind: "phone" } })],
  ];
  for (const [name, input] of cases) {
    it(`${name}`, () => expect(parseHostBranding(input)).toBe(NEUTRAL_BRAND));
  }
});

describe("parseHostBranding: ALL OR NOTHING (one bad field takes the whole brand down)", () => {
  const bad: Array<[string, Record<string, unknown>]> = [
    ["a bad name", { product_name: "ab" }],
    ["a bad accent", { accent_color: "red" }],
    ["a bad logo hash", { logo_rev: "../../etc/passwd" }],
    ["a bad support text", { support_text: "a‮b" }],
    ["a bad contact", { support_contact: { kind: "url", value: "javascript:alert(1)" } }],
    ["an unknown contact kind", { support_contact: { kind: "sms", value: "442079460958" } }],
    ["a kind with no value", { support_contact: { kind: "phone", value: "" } }],
    ["a value with no kind", { support_contact: { kind: "", value: "442079460958" } }],
  ];
  for (const [name, over] of bad) {
    it(`${name} makes the response neutral, not partial`, () => {
      expect(parseHostBranding(body(over))).toBe(NEUTRAL_BRAND);
    });
  }

  it("a response with a text, accent or logo but NO name is inconsistent, so neutral", () => {
    expect(parseHostBranding(body({ product_name: "" }))).toBe(NEUTRAL_BRAND);
    expect(parseHostBranding(body({ product_name: "", accent_color: "", logo_rev: "", support_contact: { kind: "", value: "" } }))).toBe(NEUTRAL_BRAND);
  });
});

describe("the product name", () => {
  it("accepts ordinary names in any script", () => {
    for (const n of ["Acme IT", "Acme 24/7 Help-Desk", "Ünïcödé Support", "株式会社サポート", "دعم العربية", "Служба поддержки", "abc", "x".repeat(100)]) {
      expect(validBrandName(n), n).toBe(true);
    }
  });

  it("refuses the wrong length, counted in code points", () => {
    expect(validBrandName("ab")).toBe(false);
    expect(validBrandName("")).toBe(false);
    expect(validBrandName("x".repeat(101))).toBe(false);
    // 100 astral code points are 200 UTF-16 units: still within the limit; 101 are not.
    expect(validBrandName("\u{1D4D0}".repeat(100))).toBe(true);
    expect(validBrandName("\u{1D4D0}".repeat(101))).toBe(false);
  });

  it("refuses spoofing and layout characters, however they are spelled", () => {
    const hostile: Array<[string, string]> = [
      ["right-to-left override", "Acme‮IT"],
      ["bidi isolate", "Acme⁦IT"],
      ["zero-width space", "Acme​IT"],
      ["zero-width joiner", "Acme‍IT"],
      ["word joiner", "Acme⁠IT"],
      ["byte order mark", "﻿Acme IT"],
      ["NUL", "Acme\u0000IT"],
      ["bell", "Acme\u0007IT"],
      ["tab", "Acme\tIT"],
      ["newline", "Acme\nIT"],
      ["carriage return", "Acme\rIT"],
      ["private use", "AcmeIT"],
      ["unassigned code point", "Acme͸IT"],
      ["line separator", "Acme IT"],
      ["paragraph separator", "Acme IT"],
      ["no-break space", "Acme IT"],
      ["ideographic space", "Acme　IT"],
      ["en space", "Acme IT"],
      ["lone high surrogate", "Acme\uD800IT"],
      ["replacement character", "Acme�IT"],
      ["leading space", " Acme IT"],
      ["trailing space", "Acme IT "],
      ["a run of spaces", "Acme  IT"],
      ["no letter or digit", "--- ---"],
    ];
    for (const [what, name] of hostile) expect(validBrandName(name), what).toBe(false);
  });

  it("accepts a name that LOOKS like markup, because it is only ever text", () => {
    expect(validBrandName("<img src=x onerror=alert(1)>")).toBe(true);
    expect(validBrandName('"><script>alert(1)</script>')).toBe(true);
  });
});

describe("the message", () => {
  it("accepts empty, ordinary text and up to four lines", () => {
    expect(validSupportText("")).toBe(true);
    expect(validSupportText("We are open 9 to 5.")).toBe(true);
    expect(validSupportText("a\nb\nc\nd")).toBe(true);
    expect(validSupportText("a\n\nc")).toBe(true);
    expect(validSupportText("x".repeat(280))).toBe(true);
  });

  it("refuses too long, too many lines, odd whitespace and spoofing characters", () => {
    expect(validSupportText("x".repeat(281))).toBe(false);
    expect(validSupportText("a\nb\nc\nd\ne")).toBe(false);
    expect(validSupportText("\nabc")).toBe(false);
    expect(validSupportText("abc\n")).toBe(false);
    expect(validSupportText("abc ")).toBe(false);
    expect(validSupportText("a\r\nb")).toBe(false);
    expect(validSupportText("a\tb")).toBe(false);
    expect(validSupportText("a‮b")).toBe(false);
    expect(validSupportText("a​b")).toBe(false);
    expect(validSupportText("a\u0000b")).toBe(false);
    expect(validSupportText("a b")).toBe(false);
    expect(validSupportText("a b")).toBe(false);
    expect(validSupportText("line one \nline two")).toBe(false);
  });
});

describe("the accent and the logo hash", () => {
  it("accepts empty or exactly #rrggbb in lowercase", () => {
    for (const a of ["", "#000000", "#1d4ed8", "#ffffff", "#0a0b0c"]) expect(validAccent(a), a).toBe(true);
  });

  it("refuses everything else, including anything that could carry CSS", () => {
    for (const a of ["red", "#FFF", "#FFFFFF", "#1D4ED8", "#12345", "#1234567", "#12345g", "1d4ed8", "#1d4ed8;", "#1d4ed8 ", " #1d4ed8",
      "#1d4ed8; background:url(//evil.example/x)", "url(x)", "var(--x)", "rgb(0,0,0)", "#1d4ed8\n", "expression(alert(1))"]) {
      expect(validAccent(a), a).toBe(false);
    }
  });

  it("accepts empty or exactly 64 lowercase hex digits", () => {
    expect(validLogoRev("")).toBe(true);
    expect(validLogoRev(HASH)).toBe(true);
    for (const r of [HASH.slice(1), HASH + "0", HASH.toUpperCase(), "g".repeat(64), `../${HASH.slice(3)}`, `${HASH.slice(0, 60)}?x=1&`, " " + HASH.slice(1)]) {
      expect(validLogoRev(r), r).toBe(false);
    }
  });
});

describe("the three contact kinds", () => {
  it("phone: exactly 5 to 15 digits", () => {
    for (const p of ["55512", "5551234567", "442079460958", "123456789012345"]) expect(validPhone(p), p).toBe(true);
    for (const p of ["", "5551", "1234567890123456", "+442079460958", "555-1234", "555 1234", "55512a", "(555)1234", "tel:5551234", "٥٥٥١٢٣٤"]) {
      expect(validPhone(p), p).toBe(false);
    }
  });

  it("phone: the link is tel: plus the digits, built here", () => {
    expect(phoneHref("442079460958")).toBe("tel:442079460958");
    expect(phoneHref("+442079460958")).toBeNull();
    expect(phoneHref("javascript:alert(1)")).toBeNull();
    expect(phoneHref("5551234;rm")).toBeNull();
  });

  it("email: a plain address, shown as text", () => {
    for (const e of ["help@example.com", "a.b+c@mail.example.co.uk", "o'brien@example.com", "a?b=c&d@example.com", "x@a.bc"]) {
      expect(validEmail(e), e).toBe(true);
    }
    for (const e of ["help@EXAMPLE.com", "help@localhost", "help@example", "@example.com", "help@", "help@1.2.3.4", "help @example.com",
      "mailto:help@example.com", ".a@example.com", "a..b@example.com", `${"x".repeat(65)}@example.com`, "help@exa_mple.com",
      "help@example.com:25", "help@@example.com", "<help>@example.com", "help@example.com\n", "hélp@example.com", `${"a".repeat(190)}@example.com`]) {
      expect(validEmail(e), e).toBe(false);
    }
  });

  it("url: https plus a public DNS name; split for display, href built from the browser's own parse", () => {
    expect(urlContact("https://help.example.com")).toEqual({ href: "https://help.example.com/", host: "help.example.com", rest: "" });
    expect(urlContact("https://help.example.com/support?x=1&y=2")).toEqual({
      href: "https://help.example.com/support?x=1&y=2", host: "help.example.com", rest: "/support?x=1&y=2",
    });
    expect(urlContact("https://xn--e1afmkfd.xn--p1ai/")?.host).toBe("xn--e1afmkfd.xn--p1ai");
    expect(urlContact('https://example.com/a?b=<script>&c="x"')?.href).toBe("https://example.com/a?b=%3Cscript%3E&c=%22x%22");
  });

  it("url: refuses every other scheme, user-info, port, IP literal, odd spelling and overlong value", () => {
    const bad = [
      "http://example.com", "HTTPS://example.com", "javascript:alert(1)", "data:text/html,<b>", "//example.com", "example.com",
      "https://user@example.com", "https://user:pw@example.com/", "https://example.com:8443/", "https://example.com:443/",
      "https://1.2.3.4/", "https://[::1]/", "https://localhost/", "https://example/", "https://EXAMPLE.com/", "https://example.com./",
      "https://example.com/a b", "https://example.com/a\\b", "https://example.com/#frag", "https:///example.com", "https://exa mple.com",
      "https://-bad.example.com", "https://exa_mple.com", "https://example.com\u0000", "https://exämple.com/",
      `https://example.com/${"a".repeat(200)}`, "https://example.com/\n", "https://example.com@evil.example/",
    ];
    for (const u of bad) expect(urlContact(u), u).toBeNull();
  });

  it("validContact decides kind and value together", () => {
    expect(validContact("phone", "442079460958")).toBe(true);
    expect(validContact("email", "help@example.com")).toBe(true);
    expect(validContact("url", "https://help.example.com/x")).toBe(true);
    expect(validContact("phone", "help@example.com")).toBe(false);
    expect(validContact("url", "442079460958")).toBe(false);
    expect(validContact("sms", "442079460958")).toBe(false);
    expect(validContact("", "")).toBe(false);
  });

  it("parses each kind through the response, and refuses a hostile one as a whole", () => {
    expect(parseHostBranding(contactBody("email", "help@example.com")).contact).toEqual({ kind: "email", value: "help@example.com" });
    expect(parseHostBranding(contactBody("url", "https://help.example.com/x")).contact).toEqual({ kind: "url", value: "https://help.example.com/x" });
    for (const [kind, value] of [["url", "javascript:alert(1)"], ["url", "http://example.com"], ["email", "mailto:a@example.com"], ["phone", "+4420794609"],
      ["url", "https://user@example.com"], ["email", "help@example.com‮"]]) {
      expect(parseHostBranding(contactBody(kind!, value!)), `${kind} ${value}`).toBe(NEUTRAL_BRAND);
    }
  });
});

describe("where to ask", () => {
  it("builds the public route on the page's own origin through the /cp prefix", () => {
    expect(publicBrandingUrl("https://acme.deskrally.com")).toBe("https://acme.deskrally.com/cp/public/branding");
    expect(publicBrandingUrl("https://acme.deskrally.com/")).toBe("https://acme.deskrally.com/cp/public/branding");
    expect(publicBrandingUrl("http://127.0.0.1:5173")).toBe("http://127.0.0.1:5173/cp/public/branding");
  });

  it("builds the logo address from a valid hash only", () => {
    expect(publicBrandingLogoUrl("https://acme.deskrally.com", HASH)).toBe(`https://acme.deskrally.com/cp/public/branding/logo?rev=${HASH}`);
    expect(publicBrandingLogoUrl("https://acme.deskrally.com", "")).toBe("");
    expect(publicBrandingLogoUrl("https://acme.deskrally.com", "nothex")).toBe("");
    expect(publicBrandingLogoUrl("https://acme.deskrally.com", `${HASH}&x=1`)).toBe("");
  });
});

describe("validLogoSrc: the only three constructions an <img> may be given", () => {
  it("accepts the published-hash route (relative or absolute), a blob: URL and a raster data: URI", () => {
    for (const ok of [
      `/cp/public/branding/logo?rev=${HASH}`,
      `https://acme.deskrally.com/cp/public/branding/logo?rev=${HASH}`,
      `http://127.0.0.1:5173/cp/public/branding/logo?rev=${HASH}`,
      "blob:https://acme.deskrally.com/3f1c2a9e-5b7d-4f0a-9c3e-0d1e2f3a4b5c",
      "blob:http://127.0.0.1:5173/3f1c2a9e-5b7d-4f0a-9c3e-0d1e2f3a4b5c",
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC",
      "data:image/jpeg;base64,/9j/4AAQSkZJRg==",
      "data:image/gif;base64,R0lGODlhAQABAAAAACw=",
      "data:image/webp;base64,UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==",
    ]) {
      expect(validLogoSrc(ok), ok.slice(0, 60)).toBe(true);
    }
  });

  it("refuses everything else", () => {
    for (const bad of [
      undefined, "", "javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "data:image/svg+xml;base64,PHN2Zz4=",
      "data:image/svg+xml,<svg onload=alert(1)>", "data:image/png,rawbytes", "data:image/png;base64,AAAA\"onerror=alert(1)",
      "https://evil.example/logo.png", "//evil.example/cp/public/branding/logo?rev=" + HASH, "/cp/public/branding/logo", "/cp/public/branding/logo?rev=",
      `/cp/public/branding/logo?rev=${HASH.slice(1)}`, `/cp/public/branding/logo?rev=${HASH}&x=1`, `/cp/public/branding/logo?rev=${HASH.toUpperCase()}`,
      `/cp/public/branding/logo/../../../etc/passwd?rev=${HASH}`, `/cp/other?rev=${HASH}`, `/x/cp/public/branding/logo?rev=${HASH}`,
      `javascript:/cp/public/branding/logo?rev=${HASH}`, `/cp/public/branding/logo?rev=${HASH}#x`, `/cp/public/branding/logo?rev=${HASH}\n`,
      "blob:javascript:alert(1)", "blob:https://acme.deskrally.com/not-a-uuid", "file:///etc/passwd", "ftp://x.example/a.png",
      "data:image/png;base64," + "A".repeat(260_000),
    ]) {
      expect(validLogoSrc(bad), String(bad).slice(0, 70)).toBe(false);
    }
  });
});

// ---- the lookup -------------------------------------------------------------------------------------------

type Call = { url: string; init: RequestInit };

function recorder(handler: (call: Call) => Promise<Response> | Response) {
  const calls: Call[] = [];
  const fetchFn = (url: string, init?: RequestInit) => {
    const call = { url, init: init ?? {} };
    calls.push(call);
    return Promise.resolve().then(() => handler(call));
  };
  return { calls, fetchFn };
}

const ORIGIN = "https://acme.deskrally.com";

describe("fetchHostBranding", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("asks exactly once, with no cache, no cookies, no referrer, no redirects", async () => {
    const { calls, fetchFn } = recorder(() => new Response(JSON.stringify(body()), { status: 200 }));
    const brand = await fetchHostBranding(ORIGIN, { fetchFn });
    expect(brand.name).toBe("Acme IT Support");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://acme.deskrally.com/cp/public/branding");
    expect(calls[0]!.init).toMatchObject({ method: "GET", cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
    expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
    expect(calls[0]!.init.headers).toBeUndefined();
    expect(calls[0]!.init.body).toBeUndefined();
  });

  it("is neutral for the control plane's neutral bytes", async () => {
    const { fetchFn } = recorder(() => new Response(NEUTRAL_BYTES, { status: 200 }));
    expect(await fetchHostBranding(ORIGIN, { fetchFn })).toBe(NEUTRAL_BRAND);
  });

  for (const status of [201, 204, 301, 304, 400, 401, 403, 404, 421, 429, 500, 502, 503]) {
    it(`is neutral for HTTP ${status}, even with a valid brand in the body`, async () => {
      const { calls, fetchFn } = recorder(() => new Response(status === 204 || status === 304 ? null : JSON.stringify(body()), { status }));
      expect(await fetchHostBranding(ORIGIN, { fetchFn })).toBe(NEUTRAL_BRAND);
      expect(calls).toHaveLength(1);
    });
  }

  it("releases the body of an answer it ignores", async () => {
    let cancelled = false;
    const { fetchFn } = recorder(() => ({ status: 429, body: { cancel: () => { cancelled = true; return Promise.resolve(); } } }) as unknown as Response);
    expect(await fetchHostBranding(ORIGIN, { fetchFn })).toBe(NEUTRAL_BRAND);
    expect(cancelled).toBe(true);
  });

  for (const [what, text] of [
    ["an empty body", ""],
    ["not JSON", "not json"],
    ["an HTML page (an SPA fallback answering the route)", "<!doctype html><title>x</title>"],
    ["JSON null", "null"],
    ["a JSON array", "[]"],
    ["a JSON string", '"Acme"'],
    ["a truncated object", '{"product_name":"Acme IT"'],
    ["an oversized body", JSON.stringify({ ...body(), padding: "x".repeat(HOST_BRANDING_MAX_BODY) })],
  ] as const) {
    it(`is neutral for ${what}`, async () => {
      const { fetchFn } = recorder(() => new Response(text, { status: 200 }));
      expect(await fetchHostBranding(ORIGIN, { fetchFn })).toBe(NEUTRAL_BRAND);
    });
  }

  it("is neutral when the network fails, and never rejects", async () => {
    const { calls, fetchFn } = recorder(() => Promise.reject(new TypeError("Failed to fetch")));
    await expect(fetchHostBranding(ORIGIN, { fetchFn })).resolves.toBe(NEUTRAL_BRAND);
    expect(calls).toHaveLength(1);
  });

  it("is neutral when fetch itself throws", async () => {
    const fetchFn = () => {
      throw new Error("boom");
    };
    await expect(fetchHostBranding(ORIGIN, { fetchFn })).resolves.toBe(NEUTRAL_BRAND);
  });

  it("is neutral when the body cannot be read", async () => {
    const { fetchFn } = recorder(() => ({ status: 200, text: () => Promise.reject(new Error("reset")) }) as unknown as Response);
    await expect(fetchHostBranding(ORIGIN, { fetchFn })).resolves.toBe(NEUTRAL_BRAND);
  });

  it("gives up at 1.5 s, aborts the request, and does not retry", async () => {
    // The documented "about 1.5 s". Everything below follows the constant, so the number itself is pinned here (a guest is
    // never kept waiting on a brand: docs/66 stage 2).
    expect(HOST_BRANDING_TIMEOUT_MS).toBe(1500);
    vi.useFakeTimers();
    const { calls, fetchFn } = recorder((call) => new Promise<Response>((_, reject) => {
      call.init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }));
    let result: unknown;
    void fetchHostBranding(ORIGIN, { fetchFn }).then((b) => { result = b; });
    await vi.advanceTimersByTimeAsync(HOST_BRANDING_TIMEOUT_MS - 1);
    expect(result).toBeUndefined();
    expect(calls[0]!.init.signal!.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(result).toBe(NEUTRAL_BRAND);
    expect(calls[0]!.init.signal!.aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toHaveLength(1);
  });

  it("settles on time even when fetch ignores the abort signal", async () => {
    vi.useFakeTimers();
    const { fetchFn } = recorder(() => new Promise<Response>(() => {}));
    let result: unknown;
    void fetchHostBranding(ORIGIN, { fetchFn, timeoutMs: 250 }).then((b) => { result = b; });
    await vi.advanceTimersByTimeAsync(249);
    expect(result).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(result).toBe(NEUTRAL_BRAND);
  });

  it("settles on time when the body stalls after the headers", async () => {
    vi.useFakeTimers();
    const { fetchFn } = recorder(() => ({ status: 200, text: () => new Promise<string>(() => {}) }) as unknown as Response);
    let result: unknown;
    void fetchHostBranding(ORIGIN, { fetchFn }).then((b) => { result = b; });
    await vi.advanceTimersByTimeAsync(HOST_BRANDING_TIMEOUT_MS);
    expect(result).toBe(NEUTRAL_BRAND);
  });

  it("an answer that arrives after the timeout is never applied", async () => {
    vi.useFakeTimers();
    let answer!: (r: Response) => void;
    const { fetchFn } = recorder(() => new Promise<Response>((resolve) => { answer = resolve; }));
    let result: unknown;
    void fetchHostBranding(ORIGIN, { fetchFn }).then((b) => { result = b; });
    await vi.advanceTimersByTimeAsync(HOST_BRANDING_TIMEOUT_MS + 500);
    answer(new Response(JSON.stringify(body()), { status: 200 }));
    await vi.advanceTimersByTimeAsync(10);
    expect(result).toBe(NEUTRAL_BRAND);
  });

  it("abandons the lookup when the caller aborts (the page went away)", async () => {
    const ac = new AbortController();
    const { calls, fetchFn } = recorder((call) => new Promise<Response>((_, reject) => {
      call.init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }));
    const pending = fetchHostBranding(ORIGIN, { fetchFn, signal: ac.signal });
    await Promise.resolve();
    ac.abort();
    await expect(pending).resolves.toBe(NEUTRAL_BRAND);
    expect(calls[0]!.init.signal!.aborted).toBe(true);
    // An already-aborted signal never even needs the network to settle.
    const { fetchFn: never } = recorder(() => new Promise<Response>(() => {}));
    await expect(fetchHostBranding(ORIGIN, { fetchFn: never, signal: ac.signal })).resolves.toBe(NEUTRAL_BRAND);
  });

  it("a hostile brand in a 200 is neutral end to end", async () => {
    const { fetchFn } = recorder(() => new Response(JSON.stringify(contactBody("url", "javascript:alert(document.cookie)")), { status: 200 }));
    expect(await fetchHostBranding(ORIGIN, { fetchFn })).toBe(NEUTRAL_BRAND);
  });
});
