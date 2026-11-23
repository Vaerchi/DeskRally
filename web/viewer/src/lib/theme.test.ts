import { describe, expect, it } from "vitest";
import initScript from "../../public/theme-init.js?raw";
import indexHtml from "../../index.html?raw";
// The viewer has no @types/node; vitest runs in node, so the import resolves at run time.
// @ts-ignore TS2307
import { readFileSync } from "node:fs";
import {
  applyThemePreference,
  parseThemePreference,
  prefersReducedMotion,
  readThemePreference,
  resolveTheme,
  saveThemePreference,
  THEME_COLOR,
  THEME_PREF_KEY,
} from "./theme";

/** A document with just what applyThemePreference touches. */
function fakeDoc(metaColors: string[] = ["#f6f8fa", "#0e1116"]) {
  const attrs = new Map<string, string>();
  const metas = metaColors.map((content) => ({ content, dataset: {} as Record<string, string | undefined> }));
  const doc = {
    documentElement: {
      setAttribute: (k: string, v: string) => void attrs.set(k, v),
      removeAttribute: (k: string) => void attrs.delete(k),
      getAttribute: (k: string) => attrs.get(k) ?? null,
    },
    querySelectorAll: () => ({ forEach: (fn: (m: unknown) => void) => metas.forEach(fn) }),
  };
  return { doc: doc as unknown as Document, attrs, metas };
}
const win = (light: boolean, reduce = false) =>
  ({ matchMedia: (q: string) => ({ matches: q.includes("reduced-motion") ? reduce : q.includes("light") ? light : false }) }) as Pick<Window, "matchMedia">;
function fakeStorage(initial: Record<string, string> = {}) {
  const m = new Map(Object.entries(initial));
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k), m };
}

// A .css ?raw import is emptied by the CSS pipeline, so read the shipped stylesheet from disk.
const indexCss = readFileSync(new URL("../index.css", import.meta.url), "utf8");

describe("theme preference", () => {
  it("defaults to System for absent, empty and unrecognised values", () => {
    for (const raw of [null, undefined, "", "system", "auto", "LIGHT", "{}", "dark "]) expect(parseThemePreference(raw)).toBe("system");
  });
  it("reads a stored explicit choice", () => {
    expect(parseThemePreference("light")).toBe("light");
    expect(parseThemePreference("dark")).toBe("dark");
    expect(readThemePreference(fakeStorage({ [THEME_PREF_KEY]: "light" }))).toBe("light");
    expect(readThemePreference(fakeStorage())).toBe("system");
    expect(readThemePreference(null)).toBe("system");
  });
  it("a throwing storage reads as System", () => {
    expect(readThemePreference({ getItem: () => { throw new Error("blocked"); } })).toBe("system");
  });
  it("resolves System through the OS preference", () => {
    expect(resolveTheme("system", true)).toBe("light");
    expect(resolveTheme("system", false)).toBe("dark");
    expect(resolveTheme("dark", true)).toBe("dark");
    expect(resolveTheme("light", false)).toBe("light");
  });
});

describe("applying the preference", () => {
  it("an explicit choice sets data-theme and the browser chrome colour", () => {
    const { doc, attrs, metas } = fakeDoc();
    applyThemePreference("light", doc, win(false));
    expect(attrs.get("data-theme")).toBe("light");
    expect(metas.every((m) => m.content === THEME_COLOR.light)).toBe(true);
    applyThemePreference("dark", doc, win(true));
    expect(attrs.get("data-theme")).toBe("dark");
    expect(metas.every((m) => m.content === THEME_COLOR.dark)).toBe(true);
  });
  it("System removes the attribute and restores the shipped meta colours", () => {
    const { doc, attrs, metas } = fakeDoc();
    applyThemePreference("dark", doc, win(true));
    applyThemePreference("system", doc, win(true));
    expect(attrs.has("data-theme")).toBe(false);
    expect(metas.map((m) => m.content)).toEqual(["#f6f8fa", "#0e1116"]);
  });
  it("saving stores an explicit choice, clears it for System, and applies either way", () => {
    const st = fakeStorage();
    const { doc, attrs } = fakeDoc();
    saveThemePreference("light", st, doc, win(false));
    expect(st.m.get(THEME_PREF_KEY)).toBe("light");
    expect(attrs.get("data-theme")).toBe("light");
    saveThemePreference("system", st, doc, win(false));
    expect(st.m.has(THEME_PREF_KEY)).toBe(false);
    expect(attrs.has("data-theme")).toBe(false);
  });
  it("still applies when storage throws", () => {
    const { doc, attrs } = fakeDoc();
    const bad = { setItem: () => { throw new Error("full"); }, removeItem: () => { throw new Error("full"); } };
    saveThemePreference("dark", bad, doc, win(false));
    expect(attrs.get("data-theme")).toBe("dark");
  });
});

describe("the first-paint script and the stylesheet agree with the module", () => {
  /** Run the shipped theme-init.js against a stubbed window and document. */
  function runInit(stored: string | null) {
    const attrs = new Map<string, string>();
    const meta = { attrs: new Map<string, string>([["content", "#0e1116"]]), getAttribute(k: string) { return this.attrs.get(k) ?? null; }, setAttribute(k: string, v: string) { this.attrs.set(k, v); } };
    const window = { localStorage: { getItem: (k: string) => (k === THEME_PREF_KEY ? stored : null) } };
    const document = { documentElement: { setAttribute: (k: string, v: string) => void attrs.set(k, v) }, querySelectorAll: () => [meta] };
    new Function("window", "document", initScript)(window, document);
    return { attrs, meta };
  }
  it("applies a stored choice and ignores everything else", () => {
    expect(runInit("light").attrs.get("data-theme")).toBe("light");
    expect(runInit("light").meta.attrs.get("content")).toBe(THEME_COLOR.light);
    expect(runInit("dark").attrs.get("data-theme")).toBe("dark");
    expect(runInit("dark").meta.attrs.get("content")).toBe(THEME_COLOR.dark);
    for (const v of [null, "system", "bogus"]) expect(runInit(v).attrs.size).toBe(0);
  });
  it("is loaded from the head as an external script, before the stylesheet can paint", () => {
    expect(indexHtml).toMatch(/<script src="\/theme-init\.js"><\/script>/);
    expect(indexHtml.indexOf("theme-init.js")).toBeLessThan(indexHtml.indexOf("/src/main.tsx"));
    expect(initScript).not.toMatch(/<script/);
  });
  it("the stylesheet has dark, light and system-light palettes with the same token names", () => {
    const tokens = (block: string) => [...block.matchAll(/^\s*(--[a-z0-9-]+):/gm)].map((m) => m[1]!);
    const dark = indexCss.match(/:root,\s*:root\[data-theme="dark"\]\s*\{([\s\S]*?)\n\}/)![1]!;
    const light = indexCss.match(/:root\[data-theme="light"\]\s*\{([\s\S]*?)\n\}/)![1]!;
    const sys = indexCss.match(/@media \(prefers-color-scheme: light\) \{\s*:root:not\(\[data-theme\]\) \{([\s\S]*?)\n  \}/)![1]!;
    expect(dark).toContain("color-scheme: dark");
    expect(light).toContain("color-scheme: light");
    expect(sys).toContain("color-scheme: light");
    // The two light blocks are the same palette, token for token and value for value.
    const norm = (b: string) => b.split("\n").map((l) => l.trim()).filter(Boolean).sort().join("\n");
    expect(norm(sys)).toBe(norm(light));
    // Every token the light palette overrides exists in the dark one, so no theme leaves a gap.
    const darkSet = new Set(tokens(dark));
    for (const t of tokens(light)) expect(darkSet.has(t), t).toBe(true);
  });
  it("has a reduced-motion block", () => {
    expect(indexCss).toContain("@media (prefers-reduced-motion: reduce)");
    expect(prefersReducedMotion(win(false, true))).toBe(true);
    expect(prefersReducedMotion(win(false, false))).toBe(false);
  });
});
