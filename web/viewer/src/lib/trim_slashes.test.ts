import { describe, expect, it } from "vitest";
import { trimTrailingSlashes } from "./trim_slashes";

describe("trimTrailingSlashes", () => {
  it("removes every trailing slash and nothing else", () => {
    expect(trimTrailingSlashes("https://a.example/")).toBe("https://a.example");
    expect(trimTrailingSlashes("https://a.example///")).toBe("https://a.example");
    expect(trimTrailingSlashes("https://a.example/cp")).toBe("https://a.example/cp");
    expect(trimTrailingSlashes("a//b/")).toBe("a//b");
    expect(trimTrailingSlashes("///")).toBe("");
    expect(trimTrailingSlashes("")).toBe("");
  });

  it("is linear on a long run of slashes that is not at the end", () => {
    const s = "/".repeat(200_000) + "x";
    const t0 = performance.now();
    expect(trimTrailingSlashes(s)).toBe(s);
    expect(performance.now() - t0).toBeLessThan(200);
  });
});
