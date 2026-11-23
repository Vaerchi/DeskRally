import { describe, expect, it, vi } from "vitest";
import { gateUploadOnCapability } from "./download_callbacks";
import { isSamePath } from "./filepath";

describe("isSamePath", () => {
  it("matches the same folder across case, separator and trailing separators", () => {
    expect(isSamePath("C:\\rmt-agent\\transfers", "c:\\RMT-AGENT\\transfers\\")).toBe(true);
    expect(isSamePath("C:\\rmt-agent\\transfers", "C:/rmt-agent/transfers")).toBe(true);
  });

  it("does not match a parent, a child, a sibling prefix or the drive roots", () => {
    expect(isSamePath("C:\\rmt-agent\\transfers", "C:\\rmt-agent")).toBe(false);
    expect(isSamePath("C:\\rmt-agent\\transfers", "C:\\rmt-agent\\transfers\\sub")).toBe(false);
    expect(isSamePath("C:\\rmt-agent\\transfers", "C:\\rmt-agent\\transfers2")).toBe(false);
    expect(isSamePath("", "")).toBe(false);
    expect(isSamePath("C:\\rmt-agent\\transfers", "")).toBe(false);
  });
});

describe("gateUploadOnCapability", () => {
  const ROOT = "C:\\rmt-agent\\transfers";
  const fn = vi.fn();

  it("offers upload with no grant yet (dev/direct-connect) or a grant that includes file_upload", () => {
    expect(gateUploadOnCapability(null, ROOT, fn)).toBe(fn);
    expect(gateUploadOnCapability(new Set(["file_upload"]), ROOT, fn)).toBe(fn);
  });

  it("hides upload when the grant explicitly omits file_upload, even if it has file_download", () => {
    expect(gateUploadOnCapability(new Set(["file_download", "file_browse"]), ROOT, fn)).toBeUndefined();
  });

  it("hides upload when the transfer root is unknown, whatever the grant", () => {
    expect(gateUploadOnCapability(null, undefined, fn)).toBeUndefined();
    expect(gateUploadOnCapability(new Set(["file_upload"]), undefined, fn)).toBeUndefined();
  });
});
