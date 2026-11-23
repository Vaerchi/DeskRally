/**
 * Unit tests for the credential-setup link helpers (docs/01 §5). Pure functions: the link an admin
 * hands over (`<origin>/set-password#<token>`) and the token recovery the redemption page does.
 */
import { describe, it, expect } from "vitest";
import {
  SETUP_LINK_PATH,
  setupLinkUrl,
  parseSetupToken,
  newPasswordsReady,
  showPasswordMismatch,
} from "./setup_link";

describe("setupLinkUrl", () => {
  it("builds <origin>/set-password#<token>", () => {
    expect(setupLinkUrl("https://console.example", "tok-abc")).toBe(
      "https://console.example/set-password#tok-abc",
    );
  });

  it("normalises trailing slashes on the origin so host and host/ agree", () => {
    const want = `https://h${SETUP_LINK_PATH}#t`;
    expect(setupLinkUrl("https://h", "t")).toBe(want);
    expect(setupLinkUrl("https://h/", "t")).toBe(want);
    expect(setupLinkUrl("https://h///", "t")).toBe(want);
  });

  it("percent-encodes the token so a '+', space, or '/' survives the fragment", () => {
    expect(setupLinkUrl("https://h", "a b+c/d")).toBe("https://h/set-password#a%20b%2Bc%2Fd");
  });

  it("returns '' for an empty token (no usable link without a secret)", () => {
    expect(setupLinkUrl("https://h", "")).toBe("");
  });
});

describe("parseSetupToken", () => {
  it("strips a leading '#' and returns the token", () => {
    expect(parseSetupToken("#tok-abc")).toBe("tok-abc");
  });

  it("accepts a fragment with no leading '#'", () => {
    expect(parseSetupToken("tok-abc")).toBe("tok-abc");
  });

  it("decodes percent-encoding (the inverse of setupLinkUrl)", () => {
    expect(parseSetupToken("#a%20b%2Bc%2Fd")).toBe("a b+c/d");
  });

  it("returns '' for an empty or bare-'#' fragment", () => {
    expect(parseSetupToken("")).toBe("");
    expect(parseSetupToken("#")).toBe("");
  });

  it("falls back to the raw fragment when the percent-encoding is malformed", () => {
    // decodeURIComponent("%") throws — the page must not crash on a hand-mangled link.
    expect(parseSetupToken("#%")).toBe("%");
  });

  it("round-trips any token through setupLinkUrl's encoding", () => {
    const token = "AbC+/=_-9 zx#weird";
    const url = setupLinkUrl("https://h", token);
    const frag = url.slice(url.indexOf("#"));
    expect(parseSetupToken(frag)).toBe(token);
  });
});

describe("newPasswordsReady (set-password submit gate)", () => {
  it("is true only when a non-empty password exactly matches its confirmation", () => {
    expect(newPasswordsReady("hunter2!", "hunter2!")).toBe(true);
  });

  it("is false while the confirmation is still empty — the button must stay DISABLED (the bug)", () => {
    // This is the exact defect the review caught: a lenient check enabled the button with confirm empty
    // while the submit handler required equality, so the click was a silent no-op.
    expect(newPasswordsReady("hunter2!", "")).toBe(false);
  });

  it("is false when the two differ", () => {
    expect(newPasswordsReady("hunter2!", "hunterX")).toBe(false);
  });

  it("is false when the password itself is empty (even if confirm also is)", () => {
    expect(newPasswordsReady("", "")).toBe(false);
  });
});

describe("showPasswordMismatch (set-password note)", () => {
  it("is true only once confirm is non-empty AND differs", () => {
    expect(showPasswordMismatch("hunter2!", "hunterX")).toBe(true);
  });

  it("is false while confirm is empty (not-yet, not wrong — no note)", () => {
    expect(showPasswordMismatch("hunter2!", "")).toBe(false);
  });

  it("is false when they match", () => {
    expect(showPasswordMismatch("hunter2!", "hunter2!")).toBe(false);
  });
});
