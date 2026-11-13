/**
 * The relay-limit notice's pure rules (lib/relay_notice.ts): which wire values count as a notice, the words
 * the technician reads, the clause a failure carries, and how the server's own text is cleaned for display.
 * The transport side (state, events, lifecycle, failure wording) is in transport.test.ts, the banner in
 * components/RelayNotice.test.tsx, the wiring in relay_notice_wiring.test.ts and the behaviour in
 * e2e/relay_notice.spec.ts.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  RELAY_LIMIT_CAUSE,
  RELAY_NOTICE_COPY,
  RELAY_NOTICE_DETAIL_MAX,
  RELAY_NOTICE_SCAN_MAX,
  isRelayNotice,
  relayNoticeDetail,
  withRelayLimitCause,
} from "./relay_notice";
import { SessionRecovery } from "./session_recovery";

afterEach(() => vi.useRealTimers());

describe("isRelayNotice", () => {
  it("accepts a string with something in it", () => {
    expect(isRelayNotice("relay capacity exhausted for your account; direct connection only")).toBe(true);
    expect(isRelayNotice("x")).toBe(true);
    // Padding around real text is still real text.
    expect(isRelayNotice("  x  ")).toBe(true);
  });

  it("treats empty, blank and non-string values as absent", () => {
    for (const value of [undefined, null, "", " ", "\n\t ", 0, 1, true, false, {}, [], ["x"], { toString: () => "x" }]) {
      expect(isRelayNotice(value), JSON.stringify(value)).toBe(false);
    }
  });
});

describe("the notice copy", () => {
  it("says what happened, what it means and what to do, in plain words", () => {
    const { headline, what, consequence, action } = RELAY_NOTICE_COPY;
    // What happened.
    expect(headline).toMatch(/no relay connection is available/i);
    expect(what).toMatch(/this account has reached its limit of relay credentials/i);
    // The consequence.
    expect(what).toMatch(/only a direct connection can be tried/i);
    expect(consequence).toMatch(/may fail on restrictive networks/i);
    // What to do: wait, or ask. Closing sessions is NOT advice: the server counts the credentials it has issued
    // and not yet expired, not the sessions alive (server/signaling/turn.go), so ending a session frees nothing,
    // and the copy says so instead of sending a technician off to do it.
    expect(action).not.toMatch(/close sessions you no longer need/i);
    expect(action).not.toMatch(/\bclose\b/i);
    expect(action).toMatch(/closing sessions will not free a relay credential/i);
    expect(action).toMatch(/kept until it expires, even after its session ends/i);
    expect(action).toMatch(/older relay credentials expire/i);
    expect(action).toMatch(/within 2 hours/i);
    expect(action).toMatch(/ask an administrator/i);
  });
});

describe("withRelayLimitCause", () => {
  it("names the relay limit as the likely cause, in the message's own sentence", () => {
    const out = withRelayLimitCause("Connection timed out", RELAY_LIMIT_CAUSE);
    expect(out).toBe(`Connection timed out (${RELAY_LIMIT_CAUSE})`);
    expect(out).toMatch(/likely cause/);
    expect(out).toMatch(/limit of relay credentials/);
  });

  it("returns the message untouched without a cause (nothing changes for an older server)", () => {
    expect(withRelayLimitCause("Connection lost", null)).toBe("Connection lost");
    expect(withRelayLimitCause("Connection lost", undefined)).toBe("Connection lost");
    expect(withRelayLimitCause("Connection lost", "")).toBe("Connection lost");
  });

  it("ends without a period, so the recovery notice that appends one stays a single sentence", () => {
    expect(RELAY_LIMIT_CAUSE.endsWith(".")).toBe(false);
    vi.useFakeTimers();
    const notices: string[] = [];
    const recovery = new SessionRecovery(async () => {}, (notice) => { if (notice) notices.push(notice.message); });
    recovery.enabled = true;
    recovery.lost(withRelayLimitCause("Connection lost", RELAY_LIMIT_CAUSE));
    recovery.cancel();
    expect(notices[0]).toBe(`Connection lost (${RELAY_LIMIT_CAUSE}). Reconnecting in 2s…`);
    expect(notices[0]).not.toContain("..");
  });
});

describe("relayNoticeDetail (the server's own text, cleaned for display as text)", () => {
  it("shows the server's wording as it is when it is plain", () => {
    expect(relayNoticeDetail("relay capacity exhausted for your account; direct connection only")).toBe(
      "relay capacity exhausted for your account; direct connection only",
    );
  });

  it("collapses whitespace and line breaks into one line", () => {
    expect(relayNoticeDetail("  a \n\n b\t c  ")).toBe("a b c");
  });

  it("drops control and format characters that could reorder or hide the text around it", () => {
    // U+202E RIGHT-TO-LEFT OVERRIDE, U+200B ZERO WIDTH SPACE, U+2066 LRI, NUL, ESC.
    expect(relayNoticeDetail("abc\u202Edef\u200Bghi\u2066j\u0000k\u001bl")).toBe("abc def ghi j k l");
  });

  it("leaves markup as the literal text it is (React escapes it; nothing here interprets it)", () => {
    const hostile = '<img src=x onerror="alert(1)"> <script>steal()</script>';
    expect(relayNoticeDetail(hostile)).toBe(hostile);
  });

  it("returns null when nothing displayable is left, or for a non-string", () => {
    for (const value of [undefined, null, "", "   ", "\u200B\u202E\u0000", 5, {}, ["x"]]) {
      expect(relayNoticeDetail(value), JSON.stringify(value)).toBeNull();
    }
  });

  it("cuts a long text at the limit with an ellipsis, by code point so a surrogate pair is never split", () => {
    const long = relayNoticeDetail("a".repeat(RELAY_NOTICE_DETAIL_MAX * 3))!;
    expect(Array.from(long)).toHaveLength(RELAY_NOTICE_DETAIL_MAX);
    expect(long.endsWith("…")).toBe(true);

    const emoji = relayNoticeDetail("😀".repeat(RELAY_NOTICE_DETAIL_MAX * 3))!;
    expect(Array.from(emoji)).toHaveLength(RELAY_NOTICE_DETAIL_MAX);
    // A lone surrogate would make this throw.
    expect(() => encodeURIComponent(emoji)).not.toThrow();

    // At the limit exactly: untouched.
    const exact = "b".repeat(RELAY_NOTICE_DETAIL_MAX);
    expect(relayNoticeDetail(exact)).toBe(exact);
  });

  it("does bounded work on a string from the network: only a prefix is looked at", () => {
    // Real text just past the window is never reached (without the bound this would return it).
    expect(relayNoticeDetail(" ".repeat(RELAY_NOTICE_SCAN_MAX) + "after the window")).toBeNull();
    // Real text inside it is.
    expect(relayNoticeDetail(" ".repeat(RELAY_NOTICE_SCAN_MAX - 7) + "visible")).toBe("visible");
    // A huge string still yields the bounded, ellipsised text.
    const huge = relayNoticeDetail("a".repeat(5_000_000))!;
    expect(Array.from(huge)).toHaveLength(RELAY_NOTICE_DETAIL_MAX);
  });

  it("never returns half a surrogate pair when the scan window cuts one", () => {
    // 999 spaces then an emoji: the 1000-unit window ends between its two halves.
    const cut = " ".repeat(RELAY_NOTICE_SCAN_MAX - 1) + "😀";
    expect(relayNoticeDetail(cut)).toBeNull();
    // One unit further and the whole pair is inside the window and survives.
    expect(relayNoticeDetail(" ".repeat(RELAY_NOTICE_SCAN_MAX - 2) + "😀")).toBe("😀");
  });
});
