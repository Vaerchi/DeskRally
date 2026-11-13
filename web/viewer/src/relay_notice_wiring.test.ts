/**
 * App wiring of the relay-limit notice (lib/relay_notice.ts, components/RelayNotice.tsx).
 *
 * App.tsx is not collected by vitest, so its wiring is pinned by SOURCE TEXT, region by region: an assertion
 * is about WHERE something is (the teardown body, the header, the session area), not merely that the string
 * exists somewhere. e2e/relay_notice.spec.ts proves the behaviour; this catches a silent unplug, and the one
 * placement rule that is a rule rather than a behaviour: the session top bar is a Chrome-Remote-Desktop-style
 * tab, so nothing may be added to it.
 *
 * The same source-text approach guards the feature's own files against raw invisible characters (see the last
 * describe): its tests feed the sanitiser bidi and zero-width characters, and those must be written as escapes.
 */
import { describe, expect, it } from "vitest";
import appSource from "./App.tsx?raw";
import relayNoticeSource from "./lib/relay_notice.ts?raw";
import relayNoticeTestSource from "./lib/relay_notice.test.ts?raw";
import relayNoticeComponentSource from "./components/RelayNotice.tsx?raw";
import relayNoticeComponentTestSource from "./components/RelayNotice.test.tsx?raw";
import transportTestSource from "./lib/transport.test.ts?raw";
import wiringTestSource from "./relay_notice_wiring.test.ts?raw";

const src = appSource.replace(/\r\n/g, "\n");

/** The text from `start` up to the first `end` after it: a named region of App.tsx. */
function region(start: string, end: string): string {
  const from = src.indexOf(start);
  expect(from, `App.tsx no longer contains: ${start}`).toBeGreaterThanOrEqual(0);
  const to = src.indexOf(end, from + start.length);
  expect(to, `App.tsx no longer contains, after "${start}": ${end}`).toBeGreaterThan(from);
  return src.slice(from, to);
}

const teardownBody = () => region("const teardown = useCallback((preserveRecovery = false) => {", "}, [stopRenewingLease]);");
const disconnectBody = () => region("const disconnectSession = useCallback(() => {", "}, [teardown]);");
/** What connectImpl does right after the teardown every connect starts with. */
const afterConnectTeardown = () => region("teardown(recovering);", "if (observe) preAcquired = undefined;");
const transportCreation = () => region("const transport = new WebRTCTransport(", "transportRef.current = transport;");
const stateHandler = () => region("const handleTransportState = useCallback(", "const startRenewingLease");
const headerBlock = () => region("<header className={`app__topbar", "</header>");
const sessionArea = () => region('<div className="app__session">', '{area === "live" && !session && (');

describe("App wiring of the relay notice", () => {
  it("takes the notice from the transport's own event, for the CURRENT connection only", () => {
    const creation = transportCreation();
    // The same shape as the transport's other events: guarded, so a superseded transport cannot repaint.
    expect(creation).toMatch(/onRelayNotice: \(notice\) => \{ if \(isCurrent\(\)\) setRelayNotice\(notice\); \},/);
    // And nothing polls the transport for it.
    expect(src).not.toMatch(/setInterval\([^)]*relayNotice/);
    expect(src).not.toMatch(/transportRef\.current\??\.relayNotice/);
  });

  it("resets the notice with every transport, and leaves its dismissal to the MACHINE, not to teardown", () => {
    const body = teardownBody();
    expect(body).toContain("setRelayNotice(null);");
    // Teardown runs for EVERY reconnect. A display-layout end reconnects through a fresh connect (reconnectManually,
    // recovering=false), not teardown(true), so a reset here brought a closed strip back after each layout change.
    expect(body).not.toMatch(/RelayNoticeDismiss/i);
    // The old, per-transport flag is gone for good.
    expect(src).not.toMatch(/\brelayNoticeDismissed\b|\bsetRelayNoticeDismissed\(/);
  });

  it("ends the dismissal for a disconnect and for a connect to ANOTHER machine, and for nothing else", () => {
    expect(disconnectBody()).toContain("setRelayNoticeDismissedFor(null);");
    // Kept for the same device (recovery, a layout reconnect, the Reconnect button), cleared for another.
    expect(afterConnectTeardown()).toContain("setRelayNoticeDismissedFor((kept) => (kept === device ? kept : null));");
    // These two and the banner's own Dismiss are the only writers: a fourth is a new way to bring it back.
    expect([...src.matchAll(/setRelayNoticeDismissedFor\(/g)]).toHaveLength(3);
  });

  it("passes the transport's relay-limit cause with a failed state, and with nothing else", () => {
    const creation = transportCreation();
    expect(creation).toContain(
      'handleTransportState(s, undefined, s === "failed" ? transport.relayLimitCause() : null)',
    );
    // The other callers know their own reason (offline, a refused lease) and pass none.
    expect(src).not.toMatch(/handleTransportState\("failed", [^)]*relayLimitCause/);
  });

  it("words both failure messages (the recovery notice and the released-session error) with the cause", () => {
    const handler = stateHandler();
    expect(handler).toContain('const lost = withRelayLimitCause("Connection lost", relayCause);');
    // Recovery: the generic message, and its attended variant, both go through `lost`.
    expect(handler).toMatch(/\? `\$\{lost\}\. Return to Support to reconnect with guest consent` : lost\)/);
    // The error shown when recovery is off.
    expect(handler).toContain('withRelayLimitCause("the connection to this machine was lost", relayCause)');
    // With no cause the old wording is exactly what is left: both messages are built around the same words.
    expect(handler).toContain("the session has been released; reconnect to continue");
  });

  it("shows the banner in the SESSION AREA, below the views, until it is dismissed for THIS machine", () => {
    const area = sessionArea();
    expect(area).toMatch(
      /\{relayNotice && relayNoticeDismissedFor !== session\.device && \(\n\s+<RelayNotice notice=\{relayNotice\} onDismiss=\{\(\) => setRelayNoticeDismissedFor\(session\.device\)\} \/>\n\s+\)\}/,
    );
    // After the last view (so it is a strip under the picture and the panels, not above them).
    expect(area.indexOf("<RelayNotice")).toBeGreaterThan(area.indexOf('view === "chat"'));
    expect(area.indexOf("<RelayNotice")).toBeGreaterThan(area.indexOf("<SessionViewer"));
  });

  it("NEVER puts the notice in the session top bar (the Chrome-Remote-Desktop-style tab has no room)", () => {
    const header = headerBlock();
    expect(header).not.toContain("RelayNotice");
    expect(header).not.toContain("relayNotice");
    expect(header).not.toContain("relay-notice");
    // The notice is the component, not the app error banner (which lives in the bar and forces it open).
    expect(src).not.toMatch(/setError\([^)]*relayNotice/);
  });
});

/**
 * Every line of `text` with an invisible FORMAT character on it (Unicode Cf: the bidi overrides and isolates,
 * zero-width space and non-joiner, word joiner, soft hyphen, a byte-order mark inside a file...), as
 * "line N: U+XXXX". U+200D, the joiner inside an emoji sequence, is not one: an emoji is not a hidden character.
 * The pattern is written with escapes for the same reason this guard exists.
 */
function invisibleCharacters(text: string): string[] {
  const found: string[] = [];
  text.split("\n").forEach((line, index) => {
    for (const ch of line) {
      if (/(?!\u200D)\p{Cf}/u.test(ch)) found.push(`line ${index + 1}: U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`);
    }
  });
  return found;
}

describe("the relay notice's own sources carry no raw invisible characters", () => {
  // The sanitiser tests feed it bidi overrides and zero-width characters, and they are written as \u escapes.
  // Raw ones in source are the "Trojan Source" pattern: a hidden-Unicode linter flags the file, a reviewer sees the
  // line reordered or blank and cannot tell which string is under test, and an editor or formatter that strips
  // them changes what the test checks without a word. (file_transfer_error_name.test.ts does the same.)
  const sources: Record<string, string> = {
    "lib/relay_notice.ts": relayNoticeSource,
    "lib/relay_notice.test.ts": relayNoticeTestSource,
    "components/RelayNotice.tsx": relayNoticeComponentSource,
    "components/RelayNotice.test.tsx": relayNoticeComponentTestSource,
    "lib/transport.test.ts": transportTestSource,
    "relay_notice_wiring.test.ts": wiringTestSource,
  };

  for (const [name, text] of Object.entries(sources)) {
    it(name, () => {
      expect(invisibleCharacters(text), `${name}: write them as \\u escapes`).toEqual([]);
    });
  }

  it("the check itself sees what it is for (it flags the characters, and leaves an emoji joiner alone)", () => {
    // Built from escapes at run time, so this file stays clean.
    for (const cp of [0x202e, 0x200b, 0x2066, 0x2069, 0x200f, 0x2060, 0xfeff, 0x00ad]) {
      expect(invisibleCharacters(`a${String.fromCodePoint(cp)}b`), cp.toString(16)).toHaveLength(1);
    }
    expect(invisibleCharacters("clean \\u202E text\nand \u{1F469}\u200D\u{1F4BB}")).toEqual([]);
    expect(invisibleCharacters("one\ntwo\u202Ethree")).toEqual(["line 2: U+202E"]);
  });
});
