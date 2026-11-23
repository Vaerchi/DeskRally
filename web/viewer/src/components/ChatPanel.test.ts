/**
 * Pure-logic tests for the chat panel (M12): transcript formatting, the send-enabled rule, the
 * composer's disabled/explanation state and the Enter/Shift+Enter rule. Rendering is not exercised
 * (the project has no component test harness), matching `Viewer.test.ts`.
 */

import { describe, it, expect } from "vitest";
import {
  chatComposerState,
  chatFromLabel,
  chatKeySends,
  chatLines,
  chatSendEnabled,
  formatChatTime,
} from "./ChatPanel";
import type { ChatEntry } from "../lib/chat";

/** A local wall-clock time expressed as Unix ms — `Date(y, m, d, h, min)` is LOCAL, like the formatter. */
const at = (h: number, min: number) => new Date(2024, 0, 2, h, min, 30).getTime();

const transcript: ChatEntry[] = [
  { seq: 1, from: "Technician", body: "Hi, I can see your desktop", at_unix_ms: at(9, 5) },
  { seq: 2, from: "Guest", body: "my printer is broken", at_unix_ms: at(9, 6) },
  { seq: 3, from: "Technician", body: "let me look", at_unix_ms: at(14, 30) },
];

describe("chat transcript formatting", () => {
  it("formats one line per entry, in the order given, keyed by the agent's seq", () => {
    const lines = chatLines(transcript);
    expect(lines.map((l) => l.seq)).toEqual([1, 2, 3]);
    expect(lines.map((l) => l.body)).toEqual([
      "Hi, I can see your desktop",
      "my printer is broken",
      "let me look",
    ]);
  });

  it("labels the sender's ROLE and marks the technician's own side", () => {
    const lines = chatLines(transcript);
    expect(lines.map((l) => l.label)).toEqual(["Technician", "Guest", "Technician"]);
    // The visual distinction is `mine`, not the label: `ChatFrom` is a role, not an identity, so a
    // line must never claim to be "You" — a second technician's message would then read as ours.
    expect(lines.map((l) => l.mine)).toEqual([true, false, true]);
    expect(chatFromLabel("Technician")).toBe("Technician");
    expect(chatFromLabel("Guest")).toBe("Guest");
  });

  it("renders local wall-clock HH:MM, zero-padded", () => {
    // Zero padding keeps the column fixed-width; asserting it explicitly because a bare
    // `getHours()` reads "9:05" and makes the log jitter at 10:00.
    expect(formatChatTime(at(9, 5))).toBe("09:05");
    expect(formatChatTime(at(14, 30))).toBe("14:30");
    expect(formatChatTime(at(0, 0))).toBe("00:00");
    expect(chatLines(transcript).map((l) => l.time)).toEqual(["09:05", "09:06", "14:30"]);
  });

  it("formats an empty transcript as no lines", () => {
    expect(chatLines([])).toEqual([]);
  });
});

describe("chat send-enabled rule", () => {
  it("needs both a live session and a non-blank draft", () => {
    expect(chatSendEnabled("hello", true)).toBe(true);
    expect(chatSendEnabled("hello", false)).toBe(false); // no session
    expect(chatSendEnabled("", true)).toBe(false);
  });

  it("treats a whitespace-only draft as empty", () => {
    // The agent RECORDS what it is sent (it truncates over-long bodies rather than rejecting them),
    // so a stray Enter would persist a blank line into a support transcript that outlives the session.
    expect(chatSendEnabled("   ", true)).toBe(false);
    expect(chatSendEnabled("\n\t ", true)).toBe(false);
    // ...but content with surrounding whitespace is real content.
    expect(chatSendEnabled("  ok  ", true)).toBe(true);
  });
});

describe("chat composer state", () => {
  it("disables with an explanation when there is no session", () => {
    const off = chatComposerState(false);
    expect(off.disabled).toBe(true);
    // A disabled box with no explanation leaves the operator unable to tell "broken" from "no
    // session yet", so assert the reason is actually carried.
    expect(off.title).toMatch(/connect to a machine/i);
  });

  it("is enabled, and still explains itself, with a live session", () => {
    const on = chatComposerState(true);
    expect(on.disabled).toBe(false);
    expect(on.title).toMatch(/message/i);
  });
});

describe("chat composer keys", () => {
  it("Enter sends, Shift+Enter inserts a newline", () => {
    expect(chatKeySends("Enter", false)).toBe(true);
    expect(chatKeySends("Enter", true)).toBe(false);
    expect(chatKeySends("a", false)).toBe(false);
    expect(chatKeySends("Escape", false)).toBe(false);
  });

  it("Enter mid-IME composition does NOT send", () => {
    // That Enter commits the candidate the user is picking (Japanese/Chinese/Korean input). Sending
    // on it would fire a half-finished fragment on the first keystroke — and chat is exactly the
    // channel where non-Latin input is expected.
    expect(chatKeySends("Enter", false, true)).toBe(false);
    expect(chatKeySends("Enter", false, false)).toBe(true);
  });
});
