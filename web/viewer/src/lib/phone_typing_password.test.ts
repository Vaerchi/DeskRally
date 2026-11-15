/**
 * Phone typing in BOTH field modes (text and password). The diff, sentinel and reseed rules never look
 * at the element, only at its value, so a password input must give the guest exactly the events a text
 * field does for every input-event sequence Gboard, Samsung Keyboard and iOS produce. The only
 * behavioural differences are Enter (a single-line input has no newline edit) and that nothing may echo
 * a typed character. No DOM: a tiny field model plays the part of the element.
 */
import { describe, it, expect } from "vitest";
import {
  TYPING_SENTINEL as S,
  TYPING_RESEED_AT,
  typedLabel,
  typingFieldAttrs,
  typingFieldKey,
  typingStep,
  type TypingFieldMode,
} from "./phone_typing";
import { key, text, type InputEvent } from "./input";
import { vkForCode } from "./dom_input";
import viewerSource from "../components/Viewer.tsx?raw";

const tap = (code: string): InputEvent[] => [key(vkForCode(code), true), key(vkForCode(code), false)];
const BS = tap("Backspace");

/** One input event: what the keyboard did to the value, and whether a composition is open. */
interface Ev {
  inputType: string;
  /** The field's new value, from its current one. */
  to: (v: string) => string;
  composing?: boolean;
}
const insert = (s: string): Ev => ({ inputType: "insertText", to: (v) => v + s });
const del = (n = 1): Ev => ({ inputType: "deleteContentBackward", to: (v) => v.slice(0, Math.max(0, v.length - n)) });
const compose = (s: string): Ev => ({ inputType: "insertCompositionText", to: (v) => v + s, composing: true });
/** A composition that REWRITES its own marked text: the last `from` characters become `s`. */
const recompose = (from: number, s: string): Ev => ({
  inputType: "insertCompositionText",
  to: (v) => v.slice(0, v.length - from) + s,
  composing: true,
});
const replacement = (from: number, s: string): Ev => ({ inputType: "insertReplacementText", to: (v) => v.slice(0, v.length - from) + s });
const paste = (s: string): Ev => ({ inputType: "insertFromPaste", to: (v) => v + s });

/** The component's loop: diff against the last content, send, then reseed if the rules say so. */
function run(events: Ev[]): { sent: InputEvent[]; value: string } {
  let value = S;
  let content = "";
  const sent: InputEvent[] = [];
  for (const ev of events) {
    value = ev.to(value);
    const step = typingStep(content, value, ev.inputType, !!ev.composing);
    if (step.overflow) {
      value = S;
      content = "";
      continue;
    }
    sent.push(...step.events);
    content = step.content;
    if (step.reseed) {
      value = S;
      content = "";
    }
  }
  return { sent, value };
}

// The pure rules take no mode at all: running the same sequences once per mode documents that this IS the
// property (the component feeds both elements through the same function).
describe.each<TypingFieldMode>(["text", "password"])("input-event sequences in %s mode", () => {
  it("insertText: each typed character is one Text event (Gboard, no composition)", () => {
    expect(run([insert("p"), insert("a"), insert("s"), insert("s")]).sent).toEqual([text("p"), text("a"), text("s"), text("s")]);
  });

  it("deleteContentBackward after typing: one Backspace per deleted character", () => {
    expect(run([insert("a"), insert("b"), del()]).sent).toEqual([text("a"), text("b"), ...BS]);
  });

  it("deleteContentBackward on the empty field (only the sentinel is left) still sends a Backspace", () => {
    const first = run([del()]);
    expect(first.sent).toEqual(BS);
    // The sentinel went and the field reseeds, so the NEXT backspace is a Backspace too.
    expect(first.value).toBe(S);
    expect(run([del(), del()]).sent).toEqual([...BS, ...BS]);
  });

  it("insertCompositionText then compositionend: the word grows live, then the commit adds nothing", () => {
    const grow = run([compose("h"), recompose(1, "he"), recompose(2, "hel"), recompose(3, "hell"), recompose(4, "hello")]);
    // Each rewrite keeps the common prefix, so only the new character goes.
    expect(grow.sent).toEqual([text("h"), text("e"), text("l"), text("l"), text("o")]);
    // compositionend with an unchanged value sends nothing more.
    const done = typingStep("hello", S + "hello", undefined, false);
    expect(done.events).toEqual([]);
  });

  it("a pure append during composition costs only the new characters", () => {
    expect(run([compose("h"), compose("e"), compose("y")]).sent).toEqual([text("h"), text("e"), text("y")]);
  });

  it("a composition is never reseeded mid-word, even past the reseed length", () => {
    const long = "x".repeat(TYPING_RESEED_AT + 5);
    const step = typingStep("", S + long, "insertCompositionText", true);
    expect(step.reseed).toBe(false);
    expect(typingStep(long, S + long, undefined, false).reseed).toBe(true); // once it is committed
  });

  it("insertReplacementText (iOS autocorrect, a Gboard suggestion): teh -> the", () => {
    expect(run([insert("t"), insert("e"), insert("h"), replacement(3, "the")]).sent).toEqual([
      text("t"),
      text("e"),
      text("h"),
      ...BS,
      ...BS,
      text("he"),
    ]);
  });

  it("paste is one Text event, and a long paste reseeds the field", () => {
    expect(run([paste("hunter2")]).sent).toEqual([text("hunter2")]);
    const long = "z".repeat(TYPING_RESEED_AT + 1);
    const r = run([paste(long)]);
    expect(r.sent).toEqual([text(long)]);
    expect(r.value).toBe(S);
  });

  it("select-all + paste replaces the sentinel and the content: Backspaces for the content only", () => {
    const step = typingStep("abc", "xyz", "insertFromPaste", false);
    expect(step.events).toEqual([...BS, ...BS, ...BS, text("xyz")]);
  });

  it("a pasted password with a space and symbols arrives exactly as typed", () => {
    const pw = "P@ss w0rd!é\u{1F600}";
    expect(run([paste(pw)]).sent).toEqual([text(pw)]);
  });

  it("an edit beyond the cap is refused and the field resets", () => {
    const r = run([paste("q".repeat(1500))]);
    expect(r.sent).toEqual([]);
    expect(r.value).toBe(S);
  });
});

describe("Enter", () => {
  const base = { code: "Enter", keyCode: 13, isComposing: false };
  it("text mode: Enter is an edit (a newline in the textarea), not a passthrough key", () => {
    expect(typingFieldKey({ ...base, key: "Enter" })).toBeNull();
    expect(run([insert("dir"), insert("\n")]).sent).toEqual([text("dir"), ...tap("Enter")]);
  });
  it("password mode: a single-line input makes no edit for Enter, so it goes straight to the guest", () => {
    expect(typingFieldKey({ ...base, key: "Enter" }, { singleLine: true })).toEqual(tap("Enter"));
  });
  it("never hijacks an IME placeholder or a composition", () => {
    expect(typingFieldKey({ ...base, key: "Enter", keyCode: 229 }, { singleLine: true })).toBeNull();
    expect(typingFieldKey({ ...base, key: "Enter", isComposing: true }, { singleLine: true })).toBeNull();
  });
  it("printable keys and Backspace stay with the field in both modes", () => {
    for (const singleLine of [false, true]) {
      expect(typingFieldKey({ key: "a", code: "KeyA", keyCode: 65, isComposing: false }, { singleLine })).toBeNull();
      expect(typingFieldKey({ key: "Backspace", code: "Backspace", keyCode: 8, isComposing: false }, { singleLine })).toBeNull();
    }
  });
});

describe("typingFieldAttrs", () => {
  it("password: no autocomplete, autocorrect, autocapitalize or spellcheck, and never an inputMode", () => {
    const a = typingFieldAttrs("password");
    expect(a).toMatchObject({ autoComplete: "off", autoCorrect: "off", autoCapitalize: "off", spellCheck: false, managerOptOut: true });
    expect("inputMode" in a).toBe(false);
  });
  it("text mode keeps its own wording and no manager opt-out", () => {
    const a = typingFieldAttrs("text");
    expect(a.managerOptOut).toBe(false);
    expect(a.ariaLabel).toBe("Type to send to the remote machine");
    expect(a.ariaLabel).not.toBe(typingFieldAttrs("password").ariaLabel);
  });
});

describe("typedLabel", () => {
  it("password mode never carries the typed character", () => {
    expect(typedLabel("password", "typed Ctrl+s", "s")).toBe("typed Ctrl+(hidden)");
  });
  it("text mode and label-only cases are unchanged", () => {
    expect(typedLabel("text", "typed Ctrl+s", "s")).toBe("typed Ctrl+s");
    expect(typedLabel("password", "typed", null)).toBe("typed");
  });
});

describe("no trace", () => {
  const src: string = viewerSource;
  it("password mode is plain component state: never read from or written to storage", () => {
    expect(src).toMatch(/const \[passwordMode, setPasswordMode\] = useState\(false\)/);
    expect(src).not.toMatch(/(localStorage|sessionStorage|indexedDB)[^\n]*passwordMode|passwordMode[^\n]*(localStorage|sessionStorage|indexedDB)/);
  });
  it("the masked field is a real password input", () => {
    expect(src).toContain('<input key="pw" type="password"');
  });
});

describe("eager reseed (password mode retains nothing after an edit)", () => {
  const eager = { eager: true };
  it("reseeds after every ordinary edit, so nothing but that edit is ever held", () => {
    for (const v of [S + "a", S + "Zq9x7", S + "pw"]) {
      const step = typingStep("", v, "insertText", false, eager);
      expect(step.reseed).toBe(true);
      expect(step.events.length).toBeGreaterThan(0);
    }
    // The lazy (text-mode) rule keeps a short word in the field.
    expect(typingStep("", S + "a", "insertText", false).reseed).toBe(false);
  });
  it("never reseeds under a live composition, and never after an overflow refusal", () => {
    expect(typingStep("", S + "a", "insertCompositionText", true, eager).reseed).toBe(false);
    expect(typingStep("", S + "q".repeat(1500), "insertFromPaste", false, eager).reseed).toBe(false);
  });
  it("an eager field sends the same Text and Backspaces as the lazy one", () => {
    const run2 = (evs: Ev[], opts: { eager?: boolean }) => {
      let value = S;
      let content = "";
      const sent: InputEvent[] = [];
      for (const ev of evs) {
        value = ev.to(value);
        const st = typingStep(content, value, ev.inputType, !!ev.composing, opts);
        sent.push(...st.events);
        content = st.content;
        if (st.reseed) {
          value = S;
          content = "";
        }
      }
      return sent;
    };
    // Eager: the delete lands on the bare sentinel, which is a Backspace by the empty-field rule.
    expect(run2([insert("a"), insert("b"), del(), insert("c")], { eager: true })).toEqual([text("a"), text("b"), ...BS, text("c")]);
    expect(run2([del(), del()], { eager: true })).toEqual([...BS, ...BS]);
  });
});
