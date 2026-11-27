import { describe, it, expect } from "vitest";
import { terminalKeyAction, type TerminalKey } from "./terminal_keys";

const key = (k: string, mods: Partial<TerminalKey> = {}): TerminalKey => ({
  type: "keydown", key: k, ctrlKey: false, shiftKey: false, altKey: false, metaKey: false, ...mods,
});

describe("terminalKeyAction", () => {
  it("lets the browser paste on Ctrl+V, Ctrl+Shift+V and Shift+Insert", () => {
    expect(terminalKeyAction(key("v", { ctrlKey: true }), false)).toBe("paste");
    expect(terminalKeyAction(key("V", { ctrlKey: true, shiftKey: true }), false)).toBe("paste");
    expect(terminalKeyAction(key("Insert", { shiftKey: true }), false)).toBe("paste");
  });

  it("copies only with a selection (or Ctrl+Shift+C); plain Ctrl+C stays the interrupt", () => {
    expect(terminalKeyAction(key("c", { ctrlKey: true }), true)).toBe("copy");
    expect(terminalKeyAction(key("C", { ctrlKey: true, shiftKey: true }), false)).toBe("copy");
    expect(terminalKeyAction(key("c", { ctrlKey: true }), false)).toBe("terminal");
  });

  it("leaves everything else to the terminal, including key-up and Alt/Meta combinations", () => {
    expect(terminalKeyAction(key("a"), false)).toBe("terminal");
    expect(terminalKeyAction({ ...key("v", { ctrlKey: true }), type: "keyup" }, false)).toBe("terminal");
    expect(terminalKeyAction(key("v", { ctrlKey: true, altKey: true }), false)).toBe("terminal");
    expect(terminalKeyAction(key("d", { ctrlKey: true }), false)).toBe("terminal");
  });
});
