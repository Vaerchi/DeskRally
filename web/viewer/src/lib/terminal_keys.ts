// Under the Hood -> Command prompt: which keys the console handles itself instead of sending to the remote shell
// (2026-11-27 operator report: Ctrl+V did not paste - xterm.js turns it into ^V and cancels the browser's paste).

export interface TerminalKey {
  type: string;
  key: string;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  metaKey: boolean;
}

/**
 * - "paste": let the browser run its native paste; xterm turns the paste event into input for the shell.
 * - "copy": copy the terminal's selection (only when something is selected; otherwise Ctrl+C stays the interrupt).
 * - "terminal": xterm handles the key as usual.
 */
export type TerminalKeyAction = "paste" | "copy" | "terminal";

export function terminalKeyAction(e: TerminalKey, hasSelection: boolean): TerminalKeyAction {
  if (e.type !== "keydown" || e.altKey || e.metaKey) return "terminal";
  const k = e.key.toLowerCase();
  if (e.ctrlKey && k === "v") return "paste"; // Ctrl+V and Ctrl+Shift+V
  if (!e.ctrlKey && e.shiftKey && e.key === "Insert") return "paste";
  if (e.ctrlKey && k === "c" && (e.shiftKey || hasSelection)) return "copy";
  return "terminal";
}
