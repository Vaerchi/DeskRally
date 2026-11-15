/**
 * "Share clipboard automatically" — the technician's standing choice (2026-10-22, Ed: "automatic on,
 * but can be turned off").
 *
 * ON (the default when nothing is stored): every session starts with Receive enabled, and a click
 * into the remote screen sends the local clipboard first. OFF: the docs/25 F08 behaviour, where
 * Receive starts off in every session and Send is a button.
 *
 * Per browser profile (localStorage), which is the scope a technician expects of a viewer setting.
 * Storage can be missing or throw (private window, blocked site data): reads then fall back to the
 * default and writes still update this page, so the control always reflects what is in force.
 */
export const CLIPBOARD_AUTO_KEY = "deskrally.clipboard.auto";

let fallback: boolean | null = null;
const listeners = new Set<(on: boolean) => void>();

export function readClipboardAuto(): boolean {
  try {
    const stored = window.localStorage.getItem(CLIPBOARD_AUTO_KEY);
    if (stored === "1") return true;
    if (stored === "0") return false;
  } catch { /* storage unavailable */ }
  return fallback ?? true;
}

export function writeClipboardAuto(on: boolean): void {
  fallback = on;
  try { window.localStorage.setItem(CLIPBOARD_AUTO_KEY, on ? "1" : "0"); } catch { /* page-only */ }
  for (const notify of [...listeners]) notify(on);
}

/** Keeps every mounted control (main window and pop-out) showing the same choice. */
export function subscribeClipboardAuto(notify: (on: boolean) => void): () => void {
  listeners.add(notify);
  return () => { listeners.delete(notify); };
}

/** The remote screen: a press here is the gesture that carries the local clipboard across. */
export const REMOTE_SURFACE_SELECTOR = '[data-testid="viewer-surface"]';
