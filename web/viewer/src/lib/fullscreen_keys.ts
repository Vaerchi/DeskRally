// Full screen and the Escape key (Ed, 2026-11-18: "i want to push escape to the client. maybe shift+esc?").
//
// In browser full screen, Chromium (Chrome, Edge and the desktop app's WebView2) consumes Escape to leave full
// screen, so the remote machine never sees it. The Keyboard Lock API (navigator.keyboard.lock) hands Escape to the
// page while the page is full screen; we forward it to the remote like any other key. To leave full screen the
// operator presses Shift+Esc, which we handle ourselves and do NOT forward. The lock is held only while the viewer
// captures keys for the remote (Viewer.tsx), so a view-only or idle viewer keeps the browser's own Escape exit. The browser keeps its own safety exit
// (press and HOLD Escape), which no page can disable. Browsers without Keyboard Lock (Firefox, Safari) keep
// today's behaviour: Escape leaves full screen.

type KeyboardLock = { lock?: (keys?: string[]) => Promise<void>; unlock?: () => void };

function keyboardOf(win: Window | null | undefined): KeyboardLock | undefined {
  return (win?.navigator as (Navigator & { keyboard?: KeyboardLock }) | undefined)?.keyboard;
}

/** Ask the browser to deliver Escape to the page while it is full screen. Best effort: unsupported or refused is fine. */
export function lockEscape(win: Window | null | undefined): void {
  try {
    void keyboardOf(win)?.lock?.(["Escape"])?.catch(() => {});
  } catch {
    // An exotic host without the API shape: keep the browser's default.
  }
}

/** Release the lock (on leaving full screen). Safe to call when nothing is locked. */
export function unlockKeys(win: Window | null | undefined): void {
  try {
    keyboardOf(win)?.unlock?.();
  } catch {
    // Nothing locked, or no API.
  }
}

/** Shift+Esc (and no other modifier) is the operator's way out of full screen; it never reaches the remote. */
export function isFullscreenBreakout(e: { key: string; shiftKey: boolean; ctrlKey: boolean; altKey: boolean; metaKey: boolean }): boolean {
  return e.key === "Escape" && e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey;
}

