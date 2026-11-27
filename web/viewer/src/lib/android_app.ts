// docs/78: the console's side of the DeskRally Android app (an in-app WebView). The app injects `window.DeskRallyApp`
// (WebViewCompat.addWebMessageListener, restricted to the console's own origin). The console tells it when a session
// is live, so the app keeps itself running in the background (a foreground service with a "session active"
// notification), and the app asks the console to end the session (the notification's End action, or its background
// time limit). Nothing else crosses this bridge. In a browser `window.DeskRallyApp` does not exist and every call
// here is a no-op.

/** The object the Android app injects (a WebMessageListener JS object). */
export interface AppBridge {
  postMessage(message: string): void;
  onmessage: ((event: { data: unknown }) => void) | null;
}

export function appBridge(win: unknown = globalThis): AppBridge | null {
  const b = (win as { DeskRallyApp?: unknown }).DeskRallyApp as AppBridge | undefined;
  return b && typeof b.postMessage === "function" ? b : null;
}

/** The machine name as the app shows it in its notification: one line, no control characters, at most 60 chars. */
export function notificationName(name: string): string {
  const clean = name.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, " ").replace(/\s+/g, " ").trim();
  return (clean || "a machine").slice(0, 60);
}

/** The message for "a session is live on `name`" / "no session". */
export function sessionMessage(active: boolean, name?: string): string {
  return active ? `session:on:${notificationName(name ?? "")}` : "session:off";
}

/**
 * Tell the app the session state now (only changes are sent) and route its "end" requests to `onEnd`. Returns the
 * teardown, which also reports "session:off".
 */
export class AppSessionLink {
  private last: string | null = null;
  constructor(private readonly bridge: AppBridge | null, onEnd: () => void) {
    if (bridge) {
      bridge.onmessage = (ev) => {
        if (ev.data === "end") onEnd();
      };
    }
  }

  report(active: boolean, name?: string): void {
    if (!this.bridge) return;
    const msg = sessionMessage(active, name);
    if (msg === this.last) return;
    this.last = msg;
    try {
      this.bridge.postMessage(msg);
    } catch {
      /* the app went away; nothing to do */
    }
  }

  dispose(): void {
    this.report(false);
    if (this.bridge) this.bridge.onmessage = null;
  }
}
