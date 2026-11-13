/**
 * Background mode: when every window showing a session is hidden (minimised, a background tab, or
 * covered), the console tells the agent with `SetBackground`, and the agent sends that session about
 * one frame a second with no keep-alive frames. Capture and encoding are the agent's main CPU cost on
 * the customer's machine, and a hidden viewer gains nothing from either. The operator's quality
 * settings are not touched; showing any window brings the session back at once.
 *
 * One session can be shown in several windows at the same time: the main console, a popped-out
 * desktop, and one window per monitor in a multi-monitor canvas. The session is in the background
 * only when ALL of them are hidden, hence the tracker rather than a single visibility flag. A session
 * with NO window at all (the operator switched to the Files, Chat or Under the Hood tab, which unmount
 * the desktop) is in the background too: nothing is showing its picture.
 */

/** Which of a session's viewer windows are hidden. */
export class BackgroundTracker {
  private readonly hidden = new Map<object, boolean>();
  private state = false;

  /** Whether the session is in the background now. */
  get background(): boolean {
    return this.state;
  }

  /**
   * Record viewer `viewer` as hidden or visible, or remove it (`null`, on unmount). Returns the new
   * background state when it CHANGED, otherwise `undefined`, so the caller sends only transitions.
   */
  update(viewer: object, hidden: boolean | null): boolean | undefined {
    if (hidden === null) this.hidden.delete(viewer);
    else this.hidden.set(viewer, hidden);
    // No window left is "every window hidden" too (vacuously): nobody can see the picture.
    const next = [...this.hidden.values()].every(Boolean);
    if (next === this.state) return undefined;
    this.state = next;
    return next;
  }
}

/** The slice of `Document` that visibility tracking needs (a fake is enough in tests). */
export type VisibilityDocument = Pick<Document, "visibilityState" | "addEventListener" | "removeEventListener">;

/**
 * Report `doc`'s visibility now and on every change. Returns the unsubscribe function, so it drops
 * straight into a React effect.
 */
export function watchVisibility(doc: VisibilityDocument, onChange: (hidden: boolean) => void): () => void {
  const report = () => onChange(doc.visibilityState === "hidden");
  report();
  doc.addEventListener("visibilitychange", report);
  return () => doc.removeEventListener("visibilitychange", report);
}
