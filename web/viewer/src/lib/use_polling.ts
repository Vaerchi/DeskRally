import { useEffect } from "react";

/**
 * Visibility-aware polling for UI-freshness reads (diagnostics, lists, notification bells).
 *
 * NEVER use this for anything that keeps a live session alive (signaling, WebRTC health, lease renewal,
 * audit flush, auth keep-alive): those must run while the tab is hidden. A hidden tab has nobody to show
 * fresh data to, so a freshness poll is pure background load.
 */

export function pageHidden(): boolean {
  return typeof document !== "undefined" && document.hidden === true;
}

/**
 * Runs `watch` hooks on page visibility changes. Returns the unsubscribe. A no-op outside a browser.
 */
export function watchVisibility(onHidden: () => void, onVisible: () => void): () => void {
  if (typeof document === "undefined") return () => undefined;
  const handler = () => (document.hidden ? onHidden() : onVisible());
  document.addEventListener("visibilitychange", handler);
  return () => document.removeEventListener("visibilitychange", handler);
}

export interface PollingOptions {
  /** Poll only while true (e.g. the owning panel is open). Default true. */
  active?: boolean;
  /** Run one tick straight away on start. Default true. */
  immediate?: boolean;
}

/**
 * Calls `fn` every `intervalMs` (measured from the end of the previous call, so calls never overlap) while
 * the document is visible. While hidden the timer is cleared; on becoming visible again one tick runs at
 * once, unless a call is still in flight (its completion reschedules). Errors from `fn` are swallowed:
 * the caller handles its own failures. Returns a stop function.
 */
export function startPolling(fn: () => unknown, intervalMs: number, opts: { immediate?: boolean } = {}): () => void {
  let stopped = false;
  let inFlight = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const schedule = () => {
    clearTimeout(timer);
    if (!stopped && !pageHidden()) timer = setTimeout(() => void run(), intervalMs);
  };
  const run = async () => {
    clearTimeout(timer);
    if (stopped || inFlight || pageHidden()) return;
    inFlight = true;
    try {
      await fn();
    } catch {
      /* the caller reports its own failures; the next tick retries */
    } finally {
      inFlight = false;
    }
    schedule();
  };

  const unwatch = watchVisibility(
    () => clearTimeout(timer),
    () => { clearTimeout(timer); void run(); },
  );
  if (opts.immediate ?? true) void run();
  else schedule();

  return () => {
    stopped = true;
    clearTimeout(timer);
    unwatch();
  };
}

/**
 * React wrapper over startPolling. A new `fn` identity restarts the poll (with an immediate tick), so
 * wrap `fn` in useCallback over exactly the inputs whose change should refresh the data.
 */
export function usePolling(fn: () => unknown, intervalMs: number, opts: PollingOptions = {}): void {
  const active = opts.active ?? true;
  const immediate = opts.immediate ?? true;
  useEffect(() => {
    if (!active) return;
    return startPolling(fn, intervalMs, { immediate });
  }, [fn, intervalMs, active, immediate]);
}
