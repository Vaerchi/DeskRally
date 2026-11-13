import type { MonitorCanvas } from "./monitor_canvas";

/**
 * The displays this viewer is looking at, for the agent's WatchedMonitors hint: the agent keeps the
 * other displays' pixels still so the encoder spends the bitrate on these. Null means "all" (nothing
 * frozen) and is the fail-open answer: whole canvas shown, an unknown crop, or recording.
 */
export function watchedMonitors(canvas: MonitorCanvas, main: number | null,
  windows: readonly (number | null)[], recording: boolean): number[] | null {
  if (recording || main === null || windows.includes(null)) return null;
  const valid = new Set(canvas.monitors.map(m => m.id));
  const views = [main, ...windows] as number[];
  if (views.some(id => !valid.has(id))) return null;
  const ids = [...new Set(views)].sort((a, b) => a - b);
  return ids.length === valid.size ? null : ids;
}

/**
 * Sends the hint on change only. A NEW canvas object (each MonitorCanvas the agent sends, including
 * after a reconnect, when the agent's session starts again from "all") resends the current value.
 */
export function watchedSender() {
  let previous: string | undefined;
  let previousCanvas: MonitorCanvas | undefined;
  return (canvas: MonitorCanvas | undefined, ids: number[] | null,
    send: ((ids: number[] | null) => void) | undefined) => {
    if (canvas !== previousCanvas) { previous = undefined; previousCanvas = canvas; }
    if (!canvas || !send) return;
    const key = JSON.stringify(ids);
    if (key !== previous) { send(ids); previous = key; }
  };
}
