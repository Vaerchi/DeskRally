import { useCallback, useEffect, useRef, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { Viewer, type ViewerProps } from "./Viewer";
import { openPopout } from "../lib/popout";

import { watchedMonitors, watchedSender } from "../lib/watched_monitors";

let nextWindowGroup = 0;

/** Monitor windows share this session's transport; each owns its crop and input listeners. */
export function SessionViewer(props: ViewerProps) {
  const windows = useRef(new Map<number, { win: Window; root: Root }>());
  const [mainCrop, setMainCrop] = useState<number | null>(null);
  const crops = useRef(new Map<number, number | null>());
  const [sendWatched] = useState(watchedSender);
  const pending = useRef(new Set<number>());
  const alive = useRef(true);
  const [group] = useState(() => ++nextWindowGroup);
  const [, refresh] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const close = useCallback((id: number) => {
    const entry = windows.current.get(id);
    if (!entry) return;
    windows.current.delete(id);
    crops.current.delete(id);
    // React may currently be unmounting the parent. Release child input listeners first.
    queueMicrotask(() => {
      try { entry.root.unmount(); } catch { /* window already closed */ }
      try { entry.win.close(); } catch { /* window already closed */ }
    });
    if (alive.current) refresh(n => n + 1);
  }, []);
  useEffect(() => {
    alive.current = true;
    const timer = setInterval(() => {
      for (const [id, entry] of windows.current) if (entry.win.closed) close(id);
    }, 500);
    return () => {
      alive.current = false;
      clearInterval(timer);
      for (const id of windows.current.keys()) close(id);
    };
  }, [close]);
  const open = async (id: number, label: string) => {
    const previous = windows.current.get(id);
    if (previous && !previous.win.closed) { previous.win.focus(); return; }
    if (previous) close(id);
    if (pending.current.has(id)) return;
    pending.current.add(id);
    setError(null);
    try {
      const opened = await openPopout(`${props.machineAlias ?? props.machineName} — ${label} — DeskRally`, `rmt-monitor-${group}-${id}`);
      if (!opened) { if (alive.current) setError("Allow pop-ups to open a monitor window, then try again."); return; }
      if (!alive.current) { opened.win.close(); return; }
      crops.current.set(id, id);
      windows.current.set(id, { win: opened.win, root: createRoot(opened.container) });
      opened.win.addEventListener("pagehide", () => close(id), { once: true });
      refresh(n => n + 1);
    } catch {
      if (alive.current) setError("Could not open the monitor window. Try again.");
    } finally { pending.current.delete(id); }
  };
  useEffect(() => {
    for (const [id, entry] of windows.current) {
      if (!props.monitorCanvas?.monitors.some(m => m.id === id)) { close(id); continue; }
      entry.root.render(<Viewer {...props} hostWindow={entry.win} initialMonitorId={id}
        onCropMonitorChange={crop => {
          if (crops.current.get(id) !== crop) { crops.current.set(id, crop); refresh(n => n + 1); }
        }}
        disablePopout onPopoutChange={undefined} onVideoElement={undefined}
        additionalControls={props.popoutControls} disconnectLabel="Close window"
        onDisconnect={() => close(id)} />);
    }
  });
  useEffect(() => {
    const canvas = props.monitorCanvas;
    sendWatched(canvas, canvas ? watchedMonitors(canvas, mainCrop,
      [...crops.current.values()], !!(props.recording || props.recordingPending)) : null, props.onWatchedMonitors);
  });
  const controls = props.monitorCanvas && props.monitorCanvas.monitors.length > 1 ? <>
    <span>Monitor windows:</span>
    {props.monitorCanvas.monitors.map((monitor, i) => {
      const label = props.monitors?.find(m => m.id === monitor.id)?.label ?? `Display ${i + 1}`;
      return <button type="button" className="viewer__zoombtn" key={monitor.id}
        data-testid={`monitor-window-${monitor.id}`} title={`Open ${label} in its own window`}
        onClick={() => void open(monitor.id, label)}>{label} ↗</button>;
    })}
  </> : null;
  return <Viewer {...props} onCropMonitorChange={setMainCrop} additionalControls={<>{controls}{error && <span role="alert">{error}</span>}</>} />;
}
