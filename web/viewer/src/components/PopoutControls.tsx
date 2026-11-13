import { useEffect, useState } from "react";
import type { ReactNode } from "react";

export function PopoutControls({ win, onReturn, onFit, onActual, onZoomIn, onZoomOut,
  monitors, activeMonitor, onMonitorChange, monitorLocked = false, children }: {
  win: Window; onReturn: () => void; onFit: () => void; onActual: () => void;
  onZoomIn: () => void; onZoomOut: () => void;
  monitors: readonly { value: number; label: string }[];
  activeMonitor: number;
  onMonitorChange: (id: number) => void;
  monitorLocked?: boolean;
  children?: ReactNode;
}) {
  const [maximized, setMaximized] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const update = () => setMaximized(!!win.document.fullscreenElement);
    win.document.addEventListener("fullscreenchange", update);
    return () => win.document.removeEventListener("fullscreenchange", update);
  }, [win]);
  const maximize = async () => {
    try {
      setError("");
      if (win.document.fullscreenElement) await win.document.exitFullscreen();
      else await win.document.documentElement.requestFullscreen();
    } catch { setError("Fullscreen unavailable. Use the window's maximize button."); }
  };
  return <div className="viewer__popout-controls" data-testid="popout-controls"
    onKeyDown={e => e.stopPropagation()} onKeyUp={e => e.stopPropagation()}>
    <label className="viewer__monitor">
      <span className="viewer__lbl">Monitor</span>
      <select data-testid="popout-monitor" value={activeMonitor} disabled={monitorLocked}
        title={monitorLocked ? "This session is pinned to the primary display." : undefined}
        onChange={e => onMonitorChange(Number(e.target.value))}>
        {monitors.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
      </select>
    </label>
    <button type="button" onClick={onZoomOut} aria-label="Zoom out">−</button>
    <button type="button" onClick={onZoomIn} aria-label="Zoom in">+</button>
    <button type="button" onClick={onFit}>Fit</button>
    <button type="button" onClick={onActual}>1:1</button>
    <button type="button" onClick={() => void maximize()} aria-pressed={maximized}>
      {maximized ? "Restore" : "Maximize"}
    </button>
    <button type="button" onClick={onReturn}>Return to tab</button>
    {children}
    {error && <span role="alert">{error}</span>}
  </div>;
}
