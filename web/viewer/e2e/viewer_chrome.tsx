/**
 * Render harness for the REAL `<Viewer>` chrome — the first Viewer render test in this repo.
 *
 * WHY THIS EXISTS. Every layout assertion the console had was geometry: box heights, right edges,
 * counts. All of them passed while the top bar rendered "Sign / out" wrapped onto two lines and grew
 * from ~40px to 67px. Geometry cannot see that, because the numbers it reports are the numbers the
 * broken layout produced. A real browser laying out the real CSS, screenshotted, can.
 *
 * WHY IT IS NOT A LIVE-SESSION TEST. `<Viewer transport={undefined}>` documents itself as running in
 * "local preview mode", so the whole control set renders with no agent, no signaling, no WebRTC and
 * no control plane. Measuring chrome does not need media — it needs the real components, the real
 * `index.css`, and a real layout engine. Hanging this off `console.spec.ts`'s live session would add
 * an agent spawn to a serial gate to measure something media has no bearing on.
 *
 * WHY EVERY CALLBACK IS PASSED. Most controls are conditional on their handler existing ("Absent ⇒
 * the Reboot control is not shown"), so a minimal mount would measure a bar no technician ever sees.
 * The worst case — a fully-capable operator on a multi-monitor machine — is the case worth budgeting.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: reproduce the App shell (`.app__topbar`, the console nav). A
 * second copy of the shell here would drift from the real one and quietly assert against itself; the
 * shell is measured in the real app by `mobile_layout.mobile.spec.ts`.
 *
 * STATEFUL HARNESS API (used by monitor-selection tests in viewer_chrome.spec.ts):
 *   window.__setMonitors(list)     — replace the monitors prop on the live Viewer
 *   window.__monitorUpdateCount    — bumped by useEffect([monitors]) after each list commit
 *   window.__selectMonitorCalls    — array of ids passed to onSelectMonitor, in call order
 *   window.__disconnectClicks      — count of Disconnect clicks (for the reachability test)
 *   window.__inputLog              — array of {channel, byteLength} objects from mock transport.send()
 *   ?start=empty                   — start with monitors=[] to test first-announcement behavior
 */
import { StrictMode, useState, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { Viewer, type MonitorInfo } from "../src/components/Viewer";
import { type Transport, ChannelId } from "../src/lib";
import "../src/index.css";
import { ToolbarMenu } from "../src/components/ToolbarMenu";

/** A realistic multi-monitor rig: the monitor `<select>` is one of the wider status-bar items. */
const MONITORS: MonitorInfo[] = [
  { id: 0, label: "Monitor 1 (1920×1080)", width: 1920, height: 1080, primary: true },
  { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
  { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200 },
];

// ?start=empty starts with no monitors so tests can observe the first-announcement behavior.
const startEmpty = new URLSearchParams(location.search).get("start") === "empty";

/** Channel id + decoded JSON payload (from encodeInput's JSON.stringify output). */
type InputLogEntry = { channel: number; byteLength: number; json: unknown };

// Test-observable globals initialised before any React render.
(window as unknown as { __disconnectClicks: number }).__disconnectClicks = 0;
(window as unknown as { __selectMonitorCalls: number[] }).__selectMonitorCalls = [];
(window as unknown as { __monitorUpdateCount: number }).__monitorUpdateCount = 0;
(window as unknown as { __inputLog: InputLogEntry[] }).__inputLog = [];

/**
 * Minimal mock Transport. Only `send` does real work: it appends an entry to `window.__inputLog`
 * so tests can assert that input events were (or were not) forwarded to the remote.
 *
 * Each entry carries the decoded JSON so tests can verify key codes and down/up flags, not just
 * that a message was sent. The text-decode is safe: encodeInput always produces valid UTF-8 JSON.
 *
 * The mock is created once at module scope so its identity is stable across renders — the Viewer
 * effect that attaches keyboard listeners closes over `transport` and re-runs when it changes.
 */
const mockTransport: Transport = {
  kind: "webrtc",
  state: "connected",
  send(channel: ChannelId, payload: Uint8Array) {
    let json: unknown = null;
    try { json = JSON.parse(new TextDecoder().decode(payload)); } catch { /* non-JSON payload */ }
    (window as unknown as { __inputLog: InputLogEntry[] }).__inputLog.push({
      channel,
      byteLength: payload.byteLength,
      json,
    });
  },
  sendFrame() {},
  connect() { return Promise.resolve(); },
  close() {},
};

const noop = () => {};

function HarnessApp() {
  const docked = new URLSearchParams(location.search).has("docked");
  const [toolbarHost, setToolbarHost] = useState<HTMLDivElement | null>(null);
  const [toolbarEndHost, setToolbarEndHost] = useState<HTMLDivElement | null>(null);
  const [toolbarMenuOpen, setToolbarMenuOpen] = useState(false);
  const [stream, setStream] = useState<MediaStream | null>(null);
  useEffect(() => {
    (window as unknown as { __setStream: typeof setStream }).__setStream = setStream;
  }, []);
  const [monitors, setMonitors] = useState<MonitorInfo[]>(startEmpty ? [] : MONITORS);

  // Expose the setter so Playwright tests can drive monitor-list changes.
  useEffect(() => {
    (window as unknown as { __setMonitors: (m: MonitorInfo[]) => void }).__setMonitors = setMonitors;
  }, []);

  // Bump the commit counter after every monitor-list state update so tests can deterministically
  // await each list commit via waitForFunction rather than arbitrary sleeps.
  useEffect(() => {
    (window as unknown as { __monitorUpdateCount: number }).__monitorUpdateCount++;
  }, [monitors]);

  const handleSelectMonitor = useCallback((id: number) => {
    (window as unknown as { __selectMonitorCalls: number[] }).__selectMonitorCalls.push(id);
  }, []);

  return (
    <>
    {docked && <header className="app__topbar"><ToolbarMenu label="DeskRally" onOpenChange={setToolbarMenuOpen}><button>Local action</button></ToolbarMenu><div className="app__toolbar-host" ref={setToolbarHost}/><div className="app__toolbar-end" ref={setToolbarEndHost}/></header>}
    <Viewer
      toolbarHost={toolbarHost}
      toolbarEndHost={toolbarEndHost}
      toolbarMenuOpen={toolbarMenuOpen}
      transport={mockTransport}
      stream={stream}
      connectionState="connected"
      machineName="WORKSTATION-04"
      audioAvailable
      monitors={monitors}
      onSelectMonitor={handleSelectMonitor}
      onSetQuality={noop}
      qualitySupported
      inputBlocked={false}
      onToggleInputBlock={noop}
      viewOnly={false}
      onToggleViewOnly={noop}
      onReboot={noop}
      onLock={noop}
      onLogOff={() => { const w = window as unknown as { __logoffs?: number }; w.__logoffs = (w.__logoffs ?? 0) + 1; }}
      onShutDown={noop}
      onLaunchTool={noop}
      onRunCommand={noop}
      onElevatedRun={noop}
      onScreenshot={noop}
      onToggleRecording={noop}
      recording={docked}
      onBrowseDir={noop}
      onDisconnect={() => {
        (window as unknown as { __disconnectClicks: number }).__disconnectClicks++;
      }}
    />
    </>
  );
}

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("#root element not found");

createRoot(rootEl).render(
  <StrictMode>
    <HarnessApp />
  </StrictMode>,
);
