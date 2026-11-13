/**
 * Harness for popup-clipboard e2e tests (pass 52).
 *
 * Mirrors the App.tsx pattern exactly:
 *   {!poppedOut && <ClipboardControl client={client} />}   ← main chrome
 *   <Viewer popoutControls={<ClipboardControl client={client} />} onPopoutChange={...} />
 *
 * URL params:
 *   ?pinned=1  — sets pinnedMonitorId=0 so the monitor picker is locked
 *
 * Test-observable globals:
 *   window.__clipboardMainWrites  — writes to the constructor (main-window) ClipboardApi
 *   window.__clipboardSends       — decoded text payloads forwarded to the remote
 *   window.__clipboardInput(text) — injects an inbound Text frame into the live client
 *   window.__poppedOut            — updated by onPopoutChange
 *   window.__inputLog             — {channel, byteLength} entries from the mock transport.send
 */
import { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { Viewer, type MonitorInfo } from "../src/components/Viewer";
import { ClipboardControl } from "../src/components/ClipboardControl";
import { type Transport, ChannelId } from "../src/lib";
import {
  ClipboardClient,
  encodeMessage,
  decodeMessage,
  type ClipboardNotice,
} from "../src/lib/clipboard";
import "../src/index.css";

declare global {
  interface Window {
    __clipboardMainWrites: string[];
    __clipboardSends: string[];
    __clipboardInput: (text: string) => void;
    __poppedOut: boolean;
    __inputLog: { channel: number; byteLength: number }[];
  }
}

window.__clipboardMainWrites = [];
window.__clipboardSends = [];
window.__poppedOut = false;
window.__clipboardInput = () => {};
window.__inputLog = [];

// Keep both windows entirely synthetic, including failures that accidentally route to the opener.
Object.defineProperty(navigator, "clipboard", {
  configurable: true,
  value: {
    readText: async () => "main local clipboard",
    writeText: async (text: string) => { window.__clipboardMainWrites.push(text); },
  },
});

/** Minimal mock transport — records every send in __inputLog so tests can assert no keyboard leak. */
const mockTransport: Transport = {
  kind: "webrtc",
  state: "connected",
  send(channel: ChannelId, payload: Uint8Array) {
    window.__inputLog.push({ channel, byteLength: payload.byteLength });
  },
  sendFrame() {},
  connect() { return Promise.resolve(); },
  close() {},
};

const MONITORS: MonitorInfo[] = [
  { id: 0, label: "Primary (1920×1080)", width: 1920, height: 1080, primary: true },
  { id: 1, label: "Secondary (2560×1440)", width: 2560, height: 1440 },
];

const pinned = new URLSearchParams(location.search).has("pinned");

const noop = () => {};

function HarnessApp() {
  const [notice, setNotice] = useState<ClipboardNotice | null>(null);
  const [poppedOut, setPoppedOut] = useState(false);

  // Stable client for the session lifetime.
  const [client] = useState(() =>
    new ClipboardClient(
      payload => window.__clipboardSends.push(decodeMessage(payload).c),
      {
        // Main-window clipboard: a different value than any popup mock so tests can prove ownership.
        readText: () => Promise.resolve("main local clipboard"),
        writeText: async (text) => { window.__clipboardMainWrites.push(text); },
      },
      { onNotice: setNotice },
    ),
  );

  useEffect(() => {
    window.__clipboardInput = (text: string) =>
      void client.handleMessage(encodeMessage({ t: "Text", c: text }));
    return () => { client.dispose(); };
  // client is stable for the component's lifetime; disable-next-line intentional.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { window.__poppedOut = poppedOut; }, [poppedOut]);

  return (
    <>
      {/* Mirror App.tsx: main-chrome ClipboardControl hidden while viewer is popped out. */}
      {!poppedOut && <ClipboardControl client={client} notice={notice} />}
      <Viewer
        transport={mockTransport}
        popoutControls={<ClipboardControl client={client} notice={notice} />}
        onPopoutChange={setPoppedOut}
        machineName="TEST-MACHINE"
        connectionState="connected"
        monitors={MONITORS}
        pinnedMonitorId={pinned ? 0 : undefined}
        onSelectMonitor={noop}
        onSetQuality={noop}
        qualitySupported
        inputBlocked={false}
        onToggleInputBlock={noop}
        viewOnly={false}
        onToggleViewOnly={noop}
        onReboot={noop}
        onLock={noop}
        onLogOff={noop}
        onShutDown={noop}
        onLaunchTool={noop}
        onRunCommand={noop}
        onElevatedRun={noop}
        onScreenshot={noop}
        onToggleRecording={noop}
        recording={false}
        onBrowseDir={noop}
        onDisconnect={noop}
      />
    </>
  );
}

createRoot(document.getElementById("root")!).render(<HarnessApp />);
