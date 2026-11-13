/**
 * Harness for trackpad.mobile.spec.ts: the real Viewer on a 400x300 canvas "desktop" with a recording
 * transport, so the spec asserts on the exact input events the agent would receive (window.__logs).
 * `?viewonly` renders the view-only state the agent reports; `?monitors` advertises two monitors
 * (the full-screen mobile bar's 1/2/All buttons); `?pinned` pins monitor 0.
 */
import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Viewer } from "../src/components/Viewer";
import type { Transport } from "../src/lib";
import "../src/index.css";

const logs: unknown[] = [];
Object.assign(window, { __logs: logs });
const transport = {
  kind: "webrtc",
  state: "connected",
  send(_channel: unknown, payload: Uint8Array) {
    logs.push(JSON.parse(new TextDecoder().decode(payload)));
  },
  sendFrame() {},
  connect: async () => {},
  close() {},
} as unknown as Transport;

function App() {
  const [stream, setStream] = useState<MediaStream | null>(null);
  useEffect(() => {
    const c = document.createElement("canvas");
    c.width = 400;
    c.height = 300;
    const ctx = c.getContext("2d")!;
    const draw = () => {
      ctx.fillStyle = "#234";
      ctx.fillRect(0, 0, 400, 300);
      ctx.fillStyle = "#c33";
      ctx.fillRect(0, 0, 40, 30);
    };
    draw();
    const media = c.captureStream(20);
    setStream(media);
    const i = setInterval(draw, 50);
    return () => {
      clearInterval(i);
      media.getTracks().forEach((t) => t.stop());
    };
  }, []);
  const viewOnly = new URLSearchParams(location.search).has("viewonly");
  const monitors = new URLSearchParams(location.search).has("monitors")
    ? [
        { id: 0, label: "Display 1", width: 400, height: 300, primary: true },
        { id: 1, label: "Display 2", width: 400, height: 300, primary: false },
      ]
    : undefined;
  return (
    <div className="session">
      <Viewer machineName="Trackpad test" stream={stream} transport={transport} connectionState="connected" viewOnly={viewOnly} monitors={monitors} pinnedMonitorId={new URLSearchParams(location.search).has("pinned") ? 0 : undefined} />
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
