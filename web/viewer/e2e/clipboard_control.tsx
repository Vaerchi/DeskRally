// Local-only UI harness. All clipboard reads/writes and transport sends use synthetic seams.
import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ClipboardControl } from "../src/components/ClipboardControl";
import { ClipboardQuick } from "../src/components/ClipboardQuick";
import { ClipboardClient, encodeMessage, decodeMessage, type ClipboardNotice } from "../src/lib/clipboard";
import "../src/index.css";

declare global {
  interface Window {
    __clipboardInput: (text: string) => Promise<void>;
    __clipboardWrites: string[];
    __clipboardSends: string[];
    __clipboardBlockRead: boolean;
    __clipboardResolveRead: () => void;
  }
}
window.__clipboardWrites = [];
window.__clipboardSends = [];
window.__clipboardBlockRead = false;
window.__clipboardResolveRead = () => {};

// ClipboardControl now calls clipboardForWindow(window), which delegates to
// window.navigator.clipboard. Install a fake here so reads/writes still go through
// the synthetic seams the consent tests depend on. This is a harness-only shim.
Object.defineProperty(navigator, "clipboard", {
  configurable: true,
  value: {
    readText: (): Promise<string> =>
      (window as unknown as { __clipboardFailRead?: boolean }).__clipboardFailRead
        ? Promise.reject(new DOMException("Read permission denied.", "NotAllowedError"))
        : window.__clipboardBlockRead
        ? new Promise<string>(resolve => { window.__clipboardResolveRead = () => resolve("synthetic local clipboard"); })
        : Promise.resolve("synthetic local clipboard"),
    writeText: async (text: string): Promise<void> => { window.__clipboardWrites.push(text); },
  },
});

function Harness() {
  const [notice, setNotice] = useState<ClipboardNotice | null>(null);
  const makeClient = () => new ClipboardClient(
    payload => window.__clipboardSends.push(decodeMessage(payload).c),
    {
      readText: () => window.__clipboardBlockRead
        ? new Promise<string>(resolve => { window.__clipboardResolveRead = () => resolve("synthetic local clipboard"); })
        : Promise.resolve("synthetic local clipboard"),
      writeText: async text => { window.__clipboardWrites.push(text); },
    },
    { onNotice: setNotice },
  );
  const [client, setClient] = useState(makeClient);
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    window.__clipboardInput = text => client.handleMessage(encodeMessage({ t: "Text", c: text }));
    return () => client.dispose();
  }, [client]);
  return <main>
    {visible && <ClipboardControl client={client} notice={notice} />}
    <ClipboardQuick client={client} />
    <button data-testid="replace-session" onClick={() => {
      client.dispose(); setNotice(null); setClient(makeClient());
    }}>Replace synthetic session</button>
    <div data-testid="viewer-surface" style={{ width: 240, height: 120, background: "#333" }} />
    <button data-testid="toggle-control" onClick={() => setVisible(value => !value)}>Toggle control</button>
  </main>;
}
createRoot(document.getElementById("root")!).render(<Harness />);
