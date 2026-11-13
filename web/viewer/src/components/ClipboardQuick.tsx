/**
 * The clipboard's place in the viewer's Input menu, where technicians look for it (Ed, 2026-10-22: he
 * looked under View, Input, Tools and More, never Session).
 *
 * Deliberately NOT a second ClipboardControl: the Input panel unmounts whenever it closes, and the
 * control that owns "receive" must stay mounted or receiving would stop with the menu. So this offers
 * the standing switch (shared with the Session menu's control through lib/clipboard_auto, which applies
 * it to the live session) and a one-click send. The per-session Receive toggle stays in Session.
 */
import { useEffect, useRef, useState } from "react";
import { clipboardForWindow, type ClipboardClient } from "../lib/clipboard";
import { readClipboardAuto, subscribeClipboardAuto, writeClipboardAuto } from "../lib/clipboard_auto";

/** What to tell the technician when a send sent nothing, by cause. */
export function noSendMessage(outcome: ClipboardClient["lastSendOutcome"]): string {
  switch (outcome) {
    case "unreadable":
      return "Could not read your clipboard. Allow clipboard access for DeskRally (in the app: restart it and answer Yes).";
    case "unchanged":
      return "Already sent: the remote machine has this text (a click on the remote screen sends your clipboard automatically). Copy something new to send it.";
    case "too-large":
      return "Your clipboard is larger than 1 MB, too large to send to this machine.";
    case "failed":
      return "Could not send: the session's connection refused it. Try again.";
    default:
      return "Nothing was sent.";
  }
}

export function ClipboardQuick({ client }: { client?: ClipboardClient }) {
  const host = useRef<HTMLDivElement>(null);
  const [auto, setAuto] = useState(readClipboardAuto);
  const [status, setStatus] = useState("");
  // The CURRENT client, so a read that settles after the session changed does not report into the next one.
  const current = useRef(client);
  current.current = client;
  useEffect(() => subscribeClipboardAuto(setAuto), []);
  useEffect(() => setStatus(""), [client]);

  const send = async () => {
    if (!client) return;
    const forClient = client;
    // Inside this click, so the browser lets the page read the clipboard.
    const sent = await client.sendText(clipboardForWindow(host.current?.ownerDocument.defaultView ?? null));
    if (current.current !== forClient) return;
    setStatus(sent !== null ? `Sent ${sent.length} characters.` : noSendMessage(forClient.lastSendOutcome));
  };

  return (
    <div ref={host} className="viewer__menupanel-field" data-testid="clipboard-quick">
      <label className="viewer__toggle">
        <input type="checkbox" data-testid="clipboard-quick-auto" checked={auto}
          onChange={(e) => writeClipboardAuto(e.target.checked)} />
        <span className="viewer__menupanel-label">Share clipboard automatically</span>
      </label>
      <button type="button" className="viewer__zoombtn" data-testid="clipboard-quick-send" disabled={!client}
        onClick={() => void send()} title="Send your clipboard to the remote machine, ready to paste there">
        Send clipboard now
      </button>
      {status && <span className="viewer__qualityhint" data-testid="clipboard-quick-status">{status}</span>}
    </div>
  );
}
