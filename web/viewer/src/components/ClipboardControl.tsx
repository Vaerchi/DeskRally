/**
 * Clipboard control (Milestone V3 + docs/25 F08): the operator's per-session UI for BOTH directions.
 *
 * ## Directions
 *
 *  - **Send** — a button reads the local clipboard on click (a user gesture, required by
 *    `navigator.clipboard.readText`) and frames it out to the agent.
 *  - **Receive** — a checkbox opts this session into applying inbound remote text with `writeText`.
 *    Resets when the underlying `ClipboardClient` identity changes, to the "automatic" choice below.
 *  - **Share clipboard automatically** (lib/clipboard_auto; default ON, remembered per browser):
 *    each session starts receiving, and a press on the remote screen sends the local clipboard.
 *    Turning it off restores the default-off behaviour described next. The default was chosen by
 *    the operator on 2026-10-22, knowingly trading the F08 protection for convenience.
 *
 * ## Why default-off receive (when automatic sharing is off)
 *
 * Prior to docs/25 F08 every valid inbound Text was applied automatically. Where the browser grants
 * `writeText`, that would let a remote peer overwrite what the operator later pastes into a
 * terminal. The consent gate lives on the CLIENT (`ClipboardClient.setReceiveEnabled`) — this
 * component is only the surfacing seam.
 */

import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import type { ClipboardClient, ClipboardNotice } from "../lib/clipboard";
import { noSendMessage } from "./ClipboardQuick";
import { clipboardForWindow } from "../lib/clipboard";
import { desktopClientPromptsEveryClipboardRead } from "../lib/desktop_launch";
import { readClipboardAuto,REMOTE_SURFACE_SELECTOR, subscribeClipboardAuto, writeClipboardAuto } from "../lib/clipboard_auto";

export interface ClipboardControlProps {
  /** Live client over `ChannelId.Clipboard`. Absent ⇒ both controls are disabled (no session). */
  client?: ClipboardClient;
  /** Latest own-status notice (byte counts + result kinds only — never remote content). */
  notice?: ClipboardNotice | null;
}

/** Format a client-emitted notice into a short, content-free status line. */
function noticeLabel(n: ClipboardNotice): string {
  switch (n.kind) {
    case "written":
      return `Applied remote clipboard (${n.bytes ?? 0} bytes).`;
    case "too-large":
      return "Remote clipboard rejected: text exceeds the size limit.";
    case "rate-limited":
      return "Remote clipboard rate-limited.";
    case "malformed":
      return "Remote clipboard rejected: malformed.";
    case "permission-failed":
      return "Remote clipboard write blocked by the browser.";
  }
}

/** Trim a clipboard preview so the status line stays short. */
function preview(text: string): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > 32 ? `${oneLine.slice(0, 32)}…` : oneLine;
}

// One receive destination per session, even when controls are shown in several monitor windows.
const receiveOwners = new WeakMap<ClipboardClient, {
  owner: object | null;
  listeners: Map<object, (enabled: boolean) => void>;
}>();
function notifyReceiveOwner(state: NonNullable<ReturnType<typeof receiveOwners.get>>) {
  for (const [owner, notify] of state.listeners) notify(owner === state.owner);
}

export function ClipboardControl({ client, notice }: ClipboardControlProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [sendStatus, setSendStatus] = useState<string>("");
  const [receive, setReceive] = useState<boolean>(false);
  const [auto, setAuto] = useState<boolean>(readClipboardAuto);
  const [, rerender] = useReducer((n: number) => n + 1, 0);
  const receiveOwner = useRef<object>({});
  useEffect(() => subscribeClipboardAuto(setAuto), []);

  // A new client (a new session) resets both the toggle and the status: opt-in is per-session and
  // never persisted, and a stale "Sent → …" from the previous machine must not linger.
  useEffect(() => {
    setReceive(false);
    setSendStatus("");
    if (!client) return;
    let state = receiveOwners.get(client);
    if (!state) {
      client.setReceiveEnabled(false);
      state = { owner: null, listeners: new Map() };
      receiveOwners.set(client, state);
    }
    const owner = receiveOwner.current;
    state.listeners.set(owner, setReceive);
    // Automatic sharing: the session starts receiving, into THIS control's window, unless another
    // mounted control already owns receive.
    if (readClipboardAuto() && state.owner === null) {
      state.owner = owner;
      client.setReceiveEnabled(true, clipboardForWindow(hostRef.current?.ownerDocument.defaultView ?? null));
      notifyReceiveOwner(state);
    }
    setReceive(state.owner === owner);
    // The checkbox also reads client.isReceiveEnabled(), which the render before this effect saw as
    // false. When `receive` nets back to its previous value (true → false → true across a session
    // replacement), React skips the re-render and the box would show "off" while receiving.
    rerender();
    return () => {
      state.listeners.delete(owner);
      if (state.owner === owner) {
        state.owner = null;
        client.setReceiveEnabled(false);
        notifyReceiveOwner(state);
      }
      if (state.listeners.size === 0) receiveOwners.delete(client);
    };
  }, [client]);
  useEffect(() => { setSendStatus(""); }, [notice]);

  // Guard against a stale sendText() resolving after the client changed — its result belongs to a
  // dead session and must not overwrite the next session's status line.
  const clientRef = useRef<ClipboardClient | undefined>(client);
  clientRef.current = client;

  const onToggleReceive = useCallback(
    (next: boolean) => {
      // Never show CHECKED without a live client behind it.
      if (!client) {
        setReceive(false);
        return;
      }
      const state = receiveOwners.get(client);
      if (!state) return;
      if (next) {
        state.owner = receiveOwner.current;
        client.setReceiveEnabled(true, clipboardForWindow(hostRef.current?.ownerDocument.defaultView ?? null));
      } else if (state.owner === receiveOwner.current) {
        state.owner = null;
        client.setReceiveEnabled(false);
      }
      notifyReceiveOwner(state);
    },
    [client],
  );

  const onSend = useCallback(async () => {
    if (!client) return;
    const forClient = client;
    setSendStatus("Reading clipboard…");
    // Must run inside this click (a user gesture) for readText() to be permitted.
    const sent = await client.sendText(clipboardForWindow(hostRef.current?.ownerDocument.defaultView ?? null));
    if (clientRef.current !== forClient) return; // session changed while awaiting readText
    if (sent === null) {
      setSendStatus(noSendMessage(forClient.lastSendOutcome));
    } else if (sent === "") {
      setSendStatus("Sent empty clipboard → agent.");
    } else {
      setSendStatus(`Sent → agent: "${preview(sent)}"`);
    }
  }, [client]);

  // Automatic send: a press on the remote screen is a user gesture, so the browser (and the app's
  // gesture check) lets it read the local clipboard. Copy locally, click into the remote, paste.
  // sendText skips an unchanged value, so ordinary clicking sends nothing new.
  useEffect(() => {
    const doc = hostRef.current?.ownerDocument;
    if (!client || !auto || !doc) return;
    // An app older than 0.8.3 would show its consent dialog on every press; it keeps the button.
    if (desktopClientPromptsEveryClipboardRead(navigator.userAgent)) return;
    const forClient = client;
    const onPress = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (typeof target?.closest !== "function" || !target.closest(REMOTE_SURFACE_SELECTOR)) return;
      void forClient.sendText(clipboardForWindow(doc.defaultView)).then((sent) => {
        if (clientRef.current !== forClient || sent === null) return;
        setSendStatus(`Clipboard shared automatically (${sent.length} characters).`);
      });
    };
    doc.addEventListener("pointerdown", onPress, true);
    return () => doc.removeEventListener("pointerdown", onPress, true);
  }, [client, auto]);

  // The switch can be flipped from ANY control (this one, or the Input menu's ClipboardQuick), and the
  // choice applies to the live session at once, not just the next one: switching on starts receiving
  // here unless another control already owns receive; switching off stops it if this control owns it.
  const applyAuto = useRef<(on: boolean) => void>(() => {});
  applyAuto.current = (on: boolean) => {
    if (!client) return;
    const state = receiveOwners.get(client);
    if (!state) return;
    if (on && state.owner === null) onToggleReceive(true);
    else if (!on && state.owner === receiveOwner.current) onToggleReceive(false);
  };
  useEffect(() => subscribeClipboardAuto((on) => applyAuto.current(on)), []);
  const onToggleAuto = useCallback((next: boolean) => writeClipboardAuto(next), []);

  const receiveChecked = receive && Boolean(client?.isReceiveEnabled());
  const status = sendStatus || (notice ? noticeLabel(notice) : "");

  return (
    <div ref={hostRef} className="clipctl" data-testid="clipboard-control">
      <label className="clipctl__receive" data-testid="clipboard-auto-label"
        title="On: what you copy goes to the remote when you click into its screen, and what is copied there comes back to you.">
        <input
          type="checkbox"
          data-testid="clipboard-auto"
          checked={auto}
          onChange={(e) => onToggleAuto(e.target.checked)}
        />
        Share clipboard automatically
      </label>
      <button
        type="button"
        className="clipctl__btn"
        disabled={!client}
        onClick={onSend}
        data-testid="clipboard-send"
        title="Read your local clipboard and send it to the controlled machine"
      >
        Send clipboard → agent
      </button>
      <label className="clipctl__receive" data-testid="clipboard-receive-label">
        <input
          type="checkbox"
          data-testid="clipboard-receive"
          checked={receiveChecked}
          disabled={!client}
          onChange={(e) => onToggleReceive(e.target.checked)}
        />
        Receive remote clipboard {receiveChecked ? "(on)" : "(off)"}
      </label>
      {status && (
        <span className="clipctl__status" data-testid="clipboard-status">
          {status}
        </span>
      )}
    </div>
  );
}
