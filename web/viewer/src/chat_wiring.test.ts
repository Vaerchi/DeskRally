/**
 * M12 App wiring contract: in-session chat over the live session.
 *
 * `App.tsx` extends its single `onMessage(channel, payload)` router with a `ChannelId.Chat` arm
 * feeding a `ChatClient`, builds that client so `send` frames onto the transport, and calls
 * `requestHistory()` once the transport connects so opening a session shows the conversation the
 * machine already has. App is `.tsx` and the vitest env is `node`, so — following
 * `v3_wiring.test.ts` and `backstage/app_routing.test.ts` — rather than render the component we
 * exercise the exact routing + client usage the panel relies on.
 */

import { describe, it, expect } from "vitest";

import { ChannelId } from "./lib";
import { ChatClient, decodeChat, encodeChat, type ChatEntry, type ChatMessage } from "./lib/chat";
import { ControlClient, encodeControl } from "./lib/control";
import { chatLines } from "./components/ChatPanel";

/** Build the chat client + the App-shaped router exactly as `App.tsx` composes them. */
function wire() {
  const chatSent: Uint8Array[] = [];
  const controlSent: Uint8Array[] = [];
  /** What App pushes into React state from `onMessages` (the ChatPanel's `messages` prop). */
  let panelMessages: readonly ChatEntry[] = [];
  let panelTruncated = false;
  /** Frames that reached the CONTROL client — used to prove no channel steals another's. */
  const monitorLists: number[] = [];

  const chat = new ChatClient((payload) => chatSent.push(payload), {
    onMessages: (m) => (panelMessages = [...m]),
    onTruncated: () => (panelTruncated = true),
  });
  const control = new ControlClient((payload) => controlSent.push(payload), {
    onMonitors: (list) => monitorLists.push(list.length),
  });

  // Byte-for-byte the routing in App.tsx's `onMessage`.
  const route = (channel: ChannelId, payload: Uint8Array) => {
    if (channel === ChannelId.Control) control.handleMessage(payload);
    else if (channel === ChannelId.Chat) chat.handleMessage(payload);
  };

  return {
    route,
    chat,
    chatSent,
    monitorLists,
    sentMessages: () => chatSent.map((p) => decodeChat(p)),
    panel: () => ({ messages: panelMessages, truncated: panelTruncated }),
  };
}

const entry = (seq: number, from: ChatEntry["from"], body: string): ChatEntry => ({
  seq,
  from,
  body,
  at_unix_ms: 1700000000000 + seq * 1000,
});

describe("M12 chat wiring (send/receive over the App router)", () => {
  it("connect asks for the machine's existing conversation, and the reply fills the panel", () => {
    const { route, chat, sentMessages, panel } = wire();

    // App calls this right after `transport.connect` resolves (the send is buffered until the
    // channel opens). A fresh client holds nothing, so the cursor is 0: replay everything.
    chat.requestHistory();
    expect(sentMessages()).toEqual<ChatMessage[]>([{ t: "RequestHistory", c: { since_seq: 0 } }]);

    route(
      ChannelId.Chat,
      encodeChat({
        t: "History",
        c: { entries: [entry(1, "Guest", "my printer is broken"), entry(2, "Technician", "on it")], truncated: false },
      }),
    );
    expect(panel().messages.map((e) => e.body)).toEqual(["my printer is broken", "on it"]);
    expect(panel().truncated).toBe(false);
    // ...and the panel's formatting consumes that state as-is.
    expect(chatLines(panel().messages).map((l) => l.label)).toEqual(["Guest", "Technician"]);
  });

  it("an operator message goes out as a Send and appears only via the agent's Posted echo", () => {
    const { route, chat, sentMessages, panel } = wire();

    chat.send("have you tried the other tray?");
    expect(sentMessages()).toEqual<ChatMessage[]>([
      { t: "Send", c: { from: "Technician", body: "have you tried the other tray?" } },
    ]);
    // Nothing yet: the agent owns the transcript and has not recorded it.
    expect(panel().messages).toEqual([]);

    route(ChannelId.Chat, encodeChat({ t: "Posted", c: { entry: entry(7, "Technician", "have you tried the other tray?") } }));
    expect(panel().messages.map((e) => e.seq)).toEqual([7]);
  });

  it("a reconnect-style history replay does not duplicate what the echo already delivered", () => {
    // The sequence that produces a double-rendered transcript without de-duplication: an echo lands
    // during the session, then a later RequestHistory replays a window that still contains it.
    const { route, chat, sentMessages, panel } = wire();

    route(ChannelId.Chat, encodeChat({ t: "Posted", c: { entry: entry(1, "Guest", "hello?") } }));
    chat.requestHistory();
    expect(sentMessages()).toEqual<ChatMessage[]>([{ t: "RequestHistory", c: { since_seq: 1 } }]);

    route(
      ChannelId.Chat,
      encodeChat({
        t: "History",
        c: { entries: [entry(1, "Guest", "hello?"), entry(2, "Technician", "hi")], truncated: false },
      }),
    );
    expect(panel().messages.map((e) => e.seq)).toEqual([1, 2]);
  });

  it("a truncated History raises the panel's missing-messages notice", () => {
    const { route, panel } = wire();
    route(
      ChannelId.Chat,
      encodeChat({ t: "History", c: { entries: [entry(300, "Guest", "…")], truncated: true } }),
    );
    expect(panel().truncated).toBe(true);
  });

  it("no channel steals another's frames, and a bad chat frame does not break the router", () => {
    const { route, chat, monitorLists, panel } = wire();

    // A Control frame must reach the control client only...
    route(ChannelId.Control, encodeControl({ t: "MonitorList", c: { monitors: [{ id: 0, width: 1920, height: 1080, primary: true }] } }));
    expect(monitorLists).toEqual([1]);
    expect(panel().messages).toEqual([]);

    // ...and a Chat frame the chat client only (the control client never sees it).
    route(ChannelId.Chat, encodeChat({ t: "Posted", c: { entry: entry(1, "Guest", "hi") } }));
    expect(monitorLists).toEqual([1]);
    expect(chat.messages).toHaveLength(1);

    // An undecodable chat frame is absorbed: `onMessage` runs inside transport.ts's loop over the
    // frames coalesced into one SCTP message, so a throw here would discard its innocent siblings.
    expect(() => route(ChannelId.Chat, new TextEncoder().encode("{not json"))).not.toThrow();
    route(ChannelId.Chat, encodeChat({ t: "Posted", c: { entry: entry(2, "Technician", "still routing") } }));
    expect(panel().messages.map((e) => e.body)).toEqual(["hi", "still routing"]);
  });
});
