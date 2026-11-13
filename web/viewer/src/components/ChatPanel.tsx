/**
 * In-session chat console (Milestone M12).
 *
 * A tab in the session UI that drives the `ChatClient` over the live session's `ChannelId.Chat`:
 * the operator types a line, the client frames a `Send`, and the AGENT — which owns the transcript —
 * echoes it back as a `Posted` carrying the sequence number and timestamp it recorded. So everything
 * rendered here came from the agent; nothing is a local optimistic guess (see `lib/chat.ts`).
 *
 * The transcript arrives as the `messages` prop rather than being read off the client, matching how
 * `Viewer` receives `monitors` and `FileTransferPanel` receives `download`: `App.tsx` holds the state
 * the client's `onMessages` callback pushes, so React re-renders when the agent posts.
 *
 * As with the other panels, the pure logic (formatting, the send-enabled rule, the Enter/Shift+Enter
 * rule) is exported so it is unit-testable without a rendering harness — the pattern `Viewer.tsx`
 * uses with `viewerMonitorOptions` (and `lib/viewport` for the zoom/pan transform).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatClient, ChatEntry, ChatFrom } from "../lib/chat";

/** One rendered transcript line: everything the list needs, already formatted. */
export interface ChatLine {
  /** The agent-assigned sequence — also the React key, since the agent assigns each exactly once. */
  seq: number;
  /** Display label for the sender's ROLE. */
  label: string;
  /** Local wall-clock time the agent recorded the message. */
  time: string;
  body: string;
  /** True for the technician side — drives the visual distinction from the guest's messages. */
  mine: boolean;
}

/**
 * Display label for a sender.
 *
 * Deliberately the ROLE and not "You". `ChatFrom` is a role, not an identity — the agent cannot
 * authenticate a name, and a session can involve more than one technician over its life — so
 * labelling `Technician` as "You" would state something the wire does not know. The operator's own
 * side is distinguished visually instead (see {@link ChatLine.mine}).
 */
export function chatFromLabel(from: ChatFrom): string {
  return from === "Technician" ? "Technician" : "Guest";
}

/**
 * Local wall-clock `HH:MM` for a Unix-millisecond timestamp.
 *
 * LOCAL, not UTC: the agent stamps messages with its own clock in Unix ms, and the operator reading
 * "was that before or after I rebooted it?" is comparing against their own wall clock. Fixed-width
 * (zero-padded, 24-hour) so the column does not jitter between 9:05 and 10:05 — and because the
 * transcript is scanned, not read.
 */
export function formatChatTime(atUnixMs: number): string {
  const d = new Date(atUnixMs);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/** Format a transcript for rendering. Order is preserved — the client already sorted it by seq. */
export function chatLines(entries: readonly ChatEntry[]): ChatLine[] {
  return entries.map((e) => ({
    seq: e.seq,
    label: chatFromLabel(e.from),
    time: formatChatTime(e.at_unix_ms),
    body: e.body,
    mine: e.from === "Technician",
  }));
}

/**
 * Whether the Send button does anything: a live session AND a draft with actual content.
 *
 * Whitespace-only is blocked because the agent RECORDS what it is sent (it truncates, it does not
 * reject), so a stray Enter would put a blank line into a persisted support transcript that outlives
 * the session.
 */
export function chatSendEnabled(draft: string, connected: boolean): boolean {
  return connected && draft.trim() !== "";
}

/** Whether the composer is interactive, and the tooltip explaining it when it is not. */
export interface ChatComposerState {
  disabled: boolean;
  title: string;
}

/**
 * Enable/disable state for the composer.
 *
 * The `title` carries the reason in both states: a greyed-out box with no explanation leaves the
 * operator unable to tell "chat is broken" from "there is no session yet" (the same rule
 * `qualityControlState` follows in `Viewer.tsx`).
 */
export function chatComposerState(connected: boolean): ChatComposerState {
  return connected
    ? { disabled: false, title: "Send a message to the person at the remote machine." }
    : {
        disabled: true,
        title: "Connect to a machine to chat with the person at it.",
      };
}

/**
 * Whether this keypress in the composer should SEND (vs. insert a newline).
 *
 * Enter sends, Shift+Enter newlines — the convention of every chat client, and the reason the
 * composer is a `<textarea>` rather than an `<input>`.
 *
 * `isComposing` guards an IME: while composing Japanese, Chinese or Korean text the Enter key
 * COMMITS the candidate the user is choosing and must not send. Without this check the guest's name
 * would be sent as a half-finished fragment on their first keystroke — and chat is precisely the
 * channel where non-Latin input is expected (`chat.test.ts` pins 日本語 through the codec).
 */
export function chatKeySends(key: string, shiftKey: boolean, isComposing = false): boolean {
  return key === "Enter" && !shiftKey && !isComposing;
}

export interface ChatPanelProps {
  /** Live client over `ChannelId.Chat`. Absent ⇒ the composer is disabled (no session). */
  client?: ChatClient;
  /** The transcript as the agent has posted it (from the client's `onMessages`), oldest first. */
  messages?: readonly ChatEntry[];
  /** True once the agent reported a `History` that omitted entries — the transcript has a hole. */
  truncated?: boolean;
}

export function ChatPanel({ client, messages = [], truncated = false }: ChatPanelProps) {
  const [draft, setDraft] = useState("");
  const logRef = useRef<HTMLDivElement>(null);

  const connected = !!client;
  const composer = chatComposerState(connected);
  const canSend = chatSendEnabled(draft, connected);
  const lines = chatLines(messages);

  const onSend = useCallback(() => {
    if (!client || draft.trim() === "") return;
    // Send the draft as typed (only the blank check is trimmed) — leading indentation in a pasted
    // command or path is content, not noise.
    client.send(draft);
    setDraft("");
  }, [client, draft]);

  // Follow the conversation: a message arriving below the fold is one the operator never sees, and
  // an unread reply in a support session is the whole point of the feature. Keyed on the message
  // count so it fires on a new line, not on every keystroke in the composer.
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  return (
    <div className="chatpanel" data-testid="chat-panel">
      {truncated && (
        <p className="chatpanel__truncated" role="status" data-testid="chat-truncated">
          Older messages are missing: the agent&rsquo;s transcript is longer than one reply can
          carry, so this is not the whole conversation.
        </p>
      )}

      <div className="chatpanel__log" data-testid="chat-log" ref={logRef}>
        {lines.length === 0 && (
          <p className="chatpanel__empty">
            {connected
              ? "No messages yet. Say hello to the person at the machine."
              : "Connect to a machine to see its chat history."}
          </p>
        )}
        {lines.map((l) => (
          <div
            className="chatpanel__line"
            key={l.seq}
            data-mine={l.mine}
            data-testid="chat-line"
          >
            <span className="chatpanel__time">{l.time}</span>
            <span className="chatpanel__from">{l.label}</span>
            <span className="chatpanel__body">{l.body}</span>
          </div>
        ))}
      </div>

      <div className="chatpanel__composer">
        <textarea
          className="chatpanel__input"
          rows={2}
          placeholder={connected ? "Message… (Enter sends, Shift+Enter for a new line)" : ""}
          value={draft}
          disabled={composer.disabled}
          title={composer.title}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            // `nativeEvent.isComposing` is true mid-IME: that Enter belongs to the candidate picker.
            if (chatKeySends(e.key, e.shiftKey, e.nativeEvent.isComposing)) {
              e.preventDefault(); // ...or the textarea also inserts the newline we just sent on
              onSend();
            }
          }}
          data-testid="chat-input"
        />
        <button
          type="button"
          className="chatpanel__send"
          disabled={!canSend}
          title={composer.title}
          onClick={onSend}
          data-testid="chat-send"
        >
          Send
        </button>
      </div>
    </div>
  );
}
