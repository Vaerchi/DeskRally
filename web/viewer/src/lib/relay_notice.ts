/**
 * The relay-limit notice: what the technician is told when signaling brokers a session WITHOUT a relay
 * credential, and how a connection that then fails names that as its likely cause.
 *
 * Why it exists. A TURN credential outlives the session it was issued for (it stays valid until it
 * expires), so signaling caps the credentials OUTSTANDING per technician and per tenant, not the
 * sessions alive (server/signaling/turn.go). At the cap a session is still brokered, but with STUN only,
 * and the requester's `ice_servers` message carries `relay_notice`. Only a direct connection can then
 * succeed, so a technician behind a strict firewall or NAT got a session that simply never connected,
 * with nothing to say why. The transport reports the notice (`onRelayNotice`), App holds it, and
 * `RelayNotice` shows it; a failure that follows is worded with {@link withRelayLimitCause}.
 *
 * Pure (no React, no transport) so the wording and the display rules are unit-tested.
 */

/**
 * A `relay_notice` the transport acts on: a string with something in it.
 *
 * The wire type says `string`, but `decodeSignaling` only checks the `type` tag, so a buggy or hostile
 * server can put anything there. Everything else is treated as ABSENT rather than coerced: an object
 * handed to React as a child throws at render time and takes the whole console down with it.
 * Whitespace-only counts as empty, like the Go side's `omitempty` on an empty string.
 */
export function isRelayNotice(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * What the technician reads, in the order they need it: what happened, what it means, what to do.
 *
 * The 2 hours is the signaling server's DEFAULT credential lifetime (SIGNALING_TURN_TTL); an operator
 * can change it and the server does not say, so the copy says "normally".
 *
 * What to do is wait or ask, NOT close sessions. The cap counts the credentials the server has issued and
 * not yet expired, not the sessions alive (server/signaling/turn.go; TestSecurityTurnStartEndRepeatIsBounded
 * drops the session and its credential still counts), so ending a session frees nothing. Telling a
 * technician to close sessions would have them end work for no effect, with the strip still there, so the
 * copy says it will not help.
 */
export const RELAY_NOTICE_COPY = {
  headline: "No relay connection is available.",
  what: "This account has reached its limit of relay credentials, so only a direct connection can be tried.",
  consequence: "That may fail on restrictive networks.",
  action:
    "Closing sessions will not free a relay credential: each is kept until it expires, even after its session ends. Wait: older relay credentials expire on their own, normally within 2 hours. Ask an administrator if this keeps happening.",
} as const;

/**
 * The clause a connection failure carries while the notice is active. No trailing period on purpose:
 * `SessionRecovery.lost` appends ". Reconnecting in Ns…" to whatever it is given.
 */
export const RELAY_LIMIT_CAUSE =
  "likely cause: this account has reached its limit of relay credentials, so only a direct connection was tried";

/** `message` with the relay limit named as its likely cause, or `message` untouched when there is none. */
export function withRelayLimitCause(message: string, cause: string | null | undefined): string {
  return cause ? `${message} (${cause})` : message;
}

/** Longest server text shown, in characters. The aside is one line, not a place for a paragraph. */
export const RELAY_NOTICE_DETAIL_MAX = 200;

/** How much of a server's text is looked at, in UTF-16 units. Nothing bounds what arrives off the network. */
export const RELAY_NOTICE_SCAN_MAX = 1000;

/**
 * The server's own wording, cleaned for display as a single line of TEXT; `null` when nothing is left.
 *
 * This is a string from the network. React escapes it, so it can never become markup, but it can still
 * be long, span lines, or carry bidi overrides and zero-width characters that reorder or hide the text
 * around it. Only the first {@link RELAY_NOTICE_SCAN_MAX} units are looked at (a multi-megabyte string is
 * never scanned or split); control and format characters become spaces, whitespace collapses, and the
 * result is cut at {@link RELAY_NOTICE_DETAIL_MAX} characters (by code point, so a surrogate pair is never
 * split).
 */
export function relayNoticeDetail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const text = raw
    .slice(0, RELAY_NOTICE_SCAN_MAX)
    // The cut can land inside a surrogate pair; a lone high surrogate at the end is not text.
    .replace(/[\uD800-\uDBFF]$/, "")
    .replace(/[\p{Cc}\p{Cf}]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (text === "") return null;
  const chars = Array.from(text);
  return chars.length > RELAY_NOTICE_DETAIL_MAX ? `${chars.slice(0, RELAY_NOTICE_DETAIL_MAX - 1).join("")}…` : text;
}
