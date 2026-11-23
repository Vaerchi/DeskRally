//! Canonical wire codec for **in-session chat** (M12), plus the agent-side transcript.
//!
//! Like [`crate::input_codec`], [`crate::clipboard`], [`crate::file_transfer`] and
//! [`crate::control`], this is the **one** encoding both ends agree on: the Rust agent
//! decodes/encodes chat frames with [`decode`]/[`encode`], and the browser controller
//! (`web/viewer/src/lib/chat.ts`) produces byte-identical frames. Messages ride as the payload of a
//! [`Frame`](rmt_protocol::Frame) tagged [`rmt_protocol::ChannelId::Chat`].
//!
//! # The flow
//!
//! 1. either side → other: [`ChatMessage::Send`] — a line of text someone typed.
//! 2. agent → controller: [`ChatMessage::Posted`] — the message as **recorded**, carrying the
//!    sequence number and timestamp the transcript assigned it.
//! 3. controller → agent: [`ChatMessage::RequestHistory`] — "replay what I missed".
//! 4. agent → controller: [`ChatMessage::History`] — the backlog.
//!
//! # Why the agent assigns the sequence numbers
//!
//! The agent is the only party present for *every* session with this machine, so it is the only one
//! that can order a transcript spanning several technicians and several connections. A controller
//! that numbered its own messages would produce a transcript whose order depended on who happened
//! to be connected, and two technicians in the same session would collide immediately.
//!
//! It also makes `RequestHistory { since_seq }` a resumable cursor rather than a guess: a viewer
//! that reconnects asks for everything after the highest sequence it already has, and gets exactly
//! the gap — not a duplicate of the whole transcript, which is what a timestamp-based cursor gives
//! you the moment two messages share a millisecond.
//!
//! # Wire shape
//!
//! JSON, **adjacently tagged** (`{"t":<variant>,"c":<content>}`) exactly like the sibling codecs.

use serde::{Deserialize, Serialize};

/// Who wrote a message.
///
/// Deliberately a role and not a name. The agent cannot authenticate a display name — it receives
/// whatever the controller sends — so a transcript that recorded "Alice" would be recording a claim
/// as if it were a fact. The role is something the agent *knows*: one side of the connection is the
/// remote technician, the other is the person at the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatFrom {
    /// The remote operator (the controller end of the session).
    Technician,
    /// The person at the machine being controlled.
    Guest,
}

/// One recorded chat line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatEntry {
    /// Monotonic per-machine sequence number, assigned by the agent. Starts at 1.
    pub seq: u64,
    /// Which side wrote it.
    pub from: ChatFrom,
    /// The text, already truncated to [`MAX_BODY_CHARS`].
    pub body: String,
    /// Unix milliseconds when the agent recorded it.
    pub at_unix_ms: i64,
}

/// A single decoded chat message. Adjacently-tagged as `{"t":…,"c":…}` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
pub enum ChatMessage {
    /// Either side → the other: a line someone typed. The sender does **not** assign a sequence
    /// number or timestamp; the agent's transcript does, and echoes them back in
    /// [`ChatMessage::Posted`].
    Send {
        /// Who is writing. A controller sends `Technician`; the guest UI sends `Guest`.
        from: ChatFrom,
        /// The text. Longer than [`MAX_BODY_CHARS`] is truncated, not rejected — see
        /// [`Transcript::post`].
        body: String,
    },
    /// agent → controller: a message as recorded, including its assigned sequence and timestamp.
    /// Sent for **every** message the transcript accepts, including the controller's own — so the
    /// controller's view of the transcript is the agent's, not a local guess.
    Posted {
        /// The recorded entry.
        entry: ChatEntry,
    },
    /// controller → agent: replay everything after `since_seq`. `0` means "everything you have".
    RequestHistory {
        /// The highest sequence the requester already holds.
        since_seq: u64,
    },
    /// agent → controller: the requested backlog, oldest first.
    History {
        /// The entries after the requested cursor, at most [`MAX_HISTORY_REPLY`].
        entries: Vec<ChatEntry>,
        /// `true` when entries were omitted because the backlog exceeded the reply cap — so a
        /// viewer knows its transcript has a hole rather than silently believing it is complete.
        truncated: bool,
    },
}

/// Longest accepted message body, in **characters** (not bytes — a byte cap would split a
/// multi-byte character and produce invalid UTF-8 on the wire).
pub const MAX_BODY_CHARS: usize = 4000;
/// How many entries the agent keeps in its in-memory transcript. At ~4 KB each this bounds the
/// session's chat memory at a few megabytes even if someone pastes continuously.
pub const MAX_TRANSCRIPT: usize = 500;
/// Most entries returned by a single [`ChatMessage::History`]. Bounded because one reply becomes one
/// data-channel message, and the transport chunks anything large.
pub const MAX_HISTORY_REPLY: usize = 200;

/// Largest legal chat frame, in bytes: a full [`MAX_HISTORY_REPLY`]-entry
/// [`ChatMessage::History`] whose bodies are [`MAX_BODY_CHARS`] characters each, JSON-escaped to the
/// worst case of 12 bytes per character (a non-BMP char as a `\uXXXX\uXXXX` surrogate pair), plus
/// 512 bytes of per-entry field overhead and 4 KiB of envelope/whitespace slack. [`decode`] refuses
/// anything larger before parsing, so a peer cannot force a multi-megabyte parse/allocation.
pub const MAX_CHAT_WIRE_LEN: usize = MAX_HISTORY_REPLY * (MAX_BODY_CHARS * 12 + 512) + 4096;

/// Error decoding a chat message off the wire (malformed JSON or an unknown variant/shape).
pub type ChatCodecError = serde_json::Error;

/// Encode one [`ChatMessage`] to its canonical JSON wire bytes.
///
/// Infallible in practice; on the impossible serialize error it yields an empty vec, keeping the
/// send path total (matches the sibling codecs).
pub fn encode(msg: &ChatMessage) -> Vec<u8> {
    serde_json::to_vec(msg).unwrap_or_default()
}

/// Decode one [`ChatMessage`] from canonical JSON wire bytes.
///
/// Input longer than [`MAX_CHAT_WIRE_LEN`] (larger than any legal frame) is refused before parsing.
pub fn decode(bytes: &[u8]) -> Result<ChatMessage, ChatCodecError> {
    if bytes.len() > MAX_CHAT_WIRE_LEN {
        return Err(<ChatCodecError as serde::de::Error>::custom(format!(
            "chat frame is {} bytes, over the {} byte limit",
            bytes.len(),
            MAX_CHAT_WIRE_LEN
        )));
    }
    serde_json::from_slice(bytes)
}

/// Cut a body to [`MAX_BODY_CHARS`] characters (never mid-codepoint). Shared by `post` and `restore`.
fn truncate_body(body: &str) -> String {
    body.chars().take(MAX_BODY_CHARS).collect()
}

/// The agent's bounded chat transcript: assigns sequence numbers, keeps the recent history, and
/// answers [`ChatMessage::RequestHistory`].
///
/// Pure and clock-free — `now_unix_ms` is a parameter — so the ordering and truncation rules are
/// testable without sleeping or mocking a clock.
#[derive(Debug)]
pub struct Transcript {
    entries: std::collections::VecDeque<ChatEntry>,
    /// The sequence the next `post` hands out. Saturates at `u64::MAX`, so it can equal the last
    /// recorded sequence once the space is exhausted.
    next_seq: u64,
    /// The highest sequence ever recorded or restored (including restored entries that were then
    /// dropped from the front). Tracked apart from `next_seq` so `last_seq()` stays exact when
    /// `next_seq` has saturated.
    high_water: u64,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// An empty transcript. The first message posted gets sequence 1, so `since_seq: 0` reliably
    /// means "I have nothing" rather than colliding with a real entry.
    pub fn new() -> Self {
        Self { entries: std::collections::VecDeque::new(), next_seq: 1, high_water: 0 }
    }

    /// Reload from persisted entries (oldest first), continuing the sequence after the highest one
    /// seen. Entries beyond [`MAX_TRANSCRIPT`] are dropped from the front.
    ///
    /// Continuing rather than restarting matters: a viewer that reconnects holds sequence numbers
    /// from before the restart, and a transcript that began again at 1 would answer
    /// `RequestHistory { since_seq: 42 }` with nothing at all — the reconnect case this exists for.
    ///
    /// The persisted file is untrusted at load time, so the invariants [`Transcript::post`] enforces
    /// are re-applied here: every body is cut to [`MAX_BODY_CHARS`] the same way, and the sequence
    /// arithmetic saturates. A persisted `seq == u64::MAX` clamps `next_seq` to `u64::MAX` rather
    /// than overflowing (a debug panic, or a release wrap to 0 — the "I have nothing" sentinel).
    ///
    /// Ordering is enforced too: `post` only ever hands out strictly ascending sequences, so any
    /// entry whose `seq` is not strictly greater than the previous *kept* entry's is dropped
    /// (duplicates, regressions, out-of-order). `high_water` and `next_seq` are computed from ALL
    /// input first, so a number a viewer may already hold is never reused. The filter runs before
    /// the [`MAX_TRANSCRIPT`] trim, so invalid entries never consume cap slots.
    pub fn restore(entries: Vec<ChatEntry>) -> Self {
        let high_water = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        let next_seq = high_water.saturating_add(1);
        let mut last_kept: Option<u64> = None;
        let mut deque: std::collections::VecDeque<ChatEntry> = entries
            .into_iter()
            .filter(|e| {
                let keep = last_kept.map_or(true, |prev| e.seq > prev);
                if keep {
                    last_kept = Some(e.seq);
                }
                keep
            })
            .collect();
        while deque.len() > MAX_TRANSCRIPT {
            deque.pop_front();
        }
        for e in deque.iter_mut() {
            if e.body.chars().count() > MAX_BODY_CHARS {
                e.body = truncate_body(&e.body);
            }
        }
        Self { entries: deque, next_seq, high_water }
    }

    /// Record a message and return the entry as stored.
    ///
    /// An over-long body is **truncated, not rejected**. Rejecting would mean a technician pastes a
    /// stack trace, sees nothing appear, and has no idea why; truncating delivers the message and
    /// loses only the tail. The cap counts characters so the cut never lands mid-codepoint.
    pub fn post(&mut self, from: ChatFrom, body: &str, now_unix_ms: i64) -> ChatEntry {
        let body = truncate_body(body);
        let entry = ChatEntry { seq: self.next_seq, from, body, at_unix_ms: now_unix_ms };
        // Saturating: once `u64::MAX` is reached the transcript keeps handing out `u64::MAX` (a
        // repeat of the last sequence) rather than panicking or wrapping to the 0 sentinel.
        self.high_water = self.high_water.max(entry.seq);
        self.next_seq = self.next_seq.saturating_add(1);
        self.entries.push_back(entry.clone());
        while self.entries.len() > MAX_TRANSCRIPT {
            self.entries.pop_front();
        }
        entry
    }

    /// Everything after `since_seq`, oldest first, capped at [`MAX_HISTORY_REPLY`].
    ///
    /// Returns `(entries, truncated)`. When the backlog is larger than the cap the **oldest** are
    /// dropped, because the newest messages are the ones the operator needs — and `truncated` says
    /// so, rather than letting the viewer believe it received a complete transcript.
    pub fn history_since(&self, since_seq: u64) -> (Vec<ChatEntry>, bool) {
        let all: Vec<ChatEntry> =
            self.entries.iter().filter(|e| e.seq > since_seq).cloned().collect();
        if all.len() <= MAX_HISTORY_REPLY {
            return (all, false);
        }
        (all[all.len() - MAX_HISTORY_REPLY..].to_vec(), true)
    }

    /// The highest sequence recorded so far (0 when empty).
    pub fn last_seq(&self) -> u64 {
        self.high_water
    }

    /// Every retained entry, oldest first — for persistence.
    pub fn entries(&self) -> &std::collections::VecDeque<ChatEntry> {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a message and assert its exact canonical JSON, so the shape is pinned and the
    /// TypeScript controller can be tested against the same strings.
    ///
    /// These literals are the cross-language contract: `web/viewer/src/lib/chat.test.ts` pins the
    /// SAME strings byte-for-byte, and each file names the other.
    fn round_trip(msg: ChatMessage, expect_json: &str) {
        let bytes = encode(&msg);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            expect_json,
            "canonical JSON for {msg:?}"
        );
        assert_eq!(decode(&bytes).expect("decode"), msg, "round-trip for {msg:?}");
    }

    #[test]
    fn send_round_trips() {
        round_trip(
            ChatMessage::Send { from: ChatFrom::Technician, body: "hello there".into() },
            r#"{"t":"Send","c":{"from":"Technician","body":"hello there"}}"#,
        );
        round_trip(
            ChatMessage::Send { from: ChatFrom::Guest, body: "my printer is broken".into() },
            r#"{"t":"Send","c":{"from":"Guest","body":"my printer is broken"}}"#,
        );
    }

    #[test]
    fn posted_round_trips() {
        round_trip(
            ChatMessage::Posted {
                entry: ChatEntry {
                    seq: 7,
                    from: ChatFrom::Guest,
                    body: "ok".into(),
                    at_unix_ms: 1_700_000_000_000,
                },
            },
            r#"{"t":"Posted","c":{"entry":{"seq":7,"from":"Guest","body":"ok","at_unix_ms":1700000000000}}}"#,
        );
    }

    #[test]
    fn request_history_round_trips() {
        round_trip(
            ChatMessage::RequestHistory { since_seq: 0 },
            r#"{"t":"RequestHistory","c":{"since_seq":0}}"#,
        );
    }

    #[test]
    fn history_round_trips() {
        round_trip(
            ChatMessage::History {
                entries: vec![ChatEntry {
                    seq: 1,
                    from: ChatFrom::Technician,
                    body: "hi".into(),
                    at_unix_ms: 1_700_000_000_001,
                }],
                truncated: false,
            },
            r#"{"t":"History","c":{"entries":[{"seq":1,"from":"Technician","body":"hi","at_unix_ms":1700000000001}],"truncated":false}}"#,
        );
        round_trip(
            ChatMessage::History { entries: vec![], truncated: true },
            r#"{"t":"History","c":{"entries":[],"truncated":true}}"#,
        );
    }

    #[test]
    fn json_special_characters_survive_the_wire() {
        // Chat is the one channel where a user types arbitrary text at the protocol. Quotes,
        // backslashes, newlines and non-BMP characters must all come back intact — a codec that
        // mangled them would corrupt exactly the support transcript this feature exists to keep.
        let nasty = "he said \"hi\"\\n\nnewline\ttab 😀 日本語";
        let msg = ChatMessage::Send { from: ChatFrom::Guest, body: nasty.into() };
        let back = decode(&encode(&msg)).expect("decode");
        match back {
            ChatMessage::Send { body, .. } => assert_eq!(body, nasty),
            other => panic!("expected Send, got {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage_and_unknown_variants() {
        assert!(decode(b"not json").is_err());
        assert!(decode(br#"{"t":"Nope"}"#).is_err());
        assert!(decode(br#"{"t":"Send","c":{"from":"Nobody","body":"x"}}"#).is_err());
        assert!(
            decode(br#"{"t":"Send","c":{"body":"x"}}"#).is_err(),
            "a missing field must be rejected, never defaulted"
        );
    }

    // --- the decode size bound --------------------------------------------------------------

    /// A valid `Send` frame with trailing JSON whitespace padded to exactly `len` bytes.
    fn padded_send(len: usize) -> Vec<u8> {
        let mut v = br#"{"t":"Send","c":{"from":"Guest","body":"x"}}"#.to_vec();
        assert!(v.len() <= len);
        v.resize(len, b' ');
        v
    }

    #[test]
    fn a_full_ascii_history_round_trips() {
        let entries: Vec<ChatEntry> = (1..=MAX_HISTORY_REPLY as u64)
            .map(|s| saved_entry(s, "a".repeat(MAX_BODY_CHARS)))
            .collect();
        let msg = ChatMessage::History { entries, truncated: true };
        let bytes = encode(&msg);
        assert!(bytes.len() <= MAX_CHAT_WIRE_LEN);
        assert_eq!(decode(&bytes).expect("decode"), msg);
    }

    #[test]
    fn a_worst_case_escaped_history_still_decodes() {
        let body_escaped = "\\ud83d\\ude00".repeat(MAX_BODY_CHARS);
        assert_eq!(body_escaped.len(), MAX_BODY_CHARS * 12);
        let expect_body = "😀".repeat(MAX_BODY_CHARS);

        let entry_compact = |seq: usize| {
            format!(
                r#"{{"seq":{seq},"from":"Guest","body":"{body_escaped}","at_unix_ms":1700000000000}}"#
            )
        };
        let compact = (1..=MAX_HISTORY_REPLY).map(entry_compact).collect::<Vec<_>>().join(",");
        let compact = format!(r#"{{"t":"History","c":{{"entries":[{compact}],"truncated":false}}}}"#);
        assert!(compact.len() <= MAX_CHAT_WIRE_LEN, "{} > {}", compact.len(), MAX_CHAT_WIRE_LEN);

        // Pretty-printed whitespace and reordered `c`/`t` keys.
        let entry_pretty = |seq: usize| {
            format!(
                "    {{\n      \"at_unix_ms\": 1700000000000,\n      \"body\": \"{body_escaped}\",\n      \"from\": \"Guest\",\n      \"seq\": {seq}\n    }}"
            )
        };
        let pretty = (1..=MAX_HISTORY_REPLY).map(entry_pretty).collect::<Vec<_>>().join(",\n");
        let pretty = format!(
            "{{\n  \"c\": {{\n  \"truncated\": false,\n  \"entries\": [\n{pretty}\n  ]\n  }},\n  \"t\": \"History\"\n}}"
        );
        assert!(pretty.len() <= MAX_CHAT_WIRE_LEN, "{} > {}", pretty.len(), MAX_CHAT_WIRE_LEN);

        for wire in [compact, pretty] {
            match decode(wire.as_bytes()).expect("worst-case legal frame decodes") {
                ChatMessage::History { entries, truncated } => {
                    assert!(!truncated);
                    assert_eq!(entries.len(), MAX_HISTORY_REPLY);
                    assert!(entries.iter().all(|e| e.body == expect_body));
                }
                other => panic!("expected History, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_over_long_send_still_decodes() {
        let msg = ChatMessage::Send {
            from: ChatFrom::Technician,
            body: "x".repeat(MAX_BODY_CHARS * 2),
        };
        assert_eq!(decode(&encode(&msg)).expect("decode"), msg);
    }

    #[test]
    fn a_frame_over_the_legal_maximum_is_refused_before_parsing() {
        let err = decode(&vec![b'x'; MAX_CHAT_WIRE_LEN + 1]).expect_err("oversized");
        let text = err.to_string();
        assert!(text.contains(&(MAX_CHAT_WIRE_LEN + 1).to_string()), "{text}");
        assert!(text.contains(&MAX_CHAT_WIRE_LEN.to_string()), "{text}");

        // Valid JSON is refused too, which shows the length check does not depend on a parse failure.
        let valid = padded_send(MAX_CHAT_WIRE_LEN + 1);
        assert!(serde_json::from_slice::<ChatMessage>(&valid).is_ok(), "premise: parses fine");
        let text = decode(&valid).expect_err("oversized valid JSON").to_string();
        assert!(text.contains(&(MAX_CHAT_WIRE_LEN + 1).to_string()), "{text}");
        assert!(text.contains(&MAX_CHAT_WIRE_LEN.to_string()), "{text}");
    }

    #[test]
    fn a_frame_of_exactly_the_legal_maximum_is_not_refused() {
        let exact = padded_send(MAX_CHAT_WIRE_LEN);
        assert_eq!(exact.len(), MAX_CHAT_WIRE_LEN);
        assert_eq!(
            decode(&exact).expect("at the limit"),
            ChatMessage::Send { from: ChatFrom::Guest, body: "x".into() }
        );
    }

    #[test]
    fn small_malformed_json_still_errors_via_serde() {
        let text = decode(b"{\"t\":\"Send\",").expect_err("truncated JSON").to_string();
        assert!(!text.contains("byte limit"), "{text}");
        assert!(decode(b"").is_err());
    }

    // --- the transcript ---------------------------------------------------------------------

    #[test]
    fn sequences_start_at_one_and_increase() {
        // Starting at 1 is what makes `since_seq: 0` unambiguously "I have nothing". If the first
        // entry were 0, a fresh viewer's request would skip it.
        let mut t = Transcript::new();
        assert_eq!(t.last_seq(), 0, "an empty transcript has no last sequence");
        let a = t.post(ChatFrom::Technician, "one", 100);
        let b = t.post(ChatFrom::Guest, "two", 200);
        assert_eq!(a.seq, 1);
        assert_eq!(b.seq, 2);
        assert_eq!(t.last_seq(), 2);
        assert_eq!(a.from, ChatFrom::Technician);
        assert_eq!(b.at_unix_ms, 200);
    }

    #[test]
    fn history_since_is_a_resumable_cursor() {
        let mut t = Transcript::new();
        for i in 0..5 {
            t.post(ChatFrom::Technician, &format!("m{i}"), i as i64);
        }
        let (all, trunc) = t.history_since(0);
        assert_eq!(all.len(), 5, "since 0 replays everything");
        assert!(!trunc);
        let (tail, _) = t.history_since(3);
        assert_eq!(tail.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![4, 5], "exactly the gap");
        let (none, _) = t.history_since(5);
        assert!(none.is_empty(), "a caller already up to date gets nothing back");
        let (none, _) = t.history_since(999);
        assert!(none.is_empty(), "a cursor beyond the end is not an error");
    }

    #[test]
    fn the_transcript_is_bounded_and_drops_the_oldest() {
        let mut t = Transcript::new();
        for i in 0..(MAX_TRANSCRIPT + 50) {
            t.post(ChatFrom::Guest, &format!("m{i}"), i as i64);
        }
        assert_eq!(t.entries().len(), MAX_TRANSCRIPT, "memory is bounded");
        // The NEWEST are kept: an operator scrolling back wants recent context, and an unbounded
        // transcript is a memory leak on a machine that may be connected for hours.
        assert_eq!(t.last_seq() as usize, MAX_TRANSCRIPT + 50);
        assert_eq!(
            t.entries().front().expect("non-empty").seq as usize,
            51,
            "the oldest were evicted, not the newest"
        );
    }

    #[test]
    fn a_history_reply_is_capped_and_says_when_it_truncated() {
        let mut t = Transcript::new();
        for i in 0..MAX_TRANSCRIPT {
            t.post(ChatFrom::Guest, &format!("m{i}"), i as i64);
        }
        let (entries, truncated) = t.history_since(0);
        assert_eq!(entries.len(), MAX_HISTORY_REPLY);
        assert!(truncated, "the viewer must learn its transcript has a hole");
        // The NEWEST survive the cap — the operator needs recent context, not the start of a
        // conversation from an hour ago.
        assert_eq!(entries.last().expect("non-empty").seq as usize, MAX_TRANSCRIPT);
        // And a reply that fits is never flagged.
        let (small, truncated) = t.history_since(MAX_TRANSCRIPT as u64 - 3);
        assert_eq!(small.len(), 3);
        assert!(!truncated);
    }

    #[test]
    fn an_over_long_body_is_truncated_not_rejected() {
        let mut t = Transcript::new();
        let huge = "x".repeat(MAX_BODY_CHARS * 2);
        let e = t.post(ChatFrom::Technician, &huge, 1);
        assert_eq!(e.body.chars().count(), MAX_BODY_CHARS, "truncated to the cap");
        assert_eq!(t.last_seq(), 1, "and it WAS recorded — silence would be worse");
    }

    #[test]
    fn truncation_counts_characters_so_it_never_splits_a_codepoint() {
        // A byte-based cap would cut a multi-byte character in half and put invalid UTF-8 on the
        // wire, which `serde_json::to_vec` cannot represent — the message would vanish.
        let mut t = Transcript::new();
        let emoji = "😀".repeat(MAX_BODY_CHARS + 100);
        let e = t.post(ChatFrom::Guest, &emoji, 1);
        assert_eq!(e.body.chars().count(), MAX_BODY_CHARS);
        assert!(e.body.ends_with('😀'), "the cut landed on a character boundary");
        // ...and it survives a real encode/decode.
        let back = decode(&encode(&ChatMessage::Posted { entry: e.clone() })).expect("decode");
        assert_eq!(back, ChatMessage::Posted { entry: e });
    }

    #[test]
    fn restore_continues_the_sequence_rather_than_restarting_it() {
        // The reconnect case this exists for: a viewer holding sequence 42 asks for what it missed.
        // A transcript that restarted at 1 would answer "nothing" and the operator would silently
        // lose the conversation.
        let saved = vec![
            ChatEntry { seq: 41, from: ChatFrom::Technician, body: "a".into(), at_unix_ms: 1 },
            ChatEntry { seq: 42, from: ChatFrom::Guest, body: "b".into(), at_unix_ms: 2 },
        ];
        let mut t = Transcript::restore(saved);
        assert_eq!(t.last_seq(), 42);
        let next = t.post(ChatFrom::Technician, "c", 3);
        assert_eq!(next.seq, 43, "the sequence continues past the restored high-water mark");
        let (gap, _) = t.history_since(42);
        assert_eq!(gap.len(), 1);
        assert_eq!(gap[0].body, "c");
    }

    #[test]
    fn restore_bounds_an_oversized_saved_transcript() {
        // A file that grew beyond the cap (an older build, a hand-edit) must not un-bound memory.
        let saved: Vec<ChatEntry> = (1..=(MAX_TRANSCRIPT as u64 + 100))
            .map(|seq| ChatEntry {
                seq,
                from: ChatFrom::Guest,
                body: "x".into(),
                at_unix_ms: seq as i64,
            })
            .collect();
        let t = Transcript::restore(saved);
        assert_eq!(t.entries().len(), MAX_TRANSCRIPT);
        assert_eq!(t.last_seq() as usize, MAX_TRANSCRIPT + 100);
        assert_eq!(t.entries().back().expect("non-empty").seq as usize, MAX_TRANSCRIPT + 100);
        assert_eq!(t.entries().front().expect("non-empty").seq, 101, "the newest are kept");
        let mut t = t;
        assert_eq!(t.post(ChatFrom::Guest, "next", 0).seq as usize, MAX_TRANSCRIPT + 101);
        assert_eq!(t.last_seq() as usize, MAX_TRANSCRIPT + 101);
        assert_eq!(t.entries().len(), MAX_TRANSCRIPT);
    }

    #[test]
    fn last_seq_stays_exact_through_sequence_exhaustion() {
        let mut t = Transcript::restore(vec![saved_entry(u64::MAX - 1, "a".into())]);
        assert_eq!(t.last_seq(), u64::MAX - 1);
        assert_eq!(t.post(ChatFrom::Guest, "b", 1).seq, u64::MAX);
        assert_eq!(t.last_seq(), u64::MAX);
        assert_eq!(t.post(ChatFrom::Guest, "c", 2).seq, u64::MAX, "clamped, never wrapped");
        assert_eq!(t.last_seq(), u64::MAX);

        let mut t = Transcript::restore(vec![saved_entry(u64::MAX, "z".into())]);
        assert_eq!(t.last_seq(), u64::MAX);
        t.post(ChatFrom::Guest, "after", 3);
        assert_eq!(t.last_seq(), u64::MAX);
    }

    #[test]
    fn last_seq_counts_restored_entries_that_were_dropped() {
        // The highest seq sits at the FRONT and is evicted by the cap; it is still the high-water.
        let mut saved: Vec<ChatEntry> =
            (1..=MAX_TRANSCRIPT as u64 + 5).map(|s| saved_entry(s, "x".into())).collect();
        saved[0].seq = 9_999;
        let mut t = Transcript::restore(saved);
        assert_eq!(t.last_seq(), 9_999);
        assert_eq!(t.post(ChatFrom::Guest, "n", 0).seq, 10_000);
    }

    #[test]
    fn default_transcript_starts_at_one() {
        let mut t = Transcript::default();
        assert_eq!(t.post(ChatFrom::Guest, "first", 0).seq, 1);
    }

    fn saved_entry(seq: u64, body: String) -> ChatEntry {
        ChatEntry { seq, from: ChatFrom::Guest, body, at_unix_ms: 1 }
    }

    #[test]
    fn restore_with_max_seq_does_not_panic_or_wrap_to_zero() {
        let mut t = Transcript::restore(vec![saved_entry(u64::MAX, "last".into())]);
        assert_eq!(t.entries().len(), 1);
        let a = t.post(ChatFrom::Technician, "after", 2);
        assert_ne!(a.seq, 0, "must never collide with the since_seq:0 sentinel");
        let b = t.post(ChatFrom::Technician, "again", 3);
        assert_ne!(b.seq, 0);
        assert_eq!(b.seq, u64::MAX, "clamped at the top, not wrapped");
        assert_ne!(t.last_seq(), 0);
    }

    #[test]
    fn restore_truncates_oversized_bodies_on_char_boundaries() {
        let ascii = "x".repeat(MAX_BODY_CHARS * 2);
        let emoji = "😀".repeat(MAX_BODY_CHARS + 100);
        let t = Transcript::restore(vec![saved_entry(1, ascii), saved_entry(2, emoji)]);
        let (got, _) = t.history_since(0);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].body.chars().count(), MAX_BODY_CHARS);
        assert_eq!(got[1].body.chars().count(), MAX_BODY_CHARS);
        assert!(got[1].body.ends_with('😀'));
    }

    #[test]
    fn restore_leaves_legal_bodies_untouched() {
        let exact = "y".repeat(MAX_BODY_CHARS);
        let t = Transcript::restore(vec![
            saved_entry(1, exact.clone()),
            saved_entry(2, "short".into()),
        ]);
        assert_eq!(t.entries()[0].body, exact);
        assert_eq!(t.entries()[1].body, "short");
        assert_eq!(t.last_seq(), 2);
    }

    fn restored_seqs(t: &Transcript) -> Vec<u64> {
        t.entries().iter().map(|e| e.seq).collect()
    }

    #[test]
    fn restore_keeps_an_ascending_list_identically() {
        let t = Transcript::restore((1..=5).map(|s| saved_entry(s, format!("m{s}"))).collect());
        assert_eq!(restored_seqs(&t), vec![1, 2, 3, 4, 5]);
        assert_eq!(t.entries()[2].body, "m3");
        assert_eq!(t.last_seq(), 5);
    }

    #[test]
    fn restore_drops_a_duplicate_seq_keeping_the_first() {
        let t = Transcript::restore(vec![
            saved_entry(1, "first".into()),
            saved_entry(2, "orig".into()),
            saved_entry(2, "repeat".into()),
            saved_entry(3, "c".into()),
        ]);
        assert_eq!(restored_seqs(&t), vec![1, 2, 3]);
        assert_eq!(t.entries()[1].body, "orig");
    }

    #[test]
    fn restore_drops_a_regressing_seq() {
        let t = Transcript::restore(vec![
            saved_entry(5, "a".into()),
            saved_entry(3, "b".into()),
            saved_entry(7, "c".into()),
        ]);
        assert_eq!(restored_seqs(&t), vec![5, 7]);
    }

    #[test]
    fn restore_history_is_strictly_ascending_after_disorder() {
        let t = Transcript::restore(vec![
            saved_entry(5, "a".into()),
            saved_entry(3, "b".into()),
            saved_entry(7, "c".into()),
        ]);
        let (all, truncated) = t.history_since(0);
        assert!(!truncated);
        assert!(all.windows(2).all(|w| w[0].seq < w[1].seq), "strictly ascending");
        let (after5, _) = t.history_since(5);
        assert_eq!(after5.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![7]);
    }

    #[test]
    fn restore_never_reuses_a_seq_dropped_for_ordering() {
        let mut t = Transcript::restore(vec![saved_entry(9, "a".into()), saved_entry(2, "b".into())]);
        assert_eq!(restored_seqs(&t), vec![9]);
        assert_eq!(t.last_seq(), 9);
        assert_eq!(t.post(ChatFrom::Guest, "n", 0).seq, 10);
    }

    #[test]
    fn restore_invalid_entries_do_not_consume_cap_slots() {
        // MAX_TRANSCRIPT + 10 valid entries, each followed by a regressing duplicate.
        let mut saved = Vec::new();
        for s in 1..=(MAX_TRANSCRIPT as u64 + 10) {
            saved.push(saved_entry(s, "x".into()));
            saved.push(saved_entry(s, "dup".into()));
        }
        let t = Transcript::restore(saved);
        assert_eq!(t.entries().len(), MAX_TRANSCRIPT);
        // Front-trimmed: the oldest 10 valid entries went, the newest valid one stays.
        assert_eq!(t.entries().front().expect("non-empty").seq, 11);
        assert_eq!(t.entries().back().expect("non-empty").seq as usize, MAX_TRANSCRIPT + 10);
        assert!(t.entries().iter().all(|e| e.body == "x"));
        assert_eq!(t.last_seq() as usize, MAX_TRANSCRIPT + 10);
    }

    #[test]
    fn restore_handles_a_single_entry() {
        let t = Transcript::restore(vec![saved_entry(4, "only".into())]);
        assert_eq!(restored_seqs(&t), vec![4]);
        assert_eq!(t.last_seq(), 4);
    }

    #[test]
    fn restore_from_nothing_behaves_like_new() {
        let t = Transcript::restore(Vec::new());
        assert_eq!(t.last_seq(), 0);
        assert!(t.entries().is_empty());
        let mut t = t;
        assert_eq!(t.post(ChatFrom::Guest, "first", 0).seq, 1);
    }
}
