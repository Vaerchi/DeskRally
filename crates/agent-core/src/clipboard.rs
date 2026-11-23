//! Canonical wire codec + platform seam for bidirectional **text clipboard sync** (M9).
//!
//! Like [`crate::input_codec`] and [`crate::file_transfer`], this is the **one** encoding both ends
//! of a session agree on: the Rust agent decodes/encodes clipboard frames with [`decode`]/[`encode`],
//! and the browser controller (`web/viewer/src/lib/clipboard.ts`) produces byte-identical frames.
//! Messages ride as the payload of a [`Frame`](rmt_protocol::Frame) tagged
//! [`rmt_protocol::ChannelId::Clipboard`]; the transport frames them.
//!
//! # Wire shape
//!
//! JSON, **adjacently tagged** (`{"t":<variant>,"c":<content>}`) exactly like `input_codec`. Only a
//! text variant exists in v1, but the shape is kept an enum so image/HTML/file formats can be added
//! later without a breaking change:
//!
//! * `Text("hi")`  → `{"t":"Text","c":"hi"}`
//! * `Text("")`    → `{"t":"Text","c":""}`  (an empty clipboard is a valid, representable state)
//!
//! # Platform seam
//!
//! [`Clipboard`] is the OS-facing trait the agent's clipboard worker owns as a `Box<dyn Clipboard>`.
//! The Windows implementation lives in `rmt-agent-windows` (`clipboard::WinClipboard`); tests use an
//! in-memory fake. It is deliberately tiny: get/set the text, plus a monotonically-*changing* token
//! ([`Clipboard::sequence`]) used to detect that the local clipboard changed **and** to suppress the
//! echo of our own writes.

use serde::{Deserialize, Serialize};

/// A single decoded clipboard message. Adjacently-tagged as `{"t":…,"c":…}` on the wire.
///
/// Only [`Text`](ClipboardMessage::Text) exists today; keeping this an enum reserves room for future
/// formats (image, HTML, file list) without changing the frame's channel or the JSON envelope shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
pub enum ClipboardMessage {
    /// A run of Unicode text mirrored between the two clipboards.
    Text(String),
}

/// Error decoding a clipboard message off the wire (malformed JSON or an unknown variant/shape).
pub type ClipboardCodecError = serde_json::Error;

/// Encode one [`ClipboardMessage`] to its canonical JSON wire bytes.
///
/// Infallible in practice (a tagged enum wrapping a `String` always serializes); on the impossible
/// serialize error it yields an empty vec, keeping the send path total (matches `input_codec`).
pub fn encode(msg: &ClipboardMessage) -> Vec<u8> {
    serde_json::to_vec(msg).unwrap_or_default()
}

/// Largest clipboard text the agent accepts (1 MiB). Mirrors the session-closing limit the Windows
/// host applies after decoding.
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 1024 * 1024;

/// Largest clipboard wire frame [`decode`] will parse: worst-case JSON escaping (`\u00XX`, six bytes
/// per byte) of [`MAX_CLIPBOARD_TEXT_BYTES`] of text plus the `{"t":"Text","c":""}` envelope. Same
/// derivation as the viewer's `clipboard.ts`.
pub const MAX_CLIPBOARD_WIRE_LEN: usize = 6 * MAX_CLIPBOARD_TEXT_BYTES + 64;

/// Decode one [`ClipboardMessage`] from canonical JSON wire bytes.
///
/// Refuses a frame longer than [`MAX_CLIPBOARD_WIRE_LEN`] **before** parsing, so a peer cannot make
/// the agent allocate a multi-megabyte `String`.
pub fn decode(bytes: &[u8]) -> Result<ClipboardMessage, ClipboardCodecError> {
    if bytes.len() > MAX_CLIPBOARD_WIRE_LEN {
        return Err(serde::de::Error::custom(format!(
            "clipboard frame is {} bytes, over the {} byte limit",
            bytes.len(),
            MAX_CLIPBOARD_WIRE_LEN
        )));
    }
    serde_json::from_slice(bytes)
}

/// The OS clipboard seam the agent's clipboard worker drives.
///
/// `Send` because the worker owns its `Box<dyn Clipboard>` on a dedicated thread (the Windows
/// clipboard is **window-station**-scoped — WinSta0 — not desktop-scoped, so unlike input injection
/// it needs no `SetThreadDesktop` and can run on any thread in the process).
pub trait Clipboard: Send {
    /// Read the clipboard's current text, or `None` if it holds no text (or reading failed).
    fn get_text(&self) -> Option<String>;

    /// Replace the clipboard's text. `Err` carries a human-readable reason (the OS refused, was
    /// briefly locked by another app, etc.).
    fn set_text(&self, text: &str) -> Result<(), String>;

    /// A token that **changes** whenever the clipboard's contents change (Windows'
    /// `GetClipboardSequenceNumber`). The absolute value is meaningless; only *change* matters. It is
    /// how the worker (a) detects a local copy to forward and (b) suppresses the echo of its own
    /// writes. Returns `0` if the platform cannot report it.
    fn sequence(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a message and assert its exact canonical JSON, so the shape is pinned and the
    /// TypeScript controller can be tested against the same strings.
    fn round_trip(msg: ClipboardMessage, expect_json: &str) {
        let bytes = encode(&msg);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            expect_json,
            "canonical JSON for {msg:?}"
        );
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, msg, "round-trip for {msg:?}");
    }

    #[test]
    fn text_round_trips() {
        round_trip(ClipboardMessage::Text("hi".into()), r#"{"t":"Text","c":"hi"}"#);
    }

    #[test]
    fn empty_string_round_trips() {
        // An empty clipboard is a legitimate state and must survive the round-trip.
        round_trip(ClipboardMessage::Text(String::new()), r#"{"t":"Text","c":""}"#);
    }

    #[test]
    fn unicode_and_emoji_round_trip() {
        // Multi-byte scripts + an emoji (surrogate pair in UTF-16) survive JSON + UTF-8 exactly.
        let s = "café — 日本語 — 🦀🎉";
        round_trip(
            ClipboardMessage::Text(s.into()),
            r#"{"t":"Text","c":"café — 日本語 — 🦀🎉"}"#,
        );
    }

    #[test]
    fn rejects_garbage_and_unknown_variants() {
        assert!(decode(b"not json").is_err());
        assert!(decode(br#"{"t":"Image","c":"x"}"#).is_err());
    }

    #[test]
    fn text_of_exactly_the_limit_round_trips() {
        let msg = ClipboardMessage::Text("a".repeat(MAX_CLIPBOARD_TEXT_BYTES));
        assert_eq!(decode(&encode(&msg)).expect("decode"), msg);
    }

    #[test]
    fn text_slightly_above_the_text_limit_still_decodes() {
        // The host closes the session on this at its own check; the codec must not pre-empt it.
        let msg = ClipboardMessage::Text("a".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1));
        assert_eq!(decode(&encode(&msg)).expect("decode"), msg);
    }

    #[test]
    fn worst_case_escaped_text_still_decodes() {
        // 1 MiB of control characters escapes to \u00XX: six wire bytes each.
        let text = "\u{1}".repeat(MAX_CLIPBOARD_TEXT_BYTES);
        let msg = ClipboardMessage::Text(text);
        let bytes = encode(&msg);
        assert!(bytes.len() > 5 * MAX_CLIPBOARD_TEXT_BYTES, "must be heavily escaped");
        assert!(bytes.len() <= MAX_CLIPBOARD_WIRE_LEN);
        assert_eq!(decode(&bytes).expect("decode"), msg);
    }

    #[test]
    fn frame_one_byte_over_the_wire_limit_is_refused_with_length() {
        let bytes = vec![b' '; MAX_CLIPBOARD_WIRE_LEN + 1];
        let err = decode(&bytes).expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains(&(MAX_CLIPBOARD_WIRE_LEN + 1).to_string()), "{text}");
        assert!(text.contains(&MAX_CLIPBOARD_WIRE_LEN.to_string()), "{text}");
    }

    #[test]
    fn frame_exactly_at_the_wire_limit_reaches_the_parser() {
        // Valid JSON padded with trailing whitespace to exactly the limit decodes.
        let mut bytes = br#"{"t":"Text","c":"x"}"#.to_vec();
        bytes.resize(MAX_CLIPBOARD_WIRE_LEN, b' ');
        assert_eq!(
            decode(&bytes).expect("decode"),
            ClipboardMessage::Text("x".into())
        );
    }

    #[test]
    fn multi_megabyte_valid_text_frame_is_refused() {
        let msg = ClipboardMessage::Text("a".repeat(8 * 1024 * 1024));
        let bytes = encode(&msg);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn small_malformed_json_still_errors_with_a_parse_error() {
        let err = decode(br#"{"t":"Text","c":"#).expect_err("truncated");
        assert!(!err.to_string().contains("byte limit"), "{err}");
    }
}
