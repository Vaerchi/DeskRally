//! Canonical wire codec for controller→agent [`InputEvent`]s.
//!
//! This is the **one** encoding both sides of a session agree on: the Rust agent decodes input
//! frames with [`decode`], and the browser controller (`web/viewer/src/lib/input.ts`) produces the
//! same bytes. The format is JSON (via `serde_json`) using the adjacently-tagged shape documented
//! on [`InputEvent`] — a `"t"` variant tag plus a `"c"` content object. JSON keeps the codec
//! trivially cross-language (browser + Rust) at input's tiny volume; the high-volume video path
//! uses the VP8 media track, not this.
//!
//! The bytes produced here are the input **payload** only. On the WebRTC transport they ride as
//! the payload of a `Frame` tagged [`rmt_protocol::ChannelId::Input`]; the transport frames them.
//!
//! # Exact wire bytes (per variant)
//!
//! * `MouseMove { x: 32768, y: 100 }`               → `{"t":"MouseMove","c":{"x":32768,"y":100}}`
//! * `MouseButton { button: Left, down: true }`     → `{"t":"MouseButton","c":{"button":"Left","down":true}}`
//! * `Scroll { dx: 0, dy: 3 }`                       → `{"t":"Scroll","c":{"dx":0,"dy":3}}`
//! * `Key { code: 65, down: true }`                  → `{"t":"Key","c":{"code":65,"down":true}}`
//! * `Text("hi")`                                    → `{"t":"Text","c":"hi"}`
//!
//! # Scroll bound
//!
//! [`decode`] refuses a `Scroll` whose `dx` or `dy` magnitude exceeds [`MAX_SCROLL_DETENTS`]
//! (10,000 wheel detents), so the host's per-detent multiplication cannot overflow.
//!
//! # Key code bound
//!
//! [`decode`] refuses a `Key` whose `code` exceeds [`MAX_KEY_CODE`] (0xFFFF), so a host that
//! narrows the `u32` to 16 bits cannot silently turn an out-of-range code into a different key.
//!
//! # Text bound
//!
//! [`decode`] refuses a `Text` whose UTF-8 length exceeds [`MAX_INPUT_TEXT_BYTES`] (4096 bytes,
//! not chars), the same limit the host applies, so an over-limit frame is dropped at decode.

use crate::platform::InputEvent;

/// Error decoding an input event off the wire (malformed JSON or an unknown variant/shape).
pub type InputCodecError = serde_json::Error;

/// Encode one [`InputEvent`] to its canonical JSON wire bytes.
///
/// Infallible in practice (every `InputEvent` serializes); the internal `serde_json` error is
/// unwrapped into an empty vec only on the impossible serialization failure, so callers never
/// have to handle an error on the send path.
pub fn encode(event: &InputEvent) -> Vec<u8> {
    // Serializing an owned enum of primitives + a String cannot fail; fall back to `[]` rather
    // than panicking to keep the send path total.
    serde_json::to_vec(event).unwrap_or_default()
}

/// Largest `InputEvent::Text` payload, in UTF-8 bytes, the host will act on (mirrors the limit the
/// Windows host applies to `Text` events). [`decode`] enforces it on the decoded text.
pub const MAX_INPUT_TEXT_BYTES: usize = 4096;

/// Largest input frame [`decode`] will parse: worst-case JSON escaping of
/// [`MAX_INPUT_TEXT_BYTES`] of text (`\u00XX`, six bytes per input byte) plus the
/// `{"t":"Text","c":""}` envelope and generous slack for the numeric variants (under 100 bytes).
pub const MAX_INPUT_WIRE_LEN: usize = 6 * MAX_INPUT_TEXT_BYTES + 256;

/// Largest `InputEvent::Scroll` magnitude, in wheel detents, accepted per axis. The browser viewer
/// sends a handful of detents per event; the host multiplies by 120 per detent, so an unbounded
/// peer-supplied `i32` would overflow that arithmetic.
pub const MAX_SCROLL_DETENTS: i32 = 10_000;

/// True when both scroll axes are within [`MAX_SCROLL_DETENTS`] (`unsigned_abs` so `i32::MIN`
/// cannot overflow).
fn is_valid_scroll(dx: i32, dy: i32) -> bool {
    let max = MAX_SCROLL_DETENTS as u32;
    dx.unsigned_abs() <= max && dy.unsigned_abs() <= max
}

/// Largest `InputEvent::Key` code accepted: the host narrows the `u32` to 16 bits, so anything
/// larger would wrap into a different key. Not restricted to 0xFF; the field is a
/// platform-independent keycode.
pub const MAX_KEY_CODE: u32 = u16::MAX as u32;

/// True when `code` fits in 16 bits (is at most [`MAX_KEY_CODE`]).
fn is_valid_key_code(code: u32) -> bool {
    code <= MAX_KEY_CODE
}

/// Decode one [`InputEvent`] from canonical JSON wire bytes.
///
/// Frames longer than [`MAX_INPUT_WIRE_LEN`] are refused before any parsing, so a peer cannot make
/// the agent allocate a huge `Text` string that the host would only reject afterwards. A `Scroll`
/// whose `dx` or `dy` magnitude exceeds [`MAX_SCROLL_DETENTS`] is refused too, as is a `Key`
/// whose `code` exceeds [`MAX_KEY_CODE`], and so is a `Text` longer than [`MAX_INPUT_TEXT_BYTES`]
/// UTF-8 bytes (bytes, not chars, matching the host check).
pub fn decode(bytes: &[u8]) -> Result<InputEvent, InputCodecError> {
    if bytes.len() > MAX_INPUT_WIRE_LEN {
        return Err(serde::de::Error::custom(format!(
            "input frame is {} bytes, over the {} byte limit",
            bytes.len(),
            MAX_INPUT_WIRE_LEN
        )));
    }
    let event: InputEvent = serde_json::from_slice(bytes)?;
    if let InputEvent::Scroll { dx, dy } = &event {
        if !is_valid_scroll(*dx, *dy) {
            return Err(<InputCodecError as serde::de::Error>::custom(format!(
                "scroll delta ({dx}, {dy}) exceeds {MAX_SCROLL_DETENTS} detents"
            )));
        }
    }
    if let InputEvent::Key { code, .. } = &event {
        if !is_valid_key_code(*code) {
            return Err(<InputCodecError as serde::de::Error>::custom(format!(
                "key code {code} exceeds {MAX_KEY_CODE}"
            )));
        }
    }
    if let InputEvent::Text(text) = &event {
        if text.len() > MAX_INPUT_TEXT_BYTES {
            return Err(<InputCodecError as serde::de::Error>::custom(format!(
                "text is {} bytes, over the {MAX_INPUT_TEXT_BYTES} byte limit",
                text.len()
            )));
        }
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{InputButton, InputEvent};

    /// Round-trip every variant and assert the exact canonical JSON, so the shape is pinned and
    /// the TypeScript controller can be tested against the same strings.
    fn round_trip(ev: InputEvent, expect_json: &str) {
        let bytes = encode(&ev);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            expect_json,
            "canonical JSON for {ev:?}"
        );
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, ev, "round-trip for {ev:?}");
    }

    #[test]
    fn mouse_move_round_trips() {
        round_trip(
            InputEvent::MouseMove { x: 32768, y: 100 },
            r#"{"t":"MouseMove","c":{"x":32768,"y":100}}"#,
        );
    }

    #[test]
    fn scroll_round_trips() {
        round_trip(
            InputEvent::Scroll { dx: -2, dy: 3 },
            r#"{"t":"Scroll","c":{"dx":-2,"dy":3}}"#,
        );
    }

    #[test]
    fn in_range_scrolls_decode() {
        for (dx, dy) in [(0, 0), (-2, 3), (10_000, -10_000), (-10_000, 10_000)] {
            let ev = InputEvent::Scroll { dx, dy };
            assert_eq!(decode(&encode(&ev)).expect("decode"), ev);
        }
    }

    #[test]
    fn scrolls_over_the_limit_are_refused() {
        for (dx, dy) in [(0, 10_001), (0, -10_001), (10_001, 0), (-10_001, 0)] {
            let bytes = encode(&InputEvent::Scroll { dx, dy });
            // Positive control: plain serde accepts it, so only the bound refuses.
            assert!(serde_json::from_slice::<InputEvent>(&bytes).is_ok());
            let err = decode(&bytes).expect_err("oversized scroll").to_string();
            assert!(err.contains("10000"), "{err}");
            assert!(err.contains("detents"), "{err}");
        }
    }

    #[test]
    fn extreme_scroll_values_are_refused_without_panicking() {
        for (dx, dy) in [
            (i32::MAX, 0),
            (i32::MIN, 0),
            (0, i32::MAX),
            (0, i32::MIN),
        ] {
            let bytes = encode(&InputEvent::Scroll { dx, dy });
            assert!(decode(&bytes).is_err(), "({dx}, {dy})");
        }
    }

    #[test]
    fn hand_written_scroll_that_overflows_the_host_multiply_is_refused() {
        let frame = br#"{"t":"Scroll","c":{"dx":0,"dy":17895698}}"#;
        assert!(serde_json::from_slice::<InputEvent>(frame).is_ok());
        assert!(decode(frame).is_err());
    }

    #[test]
    fn key_down_and_up_round_trip() {
        round_trip(
            InputEvent::Key { code: 65, down: true },
            r#"{"t":"Key","c":{"code":65,"down":true}}"#,
        );
        round_trip(
            InputEvent::Key { code: 65, down: false },
            r#"{"t":"Key","c":{"code":65,"down":false}}"#,
        );
    }

    #[test]
    fn in_range_key_codes_decode() {
        for code in [0, 65, 0xE2, 0xFF, 65535] {
            for down in [true, false] {
                let ev = InputEvent::Key { code, down };
                assert_eq!(decode(&encode(&ev)).expect("decode"), ev, "code {code}");
            }
        }
    }

    #[test]
    fn key_codes_over_16_bits_are_refused() {
        for code in [65536, 65601, u32::MAX] {
            let bytes = encode(&InputEvent::Key { code, down: true });
            // Positive control: plain serde accepts it, so only the bound refuses.
            assert!(serde_json::from_slice::<InputEvent>(&bytes).is_ok());
            let err = decode(&bytes).expect_err("unrepresentable key code").to_string();
            assert!(err.contains(&code.to_string()), "{err}");
            assert!(err.contains("65535"), "{err}");
        }
    }

    #[test]
    fn hand_written_key_frame_that_truncates_to_a_letter_is_refused() {
        let frame = br#"{"t":"Key","c":{"code":65601,"down":true}}"#;
        assert!(serde_json::from_slice::<InputEvent>(frame).is_ok());
        assert!(decode(frame).is_err());
    }

    #[test]
    fn negative_key_code_still_fails_via_serde() {
        let frame = br#"{"t":"Key","c":{"code":-1,"down":true}}"#;
        assert!(serde_json::from_slice::<InputEvent>(frame).is_err());
        let err = decode(frame).expect_err("negative code").to_string();
        assert!(!err.contains("exceeds"), "{err}");
    }

    #[test]
    fn text_round_trips() {
        round_trip(
            InputEvent::Text("hi".into()),
            r#"{"t":"Text","c":"hi"}"#,
        );
    }

    #[test]
    fn sas_round_trips_as_a_bare_unit_variant() {
        // The Secure Attention Sequence carries no payload: adjacent tagging emits ONLY the tag,
        // with no `c` content key. The browser controller must produce exactly these bytes for the
        // agent's SendSAS path to fire, so the shape is pinned here alongside the others.
        round_trip(InputEvent::Sas, r#"{"t":"Sas"}"#);
    }

    #[test]
    fn every_mouse_button_round_trips() {
        let cases = [
            (InputButton::Left, r#"{"t":"MouseButton","c":{"button":"Left","down":true}}"#),
            (InputButton::Right, r#"{"t":"MouseButton","c":{"button":"Right","down":true}}"#),
            (InputButton::Middle, r#"{"t":"MouseButton","c":{"button":"Middle","down":true}}"#),
            (InputButton::Back, r#"{"t":"MouseButton","c":{"button":"Back","down":true}}"#),
            (InputButton::Forward, r#"{"t":"MouseButton","c":{"button":"Forward","down":true}}"#),
        ];
        for (button, json) in cases {
            round_trip(InputEvent::MouseButton { button, down: true }, json);
        }
        // Also exercise the release (`down: false`) edge for one button.
        round_trip(
            InputEvent::MouseButton { button: InputButton::Left, down: false },
            r#"{"t":"MouseButton","c":{"button":"Left","down":false}}"#,
        );
    }

    #[test]
    fn rejects_garbage_and_unknown_variants() {
        assert!(decode(b"not json").is_err());
        assert!(decode(br#"{"t":"Nope","c":{}}"#).is_err());
    }

    /// A valid Text frame padded with trailing whitespace to exactly `len` bytes.
    fn padded_text_frame(text: &str, len: usize) -> Vec<u8> {
        let mut bytes = encode(&InputEvent::Text(text.into()));
        assert!(bytes.len() <= len);
        bytes.resize(len, b' ');
        bytes
    }

    #[test]
    fn text_of_exactly_the_text_limit_round_trips() {
        let text = "a".repeat(MAX_INPUT_TEXT_BYTES);
        let ev = InputEvent::Text(text);
        assert_eq!(decode(&encode(&ev)).expect("decode"), ev);
    }

    #[test]
    fn worst_case_escaped_text_still_decodes_within_the_wire_limit() {
        // Control characters serialize as `\u00XX`: six wire bytes per text byte.
        let text = "\u{1}".repeat(MAX_INPUT_TEXT_BYTES);
        let ev = InputEvent::Text(text);
        let bytes = encode(&ev);
        assert!(bytes.len() >= 6 * MAX_INPUT_TEXT_BYTES);
        assert!(bytes.len() <= MAX_INPUT_WIRE_LEN, "len {}", bytes.len());
        assert_eq!(decode(&bytes).expect("decode"), ev);
    }

    #[test]
    fn frame_one_byte_over_the_wire_limit_is_refused_before_parsing() {
        let bytes = padded_text_frame("hi", MAX_INPUT_WIRE_LEN + 1);
        // Positive control: the same bytes are valid JSON, so only the length guard can refuse.
        assert!(serde_json::from_slice::<InputEvent>(&bytes).is_ok());
        let err = decode(&bytes).expect_err("oversized frame must be refused").to_string();
        assert!(err.contains(&(MAX_INPUT_WIRE_LEN + 1).to_string()), "{err}");
        assert!(err.contains(&MAX_INPUT_WIRE_LEN.to_string()), "{err}");
    }

    #[test]
    fn frame_of_exactly_the_wire_limit_is_not_refused() {
        let bytes = padded_text_frame("hi", MAX_INPUT_WIRE_LEN);
        assert_eq!(bytes.len(), MAX_INPUT_WIRE_LEN);
        assert_eq!(decode(&bytes).expect("decode"), InputEvent::Text("hi".into()));
    }

    #[test]
    fn multi_megabyte_text_frame_is_refused() {
        let bytes = encode(&InputEvent::Text("a".repeat(8 * 1024 * 1024)));
        assert!(bytes.len() > MAX_INPUT_WIRE_LEN);
        let err = decode(&bytes).expect_err("8 MiB frame must be refused").to_string();
        assert!(err.contains(&bytes.len().to_string()), "{err}");
    }

    #[test]
    fn text_one_byte_over_the_text_limit_is_refused() {
        let ev = InputEvent::Text("a".repeat(MAX_INPUT_TEXT_BYTES + 1));
        let bytes = encode(&ev);
        assert!(bytes.len() <= MAX_INPUT_WIRE_LEN);
        // Positive control: plain serde accepts it, so only the text bound refuses.
        assert!(serde_json::from_slice::<InputEvent>(&bytes).is_ok());
        let err = decode(&bytes).expect_err("oversized text").to_string();
        assert!(err.contains("4097"), "{err}");
        assert!(err.contains("4096"), "{err}");
    }

    #[test]
    fn text_limit_is_in_bytes_not_chars() {
        // "€" is three UTF-8 bytes.
        let over = InputEvent::Text("€".repeat(1366)); // 4098 bytes, 1366 chars
        let bytes = encode(&over);
        assert!(serde_json::from_slice::<InputEvent>(&bytes).is_ok());
        let err = decode(&bytes).expect_err("4098-byte text").to_string();
        assert!(err.contains("4098"), "{err}");

        let under = InputEvent::Text("€".repeat(1365)); // 4095 bytes
        assert_eq!(decode(&encode(&under)).expect("decode"), under);

        let exact = InputEvent::Text(format!("{}a", "€".repeat(1365))); // 4096 bytes
        assert_eq!(decode(&encode(&exact)).expect("decode"), exact);
    }

    #[test]
    fn oversized_control_character_text_is_refused() {
        let ev = InputEvent::Text("\u{1}".repeat(MAX_INPUT_TEXT_BYTES + 1));
        let bytes = encode(&ev);
        assert!(bytes.len() > 6 * MAX_INPUT_TEXT_BYTES);
        assert!(bytes.len() <= MAX_INPUT_WIRE_LEN, "len {}", bytes.len());
        assert!(serde_json::from_slice::<InputEvent>(&bytes).is_ok());
        let err = decode(&bytes).expect_err("oversized control text").to_string();
        assert!(err.contains("4097"), "{err}");
        assert!(!err.contains("input frame"), "{err}");
    }

    #[test]
    fn small_malformed_json_still_errors_via_serde() {
        let err = decode(br#"{"t":"Text","c":"#).expect_err("truncated JSON").to_string();
        assert!(!err.contains("byte limit"), "{err}");
    }
}
