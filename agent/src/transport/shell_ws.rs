//! Wire codec for the interactive shell channel (one WebSocket per shell session).
//!
//! ConPTY output is a raw byte stream and shell throughput can be high, so **data frames carry
//! raw bytes with a 1-byte tag** — no base64, no JSON envelope on the hot path. Only the
//! occasional control frame (resize, close, exit) is JSON. This keeps the terminal responsive
//! and lets the browser hand data frames straight to xterm.js as binary.
//!
//! Frame = `[tag: u8][payload...]`:
//!   * `0x00 Data`   — raw bytes. Client→agent = keystrokes; agent→client = program output.
//!   * `0x01 Resize` — JSON `{"cols":N,"rows":N}` (client→agent).
//!   * `0x02 Close`  — no payload (client→agent): tear the shell down.
//!   * `0x03 Exit`   — JSON `{"code":N|null}` (agent→client): child exited.
//!
//! Direction isn't encoded in the tag because a given socket end only ever sends its half;
//! [`ClientMessage`]/[`ServerMessage`] model the two halves and share the tag space.

use serde::{Deserialize, Serialize};

const TAG_DATA: u8 = 0x00;
const TAG_RESIZE: u8 = 0x01;
const TAG_CLOSE: u8 = 0x02;
const TAG_EXIT: u8 = 0x03;

/// Browser → agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessage {
    /// VT-encoded keystrokes from xterm.js, forwarded verbatim to the ConPTY input pipe.
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

/// Agent → browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    /// ConPTY output bytes; the browser writes these to xterm.js as a binary chunk.
    Output(Vec<u8>),
    Exit { code: Option<i32> },
}

#[derive(Debug, Serialize, Deserialize)]
struct ResizePayload { cols: u16, rows: u16 }
#[derive(Debug, Serialize, Deserialize)]
struct ExitPayload { code: Option<i32> }

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("empty frame (missing tag byte)")]
    Empty,
    #[error("unknown frame tag {0:#04x}")]
    UnknownTag(u8),
    #[error("malformed control payload: {0}")]
    BadPayload(String),
}

impl ClientMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ClientMessage::Input(bytes) => tagged(TAG_DATA, bytes),
            ClientMessage::Resize { cols, rows } => {
                let json = serde_json::to_vec(&ResizePayload { cols: *cols, rows: *rows }).unwrap();
                tagged(TAG_RESIZE, &json)
            }
            ClientMessage::Close => vec![TAG_CLOSE],
        }
    }

    pub fn decode(frame: &[u8]) -> Result<Self, CodecError> {
        let (tag, payload) = split(frame)?;
        match tag {
            TAG_DATA => Ok(ClientMessage::Input(payload.to_vec())),
            TAG_RESIZE => {
                let p: ResizePayload =
                    serde_json::from_slice(payload).map_err(|e| CodecError::BadPayload(e.to_string()))?;
                Ok(ClientMessage::Resize { cols: p.cols, rows: p.rows })
            }
            TAG_CLOSE => Ok(ClientMessage::Close),
            other => Err(CodecError::UnknownTag(other)),
        }
    }
}

impl ServerMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ServerMessage::Output(bytes) => tagged(TAG_DATA, bytes),
            ServerMessage::Exit { code } => {
                let json = serde_json::to_vec(&ExitPayload { code: *code }).unwrap();
                tagged(TAG_EXIT, &json)
            }
        }
    }

    pub fn decode(frame: &[u8]) -> Result<Self, CodecError> {
        let (tag, payload) = split(frame)?;
        match tag {
            TAG_DATA => Ok(ServerMessage::Output(payload.to_vec())),
            TAG_EXIT => {
                let p: ExitPayload =
                    serde_json::from_slice(payload).map_err(|e| CodecError::BadPayload(e.to_string()))?;
                Ok(ServerMessage::Exit { code: p.code })
            }
            other => Err(CodecError::UnknownTag(other)),
        }
    }
}

fn tagged(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + payload.len());
    v.push(tag);
    v.extend_from_slice(payload);
    v
}

fn split(frame: &[u8]) -> Result<(u8, &[u8]), CodecError> {
    frame.split_first().map(|(t, rest)| (*t, rest)).ok_or(CodecError::Empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_messages_round_trip() {
        for m in [
            ClientMessage::Input(b"whoami\r".to_vec()),
            ClientMessage::Resize { cols: 120, rows: 30 },
            ClientMessage::Close,
        ] {
            assert_eq!(ClientMessage::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn server_messages_round_trip() {
        for m in [
            ServerMessage::Output(vec![0x1b, b'[', b'2', b'J']), // an ANSI clear
            ServerMessage::Exit { code: Some(0) },
            ServerMessage::Exit { code: None },
        ] {
            assert_eq!(ServerMessage::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn data_frames_have_one_byte_of_overhead() {
        // The hot path must not bloat: a 4 KB output chunk encodes to exactly 4 KB + 1 tag.
        let payload = vec![b'x'; 4096];
        assert_eq!(ServerMessage::Output(payload).encode().len(), 4097);
    }

    #[test]
    fn empty_and_unknown_frames_are_errors_not_panics() {
        assert_eq!(ClientMessage::decode(&[]).unwrap_err(), CodecError::Empty);
        assert_eq!(ClientMessage::decode(&[0xFF]).unwrap_err(), CodecError::UnknownTag(0xFF));
    }

    #[test]
    fn binary_output_survives_invalid_utf8() {
        // ConPTY output can split a multibyte char across frames; the codec must be byte-exact
        // and never assume UTF-8. 0xC3 alone is an incomplete UTF-8 sequence.
        let m = ServerMessage::Output(vec![0xC3]);
        assert_eq!(ServerMessage::decode(&m.encode()).unwrap(), m);
    }
}
