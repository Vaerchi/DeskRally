//! Canonical wire codec for the bidirectional file-transfer protocol (M8).
//!
//! Like [`crate::input_codec`], this is the **one** encoding both ends of a session agree on: the
//! Rust agent decodes/encodes file-transfer frames with [`decode`]/[`encode`], and the browser
//! controller (`web/viewer/src/lib/file_transfer.ts`) produces byte-identical frames. Messages ride
//! as the payload of a [`Frame`](rmt_protocol::Frame) tagged
//! [`rmt_protocol::ChannelId::FileTransfer`]; the transport frames them.
//!
//! # Framing (mixed JSON + binary, dispatched on the first byte)
//!
//! Two categories of message share the channel, distinguished by their **first payload byte**:
//!
//! * **Control** messages ([`Message::Offer`], [`Done`](Message::Done), [`Ack`](Message::Ack),
//!   [`Request`](Message::Request), [`Error`](Message::Error)) are **JSON**, adjacently tagged
//!   exactly like `input_codec` (`{"t":<variant>,"c":<content>}`). JSON always begins with `{` =
//!   `0x7B` = [`CONTROL_TAG`], so the receiver recognizes control by that leading byte. Transfer ids
//!   are UUID strings and the digest is lowercase hex — both human-readable and trivially
//!   cross-language.
//! * **`Chunk`** — the high-volume path — is a compact **binary** payload
//!   `[0x01][id: 16 bytes][seq: u32 BE][raw data]` ([`CHUNK_TAG`] = `0x01`). Chunks carry raw file
//!   bytes with **no base64**, so a 48 KiB chunk costs one byte of tag + 20 bytes of header, not a
//!   ~33% base64 tax. `id` is the transfer's UUID as its 16 raw bytes.
//!
//! `0x01` (chunk) and `0x7B` (`{`) can never collide, so [`decode`] dispatches unambiguously on
//! `bytes[0]`.
//!
//! # Exact wire bytes
//!
//! Control (JSON), for `id = 550e8400-e29b-41d4-a716-446655440000`:
//! * `Offer`   → `{"t":"Offer","c":{"id":"550e…","name":"a.bin","size":1048576,"sha256":"<hex>"}}`
//! * `Done`    → `{"t":"Done","c":{"id":"550e…"}}`
//! * `Ack`     → `{"t":"Ack","c":{"id":"550e…","ok":true,"message":""}}`
//! * `Request` → `{"t":"Request","c":{"id":"550e…","path":"a.bin"}}`
//! * `Error`   → `{"t":"Error","c":{"id":"550e…","message":"…"}}`
//! * `Audit`   → `{"t":"Audit","c":{"id":"550e…","event":{…agent AuditEvent…}}}` (agent → controller
//!   only; the tamper-evident record of the transfer — see ADR-008)
//!
//! Chunk (binary): `01 | <16 id bytes> | <4 seq bytes, big-endian> | <raw data …>`.
//!
//! # Offer digest rule
//!
//! [`decode`] refuses an `Offer` whose `sha256` is not exactly 64 lowercase ASCII hex characters
//! (`[0-9a-f]`) with [`FileTransferError::BadDigest`]. Every real digest has that form, so this
//! cannot reject a transfer that could verify; it keeps arbitrary peer text out of audit records
//! and acknowledgements.
//!
//! # Request path rule
//!
//! [`decode`] refuses a `Request` whose `path` contains a character Windows forbids in a path
//! ([`is_windows_forbidden_control`]: NUL and the C0 controls U+0001..U+001F, which include CR and
//! LF) or is longer than [`MAX_REQUEST_PATH_UTF16`] (32767) UTF-16 code units, with
//! [`FileTransferError::BadPath`]. No Windows path can be either, so no real download request is
//! refused. DEL and the C1 range ARE legal in Windows names and are accepted; log lines print paths
//! with `Debug` formatting, which escapes them, and audit records are JSON. Empty, `..` and absolute paths still decode: `resolve_download_path` owns those.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Leading byte of a **binary** [`Message::Chunk`] payload.
pub const CHUNK_TAG: u8 = 0x01;
/// Leading byte of a **JSON control** payload — `{`. Control JSON always starts with this.
pub const CONTROL_TAG: u8 = b'{'; // 0x7B

/// Maximum raw bytes carried in one [`Chunk`]'s `data`. Kept at 48 KiB so a framed chunk
/// (tag + id + seq + data ≈ 48 KiB + 21 B) stays comfortably under the SCTP data-channel message
/// ceiling browsers enforce (~64 KiB), leaving headroom for the outer `Frame` header.
pub const MAX_CHUNK_DATA: usize = 48 * 1024;

/// Maximum bytes of one JSON control payload, sized from the largest LEGAL message rather than the
/// data-channel message size (the transport already splits a frame larger than one SCTP message):
/// a `Request` path may be [`MAX_REQUEST_PATH_UTF16`] UTF-16 units, which is at most 98,301 UTF-8
/// bytes (3 per BMP unit; a supplementary character is 4 bytes for 2 units). JSON escaping cannot
/// grow it: serde escapes only `"`, `\` (2 bytes for a 1-byte character, still within 3) and C0
/// controls, which a valid path cannot contain. Add the envelope and 128 KiB is the bound; a larger
/// payload is refused before it is parsed into owned strings. (It was 64 KiB, which refused a legal
/// path of ~22,000 CJK characters.)
pub const MAX_CONTROL_LEN: usize = 128 * 1024;

/// An `Offer` announces an incoming file (either an upload the controller is about to send, or the
/// agent's reply to a download [`Request`]): its transfer `id`, display `name`, total `size`, and
/// the lowercase-hex SHA-256 of the whole file for end-to-end integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Transfer id (UUID) tying this offer to its chunks and terminal control message.
    pub id: Uuid,
    /// File display name (basename). Receivers MUST treat this as untrusted and strip any path.
    pub name: String,
    /// Total file size in bytes (lets the receiver verify it got everything).
    pub size: u64,
    /// Lowercase-hex SHA-256 of the complete file contents. [`decode`] refuses an `Offer` whose
    /// digest is not exactly 64 characters of `[0-9a-f]` ([`FileTransferError::BadDigest`]).
    pub sha256: String,
}

/// One binary chunk of a transfer's bytes. `seq` starts at 0 and increments by 1 per chunk (the
/// receiver rejects a gap/reorder). `data.len()` MUST be ≤ [`MAX_CHUNK_DATA`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Transfer id this chunk belongs to.
    pub id: Uuid,
    /// Monotonic chunk sequence number, starting at 0.
    pub seq: u32,
    /// Raw file bytes for this chunk (never base64).
    pub data: Vec<u8>,
}

/// A single decoded file-transfer message (control or chunk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Announce an incoming file (upload from controller, or download reply from agent).
    Offer(Offer),
    /// A run of the file's raw bytes (binary-framed).
    Chunk(Chunk),
    /// The offering side has sent every chunk; the receiver should now verify + finalize.
    Done {
        /// Transfer id being finalized.
        id: Uuid,
    },
    /// Terminal receipt for an upload: `ok` on success, else `message` explains the failure.
    Ack {
        /// Transfer id being acknowledged.
        id: Uuid,
        /// True if the file was received, verified, and committed.
        ok: bool,
        /// Human-readable detail (empty on success, reason on failure).
        message: String,
    },
    /// Ask the agent to send a file back (download): `path` is resolved under the agent's transfer
    /// root (see the agent handler's path-safety policy).
    Request {
        /// Transfer id the agent should use for its `Offer`/`Chunk`/`Done` reply.
        id: Uuid,
        /// Requested file path, resolved relative to (and confined within) the transfer root.
        /// [`decode`] refuses one containing a control character or longer than
        /// [`MAX_REQUEST_PATH_UTF16`] UTF-16 units ([`FileTransferError::BadPath`]); empty, `..` and
        /// absolute paths still decode, as the path resolver owns those refusals.
        path: String,
    },
    /// A transfer failed out-of-band (bad request, path denied, I/O error).
    Error {
        /// Transfer id the error pertains to.
        id: Uuid,
        /// Human-readable failure detail.
        message: String,
    },
    /// **Agent → controller only.** The tamper-evident audit record this transfer produced
    /// (ADR-008). `event` is the agent's `AuditEvent` serialized as JSON, carried opaquely here so
    /// this crate stays free of a dependency on the backstage audit types: the controller does not
    /// interpret it, it forwards it verbatim to `POST /audit/ingest`, and the control plane
    /// re-hashes the canonical form to verify it.
    ///
    /// It rides THIS channel rather than the request/response backstage channel so an unsolicited
    /// message never lands in the middle of a correlated backstage exchange (ADR-008). A controller
    /// that receives one must treat it as informational — it is never a terminal message for a
    /// transfer, so `Ack`/`Error`/`Done` handling is unaffected.
    Audit {
        /// Transfer id the record pertains to (ties it to the `Offer`/`Request` the user sees).
        id: Uuid,
        /// The agent's `AuditEvent`, as an opaque JSON object.
        event: serde_json::Value,
    },
}

/// Private adjacently-tagged serde view of the **control** variants only (Chunk is binary and never
/// travels through this). Mirrors the `{"t":…,"c":…}` shape `input_codec` uses.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
enum Control {
    Offer(Offer),
    Done { id: Uuid },
    Ack { id: Uuid, ok: bool, message: String },
    Request { id: Uuid, path: String },
    Error { id: Uuid, message: String },
    Audit { id: Uuid, event: serde_json::Value },
}

impl Control {
    fn into_message(self) -> Message {
        match self {
            Control::Offer(o) => Message::Offer(o),
            Control::Done { id } => Message::Done { id },
            Control::Ack { id, ok, message } => Message::Ack { id, ok, message },
            Control::Request { id, path } => Message::Request { id, path },
            Control::Error { id, message } => Message::Error { id, message },
            Control::Audit { id, event } => Message::Audit { id, event },
        }
    }

    /// Borrow a control [`Message`] as its serde view. Returns `None` for [`Message::Chunk`], which
    /// is binary-framed and must not go through JSON.
    fn from_message(m: &Message) -> Option<Control> {
        Some(match m {
            Message::Offer(o) => Control::Offer(o.clone()),
            Message::Done { id } => Control::Done { id: *id },
            Message::Ack { id, ok, message } => Control::Ack {
                id: *id,
                ok: *ok,
                message: message.clone(),
            },
            Message::Request { id, path } => Control::Request {
                id: *id,
                path: path.clone(),
            },
            Message::Error { id, message } => Control::Error {
                id: *id,
                message: message.clone(),
            },
            Message::Audit { id, event } => Control::Audit {
                id: *id,
                event: event.clone(),
            },
            Message::Chunk(_) => return None,
        })
    }
}

/// Error decoding a file-transfer message off the wire.
#[derive(Debug, thiserror::Error)]
pub enum FileTransferError {
    /// The payload was empty (no tag byte).
    #[error("empty file-transfer payload")]
    Empty,
    /// The first byte was neither [`CHUNK_TAG`] nor [`CONTROL_TAG`].
    #[error("unrecognized file-transfer tag byte 0x{0:02x}")]
    BadTag(u8),
    /// A binary chunk was shorter than the fixed `tag+id+seq` header.
    #[error("truncated chunk: need at least 21 bytes, got {0}")]
    ShortChunk(usize),
    /// A binary chunk carried more than [`MAX_CHUNK_DATA`] bytes of data.
    #[error("oversized chunk: {0} data bytes exceeds MAX_CHUNK_DATA ({max})", max = MAX_CHUNK_DATA)]
    ChunkTooLarge(usize),
    /// A JSON control payload was longer than [`MAX_CONTROL_LEN`] bytes.
    #[error("oversized control message: {0} bytes exceeds MAX_CONTROL_LEN ({max})", max = MAX_CONTROL_LEN)]
    ControlTooLarge(usize),
    /// The 16 id bytes of a binary chunk were not a valid UUID.
    #[error("invalid chunk uuid")]
    BadUuid,
    /// A control payload was not valid JSON / not a known control variant.
    #[error("control json decode failed: {0}")]
    Json(#[from] serde_json::Error),
    /// A decoded [`Offer`] carried a `sha256` that was not 64 lowercase hex characters.
    #[error("offer sha256 must be 64 lowercase hex characters, got {0} bytes")]
    BadDigest(usize),
    /// A decoded [`Message::Request`] path contained a control character or exceeded
    /// [`MAX_REQUEST_PATH_UTF16`] UTF-16 units.
    #[error("request path contains control characters or exceeds 32767 UTF-16 units, got {0} bytes")]
    BadPath(usize),
}

/// Maximum UTF-16 code units of a download-request path (the Windows extended path limit).
pub const MAX_REQUEST_PATH_UTF16: usize = 32767;

/// True iff `p` has no control character and is at most [`MAX_REQUEST_PATH_UTF16`] UTF-16 units.
fn is_valid_request_path(p: &str) -> bool {
    !p.chars().any(is_windows_forbidden_control) && p.encode_utf16().count() <= MAX_REQUEST_PATH_UTF16
}

/// True for a character Windows forbids in a file or path name: NUL and the C0 controls
/// U+0001..U+001F. NOT `char::is_control`, which also covers DEL (U+007F) and the C1 range
/// (U+0080..U+009F); those are legal in Windows names, and refusing them made real folders
/// unlistable and renamed real uploads.
pub fn is_windows_forbidden_control(c: char) -> bool {
    (c as u32) < 0x20
}

/// True iff `s` is exactly 64 lowercase ASCII hex characters (the form [`sha256_hex`] produces).
fn is_valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Fixed binary-chunk header length: `[tag:1][id:16][seq:4]`.
const CHUNK_HEADER_LEN: usize = 1 + 16 + 4;

/// Encode one [`Message`] to its wire bytes: JSON for control, compact binary for a chunk.
///
/// Infallible in practice (control serialization of owned primitives + a String cannot fail); on the
/// impossible serialize error it yields an empty vec, keeping the send path total (matches
/// `input_codec::encode`).
pub fn encode(msg: &Message) -> Vec<u8> {
    match msg {
        Message::Chunk(c) => {
            let mut out = Vec::with_capacity(CHUNK_HEADER_LEN + c.data.len());
            out.push(CHUNK_TAG);
            out.extend_from_slice(c.id.as_bytes());
            out.extend_from_slice(&c.seq.to_be_bytes());
            out.extend_from_slice(&c.data);
            out
        }
        other => {
            // `from_message` only returns None for Chunk, handled above.
            let ctrl = Control::from_message(other).expect("non-chunk is always a control message");
            serde_json::to_vec(&ctrl).unwrap_or_default()
        }
    }
}

/// Decode one [`Message`] from wire bytes, dispatching on the leading byte
/// ([`CONTROL_TAG`] → JSON control, [`CHUNK_TAG`] → binary chunk).
pub fn decode(bytes: &[u8]) -> Result<Message, FileTransferError> {
    match bytes.first().copied() {
        None => Err(FileTransferError::Empty),
        Some(CONTROL_TAG) => {
            if bytes.len() > MAX_CONTROL_LEN {
                return Err(FileTransferError::ControlTooLarge(bytes.len()));
            }
            let ctrl: Control = serde_json::from_slice(bytes)?;
            if let Control::Offer(o) = &ctrl {
                if !is_valid_digest(&o.sha256) {
                    return Err(FileTransferError::BadDigest(o.sha256.len()));
                }
            }
            if let Control::Request { path, .. } = &ctrl {
                if !is_valid_request_path(path) {
                    return Err(FileTransferError::BadPath(path.len()));
                }
            }
            Ok(ctrl.into_message())
        }
        Some(CHUNK_TAG) => {
            if bytes.len() < CHUNK_HEADER_LEN {
                return Err(FileTransferError::ShortChunk(bytes.len()));
            }
            let data_len = bytes.len() - CHUNK_HEADER_LEN;
            if data_len > MAX_CHUNK_DATA {
                return Err(FileTransferError::ChunkTooLarge(data_len));
            }
            let id = Uuid::from_slice(&bytes[1..17]).map_err(|_| FileTransferError::BadUuid)?;
            // 4 bytes, big-endian; slice length is exact so the try_into cannot fail.
            let seq = u32::from_be_bytes(bytes[17..21].try_into().unwrap());
            let data = bytes[CHUNK_HEADER_LEN..].to_vec();
            Ok(Message::Chunk(Chunk { id, seq, data }))
        }
        Some(other) => Err(FileTransferError::BadTag(other)),
    }
}

/// Lowercase-hex SHA-256 of `data`. The digest carried in an [`Offer`] and verified on [`Done`].
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_lower(&h.finalize())
}

/// Encode bytes as lowercase hex (no external hex crate needed).
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Split a whole file into ordered [`Chunk`]s of at most [`MAX_CHUNK_DATA`] bytes each, `seq`
/// starting at 0. An empty file yields **zero** chunks (the [`Offer`] `size: 0` + `Done` still
/// convey a valid empty transfer).
pub fn chunk_file(id: Uuid, data: &[u8]) -> Vec<Chunk> {
    data.chunks(MAX_CHUNK_DATA)
        .enumerate()
        .map(|(i, c)| Chunk {
            id,
            seq: i as u32,
            data: c.to_vec(),
        })
        .collect()
}

/// True for a single path component that Windows would treat specially: it contains `:` (drive
/// or NTFS alternate data stream), its stem (text before the first `.`, with trailing ASCII
/// spaces trimmed because Windows ignores them, so `NUL .txt` still opens the device) is a
/// reserved device name (CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM1-9, LPT1-9, the superscript
/// variants COM\u{b9}/\u{b2}/\u{b3} and LPT\u{b9}/\u{b2}/\u{b3}, case-insensitive), or it ends in
/// `.` or a space. Pure string logic, so it behaves identically on every OS.
fn is_unsafe_windows_name(name: &str) -> bool {
    if name.contains(':') || name.ends_with('.') || name.ends_with(' ') {
        return true;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        "COM\u{b9}" | "COM\u{b2}" | "COM\u{b3}" | "LPT\u{b9}" | "LPT\u{b2}" | "LPT\u{b3}" => true,
        s => {
            (s.starts_with("COM") || s.starts_with("LPT"))
                && s.len() == 4
                && matches!(s.as_bytes()[3], b'1'..=b'9')
        }
    }
}

/// Resolve a download `Request` path against the transfer `root`, **confined to that root**.
///
/// Path-safety policy (deny-by-default): the requested path is split into components and only
/// **plain names** are accepted. Any `..` (parent), any absolute prefix (drive letter / UNC) or
/// root separator, and any current-dir `.` are rejected — so a controller can never escape the
/// transfer root via `..\..\Windows\...`, `C:\...`, or `\\server\share`. The surviving names are
/// joined onto `root`. Each plain name must also pass [`is_unsafe_windows_name`] (no NTFS
/// alternate-data-stream `:`, reserved device names, or trailing dot/space). Symlink escape is
/// additionally checked by the caller via `canonicalize` (see the agent handler) once the file
/// is known to exist.
pub fn resolve_download_path(root: &Path, requested: &str) -> Result<PathBuf, String> {
    if requested.trim().is_empty() {
        return Err("empty request path".to_string());
    }
    let mut out = root.to_path_buf();
    let mut any = false;
    for comp in Path::new(requested).components() {
        match comp {
            Component::Normal(name) => {
                if is_unsafe_windows_name(&name.to_string_lossy()) {
                    return Err(format!(
                        "unsafe file name {name:?} rejected in {requested:?}"
                    ));
                }
                out.push(name);
                any = true;
            }
            Component::CurDir => {} // skip a leading "./"
            Component::ParentDir => {
                return Err(format!("path traversal ('..') rejected in {requested:?}"))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("absolute path rejected in {requested:?}"))
            }
        }
    }
    if !any {
        return Err(format!("request path {requested:?} names no file"));
    }
    Ok(out)
}

/// Strip any directory part from an offered file name, yielding a bare basename safe to create
/// inside the transfer root. Falls back to `{id}.bin` if the name is empty/path-only, or if the
/// basename is unsafe on Windows per [`is_unsafe_windows_name`] (NTFS alternate data stream `:`,
/// reserved device name, trailing dot/space), so an upload can never target a stream or device.
/// It also falls back when the basename could not be a legitimate Windows file name per
/// [`is_uncreatable_name`]: NUL or a C0 control (which Windows forbids, and which include CR/LF that
/// would forge audit lines), any of the reserved characters `< > " | ? *`, or more than 255 UTF-16
/// code units (the NTFS component limit). DEL and C1 are legal in Windows names and are kept.
pub fn safe_basename(name: &str, id: Uuid) -> String {
    // Check the raw final segment too: on Windows `Path::file_name` treats a drive prefix such as
    // `x:` in `x:$DATA` as a prefix and returns only `$DATA`, hiding the stream separator.
    let raw_tail = name.rsplit(['/', '\\']).next().unwrap_or("");
    if is_unsafe_windows_name(raw_tail) || is_uncreatable_name(raw_tail) {
        return format!("{id}.bin");
    }
    Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty() && s != "." && s != "..")
        .filter(|n| !is_unsafe_windows_name(n) && !is_uncreatable_name(n))
        .unwrap_or_else(|| format!("{id}.bin"))
}

/// True for a name that cannot be a legitimate Windows file name: it contains a control
/// character (`char::is_control`), a reserved character (`<`, `>`, `"`, `|`, `?`, `*`), or it is
/// longer than 255 UTF-16 code units. Pure string logic, identical on every OS.
fn is_uncreatable_name(name: &str) -> bool {
    name.chars()
        .any(|c| is_windows_forbidden_control(c) || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
        || name.encode_utf16().count() > 255
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    /// Round-trip a control message and assert its exact canonical JSON (pins the shape the TS side
    /// is tested against).
    fn round_trip_control(msg: Message, expect_json: &str) {
        let bytes = encode(&msg);
        assert_eq!(bytes[0], CONTROL_TAG, "control must start with '{{'");
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            expect_json,
            "canonical JSON for {msg:?}"
        );
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, msg, "round-trip for {msg:?}");
    }

    #[test]
    fn offer_round_trips() {
        round_trip_control(
            Message::Offer(Offer {
                id: fixed_id(),
                name: "a.bin".into(),
                size: 1048576,
                sha256: sha256_hex(b"abc"),
            }),
            r#"{"t":"Offer","c":{"id":"550e8400-e29b-41d4-a716-446655440000","name":"a.bin","size":1048576,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#,
        );
    }

    fn offer_wire(sha256: &str) -> Vec<u8> {
        encode(&Message::Offer(Offer {
            id: fixed_id(),
            name: "a.bin".into(),
            size: 3,
            sha256: sha256.to_string(),
        }))
    }

    #[test]
    fn decode_accepts_valid_offer_digest() {
        let d = sha256_hex(b"abc");
        match decode(&offer_wire(&d)).expect("valid digest decodes") {
            Message::Offer(o) => assert_eq!(o.sha256, d),
            other => panic!("expected Offer, got {other:?}"),
        }
        let zeros = "0".repeat(64);
        assert!(matches!(decode(&offer_wire(&zeros)), Ok(Message::Offer(_))));
    }

    #[test]
    fn decode_refuses_malformed_offer_digest() {
        let valid = sha256_hex(b"abc");
        let with_g = format!("{}g", &valid[..63]);
        for (bad, len) in [
            ("deadbeef".to_string(), 8),
            (String::new(), 0),
            (valid[..63].to_string(), 63),
            (format!("{valid}a"), 65),
            (with_g, 64),
        ] {
            match decode(&offer_wire(&bad)) {
                Err(FileTransferError::BadDigest(n)) => assert_eq!(n, len, "{bad:?}"),
                other => panic!("{bad:?}: expected BadDigest, got {other:?}"),
            }
        }
    }

    #[test]
    fn decode_refuses_uppercase_offer_digest() {
        let upper = sha256_hex(b"abc").to_ascii_uppercase();
        assert_eq!(upper.len(), 64);
        assert!(matches!(
            decode(&offer_wire(&upper)),
            Err(FileTransferError::BadDigest(64))
        ));
    }

    #[test]
    fn decode_refuses_huge_offer_digest_with_its_length() {
        let len = 60 * 1024;
        let bytes = offer_wire(&"a".repeat(len));
        assert!(bytes.len() <= MAX_CONTROL_LEN);
        match decode(&bytes) {
            Err(e @ FileTransferError::BadDigest(_)) => {
                assert!(matches!(e, FileTransferError::BadDigest(n) if n == len));
                assert!(e.to_string().contains(&len.to_string()));
            }
            other => panic!("expected BadDigest, got {other:?}"),
        }
    }

    #[test]
    fn decode_refuses_offer_digest_with_newline_or_forged_text() {
        let valid = sha256_hex(b"abc");
        let nl_tail = format!("{}\n", &valid[..63]);
        for bad in ["a\nFORGED", nl_tail.as_str(), "a\r\nFORGED audit line"] {
            assert!(
                matches!(decode(&offer_wire(bad)), Err(FileTransferError::BadDigest(_))),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn offer_digest_rule_does_not_affect_other_messages() {
        let msgs = [
            Message::Done { id: fixed_id() },
            Message::Ack {
                id: fixed_id(),
                ok: false,
                message: "deadbeef".into(),
            },
            Message::Request {
                id: fixed_id(),
                path: "a.bin".into(),
            },
            Message::Error {
                id: fixed_id(),
                message: "x".into(),
            },
            Message::Audit {
                id: fixed_id(),
                event: serde_json::json!({ "sha256": "deadbeef" }),
            },
            Message::Chunk(Chunk {
                id: fixed_id(),
                seq: 1,
                data: b"deadbeef".to_vec(),
            }),
        ];
        for m in msgs {
            assert_eq!(decode(&encode(&m)).expect("unaffected"), m);
        }
    }

    /// ADR-008: the `Audit` control message pins the same canonical JSON the TS side is tested
    /// against (`web/viewer/src/lib/file_transfer.test.ts`). The event is carried OPAQUELY — this
    /// codec must not reshape it, or the digest the control plane re-computes stops matching.
    #[test]
    fn audit_round_trips_and_carries_the_event_verbatim() {
        round_trip_control(
            Message::Audit {
                id: fixed_id(),
                event: serde_json::json!({
                    "seq": 3,
                    "hash": "abc",
                    "action": { "kind": "file_transfer", "direction": "input" },
                }),
            },
            r#"{"t":"Audit","c":{"id":"550e8400-e29b-41d4-a716-446655440000","event":{"action":{"direction":"input","kind":"file_transfer"},"hash":"abc","seq":3}}}"#,
        );
    }

    #[test]
    fn done_round_trips() {
        round_trip_control(
            Message::Done { id: fixed_id() },
            r#"{"t":"Done","c":{"id":"550e8400-e29b-41d4-a716-446655440000"}}"#,
        );
    }

    #[test]
    fn ack_round_trips() {
        round_trip_control(
            Message::Ack {
                id: fixed_id(),
                ok: true,
                message: String::new(),
            },
            r#"{"t":"Ack","c":{"id":"550e8400-e29b-41d4-a716-446655440000","ok":true,"message":""}}"#,
        );
        round_trip_control(
            Message::Ack {
                id: fixed_id(),
                ok: false,
                message: "sha256 mismatch".into(),
            },
            r#"{"t":"Ack","c":{"id":"550e8400-e29b-41d4-a716-446655440000","ok":false,"message":"sha256 mismatch"}}"#,
        );
    }

    #[test]
    fn request_round_trips() {
        round_trip_control(
            Message::Request {
                id: fixed_id(),
                path: "sub/a.bin".into(),
            },
            r#"{"t":"Request","c":{"id":"550e8400-e29b-41d4-a716-446655440000","path":"sub/a.bin"}}"#,
        );
    }

    #[test]
    fn error_round_trips() {
        round_trip_control(
            Message::Error {
                id: fixed_id(),
                message: "not found".into(),
            },
            r#"{"t":"Error","c":{"id":"550e8400-e29b-41d4-a716-446655440000","message":"not found"}}"#,
        );
    }

    #[test]
    fn chunk_round_trips_with_real_bytes() {
        // Include a 0x7B byte inside the data to prove the binary path never confuses data with the
        // JSON control tag (dispatch is on the FIRST byte only, which is 0x01 here).
        let data = vec![0x7B, 0x00, 0xFF, 0x10, 0x7B, 0x42, 0x99];
        let msg = Message::Chunk(Chunk {
            id: fixed_id(),
            seq: 258,
            data: data.clone(),
        });
        let bytes = encode(&msg);
        assert_eq!(bytes[0], CHUNK_TAG, "chunk must start with 0x01");
        assert_eq!(&bytes[1..17], fixed_id().as_bytes(), "id bytes");
        assert_eq!(&bytes[17..21], &258u32.to_be_bytes(), "seq big-endian");
        assert_eq!(&bytes[21..], &data[..], "raw data verbatim");
        let back = decode(&bytes).expect("decode chunk");
        assert_eq!(back, msg);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(matches!(decode(&[]), Err(FileTransferError::Empty)));
        assert!(matches!(decode(&[0x02, 1, 2]), Err(FileTransferError::BadTag(0x02))));
        assert!(matches!(
            decode(&[CHUNK_TAG, 1, 2, 3]),
            Err(FileTransferError::ShortChunk(4))
        ));
        assert!(decode(b"{not json").is_err());
    }

    fn chunk_wire(len: usize) -> Vec<u8> {
        encode(&Message::Chunk(Chunk {
            id: fixed_id(),
            seq: 7,
            data: vec![0xAB; len],
        }))
    }

    #[test]
    fn decode_accepts_chunk_of_exactly_max_data() {
        let bytes = chunk_wire(MAX_CHUNK_DATA);
        match decode(&bytes).expect("max-size chunk is legal") {
            Message::Chunk(c) => {
                assert_eq!(c.data.len(), MAX_CHUNK_DATA);
                assert_eq!(c.seq, 7);
                assert_eq!(c.id, fixed_id());
            }
            other => panic!("expected chunk, got {other:?}"),
        }
    }

    #[test]
    fn decode_refuses_chunk_one_byte_over_max() {
        let bytes = chunk_wire(MAX_CHUNK_DATA + 1);
        match decode(&bytes) {
            Err(FileTransferError::ChunkTooLarge(n)) => assert_eq!(n, MAX_CHUNK_DATA + 1),
            other => panic!("expected ChunkTooLarge, got {other:?}"),
        }
        let msg = decode(&bytes).unwrap_err().to_string();
        assert!(msg.contains(&(MAX_CHUNK_DATA + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_CHUNK_DATA.to_string()), "{msg}");
    }

    #[test]
    fn decode_refuses_multi_megabyte_chunk() {
        let len = 4 * 1024 * 1024;
        assert!(matches!(
            decode(&chunk_wire(len)),
            Err(FileTransferError::ChunkTooLarge(n)) if n == len
        ));
    }

    /// A valid Ack control payload of exactly `total` bytes (message padded with spaces).
    fn ack_wire_of_len(total: usize) -> Vec<u8> {
        let base = encode(&Message::Ack {
            id: fixed_id(),
            ok: true,
            message: String::new(),
        });
        assert!(total >= base.len());
        encode(&Message::Ack {
            id: fixed_id(),
            ok: true,
            message: " ".repeat(total - base.len()),
        })
    }

    #[test]
    fn decode_accepts_control_of_exactly_max_len() {
        let bytes = ack_wire_of_len(MAX_CONTROL_LEN);
        assert_eq!(bytes.len(), MAX_CONTROL_LEN);
        match decode(&bytes).expect("max-size control is legal") {
            Message::Ack { id, ok, message } => {
                assert_eq!(id, fixed_id());
                assert!(ok);
                assert!(message.chars().all(|c| c == ' '));
            }
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    #[test]
    fn decode_refuses_control_one_byte_over_max() {
        let bytes = ack_wire_of_len(MAX_CONTROL_LEN + 1);
        assert_eq!(bytes.len(), MAX_CONTROL_LEN + 1);
        match decode(&bytes) {
            Err(FileTransferError::ControlTooLarge(n)) => assert_eq!(n, MAX_CONTROL_LEN + 1),
            other => panic!("expected ControlTooLarge, got {other:?}"),
        }
        let msg = decode(&bytes).unwrap_err().to_string();
        assert!(msg.contains(&(MAX_CONTROL_LEN + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_CONTROL_LEN.to_string()), "{msg}");
    }

    #[test]
    fn decode_refuses_multi_megabyte_request_path() {
        let len = 4 * 1024 * 1024;
        let bytes = encode(&Message::Request {
            id: fixed_id(),
            path: "a".repeat(len),
        });
        assert!(matches!(
            decode(&bytes),
            Err(FileTransferError::ControlTooLarge(n)) if n == bytes.len()
        ));
    }

    fn request_wire(path: &str) -> Vec<u8> {
        encode(&Message::Request {
            id: fixed_id(),
            path: path.to_string(),
        })
    }

    #[test]
    fn decode_accepts_normal_and_unicode_request_paths() {
        for p in ["sub/dir/a.txt", "dossier/résumé 日本語 😀.txt"] {
            match decode(&request_wire(p)).expect("normal path decodes") {
                Message::Request { path, .. } => assert_eq!(path, p),
                other => panic!("expected Request, got {other:?}"),
            }
        }
    }

    #[test]
    fn decode_refuses_request_path_with_control_characters() {
        for bad in [
            "a\nb",
            "a\r\nFORGED audit line",
            "a\0b",
            "a\u{1f}b",
            "\u{1b}[31m",
        ] {
            match decode(&request_wire(bad)) {
                Err(FileTransferError::BadPath(n)) => assert_eq!(n, bad.len(), "{bad:?}"),
                other => panic!("{bad:?}: expected BadPath, got {other:?}"),
            }
        }
    }

    #[test]
    fn decode_accepts_request_paths_with_del_and_c1_which_windows_allows() {
        for ok in ["a\u{7f}b", "a\u{85}b", "dir/\u{9f}.txt"] {
            assert!(matches!(decode(&request_wire(ok)), Ok(Message::Request { .. })), "{ok:?}");
        }
    }

    /// A legal maximum-length path of 3-byte UTF-8 characters must fit the control cap.
    #[test]
    fn a_maximal_cjk_request_path_fits_the_control_cap() {
        let path = "\u{65e5}".repeat(MAX_REQUEST_PATH_UTF16);
        let wire = request_wire(&path);
        assert!(wire.len() <= MAX_CONTROL_LEN, "{} > {MAX_CONTROL_LEN}", wire.len());
        assert!(matches!(decode(&wire), Ok(Message::Request { .. })));
    }

    #[test]
    fn decode_request_path_utf16_limit_is_exact() {
        let ok = request_wire(&"a".repeat(MAX_REQUEST_PATH_UTF16));
        assert!(matches!(decode(&ok), Ok(Message::Request { .. })));
        let bad = request_wire(&"a".repeat(MAX_REQUEST_PATH_UTF16 + 1));
        assert!(matches!(
            decode(&bad),
            Err(FileTransferError::BadPath(n)) if n == MAX_REQUEST_PATH_UTF16 + 1
        ));
    }

    #[test]
    fn decode_request_path_limit_counts_utf16_units_not_chars() {
        // 16000 emoji (2 units each) + 800 ASCII = 16800 chars but 32800 units: over the limit.
        let heavy = format!("{}{}", "😀".repeat(16000), "a".repeat(800));
        assert_eq!(heavy.chars().count(), 16800);
        assert!(heavy.encode_utf16().count() > MAX_REQUEST_PATH_UTF16);
        let bytes = request_wire(&heavy);
        assert!(bytes.len() <= MAX_CONTROL_LEN);
        assert!(matches!(decode(&bytes), Err(FileTransferError::BadPath(_))));
        // The same char count of ASCII is well under the limit.
        let light = "a".repeat(16800);
        assert!(matches!(
            decode(&request_wire(&light)),
            Ok(Message::Request { .. })
        ));
        // Emoji-only path under the limit (128 emoji = 256 units) decodes.
        assert!(matches!(
            decode(&request_wire(&"😀".repeat(128))),
            Ok(Message::Request { .. })
        ));
    }

    #[test]
    fn decode_request_path_rule_leaves_resolver_cases_decodable() {
        for p in ["", "../x", "/etc/passwd", "C:\\Windows\\win.ini"] {
            assert!(
                matches!(decode(&request_wire(p)), Ok(Message::Request { .. })),
                "{p:?} must still decode"
            );
        }
    }

    #[test]
    fn oversized_control_check_does_not_affect_chunks_or_small_control() {
        // The control bound applies only to the '{' arm; a max-data chunk still decodes.
        assert!(matches!(
            decode(&chunk_wire(MAX_CHUNK_DATA)),
            Ok(Message::Chunk(_))
        ));
        let small = encode(&Message::Error {
            id: fixed_id(),
            message: "not found".into(),
        });
        assert!(matches!(decode(&small), Ok(Message::Error { .. })));
    }

    #[test]
    fn decode_accepts_empty_data_chunk() {
        match decode(&chunk_wire(0)).expect("empty chunk decodes") {
            Message::Chunk(c) => assert!(c.data.is_empty()),
            other => panic!("expected chunk, got {other:?}"),
        }
    }

    #[test]
    fn chunk_file_output_always_decodes() {
        let data: Vec<u8> = (0..(MAX_CHUNK_DATA * 2 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let chunks = chunk_file(fixed_id(), &data);
        assert_eq!(chunks.len(), 3);
        for c in chunks {
            let msg = Message::Chunk(c);
            assert_eq!(decode(&encode(&msg)).expect("legal chunk decodes"), msg);
        }
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // SHA-256("abc") — a standard test vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"").len(), 64);
    }

    #[test]
    fn chunk_file_splits_and_reassembles() {
        let id = fixed_id();
        let data: Vec<u8> = (0..(MAX_CHUNK_DATA * 2 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let chunks = chunk_file(id, &data);
        assert_eq!(chunks.len(), 3, "two full chunks + a remainder");
        assert_eq!(chunks[0].seq, 0);
        assert_eq!(chunks[2].seq, 2);
        let mut back = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.seq as usize, i, "monotonic seq");
            assert!(c.data.len() <= MAX_CHUNK_DATA);
            back.extend_from_slice(&c.data);
        }
        assert_eq!(back, data, "reassembled == original");
        assert!(chunk_file(id, &[]).is_empty(), "empty file → no chunks");
    }

    #[test]
    fn resolve_download_path_confines_to_root() {
        let root = Path::new("C:\\rmt-agent\\transfers");
        // Plain name and a subdir are allowed.
        assert_eq!(
            resolve_download_path(root, "a.bin").unwrap(),
            root.join("a.bin")
        );
        assert_eq!(
            resolve_download_path(root, "sub/a.bin").unwrap(),
            root.join("sub").join("a.bin")
        );
        // A leading "./" is silently skipped (CurDir branch).
        assert_eq!(
            resolve_download_path(root, "./a.bin").unwrap(),
            root.join("a.bin")
        );
        // Traversal, absolute, and empty are denied.
        assert!(resolve_download_path(root, "../secret").is_err());
        assert!(resolve_download_path(root, "sub/../../secret").is_err());
        assert!(resolve_download_path(root, "C:\\Windows\\win.ini").is_err());
        // "\\" is a separator only on Windows (where the agent runs); elsewhere it is a
        // filename character, so a UNC-looking request is one literal name that stays in root.
        #[cfg(windows)]
        assert!(resolve_download_path(root, "\\\\server\\share\\x").is_err());
        #[cfg(not(windows))]
        assert_eq!(
            resolve_download_path(root, "\\\\server\\share\\x").unwrap().parent(),
            Some(root)
        );
        assert!(resolve_download_path(root, "   ").is_err());
    }

    #[test]
    fn resolve_download_path_refuses_windows_stream_and_device_names() {
        let root = Path::new("C:\\rmt-agent\\transfers");
        for bad in [
            "a.txt:Zone.Identifier",
            "a:b",
            "nul",
            "NUL.txt",
            "com1",
            "LPT9.log",
            "name.",
            "name ",
            "sub/NUL",
        ] {
            assert!(
                resolve_download_path(root, bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        // Positive controls: look-alike but ordinary names still resolve.
        assert_eq!(
            resolve_download_path(root, "console.txt").unwrap(),
            root.join("console.txt")
        );
        assert_eq!(
            resolve_download_path(root, "communist.bin").unwrap(),
            root.join("communist.bin")
        );
        assert_eq!(
            resolve_download_path(root, "a.txt").unwrap(),
            root.join("a.txt")
        );
        assert_eq!(
            resolve_download_path(root, "sub/a.txt").unwrap(),
            root.join("sub").join("a.txt")
        );
        assert_eq!(
            resolve_download_path(root, "./a.txt").unwrap(),
            root.join("a.txt")
        );
    }

    #[test]
    fn is_unsafe_windows_name_classifies_names() {
        for bad in [
            "a:b", "a.txt:s", "CON", "prn", "Aux.log", "NUL", "com1", "COM9", "lpt1", "LPT9.log",
            "name.", "name ",
        ] {
            assert!(is_unsafe_windows_name(bad), "{bad:?} must be unsafe");
        }
        for ok in [
            "a.txt", "console.txt", "communist.bin", "com0", "com10", "lpt", "nully", "a.b.c",
            ".hidden",
        ] {
            assert!(!is_unsafe_windows_name(ok), "{ok:?} must be safe");
        }
    }

    #[test]
    fn safe_basename_strips_directories() {
        let id = fixed_id();
        assert_eq!(safe_basename("a.bin", id), "a.bin");
        // "\\" separates directories only on Windows; elsewhere the whole string is one name,
        // which still contains no "/" and so cannot leave the transfer root.
        #[cfg(windows)]
        assert_eq!(safe_basename("sub\\dir\\a.bin", id), "a.bin");
        #[cfg(not(windows))]
        assert!(!safe_basename("sub\\dir\\a.bin", id).contains('/'));
        assert_eq!(safe_basename("../../a.bin", id), "a.bin");
        assert_eq!(safe_basename("", id), format!("{id}.bin"));
        assert_eq!(safe_basename("report.final.pdf", id), "report.final.pdf");
    }

    #[test]
    fn safe_basename_refuses_control_reserved_and_overlong_names() {
        let id = fixed_id();
        let fallback = format!("{id}.bin");
        let ascii_256 = "a".repeat(256);
        let emoji_128 = "\u{1F600}".repeat(128);
        let huge = "a".repeat(64 * 1024);
        for bad in [
            "a\nb.txt",
            "a\r\nFORGED audit line.txt",
            "x\u{0}y",
            "x\u{1f}y",
            "what?.txt",
            "a*b",
            "a<b>",
            "a|b",
            "q\"x",
            "dir\\a|b",
            ascii_256.as_str(),
            emoji_128.as_str(),
            huge.as_str(),
        ] {
            assert_eq!(safe_basename(bad, id), fallback, "{:?} must fall back", bad.len());
        }
        // Positive controls: legitimate names at and under the limit stay unchanged.
        let ascii_255 = "a".repeat(255);
        let emoji_127 = "\u{1F600}".repeat(127);
        for ok in [
            ascii_255.as_str(),
            emoji_127.as_str(),
            "report (final), v2.pdf",
            "Zo\u{eb} \u{65e5}\u{672c}\u{8a9e}.txt",
            "x\u{7f}y",
            "x\u{85}y.txt",
        ] {
            assert_eq!(safe_basename(ok, id), ok);
        }
    }

    #[test]
    fn safe_basename_never_returns_an_uncreatable_name() {
        let id = fixed_id();
        let long = "b".repeat(300);
        let table = [
            "a.bin",
            "a\nb",
            "a\r\nb",
            "x\u{0}y",
            "x\u{7f}y",
            "x\u{9f}y",
            "dir\\what?.txt",
            "a/b*c",
            "q\"x",
            "<a>",
            "a|b",
            "ok name (1).txt",
            "\u{65e5}\u{672c}.txt",
            long.as_str(),
            "",
            "..",
        ];
        for name in table {
            let out = safe_basename(name, id);
            assert!(!is_uncreatable_name(&out), "{name:?} -> {out:?} is uncreatable");
            assert!(out.encode_utf16().count() <= 255);
            assert!(!out.chars().any(is_windows_forbidden_control));
        }
    }

    #[test]
    fn safe_basename_refuses_windows_stream_and_device_names() {
        let id = fixed_id();
        let fallback = format!("{id}.bin");
        for bad in [
            "evil.txt:hidden",
            "x:$DATA",
            "CON",
            "nul.txt",
            "COM1",
            "lpt9.log",
            "name.",
            "name ",
            "dir\\aux",
            "C:evil.txt",
            "dir\\x:$DATA",
        ] {
            assert_eq!(safe_basename(bad, id), fallback, "{bad:?} must fall back");
        }
        // Negative controls: near-miss names are not reserved and stay unchanged.
        assert_eq!(safe_basename("console.txt", id), "console.txt");
        assert_eq!(safe_basename("COM10", id), "COM10");
    }

    /// Spaced-stem and console/superscript device spellings the plain stem check missed.
    const SPACED_AND_CONSOLE_DEVICES: [&str; 7] = [
        "nul .txt",
        "con  .log",
        "COM1 .x",
        "conin$",
        "CONOUT$.txt",
        "COM\u{b9}",
        "lpt\u{b3}.txt",
    ];

    #[test]
    fn resolve_download_path_refuses_spaced_stem_and_console_devices() {
        let root = Path::new("C:\\rmt-agent\\transfers");
        for bad in SPACED_AND_CONSOLE_DEVICES {
            assert!(
                resolve_download_path(root, bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(resolve_download_path(root, "dir/con  .log").is_err());
        assert!(resolve_download_path(root, "dir\\con  .log").is_err() || !cfg!(windows));
        for ok in [
            "console.txt",
            "COM10",
            "COM0",
            "nullable.bin",
            "report final.pdf",
            "a b.txt",
        ] {
            assert_eq!(resolve_download_path(root, ok).unwrap(), root.join(ok));
        }
    }

    #[test]
    fn safe_basename_refuses_spaced_stem_and_console_devices() {
        let id = fixed_id();
        let fallback = format!("{id}.bin");
        for bad in SPACED_AND_CONSOLE_DEVICES {
            assert_eq!(safe_basename(bad, id), fallback, "{bad:?} must fall back");
        }
        assert_eq!(safe_basename("dir\\con  .log", id), fallback);
        for ok in [
            "console.txt",
            "COM10",
            "COM0",
            "nullable.bin",
            "report final.pdf",
            "a b.txt",
        ] {
            assert_eq!(safe_basename(ok, id), ok);
        }
    }

    #[test]
    fn flagged_names_are_rejected_by_both_entry_points() {
        let id = fixed_id();
        let root = Path::new("C:\\rmt-agent\\transfers");
        for name in [
            "nul .txt", "con  .log", "COM1 .x", "conin$", "CONOUT$.txt", "COM\u{b2}", "LPT\u{b9}.x",
            "aux", "a:b", "name.", "name ", "com5", "a.txt", "console.txt", "COM10", "a b.txt",
        ] {
            if is_unsafe_windows_name(name) {
                assert!(
                    resolve_download_path(root, name).is_err(),
                    "{name:?} flagged but resolved"
                );
                assert_eq!(safe_basename(name, id), format!("{id}.bin"), "{name:?}");
            }
        }
    }

    #[test]
    fn safe_basename_never_returns_an_unsafe_windows_name() {
        let id = fixed_id();
        for name in [
            "a.bin", "a:b", "x.txt:s", "CON", "Aux.log", "dir\\nul", "dir\\a.bin", "name.",
            "name ", "com5", "LPT3.txt", "console.txt", "COM10", "", "..", "a/b:c", "C:\\x\\y.txt",
        ] {
            let out = safe_basename(name, id);
            assert!(!is_unsafe_windows_name(&out), "{name:?} -> {out:?} is unsafe");
        }
    }
}
