//! Canonical **v1** signing-bytes for backstage grants (H1b).
//!
//! H1 signed `serde_json::to_vec(&GrantClaims)`. That is deterministic *within Rust* but Go's
//! `encoding/json` cannot reproduce those exact bytes (key ordering, number/escape formatting),
//! so a Go control-plane could not mint a grant a Rust agent would verify. H1b replaces the JSON
//! preimage with a **language-agnostic, length-prefixed binary encoding** that Rust and Go build
//! byte-for-byte identically. The [`SignedGrant`](super::grant::SignedGrant) *wire shape* is
//! unchanged (claims JSON + hex sig) — only the bytes that get signed/verified change.
//!
//! # Layout (canonical v1 — big-endian throughout)
//!
//! ```text
//! DOMAIN_TAG                                  // 12 bytes: b"RMTGRANTv1\x00\x00"
//! || technician_id                            // 16 raw bytes (Uuid::as_bytes)
//! || session_id                               // 16 raw bytes
//! || machine_id                               // 16 raw bytes
//! || u32be(capabilities.len())
//! || for each capability, in slice order:
//!        u32be(len(name_utf8)) || name_utf8   // name = canonical snake_case serde string
//! || i64be(issued_at_ms)
//! || i64be(expires_at_ms)
//! ```
//!
//! The 12-byte domain-separation tag prevents this preimage from ever colliding with a different
//! signed message type (the audit chain gets its own tag in H2b). Exact tag bytes (hex):
//! `52 4d 54 47 52 41 4e 54 76 31 00 00` = ASCII `"RMTGRANTv1"` + two `0x00` bytes.

use crate::backstage::rbac::Capability;

/// The 12-byte canonical-v1 domain-separation tag: ASCII `"RMTGRANTv1"` (10 bytes) followed by
/// two `0x00` bytes. Hex: `52 4d 54 47 52 41 4e 54 76 31 00 00`.
pub const DOMAIN_TAG: [u8; 12] = *b"RMTGRANTv1\x00\x00";

/// The 12-byte canonical-**audit**-v1 domain-separation tag: ASCII `"RMTAUDITv1"` (10 bytes)
/// followed by two `0x00` bytes. Hex: `52 4d 54 41 55 44 49 54 76 31 00 00`. It MUST differ from
/// [`DOMAIN_TAG`] so an audit preimage can never collide with a grant preimage (domain separation):
/// changing one byte here re-namespaces every audit hash. Mirrored in Go as `auditDomainTag`.
pub const AUDIT_DOMAIN_TAG: [u8; 12] = *b"RMTAUDITv1\x00\x00";

/// The 12-byte canonical-**session-policy**-v1 domain-separation tag: ASCII `"RMTSPOLv1"` (9 bytes)
/// followed by three `0x00` bytes. Hex: `52 4d 54 53 50 4f 4c 76 31 00 00 00`. It MUST differ from
/// [`DOMAIN_TAG`] and [`AUDIT_DOMAIN_TAG`] so a session-policy preimage can never collide with a
/// backstage-grant or an audit preimage.
///
/// Domain separation is load-bearing here, not decorative: a session policy and a backstage grant are
/// signed by the SAME control-plane Ed25519 identity, and both preimages open with the same three
/// UUIDs (technician, session, machine). Without distinct tags a signature minted over one could be
/// replayed as the other whenever the remaining bytes lined up; the tag makes the two preimage spaces
/// provably disjoint from byte 0. Mirrored in Go as `sessionPolicyDomainTag`, and
/// `tests::domain_tags_are_pairwise_distinct` pins all of this crate's tags apart.
pub const SESSION_POLICY_DOMAIN_TAG: [u8; 12] = *b"RMTSPOLv1\x00\x00\x00";

/// The 12-byte canonical-**elevation**-v1 domain-separation tag: ASCII `"RMTELEVv1"` (9 bytes)
/// followed by three `0x00` bytes. Hex: `52 4d 54 45 4c 45 56 76 31 00 00 00`.
///
/// Same key, same opening three UUIDs, same load-bearing reason as
/// [`SESSION_POLICY_DOMAIN_TAG`] — and here the stake is higher than anywhere else, because an
/// elevation grant is the one artifact in this system that GRANTS rather than restricts (see
/// [`crate::elevation`]). A signature minted over a harmless session policy must never be
/// reinterpretable as authorization to run a command with the guest's full admin token; the tag is
/// what makes those preimage spaces disjoint from byte 0. It diverges from `RMTSPOLv1` at byte 3
/// (`0x45` vs `0x53`). Mirrored in Go as `elevationDomainTag`.
pub const ELEVATION_DOMAIN_TAG: [u8; 12] = *b"RMTELEVv1\x00\x00\x00";

/// The 12-byte canonical-**update**-v1 domain-separation tag: ASCII `"RMTUPDATEv1"` (11 bytes)
/// followed by one `0x00` byte. Hex: `52 4d 54 55 50 44 41 54 45 76 31 00`.
///
/// This tag is different in kind from its four siblings, and the difference is the whole reason
/// [`crate::update`] exists as its own module. The other four preimages are all signed by the
/// control plane's `GrantIssuer` key, and their doc comments argue — correctly, for them — that one
/// key separated by domain tags is the right trade, because the agent then has exactly one public
/// key to pin, provision and rotate. **An update manifest is signed by a DIFFERENT key that never
/// touches the control plane at all** (docs/21 §3, "the most important sentence in this document"),
/// so here the tag is not the thing keeping the artifacts apart: the *keys* are. The tag is defence
/// in depth for the day someone "simplifies" the deployment by reusing the issuer seed — a
/// configuration [`crate::update::UpdateTrust::from_config`] refuses outright.
///
/// Why it still earns its place. If the two keys were ever unified — an operator pasting
/// `grant_issuer_pubkey` into `update_signer_pubkey`, a future minter, a seed copied between `.env`
/// files — then without a distinct tag a signature minted over a *session policy* (the most
/// commonly minted artifact in the system, produced for practically every enforcing session) could
/// be re-presented as a signed instruction naming an executable to install as SYSTEM on every
/// machine in the fleet. That is the worst outcome any collision in this table can produce, which
/// is why it is pinned twice: `tests::update_domain_tag_is_the_documented_bytes` and
/// `tests::domain_tags_are_pairwise_distinct`. Mirrored in Go as `updateDomainTag`.
pub const UPDATE_DOMAIN_TAG: [u8; 12] = *b"RMTUPDATEv1\x00";

/// The 12-byte canonical-**update**-v2 domain-separation tag: ASCII `"RMTUPDATEv2"` (11 bytes)
/// followed by one NUL.
///
/// Format 2 is an MSI-delivering manifest with a different field set, so its preimage must never be
/// reinterpretable as a v1 one (or the reverse) even though both are signed by the SAME update key:
/// a signature over a v1 manifest has to be useless as a v2 one. The distinct tag is what enforces
/// that, on top of the wire format's own `format` discriminator. Mirrored in Go as
/// `updateDomainTagV2`; pinned by `tests::update_v2_domain_tag_is_the_documented_bytes` and
/// `tests::domain_tags_are_pairwise_distinct`.
pub const UPDATE_V2_DOMAIN_TAG: [u8; 12] = *b"RMTUPDATEv2\x00";

/// The canonical snake_case name of a [`Capability`] — the exact string serde's `rename_all =
/// "snake_case"` emits for the variant. This is the on-wire token used both in the claims JSON's
/// `capabilities` array and (length-prefixed) in the canonical signing bytes, so it MUST match
/// serde exactly; `tests::capability_name_matches_serde` asserts that for every variant.
///
/// Every variant is enumerated explicitly (no catch-all) so adding a `Capability` fails to compile
/// until its canonical name is defined here — the same anti-drift discipline the Go side mirrors in
/// `capabilityName`.
pub fn capability_name(cap: Capability) -> &'static str {
    use Capability::*;
    match cap {
        // --- read-only (Tier 1) ---
        ProcessList => "process_list",
        ServiceList => "service_list",
        EventLogRead => "event_log_read",
        FileBrowse => "file_browse",
        FileDownload => "file_download",
        RegistryRead => "registry_read",
        SystemInfoRead => "system_info_read",
        // --- operator (Tier 2) ---
        ServiceControl => "service_control",
        ProcessKill => "process_kill",
        FileUpload => "file_upload",
        ShellAsUser => "shell_as_user",
        // --- admin (Tier 3) ---
        RegistryWrite => "registry_write",
        RegistryHiveLoad => "registry_hive_load",
        ServiceConfig => "service_config",
        FileDelete => "file_delete",
        ShellAsSystem => "shell_as_system",
        ShellAsCredential => "shell_as_credential",
        UninstallProgram => "uninstall_program",
        LocalUserAdmin => "local_user_admin",
    }
}

/// A tiny append-only writer that produces the canonical big-endian, length-prefixed byte stream.
/// Deliberately minimal and allocation-simple so the Go port (`canonicalWriter` in grant.go) is a
/// line-for-line mirror.
#[derive(Default)]
pub struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append the 12-byte grant domain-separation tag.
    pub fn tag(&mut self) -> &mut Self {
        self.buf.extend_from_slice(&DOMAIN_TAG);
        self
    }

    /// Append the 12-byte audit domain-separation tag ([`AUDIT_DOMAIN_TAG`]).
    pub fn audit_tag(&mut self) -> &mut Self {
        self.buf.extend_from_slice(&AUDIT_DOMAIN_TAG);
        self
    }

    /// Append the 12-byte session-policy domain-separation tag ([`SESSION_POLICY_DOMAIN_TAG`]).
    pub fn session_policy_tag(&mut self) -> &mut Self {
        self.buf.extend_from_slice(&SESSION_POLICY_DOMAIN_TAG);
        self
    }

    /// Append the 12-byte elevation domain-separation tag ([`ELEVATION_DOMAIN_TAG`]).
    pub fn elevation_tag(&mut self) -> &mut Self {
        self.buf.extend_from_slice(&ELEVATION_DOMAIN_TAG);
        self
    }

    /// Append the 12-byte update-manifest domain-separation tag ([`UPDATE_DOMAIN_TAG`]).
    pub fn update_tag(&mut self) -> &mut Self {
        self.buf.extend_from_slice(&UPDATE_DOMAIN_TAG);
        self
    }

    /// Append the 12-byte update-manifest **v2** domain-separation tag ([`UPDATE_V2_DOMAIN_TAG`]).
    pub fn update_v2_tag(&mut self) -> &mut Self {
        self.buf.extend_from_slice(&UPDATE_V2_DOMAIN_TAG);
        self
    }

    /// Append a single byte (used for `Option` presence flags and `bool`s: 0 or 1).
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a `u64` big-endian.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append an `i32` big-endian.
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append 16 raw bytes (a UUID's `as_bytes()`).
    pub fn raw16(&mut self, b: &[u8; 16]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Append a `u32` big-endian.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append an `i64` big-endian.
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append `u32be(len)` then the UTF-8 bytes of `s`.
    pub fn lp_str(&mut self, s: &str) -> &mut Self {
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    /// Consume the writer and return the accumulated bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

// =====================================================================================
// Canonical **audit** v1 (H2b) — a language-agnostic preimage for a backstage AuditEvent.
//
// H2 stored the audit chain treating each `hash` as an opaque chain pointer (linkage only). H2b
// lets the Go control-plane RECOMPUTE each event's SHA-256 content hash byte-for-byte, so a
// field-level edit (that keeps the pointers self-consistent) is still detected. This module defines
// the exact preimage both languages hash; `control-plane/audit.go`'s `auditPreimage` is its twin.
//
// Layout (canonical audit v1 — big-endian; `str` = u32be(len) || utf8; `uuid` = 16 raw bytes):
//
//   AUDIT_DOMAIN_TAG                          // 12 bytes: b"RMTAUDITv1\x00\x00"
//   || uuid(id)
//   || u64be(seq)
//   || uuid(session_id) || uuid(technician_id) || uuid(machine_id)
//   || i64be(occurred_at_unix_ms)
//   || canonical(action)                      // str(variant) then fields in decl order (see below)
//   || canonical(outcome)                     // str(variant) then fields in decl order
//   || str(prev_hash)
//
// `hash = lower_hex(SHA256(preimage))`. The preimage covers every content field EXCEPT `hash`.
//
// Per-variant encoding (str(name) then, in declaration order):
//   AuditAction (serde tag "kind"):
//     shell_open            : uuid(shell_id), str(program), <RunAs>(identity)
//     shell_close           : uuid(shell_id), opt_i32(exit_code)      // u8(0)=None | u8(1) i32be(v)
//     shell_data            : uuid(shell_id), <Direction>, u32be(bytes_len), str(redacted_text)
//     file_browse           : str(path)
//     service_control       : str(service), str(verb)
//     service_config_change : str(service), str(before), str(after)
//     process_kill          : u32be(pid), str(image), str(owner)
//     registry_write        : str(path), str(value), opt_str(before), str(after)   // opt_str: u8(0)=None | u8(1) str(s)
//     file_transfer         : <Direction>, str(path), str(sha256), u64be(bytes)
//     file_delete           : str(path)
//     file_create_dir       : str(path)                                // docs/58
//     file_rename           : str(from), str(to)                       // docs/58
//     file_place            : uuid(transfer_id), str(sha256), str(to)  // docs/58
//     credential_use        : str(username), str(domain), str(purpose)
//     consent_signal        : u8(user_notified 0|1), str(policy)
//     input_control_handed  : uuid(from_session), uuid(from_technician), uuid(to_session), uuid(to_technician), u64be(epoch)   // docs/61
//   RunAs (serde tag "as"):     system : () | logged_in_user : str(username) | credential : str(username), str(domain)
//   Direction (unit):           str("input") | str("output")
//   Outcome (serde tag "result"): ok : () | denied : str(reason) | failed : str(error)
// =====================================================================================

use crate::backstage::audit::{AuditAction, Direction, Outcome, RunAs};

/// Canonical name of a [`Direction`] — exactly serde's `rename_all = "snake_case"` string.
pub fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::Input => "input",
        Direction::Output => "output",
    }
}

/// Canonical name of a [`RunAs`] variant — exactly serde's `tag = "as"` value.
pub fn run_as_name(r: &RunAs) -> &'static str {
    match r {
        RunAs::System => "system",
        RunAs::LoggedInUser { .. } => "logged_in_user",
        RunAs::Credential { .. } => "credential",
    }
}

/// Canonical name of an [`AuditAction`] variant — exactly serde's `tag = "kind"` value. Every
/// variant is enumerated (no catch-all) so a new action fails to compile until named here;
/// `tests::audit_variant_names_match_serde` proves each equals the serde string.
pub fn audit_action_name(a: &AuditAction) -> &'static str {
    use AuditAction::*;
    match a {
        ShellOpen { .. } => "shell_open",
        ShellClose { .. } => "shell_close",
        ShellData { .. } => "shell_data",
        FileBrowse { .. } => "file_browse",
        ServiceControl { .. } => "service_control",
        ServiceConfigChange { .. } => "service_config_change",
        ProcessKill { .. } => "process_kill",
        RegistryWrite { .. } => "registry_write",
        FileTransfer { .. } => "file_transfer",
        FileDelete { .. } => "file_delete",
        FileCreateDir { .. } => "file_create_dir",
        FileRename { .. } => "file_rename",
        FilePlace { .. } => "file_place",
        CredentialUse { .. } => "credential_use",
        ConsentSignal { .. } => "consent_signal",
        RecordingStarted { .. } => "recording_started",
        RecordingStopped { .. } => "recording_stopped",
        InputControlHanded { .. } => "input_control_handed",
    }
}

/// Canonical name of an [`Outcome`] variant — exactly serde's `tag = "result"` value.
pub fn outcome_name(o: &Outcome) -> &'static str {
    match o {
        Outcome::Ok => "ok",
        Outcome::Denied { .. } => "denied",
        Outcome::Failed { .. } => "failed",
    }
}

fn encode_direction(w: &mut CanonicalWriter, d: Direction) {
    w.lp_str(direction_name(d));
}

fn encode_run_as(w: &mut CanonicalWriter, r: &RunAs) {
    w.lp_str(run_as_name(r));
    match r {
        RunAs::System => {}
        RunAs::LoggedInUser { username } => {
            w.lp_str(username);
        }
        RunAs::Credential { username, domain } => {
            w.lp_str(username).lp_str(domain);
        }
    }
}

fn encode_action(w: &mut CanonicalWriter, a: &AuditAction) {
    use AuditAction::*;
    w.lp_str(audit_action_name(a));
    match a {
        ShellOpen { shell_id, program, identity } => {
            w.raw16(shell_id.as_bytes()).lp_str(program);
            encode_run_as(w, identity);
        }
        ShellClose { shell_id, exit_code } => {
            w.raw16(shell_id.as_bytes());
            match exit_code {
                None => {
                    w.u8(0);
                }
                Some(c) => {
                    w.u8(1).i32(*c);
                }
            }
        }
        ShellData { shell_id, direction, bytes_len, redacted_text } => {
            w.raw16(shell_id.as_bytes());
            encode_direction(w, *direction);
            w.u32(*bytes_len).lp_str(redacted_text);
        }
        FileBrowse { path } => {
            w.lp_str(path);
        }
        ServiceControl { service, verb } => {
            w.lp_str(service).lp_str(verb);
        }
        ServiceConfigChange { service, before, after } => {
            w.lp_str(service).lp_str(before).lp_str(after);
        }
        ProcessKill { pid, image, owner } => {
            w.u32(*pid).lp_str(image).lp_str(owner);
        }
        RegistryWrite { path, value, before, after } => {
            w.lp_str(path).lp_str(value);
            match before {
                None => {
                    w.u8(0);
                }
                Some(b) => {
                    w.u8(1).lp_str(b);
                }
            }
            w.lp_str(after);
        }
        FileTransfer { direction, path, sha256, bytes } => {
            encode_direction(w, *direction);
            w.lp_str(path).lp_str(sha256).u64(*bytes);
        }
        FileDelete { path } => {
            w.lp_str(path);
        }
        FileCreateDir { path } => {
            w.lp_str(path);
        }
        FileRename { from, to } => {
            w.lp_str(from).lp_str(to);
        }
        FilePlace { transfer_id, sha256, to } => {
            w.raw16(transfer_id.as_bytes()).lp_str(sha256).lp_str(to);
        }
        CredentialUse { username, domain, purpose } => {
            w.lp_str(username).lp_str(domain).lp_str(purpose);
        }
        ConsentSignal { user_notified, policy } => {
            w.u8(if *user_notified { 1 } else { 0 }).lp_str(policy);
        }
        RecordingStarted { started_at_unix_ms, directory } => {
            w.i64(*started_at_unix_ms).lp_str(directory);
        }
        // `segment_sha256` is the first VARIABLE-LENGTH sequence in an audit preimage, so it is
        // length-prefixed exactly the way the grant preimage encodes its capability list:
        // `u32be(count)` then each element as a length-prefixed string, in slice order. Without the
        // count, ["ab","c"] and ["a","bc"] would both be a run of length-prefixed strings that the
        // NEXT field (`directory`) has to disambiguate — and a preimage whose parse depends on what
        // follows it is not canonical. Go's `encodeAuditAction` mirrors this shape byte-for-byte;
        // `audit_golden_recording_vector_v1` and its Go twin pin it.
        RecordingStopped {
            frames,
            payload_bytes,
            truncated,
            dropped_frames,
            segment_sha256,
            directory,
        } => {
            w.u64(*frames).u64(*payload_bytes);
            match truncated {
                None => {
                    w.u8(0);
                }
                Some(t) => {
                    w.u8(1).lp_str(t);
                }
            }
            w.u64(*dropped_frames);
            w.u32(segment_sha256.len() as u32);
            for d in segment_sha256 {
                w.lp_str(d);
            }
            w.lp_str(directory);
        }
        // docs/61. Go's `encodeAuditAction` mirrors this byte-for-byte;
        // `audit_golden_input_control_vector_v1` and its Go twin pin it.
        InputControlHanded { from_session, from_technician, to_session, to_technician, epoch } => {
            w.raw16(from_session.as_bytes())
                .raw16(from_technician.as_bytes())
                .raw16(to_session.as_bytes())
                .raw16(to_technician.as_bytes())
                .u64(*epoch);
        }
    }
}

fn encode_outcome(w: &mut CanonicalWriter, o: &Outcome) {
    w.lp_str(outcome_name(o));
    match o {
        Outcome::Ok => {}
        Outcome::Denied { reason } => {
            w.lp_str(reason);
        }
        Outcome::Failed { error } => {
            w.lp_str(error);
        }
    }
}

/// Build the canonical audit v1 preimage for one event's content fields (everything except its own
/// `hash`). Its SHA-256 lower-hex digest is the event's `hash`. The Go control-plane's
/// `auditPreimage` produces identical bytes for the same event; golden vectors prove it.
#[allow(clippy::too_many_arguments)]
pub fn audit_preimage(
    id: &uuid::Uuid,
    seq: u64,
    session_id: &uuid::Uuid,
    technician_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    occurred_at_unix_ms: i64,
    action: &AuditAction,
    outcome: &Outcome,
    prev_hash: &str,
) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    w.audit_tag()
        .raw16(id.as_bytes())
        .u64(seq)
        .raw16(session_id.as_bytes())
        .raw16(technician_id.as_bytes())
        .raw16(machine_id.as_bytes())
        .i64(occurred_at_unix_ms);
    encode_action(&mut w, action);
    encode_outcome(&mut w, outcome);
    w.lp_str(prev_hash);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_name_matches_serde_for_every_variant() {
        // If serde's rename_all ever drifts from `capability_name`, this fails. Enumerates ALL
        // variants via `Capability::ALL` so a new variant that is added to the enum but not to the
        // ALL list (or to `capability_name`) cannot silently pass.
        for cap in Capability::ALL {
            let serde_str = serde_json::to_value(cap)
                .expect("serialize capability")
                .as_str()
                .expect("capability serializes to a JSON string")
                .to_string();
            assert_eq!(
                capability_name(cap),
                serde_str,
                "capability_name disagrees with serde for {cap:?}"
            );
        }
    }

    #[test]
    fn domain_tag_is_the_documented_bytes() {
        assert_eq!(
            DOMAIN_TAG,
            [0x52, 0x4d, 0x54, 0x47, 0x52, 0x41, 0x4e, 0x54, 0x76, 0x31, 0x00, 0x00]
        );
        assert_eq!(DOMAIN_TAG.len(), 12);
    }

    #[test]
    fn audit_domain_tag_is_the_documented_bytes_and_differs_from_grant() {
        assert_eq!(
            AUDIT_DOMAIN_TAG,
            [0x52, 0x4d, 0x54, 0x41, 0x55, 0x44, 0x49, 0x54, 0x76, 0x31, 0x00, 0x00]
        );
        assert_eq!(AUDIT_DOMAIN_TAG.len(), 12);
        // Domain separation: audit and grant preimages must never share a tag.
        assert_ne!(AUDIT_DOMAIN_TAG, DOMAIN_TAG);
    }

    /// The update tag is the only one in this table signed by a key the control plane never holds,
    /// so drift here does not merely re-namespace a preimage: it makes every agent in the field
    /// reject every manifest the release process signs, and the symptom is "updates stopped
    /// happening" — which nobody notices until a security fix fails to land.
    #[test]
    fn update_domain_tag_is_the_documented_bytes() {
        assert_eq!(
            UPDATE_DOMAIN_TAG,
            [0x52, 0x4d, 0x54, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x76, 0x31, 0x00]
        );
        assert_eq!(UPDATE_DOMAIN_TAG.len(), 12);
        // The split is asserted, not assumed. Every tag in this table is exactly 12 bytes and
        // "RMTUPDATEv1" is the longest name in the set: one character more and the constant would
        // not compile, one fewer and the NUL padding is wrong in a way `assert_eq!` on the array
        // above would catch but nothing would EXPLAIN.
        assert_eq!(&UPDATE_DOMAIN_TAG[..11], b"RMTUPDATEv1");
        assert_eq!(UPDATE_DOMAIN_TAG[11], 0x00);
    }

    /// The v2 tag differs from v1 only in the version digit; both are the same length, so the only
    /// thing keeping a v1 preimage from parsing as a v2 one is that byte.
    #[test]
    fn update_v2_domain_tag_is_the_documented_bytes() {
        assert_eq!(
            UPDATE_V2_DOMAIN_TAG,
            [0x52, 0x4d, 0x54, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x76, 0x32, 0x00]
        );
        assert_eq!(UPDATE_V2_DOMAIN_TAG.len(), 12);
        assert_eq!(&UPDATE_V2_DOMAIN_TAG[..11], b"RMTUPDATEv2");
        assert_eq!(UPDATE_V2_DOMAIN_TAG[11], 0x00);
        assert_ne!(UPDATE_V2_DOMAIN_TAG, UPDATE_DOMAIN_TAG);
    }

    #[test]
    fn elevation_domain_tag_is_the_documented_bytes() {
        assert_eq!(
            ELEVATION_DOMAIN_TAG,
            [0x52, 0x4d, 0x54, 0x45, 0x4c, 0x45, 0x56, 0x76, 0x31, 0x00, 0x00, 0x00]
        );
        assert_eq!(ELEVATION_DOMAIN_TAG.len(), 12);
    }

    /// Every domain tag this crate defines, pairwise distinct — the property the doc comments on
    /// each constant claim and which nothing here asserted until loop 87 (`SESSION_POLICY_DOMAIN_TAG`'s
    /// doc named a `tests::domain_tags_are_pairwise_distinct` that did not exist; the Go side's
    /// `TestDomainTagsArePairwiseDistinct` was the only one).
    ///
    /// Pairwise, not "all different from the grant tag": every one of these preimages is signed by
    /// the SAME Ed25519 identity, so ANY collision between two of them lets a signature over one
    /// artifact be presented as the other. The elevation tag makes that concrete — it is the only
    /// artifact that GRANTS privilege, so it is the one an attacker would want a policy's signature
    /// to be mistaken for.
    #[test]
    fn domain_tags_are_pairwise_distinct() {
        let tags: [(&str, [u8; 12]); 6] = [
            ("grant", DOMAIN_TAG),
            ("audit", AUDIT_DOMAIN_TAG),
            ("session_policy", SESSION_POLICY_DOMAIN_TAG),
            ("elevation", ELEVATION_DOMAIN_TAG),
            // Signed by a DIFFERENT key (docs/21 §3), so a collision here is not immediately
            // exploitable the way the other four are — it becomes exploitable the moment anyone
            // unifies the keys, which is precisely the mistake this table is cheap insurance
            // against. Included for that reason, not because it shares an issuer.
            ("update", UPDATE_DOMAIN_TAG),
            ("update_v2", UPDATE_V2_DOMAIN_TAG),
        ];
        for (i, (na, a)) in tags.iter().enumerate() {
            for (nb, b) in tags.iter().skip(i + 1) {
                assert_ne!(a, b, "domain tags {na} and {nb} collide — signatures become fungible");
            }
        }
    }

    #[test]
    fn audit_variant_names_match_serde() {
        use crate::backstage::audit::{AuditAction, Direction, Outcome, RunAs};
        let u = uuid::Uuid::nil();
        // One instance of EVERY AuditAction variant — the `str(name)` we encode must equal serde's
        // internally-tagged "kind" value, or Go (which reads that JSON string) would diverge.
        let actions = [
            AuditAction::ShellOpen { shell_id: u, program: "p".into(), identity: RunAs::System },
            AuditAction::ShellClose { shell_id: u, exit_code: Some(0) },
            AuditAction::ShellData { shell_id: u, direction: Direction::Input, bytes_len: 0, redacted_text: String::new() },
            AuditAction::FileBrowse { path: "p".into() },
            AuditAction::ServiceControl { service: "s".into(), verb: "v".into() },
            AuditAction::ServiceConfigChange { service: "s".into(), before: "b".into(), after: "a".into() },
            AuditAction::ProcessKill { pid: 1, image: "i".into(), owner: "o".into() },
            AuditAction::RegistryWrite { path: "p".into(), value: "v".into(), before: None, after: "a".into() },
            AuditAction::FileTransfer { direction: Direction::Output, path: "p".into(), sha256: "h".into(), bytes: 0 },
            AuditAction::FileDelete { path: "p".into() },
            AuditAction::FileCreateDir { path: "p".into() },
            AuditAction::FileRename { from: "a".into(), to: "b".into() },
            AuditAction::FilePlace { transfer_id: uuid::Uuid::nil(), sha256: "s".into(), to: "t".into() },
            AuditAction::CredentialUse { username: "u".into(), domain: "d".into(), purpose: "p".into() },
            AuditAction::ConsentSignal { user_notified: true, policy: "p".into() },
            AuditAction::RecordingStarted { started_at_unix_ms: 1, directory: "d".into() },
            AuditAction::RecordingStopped {
                frames: 1,
                payload_bytes: 2,
                truncated: None,
                dropped_frames: 0,
                segment_sha256: vec!["h".into()],
                directory: "d".into(),
            },
            AuditAction::InputControlHanded { from_session: u, from_technician: u, to_session: u, to_technician: u, epoch: 1 },
        ];
        assert_eq!(actions.len(), 18, "every AuditAction variant must be covered");
        for a in &actions {
            let v = serde_json::to_value(a).unwrap();
            assert_eq!(v["kind"].as_str().unwrap(), audit_action_name(a), "action {a:?}");
        }

        for o in &[Outcome::Ok, Outcome::Denied { reason: "r".into() }, Outcome::Failed { error: "e".into() }] {
            let v = serde_json::to_value(o).unwrap();
            assert_eq!(v["result"].as_str().unwrap(), outcome_name(o), "outcome {o:?}");
        }

        for r in &[RunAs::System, RunAs::LoggedInUser { username: "u".into() }, RunAs::Credential { username: "u".into(), domain: "d".into() }] {
            let v = serde_json::to_value(r).unwrap();
            assert_eq!(v["as"].as_str().unwrap(), run_as_name(r), "run_as {r:?}");
        }

        for d in [Direction::Input, Direction::Output] {
            let v = serde_json::to_value(d).unwrap();
            assert_eq!(v.as_str().unwrap(), direction_name(d), "direction {d:?}");
        }
    }
}
