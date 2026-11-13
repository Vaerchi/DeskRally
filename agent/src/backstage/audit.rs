//! Tamper-evident audit trail for backstage actions.
//!
//! Every backstage action — read or write — emits an [`AuditEvent`]. Events are hash-chained
//! (each carries the hash of its predecessor) so that any deletion or reordering after the
//! fact is detectable. The agent forwards events to the relay, which persists them per-tenant
//! and can forward to a customer SIEM (see the SQL schema in `migrations/`).
//!
//! Design rules, enforced here:
//!   * Shell sessions record the full transcript **and the token identity the shell ran
//!     under** (SYSTEM vs a named user vs a supplied credential).
//!   * Credential *use* is recorded (which username), the password NEVER is.
//!   * Mutating actions record before/after where feasible.
//!
//! The chain hash is SHA-256 over the **canonical audit v1** binary preimage (see
//! [`crate::backstage::canonical::audit_preimage`]) — a language-agnostic, length-prefixed encoding
//! that the Go control-plane reproduces byte-for-byte, so it can recompute each event's content hash
//! and reject field-level tampering (H2b), not just chain-pointer breaks. Managed agents additionally
//! sign the digest with their enrolled device key; unsigned legacy events prove no agent origin.

use serde::{Deserialize, Serialize};

/// A single audit record. `prev_hash`/`hash` form the tamper-evident chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    /// Monotonic per-session sequence number. Gaps prove tampering even without the hash.
    pub seq: u64,
    pub session_id: uuid::Uuid,
    pub technician_id: uuid::Uuid,
    pub machine_id: uuid::Uuid,
    /// Set by the agent from a monotonic clock; the relay also stamps its own receipt time.
    pub occurred_at_unix_ms: i64,
    pub action: AuditAction,
    /// Outcome of the guard-rail/capability check and the operation itself.
    pub outcome: Outcome,
    /// Hex SHA-256 of the previous event in this session's chain ("" for the first).
    pub prev_hash: String,
    /// Hex SHA-256 of this event's canonical form including `prev_hash`.
    pub hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditAction {
    /// A shell session was opened. The transcript is streamed as `ShellData` records keyed
    /// by `shell_id`; this event captures who/what/where at open time.
    ShellOpen {
        shell_id: uuid::Uuid,
        program: String, // "powershell.exe" | "cmd.exe"
        identity: RunAs,
    },
    ShellClose { shell_id: uuid::Uuid, exit_code: Option<i32> },
    /// A chunk of the shell transcript. `direction` distinguishes technician keystrokes from
    /// program output so the transcript can be replayed faithfully.
    ShellData { shell_id: uuid::Uuid, direction: Direction, bytes_len: u32, redacted_text: String },

    /// A directory was browsed (read-only). The path is recorded; contents are not.
    FileBrowse { path: String },
    ServiceControl { service: String, verb: String },          // start|stop|restart
    ServiceConfigChange { service: String, before: String, after: String },
    ProcessKill { pid: u32, image: String, owner: String },
    RegistryWrite { path: String, value: String, before: Option<String>, after: String },
    FileTransfer { direction: Direction, path: String, sha256: String, bytes: u64 },
    FileDelete { path: String },
    /// A directory was created (docs/58). `path` is the RESOLVED path of the new directory.
    FileCreateDir { path: String },
    /// A file or directory was renamed or moved within one volume (docs/58), resolved paths.
    FileRename { from: String, to: String },
    /// A completed upload was placed out of the transfer root (docs/58): which transfer, the digest
    /// the agent re-verified, and the resolved destination path.
    FilePlace { transfer_id: uuid::Uuid, sha256: String, to: String },
    /// A credential was USED to launch something. Records the principal, never the secret.
    CredentialUse { username: String, domain: String, purpose: String },
    /// Whether the end user was notified/consented, per policy — some jurisdictions require it.
    ConsentSignal { user_notified: bool, policy: String },

    /// A session recording STARTED on the guest's disk (loop 91, docs/01 §5).
    ///
    /// The audit-valuable fact is not the bytes, it is the moment: from here a video of somebody's
    /// screen exists. Recorded even though nothing was produced yet, because the pair
    /// started/stopped is what makes an ABSENT stop visible — a session that ends without one is a
    /// recording that was interrupted, and a trail that only logged completions could not say so.
    RecordingStarted {
        /// Wall clock, ms since the Unix epoch. The recording's own timeline is relative to this
        /// (see `recording::Sidecar`) — durations do not sum to it, because DXGI emits nothing for
        /// an idle desktop.
        started_at_unix_ms: i64,
        /// Where the files are, on the GUEST. Not a URL: nothing was uploaded anywhere.
        directory: String,
    },

    /// A session recording was FINALIZED. This is the audit-valuable half, because it carries the
    /// artifact's DIGESTS — what ties this line to the file somebody later hands over.
    ///
    /// `segment_sha256` is a LIST, not the single `sha256` the loop-90 design note sketched: a
    /// recording rolls to a new IVF file whenever the encoded resolution changes, so a real artifact
    /// is 1..n files and each has its own digest computed over the bytes on disk after finalize. One
    /// rolled-up digest would be uncheckable by a reviewer holding one file, and a single digest of
    /// "the" file would silently describe only the last of them. The list's LENGTH is the segment
    /// count, so no separate `segments` field can disagree with it.
    RecordingStopped {
        /// Frames that reached a file.
        frames: u64,
        /// Encoded payload bytes across every segment (excludes container overhead).
        payload_bytes: u64,
        /// Why it stopped early, or `None` if it ran to completion. **An audit trail that drops this
        /// is worse than none**: a truncated file ends exactly like a complete one, so a reviewer
        /// would take an incomplete record as the whole session.
        truncated: Option<String>,
        /// Frames offered to the recorder that never reached a file. Non-zero only with `truncated`.
        dropped_frames: u64,
        /// Lowercase-hex SHA-256 of each finished segment, in order.
        segment_sha256: Vec<String>,
        /// Where the files are, on the GUEST.
        directory: String,
    },
    /// docs/61: input control was handed to another technician in the same session — or claimed
    /// after the owner left, when `from_*` equals `to_*`. Sealed into BOTH parties' chains, each by its
    /// OWN session task (seal and send are one act on that session's transport), and only after the
    /// hand committed. The ids are the control-plane ones, nil where signaling vouched for none (the
    /// chain's own convention). `epoch` is the arbitration epoch the new owner's input carries.
    InputControlHanded {
        /// The control-plane session that handed (the claimant, for a claim).
        from_session: uuid::Uuid,
        /// Its technician.
        from_technician: uuid::Uuid,
        /// The control-plane session that now owns input.
        to_session: uuid::Uuid,
        /// Its technician.
        to_technician: uuid::Uuid,
        /// The arbitration epoch of the new ownership interval.
        epoch: u64,
    },
}

/// U+0000 cannot be stored in the control plane's `jsonb` audit columns (PostgreSQL rejects it
/// outright), so it is removed from every free-text field before the event is hashed. Replacing
/// rather than dropping keeps the redaction visible in a transcript instead of silently splicing
/// two unrelated characters together.
const NUL_REPLACEMENT: &str = "\u{fffd}";

fn strip_nul_str(s: &mut String) {
    if s.contains('\0') {
        *s = s.replace('\0', NUL_REPLACEMENT);
    }
}

fn strip_nul_opt(s: &mut Option<String>) {
    if let Some(v) = s {
        strip_nul_str(v);
    }
}

impl AuditAction {
    /// Remove U+0000 from every free-text field. Exhaustive by construction: this matches on all
    /// variants with no wildcard arm, so adding a variant with a `String` field fails to compile
    /// here rather than silently reintroducing an unstorable event.
    fn strip_nul(&mut self) {
        match self {
            AuditAction::ShellOpen { program, identity, .. } => {
                strip_nul_str(program);
                identity.strip_nul();
            }
            AuditAction::ShellClose { .. } => {}
            AuditAction::ShellData { redacted_text, .. } => strip_nul_str(redacted_text),
            AuditAction::FileBrowse { path } => strip_nul_str(path),
            AuditAction::ServiceControl { service, verb } => {
                strip_nul_str(service);
                strip_nul_str(verb);
            }
            AuditAction::ServiceConfigChange { service, before, after } => {
                strip_nul_str(service);
                strip_nul_str(before);
                strip_nul_str(after);
            }
            AuditAction::ProcessKill { image, owner, .. } => {
                strip_nul_str(image);
                strip_nul_str(owner);
            }
            AuditAction::RegistryWrite { path, value, before, after } => {
                strip_nul_str(path);
                strip_nul_str(value);
                strip_nul_opt(before);
                strip_nul_str(after);
            }
            AuditAction::FileTransfer { path, sha256, .. } => {
                strip_nul_str(path);
                strip_nul_str(sha256);
            }
            AuditAction::FileDelete { path } => strip_nul_str(path),
            AuditAction::FileCreateDir { path } => strip_nul_str(path),
            AuditAction::FileRename { from, to } => {
                strip_nul_str(from);
                strip_nul_str(to);
            }
            AuditAction::FilePlace { sha256, to, .. } => {
                strip_nul_str(sha256);
                strip_nul_str(to);
            }
            AuditAction::CredentialUse { username, domain, purpose } => {
                strip_nul_str(username);
                strip_nul_str(domain);
                strip_nul_str(purpose);
            }
            AuditAction::ConsentSignal { policy, .. } => strip_nul_str(policy),
            AuditAction::RecordingStarted { directory, .. } => strip_nul_str(directory),
            AuditAction::RecordingStopped { truncated, segment_sha256, directory, .. } => {
                strip_nul_opt(truncated);
                for d in segment_sha256.iter_mut() {
                    strip_nul_str(d);
                }
                strip_nul_str(directory);
            }
            // Ids and an integer only: nothing to strip.
            AuditAction::InputControlHanded { .. } => {}
        }
    }
}

impl RunAs {
    fn strip_nul(&mut self) {
        match self {
            RunAs::System => {}
            RunAs::LoggedInUser { username } => strip_nul_str(username),
            RunAs::Credential { username, domain } => {
                strip_nul_str(username);
                strip_nul_str(domain);
            }
        }
    }
}

impl Outcome {
    fn strip_nul(&mut self) {
        match self {
            Outcome::Ok => {}
            Outcome::Denied { reason } => strip_nul_str(reason),
            Outcome::Failed { error } => strip_nul_str(error),
        }
    }
}

/// The token context an action ran under. Mirrors the shell/impersonation choices in
/// `token.rs`. `Credential` deliberately carries only the principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as", rename_all = "snake_case")]
pub enum RunAs {
    System,
    LoggedInUser { username: String },
    Credential { username: String, domain: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Technician -> machine (keystrokes, uploads).
    Input,
    /// Machine -> technician (program output, downloads).
    Output,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    /// Blocked before execution by capability check or guard rail.
    Denied { reason: String },
    /// Attempted but failed at the OS level.
    Failed { error: String },
}

/// Builds a hash-chained sequence of audit events for one session. Not thread-safe by
/// design — funnel all of a session's events through a single writer task.
pub type AuditSigner = std::sync::Arc<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>;

pub fn audit_signing_bytes(hash: &str) -> Vec<u8> {
    let mut bytes = b"RMT-AUDIT-SIGN-v1\0".to_vec();
    bytes.extend_from_slice(hash.as_bytes());
    bytes
}

pub struct AuditChain {
    session_id: uuid::Uuid,
    technician_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    next_seq: u64,
    last_hash: String,
    signer: Option<(String, AuditSigner)>,
}

impl AuditChain {
    pub fn new(session_id: uuid::Uuid, technician_id: uuid::Uuid, machine_id: uuid::Uuid) -> Self {
        Self { session_id, technician_id, machine_id, next_seq: 0, last_hash: String::new(), signer: None }
    }

    /// The session this chain records.
    pub fn set_signer(&mut self, pubkey: String, signer: AuditSigner) -> bool {
        if self.next_seq != 0 || self.signer.is_some() { return false; }
        self.signer = Some((pubkey, signer));
        true
    }

    pub fn session_id(&self) -> uuid::Uuid {
        self.session_id
    }

    /// Whether this chain knows WHO and WHICH SESSION it is recording.
    ///
    /// Both halves are required and for different reasons. A nil `session_id` would key every
    /// unticketed session on the tenant to the SAME chain, so two concurrent ones would interleave
    /// and fail each other's linkage check. A nil `technician_id` is refused outright by
    /// `POST /audit/ingest`, which compares it to the authenticated forwarder.
    ///
    /// An unidentified chain seals NOTHING (see [`try_record_shared`]) — an event that cannot be
    /// delivered is a `seq` hole, and a hole wedges every later event in the session.
    /// The `seq` the next sealed event will carry — 0 while the chain has recorded nothing.
    ///
    /// Exposed so a test can state the premise it depends on LOCALLY: several `adopt_identity`
    /// refusal arms overlap, and a test that means to exercise the identity arm has to be able to
    /// show the `next_seq != 0` arm is not what actually refused.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn is_identified(&self) -> bool {
        !self.session_id.is_nil() && !self.technician_id.is_nil()
    }

    /// Adopt an identity, once, from a later and equally-trustworthy source. Returns whether it did.
    ///
    /// **Why this exists.** The chain is built at session start from what signaling vouched for, and
    /// on a deployment that does not verify session tickets signaling vouches for nothing. The next
    /// authority to arrive is the backstage GRANT: a control-plane-signed artifact carrying the same
    /// two ids, minted as `Grants.Mint(p.UserID, …)` — the very value `/audit/ingest` will compare
    /// against. Taking the identity from it is not a weaker claim, it is the same claim from the
    /// other channel.
    ///
    /// Refused unless the chain is currently UNIDENTIFIED and has sealed nothing (`next_seq == 0`).
    /// Adopting after an event exists would retroactively disagree with what that event already
    /// says, and the console keys its forwarder off the first event it sees.
    ///
    /// **A ticket-verified `session_id` is never REPLACED, only filled in.** `is_identified()`
    /// requires both halves, so a chain holding a real session id and a nil technician id reads as
    /// "unidentified" — and without the equality check below, the first grant to arrive would
    /// silently rename the trail.
    ///
    /// That half state is ordinary, not exotic: `technician_id` on `brokered` is
    /// `#[serde(default)]` and was added in loop 91, while `control_plane_session` dates from loop
    /// 86, so any signaling server older than the agent sends the session and omits the technician.
    /// The grant's `session_id`, by contrast, is caller-chosen — the console sends a fresh
    /// `crypto.randomUUID()` and the control plane takes `req.SessionID` verbatim, while
    /// `SignedGrant::verify` binds only `machine_id`. So the value being adopted is NOT
    /// equally trustworthy in this direction, and a technician who put a victim's live session id in
    /// their own grant request would have this agent write seq 0 under the victim's id — wedging
    /// that session's chain with events genuinely signed by a real agent.
    ///
    /// Filling in a MISSING half is still allowed, which is what keeps the rolling-upgrade case
    /// working: same session id, plus the technician the grant names.
    pub fn adopt_identity(&mut self, session_id: uuid::Uuid, technician_id: uuid::Uuid) -> bool {
        if self.is_identified() || self.next_seq != 0 || session_id.is_nil() || technician_id.is_nil()
        {
            return false;
        }
        if !self.session_id.is_nil() && self.session_id != session_id {
            return false;
        }
        self.session_id = session_id;
        self.technician_id = technician_id;
        true
    }

    /// Seal an action into the chain. `now_ms` is injected (no ambient clock) so this is
    /// deterministic and testable.
    pub fn record(&mut self, action: AuditAction, outcome: Outcome, now_ms: i64) -> AuditEvent {
        // Strip NUL BEFORE hashing, so the hash covers exactly what can be stored.
        //
        // These strings carry raw OS data — ConPTY transcript bytes, registry values, and
        // `io::Error` text — any of which can contain U+0000. The control plane stores `action`
        // and `outcome` in PostgreSQL `jsonb` columns, and jsonb cannot represent U+0000 at all,
        // while both serde_json and Go's decoder accept it happily. An event carrying one used to
        // hash correctly, verify correctly, and then fail the INSERT — and because this chain is
        // strictly SEQUENTIAL the agent could not skip it, so it re-sent the same batch forever and
        // the session's entire audit trail was never persisted. A stuck chain, not a lost event.
        //
        // Sanitizing here (rather than at the transport) is what makes it safe: the sanitized value
        // is what gets hashed, so the digest still matches the bytes the control plane stores and
        // re-hashes. Sanitizing later would break the chain instead of saving it.
        let mut action = action;
        let mut outcome = outcome;
        action.strip_nul();
        outcome.strip_nul();

        let seq = self.next_seq;
        self.next_seq += 1;
        let id = uuid::Uuid::new_v4();
        let prev_hash = self.last_hash.clone();

        // Canonical audit v1 preimage (see `canonical::audit_preimage`): a language-agnostic,
        // length-prefixed binary encoding of every content field EXCEPT this event's own `hash`, so
        // the Go control-plane can recompute this digest byte-for-byte and detect field-level edits.
        let preimage = crate::backstage::canonical::audit_preimage(
            &id,
            seq,
            &self.session_id,
            &self.technician_id,
            &self.machine_id,
            now_ms,
            &action,
            &outcome,
            &prev_hash,
        );
        let hash = sha256_hex(&preimage);
        self.last_hash = hash.clone();

        let (agent_pubkey, agent_signature) = match &self.signer {
            Some((key, sign)) => (key.clone(), sign(&audit_signing_bytes(&hash)).iter().map(|b| format!("{b:02x}")).collect()),
            None => (String::new(), String::new()),
        };
        AuditEvent {
            id, seq,
            agent_pubkey, agent_signature,
            session_id: self.session_id,
            technician_id: self.technician_id,
            machine_id: self.machine_id,
            occurred_at_unix_ms: now_ms,
            action, outcome, prev_hash, hash,
        }
    }
}

/// One session's [`AuditChain`], shared by every producer in that session.
///
/// **Why this type exists (loop 91).** The chain used to be built inside `Dispatcher::new` from a
/// backstage GRANT, and `host.rs` holds the dispatcher as an `Option`. Two consequences, neither
/// intended, both measured:
///
///  * a session with **no grant had no chain at all** — so ADR-008's file-transfer trail was
///    silently absent for every such session, and session recording (which needs no grant) had
///    nowhere to record; and
///  * installing a SECOND grant replaced the dispatcher wholesale, restarting the chain at `seq 0`
///    — a fork, which the console's forwarder then de-duplicates into oblivion because it keys
///    `seen` on `seq`.
///
/// So the chain's lifetime is now the SESSION's, constructed from the control-plane session id, the
/// technician signaling vouched for, and the agent's own device. A `Dispatcher` borrows it rather
/// than owning it.
///
/// `Mutex` and not `RefCell`: the session future is `Send`. It is never held across an `await` —
/// every producer takes it, seals one event, and drops it — so this is not a place a deadlock can
/// form, and there is no async mutex to justify.
pub type SharedAuditChain = std::sync::Arc<std::sync::Mutex<AuditChain>>;

/// Build a fresh session-scoped chain. `technician_id` is `Uuid::nil()` when signaling vouched for
/// none; the control plane then REFUSES the batch (it compares the id to the authenticated
/// forwarder), which is the intended fail-closed outcome — a local trail and no false central one.
pub fn new_shared_chain(
    session_id: uuid::Uuid,
    technician_id: uuid::Uuid,
    machine_id: uuid::Uuid,
) -> SharedAuditChain {
    std::sync::Arc::new(std::sync::Mutex::new(AuditChain::new(session_id, technician_id, machine_id)))
}

/// Seal one action into a [`SharedAuditChain`] **only if the chain knows who it is recording**.
///
/// `None` — sealing nothing, consuming no `seq` — when the chain is unidentified. That is the
/// fail-closed direction and it is load-bearing rather than fastidious: an event sealed here could
/// never be forwarded (`/audit/ingest` refuses a nil technician, and the console has no id to post
/// under), and an unforwardable event is a `seq` HOLE that makes `verifyLinkage` reject every later
/// event in the session, permanently. Recording an unshippable event would not add a record; it
/// would destroy the ones that follow it.
pub fn try_record_shared(
    chain: &SharedAuditChain,
    action: AuditAction,
    outcome: Outcome,
    now_ms: i64,
) -> Option<AuditEvent> {
    let mut guard = chain.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !guard.is_identified() {
        return None;
    }
    Some(guard.record(action, outcome, now_ms))
}

/// Seal one action into a [`SharedAuditChain`], unconditionally.
///
/// For producers that already know the chain is identified — chiefly [`super::Dispatcher`], which
/// adopts its own grant's identity when it joins. Prefer [`try_record_shared`] anywhere the chain
/// might not be identified yet.
///
/// Poisoning is recovered from rather than propagated (`into_inner`). A `Mutex` is poisoned when
/// some *other* thread panicked while holding it, and the only state behind this one is a sequence
/// number and a hash — neither can be left inconsistent by a panic, because `AuditChain::record`
/// computes the whole event before it mutates either. Treating poisoning as fatal would mean an
/// unrelated panic anywhere in the session silently ended the audit trail, which is the failure this
/// module exists to make impossible.
pub fn record_shared(
    chain: &SharedAuditChain,
    action: AuditAction,
    outcome: Outcome,
    now_ms: i64,
) -> AuditEvent {
    let mut guard = chain.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.record(action, outcome, now_ms)
}

/// Verify a received chain is intact: sequential seqs and matching hash links.
pub fn verify_chain(events: &[AuditEvent]) -> Result<(), ChainError> {
    let mut expected_prev = String::new();
    for (i, e) in events.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(ChainError::SeqGap { at: i, found: e.seq });
        }
        if e.prev_hash != expected_prev {
            return Err(ChainError::BrokenLink { at: i });
        }
        let preimage = crate::backstage::canonical::audit_preimage(
            &e.id,
            e.seq,
            &e.session_id,
            &e.technician_id,
            &e.machine_id,
            e.occurred_at_unix_ms,
            &e.action,
            &e.outcome,
            &e.prev_hash,
        );
        if sha256_hex(&preimage) != e.hash {
            return Err(ChainError::HashMismatch { at: i });
        }
        expected_prev = e.hash.clone();
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("sequence gap at index {at}: found seq {found}")]
    SeqGap { at: usize, found: u64 },
    #[error("broken hash link at index {at}")]
    BrokenLink { at: usize },
    #[error("hash mismatch at index {at} (event was altered)")]
    HashMismatch { at: usize },
}

/// Hex-encoded SHA-256 of the canonical event preimage. This is the tamper-evident link:
/// changing any field changes the digest, and each event commits to its predecessor's digest
/// via `prev_hash`, so the whole chain is bound. Signing each event with the agent's device
/// key (to also prove *origin*, not just integrity) is a reasonable later hardening step.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    // Shared with control-plane/audit_signature_test.go: zero seed, ASCII "a" digest.
    #[test]
    fn security_audit_signing_golden_vector() {
        let identity = rmt_crypto::Identity::from_seed(&[0u8; 32]);
        let signature: String = identity.sign(&super::audit_signing_bytes(&"a".repeat(64)))
            .iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(signature, "1188b6bed920ebb0370ec49b92b06cf8c1996b5742537c772bef0fd29fcefedea0c36987bafac7957146c54f956474aa0b6c2fded257dc4df725134bb6daa509");
    }

    #[test]
    fn security_audit_signs_domain_separated_digest() {
        let identity = std::sync::Arc::new(rmt_crypto::Identity::generate());
        let public = identity.public();
        let mut chain = super::AuditChain::new(uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let signer = identity.clone();
        assert!(chain.set_signer(identity.public_hex(), std::sync::Arc::new(move |bytes| signer.sign(bytes))));
        let event = chain.record(super::AuditAction::FileBrowse { path: "C:".into() }, super::Outcome::Ok, 1234);
        let bytes: Vec<u8> = (0..event.agent_signature.len()).step_by(2)
            .map(|i| u8::from_str_radix(&event.agent_signature[i..i+2], 16).unwrap()).collect();
        let signature: [u8; 64] = bytes.try_into().unwrap();
        assert!(public.verify(&super::audit_signing_bytes(&event.hash), &signature).is_ok());
        assert!(public.verify(event.hash.as_bytes(), &signature).is_err());
    }

    use super::*;

    fn chain() -> AuditChain {
        AuditChain::new(uuid::Uuid::nil(), uuid::Uuid::nil(), uuid::Uuid::nil())
    }

    #[test]
    fn intact_chain_verifies() {
        let mut c = chain();
        let e0 = c.record(AuditAction::ServiceControl { service: "spooler".into(), verb: "stop".into() }, Outcome::Ok, 1);
        let e1 = c.record(AuditAction::ProcessKill { pid: 42, image: "bad.exe".into(), owner: "u".into() }, Outcome::Ok, 2);
        assert!(verify_chain(&[e0, e1]).is_ok());
    }

    #[test]
    fn tampering_with_an_event_is_detected() {
        let mut c = chain();
        let e0 = c.record(AuditAction::ServiceControl { service: "spooler".into(), verb: "stop".into() }, Outcome::Ok, 1);
        let mut e1 = c.record(AuditAction::ProcessKill { pid: 42, image: "bad.exe".into(), owner: "u".into() }, Outcome::Ok, 2);
        // Attacker edits the killed PID after the fact but can't recompute the whole chain.
        if let AuditAction::ProcessKill { pid, .. } = &mut e1.action { *pid = 1; }
        assert_eq!(verify_chain(&[e0, e1]).unwrap_err(), ChainError::HashMismatch { at: 1 });
    }

    #[test]
    fn hash_is_real_sha256() {
        // Known vector: SHA-256("abc") — proves this is a real digest, not a stand-in.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // And every chain hash is a full 256-bit digest (64 hex chars).
        let mut c = chain();
        let e = c.record(AuditAction::ServiceControl { service: "x".into(), verb: "stop".into() }, Outcome::Ok, 1);
        assert_eq!(e.hash.len(), 64);
    }

    // =====================================================================================
    // GOLDEN CROSS-LANGUAGE AUDIT VECTORS (H2b) — the proof Rust and Go hash identically.
    //
    // The SAME three fixed events are rebuilt in control-plane/audit_test.go
    // (TestAuditGoldenVectorV1). Each event's canonical-audit-v1 preimage hex AND its SHA-256 hash
    // hex are hardcoded below; the Go test asserts the SAME constants. If either side's audit
    // encoder drifts, its hex stops matching. DO NOT change a value here without changing it
    // identically in the Go test.
    //
    //   common: session 11111111-…, technician 22222222-…, machine 33333333-…
    //   A (seq 0, genesis): id 44444444-…, occurred 1730000000000,
    //       action file_browse{path:"C:\\Users\\alice\\Documents"}, outcome ok, prev_hash ""
    //   B (seq 1): id 55555555-…, occurred 1730000001000,
    //       action registry_write{path:"HKLM\\SOFTWARE\\Acme\\Config", value:"Enabled",
    //              before:Some("0"), after:"1"}, outcome denied{reason:"capability_denied"},
    //       prev_hash = A.hash
    //   C (seq 2): id 66666666-…, occurred 1730000002000,
    //       action process_kill{pid:4242, image:"evil.exe", owner:"CORP\\alice"},
    //       outcome failed{error:"access_denied"}, prev_hash = B.hash
    // =====================================================================================
    const GOLDEN_A_PREIMAGE_HEX: &str = "524d5441554449547631000044444444444444444444444444444444000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0914000000000b66696c655f62726f77736500000018433a5c55736572735c616c6963655c446f63756d656e7473000000026f6b00000000";
    const GOLDEN_A_HASH: &str = "9f9ad6566756dd1bac7537dada03baf3e6b0ec799180e6be19c126163d9c63e4";
    const GOLDEN_B_PREIMAGE_HEX: &str = "524d5441554449547631000055555555555555555555555555555555000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0917e80000000e72656769737472795f777269746500000019484b4c4d5c534f4654574152455c41636d655c436f6e66696700000007456e61626c656401000000013000000001310000000664656e696564000000116361706162696c6974795f64656e6965640000004039663961643635363637353664643162616337353337646164613033626166336536623065633739393138306536626531396331323631363364396336336534";
    const GOLDEN_B_HASH: &str = "51e7b2b3ec830d99caa629fb2db8f4536653cef12fe794f14c084546d7cebeb9";
    const GOLDEN_C_PREIMAGE_HEX: &str = "524d5441554449547631000066666666666666666666666666666666000000000000000211111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc091bd00000000c70726f636573735f6b696c6c00001092000000086576696c2e6578650000000a434f52505c616c696365000000066661696c65640000000d6163636573735f64656e6965640000004035316537623262336563383330643939636161363239666232646238663435333636353363656631326665373934663134633038343534366437636562656239";
    const GOLDEN_C_HASH: &str = "9e1dfef64f1a36ef9daf511167197956bc7d8cf01ff222d6d9ed6895910a456b";

    fn golden_event(
        id: &str,
        seq: u64,
        occurred_ms: i64,
        action: AuditAction,
        outcome: Outcome,
        prev_hash: &str,
    ) -> (String, String) {
        let id: uuid::Uuid = id.parse().unwrap();
        let session: uuid::Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let tech: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let mach: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let preimage = crate::backstage::canonical::audit_preimage(
            &id, seq, &session, &tech, &mach, occurred_ms, &action, &outcome, prev_hash,
        );
        let preimage_hex = preimage.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let hash = sha256_hex(&preimage);
        (preimage_hex, hash)
    }

    #[test]
    fn audit_golden_vector_v1() {
        // A — read op (file_browse) + ok, genesis prev_hash.
        let (a_pre, a_hash) = golden_event(
            "44444444-4444-4444-4444-444444444444",
            0,
            1_730_000_000_000,
            AuditAction::FileBrowse { path: "C:\\Users\\alice\\Documents".into() },
            Outcome::Ok,
            "",
        );
        // B — with-fields op (registry_write, Some(before)) + denied, chains onto A.
        let (b_pre, b_hash) = golden_event(
            "55555555-5555-5555-5555-555555555555",
            1,
            1_730_000_001_000,
            AuditAction::RegistryWrite {
                path: "HKLM\\SOFTWARE\\Acme\\Config".into(),
                value: "Enabled".into(),
                before: Some("0".into()),
                after: "1".into(),
            },
            Outcome::Denied { reason: "capability_denied".into() },
            &a_hash,
        );
        // C — process_kill (u32 pid) + failed, chains onto B.
        let (c_pre, c_hash) = golden_event(
            "66666666-6666-6666-6666-666666666666",
            2,
            1_730_000_002_000,
            AuditAction::ProcessKill { pid: 4242, image: "evil.exe".into(), owner: "CORP\\alice".into() },
            Outcome::Failed { error: "access_denied".into() },
            &b_hash,
        );

        // Printed so the constants can be captured on first run (cargo test -- --nocapture).
        eprintln!("GOLDEN_A_PREIMAGE_HEX = {a_pre}");
        eprintln!("GOLDEN_A_HASH         = {a_hash}");
        eprintln!("GOLDEN_B_PREIMAGE_HEX = {b_pre}");
        eprintln!("GOLDEN_B_HASH         = {b_hash}");
        eprintln!("GOLDEN_C_PREIMAGE_HEX = {c_pre}");
        eprintln!("GOLDEN_C_HASH         = {c_hash}");

        assert_eq!(a_pre, GOLDEN_A_PREIMAGE_HEX, "A preimage drift");
        assert_eq!(a_hash, GOLDEN_A_HASH, "A hash drift");
        assert_eq!(b_pre, GOLDEN_B_PREIMAGE_HEX, "B preimage drift");
        assert_eq!(b_hash, GOLDEN_B_HASH, "B hash drift");
        assert_eq!(c_pre, GOLDEN_C_PREIMAGE_HEX, "C preimage drift");
        assert_eq!(c_hash, GOLDEN_C_HASH, "C hash drift");
    }


    // =====================================================================================
    // GOLDEN CROSS-LANGUAGE VECTORS FOR THE RECORDING ACTIONS (loop 91).
    //
    // These exist because the loop-90 design note asserted the opposite — "adding a variant is the
    // whole wire change: no new preimage, no golden vector" — and that was MEASURED false before
    // anything shipped. `control-plane/audit_canonical.go`'s `encodeAuditAction` ends in
    // `default: return fmt.Errorf("unknown audit action kind %q")`, and `verifyLinkage` recomputes
    // every ingested event's hash. So a Rust variant with no Go arm makes the batch a
    // ContentTamperError (400) — and because the chain is strictly sequential the agent can never
    // move past it, so the WHOLE session's trail wedges forever. Exactly the NUL bug's failure mode.
    //
    // The SAME two events are rebuilt in control-plane/audit_test.go (TestAuditGoldenRecordingV1).
    // DO NOT change a value here without changing it identically there.
    //
    //   common: session 11111111-…, technician 22222222-…, machine 33333333-…
    //   R1 (seq 0, genesis): id 77777777-…, occurred 1730000000000,
    //       action recording_started{started_at_unix_ms:1730000000000, directory:"D:\\rec"}
//   The directory carries a real backslash, built from the BYTE rather than written as an
//   escape: a `\\` in this file was silently collapsed to `\r` (a carriage return)
//   by the tooling that wrote it, which would have pinned a golden vector over a path no
//   Windows agent can produce. Same trick as `nul_tests::nul_escape` below, same reason.
    //   R2 (seq 1): id 88888888-…, occurred 1730000060000, action recording_stopped with TWO
    //       segment digests, `truncated: Some("size_limit")` and a non-zero dropped count —
    //       chosen so the vector exercises the Option tag, the u32 count and a multi-element list,
    //       the three shapes a hand-written Go mirror can get wrong while a single-segment clean
    //       recording would still pass.
    // =====================================================================================
    const GOLDEN_R1_PREIMAGE_HEX: &str = "524d5441554449547631000077777777777777777777777777777777000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc091400000000117265636f7264696e675f7374617274656400000192cc09140000000006443a5c726563000000026f6b00000000";
    const GOLDEN_R1_HASH: &str = "d9ae995d1d27cc8c5a9fcb664dcc148f88b24e4fc4826d9cd82d85143519de1c";
    const GOLDEN_R2_PREIMAGE_HEX: &str = "524d5441554449547631000088888888888888888888888888888888000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc09fe60000000117265636f7264696e675f73746f7070656400000000000003910000000000404289010000000a73697a655f6c696d6974000000000000002f000000020000004061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161000000406262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626200000006443a5c726563000000026f6b0000004064396165393935643164323763633863356139666362363634646363313438663838623234653466633438323664396364383264383531343335313964653163";
    const GOLDEN_R2_HASH: &str = "e1bc99fee152ba5ccc91d697003ee2b4d99b81183c40bcfa451af1c9a764a73e";

    // docs/58 file-management kinds. The Go twin is control-plane/audit_file_manage_test.go ::
    // TestAuditGoldenFileManageV1. DO NOT change one without the other.
    const GOLDEN_F1_PREIMAGE_HEX: &str = "524d5441554449547631000055555555555555555555555555555555000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0914000000000f66696c655f6372656174655f64697200000007443a5c776f726b000000026f6b00000000";
    const GOLDEN_F1_HASH: &str = "d502005b67b320a1577b8e12d91b625677a27f2f12fb145f47ab6bb0b32f7271";
    const GOLDEN_F2_PREIMAGE_HEX: &str = "524d5441554449547631000066666666666666666666666666666666000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0917e80000000b66696c655f72656e616d6500000007443a5c776f726b00000008443a5c776f726b32000000026f6b0000004064353032303035623637623332306131353737623865313264393162363235363737613237663266313266623134356634376162366262306233326637323731";
    const GOLDEN_F2_HASH: &str = "e08bd021adb3d34950fe9aed77a0b92db1ec9e986aee05cd1ec6da3986c28b1e";
    const GOLDEN_F3_PREIMAGE_HEX: &str = "524d5441554449547631000099999999999999999999999999999999000000000000000211111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc091bd00000000a66696c655f706c616365aaaaaaaabbbbccccddddeeeeeeeeeeee000000406364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636400000011443a5c776f726b325c746f6f6c2e6578650000000664656e6965640000000d73657373696f6e20656e6465640000004065303862643032316164623364333439353066653961656437376130623932646231656339653938366165653035636431656336646133393836633238623165";
    const GOLDEN_F3_HASH: &str = "1d528b5fda2e5961ac6e8a5d56d9441980d6c37bd43aa1fb2f4453d77d43f0c9";

    /// The three docs/58 kinds, chained: create_dir (genesis) -> rename -> place. Paths are built
    /// from the backslash byte, as in the recording vector, so no escape can be mangled.
    #[test]
    fn audit_golden_file_manage_vector_v1() {
        let bs = char::from(92u8);
        let dir = format!("D:{bs}work");
        let renamed = format!("D:{bs}work2");
        let placed = format!("D:{bs}work2{bs}tool.exe");
        let (f1_pre, f1_hash) = golden_event(
            "55555555-5555-5555-5555-555555555555",
            0,
            1_730_000_000_000,
            AuditAction::FileCreateDir { path: dir.clone() },
            Outcome::Ok,
            "",
        );
        let (f2_pre, f2_hash) = golden_event(
            "66666666-6666-6666-6666-666666666666",
            1,
            1_730_000_001_000,
            AuditAction::FileRename { from: dir.clone(), to: renamed.clone() },
            Outcome::Ok,
            &f1_hash,
        );
        let (f3_pre, f3_hash) = golden_event(
            "99999999-9999-9999-9999-999999999999",
            2,
            1_730_000_002_000,
            AuditAction::FilePlace {
                transfer_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".parse().unwrap(),
                sha256: "cd".repeat(32),
                to: placed,
            },
            Outcome::Denied { reason: "session ended".into() },
            &f2_hash,
        );
        eprintln!("GOLDEN_F1_PREIMAGE_HEX = {f1_pre}");
        eprintln!("GOLDEN_F1_HASH         = {f1_hash}");
        eprintln!("GOLDEN_F2_PREIMAGE_HEX = {f2_pre}");
        eprintln!("GOLDEN_F2_HASH         = {f2_hash}");
        eprintln!("GOLDEN_F3_PREIMAGE_HEX = {f3_pre}");
        eprintln!("GOLDEN_F3_HASH         = {f3_hash}");
        assert_eq!(f1_pre, GOLDEN_F1_PREIMAGE_HEX, "file_create_dir preimage drift");
        assert_eq!(f1_hash, GOLDEN_F1_HASH, "file_create_dir hash drift");
        assert_eq!(f2_pre, GOLDEN_F2_PREIMAGE_HEX, "file_rename preimage drift");
        assert_eq!(f2_hash, GOLDEN_F2_HASH, "file_rename hash drift");
        assert_eq!(f3_pre, GOLDEN_F3_PREIMAGE_HEX, "file_place preimage drift");
        assert_eq!(f3_hash, GOLDEN_F3_HASH, "file_place hash drift");
    }

    #[test]
    fn audit_golden_recording_vector_v1() {
        // A real Windows path, assembled from the byte so no escape can be mangled.
        let dir = format!("D:{}rec", char::from(92u8));
        assert_eq!(dir.len(), 6, "the directory must be D:\rec, not a control character");
        let (r1_pre, r1_hash) = golden_event(
            "77777777-7777-7777-7777-777777777777",
            0,
            1_730_000_000_000,
            AuditAction::RecordingStarted {
                started_at_unix_ms: 1_730_000_000_000,
                directory: dir.clone(),
            },
            Outcome::Ok,
            "",
        );
        let (r2_pre, r2_hash) = golden_event(
            "88888888-8888-8888-8888-888888888888",
            1,
            1_730_000_060_000,
            AuditAction::RecordingStopped {
                frames: 913,
                payload_bytes: 4_211_337,
                truncated: Some("size_limit".into()),
                dropped_frames: 47,
                segment_sha256: vec![
                    "aa".repeat(32),
                    "bb".repeat(32),
                ],
                directory: dir.clone(),
            },
            Outcome::Ok,
            &r1_hash,
        );

        eprintln!("GOLDEN_R1_PREIMAGE_HEX = {r1_pre}");
        eprintln!("GOLDEN_R1_HASH         = {r1_hash}");
        eprintln!("GOLDEN_R2_PREIMAGE_HEX = {r2_pre}");
        eprintln!("GOLDEN_R2_HASH         = {r2_hash}");

        assert_eq!(r1_pre, GOLDEN_R1_PREIMAGE_HEX, "recording_started preimage drift");
        assert_eq!(r1_hash, GOLDEN_R1_HASH, "recording_started hash drift");
        assert_eq!(r2_pre, GOLDEN_R2_PREIMAGE_HEX, "recording_stopped preimage drift");
        assert_eq!(r2_hash, GOLDEN_R2_HASH, "recording_stopped hash drift");
    }

    // docs/61 input_control_handed. The Go twin is control-plane/audit_input_control_test.go ::
    // TestAuditGoldenInputControlV1. DO NOT change one without the other.
    //   H1 (seq 0): a hand from session 4444… (technician 2222…) to session 5555… (technician 6666…),
    //       epoch 3 — four DISTINCT uuids, so a Go mirror that swapped two fields cannot pass.
    //   H2 (seq 1): a claim after the owner left (from == to), epoch 5, chained onto H1.
    const GOLDEN_H1_PREIMAGE_HEX: &str = "524d54415544495476310000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc09140000000014696e7075745f636f6e74726f6c5f68616e646564444444444444444444444444444444442222222222222222222222222222222255555555555555555555555555555555666666666666666666666666666666660000000000000003000000026f6b00000000";
    const GOLDEN_H1_HASH: &str = "4e25a93e06cbe1993f6e4e9647f6e26f1d8c58bd8d1bef484b554f8c6b539f09";
    const GOLDEN_H2_PREIMAGE_HEX: &str = "524d54415544495476310000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc09893000000014696e7075745f636f6e74726f6c5f68616e646564555555555555555555555555555555556666666666666666666666666666666655555555555555555555555555555555666666666666666666666666666666660000000000000005000000026f6b0000004034653235613933653036636265313939336636653465393634376636653236663164386335386264386431626566343834623535346638633662353339663039";
    const GOLDEN_H2_HASH: &str = "d17d9fb672512a3a0766f1037fc225be7a9b1928b1d2ec25345631fc97a10a23";
    //   H3 (seq 2): the handing session already LEFT (nil from-ids), non-uniform uuid bytes and an
    //       epoch of 0x0102030405060708, so a uuid byte-order or u64 endianness slip cannot pass.
    const GOLDEN_H3_PREIMAGE_HEX: &str = "524d544155444954763100000f1e2d3c4b5a69788796a5b4c3d2e1f0000000000000000211111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0a739000000014696e7075745f636f6e74726f6c5f68616e646564000000000000000000000000000000000000000000000000000000000000000000112233445566778899aabbccddeefff0e1d2c3b4a5968778695a4b3c2d1e0f0102030405060708000000026f6b0000004064313764396662363732353132613361303736366631303337666332323562653761396231393238623164326563323533343536333166633937613130613233";
    const GOLDEN_H3_HASH: &str = "578425e7d59255e7cafd81f8857d3e6696a7d26326792558f1d3ffa9e77c8b32";

    #[test]
    fn audit_golden_input_control_vector_v1() {
        let u = |s: &str| -> uuid::Uuid { s.parse().unwrap() };
        let (h1_pre, h1_hash) = golden_event(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            0,
            1_730_000_000_000,
            AuditAction::InputControlHanded {
                from_session: u("44444444-4444-4444-4444-444444444444"),
                from_technician: u("22222222-2222-2222-2222-222222222222"),
                to_session: u("55555555-5555-5555-5555-555555555555"),
                to_technician: u("66666666-6666-6666-6666-666666666666"),
                epoch: 3,
            },
            Outcome::Ok,
            "",
        );
        let (h2_pre, h2_hash) = golden_event(
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            1,
            1_730_000_030_000,
            AuditAction::InputControlHanded {
                from_session: u("55555555-5555-5555-5555-555555555555"),
                from_technician: u("66666666-6666-6666-6666-666666666666"),
                to_session: u("55555555-5555-5555-5555-555555555555"),
                to_technician: u("66666666-6666-6666-6666-666666666666"),
                epoch: 5,
            },
            Outcome::Ok,
            &h1_hash,
        );
        let (h3_pre, h3_hash) = golden_event(
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            2,
            1_730_000_090_000,
            AuditAction::InputControlHanded {
                from_session: uuid::Uuid::nil(),
                from_technician: uuid::Uuid::nil(),
                to_session: u("00112233-4455-6677-8899-aabbccddeeff"),
                to_technician: u("f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f"),
                epoch: 0x0102_0304_0506_0708,
            },
            Outcome::Ok,
            &h2_hash,
        );
        eprintln!("GOLDEN_H3_PREIMAGE_HEX = {h3_pre}");
        eprintln!("GOLDEN_H3_HASH         = {h3_hash}");
        eprintln!("GOLDEN_H1_PREIMAGE_HEX = {h1_pre}");
        eprintln!("GOLDEN_H1_HASH         = {h1_hash}");
        eprintln!("GOLDEN_H2_PREIMAGE_HEX = {h2_pre}");
        eprintln!("GOLDEN_H2_HASH         = {h2_hash}");
        assert_eq!(h1_pre, GOLDEN_H1_PREIMAGE_HEX, "input_control_handed preimage drift");
        assert_eq!(h1_hash, GOLDEN_H1_HASH, "input_control_handed hash drift");
        assert_eq!(h2_pre, GOLDEN_H2_PREIMAGE_HEX, "input_control_handed (claim) preimage drift");
        assert_eq!(h2_hash, GOLDEN_H2_HASH, "input_control_handed (claim) hash drift");
        assert_eq!(h3_pre, GOLDEN_H3_PREIMAGE_HEX, "input_control_handed (nil/byte-order) preimage drift");
        assert_eq!(h3_hash, GOLDEN_H3_HASH, "input_control_handed (nil/byte-order) hash drift");
    }

    /// An EMPTY digest list and a one-element list must not hash the same, and neither may collide
    /// with a list whose elements concatenate to the same bytes.
    ///
    /// This is what the `u32be(count)` prefix buys, and it is the assertion that would fail if a Go
    /// mirror wrote the elements without it: `["ab","c"]` and `["a","bc"]` are then the same run of
    /// length-prefixed strings, disambiguated only by whatever follows — a preimage whose parse
    /// depends on its successor is not canonical, and two different artifacts would share a digest.
    #[test]
    fn the_segment_digest_list_is_length_prefixed_not_merely_concatenated() {
        let stopped = |digests: Vec<String>| {
            let mut c = chain();
            c.record(
                AuditAction::RecordingStopped {
                    frames: 1,
                    payload_bytes: 1,
                    truncated: None,
                    dropped_frames: 0,
                    segment_sha256: digests,
                    directory: String::new(),
                },
                Outcome::Ok,
                1,
            )
            .hash
        };
        let empty = stopped(vec![]);
        let one = stopped(vec!["ab".into(), "c".into()]);
        let two = stopped(vec!["a".into(), "bc".into()]);
        assert_ne!(empty, one, "an empty list must not hash like a populated one");
        assert_ne!(
            one, two,
            "two splittings of the same concatenated bytes must not share a digest — the u32 count \
             prefix is what separates them"
        );
    }

    #[test]
    fn deleting_an_event_is_detected() {
        let mut c = chain();
        let e0 = c.record(AuditAction::ServiceControl { service: "a".into(), verb: "stop".into() }, Outcome::Ok, 1);
        let _e1 = c.record(AuditAction::ServiceControl { service: "b".into(), verb: "stop".into() }, Outcome::Ok, 2);
        let e2 = c.record(AuditAction::ServiceControl { service: "c".into(), verb: "stop".into() }, Outcome::Ok, 3);
        // Drop e1 and try to pass off e0,e2: the seq jumps 0 -> 2.
        assert!(verify_chain(&[e0, e2]).is_err());
    }
}

#[cfg(test)]
mod nul_tests {
    use super::*;

    /// The six-character JSON escape for U+0000, built from the byte so this source file never
    /// contains the sequence literally.
    fn nul_escape() -> String {
        format!("{}u0000", char::from(92u8))
    }
    /// A NUL in free text must be gone by the time the event is HASHED. The control plane stores
    /// `action`/`outcome` in `jsonb`, which cannot represent U+0000, so an event carrying one used
    /// to hash fine, verify fine, and then fail the INSERT forever — and because the chain is
    /// strictly sequential the agent could never move past it, losing the whole session's trail.
    #[test]
    fn nul_is_stripped_before_hashing() {
        let mut chain = AuditChain::new(uuid::Uuid::nil(), uuid::Uuid::nil(), uuid::Uuid::nil());
        let e = chain.record(
            AuditAction::ShellData {
                shell_id: uuid::Uuid::nil(),
                direction: Direction::Output,
                bytes_len: 4,
                redacted_text: "a\0b".into(),
            },
            Outcome::Failed { error: "boom\0".into() },
            1,
        );

        let action = serde_json::to_string(&e.action).unwrap();
        let outcome = serde_json::to_string(&e.outcome).unwrap();
        assert!(!action.contains('\0'), "action still carries a NUL: {action}");
        assert!(!outcome.contains('\0'), "outcome still carries a NUL: {outcome}");
        // serde_json escapes NUL as \u0000 on the wire — the exact form PostgreSQL jsonb rejects.
        assert!(!action.contains(nul_escape().as_str()), "action still carries an escaped NUL: {action}");
        assert!(!outcome.contains(nul_escape().as_str()), "outcome still carries an escaped NUL: {outcome}");

        // The surrounding text survives; only the NUL is replaced.
        assert!(action.contains('a') && action.contains('b'));
        assert!(outcome.contains("boom"));

        // And the chain still verifies: the hash was computed over the SANITIZED value, so the
        // digest matches the bytes that will actually be stored. Sanitizing after hashing would
        // have broken the chain instead of saving it.
        verify_chain(&[e]).expect("chain must verify over the sanitized event");
    }

    /// Ordinary control characters are NOT touched: jsonb stores them fine, and shell transcripts
    /// are full of tabs, bells and ANSI escapes that must survive for a faithful replay.
    #[test]
    fn other_control_characters_are_preserved() {
        let mut chain = AuditChain::new(uuid::Uuid::nil(), uuid::Uuid::nil(), uuid::Uuid::nil());
        let e = chain.record(
            AuditAction::FileBrowse { path: "tab\there\u{1b}[0m".into() },
            Outcome::Ok,
            1,
        );
        match &e.action {
            AuditAction::FileBrowse { path } => {
                assert_eq!(path, "tab\there\u{1b}[0m", "an ordinary control character was mangled");
            }
            other => panic!("unexpected action {other:?}"),
        }
    }

    /// Every free-text field is covered, not just the obvious ones.
    #[test]
    fn nul_is_stripped_from_nested_and_optional_fields() {
        let mut open = AuditAction::ShellOpen {
            shell_id: uuid::Uuid::nil(),
            program: "p\0s".into(),
            identity: RunAs::Credential { username: "u\0".into(), domain: "d\0".into() },
        };
        open.strip_nul();
        assert!(!serde_json::to_string(&open).unwrap().contains(nul_escape().as_str()));

        // The recording variants, added in loop 91. `directory` is a real path and `truncated` is a
        // fixed enum string, so neither can carry a NUL today — but `strip_nul`'s match is exhaustive
        // by construction precisely so that stays a property of the DATA rather than a habit. A NUL
        // that did reach jsonb would not lose one event, it would WEDGE the session's whole chain
        // forever: the INSERT fails, the agent cannot skip a sequential event, and it re-sends the
        // same batch until the session ends.
        let mut started = AuditAction::RecordingStarted {
            started_at_unix_ms: 1,
            directory: "D:\0rec".into(),
        };
        started.strip_nul();
        assert!(!serde_json::to_string(&started).unwrap().contains(nul_escape().as_str()));

        let mut stopped = AuditAction::RecordingStopped {
            frames: 1,
            payload_bytes: 1,
            truncated: Some("size\0limit".into()),
            dropped_frames: 0,
            // Every ELEMENT of the list, not just the list: a loop that stripped only the first
            // would pass a single-element test and fail on a two-segment recording.
            segment_sha256: vec!["a\0a".into(), "b\0b".into()],
            directory: String::new(),
        };
        stopped.strip_nul();
        let s = serde_json::to_string(&stopped).unwrap();
        assert!(!s.contains(nul_escape().as_str()), "a NUL survived: {s}");
        assert!(s.contains("size") && s.contains("limit"), "the surrounding text was lost: {s}");

        let mut reg = AuditAction::RegistryWrite {
            path: "HKLM\x5ca\0".into(),
            value: "v\0".into(),
            before: Some("b\0".into()),
            after: "a\0".into(),
        };
        reg.strip_nul();
        assert!(!serde_json::to_string(&reg).unwrap().contains(nul_escape().as_str()));
    }
}
