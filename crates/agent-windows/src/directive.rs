//! Fleet directives, agent side (docs/65 stage F4): the crash-safe execution engine.
//!
//! A directive (`reinstall` or `uninstall`) is a control-plane-signed order that reaches the agent over signaling
//! (`rmt_protocol::signaling::ServerToClient::Directive`) or, for an in-session removal, inside `EndSession`. This module
//! owns everything between "an artifact arrived" and "the machine did what it said":
//!
//! * **Verification** is `rmt_protocol::directive::verify_directive` (every golden vector), against the PINNED directive
//!   key ([`crate::directive_pin`]) and this machine's own device id, tenant and enrollment generation. A directive that
//!   does not verify changes NOTHING: no record, no ack, no side effect.
//! * **The operation record** (D-C5) is persisted BEFORE any side effect: directive id, enrollment generation, state
//!   `accepted -> executing -> failed | reboot_pending | complete`, and the acknowledgement steps still owed to the control
//!   plane. The set of record ids IS the single-use ledger, so a directive is refused as a replay the moment it is accepted,
//!   and the ledger survives restarts. A record that cannot be written means the directive is NOT accepted and nothing runs.
//! * **Resume** ([`Engine::drive`]) is idempotent: after a crash it reads the records and reconciles (a reinstall by probing
//!   the update chain, a removal by probing its helper), never repeating a side effect whose outcome it cannot rule out.
//! * **Serialization with auto-update** (D-C5): one directive runs at a time, a directive waits while an update attempt is in
//!   flight, and the update worker in turn refuses to start while a directive is executing ([`in_flight`]).
//! * **Acknowledgements** (D-C8) are signed by the DEVICE key over tenant, device, generation, directive id and the exact
//!   transition, one step at a time, in order, with strictly increasing timestamps; they are retried until the control plane
//!   answers `applied`/`replay` (or terminally `refused`).
//!
//! Every actuating call (the update chain, the removal helper) sits behind [`Actuator`] and the record store behind
//! [`RecordStore`], so tests drive the whole state machine with doubles: nothing in this module touches the machine.

use std::collections::HashSet;
use std::io;

use rmt_crypto::Identity;
use rmt_protocol::directive::{
    self as proto, DirectiveKind, Expectation, Refusal, SignedAck, VerifiedDirective,
};
use serde::{Deserialize, Serialize};

/// Agent-reportable states (a subset of `rmt_protocol::directive::state`).
pub use rmt_protocol::directive::state::{ACCEPTED, COMPLETE, EXECUTING, FAILED, REBOOT_PENDING};

/// Records kept on disk (terminal ones are pruned after their directive expired); a hard cap against a flood.
pub const MAX_RECORDS: usize = 64;
/// Terminal records stay in the ledger for this long after their directive expired.
const LEDGER_GRACE_MS: i64 = 24 * 3_600_000;
const RECORD_PREFIX: &str = "directive-";
const RECORD_SUFFIX: &str = ".json";
const MAX_RECORD_BYTES: usize = 32 * 1024;
/// A resent ack is not repeated sooner than this (the control plane's answer may simply be slow).
pub const ACK_RETRY_MS: i64 = 15_000;

/// `step` values: where inside `executing` the engine is, so a restart knows which side effect may have happened.
pub mod step {
    pub const NONE: &str = "";
    pub const REINSTALL_REQUESTED: &str = "reinstall_requested";
    pub const REMOVAL_LAUNCHING: &str = "removal_launching";
    pub const REMOVAL_STARTED: &str = "removal_started";
}

/// The identity of one sent acknowledgement: the directive and the exact transition. Answers are correlated by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckKey {
    pub directive_id: String,
    pub from: String,
    pub to: String,
    /// The sent ack's timestamp: the request id.
    pub ts_ms: i64,
}

impl AckKey {
    pub fn of(ack: &SignedAck) -> Self {
        Self { directive_id: ack.directive_id.clone(), from: ack.from.clone(), to: ack.to.clone(), ts_ms: ack.ts_ms }
    }
}

/// One acknowledgement owed (or already delivered) for a record: the transition and its human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckStep {
    pub from: String,
    pub to: String,
    pub detail: String,
    /// The control plane answered `applied` or `replay`.
    #[serde(default)]
    pub delivered: bool,
    /// The control plane answered `refused`: terminal, nothing after this step is sent.
    #[serde(default)]
    pub refused: bool,
    /// The timestamps of every send of THIS step (bounded). A timestamp is strictly increasing across the record, so it is a unique
    /// request id: an answer is attributable to this step only if it echoes one of them.
    #[serde(default)]
    pub sent_ts: Vec<i64>,
}

/// The durable operation record (D-C5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpRecord {
    pub v: u32,
    pub directive_id: String,
    pub kind: String,
    pub device_id: String,
    pub tenant_id: String,
    /// The enrollment generation the directive was bound to (SHA-256 of the device public key).
    pub key_fp: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    /// The verified signed artifact, kept so a helper can re-verify it independently.
    pub artifact: String,
    pub state: String,
    #[serde(default)]
    pub step: String,
    pub accepted_ms: i64,
    pub updated_ms: i64,
    #[serde(default)]
    pub detail: String,
    pub acks: Vec<AckStep>,
    #[serde(default)]
    pub last_ack_ts_ms: i64,
}

impl OpRecord {
    pub fn kind(&self) -> Option<DirectiveKind> {
        DirectiveKind::parse(&self.kind)
    }

    /// No further side effect will happen for this record (reboot_pending is final for a removal: the agent that
    /// would confirm it no longer exists; for a reinstall it can still resolve).
    pub fn is_terminal(&self) -> bool {
        match self.state.as_str() {
            FAILED | COMPLETE => true,
            REBOOT_PENDING => self.kind() == Some(DirectiveKind::Uninstall),
            _ => false,
        }
    }

    /// Every ack step is delivered or refused.
    pub fn acks_settled(&self) -> bool {
        // A refused step ends the chain: nothing after it is ever sent, so the steps behind it can never be delivered and
        // must not keep a terminal record (and its ledger slot) alive forever.
        for a in &self.acks {
            if a.refused {
                return true;
            }
            if !a.delivered {
                return false;
            }
        }
        true
    }

    fn push_ack(&mut self, from: &str, to: &str, detail: &str) {
        self.acks.push(AckStep {
            from: from.to_owned(),
            to: to.to_owned(),
            detail: clip(detail, proto::MAX_ACK_DETAIL_BYTES),
            delivered: false,
            refused: false,
            sent_ts: Vec::new(),
        });
    }

    /// Move to `to`, recording the ack owed for the transition. `from` is the state this record is leaving.
    fn transition(&mut self, to: &str, detail: &str, now_ms: i64) {
        let from = std::mem::replace(&mut self.state, to.to_owned());
        self.push_ack(&from, to, detail);
        self.detail = clip(detail, proto::MAX_ACK_DETAIL_BYTES);
        self.updated_ms = now_ms;
    }
}

/// UTF-8-safe clip to at most `max` bytes.
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

// ---------------------------------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------------------------------

/// Where records live. The production store is the anchored agent root ([`AnchorStore`]); tests use memory or a temp dir.
pub trait RecordStore: Send {
    fn load_all(&self) -> io::Result<Vec<OpRecord>>;
    /// Durably replace-or-create. Must not return Ok before the bytes are flushed.
    fn save(&self, rec: &OpRecord) -> io::Result<()>;
    fn remove(&self, directive_id: &str) -> io::Result<()>;
}

fn record_name(id: &str) -> Option<String> {
    // Only canonical UUIDs name a record: the id comes from a verified artifact but is still never trusted as a path.
    uuid::Uuid::parse_str(id).ok().filter(|u| u.hyphenated().to_string() == id)?;
    Some(format!("{RECORD_PREFIX}{id}{RECORD_SUFFIX}"))
}

/// Any record in `root` is a directive operation in flight (accepted or executing): the update worker must not start an
/// update attempt over it (D-C5: operations are serialized with auto-update). Unreadable or malformed records count as
/// "in flight": when in doubt, do not run an update under an unresolved removal.
pub fn in_flight(store: &dyn RecordStore) -> bool {
    match store.load_all() {
        Ok(records) => records.iter().any(|r| !r.is_terminal() && r.state != REBOOT_PENDING),
        Err(_) => true,
    }
}

/// A directive REMOVAL is unresolved (accepted or executing): the update worker must not start an update attempt under it
/// (D-C5). A reinstall directive does not count: it IS the update chain. An unreadable ledger counts as in flight.
pub fn removal_in_flight(store: &dyn RecordStore) -> bool {
    match store.load_all() {
        Ok(records) => records.iter().any(|r| r.kind() != Some(DirectiveKind::Reinstall) && !r.is_terminal()),
        Err(_) => true,
    }
}

/// The production store: records are files in a child directory of the anchored agent root, written atomically with a
/// protected SD, read through handle-relative opens that refuse a swapped-in reparse point or an untrusted file.
pub struct AnchorStore {
    dir: crate::anchor::Dir,
}

/// The agent-root subdirectory holding the records.
pub const RECORDS_DIR: &str = "directives";

impl AnchorStore {
    pub fn open(anchor: &crate::anchor::Anchor) -> io::Result<Self> {
        Ok(Self { dir: anchor.dir().child_dir(RECORDS_DIR, true)? })
    }
}

impl RecordStore for AnchorStore {
    fn load_all(&self) -> io::Result<Vec<OpRecord>> {
        load_all_from(&DirOps(&self.dir))
    }
    fn save(&self, rec: &OpRecord) -> io::Result<()> {
        save_to(&DirOps(&self.dir), rec)
    }
    fn remove(&self, id: &str) -> io::Result<()> {
        let name = record_name(id).ok_or_else(|| io::Error::other("bad directive id"))?;
        self.dir.remove(&name)
    }
}

/// The few directory operations a record store needs, so the encode/decode/validate logic is shared by the anchored
/// store and by the plain-directory store the tests use.
trait FileOps {
    fn list(&self) -> io::Result<Vec<String>>;
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>>;
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()>;
}

struct DirOps<'a>(&'a crate::anchor::Dir);
impl FileOps for DirOps<'_> {
    fn list(&self) -> io::Result<Vec<String>> {
        self.0.list()
    }
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        self.0.read(name, MAX_RECORD_BYTES)
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.0.write_atomic(name, bytes)
    }
}

fn load_all_from(ops: &dyn FileOps) -> io::Result<Vec<OpRecord>> {
    let mut out = Vec::new();
    for name in ops.list()? {
        // Stray temp files of a crashed atomic write are ignored; they are never records.
        let Some(id) = name.strip_prefix(RECORD_PREFIX).and_then(|n| n.strip_suffix(RECORD_SUFFIX)) else {
            continue;
        };
        if record_name(id).as_deref() != Some(name.as_str()) {
            continue;
        }
        let Some(bytes) = ops.read(&name)? else { continue };
        // A record that cannot be understood is an ERROR, not a gap: silently dropping it would drop its ledger entry
        // (re-opening a replay) and its half-finished operation.
        let rec: OpRecord = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::other(format!("directive record {name} is unreadable: {e}")))?;
        if rec.directive_id != id || rec.v != 1 {
            return Err(io::Error::other(format!("directive record {name} does not match its name")));
        }
        out.push(rec);
    }
    out.sort_by(|a, b| (a.accepted_ms, &a.directive_id).cmp(&(b.accepted_ms, &b.directive_id)));
    Ok(out)
}

fn save_to(ops: &dyn FileOps, rec: &OpRecord) -> io::Result<()> {
    let name = record_name(&rec.directive_id).ok_or_else(|| io::Error::other("bad directive id"))?;
    let bytes = serde_json::to_vec(rec).map_err(io::Error::other)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(io::Error::other("directive record too large"));
    }
    ops.write_atomic(&name, &bytes)
}

// ---------------------------------------------------------------------------------------------------
// The actuating seam
// ---------------------------------------------------------------------------------------------------

/// How a requested reinstall is going, as the update chain reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReinstallStatus {
    /// Requested, launched or installing: nothing to report yet.
    InProgress,
    Done,
    /// The chain finished but a reboot is owed before the new files are all in place.
    RebootPending,
    /// Nothing was requested for this directive (a crash after the durable `reinstall_requested` step but before the request
    /// marker was written): the engine REQUESTS AGAIN rather than polling forever.
    NotRequested,
    Failed(String),
}

/// How a launched removal helper is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalStatus {
    /// No helper was ever launched for this directive: launching is safe (nothing has happened yet).
    NotLaunched,
    Running,
    /// The helper is gone. `Some(..)` is the outcome it recorded; `None` means it exited without one.
    Exited(Option<RemovalOutcome>),
}

/// What a removal helper concluded (it reports its own acks; the engine only adopts the outcome after a crash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemovalOutcome {
    Complete,
    RebootPending,
    Failed(String),
}

/// Everything a removal helper needs, captured BEFORE the install is touched: the identity key is deleted with the
/// config directory, so the final signed ack must be producible from this copy (D-C6).
#[derive(Serialize, Deserialize)]
pub struct RemovalHandoff {
    pub v: u32,
    pub directive_id: String,
    pub artifact: String,
    pub device_id: String,
    pub tenant_id: String,
    pub key_fp: String,
    /// The pinned directive key the artifact is re-verified against.
    pub pinned_directive_key: String,
    /// The device identity seed (hex): handed to a SYSTEM-only directory and deleted with it.
    pub identity_seed_hex: String,
    pub accepted_ms: i64,
    pub signaling_url: String,
    /// The control plane origin (`control_plane_url` from the config): the helper delivers its FINAL ack to
    /// `POST {origin}/agent/directives/{id}/final-ack` over HTTPS, because a removed device cannot register (docs/65 section 2b).
    #[serde(default)]
    pub control_plane_url: String,
}

impl std::fmt::Debug for RemovalHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the seed.
        f.debug_struct("RemovalHandoff")
            .field("directive_id", &self.directive_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// The side effects a directive can cause. The production implementation is `directive_win::WinActuator`; a test that used
/// it would reinstall or uninstall the machine it runs on, so tests only ever use doubles.
pub trait Actuator: Send {
    /// An update attempt (or the installer itself) is in flight: do not start a directive over it.
    fn update_busy(&mut self) -> bool;
    /// Take the lock shared with the update worker (one durable lock, held across eligibility check + reservation by BOTH
    /// paths). `None`: the other path holds it, or it could not be taken: do not proceed. Dropping the guard releases it.
    fn acquire_exclusion(&mut self) -> Option<Box<dyn std::any::Any + Send>>;
    /// Ask the existing update chain to reinstall the current signed ring release. No URL comes from the directive.
    fn start_reinstall(&mut self, rec: &OpRecord, now_ms: i64) -> Result<(), String>;
    fn reinstall_status(&mut self, rec: &OpRecord, now_ms: i64) -> ReinstallStatus;
    /// Launch the removal helper (idempotent per directive: a second call for a directive whose helper exists is `Ok`).
    fn start_uninstall(&mut self, handoff: &RemovalHandoff) -> Result<(), String>;
    fn removal_status(&mut self, rec: &OpRecord) -> RemovalStatus;
}

// ---------------------------------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------------------------------

/// What this machine knows about itself.
pub struct EngineContext {
    pub device_id: String,
    pub tenant_id: String,
    /// The enrollment generation: hex SHA-256 of this device's public key.
    pub key_fp: String,
    /// The pinned directive public key; `None` refuses every directive (D-C3).
    pub pinned_key: Option<String>,
    pub signaling_url: String,
    /// The control plane origin (see [`RemovalHandoff::control_plane_url`]).
    pub control_plane_url: String,
}

/// Why a submitted artifact did not start an operation. Only `Busy` and `Deferred` are worth a retry by the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Verified, persisted as `accepted`, will run via [`Engine::drive`].
    Accepted { directive_id: String, kind: DirectiveKind },
    /// Did not verify (or is a replay). Nothing was written or changed.
    Refused(Refusal),
    /// An in-session path asked for a kind it may not carry (only a signed UNINSTALL authorizes removal).
    WrongKind,
    /// Another directive is still active; this one was not persisted so the control plane can deliver it again.
    Busy,
    /// The record store could not be read or written: fail closed, nothing runs.
    StoreFailed(String),
}

pub struct Engine {
    ctx: EngineContext,
    identity: Identity,
    store: Box<dyn RecordStore>,
    actuator: Box<dyn Actuator>,
    clock: Box<dyn Fn() -> i64 + Send>,
}

fn system_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Engine {
    pub fn new(ctx: EngineContext, identity: Identity, store: Box<dyn RecordStore>, actuator: Box<dyn Actuator>) -> Self {
        Self { ctx, identity, store, actuator, clock: Box::new(system_now_ms) }
    }

    /// Replace the clock (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Verify `artifact` and, if it passes, persist it as `accepted` BEFORE anything else happens. `only` restricts the kind
    /// (the in-session path accepts only an uninstall). The directive id enters the single-use ledger by being persisted.
    pub fn submit(&mut self, artifact: &str, only: Option<DirectiveKind>) -> SubmitOutcome {
        let now = self.now();
        let records = match self.store.load_all() {
            Ok(r) => r,
            Err(e) => return SubmitOutcome::StoreFailed(e.to_string()),
        };
        let seen: HashSet<&str> = records.iter().map(|r| r.directive_id.as_str()).collect();
        let verified: VerifiedDirective = match proto::verify_directive(
            self.ctx.pinned_key.as_deref(),
            artifact,
            &Expectation {
                device_id: &self.ctx.device_id,
                tenant_id: &self.ctx.tenant_id,
                key_fp: &self.ctx.key_fp,
                now_ms: now,
            },
            &|id: &str| seen.contains(id),
        ) {
            Ok(v) => v,
            Err(r) => return SubmitOutcome::Refused(r),
        };
        if only.is_some_and(|k| k != verified.kind) {
            return SubmitOutcome::WrongKind;
        }
        // One operation at a time. Not persisted: the control plane renotifies a directive it has not seen acknowledged.
        if records.iter().any(|r| !r.is_terminal() && r.state != REBOOT_PENDING) {
            return SubmitOutcome::Busy;
        }
        if records.len() >= MAX_RECORDS {
            return SubmitOutcome::StoreFailed("directive ledger is full".into());
        }
        let c = verified.claims;
        let mut rec = OpRecord {
            v: 1,
            directive_id: c.directive_id.clone(),
            kind: c.kind.clone(),
            device_id: c.device_id.clone(),
            tenant_id: c.tenant_id.clone(),
            key_fp: c.key_fp.clone(),
            issued_at_ms: c.issued_at_ms,
            expires_at_ms: c.expires_at_ms,
            artifact: artifact.to_owned(),
            state: ACCEPTED.to_owned(),
            step: step::NONE.to_owned(),
            accepted_ms: now,
            updated_ms: now,
            detail: String::new(),
            acks: Vec::new(),
            last_ack_ts_ms: 0,
        };
        rec.acks.push(AckStep {
            from: proto::state::ISSUED.to_owned(),
            to: ACCEPTED.to_owned(),
            detail: String::new(),
            delivered: false,
            refused: false,
            sent_ts: Vec::new(),
        });
        if let Err(e) = self.store.save(&rec) {
            return SubmitOutcome::StoreFailed(e.to_string());
        }
        SubmitOutcome::Accepted { directive_id: c.directive_id, kind: verified.kind }
    }

    /// Advance the active record as far as it can go without waiting. Idempotent: safe to call on a timer and after a
    /// restart (this IS the resume path). Returns a one-line summary per state change, for the log.
    pub fn drive(&mut self) -> Vec<String> {
        let mut log = Vec::new();
        let now = self.now();
        let records = match self.store.load_all() {
            Ok(r) => r,
            Err(e) => return vec![format!("directive records unreadable: {e}")],
        };
        for rec in records.into_iter().filter(|r| !r.is_terminal()) {
            // reboot_pending only matters for a reinstall that can still resolve.
            if rec.state == REBOOT_PENDING && rec.kind() != Some(DirectiveKind::Reinstall) {
                continue;
            }
            let id = rec.directive_id.clone();
            let parked = rec.state == REBOOT_PENDING;
            if let Some(line) = self.drive_one(rec, now) {
                log.push(format!("directive {id}: {line}"));
            }
            // A reboot_pending reinstall is parked (submit admits a new directive over it): it is polled so it can still
            // resolve, but it never consumes the one-active-operation turn, or it would starve a newer accepted directive
            // (its expiry, its start) for as long as the reboot stays owed.
            if parked {
                continue;
            }
            // One active operation at a time.
            break;
        }
        self.prune(now);
        log
    }

    fn save(&mut self, rec: &OpRecord) -> bool {
        self.store.save(rec).is_ok()
    }

    fn fail(&mut self, mut rec: OpRecord, detail: &str, now: i64) -> Option<String> {
        rec.transition(FAILED, detail, now);
        // Even if this save fails nothing more can be done; the next drive retries the same transition.
        let _ = self.save(&rec);
        Some(format!("failed: {detail}"))
    }

    fn drive_one(&mut self, mut rec: OpRecord, now: i64) -> Option<String> {
        let Some(kind) = rec.kind() else {
            return self.fail(rec, "unknown directive kind in record", now);
        };
        match rec.state.as_str() {
            ACCEPTED => {
                if now >= rec.expires_at_ms {
                    return self.fail(rec, "expired before it could run", now);
                }
                // MUTUAL EXCLUSION with auto-update (D-C5): the eligibility check and the reservation (the durable `executing`
                // record) happen under ONE lock that the update worker also takes around its own check-and-reserve, so the two
                // paths cannot both pass their checks and then both proceed. Held until the reservation is saved.
                let Some(_exclusion) = self.actuator.acquire_exclusion() else {
                    return None; // the other path is deciding right now: try again on the next drive
                };
                if self.actuator.update_busy() {
                    return None; // serialized with auto-update: wait
                }
                // executing is durable BEFORE the side effect it announces.
                rec.transition(EXECUTING, "", now);
                rec.step = match kind {
                    DirectiveKind::Reinstall => step::REINSTALL_REQUESTED,
                    DirectiveKind::Uninstall => step::REMOVAL_LAUNCHING,
                }
                .to_owned();
                if !self.save(&rec) {
                    return None; // nothing happened; the next drive retries from accepted
                }
                match kind {
                    DirectiveKind::Reinstall => self.run_side_effect(rec, kind, now),
                    // A removal first waits for the control plane to have the chain up to `executing` (see poll_removal).
                    DirectiveKind::Uninstall => Some("executing; waiting for the control plane to confirm it".into()),
                }
            }
            EXECUTING | REBOOT_PENDING => match (kind, rec.step.as_str()) {
                (DirectiveKind::Reinstall, step::REINSTALL_REQUESTED) => self.poll_reinstall(rec, now),
                (DirectiveKind::Uninstall, step::REMOVAL_LAUNCHING | step::REMOVAL_STARTED) => {
                    self.poll_removal(rec, now)
                }
                // An executing record with no recognisable step: the safe reading is that a side effect MAY have
                // happened and cannot be proven not to have, so report failure rather than repeat it.
                _ => self.fail(rec, "interrupted in an unknown step", now),
            },
            _ => None,
        }
    }

    fn run_side_effect(&mut self, mut rec: OpRecord, kind: DirectiveKind, now: i64) -> Option<String> {
        match kind {
            DirectiveKind::Reinstall => match self.actuator.start_reinstall(&rec, now) {
                Ok(()) => Some("reinstall requested from the update chain".into()),
                Err(e) => self.fail(rec, &format!("reinstall not started: {e}"), now),
            },
            DirectiveKind::Uninstall => {
                let handoff = RemovalHandoff {
                    v: 1,
                    directive_id: rec.directive_id.clone(),
                    artifact: rec.artifact.clone(),
                    device_id: rec.device_id.clone(),
                    tenant_id: rec.tenant_id.clone(),
                    key_fp: rec.key_fp.clone(),
                    pinned_directive_key: self.ctx.pinned_key.clone().unwrap_or_default(),
                    identity_seed_hex: hex::encode(self.identity.seed()),
                    accepted_ms: rec.accepted_ms,
                    signaling_url: self.ctx.signaling_url.clone(),
                    control_plane_url: self.ctx.control_plane_url.clone(),
                };
                match self.actuator.start_uninstall(&handoff) {
                    Ok(()) => {
                        rec.step = step::REMOVAL_STARTED.to_owned();
                        rec.updated_ms = now;
                        let _ = self.save(&rec);
                        Some("removal helper launched".into())
                    }
                    Err(e) => self.fail(rec, &format!("removal not started: {e}"), now),
                }
            }
        }
    }

    fn poll_reinstall(&mut self, mut rec: OpRecord, now: i64) -> Option<String> {
        match self.actuator.reinstall_status(&rec, now) {
            ReinstallStatus::InProgress => {
                if now >= rec.expires_at_ms + LEDGER_GRACE_MS {
                    return self.fail(rec, "the update chain never finished the reinstall", now);
                }
                None
            }
            ReinstallStatus::Done => {
                rec.transition(COMPLETE, "reinstalled", now);
                let _ = self.save(&rec);
                Some("complete".into())
            }
            ReinstallStatus::RebootPending => {
                if rec.state == REBOOT_PENDING {
                    return None;
                }
                rec.transition(REBOOT_PENDING, "a reboot is required to finish", now);
                let _ = self.save(&rec);
                Some("reboot_pending".into())
            }
            ReinstallStatus::NotRequested => {
                if now >= rec.expires_at_ms {
                    return self.fail(rec, "the reinstall request was never made before the directive expired", now);
                }
                // start_reinstall is idempotent per directive, so asking again can never launch a second attempt.
                self.run_side_effect(rec, DirectiveKind::Reinstall, now)
            }
            ReinstallStatus::Failed(why) => self.fail(rec, &why, now),
        }
    }

    fn poll_removal(&mut self, mut rec: OpRecord, now: i64) -> Option<String> {
        match self.actuator.removal_status(&rec) {
            RemovalStatus::Running => {
                if rec.step != step::REMOVAL_STARTED {
                    rec.step = step::REMOVAL_STARTED.to_owned();
                    let _ = self.save(&rec);
                }
                None
            }
            // Launching was recorded but no helper exists: nothing has been touched, so launching is safe, PROVIDED the
            // control plane has the chain up to `executing`. The helper's own acks start from `executing` and the agent
            // that would have delivered the earlier ones is about to be removed, so an unconfirmed chain is waited for
            // (bounded by the directive's own expiry); a chain the control plane REFUSED means it no longer tracks this
            // directive (cancelled, expired): removing the machine then would act against the control plane's record.
            RemovalStatus::NotLaunched => {
                // Expiry is checked immediately before the FIRST launch whether or not the chain is confirmed: a directive that
                // waited out its lifetime (offline, acks pending, a crash) must not start a removal the control plane no longer stands
                // behind. The helper re-checks freshness itself before its first destructive action.
                if now >= rec.expires_at_ms {
                    return self.fail(rec, "expired before the removal could start", now);
                }
                if rec.acks.iter().any(|a| a.refused) {
                    return self.fail(rec, "the control plane refused the acknowledgement chain; not removing", now);
                }
                if !rec.acks.iter().all(|a| a.delivered) {
                    if now >= rec.expires_at_ms {
                        return self.fail(rec, "expired before the control plane confirmed the chain", now);
                    }
                    return None;
                }
                self.run_side_effect(rec, DirectiveKind::Uninstall, now)
            }
            // We are still running, so the product is still installed: the helper did not finish the removal.
            RemovalStatus::Exited(outcome) => {
                let detail = match outcome {
                    Some(RemovalOutcome::Failed(why)) => why,
                    Some(RemovalOutcome::RebootPending) => {
                        rec.transition(REBOOT_PENDING, "removal needs a reboot", now);
                        let _ = self.save(&rec);
                        return Some("reboot_pending".into());
                    }
                    // Only reachable when the product survived: report honestly rather than "complete".
                    Some(RemovalOutcome::Complete) => "the helper reported completion but the product is still installed".into(),
                    None => "the removal helper exited without a result".into(),
                };
                self.fail(rec, &detail, now)
            }
        }
    }

    fn prune(&mut self, now: i64) {
        let Ok(records) = self.store.load_all() else { return };
        for r in records {
            if r.is_terminal() && r.acks_settled() && now > r.expires_at_ms + LEDGER_GRACE_MS {
                let _ = self.store.remove(&r.directive_id);
            }
        }
    }

    /// The next acknowledgement to put on the wire, signed with the device key, or `None` if nothing is owed. Steps go in
    /// order: a record's later step is never produced before an earlier one is delivered. The timestamp is strictly
    /// increasing per record (the control plane refuses anything not larger than the last it accepted).
    pub fn next_ack(&mut self) -> Option<SignedAck> {
        let now = self.now();
        let records = self.store.load_all().ok()?;
        for mut rec in records {
            let Some(idx) = rec.acks.iter().position(|a| !a.delivered && !a.refused) else { continue };
            // A refused step ends the chain for this record.
            if rec.acks[..idx].iter().any(|a| a.refused) {
                continue;
            }
            let step = rec.acks[idx].clone();
            let ts = now.max(rec.last_ack_ts_ms + 1);
            let signed = proto::sign_ack(
                &self.identity,
                &rec.tenant_id,
                &rec.device_id,
                &rec.directive_id,
                &rec.key_fp,
                &step.from,
                &step.to,
                ts,
                &step.detail,
            )
            .ok()?;
            rec.last_ack_ts_ms = ts;
            rec.acks[idx].sent_ts.push(ts);
            if rec.acks[idx].sent_ts.len() > 16 {
                rec.acks[idx].sent_ts.remove(0);
            }
            // Persist the timestamp before the ack leaves, so a restart can never reuse it.
            self.store.save(&rec).ok()?;
            return Some(signed);
        }
        None
    }

    /// The control plane answered a sent ack, identified by the EXACT transition that was sent (`sent`): `applied`/`replay`
    /// settle THAT step, `refused` ends the chain, anything else (`unavailable`) leaves it owed. An answer that names a step
    /// already settled (a delayed duplicate), a step that is not the next outstanding one, or no step at all changes nothing:
    /// a late duplicate `accepted` answer can never settle `executing`.
    pub fn on_ack_result(&mut self, sent: &AckKey, outcome: &str) {
        let Ok(records) = self.store.load_all() else { return };
        let Some(mut rec) = records.into_iter().find(|r| r.directive_id == sent.directive_id) else { return };
        let Some(idx) = rec.acks.iter().position(|a| a.from == sent.from && a.to == sent.to && a.sent_ts.contains(&sent.ts_ms)) else { return };
        if rec.acks[idx].delivered || rec.acks[idx].refused || rec.acks[..idx].iter().any(|a| !a.delivered) {
            return;
        }
        match outcome {
            "applied" | "replay" => rec.acks[idx].delivered = true,
            "refused" => rec.acks[idx].refused = true,
            _ => return,
        }
        let _ = self.store.save(&rec);
    }

    /// Whether any record still owes an ack.
    pub fn acks_owed(&self) -> bool {
        self.store
            .load_all()
            .map(|rs| rs.iter().any(|r| !r.acks_settled() && !r.acks.iter().any(|a| a.refused)))
            .unwrap_or(false)
    }

    pub fn identity_seed_hex(&self) -> String {
        hex::encode(self.identity.seed())
    }

    pub fn records(&self) -> io::Result<Vec<OpRecord>> {
        self.store.load_all()
    }
}


#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;
