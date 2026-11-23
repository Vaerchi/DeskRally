//! **Central recording upload** — the agent side (docs/63 stage R2; contracts §2a C1/C2/C9, wire §5.1).
//!
//! A finished local recording (IVF segments + the JSON sidecar written by [`crate::recording`]) is
//! uploaded to the control plane by the SERVICE, never by the user-session helper, so it works with no
//! viewer, after the session ended and across restarts.
//!
//! # Shape
//!
//! * [`UploadState`] — one persisted file per recording under [`STATE_DIR`] (`<recording-id>.json`,
//!   written atomically). It is the durable queue entry: identity it was queued under, the segment list
//!   with digests and file identities, how far each segment is believed committed, the retry schedule
//!   and the terminal outcome. The server is the source of truth for offsets: after any restart the
//!   uploader asks (create replay / HEAD) instead of trusting its own record.
//! * [`UploadApi`] — the four calls of the wire contract. [`crate::recording_upload_http`] is the real
//!   implementation; tests use a scripted fake and a loopback HTTP server.
//! * [`Uploader`] — scans for finished recordings, enqueues them, drives the due ones, classifies every
//!   server answer ([`classify`]) into retry / resync / terminal, and deletes the local files ONLY after
//!   a finish acknowledgement that binds recording id, generation, the exact digest list and status
//!   `evidence_complete` (C9), and only the segments that acknowledgement named.
//!
//! # Trust (review B1–B4)
//!
//! Every directory and file access goes through [`crate::recording_fs`]: in production, handle-relative
//! opens under [`crate::anchor`] with reparse points refused and owner/DACL validated, so the queue
//! directory is trusted only if no non-admin could have written it, and a recording is opened ONCE into a
//! held handle whose file identity was captured at enqueue (hash, chunk reads and the final delete all
//! use that identity). A persisted state is validated in FULL on load ([`validate_state`]): its local
//! directory must be a configured recording root (or a uuid leaf below the broker root), its recording id
//! must be the one derived from (device, directory, stem), and every name must be a single safe component —
//! a state file is never an arbitrary path. Enqueue, the uploader and BOTH local sweeps coordinate through
//! per-recording lock files in the queue directory ([`Lifecycle`]).
//!
//! # What "storage on" means here
//!
//! There is no capability negotiation (docs/63 D1): the tenant's policy is learned per recording from
//! the answer to `create`. `403 storage_off` ends THAT recording as "not stored" (it keeps the normal
//! 72 h local retention) and is not remembered as a preference — the next recording asks again.
//!
//! # Bounds (C9)
//!
//! A pending upload is bounded by age ([`MAX_PENDING_AGE_MS`], 7 days, re-checked between chunks), total
//! queued bytes ([`MAX_PENDING_BYTES`], 5 GiB) and consecutive failures with exponential backoff
//! ([`MAX_CONSECUTIVE_FAILURES`], [`backoff_ms`]). While pending, the local TTL is extended (the sweeps
//! consult [`Lifecycle::claim_for_sweep`]) only until the age bound.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::anchor::FileIdentity;
use crate::recording::{Sidecar, SIDECAR_KIND};
use crate::recording_fs::{DirIo, FsProvider, HeldFile};
use crate::recording_upload_sig::{format_uuid, parse_canonical_uuid};

/// Where queue state lives. Under the hardened agent root, beside (never inside) the recording
/// directories: the CLI broker's storage maintenance refuses unknown files in its leaf directories.
pub const STATE_DIR: &str = r"C:\rmt-agent\recording-uploads";

/// Server chunk size (wire contract §5.1: "every chunk is exactly 1 MiB except the last").
pub const CHUNK_SIZE: u64 = 1 << 20;
/// Server limits the agent checks BEFORE spending a request on a recording that cannot be accepted.
pub const MAX_SEGMENTS: usize = 64;
pub const MAX_SEGMENT_BYTES: u64 = 1 << 30;
/// C9: age bound for a pending upload and for the local-TTL extension.
pub const MAX_PENDING_AGE_MS: i64 = 7 * 24 * 3_600_000;
/// C9: total bytes of pending uploads. A recording that would push the queue past it is not queued.
pub const MAX_PENDING_BYTES: u64 = 5 << 30;
/// C9: consecutive failed attempts before the upload is abandoned (progress resets the count). With
/// the 1 h backoff cap this is a little over two days of continuous failure — well inside the age bound.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 60;
pub const BACKOFF_BASE_MS: i64 = 30_000;
pub const BACKOFF_CAP_MS: i64 = 3_600_000;
/// docs/63 D1: default rate cap, 2 Mbit/s.
pub const DEFAULT_RATE_BYTES_PER_SEC: u64 = 250_000;
/// The server refuses a third digest failure; the agent mirrors the count.
pub const MAX_DIGEST_FAILURES: u32 = 3;
/// How long a terminal state file is kept (it stops a rescan re-queueing a recording whose local files
/// are still there) before it is pruned.
pub const TERMINAL_KEEP_MS: i64 = 14 * 24 * 3_600_000;
const SCAN_ENTRY_LIMIT: usize = 4096;
/// Above this many state entries the uploader starts deleting terminal ones early (see `QueueOps::reclaim_queue`), and a scan stops
/// queueing new recordings at the limit itself, so the queue can always be enumerated completely.
const RECLAIM_HIGH_WATER: usize = SCAN_ENTRY_LIMIT * 3 / 4;
const RECLAIM_LOW_WATER: usize = SCAN_ENTRY_LIMIT / 2;
const RECLAIM_READ_BUDGET: usize = 1024;
const RECLAIM_MAX_ROUNDS: usize = 32;
/// Entries a scan leaves free for the states other paths create.
const ADMISSION_HEADROOM: usize = 64;
const LEAF_LIMIT: usize = 512;
const STATE_READ_MAX: usize = 256 * 1024;
const SIDECAR_READ_MAX: usize = 1024 * 1024;

// ---- persisted state ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Queued or in progress.
    Pending,
    /// The server acknowledged `evidence_complete` bound to our digests.
    Complete,
    /// `403 storage_off` at create time: the tenant does not store recordings centrally (for this one).
    NotStored,
    /// A terminal refusal (server rejection, local file changed, over a bound ...). See `reason`.
    Refused,
    /// Explicitly given up: age, retries, identity change, uninstall. See `reason`.
    Abandoned,
}

impl Status {
    pub fn is_terminal(self) -> bool {
        self != Status::Pending
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentState {
    /// File name relative to the recording directory (validated against the sidecar's stem).
    pub file: String,
    /// Exact byte length of the file when it was queued (this is the length declared to the server).
    pub length: u64,
    /// Lower-case hex sha256 of the finished file: the sidecar's digest, and what finish attests.
    pub sha256: String,
    /// Bytes the server is believed to hold (informational: the server is asked after a restart).
    pub committed: u64,
    /// Volume serial + file id captured when the file was queued: the only file this entry may read or delete.
    pub file_id: Option<FileIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UploadState {
    pub schema: u32,
    pub recording_id: String,
    pub generation: u64,
    // Identity the recording was queued under. A mismatch at drive time (re-enrollment, a new
    // control plane) abandons the upload explicitly (C9).
    pub tenant_id: String,
    pub device_id: String,
    pub key_fp_hex: String,
    pub audience: String,
    pub session_id: String,
    pub local_dir: String,
    pub stem: String,
    /// True when `local_dir` is a leaf created for this recording alone (the CLI broker's layout), so
    /// the empty directory is removed with the files.
    pub leaf_dir: bool,
    /// Identity of the recording directory when it was queued.
    pub dir_id: Option<FileIdentity>,
    /// Identity of the sidecar file when it was queued.
    pub sidecar_id: Option<FileIdentity>,
    pub segments: Vec<SegmentState>,
    pub truncated: Option<String>,
    pub dropped_frames: u64,
    pub frames: u64,
    pub payload_bytes: u64,
    pub ended_at_ms: i64,
    pub enqueued_at_ms: i64,
    pub status: Status,
    pub reason: Option<String>,
    pub finished_at_ms: Option<i64>,
    /// `create` succeeded (or replayed) for this generation.
    pub created: bool,
    /// `len:mtime_ms` of every segment when it last streamed clean against its digest.
    pub verified_sig: Option<String>,
    pub failures: u32,
    pub next_attempt_at_ms: i64,
    pub digest_failures: u32,
    pub last_error: Option<String>,
    /// The digests the server's binding acknowledgement named. Set exactly when `Complete`; it is the
    /// ONLY authority to delete a local segment (each segment whose digest it names).
    pub ack_digests: Option<Vec<String>>,
    /// Local files were removed after completion (idempotent cleanup marker).
    pub local_cleaned: bool,
}

impl UploadState {
    pub fn total_bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.length).sum()
    }
    fn finish_with(&mut self, status: Status, reason: &str, now_ms: i64) {
        self.status = status;
        self.reason = Some(reason.to_string());
        self.finished_at_ms = Some(now_ms);
    }
}

/// The identity a queue entry is made and driven under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadIdentity {
    pub tenant_id: String,
    pub device_id: String,
    pub key_fp_hex: String,
    pub audience: String,
}

/// Where finished recordings are found.
#[derive(Debug, Clone)]
pub enum ScanRoot {
    /// `<dir>/rec-<ms>.json` directly (the helper's `C:\rmt-agent\recordings`).
    Flat(PathBuf),
    /// `<dir>/<uuid>/rec-<ms>.json` (the CLI broker's layout): each child is a leaf for one recording.
    Leaves(PathBuf),
}

fn norm(p: &Path) -> String {
    p.display().to_string().trim_end_matches('\\').to_ascii_lowercase()
}

/// The recording id for a finished recording: deterministic, so a lost state file re-queues the SAME id
/// (create is idempotent per id) instead of uploading a duplicate. Version-5-shaped UUID bits.
pub fn recording_id_for(device_id: &str, dir: &Path, stem: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"RMT-RECORDING-ID-v1\0");
    h.update(device_id.as_bytes());
    h.update([0]);
    h.update(dir.display().to_string().to_ascii_lowercase().as_bytes());
    h.update([0]);
    h.update(stem.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    format_uuid(&b)
}

/// `rec-<digits>`: the only stem the recorder writes.
fn valid_stem(stem: &str) -> bool {
    stem.strip_prefix("rec-").is_some_and(|ms| !ms.is_empty() && ms.len() <= 20 && ms.bytes().all(|c| c.is_ascii_digit()))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Is `dir` a directory this uploader may ever act on, and is `leaf` the right flag for it? A configured flat
/// root as is, or a direct uuid-named child of a configured leaves root.
fn dir_is_allowed(dir: &str, leaf: bool, roots: &[ScanRoot]) -> bool {
    let d = Path::new(dir);
    roots.iter().any(|r| match r {
        ScanRoot::Flat(f) => !leaf && norm(f) == norm(d),
        ScanRoot::Leaves(l) => {
            leaf && d.parent().is_some_and(|p| norm(p) == norm(l))
                && d.file_name().and_then(|n| n.to_str()).is_some_and(|n| uuid::Uuid::parse_str(n).is_ok())
        }
    })
}

/// Validate a loaded state in FULL (B1). A state file is data from disk: nothing in it is trusted as a path,
/// a name, or an authority until it passes this.
pub fn validate_state(st: &UploadState, file_id: &str, roots: &[ScanRoot]) -> Result<(), String> {
    let bad = |m: &str| Err(m.to_string());
    if st.schema != 1 {
        return bad("unknown schema");
    }
    if st.recording_id != file_id || parse_canonical_uuid(&st.recording_id).is_none() {
        return bad("recording id does not match its file name");
    }
    if st.generation == 0 || st.tenant_id.is_empty() || st.tenant_id.len() > 64 || st.device_id.is_empty() || st.device_id.len() > 128 {
        return bad("bad identity fields");
    }
    if !dir_is_allowed(&st.local_dir, st.leaf_dir, roots) {
        return bad("local_dir is not a configured recording directory");
    }
    if !valid_stem(&st.stem) {
        return bad("bad stem");
    }
    if recording_id_for(&st.device_id, Path::new(&st.local_dir), &st.stem) != st.recording_id {
        return bad("recording id is not the one derived from device, directory and stem");
    }
    // A refused-at-birth entry records why a recording was not queued and may carry no usable segments.
    let needs_segments = matches!(st.status, Status::Pending | Status::Complete);
    if st.segments.len() > MAX_SEGMENTS || (needs_segments && st.segments.is_empty()) {
        return bad("bad segment count");
    }
    for s in &st.segments {
        if crate::recording::sweepable_segment(&st.stem, &s.file) != Some(s.file.as_str()) {
            return bad("segment name is not a safe component of this recording");
        }
        if s.length == 0 || s.length > MAX_SEGMENT_BYTES || s.committed > s.length || !is_hex64(&s.sha256) {
            return bad("bad segment fields");
        }
    }
    if st.status == Status::Complete {
        let digests: Vec<&String> = st.segments.iter().map(|s| &s.sha256).collect();
        match &st.ack_digests {
            Some(a) if a.iter().collect::<Vec<_>>() == digests => {}
            _ => return bad("a Complete state must carry the acknowledged digests"),
        }
    }
    Ok(())
}

/// A queue entry's lock file name. A leaf directory holds exactly one recording, so the directory is the key
/// (the CLI broker's budget pass has the directory, not the recording's stem); a flat-root recording is keyed
/// by its id. Enqueue, the uploader, and both sweeps take the same name.
pub fn lock_name(dir: &Path, leaf: bool, device_id: &str, stem: &str) -> String {
    if leaf {
        let h = Sha256::digest(norm(dir).as_bytes());
        format!("d-{}.lock", hex::encode(&h[..16]))
    } else {
        format!("r-{}.lock", recording_id_for(device_id, dir, stem))
    }
}

/// Queue-state store over a trusted directory.
#[derive(Clone)]
pub struct StateStore {
    fs: Arc<dyn FsProvider>,
    dir: PathBuf,
    roots: Vec<ScanRoot>,
}

/// What a full listing of the queue found.
#[derive(Debug, Default)]
pub struct Listing {
    pub states: Vec<UploadState>,
    /// Entries that could not be read or failed validation: never used, but never silently dropped either.
    pub issues: Vec<String>,
    /// The state file id (the `<id>` of `<id>.json`) of each issue, in the same order.
    pub issue_ids: Vec<String>,
}

impl StateStore {
    pub fn new(fs: Arc<dyn FsProvider>, dir: impl Into<PathBuf>, roots: Vec<ScanRoot>) -> Self {
        Self { fs, dir: dir.into(), roots }
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn fs(&self) -> &Arc<dyn FsProvider> {
        &self.fs
    }
    pub fn roots(&self) -> &[ScanRoot] {
        &self.roots
    }
    /// Open the queue directory through the trusted route. In production this FAILS when the directory is
    /// not SYSTEM/Administrators-owned with no non-admin write — so nothing here is trusted from a directory a
    /// non-admin could have written.
    pub fn open(&self, create: bool) -> std::io::Result<Box<dyn DirIo>> {
        self.fs.open(&self.dir, create)
    }
    fn parse(&self, d: &dyn DirIo, id: &str) -> Result<Option<UploadState>, String> {
        let name = format!("{id}.json");
        let bytes = match d.read(&name, STATE_READ_MAX) {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(None),
            Err(e) => return Err(format!("unreadable: {e}")),
        };
        let st: UploadState = serde_json::from_slice(&bytes).map_err(|e| format!("not a queue state: {e}"))?;
        validate_state(&st, id, &self.roots)?;
        Ok(Some(st))
    }
    pub fn load(&self, id: &str) -> Option<UploadState> {
        parse_canonical_uuid(id)?;
        let d = self.open(false).ok()?;
        self.parse(d.as_ref(), id).ok().flatten()
    }
    /// Durable, validated save (atomic write, flushed). The caller must treat an error as "not queued".
    pub fn save(&self, st: &UploadState) -> std::io::Result<()> {
        validate_state(st, &st.recording_id, &self.roots).map_err(std::io::Error::other)?;
        self.open(true)?.write_atomic(&format!("{}.json", st.recording_id), &serde_json::to_vec_pretty(st).map_err(std::io::Error::other)?)
    }
    /// Reload one state fresh from disk (validated). `Ok(None)`: no such entry. `Err`: unreadable or invalid.
    pub fn reload(&self, id: &str) -> std::io::Result<Option<UploadState>> {
        if parse_canonical_uuid(id).is_none() {
            return Err(std::io::Error::other("not a recording id"));
        }
        let d = match self.open(false) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        self.parse(d.as_ref(), id).map_err(std::io::Error::other)
    }
    /// Delete the state file only (the caller holds the recording's lock and reclaims the lock file itself).
    pub fn remove_state(&self, id: &str) -> std::io::Result<()> {
        if parse_canonical_uuid(id).is_none() {
            return Err(std::io::Error::other("not a recording id"));
        }
        self.open(false)?.remove(&format!("{id}.json"))
    }
    /// Every state, or an error when the directory cannot be enumerated completely. A missing queue directory is an
    /// empty queue; anything else (untrusted, unreadable, beyond the entry limit) is an error, never a quiet "nothing".
    pub fn list_checked(&self) -> std::io::Result<Listing> {
        let d = match self.open(false) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Listing::default()),
            Err(e) => return Err(e),
        };
        // Only state files count toward the limit: lock files and the drain fence are bookkeeping, not queue entries
        // (counting them would let sweep claims fill the budget over time).
        let names: Vec<String> = d.list()?.into_iter().filter(|n| n.ends_with(".json")).collect();
        if names.len() > SCAN_ENTRY_LIMIT {
            return Err(std::io::Error::other(format!("the queue directory holds {} entries; refusing a partial enumeration", names.len())));
        }
        let mut out = Listing::default();
        for n in names {
            let Some(id) = n.strip_suffix(".json") else { continue };
            if parse_canonical_uuid(id).is_none() {
                continue;
            }
            match self.parse(d.as_ref(), id) {
                Ok(Some(st)) => out.states.push(st),
                Ok(None) => {}
                Err(why) => {
                    out.issues.push(format!("{n}: {why}"));
                    out.issue_ids.push(id.to_string());
                }
            }
        }
        Ok(out)
    }
    /// Lenient view for callers that only need "what is pending" (never for a decision to delete or to settle).
    pub fn list(&self) -> Vec<UploadState> {
        self.list_checked().map(|l| l.states).unwrap_or_default()
    }
}

/// While alive, the holder owns the lifecycle of one recording (or one leaf directory).
pub struct SweepGuard {
    lock: Option<std::fs::File>,
    dir: Option<Box<dyn DirIo>>,
    name: String,
}

impl SweepGuard {
    /// The recording is gone: release the lock and delete its lock file (best effort; a failure — someone else
    /// took the lock between our release and the delete — leaves the file for that holder, never two files for
    /// one recording, because the name is derived from the recording).
    pub fn reclaim(mut self) {
        drop(self.lock.take());
        if let Some(d) = self.dir.take() {
            let _ = d.remove(&self.name);
        }
    }
}

/// Coordinates the local sweeps with the uploader (B4).
#[derive(Clone)]
pub struct Lifecycle {
    store: StateStore,
}

impl Lifecycle {
    pub fn new(store: StateStore) -> Self {
        Self { store }
    }
    pub fn production() -> Self {
        let cfg = UploaderConfig::production();
        // Unit tests of the sweeps must never open (or create lock files in) the machine's real queue.
        #[cfg(test)]
        let (fs, dir): (Arc<dyn FsProvider>, PathBuf) = (Arc::new(crate::recording_fs::StdFs), std::env::temp_dir().join("rmt-no-upload-queue"));
        #[cfg(not(test))]
        let (fs, dir): (Arc<dyn FsProvider>, PathBuf) = (Arc::new(crate::recording_fs::AnchoredFs), cfg.state_dir.clone());
        Self::new(StateStore::new(fs, dir, cfg.roots))
    }

    /// A local sweep is about to delete the recording `stem` of `device` in `dir` (`stem`/`device` are `None` for the
    /// CLI broker's leaf-directory pass). `Some(guard)`: free to delete while the guard lives — no pending upload holds
    /// it and nobody else (uploader, enqueue, another sweep) is working on it. `None`: HELD — skip it this time. A
    /// queue that cannot be read holds everything: failing to see the queue must never turn into deleting under it.
    pub fn claim_for_sweep(&self, dir: &Path, leaf: bool, stem: Option<&str>, device: Option<&str>, now_ms: i64) -> Option<SweepGuard> {
        // The queue directory is created on first use: the lock below lives in it, and a sweep that raced the first
        // enqueue must still exclude it.
        let d = match self.store.open(true) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "recording sweep: the upload queue cannot be opened; holding every recording");
                return None;
            }
        };
        let name = match (leaf, stem, device) {
            (true, _, _) => lock_name(dir, true, "", ""),
            (false, Some(s), Some(dev)) => lock_name(dir, false, dev, s),
            // A flat-root recording without a known owner cannot be locked: hold it.
            _ => return None,
        };
        let lock = match d.lock(&name) {
            Ok(Some(f)) => f,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "recording sweep: could not take the recording lock; holding it");
                return None;
            }
        };
        let listing = match self.store.list_checked() {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "recording sweep: the upload queue cannot be enumerated; holding every recording");
                return None;
            }
        };
        // An unreadable or invalid queue entry might BE this recording's pending hold. Refuse unless the entry is
        // attributable to a different recording: a flat recording knows its own state id; a leaf directory does not
        // (its id needs the device and stem), so any issue holds a leaf.
        let own_id = match (leaf, stem, device) {
            (false, Some(s), Some(dev)) => Some(recording_id_for(dev, dir, s)),
            _ => None,
        };
        if listing.issue_ids.iter().any(|id| own_id.as_deref().is_none_or(|own| own == id)) {
            tracing::warn!(issues = ?listing.issues, "recording sweep: an unusable queue entry could be this recording's hold; holding it");
            return None;
        }
        let want = norm(dir);
        let held = listing.states.iter().any(|st| {
            st.status == Status::Pending
                && now_ms.saturating_sub(st.enqueued_at_ms) < MAX_PENDING_AGE_MS
                && norm(Path::new(&st.local_dir)) == want
                && stem.is_none_or(|s| s == st.stem)
        });
        if held {
            return None;
        }
        Some(SweepGuard { lock: Some(lock), dir: Some(d), name })
    }
}

// ---- wire abstraction --------------------------------------------------------------------------

/// What the agent identifies a recording by on every call.
#[derive(Debug, Clone, Copy)]
pub struct RecRef<'a> {
    pub recording_id: &'a str,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOk {
    pub state: String,
    pub generation: u64,
    pub chunk_size: u64,
    /// `(index, declared length, committed offset)` per segment, as the server holds them.
    pub segments: Vec<(u32, u64, u64)>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadOk {
    pub committed: u64,
    pub length: u64,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutOk {
    pub committed: u64,
    pub resent: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishReq {
    pub digests: Vec<String>,
    pub truncated: Option<String>,
    pub dropped_frames: u64,
    pub frames: u64,
    pub payload_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishOk {
    pub recording_id: String,
    pub generation: u64,
    pub state: String,
    pub digests: Vec<String>,
}

/// A failed call. `status == 0` means the request never produced an HTTP answer (connect, TLS, timeout,
/// reset): always retryable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiFail {
    pub status: u16,
    /// The server's `error` code, or a short local description for transport failures.
    pub code: String,
    pub retry_after_s: Option<u64>,
    /// `committed_offset` from a 409 `bad_offset`.
    pub committed_offset: Option<u64>,
    /// Segment indexes named by a 409 `incomplete` / 422 `digest_mismatch`.
    pub segments: Vec<u32>,
    /// `state` named by the error body (e.g. a refused recording).
    pub state: Option<String>,
}

impl ApiFail {
    pub fn transport(why: impl Into<String>) -> Self {
        Self { status: 0, code: why.into(), ..Default::default() }
    }
    pub fn http(status: u16, code: &str) -> Self {
        Self { status, code: code.to_string(), ..Default::default() }
    }
}

pub trait UploadApi {
    fn create(&self, r: RecRef<'_>, session_id: &str, lengths: &[u64]) -> Result<CreateOk, ApiFail>;
    fn head(&self, r: RecRef<'_>, segment: u32) -> Result<HeadOk, ApiFail>;
    fn put(&self, r: RecRef<'_>, segment: u32, offset: u64, chunk: &[u8]) -> Result<PutOk, ApiFail>;
    fn finish(&self, r: RecRef<'_>, req: &FinishReq) -> Result<FinishOk, ApiFail>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Head,
    Put,
    Finish,
}

/// What an [`ApiFail`] means for the upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Try again later on the backoff schedule (`min_delay_s` is the server's Retry-After, if any).
    Retry { min_delay_s: Option<u64> },
    /// The upload ends here.
    Terminal { status: Status, reason: String },
    /// `bad_offset` / `chunk_conflict` / `incomplete`: ask the server where each segment stands.
    Resync,
    /// The server has no such recording (404): create it again (idempotent).
    Recreate,
    /// The server already holds a complete recording under this id: go straight to finish (a replay
    /// answers with the stored digests, which must still bind ours).
    GoFinish,
    /// `digest_mismatch`: the named segments were reset to 0 on the server and must be re-sent.
    DigestReset { segments: Vec<u32> },
}

fn terminal(status: Status, reason: &str) -> Disposition {
    Disposition::Terminal { status, reason: reason.to_string() }
}

/// Classify a failed call. Pure and exhaustive over the wire contract's status table (docs/63 §5.1) so
/// every refusal path is one table row, tested as such.
pub fn classify(op: Op, f: &ApiFail) -> Disposition {
    use Disposition::*;
    let retry = || Retry { min_delay_s: f.retry_after_s };
    match (f.status, f.code.as_str()) {
        (0, _) => retry(),
        // Identity, signature and the clock window answer one uniform 401. A skewed clock looks exactly
        // like a bad signature, so it is retried on the schedule (bounded by the failure budget), not
        // treated as final on first sight.
        (401, _) => retry(),
        (403, "storage_off") => terminal(Status::NotStored, "storage_off"),
        (403, "machine_not_active") => retry(),
        (403, "session_not_on_this_machine") => terminal(Status::Refused, "session_not_on_this_machine"),
        (403, _) => terminal(Status::Refused, "forbidden"),
        (413, "too_large") => terminal(Status::Refused, "too_large"),
        (413, _) => terminal(Status::Refused, "body_too_large"),
        (507, _) => retry(), // tenant_quota / server_full: a retention sweep frees space
        (410, c) => terminal(Status::Refused, if c.is_empty() { "gone" } else { c }),
        (404, "session_unknown") => terminal(Status::Refused, "session_unknown"),
        (404, _) => match op {
            Op::Create => terminal(Status::Refused, "not_found"),
            _ => Recreate,
        },
        (409, "already_complete") => GoFinish,
        (409, "bad_offset") | (409, "chunk_conflict") | (409, "incomplete") => Resync,
        (409, "generation_mismatch") => terminal(Status::Refused, "generation_mismatch"),
        (409, "audit_conflict") => terminal(Status::Refused, "audit_conflict"),
        (409, _) => terminal(Status::Refused, "conflict"),
        (422, "digest_mismatch") => {
            if f.state.as_deref() == Some("refused") {
                terminal(Status::Refused, "digest_mismatch")
            } else {
                DigestReset { segments: f.segments.clone() }
            }
        }
        (503, _) | (408, _) | (429, _) => retry(),
        (400, _) | (411, _) => terminal(Status::Refused, "bad_request"),
        (s, _) if s >= 500 => retry(),
        _ => terminal(Status::Refused, "unexpected_status"),
    }
}

// ---- time, pacing, session gate ----------------------------------------------------------------

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
    fn sleep(&self, d: Duration);
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        crate::recording::now_unix_ms()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d)
    }
}

/// "Is a remote session live on this machine right now?" Uploads never run while one is.
pub trait SessionProbe: Send + Sync {
    fn session_live(&self) -> bool;
}

pub struct NeverLive;
impl SessionProbe for NeverLive {
    fn session_live(&self) -> bool {
        false
    }
}

/// Exponential backoff for the `failures`-th consecutive failure (1-based): base * 2^(n-1), plus up to
/// 25 % deterministic jitter derived from `seed` (so a fleet does not retry in lock-step and a test can
/// assert exact bounds), never above [`BACKOFF_CAP_MS`], and at least the server's Retry-After (itself
/// capped).
pub fn backoff_ms(failures: u32, seed: u64, min_delay_s: Option<u64>) -> i64 {
    let n = failures.max(1) - 1;
    let exp = BACKOFF_BASE_MS.checked_shl(n.min(20)).unwrap_or(BACKOFF_CAP_MS).min(BACKOFF_CAP_MS);
    let jitter = (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 33) as i64 % (exp / 4 + 1);
    let mut d = (exp + jitter).min(BACKOFF_CAP_MS);
    if let Some(s) = min_delay_s {
        d = d.max((s.min(3600) as i64) * 1000);
    }
    d.min(BACKOFF_CAP_MS)
}

// ---- the uploader ------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UploaderConfig {
    pub state_dir: PathBuf,
    pub roots: Vec<ScanRoot>,
    pub rate_bytes_per_sec: u64,
    pub max_pending_bytes: u64,
    pub max_pending_age_ms: i64,
    pub max_failures: u32,
}

impl UploaderConfig {
    pub fn production() -> Self {
        Self {
            state_dir: PathBuf::from(STATE_DIR),
            roots: vec![
                ScanRoot::Flat(PathBuf::from(crate::config::DEFAULT_RECORDING_DIR)),
                ScanRoot::Leaves(PathBuf::from(crate::recording_broker::DIRECTORY)),
            ],
            rate_bytes_per_sec: DEFAULT_RATE_BYTES_PER_SEC,
            max_pending_bytes: MAX_PENDING_BYTES,
            max_pending_age_ms: MAX_PENDING_AGE_MS,
            max_failures: MAX_CONSECUTIVE_FAILURES,
        }
    }
}

/// What one pass did (logged, and asserted by tests).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub queued: u32,
    pub completed: u32,
    pub not_stored: u32,
    pub refused: u32,
    pub abandoned: u32,
    pub retry_scheduled: u32,
    pub deferred_session_live: bool,
    /// A drain/re-enrollment fence is up: nothing new was started this pass.
    pub fenced: bool,
    /// Things that could not be done safely (unreadable queue entries, enumeration or persistence failures).
    pub problems: u32,
}

/// What [`Uploader::finish_or_abandon`] did — the contract the fleet uninstall path (docs/65 D-C9)
/// consumes. `problems` is the part that MUST block a removal: an enumeration that was incomplete, an
/// entry that could not be read, a recording that was deferred or busy and never reconciled, a settlement
/// that could not be made durable. When `problems` is empty, EVERY local recording has a durable
/// disposition: complete (local copy deleted), not going to be stored, or abandoned — and nothing is pending.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainReport {
    pub uploaded: u32,
    pub abandoned: u32,
    /// Terminal before the call (complete / not stored / refused / abandoned).
    pub already_settled: u32,
    /// True when the time budget ran out and the rest were abandoned for that reason.
    pub budget_exhausted: bool,
    pub problems: Vec<String>,
}

impl DrainReport {
    pub fn is_settled(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Why a drive stopped (internal to one drive).
#[derive(Debug)]
enum Stop {
    /// Paused without failing: a session went live, the service is stopping, a fence went up or a drain budget ended.
    Paused(&'static str),
    Retry { min_delay_s: Option<u64>, why: String },
    Terminal(Status, String),
}

/// What a drive achieved, after its durable bookkeeping (done under the recording's lock).
#[derive(Debug)]
enum Outcome {
    Completed,
    Paused(&'static str),
    /// Backoff scheduled (background) — or, in a drain, "failed, nothing recorded; the caller decides".
    #[allow(dead_code)] // the reason is carried for debugging output only
    Retried(String),
    Settled(Status),
    /// Another worker finished it (terminal on disk) or it is gone: nothing to do, nothing overwritten.
    AlreadySettled,
    /// Busy (lock held elsewhere) in a background pass.
    Busy,
    /// Could not be done safely.
    Problem(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Normal background operation: honours backoff, the session gate, the fence and the rate cap.
    Background,
    /// Uninstall drain: ignores the gate, backoff, fence and cap, bounded by a deadline.
    Drain { deadline_ms: i64 },
}

// ---- queue operations shared by the uploader, the drain, re-enrollment and the unwired hand-off ---

/// The drain fence: a durable file in the queue directory holding a unix-ms deadline. While it is in the future,
/// background enqueue and background drives start nothing and stop at the next chunk. It expires on its own, so a
/// removal that fails cannot leave uploads blocked forever.
pub const FENCE_NAME: &str = "draining.flag";
/// How long a drain's fence outlives its budget (the removal itself follows the drain).
pub const FENCE_AFTER_DRAIN_MS: i64 = 15 * 60_000;
/// The ONE lock that serializes every hand-off (removal drain, unwired drain, re-enrollment) for its whole
/// duration. Taken through `open_exclusive` (no sharing at all).
pub const HANDOFF_LOCK: &str = "handoff.lock";

/// Who raised the fence. A removal fence is never cleared by a re-enrollment, and a re-enrollment may not even
/// start while one is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceKind {
    Removal,
    Reenroll,
}

impl FenceKind {
    fn as_str(self) -> &'static str {
        match self {
            FenceKind::Removal => "removal",
            FenceKind::Reenroll => "reenroll",
        }
    }
}

/// Proof of ownership of a fence: the operation kind and a random token written into the fence file. Only the
/// owner can clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceToken {
    pub kind: FenceKind,
    token: String,
}

/// A parsed fence file: `<kind>:<token>:<until-unix-ms>`. A bare number (an older fence) is a removal fence
/// with no owner.
struct ParsedFence {
    kind: FenceKind,
    token: String,
    until: i64,
}

fn parse_fence(b: &[u8]) -> Option<ParsedFence> {
    let t = std::str::from_utf8(b).ok()?.trim();
    if let Ok(until) = t.parse::<i64>() {
        return Some(ParsedFence { kind: FenceKind::Removal, token: String::new(), until });
    }
    let mut parts = t.split(':');
    let kind = match parts.next()? {
        "removal" => FenceKind::Removal,
        "reenroll" => FenceKind::Reenroll,
        _ => return None,
    };
    let token = parts.next()?.to_string();
    let until = parts.next()?.parse::<i64>().ok()?;
    (parts.next().is_none() && !token.is_empty() && token.bytes().all(|c| c.is_ascii_hexdigit())).then_some(ParsedFence { kind, token, until })
}

/// Proof that the holder owns one recording's lifecycle lock (released on drop).
pub struct LockGuard {
    _file: std::fs::File,
    name: String,
}

pub enum Settle {
    Done(UploadState),
    /// It was no longer pending (someone else completed/settled it): NOT overwritten.
    Already(UploadState),
    Gone,
}

/// A finished local recording found on disk.
pub struct LocalRec {
    pub dir: PathBuf,
    pub leaf: bool,
    pub stem: String,
    pub side: Sidecar,
    pub dio: Rc<dyn DirIo>,
}

#[derive(Default)]
pub struct Enumeration {
    pub recs: Vec<LocalRec>,
    /// Things that could not be examined: an incomplete enumeration is never a clean one.
    pub problems: Vec<String>,
}

enum FenceFile {
    Absent,
    Garbled,
    Valid(ParsedFence),
}

#[derive(Clone)]
pub struct QueueOps {
    store: StateStore,
    clock: Arc<dyn Clock>,
    /// Where the next [`QueueOps::reclaim_queue`] pass starts reading (rotates, so every entry is eventually reached).
    reclaim_cursor: Arc<std::sync::atomic::AtomicUsize>,
}

/// An entry the queue may give up early: terminal, and not a completed upload whose local cleanup is still owed.
fn reclaimable(st: &UploadState) -> bool {
    st.status.is_terminal() && !(st.status == Status::Complete && !st.local_cleaned)
}

fn state_lock_name(st: &UploadState) -> String {
    lock_name(Path::new(&st.local_dir), st.leaf_dir, &st.device_id, &st.stem)
}

impl QueueOps {
    pub fn new(store: StateStore, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock, reclaim_cursor: Arc::default() }
    }
    pub fn store(&self) -> &StateStore {
        &self.store
    }

    // -- queue pressure -----------------------------------------------------------------------------

    /// Relieve a queue that is growing toward the enumeration limit by deleting TERMINAL entries (never a pending one, never a
    /// completed one whose local cleanup is still owed), so the full-enumeration guarantee every sweep and drain relies on can be
    /// met again WITHOUT ever listing past the limit. Terminal entries normally live [`TERMINAL_KEEP_MS`] (they stop a rescan
    /// re-queueing a recording whose files are still local); under pressure the cheapest to give up go first: completed and cleaned
    /// (nothing local can re-queue them), then the oldest. Each pass reads at most [`RECLAIM_READ_BUDGET`] entries from a rotating
    /// window, so the work is bounded however large the directory has become, and repeated passes recover any size. Returns
    /// the number deleted and the number of entries left. Cheap (one directory listing) when the queue is below the high-water mark.
    pub fn reclaim_queue(&self) -> (usize, usize) {
        let Ok(d) = self.store.open(false) else { return (0, 0) };
        let Ok(names) = d.list() else { return (0, 0) };
        let mut ids: Vec<&str> =
            names.iter().filter_map(|n| n.strip_suffix(".json")).filter(|id| parse_canonical_uuid(id).is_some()).collect();
        if ids.len() <= RECLAIM_HIGH_WATER {
            return (0, ids.len());
        }
        ids.sort_unstable();
        let start = self.reclaim_cursor.load(Ordering::Relaxed) % ids.len();
        let take = RECLAIM_READ_BUDGET.min(ids.len());
        self.reclaim_cursor.store(start + take, Ordering::Relaxed);
        let mut cands: Vec<UploadState> = ids
            .iter()
            .cycle()
            .skip(start)
            .take(take)
            .filter_map(|id| match self.store.reload(id) {
                Ok(Some(st)) if reclaimable(&st) => Some(st),
                _ => None,
            })
            .collect();
        cands.sort_by_key(|s| (!(s.status == Status::Complete), s.finished_at_ms.unwrap_or(0)));
        let mut excess = ids.len().saturating_sub(RECLAIM_LOW_WATER);
        let mut removed = 0;
        for st in cands {
            if excess == 0 {
                break;
            }
            // Under the recording's lock, reloaded, still reclaimable: the same discipline as the age-based prune.
            let Ok(Some(guard)) = self.try_lock(&state_lock_name(&st)) else { continue };
            match self.store.reload(&st.recording_id) {
                Ok(Some(cur)) if reclaimable(&cur) && self.store.remove_state(&cur.recording_id).is_ok() => {
                    self.release_and_reclaim(guard);
                    removed += 1;
                    excess -= 1;
                }
                _ => {}
            }
        }
        if removed > 0 {
            tracing::warn!(removed, entries = ids.len(), "recording upload: the queue neared its entry limit; terminal entries were reclaimed early");
        }
        (removed, ids.len() - removed)
    }

    /// [`reclaim_queue`](Self::reclaim_queue) repeated until the queue is back under the high-water mark (bounded
    /// rounds): for a caller that needs a complete listing NOW (a drain).
    pub fn reclaim_queue_until_enumerable(&self) {
        for _ in 0..RECLAIM_MAX_ROUNDS {
            // A pass that found nothing to delete still moved the window on: keep going until the queue is small enough.
            if self.reclaim_queue().1 <= RECLAIM_HIGH_WATER {
                break;
            }
        }
    }

    // -- fence ----------------------------------------------------------------------------------

    fn read_fence(&self) -> std::io::Result<FenceFile> {
        let d = match self.store.open(false) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FenceFile::Absent),
            Err(e) => return Err(e),
        };
        Ok(match d.read(FENCE_NAME, 128)? {
            None => FenceFile::Absent,
            Some(b) => match parse_fence(&b) {
                Some(f) => FenceFile::Valid(f),
                None => FenceFile::Garbled,
            },
        })
    }

    /// Raise (or extend) the fence for `kind`. NEVER shortens an existing active fence (the new deadline is the later
    /// of the two) and never takes one over from a removal: a re-enrollment refuses while a removal fence is up. The
    /// fence file records the owner (kind + a fresh random token) and the deadline.
    pub fn set_fence(&self, kind: FenceKind, hold_ms: i64) -> Result<FenceToken, String> {
        let now = self.clock.now_ms();
        let mut until = now.saturating_add(hold_ms);
        match self.read_fence().map_err(|e| format!("the fence cannot be read: {e}"))? {
            FenceFile::Valid(f) if f.until > now => {
                if kind == FenceKind::Reenroll && f.kind == FenceKind::Removal {
                    return Err("a removal is in progress (its fence is up); re-enrollment must not touch it".into());
                }
                until = until.max(f.until);
            }
            // Absent, expired or garbled: a hand-off that holds the hand-off lock may (re)establish it.
            _ => {}
        }
        let token = uuid::Uuid::new_v4().simple().to_string();
        self.store
            .open(true)
            .and_then(|d| d.write_atomic(FENCE_NAME, format!("{}:{token}:{until}", kind.as_str()).as_bytes()))
            .map_err(|e| format!("the fence could not be written: {e}"))?;
        Ok(FenceToken { kind, token })
    }

    /// Clear the fence ONLY if `owner` raised it (kind and token match what is in the file). `Ok(true)`: cleared.
    /// `Ok(false)`: it is someone else's (or gone) and was left untouched.
    pub fn clear_fence_owned(&self, owner: &FenceToken) -> std::io::Result<bool> {
        match self.read_fence()? {
            FenceFile::Valid(f) if f.kind == owner.kind && f.token == owner.token => {
                self.store.open(false)?.remove(FENCE_NAME)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Is the fence up? A missing flag is "no"; an unreadable queue is an error; a flag that cannot be parsed is
    /// treated as UP (fail closed).
    pub fn fence_active(&self) -> std::io::Result<bool> {
        Ok(match self.read_fence()? {
            FenceFile::Absent => false,
            FenceFile::Garbled => true,
            FenceFile::Valid(f) => self.clock.now_ms() < f.until,
        })
    }

    /// Begin a hand-off: take the global hand-off lock (waiting until `wait_until_ms`), then raise the fence.
    /// Dropping the returned guard ends the operation; the fence is NOT cleared by the drop (a removal leaves it up).
    fn begin_handoff(&self, kind: FenceKind, wait_until_ms: i64, hold_ms: i64) -> Result<(LockGuard, FenceToken), String> {
        let guard = match self.lock_until(HANDOFF_LOCK, wait_until_ms) {
            Ok(Some(g)) => g,
            Ok(None) => return Err("another hand-off (a removal drain, an unwired drain or a re-enrollment) is running".into()),
            Err(e) => return Err(format!("the hand-off lock could not be taken: {e}")),
        };
        let token = self.set_fence(kind, hold_ms)?;
        Ok((guard, token))
    }

    // -- locks ----------------------------------------------------------------------------------

    pub fn try_lock(&self, name: &str) -> std::io::Result<Option<LockGuard>> {
        Ok(self.store.open(true)?.lock(name)?.map(|f| LockGuard { _file: f, name: name.to_string() }))
    }
    /// Wait (polling) for the lock until `deadline_ms`. `Ok(None)`: still busy at the deadline.
    pub fn lock_until(&self, name: &str, deadline_ms: i64) -> std::io::Result<Option<LockGuard>> {
        loop {
            if let Some(g) = self.try_lock(name)? {
                return Ok(Some(g));
            }
            if self.clock.now_ms() >= deadline_ms {
                return Ok(None);
            }
            self.clock.sleep(Duration::from_millis(50));
        }
    }
    /// Release the lock and delete its file (the recording has no state and no local files). A concurrent taker
    /// makes the delete fail, which is fine: the name is derived from the recording, so there is one file per recording.
    pub fn release_and_reclaim(&self, g: LockGuard) {
        let name = g.name.clone();
        drop(g);
        if let Ok(d) = self.store.open(false) {
            let _ = d.remove(&name);
        }
    }

    // -- transitions (always: lock, reload, change, durable write, still under the lock) ------------

    /// Under `_g` (the caller holds the recording's lock): reload the state; if it is STILL pending settle it
    /// durably, otherwise leave it exactly as it is.
    pub fn settle_pending(&self, _g: &LockGuard, id: &str, status: Status, reason: &str) -> std::io::Result<Settle> {
        let Some(mut st) = self.store.reload(id)? else { return Ok(Settle::Gone) };
        if st.status != Status::Pending {
            return Ok(Settle::Already(st));
        }
        st.finish_with(status, reason, self.clock.now_ms());
        if status == Status::Abandoned {
            tracing::warn!(recording = %st.recording_id, reason, "recording upload: ABANDONED (the local copy keeps its normal retention)");
        }
        self.store.save(&st)?;
        Ok(Settle::Done(st))
    }

    /// Lock + settle one listed entry. `wait_until`: poll the lock until then (a drain); `None` = try once.
    fn settle_listed(&self, listed: &UploadState, status: Status, reason: &str, wait_until: Option<i64>) -> Result<Settle, String> {
        let name = state_lock_name(listed);
        let guard = match wait_until {
            Some(d) => self.lock_until(&name, d),
            None => self.try_lock(&name),
        }
        .map_err(|e| format!("{}: could not take the recording lock: {e}", listed.recording_id))?;
        let Some(guard) = guard else { return Err(format!("{}: the recording is busy (its lock is held elsewhere)", listed.recording_id)) };
        self.settle_pending(&guard, &listed.recording_id, status, reason).map_err(|e| format!("{}: could not durably settle: {e}", listed.recording_id))
    }

    // -- enumeration of what is on disk -----------------------------------------------------------

    /// Every finished recording under the configured roots, found through the trusted route. Anything that cannot be
    /// examined completely is a problem — the enumeration is never silently partial.
    pub fn enumerate(&self) -> Enumeration {
        let fs = self.store.fs().clone();
        let mut out = Enumeration::default();
        let mut dirs: Vec<(PathBuf, bool)> = Vec::new();
        for root in self.store.roots() {
            match root {
                ScanRoot::Flat(d) => dirs.push((d.clone(), false)),
                ScanRoot::Leaves(d) => match fs.open(d, false) {
                    Ok(rd) => match rd.subdirs() {
                        Ok(names) => {
                            if names.len() > LEAF_LIMIT {
                                out.problems.push(format!("{}: {} recording directories; refusing a partial scan", d.display(), names.len()));
                            }
                            for n in names.into_iter().take(LEAF_LIMIT) {
                                if uuid::Uuid::parse_str(&n).is_ok() {
                                    dirs.push((d.join(n), true));
                                }
                            }
                        }
                        Err(e) => out.problems.push(format!("{}: {e}", d.display())),
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => out.problems.push(format!("{}: {e}", d.display())),
                },
            }
        }
        for (dir, leaf) in dirs {
            let dio: Rc<dyn DirIo> = match fs.open(&dir, false) {
                Ok(d) => Rc::from(d),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    out.problems.push(format!("{}: {e}", dir.display()));
                    continue;
                }
            };
            let names = match dio.list() {
                Ok(n) => n,
                Err(e) => {
                    out.problems.push(format!("{}: {e}", dir.display()));
                    continue;
                }
            };
            if names.len() > SCAN_ENTRY_LIMIT {
                out.problems.push(format!("{}: {} entries; refusing a partial scan", dir.display(), names.len()));
                continue;
            }
            for name in names {
                let Some(stem) = name.strip_suffix(".json").map(str::to_string) else { continue };
                if !valid_stem(&stem) {
                    continue;
                }
                let bytes = match dio.read(&name, SIDECAR_READ_MAX) {
                    Ok(Some(b)) => b,
                    Ok(None) => continue,
                    Err(e) => {
                        out.problems.push(format!("{}\\{name}: {e}", dir.display()));
                        continue;
                    }
                };
                // Still being written, or not ours: look again next pass (a drain counts it as a problem).
                let Ok(side) = serde_json::from_slice::<Sidecar>(&bytes) else {
                    out.problems.push(format!("{}\\{name}: not a complete recording sidecar", dir.display()));
                    continue;
                };
                if side.kind != SIDECAR_KIND {
                    continue;
                }
                out.recs.push(LocalRec { dir: dir.clone(), leaf, stem, side, dio: dio.clone() });
            }
        }
        out
    }

    // -- the network-free drain steps ---------------------------------------------------------------

    /// Durably abandon every PENDING entry: for each one, take its lock (waiting until `deadline_ms`), reload it under
    /// the lock, and settle it only if it is still pending. Locks that cannot be taken, entries that cannot be read and
    /// saves that fail are problems; nothing is counted unless it is durable.
    pub fn abandon_pending(&self, reason: &str, deadline_ms: i64, rep: &mut DrainReport) {
        self.reclaim_queue_until_enumerable();
        let listing = match self.store.list_checked() {
            Ok(l) => l,
            Err(e) => {
                rep.problems.push(format!("the upload queue cannot be enumerated: {e}"));
                return;
            }
        };
        for i in &listing.issues {
            rep.problems.push(format!("unusable queue entry {i}"));
        }
        for st in listing.states.iter().filter(|s| s.status == Status::Pending) {
            match self.settle_listed(st, Status::Abandoned, reason, Some(deadline_ms)) {
                Ok(Settle::Done(_)) => rep.abandoned += 1,
                Ok(Settle::Already(_)) | Ok(Settle::Gone) => rep.already_settled += 1,
                Err(p) => rep.problems.push(p),
            }
        }
        match self.store.list_checked() {
            Ok(l) => {
                for st in l.states.iter().filter(|s| s.status == Status::Pending) {
                    rep.problems.push(format!("{}: still pending after the abandonment", st.recording_id));
                }
            }
            Err(e) => rep.problems.push(format!("the upload queue cannot be re-read: {e}")),
        }
    }

    /// Give every local recording that has NO queue entry a durable terminal one (`reason`), so it has an explicit
    /// disposition: used when the machine cannot be wired (no identity to upload under). Each recording is handled
    /// under its own lock with the state re-checked under it; busy locks, locked files and failed saves are problems.
    pub fn dispose_unqueued(&self, reason: &str, deadline_ms: i64, rep: &mut DrainReport) {
        let en = self.enumerate();
        rep.problems.extend(en.problems);
        for rec in en.recs {
            let id = recording_id_for(&rec.side.device_id, &rec.dir, &rec.stem);
            let name = lock_name(&rec.dir, rec.leaf, &rec.side.device_id, &rec.stem);
            let guard = match self.lock_until(&name, deadline_ms) {
                Ok(Some(g)) => g,
                Ok(None) => {
                    rep.problems.push(format!("{id}: the recording is busy; its disposition could not be recorded"));
                    continue;
                }
                Err(e) => {
                    rep.problems.push(format!("{id}: could not take the recording lock: {e}"));
                    continue;
                }
            };
            match self.store.reload(&id) {
                Ok(Some(_)) => continue, // already has an entry (its own disposition is handled by abandon_pending)
                Ok(None) => {}
                Err(e) => {
                    rep.problems.push(format!("{id}: its queue entry is unreadable: {e}"));
                    continue;
                }
            }
            let ident = UploadIdentity { tenant_id: "unwired".into(), device_id: rec.side.device_id.clone(), key_fp_hex: "unwired".into(), audience: "unwired".into() };
            let mut st = skeleton(&ident, &rec.dir, &rec.stem, rec.leaf, &rec.side, &id, self.clock.now_ms());
            st.finish_with(Status::Abandoned, reason, self.clock.now_ms());
            match self.store.save(&st) {
                Ok(()) => rep.abandoned += 1,
                Err(e) => rep.problems.push(format!("{id}: its disposition could not be recorded durably: {e}")),
            }
            drop(guard);
        }
    }

    /// The whole network-free hand-off: fence admission, give unqueued recordings a durable disposition, abandon
    /// everything pending. The fence stays up (the removal follows; it expires by itself).
    pub fn drain_unwired(&self, reason: &str, budget: Duration) -> DrainReport {
        let mut rep = DrainReport::default();
        let deadline = self.clock.now_ms().saturating_add(budget.as_millis() as i64);
        // One hand-off at a time, for the whole operation; the removal fence is left up when this returns.
        let _handoff = match self.begin_handoff(FenceKind::Removal, deadline, budget.as_millis() as i64 + FENCE_AFTER_DRAIN_MS) {
            Ok(h) => h,
            Err(e) => {
                rep.problems.push(e);
                return rep;
            }
        };
        self.dispose_unqueued(reason, deadline, &mut rep);
        self.abandon_pending(reason, deadline, &mut rep);
        rep
    }

    /// Re-enrollment: fence, abandon everything pending (the old key can no longer sign for it), lift the fence.
    pub fn abandon_for_reenrollment(&self, reason: &str, budget: Duration) -> Result<u32, Vec<String>> {
        let mut rep = DrainReport::default();
        let deadline = self.clock.now_ms().saturating_add(budget.as_millis() as i64);
        let (_handoff, fence) = match self.begin_handoff(FenceKind::Reenroll, deadline, budget.as_millis() as i64 + 60_000) {
            Ok(h) => h,
            Err(e) => return Err(vec![e]),
        };
        self.abandon_pending(reason, deadline, &mut rep);
        // Only OUR fence is lifted: if a removal took over in between (it cannot, while we hold the hand-off lock),
        // the token would not match and the fence would stay.
        if let Err(e) = self.clear_fence_owned(&fence) {
            rep.problems.push(format!("the fence could not be lifted (it will expire): {e}"));
        }
        if rep.problems.is_empty() {
            Ok(rep.abandoned)
        } else {
            Err(rep.problems)
        }
    }
}

fn skeleton(ident: &UploadIdentity, dir: &Path, stem: &str, leaf: bool, side: &Sidecar, id: &str, now: i64) -> UploadState {
    UploadState {
        schema: 1,
        recording_id: id.to_string(),
        generation: 1,
        tenant_id: ident.tenant_id.clone(),
        device_id: side.device_id.clone(),
        key_fp_hex: ident.key_fp_hex.clone(),
        audience: ident.audience.clone(),
        session_id: side.session_id.clone().unwrap_or_default(),
        local_dir: dir.display().to_string(),
        stem: stem.to_string(),
        leaf_dir: leaf,
        dir_id: None,
        sidecar_id: None,
        // A state must carry at least one segment to validate while pending; refused-at-birth ones keep the sidecar's.
        segments: side
            .segments
            .iter()
            .filter(|s| crate::recording::sweepable_segment(stem, &s.file).is_some() && is_hex64(&s.sha256))
            .map(|s| SegmentState { file: s.file.clone(), length: 1, sha256: s.sha256.clone(), committed: 0, file_id: None })
            .take(MAX_SEGMENTS)
            .collect(),
        truncated: side.truncated.clone(),
        dropped_frames: side.dropped_frames,
        frames: 0,
        payload_bytes: 0,
        ended_at_ms: side.ended_at_unix_ms,
        enqueued_at_ms: now,
        status: Status::Pending,
        reason: None,
        finished_at_ms: None,
        created: false,
        verified_sig: None,
        failures: 0,
        next_attempt_at_ms: 0,
        digest_failures: 0,
        last_error: None,
        ack_digests: None,
        local_cleaned: false,
    }
}

#[derive(Default)]
struct ScanOutcome {
    queued: u32,
    fenced: bool,
    /// Hard problems (could not be examined, could not be recorded).
    problems: Vec<String>,
    /// Recordings skipped THIS pass because their lock was busy or a segment was locked: harmless in the background
    /// (the next pass retries), UNRESOLVED in a drain.
    deferred: Vec<String>,
    /// Lock-file names of every local recording seen (for reclaiming orphans).
    local_locks: std::collections::HashSet<String>,
}

pub struct Uploader<A: UploadApi> {
    cfg: UploaderConfig,
    api: A,
    ident: UploadIdentity,
    probe: Arc<dyn SessionProbe>,
    clock: Arc<dyn Clock>,
    stop: Arc<AtomicBool>,
    fs: Arc<dyn FsProvider>,
    store: StateStore,
    ops: QueueOps,
}

fn io_why(e: &std::io::Error) -> String {
    e.to_string()
}

impl<A: UploadApi> Uploader<A> {
    pub fn new(
        cfg: UploaderConfig,
        api: A,
        ident: UploadIdentity,
        probe: Arc<dyn SessionProbe>,
        clock: Arc<dyn Clock>,
        stop: Arc<AtomicBool>,
        fs: Arc<dyn FsProvider>,
    ) -> Self {
        let store = StateStore::new(fs.clone(), cfg.state_dir.clone(), cfg.roots.clone());
        let ops = QueueOps::new(store.clone(), clock.clone());
        Self { cfg, api, ident, probe, clock, stop, fs, store, ops }
    }

    pub fn store(&self) -> &StateStore {
        &self.store
    }
    pub fn ops(&self) -> &QueueOps {
        &self.ops
    }

    /// One background pass: queue new recordings, settle identity changes and aged-out entries, drive
    /// every due pending upload (oldest first), finish interrupted local cleanups, prune old tombstones and
    /// orphan lock files. While a drain/re-enrollment fence is up it starts nothing.
    pub fn tick(&mut self) -> TickReport {
        let mut rep = TickReport::default();
        let now = self.clock.now_ms();
        match self.ops.fence_active() {
            Ok(true) => {
                rep.fenced = true;
                return rep;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!(error = %e, "recording upload: the drain fence cannot be read; nothing is started this pass");
                rep.problems += 1;
                return rep;
            }
        }
        // Keep the queue enumerable: terminal entries are reclaimed BEFORE anything needs a complete listing (a full queue must
        // recover by itself, not refuse every pass forever).
        self.ops.reclaim_queue();
        let scan = self.scan(now, None);
        rep.queued = scan.queued;
        for p in scan.problems.iter().chain(&scan.deferred) {
            tracing::warn!(problem = %p, "recording upload: scan problem or deferral");
        }
        rep.problems += scan.problems.len() as u32;
        let listing = match self.store.list_checked() {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "recording upload: the queue cannot be enumerated; nothing is driven this pass");
                rep.problems += 1;
                return rep;
            }
        };
        for i in &listing.issues {
            tracing::warn!(entry = %i, "recording upload: unusable queue entry (never used, never deleted on its word)");
            rep.problems += 1;
        }
        self.reap_orphan_locks(&listing.states, &scan.local_locks);
        let mut states = listing.states;
        states.sort_by_key(|s| (s.ended_at_ms, s.recording_id.clone()));
        for listed in states {
            if listed.status == Status::Complete && !listed.local_cleaned {
                self.cleanup_listed(&listed);
                continue;
            }
            if listed.status.is_terminal() {
                if listed.finished_at_ms.is_some_and(|t| now - t > TERMINAL_KEEP_MS) && !self.prune_listed(&listed) {
                    rep.problems += 1;
                }
                continue;
            }
            // Settle things that need no network first, so they happen even while a session is live.
            if let Some(Stop::Terminal(status, reason)) = self.pre_gate(&listed, now) {
                match self.ops.settle_listed(&listed, status, &reason, None) {
                    Ok(Settle::Done(_)) => {
                        match status {
                            Status::Abandoned => rep.abandoned += 1,
                            _ => rep.refused += 1,
                        }
                        tracing::info!(recording = %listed.recording_id, ?status, reason, "recording upload: ended");
                    }
                    Ok(_) => {}
                    Err(p) => {
                        tracing::error!(problem = %p, "recording upload: could not settle");
                        rep.problems += 1;
                    }
                }
                continue;
            }
            if listed.next_attempt_at_ms > now {
                continue;
            }
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            if self.probe.session_live() {
                rep.deferred_session_live = true;
                continue;
            }
            match self.drive(&listed, Mode::Background) {
                Outcome::Completed => rep.completed += 1,
                Outcome::Settled(status) => match status {
                    Status::NotStored => rep.not_stored += 1,
                    Status::Abandoned => rep.abandoned += 1,
                    _ => rep.refused += 1,
                },
                Outcome::Retried(_) => rep.retry_scheduled += 1,
                Outcome::Paused(why) => {
                    if why == "session_live" {
                        rep.deferred_session_live = true;
                    }
                    if why == "fenced" {
                        rep.fenced = true;
                    }
                }
                Outcome::AlreadySettled | Outcome::Busy => {}
                Outcome::Problem(p) => {
                    tracing::error!(problem = %p, "recording upload: drive problem");
                    rep.problems += 1;
                }
            }
        }
        rep
    }

    /// The API the fleet uninstall path calls (docs/65 D-C9): FENCE admission (a durable flag every background
    /// enqueue and drive checks), reconcile EVERY local recording (queue it, or give it a durable disposition),
    /// try to complete every pending upload within `budget`, then EXPLICITLY abandon whatever is left (reason
    /// `uninstall` / `uninstall_budget`). FALLIBLE: a busy or locked recording that could not be reconciled, an
    /// incomplete enumeration, an unreadable entry, or a settlement that could not be made durable is in
    /// [`DrainReport::problems`], and the caller must not remove the machine while any exist. The fence is left up
    /// (it expires on its own); uploaded recordings have had their local copy deleted by the normal completion
    /// path, abandoned ones keep their files (the uninstall's own directory removal deals with them).
    pub fn finish_or_abandon(&mut self, budget: Duration) -> DrainReport {
        let mut rep = DrainReport::default();
        let started = self.clock.now_ms();
        let deadline_ms = started.saturating_add(budget.as_millis() as i64);
        // One hand-off at a time, for the whole operation (including the final verification); the removal fence is
        // left up when this returns (it expires on its own and is never cleared by a re-enrollment).
        let _handoff = match self.ops.begin_handoff(FenceKind::Removal, deadline_ms, budget.as_millis() as i64 + FENCE_AFTER_DRAIN_MS) {
            Ok(h) => h,
            Err(e) => {
                rep.problems.push(e);
                return rep;
            }
        };
        // Reconcile every local recording: queue it durably, or record why not. Busy locks and locked segments are
        // waited on until the deadline; whatever is still deferred is UNRESOLVED.
        self.ops.reclaim_queue_until_enumerable();
        let scan = self.scan(started, Some(deadline_ms));
        rep.problems.extend(scan.problems);
        rep.problems.extend(scan.deferred.into_iter().map(|d| format!("unreconciled local recording: {d}")));
        let listing = match self.store.list_checked() {
            Ok(l) => l,
            Err(e) => {
                rep.problems.push(format!("the upload queue cannot be enumerated: {}", io_why(&e)));
                return rep;
            }
        };
        for i in &listing.issues {
            rep.problems.push(format!("unusable queue entry {i}"));
        }
        let mut states = listing.states;
        states.sort_by_key(|s| (s.ended_at_ms, s.recording_id.clone()));
        let mode = Mode::Drain { deadline_ms };
        for listed in states {
            if listed.status.is_terminal() {
                rep.already_settled += 1;
                continue;
            }
            let mut tries = 0;
            loop {
                match self.drive(&listed, mode) {
                    Outcome::Completed => rep.uploaded += 1,
                    Outcome::Settled(Status::Abandoned) => rep.abandoned += 1,
                    Outcome::Settled(_) | Outcome::AlreadySettled => rep.already_settled += 1,
                    Outcome::Paused("budget") => {
                        rep.budget_exhausted = true;
                        self.abandon_listed(&listed, "uninstall_budget", deadline_ms, &mut rep);
                    }
                    Outcome::Paused(_) | Outcome::Busy => self.abandon_listed(&listed, "uninstall", deadline_ms, &mut rep),
                    Outcome::Retried(_) => {
                        tries += 1;
                        if tries < 2 {
                            // One short pause, then one more attempt (still bounded by the deadline).
                            let left = (deadline_ms - self.clock.now_ms()).max(0) as u64;
                            self.clock.sleep(Duration::from_millis(left.min(1000)));
                            continue;
                        }
                        self.abandon_listed(&listed, "uninstall", deadline_ms, &mut rep);
                    }
                    Outcome::Problem(p) => rep.problems.push(p),
                }
                break;
            }
        }
        // Anything still pending (e.g. an entry a worker held) is abandoned under its lock; then verify.
        let final_deadline = deadline_ms.max(self.clock.now_ms().saturating_add(5_000));
        self.ops.abandon_pending("uninstall", final_deadline, &mut rep);
        rep
    }

    fn abandon_listed(&self, listed: &UploadState, reason: &str, deadline_ms: i64, rep: &mut DrainReport) {
        // A budget that has already run out still gets a short window to take the lock and write the abandonment.
        let wait = deadline_ms.max(self.clock.now_ms().saturating_add(5_000));
        match self.ops.settle_listed(listed, Status::Abandoned, reason, Some(wait)) {
            Ok(Settle::Done(_)) => rep.abandoned += 1,
            Ok(_) => rep.already_settled += 1,
            Err(p) => rep.problems.push(p),
        }
    }

    /// Re-enrollment / explicit operator abandonment: fence, abandon everything pending under each recording's lock,
    /// lift the fence. `Ok(n)`: n abandoned durably and nothing pending remains.
    pub fn abandon_all(&mut self, reason: &str) -> Result<u32, Vec<String>> {
        self.ops.abandon_for_reenrollment(reason, Duration::from_secs(30))
    }

    // ---- state bookkeeping under the lifecycle lock ------------------------------------------------

    /// Delete an uploaded recording's local files for a `Complete` entry whose cleanup was interrupted: lock, reload,
    /// clean, keep the lock through the durable write.
    fn cleanup_listed(&self, listed: &UploadState) {
        let name = state_lock_name(listed);
        let Ok(Some(_guard)) = self.ops.try_lock(&name) else { return };
        let Ok(Some(mut st)) = self.store.reload(&listed.recording_id) else { return };
        if st.status != Status::Complete || st.local_cleaned {
            return;
        }
        match self.fs.open(Path::new(&st.local_dir), false) {
            Ok(dio) => self.cleanup_with(&mut st, dio.as_ref()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                st.local_cleaned = true;
                let _ = self.store.save(&st);
            }
            Err(e) => tracing::warn!(recording = %st.recording_id, error = %e, "recording upload: cannot open the recording directory to finish cleanup"),
        }
    }

    /// Remove an old terminal entry and its lock file: lock, reload, confirm it is still terminal and old.
    fn prune_listed(&self, listed: &UploadState) -> bool {
        let name = state_lock_name(listed);
        let guard = match self.ops.try_lock(&name) {
            Ok(Some(g)) => g,
            Ok(None) => return true, // busy: leave it for the next pass
            Err(_) => return false,
        };
        let now = self.clock.now_ms();
        match self.store.reload(&listed.recording_id) {
            Ok(Some(st)) if st.status.is_terminal() && st.finished_at_ms.is_some_and(|t| now - t > TERMINAL_KEEP_MS) => {
                if self.store.remove_state(&st.recording_id).is_err() {
                    return false;
                }
                self.ops.release_and_reclaim(guard);
                true
            }
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Lock files that belong to no queue entry and to no local recording seen this pass are reclaimed (a sweep that
    /// deleted a recording reclaims its own; this catches what a crash left). Taken under try-lock, so a lock someone
    /// is using is never touched.
    fn reap_orphan_locks(&self, states: &[UploadState], local: &std::collections::HashSet<String>) {
        let Ok(d) = self.store.open(false) else { return };
        let Ok(names) = d.list() else { return };
        let known: std::collections::HashSet<String> = states.iter().map(state_lock_name).collect();
        for n in names.into_iter().filter(|n| n.ends_with(".lock")) {
            if known.contains(&n) || local.contains(&n) || n == HANDOFF_LOCK {
                continue;
            }
            if let Ok(Some(g)) = self.ops.try_lock(&n) {
                self.ops.release_and_reclaim(g);
            }
        }
    }

    // ---- enqueue -------------------------------------------------------------------------------

    /// Find finished recordings and queue each one DURABLY (a recording is never driven unless its entry is on
    /// disk). `wait`: a drain's deadline — busy locks and locked segments are waited on, and enqueue is allowed under
    /// the fence. Without it (background) a fence stops everything and busy items are deferred. Anything that cannot
    /// be examined or recorded completely is a problem; anything skipped is `deferred`, never silently dropped.
    fn scan(&self, now: i64, wait: Option<i64>) -> ScanOutcome {
        let mut out = ScanOutcome::default();
        if wait.is_none() {
            match self.ops.fence_active() {
                Ok(true) => {
                    out.fenced = true;
                    return out;
                }
                Ok(false) => {}
                Err(e) => {
                    out.problems.push(format!("the drain fence cannot be read: {}", io_why(&e)));
                    return out;
                }
            }
        }
        let listing = match self.store.list_checked() {
            Ok(l) => l,
            Err(e) => {
                out.problems.push(format!("the upload queue cannot be enumerated: {}", io_why(&e)));
                return out;
            }
        };
        // The entry-count admission bound (the pending-bytes bound below does not limit the NUMBER of state files): a pass never queues
        // the directory past the enumeration limit, whatever terminal entries have piled up.
        let mut entries = listing.states.len() + listing.issues.len();
        let mut pending_bytes: u64 = listing.states.iter().filter(|s| s.status == Status::Pending).map(|s| s.total_bytes()).sum();
        let en = self.ops.enumerate();
        out.problems.extend(en.problems);
        for rec in en.recs {
            let (dir, stem, leaf, side) = (&rec.dir, &rec.stem, rec.leaf, &rec.side);
            let id = recording_id_for(&side.device_id, dir, stem);
            let lname = lock_name(dir, leaf, &side.device_id, stem);
            out.local_locks.insert(lname.clone());
            if entries + ADMISSION_HEADROOM > SCAN_ENTRY_LIMIT {
                out.deferred.push(format!("{id}: the queue already holds {entries} entries; not queued until terminal entries are reclaimed"));
                continue;
            }
            // The recording's lifecycle lock: a sweep (or another pass) working on it makes us wait (drain) or defer.
            let lock = match wait {
                Some(d) => self.ops.lock_until(&lname, d),
                None => self.ops.try_lock(&lname),
            };
            let lock = match lock {
                Ok(Some(l)) => l,
                Ok(None) => {
                    out.deferred.push(format!("{id}: its lock is busy"));
                    continue;
                }
                Err(e) => {
                    out.problems.push(format!("{id}: could not take the recording lock: {}", io_why(&e)));
                    continue;
                }
            };
            // Under the lock: is it already queued (the listing above may be stale)? Is the fence up now?
            match self.store.reload(&id) {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(e) => {
                    out.problems.push(format!("{id}: its queue entry is unreadable: {}", io_why(&e)));
                    continue;
                }
            }
            entries += 1;
            if wait.is_none() && self.ops.fence_active().unwrap_or(true) {
                out.fenced = true;
                continue;
            }
            // A locked segment (sharing violation) is retried until the drain's deadline, deferred in the background.
            let built = loop {
                match self.build_state(rec.dio.as_ref(), dir, stem, leaf, side, &id, now) {
                    Ok(None) => match wait {
                        Some(d) if self.clock.now_ms() < d => self.clock.sleep(Duration::from_millis(100)),
                        _ => break None,
                    },
                    other => break Some(other),
                }
            };
            let mut st = match built {
                None | Some(Ok(None)) => {
                    out.deferred.push(format!("{id}: a segment is locked by another process"));
                    continue;
                }
                Some(Ok(Some(st))) => st,
                Some(Err((status, reason))) => {
                    // A recording that can never be uploaded is recorded once (durably), so it is not
                    // re-examined every pass and a drain knows its disposition.
                    let mut st = skeleton(&self.ident, dir, stem, leaf, side, &id, now);
                    st.finish_with(status, &reason, now);
                    tracing::info!(recording = %id, reason, "recording upload: not queued");
                    if let Err(e) = self.store.save(&st) {
                        out.problems.push(format!("{id}: could not record why it was not queued: {}", io_why(&e)));
                    }
                    continue;
                }
            };
            if pending_bytes.saturating_add(st.total_bytes()) > self.cfg.max_pending_bytes {
                st.finish_with(Status::Refused, "queue_full", now);
                tracing::warn!(recording = %id, "recording upload: pending-bytes bound reached; not queued");
                if let Err(e) = self.store.save(&st) {
                    out.problems.push(format!("{id}: could not record why it was not queued: {}", io_why(&e)));
                }
            } else {
                match self.store.save(&st) {
                    Ok(()) => {
                        pending_bytes += st.total_bytes();
                        out.queued += 1;
                        tracing::info!(recording = %id, segments = st.segments.len(), bytes = st.total_bytes(), "recording upload: queued");
                    }
                    // Not durable => not queued => nothing will be sent for it.
                    Err(e) => out.problems.push(format!("{id}: could not be queued durably: {}", io_why(&e))),
                }
            }
            drop(lock);
        }
        out
    }

    /// `Ok(None)`: a segment is locked by another process right now. `Err`: terminal at birth.
    #[allow(clippy::too_many_arguments)]
    fn build_state(
        &self,
        dio: &dyn DirIo,
        dir: &Path,
        stem: &str,
        leaf: bool,
        side: &Sidecar,
        id: &str,
        now: i64,
    ) -> Result<Option<UploadState>, (Status, String)> {
        let refuse = |s: &str| Err((Status::Refused, s.to_string()));
        if side.device_id != self.ident.device_id {
            // A recording made under another enrollment: its key is not ours to sign for.
            return Err((Status::Abandoned, "other_device".into()));
        }
        if now.saturating_sub(side.ended_at_unix_ms) > self.cfg.max_pending_age_ms {
            return Err((Status::Abandoned, "too_old".into()));
        }
        if now >= side.delete_after_unix_ms {
            // Past its own local deadline: the sweep may take it at any moment. Not queued.
            return Err((Status::Abandoned, "expired_locally".into()));
        }
        let Some(sess) = side.session_id.as_deref().and_then(|s| uuid::Uuid::parse_str(s).ok()) else {
            return refuse("no_session");
        };
        if side.segments.is_empty() {
            return refuse("no_segments");
        }
        if side.segments.len() > MAX_SEGMENTS {
            return refuse("too_many_segments");
        }
        if let Some(t) = &side.truncated {
            // The server accepts only [a-z0-9_]{1,64}. Rewriting it would make the upload disagree with
            // the signed stop event the agent sealed, so a reason that does not fit is not uploaded.
            if t.is_empty() || t.len() > 64 || !t.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
                return refuse("bad_truncation_reason");
            }
        }
        if side.dropped_frames > (1u64 << 40) {
            return refuse("bad_dropped_frames");
        }
        let mut st = skeleton(&self.ident, dir, stem, leaf, side, id, now);
        st.session_id = sess.hyphenated().to_string();
        st.dir_id = dio.identity().ok();
        st.sidecar_id = dio.open_file(&format!("{stem}.json")).ok().map(|h| h.id);
        st.segments.clear();
        for seg in &side.segments {
            let Some(name) = crate::recording::sweepable_segment(stem, &seg.file) else {
                return refuse("bad_segment_name");
            };
            if !is_hex64(&seg.sha256) {
                return refuse("bad_digest");
            }
            let held = match dio.open_file(name) {
                Ok(h) => h,
                // The sidecar outlived a segment (swept, or an I/O failure left a hole): nothing to send.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return refuse("segment_missing"),
                // Locked or transient: not decided yet.
                Err(e) if e.raw_os_error() == Some(32) => return Ok(None),
                // A reparse point, a non-regular file, an untrusted owner/DACL: never uploaded.
                Err(_) => return refuse("unsafe_segment_file"),
            };
            if held.len == 0 || held.len > MAX_SEGMENT_BYTES {
                return refuse("bad_segment_length");
            }
            st.segments.push(SegmentState { file: name.to_string(), length: held.len, sha256: seg.sha256.clone(), committed: 0, file_id: Some(held.id) });
        }
        st.frames = side.segments.iter().map(|s| s.frames).sum();
        st.payload_bytes = side.segments.iter().map(|s| s.payload_bytes).sum();
        Ok(Some(st))
    }

    // ---- drive ---------------------------------------------------------------------------------

    /// Checks that need no network: age, identity. `Some` = the upload ends (or pauses) right now.
    fn pre_gate(&self, st: &UploadState, now: i64) -> Option<Stop> {
        if now.saturating_sub(st.enqueued_at_ms) >= self.cfg.max_pending_age_ms {
            return Some(Stop::Terminal(Status::Abandoned, "too_old".into()));
        }
        if st.tenant_id != self.ident.tenant_id
            || st.device_id != self.ident.device_id
            || st.key_fp_hex != self.ident.key_fp_hex
            || st.audience != self.ident.audience
        {
            // C9: a new key (re-enrollment) or another control plane abandons explicitly: the server
            // would refuse these requests (another key's recording), and signing them under the new
            // identity would be a lie about who recorded it.
            return Some(Stop::Terminal(Status::Abandoned, "identity_changed".into()));
        }
        None
    }

    fn paused(&self, st: &UploadState, mode: Mode) -> Option<Stop> {
        if self.stop.load(Ordering::Acquire) {
            return Some(Stop::Paused("stopping"));
        }
        // The age bound is re-checked between chunks: an upload that outlives it is durably settled (the entry's
        // hold lapses) before any sweep may delete under it.
        if let Some(stop) = self.pre_gate(st, self.clock.now_ms()) {
            return Some(stop);
        }
        match mode {
            Mode::Background => {
                // A fence raised mid-upload stops it at the next chunk; an unreadable fence stops it too (fail closed).
                if self.ops.fence_active().unwrap_or(true) {
                    return Some(Stop::Paused("fenced"));
                }
                if self.probe.session_live() {
                    return Some(Stop::Paused("session_live"));
                }
                None
            }
            Mode::Drain { deadline_ms } if self.clock.now_ms() >= deadline_ms => Some(Stop::Paused("budget")),
            Mode::Drain { .. } => None,
        }
    }

    /// Drive one listed recording: take its lifecycle lock, RELOAD the state under it (the listing may be stale; a
    /// worker that was slow must never overwrite what another finished), run the upload, then make the outcome
    /// durable while STILL holding the lock.
    fn drive(&mut self, listed: &UploadState, mode: Mode) -> Outcome {
        let name = state_lock_name(listed);
        let guard = match mode {
            Mode::Background => self.ops.try_lock(&name),
            Mode::Drain { deadline_ms } => self.ops.lock_until(&name, deadline_ms),
        };
        let guard = match guard {
            Ok(Some(g)) => g,
            Ok(None) => return if mode == Mode::Background { Outcome::Busy } else { Outcome::Problem(format!("{}: busy: its lock is held elsewhere", listed.recording_id)) },
            Err(e) => return Outcome::Problem(format!("{}: could not take the recording lock: {}", listed.recording_id, io_why(&e))),
        };
        let mut st = match self.store.reload(&listed.recording_id) {
            Ok(Some(s)) => s,
            Ok(None) => return Outcome::AlreadySettled,
            Err(e) => return Outcome::Problem(format!("{}: its queue entry is unreadable: {}", listed.recording_id, io_why(&e))),
        };
        if st.status != Status::Pending {
            return Outcome::AlreadySettled;
        }
        let result = match self.paused(&st, mode) {
            Some(stop) => Err(stop),
            None => self.drive_inner(&mut st, mode),
        };
        match result {
            Ok(()) => Outcome::Completed,
            Err(stop) => self.record_stop(&guard, &mut st, stop, mode),
        }
    }

    /// Make a stop durable, under the lock the drive still holds.
    fn record_stop(&self, guard: &LockGuard, st: &mut UploadState, stop: Stop, mode: Mode) -> Outcome {
        match stop {
            Stop::Paused(why) => {
                let _ = self.store.save(st); // progress made so far; best effort
                Outcome::Paused(why)
            }
            Stop::Retry { min_delay_s, why } => {
                if let Mode::Drain { .. } = mode {
                    // Nothing recorded: the drain decides (one more try, then abandon).
                    return Outcome::Retried(why);
                }
                st.failures += 1;
                st.last_error = Some(why.clone());
                if st.failures >= self.cfg.max_failures {
                    return self.settle_outcome(guard, st, Status::Abandoned, "retries_exhausted");
                }
                let seed = u64::from_le_bytes(st.recording_id.as_bytes()[..8].try_into().unwrap());
                st.next_attempt_at_ms = self.clock.now_ms() + backoff_ms(st.failures, seed ^ st.failures as u64, min_delay_s);
                tracing::info!(recording = %st.recording_id, failures = st.failures, error = %why, "recording upload: will retry");
                match self.store.save(st) {
                    Ok(()) => Outcome::Retried(why),
                    Err(e) => Outcome::Problem(format!("{}: could not record the retry: {}", st.recording_id, io_why(&e))),
                }
            }
            Stop::Terminal(status, reason) => self.settle_outcome(guard, st, status, &reason),
        }
    }

    fn settle_outcome(&self, guard: &LockGuard, st: &UploadState, status: Status, reason: &str) -> Outcome {
        match self.ops.settle_pending(guard, &st.recording_id, status, reason) {
            Ok(Settle::Done(_)) => Outcome::Settled(status),
            Ok(_) => Outcome::AlreadySettled,
            Err(e) => Outcome::Problem(format!("{}: could not durably settle: {}", st.recording_id, io_why(&e))),
        }
    }

    /// Open the recording directory through the trusted route and check it is the one that was queued.
    fn open_rec_dir(&self, st: &UploadState) -> Result<Box<dyn DirIo>, Stop> {
        let dio = self.fs.open(Path::new(&st.local_dir), false).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Stop::Terminal(Status::Refused, "recording_dir_missing".into()),
            _ => Stop::Terminal(Status::Refused, "untrusted_recording_dir".into()),
        })?;
        if let (Some(want), Ok(have)) = (st.dir_id, dio.identity()) {
            if want != have {
                return Err(Stop::Terminal(Status::Refused, "recording_dir_changed".into()));
            }
        }
        Ok(dio)
    }

    /// The upload proper. The caller holds the recording's lock and passes the FRESH state.
    fn drive_inner(&mut self, st: &mut UploadState, mode: Mode) -> Result<(), Stop> {
        let dio = self.open_rec_dir(st)?;
        // EVERY freshly opened handle set is hashed against the sidecar digests before anything is sent, and the
        // identities (queued entries from before identities were recorded included) are captured and saved durably
        // before the first network call.
        let mut held = self.open_segments(dio.as_ref(), st)?;
        if st.sidecar_id.is_none() {
            // An entry queued before identities were recorded adopts the sidecar's current one.
            st.sidecar_id = dio.open_file(&format!("{}.json", st.stem)).ok().map(|h| h.id);
            self.persist(st)?;
        }
        let lengths: Vec<u64> = st.segments.iter().map(|s| s.length).collect();
        let mut recreate_budget = 2;
        let mut go_finish = false;
        'run: loop {
            // 1. Make sure the server knows the recording and learn where each segment stands.
            if !st.created {
                match self.api.create(RecRef { recording_id: &st.recording_id, generation: st.generation }, &st.session_id, &lengths) {
                    Ok(ok) => {
                        self.adopt_create(st, &ok)?;
                        st.created = true;
                        // Durable before the first byte of this generation is sent.
                        self.persist(st)?;
                    }
                    Err(f) => match classify(Op::Create, &f) {
                        Disposition::GoFinish => {
                            st.created = true;
                            go_finish = true;
                        }
                        d => return Err(self.stop_for(st, d, &f, Op::Create)),
                    },
                }
            } else if !go_finish {
                self.resync(st)?;
            }
            // 2. Send what is missing, one chunk at a time, from the held handles.
            if !go_finish {
                #[allow(clippy::needless_range_loop)] // `st` is mutated inside the loop, so it cannot be borrowed by an iterator
                for idx in 0..st.segments.len() {
                    loop {
                        let seg = st.segments[idx].clone();
                        if seg.committed >= seg.length {
                            break;
                        }
                        if let Some(stop) = self.paused(st, mode) {
                            return Err(stop);
                        }
                        let want = (seg.length - seg.committed).min(CHUNK_SIZE);
                        let chunk = read_chunk(&mut held[idx], &seg, seg.committed, want)?;
                        let t0 = std::time::Instant::now();
                        let rec = RecRef { recording_id: &st.recording_id, generation: st.generation };
                        match self.api.put(rec, idx as u32, seg.committed, &chunk) {
                            Ok(ok) => {
                                // The server's offset is authoritative but can only move forward by this chunk
                                // (or stay, for a re-send); anything else is a protocol surprise we resync from.
                                let expect = seg.committed + want;
                                if ok.committed != expect && !(ok.resent && ok.committed >= seg.committed) {
                                    st.segments[idx].committed = ok.committed.min(seg.length);
                                    self.persist(st)?;
                                    continue 'run;
                                }
                                st.segments[idx].committed = ok.committed.min(seg.length);
                                if st.segments[idx].committed <= seg.committed {
                                    // A "success" that moved nothing (a re-send answer at the offset we already held) is NOT progress: it
                                    // must not reset the failure count, or a server answering this way keeps the worker (and the
                                    // recording's lock) in a loop forever. Hand it back to the scheduler as a failed attempt (backoff,
                                    // bounded by max_failures).
                                    self.persist(st)?;
                                    return Err(Stop::Retry { min_delay_s: None, why: "put: the server accepted the chunk but made no forward progress".into() });
                                }
                                st.failures = 0;
                                st.last_error = None;
                                self.persist(st)?;
                                self.pace(mode, want, t0);
                            }
                            Err(f) => match classify(Op::Put, &f) {
                                Disposition::Resync => {
                                    if let Some(c) = f.committed_offset {
                                        st.segments[idx].committed = c.min(seg.length);
                                    }
                                    st.failures += 1;
                                    if st.failures >= self.cfg.max_failures {
                                        return Err(Stop::Terminal(Status::Abandoned, "retries_exhausted".into()));
                                    }
                                    if f.code == "chunk_conflict" {
                                        // Different bytes already sit at an offset the server committed: the
                                        // local file is not what that server holds. Not retryable.
                                        return Err(Stop::Terminal(Status::Refused, "chunk_conflict".into()));
                                    }
                                    self.persist(st)?;
                                    st.created = true;
                                    self.resync(st)?;
                                }
                                Disposition::GoFinish => {
                                    go_finish = true;
                                    continue 'run;
                                }
                                Disposition::Recreate if recreate_budget > 0 => {
                                    recreate_budget -= 1;
                                    st.created = false;
                                    continue 'run;
                                }
                                d => return Err(self.stop_for(st, d, &f, Op::Put)),
                            },
                        }
                    }
                }
            }
            // 3. Finish: attest the digests; the answer must bind ours before anything is deleted.
            let req = FinishReq {
                digests: st.segments.iter().map(|s| s.sha256.clone()).collect(),
                truncated: st.truncated.clone(),
                dropped_frames: st.dropped_frames,
                frames: st.frames,
                payload_bytes: st.payload_bytes,
            };
            if let Some(stop) = self.paused(st, mode) {
                return Err(stop);
            }
            match self.api.finish(RecRef { recording_id: &st.recording_id, generation: st.generation }, &req) {
                Ok(ack) => {
                    // The held handles close BEFORE the delete (a held, read-shared file cannot be removed).
                    drop(held);
                    return self.complete(st, &req, &ack, dio.as_ref());
                }
                Err(f) => match classify(Op::Finish, &f) {
                    Disposition::Resync => {
                        // 409 incomplete: the server holds less than we believed. `resync` at the top of
                        // the loop asks it where every segment stands.
                        go_finish = false;
                        st.created = true;
                        st.failures += 1;
                        if st.failures >= self.cfg.max_failures {
                            return Err(Stop::Terminal(Status::Abandoned, "retries_exhausted".into()));
                        }
                        self.persist(st)?;
                        continue 'run;
                    }
                    Disposition::DigestReset { segments } => {
                        st.digest_failures += 1;
                        if st.digest_failures >= MAX_DIGEST_FAILURES {
                            return Err(Stop::Terminal(Status::Refused, "digest_mismatch".into()));
                        }
                        for i in &segments {
                            if let Some(s) = st.segments.get_mut(*i as usize) {
                                s.committed = 0;
                            }
                        }
                        go_finish = false;
                        self.persist(st)?;
                        // Re-open and RE-HASH: whatever corrupted the first copy may be on this side.
                        drop(held);
                        held = self.open_segments(dio.as_ref(), st)?;
                        continue 'run;
                    }
                    Disposition::Recreate if recreate_budget > 0 => {
                        recreate_budget -= 1;
                        st.created = false;
                        go_finish = false;
                        continue 'run;
                    }
                    Disposition::GoFinish => {
                        // `already_complete` on finish itself is not a documented answer; treat as a conflict
                        // rather than loop.
                        return Err(Stop::Terminal(Status::Refused, "conflict".into()));
                    }
                    d => return Err(self.stop_for(st, d, &f, Op::Finish)),
                },
            }
        }
    }

    fn persist(&self, st: &UploadState) -> Result<(), Stop> {
        self.store
            .save(st)
            .map_err(|e| Stop::Retry { min_delay_s: None, why: format!("the queue state is not durable: {}", io_why(&e)) })
    }

    fn stop_for(&self, st: &UploadState, d: Disposition, f: &ApiFail, op: Op) -> Stop {
        let stop = match d {
            Disposition::Retry { min_delay_s } => Stop::Retry {
                min_delay_s,
                why: if f.status == 0 {
                    format!("{op:?}: transport: {}", f.code)
                } else {
                    format!("{op:?}: {} {}", f.status, f.code)
                },
            },
            Disposition::Terminal { status, reason } => Stop::Terminal(status, reason),
            // Dispositions the caller handles in-line, reaching here only when its budget ran out.
            Disposition::Recreate => Stop::Terminal(Status::Refused, "not_found".into()),
            Disposition::Resync | Disposition::GoFinish | Disposition::DigestReset { .. } => {
                Stop::Terminal(Status::Refused, "unexpected_state".into())
            }
        };
        if let Stop::Terminal(status, reason) = &stop {
            tracing::info!(recording = %st.recording_id, ?status, reason, "recording upload: server answer is terminal");
        }
        stop
    }

    fn adopt_create(&self, st: &mut UploadState, ok: &CreateOk) -> Result<(), Stop> {
        if ok.generation != st.generation || ok.segments.len() != st.segments.len() {
            return Err(Stop::Terminal(Status::Refused, "create_answer_mismatch".into()));
        }
        for (i, (idx, len, committed)) in ok.segments.iter().enumerate() {
            if *idx as usize != i || *len != st.segments[i].length || *committed > *len {
                return Err(Stop::Terminal(Status::Refused, "create_answer_mismatch".into()));
            }
            st.segments[i].committed = *committed;
        }
        if ok.chunk_size != CHUNK_SIZE {
            // Chunk geometry is fixed by the contract; a server announcing another is not this protocol.
            return Err(Stop::Terminal(Status::Refused, "chunk_size_mismatch".into()));
        }
        if ok.state != "uploading" && ok.state != "evidence_complete" && ok.state != "playback_ready" && ok.state != "playback_failed" {
            return Err(Stop::Terminal(Status::Refused, format!("server_state_{}", sanitize(&ok.state))));
        }
        Ok(())
    }

    /// HEAD every segment that is not known complete and adopt the server's committed offset.
    fn resync(&mut self, st: &mut UploadState) -> Result<(), Stop> {
        for idx in 0..st.segments.len() {
            let rec = RecRef { recording_id: &st.recording_id, generation: st.generation };
            match self.api.head(rec, idx as u32) {
                Ok(h) => {
                    if h.length != st.segments[idx].length || h.committed > h.length {
                        return Err(Stop::Terminal(Status::Refused, "server_length_mismatch".into()));
                    }
                    st.segments[idx].committed = h.committed;
                }
                Err(f) => match classify(Op::Head, &f) {
                    Disposition::Recreate => {
                        st.created = false;
                        self.persist(st)?;
                        return Err(Stop::Retry { min_delay_s: None, why: "head: recording unknown to the server; will re-create".into() });
                    }
                    d => return Err(self.stop_for(st, d, &f, Op::Head)),
                },
            }
        }
        self.persist(st)
    }

    fn pace(&self, mode: Mode, bytes: u64, t0: std::time::Instant) {
        if mode != Mode::Background || self.cfg.rate_bytes_per_sec == 0 {
            return;
        }
        let min = Duration::from_micros(bytes.saturating_mul(1_000_000) / self.cfg.rate_bytes_per_sec);
        let used = t0.elapsed();
        if min > used {
            self.clock.sleep(min - used);
        }
    }

    /// Open every segment ONCE into a held handle (read-shared: nobody can write, rename or delete it while it
    /// is held), check it is the file that was queued (identity and size where recorded), and stream-hash EVERY
    /// freshly opened handle against the sidecar digest — no cached "unchanged" shortcut. An entry queued without
    /// identities adopts the ones it was just proven to have, and the entry is saved durably before returning (so
    /// before any network call). All later reads use these handles.
    fn open_segments(&self, dio: &dyn DirIo, st: &mut UploadState) -> Result<Vec<HeldFile>, Stop> {
        let mut held = Vec::with_capacity(st.segments.len());
        for seg in &st.segments {
            let h = dio.open_file(&seg.file).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Stop::Terminal(Status::Refused, "segment_missing".into()),
                _ if e.raw_os_error() == Some(32) => Stop::Retry { min_delay_s: None, why: "segment is locked by another process".into() },
                _ => Stop::Terminal(Status::Refused, "unsafe_segment_file".into()),
            })?;
            if h.len != seg.length || seg.file_id.is_some_and(|want| want != h.id) {
                return Err(Stop::Terminal(Status::Refused, "local_file_changed".into()));
            }
            held.push(h);
        }
        for (h, seg) in held.iter_mut().zip(&st.segments) {
            h.file.seek(SeekFrom::Start(0)).map_err(|e| Stop::Retry { min_delay_s: None, why: format!("local seek: {e}") })?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            // Bounded by the declared length: a file that grows is a different file.
            let mut rd = (&h.file).take(seg.length + 1);
            loop {
                let n = rd.read(&mut buf).map_err(|e| Stop::Retry { min_delay_s: None, why: format!("local read: {e}") })?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                total += n as u64;
            }
            if total != seg.length || hex::encode(hasher.finalize()) != seg.sha256 {
                return Err(Stop::Terminal(Status::Refused, "local_file_changed".into()));
            }
        }
        let mut migrated = false;
        for (h, seg) in held.iter().zip(st.segments.iter_mut()) {
            if seg.file_id.is_none() {
                seg.file_id = Some(h.id);
                migrated = true;
            }
        }
        st.verified_sig = Some(held.iter().map(|h| format!("{}:{}", h.len, h.mtime_ms)).collect::<Vec<_>>().join(";"));
        if migrated {
            self.persist(st)?;
        }
        Ok(held)
    }

    /// The finish acknowledgement must bind recording id, generation, the exact ordered digest list and
    /// status `evidence_complete` (C9) before the local copy is deleted. The terminal `Complete` state (with the
    /// acknowledged digests) is made durable BEFORE any file goes; a state that cannot be saved deletes nothing.
    fn complete(&mut self, st: &mut UploadState, req: &FinishReq, ack: &FinishOk, dio: &dyn DirIo) -> Result<(), Stop> {
        let binds = ack.recording_id == st.recording_id
            && ack.generation == st.generation
            && ack.state == "evidence_complete"
            && ack.digests == req.digests;
        if !binds {
            tracing::error!(recording = %st.recording_id, ack_state = %ack.state, "recording upload: finish acknowledgement does not bind this recording; local copy KEPT");
            return Err(Stop::Terminal(Status::Refused, "ack_mismatch".into()));
        }
        st.ack_digests = Some(ack.digests.clone());
        let before = st.clone();
        for s in &mut st.segments {
            s.committed = s.length;
        }
        st.finish_with(Status::Complete, "evidence_complete", self.clock.now_ms());
        if let Err(e) = self.store.save(st) {
            *st = before;
            st.ack_digests = None;
            return Err(Stop::Retry { min_delay_s: None, why: format!("could not record completion durably (local copy kept): {}", io_why(&e)) });
        }
        tracing::info!(recording = %st.recording_id, "recording upload: complete (server confirmed evidence_complete)");
        self.cleanup_with(st, dio);
        Ok(())
    }

    /// Delete ONLY the segments the confirmed acknowledgement named, each only if it is still the file that was
    /// queued (identity), then the sidecar the same way. Idempotent; a state that is not durably `Complete` with
    /// matching acknowledged digests deletes nothing. The caller holds the recording's lock.
    fn cleanup_with(&self, st: &mut UploadState, dio: &dyn DirIo) {
        let Some(ack) = st.ack_digests.clone() else { return };
        if st.status != Status::Complete || ack.len() != st.segments.len() {
            return;
        }
        let mut ok = true;
        for (seg, acked) in st.segments.iter().zip(&ack) {
            if &seg.sha256 != acked {
                ok = false;
                continue;
            }
            let Some(id) = seg.file_id else {
                ok = false;
                continue;
            };
            if let Err(e) = dio.remove_file_if(&seg.file, &id) {
                tracing::warn!(file = %seg.file, error = %e, "recording upload: could not delete an uploaded segment; will retry");
                ok = false;
            }
        }
        let sidecar = format!("{}.json", st.stem);
        match st.sidecar_id {
            Some(id) => {
                if let Err(e) = dio.remove_file_if(&sidecar, &id) {
                    tracing::warn!(error = %e, "recording upload: could not delete the sidecar; will retry");
                    ok = false;
                }
            }
            None => ok = false,
        }
        if ok && st.leaf_dir {
            if let Some(parent) = Path::new(&st.local_dir).parent() {
                if let (Ok(p), Some(leaf)) = (self.fs.open(parent, false), Path::new(&st.local_dir).file_name().and_then(|n| n.to_str())) {
                    let _ = p.remove_empty_subdir(leaf);
                }
            }
        }
        if ok {
            st.local_cleaned = true;
            let _ = self.store.save(st);
        }
    }
}

/// Read exactly `len` bytes at `offset` of a held segment, within its declared length.
fn read_chunk(h: &mut HeldFile, seg: &SegmentState, offset: u64, len: u64) -> Result<Vec<u8>, Stop> {
    if offset.checked_add(len).is_none_or(|end| end > seg.length) {
        return Err(Stop::Terminal(Status::Refused, "read_out_of_bounds".into()));
    }
    let io = |e: std::io::Error| Stop::Retry { min_delay_s: None, why: format!("local read {}: {e}", seg.file) };
    h.file.seek(SeekFrom::Start(offset)).map_err(io)?;
    let mut buf = vec![0u8; len as usize];
    h.file.read_exact(&mut buf).map_err(io)?;
    Ok(buf)
}

/// Abandon every pending entry durably under each recording's lock (see [`QueueOps::abandon_pending`]). `Ok(n)`:
/// n abandoned and none remains pending.
pub fn abandon_all_in(ops: &QueueOps, reason: &str) -> Result<u32, Vec<String>> {
    ops.abandon_for_reenrollment(reason, Duration::from_secs(30))
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(32).collect()
}

#[cfg(test)]
#[path = "recording_upload_tests.rs"]
mod tests;
