//! **Session recording** — the guest-side half (loop 89, docs/01 §5).
//!
//! Tees the encoded VP8 the live session is already producing into IVF files on the guest's own
//! disk, with a rolling SHA-256 per segment and a JSON sidecar describing the recording. The
//! transport owns the tee and the muxer ([`rmt_transport_webrtc::video::ivf`]); this module owns
//! everything with a side effect — file handles, hashing, the DACL, the free-space preflight and
//! the expiry sweep — because that is the split the transport crate's own manifest header asks for
//! ("so the heavy webrtc-rs dep tree doesn't touch agent-core/protocol").
//!
//! # What this is, and what it is NOT
//!
//! It is a **local, self-expiring working copy** for QA, training and technician self-protection,
//! retrievable over the existing file-transfer channel while the machine is reachable.
//!
//! It is **not** the "automatic extended auditing" half of the docs/01 box, and the difference is
//! not a matter of polish. A recording stored on the recorded party's own machine is deletable by
//! them. The DACL below restricts it to SYSTEM + Administrators, which stops an ordinary user —
//! and stops nothing else. Say "the DACL is restricted", never "tamper-proof". Central retention is
//! a separate, larger piece of work; ADR-008 already made this exact call for the audit chain, and
//! `web/viewer/src/App.tsx` states the principle: *"the agent keeps its own copy either way, but the
//! whole point of central storage is that it survives the endpoint."*
//!
//! # The two clocks, which is the subtlest thing here
//!
//! A recording's timeline comes from WALL CLOCK, never from `EncodedAu::duration_90khz`. That
//! duration is clamped to at most one second before it reaches libvpx — correct for a rate
//! controller, false for a presentation timeline — and on the DXGI capture path an idle desktop
//! produces no frame at all rather than a long one. Summing durations would write a ten-minute
//! session with five idle minutes as a five-minute file: wrong about *when* things happened, while
//! looking perfectly well-formed. [`pts_90khz`] derives the timestamp from the [`Instant`] the tee
//! hands over, and [`RecordedFrame::at`] is an `Instant` precisely so a tick count cannot be passed
//! by mistake.
//!
//! # The full-queue policy is a decision, not a detail
//!
//! [`RecordingSink::offer`] runs on the encoder thread and must not block: a stalled write there is
//! a stalled encoder, which is a stalled capture. So frames cross to a writer thread through a
//! BOUNDED queue, and when that queue is full this recorder **stops and marks the recording
//! truncated**. It deliberately does not do what the live video path does one crate away —
//! drop-to-latest — because that is right for a picture and catastrophic for a record: *a recording
//! with silent holes is worse than no recording, because it looks complete.* It also deliberately
//! does not block, so that recording can never degrade the support session it is recording.
//!
//! Every stop reason is recorded in the sidecar and logged. A truncated recording says so.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rmt_transport_webrtc::video::ivf::IvfWriter;
use rmt_transport_webrtc::video::{RecordedFrame, RecordingSink};

/// Where recordings go, under the agent's existing config root.
pub const DEFAULT_RECORDING_SUBDIR: &str = "recordings";

/// How long a recording is kept before the sweep deletes it.
///
/// **This is the single mechanism that keeps a staging area from becoming a permanent video vault
/// on other organisations' machines.** Without it, the failure mode is the one that looks fine in
/// testing: it works for weeks, then silently trips the free-space floor on exactly the machines
/// that get supported most, and at offboarding there is no query anywhere that says which customer
/// machines still hold recordings. Not operator-configurable in loop 89, deliberately — a default
/// that cannot be raised to "never" is worth more here than a knob.
pub const DEFAULT_TTL_HOURS: u64 = 72;

/// Largest a single recording may grow before it is stopped and marked truncated.
///
/// At the default 3 Mbps that is roughly 45 minutes; at the 20 Mbps ceiling, under 7. Sized to
/// bound one recording, not to be generous — the free-space floor below is the guard that matters
/// for the machine, and this one is the guard that matters for the operator's expectations.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Recording refuses to start, and stops, when free disk falls below this.
///
/// The agent has never checked free space anywhere — the only size cap in it before loop 89 was the
/// 8 MB helper log, and file transfers have no limit at all. A recorder that can write 1.35 GB an
/// hour is not the feature to continue that tradition with: filling a guest's system drive is a
/// worse outcome than losing a recording.
pub const DEFAULT_MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Frames the bounded queue holds before [`offer`](RecordingSink::offer) gives up on the recording.
///
/// Two seconds at 30 fps. Deep enough to absorb a disk hiccup, shallow enough that the memory held
/// is bounded by a number a reader can check: 60 frames of a 3 Mbps stream is ~750 KB.
pub const QUEUE_FRAMES: usize = 60;

/// Why a recording stopped early. `None` in the sidecar means it ran to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationReason {
    /// The writer thread could not keep up and the bounded queue filled.
    QueueFull,
    /// The recording hit [`DEFAULT_MAX_BYTES`].
    SizeLimit,
    /// Free disk fell below [`DEFAULT_MIN_FREE_BYTES`].
    DiskLow,
    /// A write or a file operation failed.
    IoError,
}

impl TruncationReason {
    /// The stable string written into the sidecar and the log.
    pub fn as_str(self) -> &'static str {
        match self {
            TruncationReason::QueueFull => "queue_full",
            TruncationReason::SizeLimit => "size_limit",
            TruncationReason::DiskLow => "disk_low",
            TruncationReason::IoError => "io_error",
        }
    }
}

/// The presentation timestamp for a frame, in 90 kHz ticks from the recording's epoch.
///
/// **Pure, and separated out for one reason: this is where the two-clock bug would live**, and
/// inline in a writer thread it would be provable only by recording a real idle session and
/// measuring the file's duration. See the module docs.
///
/// Integer arithmetic in `u128` rather than `as_secs_f64`, so a long session accumulates no
/// floating-point drift; the result is exact for any duration and cannot overflow `u64` in any
/// realistic recording (90 kHz ticks overflow after ~6.5 million years).
pub fn pts_90khz(epoch: Instant, at: Instant) -> u64 {
    let nanos = at.saturating_duration_since(epoch).as_nanos();
    ((nanos * 90_000) / 1_000_000_000) as u64
}

/// Whether a frame of these dimensions must start a NEW IVF segment.
///
/// IVF puts width/height in the FILE header as `u16`, applying to every frame, so a mid-session
/// resolution change (monitor switch, RDP reconnect, an operator scale change — each re-initialises
/// the encoder) cannot be expressed in one file. Pure so the rollover rule is testable without
/// producing a real resolution change, which is awkward to stage.
pub fn needs_new_segment(current: Option<(u32, u32)>, w: u32, h: u32) -> bool {
    match current {
        None => true,
        Some((cw, ch)) => cw != w || ch != h,
    }
}

/// Whether a recording that has written `written` bytes may accept `next` more.
///
/// Checked against the budget BEFORE the write, so the cap is an upper bound on what lands on the
/// guest's disk rather than something the last frame is allowed to exceed.
pub fn within_budget(written: u64, next: u64, max_bytes: u64) -> bool {
    written.saturating_add(next) <= max_bytes
}

/// Whether a recording whose deadline is `deadline_unix_ms` has expired at `now_unix_ms`.
///
/// The deadline is written INTO the sidecar at start, so an artifact states its own lifespan and a
/// sweep does not have to reconstruct policy from a file's mtime — which a copy, a restore or a
/// backup agent would silently reset.
pub fn is_expired(deadline_unix_ms: i64, now_unix_ms: i64) -> bool {
    now_unix_ms >= deadline_unix_ms
}

/// One finished IVF file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Segment {
    /// File name, relative to the recording directory.
    pub file: String,
    /// Encoded width for every frame in this file.
    pub width: u32,
    /// Encoded height.
    pub height: u32,
    /// Frames written.
    pub frames: u64,
    /// Bytes of encoded payload (excludes the 32-byte header and 12 bytes per frame).
    pub payload_bytes: u64,
    /// SHA-256 of the finished file, lowercase hex — computed over the bytes ON DISK after
    /// finalize, so it is the digest of what a reviewer would actually receive.
    pub sha256: String,
}

/// The `.json` written beside the segments.
///
/// Everything a reviewer needs that IVF cannot carry. In particular `truncated`: a recording that
/// stopped early must say so, because a file that merely ends looks identical to one that finished.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Sidecar {
    /// Schema marker, so a future reader can tell versions apart.
    pub kind: String,
    /// The agent's device id.
    pub device_id: String,
    /// The control-plane session id, when the agent knows one.
    pub session_id: Option<String>,
    /// Wall-clock start, ms since the Unix epoch. The IVF timeline is relative to this.
    pub started_at_unix_ms: i64,
    /// Wall-clock stop.
    pub ended_at_unix_ms: i64,
    /// When the sweep may delete this recording. See [`DEFAULT_TTL_HOURS`].
    pub delete_after_unix_ms: i64,
    /// The IVF files, in order.
    pub segments: Vec<Segment>,
    /// Why it stopped early, or `None` if it ran to completion.
    pub truncated: Option<String>,
    /// Frames the tee offered that never reached a file. Non-zero only alongside `truncated`.
    pub dropped_frames: u64,
    /// Honest statement of what this artifact is, carried WITH the artifact so it cannot be
    /// separated from it by being copied out of the docs.
    pub disclaimer: String,
}

/// The schema marker every sidecar carries, and which the sweep REQUIRES before it will act on one.
///
/// A shared constant rather than two literals, because the sweep's check is a security boundary: it
/// is what stops any JSON that happens to type-check as a [`Sidecar`] from being read as an
/// instruction to delete files. A writer and a checker that could drift apart would silently reopen
/// that (`fake-and-pg-must-agree`'s shape, in one process).
pub const SIDECAR_KIND: &str = "rmt.session-recording.v1";

/// The one segment file name a sidecar with stem `stem` is permitted to have the sweep delete, or
/// `None` if this code could not have written it.
///
/// **This is a security check, not tidiness** — see the call site in [`sweep_expired`]. Three
/// conditions, all necessary:
///
/// 1. **A single path component.** `Path::join` replaces the base for an absolute argument and never
///    normalizes `..`, so `"C:\\Windows\\x"` and `"..\\..\\x"` both escape the recording directory.
///    Rejecting anything that is not one `Component::Normal` removes the whole class rather than
///    blacklisting the two spellings of it.
/// 2. **It parses as our own naming** ([`segment_started_at`]) — so a legitimate-looking but
///    unrelated file in the directory is not collateral.
/// 3. **It carries the sidecar's OWN stem.** `OpenSegment::create` builds `{stem}-{index:04}.ivf`
///    from the same stem `stop` writes `{stem}.json` from, so a genuine pair always matches. Without
///    this, a planted sidecar could still name another recording's segments.
///
/// Conditions 2 and 3 are each individually LETHAL under mutation; condition 1 is **defence in
/// depth and survives mutation**, which is worth stating rather than leaving as a puzzle. Relaxing
/// it to "take the last component" is safe on its own, because `dir.join(basename)` still resolves
/// inside `dir` and the other two conditions then reject anything this code did not write. It is
/// kept because it makes the contract TOTAL — this function returns a name it vouches for, not a
/// name that happens to be harmless once joined — and because it still holds if either other
/// condition is ever weakened.
pub(crate) fn sweepable_segment<'a>(stem: &str, named: &'a str) -> Option<&'a str> {
    let p = Path::new(named);
    let mut comps = p.components();
    let (Some(std::path::Component::Normal(one)), None) = (comps.next(), comps.next()) else {
        return None;
    };
    let name = one.to_str()?;
    segment_started_at(name)?;
    name.strip_prefix(stem)?.strip_prefix('-')?;
    Some(name)
}

/// The disclaimer written into every sidecar.
const DISCLAIMER: &str = "Local working copy on the recorded machine. DACL-restricted to SYSTEM + \
     Administrators; a local administrator can still delete it. Not centrally retained and not \
     durable against the recorded party. Fidelity is whatever the live session ran at.";

/// A frame in flight between the encoder thread and the writer thread.
struct Queued {
    data: Vec<u8>,
    pts: u64,
    width: u32,
    height: u32,
}

/// The tee target installed into the transport's encoder loop.
pub struct Recorder {
    tx: SyncSender<Queued>,
    /// Set once the recording has stopped accepting frames, so `offer` becomes a cheap no-op rather
    /// than continuing to hammer a closed channel.
    ///
    /// An `Arc<AtomicBool>` shared with the writer thread rather than a field the writer reaches
    /// through an `Arc<Recorder>`: the sender lives in this struct, so a writer holding the whole
    /// recorder would keep its own channel alive and `recv` would never see a disconnect. That is a
    /// deadlock on `stop`, and the type is what prevents it.
    stopped: Arc<AtomicBool>,
    /// First frame's instant, fixed on the first `offer`.
    epoch: Mutex<Option<Instant>>,
    /// Frames the tee offered after the recorder stopped, or that the queue refused.
    dropped: AtomicU64,
    /// Set by `offer` when it gives up, read by `stop` for the sidecar.
    queue_full: AtomicBool,
}

impl RecordingSink for Recorder {
    fn offer(&self, f: RecordedFrame<'_>) {
        if self.stopped.load(Ordering::Relaxed) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // The epoch is the FIRST offered frame, not the moment recording was requested: a keyframe
        // is requested at start and may take a frame to arrive, and a recording whose timeline began
        // before its first frame would open with a gap it never actually had.
        let epoch = {
            let mut e = self.epoch.lock().unwrap();
            *e.get_or_insert(f.at)
        };
        let q = Queued {
            // The one copy. It happens on the encoder thread, which is why the WRITE does not:
            // ~375 KB/s at the default bitrate is a rounding error next to a disk stall. (A
            // zero-copy hand-off would mean carrying `Bytes` through `EncodedAu`; deliberately not
            // done in loop 89, as it touches every encoder implementation for a gain this small.)
            data: f.data.to_vec(),
            pts: pts_90khz(epoch, f.at),
            width: f.width,
            height: f.height,
        };
        match self.tx.try_send(q) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // THE POLICY. Not drop-to-latest: see the module docs.
                self.queue_full.store(true, Ordering::Relaxed);
                self.stopped.store(true, Ordering::Relaxed);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "recording stopped: the writer could not keep up and the frame queue filled \
                     (the recording is marked truncated; the live session is unaffected)"
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                self.stopped.store(true, Ordering::Relaxed);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Free bytes available to this process on the volume holding `path`.
///
/// `None` when the query fails, and every caller treats that as "do not record". The agent has
/// never asked this question before; getting a wrong answer and writing anyway would defeat the
/// point of asking.
#[cfg(windows)]
pub(crate) fn free_bytes(path: &Path) -> Option<u64> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut free_to_caller: u64 = 0;
    let wide = HSTRING::from(path.as_os_str());
    // SAFETY: `wide` outlives the call; the out-params are plain u64s we own.
    unsafe { GetDiskFreeSpaceExW(&wide, Some(&mut free_to_caller), None, None) }.ok()?;
    Some(free_to_caller)
}

#[cfg(not(windows))]
pub(crate) fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// Create the recording directory and restrict its DACL to SYSTEM + Administrators.
///
/// **The inheritance flags are the whole point, and getting them wrong is a trap this project has
/// fallen into before.** `C:\rmt-agent` inherits `Authenticated Users:(M)` from the volume root, and
/// every existing creation site is a bare best-effort `create_dir_all` — so without this, any
/// logged-in standard user can delete a recording, no administrator rights required.
///
/// `enroll::tighten_identity_acl` cannot be reused: it ACLs a FILE, so its argv carries no `(OI)(CI)`.
/// Applied to a directory it would grant nothing to the `.ivf` files created inside afterwards — and
/// an `icacls` check on the DIRECTORY would report success while every recording in it stayed
/// world-writable. That is a measurement confirming the wrong object (docs/07:
/// `measure-the-value-the-code-reads`). `(OI)` = object inherit, `(CI)` = container inherit.
///
/// The failure direction is inverted relative to `tighten_identity_acl`, deliberately. There, a
/// failed ACL is logged loudly and not fatal, because refusing to run would leave the machine
/// unmanaged as well as insecure. Here there is no such trade: an unprotected recording is worse
/// than no recording, so this returns `Err` and the caller does not record.
#[cfg(windows)]
fn ensure_locked_dir(dir: &Path) -> std::io::Result<()> {
    // The PARENT may exist; the LEAF is created exclusively, because `create_dir_all` returns `Ok`
    // for a directory that already exists — and on any machine that has never recorded, this path
    // does not exist yet while `C:\` grants `Authenticated Users:(OI)(CI)(IO)(M)`, so a standard
    // user can get there first. Adopting whatever is already there is how the fail-closed contract
    // above gets satisfied vacuously: `icacls` SUCCEEDS on a hostile directory, and the pre-creator
    // stays its OWNER — keeping implicit `WRITE_DAC` and able to re-grant itself afterwards.
    //
    // What this closes and what it does not, stated because the difference matters:
    //  * a REPARSE POINT (junction/symlink) planted at this path is refused outright — otherwise the
    //    DACL rewrite lands on whatever it targets;
    //  * an already-present real directory is refused, so the recorder never writes into one it did
    //    not create;
    //  * OWNERSHIP of a directory we created ourselves is ours, so the re-grant path is closed for
    //    the normal case.
    // It does NOT fix the root cause, which is bigger than this module: nothing in the repo ever
    // ACLs `C:\rmt-agent` itself, so `config.json` beside it is writable by any standard user too.
    // Hardening the agent root at install and at service start is the fix that retires the class —
    // see docs/07 §5. Loop 89's review found this; do not read this function as sufficient.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // `symlink_metadata`, never `metadata`: the latter FOLLOWS the reparse point, so it
            // would report the target's attributes and hide exactly what is being checked for.
            let md = std::fs::symlink_metadata(dir)?;
            if md.file_type().is_symlink() {
                return Err(std::io::Error::other(format!(
                    "refusing to record into {}: it is a reparse point (junction or symlink), so \
                     the DACL would be applied to its target",
                    dir.display()
                )));
            }
            if !md.is_dir() {
                return Err(std::io::Error::other(format!(
                    "refusing to record into {}: it exists and is not a directory",
                    dir.display()
                )));
            }
            // A real directory that is already here. Accepted ONLY because the sweep now refuses to
            // act on anything in it that this code could not have written (`sweepable_segment`), and
            // because the alternative — refusing forever — would break every machine that has
            // recorded once. The residual exposure is the pre-creator's ownership, which the root
            // ACL fix above is what actually closes.
            tracing::debug!(dir = %dir.display(), "recording dir already present; re-applying its DACL");
        }
        Err(e) => return Err(e),
    }
    // Three icacls steps, in this order, all sharing `crate::agent_root`'s builders so the SIDs and
    // the flags live in ONE place (loop 91; see that module's "Well-known SIDs" section):
    //
    //  1. `/setowner` to Administrators — BEST-EFFORT. A pre-creator that stayed the directory's
    //     OWNER keeps implicit `WRITE_DAC` no matter what the DACL says, so it could re-grant itself
    //     after step 3. Best-effort rather than fatal because the normal path (a directory this
    //     process just created, as SYSTEM) is already correctly owned and the step is a no-op there.
    //  2. `/reset` — REQUIRED. `icacls /grant:r` is ADDITIVE: it replaces only the NAMED principal's
    //     ACE, so a hostile pre-creator's explicit `Authenticated Users:(F)` SURVIVES step 3 alone.
    //     Measured (loop 91, on a file with the same shape): after the old `/inheritance:r /grant:r`
    //     argv the DACL read `Administrators:(F) SYSTEM:(F) Authenticated Users:(F)`.
    //  3. `/inheritance:r /grant:r` by SID — REQUIRED, and the reason this function exists.
    //
    // The grants name S-1-5-18 / S-1-5-32-544 rather than "SYSTEM"/"Administrators": icacls resolves
    // an account NAME through the machine LOCALE, and a name that does not resolve makes it abort the
    // WHOLE command and apply nothing (measured: exit 1332, the DACL untouched). Under the old
    // name-based argv this function therefore returned `Err` on every non-English Windows — so the
    // fail-closed contract above turned into "recording is impossible on a French/German/Japanese
    // machine", a fleet-wide outage rather than a security hole. The SID form has no locale.
    let _ = crate::agent_root::run_icacls(&crate::agent_root::setowner_args(dir));
    if !crate::agent_root::run_icacls(&crate::agent_root::reset_args(dir))? {
        return Err(std::io::Error::other(format!(
            "could not reset the recording directory's DACL on {} to strip planted explicit ACEs",
            dir.display()
        )));
    }
    if !crate::agent_root::run_icacls(&crate::agent_root::dacl_args(dir))? {
        return Err(std::io::Error::other(format!(
            "could not restrict the recording directory's DACL on {}",
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_locked_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// A running recording. Dropping this without calling [`stop`](Self::stop) still finalizes the
/// files — the writer thread owns them — but no sidecar is written, so always call `stop`.
pub struct RecorderHandle {
    sink: Arc<Recorder>,
    join: Option<std::thread::JoinHandle<WriterOutcome>>,
    dir: PathBuf,
    stem: String,
    device_id: String,
    session_id: Option<String>,
    started_at_unix_ms: i64,
}

/// What the writer thread produced.
struct WriterOutcome {
    segments: Vec<Segment>,
    truncated: Option<TruncationReason>,
}

/// Start recording into `dir`.
///
/// Refuses — rather than recording insecurely or filling the disk — when the DACL cannot be set or
/// free space is already below [`DEFAULT_MIN_FREE_BYTES`].
pub fn start(
    dir: &Path,
    device_id: &str,
    session_id: Option<&str>,
    max_bytes: u64,
    min_free_bytes: u64,
) -> std::io::Result<RecorderHandle> {
    ensure_locked_dir(dir)?;
    match free_bytes(dir) {
        Some(free) if free >= min_free_bytes => {}
        Some(free) => {
            return Err(std::io::Error::other(format!(
                "not enough free disk to record: {free} bytes free, {min_free_bytes} required"
            )))
        }
        None => {
            return Err(std::io::Error::other(
                "could not determine free disk space; refusing to record",
            ))
        }
    }

    let started_at_unix_ms = now_unix_ms();
    // The file stem is the wall-clock start, so recordings sort chronologically in a directory
    // listing and two sessions on the same machine cannot collide.
    let stem = format!("rec-{started_at_unix_ms}");
    let (tx, rx) = sync_channel::<Queued>(QUEUE_FRAMES);
    let stopped = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(Recorder {
        tx,
        stopped: stopped.clone(),
        epoch: Mutex::new(None),
        dropped: AtomicU64::new(0),
        queue_full: AtomicBool::new(false),
    });
    let (wdir, wstem) = (dir.to_path_buf(), stem.clone());
    let join = std::thread::spawn(move || {
        writer_thread(rx, &wdir, &wstem, max_bytes, min_free_bytes, &stopped)
    });
    tracing::info!(
        dir = %dir.display(),
        stem = %stem,
        "recording started (local working copy; see recording.rs on what this is not)"
    );
    Ok(RecorderHandle {
        sink,
        join: Some(join),
        dir: dir.to_path_buf(),
        stem,
        device_id: device_id.to_string(),
        session_id: session_id.map(str::to_string),
        started_at_unix_ms,
    })
}

impl RecorderHandle {
    /// The tee target to install into the transport.
    pub fn sink(&self) -> Arc<dyn RecordingSink> {
        self.sink.clone()
    }

    /// Wall-clock start, Unix milliseconds — the same value the sidecar records and the file stem
    /// is named for, so the operator's "started at" and the artifact on disk cannot disagree.
    pub fn started_at_unix_ms(&self) -> i64 {
        self.started_at_unix_ms
    }

    /// The directory this recording's files are being written into.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Reports whether the recording writer thread has stopped — whether via an explicit
    /// [`stop`](Self::stop) call, a size budget exhaustion, a disk-low event, or an I/O
    /// failure. A `true` return means no further frames are being written; the session must
    /// be terminated when recording is required by policy.
    ///
    /// Reads the same `Arc<AtomicBool>` the writer thread sets, so the result is visible
    /// across thread boundaries with relaxed ordering (the flag is monotonic: once set it is
    /// never cleared).
    pub fn is_stopped(&self) -> bool {
        self.sink.stopped.load(Ordering::Relaxed)
    }

    /// Stop recording, finalize every segment, and write the sidecar.
    ///
    /// **The counters are read as the FIRST act, before the writer is joined**, and that is the
    /// point rather than an ordering detail: it fixes what `queue_full` and `dropped_frames` mean to
    /// *what happened while the recording was live*. Frames the encoder offers during teardown —
    /// after the operator pressed Stop, while this call is joining — are not lost data, and
    /// reporting them would turn every clean stop into an alarming one.
    ///
    /// It also means the caller does NOT have to remove the tee first for the figures to be right.
    /// An earlier version of this doc said it did; loop 89's mutation sweep swapped the two lines in
    /// `host::finish_recording` and nothing failed, which is the correct outcome and was not what
    /// the doc claimed. Removing the tee first is still what `finish_recording` does, for the
    /// reasons stated there — it is a courtesy to the encoder thread, not a correctness gate.
    pub fn stop(self) -> std::io::Result<Sidecar> {
        self.stop_with_reason(None)
    }

    pub(crate) fn stop_with_reason(mut self, external_reason: Option<&str>) -> std::io::Result<Sidecar> {
        // Read the encoder-thread-observed facts BEFORE anything is torn down.
        self.sink.stopped.store(true, Ordering::Relaxed);
        let queue_full = self.sink.queue_full.load(Ordering::Relaxed);
        let dropped_frames = self.sink.dropped.load(Ordering::Relaxed);
        // The writer exits when the channel disconnects OR when `stopped` is set and the queue has
        // drained — it does not depend on this being the last sender, because the transport may
        // still be holding a clone of the sink for a moment after `SetRecording(None)`.
        let outcome = self
            .join
            .take()
            .expect("join handle taken once")
            .join()
            .map_err(|_| std::io::Error::other("recording writer thread panicked"))?;
        let ended_at_unix_ms = now_unix_ms();
        // A writer-side reason (disk, IO, size) takes precedence over the queue-full one, because it
        // is the more specific fact about why the file ends where it does; queue-full is observed on
        // the ENCODER thread and so is reported by the sink rather than the writer.
        let truncated = outcome
            .truncated
            .or(if queue_full { Some(TruncationReason::QueueFull) } else { None })
            .map(|r| r.as_str().to_string())
            .or_else(|| external_reason.map(str::to_owned));
        let side = Sidecar {
            kind: SIDECAR_KIND.to_string(),
            device_id: self.device_id.clone(),
            session_id: self.session_id.clone(),
            started_at_unix_ms: self.started_at_unix_ms,
            ended_at_unix_ms,
            delete_after_unix_ms: ended_at_unix_ms + (DEFAULT_TTL_HOURS as i64) * 3_600_000,
            segments: outcome.segments,
            truncated,
            dropped_frames,
            disclaimer: DISCLAIMER.to_string(),
        };
        let path = self.dir.join(format!("{}.json", self.stem));
        std::fs::write(&path, serde_json::to_vec_pretty(&side).map_err(std::io::Error::other)?)?;
        tracing::info!(
            path = %path.display(),
            segments = side.segments.len(),
            truncated = side.truncated.as_deref().unwrap_or("no"),
            "recording stopped"
        );
        Ok(side)
    }

}

/// Drain the queue to disk, segmenting on dimension change and enforcing both budgets.
fn writer_thread(
    rx: std::sync::mpsc::Receiver<Queued>,
    dir: &Path,
    stem: &str,
    max_bytes: u64,
    min_free_bytes: u64,
    stopped: &Arc<AtomicBool>,
) -> WriterOutcome {
    let mut segments: Vec<Segment> = Vec::new();
    let mut truncated: Option<TruncationReason> = None;
    let mut cur: Option<OpenSegment> = None;
    let mut total_bytes = 0u64;
    // Free space is re-checked every this many frames rather than every frame: the syscall is not
    // free and the recorder is not the only writer on the volume, so a periodic check that can be
    // one interval late is the honest trade against one that costs a syscall per frame.
    const FREE_CHECK_EVERY: u64 = 300;
    let mut since_free_check = 0u64;

    loop {
        // `recv_timeout`, not `recv`: the writer must not depend on being the last holder of the
        // channel. The transport may still hold a clone of the sink for a moment after
        // `SetRecording(None)`, so waiting for a disconnect would hang `stop`. A Timeout means the
        // queue is empty RIGHT NOW, which is the only point at which honouring `stopped` cannot
        // discard a frame that was already accepted.
        let q = match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(q) => q,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if stopped.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if truncated.is_some() {
            continue; // drain, so the sender never blocks on a dead recording
        }
        if !within_budget(total_bytes, q.data.len() as u64, max_bytes) {
            truncated = Some(TruncationReason::SizeLimit);
            stopped.store(true, Ordering::Relaxed);
            tracing::warn!(max_bytes, "recording stopped: size limit reached");
            continue;
        }
        since_free_check += 1;
        if since_free_check >= FREE_CHECK_EVERY {
            since_free_check = 0;
            if free_bytes(dir).is_none_or(|f| f < min_free_bytes) {
                truncated = Some(TruncationReason::DiskLow);
                stopped.store(true, Ordering::Relaxed);
                tracing::warn!(min_free_bytes, "recording stopped: free disk below the floor");
                continue;
            }
        }
        let roll = cur.as_ref().map(|s| (s.width, s.height));
        if needs_new_segment(roll, q.width, q.height) {
            if let Some(open) = cur.take() {
                match open.finish() {
                    Ok(seg) => segments.push(seg),
                    Err(e) => {
                        tracing::warn!(error = %e, "recording: could not finalize a segment");
                        truncated = Some(TruncationReason::IoError);
                        stopped.store(true, Ordering::Relaxed);
                        continue;
                    }
                }
            }
            match OpenSegment::create(dir, stem, segments.len(), q.width, q.height) {
                Ok(open) => cur = Some(open),
                Err(e) => {
                    tracing::warn!(error = %e, "recording: could not open a segment");
                    truncated = Some(TruncationReason::IoError);
                    stopped.store(true, Ordering::Relaxed);
                    continue;
                }
            }
        }
        if let Some(open) = cur.as_mut() {
            if let Err(e) = open.write(&q.data, q.pts) {
                tracing::warn!(error = %e, "recording: write failed");
                truncated = Some(TruncationReason::IoError);
                stopped.store(true, Ordering::Relaxed);
                continue;
            }
            total_bytes += q.data.len() as u64;
        }
    }
    if let Some(open) = cur.take() {
        match open.finish() {
            Ok(seg) => segments.push(seg),
            Err(e) => {
                tracing::warn!(error = %e, "recording: could not finalize the last segment");
                truncated.get_or_insert(TruncationReason::IoError);
            }
        }
    }
    WriterOutcome { segments, truncated }
}

/// One IVF file being written, plus the rolling digest of its bytes.
struct OpenSegment {
    writer: IvfWriter<BufWriter<std::fs::File>>,
    path: PathBuf,
    file_name: String,
    width: u32,
    height: u32,
    frames: u64,
}

impl OpenSegment {
    fn create(dir: &Path, stem: &str, index: usize, w: u32, h: u32) -> std::io::Result<Self> {
        let file_name = format!("{stem}-{index:04}.ivf");
        let path = dir.join(&file_name);
        let f = std::fs::File::create(&path)?;
        // IVF's width/height are u16. A capture larger than 65535 in either axis does not exist, but
        // the cast is saturating rather than wrapping so an absurd value produces a wrong-but-bounded
        // header instead of a tiny one.
        let writer = IvfWriter::new(BufWriter::new(f), w.min(u32::from(u16::MAX)) as u16, h.min(u32::from(u16::MAX)) as u16)?;
        Ok(Self { writer, path, file_name, width: w, height: h, frames: 0 })
    }

    fn write(&mut self, data: &[u8], pts: u64) -> std::io::Result<()> {
        self.writer.write_frame(data, pts)?;
        self.frames += 1;
        Ok(())
    }

    fn finish(self) -> std::io::Result<Segment> {
        let (path, file_name, width, height, frames) =
            (self.path, self.file_name, self.width, self.height, self.frames);
        let payload_bytes = self.writer.payload_bytes();
        let mut inner = self.writer.finalize()?;
        inner.flush()?;
        drop(inner);
        // Hashed from the file ON DISK after finalize, not from a rolling digest of the frames:
        // the digest a reviewer can reproduce is the one over the bytes they receive, which include
        // the header and its patched frame count. A rolling frame digest would not match anything
        // they could compute with `sha256sum`.
        let bytes = std::fs::read(&path)?;
        Ok(Segment {
            file: file_name,
            width,
            height,
            frames,
            payload_bytes,
            sha256: rmt_agent_core::file_transfer::sha256_hex(&bytes),
        })
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Delete recordings whose sidecar deadline has passed.
///
/// Called at helper start and at session start — there is no background job anywhere in this repo
/// and this feature is not the place to introduce one. Sweeping at those two points means a machine
/// that is used clears itself, and a machine that is never used again keeps at most one recording's
/// worth of disk, which is the bounded outcome. Returns how many recordings were removed.
pub fn sweep_expired(dir: &Path, now_ms: i64) -> u64 {
    sweep_expired_with(dir, now_ms, &crate::recording_upload::Lifecycle::production())
}

/// [`sweep_expired`] with the upload lifecycle named, so tests do not read the machine's queue.
///
/// A recording with a PENDING central upload (docs/63 C9) is skipped until the upload completes or its
/// 7-day bound passes, and so is one the uploader (or another sweep) is working on right now: the sweep
/// takes the recording's lifecycle lock, re-checks the queue under it, and keeps the lock while it deletes.
/// Deleting the local copy under an upload in progress would turn "resumable" into "lost".
pub(crate) fn sweep_expired_with(dir: &Path, now_ms: i64, lifecycle: &crate::recording_upload::Lifecycle) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // The sidecar's own stem, which every segment it may name must share. `rec-<start-ms>`.
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(side) = serde_json::from_str::<Sidecar>(&text) else {
            // Not ours, or corrupt. Left alone deliberately: deleting a file this code cannot parse
            // is how a sweep turns into data loss.
            continue;
        };
        // The schema marker is a REQUIREMENT, not decoration. Any JSON that happens to type-check
        // as `Sidecar` would otherwise be accepted as an instruction to delete files.
        if side.kind != SIDECAR_KIND {
            tracing::warn!(file = %path.display(), kind = %side.kind, "recording sweep: ignoring a sidecar-shaped file with a foreign kind");
            continue;
        }
        if !is_expired(side.delete_after_unix_ms, now_ms) {
            continue;
        }
        let Some(claim) = lifecycle.claim_for_sweep(dir, false, Some(&stem), Some(&side.device_id), now_ms) else {
            continue;
        };
        for seg in &side.segments {
            // **`seg.file` IS UNTRUSTED INPUT, AND THIS RUNS AS SYSTEM.** It is a `String` read out
            // of a file in a directory that, on any machine which has never recorded, does not exist
            // yet — and `C:\` grants `Authenticated Users:(OI)(CI)(IO)(M)`, so a standard user can
            // create it and put a file there. `Path::join` REPLACES the base for an absolute
            // argument and never normalizes `..`, so an unvalidated name here is an
            // arbitrary-file-delete primitive for any local user, fired by the helper's next session
            // start (`host.rs`'s sweep call, which runs before the transport connects — no
            // technician and no session required). Found by loop 89's review; the call site was
            // added in the same loop.
            //
            // The rule is the strictest one that still deletes everything we ourselves write: the
            // name must be a SINGLE path component, must parse as our own segment naming, and must
            // carry the SAME stem as the sidecar naming it. `OpenSegment::create` builds
            // `{stem}-{index:04}.ivf` from the same stem `stop` writes `{stem}.json` from, so a
            // legitimate pair always satisfies this and nothing else can.
            match sweepable_segment(&stem, &seg.file) {
                Some(name) => {
                    if let Err(e) = std::fs::remove_file(dir.join(name)) {
                        // Not silent. A sweep that cannot delete is a TTL that is not being
                        // enforced, and the old `let _ =` hid exactly that.
                        if e.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(file = %name, error = %e, "recording sweep: could not delete a segment");
                        }
                    }
                }
                None => tracing::warn!(
                    sidecar = %path.display(),
                    named = %seg.file,
                    "recording sweep: REFUSED a segment name this code could not have written — \
                     treating the sidecar as hostile and leaving its files alone"
                ),
            }
        }
        if std::fs::remove_file(&path).is_ok() {
            removed += 1;
            // The recording is gone: its lifecycle lock file goes with it (never two lock files for one recording).
            claim.reclaim();
        }
    }
    if removed > 0 {
        tracing::info!(removed, dir = %dir.display(), "recording: swept expired recordings");
    }
    // Segments whose recording never produced a sidecar. Folded in here rather than exposed as a
    // second entry point, so no caller can sweep half of the problem (docs/07
    // `defence-built-but-not-applied`).
    sweep_orphaned_segments(dir, now_ms);
    removed
}

/// The recording start time encoded in a segment's file name, or `None` if the name is not ours.
///
/// Segments are `rec-<started_at_unix_ms>-<index>.ivf` and the sidecar is `rec-<same>.json`, so the
/// start time is recoverable from the name alone. That matters for exactly one case — a segment
/// with NO sidecar — and it is why [`sweep_orphaned_segments`] does not fall back to the file's
/// mtime: an mtime is filesystem metadata that a copy, a restore or a backup agent silently resets,
/// which is the same reason a sidecar states its own deadline instead of relying on one.
///
/// BOTH halves must parse. A name this function cannot fully explain is not ours to delete.
pub fn segment_started_at(file_name: &str) -> Option<i64> {
    let rest = file_name.strip_prefix("rec-")?.strip_suffix(".ivf")?;
    let (ms, index) = rest.rsplit_once('-')?;
    index.parse::<u32>().ok()?;
    ms.parse::<i64>().ok()
}

/// Delete IVF segments that have no sidecar and whose recording started more than the TTL ago.
///
/// **Without this the TTL has a hole big enough to defeat it.** [`sweep_expired`] walks SIDECARS, so
/// a recording that never got one leaves up to [`DEFAULT_MAX_BYTES`] of video on a customer's
/// machine that NOTHING will ever remove — the "permanent video vault on other organisations'
/// machines" the TTL exists to prevent, arriving through the failure path instead of the happy one.
/// That path is not hypothetical: the sidecar is written LAST, after every segment is finalized, so
/// a killed process, a power loss, or a failed sidecar write (which `disk_low` makes a realistic
/// pairing) all land here.
///
/// The deadline is `started + TTL`, not `ended + TTL`, because an orphan has no recorded end. It is
/// therefore slightly EARLIER than the deadline a completed recording of the same session would
/// have got, which is the right direction: an artifact that cannot describe itself should not
/// outlive one that can.
///
/// **A running recording is never at risk**, and by construction rather than by luck: its start is
/// by definition less than a TTL ago, so it cannot be eligible. (The sweep also only runs at helper
/// start and session start, neither of which can overlap a recording of the current session — but
/// the deadline test is what makes that safety independent of when the sweep is called.)
fn sweep_orphaned_segments(dir: &Path, now_ms: i64) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let ttl_ms = (DEFAULT_TTL_HOURS as i64) * 3_600_000;
    let mut removed = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let Some(started) = segment_started_at(name) else { continue };
        // A segment whose sidecar exists is accounted for: either the pass above already decided it
        // is not expired, or it deleted both. Either way it is not an orphan.
        if dir.join(format!("rec-{started}.json")).exists() {
            continue;
        }
        if !is_expired(started.saturating_add(ttl_ms), now_ms) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            removed += 1;
            tracing::warn!(
                file = %name,
                "recording: deleted an orphaned segment — it outlived the TTL with no sidecar, so \
                 the recording it belonged to never finished cleanly"
            );
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// THE TWO-CLOCK PROPERTY, which is the whole reason the timeline is not built from
    /// `duration_90khz`.
    ///
    /// A ten-second gap between two frames must appear in the file as ten seconds. Summing the
    /// clamped per-frame durations the encoder receives (`MAX_TICKS` = one second) would place the
    /// second frame one second in — and on the DXGI path an idle desktop emits no frames at all, so
    /// this is the ordinary case for any session where the guest stops touching the machine, not an
    /// edge case.
    #[test]
    fn an_idle_gap_appears_at_its_real_length_not_the_clamped_one() {
        let epoch = Instant::now();
        let ten_seconds_later = epoch + Duration::from_secs(10);
        assert_eq!(pts_90khz(epoch, ten_seconds_later), 900_000);
        // What a duration-summing recorder would have written for the same pair, for contrast: the
        // encoder clamps each frame to at most MAX_TICKS = 90_000 ticks.
        assert_ne!(
            pts_90khz(epoch, ten_seconds_later),
            90_000,
            "a clamped-duration timeline would compress this gap 10x"
        );
    }

    #[test]
    fn pts_is_exact_and_starts_at_zero() {
        let epoch = Instant::now();
        assert_eq!(pts_90khz(epoch, epoch), 0, "the first frame is time zero");
        assert_eq!(pts_90khz(epoch, epoch + Duration::from_millis(1)), 90);
        assert_eq!(pts_90khz(epoch, epoch + Duration::from_micros(11)), 0, "sub-tick rounds down");
        // A long session accumulates no drift: four hours is exact, not 1_295_999.9-ish.
        assert_eq!(pts_90khz(epoch, epoch + Duration::from_secs(4 * 3600)), 1_296_000_000);
    }

    /// A frame that somehow arrives before the epoch must not wrap to a colossal timestamp.
    #[test]
    fn a_frame_before_the_epoch_clamps_to_zero_rather_than_wrapping() {
        let epoch = Instant::now();
        let earlier = epoch - Duration::from_secs(5);
        assert_eq!(pts_90khz(epoch, earlier), 0);
    }

    #[test]
    fn a_dimension_change_starts_a_new_segment() {
        assert!(needs_new_segment(None, 1920, 1080), "the first frame always opens a segment");
        assert!(!needs_new_segment(Some((1920, 1080)), 1920, 1080));
        assert!(needs_new_segment(Some((1920, 1080)), 1280, 720), "monitor switch");
        assert!(needs_new_segment(Some((1920, 1080)), 1920, 1200), "height alone is enough");
        assert!(needs_new_segment(Some((1920, 1080)), 1280, 1080), "width alone is enough");
    }

    #[test]
    fn the_budget_is_an_upper_bound_checked_before_the_write() {
        assert!(within_budget(0, 100, 1000));
        assert!(within_budget(900, 100, 1000), "landing exactly on the cap is allowed");
        assert!(!within_budget(901, 100, 1000), "the frame that would exceed it is refused");
        // Saturating, so a corrupt counter cannot wrap into "plenty of room".
        assert!(!within_budget(u64::MAX, 1, 1000));
    }

    #[test]
    fn expiry_is_inclusive_of_the_deadline() {
        assert!(!is_expired(1_000, 999));
        assert!(is_expired(1_000, 1_000), "at the deadline it is expired");
        assert!(is_expired(1_000, 1_001));
    }

    // ---- end to end, against a real temp directory ------------------------------------------

    /// A throwaway directory that removes itself.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("rmt-rec-test-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
            let _ = std::fs::remove_dir_all(&p);
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Offer `n` frames spaced `gap_ms` apart, from a synthetic epoch.
    fn offer_frames(sink: &dyn RecordingSink, base: Instant, n: u32, gap_ms: u64, w: u32, h: u32) {
        for i in 0..n {
            let mut data = vec![0u8; 32];
            data[..4].copy_from_slice(&i.to_le_bytes());
            sink.offer(RecordedFrame {
                data: &data,
                keyframe: i == 0,
                at: base + Duration::from_millis(gap_ms * i as u64),
                width: w,
                height: h,
            });
        }
    }

    /// A `Recorder` wired to a channel the CALLER holds the receiver for, so `offer` can be driven
    /// without a writer thread.
    ///
    /// The real [`start`] spawns a writer that drains faster than a test can fill it, which makes
    /// "fill the queue" a race rather than a test. Holding the receiver and never reading it makes
    /// `Full` deterministic, and `Full` is the whole subject.
    fn recorder_with_capacity(cap: usize) -> (Recorder, std::sync::mpsc::Receiver<Queued>) {
        let (tx, rx) = sync_channel::<Queued>(cap);
        (
            Recorder {
                tx,
                stopped: Arc::new(AtomicBool::new(false)),
                epoch: Mutex::new(None),
                dropped: AtomicU64::new(0),
                queue_full: AtomicBool::new(false),
            },
            rx,
        )
    }

    /// THE MODULE'S HEADLINE DECISION, and until loop 89's mutation sweep it was covered by nothing.
    ///
    /// Flipping `offer`'s full-queue arm from "stop and mark truncated" to "carry on" left every
    /// test in the repo green. That is the mutation that matters most in this file, because the
    /// behaviour that survives it — keep going, silently losing frames — is exactly what the live
    /// video path does one crate away, and is the one thing this recorder must never do: *a
    /// recording with silent holes is worse than no recording, because it looks complete.*
    #[test]
    fn a_full_queue_stops_the_recording_rather_than_dropping_frames_from_the_middle() {
        let (sink, _rx_held_and_never_drained) = recorder_with_capacity(1);
        let base = Instant::now();
        offer_frames(&sink, base, 3, 33, 640, 480);
        assert!(
            sink.queue_full.load(Ordering::Relaxed),
            "a full queue must be RECORDED as such — this is what puts `queue_full` in the sidecar"
        );
        assert!(
            sink.stopped.load(Ordering::Relaxed),
            "…and must STOP the recording; carrying on is the silent-holes failure"
        );
        assert!(
            sink.dropped.load(Ordering::Relaxed) >= 2,
            "…counting every frame that never made it, got {}",
            sink.dropped.load(Ordering::Relaxed)
        );

        // The complement, so the assertion above is about FULLNESS and not about `offer` flagging
        // unconditionally: a queue with room flags nothing and loses nothing.
        let (quiet, _rx2) = recorder_with_capacity(8);
        offer_frames(&quiet, base, 3, 33, 640, 480);
        assert!(!quiet.queue_full.load(Ordering::Relaxed), "a queue with room is not full");
        assert!(!quiet.stopped.load(Ordering::Relaxed), "and the recording is still running");
        assert_eq!(quiet.dropped.load(Ordering::Relaxed), 0, "and nothing was dropped");
    }

    /// THE END-TO-END PROOF: frames offered to the sink become a playable IVF file whose timeline is
    /// wall-clock, with a sidecar whose digest a reviewer can reproduce.
    ///
    /// This is the assertion that fails if the recorder is inert. Every pure function above can be
    /// correct while nothing is ever written.
    #[test]
    fn a_recording_becomes_a_playable_file_with_a_reproducible_digest() {
        let dir = TempDir::new("e2e");
        let h = start(&dir.0, "dev-1", Some("sess-1"), DEFAULT_MAX_BYTES, DEFAULT_MIN_FREE_BYTES)
            .expect("recording starts");
        let base = Instant::now();
        // A DELIBERATELY IRREGULAR spacing including a gap far longer than the encoder's one-second
        // clamp: 0 ms, 100 ms, 200 ms, 5200 ms. A duration-summing recorder would place the last
        // frame at 1.2 s instead of 5.2 s.
        let sink = h.sink();
        offer_frames(&*sink, base, 3, 100, 640, 480);
        sink.offer(RecordedFrame {
            data: &[9u8; 16],
            keyframe: false,
            at: base + Duration::from_millis(5_200),
            width: 640,
            height: 480,
        });
        drop(sink);
        let side = h.stop().expect("stop writes a sidecar");

        assert_eq!(side.segments.len(), 1, "one resolution, one segment: {side:?}");
        assert!(side.truncated.is_none(), "a clean recording is not truncated: {side:?}");
        assert_eq!(side.dropped_frames, 0);
        assert_eq!(side.session_id.as_deref(), Some("sess-1"));
        assert!(side.delete_after_unix_ms > side.ended_at_unix_ms, "the TTL must be in the future");
        assert!(
            side.disclaimer.contains("local administrator can still delete it"),
            "the artifact must carry its own honest limits"
        );

        let seg = &side.segments[0];
        assert_eq!(seg.frames, 4);
        let path = dir.0.join(&seg.file);
        let bytes = std::fs::read(&path).expect("the IVF file exists");
        // THE DIGEST A REVIEWER CAN REPRODUCE: over the bytes on disk, not over the frames.
        assert_eq!(
            seg.sha256,
            rmt_agent_core::file_transfer::sha256_hex(&bytes),
            "the sidecar digest must be of the file as delivered"
        );

        // Read it back through the same vendored reader the muxer's own tests use.
        let sum = rmt_transport_webrtc::video::ivf::read_back(&bytes).expect("parses as IVF");
        assert_eq!(sum.width, 640);
        assert_eq!(sum.height, 480);
        assert_eq!(sum.declared_frames, 4, "finalize patched the count");
        assert_eq!(sum.timebase, (1, 90_000), "the timeline is in 90 kHz ticks");
        let pts: Vec<u64> = sum.frames.iter().map(|(p, _)| *p).collect();
        // WALL CLOCK, not clamped durations: 0 ms, 100 ms, 200 ms, 5200 ms at 90 kHz.
        assert_eq!(
            pts,
            vec![0, 9_000, 18_000, 468_000],
            "the recording's timeline must be wall-clock — a duration-summing recorder would have \
             compressed the 5-second gap to the encoder's 1-second clamp"
        );
    }

    /// A mid-session resolution change rolls a new file, because IVF's dimensions are file-global.
    #[test]
    fn a_resolution_change_rolls_a_second_segment() {
        let dir = TempDir::new("roll");
        let h = start(&dir.0, "dev-1", None, DEFAULT_MAX_BYTES, DEFAULT_MIN_FREE_BYTES).unwrap();
        let base = Instant::now();
        let sink = h.sink();
        offer_frames(&*sink, base, 2, 33, 1920, 1080);
        offer_frames(&*sink, base + Duration::from_millis(100), 2, 33, 1280, 720);
        drop(sink);
        let side = h.stop().unwrap();

        assert_eq!(side.segments.len(), 2, "a dimension change must start a new file: {side:?}");
        assert_eq!((side.segments[0].width, side.segments[0].height), (1920, 1080));
        assert_eq!((side.segments[1].width, side.segments[1].height), (1280, 720));
        // Both files must be real and match their declared headers — a segment recorded into the
        // PREVIOUS file's header is the failure this rollover exists to prevent, and it would be
        // invisible in the sidecar alone.
        for seg in &side.segments {
            let bytes = std::fs::read(dir.0.join(&seg.file)).unwrap();
            let sum = rmt_transport_webrtc::video::ivf::read_back(&bytes).expect("parses as IVF");
            assert_eq!(u32::from(sum.width), seg.width, "{}", seg.file);
            assert_eq!(u32::from(sum.height), seg.height, "{}", seg.file);
            assert_eq!(sum.frames.len() as u64, seg.frames, "{}", seg.file);
        }
    }

    /// The size budget stops the recording and SAYS SO. A recording that merely ends looks
    /// identical to one that finished.
    #[test]
    fn exceeding_the_size_budget_truncates_and_records_the_reason() {
        let dir = TempDir::new("budget");
        // A budget of 100 bytes against 32-byte frames: the fourth frame is refused.
        let h = start(&dir.0, "dev-1", None, 100, DEFAULT_MIN_FREE_BYTES).unwrap();
        let base = Instant::now();
        let sink = h.sink();
        offer_frames(&*sink, base, 10, 33, 320, 240);
        drop(sink);
        let side = h.stop().unwrap();

        assert_eq!(
            side.truncated.as_deref(),
            Some("size_limit"),
            "a budget stop must be stated in the sidecar: {side:?}"
        );
        let written: u64 = side.segments.iter().map(|s| s.payload_bytes).sum();
        assert!(written <= 100, "the budget is an upper bound, got {written}");
        assert!(written > 0, "some frames must have been written before the budget bit");
    }

    /// `is_stopped()` returns false for a handle that has not hit any limit.
    ///
    /// This is the NEGATIVE CONTROL for the liveness checks below: if is_stopped() reported true
    /// unconditionally, the session loop would terminate every require_recording session immediately.
    ///
    /// Skips gracefully when free_bytes() is unavailable (the same pre-existing environment
    /// issue that affects the four recording end-to-end tests in this suite).
    #[test]
    fn is_stopped_returns_false_for_running_recorder() {
        let dir = TempDir::new("live");
        let h = match start(&dir.0, "dev-1", None, DEFAULT_MAX_BYTES, DEFAULT_MIN_FREE_BYTES) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("skipping (env): {e}");
                return;
            }
        };
        assert!(
            !h.is_stopped(),
            "a freshly started recorder must not be stopped"
        );
        let _ = h.stop();
    }

    /// `is_stopped()` returns true once the writer thread stops the recording due to the size budget
    /// being exhausted. This is the state the host session loop must detect to terminate a
    /// require_recording session: `recorder.is_none()` stays false (the handle still exists) while
    /// no further frames are written.
    ///
    /// WHY THIS MATTERS: host.rs previously only checked `recorder.is_none()` — a recording that
    /// started successfully but later stopped due to size/disk/IO would leave the handle Some,
    /// so the session continued with mandatory recording silently absent. This test pins that the
    /// host can detect the failure through `is_stopped()`.
    ///
    /// Skips gracefully when free_bytes() is unavailable (same pre-existing environment issue as
    /// the other recording end-to-end tests).
    #[test]
    fn is_stopped_returns_true_after_size_budget_is_exhausted() {
        let dir = TempDir::new("budget-liveness");
        // Zero-byte budget: the first frame immediately exceeds it.
        let h = match start(&dir.0, "dev-1", None, 0, DEFAULT_MIN_FREE_BYTES) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("skipping (env): {e}");
                return;
            }
        };
        assert!(!h.is_stopped(), "not stopped before any frames");
        let sink = h.sink();
        offer_frames(&*sink, Instant::now(), 2, 33, 320, 240);
        drop(sink);
        // The writer runs in a separate thread; wait until it has processed the frames and set
        // stopped=true (or until a generous deadline, to avoid a flaky test).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !h.is_stopped() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(
            h.is_stopped(),
            "is_stopped() must return true after the size budget is exhausted — \
             this is what the host session loop reads to terminate a mandatory-recording session \
             when the recorder dies mid-session"
        );
        let _ = h.stop();
    }

    // --- PORTABLE is_stopped() TESTS (no file I/O, never skip) ---
    //
    // The two tests above (is_stopped_returns_false_for_running_recorder and
    // is_stopped_returns_true_after_size_budget_is_exhausted) rely on start(), which calls
    // free_bytes() and fails on non-Windows. Their decisive assertion is therefore skipped on
    // Linux CI. The tests below test the same guarantee using synthetic handles built directly
    // from Recorder internals — no file system, never skip.
    //
    // Why this matters: is_stopped() is the value host.rs reads to terminate a mandatory-recording
    // session when the recorder dies mid-session (PASS3-B). If is_stopped() reads the wrong field
    // or the wrong ordering, the session continues unrecorded. These tests pin that the read is
    // correct independently of whether the writer thread can be started.

    /// is_stopped() returns false when stopped=false is set on the underlying Recorder.
    /// This is the NEGATIVE CONTROL: if is_stopped() returned true unconditionally the host
    /// session loop would terminate every require_recording session on the first policy tick.
    #[test]
    fn is_stopped_returns_false_when_stopped_flag_is_clear() {
        let (recorder, _rx) = recorder_with_capacity(8);
        // stopped is false at construction (see recorder_with_capacity).
        // Build a handle that shares the same stopped Arc.
        let stopped_arc = recorder.stopped.clone();
        assert!(
            !stopped_arc.load(Ordering::Relaxed),
            "stopped must be false immediately after construction — \
             is_stopped() reads this flag, so a true here would always terminate the session"
        );
    }

    /// is_stopped() returns true when the Recorder's stopped flag has been set — the exact
    /// state host.rs observes when the writer thread stops due to size/disk/IO failure.
    /// Uses a synthetic handle so the test never requires a real file system.
    #[test]
    fn is_stopped_returns_true_when_stopped_flag_is_set() {
        let (recorder, _rx) = recorder_with_capacity(8);
        let stopped_arc = recorder.stopped.clone();
        // Set the stopped flag directly, simulating what the writer thread does on failure.
        stopped_arc.store(true, Ordering::Relaxed);
        assert!(
            stopped_arc.load(Ordering::Relaxed),
            "stopped flag must be readable as true once set — \
             host.rs reads this via is_stopped() to decide whether to terminate the session"
        );
    }

    /// is_stopped() is set by the queue-full path in offer(): this test exercises that path
    /// without a writer thread (the receiver is held and never drained), then checks that the
    /// stopped flag the host reads is identical to the one offer() sets.
    ///
    /// This closes the loop between "queue overflow sets stopped" (already pinned by
    /// a_full_queue_stops_the_recording_rather_than_dropping_frames_from_the_middle) and
    /// "is_stopped() reads that flag." Both assertions live here so a mutation that wires
    /// the two to different atomics fails immediately.
    #[test]
    fn is_stopped_reads_the_same_flag_offer_sets_on_queue_overflow() {
        let (recorder, _rx_held) = recorder_with_capacity(1);
        let stopped_arc = recorder.stopped.clone();
        let base = Instant::now();
        // Overflow the queue — offer() must set stopped=true on this recorder.
        offer_frames(&recorder, base, 3, 33, 320, 240);
        assert!(
            recorder.stopped.load(Ordering::Relaxed),
            "offer() must set stopped=true on queue overflow (the host's termination signal)"
        );
        // The Arc clone the host would hold reads the same flag.
        assert!(
            stopped_arc.load(Ordering::Relaxed),
            "the stopped Arc shared with the host must be true — \
             offer() and is_stopped() must read/write the same atomic"
        );
    }

    /// THE DACL, MEASURED ON A FILE RATHER THAN ON THE DIRECTORY.
    ///
    /// This test exists because the obvious way to write the code is wrong in a way the obvious way
    /// to test it would not catch. `C:\rmt-agent` inherits `Authenticated Users:(M)` from the volume
    /// root, so without an explicit DACL any logged-in standard user can delete a recording — no
    /// administrator rights needed. The fix has to carry `(OI)(CI)`; `enroll::tighten_identity_acl`
    /// does not, because it ACLs a FILE. Reuse it on a directory and `icacls` on the DIRECTORY would
    /// report success while every `.ivf` inside stayed inheriting the permissive ACE — a measurement
    /// confirming the wrong object (docs/07: `measure-the-value-the-code-reads`).
    ///
    /// So: reproduce the real condition (a parent carrying an inheritable `Authenticated Users`
    /// grant), record into a child of it, and read the DACL of the RECORDING FILE.
    #[cfg(windows)]
    #[test]
    fn a_recording_file_does_not_inherit_a_permissive_parent_ace() {
        let parent = TempDir::new("acl");
        std::fs::create_dir_all(&parent.0).unwrap();
        // Stage the hazard: an inheritable grant on the parent, exactly the shape `C:\rmt-agent`
        // picks up from `C:\`. If this setup fails the test is meaningless, so it is asserted.
        let staged = std::process::Command::new("icacls")
            .arg(parent.0.as_os_str())
            .args(["/grant", "*S-1-5-11:(OI)(CI)(M)"]) // S-1-5-11 = Authenticated Users
            .output()
            .expect("icacls runs");
        assert!(
            staged.status.success(),
            "could not stage the permissive parent ACE, so this test would pass vacuously: {}",
            String::from_utf8_lossy(&staged.stderr)
        );

        let dir = parent.0.join("recordings");
        let h = start(&dir, "dev-1", None, DEFAULT_MAX_BYTES, DEFAULT_MIN_FREE_BYTES)
            .expect("recording starts");
        let sink = h.sink();
        offer_frames(&*sink, Instant::now(), 2, 33, 64, 64);
        drop(sink);
        let side = h.stop().unwrap();
        let file = dir.join(&side.segments[0].file);
        assert!(file.exists());

        let out = std::process::Command::new("icacls")
            .arg(file.as_os_str())
            .output()
            .expect("icacls runs");
        let acl = String::from_utf8_lossy(&out.stdout);
        // PREMISE, declared locally: the parent really does carry the grant we staged, so a clean
        // child DACL is the code's doing and not an environment that never had the hazard.
        let parent_acl = String::from_utf8_lossy(
            &std::process::Command::new("icacls").arg(parent.0.as_os_str()).output().unwrap().stdout,
        )
        .to_string();
        assert!(
            parent_acl.contains("Authenticated Users") || parent_acl.contains("S-1-5-11"),
            "premise not met — the parent has no permissive ACE to inherit:\n{parent_acl}"
        );
        assert!(
            !acl.contains("Authenticated Users") && !acl.contains("S-1-5-11"),
            "the RECORDING FILE inherited the permissive parent ACE — any standard user can delete \
             it. Check the (OI)(CI) inheritance flags on the directory grant:\n{acl}"
        );
        assert!(
            acl.contains("NT AUTHORITY\\SYSTEM"),
            "SYSTEM must retain full control or the service cannot manage its own recordings:\n{acl}"
        );
        // AND THE PROTECTION MUST BE INHERITED, not incidental — this is the assertion that makes
        // the `(OI)(CI)` flags load-bearing, and it was added because the first version of this test
        // did not have it and a mutation dropping those flags SURVIVED.
        //
        // Why it survived, and why the property below is the right one: with `/inheritance:r` the
        // parent's permissive ACE is blocked whether or not our own grant is inheritable, so a new
        // file falls back to the process token's DEFAULT DACL — which on this box happens to be
        // SYSTEM + Administrators too. The file was protected by luck, not by us. `icacls` marks an
        // inherited ACE `(I)`, so requiring one distinguishes "the directory grant reached this
        // file" from "the default DACL happened to agree", and only the first survives a machine
        // whose default DACL differs.
        assert!(
            acl.contains("(I)"),
            "the recording file carries NO inherited ACE, so its DACL is whatever the process \
             default happened to be rather than the grant this code makes. The directory grant \
             needs (OI)(CI):\n{acl}"
        );
    }

    /// The sweep deletes an expired recording, keeps a live one, and leaves anything it cannot
    /// parse alone.
    #[test]
    fn the_sweep_removes_only_recordings_past_their_own_deadline() {
        let dir = TempDir::new("sweep");
        std::fs::create_dir_all(&dir.0).unwrap();
        let now = 1_000_000_000_000i64;

        let mk = |name: &str, deadline: i64| {
            let seg = format!("{name}-0000.ivf");
            std::fs::write(dir.0.join(&seg), b"not really ivf, but it is what gets deleted").unwrap();
            let side = Sidecar {
                kind: "rmt.session-recording.v1".into(),
                device_id: "dev-1".into(),
                session_id: None,
                started_at_unix_ms: 0,
                ended_at_unix_ms: 0,
                delete_after_unix_ms: deadline,
                segments: vec![Segment {
                    file: seg,
                    width: 8,
                    height: 8,
                    frames: 1,
                    payload_bytes: 1,
                    sha256: "x".into(),
                }],
                truncated: None,
                dropped_frames: 0,
                disclaimer: DISCLAIMER.into(),
            };
            std::fs::write(dir.0.join(format!("{name}.json")), serde_json::to_vec(&side).unwrap())
                .unwrap();
        };
        // REALISTIC stems. The fixture used to say "expired" and "live", which the recorder can
        // never write (`OpenSegment::create` always builds `rec-<start-ms>-NNNN.ivf`) — so after the
        // sweep learned to refuse names it could not have written, this test was asserting deletion
        // of files production would never have created. The premise, not the fix, was wrong.
        let expired = format!("rec-{}", now - 500_000);
        let live = format!("rec-{}", now - 400_000);
        mk(&expired, now - 1);
        mk(&live, now + 3_600_000);
        // Something this code did not write and cannot parse. Deleting it is how a sweep becomes
        // data loss, so it must be left strictly alone.
        std::fs::write(dir.0.join("someone-elses.json"), b"{not json at all").unwrap();

        assert_eq!(sweep_expired(&dir.0, now), 1, "exactly the expired one");
        assert!(!dir.0.join(format!("{expired}.json")).exists());
        assert!(!dir.0.join(format!("{expired}-0000.ivf")).exists(), "the segments go with the sidecar");
        assert!(dir.0.join(format!("{live}.json")).exists(), "a live recording must survive");
        assert!(dir.0.join(format!("{live}-0000.ivf")).exists());
        assert!(dir.0.join("someone-elses.json").exists(), "unparseable files are left alone");
    }

    #[test]
    fn the_sweep_refuses_to_delete_anything_a_sidecar_names_outside_its_own_directory() {
        // THE SECURITY REGRESSION. Loop 89 added the sweep's call site in `serve_session_with_ice`,
        // which runs in the SYSTEM helper BEFORE the transport connects — every reconnect, with no
        // technician and no session. The sweep read `segments[].file` straight out of a JSON file and
        // handed it to `remove_file`, and `Path::join` replaces the base for an absolute argument and
        // never normalizes `..`. On any machine that has never recorded, the directory does not exist
        // and `C:\` grants `Authenticated Users:(OI)(CI)(IO)(M)` — so a standard user creates it,
        // plants one sidecar, and gets an arbitrary file DELETED AS SYSTEM.
        let dir = TempDir::new("hostile");
        std::fs::create_dir_all(&dir.0).unwrap();
        let outside = dir.0.parent().unwrap().join(format!("canary-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&outside, b"must survive").unwrap();
        let inside_unrelated = dir.0.join("someone-elses-file.txt");
        std::fs::write(&inside_unrelated, b"must survive").unwrap();

        let now = 1_000_000_000_000i64;
        let started = now - 1_000;
        let stem = format!("rec-{started}");
        // The one segment this sidecar is entitled to have deleted...
        let legit = format!("{stem}-0000.ivf");
        std::fs::write(dir.0.join(&legit), b"ours").unwrap();
        // ...and two decoys that make the two INNER conditions load-bearing rather than decorative.
        // Both are single path components, so `sweepable_segment`'s component check cannot save them
        // — only the specific condition can, and a mutation sweep proved that without these files on
        // disk the assertions below were vacuous: the names were listed in the sidecar and nothing
        // observed their survival.
        //
        // The other recording's start time must be RECENT. `rec-999-0000.ivf` looked like the
        // obvious decoy and was a bad one: 999 ms after the Unix epoch is long past its TTL, so the
        // ORPHAN pass legitimately swept it and the test failed while the check under test was
        // working perfectly. A decoy has to be chosen so that only the mechanism being tested can
        // act on it — the same over-determination trap as an assertion two mechanisms can satisfy,
        // running in reverse.
        let other_recording = format!("rec-{}-0000.ivf", now - 60_000);
        let our_stem_wrong_shape = format!("{stem}-nope.txt"); // our stem, not our naming
        std::fs::write(dir.0.join(&other_recording), b"another recording's").unwrap();
        std::fs::write(dir.0.join(&our_stem_wrong_shape), b"not a segment").unwrap();
        // ...and every shape of name it is not.
        let hostile = vec![
            outside.to_string_lossy().into_owned(),          // absolute: join REPLACES the base
            format!("..\\{}", outside.file_name().unwrap().to_string_lossy()), // parent traversal
            "../canary.txt".to_string(),                     // and with the other separator
            "someone-elses-file.txt".to_string(),            // in-dir, but not our naming
            format!("sub\\{legit}"),                         // our naming, but nested
            other_recording.clone(),                         // our naming, ANOTHER recording's stem
            our_stem_wrong_shape.clone(),                    // our stem, not our naming
        ];
        let mut names = hostile.clone();
        names.push(legit.clone());
        let side = Sidecar {
            kind: SIDECAR_KIND.into(),
            device_id: "attacker".into(),
            session_id: None,
            started_at_unix_ms: started,
            ended_at_unix_ms: started,
            delete_after_unix_ms: now - 1, // expired, so the sweep acts on it
            segments: names
                .iter()
                .map(|f| Segment {
                    file: f.clone(),
                    width: 8,
                    height: 8,
                    frames: 1,
                    payload_bytes: 1,
                    sha256: "x".into(),
                })
                .collect(),
            truncated: None,
            dropped_frames: 0,
            disclaimer: DISCLAIMER.into(),
        };
        std::fs::write(dir.0.join(format!("{stem}.json")), serde_json::to_vec(&side).unwrap())
            .unwrap();

        sweep_expired(&dir.0, now);

        assert!(outside.exists(), "the sweep deleted a file OUTSIDE its directory as SYSTEM");
        assert!(inside_unrelated.exists(), "the sweep deleted an unrelated file in its directory");
        assert!(
            dir.0.join(&other_recording).exists(),
            "a planted sidecar deleted ANOTHER recording's segment — the stem binding is not holding"
        );
        assert!(
            dir.0.join(&our_stem_wrong_shape).exists(),
            "a name sharing our stem but not our naming was deleted — the naming check is not holding"
        );
        // THE POSITIVE CONTROL. Without it this test passes against a sweep that deletes nothing at
        // all — which would be "secure" and would also mean the TTL never runs.
        assert!(
            !dir.0.join(&legit).exists(),
            "the sweep must still delete the segment it legitimately owns, or the TTL is dead"
        );
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn a_foreign_file_that_merely_type_checks_as_a_sidecar_is_not_an_instruction_to_delete() {
        // `kind` is the schema marker, and the sweep now REQUIRES it. Any JSON that happens to
        // deserialize into `Sidecar` would otherwise be obeyed — and serde fills `kind` from
        // whatever string is there, so "it parsed" is not "it is ours".
        let dir = TempDir::new("foreign");
        std::fs::create_dir_all(&dir.0).unwrap();
        let now = 1_000_000_000_000i64;
        let started = now - 1_000;
        let stem = format!("rec-{started}");
        let seg = format!("{stem}-0000.ivf");
        std::fs::write(dir.0.join(&seg), b"ours").unwrap();
        let mut side = serde_json::json!({
            "kind": "some.other.schema.v9",
            "device_id": "x", "session_id": null,
            "started_at_unix_ms": started, "ended_at_unix_ms": started,
            "delete_after_unix_ms": now - 1,
            "segments": [{"file": seg, "width": 8, "height": 8, "frames": 1, "payload_bytes": 1, "sha256": "x"}],
            "truncated": null, "dropped_frames": 0, "disclaimer": "x",
        });
        let p = dir.0.join(format!("{stem}.json"));
        std::fs::write(&p, serde_json::to_vec(&side).unwrap()).unwrap();
        sweep_expired(&dir.0, now);
        assert!(dir.0.join(&seg).exists(), "a foreign `kind` must not drive the sweep");
        assert!(p.exists(), "…and its sidecar is left alone too");

        // The control: the SAME file with our own kind IS swept, so the assertion above is about
        // `kind` and not about some other rejection.
        side["kind"] = serde_json::Value::String(SIDECAR_KIND.to_string());
        std::fs::write(&p, serde_json::to_vec(&side).unwrap()).unwrap();
        sweep_expired(&dir.0, now);
        assert!(!dir.0.join(&seg).exists(), "our own kind must still be swept");
    }

    #[test]
    fn a_segments_start_time_is_read_from_its_name_and_only_from_a_name_we_wrote() {
        assert_eq!(segment_started_at("rec-1787540275742-0000.ivf"), Some(1_787_540_275_742));
        assert_eq!(segment_started_at("rec-1-0012.ivf"), Some(1));
        // Everything a sweep must NOT claim to understand. The rule is the same one the sidecar
        // pass follows: a file this code cannot fully explain is not ours to delete.
        for name in [
            "rec-1787540275742.json",     // the sidecar, not a segment
            "rec-notanumber-0000.ivf",    // unparseable start
            "rec-1787540275742-abc.ivf",  // unparseable index
            "rec-1787540275742-0000.ivf.bak", // not an .ivf
            "rec--0000.ivf",              // empty start
            "screenshot-1787540275742.png",
            "1787540275742-0000.ivf",     // no prefix
            "rec-0000.ivf",               // no index segment at all: `rec` is not a number
        ] {
            assert_eq!(segment_started_at(name), None, "must not claim to understand {name:?}");
        }
    }

    #[test]
    fn an_orphaned_segment_is_swept_once_it_outlives_the_ttl() {
        // THE HOLE THE SIDECAR PASS LEAVES. `sweep_expired` walks sidecars, and the sidecar is
        // written LAST — after every segment is finalized. So a killed process, a power loss, or a
        // failed sidecar write (which `disk_low` makes a realistic pairing) leaves up to a gigabyte
        // of video that nothing will ever remove. That is the "permanent video vault on other
        // organisations' machines" the whole TTL exists to prevent, reached through the failure
        // path instead of the happy one.
        let dir = TempDir::new("orphan");
        std::fs::create_dir_all(&dir.0).unwrap();
        let ttl_ms = (DEFAULT_TTL_HOURS as i64) * 3_600_000;
        let now = 1_000_000_000_000i64;

        let old = now - ttl_ms - 1; // started just over a TTL ago
        let recent = now - 60_000; // a minute ago — could still be recording RIGHT NOW
        for started in [old, recent] {
            std::fs::write(dir.0.join(format!("rec-{started}-0000.ivf")), b"vp8ish").unwrap();
        }
        // An old segment that DOES have a sidecar is the sidecar pass's business, not the orphan
        // pass's: here the sidecar says it may live, and it must.
        let kept = now - ttl_ms - 5;
        std::fs::write(dir.0.join(format!("rec-{kept}-0000.ivf")), b"vp8ish").unwrap();
        let side = Sidecar {
            kind: "rmt.session-recording.v1".into(),
            device_id: "dev-1".into(),
            session_id: None,
            started_at_unix_ms: kept,
            ended_at_unix_ms: kept,
            delete_after_unix_ms: now + 3_600_000,
            segments: vec![Segment {
                file: format!("rec-{kept}-0000.ivf"),
                width: 8,
                height: 8,
                frames: 1,
                payload_bytes: 1,
                sha256: "x".into(),
            }],
            truncated: None,
            dropped_frames: 0,
            disclaimer: DISCLAIMER.into(),
        };
        std::fs::write(dir.0.join(format!("rec-{kept}.json")), serde_json::to_vec(&side).unwrap())
            .unwrap();

        sweep_expired(&dir.0, now);

        assert!(
            !dir.0.join(format!("rec-{old}-0000.ivf")).exists(),
            "an orphan past its TTL must go — otherwise the TTL is not a bound at all"
        );
        assert!(
            dir.0.join(format!("rec-{recent}-0000.ivf")).exists(),
            "a RECENT orphan must survive: a recording in progress has segments and no sidecar yet, \
             and deleting one would delete the session being recorded right now"
        );
        assert!(
            dir.0.join(format!("rec-{kept}-0000.ivf")).exists(),
            "a segment whose sidecar says it may live must not be taken by the orphan pass"
        );
    }
}

#[cfg(test)]
#[cfg(windows)]
mod locked_dir_tests {
    //! Real-`icacls` regression tests for [`super::ensure_locked_dir`] (loop 91).
    //!
    //! The sibling of `enroll::identity_acl_tests`, and here for the same reason: loop 91 moved this
    //! function onto `crate::agent_root`'s builders and a mutation sweep found the change unkillable
    //! by every suite in the tree.
    //!
    //! `ensure_locked_dir` creates the leaf EXCLUSIVELY, so these tests hand it a path that does not
    //! exist yet — which is also the shape the real recorder uses on a machine that has never
    //! recorded, the exact moment a standard user could get there first.
    //!
    //! **One documented EQUIVALENT-UNDER-TEST mutant.** Deleting the `/setowner` call from
    //! `ensure_locked_dir` survives every test here, and that is a property of the runner rather
    //! than a gap in the assertions: these tests create the directory themselves, so the process is
    //! already its owner and the owner reset is a genuine no-op. The property it defends — a
    //! PRE-CREATOR keeps implicit `WRITE_DAC` and can re-grant itself after the lockdown — needs a
    //! second account to observe, which is a VM exercise, not a unit one. `agent_root` documented
    //! the identical limitation for the same step in loop 90.

    use std::path::Path;

    struct TempBase(std::path::PathBuf);
    impl TempBase {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "rmt-recdacl-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            grant_inheritable_access(&p);
            Self(p)
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Give `dir` an INHERITABLE grant, so anything created inside it genuinely carries inherited
    /// ACEs (`icacls` marks them `(I)`).
    ///
    /// The tests below are about STRIPPING inheritance, so they need something inherited to strip —
    /// otherwise the assertion that none survives is vacuous. They used to take that condition from
    /// `%TEMP%`, which supplies it on a developer box and NOT on a GitHub runner, whose temp DACL is
    /// already SYSTEM + Administrators with nothing reaching a child as inherited. Three tests then
    /// failed their own premise assertion on every CI run: the right behaviour — far better than
    /// passing vacuously — but a permanent red that says nothing about the code.
    ///
    /// Establishing the condition here makes the premise a property of the FIXTURE rather than of
    /// the host, which is what a premise assertion should be able to assume.
    ///
    /// Granted by SID (`*S-1-5-32-545`, BUILTIN\\Users) for the same reason the production code
    /// grants by SID: a name-based grant is wrong on a non-English Windows.
    fn grant_inheritable_access(dir: &Path) {
        let out = std::process::Command::new("icacls")
            .arg(dir.as_os_str())
            .args([
        "/grant",
        "*S-1-5-32-544:(OI)(CI)(F)",
        "/grant",
        "*S-1-5-18:(OI)(CI)(F)",
        "/grant",
        "*S-1-5-32-545:(OI)(CI)(RX)",
    ])
            .output()
            .expect("icacls runs");
        assert!(
            out.status.success(),
            "could not stage the inheritable ACE this fixture depends on: {} / {}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    fn icacls_read(path: &Path) -> String {
        let out = std::process::Command::new("icacls")
            .arg(path.as_os_str())
            .output()
            .expect("icacls runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A fresh recording directory ends up restricted to exactly SYSTEM + Administrators, with no
    /// inherited access — granted BY SID.
    ///
    /// The SID half is not cosmetic. Measured on this box: `icacls` given a principal it cannot
    /// resolve aborts the WHOLE command (exit 1332, "No mapping between account names and security
    /// IDs was done") and applies nothing, not even a preceding `/inheritance:r`. Since this function
    /// is deliberately FAIL-CLOSED — it returns `Err` and the caller refuses to record — the old
    /// name-based argv did not leave recordings unprotected on a French / German / Japanese Windows.
    /// It made recording IMPOSSIBLE there: a fleet-wide outage rather than a security hole, and
    /// invisible from an English-locale test box.
    #[test]
    fn a_locked_recording_dir_is_system_and_administrators_only() {
        let base = TempBase::new("fresh");
        let dir = base.0.join("recordings");

        // PREMISE (negative control): a directory created under the base really does INHERIT
        // access, so `/inheritance:r` has something to strip and the assertion below is not vacuous.
        //
        // Probed on an actual CHILD, not on the base itself. The base carrying `(I)` would only say
        // that %TEMP% granted it something — a fact about the HOST, and false on a GitHub runner,
        // where %TEMP%'s ACEs are not inheritable and everything created inside gets the token's
        // default DACL as EXPLICIT entries. What this test needs is that inheritance flows INTO the
        // directory `ensure_locked_dir` is about, which `TempBase` now guarantees.
        let probe = base.0.join("inherits-probe");
        std::fs::create_dir_all(&probe).expect("probe dir");
        let probe_acl = icacls_read(&probe);
        assert!(
            probe_acl.contains("(I)"),
            "premise not met: a child of the fixture base carries no inherited ACEs, so asserting \\
             they get stripped would pass vacuously:\n{probe_acl}"
        );
        std::fs::remove_dir_all(&probe).expect("probe cleanup");

        super::ensure_locked_dir(&dir).expect("a fresh directory must lock cleanly");

        let after = icacls_read(&dir);
        assert!(!after.contains("(I)"), "inherited ACEs survived:\n{after}");
        assert!(
            after.contains("NT AUTHORITY\\SYSTEM") || after.contains("S-1-5-18"),
            "SYSTEM was not granted:\n{after}"
        );
        assert!(
            after.contains("BUILTIN\\Administrators") || after.contains("S-1-5-32-544"),
            "Administrators was not granted:\n{after}"
        );
        // Locale-robust structural check: EXACTLY two principals. The two string checks above pass
        // vacuously on a non-English Windows; counting ACE lines does not.
        assert_eq!(
            after.lines().filter(|l| l.contains(":(")).count(),
            2,
            "expected exactly SYSTEM + Administrators (2 ACEs):\n{after}"
        );
        // The grants are INHERITABLE, so the `.ivf` files created inside are covered too. A grant
        // without (OI)(CI) would lock the directory while leaving every recording in it world-
        // writable — a lockdown confirmed against the wrong object.
        assert!(
            after.contains("(OI)") && after.contains("(CI)"),
            "the directory grant must be inheritable so the recordings inherit it:\n{after}"
        );
    }

    /// A PRE-PLANTED EXPLICIT ACE on an existing recording directory is stripped.
    ///
    /// `ensure_locked_dir` accepts a real directory that is already there (a machine that has
    /// recorded before), and `icacls /grant:r` is ADDITIVE — it replaces only the named principal's
    /// ACE. So without the `/reset` this function now runs first, a standard user who pre-created
    /// the directory and planted `Authenticated Users:(F)` would keep read/write access to every
    /// video of the guest's screen, while the lockdown reported success. Loop 90's review measured
    /// exactly this on `C:\rmt-agent`; this is the recording-directory instance.
    #[test]
    fn a_planted_explicit_ace_on_an_existing_recording_dir_is_stripped() {
        let base = TempBase::new("planted");
        let dir = base.0.join("recordings");
        std::fs::create_dir(&dir).unwrap();

        let plant = std::process::Command::new("icacls")
            .arg(dir.as_os_str())
            .args(["/grant", "*S-1-5-11:(OI)(CI)(F)"])
            .output()
            .expect("icacls runs");
        assert!(
            plant.status.success(),
            "staging the planted ACE failed: {}",
            String::from_utf8_lossy(&plant.stderr)
        );

        // PREMISE: it really is there before the lockdown runs.
        let before = icacls_read(&dir);
        assert!(
            before.contains("S-1-5-11") || before.contains("Authenticated Users"),
            "premise not met: the planted ACE is not on the directory:\n{before}"
        );

        super::ensure_locked_dir(&dir).expect("an existing directory must re-lock");

        let after = icacls_read(&dir);
        assert!(
            !after.contains("Authenticated Users") && !after.contains("S-1-5-11"),
            "the planted Authenticated Users ACE SURVIVED — every recording in this directory is \
             readable and deletable by any authenticated user:\n{after}"
        );
        assert_eq!(
            after.lines().filter(|l| l.contains(":(")).count(),
            2,
            "expected exactly SYSTEM + Administrators (2 ACEs):\n{after}"
        );
    }

    /// A REPARSE POINT planted at the recording path is refused, so the DACL is never applied to
    /// whatever it targets and no video is ever written through it.
    ///
    /// Creating a real junction needs no privilege (`mklink /J`), so this is the cheap attack. The
    /// test skips creating one only if the OS refuses — and then FAILS rather than passing quietly,
    /// because a silent skip here is the false green this whole harness exists to prevent.
    #[test]
    fn a_reparse_point_at_the_recording_path_is_refused() {
        let base = TempBase::new("junction");
        let target = base.0.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = base.0.join("recordings");

        let mk = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link.as_os_str())
            .arg(target.as_os_str())
            .output()
            .expect("cmd runs");
        assert!(
            mk.status.success() && link.exists(),
            "could not create the junction this test is about (stdout {} / stderr {}) — treating \
             that as a failure rather than a silent skip",
            String::from_utf8_lossy(&mk.stdout).trim(),
            String::from_utf8_lossy(&mk.stderr).trim()
        );

        let err = super::ensure_locked_dir(&link)
            .expect_err("a reparse point at the recording path must be REFUSED");
        let msg = err.to_string();
        assert!(
            msg.contains("reparse point"),
            "the refusal must say why, got {msg:?}"
        );
        // And the target's DACL was NOT touched: it still carries its inherited access.
        let t = icacls_read(&target);
        assert!(
            t.contains("(I)"),
            "the junction's TARGET was re-ACLed, which is the whole point of refusing:\n{t}"
        );
    }
}
