//! docs/77 phase 3 (3a): streamed downloads on the console's `files` data channel.
//!
//! The session-channel download (`serve_download`) reads the whole file into memory and queues every chunk at once on
//! the shared `frames` channel. Here one file at a time is streamed from the open handle on its own channel, paced by
//! the channel's buffered amount AND by the console's CREDITS (bytes it has written to disk): the agent never runs more
//! than [`WINDOW`] ahead, so neither side's memory grows with the file or with a stalled console.
//!
//! Wire (text = JSON control, binary = file bytes of the one active download):
//! - console -> agent: `{"t":"get","id":..,"path":..}`, `{"t":"credit","id":..,"written":N}`, `{"t":"cancel","id":..}`
//! - agent -> console: `{"t":"start","id":..,"name":..,"size":N,"sha256":..}`, binary chunks,
//!   `{"t":"done","id":..,"bytes":N}`, `{"t":"error","id":..?,"message":..}`
//!
//! The same rules as the session-channel download decide WHAT may be read (permission first, then
//! [`crate::host::open_download`]: transfer-folder confinement and staged-copy ownership). The digest in `start` is of
//! the whole file, computed before the first byte leaves, and the audit record is written then, exactly like today.
//! If the file changes while it streams, the console's running digest disagrees and it discards the file; the agent
//! notices too (the size or its own running digest) and records the failure. What may CONTINUE is re-checked every
//! chunk (the session's authority: ended, binding, indicator, grant generation and expiry), the permission at least once a
//! second, and a console that stops crediting for [`STALL_LIMIT`] loses the stream. Audit: a start record before the first
//! byte (as today) and a Failed record for any stream that does not complete, also one dropped by an aborted task (a drop
//! guard). Audit events go to the SESSION loop, as the shell relay's do.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_agent::backstage::audit::{AuditAction, AuditEvent, Direction, Outcome, SharedAuditChain};
use rmt_agent::backstage::Dispatcher;
use rmt_transport_webrtc::{FilesChannel, ShellMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use crate::shell_relay::{Admission, ShellAuthority};

/// Bytes per binary message (well under every browser's SCTP message limit).
pub(crate) const CHUNK: usize = 32 * 1024;
/// How far ahead of the console's written bytes the agent may be.
pub(crate) const WINDOW: u64 = 8 * 1024 * 1024;
/// Above this many bytes queued on the channel the agent waits (the link, not the console, is the bottleneck).
pub(crate) const HIGH_WATER: usize = 1024 * 1024;
/// The largest file streamed from the transfer folder (a staged copy, or a file already there): today's limit. A LEASE
/// may be up to `fs_manage::MAX_LEASE_BYTES` (3b review SEC-004: the larger limit applies to leases only).
pub(crate) const MAX_STREAM_BYTES: u64 = crate::fs_manage::MAX_STAGE_BYTES;
/// Streamed downloads at once across ALL sessions of this agent (several consoles on one machine).
pub(crate) const AGENT_MAX_STREAMS: usize = 2;
static ACTIVE_STREAMS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum ConsoleMsg {
    Get { id: Uuid, path: String },
    Credit { id: Uuid, written: u64 },
    Cancel { id: Uuid },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum AgentMsg {
    Start { id: Uuid, name: String, size: u64, sha256: String },
    Done { id: Uuid, bytes: u64 },
    Error { #[serde(skip_serializing_if = "Option::is_none")] id: Option<Uuid>, message: String },
}

/// The credit window: how much may be sent now.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) sent: u64,
    pub(crate) written: u64,
}

impl Window {
    /// Bytes that may be sent before the next credit.
    pub(crate) fn allowance(&self) -> u64 {
        self.written.saturating_add(WINDOW).saturating_sub(self.sent)
    }

    /// The console wrote `written` bytes in total. Credits only move forward (a stale one is ignored); a credit for
    /// bytes never sent is a protocol error.
    pub(crate) fn credit(&mut self, written: u64) -> Result<(), &'static str> {
        if written > self.sent {
            return Err("credit for bytes that were never sent");
        }
        self.written = self.written.max(written);
        Ok(())
    }
}

/// One slot of [`AGENT_MAX_STREAMS`], released on drop.
struct StreamSlot;

impl StreamSlot {
    fn try_take() -> Option<Self> {
        let mut cur = ACTIVE_STREAMS.load(Ordering::SeqCst);
        loop {
            if cur >= AGENT_MAX_STREAMS {
                return None;
            }
            match ACTIVE_STREAMS.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(StreamSlot),
                Err(now) => cur = now,
            }
        }
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        ACTIVE_STREAMS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Everything the stream server needs from the session.
pub(crate) struct FileStreamContext {
    pub(crate) authority: Arc<ShellAuthority>,
    /// The session's Backstage dispatcher twin (as the shell relay has): the permission and the audit records.
    pub(crate) dispatcher: Arc<Mutex<Option<Dispatcher>>>,
    /// The session's audit chain: a denial with NO grant is sealed here (as `audit_file_transfer` does).
    pub(crate) chain: SharedAuditChain,
    /// Sealed events go to the SESSION loop, which forwards them on the session channel.
    pub(crate) audit_out: tokio::sync::mpsc::UnboundedSender<AuditEvent>,
    pub(crate) transfer_dir: PathBuf,
    pub(crate) staged: Arc<crate::fs_manage::StagedLedger>,
    /// Each chunk sent counts as session activity (an agent update waits for an idle session).
    pub(crate) touch: Box<dyn Fn() + Send + Sync>,
    /// True from a Get until its outcome is recorded, hashing included (teardown waits for the record).
    pub(crate) streaming: Arc<std::sync::atomic::AtomicBool>,
}

/// A console that stops crediting (or reading) for this long loses the download and its agent-wide slot (review M2).
pub(crate) const STALL_LIMIT: Duration = Duration::from_secs(60);
/// Refused or failed Gets on one channel before it is closed (review L4: each costs a hashing pass and audit events).
pub(crate) const MAX_FAILED_GETS: u32 = 20;
/// The grant is re-checked at least this often while a stream is alive (the authority itself: every chunk).
const PERMISSION_RECHECK: Duration = Duration::from_secs(1);

fn lock_dispatcher(ctx: &FileStreamContext) -> std::sync::MutexGuard<'_, Option<Dispatcher>> {
    ctx.dispatcher.lock().unwrap_or_else(|p| p.into_inner())
}

/// Record one file-transfer event through the dispatcher twin and hand it to the session loop.
fn audit(ctx: &FileStreamContext, path: String, sha256: String, bytes: u64, outcome: Outcome) {
    if let Some(d) = lock_dispatcher(ctx).as_mut() {
        let (ev, _) = d.record_file_transfer(Direction::Output, path, sha256, bytes, outcome, now_ms());
        let _ = ctx.audit_out.send(ev);
    }
}

/// ADR-008: authorize BEFORE resolving or reading anything. A refusal is recorded in the SAME lock scope as the check
/// (review L2: a grant installed between the two could otherwise seal Ok for a transfer that never ran); with no grant at
/// all it is sealed into the session chain directly, as `audit_file_transfer` does.
fn authorize(ctx: &FileStreamContext, path: &str) -> bool {
    let mut guard = lock_dispatcher(ctx);
    match guard.as_mut() {
        Some(d) if d.allows_file_transfer(Direction::Output) => true,
        Some(d) => {
            // `record_file_transfer` replaces the outcome with the denial reason when the grant does not allow it.
            let (ev, _) = d.record_file_transfer(Direction::Output, path.to_string(), String::new(), 0, Outcome::Ok, now_ms());
            let _ = ctx.audit_out.send(ev);
            false
        }
        None => {
            drop(guard);
            if let Some(ev) = rmt_agent::backstage::audit::try_record_shared(
                &ctx.chain,
                AuditAction::FileTransfer { direction: Direction::Output, path: path.to_string(), sha256: String::new(), bytes: 0 },
                Outcome::Denied { reason: "no backstage grant is installed for this session".into() },
                now_ms(),
            ) {
                let _ = ctx.audit_out.send(ev);
            }
            false
        }
    }
}

fn permitted(ctx: &FileStreamContext) -> bool {
    lock_dispatcher(ctx).as_ref().is_some_and(|d| d.allows_file_transfer(Direction::Output))
}

struct Active {
    id: Uuid,
    file: tokio::fs::File,
    resolved: PathBuf,
    staged_name: Option<String>,
    size: u64,
    sha256: String,
    running: Sha256,
    window: Window,
    admission: Admission,
    last_permission_check: Instant,
    /// When the console last let the stream move (a credit that advanced, or the start).
    last_progress: Instant,
    /// Set once the outcome is recorded (success, or an explicit failure): the drop guard then records nothing.
    concluded: bool,
    /// For the drop guard: a stream dropped WITHOUT a recorded outcome (the task aborted at teardown) records Failed.
    sink: AuditSink,
    _slot: StreamSlot,
}

/// What the drop guard needs to record an outcome without the context.
#[derive(Clone)]
struct AuditSink {
    dispatcher: Arc<Mutex<Option<Dispatcher>>>,
    audit_out: tokio::sync::mpsc::UnboundedSender<AuditEvent>,
}

impl Active {
    /// The digest of the bytes that actually left so far (review L1: a Failed record names what left, not pass 1).
    fn sent_digest(&self) -> String {
        hex::encode(self.running.clone().finalize())
    }

    fn record_failed(&mut self, why: &str) {
        if self.concluded {
            return;
        }
        self.concluded = true;
        let mut guard = self.sink.dispatcher.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(d) = guard.as_mut() {
            let (ev, _) = d.record_file_transfer(
                Direction::Output,
                self.resolved.to_string_lossy().into_owned(),
                self.sent_digest(),
                self.window.sent,
                Outcome::Failed { error: format!("{why} after {} of {} bytes", self.window.sent, self.size) },
                now_ms(),
            );
            let _ = self.sink.audit_out.send(ev);
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        // Review M1: a stream cut short without a recorded outcome (the task aborted) must not read as complete.
        self.record_failed("the transfer was interrupted");
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn send(chan: &FilesChannel, msg: &AgentMsg) -> bool {
    match serde_json::to_string(msg) {
        Ok(s) => chan.send_text(&s).await.is_ok(),
        Err(_) => false,
    }
}

/// Open, check and hash a requested file. Errors are the reply text (audited by the caller).
async fn begin(ctx: &FileStreamContext, id: Uuid, path: &str) -> Result<Active, String> {
    let admission = ctx.authority.admit_read(ctx.authority.now()).map_err(str::to_string)?;
    let slot = StreamSlot::try_take().ok_or("this machine is already sending its limit of files; try again shortly")?;
    let dir = ctx.transfer_dir.clone();
    let staged = ctx.staged.clone();
    let path_owned = path.to_string();
    let auth = ctx.authority.clone();
    // Blocking work (open, metadata, the hashing pass) off the async threads. The slot travels with it, and the pass
    // re-checks the session every buffer: an ended session (or a lost indicator) stops a 4 GiB read at once instead of
    // after it, even when teardown aborted the awaiting task (1.3.39 release review L1).
    let (file, resolved, staged_name, size, sha256, slot) = tokio::task::spawn_blocking(move || -> Result<_, String> {
        // docs/77 phase 3b: a LEASED file (too big to copy) is reopened by its recorded identity; anything else is the
        // transfer-folder download with today's checks.
        let lease_name = path_owned.to_lowercase();
        let (crate::host::OpenedDownload { mut file, resolved, staged_name }, limit) = match staged.attempt_lease(&lease_name) {
            Ok(lease) => {
                let (file, real) = crate::fs_manage::open_lease(&lease).map_err(|e| format!("read failed: {e}"))?;
                // The path audited is the reopened handle's own (3b review SEC-005).
                (crate::host::OpenedDownload { file, resolved: PathBuf::from(real), staged_name: Some(lease_name) }, crate::fs_manage::MAX_LEASE_BYTES)
            }
            Err(true) => return Err("this file was already tried several times; choose it again".into()),
            Err(false) => (crate::host::open_download(&dir, &path_owned, Some(&staged))?, MAX_STREAM_BYTES),
        };
        let size = file.metadata().map_err(|e| format!("read failed: {e}"))?.len();
        if size > limit {
            return Err(format!("the file is larger than {} MiB", limit / (1024 * 1024)));
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            auth.check_read(&admission, auth.now()).map_err(str::to_string)?;
            let n = file.read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > size {
                return Err("the file changed while it was being read".into());
            }
            h.update(&buf[..n]);
        }
        if total != size {
            return Err("the file changed while it was being read".into());
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| format!("read failed: {e}"))?;
        Ok((file, resolved, staged_name, size, hex::encode(h.finalize()), slot))
    })
    .await
    .map_err(|_| "read failed".to_string())??;
    let now = Instant::now();
    Ok(Active {
        id,
        file: tokio::fs::File::from_std(file),
        resolved,
        staged_name,
        size,
        sha256,
        running: Sha256::new(),
        window: Window::default(),
        admission,
        last_permission_check: now,
        last_progress: now,
        concluded: false,
        sink: AuditSink { dispatcher: ctx.dispatcher.clone(), audit_out: ctx.audit_out.clone() },
        _slot: slot,
    })
}

/// 1.3.39 release review L2: a Get cut short while it is still being opened and hashed (the task aborted at teardown)
/// records Failed too; disarmed once `begin` returned (the stream, or the caller's own failure record, takes over).
struct PendingGet {
    sink: AuditSink,
    path: String,
    armed: bool,
}

impl Drop for PendingGet {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut guard = self.sink.dispatcher.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(d) = guard.as_mut() {
            let (ev, _) = d.record_file_transfer(
                Direction::Output,
                std::mem::take(&mut self.path),
                String::new(),
                0,
                Outcome::Failed { error: "interrupted before anything was sent".into() },
                now_ms(),
            );
            let _ = self.sink.audit_out.send(ev);
        }
    }
}

/// End an active download that did not complete: tell the console (if it can still hear) and record the outcome.
async fn abort(chan: &FilesChannel, mut a: Active, why: &str) {
    a.record_failed(why);
    let _ = send(chan, &AgentMsg::Error { id: Some(a.id), message: why.to_string() }).await;
}

/// May the stream keep going? The authority (atomics) every time; the grant at least once a second; and the console
/// must keep the stream moving (review M2).
fn keep_going(ctx: &FileStreamContext, a: &mut Active) -> Result<(), &'static str> {
    ctx.authority.check_read(&a.admission, ctx.authority.now())?;
    if a.last_permission_check.elapsed() >= PERMISSION_RECHECK {
        a.last_permission_check = Instant::now();
        if !permitted(ctx) {
            return Err("file download is no longer permitted");
        }
    }
    if a.last_progress.elapsed() >= STALL_LIMIT {
        return Err("the console stopped accepting the file");
    }
    Ok(())
}

/// Serve one files channel until it closes. One download at a time on it.
pub(crate) async fn run(mut chan: FilesChannel, ctx: &FileStreamContext) {
    let mut active: Option<Active> = None;
    let mut failed_gets: u32 = 0;
    let mut buf = vec![0u8; CHUNK];
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ctx.streaming.store(active.is_some(), Ordering::SeqCst);
        // May the active download send a chunk right now (credits and the channel's queue)?
        let ready = match active.as_ref() {
            Some(a) => a.window.allowance() > 0 && chan.buffered_amount().await <= HIGH_WATER,
            None => false,
        };
        tokio::select! {
            biased;
            m = chan.recv() => {
                let Some(m) = m else {
                    if let Some(a) = active.take() {
                        abort(&chan, a, "the console closed the transfer channel").await;
                    }
                    ctx.streaming.store(false, Ordering::SeqCst);
                    return;
                };
                let ShellMessage::Text(text) = m else {
                    // Binary from the console is never valid here.
                    if let Some(a) = active.take() {
                        abort(&chan, a, "protocol error").await;
                    }
                    chan.close().await;
                    return;
                };
                match serde_json::from_str::<ConsoleMsg>(&text) {
                    Ok(ConsoleMsg::Get { id, path }) => {
                        if active.is_some() {
                            let _ = send(&chan, &AgentMsg::Error { id: Some(id), message: "a file is already being sent on this channel".into() }).await;
                            continue;
                        }
                        // Review L3: before the session is bound (docs/69) say nothing specific and seal nothing.
                        if !ctx.authority.is_bound() {
                            let _ = send(&chan, &AgentMsg::Error { id: Some(id), message: "file download is not available".into() }).await;
                            continue;
                        }
                        // Busy from here (hashing included): teardown waits for this Get's record (review M1).
                        ctx.streaming.store(true, Ordering::SeqCst);
                        let outcome = if !authorize(ctx, &path) {
                            Err("file download not permitted for this session".to_string())
                        } else {
                            let mut pending = PendingGet {
                                sink: AuditSink { dispatcher: ctx.dispatcher.clone(), audit_out: ctx.audit_out.clone() },
                                path: path.clone(),
                                armed: true,
                            };
                            let began = begin(ctx, id, &path).await;
                            pending.armed = false;
                            match began {
                                Ok(a) => Ok(a),
                                Err(e) => {
                                    audit(ctx, path.clone(), String::new(), 0, Outcome::Failed { error: e.clone() });
                                    Err(e)
                                }
                            }
                        };
                        match outcome {
                            Ok(a) if !permitted(ctx) => {
                                // The grant may have changed during a long hashing pass: re-check before the first
                                // byte (1.3.39 release review round 2, Low).
                                abort(&chan, a, "file download is no longer permitted").await;
                                continue;
                            }
                            Ok(a) => {
                                failed_gets = 0;
                                let name = a.resolved.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "download.bin".into());
                                // The record of what leaves, before the first byte does (as the session-channel path).
                                audit(ctx, a.resolved.to_string_lossy().into_owned(), a.sha256.clone(), a.size, Outcome::Ok);
                                if !send(&chan, &AgentMsg::Start { id, name, size: a.size, sha256: a.sha256.clone() }).await {
                                    abort(&chan, a, "the transfer channel failed").await;
                                    continue;
                                }
                                active = Some(a);
                            }
                            Err(e) => {
                                let _ = send(&chan, &AgentMsg::Error { id: Some(id), message: e }).await;
                                failed_gets += 1;
                                if failed_gets >= MAX_FAILED_GETS {
                                    // Review L4: a console that keeps asking for what it cannot have loses the channel.
                                    ctx.streaming.store(false, Ordering::SeqCst);
                                    chan.close().await;
                                    return;
                                }
                            }
                        }
                    }
                    Ok(ConsoleMsg::Credit { id, written }) => {
                        if let Some(a) = active.as_mut().filter(|a| a.id == id) {
                            let before = a.window.written;
                            if let Err(e) = a.window.credit(written) {
                                let a = active.take().expect("active");
                                abort(&chan, a, e).await;
                            } else if a.window.written == a.size && a.window.sent == a.size {
                                // Everything sent and written: done. The start record stands as the transfer's record;
                                // the drop guard records nothing. A staged copy has done its job.
                                let mut a = active.take().expect("active");
                                a.concluded = true;
                                let _ = send(&chan, &AgentMsg::Done { id: a.id, bytes: a.size }).await;
                                if let Some(n) = a.staged_name.clone() {
                                    drop(a);
                                    if ctx.staged.release(&n) {
                                        let _ = std::fs::remove_file(ctx.transfer_dir.join(&n));
                                    }
                                }
                            } else if a.window.written > before {
                                a.last_progress = Instant::now();
                            }
                        }
                    }
                    Ok(ConsoleMsg::Cancel { id }) => {
                        if active.as_ref().is_some_and(|a| a.id == id) {
                            let a = active.take().expect("active");
                            abort(&chan, a, "cancelled by the technician").await;
                        }
                    }
                    Err(_) => {
                        if let Some(a) = active.take() {
                            abort(&chan, a, "protocol error").await;
                        }
                        chan.close().await;
                        return;
                    }
                }
            }
            _ = async {}, if ready => {
                let a = active.as_mut().expect("ready implies active");
                if let Err(why) = keep_going(ctx, a) {
                    let a = active.take().expect("active");
                    abort(&chan, a, why).await;
                    continue;
                }
                let want = (a.size - a.window.sent).min(a.window.allowance()).min(CHUNK as u64) as usize;
                if want == 0 {
                    // Everything is sent; waiting for the final credit (keep_going above still runs every pass).
                    tick.tick().await;
                    continue;
                }
                let n = match a.file.read(&mut buf[..want]).await {
                    Ok(n) => n,
                    Err(e) => {
                        let a = active.take().expect("active");
                        abort(&chan, a, &format!("read failed: {e}")).await;
                        continue;
                    }
                };
                if n == 0 {
                    let a = active.take().expect("active");
                    abort(&chan, a, "the file changed while it was being copied").await;
                    continue;
                }
                a.running.update(&buf[..n]);
                if chan.send_binary(&buf[..n]).await.is_err() {
                    let a = active.take().expect("active");
                    abort(&chan, a, "the transfer channel failed").await;
                    continue;
                }
                a.window.sent += n as u64;
                (ctx.touch)();
                if a.window.sent == a.size && a.sent_digest() != a.sha256 {
                    // Our own running digest must match the one announced: a file rewritten between the hashing pass
                    // and the stream is caught here as well as by the console.
                    let a = active.take().expect("active");
                    abort(&chan, a, "the file changed while it was being copied").await;
                }
            }
            _ = tick.tick() => {
                // Waiting on credits or a full queue: still notice an authority change or a stalled console.
                if let Some(a) = active.as_mut() {
                    if let Err(why) = keep_going(ctx, a) {
                        let a = active.take().expect("active");
                        abort(&chan, a, why).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_allows_at_most_window_bytes_ahead_of_the_console() {
        let mut w = Window::default();
        assert_eq!(w.allowance(), WINDOW);
        w.sent = WINDOW;
        assert_eq!(w.allowance(), 0, "a stalled console stops the agent");
        w.credit(1024).unwrap();
        assert_eq!(w.allowance(), 1024);
        w.credit(10).unwrap();
        assert_eq!(w.written, 1024, "a stale credit never moves the window back");
        assert!(w.credit(WINDOW + 1).is_err(), "credit for bytes never sent is refused");
    }

    #[test]
    fn console_messages_parse_strictly() {
        let id = Uuid::new_v4();
        assert_eq!(
            serde_json::from_str::<ConsoleMsg>(&format!(r#"{{"t":"get","id":"{id}","path":"a.txt"}}"#)).unwrap(),
            ConsoleMsg::Get { id, path: "a.txt".into() }
        );
        assert_eq!(
            serde_json::from_str::<ConsoleMsg>(&format!(r#"{{"t":"credit","id":"{id}","written":5}}"#)).unwrap(),
            ConsoleMsg::Credit { id, written: 5 }
        );
        assert!(serde_json::from_str::<ConsoleMsg>(r#"{"t":"credit","id":"nope","written":5}"#).is_err());
        assert!(serde_json::from_str::<ConsoleMsg>(r#"{"t":"rm","path":"x"}"#).is_err());
        assert!(serde_json::from_str::<ConsoleMsg>(&format!(r#"{{"t":"credit","id":"{id}","written":-1}}"#)).is_err());
    }

    #[test]
    fn agent_messages_have_the_documented_shape() {
        let id = Uuid::nil();
        assert_eq!(
            serde_json::to_string(&AgentMsg::Error { id: None, message: "x".into() }).unwrap(),
            r#"{"t":"error","message":"x"}"#
        );
        assert_eq!(
            serde_json::to_string(&AgentMsg::Done { id, bytes: 3 }).unwrap(),
            format!(r#"{{"t":"done","id":"{id}","bytes":3}}"#)
        );
    }

    #[test]
    fn the_agent_wide_stream_cap_holds_and_frees() {
        let a = StreamSlot::try_take().expect("first");
        let b = StreamSlot::try_take().expect("second");
        assert!(StreamSlot::try_take().is_none(), "a third concurrent stream is refused");
        drop(a);
        let c = StreamSlot::try_take().expect("a freed slot can be taken again");
        drop((b, c));
    }
}
