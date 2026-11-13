//! The upload writer (docs/58 §1, §12): ONE thread owns every upload of the session (its state, its
//! `.part` handle, its hasher) and does all upload disk I/O, so a stalled write or commit never
//! stalls the session loop, which must keep processing indicator loss and teardown.
//!
//! The loop never waits on it and never touches upload state. It only:
//!   * forwards `Offer` / `Chunk` / `Done` through a BOUNDED channel ([`QUEUE`]) with `try_send`, and
//!     a newly installed grant through a slot the writer picks up ([`UploadWriter::install`]);
//!   * keeps one [`Flag`] per upload, created at the `Offer` and shared with the writer. A full
//!     channel cancels that upload ([`OVERFLOW`]); indicator loss cancels every live upload
//!     ([`INDICATOR_LOST`]); teardown cancels them ([`SESSION_ENDED`]). A cancel never returns to
//!     [`LIVE`], and none applies once the writer has admitted the commit ([`COMMITTING`]).
//!
//! The writer discovers cancellations itself: it waits with `recv_timeout` ([`WAKE`], never an
//! unbounded `recv`) and scans its uploads on every wake, so an idle cancelled upload is finished
//! within 250 ms with no further frame and no queue capacity. It checks admission (the flag, and the
//! mutation gate's generation stamped at the `Offer`) immediately before each write and the commit.
//!
//! **Exactly one terminal record per upload, and none after teardown.** Cancelling and recording are
//! separate. The writer does an ending's disk work (dispose, commit) FIRST and only then appends its
//! record, through the session's [`Ledger`]. Teardown, after waiting up to 5 s, closes the ledger and
//! records "abandoned" for every upload still without a record, whatever it was cancelled for or
//! whether its commit was under way. A writer that comes back from a system call after that only
//! disposes and logs its outcome to the agent log: it never appends to the chain again.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmt_agent::backstage::audit::SharedAuditChain;
use rmt_agent::backstage::gate::MutationGate;
use rmt_agent::backstage::Dispatcher;
use rmt_agent_core::file_transfer::{Chunk, Message as FtMessage, Offer};
use uuid::Uuid;

use crate::host::{self, PendingRecord, Step, UploadState};
use crate::upload_root::{LazyRoot, UploadRoot};

/// Upload states. [`LIVE`] is the only one that admits work.
pub(crate) const LIVE: u8 = 0;
pub(crate) const INDICATOR_LOST: u8 = 1;
pub(crate) const OVERFLOW: u8 = 2;
pub(crate) const SESSION_ENDED: u8 = 3;
/// The writer admitted the commit: its real result is the outcome; no cancel applies any more.
pub(crate) const COMMITTING: u8 = 4;
/// The writer ended the upload.
pub(crate) const ENDED: u8 = 5;

pub(crate) const QUEUE: usize = 64;
pub(crate) const WAKE: Duration = Duration::from_millis(250);

pub(crate) fn reason(code: u8) -> &'static str {
    match code {
        INDICATOR_LOST => "upload stopped: the guest's on-screen indicator could not be shown",
        OVERFLOW => "upload stopped: this machine's disk is not keeping up",
        SESSION_ENDED => "upload stopped: the session ended",
        _ => "upload stopped",
    }
}

/// One upload's shared control: its state, and whether its terminal record has been claimed.
#[derive(Debug, Default)]
pub(crate) struct Ctl {
    state: AtomicU8,
    recorded: AtomicBool,
}

impl Ctl {
    pub(crate) fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }

    /// Claim the right to append this upload's terminal record (true exactly once).
    pub(crate) fn claim_record(&self) -> bool {
        !self.recorded.swap(true, Ordering::SeqCst)
    }
}

pub(crate) type Flag = Arc<Ctl>;

pub(crate) fn new_flag() -> Flag {
    Arc::new(Ctl::default())
}

/// Cancel a live upload with `code` (no-op if it was already cancelled, committing, or ended).
pub(crate) fn cancel(flag: &Flag, code: u8) {
    let _ = flag.state.compare_exchange(LIVE, code, Ordering::SeqCst, Ordering::SeqCst);
}

/// The session's upload record book. The writer appends a terminal record only through it; teardown
/// closes it, after which nothing the writer finishes is appended.
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    closed: Mutex<bool>,
}

impl Ledger {
    /// Run `append` (which seals `flag`'s upload's terminal record) unless the ledger is closed or
    /// that upload already has its record.
    pub(crate) fn record<R>(&self, flag: &Flag, append: impl FnOnce() -> R) -> Option<R> {
        let closed = self.closed.lock().unwrap_or_else(|p| p.into_inner());
        if *closed || !flag.claim_record() {
            return None;
        }
        Some(append())
    }

    /// Teardown: close the ledger and, under the same lock, record what is still unrecorded.
    pub(crate) fn close<R>(&self, record_rest: impl FnOnce() -> R) -> R {
        let mut closed = self.closed.lock().unwrap_or_else(|p| p.into_inner());
        *closed = true;
        record_rest()
    }
}

pub(crate) enum Item {
    Offer { offer: Offer, stamp: u64, flag: Flag },
    Chunk(Chunk),
    Done(Uuid),
}

/// What the writer hands back to the loop.
#[derive(Debug, Default)]
pub(crate) struct Out {
    /// Replies for the file-transfer channel.
    pub frames: Vec<FtMessage>,
    /// Uploads that reached their terminal outcome (the loop forgets their flags).
    pub finished: Vec<Uuid>,
}

pub(crate) enum Submit {
    Sent,
    /// The queue is full (the writer is stalled): the caller cancels the upload.
    Full,
    /// The writer is gone.
    Closed,
}

/// The loop's handle on the writer.
pub(crate) struct UploadWriter {
    tx: SyncSender<Item>,
    install: Arc<Mutex<Option<Dispatcher>>>,
}

impl UploadWriter {
    pub(crate) fn spawn(
        chain: SharedAuditChain,
        ledger: Arc<Ledger>,
        root: LazyRoot,
        root_slot: Arc<Mutex<Option<Arc<UploadRoot>>>>,
        gate: Arc<MutationGate>,
        out: tokio::sync::mpsc::UnboundedSender<Out>,
        now_ms: fn() -> i64,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Item>(QUEUE);
        let install = Arc::new(Mutex::new(None));
        let writer = Writer {
            chain,
            ledger,
            root,
            root_slot,
            gate,
            out,
            now_ms,
            install: Arc::clone(&install),
            dispatcher: None,
            uploads: HashMap::new(),
            meta: HashMap::new(),
        };
        std::thread::Builder::new()
            .name("upload-writer".into())
            .spawn(move || writer.run(rx))
            .expect("spawn upload writer");
        Self { tx, install }
    }

    /// Never blocks.
    pub(crate) fn submit(&self, item: Item) -> Submit {
        match self.tx.try_send(item) {
            Ok(()) => Submit::Sent,
            Err(TrySendError::Full(_)) => Submit::Full,
            Err(TrySendError::Disconnected(_)) => Submit::Closed,
        }
    }

    /// The dispatcher for a newly installed grant. Never blocks on the writer (Codex phase B review):
    /// it is left in a slot the writer takes before handling its next item, so an `Offer` the loop
    /// submits after this call is handled under this grant.
    pub(crate) fn install(&self, d: Dispatcher) {
        *self.install.lock().unwrap_or_else(|p| p.into_inner()) = Some(d);
    }
}

struct Meta {
    stamp: u64,
    flag: Flag,
}

struct Writer {
    chain: SharedAuditChain,
    ledger: Arc<Ledger>,
    root: LazyRoot,
    root_slot: Arc<Mutex<Option<Arc<UploadRoot>>>>,
    gate: Arc<MutationGate>,
    out: tokio::sync::mpsc::UnboundedSender<Out>,
    now_ms: fn() -> i64,
    install: Arc<Mutex<Option<Dispatcher>>>,
    dispatcher: Option<Dispatcher>,
    uploads: HashMap<Uuid, UploadState>,
    meta: HashMap<Uuid, Meta>,
}

impl Writer {
    fn run(mut self, rx: mpsc::Receiver<Item>) {
        loop {
            let mut out = Out::default();
            let item = rx.recv_timeout(WAKE);
            if let Some(d) = self.install.lock().unwrap_or_else(|p| p.into_inner()).take() {
                self.dispatcher = Some(d);
            }
            // Cancellations first, on EVERY wake: an already-cancelled upload is ended before this
            // item can start new disk work (Codex phase B review, r2).
            self.scan(&mut out);
            match item {
                Ok(Item::Offer { offer, stamp, flag }) => self.offer(offer, stamp, flag, &mut out),
                Ok(Item::Chunk(chunk)) => self.chunk(chunk, &mut out),
                Ok(Item::Done(id)) => self.done(id, &mut out),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    // The session is tearing down: every upload still here ends now.
                    for m in self.meta.values() {
                        cancel(&m.flag, SESSION_ENDED);
                    }
                    self.scan(&mut out);
                    self.emit(out);
                    return;
                }
            }
            self.scan(&mut out);
            self.emit(out);
        }
    }

    fn emit(&self, out: Out) {
        if !out.frames.is_empty() || !out.finished.is_empty() {
            let _ = self.out.send(out);
        }
    }

    fn admitted(&self, m: &Meta) -> bool {
        m.flag.state() == LIVE && self.gate.admits(m.stamp)
    }

    /// An upload's ending: its replies, then its record through the ledger (its disk work is done).
    fn conclude(&mut self, id: Uuid, flag: &Flag, step: Step, out: &mut Out) {
        flag.state.store(ENDED, Ordering::SeqCst);
        out.frames.extend(step.frames);
        if let Some(rec) = step.record {
            self.append(id, flag, rec, out);
        }
        out.finished.push(id);
    }

    fn append(&mut self, id: Uuid, flag: &Flag, rec: PendingRecord, out: &mut Out) {
        let outcome = format!("{:?}", rec.outcome);
        let (chain, dispatcher) = (&self.chain, self.dispatcher.as_mut());
        match self.ledger.record(flag, || rec.record(chain, dispatcher)) {
            Some(audit) => out.frames.extend(audit),
            None => tracing::warn!(
                transfer = %id,
                outcome,
                "upload ended after session teardown recorded it as abandoned; outcome logged here only"
            ),
        }
    }

    fn offer(&mut self, offer: Offer, stamp: u64, flag: Flag, out: &mut Out) {
        let id = offer.id;
        let now = (self.now_ms)();
        if self.meta.contains_key(&id) {
            // The loop refuses a repeated id before it gets here; never disturb the running upload
            // (its meta, its state, or the loop's record of it) if one does.
            let step = host::upload_refused_step(id, offer.name, "upload repeats an active id".into(), now);
            out.frames.extend(step.frames);
            if let Some(rec) = step.record {
                self.append(id, &flag, rec, out);
            }
            return;
        }
        let meta = Meta { stamp, flag };
        if !self.admitted(&meta) {
            // Cancelled before it started: one refusal, one record (it was authorized to try).
            let cur = meta.flag.state();
            let code = if cur == LIVE { INDICATOR_LOST } else { cur };
            let step = host::upload_refused_step(id, offer.name, reason(code).into(), now);
            self.conclude(id, &meta.flag, step, out);
            return;
        }
        let step = host::start_upload_step(offer, &mut self.uploads, &mut self.root, self.dispatcher.as_ref(), now);
        if let Some(root) = self.root.opened() {
            let mut slot = self.root_slot.lock().unwrap_or_else(|p| p.into_inner());
            if slot.is_none() {
                *slot = Some(Arc::clone(root));
            }
        }
        if step.record.is_none() && self.uploads.contains_key(&id) {
            self.meta.insert(id, meta);
            out.frames.extend(step.frames);
        } else {
            // Refused (denied, a limit, no root): the refusal is its terminal outcome.
            self.conclude(id, &meta.flag, step, out);
        }
    }

    fn chunk(&mut self, chunk: Chunk, out: &mut Out) {
        let id = chunk.id;
        match self.meta.get(&id) {
            // Not admitted: the scan below ends it with the right reason.
            Some(m) if !self.admitted(m) => {}
            Some(_) => {
                let step = host::append_chunk_step(chunk, &mut self.uploads, (self.now_ms)());
                if step.record.is_some() {
                    // The chunk aborted the upload (a limit, a gap, a write error): that was its end.
                    let m = self.meta.remove(&id).expect("checked above");
                    self.conclude(id, &m.flag, step, out);
                } else {
                    out.frames.extend(step.frames);
                }
            }
            // Nothing this writer is running: just the "unknown transfer" reply.
            None => out.frames.extend(host::append_chunk_step(chunk, &mut self.uploads, (self.now_ms)()).frames),
        }
    }

    fn done(&mut self, id: Uuid, out: &mut Out) {
        let Some(m) = self.meta.get(&id) else {
            // A Done for nothing this writer is running: the engine answers it (no record).
            if let Some(root) = self.root.opened().cloned() {
                out.frames.extend(host::finish_upload_step(id, &mut self.uploads, &root, (self.now_ms)()).frames);
            }
            return;
        };
        if !self.gate.admits(m.stamp) {
            cancel(&m.flag, INDICATOR_LOST);
        }
        // Commit admission: win LIVE -> COMMITTING first. A cancellation that got there first is
        // finished by the scan instead; once won, the commit's REAL result is the outcome.
        if m.flag.state.compare_exchange(LIVE, COMMITTING, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return;
        }
        let m = self.meta.remove(&id).expect("checked above");
        let root = self.root.opened().cloned().expect("an upload in flight has an open root");
        let step = host::finish_upload_step(id, &mut self.uploads, &root, (self.now_ms)());
        self.conclude(id, &m.flag, step, out);
    }

    /// End every upload that was cancelled or whose admission generation died.
    fn scan(&mut self, out: &mut Out) {
        let ids: Vec<Uuid> = self.meta.keys().copied().collect();
        for id in ids {
            let m = &self.meta[&id];
            if !self.gate.admits(m.stamp) {
                cancel(&m.flag, INDICATOR_LOST);
            }
            let code = m.flag.state();
            if code == LIVE || code == COMMITTING {
                continue;
            }
            let m = self.meta.remove(&id).expect("listed above");
            let up = self.uploads.remove(&id);
            if let Some(up) = &up {
                // Disposal by handle needs no admission: it only removes this upload's own temp file.
                let _ = UploadRoot::discard(&up.file);
            }
            let received = up.as_ref().map_or(0, |u| u.received);
            let dest = up.as_ref().map_or_else(String::new, |u| u.dest.clone());
            let step = Step {
                frames: vec![FtMessage::Error { id, message: reason(code).into() }],
                record: Some(PendingRecord::upload_failed(id, dest, received, reason(code).into(), (self.now_ms)())),
            };
            self.conclude(id, &m.flag, step, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_agent::backstage::rbac::{Capability, Grant};
    use rmt_agent_core::file_transfer::sha256_hex;

    fn now() -> i64 {
        1
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rmt-writer-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct Rig {
        w: UploadWriter,
        rx: tokio::sync::mpsc::UnboundedReceiver<Out>,
        gate: Arc<MutationGate>,
        dir: std::path::PathBuf,
        slot: Arc<Mutex<Option<Arc<UploadRoot>>>>,
        ledger: Arc<Ledger>,
    }

    fn rig(tag: &str) -> Rig {
        let dir = tmp(tag);
        let chain = rmt_agent::backstage::audit::new_shared_chain(Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let gate = Arc::new(MutationGate::new());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let slot = Arc::new(Mutex::new(None));
        let ledger = Arc::new(Ledger::default());
        let w = UploadWriter::spawn(chain.clone(), Arc::clone(&ledger), LazyRoot::new(dir.clone(), false), Arc::clone(&slot), Arc::clone(&gate), tx, now);
        let mut d = Dispatcher::with_chain(
            Grant {
                technician_id: Uuid::from_u128(2),
                session_id: Uuid::from_u128(1),
                machine_id: Uuid::from_u128(3),
                capabilities: vec![Capability::FileUpload],
            },
            "agent_host.exe",
            chain,
        );
        d.set_mutation_gate(Arc::clone(&gate));
        w.install(d);
        Rig { w, rx, gate, dir, slot, ledger }
    }

    fn offer(id: Uuid, name: &str, bytes: &[u8]) -> Offer {
        Offer { id, name: name.into(), size: bytes.len() as u64, sha256: sha256_hex(bytes) }
    }

    /// Generous bound for anything the writer thread is waited for: a loaded box (or Defender
    /// scanning a fresh test exe) stretches scheduling by orders of magnitude, and every wait here
    /// returns the moment its condition holds, so only a real hang ever reaches it.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// Wait until the writer has processed the upload's Offer: its `.part` exists on disk.
    fn wait_in_flight(dir: &std::path::Path, id: Uuid) -> std::path::PathBuf {
        let part = dir.join(crate::upload_root::STAGING).join(format!("{id}.part"));
        let deadline = std::time::Instant::now() + PATIENCE;
        while !part.exists() {
            assert!(std::time::Instant::now() < deadline, "premise: the upload never became in flight");
            std::thread::sleep(Duration::from_millis(2));
        }
        part
    }

    /// Collect writer output until `id` is reported finished (or the timeout passes).
    fn until_finished(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Out>, id: Uuid) -> Vec<FtMessage> {
        let deadline = std::time::Instant::now() + PATIENCE;
        let mut frames = Vec::new();
        while std::time::Instant::now() < deadline {
            match rx.try_recv() {
                Ok(out) => {
                    frames.extend(out.frames);
                    if out.finished.contains(&id) {
                        return frames;
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("upload {id} never finished; frames so far: {frames:?}");
    }

    fn acks(frames: &[FtMessage]) -> Vec<(bool, String)> {
        frames
            .iter()
            .filter_map(|f| match f {
                FtMessage::Ack { ok, message, .. } => Some((*ok, message.clone())),
                _ => None,
            })
            .collect()
    }

    fn audit_count(frames: &[FtMessage]) -> usize {
        frames.iter().filter(|f| matches!(f, FtMessage::Audit { .. })).count()
    }

    #[test]
    fn an_upload_commits_through_the_writer_and_publishes_the_root() {
        let mut r = rig("ok");
        let id = Uuid::new_v4();
        let bytes = b"hello writer";
        assert!(matches!(r.w.submit(Item::Offer { offer: offer(id, "a.txt", bytes), stamp: r.gate.stamp(), flag: new_flag() }), Submit::Sent));
        assert!(matches!(r.w.submit(Item::Chunk(Chunk { id, seq: 0, data: bytes.to_vec() })), Submit::Sent));
        assert!(matches!(r.w.submit(Item::Done(id)), Submit::Sent));
        let frames = until_finished(&mut r.rx, id);
        assert_eq!(acks(&frames), vec![(true, "a.txt".to_string())]);
        assert_eq!(audit_count(&frames), 1, "exactly one record");
        assert_eq!(std::fs::read(r.dir.join("a.txt")).unwrap(), bytes);
        let root = r.slot.lock().unwrap().clone().expect("the writer publishes the opened root");
        assert_eq!(root.completed(id).map(|c| c.name), Some("a.txt".into()));
    }

    /// An idle upload (no more frames) whose flag is set is finished by the writer within its wake
    /// period: the `.part` is gone, one failed reply and one record, and the loop is told.
    #[test]
    fn an_idle_cancelled_upload_is_finished_without_any_further_frame() {
        let mut r = rig("idle");
        let id = Uuid::new_v4();
        let flag = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "b.bin", b"0123456789"), stamp: r.gate.stamp(), flag: Arc::clone(&flag) });
        r.w.submit(Item::Chunk(Chunk { id, seq: 0, data: b"01234".to_vec() }));
        let part = wait_in_flight(&r.dir, id);
        assert!(part.exists(), "premise: the upload is in flight");
        let t0 = std::time::Instant::now();
        cancel(&flag, INDICATOR_LOST);
        let frames = until_finished(&mut r.rx, id);
        // The writer's own wake period is WAKE (250 ms): on an idle box this finishes within it.
        // The bound is wall-clock, so it carries load headroom; what it proves is that the writer
        // ended the upload ON ITS OWN SCAN (no frame is ever submitted after the cancel, so a
        // writer that only looked when an item arrived would hang until until_finished's deadline).
        assert!(t0.elapsed() < PATIENCE, "finished in {:?}", t0.elapsed());
        assert!(frames.iter().any(|f| matches!(f, FtMessage::Error { message, .. } if message.contains("indicator"))));
        assert_eq!(audit_count(&frames), 1);
        assert!(!part.exists());
        assert_eq!(flag.state(), ENDED);
    }

    /// Revoking the gate cancels admitted-before uploads even if the indicator returns before the
    /// writer looks (the stamp is dead).
    #[test]
    fn a_revoked_generation_ends_the_upload_even_after_reopening() {
        let mut r = rig("gen");
        let id = Uuid::new_v4();
        let stamp = r.gate.stamp();
        r.w.submit(Item::Offer { offer: offer(id, "c.bin", b"abc"), stamp, flag: new_flag() });
        r.gate.revoke();
        r.gate.reopen();
        r.w.submit(Item::Chunk(Chunk { id, seq: 0, data: b"abc".to_vec() }));
        r.w.submit(Item::Done(id));
        let frames = until_finished(&mut r.rx, id);
        assert!(acks(&frames).iter().all(|(ok, _)| !ok), "nothing commits: {frames:?}");
        assert!(!r.dir.join("c.bin").exists());
    }

    /// Teardown (the loop drops the writer) ends every upload with one record each.
    #[test]
    fn dropping_the_writer_ends_every_upload_once() {
        let mut r = rig("drop");
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            r.w.submit(Item::Offer { offer: offer(*id, &format!("{id}.bin"), b"zz"), stamp: r.gate.stamp(), flag: new_flag() });
        }
        drop(r.w);
        // The writer may report several endings in one batch: collect until every id is finished.
        let mut frames = Vec::new();
        let mut done = std::collections::HashSet::new();
        let deadline = std::time::Instant::now() + PATIENCE;
        while done.len() < ids.len() && std::time::Instant::now() < deadline {
            match r.rx.try_recv() {
                Ok(out) => {
                    frames.extend(out.frames);
                    done.extend(out.finished);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        assert_eq!(done.len(), ids.len(), "every upload must end: {frames:?}");
        assert_eq!(audit_count(&frames), 3, "{frames:?}");
        assert!(std::fs::read_dir(r.dir.join(crate::upload_root::STAGING)).unwrap().next().is_none(), "no .part is left");
    }

    /// Teardown closed the ledger (and recorded the upload) while it was cancelled for a reason OTHER
    /// than the session ending: the writer disposes it and records nothing (Codex phase B review).
    #[test]
    fn a_closed_ledger_takes_any_cancelled_upload_and_the_writer_records_nothing() {
        let mut r = rig("sealed");
        let id = Uuid::new_v4();
        let flag = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "d.bin", b"0123456789"), stamp: r.gate.stamp(), flag: Arc::clone(&flag) });
        let part = wait_in_flight(&r.dir, id);
        assert!(part.exists(), "premise: the upload is in flight");
        assert!(r.ledger.close(|| flag.claim_record()), "teardown records it whatever its state");
        cancel(&flag, INDICATOR_LOST);
        let frames = until_finished(&mut r.rx, id);
        assert_eq!(audit_count(&frames), 0, "teardown already recorded it: {frames:?}");
        assert!(!part.exists(), "the writer still disposes it");
    }

    /// A closed ledger refuses EVERY append, also for an upload teardown did not list (and so never
    /// claimed): nothing reaches the chain after teardown's decision.
    #[test]
    fn a_closed_ledger_appends_nothing_even_for_an_unlisted_upload() {
        let mut r = rig("closed-unlisted");
        let id = Uuid::new_v4();
        let flag = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "i.bin", b"0123456789"), stamp: r.gate.stamp(), flag: Arc::clone(&flag) });
        wait_in_flight(&r.dir, id);
        r.ledger.close(|| ());
        cancel(&flag, SESSION_ENDED);
        let frames = until_finished(&mut r.rx, id);
        assert_eq!(audit_count(&frames), 0, "{frames:?}");
    }

    /// An idle upload whose admission generation died ends on the writer's own scan, with no frame
    /// and no flag set by the loop.
    #[test]
    fn an_idle_upload_ends_when_its_generation_dies_without_a_cancel() {
        let mut r = rig("gen-idle");
        let id = Uuid::new_v4();
        let flag = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "j.bin", b"0123456789"), stamp: r.gate.stamp(), flag: Arc::clone(&flag) });
        wait_in_flight(&r.dir, id);
        r.gate.revoke();
        r.gate.reopen();
        let frames = until_finished(&mut r.rx, id);
        assert!(frames.iter().any(|f| matches!(f, FtMessage::Error { message, .. } if message.contains("indicator"))), "{frames:?}");
        assert_eq!(audit_count(&frames), 1);
    }

    /// A cancelled idle upload is ended BEFORE the writer starts work on the item that woke it.
    #[test]
    fn a_cancelled_upload_ends_before_the_next_item_is_handled() {
        let mut r = rig("scan-first");
        let a = Uuid::new_v4();
        let flag = new_flag();
        r.w.submit(Item::Offer { offer: offer(a, "k.bin", b"0123456789"), stamp: r.gate.stamp(), flag: Arc::clone(&flag) });
        wait_in_flight(&r.dir, a);
        // The writer is now waiting; the Offer below wakes it at once, with A already cancelled.
        let b = Uuid::new_v4();
        cancel(&flag, OVERFLOW);
        r.w.submit(Item::Offer { offer: offer(b, crate::upload_root::STAGING, b"x"), stamp: r.gate.stamp(), flag: new_flag() });
        let mut frames = Vec::new();
        let mut done = std::collections::HashSet::new();
        let deadline = std::time::Instant::now() + PATIENCE;
        while done.len() < 2 && std::time::Instant::now() < deadline {
            match r.rx.try_recv() {
                Ok(out) => {
                    frames.extend(out.frames);
                    done.extend(out.finished);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        let pos = |id: Uuid| frames.iter().position(|f| matches!(f, FtMessage::Error { id: i, .. } if *i == id)).expect("an error each");
        assert!(pos(a) < pos(b), "A must end before B is handled: {frames:?}");
    }

    /// A chunk that fails after teardown closed the ledger (a stalled write returning late) appends
    /// nothing: its outcome is decided before, and recorded only through, the ledger.
    #[test]
    fn a_chunk_failure_after_the_ledger_closed_appends_nothing() {
        let mut r = rig("late-chunk");
        let id = Uuid::new_v4();
        let flag = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "e.bin", b"0123456789"), stamp: r.gate.stamp(), flag: Arc::clone(&flag) });
        wait_in_flight(&r.dir, id);
        assert!(r.ledger.close(|| flag.claim_record()));
        // Out of order: the chunk aborts the upload.
        r.w.submit(Item::Chunk(Chunk { id, seq: 7, data: b"01".to_vec() }));
        let frames = until_finished(&mut r.rx, id);
        assert!(frames.iter().any(|f| matches!(f, FtMessage::Error { message, .. } if message.contains("out-of-order"))), "{frames:?}");
        assert_eq!(audit_count(&frames), 0, "{frames:?}");
        assert!(!r.dir.join(crate::upload_root::STAGING).join(format!("{id}.part")).exists());
    }

    /// Without teardown, the same abort is recorded exactly once (the negative control).
    #[test]
    fn a_chunk_failure_is_recorded_once_while_the_session_lives() {
        let mut r = rig("chunk");
        let id = Uuid::new_v4();
        r.w.submit(Item::Offer { offer: offer(id, "f.bin", b"0123456789"), stamp: r.gate.stamp(), flag: new_flag() });
        r.w.submit(Item::Chunk(Chunk { id, seq: 7, data: b"01".to_vec() }));
        let frames = until_finished(&mut r.rx, id);
        assert_eq!(audit_count(&frames), 1, "{frames:?}");
    }

    /// A repeated Offer id never disturbs the running upload: it is refused on its own flag, and the
    /// original still commits with its own single record.
    #[test]
    fn a_repeated_offer_id_leaves_the_running_upload_alone() {
        let mut r = rig("dup");
        let id = Uuid::new_v4();
        let bytes = b"original";
        let first = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "g.txt", bytes), stamp: r.gate.stamp(), flag: Arc::clone(&first) });
        let second = new_flag();
        r.w.submit(Item::Offer { offer: offer(id, "h.txt", b"other"), stamp: r.gate.stamp(), flag: Arc::clone(&second) });
        r.w.submit(Item::Chunk(Chunk { id, seq: 0, data: bytes.to_vec() }));
        r.w.submit(Item::Done(id));
        let frames = until_finished(&mut r.rx, id);
        assert!(frames.iter().any(|f| matches!(f, FtMessage::Error { message, .. } if message.contains("repeats an active id"))), "{frames:?}");
        assert_eq!(acks(&frames), vec![(true, "g.txt".to_string())], "{frames:?}");
        assert_eq!(audit_count(&frames), 2, "one for the refused repeat, one for the commit: {frames:?}");
        assert_eq!(std::fs::read(r.dir.join("g.txt")).unwrap(), bytes);
        assert!(!r.dir.join("h.txt").exists());
        assert_eq!(first.state(), ENDED);
    }

    /// A commit admitted before a cancellation stands: the cancel is a no-op on a committing upload.
    #[test]
    fn a_cancel_never_applies_to_a_committing_upload() {
        let flag = new_flag();
        assert!(flag.state.compare_exchange(LIVE, COMMITTING, Ordering::SeqCst, Ordering::SeqCst).is_ok());
        cancel(&flag, INDICATOR_LOST);
        assert_eq!(flag.state(), COMMITTING);
    }

    /// Installing a grant never waits on the writer, even with its queue full and nobody draining it.
    #[test]
    fn install_never_blocks_on_a_full_queue() {
        let (tx, rx) = mpsc::sync_channel::<Item>(QUEUE);
        let w = UploadWriter { tx, install: Arc::new(Mutex::new(None)) };
        let id = Uuid::new_v4();
        while let Submit::Sent = w.submit(Item::Chunk(Chunk { id, seq: 0, data: vec![0] })) {}
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let chain = rmt_agent::backstage::audit::new_shared_chain(Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let d = Dispatcher::with_chain(
            Grant { technician_id: Uuid::from_u128(2), session_id: Uuid::from_u128(1), machine_id: Uuid::from_u128(3), capabilities: vec![] },
            "agent_host.exe",
            chain,
        );
        std::thread::spawn(move || {
            w.install(d);
            let _ = done_tx.send(w);
        });
        let w = done_rx.recv_timeout(PATIENCE).expect("install must return while the queue is full");
        assert!(w.install.lock().unwrap().is_some());
        drop(rx);
    }

    /// The queue is bounded and `submit` never blocks: a stalled writer fills it and `Full` comes back.
    #[test]
    fn a_full_queue_reports_full_instead_of_blocking() {
        let (tx, rx) = mpsc::sync_channel::<Item>(QUEUE);
        let w = UploadWriter { tx, install: Arc::new(Mutex::new(None)) };
        let id = Uuid::new_v4();
        let mut full = false;
        for seq in 0..(QUEUE as u32 + 5) {
            match w.submit(Item::Chunk(Chunk { id, seq, data: vec![0] })) {
                Submit::Full => {
                    full = true;
                    break;
                }
                Submit::Sent => {}
                Submit::Closed => panic!("closed"),
            }
        }
        assert!(full, "a bounded queue must report Full");
        drop(rx);
    }
}
