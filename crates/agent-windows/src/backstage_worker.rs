//! The Backstage worker (docs/58 §1, §12): one thread that executes this session's Backstage
//! requests serially, so a request that stalls in a system call (a walk, a rename or a delete on a
//! slow or failing disk) never stalls the session loop, which must keep processing indicator loss
//! and teardown.
//!
//! It owns its OWN dispatcher, a twin of the loop's (same grant, same shared audit chain, same
//! mutation gate; see `Dispatcher::twin`), so the loop never waits on a lock the worker could hold
//! across a system call. Requests arrive stamped with the gate generation current when the loop
//! queued them, so work queued before the indicator was lost is refused even if it is visible
//! again by the time the worker reaches it. Replies go back in arrival order, which the console's
//! in-order correlation depends on: one serial worker, one FIFO channel, one reply per request.
//!
//! At teardown the loop revokes the gate first, then drops its sender. The worker finishes (or is
//! still inside) the request in hand, answers every queued request with a refusal (dead stamp), and
//! exits when the channel is empty and closed. Nothing waits for it: an admitted system call may
//! outlive the session, and its outcome is still sealed into the chain the worker holds.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use rmt_agent::backstage::{Confirmation, Dispatcher};
use rmt_agent::transport::backstage_api;

/// Requests (and their bytes) that may wait for the worker at once. Past either, a request is not
/// kept (Codex 1.3.18 release review: a stalled system call must not let a peer queue unbounded
/// work). Consecutive overflowing requests COALESCE into one payload-free [`WorkerMsg::Busy`] run
/// in the FIFO, so their refusals still come back in order and the queue holds at most
/// `QUEUE_REQUESTS + 1` entries. A run answers at most [`MAX_BUSY_RUN`] requests. One more is
/// TERMINAL for the session's Backstage channel (Codex release review r3): from that request on,
/// nothing executes and nothing replies, so no later reply can be matched to a dropped request.
/// The console, waiting for replies in order, times out and closes its channel.
pub(crate) const QUEUE_REQUESTS: usize = 256;
pub(crate) const QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_BUSY_RUN: usize = 1024;
pub(crate) const BUSY: &str = "the agent is still working on earlier requests; try again shortly";

pub(crate) enum WorkerMsg {
    /// A grant was installed: from now on requests run against this dispatcher.
    Install(Dispatcher),
    /// One Backstage request frame, stamped at admission.
    Request { json: String, stamp: u64, observer: bool },
    /// A run of requests that did not fit the queue: each answered with a refusal, in its turn.
    Busy,
    /// Overflow past the cap: everything from here on is dropped unanswered, and the worker exits.
    Poison,
}

#[derive(Default)]
struct Load {
    requests: AtomicUsize,
    bytes: AtomicUsize,
    runs: Mutex<Runs>,
    /// Set (once, by the loop) when overflow passed the cap: nothing more is queued.
    poisoned: AtomicBool,
}

/// The sizes of the Busy runs in the FIFO, oldest first, and whether the newest can still grow
/// (no request was queued after it, and the worker has not taken it).
#[derive(Default)]
struct Runs {
    counts: VecDeque<usize>,
    open: bool,
}

pub(crate) struct BackstageWorker {
    tx: mpsc::Sender<WorkerMsg>,
    load: Arc<Load>,
}

impl BackstageWorker {
    /// Start the worker. Every request is answered on `replies` with exactly one envelope JSON.
    pub(crate) fn spawn(replies: tokio::sync::mpsc::UnboundedSender<String>, now_ms: fn() -> i64) -> Self {
        let (tx, rx) = mpsc::channel::<WorkerMsg>();
        let load = Arc::new(Load::default());
        let worker_load = Arc::clone(&load);
        std::thread::Builder::new()
            .name("backstage-worker".into())
            .spawn(move || run(rx, replies, now_ms, worker_load))
            .expect("spawn backstage worker");
        Self { tx, load }
    }

    /// Hand the worker the dispatcher for a newly installed grant. Never blocks.
    pub(crate) fn install(&self, dispatcher: Dispatcher) {
        let _ = self.tx.send(WorkerMsg::Install(dispatcher));
    }

    /// Queue one request. Never blocks. `false` if the worker is gone (the caller answers itself).
    /// Past [`QUEUE_REQUESTS`] or [`QUEUE_BYTES`] the payload is dropped and a [`WorkerMsg::Busy`]
    /// is queued instead.
    pub(crate) fn submit(&self, json: String, stamp: u64, observer: bool) -> bool {
        if self.load.poisoned.load(Ordering::SeqCst) {
            return true; // dropped unanswered: see the module note on MAX_BUSY_RUN
        }
        let len = json.len();
        let fits = self.load.requests.load(Ordering::SeqCst) < QUEUE_REQUESTS
            && self.load.bytes.load(Ordering::SeqCst) + len <= QUEUE_BYTES;
        let mut runs = self.load.runs.lock().unwrap_or_else(|p| p.into_inner());
        if !fits {
            if runs.open {
                let last = runs.counts.back_mut().expect("an open run is queued");
                if *last < MAX_BUSY_RUN {
                    *last += 1;
                    return true;
                }
                tracing::warn!("backstage: request overflow past the cap; the Backstage channel stops answering for this session");
                self.load.poisoned.store(true, Ordering::SeqCst);
                let _ = self.tx.send(WorkerMsg::Poison);
                return true; // dropped unanswered
            }
            runs.counts.push_back(1);
            runs.open = true;
            return self.tx.send(WorkerMsg::Busy).is_ok();
        }
        // A request queued after a run closes it: later overflows start a new run behind it.
        runs.open = false;
        drop(runs);
        self.load.requests.fetch_add(1, Ordering::SeqCst);
        self.load.bytes.fetch_add(len, Ordering::SeqCst);
        self.tx.send(WorkerMsg::Request { json, stamp, observer }).is_ok()
    }
}

fn run(
    rx: mpsc::Receiver<WorkerMsg>,
    replies: tokio::sync::mpsc::UnboundedSender<String>,
    now_ms: fn() -> i64,
    load: Arc<Load>,
) {
    let mut dispatcher: Option<Dispatcher> = None;
    while let Ok(msg) = rx.recv() {
        match msg {
            WorkerMsg::Install(d) => dispatcher = Some(d),
            // Everything before this point was answered; nothing after it ever is.
            WorkerMsg::Poison => return,
            WorkerMsg::Busy => {
                let n = {
                    let mut runs = load.runs.lock().unwrap_or_else(|p| p.into_inner());
                    let n = runs.counts.pop_front().unwrap_or(0);
                    if runs.counts.is_empty() {
                        runs.open = false; // the run just taken can no longer grow
                    }
                    n
                };
                for _ in 0..n {
                    if replies.send(backstage_api::refused_json(BUSY)).is_err() {
                        break;
                    }
                }
            }
            WorkerMsg::Request { json, stamp, observer } => {
                load.requests.fetch_sub(1, Ordering::SeqCst);
                load.bytes.fetch_sub(json.len(), Ordering::SeqCst);
                let reply = match dispatcher.as_mut() {
                    Some(d) => backstage_api::dispatch_json_stamped(
                        d,
                        &json,
                        Confirmation::NotProvided,
                        now_ms(),
                        observer,
                        Some(stamp),
                    )
                    // Only an envelope that cannot be encoded lands here; answer anyway, so the
                    // console's in-order correlation never loses a reply.
                    .unwrap_or_else(|_| backstage_api::denied_no_grant_json()),
                    None => backstage_api::denied_no_grant_json(),
                };
                if replies.send(reply).is_err() {
                    // The session is gone; keep draining so queued requests are refused rather than
                    // executed later, then exit when the loop's sender is dropped.
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_agent::backstage::rbac::{Capability, Grant};
    use std::sync::Arc;

    fn now() -> i64 {
        1
    }

    fn dispatcher(caps: Vec<Capability>) -> Dispatcher {
        Dispatcher::new(
            Grant {
                technician_id: uuid::Uuid::from_u128(1),
                session_id: uuid::Uuid::from_u128(2),
                machine_id: uuid::Uuid::from_u128(3),
                capabilities: caps,
            },
            "agent_host.exe",
        )
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn replies_come_back_in_order_one_per_request() {
        rt().block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let w = BackstageWorker::spawn(tx, now);
            // Before a grant: a denial, still one reply.
            assert!(w.submit(r#"{"type":"GetSystemInfo"}"#.into(), 0, false));
            w.install(dispatcher(vec![Capability::SystemInfoRead]));
            assert!(w.submit(r#"{"type":"GetSystemInfo"}"#.into(), 0, false));
            assert!(w.submit("not json".into(), 0, false));
            let a: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
            let b: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
            let c: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
            assert_eq!(a["error"]["kind"], "denied");
            assert_eq!(b["ok"], true);
            assert_eq!(c["error"]["kind"], "refused");
        });
    }

    #[test]
    fn a_request_queued_before_revocation_is_refused_after_it() {
        rt().block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let w = BackstageWorker::spawn(tx, now);
            let gate = Arc::new(rmt_agent::backstage::gate::MutationGate::new());
            let mut d = dispatcher(vec![Capability::ServiceControl]);
            d.set_mutation_gate(Arc::clone(&gate));
            w.install(d);
            let stamp = gate.stamp();
            gate.revoke();
            gate.reopen(); // the indicator came back: the OLD stamp must stay dead
            assert!(w.submit(r#"{"type":"ControlService","data":{"service":"rmt-no-such-service-58","verb":"start"}}"#.into(), stamp, false));
            let r: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
            assert_eq!(r["error"]["kind"], "refused", "{r}");
        });
    }

    /// A stalled worker holds at most QUEUE_REQUESTS payloads; the rest are refused as busy, IN
    /// ORDER, and the queue admits again once the worker drains.
    #[test]
    fn a_stalled_worker_bounds_its_queue_and_refuses_in_order() {
        rt().block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            // A worker that never runs: hold its receiver by building the parts by hand.
            let (wtx, wrx) = mpsc::channel::<WorkerMsg>();
            let w = BackstageWorker { tx: wtx, load: Arc::new(Load::default()) };
            for _ in 0..QUEUE_REQUESTS + 3 {
                assert!(w.submit(r#"{"type":"ListProcesses"}"#.into(), 0, false));
            }
            assert_eq!(w.load.requests.load(Ordering::SeqCst), QUEUE_REQUESTS, "only the bound is kept");
            {
                let runs = w.load.runs.lock().unwrap();
                assert_eq!(runs.counts, [3], "the three overflows coalesce into ONE queued entry");
            }
            // Big payloads hit the byte bound first.
            let w2 = BackstageWorker { tx: mpsc::channel().0, load: Arc::new(Load::default()) };
            let big = "x".repeat(QUEUE_BYTES / 2 + 1);
            w2.submit(big.clone(), 0, false);
            w2.submit(big, 0, false);
            assert_eq!(w2.load.requests.load(Ordering::SeqCst), 1, "the byte bound refuses the second");
            // Now let the worker run: replies come back one per submit, the overflow ones as busy, last.
            let load = Arc::clone(&w.load);
            // No grant installed: each queued request is answered quickly (denied), which is all the
            // ordering needs.
            std::thread::spawn(move || run(wrx, tx, now, load));
            let mut kinds = Vec::new();
            for _ in 0..QUEUE_REQUESTS + 3 {
                let r: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
                kinds.push(r["error"]["message"].as_str().unwrap_or("").to_string());
            }
            assert!(kinds[..QUEUE_REQUESTS].iter().all(|m| m != BUSY));
            assert!(kinds[QUEUE_REQUESTS..].iter().all(|m| m == BUSY), "{:?}", &kinds[QUEUE_REQUESTS..]);
            assert_eq!(w.load.requests.load(Ordering::SeqCst), 0, "drained");
            assert!(w.submit(r#"{"type":"ListProcesses"}"#.into(), 0, false));
            let r: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
            assert_ne!(r["error"]["message"], BUSY, "admits again once drained");
        });
    }

    /// Sustained overflow is bounded: one queued entry per run, at most MAX_BUSY_RUN refusals each,
    /// and nothing more (the console times out and closes its channel).
    #[test]
    fn sustained_overflow_is_bounded() {
        rt().block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let (wtx, wrx) = mpsc::channel::<WorkerMsg>();
            let w = BackstageWorker { tx: wtx, load: Arc::new(Load::default()) };
            for _ in 0..QUEUE_REQUESTS + MAX_BUSY_RUN * 3 {
                w.submit(r#"{"type":"ListProcesses"}"#.into(), 0, false);
            }
            assert_eq!(w.load.runs.lock().unwrap().counts, [MAX_BUSY_RUN], "one run, capped");
            assert!(w.load.poisoned.load(Ordering::SeqCst), "past the cap is terminal");
            // A request that would FIT now is still dropped: no later reply can be mis-matched.
            w.load.requests.store(0, Ordering::SeqCst);
            assert!(w.submit(r#"{"type":"ListProcesses"}"#.into(), 0, false));
            let load = Arc::clone(&w.load);
            std::thread::spawn(move || run(wrx, tx, now, load));
            for _ in 0..QUEUE_REQUESTS + MAX_BUSY_RUN {
                rx.recv().await.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert!(rx.try_recv().is_err(), "nothing past the cap is answered, not even a later request");
            drop(w);
        });
    }

    /// The loop never waits on the worker: a submit while the worker is busy returns at once.
    #[test]
    fn submit_never_blocks_on_a_busy_worker() {
        rt().block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let w = BackstageWorker::spawn(tx, now);
            w.install(dispatcher(vec![Capability::ProcessList]));
            let t0 = std::time::Instant::now();
            for _ in 0..50 {
                assert!(w.submit(r#"{"type":"ListProcesses"}"#.into(), 0, false));
            }
            assert!(t0.elapsed() < std::time::Duration::from_millis(200), "submit blocked: {:?}", t0.elapsed());
            for _ in 0..50 {
                rx.recv().await.unwrap();
            }
        });
    }
}
