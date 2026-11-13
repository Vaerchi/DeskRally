//! Tests for the recording uploader against a scripted in-memory server that enforces the wire
//! contract's rules (chunk geometry, offsets, digest verification at finish), so the uploader is
//! exercised against refusals it must handle, not against a mirror of itself. The real HTTP wire and
//! the real Go handler are covered by `tests/recording_upload_wire.rs`.

use super::*;
use crate::recording::{Segment, Sidecar};
use crate::recording_fs::StdFs;
use std::collections::VecDeque;
use std::sync::Mutex;

const MIB: usize = 1 << 20;

// ---- fakes -------------------------------------------------------------------------------------

struct FakeClock {
    now: Mutex<i64>,
    slept: Mutex<Vec<Duration>>,
}
impl FakeClock {
    fn new(now: i64) -> Arc<Self> {
        Arc::new(Self { now: Mutex::new(now), slept: Mutex::new(Vec::new()) })
    }
    fn advance(&self, ms: i64) {
        *self.now.lock().unwrap() += ms;
    }
    fn total_slept(&self) -> Duration {
        self.slept.lock().unwrap().iter().sum()
    }
}
impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        *self.now.lock().unwrap()
    }
    fn sleep(&self, d: Duration) {
        self.slept.lock().unwrap().push(d);
        self.advance(d.as_millis() as i64);
    }
}

struct FnProbe(Box<dyn Fn() -> bool + Send + Sync>);
impl SessionProbe for FnProbe {
    fn session_live(&self) -> bool {
        (self.0)()
    }
}

#[derive(Default)]
struct Inner {
    // Server-side recording, by id.
    recs: std::collections::HashMap<String, Rec>,
    // Failures to return instead of executing the next matching call.
    inject: VecDeque<(Op, ApiFail)>,
    // Corrupt the next stored chunk (flip a byte) to force a digest mismatch at finish.
    corrupt_next_put: bool,
    storage_off: bool,
    // Answer every PUT "ok, re-sent" at the offset the agent already held: a success that makes no progress.
    stuck_put: bool,
    // Never answer "refused" at the third digest failure: the AGENT's own counter must stop it.
    never_refuse: bool,
    calls: Vec<String>,
    // The finish acknowledgement is altered by this closure (ack-binding tests).
    ack_tweak: Option<fn(&mut FinishOk)>,
    // Every call advances the clock by this much (drain-budget tests).
    call_cost_ms: i64,
    clock: Option<Arc<FakeClock>>,
}
struct Rec {
    generation: u64,
    lens: Vec<u64>,
    data: Vec<Vec<u8>>,
    complete: bool,
    digests: Vec<String>,
    finish_failures: u32,
}

#[derive(Default)]
struct FakeServer {
    inner: Mutex<Inner>,
}

impl FakeServer {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().calls.clone()
    }
    fn count(&self, prefix: &str) -> usize {
        self.calls().iter().filter(|c| c.starts_with(prefix)).count()
    }
    fn inject(&self, op: Op, f: ApiFail) {
        self.inner.lock().unwrap().inject.push_back((op, f));
    }
    fn inject_n(&self, op: Op, f: ApiFail, n: usize) {
        for _ in 0..n {
            self.inject(op, f.clone());
        }
    }
    fn committed(&self, id: &str, seg: usize) -> usize {
        self.inner.lock().unwrap().recs[id].data[seg].len()
    }
    fn received(&self, id: &str, seg: usize) -> Vec<u8> {
        self.inner.lock().unwrap().recs[id].data[seg].clone()
    }
    fn begin(&self, op: Op, what: String) -> Option<ApiFail> {
        let mut g = self.inner.lock().unwrap();
        g.calls.push(what);
        if g.call_cost_ms > 0 {
            if let Some(c) = &g.clock {
                c.advance(g.call_cost_ms);
            }
        }
        if g.inject.front().is_some_and(|(o, _)| *o == op) {
            return g.inject.pop_front().map(|(_, f)| f);
        }
        None
    }
}

/// The uploader owns its API by value; this lets a test keep a handle on the server too.
struct Api(Arc<FakeServer>);

impl UploadApi for Api {
    fn create(&self, r: RecRef<'_>, _session: &str, lengths: &[u64]) -> Result<CreateOk, ApiFail> {
        if let Some(f) = self.0.begin(Op::Create, format!("create {}", r.recording_id)) {
            return Err(f);
        }
        let mut g = self.0.inner.lock().unwrap();
        if g.storage_off {
            return Err(ApiFail::http(403, "storage_off"));
        }
        let rec = g.recs.entry(r.recording_id.to_string()).or_insert_with(|| Rec {
            generation: r.generation,
            lens: lengths.to_vec(),
            data: lengths.iter().map(|_| Vec::new()).collect(),
            complete: false,
            digests: Vec::new(),
            finish_failures: 0,
        });
        if rec.lens != lengths || rec.generation != r.generation {
            return Err(ApiFail::http(409, "conflict"));
        }
        if rec.complete {
            return Err(ApiFail::http(409, "already_complete"));
        }
        Ok(CreateOk {
            state: "uploading".into(),
            generation: rec.generation,
            chunk_size: CHUNK_SIZE,
            segments: rec.lens.iter().enumerate().map(|(i, l)| (i as u32, *l, rec.data[i].len() as u64)).collect(),
        })
    }

    fn head(&self, r: RecRef<'_>, segment: u32) -> Result<HeadOk, ApiFail> {
        if let Some(f) = self.0.begin(Op::Head, format!("head {} {segment}", r.recording_id)) {
            return Err(f);
        }
        let g = self.0.inner.lock().unwrap();
        let Some(rec) = g.recs.get(r.recording_id) else { return Err(ApiFail::http(404, "not_found")) };
        Ok(HeadOk {
            committed: rec.data[segment as usize].len() as u64,
            length: rec.lens[segment as usize],
            state: if rec.complete { "evidence_complete".into() } else { "uploading".into() },
        })
    }

    fn put(&self, r: RecRef<'_>, segment: u32, offset: u64, chunk: &[u8]) -> Result<PutOk, ApiFail> {
        if let Some(f) = self.0.begin(Op::Put, format!("put {} {segment} {offset} {}", r.recording_id, chunk.len())) {
            return Err(f);
        }
        if self.0.inner.lock().unwrap().stuck_put {
            return Ok(PutOk { committed: offset, resent: true });
        }
        let mut g = self.0.inner.lock().unwrap();
        let corrupt = std::mem::take(&mut g.corrupt_next_put);
        let Some(rec) = g.recs.get_mut(r.recording_id) else { return Err(ApiFail::http(404, "not_found")) };
        let len = rec.lens[segment as usize];
        let have = rec.data[segment as usize].len() as u64;
        // Geometry: offset on a chunk boundary, exact chunk length (the last one the remainder).
        let want = (len.saturating_sub(offset)).min(CHUNK_SIZE);
        if offset >= len || !offset.is_multiple_of(CHUNK_SIZE) {
            let mut f = ApiFail::http(409, "bad_offset");
            f.committed_offset = Some(have);
            return Err(f);
        }
        if chunk.len() as u64 != want {
            return Err(ApiFail::http(400, "bad_chunk_length"));
        }
        if offset < have {
            // An exact re-send is a no-op; different bytes are a conflict.
            let same = rec.data[segment as usize][offset as usize..(offset as usize + chunk.len()).min(have as usize)]
                == chunk[..chunk.len().min((have - offset) as usize)];
            return if same {
                Ok(PutOk { committed: have, resent: true })
            } else {
                Err(ApiFail::http(409, "chunk_conflict"))
            };
        }
        if offset > have {
            let mut f = ApiFail::http(409, "bad_offset");
            f.committed_offset = Some(have);
            return Err(f);
        }
        let mut c = chunk.to_vec();
        if corrupt {
            c[0] ^= 0xff;
        }
        rec.data[segment as usize].extend_from_slice(&c);
        Ok(PutOk { committed: rec.data[segment as usize].len() as u64, resent: false })
    }

    fn finish(&self, r: RecRef<'_>, req: &FinishReq) -> Result<FinishOk, ApiFail> {
        if let Some(f) = self.0.begin(Op::Finish, format!("finish {}", r.recording_id)) {
            return Err(f);
        }
        let mut g = self.0.inner.lock().unwrap();
        let tweak = g.ack_tweak;
        let never = g.never_refuse;
        let Some(rec) = g.recs.get_mut(r.recording_id) else { return Err(ApiFail::http(404, "not_found")) };
        if rec.complete {
            return if rec.digests == req.digests {
                let mut ok = FinishOk {
                    recording_id: r.recording_id.into(),
                    generation: rec.generation,
                    state: "evidence_complete".into(),
                    digests: rec.digests.clone(),
                };
                if let Some(t) = tweak {
                    t(&mut ok);
                }
                Ok(ok)
            } else {
                Err(ApiFail::http(409, "conflict"))
            };
        }
        let owed: Vec<u32> = (0..rec.lens.len()).filter(|i| rec.data[*i].len() as u64 != rec.lens[*i]).map(|i| i as u32).collect();
        if !owed.is_empty() {
            let mut f = ApiFail::http(409, "incomplete");
            f.segments = owed;
            return Err(f);
        }
        let bad: Vec<u32> = (0..rec.lens.len())
            .filter(|i| rmt_agent_core::file_transfer::sha256_hex(&rec.data[*i]) != req.digests[*i])
            .map(|i| i as u32)
            .collect();
        if !bad.is_empty() {
            rec.finish_failures += 1;
            for i in &bad {
                rec.data[*i as usize].clear();
            }
            let mut f = ApiFail::http(422, "digest_mismatch");
            f.segments = bad;
            f.state = Some(if rec.finish_failures >= 3 && !never { "refused".into() } else { "uploading".into() });
            return Err(f);
        }
        rec.complete = true;
        rec.digests = req.digests.clone();
        let mut ok = FinishOk {
            recording_id: r.recording_id.into(),
            generation: rec.generation,
            state: "evidence_complete".into(),
            digests: rec.digests.clone(),
        };
        if let Some(t) = tweak {
            t(&mut ok);
        }
        Ok(ok)
    }
}

// ---- fixture -----------------------------------------------------------------------------------

const TENANT: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const DEVICE: &str = "dev-0001";
const SESSION: &str = "11111111-2222-4333-8444-555555555555";

fn ident() -> UploadIdentity {
    UploadIdentity {
        tenant_id: TENANT.into(),
        device_id: DEVICE.into(),
        key_fp_hex: "ab".repeat(32),
        audience: "https://cp.example.test".into(),
    }
}

struct Fx {
    _tmp: tempfile_dir::Dir,
    rec_dir: PathBuf,
    state_dir: PathBuf,
    clock: Arc<FakeClock>,
    server: Arc<FakeServer>,
}

/// A tiny temp dir that removes itself (no tempfile crate in this workspace).
mod tempfile_dir {
    use std::path::{Path, PathBuf};
    pub struct Dir(PathBuf);
    impl Dir {
        pub fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("rmt-upload-test-{tag}-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

const T0: i64 = 1_790_000_000_000;

impl Fx {
    fn new(tag: &str) -> Self {
        let tmp = tempfile_dir::Dir::new(tag);
        let rec_dir = tmp.path().join("recordings");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&rec_dir).unwrap();
        Self { _tmp: tmp, rec_dir, state_dir, clock: FakeClock::new(T0), server: FakeServer::new() }
    }
    fn cfg(&self) -> UploaderConfig {
        UploaderConfig {
            state_dir: self.state_dir.clone(),
            roots: vec![ScanRoot::Flat(self.rec_dir.clone())],
            rate_bytes_per_sec: DEFAULT_RATE_BYTES_PER_SEC,
            max_pending_bytes: MAX_PENDING_BYTES,
            max_pending_age_ms: MAX_PENDING_AGE_MS,
            max_failures: MAX_CONSECUTIVE_FAILURES,
        }
    }
    fn uploader(&self) -> Uploader<Api> {
        self.uploader_with(self.cfg(), ident(), Arc::new(NeverLive))
    }
    fn uploader_with(&self, cfg: UploaderConfig, id: UploadIdentity, probe: Arc<dyn SessionProbe>) -> Uploader<Api> {
        Uploader::new(cfg, Api(self.server.clone()), id, probe, self.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs))
    }
    /// Write a finished recording `rec-<ms>` with these segment sizes; returns its stem.
    fn recording(&self, ms: i64, sizes: &[usize]) -> String {
        self.recording_in(&self.rec_dir, ms, sizes, Some(SESSION), DEVICE, None)
    }
    fn recording_in(&self, dir: &Path, ms: i64, sizes: &[usize], session: Option<&str>, device: &str, truncated: Option<&str>) -> String {
        let stem = format!("rec-{ms}");
        let mut segments = Vec::new();
        for (i, n) in sizes.iter().enumerate() {
            let data: Vec<u8> = (0..*n).map(|b| ((b * 31 + i * 7 + ms as usize) % 251) as u8).collect();
            let file = format!("{stem}-{i:04}.ivf");
            std::fs::write(dir.join(&file), &data).unwrap();
            segments.push(Segment {
                file,
                width: 640,
                height: 480,
                frames: 10 + i as u64,
                payload_bytes: *n as u64 / 2,
                sha256: rmt_agent_core::file_transfer::sha256_hex(&data),
            });
        }
        let side = Sidecar {
            kind: SIDECAR_KIND.into(),
            device_id: device.into(),
            session_id: session.map(str::to_string),
            started_at_unix_ms: ms,
            ended_at_unix_ms: self.clock.now_ms() - 1000,
            delete_after_unix_ms: self.clock.now_ms() + 72 * 3_600_000,
            segments,
            truncated: truncated.map(str::to_string),
            dropped_frames: 3,
            disclaimer: "test".into(),
        };
        std::fs::write(dir.join(format!("{stem}.json")), serde_json::to_vec_pretty(&side).unwrap()).unwrap();
        stem
    }
    fn ops(&self) -> QueueOps {
        QueueOps::new(self.store(), self.clock.clone())
    }
    fn store(&self) -> StateStore {
        StateStore::new(Arc::new(StdFs), self.state_dir.clone(), self.cfg().roots)
    }
    fn lifecycle(&self) -> Lifecycle {
        Lifecycle::new(self.store())
    }
    fn files_left(&self) -> usize {
        std::fs::read_dir(&self.rec_dir).unwrap().count()
    }
    fn states(&self) -> Vec<UploadState> {
        self.store().list()
    }
    fn only_state(&self) -> UploadState {
        let mut s = self.states();
        assert_eq!(s.len(), 1, "exactly one queue entry: {s:?}");
        s.remove(0)
    }
}

fn http(status: u16, code: &str) -> ApiFail {
    ApiFail::http(status, code)
}

// ---- happy path --------------------------------------------------------------------------------

#[test]
fn a_finished_recording_uploads_in_one_mib_chunks_and_the_local_copy_goes_only_after_the_binding_ack() {
    let fx = Fx::new("happy");
    fx.recording(1000, &[2 * MIB + 500, 700]);
    let mut up = fx.uploader();
    let rep = up.tick();
    assert_eq!((rep.queued, rep.completed), (1, 1), "{rep:?}");
    let st = fx.only_state();
    assert_eq!(st.status, Status::Complete);
    assert!(st.local_cleaned);
    assert_eq!(fx.files_left(), 0, "segments and sidecar are deleted after the confirmed upload");
    // Wire sequence: create, three chunks of segment 0 (1 MiB, 1 MiB, 500), one of segment 1, finish.
    let puts: Vec<String> = fx.server.calls().into_iter().filter(|c| c.starts_with("put")).collect();
    let tail: Vec<String> = puts.iter().map(|p| p.split(' ').skip(2).collect::<Vec<_>>().join(" ")).collect();
    assert_eq!(tail, ["0 0 1048576", format!("0 1048576 {MIB}").as_str(), "0 2097152 500", "1 0 700"]);
    assert_eq!(fx.server.count("create"), 1);
    assert_eq!(fx.server.count("finish"), 1);
    // The bytes on the server are the bytes that were on disk.
    let id = &st.recording_id;
    assert_eq!(fx.server.committed(id, 0), 2 * MIB + 500);
    assert_eq!(rmt_agent_core::file_transfer::sha256_hex(&fx.server.received(id, 1)), st.segments[1].sha256);
    // And a second pass does nothing at all.
    let before = fx.server.calls().len();
    assert_eq!(up.tick(), TickReport::default());
    assert_eq!(fx.server.calls().len(), before);
}

#[test]
fn the_rate_cap_paces_every_chunk() {
    let fx = Fx::new("pace");
    fx.recording(1000, &[2 * MIB]);
    let mut up = fx.uploader();
    let wall = std::time::Instant::now();
    up.tick();
    let wall = wall.elapsed();
    // 2 MiB at 250 000 B/s = 8.39 s of pacing, in two sleeps. pace() deducts the REAL time each chunk already
    // took (Instant, not the fake clock), so the sleeps fall short of the budget by at most the tick's own wall
    // time. A fixed 200 ms tolerance failed the full gate on a loaded machine (2026-11-05).
    let expected = Duration::from_micros(2 * (MIB as u64) * 1_000_000 / DEFAULT_RATE_BYTES_PER_SEC);
    let slept = fx.clock.total_slept();
    assert!(slept <= expected && slept + wall >= expected, "slept {slept:?} + wall {wall:?} vs expected {expected:?}");}

#[test]
fn the_finish_carries_the_attested_metadata_the_stop_event_carries() {
    let fx = Fx::new("finishmeta");
    fx.recording_in(&fx.rec_dir, 1000, &[100, 200], Some(SESSION), DEVICE, Some("size_limit"));
    let seen: Arc<Mutex<Option<FinishReq>>> = Arc::default();
    struct Spy(Api, Arc<Mutex<Option<FinishReq>>>);
    impl UploadApi for Spy {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            self.0.put(r, s, o, c)
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            *self.1.lock().unwrap() = Some(q.clone());
            self.0.finish(r, q)
        }
    }
    let mut up = Uploader::new(fx.cfg(), Spy(Api(fx.server.clone()), seen.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
    up.tick();
    let q = seen.lock().unwrap().clone().expect("finish was called");
    assert_eq!(q.truncated.as_deref(), Some("size_limit"));
    assert_eq!(q.dropped_frames, 3);
    assert_eq!(q.frames, 10 + 11, "sum of segment frames (what recording_stopped seals)");
    assert_eq!(q.payload_bytes, 50 + 100, "sum of segment payload bytes");
    assert_eq!(q.digests.len(), 2);
}

// ---- refusals ----------------------------------------------------------------------------------

#[test]
fn storage_off_ends_that_recording_only_and_keeps_the_local_copy() {
    let fx = Fx::new("off");
    fx.server.inner.lock().unwrap().storage_off = true;
    fx.recording(1000, &[300]);
    let mut up = fx.uploader();
    let rep = up.tick();
    assert_eq!(rep.not_stored, 1);
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::NotStored, Some("storage_off")));
    assert_eq!(fx.files_left(), 2, "not stored centrally: the local copy keeps its normal retention");
    assert_eq!(fx.server.count("put"), 0);
    // It is not a permanent preference: once the tenant turns storage on, the NEXT recording uploads.
    fx.server.inner.lock().unwrap().storage_off = false;
    fx.recording(2000, &[400]);
    let rep = up.tick();
    assert_eq!((rep.queued, rep.completed), (1, 1));
    assert_eq!(fx.server.count("create"), 2, "asked again per recording");
}

#[test]
fn every_terminal_server_refusal_ends_the_upload_and_keeps_the_files() {
    let cases: Vec<(ApiFail, Status, &str)> = vec![
        (http(403, "session_not_on_this_machine"), Status::Refused, "session_not_on_this_machine"),
        (http(403, "forbidden"), Status::Refused, "forbidden"),
        (http(413, "too_large"), Status::Refused, "too_large"),
        (http(410, "gone"), Status::Refused, "gone"),
        (http(410, "upload_expired"), Status::Refused, "upload_expired"),
        (http(404, "session_unknown"), Status::Refused, "session_unknown"),
        (http(409, "conflict"), Status::Refused, "conflict"),
        (http(409, "generation_mismatch"), Status::Refused, "generation_mismatch"),
        (http(400, "bad_request"), Status::Refused, "bad_request"),
    ];
    for (fail, status, reason) in cases {
        let fx = Fx::new("term");
        fx.recording(1000, &[300]);
        fx.server.inject(Op::Create, fail.clone());
        let mut up = fx.uploader();
        up.tick();
        let st = fx.only_state();
        assert_eq!((st.status, st.reason.as_deref()), (status, Some(reason)), "{fail:?}");
        assert_eq!(fx.files_left(), 2, "{fail:?}: files kept");
        assert_eq!(fx.server.count("put"), 0);
        // And it is not retried.
        fx.clock.advance(10 * 3_600_000);
        let calls = fx.server.calls().len();
        up.tick();
        assert_eq!(fx.server.calls().len(), calls, "{fail:?}: a terminal answer is never retried");
    }
}

#[test]
fn retryable_answers_schedule_a_retry_and_never_delete_anything() {
    let cases = vec![
        ApiFail::transport("timeout"),
        http(401, "unauthorized"),
        http(403, "machine_not_active"),
        http(507, "tenant_quota"),
        http(507, "server_full"),
        http(503, "busy"),
        http(429, "rate_limited"),
        http(408, "timeout"),
        http(500, "internal"),
    ];
    for fail in cases {
        let fx = Fx::new("retry");
        fx.recording(1000, &[300]);
        fx.server.inject(Op::Create, fail.clone());
        let mut up = fx.uploader();
        let rep = up.tick();
        assert_eq!(rep.retry_scheduled, 1, "{fail:?}");
        let st = fx.only_state();
        assert_eq!(st.status, Status::Pending, "{fail:?}");
        assert_eq!(st.failures, 1);
        assert!(st.next_attempt_at_ms > fx.clock.now_ms(), "{fail:?}: a backoff is scheduled");
        assert_eq!(fx.files_left(), 2);
    }
}

#[test]
fn an_auth_failure_is_retried_on_the_schedule_and_abandoned_when_the_budget_is_spent() {
    let fx = Fx::new("auth");
    fx.recording(1000, &[300]);
    let mut cfg = fx.cfg();
    cfg.max_failures = 3;
    fx.server.inject_n(Op::Create, http(401, "unauthorized"), 10);
    let mut up = fx.uploader_with(cfg, ident(), Arc::new(NeverLive));
    for _ in 0..3 {
        up.tick();
        fx.clock.advance(2 * 3_600_000);
    }
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("retries_exhausted")));
    assert_eq!(fx.server.count("create"), 3);
    assert_eq!(fx.files_left(), 2, "abandoned uploads keep the normal local retention");
}

// ---- backoff -----------------------------------------------------------------------------------

#[test]
fn backoff_is_exponential_jittered_and_bounded_by_the_cap() {
    for seed in [0u64, 1, 0xdead_beef, u64::MAX] {
        let mut prev_floor = 0;
        for n in 1..=100u32 {
            let d = backoff_ms(n, seed, None);
            let exp = (BACKOFF_BASE_MS << (n - 1).min(20)).min(BACKOFF_CAP_MS);
            assert!(d >= exp && d <= BACKOFF_CAP_MS, "n={n} seed={seed}: {d} vs floor {exp}");
            assert!(d <= exp + exp / 4 || d == BACKOFF_CAP_MS, "jitter is at most 25%: n={n} {d} vs {exp}");
            assert!(exp >= prev_floor, "the floor never shrinks");
            prev_floor = exp;
        }
    }
    assert!(backoff_ms(1, 7, None) >= 30_000 && backoff_ms(1, 7, None) <= 37_500);
    assert_eq!(backoff_ms(100, 7, None), BACKOFF_CAP_MS, "the cap holds");
    // Retry-After raises the delay, but never above the cap.
    assert!(backoff_ms(1, 7, Some(600)) >= 600_000);
    assert_eq!(backoff_ms(1, 7, Some(86_400)), BACKOFF_CAP_MS);
}

#[test]
fn nothing_is_attempted_before_the_scheduled_retry_time_and_progress_resets_the_count() {
    let fx = Fx::new("sched");
    fx.recording(1000, &[300]);
    fx.server.inject(Op::Create, ApiFail::transport("connect"));
    let mut up = fx.uploader();
    up.tick();
    let st = fx.only_state();
    let calls = fx.server.calls().len();
    // Just before the retry time: no call.
    fx.clock.advance(st.next_attempt_at_ms - fx.clock.now_ms() - 1);
    up.tick();
    assert_eq!(fx.server.calls().len(), calls, "too early");
    // At it: the upload runs, completes, and the failure count is irrelevant afterwards.
    fx.clock.advance(1);
    up.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
}

#[test]
fn a_retry_after_header_pushes_the_next_attempt_out() {
    let fx = Fx::new("retryafter");
    fx.recording(1000, &[300]);
    let mut f = http(507, "server_full");
    f.retry_after_s = Some(1200);
    fx.server.inject(Op::Create, f);
    fx.uploader().tick();
    let st = fx.only_state();
    assert!(st.next_attempt_at_ms - fx.clock.now_ms() >= 1_200_000);
}

#[test]
fn classify_covers_the_documented_status_table() {
    use Disposition::*;
    let c = |op, f: ApiFail| classify(op, &f);
    let t = |s: Status, r: &str| Terminal { status: s, reason: r.into() };
    assert_eq!(c(Op::Create, ApiFail::transport("x")), Retry { min_delay_s: None });
    assert_eq!(c(Op::Put, http(401, "unauthorized")), Retry { min_delay_s: None });
    assert_eq!(c(Op::Create, http(403, "storage_off")), t(Status::NotStored, "storage_off"));
    assert_eq!(c(Op::Create, http(413, "too_large")), t(Status::Refused, "too_large"));
    assert_eq!(c(Op::Create, http(507, "tenant_quota")), Retry { min_delay_s: None });
    assert_eq!(c(Op::Put, http(410, "gone")), t(Status::Refused, "gone"));
    assert_eq!(c(Op::Create, http(409, "already_complete")), GoFinish);
    assert_eq!(c(Op::Put, http(409, "already_complete")), GoFinish);
    assert_eq!(c(Op::Put, http(409, "bad_offset")), Resync);
    assert_eq!(c(Op::Put, http(409, "chunk_conflict")), Resync);
    assert_eq!(c(Op::Finish, http(409, "incomplete")), Resync);
    assert_eq!(c(Op::Finish, http(409, "audit_conflict")), t(Status::Refused, "audit_conflict"));
    assert_eq!(c(Op::Finish, http(503, "audit_unavailable")), Retry { min_delay_s: None });
    assert_eq!(c(Op::Head, http(404, "not_found")), Recreate);
    assert_eq!(c(Op::Create, http(404, "not_found")), t(Status::Refused, "not_found"));
    let mut dm = http(422, "digest_mismatch");
    dm.segments = vec![1];
    assert_eq!(c(Op::Finish, dm.clone()), DigestReset { segments: vec![1] });
    dm.state = Some("refused".into());
    assert_eq!(c(Op::Finish, dm), t(Status::Refused, "digest_mismatch"));
    assert_eq!(c(Op::Put, http(418, "")), t(Status::Refused, "unexpected_status"));
}

// ---- resume, restart ---------------------------------------------------------------------------

#[test]
fn after_a_restart_the_upload_resumes_from_the_servers_offset_not_from_zero() {
    let fx = Fx::new("resume");
    fx.recording(1000, &[3 * MIB]);
    {
        // The second chunk's PUT dies on the wire: the process "crashes" after chunk one committed.
        struct Crash(Api, Mutex<u32>);
        impl UploadApi for Crash {
            fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
                self.0.create(r, s, l)
            }
            fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
                self.0.head(r, s)
            }
            fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
                let mut n = self.1.lock().unwrap();
                *n += 1;
                if *n == 2 {
                    return Err(ApiFail::transport("reset"));
                }
                self.0.put(r, s, o, c)
            }
            fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
                self.0.finish(r, q)
            }
        }
        let mut up = Uploader::new(fx.cfg(), Crash(Api(fx.server.clone()), Mutex::new(0)), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
        up.tick();
    }
    let st = fx.only_state();
    assert_eq!(st.status, Status::Pending);
    assert_eq!(st.segments[0].committed, MIB as u64, "the committed offset is persisted");
    let puts_before = fx.server.count("put");
    // A brand-new uploader over the same state directory (a restart), past the backoff.
    fx.clock.advance(3_600_000);
    let mut up2 = fx.uploader();
    up2.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    let all = fx.server.calls();
    let after: Vec<&String> = all.iter().filter(|c| c.starts_with("put")).skip(puts_before).collect();
    // Exactly the two remaining chunks, starting at the server's offset (1 MiB), never offset 0.
    assert_eq!(after.len(), 2, "{after:?}");
    assert!(after[0].contains(" 0 1048576 "), "{}", after[0]);
    assert!(after[1].contains(" 0 2097152 "), "{}", after[1]);
    assert!(all.iter().any(|c| c.starts_with("head")), "the restart asks the server where it stands");
}

#[test]
fn the_server_offset_wins_when_it_disagrees_with_the_local_record() {
    let fx = Fx::new("offsetwins");
    fx.recording(1000, &[2 * MIB]);
    let mut up = fx.uploader();
    // The server answers the first PUT with 409 bad_offset claiming it already has chunk one: the
    // uploader adopts that, re-syncs with HEAD, and sends only what is missing.
    fx.server.inject(Op::Create, ApiFail::transport("connect")); // gets the record created locally
    up.tick();
    let id = fx.only_state().recording_id;
    // Simulate a previous process having committed chunk one on the server only.
    {
        let mut g = fx.server.inner.lock().unwrap();
        g.recs.insert(id.clone(), Rec { generation: 1, lens: vec![2 * MIB as u64], data: vec![vec![0u8; 0]], complete: false, digests: vec![], finish_failures: 0 });
        let data: Vec<u8> = std::fs::read(fx.rec_dir.join("rec-1000-0000.ivf")).unwrap();
        g.recs.get_mut(&id).unwrap().data[0] = data[..MIB].to_vec();
    }
    fx.clock.advance(3_600_000);
    up.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    let first_put = fx.server.calls().into_iter().find(|c| c.starts_with("put")).unwrap();
    assert!(first_put.contains(" 0 1048576 "), "never re-sent the committed chunk: {first_put}");
}

#[test]
fn a_server_that_forgot_the_recording_is_re_created_not_abandoned() {
    let fx = Fx::new("recreate");
    fx.recording(1000, &[100]);
    let mut up = fx.uploader();
    fx.server.inject(Op::Put, ApiFail::transport("reset"));
    up.tick();
    assert!(fx.only_state().created);
    // The server lost it (restore, tombstone-free wipe): HEAD answers 404.
    fx.server.inner.lock().unwrap().recs.clear();
    fx.clock.advance(3_600_000);
    up.tick();
    fx.clock.advance(3_600_000);
    up.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    assert_eq!(fx.server.count("create"), 2);
}

#[test]
fn already_complete_on_create_goes_straight_to_a_binding_finish_replay() {
    let fx = Fx::new("already");
    fx.recording(1000, &[100]);
    // Upload once.
    let mut up = fx.uploader();
    up.tick();
    let st = fx.only_state();
    assert_eq!(st.status, Status::Complete);
    // Pretend the ack was lost: the local state says pending again, the server says complete.
    let side_files = fx.recording(1000, &[100]); // same content & stem, so the same digests
    let _ = side_files;
    let mut st2 = st.clone();
    st2.status = Status::Pending;
    st2.reason = None;
    st2.finished_at_ms = None;
    st2.created = false;
    st2.local_cleaned = false;
    for s in &mut st2.segments {
        s.committed = 0;
        s.file_id = None; // the files were re-created above: new identities, adopted on the next drive
    }
    st2.dir_id = None;
    st2.sidecar_id = None;
    st2.verified_sig = None;
    fx.store().save(&st2).unwrap();
    let puts = fx.server.count("put");
    up.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    assert_eq!(fx.server.count("put"), puts, "no bytes re-sent for an already complete recording");
    assert_eq!(fx.files_left(), 0, "the replayed ack bound the digests, so the local copy goes");
}

// ---- integrity ---------------------------------------------------------------------------------

#[test]
fn a_local_file_that_changed_since_it_was_finalised_is_refused_before_any_byte_is_sent() {
    let fx = Fx::new("tamper");
    let stem = fx.recording(1000, &[500]);
    let mut up = fx.uploader();
    // Queue it, then change the file before the first drive: make the first pass defer (session live).
    let live = Arc::new(AtomicBool::new(true));
    let l2 = live.clone();
    let mut up_live = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(move || l2.load(Ordering::SeqCst)))));
    up_live.tick();
    assert_eq!(fx.only_state().status, Status::Pending);
    let path = fx.rec_dir.join(format!("{stem}-0000.ivf"));
    let mut data = std::fs::read(&path).unwrap();
    data[10] ^= 1;
    std::fs::write(&path, data).unwrap();
    live.store(false, Ordering::SeqCst);
    up.tick();
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Refused, Some("local_file_changed")));
    assert_eq!(fx.server.count("put"), 0);
    assert_eq!(fx.files_left(), 2);
}

#[test]
fn a_finish_ack_that_does_not_bind_the_recording_keeps_the_local_copy() {
    // Each variant breaks ONE of the four things C9 says the ack must bind.
    type Tweak = fn(&mut FinishOk);
    let tweaks: Vec<(&str, Tweak)> = vec![
        ("recording id", |a| a.recording_id = "00000000-0000-4000-8000-000000000000".into()),
        ("generation", |a| a.generation += 1),
        ("status", |a| a.state = "uploading".into()),
        ("digest value", |a| a.digests[0] = "0".repeat(64)),
        ("digest count", |a| a.digests.push("1".repeat(64))),
        ("digest order", |a| a.digests.reverse()),
    ];
    for (what, tweak) in tweaks {
        let fx = Fx::new("ack");
        fx.recording(1000, &[100, 200]);
        fx.server.inner.lock().unwrap().ack_tweak = Some(tweak);
        let mut up = fx.uploader();
        up.tick();
        let st = fx.only_state();
        assert_eq!((st.status, st.reason.as_deref()), (Status::Refused, Some("ack_mismatch")), "{what}");
        assert_eq!(fx.files_left(), 3, "{what}: the local copy must survive a non-binding ack");
    }
}

#[test]
fn a_digest_mismatch_resets_and_resends_and_a_third_failure_is_final() {
    // One corrupted chunk: finish says 422 + resets the segment, the agent re-hashes and re-sends.
    let fx = Fx::new("digest");
    fx.recording(1000, &[500]);
    fx.server.inner.lock().unwrap().corrupt_next_put = true;
    let mut up = fx.uploader();
    up.tick();
    let st = fx.only_state();
    assert_eq!(st.status, Status::Complete);
    assert_eq!(st.digest_failures, 1);
    assert_eq!(fx.server.count("put"), 2, "the segment was sent twice");

    // Persistently corrupted: the third mismatch refuses the recording and the files stay.
    let fx = Fx::new("digest3");
    fx.recording(1000, &[500]);
    fx.server.inner.lock().unwrap().never_refuse = true; // only the agent's own counter can stop this
    struct AlwaysCorrupt(Api);
    impl UploadApi for AlwaysCorrupt {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            self.0 .0.inner.lock().unwrap().corrupt_next_put = true;
            self.0.put(r, s, o, c)
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let mut up = Uploader::new(fx.cfg(), AlwaysCorrupt(Api(fx.server.clone())), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
    up.tick();
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Refused, Some("digest_mismatch")));
    assert_eq!(fx.server.count("finish"), 3);
    assert_eq!(fx.files_left(), 2);
}

#[test]
fn chunk_conflict_is_terminal_not_a_loop() {
    let fx = Fx::new("conflict");
    fx.recording(1000, &[2 * MIB]);
    // The server says different bytes already sit at a committed offset: the local file is not what
    // that server holds, and no amount of retrying changes that.
    fx.server.inject(Op::Put, http(409, "chunk_conflict"));
    let mut up = fx.uploader();
    up.tick();
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Refused, Some("chunk_conflict")));
    assert_eq!(fx.server.count("put"), 1);
    assert_eq!(fx.files_left(), 2);
}

// ---- gates -------------------------------------------------------------------------------------

#[test]
fn nothing_uploads_while_a_session_is_live_and_a_session_starting_mid_upload_pauses_it() {
    let fx = Fx::new("live");
    fx.recording(1000, &[3 * MIB]);
    let live = Arc::new(AtomicBool::new(true));
    let l2 = live.clone();
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(move || l2.load(Ordering::SeqCst)))));
    let rep = up.tick();
    assert!(rep.deferred_session_live);
    assert_eq!(fx.server.calls().len(), 0, "not one request while a session is live");
    // Session ends: upload starts. Then a session starts after the first chunk: it stops at once.
    live.store(false, Ordering::SeqCst);
    struct Trip(Api, Arc<AtomicBool>);
    impl UploadApi for Trip {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            let ok = self.0.put(r, s, o, c);
            self.1.store(true, Ordering::SeqCst); // a session starts right after the first chunk
            ok
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let l3 = live.clone();
    let mut up = Uploader::new(fx.cfg(), Trip(Api(fx.server.clone()), live.clone()), ident(), Arc::new(FnProbe(Box::new(move || l3.load(Ordering::SeqCst)))), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
    up.tick();
    assert_eq!(fx.server.count("put"), 1, "paused after the chunk in flight");
    let st = fx.only_state();
    assert_eq!(st.status, Status::Pending);
    assert_eq!(st.failures, 0, "a pause is not a failure");
    assert_eq!(st.segments[0].committed, MIB as u64);
    // The session ends: it resumes where it stopped.
    live.store(false, Ordering::SeqCst);
    let mut up = fx.uploader();
    up.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
}

#[test]
fn a_stopping_service_pauses_between_chunks() {
    let fx = Fx::new("stop");
    fx.recording(1000, &[3 * MIB]);
    let stop = Arc::new(AtomicBool::new(false));
    struct StopAfterFirst(Api, Arc<AtomicBool>);
    impl UploadApi for StopAfterFirst {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            let ok = self.0.put(r, s, o, c);
            self.1.store(true, Ordering::SeqCst);
            ok
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let mut up = Uploader::new(fx.cfg(), StopAfterFirst(Api(fx.server.clone()), stop.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), stop, Arc::new(StdFs));
    up.tick();
    assert_eq!(fx.server.count("put"), 1);
    assert_eq!(fx.only_state().status, Status::Pending);
}

#[test]
fn a_recording_queued_under_another_key_or_control_plane_is_abandoned_explicitly() {
    for variant in 0..4 {
        let fx = Fx::new("identity");
        fx.recording(1000, &[100]);
        // Queue under the original identity while a session is live (no network).
        let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
        up.tick();
        assert_eq!(fx.only_state().status, Status::Pending);
        let mut other = ident();
        match variant {
            0 => other.key_fp_hex = "cd".repeat(32), // re-enrollment: a new key
            1 => other.tenant_id = "ffffffff-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
            2 => other.device_id = "dev-0002".into(),
            _ => other.audience = "https://other.example.test".into(),
        }
        let mut up2 = fx.uploader_with(fx.cfg(), other, Arc::new(NeverLive));
        let rep = up2.tick();
        assert_eq!(rep.abandoned, 1, "variant {variant}");
        let st = fx.only_state();
        assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("identity_changed")), "variant {variant}");
        assert_eq!(fx.server.calls().len(), 0, "variant {variant}: the new identity never signs for the old recording");
        assert_eq!(fx.files_left(), 2);
    }
}

// ---- bounds ------------------------------------------------------------------------------------

#[test]
fn a_pending_upload_older_than_seven_days_is_abandoned_and_the_local_hold_lapses() {
    let fx = Fx::new("age");
    let stem = fx.recording(1000, &[100]);
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
    up.tick();
    let st = fx.only_state();
    let now = fx.clock.now_ms();
    let lc = fx.lifecycle();
    let held = |dir: &Path, stem: &str, at: i64| lc.claim_for_sweep(dir, false, Some(stem), Some(DEVICE), at).is_none();
    assert!(held(&fx.rec_dir, &stem, now), "pending: held past the 72 h local TTL");
    assert!(held(&fx.rec_dir, &stem, st.enqueued_at_ms + MAX_PENDING_AGE_MS - 1));
    assert!(!held(&fx.rec_dir, &stem, st.enqueued_at_ms + MAX_PENDING_AGE_MS), "the extension ends at the bound");
    assert!(!held(&fx.rec_dir, "rec-999", now), "another recording is not held");
    assert!(!held(&fx.rec_dir.join("other"), &stem, now), "another directory is not held");
    fx.clock.advance(MAX_PENDING_AGE_MS + 1000);
    let mut up = fx.uploader();
    let rep = up.tick();
    assert_eq!(rep.abandoned, 1);
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("too_old")));
    assert!(fx.lifecycle().claim_for_sweep(&fx.rec_dir, false, Some(&stem), Some(DEVICE), fx.clock.now_ms()).is_some(), "a terminal upload holds nothing");
    assert_eq!(fx.server.calls().len(), 0);
}

#[test]
fn the_local_sweep_skips_a_recording_with_a_pending_upload_and_deletes_it_once_settled() {
    let fx = Fx::new("sweep");
    let stem = fx.recording(1000, &[100]);
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
    up.tick();
    let later = fx.clock.now_ms() + 100 * 3_600_000; // past the 72 h deadline in the sidecar
    let removed = crate::recording::sweep_expired_with(&fx.rec_dir, later, &fx.lifecycle());
    assert_eq!(removed, 0, "held");
    assert!(fx.rec_dir.join(format!("{stem}.json")).exists());
    assert!(fx.rec_dir.join(format!("{stem}-0000.ivf")).exists());
    // Abandon it: the hold lapses and the next sweep deletes the files as usual.
    up.abandon_all("test").unwrap();
    let removed = crate::recording::sweep_expired_with(&fx.rec_dir, later, &fx.lifecycle());
    assert_eq!(removed, 1);
    assert_eq!(fx.files_left(), 0);
}

#[test]
fn recordings_past_the_pending_bytes_bound_are_not_queued() {
    let fx = Fx::new("bytes");
    fx.recording(1000, &[600]);
    fx.recording(2000, &[600]);
    let mut cfg = fx.cfg();
    cfg.max_pending_bytes = 1000;
    let mut up = fx.uploader_with(cfg, ident(), Arc::new(FnProbe(Box::new(|| true))));
    let rep = up.tick();
    assert_eq!(rep.queued, 1);
    let mut states = fx.states();
    states.sort_by_key(|s| s.status == Status::Pending);
    assert_eq!(states.len(), 2);
    assert_eq!((states[0].status, states[0].reason.as_deref()), (Status::Refused, Some("queue_full")));
    assert_eq!(states[1].status, Status::Pending);
}

// ---- enqueue validation ------------------------------------------------------------------------

#[test]
fn recordings_that_can_never_upload_are_recorded_once_with_the_reason() {
    let fx = Fx::new("validate");
    fx.recording_in(&fx.rec_dir, 1000, &[100], None, DEVICE, None); // no session id
    fx.recording_in(&fx.rec_dir, 2000, &[100], Some(SESSION), "dev-other", None); // another enrollment
    fx.recording_in(&fx.rec_dir, 3000, &[100], Some(SESSION), DEVICE, Some("Bad Reason!")); // unacceptable label
    fx.recording_in(&fx.rec_dir, 4000, &[100], Some("not-a-uuid"), DEVICE, None);
    // A sidecar whose segment file is gone.
    let stem = fx.recording(5000, &[100]);
    std::fs::remove_file(fx.rec_dir.join(format!("{stem}-0000.ivf"))).unwrap();
    // A sidecar naming a traversal path as its segment.
    let stem6 = fx.recording(6000, &[100]);
    let p = fx.rec_dir.join(format!("{stem6}.json"));
    let text = std::fs::read_to_string(&p).unwrap().replace(&format!("{stem6}-0000.ivf"), "..\\\\..\\\\x.ivf");
    std::fs::write(&p, text).unwrap();
    // A zero-length segment.
    let stem7 = fx.recording(7000, &[100]);
    std::fs::write(fx.rec_dir.join(format!("{stem7}-0000.ivf")), b"").unwrap();

    let mut up = fx.uploader();
    let rep = up.tick();
    assert_eq!(rep.queued, 0);
    let mut reasons: Vec<String> = fx.states().iter().map(|s| format!("{:?}:{}", s.status, s.reason.clone().unwrap_or_default())).collect();
    reasons.sort();
    assert_eq!(
        reasons,
        [
            "Abandoned:other_device",
            "Refused:bad_segment_length",
            "Refused:bad_segment_name",
            "Refused:bad_truncation_reason",
            "Refused:no_session",
            "Refused:no_session",
            "Refused:segment_missing",
        ]
    );
    assert_eq!(fx.server.calls().len(), 0, "none of them touches the network");
    // And a second pass does not re-examine them (no new state files, same count).
    up.tick();
    assert_eq!(fx.states().len(), 7);
}

// ---- finish or abandon (uninstall hand-off) ----------------------------------------------------

#[test]
fn finish_or_abandon_completes_what_it_can_ignoring_the_session_gate_and_the_backoff() {
    let fx = Fx::new("drain");
    fx.recording(1000, &[MIB + 10]);
    fx.recording(2000, &[100]);
    // One create fails first, so at least one recording is pending with a backoff scheduled.
    fx.server.inject(Op::Create, ApiFail::transport("connect"));
    let mut up = fx.uploader();
    up.tick();
    assert!(fx.states().iter().any(|s| s.status == Status::Pending && s.next_attempt_at_ms > fx.clock.now_ms()));
    // The uninstall runs INSIDE a session (the technician issued it) and long before the backoff ends.
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
    let rep = up.finish_or_abandon(Duration::from_secs(600));
    assert!(rep.uploaded >= 1, "{rep:?}");
    assert_eq!(fx.states().iter().filter(|s| s.status == Status::Pending).count(), 0, "nothing is left pending");
    assert_eq!(fx.states().iter().filter(|s| s.status == Status::Complete).count(), 2);
    assert_eq!(fx.files_left(), 0);
}

#[test]
fn finish_or_abandon_does_not_pace_but_background_uploads_do() {
    let fx = Fx::new("drainpace");
    fx.recording(1000, &[2 * MIB]);
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
    up.tick(); // queue it (session live: no upload)
    let slept_before = fx.clock.total_slept();
    let rep = up.finish_or_abandon(Duration::from_secs(600));
    assert_eq!(rep.uploaded, 1);
    assert_eq!(fx.clock.total_slept(), slept_before, "a drain is not rate capped");
}

#[test]
fn finish_or_abandon_abandons_explicitly_what_it_cannot_finish() {
    let fx = Fx::new("drainfail");
    fx.recording(1000, &[100]);
    fx.recording(2000, &[100]);
    fx.server.inject_n(Op::Create, http(503, "busy"), 20);
    let mut up = fx.uploader();
    let rep = up.finish_or_abandon(Duration::from_secs(600));
    assert_eq!((rep.uploaded, rep.abandoned), (0, 2), "{rep:?}");
    for st in fx.states() {
        assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("uninstall")));
    }
    assert_eq!(fx.files_left(), 4, "abandoned recordings keep their files; the uninstall removes the directory");
}

#[test]
fn finish_or_abandon_is_bounded_by_its_budget() {
    let fx = Fx::new("drainbudget");
    for i in 0..5 {
        fx.recording(1000 + i, &[100]);
    }
    {
        let mut g = fx.server.inner.lock().unwrap();
        g.call_cost_ms = 20_000; // every request takes 20 s of (fake) time
        g.clock = Some(fx.clock.clone());
    }
    let mut up = fx.uploader();
    let started = fx.clock.now_ms();
    let rep = up.finish_or_abandon(Duration::from_secs(60));
    assert!(rep.budget_exhausted, "{rep:?}");
    assert!(rep.uploaded < 5);
    assert_eq!(fx.states().iter().filter(|s| s.status == Status::Pending).count(), 0, "the rest are abandoned, not left pending");
    assert!(fx.states().iter().any(|s| s.reason.as_deref() == Some("uninstall_budget")));
    // It stopped promptly: one request's overshoot past the budget, not a full pass of 5 recordings.
    assert!(fx.clock.now_ms() - started < 60_000 + 3 * 20_000, "{} ms", fx.clock.now_ms() - started);
}

#[test]
fn finish_or_abandon_reports_settled_entries_and_abandon_all_is_network_free() {
    let fx = Fx::new("settled");
    fx.server.inner.lock().unwrap().storage_off = true;
    fx.recording(1000, &[100]);
    fx.uploader().tick(); // not stored
    fx.server.inner.lock().unwrap().storage_off = false;
    fx.recording(2000, &[100]);
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
    up.tick(); // queued, deferred
    let calls = fx.server.calls().len();
    assert_eq!(up.abandon_all("reenrolled"), Ok(1));
    assert_eq!(fx.server.calls().len(), calls, "abandon_all never touches the network");
    let rep = up.finish_or_abandon(Duration::from_secs(5));
    assert_eq!((rep.uploaded, rep.abandoned, rep.already_settled), (0, 0, 2));
}

// ---- persistence -------------------------------------------------------------------------------

#[test]
fn state_round_trips_atomically_and_hostile_or_corrupt_files_are_ignored() {
    let fx = Fx::new("store");
    fx.recording(1000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true)))).tick();
    let st = fx.only_state();
    let store = fx.store();
    store.save(&st).unwrap();
    assert_eq!(store.load(&st.recording_id).unwrap(), st);
    assert!(!fx.state_dir.join(format!("{}.json.tmp", st.recording_id)).exists(), "the temp file is renamed away");
    // Junk beside it: a non-uuid name, garbage under a uuid name, a foreign schema.
    std::fs::write(fx.state_dir.join("notes.json"), b"{}").unwrap();
    std::fs::write(fx.state_dir.join("00000000-0000-4000-8000-000000000001.json"), b"{not json").unwrap();
    let mut foreign = st.clone();
    foreign.schema = 99;
    foreign.recording_id = "00000000-0000-4000-8000-000000000002".into();
    std::fs::write(fx.state_dir.join("00000000-0000-4000-8000-000000000002.json"), serde_json::to_vec(&foreign).unwrap()).unwrap();
    // A state file whose id does not match its name is not trusted.
    std::fs::write(fx.state_dir.join("00000000-0000-4000-8000-000000000003.json"), serde_json::to_vec(&st).unwrap()).unwrap();
    assert_eq!(store.list().len(), 1);
    assert!(store.load("../../etc/passwd").is_none());
    assert!(store.save(&UploadState { recording_id: "..\\evil".into(), ..st }).is_err(), "a non-canonical id is never joined into a path");
}

#[test]
fn recording_ids_are_deterministic_and_distinguish_device_dir_and_stem() {
    let d = Path::new(r"C:\rmt-agent\recordings");
    let a = recording_id_for("dev-1", d, "rec-1");
    assert_eq!(a, recording_id_for("dev-1", d, "rec-1"));
    assert!(parse_canonical_uuid(&a).is_some(), "canonical lower-case uuid: {a}");
    assert_ne!(a, recording_id_for("dev-2", d, "rec-1"));
    assert_ne!(a, recording_id_for("dev-1", d, "rec-2"));
    assert_ne!(a, recording_id_for("dev-1", Path::new(r"C:\rmt-agent\cli-recordings\x"), "rec-1"));
    assert_eq!(a, recording_id_for("dev-1", Path::new(r"c:\RMT-AGENT\recordings"), "rec-1"), "path case is not identity on Windows");
}

#[test]
fn a_lost_state_file_requeues_the_same_recording_id_and_the_server_replays_it_idempotently() {
    let fx = Fx::new("lost");
    fx.recording(1000, &[MIB + 5]);
    let mut up = fx.uploader();
    fx.server.inject(Op::Put, ApiFail::transport("reset"));
    up.tick();
    let id = fx.only_state().recording_id;
    std::fs::remove_dir_all(&fx.state_dir).unwrap();
    fx.clock.advance(3_600_000);
    up.tick();
    let st = fx.only_state();
    assert_eq!(st.recording_id, id);
    assert_eq!(st.status, Status::Complete);
    assert_eq!(fx.server.count("create"), 2, "create is replayed for the same id");
}

#[test]
fn terminal_tombstones_are_pruned_after_their_keep_period() {
    let fx = Fx::new("prune");
    fx.server.inner.lock().unwrap().storage_off = true;
    fx.recording(1000, &[100]);
    let mut up = fx.uploader();
    up.tick();
    assert_eq!(fx.states().len(), 1);
    fx.clock.advance(TERMINAL_KEEP_MS + 1000);
    // The local copy is long gone by then.
    for e in std::fs::read_dir(&fx.rec_dir).unwrap().flatten() {
        std::fs::remove_file(e.path()).unwrap();
    }
    up.tick();
    assert_eq!(fx.states().len(), 0);
}

#[test]
fn a_recording_in_a_cli_broker_leaf_directory_is_found_and_its_directory_removed_with_it() {
    let fx = Fx::new("leaf");
    let root = fx.rec_dir.join("cli");
    let leaf = root.join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&leaf).unwrap();
    fx.recording_in(&leaf, 1000, &[100], Some(SESSION), DEVICE, None);
    let mut cfg = fx.cfg();
    cfg.roots = vec![ScanRoot::Leaves(root.clone())];
    // A non-uuid directory beside it is never entered.
    let junk = root.join("not-a-uuid");
    std::fs::create_dir_all(&junk).unwrap();
    fx.recording_in(&junk, 2000, &[100], Some(SESSION), DEVICE, None);
    let mut up = fx.uploader_with(cfg, ident(), Arc::new(NeverLive));
    let rep = up.tick();
    assert_eq!((rep.queued, rep.completed), (1, 1));
    assert!(!leaf.exists(), "the empty leaf is removed with the recording");
    assert!(junk.exists() && std::fs::read_dir(&junk).unwrap().count() == 2, "untouched");
}

#[test]
fn too_many_segments_and_old_recordings_are_not_queued() {
    let fx = Fx::new("limits");
    let sizes = vec![10usize; MAX_SEGMENTS + 1];
    fx.recording(1000, &sizes);
    // A recording that ended 8 days ago.
    let stem = fx.recording(2000, &[10]);
    let p = fx.rec_dir.join(format!("{stem}.json"));
    let mut side: Sidecar = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    side.ended_at_unix_ms = fx.clock.now_ms() - 8 * 24 * 3_600_000;
    std::fs::write(&p, serde_json::to_vec(&side).unwrap()).unwrap();
    fx.uploader().tick();
    let mut r: Vec<String> = fx.states().iter().map(|s| s.reason.clone().unwrap()).collect();
    r.sort();
    assert_eq!(r, ["too_many_segments", "too_old"]);
}

// ==== review repair: durability, trust, identity, lifecycle ======================================

use std::sync::atomic::AtomicUsize;

#[derive(Default)]
struct Faults {
    fail_write: AtomicBool,
    fail_list: AtomicBool,
    fail_open: AtomicBool,
    /// Opening the recording directory fails (an enumeration that cannot be completed).
    fail_open_rec: AtomicBool,
}

/// StdFs, except operations on the QUEUE directory can be made to fail (a full or locked disk, a directory that
/// is no longer trusted).
struct FaultFs {
    state_dir: PathBuf,
    rec_dir: PathBuf,
    f: Arc<Faults>,
}

struct FaultDir {
    inner: Box<dyn DirIo>,
    is_state: bool,
    f: Arc<Faults>,
}

impl FsProvider for FaultFs {
    fn open(&self, path: &Path, create: bool) -> std::io::Result<Box<dyn DirIo>> {
        let is_state = path == self.state_dir;
        if path == self.rec_dir && self.f.fail_open_rec.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected: the recording directory cannot be opened"));
        }
        if is_state && self.f.fail_open.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "untrusted owner or DACL"));
        }
        Ok(Box::new(FaultDir { inner: StdFs.open(path, create)?, is_state, f: self.f.clone() }))
    }
}

impl DirIo for FaultDir {
    fn list(&self) -> std::io::Result<Vec<String>> {
        if self.is_state && self.f.fail_list.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected list failure"));
        }
        self.inner.list()
    }
    fn subdirs(&self) -> std::io::Result<Vec<String>> {
        self.inner.subdirs()
    }
    fn read(&self, name: &str, max: usize) -> std::io::Result<Option<Vec<u8>>> {
        self.inner.read(name, max)
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        if self.is_state && self.f.fail_write.load(Ordering::SeqCst) && name.ends_with(".json") {
            return Err(std::io::Error::other("injected write failure (disk full)"));
        }
        self.inner.write_atomic(name, bytes)
    }
    fn remove(&self, name: &str) -> std::io::Result<()> {
        self.inner.remove(name)
    }
    fn open_file(&self, name: &str) -> std::io::Result<crate::recording_fs::HeldFile> {
        self.inner.open_file(name)
    }
    fn remove_file_if(&self, name: &str, id: &FileIdentity) -> std::io::Result<()> {
        self.inner.remove_file_if(name, id)
    }
    fn identity(&self) -> std::io::Result<FileIdentity> {
        self.inner.identity()
    }
    fn child(&self, name: &str) -> std::io::Result<Box<dyn DirIo>> {
        self.inner.child(name)
    }
    fn remove_empty_subdir(&self, name: &str) -> std::io::Result<()> {
        self.inner.remove_empty_subdir(name)
    }
    fn lock(&self, name: &str) -> std::io::Result<Option<std::fs::File>> {
        self.inner.lock(name)
    }
}

impl Fx {
    fn faults(&self) -> (Arc<Faults>, Arc<dyn FsProvider>) {
        let f = Arc::new(Faults::default());
        (f.clone(), Arc::new(FaultFs { state_dir: self.state_dir.clone(), rec_dir: self.rec_dir.clone(), f }))
    }
    fn faulty_uploader(&self, fs: Arc<dyn FsProvider>, probe: Arc<dyn SessionProbe>) -> Uploader<Api> {
        Uploader::new(self.cfg(), Api(self.server.clone()), ident(), probe, self.clock.clone(), Arc::new(AtomicBool::new(false)), fs)
    }
}

fn live() -> Arc<dyn SessionProbe> {
    Arc::new(FnProbe(Box::new(|| true)))
}

#[test]
fn a_queue_entry_that_cannot_be_written_means_not_queued_and_not_one_byte_is_sent() {
    let fx = Fx::new("b2-queue");
    fx.recording(1000, &[300]);
    let (faults, fs) = fx.faults();
    faults.fail_write.store(true, Ordering::SeqCst);
    let mut up = fx.faulty_uploader(fs, Arc::new(NeverLive));
    let rep = up.tick();
    assert_eq!((rep.queued, rep.completed), (0, 0), "{rep:?}");
    assert!(rep.problems >= 1, "the failure is reported, not swallowed: {rep:?}");
    assert_eq!(fx.server.calls().len(), 0, "no request without a durable queue entry");
    assert_eq!(fx.states().len(), 0);
    // A drain over the same fault is NOT settled: the recording is neither queued nor dispositioned.
    let rep = up.finish_or_abandon(Duration::from_secs(5));
    assert!(!rep.is_settled(), "{rep:?}");
    assert_eq!((rep.uploaded, rep.abandoned), (0, 0));
}

#[test]
fn a_state_that_cannot_be_saved_after_create_stops_the_upload_before_any_chunk() {
    let fx = Fx::new("b2-create");
    fx.recording(1000, &[MIB + 1]);
    // First pass: the drive verifies the file (its signature becomes durable) and then CREATE fails on the wire, so the
    // only unsaved fact left is the `created` record.
    fx.server.inject(Op::Create, ApiFail::transport("connect"));
    fx.uploader().tick();
    assert!(fx.only_state().verified_sig.is_some() && !fx.only_state().created);
    fx.clock.advance(2 * 3_600_000);
    // Second pass: create succeeds server-side but the disk cannot take the record of it.
    let (faults, fs) = fx.faults();
    faults.fail_write.store(true, Ordering::SeqCst);
    let mut up = fx.faulty_uploader(fs, Arc::new(NeverLive));
    let rep = up.tick();
    assert_eq!(fx.server.count("create"), 2, "the create DID reach the server");
    assert_eq!(fx.server.count("put"), 0, "not one chunk without a durable record of the create: {rep:?}");
    assert_eq!(rep.completed, 0);
    assert!(rep.problems >= 1);
}

#[test]
fn a_queue_that_cannot_be_enumerated_blocks_the_drain_instead_of_reporting_nothing_pending() {
    let fx = Fx::new("a2-enum");
    fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let (faults, fs) = fx.faults();
    faults.fail_list.store(true, Ordering::SeqCst);
    let mut up = fx.faulty_uploader(fs.clone(), Arc::new(NeverLive));
    let rep = up.finish_or_abandon(Duration::from_secs(5));
    assert!(!rep.is_settled(), "an unenumerable queue is an error, never an empty one: {rep:?}");
    assert_eq!((rep.uploaded, rep.abandoned), (0, 0));
    let store = StateStore::new(fs, fx.state_dir.clone(), fx.cfg().roots);
    assert!(crate::recording_upload_http::abandon_pending_unwired(&QueueOps::new(store.clone(), fx.clock.clone()), Duration::from_secs(1)).problems.len() == 1);
    assert!(abandon_all_in(&QueueOps::new(store.clone(), fx.clock.clone()), "reenrolled").is_err());
    assert_eq!(fx.only_state().status, Status::Pending, "and nothing was claimed settled");
}

#[test]
fn an_abandonment_that_cannot_be_saved_is_not_counted_and_the_entry_stays_pending() {
    let fx = Fx::new("a2-save");
    fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    fx.server.inject_n(Op::Create, http(503, "busy"), 10);
    let (faults, fs) = fx.faults();
    faults.fail_write.store(true, Ordering::SeqCst);
    let mut up = fx.faulty_uploader(fs.clone(), Arc::new(NeverLive));
    let rep = up.finish_or_abandon(Duration::from_secs(60));
    assert_eq!(rep.abandoned, 0, "an abandonment that is not durable is not an abandonment: {rep:?}");
    assert!(!rep.is_settled());
    assert_eq!(fx.only_state().status, Status::Pending);
    let store = StateStore::new(fs, fx.state_dir.clone(), fx.cfg().roots);
    let un = crate::recording_upload_http::abandon_pending_unwired(&QueueOps::new(store.clone(), fx.clock.clone()), Duration::from_secs(1));
    assert_eq!((un.abandoned, un.is_settled()), (0, false));
    assert!(abandon_all_in(&QueueOps::new(store.clone(), fx.clock.clone()), "reenrolled").is_err());
    // Healthy again (and the removal drain's fence has long expired): everything settles.
    faults.fail_write.store(false, Ordering::SeqCst);
    fx.clock.advance(2 * 3_600_000);
    assert_eq!(abandon_all_in(&QueueOps::new(store.clone(), fx.clock.clone()), "reenrolled"), Ok(1));
    assert_eq!(fx.only_state().status, Status::Abandoned);
}

#[test]
fn the_unwired_abandonment_settles_every_pending_entry_without_the_network() {
    let fx = Fx::new("unwired");
    fx.recording(1000, &[100]);
    fx.recording(2000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let rep = crate::recording_upload_http::abandon_pending_unwired(&fx.ops(), Duration::from_secs(5));
    assert_eq!((rep.abandoned, rep.is_settled()), (2, true));
    for st in fx.states() {
        assert_eq!((st.status, st.reason.as_deref(), st.finished_at_ms), (Status::Abandoned, Some("uninstall_unwired"), Some(fx.clock.now_ms())));
    }
    assert_eq!(fx.server.calls().len(), 0);
}

#[test]
fn a_drain_with_an_unreadable_recording_sidecar_is_not_settled() {
    let fx = Fx::new("a2-unreadable");
    std::fs::write(fx.rec_dir.join("rec-1000.json"), b"{ this is not complete").unwrap();
    let mut up = fx.uploader();
    let rep = up.finish_or_abandon(Duration::from_secs(5));
    assert!(!rep.is_settled(), "an unexamined recording is not a settled one: {rep:?}");
}

#[test]
fn a_completion_that_cannot_be_recorded_durably_deletes_nothing() {
    let fx = Fx::new("b2-complete");
    fx.recording(1000, &[300]);
    let (faults, fs) = fx.faults();
    struct BreakDiskAfterFinish(Api, Arc<Faults>);
    impl UploadApi for BreakDiskAfterFinish {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            self.0.put(r, s, o, c)
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            let ok = self.0.finish(r, q);
            self.1.fail_write.store(true, Ordering::SeqCst); // the disk fills up right after the server's acknowledgement
            ok
        }
    }
    let mut up = Uploader::new(fx.cfg(), BreakDiskAfterFinish(Api(fx.server.clone()), faults.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), fs);
    up.tick();
    assert_eq!(fx.files_left(), 2, "Complete was not durable, so no local file may be deleted");
    assert_eq!(fx.only_state().status, Status::Pending);
}

// ---- B1: nothing from disk is trusted as a path, a name or an authority ---------------------------

fn write_state(fx: &Fx, file_id: &str, st: &UploadState) {
    std::fs::create_dir_all(&fx.state_dir).unwrap();
    std::fs::write(fx.state_dir.join(format!("{file_id}.json")), serde_json::to_vec_pretty(st).unwrap()).unwrap();
}

#[test]
fn a_planted_or_edited_state_is_never_obeyed_and_never_deletes_anything() {
    let fx = Fx::new("b1-plant");
    // A real, queued entry to start from, and a victim directory the entry must never touch.
    fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let good = fx.only_state();
    let victim = fx._tmp.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("rec-1000-0000.ivf"), b"precious").unwrap();
    std::fs::write(victim.join("rec-1000.json"), b"precious").unwrap();
    std::fs::write(fx.rec_dir.join("keep-me.txt"), b"unrelated").unwrap();
    std::fs::remove_file(fx.state_dir.join(format!("{}.json", good.recording_id))).unwrap();

    let mut complete = good.clone();
    complete.status = Status::Complete;
    complete.ack_digests = Some(good.segments.iter().map(|s| s.sha256.clone()).collect());
    complete.local_cleaned = false;

    let mut planted: Vec<(&str, UploadState)> = Vec::new();
    // (a) a Complete state whose local_dir is somewhere else entirely (id re-derived so ONLY the directory is wrong)
    let mut a = complete.clone();
    a.local_dir = victim.display().to_string();
    a.recording_id = recording_id_for(&a.device_id, &victim, &a.stem);
    planted.push(("local_dir outside the roots", a));
    // (b) a segment name that escapes the directory
    let mut b = complete.clone();
    b.segments[0].file = "..\\..\\victim\\rec-1000-0000.ivf".into();
    planted.push(("segment name traverses", b));
    // (c) a segment name that is not this recording's naming
    let mut c = complete.clone();
    c.segments[0].file = "keep-me.txt".into();
    planted.push(("segment is not a recording file", c));
    // (d) a stem that is not ours
    let mut d = complete.clone();
    d.stem = "evil".into();
    planted.push(("stem is not rec-<ms>", d));
    // (e) Complete without acknowledged digests
    let mut e = complete.clone();
    e.ack_digests = None;
    planted.push(("Complete without ack digests", e));
    // (f) a recording id that is not the derived one
    let mut f = complete.clone();
    f.recording_id = "00000000-0000-4000-8000-0000000000ff".into();
    planted.push(("recording id is not derived", f));
    // (g) acknowledged digests that do not match the segments
    let mut g = complete.clone();
    g.ack_digests = Some(vec!["0".repeat(64)]);
    planted.push(("ack digests differ from the segments", g));
    for (what, st) in &planted {
        write_state(&fx, &st.recording_id, st);
        let listing = fx.store().list_checked().unwrap();
        assert!(listing.states.iter().all(|s| s.local_dir != victim.display().to_string()), "{what}: accepted");
        assert!(listing.issues.iter().any(|i| i.starts_with(&st.recording_id)), "{what}: not reported: {:?}", listing.issues);
        let mut up = fx.uploader_with(fx.cfg(), ident(), live());
        let rep = up.tick();
        // Reported either way; an unreadable entry for a recording is never silently overwritten by a fresh one.
        assert!(rep.problems >= 1, "{what}: {rep:?}");
        assert!(victim.join("rec-1000-0000.ivf").exists() && victim.join("rec-1000.json").exists(), "{what}: the victim directory is untouched");
        assert!(fx.rec_dir.join("keep-me.txt").exists(), "{what}: an unrelated file in the recording directory is untouched");
        let _ = std::fs::remove_file(fx.state_dir.join(format!("{}.json", st.recording_id)));
    }
    assert_eq!(fx.server.count("put"), 0, "nothing was ever uploaded on a planted state's word");
}

#[test]
fn cleanup_deletes_only_what_the_ack_named_and_leaves_other_files_alone() {
    let fx = Fx::new("b1-ackonly");
    fx.recording(1000, &[300, 400]);
    std::fs::write(fx.rec_dir.join("rec-1000-0099.ivf"), b"not in the sidecar").unwrap();
    std::fs::write(fx.rec_dir.join("notes.txt"), b"unrelated").unwrap();
    fx.uploader().tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    let mut left: Vec<String> = std::fs::read_dir(&fx.rec_dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    left.sort();
    assert_eq!(left, ["notes.txt", "rec-1000-0099.ivf"], "only the acknowledged segments and the sidecar went");
}

#[test]
fn an_untrusted_queue_directory_is_not_a_delete_authority_and_a_pass_reports_it() {
    let fx = Fx::new("b1-untrusted");
    fx.recording(1000, &[300]);
    // A valid Complete entry that never got its cleanup...
    fx.uploader().tick();
    let mut st = fx.only_state();
    st.local_cleaned = false;
    // (recreate the files so there is something to wrongly delete)
    fx.recording(1000, &[300]);
    st.segments[0].file_id = None;
    st.sidecar_id = None;
    fx.store().save(&st).unwrap();
    // ... and a queue directory that fails the trust check (not SYSTEM/Administrators-owned, or writable by others).
    let (faults, fs) = fx.faults();
    faults.fail_open.store(true, Ordering::SeqCst);
    let mut up = fx.faulty_uploader(fs.clone(), Arc::new(NeverLive));
    let rep = up.tick();
    assert!(rep.problems >= 1, "{rep:?}");
    assert_eq!(fx.files_left(), 2, "a state read from an untrusted directory deletes nothing");
    let drain = up.finish_or_abandon(Duration::from_secs(5));
    assert!(!drain.is_settled(), "{drain:?}");
    // Sweeps hold everything while the queue cannot be opened.
    let lc = Lifecycle::new(StateStore::new(fs, fx.state_dir.clone(), fx.cfg().roots));
    assert!(lc.claim_for_sweep(&fx.rec_dir, false, Some("rec-1000"), Some(DEVICE), fx.clock.now_ms()).is_none());
}

#[test]
fn the_production_provider_refuses_a_directory_a_non_admin_can_write() {
    // A user-profile temp directory (and its parent) is writable by its owner, who is not SYSTEM/Administrators:
    // exactly what the anchored route must refuse before it trusts anything read from it.
    let dir = std::env::temp_dir().join(format!("rmt-untrusted-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let r = crate::recording_fs::AnchoredFs.open(&dir, false);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(r.is_err(), "a user-writable directory must not be trusted");
}

// ---- B3: file identity, handles, reparse points -----------------------------------------------------

#[test]
fn a_recording_replaced_after_queueing_is_refused_before_any_byte_is_sent() {
    let fx = Fx::new("b3-replaced");
    let stem = fx.recording(1000, &[500]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    // Same name, same bytes, but a different file (delete + recreate): a different identity.
    let path = fx.rec_dir.join(format!("{stem}-0000.ivf"));
    let data = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, data).unwrap();
    fx.uploader().tick();
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Refused, Some("local_file_changed")));
    assert_eq!(fx.server.count("put"), 0);
}

#[test]
fn deleting_requires_the_confirmed_file_identity() {
    let dir = tempfile_dir::Dir::new("b3-delete");
    let d = StdFs.open(dir.path(), false).unwrap();
    std::fs::write(dir.path().join("rec-1-0000.ivf"), b"original").unwrap();
    let id = d.open_file("rec-1-0000.ivf").unwrap().id;
    // Another file takes the name.
    std::fs::remove_file(dir.path().join("rec-1-0000.ivf")).unwrap();
    std::fs::write(dir.path().join("rec-1-0000.ivf"), b"original").unwrap();
    assert!(d.remove_file_if("rec-1-0000.ivf", &id).is_err(), "not the confirmed file");
    assert!(dir.path().join("rec-1-0000.ivf").exists());
    let id2 = d.open_file("rec-1-0000.ivf").unwrap().id;
    d.remove_file_if("rec-1-0000.ivf", &id2).unwrap();
    assert!(!dir.path().join("rec-1-0000.ivf").exists());
    d.remove_file_if("rec-1-0000.ivf", &id2).unwrap(); // gone is success
    // Names are single safe components.
    assert!(d.open_file("..\\x").is_err() && d.remove("a\\b").is_err() && d.read("C:evil", 10).is_err());
}

#[test]
fn a_recording_directory_that_is_a_junction_is_not_followed() {
    let fx = Fx::new("b3-junction");
    let root = fx.rec_dir.join("cli");
    std::fs::create_dir_all(&root).unwrap();
    let target = fx._tmp.path().join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    fx.recording_in(&target, 1000, &[100], Some(SESSION), DEVICE, None);
    let link = root.join(uuid::Uuid::new_v4().to_string());
    let st = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&link).arg(&target).output().unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stdout));
    let mut cfg = fx.cfg();
    cfg.roots = vec![ScanRoot::Leaves(root)];
    let mut up = fx.uploader_with(cfg, ident(), Arc::new(NeverLive));
    let rep = up.tick();
    assert_eq!(rep.queued, 0, "a reparse point is never entered: {rep:?}");
    assert_eq!(rep.problems, 0, "it is excluded when the directory is listed, not merely refused when opened: {rep:?}");
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 2, "the target's recording is untouched");
    assert_eq!(fx.server.calls().len(), 0);
}

// ---- B4: one lifecycle per recording --------------------------------------------------------------

#[test]
fn enqueue_the_uploader_and_both_sweeps_share_one_lock_per_recording() {
    let fx = Fx::new("b4-lock");
    let stem = fx.recording(1000, &[MIB + 7]);
    let lc = fx.lifecycle();
    let now = fx.clock.now_ms();
    // (1) A sweep working on the recording keeps the uploader from queueing it.
    let claim = lc.claim_for_sweep(&fx.rec_dir, false, Some(&stem), Some(DEVICE), now + 100 * 3_600_000).expect("free: nothing queued");
    let mut up = fx.uploader_with(fx.cfg(), ident(), live());
    assert_eq!(up.tick().queued, 0, "skipped while a sweep owns it");
    assert!(lc.claim_for_sweep(&fx.rec_dir, false, Some(&stem), Some(DEVICE), now).is_none(), "a second sweep cannot claim it either");
    drop(claim);
    assert_eq!(up.tick().queued, 1);
    // (2) While the uploader is mid-drive, a sweep is refused even before any hold would apply.
    let seen: Arc<Mutex<Vec<bool>>> = Arc::default();
    struct Sweeper(Api, Arc<Mutex<Vec<bool>>>, Lifecycle, PathBuf, String, i64);
    impl UploadApi for Sweeper {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            // Far beyond the 72 h TTL and the age bound irrelevant: only the lock can refuse this.
            let refused = self.2.claim_for_sweep(&self.3, false, Some(&self.4), Some(DEVICE), self.5).is_none();
            self.1.lock().unwrap().push(refused);
            self.0.put(r, s, o, c)
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let fs = Arc::new(StdFs);
    let mut up = Uploader::new(fx.cfg(), Sweeper(Api(fx.server.clone()), seen.clone(), lc.clone(), fx.rec_dir.clone(), stem.clone(), now), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), fs);
    up.tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    let seen = seen.lock().unwrap().clone();
    assert!(seen.len() >= 2 && seen.iter().all(|r| *r), "every chunk of the drive ran under the lock: {seen:?}");
}

#[test]
fn an_upload_that_outlives_the_age_bound_is_settled_durably_before_a_sweep_may_delete() {
    let fx = Fx::new("b4-age");
    let stem = fx.recording(1000, &[3 * MIB]);
    struct Slow(Api, Arc<FakeClock>);
    impl UploadApi for Slow {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            let ok = self.0.put(r, s, o, c);
            self.1.advance(MAX_PENDING_AGE_MS + 1000); // the link is so slow that the bound passes mid-upload
            ok
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let mut up = Uploader::new(fx.cfg(), Slow(Api(fx.server.clone()), fx.clock.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
    let rep = up.tick();
    assert_eq!(rep.abandoned, 1, "{rep:?}");
    assert_eq!(fx.server.count("put"), 1, "stopped between chunks, not after finishing");
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("too_old")));
    // Settled durably, lock released: now the sweep may take it.
    let removed = crate::recording::sweep_expired_with(&fx.rec_dir, fx.clock.now_ms() + 100 * 3_600_000, &fx.lifecycle());
    assert_eq!(removed, 1);
    assert!(!fx.rec_dir.join(format!("{stem}.json")).exists());
}

#[test]
fn the_sweeps_hold_everything_when_the_queue_cannot_be_enumerated() {
    let fx = Fx::new("b4-enum");
    let stem = fx.recording(1000, &[100]);
    let (faults, fs) = fx.faults();
    faults.fail_list.store(true, Ordering::SeqCst);
    let lc = Lifecycle::new(StateStore::new(fs, fx.state_dir.clone(), fx.cfg().roots));
    let removed = crate::recording::sweep_expired_with(&fx.rec_dir, fx.clock.now_ms() + 100 * 3_600_000, &lc);
    assert_eq!(removed, 0);
    assert!(fx.rec_dir.join(format!("{stem}.json")).exists());
    let _ = AtomicUsize::new(0);
}

// ==== C: the live-session gate reads the helper's stamp ============================================

struct FakeMarker {
    /// One entry per helper (`session-live.<pid>`).
    content: Mutex<Vec<Vec<u8>>>,
    err: AtomicBool,
    overflow: AtomicBool,
}
impl crate::session_live::MarkerSource for FakeMarker {
    fn read_all(&self) -> std::io::Result<crate::session_live::Markers> {
        if self.err.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("untrusted owner or DACL"));
        }
        if self.overflow.load(Ordering::SeqCst) {
            return Ok(crate::session_live::Markers::Overflow);
        }
        Ok(crate::session_live::Markers::Stamps(self.content.lock().unwrap().clone()))
    }
}

fn marker(content: Option<&str>) -> Arc<FakeMarker> {
    Arc::new(FakeMarker { content: Mutex::new(content.map(|c| c.as_bytes().to_vec()).into_iter().collect()), err: AtomicBool::new(false), overflow: AtomicBool::new(false) })
}

#[test]
fn the_probe_believes_only_a_fresh_valid_stamp() {
    use crate::recording_upload_http::FsSessionProbe;
    let clock = FakeClock::new(T0);
    let m = marker(Some(&T0.to_string()));
    let probe = FsSessionProbe { marker: m.clone(), clock: clock.clone(), roots: vec![] };
    assert!(probe.session_live(), "fresh stamp");
    clock.advance(crate::session_live::FRESH_MS - 1);
    assert!(probe.session_live(), "still fresh just inside two minutes");
    clock.advance(1);
    assert!(!probe.session_live(), "stale at two minutes: a crashed helper must not block uploads");
    *m.content.lock().unwrap() = vec![b"not a number".to_vec()];
    assert!(!probe.session_live(), "garbage is not a stamp");
    *m.content.lock().unwrap() = vec![clock.now_ms().to_string().into_bytes()];
    assert!(probe.session_live());
    m.err.store(true, Ordering::SeqCst);
    assert!(!probe.session_live(), "an unreadable or untrusted (non-admin-written) stamp cannot stall uploads");
    m.err.store(false, Ordering::SeqCst);
    m.content.lock().unwrap().clear();
    assert!(!probe.session_live(), "no stamp: no session");
}

#[test]
fn a_recording_in_progress_also_counts_as_live() {
    use crate::recording_upload_http::FsSessionProbe;
    let fx = Fx::new("live-rec");
    let probe = FsSessionProbe { marker: marker(None), clock: fx.clock.clone(), roots: vec![ScanRoot::Flat(fx.rec_dir.clone())] };
    assert!(!probe.session_live());
    std::fs::write(fx.rec_dir.join("rec-5-0000.ivf"), b"partial").unwrap(); // a segment with no sidecar, just written
    assert!(probe.session_live());
    std::fs::write(fx.rec_dir.join("rec-5.json"), b"{}").unwrap(); // finished: its sidecar exists
    assert!(!probe.session_live());
}

#[test]
fn uploads_wait_for_the_stamp_to_go_stale_and_then_run() {
    use crate::recording_upload_http::FsSessionProbe;
    let fx = Fx::new("live-gate");
    fx.recording(1000, &[300]);
    let m = marker(Some(&fx.clock.now_ms().to_string()));
    let probe = Arc::new(FsSessionProbe { marker: m.clone(), clock: fx.clock.clone(), roots: vec![] });
    let mut up = fx.uploader_with(fx.cfg(), ident(), probe);
    let rep = up.tick();
    assert!(rep.deferred_session_live && rep.completed == 0, "{rep:?}");
    assert_eq!(fx.server.calls().len(), 0, "not one request while the helper says a session is live");
    // The helper keeps stamping: still deferred a minute later.
    *m.content.lock().unwrap() = vec![(fx.clock.now_ms() + 60_000).to_string().into_bytes()];
    fx.clock.advance(60_000);
    assert!(up.tick().deferred_session_live);
    // The helper is gone: no new stamps, the last one ages out.
    fx.clock.advance(crate::session_live::FRESH_MS);
    let rep = up.tick();
    assert_eq!(rep.completed, 1, "{rep:?}");
}

// ---- guards exercised directly where another layer would otherwise mask them ------------------------

#[test]
fn a_terminal_server_answer_whose_settlement_cannot_be_saved_is_not_counted_and_stays_pending() {
    let fx = Fx::new("a2-terminal");
    fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick(); // queued
    fx.server.inject(Op::Create, http(410, "gone")); // a terminal answer for the drain's first drive
    let (faults, fs) = fx.faults();
    faults.fail_write.store(true, Ordering::SeqCst);
    let mut up = fx.faulty_uploader(fs, Arc::new(NeverLive));
    let rep = up.finish_or_abandon(Duration::from_secs(60));
    assert_eq!((rep.abandoned, rep.already_settled), (0, 0), "an unsaved terminal state counts as nothing: {rep:?}");
    assert!(!rep.is_settled());
    assert_eq!(fx.only_state().status, Status::Pending, "and it is still pending on disk");
}

#[test]
fn listing_an_untrusted_queue_is_an_error_and_a_missing_one_is_empty() {
    let fx = Fx::new("b1-list");
    let (faults, fs) = fx.faults();
    let store = StateStore::new(fs, fx.state_dir.clone(), fx.cfg().roots);
    assert!(store.list_checked().unwrap().states.is_empty(), "no queue directory yet: an empty queue");
    fx.recording(1000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    assert_eq!(store.list_checked().unwrap().states.len(), 1);
    faults.fail_open.store(true, Ordering::SeqCst);
    assert!(store.list_checked().is_err(), "a queue directory that fails the trust check is never read as 'empty'");
    faults.fail_open.store(false, Ordering::SeqCst);
    faults.fail_list.store(true, Ordering::SeqCst);
    assert!(store.list_checked().is_err());
}

#[test]
fn a_chunk_read_never_goes_beyond_the_declared_length() {
    let dir = tempfile_dir::Dir::new("b3-bounds");
    std::fs::write(dir.path().join("rec-1-0000.ivf"), vec![7u8; 100]).unwrap();
    let d = StdFs.open(dir.path(), false).unwrap();
    let mut held = d.open_file("rec-1-0000.ivf").unwrap();
    let seg = SegmentState { file: "rec-1-0000.ivf".into(), length: 100, sha256: "0".repeat(64), committed: 0, file_id: Some(held.id) };
    assert_eq!(read_chunk(&mut held, &seg, 90, 10).unwrap().len(), 10, "exactly to the end is fine");
    assert!(matches!(read_chunk(&mut held, &seg, 90, 11), Err(Stop::Terminal(Status::Refused, _))), "one byte past the declared length is refused");
    assert!(matches!(read_chunk(&mut held, &seg, u64::MAX, 2), Err(Stop::Terminal(Status::Refused, _))), "overflow is refused, not wrapped");
}

// ==== review round 2: reconciliation, fencing, locked transitions, hashing, lock files, markers =====

fn lock_of(fx: &Fx, stem: &str) -> String {
    lock_name(&fx.rec_dir, false, DEVICE, stem)
}

// ---- 1: nothing unreconciled may be reported as settled -------------------------------------------

#[test]
fn a_busy_recording_lock_is_unresolved_in_a_drain_and_merely_deferred_in_the_background() {
    let fx = Fx::new("r2-1-lock");
    let stem = fx.recording(1000, &[300]);
    let ops = fx.ops();
    let held = ops.try_lock(&lock_of(&fx, &stem)).unwrap().expect("free");
    // Background: skipped this pass, not an error.
    let mut up = fx.uploader();
    let rep = up.tick();
    assert_eq!((rep.queued, rep.problems), (0, 0), "{rep:?}");
    // Drain: the recording could not be reconciled, so the drain is NOT settled.
    let rep = up.finish_or_abandon(Duration::from_secs(2));
    assert!(!rep.is_settled(), "{rep:?}");
    assert!(rep.problems.iter().any(|p| p.contains("unreconciled")), "{:?}", rep.problems);
    assert_eq!(fx.server.calls().len(), 0);
    // Once the lock is free a drain reconciles it and settles.
    drop(held);
    let rep = up.finish_or_abandon(Duration::from_secs(60));
    assert!(rep.is_settled(), "{rep:?}");
    assert_eq!(rep.uploaded, 1);
}

#[test]
fn a_segment_locked_by_another_process_is_unresolved_in_a_drain() {
    let fx = Fx::new("r2-1-seg");
    let stem = fx.recording(1000, &[300]);
    // Another process holds the segment with no sharing at all.
    let exclusive = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(0).open(fx.rec_dir.join(format!("{stem}-0000.ivf"))).unwrap()
    };
    let mut up = fx.uploader();
    let rep = up.tick();
    assert_eq!((rep.queued, rep.problems), (0, 0), "deferred, not queued, not an error: {rep:?}");
    let rep = up.finish_or_abandon(Duration::from_secs(2));
    assert!(!rep.is_settled(), "{rep:?}");
    assert_eq!(fx.states().len(), 0, "nothing was queued on a guess");
    drop(exclusive);
    assert!(up.finish_or_abandon(Duration::from_secs(60)).is_settled());
}

// ---- 2: every transition is under the lock, reloaded, fenced ---------------------------------------

#[test]
fn a_stale_worker_never_overwrites_what_another_worker_finished() {
    let fx = Fx::new("r2-2-stale");
    fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let listed = fx.only_state(); // a worker's (stale) view: Pending
    // Meanwhile another worker abandons it...
    let ops = fx.ops();
    assert!(matches!(ops.settle_listed(&listed, Status::Abandoned, "elsewhere", None), Ok(Settle::Done(_))));
    // ...and the slow worker, still holding the old listing, tries to drive it.
    let mut up = fx.uploader();
    assert!(matches!(up.drive(&listed, Mode::Background), Outcome::AlreadySettled));
    assert_eq!(fx.server.calls().len(), 0, "not one request on a stale listing");
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("elsewhere")), "the other worker's state stands");
    // The same for a state that was COMPLETED meanwhile: settle never turns it into Abandoned.
    let fx = Fx::new("r2-2-stale2");
    fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let listed = fx.only_state();
    fx.uploader().tick();
    assert_eq!(fx.only_state().status, Status::Complete);
    let r = fx.ops().settle_listed(&listed, Status::Abandoned, "late", None);
    assert!(matches!(r, Ok(Settle::Already(ref s)) if s.status == Status::Complete), "{:?}", r.is_ok());
    assert_eq!(fx.only_state().status, Status::Complete);
}

#[test]
fn transitions_wait_for_the_recording_lock_and_never_run_without_it() {
    let fx = Fx::new("r2-2-lock");
    let stem = fx.recording(1000, &[300]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let held = fx.ops().try_lock(&lock_of(&fx, &stem)).unwrap().unwrap();
    let mut up = fx.uploader();
    assert!(matches!(up.drive(&fx.only_state(), Mode::Background), Outcome::Busy));
    assert!(fx.ops().settle_listed(&fx.only_state(), Status::Abandoned, "x", None).is_err(), "no lock, no transition");
    // Re-enrollment cannot claim success while a recording's lock is held elsewhere.
    let r = fx.ops().abandon_for_reenrollment("reenrolled", Duration::from_secs(1));
    assert!(r.is_err(), "{r:?}");
    assert_eq!(fx.only_state().status, Status::Pending);
    drop(held);
    assert_eq!(fx.ops().abandon_for_reenrollment("reenrolled", Duration::from_secs(5)), Ok(1));
}

#[test]
fn a_drain_fence_stops_new_enqueue_and_new_drives_and_a_mid_upload_drive_at_its_next_chunk() {
    let fx = Fx::new("r2-2-fence");
    fx.recording(1000, &[3 * MIB]);
    let ops = fx.ops();
    ops.set_fence(FenceKind::Removal, 60_000).unwrap();
    let mut up = fx.uploader();
    let rep = up.tick();
    assert!(rep.fenced && rep.queued == 0 && rep.completed == 0, "{rep:?}");
    assert_eq!((fx.states().len(), fx.server.calls().len()), (0, 0));
    // Expiry: the fence is not forever (a removal that fails must not strand uploads).
    fx.clock.advance(60_001);
    assert!(!ops.fence_active().unwrap());
    // A fence raised mid-upload stops the drive at the next chunk.
    struct RaiseFence(Api, QueueOps);
    impl UploadApi for RaiseFence {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            let ok = self.0.put(r, s, o, c);
            let _ = self.1.set_fence(FenceKind::Removal, 600_000);
            ok
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let mut up = Uploader::new(fx.cfg(), RaiseFence(Api(fx.server.clone()), ops.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
    let rep = up.tick();
    assert_eq!(fx.server.count("put"), 1, "stopped at the next chunk: {rep:?}");
    assert_eq!(fx.only_state().status, Status::Pending);
    // Lifted: resumes.
    ops.store().open(true).unwrap().remove(FENCE_NAME).unwrap();
    fx.uploader().tick();
    assert_eq!(fx.only_state().status, Status::Complete);
}

#[test]
fn a_garbled_fence_is_treated_as_up_and_the_drain_leaves_it_up() {
    let fx = Fx::new("r2-2-fence2");
    let ops = fx.ops();
    ops.store().open(true).unwrap().write_atomic(FENCE_NAME, b"not a number").unwrap();
    assert!(ops.fence_active().unwrap(), "fail closed");
    ops.store().open(true).unwrap().remove(FENCE_NAME).unwrap();
    assert!(!ops.fence_active().unwrap());
    // The drain raises it and leaves it up: a recording that appears afterwards is not queued.
    let mut up = fx.uploader();
    assert!(up.finish_or_abandon(Duration::from_secs(5)).is_settled());
    assert!(ops.fence_active().unwrap(), "the fence outlives the drain (the removal follows)");
    fx.recording(5000, &[100]);
    let rep = up.tick();
    assert!(rep.fenced && rep.queued == 0, "{rep:?}");
}

#[test]
fn re_enrollment_fences_for_its_duration_and_lifts_the_fence() {
    let fx = Fx::new("r2-2-reenroll");
    fx.recording(1000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    assert_eq!(fx.ops().abandon_for_reenrollment("reenrolled", Duration::from_secs(5)), Ok(1));
    assert!(!fx.ops().fence_active().unwrap(), "uploads under the NEW identity must not stay blocked");
}

// ---- 3: every freshly opened handle set is hashed; identities required ------------------------------

#[test]
fn a_file_changed_in_place_keeping_its_length_and_mtime_is_caught_on_the_next_open() {
    let fx = Fx::new("r2-3-hash");
    let stem = fx.recording(1000, &[500]);
    // First drive: verified, then CREATE fails, so the entry stays pending with its verification recorded.
    fx.server.inject(Op::Create, ApiFail::transport("connect"));
    fx.uploader().tick();
    assert!(fx.only_state().verified_sig.is_some());
    // Rewrite one byte in place, then restore the modification time: same length, same mtime, same file id.
    let path = fx.rec_dir.join(format!("{stem}-0000.ivf"));
    let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    let mut data = std::fs::read(&path).unwrap();
    data[3] ^= 0x55;
    {
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        use std::io::Write;
        (&f).write_all(&data).unwrap();
        f.set_modified(mtime).unwrap();
    }
    fx.clock.advance(2 * 3_600_000);
    fx.uploader().tick();
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Refused, Some("local_file_changed")));
    assert_eq!(fx.server.count("put"), 0, "never sent");
}

#[test]
fn an_entry_without_identities_is_migrated_and_saved_before_any_network_call() {
    struct CheckAtCreate(Api, StateStore, Arc<Mutex<Option<bool>>>);
    impl UploadApi for CheckAtCreate {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            let on_disk = self.1.list().into_iter().next().unwrap();
            *self.2.lock().unwrap() = Some(on_disk.segments.iter().all(|g| g.file_id.is_some()) && on_disk.sidecar_id.is_some());
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            self.0.put(r, s, o, c)
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    // Each case strips ONE kind of identity, so each migration step is the only thing that can make it durable.
    for (strip_segments, strip_sidecar) in [(true, false), (false, true), (true, true)] {
        let fx = Fx::new("r2-3-migrate");
        fx.recording(1000, &[500]);
        fx.uploader_with(fx.cfg(), ident(), live()).tick();
        let mut st = fx.only_state();
        if strip_segments {
            for seg in &mut st.segments {
                seg.file_id = None;
            }
        }
        if strip_sidecar {
            st.sidecar_id = None;
        }
        fx.store().save(&st).unwrap();
        let seen: Arc<Mutex<Option<bool>>> = Arc::default();
        let mut up = Uploader::new(fx.cfg(), CheckAtCreate(Api(fx.server.clone()), fx.store(), seen.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
        up.tick();
        assert_eq!(*seen.lock().unwrap(), Some(true), "identities were durable BEFORE the first network call ({strip_segments}, {strip_sidecar})");
        assert_eq!(fx.only_state().status, Status::Complete);
        assert_eq!(fx.files_left(), 0, "and the migrated identities let the cleanup delete exactly the confirmed files");
    }
}

// ---- 4: lock files are bounded and reclaimed ------------------------------------------------------

#[test]
fn lock_files_do_not_count_toward_the_queue_limit() {
    let fx = Fx::new("r2-4-limit");
    fx.recording(1000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    for i in 0..(SCAN_ENTRY_LIMIT + 50) {
        std::fs::write(fx.state_dir.join(format!("r-{i:08}.lock")), b"").unwrap();
    }
    let l = fx.store().list_checked().expect("4096+ lock files are not queue entries");
    assert_eq!(l.states.len(), 1);
}

#[test]
fn a_sweep_reclaims_its_lock_file_and_one_recording_never_has_two() {
    let fx = Fx::new("r2-4-reclaim");
    let stem = fx.recording(1000, &[100]);
    let locks = |fx: &Fx| -> Vec<String> {
        std::fs::read_dir(&fx.state_dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.ends_with(".lock") && n != HANDOFF_LOCK).collect()).unwrap_or_default()
    };
    // Uploader and sweep use the same name for the same recording.
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    assert_eq!(locks(&fx), vec![lock_of(&fx, &stem)]);
    fx.ops().abandon_for_reenrollment("x", Duration::from_secs(5)).unwrap();
    let removed = crate::recording::sweep_expired_with(&fx.rec_dir, fx.clock.now_ms() + 100 * 3_600_000, &fx.lifecycle());
    assert_eq!(removed, 1);
    assert_eq!(locks(&fx), Vec::<String>::new(), "the recording is gone, so is its lock file");
}

#[test]
fn orphan_lock_files_are_reclaimed_and_live_ones_are_not() {
    let fx = Fx::new("r2-4-orphan");
    let stem = fx.recording(1000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let orphan = "r-00000000-0000-4000-8000-0000000000aa.lock";
    std::fs::write(fx.state_dir.join(orphan), b"").unwrap();
    // A lock someone is holding is never touched, even if it looks orphaned.
    let busy = "r-00000000-0000-4000-8000-0000000000bb.lock";
    let held = fx.ops().try_lock(busy).unwrap().unwrap();
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    assert!(!fx.state_dir.join(orphan).exists(), "reclaimed");
    assert!(fx.state_dir.join(busy).exists(), "in use: untouched");
    assert!(fx.state_dir.join(lock_of(&fx, &stem)).exists(), "belongs to a live entry and a local recording");
    drop(held);
}

// ---- 5: an unreadable pending entry keeps the hold ----------------------------------------------

#[test]
fn an_unreadable_queue_entry_that_could_be_this_recordings_hold_refuses_the_claim() {
    let fx = Fx::new("r2-5-issues");
    let stem = fx.recording(1000, &[100]);
    let lc = fx.lifecycle();
    let later = fx.clock.now_ms() + 100 * 3_600_000;
    // Another recording's broken entry does not hold this one.
    std::fs::create_dir_all(&fx.state_dir).unwrap();
    std::fs::write(fx.state_dir.join("00000000-0000-4000-8000-0000000000cc.json"), b"garbage").unwrap();
    let c = lc.claim_for_sweep(&fx.rec_dir, false, Some(&stem), Some(DEVICE), later);
    assert!(c.is_some(), "attributable to another recording: not this one's problem");
    drop(c);
    // THIS recording's entry is unreadable (corrupt): it might be the pending hold. Refuse.
    let id = recording_id_for(DEVICE, &fx.rec_dir, &stem);
    std::fs::write(fx.state_dir.join(format!("{id}.json")), b"garbage").unwrap();
    assert!(lc.claim_for_sweep(&fx.rec_dir, false, Some(&stem), Some(DEVICE), later).is_none());
    let removed = crate::recording::sweep_expired_with(&fx.rec_dir, later, &lc);
    assert_eq!(removed, 0);
    // A leaf directory cannot attribute an issue, so ANY issue holds it.
    let leaf = fx.rec_dir.join("cli").join(uuid::Uuid::new_v4().to_string());
    assert!(lc.claim_for_sweep(&leaf, true, None, None, later).is_none());
}

// ---- 6 + 7: the unwired hand-off -----------------------------------------------------------------

#[test]
fn the_unwired_hand_off_gives_every_unqueued_local_recording_a_durable_disposition() {
    let fx = Fx::new("r2-7-dispose");
    fx.recording(1000, &[100]);
    fx.recording(2000, &[100, 200]);
    fx.recording_in(&fx.rec_dir, 3000, &[100], None, DEVICE, None); // even one that could never upload
    let rep = fx.ops().drain_unwired("uninstall_unwired", Duration::from_secs(5));
    assert!(rep.is_settled(), "{rep:?}");
    assert_eq!(rep.abandoned, 3);
    let states = fx.states();
    assert_eq!(states.len(), 3);
    assert!(states.iter().all(|s| s.status == Status::Abandoned && s.reason.as_deref() == Some("uninstall_unwired")));
    assert_eq!(fx.files_left(), 3 * 2 + 1, "the local files stay (the removal deletes the directory); only the disposition is recorded");
    assert!(fx.ops().fence_active().unwrap(), "admission is fenced for the hand-off");
    assert_eq!(fx.server.calls().len(), 0);
}

#[test]
fn the_unwired_hand_off_is_not_settled_when_enumeration_or_settlement_fails_or_a_lock_is_busy() {
    // Enumeration of the recording root fails.
    let fx = Fx::new("r2-7-enum");
    fx.recording(1000, &[100]);
    let (faults, fs) = fx.faults();
    faults.fail_open_rec.store(true, Ordering::SeqCst);
    let ops = QueueOps::new(StateStore::new(fs.clone(), fx.state_dir.clone(), fx.cfg().roots), fx.clock.clone());
    let rep = ops.drain_unwired("uninstall_unwired", Duration::from_secs(2));
    assert!(!rep.is_settled(), "an incomplete enumeration blocks the removal: {rep:?}");
    // Settlement cannot be saved.
    faults.fail_open_rec.store(false, Ordering::SeqCst);
    faults.fail_write.store(true, Ordering::SeqCst);
    let rep = ops.drain_unwired("uninstall_unwired", Duration::from_secs(2));
    assert!(!rep.is_settled() && rep.abandoned == 0, "{rep:?}");
    // A recording's lock is busy.
    faults.fail_write.store(false, Ordering::SeqCst);
    let stem = "rec-1000";
    let held = ops.try_lock(&lock_of(&fx, stem)).unwrap().unwrap();
    let rep = ops.drain_unwired("uninstall_unwired", Duration::from_secs(1));
    assert!(!rep.is_settled(), "{rep:?}");
    drop(held);
    let rep = ops.drain_unwired("uninstall_unwired", Duration::from_secs(5));
    assert!(rep.is_settled() && rep.abandoned == 1, "{rep:?}");
}

#[test]
fn the_unwired_hand_off_reloads_under_the_lock_and_never_overwrites_a_finished_entry() {
    let fx = Fx::new("r2-6-reload");
    fx.recording(1000, &[100]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick();
    let stale = fx.only_state();
    fx.uploader().tick(); // completes it behind the hand-off's back
    assert_eq!(fx.only_state().status, Status::Complete);
    let mut rep = DrainReport::default();
    // The hand-off acts on a LISTING that still says Pending: it must reload, see Complete, and leave it alone.
    let r = fx.ops().settle_listed(&stale, Status::Abandoned, "uninstall_unwired", None);
    assert!(matches!(r, Ok(Settle::Already(_))));
    fx.ops().abandon_pending("uninstall_unwired", fx.clock.now_ms() + 1000, &mut rep);
    assert_eq!(fx.only_state().status, Status::Complete);
}

// ---- 8: per-helper session markers ----------------------------------------------------------------

#[test]
fn one_helper_ending_never_clears_another_helpers_live_signal() {
    use crate::recording_upload_http::FsSessionProbe;
    let clock = FakeClock::new(T0);
    let m = Arc::new(FakeMarker { content: Mutex::new(vec![T0.to_string().into_bytes(), T0.to_string().into_bytes()]), err: AtomicBool::new(false), overflow: AtomicBool::new(false) });
    let probe = FsSessionProbe { marker: m.clone(), clock: clock.clone(), roots: vec![] };
    assert!(probe.session_live());
    // Helper A ends and removes ITS marker; helper B is still stamping.
    m.content.lock().unwrap().remove(0);
    clock.advance(60_000);
    m.content.lock().unwrap()[0] = clock.now_ms().to_string().into_bytes();
    assert!(probe.session_live(), "B's fresh stamp keeps uploads paused");
    // B's stamp ages out (its helper died): now it is quiet.
    clock.advance(crate::session_live::FRESH_MS);
    assert!(!probe.session_live());
    // One stale and one fresh: live while ANY is fresh.
    *m.content.lock().unwrap() = vec![(clock.now_ms() - 10 * 60_000).to_string().into_bytes(), clock.now_ms().to_string().into_bytes()];
    assert!(probe.session_live());
    assert_eq!(crate::session_live::marker_name(4242), "session-live.4242");
}

// ==== review r3: hand-offs are serialized and the fence has an owner ===============================

fn fence_until(fx: &Fx) -> i64 {
    let raw = fx.store().open(false).unwrap().read(FENCE_NAME, 128).unwrap().expect("fence file");
    parse_fence(&raw).expect("a valid fence").until
}

#[test]
fn a_re_enrollment_can_neither_clear_nor_shorten_nor_even_start_under_a_removal_fence() {
    let fx = Fx::new("r3-fence-owner");
    fx.recording(1000, &[100]);
    assert!(fx.uploader().finish_or_abandon(Duration::from_secs(5)).is_settled());
    let raw_before = fx.store().open(false).unwrap().read(FENCE_NAME, 128).unwrap().unwrap();
    assert!(String::from_utf8_lossy(&raw_before).starts_with("removal:"), "the file records its owner kind");
    // Re-enrollment while the removal fence is up: refused, fence untouched byte for byte.
    let r = fx.ops().abandon_for_reenrollment("reenrolled", Duration::from_secs(5));
    assert!(matches!(&r, Err(p) if p.iter().any(|m| m.contains("removal"))), "{r:?}");
    assert_eq!(fx.store().open(false).unwrap().read(FENCE_NAME, 128).unwrap().unwrap(), raw_before);
    assert!(fx.ops().fence_active().unwrap());
    // Only the owner can clear: a token for the wrong operation or with the wrong secret changes nothing.
    for wrong in [FenceToken { kind: FenceKind::Reenroll, token: "deadbeef".into() }, FenceToken { kind: FenceKind::Removal, token: "deadbeef".into() }] {
        assert!(!fx.ops().clear_fence_owned(&wrong).unwrap());
        assert!(fx.ops().fence_active().unwrap(), "{wrong:?}");
    }
}

#[test]
fn extending_a_fence_never_shortens_it() {
    let fx = Fx::new("r3-fence-extend");
    let ops = fx.ops();
    ops.set_fence(FenceKind::Removal, 3_600_000).unwrap();
    let long = fence_until(&fx);
    ops.set_fence(FenceKind::Removal, 60_000).unwrap();
    assert_eq!(fence_until(&fx), long, "a shorter request cannot shrink an existing fence");
    ops.set_fence(FenceKind::Removal, 7_200_000).unwrap();
    assert!(fence_until(&fx) > long, "a longer one extends it");
    // A garbled fence (fail closed) can be re-established by a hand-off; an EXPIRED removal fence lets a re-enrollment in.
    let fx = Fx::new("r3-fence-expired");
    fx.ops().set_fence(FenceKind::Removal, 1000).unwrap();
    fx.clock.advance(2000);
    assert_eq!(fx.ops().abandon_for_reenrollment("reenrolled", Duration::from_secs(5)), Ok(0));
}

#[test]
fn a_re_enrollment_during_a_removal_drain_is_refused_and_admission_stays_fenced() {
    let fx = Fx::new("r3-interleave");
    fx.recording(1000, &[2 * MIB]);
    fx.uploader_with(fx.cfg(), ident(), live()).tick(); // queued
    // While the drain is uploading (mid-chunk), a re-enrollment starts on another thread of control.
    type Attempts = Arc<Mutex<Vec<Result<u32, Vec<String>>>>>;
    struct Intruder(Api, QueueOps, Attempts);
    impl UploadApi for Intruder {
        fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
            self.0.create(r, s, l)
        }
        fn head(&self, r: RecRef<'_>, s: u32) -> Result<HeadOk, ApiFail> {
            self.0.head(r, s)
        }
        fn put(&self, r: RecRef<'_>, s: u32, o: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
            let ok = self.0.put(r, s, o, c);
            self.2.lock().unwrap().push(self.1.abandon_for_reenrollment("reenrolled", Duration::from_secs(1)));
            ok
        }
        fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
            self.0.finish(r, q)
        }
    }
    let seen: Attempts = Arc::default();
    let mut up = Uploader::new(fx.cfg(), Intruder(Api(fx.server.clone()), fx.ops(), seen.clone()), ident(), Arc::new(NeverLive), fx.clock.clone(), Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
    let rep = up.finish_or_abandon(Duration::from_secs(60));
    assert!(rep.is_settled() && rep.uploaded == 1, "the drain finishes its work undisturbed: {rep:?}");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the intruder ran");
    assert!(
        seen.iter().all(|r| matches!(r, Err(p) if p.iter().any(|m| m.contains("another hand-off")))),
        "every intrusion was stopped by the hand-off lock the drain holds for its whole run: {seen:?}"
    );
    assert_eq!(fx.only_state().status, Status::Complete, "the intruder abandoned nothing");
    assert!(fx.ops().fence_active().unwrap(), "admission is STILL fenced after the intrusions and after the drain");
    // And a recording that appears afterwards is not queued.
    fx.recording(9000, &[100]);
    let rep = fx.uploader().tick();
    assert!(rep.fenced && rep.queued == 0, "{rep:?}");
}

#[test]
fn every_hand_off_is_serialized_by_one_lock() {
    let fx = Fx::new("r3-handoff-lock");
    fx.recording(1000, &[100]);
    let ops = fx.ops();
    let held = ops.try_lock(HANDOFF_LOCK).unwrap().expect("free");
    // Each kind of hand-off refuses to run beside another one, and leaves the fence alone.
    let rep = ops.drain_unwired("uninstall_unwired", Duration::from_secs(1));
    assert!(!rep.is_settled() && rep.problems.iter().any(|p| p.contains("another hand-off")), "{rep:?}");
    let rep = fx.uploader().finish_or_abandon(Duration::from_secs(1));
    assert!(!rep.is_settled() && rep.problems.iter().any(|p| p.contains("another hand-off")), "{rep:?}");
    assert!(ops.abandon_for_reenrollment("reenrolled", Duration::from_secs(1)).is_err());
    assert!(!ops.fence_active().unwrap(), "a refused hand-off raised nothing");
    assert_eq!(fx.states().len(), 0, "and touched nothing");
    drop(held);
    assert!(fx.uploader().finish_or_abandon(Duration::from_secs(5)).is_settled());
}

#[test]
fn a_marker_overflow_makes_the_probe_live() {
    use crate::recording_upload_http::FsSessionProbe;
    let clock = FakeClock::new(T0);
    let m = marker(None);
    let probe = FsSessionProbe { marker: m.clone(), clock, roots: vec![] };
    assert!(!probe.session_live());
    m.overflow.store(true, Ordering::SeqCst);
    assert!(probe.session_live(), "too many stamps to examine: pause uploads, never assume quiet");
}

// ---- release review 1.3.19 C: a queue crowded with terminal entries recovers by itself ---------------------------------

/// Plant `n` queue entries directly (no recording files needed): terminal ones carry no segments, pending ones one dummy segment.
fn plant(fx: &Fx, from: usize, n: usize, status: Status, finished_at: Option<i64>, local_cleaned: bool) {
    std::fs::create_dir_all(&fx.state_dir).unwrap();
    for i in from..from + n {
        let stem = format!("rec-{}", 9_000_000 + i); // never collides with fx.recording(ms)
        let id = recording_id_for(DEVICE, &fx.rec_dir, &stem);
        let segments = if matches!(status, Status::Pending | Status::Complete) {
            vec![SegmentState { file: format!("{stem}-0000.ivf"), length: 1, sha256: "ab".repeat(32), committed: 0, file_id: None }]
        } else {
            vec![]
        };
        let st = UploadState {
            schema: 1,
            recording_id: id.clone(),
            generation: 1,
            tenant_id: TENANT.into(),
            device_id: DEVICE.into(),
            key_fp_hex: "ab".repeat(32),
            audience: "https://cp.example.test".into(),
            session_id: SESSION.into(),
            local_dir: fx.rec_dir.display().to_string(),
            stem,
            leaf_dir: false,
            dir_id: None,
            sidecar_id: None,
            segments,
            truncated: None,
            dropped_frames: 0,
            frames: 0,
            payload_bytes: 0,
            ended_at_ms: T0 - 10_000 + i as i64,
            enqueued_at_ms: T0,
            status,
            reason: if status == Status::Pending { None } else { Some("planted".into()) },
            finished_at_ms: finished_at.map(|t| t + i as i64),
            created: false,
            verified_sig: None,
            failures: 0,
            next_attempt_at_ms: 0,
            digest_failures: 0,
            last_error: None,
            ack_digests: (status == Status::Complete).then(|| vec!["ab".repeat(32)]),
            local_cleaned,
        };
        std::fs::write(fx.state_dir.join(format!("{id}.json")), serde_json::to_vec(&st).unwrap()).unwrap();
    }
}

#[test]
fn a_queue_past_the_enumeration_limit_with_terminal_entries_recovers_by_itself() {
    let fx = Fx::new("overflow");
    fx.recording(1000, &[100]); // a real pending hold that must survive
    // Recent terminal entries (nothing age-based can prune them), more than the enumeration limit.
    plant(&fx, 0, SCAN_ENTRY_LIMIT + 200, Status::Refused, Some(T0), false);
    assert!(fx.store().list_checked().is_err(), "premise: the directory can no longer be enumerated completely");
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true)))); // a live session: nothing is driven
    let mut passes = 0;
    while fx.store().list_checked().is_err() {
        up.tick();
        passes += 1;
        assert!(passes <= 10, "the queue never recovered");
    }
    up.tick();
    let l = fx.store().list_checked().unwrap();
    assert!(l.states.len() <= SCAN_ENTRY_LIMIT);
    assert_eq!(l.states.iter().filter(|s| s.status == Status::Pending).count(), 1, "the real pending upload was queued and kept");
}

#[test]
fn a_drain_over_a_queue_past_the_limit_reclaims_first_and_is_not_blocked_by_enumeration() {
    let fx = Fx::new("overflow-drain");
    plant(&fx, 0, SCAN_ENTRY_LIMIT + 1500, Status::Abandoned, Some(T0), false);
    plant(&fx, 100_000, 10, Status::Complete, Some(T0), true);
    let mut up = fx.uploader();
    let rep = up.finish_or_abandon(Duration::from_secs(60));
    assert!(rep.problems.is_empty(), "{:?}", rep.problems);
    assert!(fx.store().list_checked().is_ok());
}

#[test]
fn reclaiming_never_deletes_a_pending_entry_or_a_completed_one_whose_cleanup_is_owed() {
    let fx = Fx::new("overflow-keep");
    plant(&fx, 0, 100, Status::Pending, None, false);
    plant(&fx, 1000, 100, Status::Complete, Some(T0), false); // cleanup still owed
    plant(&fx, 2000, RECLAIM_HIGH_WATER, Status::Refused, Some(T0), false);
    let ops = fx.ops();
    for _ in 0..16 {
        ops.reclaim_queue();
    }
    let l = fx.store().list_checked().unwrap_or_else(|_| panic!("unreadable"));
    assert_eq!(l.states.iter().filter(|s| s.status == Status::Pending).count(), 100);
    assert_eq!(l.states.iter().filter(|s| s.status == Status::Complete).count(), 100);
    assert!(l.states.len() <= RECLAIM_HIGH_WATER, "{}", l.states.len());
}

#[test]
fn a_scan_never_queues_the_directory_past_the_enumeration_limit() {
    let fx = Fx::new("admission");
    // Pending entries cannot be reclaimed; leave room for only a few more.
    let planted = SCAN_ENTRY_LIMIT - ADMISSION_HEADROOM - 20;
    plant(&fx, 0, planted, Status::Pending, None, false);
    for i in 0..60 {
        fx.recording(10_000 + i, &[10]);
    }
    let mut up = fx.uploader_with(fx.cfg(), ident(), Arc::new(FnProbe(Box::new(|| true))));
    let rep = up.tick();
    assert_eq!(rep.queued, 21, "only what fits under the limit is queued; the rest stays local for a later pass");
    assert!(fx.store().list_checked().is_ok(), "the queue is still completely enumerable");
}

// ---- release review 1.3.19 C: a PUT "success" that makes no progress is a failure --------------------------------------

#[test]
fn a_put_that_succeeds_without_advancing_counts_as_a_failure_and_ends_in_a_bounded_backoff() {
    let fx = Fx::new("stuck-put");
    fx.recording(1000, &[300]);
    fx.server.inner.lock().unwrap().stuck_put = true;
    let mut up = fx.uploader();
    up.tick();
    // One attempt, one PUT: handed back to the scheduler with a backoff instead of looping in the worker.
    assert_eq!(fx.server.count("put"), 1, "no hot loop inside one pass: {:?}", fx.server.calls());
    let st = fx.only_state();
    assert_eq!((st.status, st.failures), (Status::Pending, 1));
    assert!(st.next_attempt_at_ms > fx.clock.now_ms(), "a backoff is scheduled");
    // The count is NOT reset by the next "success": it climbs until the retry budget ends the upload.
    let mut passes = 0;
    while fx.only_state().status == Status::Pending {
        fx.clock.advance(BACKOFF_CAP_MS + 1);
        up.tick();
        passes += 1;
        assert!(passes <= MAX_CONSECUTIVE_FAILURES as usize + 2, "the failure bound never fired");
    }
    let st = fx.only_state();
    assert_eq!((st.status, st.reason.as_deref()), (Status::Abandoned, Some("retries_exhausted")));
}
