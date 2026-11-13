//! The recording uploader's REAL HTTP wire (docs/63 §5.1), against a hand-rolled loopback server, plus
//! the entry point the Go interop test drives against the real control-plane upload handler.
//!
//! Two jobs, kept apart:
//!
//! * `wire_*` — run by default. A loopback responder records the raw requests `HttpUploadApi` sends and
//!   this file checks them with an independent parse: every `X-Rmt-*` header exactly once, exact
//!   `Content-Length`, the canonical (proxy-stripped) path, no query, a signature that verifies under the
//!   agent's public key over the preimage REBUILT from the headers, the audience being the bare origin.
//!   Canned answers cover the success shapes and the error bodies (`Retry-After`, `committed_offset`).
//! * `go_driven_upload` — `#[ignore]`d; `control-plane/recording_rust_agent_test.go` (build tag
//!   `rustinterop`) starts the real Go handler, prepares a recording directory and runs this test with
//!   `--ignored` and the `RMT_E2E_*` environment. It proves the Rust signer and uploader are accepted
//!   by the real verifier — the one thing the shared golden vectors cannot show.

#![cfg(windows)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmt_agent_windows::recording_fs::{FsProvider, StdFs};
use rmt_agent_windows::recording_upload::*;
use rmt_agent_windows::recording_upload_http::HttpUploadApi;
use rmt_agent_windows::recording_upload_sig::*;
use rmt_crypto::Identity;

#[derive(Debug, Clone)]
struct Raw {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    }
    fn header(&self, name: &str) -> &str {
        let v = self.header_all(name);
        assert_eq!(v.len(), 1, "header {name} must appear exactly once, saw {v:?}");
        v[0]
    }
}

/// Canned answers, popped in order; every request is recorded.
type Canned = (u16, Vec<(&'static str, String)>, String);

fn serve(answers: Vec<Canned>) -> (String, Arc<Mutex<Vec<Raw>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Raw>>> = Arc::default();
    let seen2 = seen.clone();
    let answers = Mutex::new(std::collections::VecDeque::from(answers));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut rd = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if rd.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("").to_string();
            let mut headers = Vec::new();
            let mut clen = 0usize;
            loop {
                let mut h = String::new();
                rd.read_line(&mut h).unwrap();
                let h = h.trim_end().to_string();
                if h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        clen = v.trim().parse().unwrap();
                    }
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            let mut body = vec![0u8; clen];
            rd.read_exact(&mut body).unwrap();
            seen2.lock().unwrap().push(Raw { method: method.clone(), target, headers, body });
            let (status, extra, text) = answers.lock().unwrap().pop_front().unwrap_or((500, vec![], "{}".into()));
            let mut resp = format!("HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: application/json\r\n");
            for (k, v) in extra {
                resp.push_str(&format!("{k}: {v}\r\n"));
            }
            // A HEAD answer carries no body (but the server may still describe one).
            let body_out = if method == "HEAD" { String::new() } else { text.clone() };
            resp.push_str(&format!("Content-Length: {}\r\n\r\n{}", if method == "HEAD" { 0 } else { text.len() }, body_out));
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (format!("http://{addr}"), seen)
}

const TENANT: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const REC: &str = "f0e1d2c3-b4a5-4968-8776-655443322110";
const SESSION: &str = "11111111-2222-4333-8444-555555555555";

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
    fn sleep(&self, _d: Duration) {}
}

fn identity() -> Identity {
    Identity::from_seed(&[42u8; 32])
}

fn api(base: &str) -> HttpUploadApi {
    let origin = audience_from_base(base).unwrap();
    HttpUploadApi::new(&format!("{base}/cp"), &origin, identity(), TENANT, "dev-wire", Arc::new(FixedClock(1_790_000_000_000))).unwrap()
}

/// Rebuild the preimage from what is ON THE WIRE and verify the signature, the way the server does.
fn check_signed(raw: &Raw, op: UploadOp, audience: &str) {
    for h in ["X-Rmt-Device", "X-Rmt-Tenant", "X-Rmt-Key-Fp", "X-Rmt-Recording", "X-Rmt-Generation", "X-Rmt-Segment", "X-Rmt-Offset", "X-Rmt-Body-Sha256", "X-Rmt-Timestamp", "X-Rmt-Signature"] {
        raw.header(h);
    }
    assert!(!raw.target.contains('?'), "no query string: {}", raw.target);
    let path = raw.target.strip_prefix("/cp").expect("requests go to <base>/cp/...; the proxy strips the prefix");
    let seg: u32 = raw.header("X-Rmt-Segment").parse().unwrap();
    assert_eq!(path, canonical_path(op, raw.header("X-Rmt-Recording"), seg), "the signed path is the stripped canonical one");
    let mut fp = [0u8; 32];
    hex::decode_to_slice(raw.header("X-Rmt-Key-Fp"), &mut fp).unwrap();
    assert_eq!(fp, key_fingerprint(&identity().public()));
    let mut sha = [0u8; 32];
    hex::decode_to_slice(raw.header("X-Rmt-Body-Sha256"), &mut sha).unwrap();
    assert_eq!(sha, sha256_bytes(&raw.body), "the signed digest is of the bytes actually sent");
    // Content-Length is present exactly once on EVERY operation, a bodyless HEAD included, and equals the signed length.
    assert_eq!(raw.header("Content-Length").parse::<usize>().unwrap(), raw.body.len(), "{} {}", raw.method, raw.target);
    let fields = UploadSigFields {
        audience: audience.to_string(),
        op,
        path: path.to_string(),
        tenant_id: parse_canonical_uuid(raw.header("X-Rmt-Tenant")).unwrap(),
        device_id: raw.header("X-Rmt-Device").to_string(),
        key_fp: fp,
        recording_id: parse_canonical_uuid(raw.header("X-Rmt-Recording")).unwrap(),
        generation: raw.header("X-Rmt-Generation").parse().unwrap(),
        segment: seg,
        offset: raw.header("X-Rmt-Offset").parse().unwrap(),
        body_len: raw.body.len() as u64,
        body_sha256: sha,
        timestamp_ms: raw.header("X-Rmt-Timestamp").parse().unwrap(),
    };
    let mut sig = [0u8; 64];
    hex::decode_to_slice(raw.header("X-Rmt-Signature"), &mut sig).unwrap();
    assert!(fields.verify(&identity().public(), &sig), "the signature verifies over the preimage rebuilt from the wire");
    assert_eq!(fields.timestamp_ms, 1_790_000_000_000);
}

fn rec() -> RecRef<'static> {
    RecRef { recording_id: REC, generation: 1 }
}

#[test]
fn wire_all_four_operations_are_signed_exactly_as_the_contract_says() {
    let ok = |s: &str| (200u16, vec![], s.to_string());
    let (base, seen) = serve(vec![
        (201, vec![], format!(r#"{{"recording_id":"{REC}","generation":1,"state":"uploading","chunk_size":1048576,"segments":[{{"index":0,"length":5,"committed_offset":0}},{{"index":1,"length":7,"committed_offset":3}}]}}"#)),
        (200, vec![("X-Rmt-Committed-Offset", "3".into()), ("X-Rmt-Segment-Length", "7".into()), ("X-Rmt-State", "uploading".into())], String::new()),
        ok(r#"{"committed_offset":5,"resent":false}"#),
        ok(&format!(r#"{{"recording_id":"{REC}","generation":1,"state":"evidence_complete","digests":["{}"],"provenance":"x"}}"#, "ab".repeat(32))),
    ]);
    let api = api(&base);
    let audience = audience_from_base(&base).unwrap();

    let c = api.create(rec(), SESSION, &[5, 7]).unwrap();
    assert_eq!(c.segments, vec![(0, 5, 0), (1, 7, 3)]);
    assert_eq!((c.state.as_str(), c.chunk_size, c.generation), ("uploading", 1 << 20, 1));
    let h = api.head(rec(), 1).unwrap();
    assert_eq!((h.committed, h.length, h.state.as_str()), (3, 7, "uploading"));
    let p = api.put(rec(), 0, 0, b"hello").unwrap();
    assert_eq!((p.committed, p.resent), (5, false));
    let digests = vec!["ab".repeat(32)];
    let f = api
        .finish(rec(), &FinishReq { digests: digests.clone(), truncated: Some("size_limit".into()), dropped_frames: 2, frames: 30, payload_bytes: 400 })
        .unwrap();
    assert_eq!((f.recording_id.as_str(), f.state.as_str(), f.digests.clone()), (REC, "evidence_complete", digests));

    let reqs = seen.lock().unwrap().clone();
    assert_eq!(reqs.len(), 4);
    let methods: Vec<&str> = reqs.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(methods, ["POST", "HEAD", "PUT", "POST"]);
    for (r, op) in reqs.iter().zip([UploadOp::Create, UploadOp::Head, UploadOp::Put, UploadOp::Finish]) {
        check_signed(r, op, &audience);
    }
    // Bodies: the exact JSON shapes the strict server decoder accepts (no extra fields).
    let create: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(create, serde_json::json!({"recording_id": REC, "session_id": SESSION, "generation": 1, "segments": [{"index":0,"length":5},{"index":1,"length":7}]}));
    assert_eq!(reqs[2].body, b"hello");
    assert_eq!(reqs[2].header("X-Rmt-Offset"), "0");
    let finish: serde_json::Value = serde_json::from_slice(&reqs[3].body).unwrap();
    assert_eq!(
        finish,
        serde_json::json!({"recording_id": REC, "generation": 1, "digests": ["ab".repeat(32)], "truncated": "size_limit", "dropped_frames": 2, "frames": 30, "payload_bytes": 400})
    );
    // A HEAD signs the digest of the empty body.
    assert_eq!(reqs[1].header("X-Rmt-Body-Sha256"), hex::encode(sha256_bytes(b"")));
    assert_eq!(reqs[1].header("X-Rmt-Segment"), "1");
}

#[test]
fn wire_a_finish_without_truncation_sends_null_not_a_missing_field() {
    let (base, seen) = serve(vec![(500, vec![], "{}".into())]);
    let api = api(&base);
    let _ = api.finish(rec(), &FinishReq { digests: vec!["cd".repeat(32)], truncated: None, dropped_frames: 0, frames: 1, payload_bytes: 1 });
    let body: serde_json::Value = serde_json::from_slice(&seen.lock().unwrap()[0].body).unwrap();
    assert!(body.get("truncated").is_some_and(|v| v.is_null()), "{body}");
}

#[test]
fn wire_error_answers_carry_their_code_retry_after_offsets_and_segments() {
    let (base, _seen) = serve(vec![
        (507, vec![("Retry-After", "30".into())], r#"{"error":"server_full"}"#.into()),
        (409, vec![], r#"{"error":"bad_offset","committed_offset":1048576}"#.into()),
        (409, vec![], r#"{"error":"incomplete","segments":[{"index":1,"committed_offset":0,"length":9}]}"#.into()),
        (422, vec![], r#"{"error":"digest_mismatch","segments":[0,2],"state":"uploading"}"#.into()),
        (302, vec![("Location", "http://127.0.0.1:1/elsewhere".into())], String::new()),
        (401, vec![], "not json at all".into()),
    ]);
    let api = api(&base);
    let f = api.create(rec(), SESSION, &[5]).unwrap_err();
    assert_eq!((f.status, f.code.as_str(), f.retry_after_s), (507, "server_full", Some(30)));
    let f = api.put(rec(), 0, 0, b"x").unwrap_err();
    assert_eq!((f.status, f.code.as_str(), f.committed_offset), (409, "bad_offset", Some(1_048_576)));
    let f = api.finish(rec(), &FinishReq { digests: vec![], truncated: None, dropped_frames: 0, frames: 0, payload_bytes: 0 }).unwrap_err();
    assert_eq!((f.code.as_str(), f.segments.clone()), ("incomplete", vec![1]));
    let f = api.finish(rec(), &FinishReq { digests: vec![], truncated: None, dropped_frames: 0, frames: 0, payload_bytes: 0 }).unwrap_err();
    assert_eq!((f.code.as_str(), f.segments.clone(), f.state.as_deref()), ("digest_mismatch", vec![0, 2], Some("uploading")));
    // A redirect is NOT followed (a signed request must reach the host it was signed for): it surfaces as
    // a plain 302, which the classifier refuses as an unexpected status.
    let f = api.head(rec(), 0).unwrap_err();
    assert_eq!(f.status, 302);
    assert!(matches!(classify(Op::Head, &f), Disposition::Terminal { .. }));
    // A non-JSON error body still yields the status.
    let f = api.create(rec(), SESSION, &[5]).unwrap_err();
    assert_eq!((f.status, f.code.as_str()), (401, ""));
}

#[test]
fn wire_a_dead_server_is_a_transport_failure_which_is_always_retryable() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    drop(l); // nothing is listening
    let f = api(&base).create(rec(), SESSION, &[5]).unwrap_err();
    assert_eq!(f.status, 0);
    assert!(matches!(classify(Op::Create, &f), Disposition::Retry { .. }));
}

#[test]
fn wire_a_success_answer_in_the_wrong_shape_is_a_failure_not_a_guess() {
    let (base, _s) = serve(vec![(200, vec![], r#"{"committed_offset":"nope"}"#.into()), (200, vec![], r#"{}"#.into())]);
    let api = api(&base);
    assert!(api.put(rec(), 0, 0, b"x").is_err());
    assert!(api.create(rec(), SESSION, &[5]).is_err());
}

// ---- driven by the Go interop test -------------------------------------------------------------

/// Uploads every recording found in `RMT_E2E_DIR` to the Go handler at `RMT_E2E_BASE`, signing with the
/// seed in `RMT_E2E_SEED_HEX`, and prints `RECORDING_ID=<id>` per recording for the driver to verify
/// server-side. Asserts every queue entry ends `Complete` and that the local files are gone.
#[test]
#[ignore = "driven by control-plane/recording_rust_agent_test.go (-tags rustinterop), which provides the RMT_E2E_* environment"]
fn go_driven_upload() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set; this test is driven by the Go interop test"));
    let mut seed = [0u8; 32];
    hex::decode_to_slice(env("RMT_E2E_SEED_HEX"), &mut seed).unwrap();
    let identity = Identity::from_seed(&seed);
    let (base, audience) = (env("RMT_E2E_BASE"), env("RMT_E2E_AUDIENCE"));
    let (tenant, device) = (env("RMT_E2E_TENANT"), env("RMT_E2E_DEVICE"));
    let (dir, state_dir) = (std::path::PathBuf::from(env("RMT_E2E_DIR")), std::path::PathBuf::from(env("RMT_E2E_STATE_DIR")));
    let ident = UploadIdentity {
        tenant_id: tenant.clone(),
        device_id: device.clone(),
        key_fp_hex: hex::encode(key_fingerprint(&identity.public())),
        audience: audience.clone(),
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut cfg = UploaderConfig::production();
    // Test-only provider: the anchored production route refuses a user-writable temp directory (as it must).
    let fs: Arc<dyn FsProvider> = Arc::new(StdFs);
    cfg.state_dir = state_dir.clone();
    cfg.roots = vec![ScanRoot::Flat(dir.clone())];
    cfg.rate_bytes_per_sec = 0; // the rate cap is unit-tested; do not make an e2e wait on it
    let store = StateStore::new(fs.clone(), state_dir.clone(), cfg.roots.clone());
    let heads = Arc::new(AtomicUsize::new(0));
    let mk_api = |stop_after_first_put: Option<Arc<AtomicBool>>| {
        let api = HttpUploadApi::new(&base, &audience, Identity::from_seed(&seed), &tenant, &device, clock.clone()).unwrap();
        Counting { inner: api, heads: heads.clone(), stop_after_put: stop_after_first_put }
    };
    let rep = if std::env::var("RMT_E2E_MODE").as_deref() == Ok("restart") {
        // Phase 1: the process "dies" (pauses) after the first chunk is acknowledged.
        let stop = Arc::new(AtomicBool::new(false));
        let mut up1 = Uploader::new(cfg.clone(), mk_api(Some(stop.clone())), ident.clone(), Arc::new(NeverLive), clock.clone(), stop, Arc::new(StdFs));
        up1.tick();
        let mid = store.list();
        assert!(mid.iter().all(|s| s.status == Status::Pending), "paused mid-upload: {mid:?}");
        assert_eq!(heads.load(Ordering::SeqCst), 0, "no HEAD before the restart");
        // Phase 2: a brand-new uploader resumes: it must ask the strict server where it stands (a real HEAD).
        let mut up2 = Uploader::new(cfg, mk_api(None), ident, Arc::new(NeverLive), clock, Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
        let rep = up2.tick();
        assert!(heads.load(Ordering::SeqCst) >= 1, "the restart must resync with a real signed HEAD");
        println!("HEADS={}", heads.load(Ordering::SeqCst));
        rep
    } else {
        let mut up = Uploader::new(cfg, mk_api(None), ident, Arc::new(NeverLive), clock, Arc::new(AtomicBool::new(false)), Arc::new(StdFs));
        up.tick()
    };
    println!("TICK {rep:?}");
    let states = store.list();
    assert!(!states.is_empty(), "nothing was queued: {rep:?}");
    for st in &states {
        println!("RECORDING_ID={} STATUS={:?} REASON={:?}", st.recording_id, st.status, st.reason);
    }
    let expect_status = std::env::var("RMT_E2E_EXPECT").unwrap_or_else(|_| "complete".into());
    for st in &states {
        let want = match expect_status.as_str() {
            "complete" => Status::Complete,
            "not_stored" => Status::NotStored,
            other => panic!("unknown RMT_E2E_EXPECT {other}"),
        };
        assert_eq!(st.status, want, "{st:?}");
    }
    let left = std::fs::read_dir(&dir).unwrap().count();
    if expect_status == "complete" {
        assert_eq!(left, 0, "the local copy is deleted after the server's binding acknowledgement");
    } else {
        assert!(left > 0, "a recording the server declined to store keeps its local copy");
    }
}

/// Counts HEADs and (optionally) raises a stop flag after the first acknowledged chunk, so a test can
/// interrupt an upload mid-way and then resume it with a fresh uploader.
struct Counting {
    inner: HttpUploadApi,
    heads: Arc<AtomicUsize>,
    stop_after_put: Option<Arc<AtomicBool>>,
}

impl UploadApi for Counting {
    fn create(&self, r: RecRef<'_>, s: &str, l: &[u64]) -> Result<CreateOk, ApiFail> {
        self.inner.create(r, s, l)
    }
    fn head(&self, r: RecRef<'_>, seg: u32) -> Result<HeadOk, ApiFail> {
        self.heads.fetch_add(1, Ordering::SeqCst);
        self.inner.head(r, seg)
    }
    fn put(&self, r: RecRef<'_>, seg: u32, off: u64, c: &[u8]) -> Result<PutOk, ApiFail> {
        let ok = self.inner.put(r, seg, off, c);
        if let Some(s) = &self.stop_after_put {
            s.store(true, Ordering::SeqCst);
        }
        ok
    }
    fn finish(&self, r: RecRef<'_>, q: &FinishReq) -> Result<FinishOk, ApiFail> {
        self.inner.finish(r, q)
    }
}
