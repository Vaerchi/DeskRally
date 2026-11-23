//! The real [`UploadApi`]: signed HTTPS calls to the control plane (docs/63 §5.1), plus the service
//! worker that drives the [`Uploader`] and the public hand-off the fleet uninstall path calls.
//!
//! Every request carries the ten `X-Rmt-*` headers the server mirrors into its preimage, an exact
//! `Content-Length`, no query string, and goes to `<base>/agent/recordings…` where `<base>` is the
//! configured control-plane URL INCLUDING any reverse-proxy prefix (`…/cp`). The SIGNED path is the
//! stripped one (`/agent/recordings…`) and the signed audience is the bare origin.
//! Redirects are never followed: a signed request must reach the host it was signed for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmt_crypto::Identity;

use crate::recording_upload::*;
use crate::recording_upload_sig::*;

/// One request/response budget for create, head and finish.
const SMALL_TIMEOUT: Duration = Duration::from_secs(60);
/// A 1 MiB chunk: the server's total bound for a chunk body is 3 minutes.
const PUT_TIMEOUT: Duration = Duration::from_secs(200);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Error bodies are tiny JSON objects; never buffer more than this from a server.
const MAX_ERROR_BODY: usize = 64 * 1024;

pub struct HttpUploadApi {
    client: reqwest::blocking::Client,
    base: String,
    identity: Identity,
    tenant: String,
    tenant_raw: [u8; 16],
    device: String,
    key_fp: [u8; 32],
    audience: String,
    clock: Arc<dyn Clock>,
}

impl HttpUploadApi {
    /// `base` is the control-plane base URL as configured; `audience` the bare normalised origin
    /// ([`audience_from_base`]).
    pub fn new(
        base: &str,
        audience: &str,
        identity: Identity,
        tenant_id: &str,
        device_id: &str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        let tenant_raw = parse_canonical_uuid(tenant_id).ok_or("tenant_id is not a canonical lower-case uuid")?;
        let client = reqwest::blocking::Client::builder()
            // Same trust roots as enrollment: the OS store UNION the bundled public roots.
            .use_preconfigured_tls(rmt_transport_webrtc::tls_trust::client_config()?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| format!("could not build the upload HTTP client: {e}"))?;
        let key_fp = key_fingerprint(&identity.public());
        Ok(Self {
            client,
            base: base.trim().trim_end_matches('/').to_string(),
            identity,
            tenant: tenant_id.to_string(),
            tenant_raw,
            device: device_id.to_string(),
            key_fp,
            audience: audience.to_string(),
            clock,
        })
    }

    fn call(
        &self,
        op: UploadOp,
        r: RecRef<'_>,
        segment: u32,
        offset: u64,
        body: Vec<u8>,
        json: bool,
    ) -> Result<reqwest::blocking::Response, ApiFail> {
        let rec_raw = parse_canonical_uuid(r.recording_id).ok_or_else(|| ApiFail::transport("recording id is not canonical"))?;
        let path = canonical_path(op, r.recording_id, segment);
        let fields = UploadSigFields {
            audience: self.audience.clone(),
            op,
            path: path.clone(),
            tenant_id: self.tenant_raw,
            device_id: self.device.clone(),
            key_fp: self.key_fp,
            recording_id: rec_raw,
            generation: r.generation,
            segment,
            offset,
            body_len: body.len() as u64,
            body_sha256: sha256_bytes(&body),
            timestamp_ms: self.clock.now_ms().max(1) as u64,
        };
        let sig = fields.sign(&self.identity);
        let url = format!("{}{}", self.base, path);
        let mut req = match op {
            UploadOp::Create | UploadOp::Finish => self.client.post(&url),
            UploadOp::Put => self.client.put(&url),
            UploadOp::Head => self.client.head(&url),
        }
        .timeout(if op == UploadOp::Put { PUT_TIMEOUT } else { SMALL_TIMEOUT })
        .header("X-Rmt-Device", &self.device)
        .header("X-Rmt-Tenant", &self.tenant)
        .header("X-Rmt-Key-Fp", hex::encode(self.key_fp))
        .header("X-Rmt-Recording", r.recording_id)
        .header("X-Rmt-Generation", r.generation.to_string())
        .header("X-Rmt-Segment", segment.to_string())
        .header("X-Rmt-Offset", offset.to_string())
        .header("X-Rmt-Body-Sha256", hex::encode(fields.body_sha256))
        .header("X-Rmt-Timestamp", fields.timestamp_ms.to_string())
        .header("X-Rmt-Signature", hex::encode(sig))
        // The signed `body_len` IS the Content-Length, on every operation: a bodyless HEAD would otherwise leave the
        // length implicit, and the strict server reads the header (a missing one is 411, chunked is refused).
        .header("Content-Length", fields.body_len.to_string());
        if op != UploadOp::Head {
            req = req
                .header("Content-Type", if json { "application/json" } else { "application/octet-stream" })
                .body(body);
        }
        let resp = req.send().map_err(|e| ApiFail::transport(describe(&e)))?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(read_failure(resp))
    }
}

fn describe(e: &reqwest::Error) -> String {
    // No URL in the text: it is the configured control plane and adds nothing, but a stray query or
    // credential in a mis-set URL must not reach a log.
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_connect() {
        "connect".into()
    } else if e.is_request() {
        "request".into()
    } else {
        "io".into()
    }
}

fn read_failure(resp: reqwest::blocking::Response) -> ApiFail {
    use std::io::Read;
    let status = resp.status().as_u16();
    let retry_after_s = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let mut buf = Vec::new();
    let _ = resp.take(MAX_ERROR_BODY as u64).read_to_end(&mut buf);
    let v: serde_json::Value = serde_json::from_slice(&buf).unwrap_or(serde_json::Value::Null);
    let mut f = ApiFail::http(status, v.get("error").and_then(|e| e.as_str()).unwrap_or(""));
    f.retry_after_s = retry_after_s;
    f.committed_offset = v.get("committed_offset").and_then(|x| x.as_u64());
    f.state = v.get("state").and_then(|x| x.as_str()).map(str::to_string);
    if let Some(arr) = v.get("segments").and_then(|x| x.as_array()) {
        f.segments = arr
            .iter()
            .filter_map(|e| e.as_u64().or_else(|| e.get("index").and_then(|i| i.as_u64())))
            .map(|i| i as u32)
            .collect();
    }
    f
}

fn json_body(resp: reqwest::blocking::Response) -> Result<serde_json::Value, ApiFail> {
    use std::io::Read;
    let mut buf = Vec::new();
    resp.take(MAX_ERROR_BODY as u64)
        .read_to_end(&mut buf)
        .map_err(|e| ApiFail::transport(describe_io(&e)))?;
    serde_json::from_slice(&buf).map_err(|_| ApiFail::transport("unparseable success body"))
}

fn describe_io(_e: &std::io::Error) -> String {
    "io".into()
}

fn header_u64(resp: &reqwest::blocking::Response, name: &str) -> Option<u64> {
    resp.headers().get(name)?.to_str().ok()?.trim().parse().ok()
}

impl UploadApi for HttpUploadApi {
    fn create(&self, r: RecRef<'_>, session_id: &str, lengths: &[u64]) -> Result<CreateOk, ApiFail> {
        let segments: Vec<_> = lengths
            .iter()
            .enumerate()
            .map(|(i, l)| serde_json::json!({"index": i, "length": l}))
            .collect();
        let body = serde_json::to_vec(&serde_json::json!({
            "recording_id": r.recording_id,
            "session_id": session_id,
            "generation": r.generation,
            "segments": segments,
        }))
        .map_err(|_| ApiFail::transport("serialize"))?;
        let resp = self.call(UploadOp::Create, r, 0, 0, body, true)?;
        let v = json_body(resp)?;
        let bad = || ApiFail::transport("create answer is not the documented shape");
        let segs = v
            .get("segments")
            .and_then(|s| s.as_array())
            .ok_or_else(bad)?
            .iter()
            .map(|s| {
                Some((
                    s.get("index")?.as_u64()? as u32,
                    s.get("length")?.as_u64()?,
                    s.get("committed_offset")?.as_u64()?,
                ))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(bad)?;
        Ok(CreateOk {
            state: v.get("state").and_then(|x| x.as_str()).ok_or_else(bad)?.to_string(),
            generation: v.get("generation").and_then(|x| x.as_u64()).ok_or_else(bad)?,
            chunk_size: v.get("chunk_size").and_then(|x| x.as_u64()).ok_or_else(bad)?,
            segments: segs,
        })
    }

    fn head(&self, r: RecRef<'_>, segment: u32) -> Result<HeadOk, ApiFail> {
        let resp = self.call(UploadOp::Head, r, segment, 0, Vec::new(), false)?;
        let bad = || ApiFail::transport("head answer lacks the X-Rmt-* headers");
        Ok(HeadOk {
            committed: header_u64(&resp, "x-rmt-committed-offset").ok_or_else(bad)?,
            length: header_u64(&resp, "x-rmt-segment-length").ok_or_else(bad)?,
            state: resp.headers().get("x-rmt-state").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
        })
    }

    fn put(&self, r: RecRef<'_>, segment: u32, offset: u64, chunk: &[u8]) -> Result<PutOk, ApiFail> {
        let resp = self.call(UploadOp::Put, r, segment, offset, chunk.to_vec(), false)?;
        let v = json_body(resp)?;
        let bad = || ApiFail::transport("put answer is not the documented shape");
        Ok(PutOk {
            committed: v.get("committed_offset").and_then(|x| x.as_u64()).ok_or_else(bad)?,
            resent: v.get("resent").and_then(|x| x.as_bool()).unwrap_or(false),
        })
    }

    fn finish(&self, r: RecRef<'_>, req: &FinishReq) -> Result<FinishOk, ApiFail> {
        let body = serde_json::to_vec(&serde_json::json!({
            "recording_id": r.recording_id,
            "generation": r.generation,
            "digests": req.digests,
            "truncated": req.truncated,
            "dropped_frames": req.dropped_frames,
            "frames": req.frames,
            "payload_bytes": req.payload_bytes,
        }))
        .map_err(|_| ApiFail::transport("serialize"))?;
        let resp = self.call(UploadOp::Finish, r, 0, 0, body, true)?;
        let v = json_body(resp)?;
        let bad = || ApiFail::transport("finish answer is not the documented shape");
        Ok(FinishOk {
            recording_id: v.get("recording_id").and_then(|x| x.as_str()).ok_or_else(bad)?.to_string(),
            generation: v.get("generation").and_then(|x| x.as_u64()).ok_or_else(bad)?,
            state: v.get("state").and_then(|x| x.as_str()).ok_or_else(bad)?.to_string(),
            digests: v
                .get("digests")
                .and_then(|x| x.as_array())
                .ok_or_else(bad)?
                .iter()
                .map(|d| d.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(bad)?,
        })
    }
}

// ---- service wiring ----------------------------------------------------------------------------

/// A segment with no sidecar that was written this recently belongs to a recording in progress.
const RECORDING_ACTIVE_FRESH: Duration = Duration::from_secs(5 * 60);

/// Live-session gate for the service. Two signals, either one defers uploads:
///
/// 1. the helper's stamp ([`crate::session_live`]: `C:\rmt-agent\session-live`, written SYSTEM/Administrators-only
///    and atomically while ANY session task is alive, refreshed every 30 s) is fresh (under two minutes). A stamp
///    that is missing, stale, unreadable or fails the owner/DACL check is "no session": it cannot stall uploads;
/// 2. a recording is in progress: an `.ivf` segment without its sidecar was modified in the last 5 minutes in one
///    of the recording roots (observable from the service alone).
pub struct FsSessionProbe {
    pub marker: Arc<dyn crate::session_live::MarkerSource>,
    pub clock: Arc<dyn Clock>,
    pub roots: Vec<ScanRoot>,
}

fn fresh(md: &std::fs::Metadata, within: Duration) -> bool {
    md.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age < within)
}

impl SessionProbe for FsSessionProbe {
    fn session_live(&self) -> bool {
        // ANY fresh per-helper stamp means a session is live: one helper ending never clears another's signal.
        match self.marker.read_all() {
            // Too many stamps to examine is not a quiet machine: fail toward pausing uploads.
            Ok(crate::session_live::Markers::Overflow) => return true,
            Ok(crate::session_live::Markers::Stamps(stamps)) => {
                let now = self.clock.now_ms();
                if stamps.iter().any(|bytes| crate::session_live::is_fresh(bytes, now)) {
                    return true;
                }
            }
            Err(_) => {}
        }
        let mut dirs = Vec::new();
        for root in &self.roots {
            match root {
                ScanRoot::Flat(d) => dirs.push(d.clone()),
                ScanRoot::Leaves(d) => {
                    if let Ok(rd) = std::fs::read_dir(d) {
                        dirs.extend(rd.flatten().take(512).map(|e| e.path()));
                    }
                }
            }
        }
        for dir in dirs {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten().take(4096) {
                let name = e.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(started) = crate::recording::segment_started_at(name) else { continue };
                if dir.join(format!("rec-{started}.json")).exists() {
                    continue;
                }
                if e.metadata().is_ok_and(|m| fresh(&m, RECORDING_ACTIVE_FRESH)) {
                    return true;
                }
            }
        }
        false
    }
}

/// Everything the worker and the uninstall hand-off need, derived from the machine's own config.
pub struct Wiring {
    pub uploader: Uploader<HttpUploadApi>,
}

/// Build an uploader from `config.json` + the identity key. `Err` is not a failure of the service: it
/// means "this machine cannot upload (not enrolled, no control plane, no identity)" and says why.
pub fn wire_from_config(cfg: &crate::config::HelperConfig, stop: Arc<AtomicBool>) -> Result<Wiring, String> {
    let base = cfg
        .control_plane_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("not control-plane managed")?;
    let device = cfg.device_id.as_deref().map(str::trim).filter(|s| !s.is_empty()).ok_or("no device id")?;
    let tenant = cfg.tenant_id.as_deref().map(str::trim).filter(|s| !s.is_empty()).ok_or("no tenant id")?;
    let audience = audience_from_base(base)?;
    let identity = crate::enroll::read_identity(&cfg.identity_path_or_default())?.ok_or("no identity key")?;
    let ident = UploadIdentity {
        tenant_id: tenant.to_string(),
        device_id: device.to_string(),
        key_fp_hex: hex::encode(key_fingerprint(&identity.public())),
        audience: audience.clone(),
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let api = HttpUploadApi::new(base, &audience, identity, tenant, device, clock.clone())?;
    let ucfg = UploaderConfig::production();
    let probe = Arc::new(FsSessionProbe { marker: Arc::new(crate::session_live::AnchorMarker), clock: clock.clone(), roots: ucfg.roots.clone() });
    Ok(Wiring { uploader: Uploader::new(ucfg, api, ident, probe, clock, stop, Arc::new(crate::recording_fs::AnchoredFs)) })
}

/// Interval between background passes.
const WORKER_PERIOD: Duration = Duration::from_secs(30);

/// The service's upload thread. Started once from the service main; stopped (and joined within a
/// bounded wait) when the service stops. A pass that cannot wire (not enrolled yet, config being
/// rewritten) is skipped quietly and retried next period — config is re-read every pass, so an
/// enrollment or a re-enrollment is picked up without a restart.
pub struct UploadWorker {
    stop: Arc<AtomicBool>,
    done: std::sync::mpsc::Receiver<()>,
}

impl UploadWorker {
    pub fn start() -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (tx, done) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new().name("recording-upload".into()).spawn(move || {
            let mut last_unwired = String::new();
            while !flag.load(Ordering::Acquire) {
                match crate::config::HelperConfig::load().ok_or("no config".to_string()).and_then(|c| wire_from_config(&c, flag.clone())) {
                    Ok(mut w) => {
                        last_unwired.clear();
                        let rep = w.uploader.tick();
                        if rep != TickReport::default() {
                            tracing::info!(?rep, "recording upload: pass");
                        }
                    }
                    Err(why) => {
                        if why != last_unwired {
                            tracing::info!(reason = %why, "recording upload: idle");
                            last_unwired = why;
                        }
                    }
                }
                let mut waited = Duration::ZERO;
                while waited < WORKER_PERIOD && !flag.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(250));
                    waited += Duration::from_millis(250);
                }
            }
            let _ = tx.send(());
        })?;
        Ok(Self { stop, done })
    }
}

impl Drop for UploadWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if self.done.recv_timeout(Duration::from_secs(8)).is_err() {
            tracing::error!("recording upload worker did not stop within the service shutdown budget");
        }
    }
}

/// **The hand-off for the fleet uninstall path (docs/65 D-C9).** Call it BEFORE removing the agent:
/// it tries to complete every pending upload within `budget`, then explicitly abandons the rest.
///
/// FALLIBLE: `Ok(report)` means everything is settled — each recording is durably complete (local copy
/// deleted), durably not going to be stored, or durably abandoned — and `report.abandoned` says how many
/// uploads were given up. `Err` means something could not be settled safely (an incomplete enumeration, an
/// unreadable queue entry, a recording that could not be queued, a settlement that could not be saved): the
/// removal must NOT proceed. A machine that cannot even be wired (not enrolled) abandons its queued entries
/// without the network, under the same rule.
pub fn finish_or_abandon_pending(budget: Duration) -> Result<DrainReport, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let rep = match crate::config::HelperConfig::load().ok_or("no config".to_string()).and_then(|c| wire_from_config(&c, stop)) {
        Ok(mut w) => w.uploader.finish_or_abandon(budget),
        Err(why) => {
            tracing::warn!(reason = %why, "recording upload: cannot reach the control plane for the final drain; disposing of every local recording without the network");
            abandon_pending_unwired(&production_ops(), UNWIRED_BUDGET)
        }
    };
    if rep.is_settled() {
        Ok(rep)
    } else {
        Err(rep.problems.join("; "))
    }
}

/// Time the network-free hand-off may spend taking recording locks (an upload in flight is stopped by the fence
/// within one chunk).
const UNWIRED_BUDGET: Duration = Duration::from_secs(20);

fn production_store() -> StateStore {
    let cfg = UploaderConfig::production();
    StateStore::new(Arc::new(crate::recording_fs::AnchoredFs), cfg.state_dir, cfg.roots)
}

fn production_ops() -> QueueOps {
    QueueOps::new(production_store(), Arc::new(SystemClock))
}

/// The network-free hand-off for a machine that cannot be wired (no identity to upload under): FENCE admission,
/// give every local recording that has no queue entry a durable terminal one, and abandon every pending entry --
/// each under the recording's lock with its state reloaded under it. Anything that cannot be enumerated, locked,
/// read or saved durably is a problem (the removal must not proceed). The fence stays up (it expires by itself).
pub fn abandon_pending_unwired(ops: &QueueOps, budget: Duration) -> DrainReport {
    ops.drain_unwired("uninstall_unwired", budget)
}

/// Re-enrollment hook (C9): the old key can no longer sign for these recordings, so pending uploads are
/// abandoned explicitly. `Ok(n)`: n abandoned durably and nothing pending remains; `Err`: what could not be
/// done (the enrollment must not claim the old uploads are settled). (The uploader also abandons any entry
/// queued under another key by itself the next time it sees one.)
pub fn abandon_pending_for_reenrollment() -> Result<u32, String> {
    production_ops().abandon_for_reenrollment("reenrolled", Duration::from_secs(30)).map_err(|p| p.join("; "))
}
