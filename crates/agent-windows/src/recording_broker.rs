//! Explicit CLI recording through an opt-in, local SYSTEM service writer.
//! No filesystem path, caller SID, retention setting or OS handle is accepted on the wire.
//! This is local working-copy storage, not authenticated central audit evidence.
use crate::recording::{self, RecorderHandle, Sidecar};
use rmt_transport_webrtc::video::{RecordedFrame, RecordingSink};
use serde::{Deserialize, Serialize};
use std::os::windows::io::AsRawHandle;
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
};
use windows::{
    core::HSTRING,
    Win32::{
        Foundation::{CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL},
        Security::{
            self,
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SE_FILE_OBJECT, SE_KERNEL_OBJECT,
            },
            PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
        },
        System::{
            Pipes::ImpersonateNamedPipeClient,
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    },
};

const PIPE: &str = r"\\.\pipe\DeskRally.Recording.v1";
pub(crate) const DIRECTORY: &str = r"C:\rmt-agent\cli-recordings";
const VERSION: u32 = 1;
const MAX_FRAME: usize = 2 * 1024 * 1024;
const MAX_MESSAGE: usize = MAX_FRAME * 4 + 4096; // JSON byte arrays, bounded before allocation
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DURATION: Duration = Duration::from_secs(3600);
// Specific data/attribute/read-control/synchronize rights, excluding FILE_CREATE_PIPE_INSTANCE (4).
const CLIENT_ACCESS: u32 = 0x0012_019b;
const PIPE_SDDL: &str = "O:SYG:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;IU)";

fn error(s: impl Into<String>) -> io::Error {
    io::Error::other(s.into())
}
fn win(e: windows::core::Error) -> io::Error {
    error(e.to_string())
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", deny_unknown_fields)]
enum Request {
    Start {
        version: u32,
        device: String,
        session: Option<String>,
    },
    Frame {
        micros: u64,
        width: u32,
        height: u32,
        keyframe: bool,
        data: Vec<u8>,
    },
    Poll,
    Stop {
        truncated: bool,
    },
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", deny_unknown_fields)]
enum Reply {
    Ready { started_at: i64, directory: String },
    Alive,
    Finished { sidecar: Sidecar },
}
async fn send<T: Serialize, W: AsyncWrite + Unpin>(w: &mut W, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(error_from_json)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(error("recording broker message too large"));
    }
    tokio::time::timeout(IO_TIMEOUT, async {
        w.write_u32_le(bytes.len() as u32).await?;
        w.write_all(&bytes).await
    })
    .await
    .map_err(|_| error("recording broker write timeout"))?
}
fn error_from_json(e: serde_json::Error) -> io::Error {
    error(e.to_string())
}
async fn receive<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> io::Result<T> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let len = r.read_u32_le().await? as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Err(error("invalid recording broker message length"));
        }
        let mut bytes = vec![0; len];
        r.read_exact(&mut bytes).await?;
        serde_json::from_slice(&bytes).map_err(error_from_json)
    })
    .await
    .map_err(|_| error("recording broker read timeout"))?
}

/// Verify ownership on the connected pipe handle, not a name or a PID sampled separately.
fn verify_server(pipe: &NamedPipeClient) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            HANDLE(pipe.as_raw_handle()),
            SE_KERNEL_OBJECT,
            Security::OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
        .ok()
        .map_err(win)?;
        let valid = Security::IsWellKnownSid(owner, Security::WinLocalSystemSid).as_bool();
        let _ = LocalFree(HLOCAL(sd.0));
        if !valid {
            return Err(error("recording broker pipe is not owned by SYSTEM"));
        }
    }
    Ok(())
}
fn connect() -> io::Result<NamedPipeClient> {
    // Identification only: a squatted server never receives authority to act as this client.
    // ClientOptions uses GENERIC_WRITE (includes create-instance); request exact rights instead.
    let handle = unsafe { CreateFileW(&HSTRING::from(PIPE), CLIENT_ACCESS, FILE_SHARE_MODE(0), None,
        OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0x40000000 | 0x00100000 | 0x00010000), None) }
        .map_err(|e| error(format!("service recording unavailable (compatible service with allow_cli_recording required): {e}")))?;
    let pipe = unsafe { NamedPipeClient::from_raw_handle(handle.0) }?;
    verify_server(&pipe)?;
    Ok(pipe)
}
fn listen() -> io::Result<NamedPipeServer> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(PIPE_SDDL),
            1,
            &mut sd,
            None,
        )
    }
    .map_err(win)?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: BOOL(0),
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                PIPE,
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    unsafe {
        let _ = LocalFree(HLOCAL(sd.0));
    }
    result
}
fn authenticate_client(pipe: &NamedPipeServer) -> io::Result<()> {
    // Runs synchronously on the dedicated broker thread; never suspend with an impersonation token.
    unsafe { ImpersonateNamedPipeClient(HANDLE(pipe.as_raw_handle())) }.map_err(win)?;
    let result = (|| unsafe {
        let mut token = HANDLE::default();
        OpenThreadToken(GetCurrentThread(), Security::TOKEN_QUERY, true, &mut token)
            .map_err(win)?;
        let check = (|| {
            let mut sid_buffer = [0u64; 16];
            let sid = PSID(sid_buffer.as_mut_ptr().cast());
            let mut size = std::mem::size_of_val(&sid_buffer) as u32;
            Security::CreateWellKnownSid(Security::WinInteractiveSid, None, sid, &mut size)
                .map_err(win)?;
            let mut member = BOOL(0);
            Security::CheckTokenMembership(token, sid, &mut member).map_err(win)?;
            let mut session = 0u32;
            let mut got = 0;
            Security::GetTokenInformation(
                token,
                Security::TokenSessionId,
                Some((&mut session as *mut u32).cast()),
                4,
                &mut got,
            )
            .map_err(win)?;
            if !member.as_bool() || session == 0 {
                return Err(error("recording broker requires a local interactive logon"));
            }
            Ok(())
        })();
        let _ = CloseHandle(token);
        check
    })();
    // Continuing with an unknown effective identity is forbidden, even on an error path.
    if unsafe { Security::RevertToSelf() }.is_err() {
        std::process::abort();
    }
    result
}

/// One explicit backend used by both optional and mandatory host recording paths.
pub(crate) enum SessionRecorder {
    Direct(RecorderHandle),
    Service(RemoteRecorder),
}
impl SessionRecorder {
    pub(crate) fn start(
        dir: &Path,
        via_service: bool,
        device: &str,
        session: Option<&str>,
        max: u64,
        min: u64,
    ) -> io::Result<Self> {
        if via_service {
            RemoteRecorder::start(device, session).map(Self::Service)
        } else {
            recording::start(dir, device, session, max, min).map(Self::Direct)
        }
    }
    pub(crate) fn sink(&self) -> Arc<dyn RecordingSink> {
        match self {
            Self::Direct(h) => h.sink(),
            Self::Service(h) => h.sink.clone(),
        }
    }
    pub(crate) fn dir(&self) -> &Path {
        match self {
            Self::Direct(h) => h.dir(),
            Self::Service(h) => &h.dir,
        }
    }
    pub(crate) fn started_at_unix_ms(&self) -> i64 {
        match self {
            Self::Direct(h) => h.started_at_unix_ms(),
            Self::Service(h) => h.started_at,
        }
    }
    pub(crate) fn is_stopped(&self) -> bool {
        match self {
            Self::Direct(h) => h.is_stopped(),
            Self::Service(h) => h.sink.failed.load(Ordering::Acquire),
        }
    }
    pub(crate) fn stop(self) -> io::Result<Sidecar> {
        match self {
            Self::Direct(h) => h.stop(),
            Self::Service(h) => h.stop(),
        }
    }
}

struct ClientSink {
    tx: tokio::sync::mpsc::Sender<Request>,
    epoch: Mutex<Option<Instant>>,
    failed: AtomicBool,
    finish: AtomicBool,
}
impl ClientSink {
    fn request_finish(&self) {
        // Serialize the stop boundary with a frame offer already in progress. Once finish
        // becomes visible, every accepted offer is already queued and can be drained.
        let _guard = self.epoch.lock().unwrap_or_else(|e| {
            self.failed.store(true, Ordering::Release);
            e.into_inner()
        });
        self.finish.store(true, Ordering::Release);
    }
}
impl RecordingSink for ClientSink {
    fn offer(&self, frame: RecordedFrame<'_>) {
        if self.failed.load(Ordering::Acquire) || self.finish.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut epoch) = self.epoch.lock() else {
            self.failed.store(true, Ordering::Release);
            return;
        };
        // An offer may have waited behind request_finish after its first check.
        if self.finish.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return;
        }
        if frame.data.len() > MAX_FRAME {
            self.failed.store(true, Ordering::Release);
            return;
        }
        let start = *epoch.get_or_insert(frame.at);
        let micros = frame
            .at
            .saturating_duration_since(start)
            .as_micros()
            .min(u64::MAX as u128) as u64;
        let req = Request::Frame {
            micros,
            width: frame.width,
            height: frame.height,
            keyframe: frame.keyframe,
            data: frame.data.to_vec(),
        };
        if self.tx.try_send(req).is_err() {
            self.failed.store(true, Ordering::Release);
        }
    }
}
pub(crate) struct RemoteRecorder {
    sink: Arc<ClientSink>,
    dir: PathBuf,
    started_at: i64,
    done: std::sync::mpsc::Receiver<io::Result<Sidecar>>,
}
impl RemoteRecorder {
    fn start(device: &str, session: Option<&str>) -> io::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let sink = Arc::new(ClientSink {
            tx,
            epoch: Mutex::new(None),
            failed: AtomicBool::new(false),
            finish: AtomicBool::new(false),
        });
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done) = std::sync::mpsc::sync_channel(1);
        let worker_sink = sink.clone();
        let start = Request::Start {
            version: VERSION,
            device: device.to_owned(),
            session: session.map(str::to_owned),
        };
        std::thread::Builder::new()
            .name("recording-client".into())
            .spawn(move || {
                let result = (|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    rt.block_on(client_worker(start, rx, &worker_sink, ready_tx))
                })();
                worker_sink.failed.store(true, Ordering::Release);
                let _ = done_tx.send(result);
            })?;
        match ready_rx.recv_timeout(Duration::from_secs(7)) {
            Ok((started_at, dir)) => Ok(Self {
                sink,
                dir,
                started_at,
                done,
            }),
            Err(_) => {
                sink.request_finish();
                match done.recv_timeout(Duration::from_millis(100)) {
                    Ok(Err(e)) => Err(e),
                    _ => Err(error("service recording startup failed or timed out")),
                }
            }
        }
    }
    fn stop(self) -> io::Result<Sidecar> {
        self.sink.request_finish();
        self.done
            .recv_timeout(Duration::from_secs(8))
            .map_err(|_| error("service recording finalization unavailable"))?
    }
}
impl Drop for RemoteRecorder {
    fn drop(&mut self) {
        self.sink.request_finish();
    }
}
async fn client_worker(
    start: Request,
    rx: tokio::sync::mpsc::Receiver<Request>,
    sink: &ClientSink,
    ready: std::sync::mpsc::SyncSender<(i64, PathBuf)>,
) -> io::Result<Sidecar> {
    let mut pipe = connect()?;
    client_protocol(&mut pipe, start, rx, sink, ready).await
}

// Pure stream protocol, reached in production only AFTER connect authenticates the pipe.
// A duplex stream can exercise ordering/failure semantics without a privileged service.
async fn client_protocol<P: AsyncRead + AsyncWrite + Unpin>(
    mut pipe: &mut P,
    start: Request,
    mut rx: tokio::sync::mpsc::Receiver<Request>,
    sink: &ClientSink,
    ready: std::sync::mpsc::SyncSender<(i64, PathBuf)>,
) -> io::Result<Sidecar> {
    send(&mut pipe, &start).await?;
    match receive::<Reply, _>(&mut pipe).await? {
        Reply::Ready {
            started_at,
            directory,
        } => {
            ready
                .send((started_at, PathBuf::from(directory)))
                .map_err(|_| error("recording caller left during startup"))?;
        }
        _ => return Err(error("invalid recording broker startup reply")),
    }
    let mut finish_since = None;
    loop {
        let stopping = sink.finish.load(Ordering::Acquire);
        // The finish acquire precedes this read so an error from the final in-flight
        // offer cannot be missed when deciding whether Stop is clean or truncated.
        let failed = sink.failed.load(Ordering::Acquire);
        if stopping && finish_since.is_none() {
            finish_since = Some(Instant::now());
        }
        let deadline = finish_since.is_some_and(|at| at.elapsed() > Duration::from_secs(2));
        let request = if failed || deadline || (stopping && rx.is_empty()) {
            Request::Stop {
                truncated: failed || deadline,
            }
        } else {
            tokio::select! { r=rx.recv()=>r.unwrap_or(Request::Stop{truncated:true}), _=tokio::time::sleep(Duration::from_millis(250))=>Request::Poll }
        };
        let stop = matches!(request, Request::Stop { .. });
        send(&mut pipe, &request).await?;
        match receive::<Reply, _>(&mut pipe).await? {
            Reply::Alive if !stop => {}
            Reply::Finished { sidecar } if stop => return Ok(sidecar),
            _ => return Err(error("invalid recording broker state reply")),
        }
    }
}

/// Owns the service worker. No installer or elevation is triggered here.
pub(crate) struct ServiceWorker {
    stop: Arc<AtomicBool>,
    done: std::sync::mpsc::Receiver<()>,
}
impl ServiceWorker {
    pub(crate) fn start() -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let (tx, done) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("recording-service".into())
            .spawn(move || {
                let result = (|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    rt.block_on(server(&flag))
                })();
                if let Err(e) = result {
                    tracing::error!(error=%e,"CLI recording broker stopped");
                }
                let _ = tx.send(());
            })?;
        Ok(Self { stop, done })
    }
}
impl Drop for ServiceWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if self.done.recv_timeout(Duration::from_secs(8)).is_err() {
            tracing::error!("CLI recording broker did not finalize within service shutdown budget");
        }
    }
}
async fn server(stop: &AtomicBool) -> io::Result<()> {
    // CONFIG_DIR was hardened by service_main before this worker. No untrusted path is used.
    let root = Path::new(DIRECTORY);
    crate::agent_root::harden_agent_root(root)?;
    let mut pipe = listen()?; // Keep the first instance for the entire worker lifetime (including idle).
    loop {
        tokio::select! {
            result=pipe.connect()=>result?,
            _=wait_stop(stop)=>return Ok(()),
            _=tokio::time::sleep(Duration::from_secs(60))=>{
                if let Err(e)=storage_budget(root) {tracing::warn!(error=%e,"CLI recording storage maintenance");}
                continue;
            },
        }
        let result = serve_connection(&mut pipe, root, stop).await;
        if let Err(e) = result {
            tracing::warn!(error=%e,"CLI recording connection failed");
        }
        pipe.disconnect()?;
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
    }
}
async fn wait_stop(stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn validate_start(version: u32, device: &str, session: Option<&str>) -> io::Result<()> {
    if version != VERSION
        || uuid::Uuid::parse_str(device).is_err()
        || session.is_some_and(|s| uuid::Uuid::parse_str(s).is_err())
    {
        return Err(error(
            "invalid recording start metadata or protocol version",
        ));
    }
    Ok(())
}
fn validate_frame(
    micros: u64,
    previous: u64,
    width: u32,
    height: u32,
    data: &[u8],
) -> io::Result<()> {
    if micros < previous
        || micros > MAX_DURATION.as_micros() as u64
        || width == 0
        || height == 0
        || width > 16384
        || height > 16384
        || data.is_empty()
        || data.len() > MAX_FRAME
    {
        return Err(error("invalid recording frame bounds or timestamp"));
    }
    Ok(())
}

/// Pin a privileged-owned real directory. Never walk a leftover user-owned child under SYSTEM.
fn trusted_directory(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .access_mode(0x20080)
        .share_mode(3)
        .custom_flags(0x02200000)
        .open(path)?; // BACKUP_SEMANTICS | OPEN_REPARSE_POINT, no share-delete
    let md = file.metadata()?;
    if !md.is_dir() || crate::agent_root::is_reparse_point(&md) {
        return Err(error("broker storage is not a real directory"));
    }
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            Security::OWNER_SECURITY_INFORMATION | Security::DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
        .ok()
        .map_err(win)?;
        let mut trusted = Security::IsWellKnownSid(owner, Security::WinLocalSystemSid).as_bool()
            || Security::IsWellKnownSid(owner, Security::WinBuiltinAdministratorsSid).as_bool();
        // Owner alone is insufficient: reject explicit or inherited grants to other users.
        trusted &= !dacl.is_null();
        if trusted {
            for index in 0..(*dacl).AceCount {
                let mut ace = std::ptr::null_mut();
                if Security::GetAce(dacl, index as u32, &mut ace).is_err() {
                    trusted = false;
                    break;
                }
                let header = &*(ace as *const Security::ACE_HEADER);
                if header.AceType != 0
                    || (header.AceSize as usize)
                        < std::mem::size_of::<Security::ACCESS_ALLOWED_ACE>()
                {
                    trusted = false;
                    break;
                }
                let allowed = &*(ace as *const Security::ACCESS_ALLOWED_ACE);
                let sid = PSID((&allowed.SidStart as *const u32).cast_mut().cast());
                if !Security::IsWellKnownSid(sid, Security::WinLocalSystemSid).as_bool()
                    && !Security::IsWellKnownSid(sid, Security::WinBuiltinAdministratorsSid)
                        .as_bool()
                {
                    trusted = false;
                    break;
                }
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        if !trusted {
            return Err(error(
                "broker storage directory has an untrusted owner or DACL",
            ));
        }
    }
    Ok(file)
}
/// Bound persisted storage and expire whole completed directories without parsing sidecars.
/// The root is pinned and hardened; each child is pinned and must have a privileged owner.
fn storage_budget(root: &Path) -> io::Result<()> {
    let _root = trusted_directory(root)?;
    let mut used = 0u64;
    let mut entries = 0usize;
    let ttl = Duration::from_secs(recording::DEFAULT_TTL_HOURS * 3600);
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        entries += 1;
        if entries > 512 {
            return Err(error("recording directory budget exhausted"));
        }
        if uuid::Uuid::parse_str(&entry.file_name().to_string_lossy()).is_err() {
            return Err(error("unexpected broker storage entry"));
        }
        let guard = trusted_directory(&entry.path())?;
        let mut newest = guard.metadata()?.modified()?;
        let mut files = Vec::new();
        let mut bytes = 0u64;
        for file in std::fs::read_dir(entry.path())? {
            let file = file?;
            if files.len() >= 260 {
                return Err(error("recording segment budget exhausted"));
            }
            let md = std::fs::symlink_metadata(file.path())?;
            if !md.is_file() || crate::agent_root::is_reparse_point(&md) {
                return Err(error("unsafe broker recording file"));
            }
            let name = file.file_name();
            let name = name.to_string_lossy();
            let sidecar = name
                .strip_prefix("rec-")
                .and_then(|n| n.strip_suffix(".json"))
                .is_some_and(|n| n.parse::<i64>().is_ok());
            if recording::segment_started_at(&name).is_none() && !sidecar && name != ".write-probe"
            {
                return Err(error("unexpected broker recording file"));
            }
            newest = newest.max(md.modified()?);
            bytes = bytes
                .checked_add(md.len())
                .ok_or_else(|| error("recording storage overflow"))?;
            files.push(file.path());
        }
        // A pending central upload (docs/63 C9) holds the directory past the TTL, up to its 7-day bound.
        // The claim also takes the leaf's lifecycle lock, which it keeps while the directory is deleted.
        let claim = if newest.elapsed().is_ok_and(|age| age >= ttl) {
            crate::recording_upload::Lifecycle::production().claim_for_sweep(&entry.path(), true, None, None, recording::now_unix_ms())
        } else {
            None
        };
        if let Some(claim) = claim {
            for file in files {
                std::fs::remove_file(file)?;
            }
            drop(guard);
            std::fs::remove_dir(entry.path())?;
            claim.reclaim();
        } else {
            used = used
                .checked_add(bytes)
                .ok_or_else(|| error("recording storage overflow"))?;
        }
    }
    if used > 3 * recording::DEFAULT_MAX_BYTES - 1024 * 1024 {
        return Err(error("service recording storage budget exhausted"));
    }
    Ok(())
}
async fn serve_connection(
    mut pipe: &mut NamedPipeServer,
    root: &Path,
    stop: &AtomicBool,
) -> io::Result<()> {
    let Request::Start {
        version,
        device,
        session,
    } = receive::<Request, _>(&mut pipe).await?
    else {
        return Err(error("recording Start required"));
    };
    authenticate_client(pipe)?;
    validate_start(version, &device, session.as_deref())?;
    storage_budget(root)?;
    let dir = root.join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir(&dir)?; // exclusive, server-generated leaf beneath hardened parent
    let handle = recording::start(
        &dir,
        &device,
        session.as_deref(),
        recording::DEFAULT_MAX_BYTES,
        recording::DEFAULT_MIN_FREE_BYTES,
    )?;
    // Confirm file creation AFTER the ACL was set, before reporting readiness.
    let probe = dir.join(".write-probe");
    let prepared = (|| {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        file.sync_all()?;
        drop(file);
        std::fs::remove_file(&probe)
    })();
    if let Err(e) = prepared {
        let _ = handle.stop_with_reason(Some("writer_preflight_failed"));
        return Err(e);
    }
    let started_at = handle.started_at_unix_ms();
    let sink = handle.sink();
    let epoch = Instant::now();
    let mut previous = 0;
    let mut dimensions = None;
    let mut segments = 0;
    let stream_result:io::Result<bool>=async {
        send(&mut pipe,&Reply::Ready{started_at,directory:dir.display().to_string()}).await?;
        loop {
            let request=tokio::select! { r=receive::<Request,_>(&mut pipe)=>r?, _=wait_stop(stop)=>return Err(error("service stopping")) };
            if epoch.elapsed()>MAX_DURATION {return Err(error("recording time budget exhausted"));}
            match request {
                Request::Frame{micros,width,height,keyframe,data}=>{
                    validate_frame(micros,previous,width,height,&data)?;previous=micros;
                    if dimensions!=Some((width,height)) {segments+=1;dimensions=Some((width,height));}
                    if segments>256 {return Err(error("recording segment budget exhausted"));}
                    sink.offer(RecordedFrame{at:epoch+Duration::from_micros(micros),width,height,keyframe,data:&data});
                },
                Request::Poll=>{},Request::Stop{truncated}=>return Ok(truncated),
                Request::Start{..}=>return Err(error("duplicate recording Start")),
            }
            if handle.is_stopped() {return Err(error("service recording writer stopped"));}
            send(&mut pipe,&Reply::Alive).await?;
        }
    }.await;
    let reason = match &stream_result {
        Ok(false) => None,
        Ok(true) => Some("client_queue_or_frame_failure"),
        Err(_) => Some("broker_disconnect_or_failure"),
    };
    let sidecar = handle.stop_with_reason(reason)?;
    if stream_result.is_ok() {
        send(&mut pipe, &Reply::Finished { sidecar }).await?;
    }
    stream_result.map(|_| ())
}

#[cfg(test)]
#[path = "recording_broker_tests.rs"]
mod tests;
