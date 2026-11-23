//! Test doubles for the directive engine. NOTHING here touches the machine: the actuator records calls, the stores are
//! memory or a temp directory, the clock is a number.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use rmt_crypto::Identity;
use rmt_protocol::directive::{directive_signing_bytes, key_fingerprint, DirectiveClaims, SignedDirective};

use super::*;

pub const TENANT: &str = "11111111-2222-4333-8444-555555555555";
pub const DEVICE: &str = "66666666-7777-4888-8999-aaaaaaaaaaaa";
pub const DIRECTIVE_ID: &str = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
pub const OTHER_ID: &str = "cccccccc-cccc-4ddd-8eee-ffffffffffff";
pub const NOW: i64 = 1_800_000_001_000;

pub fn directive_key() -> Identity {
    Identity::from_seed(&[0x11; 32])
}
pub fn device_key() -> Identity {
    Identity::from_seed(&[0x22; 32])
}
pub fn fp() -> String {
    key_fingerprint(&device_key().public_hex()).unwrap()
}

pub fn claims(kind: &str, id: &str, issued: i64, expires: i64) -> DirectiveClaims {
    DirectiveClaims {
        tenant_id: TENANT.into(),
        device_id: DEVICE.into(),
        directive_id: id.into(),
        kind: kind.into(),
        key_fp: fp(),
        nonce: "000102030405060708090a0b0c0d0e0f".into(),
        issued_at_ms: issued,
        expires_at_ms: expires,
    }
}

/// Sign `c` with `key` (the Rust twin of the Go issuer, used only here).
pub fn sign_with(key: &Identity, c: DirectiveClaims) -> String {
    let msg = directive_signing_bytes(&c).expect("encodable claims");
    serde_json::to_string(&SignedDirective { claims: c, sig: hex::encode(key.sign(&msg)) }).unwrap()
}

pub fn mint(kind: &str, id: &str) -> String {
    let (issued, ttl) = if kind == "uninstall" { (NOW - 1_000, 3_600_000) } else { (NOW - 1_000, 86_400_000) };
    sign_with(&directive_key(), claims(kind, id, issued, issued + ttl))
}

pub fn ctx(pinned: Option<String>) -> EngineContext {
    EngineContext {
        device_id: DEVICE.into(),
        tenant_id: TENANT.into(),
        key_fp: fp(),
        pinned_key: pinned,
        signaling_url: "wss://signal.example/ws".into(),
        control_plane_url: "https://cp.example".into(),
    }
}

pub fn pinned() -> Option<String> {
    Some(directive_key().public_hex())
}

/// One shared, ordered log of everything the doubles were asked to do.
pub type Events = Arc<Mutex<Vec<String>>>;

#[derive(Clone, Default)]
pub struct MemStore {
    pub records: Arc<Mutex<BTreeMap<String, OpRecord>>>,
    pub fail_saves: Arc<AtomicBool>,
    pub fail_loads: Arc<AtomicBool>,
    pub events: Events,
}

impl MemStore {
    pub fn get(&self, id: &str) -> Option<OpRecord> {
        self.records.lock().unwrap().get(id).cloned()
    }
}

impl RecordStore for MemStore {
    fn load_all(&self) -> io::Result<Vec<OpRecord>> {
        if self.fail_loads.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected load failure"));
        }
        let mut v: Vec<_> = self.records.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| (a.accepted_ms, &a.directive_id).cmp(&(b.accepted_ms, &b.directive_id)));
        Ok(v)
    }
    fn save(&self, rec: &OpRecord) -> io::Result<()> {
        if self.fail_saves.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected save failure"));
        }
        self.events.lock().unwrap().push(format!("save:{}:{}:{}", rec.directive_id, rec.state, rec.step));
        self.records.lock().unwrap().insert(rec.directive_id.clone(), rec.clone());
        Ok(())
    }
    fn remove(&self, id: &str) -> io::Result<()> {
        self.records.lock().unwrap().remove(id);
        Ok(())
    }
}

/// A plain-directory store over the REAL encode/decode path, for corruption and restart tests.
pub struct FsStore {
    pub dir: std::path::PathBuf,
}

impl FsStore {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rmt-directive-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
}

impl Drop for FsStore {
    fn drop(&mut self) {
        // A temp dir this test created; never anything else.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct PlainOps<'a>(&'a std::path::Path);
impl FileOps for PlainOps<'_> {
    fn list(&self) -> io::Result<Vec<String>> {
        Ok(std::fs::read_dir(self.0)?.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
    }
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.0.join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let tmp = self.0.join(format!("{name}.tmp-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, self.0.join(name))
    }
}

impl RecordStore for FsStore {
    fn load_all(&self) -> io::Result<Vec<OpRecord>> {
        load_all_from(&PlainOps(&self.dir))
    }
    fn save(&self, rec: &OpRecord) -> io::Result<()> {
        save_to(&PlainOps(&self.dir), rec)
    }
    fn remove(&self, id: &str) -> io::Result<()> {
        let name = record_name(id).ok_or_else(|| io::Error::other("bad id"))?;
        match std::fs::remove_file(self.dir.join(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// Doubles for the actuating seam. Every call is logged; the answers are scripted.
#[derive(Clone)]
pub struct FakeActuator {
    pub events: Events,
    pub busy: Arc<AtomicBool>,
    /// The shared update/removal lock (held ⇒ true).
    pub exclusion: Arc<AtomicBool>,
    pub reinstall: Arc<Mutex<ReinstallStatus>>,
    pub removal: Arc<Mutex<RemovalStatus>>,
    pub start_reinstall_err: Arc<Mutex<Option<String>>>,
    pub start_uninstall_err: Arc<Mutex<Option<String>>>,
    pub handoffs: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeActuator {
    pub fn new(events: Events) -> Self {
        Self {
            events,
            busy: Arc::new(AtomicBool::new(false)),
            exclusion: Arc::new(AtomicBool::new(false)),
            reinstall: Arc::new(Mutex::new(ReinstallStatus::InProgress)),
            removal: Arc::new(Mutex::new(RemovalStatus::NotLaunched)),
            start_reinstall_err: Arc::new(Mutex::new(None)),
            start_uninstall_err: Arc::new(Mutex::new(None)),
            handoffs: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn calls(&self, what: &str) -> usize {
        self.events.lock().unwrap().iter().filter(|e| e.starts_with(what)).count()
    }
}

impl Actuator for FakeActuator {
    fn acquire_exclusion(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        if self.exclusion.swap(true, Ordering::SeqCst) {
            return None;
        }
        Some(Box::new(Guard(self.exclusion.clone())))
    }
    fn update_busy(&mut self) -> bool {
        let busy = self.busy.load(Ordering::SeqCst);
        std::thread::yield_now(); // widen the check-then-reserve window for the interleaving test
        busy
    }
    fn start_reinstall(&mut self, rec: &OpRecord, _now: i64) -> Result<(), String> {
        self.events.lock().unwrap().push(format!("start_reinstall:{}", rec.directive_id));
        match self.start_reinstall_err.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn reinstall_status(&mut self, rec: &OpRecord, _now: i64) -> ReinstallStatus {
        self.events.lock().unwrap().push(format!("reinstall_status:{}", rec.directive_id));
        self.reinstall.lock().unwrap().clone()
    }
    fn start_uninstall(&mut self, h: &RemovalHandoff) -> Result<(), String> {
        self.events.lock().unwrap().push(format!("start_uninstall:{}", h.directive_id));
        self.handoffs.lock().unwrap().push((h.directive_id.clone(), h.identity_seed_hex.clone()));
        match self.start_uninstall_err.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => {
                *self.removal.lock().unwrap() = RemovalStatus::Running;
                Ok(())
            }
        }
    }
    fn removal_status(&mut self, rec: &OpRecord) -> RemovalStatus {
        self.events.lock().unwrap().push(format!("removal_status:{}", rec.directive_id));
        self.removal.lock().unwrap().clone()
    }
}

pub struct Rig {
    pub engine: Engine,
    pub store: MemStore,
    pub act: FakeActuator,
    pub clock: Arc<AtomicI64>,
    pub events: Events,
}

pub fn rig_with(pinned_key: Option<String>) -> Rig {
    let events: Events = Arc::default();
    let store = MemStore { events: events.clone(), ..Default::default() };
    let act = FakeActuator::new(events.clone());
    let clock = Arc::new(AtomicI64::new(NOW));
    let c = clock.clone();
    let engine = Engine::new(ctx(pinned_key), device_key(), Box::new(store.clone()), Box::new(act.clone()))
        .with_clock(move || c.load(Ordering::SeqCst));
    Rig { engine, store, act, clock, events }
}

pub fn rig() -> Rig {
    rig_with(pinned())
}

impl Rig {
    pub fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }
    /// A restarted process: a NEW engine over the SAME store (and the same actuator world).
    pub fn restart(&mut self) {
        let c = self.clock.clone();
        self.engine = Engine::new(ctx(pinned()), device_key(), Box::new(self.store.clone()), Box::new(self.act.clone()))
            .with_clock(move || c.load(Ordering::SeqCst));
    }
    pub fn no_side_effects(&self) -> bool {
        let ev = self.events.lock().unwrap();
        !ev.iter().any(|e| e.starts_with("start_") || e.starts_with("save:"))
    }
}

impl Rig {
    /// Deliver every owed ack (the control plane answering `applied`), as the relay would.
    pub fn settle_acks(&mut self) {
        let mut guard = 0;
        while let Some(ack) = self.engine.next_ack() {
            self.engine.on_ack_result(&AckKey::of(&ack), "applied");
            guard += 1;
            assert!(guard < 50, "ack chain does not terminate");
        }
    }
}

impl Rig {
    /// Answer the first outstanding ack step of DIRECTIVE_ID (as a well-behaved relay would after its send).
    pub fn answer(&mut self, outcome: &str) {
        let mut rec = self.store.get(DIRECTIVE_ID).expect("record");
        if rec.acks.iter().find(|a| !a.delivered && !a.refused).is_some_and(|s| s.sent_ts.is_empty()) {
            self.engine.next_ack(); // the step must have been SENT for an answer to be attributable
            rec = self.store.get(DIRECTIVE_ID).expect("record");
        }
        if let Some(step) = rec.acks.iter().find(|a| !a.delivered && !a.refused) {
            let key = AckKey { directive_id: DIRECTIVE_ID.into(), from: step.from.clone(), to: step.to.clone(), ts_ms: *step.sent_ts.last().unwrap_or(&0) };
            self.engine.on_ack_result(&key, outcome);
        }
    }
}
