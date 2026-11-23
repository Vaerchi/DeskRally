//! The removal procedure against doubles (including a crash at every journal boundary), and the path / tree / install-chain
//! validation against REAL temp directories (junctions, swapped directories, user-writable components). No test here can
//! uninstall anything or delete anything outside the temp directories it creates.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rmt_protocol::directive::{self as proto, SignedAck};
use crate::anchor::FileIdentity;

use super::*;
use crate::directive::testkit::{claims, device_key, directive_key, fp, mint, sign_with, DEVICE, DIRECTIVE_ID, NOW, TENANT};

const CODE: &str = "{11111111-2222-3333-4444-555555555555}";
const INSTALL: &str = r"C:\Program Files\RMT Agent";
const CONFIG: &str = r"C:\rmt-agent";
const ROOT_ID: FileIdentity = FileIdentity { volume: 1, id: [7; 16] };

/// Everything the fake machine remembers ACROSS simulated process restarts (a crash drops the process, not the machine).
struct World {
    log: Vec<String>,
    products: Vec<String>,
    after_removal: Vec<String>,
    per_machine: bool,
    location: String,
    verify_err: Option<String>,
    tree_err: Option<String>,
    recordings: Result<RecordingDisposition, String>,
    rc: u32,
    removed: bool,
    /// The install directory survives (a reboot-time removal that failed or rolled back).
    install_dir_present: bool,
    installer_busy: bool,
    boot: String,
    hold_err: Option<String>,
    task_err: Option<String>,
    task_installed: bool,
    held: bool,
    /// While Some, deleting the config tree fails with this.
    cleanup_err: Option<String>,
    /// Entries a verify would find besides identity.key (cleared by a successful delete).
    config_entries: Vec<String>,
    identity_present: bool,
    root_present: bool,
    delete_identity_err: Option<String>,
    secrets_present: bool,
    /// verify_config_clean fails with this while Some, even if the delete reported success.
    leftover: Option<String>,
    /// Panic right AFTER the named operation took effect (simulating a crash/power loss there).
    crash_after: Option<&'static str>,
    task_remove_err: Option<String>,
    secrets_err: Option<String>,
    /// Allow flags the identity deletion was called with.
    identity_calls: Vec<bool>,
    expected_root: Vec<Option<FileIdentity>>,
    /// When the restart task is installed the clock jumps by this much (a directive that expires during the setup).
    advance_at_task: i64,
    clock: Rc<RefCell<i64>>,
}

type W = Rc<RefCell<World>>;

fn world() -> W {
    Rc::new(RefCell::new(World {
        log: vec![],
        products: vec![CODE.into()],
        after_removal: vec![],
        per_machine: true,
        location: INSTALL.into(),
        verify_err: None,
        tree_err: None,
        recordings: Ok(RecordingDisposition::NoneToUpload),
        rc: 0,
        removed: false,
        install_dir_present: false,
        installer_busy: false,
        boot: "boot-1".into(),
        hold_err: None,
        task_err: None,
        task_installed: false,
        held: false,
        cleanup_err: None,
        config_entries: vec!["config.json".into(), "recordings".into()],
        identity_present: true,
        root_present: true,
        delete_identity_err: None,
        secrets_present: true,
        leftover: None,
        crash_after: None,
        task_remove_err: None,
        secrets_err: None,
        identity_calls: vec![],
        expected_root: vec![],
        advance_at_task: 0,
        clock: Rc::new(RefCell::new(NOW)),
    }))
}

struct FakeOps(W);

impl FakeOps {
    fn note(&self, s: &str) {
        self.0.borrow_mut().log.push(s.to_owned());
    }
    fn crash_point(&self, name: &'static str) {
        if self.0.borrow().crash_after == Some(name) {
            self.0.borrow_mut().crash_after = None;
            panic!("simulated crash after {name}");
        }
    }
}

impl RemovalOps for FakeOps {
    fn installed_products(&mut self) -> Result<Vec<String>, String> {
        self.note("installed_products");
        let w = self.0.borrow();
        Ok(if w.removed { w.after_removal.clone() } else { w.products.clone() })
    }
    fn installer_busy(&mut self) -> bool {
        self.0.borrow().installer_busy
    }
    fn boot_id(&mut self) -> String {
        self.0.borrow().boot.clone()
    }
    fn product_is_per_machine(&mut self, _: &str) -> Result<bool, String> {
        Ok(self.0.borrow().per_machine)
    }
    fn product_install_location(&mut self, _: &str) -> Result<String, String> {
        Ok(self.0.borrow().location.clone())
    }
    fn verify_install_dir(&mut self, claimed: &str, expected: &str) -> Result<(), String> {
        let w = self.0.borrow();
        match &w.verify_err {
            Some(e) => Err(e.clone()),
            None if claimed == expected => Ok(()),
            None => Err("different location".into()),
        }
    }
    fn hold_install_dir(&mut self, _: &str) -> Result<(), String> {
        self.note("hold_install_dir");
        let err = self.0.borrow().hold_err.clone();
        if let Some(e) = err {
            return Err(e);
        }
        self.0.borrow_mut().held = true;
        Ok(())
    }
    fn release_install_dir(&mut self) {
        self.note("release_install_dir");
        self.0.borrow_mut().held = false;
    }
    fn install_dir_absent(&mut self, _: &str) -> Result<bool, String> {
        self.note("install_dir_absent");
        Ok(!self.0.borrow().install_dir_present)
    }
    fn preflight_config_tree(&mut self, _: &str) -> Result<usize, String> {
        self.note("preflight_config_tree");
        self.0.borrow().tree_err.clone().map_or(Ok(3), Err)
    }
    fn settle_recordings(&mut self) -> Result<RecordingDisposition, String> {
        self.note("settle_recordings");
        self.0.borrow().recordings.clone()
    }
    fn install_resume_task(&mut self) -> Result<(), String> {
        self.note("install_resume_task");
        let err = self.0.borrow().task_err.clone();
        if let Some(e) = err {
            return Err(e);
        }
        let advance = self.0.borrow().advance_at_task;
        if advance > 0 {
            let clock = self.0.borrow().clock.clone();
            *clock.borrow_mut() += advance;
        }
        self.0.borrow_mut().task_installed = true;
        Ok(())
    }
    fn remove_resume_task(&mut self) -> Result<(), String> {
        self.note("remove_resume_task");
        let err = self.0.borrow().task_remove_err.clone();
        if let Some(e) = err {
            return Err(e);
        }
        self.0.borrow_mut().task_installed = false;
        Ok(())
    }
    fn config_root_identity(&mut self) -> Option<FileIdentity> {
        Some(ROOT_ID)
    }
    fn expect_config_root(&mut self, id: Option<FileIdentity>) {
        self.note("expect_config_root");
        self.0.borrow_mut().expected_root.push(id);
    }
    fn delete_helper_secrets(&mut self) -> Result<(), String> {
        self.note("delete_helper_secrets");
        let err = self.0.borrow().secrets_err.clone();
        if let Some(e) = err {
            return Err(e);
        }
        self.0.borrow_mut().secrets_present = false;
        self.crash_point("delete_secrets");
        Ok(())
    }
    fn configure_absent(&mut self, code: &str) -> u32 {
        self.note(&format!("configure_absent:{code}"));
        let rc = self.0.borrow().rc;
        if rc == 0 || rc == 3010 || rc == 1641 {
            self.0.borrow_mut().removed = true;
        }
        self.crash_point("configure_absent");
        rc
    }
    fn cleanup_footprint(&mut self) {
        self.note("cleanup_footprint");
    }
    fn delete_config_tree_keep_identity(&mut self, _: &str) -> Result<usize, String> {
        self.note("delete_config_tree_keep_identity");
        let err = self.0.borrow().cleanup_err.clone();
        if let Some(e) = err {
            return Err(e);
        }
        let n = self.0.borrow().config_entries.len();
        self.0.borrow_mut().config_entries.clear();
        self.crash_point("delete_keep");
        Ok(n)
    }
    fn verify_config_clean(&mut self, _: &str) -> Result<(), String> {
        self.note("verify_config_clean");
        let w = self.0.borrow();
        if let Some(l) = &w.leftover {
            return Err(format!("{l} remains"));
        }
        if w.config_entries.is_empty() {
            Ok(())
        } else {
            Err(format!("{} entries remain", w.config_entries.len()))
        }
    }
    fn delete_identity_and_root(&mut self, _: &str, allow_absent: bool) -> Result<(), String> {
        self.note("delete_identity_and_root");
        self.0.borrow_mut().identity_calls.push(allow_absent);
        let err = self.0.borrow().delete_identity_err.clone();
        if let Some(e) = err {
            return Err(e);
        }
        if !self.0.borrow().identity_present && !allow_absent {
            return Err("identity.key is not there".into());
        }
        {
            let mut w = self.0.borrow_mut();
            w.identity_present = false;
            w.root_present = false;
        }
        self.crash_point("delete_identity");
        Ok(())
    }
    fn schedule_self_cleanup(&mut self) {
        self.note("schedule_self_cleanup");
    }
}

/// Scripted ack channel: answers are popped per call (default Delivered); every send is recorded.
struct FakeAck {
    w: W,
    answers: Rc<RefCell<Vec<AckDelivery>>>,
    sent: Rc<RefCell<Vec<SignedAck>>>,
    /// Per PROCESS RUN (a restarted process starts with `false`): whether `agent_removed` was called yet.
    agent_gone: bool,
    /// For every delivery, whether the channel already knew the agent was gone.
    gone_at_send: Rc<RefCell<Vec<bool>>>,
}

impl AckChannel for FakeAck {
    fn deliver(&mut self, ack: &SignedAck) -> AckDelivery {
        self.w.borrow_mut().log.push(format!("ack:{}->{}", ack.from, ack.to));
        self.sent.borrow_mut().push(ack.clone());
        self.gone_at_send.borrow_mut().push(self.agent_gone);
        let mut a = self.answers.borrow_mut();
        if a.is_empty() { AckDelivery::Delivered } else { a.remove(0) }
    }
    fn agent_removed(&mut self) {
        self.agent_gone = true;
    }
}

/// An in-memory journal that survives "restarts" and can crash right after its nth save.
#[derive(Clone, Default)]
struct MemJournal {
    j: Rc<RefCell<Option<Journal>>>,
    saves: Rc<RefCell<usize>>,
    crash_after_save: Rc<RefCell<Option<usize>>>,
    fail_saves: Rc<RefCell<bool>>,
    /// Saves numbered >= this fail.
    fail_from: Rc<RefCell<Option<usize>>>,
}

impl JournalStore for MemJournal {
    fn load(&self) -> io::Result<Option<Journal>> {
        Ok(self.j.borrow().clone())
    }
    fn save(&mut self, j: &Journal) -> io::Result<()> {
        if *self.fail_saves.borrow() {
            return Err(io::Error::other("injected journal failure"));
        }
        if self.fail_from.borrow().is_some_and(|n| *self.saves.borrow() + 1 >= n) {
            return Err(io::Error::other("injected journal failure"));
        }
        *self.j.borrow_mut() = Some(j.clone());
        *self.saves.borrow_mut() += 1;
        let n = *self.saves.borrow();
        if *self.crash_after_save.borrow() == Some(n) {
            *self.crash_after_save.borrow_mut() = None;
            panic!("simulated crash after journal save #{n}");
        }
        Ok(())
    }
}

fn handoff() -> HelperHandoff {
    HelperHandoff {
        base: RemovalHandoff {
            v: 1,
            directive_id: DIRECTIVE_ID.into(),
            artifact: mint("uninstall", DIRECTIVE_ID),
            device_id: DEVICE.into(),
            tenant_id: TENANT.into(),
            key_fp: fp(),
            pinned_directive_key: directive_key().public_hex(),
            identity_seed_hex: hex::encode([0x22u8; 32]),
            accepted_ms: NOW,
            signaling_url: "wss://signal.example/ws".into(),
            control_plane_url: "https://cp.example".into(),
        },
        product_code: CODE.into(),
        install_dir: INSTALL.into(),
        config_dir: CONFIG.into(),
    }
}

/// One simulated machine + its journal + its control plane, over which any number of "process runs" happen.
struct Rig {
    w: W,
    journal: MemJournal,
    answers: Rc<RefCell<Vec<AckDelivery>>>,
    sent: Rc<RefCell<Vec<SignedAck>>>,
    gone_at_send: Rc<RefCell<Vec<bool>>>,
    now: Rc<RefCell<i64>>,
    h: HelperHandoff,
}

fn rig() -> Rig {
    let w = world();
    let now = w.borrow().clock.clone();
    Rig { w, journal: MemJournal::default(), answers: Rc::default(), sent: Rc::default(), gone_at_send: Rc::default(), now, h: handoff() }
}

impl Rig {
    /// One process run. `Err` means the run panicked (a simulated crash).
    fn try_run(&mut self) -> Result<RemovalResult, ()> {
        let mut ops = FakeOps(self.w.clone());
        let mut ack = FakeAck { w: self.w.clone(), answers: self.answers.clone(), sent: self.sent.clone(), agent_gone: false, gone_at_send: self.gone_at_send.clone() };
        let mut journal = self.journal.clone();
        let now = self.now.clone();
        let h = &self.h;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_removal(h, &mut ops, &mut ack, &mut journal, &move || *now.borrow())
        }))
        .map_err(|_| ())
    }
    fn run(&mut self) -> RemovalResult {
        self.try_run().expect("no crash scheduled")
    }
    fn log(&self) -> Vec<String> {
        self.w.borrow().log.clone()
    }
    fn count(&self, what: &str) -> usize {
        self.log().iter().filter(|e| e.starts_with(what)).count()
    }
    fn pos(&self, what: &str) -> usize {
        self.log().iter().position(|e| e.starts_with(what)).unwrap_or_else(|| panic!("{what} missing: {:?}", self.log()))
    }
    fn advance(&self, ms: i64) {
        *self.now.borrow_mut() += ms;
    }
    fn nothing_touched(&self) {
        assert_eq!(self.count("configure_absent"), 0, "{:?}", self.log());
        assert_eq!(self.count("delete_config_tree"), 0, "{:?}", self.log());
        assert_eq!(self.count("delete_identity"), 0, "{:?}", self.log());
        assert_eq!(self.count("cleanup_footprint"), 0, "{:?}", self.log());
        assert!(self.w.borrow().identity_present);
    }
    fn acks(&self) -> Vec<SignedAck> {
        self.sent.borrow().clone()
    }
}

fn verify(a: &SignedAck) -> bool {
    proto::verify_ack(&device_key().public_hex(), TENANT, DEVICE, DIRECTIVE_ID, &fp(), a)
}

// ---- the happy path and its ORDER (R1, R2, R3) ---------------------------------------------------------------

#[test]
fn a_clean_removal_follows_the_documented_order() {
    let mut r = rig();
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    let p = |s: &str| r.pos(s);
    assert!(p("preflight_config_tree") < p("hold_install_dir"), "validate, then hold");
    assert!(p("hold_install_dir") < p("install_resume_task"));
    assert!(p("install_resume_task") < p("configure_absent"), "the restart task exists BEFORE the first irreversible step");
    assert!(p("configure_absent") < p("release_install_dir"));
    assert!(p("release_install_dir") < p("delete_config_tree_keep_identity"));
    assert!(p("delete_config_tree_keep_identity") < p("verify_config_clean"));
    assert!(p("verify_config_clean") < p("ack:executing->complete"), "R1: nothing is reported complete before the cleanup is VERIFIED");
    assert!(p("ack:executing->complete") < p("delete_identity_and_root"), "identity last, after the confirmed report");
    assert!(p("delete_identity_and_root") < p("remove_resume_task"));
    let w = r.w.borrow();
    assert!(!w.identity_present && !w.task_installed && !w.secrets_present && !w.held);
    drop(w);
    let acks = r.acks();
    assert_eq!(acks.len(), 1);
    assert!(verify(&acks[0]));
    assert!(acks[0].detail.contains("no local recordings"));
    assert!(!r.gone_at_send.borrow().is_empty() && r.gone_at_send.borrow().iter().all(|g| *g), "every delivery after the MSI removal knows the agent is gone");
}

#[test]
fn the_msi_removal_uses_the_expected_product_code_and_the_journal_is_durable_before_it() {
    let mut r = rig();
    r.run();
    assert!(r.log().contains(&format!("configure_absent:{CODE}")));
    // The journal's first save (MsiStarting) must precede the irreversible call: crash right after it, MSI must not have run.
    let mut r = rig();
    *r.journal.crash_after_save.borrow_mut() = Some(1);
    assert!(r.try_run().is_err());
    assert_eq!(r.count("configure_absent"), 0);
    assert_eq!(r.journal.j.borrow().as_ref().unwrap().phase, Phase::MsiStarting);
}

// ---- refusals: nothing is touched --------------------------------------------------------------------------

#[test]
fn an_unexpected_or_extra_product_is_refused_and_nothing_is_touched() {
    for products in [vec!["{99999999-2222-3333-4444-555555555555}".to_owned()], vec![CODE.to_owned(), "{99999999-2222-3333-4444-555555555555}".to_owned()], vec![]] {
        let mut r = rig();
        r.w.borrow_mut().products = products.clone();
        assert!(matches!(r.run(), RemovalResult::Failed(_)), "{products:?}");
        r.nothing_touched();
        assert_eq!(r.count("install_resume_task"), 0);
        assert_eq!(r.count("hold_install_dir"), 0);
    }
}

#[test]
fn a_per_user_install_a_wrong_location_and_a_bad_config_tree_are_refused() {
    let mut r = rig();
    r.w.borrow_mut().per_machine = false;
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("per-machine")));
    r.nothing_touched();
    let mut r = rig();
    r.w.borrow_mut().location = r"C:\Users\guest\Downloads".into();
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("install location")));
    r.nothing_touched();
    let mut r = rig();
    r.w.borrow_mut().verify_err = Some("C:\\x is a reparse point".into());
    assert!(matches!(r.run(), RemovalResult::Failed(_)));
    r.nothing_touched();
    let mut r = rig();
    r.w.borrow_mut().tree_err = Some("refusing a reparse point".into());
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("config directory")));
    r.nothing_touched();
}

#[test]
fn an_unsafe_install_chain_or_a_failed_restart_task_refuses_before_the_installer_runs() {
    let mut r = rig();
    r.w.borrow_mut().hold_err = Some("a component is writable by Users".into());
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("not safe to remove")));
    r.nothing_touched();
    assert_eq!(r.count("install_resume_task"), 0, "no task is installed for a removal that will not happen");
    assert!(r.journal.j.borrow().is_none());

    let mut r = rig();
    r.w.borrow_mut().task_err = Some("schtasks exited Some(1)".into());
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("restart task")));
    r.nothing_touched();
    assert!(!r.w.borrow().held, "the held chain is released when the removal is refused");
}

#[test]
fn a_journal_that_cannot_be_written_means_no_removal() {
    let mut r = rig();
    *r.journal.fail_saves.borrow_mut() = true;
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("journal")));
    r.nothing_touched();
    let w = r.w.borrow();
    assert!(!w.task_installed && !w.held, "the task and the held chain are undone");
}

#[test]
fn recordings_that_cannot_be_settled_block_the_removal_and_abandoned_ones_are_reported() {
    let mut r = rig();
    r.w.borrow_mut().recordings = Err("an upload is still running".into());
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("upload")));
    r.nothing_touched();
    let mut r = rig();
    r.w.borrow_mut().recordings = Ok(RecordingDisposition::Abandoned(7));
    r.run();
    assert!(r.acks()[0].detail.contains("7 local recording file(s) abandoned"), "{}", r.acks()[0].detail);
    let mut r = rig();
    r.w.borrow_mut().recordings = Ok(RecordingDisposition::Finished(2));
    r.run();
    assert!(r.acks()[0].detail.contains("2 recording upload(s) finished"));
}

#[test]
fn settled_uploads_report_the_abandoned_count_in_the_ack_detail() {
    // Some finished, some explicitly abandoned, some local files left: every number reaches the central ack.
    let mut r = rig();
    r.w.borrow_mut().recordings = Ok(recording_disposition(2, 3, 5));
    r.run();
    let d = r.acks()[0].detail.clone();
    assert!(d.contains("2 recording upload(s) finished"), "{d}");
    assert!(d.contains("3 pending upload(s) explicitly abandoned"), "{d}");
    assert!(d.contains("5 local recording file(s) deleted with the machine"), "{d}");
    // Nothing uploaded, only abandonment.
    let mut r = rig();
    r.w.borrow_mut().recordings = Ok(recording_disposition(0, 4, 4));
    r.run();
    assert!(r.acks()[0].detail.contains("4 pending upload(s) explicitly abandoned"), "{}", r.acks()[0].detail);
}

#[test]
fn recording_disposition_maps_every_outcome() {
    assert_eq!(recording_disposition(0, 0, 0), RecordingDisposition::NoneToUpload);
    assert_eq!(recording_disposition(3, 0, 0), RecordingDisposition::Finished(3));
    assert_eq!(recording_disposition(0, 0, 6), RecordingDisposition::Abandoned(6));
    assert_eq!(
        recording_disposition(1, 2, 3),
        RecordingDisposition::Settled { uploaded: 1, abandoned_uploads: 2, local_files: 3 }
    );
    // An abandoned upload with no files left is still stated, never reported as a clean finish.
    assert_eq!(
        recording_disposition(2, 1, 0),
        RecordingDisposition::Settled { uploaded: 2, abandoned_uploads: 1, local_files: 0 }
    );
    assert!(recording_note(&recording_disposition(2, 1, 0)).contains("1 pending upload(s) explicitly abandoned"));
}

#[test]
fn a_directive_that_fails_re_verification_removes_nothing() {
    let mut r = rig();
    r.h.base.pinned_directive_key = rmt_crypto::Identity::from_seed(&[0x44; 32]).public_hex();
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("signature")));
    assert_eq!(r.count("installed_products"), 0, "not even the pre-flight runs: {:?}", r.log());
    r.nothing_touched();
    let mut r = rig();
    r.h.base.artifact = mint("reinstall", DIRECTIVE_ID);
    assert!(matches!(r.run(), RemovalResult::Failed(_)));
    r.nothing_touched();
    let mut r = rig();
    r.h.base.artifact = sign_with(&directive_key(), claims("uninstall", "cccccccc-cccc-4ddd-8eee-ffffffffffff", NOW - 1000, NOW + 600_000));
    assert!(matches!(r.run(), RemovalResult::Failed(_)));
    r.nothing_touched();
    let mut r = rig();
    r.h.base.device_id = "66666666-7777-4888-8999-bbbbbbbbbbbb".into();
    assert!(matches!(r.run(), RemovalResult::Failed(_)));
    let mut r = rig();
    r.h.base.identity_seed_hex = "nothex".into();
    assert!(matches!(r.run(), RemovalResult::Failed(_)));
    assert!(r.log().is_empty() && r.acks().is_empty());
}

// ---- E4: the helper checks freshness itself ----------------------------------------------------------------------

#[test]
fn a_helper_that_starts_after_the_directive_expired_does_nothing() {
    let mut r = rig();
    r.advance(3_600_000 + 1_000); // the uninstall directive lives one hour from NOW-1000
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("expired")), "{:?}", r.log());
    assert_eq!(r.count("installed_products"), 0);
    r.nothing_touched();
    assert!(r.journal.j.borrow().is_none());
    // One second inside the window it proceeds (the boundary is real, not "always refuse").
    let mut r = rig();
    r.advance(3_600_000 - 1_500);
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
}

// ---- MSI outcomes ------------------------------------------------------------------------------------------

#[test]
fn a_partial_or_failed_msi_removal_is_failed_undone_and_deletes_nothing() {
    for rc in [1603u32, 1618, 1602, 1605] {
        let mut r = rig();
        r.w.borrow_mut().rc = rc;
        assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains(&rc.to_string())), "{rc}");
        assert_eq!(r.count("delete_config_tree"), 0, "rc {rc} must keep everything: {:?}", r.log());
        assert_eq!(r.count("cleanup_footprint"), 0);
        let w = r.w.borrow();
        assert!(w.identity_present && !w.task_installed && !w.held, "rc {rc}: task removed, chain released, identity kept");
        assert!(r.gone_at_send.borrow().is_empty(), "the agent survives a failed removal and reports it from the result file");
        assert!(r.acks().is_empty(), "nothing is sent over a second registration while the agent lives");
    }
}

#[test]
fn msi_success_while_the_product_is_still_registered_is_not_complete() {
    let mut r = rig();
    r.w.borrow_mut().after_removal = vec![CODE.into()];
    assert!(matches!(&r.run(), RemovalResult::Failed(w) if w.contains("still registered")));
    assert_eq!(r.count("delete_config_tree"), 0);
    assert!(r.w.borrow().identity_present);
}

// ---- R1: cleanup is verified before complete ---------------------------------------------------------------

#[test]
fn a_cleanup_failure_is_never_complete_it_is_retried_then_reported_failed() {
    let mut r = rig();
    r.w.borrow_mut().cleanup_err = Some("recordings\\one.rmtrec: access denied".into());
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("cleanup incomplete")), "{first:?}");
    assert!(r.acks().is_empty(), "no complete, no failed yet: the window is still open");
    assert!(r.w.borrow().identity_present, "identity kept while the cleanup is unfinished");
    assert_eq!(r.journal.j.borrow().as_ref().unwrap().cleanup_attempts, 1);
    // The retry (a restart) succeeds once the file is no longer locked: the removal completes.
    r.w.borrow_mut().cleanup_err = None;
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert_eq!(r.acks().len(), 1);
    assert_eq!(r.acks()[0].to, "complete");

    // The window closes with the cleanup still failing: failed, with the reason, truthfully (never complete).
    let mut r = rig();
    r.w.borrow_mut().cleanup_err = Some("access denied".into());
    r.run();
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    let last = r.run();
    assert!(matches!(&last, RemovalResult::Failed(w) if w.contains("cleanup could not be completed") && w.contains("access denied")), "{last:?}");
    let acks = r.acks();
    assert_eq!(acks.len(), 1);
    assert_eq!((acks[0].from.as_str(), acks[0].to.as_str()), ("executing", "failed"), "{acks:?}");
    assert!(acks[0].detail.contains("access denied"));
    assert!(verify(&acks[0]));
    assert!(!r.log().iter().any(|e| e == "ack:executing->complete"));
    assert!(r.w.borrow().identity_present, "an incomplete removal leaves the identity for the operator");
}

#[test]
fn leftovers_after_a_delete_that_reported_success_still_block_complete() {
    // The delete returns Ok but something is still there (re-created, a partial sweep): VERIFY is what decides.
    let mut r = rig();
    r.w.borrow_mut().leftover = Some("straggler.tmp".into());
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("straggler.tmp")), "{first:?}");
    assert!(!r.log().iter().any(|e| e == "ack:executing->complete"), "never complete over a failed verification");
    assert!(r.w.borrow().identity_present);
    r.w.borrow_mut().leftover = None;
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
}

// ---- R2: crash at every journal boundary ------------------------------------------------------------------------

#[test]
fn a_crash_after_any_journal_save_resumes_to_a_truthful_end() {
    for n in 1..=8usize {
        let mut r = rig();
        *r.journal.crash_after_save.borrow_mut() = Some(n);
        let mut results = vec![];
        for _ in 0..6 {
            match r.try_run() {
                Ok(res) => {
                    let done = res.is_final();
                    results.push(res);
                    if done {
                        break;
                    }
                }
                Err(()) => results.push(RemovalResult::Deferred { reason: "crashed".into(), in_process: false }),
            }
        }
        let last = results.last().unwrap().clone();
        assert!(matches!(last, RemovalResult::Complete { .. } | RemovalResult::Failed(_)), "n={n}: {results:?}");
        // The MSI removal ran AT MOST once, ever.
        assert!(r.count("configure_absent") <= 1, "n={n}: {:?}", r.log());
        // No complete without a verified cleanup before it; identity deleted only after a delivered complete.
        let log = r.log();
        if let Some(c) = log.iter().position(|e| e == "ack:executing->complete") {
            let v = log.iter().position(|e| e == "verify_config_clean").expect("verified before complete");
            assert!(v < c, "n={n}");
        }
        if let Some(d) = log.iter().position(|e| e.starts_with("delete_identity")) {
            assert!(log.iter().position(|e| e == "ack:executing->complete").is_some_and(|c| c < d), "n={n}: identity deleted before the report: {log:?}");
        }
        match last {
            // The crash window before the irreversible step fails SAFE: the product is intact and the failure is reported.
            RemovalResult::Failed(ref why) if why.contains("interrupted") => {
                assert_eq!(r.count("configure_absent"), 0, "n={n}");
                assert!(r.w.borrow().identity_present && !r.w.borrow().task_installed, "n={n}");
            }
            RemovalResult::Complete { .. } => {
                let w = r.w.borrow();
                assert!(!w.identity_present && !w.task_installed && !w.secrets_present && !w.held, "n={n}");
            }
            other => panic!("n={n}: unexpected {other:?}"),
        }
    }
}

#[test]
fn a_crash_right_after_the_msi_removal_before_its_journal_entry_resumes_from_the_registration() {
    let mut r = rig();
    r.w.borrow_mut().crash_after = Some("configure_absent");
    assert!(r.try_run().is_err(), "power loss right after the installer removed the product");
    assert_eq!(r.journal.j.borrow().as_ref().unwrap().phase, Phase::MsiStarting, "the journal only knows the removal started");
    assert!(r.w.borrow().task_installed, "the restart task survives the crash");
    // While the installer is still busy the resume waits.
    r.w.borrow_mut().installer_busy = true;
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.w.borrow_mut().installer_busy = false;
    // A2: product gone, installer answer lost (a reboot MAY be owed): the SAME boot is not enough; no cleanup, no complete.
    let waiting = r.run();
    assert!(matches!(&waiting, RemovalResult::Deferred { reason, in_process: false } if reason.contains("reboot")), "{waiting:?}");
    assert_eq!(r.count("delete_config_tree"), 0);
    assert!(r.acks().is_empty());
    assert!(r.journal.j.borrow().as_ref().unwrap().reboot_required);
    r.w.borrow_mut().boot = "boot-2".into();
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert_eq!(r.count("configure_absent"), 1, "never run twice");
    assert_eq!(r.acks().len(), 1, "no interim reboot_pending claim: the installer never said so");
    assert_eq!(r.acks()[0].from, "executing");
}

#[test]
fn a_crash_during_cleanup_continues_the_cleanup_without_running_the_installer_again() {
    let mut r = rig();
    r.w.borrow_mut().crash_after = Some("delete_keep");
    assert!(r.try_run().is_err());
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert_eq!(r.count("configure_absent"), 1);
    assert_eq!(r.count("delete_config_tree_keep_identity"), 2, "the interrupted sweep is simply repeated (idempotent)");
}

#[test]
fn a_finished_journal_resumes_to_the_same_answer_and_only_removes_the_task() {
    let mut r = rig();
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    let before = r.count("configure_absent");
    r.w.borrow_mut().task_installed = true; // a stale task fires again
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert_eq!(r.count("configure_absent"), before);
    assert!(!r.w.borrow().task_installed);
}

// ---- R2: reboot-pending uses the same mechanism -------------------------------------------------------------

#[test]
fn a_reboot_requirement_is_reported_waited_out_and_finished_after_the_reboot() {
    for rc in [3010u32, 1641] {
        let mut r = rig();
        r.w.borrow_mut().rc = rc;
        r.w.borrow_mut().after_removal = vec![CODE.into()]; // registration still visible until the reboot
        assert_eq!(r.run(), RemovalResult::RebootPending, "rc {rc}");
        assert_eq!(r.acks().len(), 1);
        assert_eq!((r.acks()[0].from.as_str(), r.acks()[0].to.as_str()), ("executing", "reboot_pending"));
        assert_eq!(r.count("delete_config_tree"), 0, "nothing local is deleted before the reboot");
        assert!(r.w.borrow().task_installed && r.w.borrow().identity_present, "the restart task and the identity wait");
        // Same boot: the restart task (or a repeat) changes nothing.
        assert_eq!(r.run(), RemovalResult::RebootPending);
        assert_eq!(r.acks().len(), 1, "no duplicate interim report");
        // After the reboot the product is gone: cleanup, then the final report FROM reboot_pending.
        {
            let mut w = r.w.borrow_mut();
            w.boot = "boot-2".into();
            w.after_removal = vec![];
        }
        assert_eq!(r.run(), RemovalResult::Complete { residue: None });
        let acks = r.acks();
        assert_eq!((acks[1].from.as_str(), acks[1].to.as_str()), ("reboot_pending", "complete"));
        assert!(acks[1].ts_ms > acks[0].ts_ms, "timestamps strictly increase across the helper's acks");
        assert!(proto::transition_allowed("reboot_pending", "complete"));
        assert!(verify(&acks[1]));
        let w = r.w.borrow();
        assert!(!w.identity_present && !w.task_installed && !w.secrets_present);
    }
}

// ---- R3: the final report ----------------------------------------------------------------------------------

#[test]
fn the_exact_final_ack_is_persisted_and_resent_verbatim_across_restarts() {
    let mut r = rig();
    r.answers.borrow_mut().extend([AckDelivery::Undeliverable, AckDelivery::Undeliverable]);
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("not confirmed")), "{first:?}");
    assert!(r.w.borrow().identity_present, "identity stays until the report is confirmed");
    let stored = r.journal.j.borrow().as_ref().unwrap().final_ack.clone().expect("persisted BEFORE it was sent");
    assert_eq!(r.acks()[0], stored);
    // A restart: the SAME ack (same timestamp, same signature) goes out again; the cleanup is not repeated.
    let second = r.run();
    assert!(matches!(second, RemovalResult::Deferred { .. }));
    assert_eq!(r.acks()[1], stored, "re-sent verbatim, not re-signed");
    assert_eq!(r.count("delete_config_tree_keep_identity"), 1);
    // Delivered at last: only now the identity goes.
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert_eq!(r.acks()[2], stored);
    assert!(r.pos("ack:executing->complete") < r.pos("delete_identity_and_root"));
}

#[test]
fn a_stored_final_ack_that_grew_stale_is_re_signed_with_a_larger_timestamp() {
    let mut r = rig();
    r.answers.borrow_mut().push(AckDelivery::Undeliverable);
    r.run();
    let first = r.acks()[0].clone();
    r.advance(FINAL_ACK_FRESH_MS + 5_000);
    // (still inside the window: the directive's own lifetime is 1 h, the retry window 24 h longer)
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    let second = r.acks()[1].clone();
    assert_eq!((second.from.as_str(), second.to.as_str()), (first.from.as_str(), first.to.as_str()));
    assert!(second.ts_ms > first.ts_ms, "a fresh timestamp: the control plane refuses a NEW transition whose ts is over an hour old");
    assert!(verify(&second));
}

#[test]
fn without_a_confirmation_complete_is_never_claimed_the_retries_are_bounded_then_the_identity_goes() {
    // R3 branch 2 (a REMOVED device's registration is refused with the same generic reason as any other refusal, so a refusal
    // is not a confirmation): retry until the directive's expiry + 24 h, then clean up anyway and say "unreported".
    let mut r = rig();
    r.answers.borrow_mut().extend(std::iter::repeat_n(AckDelivery::Undeliverable, 10));
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.advance(3_600_000 + 12 * 3_600_000);
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }), "still inside the window");
    assert!(r.w.borrow().identity_present);
    r.advance(13 * 3_600_000);
    let end = r.run();
    assert_eq!(end, RemovalResult::Unreported, "never Complete without a confirmation");
    assert_eq!(end.exit_code(), 12);
    let w = r.w.borrow();
    assert!(!w.identity_present && !w.root_present && !w.task_installed && !w.secrets_present, "everything local is gone once the window closes");
}

#[test]
fn a_refused_final_report_stops_the_retrying_and_cleans_up_as_unreported() {
    let mut r = rig();
    r.answers.borrow_mut().push(AckDelivery::Refused);
    assert_eq!(r.run(), RemovalResult::Unreported);
    assert!(!r.w.borrow().identity_present);
    assert_eq!(r.acks().len(), 1, "not retried");
}

#[test]
fn an_identity_that_cannot_be_deleted_is_retried_not_forgotten() {
    let mut r = rig();
    r.w.borrow_mut().delete_identity_err = Some("sharing violation".into());
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("identity")), "{first:?}");
    assert!(r.w.borrow().task_installed, "the restart task stays until the identity is gone");
    r.w.borrow_mut().delete_identity_err = None;
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
}

// ---- R2: the restart task definition ----------------------------------------------------------------------

#[test]
fn the_restart_task_runs_as_system_at_boot_and_on_a_repeat_with_separate_command_and_argument() {
    let xml = resume_task_xml(r"C:\Windows\Temp\DeskRallyRemoval-x\helper.exe", r"C:\Windows\Temp\DeskRallyRemoval-x\handoff.json").unwrap();
    assert!(xml.contains("<UserId>S-1-5-18</UserId>"), "SYSTEM");
    assert!(xml.contains("<BootTrigger>") && xml.contains("<Repetition><Interval>PT10M</Interval>"));
    assert!(xml.contains(r"<Command>C:\Windows\Temp\DeskRallyRemoval-x\helper.exe</Command>"));
    assert!(xml.contains(r#"<Arguments>directive-removal "C:\Windows\Temp\DeskRallyRemoval-x\handoff.json"</Arguments>"#));
    assert!(xml.contains("IgnoreNew"), "one instance at a time");
    // Who can modify or run the task: an explicit PROTECTED security descriptor, SYSTEM and Administrators only.
    assert!(xml.contains("<SecurityDescriptor>D:P(A;;FA;;;SY)(A;;FA;;;BA)</SecurityDescriptor>"));
    assert_eq!(TASK_SDDL, "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
}

#[test]
fn the_restart_task_refuses_paths_that_could_break_out_of_its_fields() {
    for bad in ["C:\\a\"b\\helper.exe", "C:\\a%PATH%\\helper.exe", "C:\\a\nb", ""] {
        assert!(resume_task_xml(bad, r"C:\h.json").is_err(), "{bad:?}");
        assert!(resume_task_xml(r"C:\h.exe", bad).is_err(), "{bad:?}");
    }
    let escaped = resume_task_xml(r"C:\R&D\helper.exe", r"C:\R&D\h.json").unwrap();
    assert!(escaped.contains("R&amp;D") && !escaped.contains("R&D\\h"));
}

// ---- path validation against REAL directories --------------------------------------------------------------

fn temp_base(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("rmt-removal-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn junction(link: &Path, target: &Path) {
    let made = std::process::Command::new(crate::agent_root::system32_exe("cmd.exe"))
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "premise: junction created: {}", String::from_utf8_lossy(&made.stdout));
}

fn remove_junction(link: &Path) {
    let _ = std::fs::remove_dir(link); // removes the junction itself, never its target
}

#[test]
fn a_plain_directory_matching_the_expected_one_is_accepted() {
    let base = temp_base("plain");
    let install = base.join("Program Files").join("RMT Agent");
    std::fs::create_dir_all(&install).unwrap();
    let resolved = verify_dir_identity(&install, &install).unwrap();
    assert!(same_place(&resolved, &install));
    // Case and a trailing separator are not differences.
    let upper = PathBuf::from(install.to_string_lossy().to_uppercase());
    assert!(verify_dir_identity(&upper, &install).is_ok());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn relative_traversing_and_non_drive_paths_are_refused() {
    let base = temp_base("shape");
    let ok = base.join("a");
    std::fs::create_dir_all(&ok).unwrap();
    assert_eq!(verify_dir_identity(Path::new(r"a\b"), &ok), Err(PathError::NotAbsolute));
    let dotdot = base.join("a").join("..").join("a");
    assert_eq!(verify_dir_identity(&dotdot, &ok), Err(PathError::NotCanonical));
    assert_eq!(verify_dir_identity(Path::new(r"\\?\C:\Windows"), &ok), Err(PathError::NotCanonical));
    assert_eq!(verify_dir_identity(Path::new(r"\\server\share\x"), &ok), Err(PathError::NotCanonical));
    assert_eq!(verify_dir_identity(&base.join("missing"), &ok), Err(PathError::Missing));
    let file = base.join("file.txt");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(verify_dir_identity(&file, &ok), Err(PathError::NotADirectory));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_junction_at_the_leaf_or_on_any_ancestor_is_refused() {
    let base = temp_base("junction");
    let real = base.join("real");
    std::fs::create_dir_all(real.join("RMT Agent")).unwrap();
    // Leaf: <base>\Program Files\RMT Agent is a junction to the real directory.
    let pf = base.join("Program Files");
    std::fs::create_dir_all(&pf).unwrap();
    let leaf = pf.join("RMT Agent");
    junction(&leaf, &real.join("RMT Agent"));
    assert!(matches!(verify_dir_identity(&leaf, &real.join("RMT Agent")), Err(PathError::ReparsePoint(_))), "leaf junction");
    remove_junction(&leaf);
    // Ancestor: <base>\linked is a junction to <base>\real, claimed as <base>\linked\RMT Agent.
    let linked = base.join("linked");
    junction(&linked, &real);
    let through = linked.join("RMT Agent");
    assert!(matches!(verify_dir_identity(&through, &real.join("RMT Agent")), Err(PathError::ReparsePoint(p)) if same_place(&p, &linked)), "ancestor junction");
    remove_junction(&linked);
    assert!(real.join("RMT Agent").is_dir(), "the junction target is untouched");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_directory_that_is_not_the_expected_one_is_refused() {
    let base = temp_base("mismatch");
    let (a, b) = (base.join("RMT Agent"), base.join("Downloads"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    assert!(matches!(verify_dir_identity(&b, &a), Err(PathError::Mismatch { .. })));
    let _ = std::fs::remove_dir_all(&base);
}

// ---- the config tree: tree validation, junctions, swaps ----------------------------------------------------

/// A temp `<base>\rmt-agent` pair hardened like production (needs the same elevation the anchor tests need).
fn hardened_root(tag: &str) -> (PathBuf, PathBuf) {
    let base = temp_base(tag);
    let root = base.join("rmt-agent");
    std::fs::create_dir_all(&root).unwrap();
    for dir in [&base, &root] {
        for args in [crate::agent_root::setowner_args(dir), crate::agent_root::dacl_args(dir)] {
            let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe")).args(args).output().unwrap();
            assert!(out.status.success(), "icacls failed (elevation required): {}", String::from_utf8_lossy(&out.stdout));
        }
    }
    (base, root)
}

fn populate(root: &Path) {
    // Created through the anchor (protected admin SD, trusted owner) exactly as SYSTEM-written state is in production; a plain
    // `std::fs::write` here would be owned by the test user, which the tree validation correctly refuses.
    let anchor = Anchor::open_at(root).unwrap();
    anchor.dir().write_atomic("config.json", b"{}").unwrap();
    anchor.dir().write_atomic("identity.key", "a".repeat(64).as_bytes()).unwrap();
    let rec = anchor.dir().child_dir("recordings", true).unwrap();
    rec.write_atomic("one.rmtrec", b"x").unwrap();
    rec.write_atomic("two.rmtrec", b"x").unwrap();
}

#[test]
fn the_config_tree_is_preflighted_then_deleted_contents_and_root() {
    let (base, root) = hardened_root("tree");
    populate(&root);
    let mut tree = ConfigTree::new();
    assert_eq!(tree.preflight(&root).unwrap(), 5, "config.json, identity.key, recordings, two files");
    // R1: everything EXCEPT identity.key goes first and is VERIFIED; the identity and the root go last.
    assert_eq!(tree.delete_except_identity(&root).unwrap(), 2, "config.json and the recordings directory (with its files)");
    tree.verify_only_identity_left(&root).unwrap();
    assert!(root.join("identity.key").exists(), "the identity survives the cleanup");
    assert!(!root.join("recordings").exists() && !root.join("config.json").exists());
    tree.delete_identity_and_root(&root, false).unwrap();
    assert!(!root.exists(), "the emptied agent root is removed too");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_junction_planted_in_the_config_tree_stops_the_preflight_and_the_target_survives() {
    let (base, root) = hardened_root("planted");
    populate(&root);
    let precious = base.join("precious");
    std::fs::create_dir_all(&precious).unwrap();
    std::fs::write(precious.join("keep.txt"), b"keep").unwrap();
    junction(&root.join("recordings-link"), &precious);
    let mut tree = ConfigTree::new();
    let err = tree.preflight(&root).unwrap_err();
    assert!(err.contains("reparse point"), "{err}");
    // Deleting without a pre-flight is refused outright.
    assert!(ConfigTree::new().delete_except_identity(&root).is_err());
    assert!(precious.join("keep.txt").exists());
    assert!(root.join("identity.key").exists(), "nothing was deleted");
    remove_junction(&root.join("recordings-link"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_junction_planted_between_preflight_and_delete_deletes_nothing_and_spares_its_target() {
    let (base, root) = hardened_root("late");
    populate(&root);
    let precious = base.join("precious");
    std::fs::create_dir_all(&precious).unwrap();
    std::fs::write(precious.join("keep.txt"), b"keep").unwrap();
    let mut tree = ConfigTree::new();
    tree.preflight(&root).unwrap();
    // After the pre-flight, a hostile process swaps a directory for a junction to somewhere precious.
    std::fs::remove_dir_all(root.join("recordings")).unwrap();
    junction(&root.join("recordings"), &precious);
    let err = tree.delete_except_identity(&root).unwrap_err();
    assert!(err.contains("reparse point"), "{err}");
    assert!(precious.join("keep.txt").exists(), "the junction target must survive");
    assert!(root.join("identity.key").exists(), "the re-walk stops the deletion before anything is removed");
    remove_junction(&root.join("recordings"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_root_swapped_for_another_directory_after_the_preflight_is_refused() {
    let (base, root) = hardened_root("swap");
    populate(&root);
    let mut tree = ConfigTree::new();
    tree.preflight(&root).unwrap();
    // Move the validated root away and put a different (also hardened) directory with the same name in its place.
    let moved = base.join("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    for args in [crate::agent_root::setowner_args(&root), crate::agent_root::dacl_args(&root)] {
        let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe")).args(args).output().unwrap();
        assert!(out.status.success());
    }
    std::fs::write(root.join("innocent.txt"), b"not the agent's").unwrap();
    let err = tree.delete_except_identity(&root).unwrap_err();
    assert!(err.contains("identity changed"), "{err}");
    assert!(root.join("innocent.txt").exists(), "the swapped-in directory is untouched");
    assert!(moved.join("identity.key").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_tree_deeper_or_larger_than_the_limit_is_refused() {
    let (base, root) = hardened_root("limits");
    let mut deep = root.clone();
    for i in 0..20 {
        deep = deep.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    let anchor = Anchor::open_at(&root).unwrap();
    assert!(anchor.dir().validate_tree(&TreeLimits { max_entries: 1000, max_depth: 4 }).is_err());
    assert!(anchor.dir().remove_tree_contents(&TreeLimits { max_entries: 1000, max_depth: 4 }).is_err());
    let _ = std::fs::remove_dir_all(&root.join("d0"));
    for i in 0..10 {
        std::fs::write(root.join(format!("f{i}")), b"x").unwrap();
    }
    assert!(anchor.dir().validate_tree(&TreeLimits { max_entries: 5, max_depth: 4 }).is_err());
    drop(anchor);
    let _ = std::fs::remove_dir_all(&base);
}

// ---- R4: the install chain is validated per component and HELD ---------------------------------------------

fn harden(dir: &Path) {
    for args in [crate::agent_root::setowner_args(dir), crate::agent_root::dacl_args(dir)] {
        let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe")).args(args).output().unwrap();
        assert!(out.status.success(), "icacls failed (elevation required): {}", String::from_utf8_lossy(&out.stdout));
    }
}

/// `<base>\Program Files\RMT Agent`, every component hardened like production; `base` plays the volume root (the floor).
fn install_chain(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = temp_base(tag);
    let pf = base.join("Program Files");
    let leaf = pf.join("RMT Agent");
    std::fs::create_dir_all(&leaf).unwrap();
    for d in [&base, &pf, &leaf] {
        harden(d);
    }
    (base, pf, leaf)
}

fn grant_users_write(dir: &Path) {
    let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe"))
        .arg(dir)
        .args(["/grant", "*S-1-5-32-545:(W)"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn a_hardened_install_chain_is_held_and_ancestors_cannot_be_renamed_while_it_is() {
    let (base, pf, leaf) = install_chain("hold-ok");
    let held = crate::anchor::hold_chain(&leaf, &base).expect("a hardened chain is accepted");
    assert!(same_place(Path::new(held.leaf_path()), &leaf), "the leaf path comes from the held handle: {}", held.leaf_path());
    // While held, the ancestor cannot be moved away and replaced (the swap the by-name check could not stop).
    // Delete access: an ancestor refuses it (sharing violation); the LEAF allows it, because the MSI removal deletes the leaf.
    let open_for_delete = |p: &Path| {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().access_mode(0x0001_0000).custom_flags(0x0200_0000).open(p).map(drop)
    };
    assert_eq!(open_for_delete(&pf).unwrap_err().raw_os_error(), Some(32), "ancestors are held without delete sharing");
    assert!(open_for_delete(&leaf).is_ok(), "the leaf stays deletable for the installer");
    let moved = base.join("moved-away");
    assert!(std::fs::rename(&pf, &moved).is_err(), "an ancestor of a held chain must not be renameable");
    assert!(pf.join("RMT Agent").exists());
    drop(held);
    std::fs::rename(&pf, &moved).expect("released: the ancestor can move again");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_user_writable_component_anywhere_in_the_chain_is_refused() {
    for which in ["leaf", "middle"] {
        let (base, pf, leaf) = install_chain(&format!("hold-bad-{which}"));
        grant_users_write(if which == "leaf" { &leaf } else { &pf });
        let err = crate::anchor::hold_chain(&leaf, &base).err().unwrap_or_else(|| panic!("{which} writable by Users must be refused"));
        assert!(err.to_string().contains("untrusted"), "{which}: {err}");
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[test]
fn a_junction_for_any_component_is_refused() {
    let (base, pf, leaf) = install_chain("hold-junction");
    let real = base.join("elsewhere");
    std::fs::create_dir_all(real.join("RMT Agent")).unwrap();
    harden(&real);
    harden(&real.join("RMT Agent"));
    // The middle component is a junction to a perfectly trusted directory: still refused (it could be repointed).
    std::fs::remove_dir_all(&pf).unwrap();
    junction(&pf, &real);
    let err = crate::anchor::hold_chain(&leaf, &base).err().expect("a junction component is refused");
    assert!(err.to_string().contains("reparse point"), "{err}");
    remove_junction(&pf);
    // A junction as the leaf.
    std::fs::create_dir_all(&pf).unwrap();
    harden(&pf);
    junction(&pf.join("RMT Agent"), &real.join("RMT Agent"));
    assert!(crate::anchor::hold_chain(&pf.join("RMT Agent"), &base).is_err());
    remove_junction(&pf.join("RMT Agent"));
    assert!(real.join("RMT Agent").exists(), "targets untouched");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_path_outside_the_floor_or_with_dots_is_refused() {
    let (base, _pf, leaf) = install_chain("hold-shape");
    assert!(crate::anchor::hold_chain(Path::new(r"C:\Windows"), &base).is_err(), "not under the floor");
    assert!(crate::anchor::hold_chain(&leaf.join("..").join("RMT Agent"), &base).is_err(), "dot components");
    let _ = std::fs::remove_dir_all(&base);
}

// ---- A2: the boot id is durable before the installer; the wait is bounded --------------------------------------

#[test]
fn the_boot_id_is_journaled_before_the_installer_runs_and_an_ambiguous_wait_is_bounded_by_the_deadline() {
    let mut r = rig();
    *r.journal.crash_after_save.borrow_mut() = Some(1);
    assert!(r.try_run().is_err());
    let j = r.journal.j.borrow().clone().unwrap();
    assert_eq!((j.phase, j.boot_at_msi.as_str()), (Phase::MsiStarting, "boot-1"), "persisted BEFORE configure_absent");
    // An ambiguous recovery that never sees a reboot cannot wait forever, but it also never claims `complete`: past the deadline it
    // reports `failed` (reboot not observed) and leaves everything for the operator.
    let mut r = rig();
    r.w.borrow_mut().crash_after = Some("configure_absent");
    assert!(r.try_run().is_err());
    assert!(matches!(r.run(), RemovalResult::Deferred { in_process: false, .. }));
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    let end = r.run();
    assert!(matches!(&end, RemovalResult::Failed(w) if w.contains("reboot")), "{end:?}");
    assert_eq!(r.count("delete_config_tree"), 0, "no cleanup before a reboot was observed");
    assert!(!r.log().iter().any(|e| e == "ack:executing->complete"), "complete is never generated before a later boot");
    assert_eq!(r.acks().last().unwrap().to, "failed");
    assert!(r.w.borrow().identity_present, "identity and config stay for the operator");
}

// ---- A1: the interim reboot_pending ack ----------------------------------------------------------------------------

fn reboot_rig() -> Rig {
    let r = rig();
    {
        let mut w = r.w.borrow_mut();
        w.rc = 3010;
        w.after_removal = vec![CODE.into()];
    }
    r
}

#[test]
fn a_lost_reboot_pending_answer_resends_the_identical_ack_and_never_signs_a_new_transition() {
    let mut r = reboot_rig();
    r.answers.borrow_mut().push(AckDelivery::Undeliverable);
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("reboot_pending")), "{first:?}");
    let j = r.journal.j.borrow().clone().unwrap();
    assert!(j.reboot_required && j.reboot_known && !j.reboot_ack_settled);
    assert_eq!(j.confirmed_state, "executing", "an undelivered ack must not advance the confirmed state");
    let stored = j.reboot_ack.clone().expect("persisted BEFORE it was sent");
    assert_eq!(r.acks()[0], stored);
    // The restart: the SAME ack goes out again (answered this time), only then the confirmed state advances.
    assert_eq!(r.run(), RemovalResult::RebootPending);
    assert_eq!(r.acks()[1], stored, "re-sent verbatim, not re-signed");
    let j = r.journal.j.borrow().clone().unwrap();
    assert_eq!((j.confirmed_state.as_str(), j.reboot_ack_settled), ("reboot_pending", true));
    assert!(r.acks().iter().filter(|a| a.to == "reboot_pending").all(|a| *a == stored), "exactly one reboot_pending transition ever signed");
    // After the reboot the final ack goes from reboot_pending.
    reboot_completes(&r);
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert_eq!(r.acks().last().unwrap().from, "reboot_pending");
}

#[test]
fn a_refused_reboot_pending_ack_is_not_confirmation_and_the_final_ack_goes_from_executing() {
    let mut r = reboot_rig();
    r.answers.borrow_mut().push(AckDelivery::Refused);
    assert_eq!(r.run(), RemovalResult::RebootPending);
    let j = r.journal.j.borrow().clone().unwrap();
    assert_eq!((j.confirmed_state.as_str(), j.reboot_ack_settled), ("executing", true), "Refused settles the attempt but confirms nothing");
    assert!(j.reboot_required, "the LOCAL reboot requirement is independent of the ack");
    reboot_completes(&r);
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    let last = r.acks().last().unwrap().clone();
    assert_eq!((last.from.as_str(), last.to.as_str()), ("executing", "complete"));
    assert!(proto::transition_allowed("executing", "complete"));
}

#[test]
fn an_undelivered_reboot_pending_ack_at_the_deadline_is_given_up_without_advancing_the_state() {
    let mut r = reboot_rig();
    r.answers.borrow_mut().extend(std::iter::repeat_n(AckDelivery::Undeliverable, 4));
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    reboot_completes(&r);
    let end = r.run();
    assert!(matches!(end, RemovalResult::Complete { .. } | RemovalResult::Unreported), "{end:?}");
    let j = r.journal.j.borrow().clone().unwrap();
    assert!(j.reboot_ack_settled);
    assert_eq!(j.confirmed_state, "executing", "never advanced without an applied/replay answer");
    let reboot_acks: Vec<_> = r.acks().into_iter().filter(|a| a.to == "reboot_pending").collect();
    // Re-signing happens only for a STALE ack (over 30 min), always the same transition, with a strictly larger timestamp.
    assert!(reboot_acks.iter().all(|a| (a.from.as_str(), a.to.as_str()) == ("executing", "reboot_pending")));
    assert!(reboot_acks.windows(2).all(|w| w[1].ts_ms > w[0].ts_ms));
}

// ---- A3: durable phases, Finished before the leftovers --------------------------------------------------------

#[test]
fn finished_is_durable_before_the_leftovers_go_and_the_handoff_goes_before_the_task() {
    let mut r = rig();
    // 1. The handoff cannot be deleted: the task MUST stay (it retries), and Finished is already durable.
    r.w.borrow_mut().secrets_err = Some("sharing violation".into());
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("secrets")), "{first:?}");
    assert_eq!(r.journal.j.borrow().as_ref().unwrap().phase, Phase::Finished { reported: true }, "Finished is written FIRST");
    assert!(r.w.borrow().task_installed, "a handoff that cannot be deleted keeps the restart task");
    assert_eq!(r.count("remove_resume_task"), 0, "the task is removed LAST: not before the handoff is gone");
    // 2. The handoff goes; the TASK cannot be removed: a propagated failure, the secrets are already gone.
    r.w.borrow_mut().secrets_err = None;
    r.w.borrow_mut().task_remove_err = Some("access denied".into());
    let second = r.run();
    assert!(matches!(&second, RemovalResult::Deferred { reason, .. } if reason.contains("restart task")), "{second:?}");
    assert!(!r.w.borrow().secrets_present && r.w.borrow().task_installed);
    // 3. Everything goes.
    r.w.borrow_mut().task_remove_err = None;
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    assert!(!r.w.borrow().task_installed);
    assert_eq!(r.count("configure_absent"), 1);
    assert_eq!(r.count("delete_config_tree_keep_identity"), 1, "a re-run in Finished only removes leftovers");
    // Order in a clean run: handoff, then task.
    let mut r = rig();
    r.run();
    assert!(r.pos("delete_helper_secrets") < r.pos("remove_resume_task"));
}

#[test]
fn a_crash_between_the_handoff_and_the_task_leaves_a_task_whose_finished_only_entry_point_removes_it_without_the_handoff() {
    let mut r = rig();
    r.w.borrow_mut().crash_after = Some("delete_secrets");
    assert!(r.try_run().is_err(), "power loss right after the handoff (identity seed) was deleted");
    assert!(!r.w.borrow().secrets_present && r.w.borrow().task_installed, "the task survives: it is what finishes the job");
    // The task fires; the handoff is gone, so the helper cannot load it. The Finished-only entry point needs the journal alone.
    let mut ops = FakeOps(r.w.clone());
    let res = run_leftovers_only(&mut ops, &r.journal);
    assert_eq!(res, RemovalResult::Complete { residue: None });
    assert!(!r.w.borrow().task_installed);
    assert_eq!(r.count("delete_config_tree_keep_identity"), 1, "nothing of the removal is repeated");
}

#[test]
fn the_finished_only_entry_point_touches_nothing_unless_the_removal_is_finished_or_aborted() {
    // No journal at all.
    let r = rig();
    let mut ops = FakeOps(r.w.clone());
    assert!(matches!(run_leftovers_only(&mut ops, &r.journal), RemovalResult::Failed(_)));
    // A removal that is only partly done (MsiDone): the handoff it needs is missing; the task must STAY.
    let mut r = rig();
    *r.journal.crash_after_save.borrow_mut() = Some(2);
    assert!(r.try_run().is_err());
    let mut ops = FakeOps(r.w.clone());
    let res = run_leftovers_only(&mut ops, &r.journal);
    assert!(matches!(&res, RemovalResult::Failed(w) if w.contains("not finished")), "{res:?}");
    assert!(r.w.borrow().task_installed, "an unfinished removal keeps its recovery task");
    assert_eq!(r.count("remove_resume_task"), 0);
    // Aborted: leftovers are removed.
    let mut r = rig();
    r.w.borrow_mut().rc = 1603;
    r.w.borrow_mut().task_remove_err = Some("busy".into());
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.w.borrow_mut().task_remove_err = None;
    let mut ops = FakeOps(r.w.clone());
    assert!(matches!(run_leftovers_only(&mut ops, &r.journal), RemovalResult::Failed(w) if w.contains("1603")));
    assert!(!r.w.borrow().task_installed);
}

#[test]
fn a_reboot_that_was_announced_but_never_observed_ends_failed_at_the_deadline_never_complete() {
    let mut r = reboot_rig();
    assert_eq!(r.run(), RemovalResult::RebootPending);
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    let end = r.run();
    assert!(matches!(&end, RemovalResult::Failed(w) if w.contains("reboot")), "{end:?}");
    assert!(!r.log().iter().any(|e| e == "ack:executing->complete" || e == "ack:reboot_pending->complete"));
    assert_eq!(r.count("delete_config_tree"), 0);
    let last = r.acks().last().unwrap().clone();
    assert_eq!(last.to, "failed");
    assert!(proto::transition_allowed(&last.from, "failed"));
    assert!(verify(&last));
    assert!(r.w.borrow().identity_present);
    // Had the boot changed, it would have completed.
    let mut r = reboot_rig();
    assert_eq!(r.run(), RemovalResult::RebootPending);
    reboot_completes(&r);
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    assert!(matches!(r.run(), RemovalResult::Complete { .. } | RemovalResult::Unreported));
}

#[test]
fn a_crash_after_the_identity_is_deleted_but_before_its_journal_entry_finishes_the_recovery() {
    let mut r = rig();
    r.w.borrow_mut().crash_after = Some("delete_identity");
    assert!(r.try_run().is_err());
    assert_eq!(r.journal.j.borrow().as_ref().unwrap().phase, Phase::ReportConfirmed { reported: true }, "the report is durable BEFORE the identity is touched");
    assert!(!r.w.borrow().identity_present);
    assert_eq!(r.run(), RemovalResult::Complete { residue: None }, "missing identity/root are success on retry");
    assert_eq!(r.w.borrow().identity_calls, vec![true, true], "finalization recovery allows an absent identity");
    assert_eq!(r.count("ack:executing->complete"), 1, "the report is not repeated");
}

#[test]
fn a_journal_write_failure_before_the_identity_phase_stops_the_identity_deletion() {
    let mut r = rig();
    // Saves: 1 MsiStarting, 2 MsiDone, 3 CleanupDone, 4 final ack, 5 ReportConfirmed. Fail the 5th.
    *r.journal.fail_from.borrow_mut() = Some(5);
    let res = r.run();
    assert!(matches!(&res, RemovalResult::Deferred { reason, .. } if reason.contains("journal")), "{res:?}");
    assert!(r.w.borrow().identity_present, "an identity is never deleted before ReportConfirmed is durable");
    assert_eq!(r.count("delete_identity_and_root"), 0);
    *r.journal.fail_from.borrow_mut() = None;
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
}

// ---- A4: agent_gone comes from the durable phase ----------------------------------------------------------------

#[test]
fn a_restarted_helper_knows_the_agent_is_gone_from_the_journal_before_it_delivers_anything() {
    let mut r = rig();
    *r.journal.crash_after_save.borrow_mut() = Some(2); // right after MsiDone is durable
    assert!(r.try_run().is_err());
    // A NEW process: its channel starts with agent_gone = false. A post-MSI failure report must still be delivered by it.
    r.w.borrow_mut().cleanup_err = Some("access denied".into());
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    let end = r.run();
    assert!(matches!(end, RemovalResult::Failed(_)), "{end:?}");
    assert_eq!(r.acks().last().unwrap().to, "failed");
    assert!(r.gone_at_send.borrow().iter().all(|g| *g), "every delivery after the MSI knew the agent was gone: {:?}", r.gone_at_send.borrow());
}

#[test]
fn the_helper_suppresses_its_own_failure_delivery_only_for_a_surviving_agent_with_a_durable_result() {
    for (gone, durable, suppressed) in [(false, true, true), (false, false, false), (true, true, false), (true, false, false)] {
        assert_eq!(crate::directive_win::failed_ack_suppressed(gone, durable), suppressed, "gone={gone} durable={durable}");
    }
}

// ---- A5: the clock is re-checked immediately before the installer -------------------------------------------------

#[test]
fn a_directive_that_expires_during_setup_is_durably_cancelled_and_no_installer_runs() {
    let mut r = rig();
    r.w.borrow_mut().advance_at_task = 3_600_000; // the restart task takes "an hour": the directive expires before the MSI call
    let res = r.run();
    assert!(matches!(&res, RemovalResult::Failed(w) if w.contains("expired")), "{res:?}");
    assert_eq!(r.count("configure_absent"), 0);
    assert!(matches!(&r.journal.j.borrow().as_ref().unwrap().phase, Phase::Aborted { reason } if reason.contains("expired")));
    let w = r.w.borrow();
    assert!(!w.task_installed && !w.held && !w.secrets_present, "the recovery task, the held chain and the handoff are all undone");
    assert!(w.identity_present);
    drop(w);
    // A stale firing of the task finds Aborted and still never runs the installer.
    r.w.borrow_mut().task_installed = true;
    assert!(matches!(r.run(), RemovalResult::Failed(_)));
    assert_eq!(r.count("configure_absent"), 0);
    assert!(!r.w.borrow().task_installed);
}

#[test]
fn an_aborted_removal_retries_the_task_removal_instead_of_swallowing_its_failure() {
    let mut r = rig();
    r.w.borrow_mut().rc = 1603;
    r.w.borrow_mut().task_remove_err = Some("access denied".into());
    let first = r.run();
    assert!(matches!(&first, RemovalResult::Deferred { reason, .. } if reason.contains("restart task")), "{first:?}");
    assert!(matches!(r.journal.j.borrow().as_ref().unwrap().phase, Phase::Aborted { .. }), "the abort is durable");
    r.w.borrow_mut().task_remove_err = None;
    assert!(matches!(r.run(), RemovalResult::Failed(w) if w.contains("1603")));
    assert_eq!(r.count("configure_absent"), 1);
}

// ---- A6: the identity and root are deleted only through the expected root -----------------------------------------

fn populated_identity_only(tag: &str) -> (PathBuf, PathBuf, ConfigTree) {
    let (base, root) = hardened_root(tag);
    populate(&root);
    let mut tree = ConfigTree::new();
    tree.preflight(&root).unwrap();
    tree.delete_except_identity(&root).unwrap();
    tree.verify_only_identity_left(&root).unwrap();
    (base, root, tree)
}

#[test]
fn the_identity_and_root_go_only_through_the_expected_root_with_nothing_else_in_it() {
    // Success path.
    let (base, root, mut tree) = populated_identity_only("a6-ok");
    tree.delete_identity_and_root(&root, false).unwrap();
    assert!(!root.exists());
    let _ = std::fs::remove_dir_all(&base);

    // Something besides identity.key is still there: refused, and the identity is NOT deleted.
    let (base, root, mut tree) = populated_identity_only("a6-extra");
    Anchor::open_at(&root).unwrap().dir().write_atomic("straggler.json", b"{}").unwrap();
    let err = tree.delete_identity_and_root(&root, false).unwrap_err();
    assert!(err.contains("straggler.json"), "{err}");
    assert!(root.join("identity.key").exists());
    let _ = std::fs::remove_dir_all(&base);

    // No expected identity (a tree that was never pre-flighted or expected): refused.
    let (base, root, _tree) = populated_identity_only("a6-noid");
    let mut fresh = ConfigTree::new();
    assert!(fresh.delete_identity_and_root(&root, true).unwrap_err().contains("identity is not known"));
    assert!(root.join("identity.key").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_root_swapped_for_another_directory_is_refused_even_during_finalization_recovery() {
    let (base, root, mut tree) = populated_identity_only("a6-swap");
    let moved = base.join("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    harden(&root);
    Anchor::open_at(&root).unwrap().dir().write_atomic("identity.key", b"someone else's key").unwrap();
    for allow in [false, true] {
        let err = tree.delete_identity_and_root(&root, allow).unwrap_err();
        assert!(err.contains("identity changed"), "allow_absent={allow}: {err}");
    }
    assert!(root.join("identity.key").exists(), "the swapped-in directory is untouched");
    assert!(moved.join("identity.key").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn an_absent_identity_or_root_is_success_only_during_finalization_recovery() {
    // Identity already gone (root empty): allowed only with allow_absent.
    let (base, root, mut tree) = populated_identity_only("a6-absent-id");
    Anchor::open_at(&root).unwrap().dir().remove_validated_file("identity.key").unwrap();
    assert!(tree.delete_identity_and_root(&root, false).unwrap_err().contains("not there"));
    tree.delete_identity_and_root(&root, true).unwrap();
    assert!(!root.exists());
    // The root itself already gone.
    assert!(tree.delete_identity_and_root(&root, true).is_ok(), "a vanished root is finished business during recovery");
    assert!(tree.delete_identity_and_root(&root, false).is_err(), "but not on the first attempt");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn nothing_of_the_recovery_setup_is_removed_before_finished_is_durable() {
    // Saves: 1 MsiStarting, 2 MsiDone, 3 CleanupDone, 4 final ack, 5 ReportConfirmed, 6 IdentityDeleted, 7 Finished.
    let mut r = rig();
    *r.journal.crash_after_save.borrow_mut() = Some(7);
    assert!(r.try_run().is_err(), "power loss right after Finished became durable");
    assert!(r.w.borrow().task_installed && r.w.borrow().secrets_present, "task and handoff are still there");
    assert_eq!(r.count("remove_resume_task"), 0, "{:?}", r.log());
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
    // And a crash BEFORE Finished (after IdentityDeleted) also leaves them.
    let mut r = rig();
    *r.journal.crash_after_save.borrow_mut() = Some(6);
    assert!(r.try_run().is_err());
    assert_eq!(r.count("remove_resume_task"), 0);
    assert!(r.w.borrow().task_installed);
}

// ---- the final-ack route's answers (docs/65 section 2b) ------------------------------------------------------

#[test]
fn a_410_is_terminal_not_confirmed_and_the_helper_cleans_up_as_unreported() {
    let mut r = rig();
    r.answers.borrow_mut().push(AckDelivery::Gone);
    assert_eq!(r.run(), RemovalResult::Unreported);
    assert_eq!(r.acks().len(), 1, "not retried");
    assert!(!r.w.borrow().identity_present, "the window is closed: the bounded policy applies (clean up, never claim complete)");
}

#[test]
fn a_404_is_retried_a_few_times_with_the_identical_ack_then_terminal_not_confirmed() {
    let mut r = rig();
    r.answers.borrow_mut().extend([AckDelivery::NotFound, AckDelivery::NotFound, AckDelivery::NotFound]);
    for n in 1..FINAL_ACK_NOTFOUND_LIMIT {
        assert!(matches!(r.run(), RemovalResult::Deferred { .. }), "404 #{n} is retried");
        assert!(r.w.borrow().identity_present);
        assert_eq!(r.journal.j.borrow().as_ref().unwrap().final_ack_notfound, n);
    }
    assert_eq!(r.run(), RemovalResult::Unreported, "the limit is terminal-not-confirmed");
    let acks = r.acks();
    assert_eq!(acks.len(), FINAL_ACK_NOTFOUND_LIMIT as usize);
    assert!(acks.iter().all(|a| *a == acks[0]), "the exact persisted ack every time");
    assert!(!r.w.borrow().identity_present);
}

#[test]
fn a_404_followed_by_a_confirmation_completes() {
    let mut r = rig();
    r.answers.borrow_mut().push(AckDelivery::NotFound);
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
}

#[test]
fn only_a_delivered_answer_makes_the_removal_complete() {
    // With the window open, only Delivered completes.
    for (answer, complete) in [(AckDelivery::Delivered, true), (AckDelivery::Refused, false), (AckDelivery::Gone, false)] {
        let mut r = rig();
        r.answers.borrow_mut().push(answer);
        let res = r.run();
        assert_eq!(matches!(res, RemovalResult::Complete { .. }), complete, "{answer:?} -> {res:?}");
        assert_eq!(matches!(res, RemovalResult::Unreported), !complete, "{answer:?}");
    }
}

#[test]
fn a_post_msi_cleanup_failure_is_persisted_as_the_exact_failed_ack_and_delivered_by_the_same_machinery() {
    let mut r = rig();
    r.w.borrow_mut().cleanup_err = Some("access denied".into());
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    r.answers.borrow_mut().push(AckDelivery::Undeliverable);
    let end = r.run();
    assert!(matches!(&end, RemovalResult::Failed(w) if w.contains("access denied")), "{end:?}");
    let j = r.journal.j.borrow().clone().unwrap();
    let stored = j.final_ack.clone().expect("persisted");
    assert_eq!((stored.from.as_str(), stored.to.as_str()), ("executing", "failed"));
    assert_eq!(r.acks().last().unwrap(), &stored, "the delivered ack IS the persisted one");
    assert!(verify(&stored));
    assert!(r.w.borrow().identity_present, "the failure leaves the identity for the operator");
    assert_eq!(r.count("delete_identity_and_root"), 0);
    assert!(matches!(j.phase, Phase::Finished { .. }));
}

#[test]
fn a_crash_after_the_failed_ack_is_persisted_resends_it_unchanged() {
    let mut r = rig();
    r.w.borrow_mut().cleanup_err = Some("access denied".into());
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    r.advance(3_600_000 + 24 * 3_600_000 + 1_000);
    // Saves so far: 1 MsiStarting, 2 MsiDone, then the failed-ack save (3 failed-attempt journal write, 4 persisted failed ack).
    let before = *r.journal.saves.borrow();
    *r.journal.crash_after_save.borrow_mut() = Some(before + 2);
    assert!(r.try_run().is_err());
    let stored = r.journal.j.borrow().as_ref().unwrap().final_ack.clone().expect("persisted before any send");
    assert!(r.acks().is_empty(), "nothing was sent before the crash");
    let res = r.run();
    assert!(matches!(res, RemovalResult::Failed(_)), "{res:?}");
    assert_eq!(r.acks()[0], stored);
}

// ---- release review 1.3.19 B1: the reboot-time removal is VERIFIED before any cleanup or `complete` -----------------

#[test]
fn a_reboot_time_removal_that_rolled_back_is_failed_and_keeps_identity_and_config() {
    let mut r = reboot_rig();
    assert_eq!(r.run(), RemovalResult::RebootPending);
    // After the reboot the product is STILL registered (the reboot-time removal failed or rolled back).
    r.w.borrow_mut().boot = "boot-2".into();
    let end = r.run();
    assert!(matches!(&end, RemovalResult::Failed(w) if w.contains("still installed")), "{end:?}");
    assert_eq!(r.count("delete_config_tree"), 0, "no cleanup of a product that is still installed");
    assert_eq!(r.count("delete_identity"), 0);
    assert!(r.w.borrow().identity_present, "the identity stays");
    let last = r.acks().last().unwrap().clone();
    assert_eq!((last.from.as_str(), last.to.as_str()), ("reboot_pending", "failed"));
    assert!(!r.acks().iter().any(|a| a.to == "complete"), "never complete");
}

#[test]
fn a_surviving_install_directory_after_the_reboot_is_failed_not_complete() {
    let mut r = reboot_rig();
    assert_eq!(r.run(), RemovalResult::RebootPending);
    {
        let mut w = r.w.borrow_mut();
        w.boot = "boot-2".into();
        w.after_removal = vec![]; // unregistered...
        w.install_dir_present = true; // ...but the files are still there
    }
    let end = r.run();
    assert!(matches!(&end, RemovalResult::Failed(w) if w.contains("install directory")), "{end:?}");
    assert_eq!(r.count("delete_config_tree"), 0);
    assert!(r.w.borrow().identity_present);
}

#[test]
fn a_busy_installer_after_the_reboot_defers_the_verification() {
    let mut r = reboot_rig();
    assert_eq!(r.run(), RemovalResult::RebootPending);
    {
        let mut w = r.w.borrow_mut();
        w.boot = "boot-2".into();
        w.after_removal = vec![];
        w.installer_busy = true;
    }
    assert!(matches!(r.run(), RemovalResult::Deferred { .. }));
    assert_eq!(r.count("delete_config_tree"), 0);
    r.w.borrow_mut().installer_busy = false;
    assert_eq!(r.run(), RemovalResult::Complete { residue: None });
}

/// The machine reboots and the reboot-time removal finishes: a later boot, and the registration is gone.
fn reboot_completes(r: &Rig) {
    let mut w = r.w.borrow_mut();
    w.boot = "boot-2".into();
    w.after_removal = vec![];
}
