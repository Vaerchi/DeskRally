//! The session's transfer root, held by handle (docs/58 §5, §12).
//!
//! Uploads used to be created, checked and committed BY NAME under `transfer_dir`. In a root a
//! local user can write, that is a SYSTEM-write primitive (swap the staging folder or an ancestor
//! between the check and the open), and the commit replaced any existing file of the same name. Here:
//!
//! * **Which root.** A host running as LocalSystem accepts ONLY the agent's own
//!   `C:\rmt-agent\transfers`, opened through the validated `C:\rmt-agent` anchor (owner and DACL
//!   checked, parent unable to delete-child) and created with the protected SD if absent. A
//!   configured `transfer_dir` naming anything else disables uploads for the session: trust is not
//!   purpose, and a trusted third-party folder is still a DLL-planting target. Any other host (the
//!   attended support client and dev runs, which run as the logged-in user and have nothing to
//!   escalate) opens its root as given, refusing only a reparse point.
//! * **By handle.** The root and its `.rmt-staging` child are opened once and held without delete
//!   sharing. `.part` files are created relative to the staging handle (`FILE_CREATE`, shared for
//!   read only while written), committed by a handle-relative rename into the root, and discarded by
//!   handle. Nothing is resolved by name after the root is opened.
//! * **Never replaces.** A commit onto an existing name lands as `name (2).ext` … `name (99).ext`,
//!   then refuses. A pre-existing file in the root is never overwritten by an upload.
//! * **Completed uploads** are recorded by transfer id with their landing name, digest and file
//!   identity, for `PlaceUpload` / `DiscardUpload` (fs_manage), which re-open them relative to the
//!   held root and check the identity.

#![cfg(windows)]

use std::collections::HashMap;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use uuid::Uuid;

use crate::anchor::{self, Disposition, FileIdentity};

/// The staging folder's name inside the root (in-progress `.part` files, named only by transfer id).
pub(crate) const STAGING: &str = ".rmt-staging";

const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_LIST_DIRECTORY: u32 = 0x1;
const FILE_TRAVERSE: u32 = 0x20;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// One committed upload, as `PlaceUpload` / `DiscardUpload` will find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Completed {
    /// The name it landed under in the root (may differ from the offered name: never replaces).
    pub name: String,
    /// The digest verified at commit.
    pub sha256: String,
    /// Volume serial + file id of the committed file.
    pub identity: FileIdentity,
}

enum Held {
    /// `C:\rmt-agent` (held, validated) and its `transfers` child (validated).
    Anchored { _anchor: anchor::Anchor, dir: anchor::Dir },
    /// A root opened as given (non-SYSTEM hosts).
    Plain(OwnedHandle),
}

impl Held {
    fn raw(&self) -> RawHandle {
        match self {
            Held::Anchored { dir, .. } => dir.raw(),
            Held::Plain(h) => h.as_raw_handle(),
        }
    }
}

enum Staging {
    /// The anchored root's `.rmt-staging`: owner and DACL validated, created with the protected SD.
    Validated(anchor::Dir),
    /// A plain root's staging folder (non-SYSTEM hosts).
    Plain(OwnedHandle),
}

impl Staging {
    fn raw(&self) -> RawHandle {
        match self {
            Staging::Validated(d) => d.raw(),
            Staging::Plain(h) => h.as_raw_handle(),
        }
    }
}

pub(crate) struct UploadRoot {
    root: Held,
    staging: Staging,
    /// Every transfer id this session has started (docs/58 §12, Codex review r2): an id is used
    /// once, so a completed record is never overwritten by a later upload under the same id.
    used: Mutex<std::collections::HashSet<Uuid>>,
    /// The root's path, for display, free-space checks and audit text only (never opened by name).
    display: PathBuf,
    /// Whether this root is the agent's own anchored folder (placement is offered only then).
    anchored: bool,
    completed: Mutex<HashMap<Uuid, Completed>>,
}

impl UploadRoot {
    /// Open the session's root. `system` is whether this process runs as LocalSystem.
    pub(crate) fn open(transfer_dir: &Path, system: bool) -> Result<Self, String> {
        if system {
            Self::open_anchored(transfer_dir)
        } else if test_harness_anchored() {
            // TEST-HARNESS BUILDS ONLY (see `test_harness_anchored`): the e2e agent is not SYSTEM, so
            // it would never offer placement. A plain root marked anchored lets the console's
            // "Upload here" flow be driven end to end against a real agent.
            let mut root = Self::open_plain(transfer_dir)?;
            root.anchored = true;
            Ok(root)
        } else {
            Self::open_plain(transfer_dir)
        }
    }

    fn open_anchored(transfer_dir: &Path) -> Result<Self, String> {
        if !same_path(transfer_dir, Path::new(crate::config::DEFAULT_TRANSFER_DIR)) {
            return Err(format!(
                "uploads use the agent's own transfer folder ({}); the configured transfer_dir {} is not used on this machine",
                crate::config::DEFAULT_TRANSFER_DIR,
                transfer_dir.display()
            ));
        }
        Self::open_anchored_at(Path::new(crate::config::CONFIG_DIR), PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR))
    }

    /// The anchored open against the anchor at `anchor_dir` (production: `C:\rmt-agent`; tests: a
    /// hardened temp pair). The root AND its staging folder are validated children (owner and DACL
    /// checked, created with the protected SD), so a pre-existing staging folder a non-admin can
    /// write is refused rather than trusted (Codex phase B review, r2).
    fn open_anchored_at(anchor_dir: &Path, display: PathBuf) -> Result<Self, String> {
        let anchor = anchor::Anchor::open_at(anchor_dir).map_err(|e| format!("the agent folder could not be verified: {e}"))?;
        let dir = anchor
            .dir()
            .child_dir("transfers", true)
            .map_err(|e| format!("the transfer folder could not be verified: {e}"))?;
        let staging = dir.child_dir(STAGING, true).map_err(|e| format!("the staging folder could not be verified: {e}"))?;
        Ok(Self {
            root: Held::Anchored { _anchor: anchor, dir },
            staging: Staging::Validated(staging),
            used: Mutex::new(Default::default()),
            display,
            anchored: true,
            completed: Mutex::new(HashMap::new()),
        })
    }

    fn open_plain(transfer_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(transfer_dir).map_err(|e| format!("create transfer dir failed: {e}"))?;
        let root = open_dir_by_path(transfer_dir).map_err(|e| format!("open transfer dir failed: {e}"))?;
        if anchor::attributes(root.as_raw_handle()).map_err(|e| e.to_string())? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("the transfer folder is a junction or link; refused".into());
        }
        let staging = open_staging(root.as_raw_handle()).map_err(|e| format!("{STAGING}: {e}"))?;
        Ok(Self {
            root: Held::Plain(root),
            staging: Staging::Plain(staging),
            used: Mutex::new(Default::default()),
            display: transfer_dir.to_path_buf(),
            anchored: false,
            completed: Mutex::new(HashMap::new()),
        })
    }

    /// TEST SEAM: a plain root that claims to be anchored, so placement can be exercised without
    /// LocalSystem (the real anchored open needs the hardened `C:\rmt-agent`).
    #[cfg(test)]
    pub(crate) fn anchored_for_test(dir: &Path) -> Self {
        let mut r = Self::open_plain(dir).expect("open test root");
        r.anchored = true;
        r
    }

    pub(crate) fn display(&self) -> &Path {
        &self.display
    }

    pub(crate) fn is_anchored(&self) -> bool {
        self.anchored
    }

    pub(crate) fn root_raw(&self) -> RawHandle {
        self.root.raw()
    }

    /// The display path a file named `name` in the root has (audit text only).
    pub(crate) fn display_of(&self, name: &str) -> String {
        self.display.join(name).to_string_lossy().into_owned()
    }

    /// Create the `.part` file for transfer `id` relative to the held staging handle. It is shared for
    /// read only, so nothing else can write, rename or delete it while the upload holds it. In the
    /// anchored root it gets the protected admin-only SD explicitly (never an inherited one), which
    /// it keeps when committed into the root. Each transfer id can start once per session.
    pub(crate) fn create_part(&self, id: Uuid) -> io::Result<std::fs::File> {
        if !self.used.lock().unwrap_or_else(|p| p.into_inner()).insert(id) {
            return Err(io::Error::other("this transfer id was already used in this session"));
        }
        let name = format!("{id}.part");
        let access = GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE;
        let h = match &self.staging {
            Staging::Validated(_) => anchor::create_protected_file(self.staging.raw(), &name, access, FILE_SHARE_READ)?,
            Staging::Plain(_) => {
                anchor::open_relative(self.staging.raw(), &name, access, FILE_SHARE_READ, Disposition::Create, FILE_NON_DIRECTORY_FILE)?
            }
        };
        Ok(std::fs::File::from(h))
    }

    /// Commit a verified `.part` (by its handle) into the root under `name`, or the first free
    /// `name (n).ext`. Returns the name used and the file's identity. Never replaces.
    pub(crate) fn commit(&self, part: &std::fs::File, name: &str) -> io::Result<(String, FileIdentity)> {
        let identity = anchor::file_identity(part.as_raw_handle())?;
        for candidate in landing_names(name) {
            match anchor::rename_into(part.as_raw_handle(), self.root.raw(), &candidate, false) {
                Ok(()) => return Ok((candidate, identity)),
                Err(e) if matches!(e.raw_os_error(), Some(80) | Some(183)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("too many files with that name in the transfer folder"))
    }

    /// Delete a `.part` (or any file this root's upload holds) by its handle.
    pub(crate) fn discard(part: &std::fs::File) -> io::Result<()> {
        anchor::delete_by_handle(part.as_raw_handle())
    }

    pub(crate) fn record_completed(&self, id: Uuid, done: Completed) {
        self.completed.lock().unwrap_or_else(|p| p.into_inner()).insert(id, done);
    }

    pub(crate) fn completed(&self, id: Uuid) -> Option<Completed> {
        self.completed.lock().unwrap_or_else(|p| p.into_inner()).get(&id).cloned()
    }

    /// Consume a completed record (a placement or discard succeeded): it can be used once.
    pub(crate) fn take_completed(&self, id: Uuid) -> Option<Completed> {
        self.completed.lock().unwrap_or_else(|p| p.into_inner()).remove(&id)
    }
}

fn open_staging(root: RawHandle) -> io::Result<OwnedHandle> {
    let h = anchor::open_relative(
        root,
        STAGING,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        Disposition::OpenIf,
        FILE_DIRECTORY_FILE,
    )?;
    if anchor::attributes(h.as_raw_handle())? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(format!("{STAGING} is a junction or link; refused")));
    }
    Ok(h)
}

fn open_dir_by_path(path: &Path) -> io::Result<OwnedHandle> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_MODE, OPEN_EXISTING,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let h = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0),
            None,
        )?
    };
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0) })
}

/// `RMT_TEST_UPLOADS_ANCHORED=1`, honoured ONLY in `test-harness` builds (production binaries do not
/// contain the check): treat the plain test root as the anchored one so e2e can exercise placement.
pub(crate) fn test_harness_anchored() -> bool {
    #[cfg(feature = "test-harness")]
    {
        std::env::var("RMT_TEST_UPLOADS_ANCHORED").as_deref() == Ok("1")
    }
    #[cfg(not(feature = "test-harness"))]
    {
        false
    }
}

/// Whether `dir` is the agent's own transfer folder (the only root a LocalSystem host uploads to).
pub(crate) fn is_default_transfer_dir(dir: &Path) -> bool {
    same_path(dir, Path::new(crate::config::DEFAULT_TRANSFER_DIR))
}

/// Case-insensitive comparison of two absolute paths, ignoring a trailing separator.
fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().trim_end_matches(['\\', '/']).replace('/', "\\").to_lowercase();
    norm(a) == norm(b)
}

/// `name`, then `stem (2).ext` … `stem (99).ext`.
pub(crate) fn landing_names(name: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    std::iter::once(name.to_string()).chain((2..=99).map(move |n| format!("{stem} ({n}){ext}")))
}

/// The session's root, opened on the FIRST authorized upload (docs/58 §12): a session that never
/// uploads creates nothing, and a refused Offer touches no disk. Shared (`Arc`) with the file manager,
/// which places and discards completed uploads relative to the same held handles.
pub(crate) struct LazyRoot {
    transfer_dir: PathBuf,
    system: bool,
    cell: Option<Result<std::sync::Arc<UploadRoot>, String>>,
}

impl LazyRoot {
    pub(crate) fn new(transfer_dir: PathBuf, system: bool) -> Self {
        Self { transfer_dir, system, cell: None }
    }

    /// The root, opening it on first use. An open that failed stays failed for the session, with
    /// its reason (every later Offer is answered with it).
    pub(crate) fn get(&mut self) -> Result<&std::sync::Arc<UploadRoot>, &str> {
        if self.cell.is_none() {
            let opened = UploadRoot::open(&self.transfer_dir, self.system).map(std::sync::Arc::new);
            if let Err(reason) = &opened {
                tracing::warn!(%reason, "uploads are disabled for this session");
            }
            self.cell = Some(opened);
        }
        match self.cell.as_ref().expect("set above") {
            Ok(root) => Ok(root),
            Err(reason) => Err(reason.as_str()),
        }
    }

    /// The root if it was opened successfully, without opening it.
    pub(crate) fn opened(&self) -> Option<&std::sync::Arc<UploadRoot>> {
        match &self.cell {
            Some(Ok(root)) => Some(root),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmt-uproot-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn landing_names_keep_the_extension_and_stop_at_99() {
        let v: Vec<String> = landing_names("tool.exe").take(3).collect();
        assert_eq!(v, ["tool.exe", "tool (2).exe", "tool (3).exe"]);
        assert_eq!(landing_names("README").nth(1).unwrap(), "README (2)");
        assert_eq!(landing_names(".env").nth(1).unwrap(), ".env (2)");
        assert_eq!(landing_names("a.b.c").nth(1).unwrap(), "a.b (2).c");
        assert_eq!(landing_names("x").count(), 99);
    }

    #[test]
    fn a_system_host_refuses_any_root_but_the_agents_own() {
        // Whatever this test process is, the PATH check comes first and refuses without touching
        // the disk: a custom root is never trusted as an upload destination for SYSTEM.
        let other = tmp("custom");
        match UploadRoot::open(&other, true) {
            Err(e) => assert!(e.contains("agent's own transfer folder"), "{e}"),
            Ok(_) => panic!("a custom root must be refused on a SYSTEM host"),
        }
    }

    #[test]
    fn commits_never_replace_and_land_under_a_free_name() {
        let dir = tmp("commit");
        std::fs::write(dir.join("tool.exe"), b"keep me").unwrap();
        let root = UploadRoot::open(&dir, false).unwrap();
        let id = Uuid::new_v4();
        let mut part = root.create_part(id).unwrap();
        part.write_all(b"new bytes").unwrap();
        let (name, identity) = root.commit(&part, "tool.exe").unwrap();
        assert_eq!(name, "tool (2).exe");
        assert_eq!(std::fs::read(dir.join("tool.exe")).unwrap(), b"keep me", "an existing file is never replaced");
        assert_eq!(std::fs::read(dir.join("tool (2).exe")).unwrap(), b"new bytes");
        assert!(!dir.join(STAGING).join(format!("{id}.part")).exists(), "the .part became the landed file");
        let landed = std::fs::File::open(dir.join("tool (2).exe")).unwrap();
        assert_eq!(anchor::file_identity(landed.as_raw_handle()).unwrap(), identity);
    }

    #[test]
    fn a_part_is_held_against_other_writers_and_discarded_by_handle() {
        let dir = tmp("held");
        let root = UploadRoot::open(&dir, false).unwrap();
        let id = Uuid::new_v4();
        let part = root.create_part(id).unwrap();
        let path = dir.join(STAGING).join(format!("{id}.part"));
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err(), "nobody else may write the .part");
        assert!(std::fs::remove_file(&path).is_err(), "nobody else may delete it");
        UploadRoot::discard(&part).unwrap();
        drop(part);
        assert!(!path.exists());
    }

    #[test]
    fn a_junction_planted_as_staging_is_refused() {
        let dir = tmp("junction");
        let target = tmp("junction-target");
        let out = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J", &dir.join(STAGING).to_string_lossy(), &target.to_string_lossy()])
            .output()
            .unwrap();
        assert!(out.status.success());
        match UploadRoot::open(&dir, false) {
            Err(e) => assert!(e.contains("junction"), "{e}"),
            Ok(_) => panic!("a planted staging junction must be refused"),
        }
    }

    /// Run AS LocalSystem in the VM (`--ignored`): the agent's real folder opens anchored, a commit
    /// lands in it, and the record is placeable. This is the path production uses and the one the
    /// ordinary test process (not SYSTEM) cannot reach.
    #[test]
    #[ignore = "needs LocalSystem and the installed agent's C:\\rmt-agent; run in the VM"]
    fn the_agents_own_folder_opens_anchored_as_system() {
        assert!(crate::update_worker::is_local_system(), "run this as NT AUTHORITY\\SYSTEM");
        let root = UploadRoot::open(Path::new(crate::config::DEFAULT_TRANSFER_DIR), true).expect("anchored open");
        assert!(root.is_anchored());
        let id = Uuid::new_v4();
        let mut part = root.create_part(id).unwrap();
        part.write_all(b"vm").unwrap();
        assert!(anchor::is_protected_file(part.as_raw_handle()).unwrap(), "the .part is admin-only");
        let (name, _) = root.commit(&part, &format!("vm-anchored-{id}.txt")).unwrap();
        drop(part);
        let landed = Path::new(crate::config::DEFAULT_TRANSFER_DIR).join(&name);
        assert_eq!(std::fs::read(&landed).unwrap(), b"vm");
        let _ = std::fs::remove_file(&landed);
        // A custom root is refused on SYSTEM.
        assert!(UploadRoot::open(&std::env::temp_dir(), true).is_err());
    }

    /// Codex phase B review r2: an id is used once per session, so a completed record can never be
    /// overwritten (and then consumed) by a later upload under the same id.
    #[test]
    fn a_transfer_id_starts_once_per_session() {
        let dir = tmp("once");
        let root = UploadRoot::open(&dir, false).unwrap();
        let id = Uuid::new_v4();
        let part = root.create_part(id).unwrap();
        UploadRoot::discard(&part).unwrap();
        drop(part);
        let err = root.create_part(id).unwrap_err();
        assert!(err.to_string().contains("already used"), "{err}");
        assert!(root.create_part(Uuid::new_v4()).is_ok(), "another id still starts");
    }

    /// A hardened `<base>\rmt-agent` pair, like production (the suite runs elevated; see anchor.rs).
    fn hardened_anchor() -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("rmt-uproot-anchor-{}", Uuid::new_v4()));
        let root = base.join("rmt-agent");
        std::fs::create_dir_all(&root).unwrap();
        for dir in [&base, &root] {
            icacls(crate::agent_root::setowner_args(dir));
            icacls(crate::agent_root::dacl_args(dir));
        }
        (base, root)
    }

    fn icacls(args: Vec<std::ffi::OsString>) {
        let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe")).args(args).output().unwrap();
        assert!(out.status.success(), "icacls failed (elevation required): {}", String::from_utf8_lossy(&out.stdout));
    }

    /// The anchored root validates its staging folder and creates each `.part` with the protected
    /// SD, whatever the folder would hand down.
    #[test]
    fn an_anchored_root_writes_protected_parts() {
        let (base, anchor_dir) = hardened_anchor();
        let root = UploadRoot::open_anchored_at(&anchor_dir, anchor_dir.join("transfers")).expect("anchored open");
        let mut part = root.create_part(Uuid::new_v4()).unwrap();
        part.write_all(b"x").unwrap();
        assert!(anchor::is_protected_file(part.as_raw_handle()).unwrap(), "the .part must be admin-only");
        let (name, _) = root.commit(&part, "p.txt").unwrap();
        assert_eq!(name, "p.txt");
        assert!(anchor::is_protected_file(part.as_raw_handle()).unwrap(), "and stays so once committed");
        drop(part);
        drop(root);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An INHERIT-ONLY grant to Users on the staging folder does not touch the folder itself, so
    /// validation passes; the explicit SD is what keeps each `.part` from inheriting it.
    #[test]
    fn a_part_never_inherits_an_inherit_only_grant_on_staging() {
        let (base, anchor_dir) = hardened_anchor();
        drop(UploadRoot::open_anchored_at(&anchor_dir, anchor_dir.join("transfers")).expect("premise: a clean open"));
        let staging = anchor_dir.join("transfers").join(STAGING);
        icacls(vec![staging.into_os_string(), "/grant".into(), "*S-1-5-32-545:(OI)(IO)(M)".into()]);
        let root = UploadRoot::open_anchored_at(&anchor_dir, anchor_dir.join("transfers")).expect("inherit-only passes validation");
        let part = root.create_part(Uuid::new_v4()).unwrap();
        assert!(anchor::is_protected_file(part.as_raw_handle()).unwrap(), "the .part must not inherit the Users grant");
        UploadRoot::discard(&part).unwrap();
        drop(part);
        drop(root);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A pre-existing staging folder that Users can write is REFUSED, not trusted (Codex r2).
    #[test]
    fn an_anchored_root_refuses_a_staging_folder_users_can_write() {
        let (base, anchor_dir) = hardened_anchor();
        drop(UploadRoot::open_anchored_at(&anchor_dir, anchor_dir.join("transfers")).expect("premise: a clean open"));
        let staging = anchor_dir.join("transfers").join(STAGING);
        icacls(vec![staging.into_os_string(), "/grant".into(), "*S-1-5-32-545:(OI)(CI)(M)".into()]);
        match UploadRoot::open_anchored_at(&anchor_dir, anchor_dir.join("transfers")) {
            Err(e) => assert!(e.contains("staging folder could not be verified"), "{e}"),
            Ok(_) => panic!("a Users-writable staging folder must be refused"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn completed_records_are_consumed_once() {
        let dir = tmp("records");
        let root = UploadRoot::open(&dir, false).unwrap();
        let id = Uuid::new_v4();
        let c = Completed { name: "a".into(), sha256: "00".into(), identity: FileIdentity { volume: 1, id: [2; 16] } };
        root.record_completed(id, c.clone());
        assert_eq!(root.completed(id), Some(c.clone()));
        assert_eq!(root.take_completed(id), Some(c));
        assert_eq!(root.take_completed(id), None);
    }
}
