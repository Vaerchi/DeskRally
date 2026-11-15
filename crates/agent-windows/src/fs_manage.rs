//! Backstage file management on Windows (docs/58 §4-§5): the [`FileManager`] the host equips its
//! dispatcher with.
//!
//! The agent acts as SYSTEM, and a local user can race any check that is made by NAME, so nothing
//! here acts by name:
//!
//! * The volume root is opened, then every directory component is opened RELATIVE to the previous
//!   handle (`NtCreateFile`, `OBJ_DONT_REPARSE`, the object itself rather than what a link points
//!   at). A component that is a reparse point (junction, symlink, mount point, a cloud or network
//!   placeholder) is refused, so no link is ever traversed.
//! * Each directory handle is held WITHOUT `FILE_SHARE_DELETE` until the operation ends, so nobody
//!   can rename or delete it in between: the directory that was checked is the directory acted in.
//! * The act itself is relative to the held parent: create with `FILE_CREATE`, delete by handle,
//!   rename by handle with no replacement. The final component is opened as itself, so a link is
//!   deleted or renamed as the link.
//! * Protection is by FILE IDENTITY (volume serial + file id), taken once from the agent's own
//!   directories and their ancestors, so case, 8.3 aliases and `\\?\` spellings cannot evade it.
//!
//! Placing and discarding an upload (`PlaceUpload` / `DiscardUpload`, docs/58 §12) work only on a
//! session whose transfer root is the agent's own anchored folder, on the completed-upload records
//! the upload writer keeps: the landing file is re-opened RELATIVE TO THE HELD ROOT and must have the
//! identity recorded at commit (no re-hash: only SYSTEM or an Administrator can change a file there).
//! Placement is a handle-relative rename that never replaces, onto the same volume.

#![cfg(windows)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use rmt_agent::backstage::audit::AuditAction;
use rmt_agent::backstage::fileops::{CommitError, FileManager, FileOp, PrepareError, Prepared};
use rmt_agent::backstage::rbac::GuardRail;

use crate::anchor::{self, Disposition, FileIdentity};

const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_LIST_DIRECTORY: u32 = 0x1;
const FILE_TRAVERSE: u32 = 0x20;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

const REFUSE_SHAPE: &str =
    r"only an absolute path on a local drive such as D:\work is allowed (no network, device or \\?\ paths, no ..)";
const REFUSE_NAME: &str = r#"that name is not allowed: no <>:"/\|?* or control characters, no trailing dot or space, and not a device name such as CON or NUL"#;
const REFUSE_REMOTE: &str = "that drive is a mapped network drive; this machine will not change files on it";
const REFUSE_LINK: &str = "a link or junction is on this path; open the folder it points to directly";
const REFUSE_PROTECTED: &str = "that is the remote-support agent's own folder (or contains it), which cannot be changed from here";
const REFUSE_ROOT: &str = "a drive's root folder cannot be created, renamed or deleted";
const REFUSE_DRIVE: &str = "only fixed and removable drives can be changed from here";
const NO_UPLOADS: &str = "placing uploads is available only for files uploaded in this session to the agent's own transfer folder";
const UPLOAD_GONE: &str = "that upload is not available (it was not received in this session, or it was already placed or discarded)";
const UPLOAD_REPLACED: &str = "that upload is no longer the file this session received; upload it again";

const CONFIRM_DELETE: &str = "deleting cannot be undone";
const CONFIRM_SYSTEM: &str = "this changes a Windows system or program folder";
const CONFIRM_ROOT_CHILD: &str = "this changes a folder at the top of a drive";

/// The identities the guard rails compare against.
pub struct WinFileManager {
    /// The agent's own directories: nothing inside them may be changed.
    protected: Vec<FileIdentity>,
    /// Every ancestor of a protected directory: none may be renamed or deleted (that would move or
    /// remove the protected directory).
    protected_ancestors: Vec<FileIdentity>,
    /// Windows and program directories: changes inside them need confirmation.
    sensitive: Vec<FileIdentity>,
    /// A protected directory that did not exist when the manager was built, as (its parent's
    /// identity, its lower-case name): nobody may create it, or rename something to it, from here
    /// (a directory created this way would inherit the parent's permissions, which for `C:\` let any
    /// user modify it, and the installer would then trust it).
    missing_protected: Vec<(FileIdentity, String)>,
    /// The session's held transfer root once the upload writer opened it (docs/58 §12).
    uploads: Option<std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::upload_root::UploadRoot>>>>>,
}

impl WinFileManager {
    /// The production set: the config root, the service-binary directory and the running
    /// executable's directory are protected; `%SystemRoot%`, `%ProgramFiles%`,
    /// `%ProgramFiles(x86)%` and `%ProgramData%` are sensitive.
    pub fn for_this_agent() -> Self {
        let mut protected = vec![
            PathBuf::from(crate::config::CONFIG_DIR),
            PathBuf::from(crate::config::BIN_DIR),
        ];
        if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
            protected.push(dir);
        }
        let sensitive: Vec<PathBuf> = ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"]
            .iter()
            .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
            .collect();
        Self::with_paths(&protected, &sensitive)
    }

    /// Build from explicit directories (tests point these at temp folders). A directory that cannot
    /// be opened contributes nothing; the identities that can be taken still protect.
    pub fn with_paths(protected: &[PathBuf], sensitive: &[PathBuf]) -> Self {
        let mut me = Self {
            protected: Vec::new(),
            protected_ancestors: Vec::new(),
            sensitive: Vec::new(),
            missing_protected: Vec::new(),
            uploads: None,
        };
        for dir in protected {
            if let Some(id) = identity_of(dir) {
                me.protected.push(id);
            } else if let (Some(parent), Some(name)) = (dir.parent(), dir.file_name().and_then(|n| n.to_str())) {
                if let Some(pid) = identity_of(parent) {
                    me.missing_protected.push((pid, name.to_lowercase()));
                }
            }
            for ancestor in dir.ancestors().skip(1) {
                if let Some(id) = identity_of(ancestor) {
                    me.protected_ancestors.push(id);
                }
            }
        }
        me.sensitive = sensitive.iter().filter_map(|d| identity_of(d)).collect();
        me
    }

    /// Let this manager place and discard the session's completed uploads.
    pub(crate) fn with_upload_root(
        mut self,
        slot: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::upload_root::UploadRoot>>>>,
    ) -> Self {
        self.uploads = Some(slot);
        self
    }

    /// The session's anchored root, if uploads have been received to it.
    fn upload_root(&self) -> Result<std::sync::Arc<crate::upload_root::UploadRoot>, PrepareError> {
        let root = self
            .uploads
            .as_ref()
            .and_then(|slot| slot.lock().unwrap_or_else(|p| p.into_inner()).clone())
            .ok_or_else(|| PrepareError::Exec(NO_UPLOADS.into()))?;
        if !root.is_anchored() {
            return Err(PrepareError::Exec(NO_UPLOADS.into()));
        }
        Ok(root)
    }

    /// Open a completed upload's landing file relative to the held root and check it is the file the
    /// session committed: a regular file, not a link, with the recorded identity.
    fn open_completed(
        &self,
        root: &crate::upload_root::UploadRoot,
        transfer_id: uuid::Uuid,
    ) -> Result<(crate::upload_root::Completed, OwnedHandle), PrepareError> {
        let rec = root.completed(transfer_id).ok_or(PrepareError::Refused(UPLOAD_GONE))?;
        let h = anchor::open_relative(
            root.root_raw(),
            &rec.name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ,
            Disposition::Open,
            FILE_NON_DIRECTORY_FILE,
        )
        .map_err(|e| if matches!(e.raw_os_error(), Some(2) | Some(3)) { PrepareError::Refused(UPLOAD_GONE) } else { io_err(e) })?;
        let attrs = anchor::attributes(h.as_raw_handle()).map_err(io_err)?;
        let id = anchor::file_identity(h.as_raw_handle()).map_err(io_err)?;
        if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 || id != rec.identity {
            return Err(PrepareError::Refused(UPLOAD_REPLACED));
        }
        Ok((rec, h))
    }

    fn deny_in_chain(&self, walk: &Walk) -> Option<GuardRail> {
        walk.ids().any(|id| self.protected.contains(id)).then_some(GuardRail::Deny { reason: REFUSE_PROTECTED })
    }

    /// Creating `name` in the walk's directory (or renaming something to it) would make one of the
    /// agent's own directories that did not exist when this manager was built.
    fn deny_new_name(&self, walk: &Walk, name: &str) -> Option<GuardRail> {
        let parent = walk.dir_id();
        let lower = name.to_lowercase();
        self.missing_protected
            .iter()
            .any(|(pid, n)| *pid == parent && *n == lower)
            .then_some(GuardRail::Deny { reason: REFUSE_PROTECTED })
    }

    fn deny_object(&self, id: &FileIdentity) -> Option<GuardRail> {
        (self.protected.contains(id) || self.protected_ancestors.contains(id))
            .then_some(GuardRail::Deny { reason: REFUSE_PROTECTED })
    }

    /// Confirmation reason for an operation whose parent chain is `walk` (and, for rename/delete,
    /// whose object is `object`), if any.
    fn confirm_reason(&self, walk: &Walk, object: Option<&FileIdentity>) -> Option<&'static str> {
        if walk.ids().chain(object).any(|id| self.sensitive.contains(id)) {
            return Some(CONFIRM_SYSTEM);
        }
        if walk.chain.len() == 1 {
            return Some(CONFIRM_ROOT_CHILD);
        }
        None
    }
}

/// The identity of a directory opened by path, following nothing special (setup-time only: these
/// are the agent's own directories and the Windows ones, not attacker-chosen paths).
fn identity_of(path: &Path) -> Option<FileIdentity> {
    let h = open_dir_by_path(path).ok()?;
    anchor::file_identity(h.as_raw_handle()).ok()
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

/// A held chain of directory handles from a volume root down to a directory.
struct Walk {
    /// `(handle, identity)`, the volume root first. Held without delete sharing.
    chain: Vec<(OwnedHandle, FileIdentity)>,
}

impl Walk {
    fn ids(&self) -> impl Iterator<Item = &FileIdentity> {
        self.chain.iter().map(|(_, id)| id)
    }
    fn dir(&self) -> RawHandle {
        self.chain.last().expect("a walk always holds the volume root").0.as_raw_handle()
    }
    fn dir_id(&self) -> FileIdentity {
        self.chain.last().expect("a walk always holds the volume root").1
    }
    fn final_path(&self) -> Result<String, PrepareError> {
        resolved(self.dir())
    }
}

/// A file or directory name as one component: what Windows itself would refuse or misread is
/// refused here first.
pub(crate) fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.chars().count() > 255 || name == "." || name == ".." {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    if name.chars().any(|c| (c as u32) < 0x20 || "<>:\"/\\|?*".contains(c)) {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_uppercase();
    let chars: Vec<char> = stem.chars().collect();
    // COM0-COM9 and LPT0-LPT9, and the superscript forms Win32 also reserves (COM¹ ... LPT³).
    let device_digit = |c: char| c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}');
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || (chars.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && device_digit(chars[3]));
    !reserved
}

/// Split an absolute local path into its drive letter and its components, enforcing the shape
/// rules before anything touches the filesystem.
fn parse(path: &str) -> Result<(char, Vec<String>), PrepareError> {
    use rmt_agent::backstage::panels::local_path;
    if path.is_empty() || local_path::validate_path_shape(path).is_err() {
        return Err(PrepareError::Refused(REFUSE_SHAPE));
    }
    let mut comps = Path::new(path).components();
    let letter = match comps.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(l) => l as char,
            _ => return Err(PrepareError::Refused(REFUSE_SHAPE)),
        },
        _ => return Err(PrepareError::Refused(REFUSE_SHAPE)),
    };
    if comps.next() != Some(Component::RootDir) {
        return Err(PrepareError::Refused(REFUSE_SHAPE));
    }
    if local_path::drive_is_remote(letter) {
        return Err(PrepareError::Refused(REFUSE_REMOTE));
    }
    if !drive_is_fixed_or_removable(letter) {
        return Err(PrepareError::Refused(REFUSE_DRIVE));
    }
    let mut names = Vec::new();
    for c in comps {
        match c {
            Component::Normal(n) => {
                let n = n.to_str().ok_or(PrepareError::Refused(REFUSE_NAME))?;
                if !valid_name(n) {
                    return Err(PrepareError::Refused(REFUSE_NAME));
                }
                names.push(n.to_string());
            }
            Component::CurDir => continue,
            _ => return Err(PrepareError::Refused(REFUSE_SHAPE)),
        }
    }
    Ok((letter, names))
}

/// docs/58 §5: only `DRIVE_FIXED` and `DRIVE_REMOVABLE`. Answered from the local device map, so
/// nothing is contacted to decide.
fn drive_is_fixed_or_removable(letter: char) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    let root: Vec<u16> = format!(r"{letter}:\").encode_utf16().chain(Some(0)).collect();
    let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
    kind == DRIVE_FIXED || kind == DRIVE_REMOVABLE
}

/// The resolved path of a held handle, or a refusal: an audit record must name the real object,
/// never a truncated or empty path.
fn resolved(h: RawHandle) -> Result<String, PrepareError> {
    anchor::final_path(h).map_err(|e| PrepareError::Exec(format!("could not resolve the path: {e}")))
}

fn io_err(e: io::Error) -> PrepareError {
    PrepareError::Exec(describe_io(&e))
}

fn describe_io(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(2) | Some(3) => "not found".into(),
        Some(5) => "access is denied".into(),
        Some(17) => "the destination is on a different drive; moving between drives is not supported".into(),
        Some(32) | Some(33) => "it is in use by another program".into(),
        Some(80) | Some(183) => "a file or folder with that name already exists".into(),
        Some(145) => "the folder is not empty; only empty folders can be deleted".into(),
        _ => e.to_string(),
    }
}

/// Open the volume root of `letter` and every directory in `names` relative to the previous one.
fn walk(letter: char, names: &[String]) -> Result<Walk, PrepareError> {
    let root = open_dir_by_path(Path::new(&format!(r"{letter}:\"))).map_err(io_err)?;
    let root_id = anchor::file_identity(root.as_raw_handle()).map_err(io_err)?;
    let mut chain = vec![(root, root_id)];
    for name in names {
        let parent = chain.last().expect("non-empty").0.as_raw_handle();
        let h = anchor::open_relative(
            parent,
            name,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Disposition::Open,
            FILE_DIRECTORY_FILE,
        )
        .map_err(|e| if is_reparse_refusal(&e) { PrepareError::Refused(REFUSE_LINK) } else { io_err(e) })?;
        let attrs = anchor::attributes(h.as_raw_handle()).map_err(io_err)?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PrepareError::Refused(REFUSE_LINK));
        }
        let id = anchor::file_identity(h.as_raw_handle()).map_err(io_err)?;
        chain.push((h, id));
    }
    Ok(Walk { chain })
}

/// `OBJ_DONT_REPARSE` meeting a reparse point: STATUS_REPARSE_POINT_ENCOUNTERED maps to
/// ERROR_CANT_ACCESS_FILE (1920) / ERROR_REPARSE_POINT_ENCOUNTERED (4395).
fn is_reparse_refusal(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(1920) | Some(4395))
}

/// Open the final object of a path (the thing a rename moves or a delete removes) relative to the
/// held parent, as itself.
fn open_object(walk: &Walk, name: &str) -> Result<(OwnedHandle, FileIdentity, u32), PrepareError> {
    let h = anchor::open_relative(
        walk.dir(),
        name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        Disposition::Open,
        0,
    )
    .map_err(io_err)?;
    let attrs = anchor::attributes(h.as_raw_handle()).map_err(io_err)?;
    let id = anchor::file_identity(h.as_raw_handle()).map_err(io_err)?;
    Ok((h, id, attrs))
}

fn identity_bytes(ids: &[&FileIdentity], extra: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for id in ids {
        out.extend_from_slice(&id.volume.to_be_bytes());
        out.extend_from_slice(&id.id);
    }
    out.extend_from_slice(extra.as_bytes());
    out
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

impl FileManager for WinFileManager {
    fn prepare(&mut self, op: FileOp<'_>) -> Result<Prepared, PrepareError> {
        match op {
            FileOp::CreateDirectory { path } => {
                let (letter, mut names) = parse(path)?;
                let name = names.pop().ok_or(PrepareError::Refused(REFUSE_ROOT))?;
                let walk = walk(letter, &names)?;
                let to = join(&walk.final_path()?, &name);
                let guard = self.deny_in_chain(&walk).or_else(|| self.deny_new_name(&walk, &name)).unwrap_or_else(|| {
                    self.confirm_reason(&walk, None)
                        .map_or(GuardRail::Allow, |reason| GuardRail::RequireConfirmation { reason })
                });
                let identity = identity_bytes(&[&walk.dir_id()], &name);
                Ok(Prepared {
                    guard,
                    identity,
                    audit: AuditAction::FileCreateDir { path: to.clone() },
                    commit: Box::new(move |admit| {
                        if !admit() {
                            return Err(CommitError::NotAdmitted);
                        }
                        anchor::open_relative(
                            walk.dir(),
                            &name,
                            FILE_LIST_DIRECTORY | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            Disposition::Create,
                            FILE_DIRECTORY_FILE,
                        )
                        .map_err(|e| CommitError::Exec(describe_io(&e)))?;
                        Ok(AuditAction::FileCreateDir { path: to })
                    }),
                })
            }
            FileOp::Delete { path } => {
                let (letter, mut names) = parse(path)?;
                let name = names.pop().ok_or(PrepareError::Refused(REFUSE_ROOT))?;
                let walk = walk(letter, &names)?;
                // Inside a protected directory: refuse before the object is even opened, so the
                // answer does not say whether it exists and SYSTEM never opens it for DELETE.
                if self.deny_in_chain(&walk).is_some() {
                    return Err(PrepareError::Refused(REFUSE_PROTECTED));
                }
                let (object, id, attrs) = open_object(&walk, &name)?;
                let resolved = resolved(object.as_raw_handle())?;
                let guard = self
                    .deny_object(&id)
                    .unwrap_or(GuardRail::RequireConfirmation { reason: CONFIRM_DELETE });
                let kind = if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    "link"
                } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    "dir"
                } else {
                    "file"
                };
                let identity = identity_bytes(&[&walk.dir_id(), &id], kind);
                Ok(Prepared {
                    guard,
                    identity,
                    audit: AuditAction::FileDelete { path: resolved.clone() },
                    commit: Box::new(move |admit| {
                        if !admit() {
                            return Err(CommitError::NotAdmitted);
                        }
                        // A link is removed as itself (opened with FILE_OPEN_REPARSE_POINT); a
                        // non-empty directory is refused by the filesystem (no recursive delete).
                        anchor::delete_by_handle(object.as_raw_handle())
                            .map_err(|e| CommitError::Exec(describe_io(&e)))?;
                        drop(walk);
                        Ok(AuditAction::FileDelete { path: resolved })
                    }),
                })
            }
            FileOp::Rename { from, to } => {
                let (from_letter, mut from_names) = parse(from)?;
                let from_name = from_names.pop().ok_or(PrepareError::Refused(REFUSE_ROOT))?;
                let (to_letter, mut to_names) = parse(to)?;
                let to_name = to_names.pop().ok_or(PrepareError::Refused(REFUSE_ROOT))?;
                let from_walk = walk(from_letter, &from_names)?;
                let to_walk = walk(to_letter, &to_names)?;
                if self.deny_in_chain(&from_walk).is_some() || self.deny_in_chain(&to_walk).is_some() {
                    return Err(PrepareError::Refused(REFUSE_PROTECTED));
                }
                let (object, id, _) = open_object(&from_walk, &from_name)?;
                if to_walk.dir_id().volume != from_walk.dir_id().volume {
                    return Err(PrepareError::Exec(
                        "the destination is on a different drive; moving between drives is not supported".into(),
                    ));
                }
                let resolved_from = resolved(object.as_raw_handle())?;
                let resolved_to = join(&to_walk.final_path()?, &to_name);
                let guard = self
                    .deny_object(&id)
                    .or_else(|| self.deny_new_name(&to_walk, &to_name))
                    .unwrap_or_else(|| {
                        self.confirm_reason(&from_walk, Some(&id))
                            .or_else(|| self.confirm_reason(&to_walk, None))
                            .map_or(GuardRail::Allow, |reason| GuardRail::RequireConfirmation { reason })
                    });
                let identity = identity_bytes(&[&from_walk.dir_id(), &id, &to_walk.dir_id()], &to_name);
                Ok(Prepared {
                    guard,
                    identity,
                    audit: AuditAction::FileRename { from: resolved_from.clone(), to: resolved_to.clone() },
                    commit: Box::new(move |admit| {
                        if !admit() {
                            return Err(CommitError::NotAdmitted);
                        }
                        anchor::rename_into(object.as_raw_handle(), to_walk.dir(), &to_name, false)
                            .map_err(|e| CommitError::Exec(describe_io(&e)))?;
                        drop(from_walk);
                        Ok(AuditAction::FileRename { from: resolved_from, to: resolved_to })
                    }),
                })
            }
            FileOp::Place { transfer_id, dest_dir } => {
                let root = self.upload_root()?;
                // The destination folder ITSELF is walked (it is traversed), and checked before the
                // upload is even opened.
                let (letter, names) = parse(dest_dir)?;
                let walk = walk(letter, &names)?;
                if self.deny_in_chain(&walk).is_some() {
                    return Err(PrepareError::Refused(REFUSE_PROTECTED));
                }
                let (rec, file) = self.open_completed(&root, transfer_id)?;
                if walk.dir_id().volume != rec.identity.volume {
                    return Err(PrepareError::Exec(
                        "files can only be placed on the drive that holds the agent's transfer folder (C:)".into(),
                    ));
                }
                let to = join(&walk.final_path()?, &rec.name);
                let guard = self.deny_new_name(&walk, &rec.name).unwrap_or_else(|| {
                    self.confirm_reason(&walk, None)
                        .map_or(GuardRail::Allow, |reason| GuardRail::RequireConfirmation { reason })
                });
                let identity = identity_bytes(&[&rec.identity, &walk.dir_id()], &rec.name);
                let audit = AuditAction::FilePlace { transfer_id, sha256: rec.sha256.clone(), to: to.clone() };
                Ok(Prepared {
                    guard,
                    identity,
                    audit: audit.clone(),
                    commit: Box::new(move |admit| {
                        if !admit() {
                            return Err(CommitError::NotAdmitted);
                        }
                        // Never replaces: a name already in the destination is an error.
                        anchor::rename_into(file.as_raw_handle(), walk.dir(), &rec.name, false)
                            .map_err(|e| CommitError::Exec(describe_io(&e)))?;
                        root.take_completed(transfer_id);
                        Ok(audit)
                    }),
                })
            }
            FileOp::Discard { transfer_id } => {
                let root = self.upload_root()?;
                let (rec, file) = self.open_completed(&root, transfer_id)?;
                let path = root.display_of(&rec.name);
                let identity = identity_bytes(&[&rec.identity], "discard");
                Ok(Prepared {
                    guard: GuardRail::Allow,
                    identity,
                    audit: AuditAction::FileDelete { path: path.clone() },
                    commit: Box::new(move |admit| {
                        if !admit() {
                            return Err(CommitError::NotAdmitted);
                        }
                        anchor::delete_by_handle(file.as_raw_handle()).map_err(|e| CommitError::Exec(describe_io(&e)))?;
                        root.take_completed(transfer_id);
                        Ok(AuditAction::FileDelete { path })
                    }),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmt-fsm-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    fn yes() -> bool {
        true
    }

    fn commit(p: Prepared) -> Result<AuditAction, CommitError> {
        (p.commit)(&yes)
    }

    fn manager_protecting(dir: &Path) -> WinFileManager {
        WinFileManager::with_paths(&[dir.to_path_buf()], &[])
    }

    fn junction(link: &Path, target: &Path) {
        let out = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J", &s(link), &s(target)])
            .output()
            .unwrap();
        assert!(out.status.success(), "premise: mklink /J must work: {out:?}");
    }

    #[test]
    fn names_windows_would_misread_are_refused() {
        for bad in ["", ".", "..", "a.", "a ", "a:b", "a/b", "a\\b", "a*", "CON", "con.txt", "NUL", "COM1", "lpt9.log", "x\u{1}",
                    "COM0", "lpt0", "COM\u{b9}", "lpt\u{b3}.txt"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        for good in ["a", "COMx", "COM10", "report.final.txt", "Program Files", "été"] {
            assert!(valid_name(good), "{good:?}");
        }
    }

    #[test]
    fn shapes_that_are_not_local_absolute_paths_are_refused_before_any_io() {
        let mut m = WinFileManager::with_paths(&[], &[]);
        for bad in [r"\\server\share\x", r"\\?\C:\x", r"\\.\PhysicalDrive0\x", r"C:x", r"x\y", r"C:\a\..\b", r"C:\a\b:stream"] {
            match m.prepare(FileOp::CreateDirectory { path: bad }) {
                Err(PrepareError::Refused(_)) => {}
                other => panic!("{bad} was not refused: {:?}", other.err()),
            }
        }
    }

    #[test]
    fn create_rename_delete_happy_path() {
        let root = tmp("happy");
        let mut m = WinFileManager::with_paths(&[], &[]);
        let a = root.join("a");
        let p = m.prepare(FileOp::CreateDirectory { path: &s(&a) }).unwrap();
        assert_eq!(p.guard, GuardRail::Allow);
        commit(p).unwrap();
        assert!(a.is_dir());

        let b = root.join("b");
        let p = m.prepare(FileOp::Rename { from: &s(&a), to: &s(&b) }).unwrap();
        let done = commit(p).unwrap();
        assert!(b.is_dir() && !a.exists());
        match done {
            AuditAction::FileRename { from, to } => {
                assert!(from.to_ascii_lowercase().ends_with("\\a") && to.to_ascii_lowercase().ends_with("\\b"), "{from} -> {to}");
            }
            other => panic!("{other:?}"),
        }

        let p = m.prepare(FileOp::Delete { path: &s(&b) }).unwrap();
        assert_eq!(p.guard, GuardRail::RequireConfirmation { reason: CONFIRM_DELETE }, "every delete is confirmed");
        commit(p).unwrap();
        assert!(!b.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_never_overwrites_and_delete_is_empty_only() {
        let root = tmp("nooverwrite");
        let mut m = WinFileManager::with_paths(&[], &[]);
        std::fs::write(root.join("x.txt"), b"x").unwrap();
        std::fs::write(root.join("y.txt"), b"keep me").unwrap();
        let p = m.prepare(FileOp::Rename { from: &s(&root.join("x.txt")), to: &s(&root.join("y.txt")) }).unwrap();
        match commit(p) {
            Err(CommitError::Exec(e)) => assert!(e.contains("already exists"), "refused for the wrong reason: {e}"),
            other => panic!("a rename onto an existing file must be refused: {other:?}"),
        }
        assert_eq!(std::fs::read(root.join("y.txt")).unwrap(), b"keep me", "an existing file is never replaced");
        // Negative control: the same rename onto a free name succeeds, so the refusal above was the
        // existing name and not a broken rename.
        let p = m.prepare(FileOp::Rename { from: &s(&root.join("x.txt")), to: &s(&root.join("z")) }).unwrap();
        commit(p).unwrap();
        assert!(root.join("z").exists());

        std::fs::create_dir(root.join("full")).unwrap();
        std::fs::write(root.join("full").join("f"), b"f").unwrap();
        let p = m.prepare(FileOp::Delete { path: &s(&root.join("full")) }).unwrap();
        match commit(p) {
            Err(CommitError::Exec(e)) => assert!(e.contains("not empty"), "refused for the wrong reason: {e}"),
            other => panic!("a non-empty folder must not be deleted: {other:?}"),
        }
        assert!(root.join("full").join("f").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_junction_on_the_path_is_refused_and_a_final_junction_is_deleted_as_itself() {
        let root = tmp("junction");
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("precious"), b"p").unwrap();
        let link = root.join("link");
        junction(&link, &target);
        let mut m = WinFileManager::with_paths(&[], &[]);

        // THROUGH the junction: refused, nothing created in the target.
        match m.prepare(FileOp::CreateDirectory { path: &s(&link.join("new")) }) {
            Err(PrepareError::Refused(r)) => assert_eq!(r, REFUSE_LINK),
            other => panic!("traversal was not refused: {:?}", other.err()),
        }
        assert!(!target.join("new").exists());

        // The junction ITSELF as the final component: deleted as the link; its target survives.
        let p = m.prepare(FileOp::Delete { path: &s(&link) }).unwrap();
        commit(p).unwrap();
        assert!(!link.exists() && std::fs::symlink_metadata(&link).is_err(), "the link is gone");
        assert!(target.join("precious").exists(), "the target was not followed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_protected_directory_its_contents_and_its_ancestors_are_denied() {
        let root = tmp("protected");
        let outer = root.join("Apps");
        let agent = outer.join("DeskRally");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("config.json"), b"{}").unwrap();
        let mut m = manager_protecting(&agent);
        // Inside a protected directory the refusal comes before the target is opened (so it does not
        // reveal whether the target exists); a protected OBJECT is a Deny guard. Either way: denied.
        let deny = |r: Result<Prepared, PrepareError>| match r {
            Ok(p) => assert_eq!(p.guard, GuardRail::Deny { reason: REFUSE_PROTECTED }),
            Err(PrepareError::Refused(reason)) => assert_eq!(reason, REFUSE_PROTECTED),
            Err(e) => panic!("expected a protected-directory refusal, got {e:?}"),
        };
        deny(m.prepare(FileOp::Delete { path: &s(&agent.join("config.json")) }));
        deny(m.prepare(FileOp::CreateDirectory { path: &s(&agent.join("evil")) }));
        deny(m.prepare(FileOp::Rename { from: &s(&agent), to: &s(&root.join("moved")) }));
        // An ANCESTOR: renaming it would relocate the agent's directory.
        deny(m.prepare(FileOp::Rename { from: &s(&outer), to: &s(&root.join("Apps2")) }));
        // Another spelling of the same directory: different case. Identity, not text, decides.
        let upper = s(&agent).to_uppercase();
        deny(m.prepare(FileOp::CreateDirectory { path: &format!("{upper}\\evil2") }));
        // Moving something INTO it is denied by the destination chain.
        std::fs::write(root.join("payload.dll"), b"x").unwrap();
        deny(m.prepare(FileOp::Rename { from: &s(&root.join("payload.dll")), to: &s(&agent.join("payload.dll")) }));
        assert!(!agent.join("evil").exists() && !agent.join("payload.dll").exists());
        // SEC-002: asking about a file that does not exist inside the protected directory gets the
        // same refusal as one that does: the answer reveals nothing.
        deny(m.prepare(FileOp::Delete { path: &s(&agent.join("no-such-file")) }));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-003: a protected directory missing at startup cannot be created (or renamed into
    /// existence) from here, in any letter case.
    #[test]
    fn a_missing_protected_directory_cannot_be_created() {
        let root = tmp("missing");
        let absent = root.join("rmt-agent-bin");
        let mut m = manager_protecting(&absent);
        for name in ["rmt-agent-bin", "RMT-AGENT-BIN"] {
            match m.prepare(FileOp::CreateDirectory { path: &s(&root.join(name)) }) {
                Ok(p) => assert_eq!(p.guard, GuardRail::Deny { reason: REFUSE_PROTECTED }, "{name}"),
                Err(e) => panic!("{name}: {e:?}"),
            }
        }
        std::fs::create_dir(root.join("x")).unwrap();
        match m.prepare(FileOp::Rename { from: &s(&root.join("x")), to: &s(&absent) }) {
            Ok(p) => assert_eq!(p.guard, GuardRail::Deny { reason: REFUSE_PROTECTED }),
            Err(e) => panic!("{e:?}"),
        }
        // A different name in the same parent is unaffected.
        let p = m.prepare(FileOp::CreateDirectory { path: &s(&root.join("other")) }).unwrap();
        assert_eq!(p.guard, GuardRail::Allow);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-001: a resolved path longer than MAX_PATH is audited in full, not truncated.
    #[test]
    fn a_path_longer_than_max_path_is_audited_in_full() {
        let root = tmp("long");
        let mut m = WinFileManager::with_paths(&[], &[]);
        let mut dir = root.clone();
        for i in 0..5 {
            let next = dir.join(format!("{i}{}", "d".repeat(240)));
            commit(m.prepare(FileOp::CreateDirectory { path: &s(&next) }).unwrap()).unwrap();
            dir = next;
        }
        let target = dir.join("leaf");
        let done = commit(m.prepare(FileOp::CreateDirectory { path: &s(&target) }).unwrap()).unwrap();
        match done {
            AuditAction::FileCreateDir { path } => {
                assert!(path.len() > 1200, "audited path was truncated: {} chars", path.len());
                assert!(path.ends_with("\\leaf"));
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sensitive_directories_need_confirmation() {
        let root = tmp("sensitive");
        let sys = root.join("Windows");
        std::fs::create_dir(&sys).unwrap();
        let mut m = WinFileManager::with_paths(&[], &[sys.clone()]);
        let p = m.prepare(FileOp::CreateDirectory { path: &s(&sys.join("x")) }).unwrap();
        assert_eq!(p.guard, GuardRail::RequireConfirmation { reason: CONFIRM_SYSTEM });
        let _ = std::fs::remove_dir_all(&root);
    }

    /// docs/58 §5: while the walk holds its handles, an intermediate directory cannot be renamed
    /// away and replaced with a junction, so the operation lands where it was checked.
    #[test]
    fn an_intermediate_directory_cannot_be_swapped_while_held() {
        let root = tmp("swap");
        let mid = root.join("mid");
        std::fs::create_dir(&mid).unwrap();
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let mut m = WinFileManager::with_paths(&[], &[]);
        let p = m.prepare(FileOp::CreateDirectory { path: &s(&mid.join("new")) }).unwrap();

        // The attacker's move: rename mid away and put a junction to elsewhere in its place.
        let swapped = std::fs::rename(&mid, root.join("mid-old"));
        assert!(swapped.is_err(), "a held directory must not be renamable: {swapped:?}");

        commit(p).unwrap();
        assert!(mid.join("new").is_dir(), "the op landed in the directory that was checked");
        assert!(!elsewhere.join("new").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_refused_admission_at_the_irreversible_step_changes_nothing() {
        let root = tmp("admit");
        let mut m = WinFileManager::with_paths(&[], &[]);
        let target = root.join("never");
        let p = m.prepare(FileOp::CreateDirectory { path: &s(&target) }).unwrap();
        let revoked = AtomicBool::new(true);
        let admit = || !revoked.load(Ordering::SeqCst);
        assert!(matches!((p.commit)(&admit), Err(CommitError::NotAdmitted)));
        assert!(!target.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A committed upload in a (test-)anchored root, as the writer leaves it.
    fn uploaded(
        root: &std::sync::Arc<crate::upload_root::UploadRoot>,
        name: &str,
        bytes: &[u8],
    ) -> (uuid::Uuid, String) {
        use std::io::Write;
        let id = uuid::Uuid::new_v4();
        let mut part = root.create_part(id).unwrap();
        part.write_all(bytes).unwrap();
        let (landed, identity) = root.commit(&part, name).unwrap();
        root.record_completed(
            id,
            crate::upload_root::Completed { name: landed.clone(), sha256: "ab".repeat(32), identity },
        );
        (id, landed)
    }

    fn placing_manager(root: &std::sync::Arc<crate::upload_root::UploadRoot>) -> WinFileManager {
        WinFileManager::with_paths(&[], &[])
            .with_upload_root(std::sync::Arc::new(std::sync::Mutex::new(Some(std::sync::Arc::clone(root)))))
    }

    #[test]
    fn a_completed_upload_is_placed_once_and_audited_with_its_digest() {
        let up_dir = tmp("place-root");
        let dest = tmp("place-dest");
        let root = std::sync::Arc::new(crate::upload_root::UploadRoot::anchored_for_test(&up_dir));
        let (id, landed) = uploaded(&root, "tool.exe", b"payload");
        let mut m = placing_manager(&root);
        let p = m.prepare(FileOp::Place { transfer_id: id, dest_dir: &s(&dest) }).unwrap();
        assert_eq!(p.guard, GuardRail::Allow);
        match commit(p).unwrap() {
            AuditAction::FilePlace { transfer_id, sha256, to } => {
                assert_eq!(transfer_id, id);
                assert_eq!(sha256, "ab".repeat(32));
                assert!(to.to_ascii_lowercase().ends_with("\\tool.exe"), "{to}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(dest.join("tool.exe")).unwrap(), b"payload");
        assert!(!up_dir.join(&landed).exists(), "placement MOVES the file");
        assert!(root.completed(id).is_none(), "the record is consumed by the placement itself");
        // Consumed: a second placement of the same transfer is refused.
        assert!(matches!(
            m.prepare(FileOp::Place { transfer_id: id, dest_dir: &s(&dest) }),
            Err(PrepareError::Refused(UPLOAD_GONE))
        ));
        let _ = std::fs::remove_dir_all(&up_dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn placement_never_replaces_and_a_replaced_upload_is_refused() {
        let up_dir = tmp("place-replace-root");
        let dest = tmp("place-replace-dest");
        std::fs::write(dest.join("a.txt"), b"keep").unwrap();
        let root = std::sync::Arc::new(crate::upload_root::UploadRoot::anchored_for_test(&up_dir));
        let (id, _) = uploaded(&root, "a.txt", b"new");
        let mut m = placing_manager(&root);
        let p = m.prepare(FileOp::Place { transfer_id: id, dest_dir: &s(&dest) }).unwrap();
        match commit(p) {
            Err(CommitError::Exec(e)) => assert!(e.contains("already exists"), "{e}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"keep");
        // The record survives a failed placement (it can be retried or discarded).
        assert!(root.completed(id).is_some());

        // The landing file is replaced by another object of the same name: the identity no longer
        // matches, so it is refused rather than placing what the session did not receive.
        let (id2, landed2) = uploaded(&root, "b.txt", b"mine");
        std::fs::remove_file(up_dir.join(&landed2)).unwrap();
        std::fs::write(up_dir.join(&landed2), b"swapped").unwrap();
        assert!(matches!(
            m.prepare(FileOp::Place { transfer_id: id2, dest_dir: &s(&dest) }),
            Err(PrepareError::Refused(UPLOAD_REPLACED))
        ));
        let _ = std::fs::remove_dir_all(&up_dir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn placement_into_a_protected_folder_is_denied_and_discard_removes_the_upload() {
        let up_dir = tmp("place-protected-root");
        let agent = tmp("place-protected-agent");
        let root = std::sync::Arc::new(crate::upload_root::UploadRoot::anchored_for_test(&up_dir));
        let (id, landed) = uploaded(&root, "x.dll", b"x");
        let mut m = WinFileManager::with_paths(&[agent.clone()], &[])
            .with_upload_root(std::sync::Arc::new(std::sync::Mutex::new(Some(std::sync::Arc::clone(&root)))));
        match m.prepare(FileOp::Place { transfer_id: id, dest_dir: &s(&agent) }) {
            Err(PrepareError::Refused(r)) => assert_eq!(r, REFUSE_PROTECTED),
            other => panic!("placing into the agent's folder must be refused: {:?}", other.err()),
        }
        let p = m.prepare(FileOp::Discard { transfer_id: id }).unwrap();
        commit(p).unwrap();
        assert!(!up_dir.join(&landed).exists());
        assert!(root.completed(id).is_none(), "discard consumes the record");
        let _ = std::fs::remove_dir_all(&up_dir);
        let _ = std::fs::remove_dir_all(&agent);
    }

    /// Without an anchored root (no uploads received to the agent's own folder) nothing can be placed.
    #[test]
    fn placing_needs_an_anchored_root() {
        let mut m = WinFileManager::with_paths(&[], &[]);
        assert!(matches!(
            m.prepare(FileOp::Place { transfer_id: uuid::Uuid::nil(), dest_dir: r"C:\x" }),
            Err(PrepareError::Exec(_))
        ));
        let dir = tmp("plain-root");
        let plain = std::sync::Arc::new(crate::upload_root::UploadRoot::open(&dir, false).unwrap());
        let mut m = WinFileManager::with_paths(&[], &[])
            .with_upload_root(std::sync::Arc::new(std::sync::Mutex::new(Some(plain))));
        assert!(
            matches!(m.prepare(FileOp::Discard { transfer_id: uuid::Uuid::nil() }), Err(PrepareError::Exec(_))),
            "a non-anchored (non-SYSTEM) root never offers placement"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
