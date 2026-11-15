//! Handle-relative access to the trusted agent root `C:\rmt-agent` (design v5 R5, v6 A1).
//!
//! Every privileged reader/writer of updater state (worker, runner, HealthGate, service, helper)
//! goes through one [`Anchor`]:
//!
//! * The root is opened ONCE, without `FILE_SHARE_DELETE` and with `FILE_FLAG_OPEN_REPARSE_POINT`,
//!   and the handle is kept for the whole operation. While it is held nobody can rename or delete
//!   the directory, so every later child open resolves inside the directory that was validated,
//!   not inside whatever a path string names by then.
//! * The root must be a plain directory owned by SYSTEM/Administrators whose DACL grants no other
//!   principal a mutating right, and its PARENT must grant no other principal `FILE_DELETE_CHILD`
//!   (v6 A1: delete-child on the parent is the right that removes a directory regardless of the
//!   directory's own DACL).
//! * Children are opened RELATIVE to the root handle (`NtCreateFile` with `RootDirectory` and
//!   `OBJ_DONT_REPARSE`), one path component at a time, and validated the same way before use.
//! * Writes create a temp sibling WITH its final security descriptor, flush it, then rename it
//!   over the target relative to the root handle. A reader never sees a partial file and a crash
//!   leaves either the old or the new bytes.
//!
//! Path-based checks (`check_no_reparse_ancestors`, `harden_agent_root`) remain for the legacy
//! callers; they act by name and are TOCTOU-prone, which is exactly why updater state does not use
//! them.

#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    GetAce, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

/// The trusted root. Not configurable: a knob would point SYSTEM at a directory nobody validated.
pub const ROOT: &str = r"C:\rmt-agent";

/// Largest state/evidence file any updater component reads.
pub const MAX_STATE_BYTES: usize = 64 * 1024;

// ─── Access-rights policy (pure, unit-tested) ──────────────────────────────────

const FILE_WRITE_DATA: u32 = 0x0002; // FILE_ADD_FILE on a directory
const FILE_APPEND_DATA: u32 = 0x0004; // FILE_ADD_SUBDIRECTORY on a directory
const FILE_DELETE_CHILD: u32 = 0x0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const INHERIT_ONLY_ACE: u8 = 0x08;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// Rights no non-admin principal may hold on a trusted object (v5 R5).
pub(crate) const OBJECT_MUTATE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;
/// Rights no non-admin principal may hold on a trusted object's PARENT (v6 A1). Adding entries to
/// `C:\` is normal (Authenticated Users have AppendData there); removing ours is not, and neither
/// is the ability to grant oneself that right.
pub(crate) const PARENT_REMOVE: u32 = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Principal {
    System,
    Administrators,
    /// Accepted only where the caller says so (Program Files is TrustedInstaller-owned).
    TrustedInstaller,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AceView {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub who: Principal,
}

/// Whether a DACL grants a non-trusted principal any of `forbidden` on the object itself.
///
/// Conservative "effective rights": every allow ACE that applies to the object counts; deny ACEs
/// are ignored (they can only remove rights, and ignoring them can only make this stricter); an ACE
/// type this does not model (object/callback ACEs) fails closed. Group membership is not expanded,
/// so a non-admin SID is "Other" however its rights were obtained, which again only errs strict.
pub(crate) fn dacl_is_trusted(
    owner: Principal,
    aces: Option<&[AceView]>,
    forbidden: u32,
    allow_trusted_installer: bool,
) -> bool {
    let trusted = |p: Principal| match p {
        Principal::System | Principal::Administrators => true,
        Principal::TrustedInstaller => allow_trusted_installer,
        Principal::Other => false,
    };
    if !trusted(owner) {
        // An owner holds implicit WRITE_DAC whatever the DACL says.
        return false;
    }
    // A NULL DACL grants everyone everything.
    let Some(aces) = aces else { return false };
    for ace in aces {
        match ace.ace_type {
            ACCESS_DENIED_ACE_TYPE => continue,
            ACCESS_ALLOWED_ACE_TYPE => {}
            _ => return false,
        }
        if ace.flags & INHERIT_ONLY_ACE != 0 || trusted(ace.who) {
            continue;
        }
        if ace.mask & forbidden != 0 {
            return false;
        }
    }
    true
}

// ─── Native plumbing ──────────────────────────────────────────────────────────

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: RawHandle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *const c_void,
    security_quality_of_service: *const c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut RawHandle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
    fn NtSetInformationFile(
        file_handle: RawHandle,
        io_status_block: *mut IoStatusBlock,
        file_information: *const c_void,
        length: u32,
        file_information_class: u32,
    ) -> i32;
}

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_WRITE_THROUGH: u32 = 0x2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_LIST_DIRECTORY: u32 = 0x1;
const FILE_TRAVERSE: u32 = 0x20;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// `NtCreateFile` create dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// FILE_OPEN: must exist.
    Open = 1,
    /// FILE_CREATE: must not exist.
    Create = 2,
    /// FILE_OPEN_IF.
    OpenIf = 3,
}

fn nt_err(status: i32) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

/// A `windows` crate error as a plain Win32 io::Error. The crate's own `From` keeps the HRESULT
/// (`0x8007_0002` = -2147024894) as the raw OS code, so `kind()` is `Other` and every "already gone"
/// check (`ErrorKind::NotFound`, `is_not_found`) missed it: a missing queue directory then read as a
/// hard failure (found in the 1.3.19 VM run). FACILITY_WIN32 HRESULTs are unwrapped to their Win32 code.
pub(crate) fn win_err(e: windows::core::Error) -> io::Error {
    let h = e.code().0 as u32;
    if h & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((h & 0xFFFF) as i32)
    } else {
        io::Error::other(e)
    }
}

/// A single path component: no separators, no `..`, no stream syntax, no device-name tricks.
pub(crate) fn valid_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !name.ends_with('.')
}

/// Owner + DACL of an open handle, as [`AceView`]s.
fn handle_security(handle: RawHandle) -> io::Result<(Principal, Option<Vec<AceView>>)> {
    unsafe {
        let mut owner = PSID::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = GetSecurityInfo(
            HANDLE(handle),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut sd),
        );
        if rc.is_err() {
            return Err(io::Error::from_raw_os_error(rc.0 as i32));
        }
        let classify = |sid: PSID| -> Principal {
            if IsWellKnownSid(sid, WinLocalSystemSid).as_bool() {
                Principal::System
            } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() {
                Principal::Administrators
            } else if is_trusted_installer(sid) {
                Principal::TrustedInstaller
            } else {
                Principal::Other
            }
        };
        let owner_p = classify(owner);
        let aces = if acl.is_null() {
            None
        } else {
            let mut out = Vec::new();
            for i in 0..(*acl).AceCount {
                let mut ace = std::ptr::null_mut();
                if GetAce(acl, u32::from(i), &mut ace).is_err() {
                    let _ = LocalFree(HLOCAL(sd.0));
                    return Err(io::Error::other("unreadable ACE"));
                }
                let header = &*(ace as *const ACE_HEADER);
                // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the layout: header, mask, SID.
                let (mask, who) = if header.AceType <= ACCESS_DENIED_ACE_TYPE {
                    let mask = *((ace as *const u8).add(4) as *const u32);
                    let sid = PSID((ace as *mut u8).add(8).cast());
                    (mask, classify(sid))
                } else {
                    (u32::MAX, Principal::Other)
                };
                out.push(AceView {
                    ace_type: header.AceType,
                    flags: header.AceFlags,
                    mask,
                    who,
                });
            }
            Some(out)
        };
        let _ = LocalFree(HLOCAL(sd.0));
        Ok((owner_p, aces))
    }
}

/// NT SERVICE\TrustedInstaller: S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464.
fn is_trusted_installer(sid: PSID) -> bool {
    use windows::Win32::Security::{GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount};
    const SUBS: [u32; 6] = [80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464];
    unsafe {
        let auth = GetSidIdentifierAuthority(sid);
        if auth.is_null() || (*auth).Value != [0, 0, 0, 0, 0, 5] {
            return false;
        }
        let count = GetSidSubAuthorityCount(sid);
        if count.is_null() || usize::from(*count) != SUBS.len() {
            return false;
        }
        SUBS.iter()
            .enumerate()
            .all(|(i, v)| *GetSidSubAuthority(sid, i as u32) == *v)
    }
}

/// File attributes of an open handle.
pub(crate) fn attributes(handle: RawHandle) -> io::Result<u32> {
    use windows::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO,
    };
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(handle),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )?;
    }
    Ok(info.FileAttributes)
}

/// Volume serial + 128-bit file id: the identity every component compares (v6 A1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileIdentity {
    pub volume: u64,
    pub id: [u8; 16],
}

pub fn file_identity(handle: RawHandle) -> io::Result<FileIdentity> {
    use windows::Win32::Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO};
    let mut info = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(handle),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )?;
    }
    Ok(FileIdentity {
        volume: info.VolumeSerialNumber,
        id: info.FileId.Identifier,
    })
}

/// The protected SD every file/dir the updater creates gets AT CREATION (never fixed up later).
struct OwnedSd(PSECURITY_DESCRIPTOR);
impl OwnedSd {
    fn protected_admin_only(container: bool) -> io::Result<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let sddl = if container {
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        } else {
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        };
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
        }
        Ok(Self(sd))
    }
}
impl Drop for OwnedSd {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

/// Open one component relative to a held directory handle (docs/58): `OBJ_DONT_REPARSE`, and the
/// object itself is opened (`FILE_OPEN_REPARSE_POINT`), never what a link points at. No security
/// descriptor is applied: a created object inherits from its parent, as anything a technician
/// creates by hand would.
pub(crate) fn open_relative(
    root: RawHandle,
    name: &str,
    access: u32,
    share: u32,
    disposition: Disposition,
    options: u32,
) -> io::Result<OwnedHandle> {
    nt_open(Some(root), name, access, share, disposition, options, None)
}

/// Create a NEW file relative to a held directory handle with the protected admin-only SD (never
/// inherited), `OBJ_DONT_REPARSE` (docs/58 §12: an upload's `.part` in the anchored root).
pub(crate) fn create_protected_file(root: RawHandle, name: &str, access: u32, share: u32) -> io::Result<OwnedHandle> {
    let sd = OwnedSd::protected_admin_only(false)?;
    nt_open(Some(root), name, access, share, Disposition::Create, FILE_NON_DIRECTORY_FILE, Some(&sd))
}

/// Whether an open file's owner and DACL are trusted (no non-admin may mutate it).
#[cfg(test)]
pub(crate) fn is_protected_file(handle: RawHandle) -> io::Result<bool> {
    Ok(validate(handle, false, OBJECT_MUTATE).is_ok())
}

/// Raw NtCreateFile relative to `root` (or absolute when `root` is None, NT path required).
fn nt_open(
    root: Option<RawHandle>,
    name: &str,
    access: u32,
    share: u32,
    disposition: Disposition,
    options: u32,
    sd: Option<&OwnedSd>,
) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(wide.len() * 2).map_err(|_| io::Error::other("name too long"))?;
    let us = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: wide.as_ptr(),
    };
    let oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: root.unwrap_or(std::ptr::null_mut()),
        object_name: &us,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        security_descriptor: sd.map_or(std::ptr::null(), |s| s.0 .0 as *const c_void),
        security_quality_of_service: std::ptr::null(),
    };
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut handle: RawHandle = std::ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition as u32,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_err(status));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Validate an open handle: not a reparse point, the expected kind, trusted owner and DACL.
fn validate(handle: RawHandle, want_dir: bool, forbidden: u32) -> io::Result<()> {
    let attrs = attributes(handle)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("refusing a reparse point"));
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY != 0) != want_dir {
        return Err(io::Error::other(if want_dir {
            "expected a directory"
        } else {
            "expected a file"
        }));
    }
    let (owner, aces) = handle_security(handle)?;
    if !dacl_is_trusted(owner, aces.as_deref(), forbidden, false) {
        return Err(io::Error::other("untrusted owner or DACL"));
    }
    Ok(())
}

// ─── The anchor ───────────────────────────────────────────────────────────────

/// A validated, immovable directory. Children are reached only through it.
pub struct Dir {
    handle: OwnedHandle,
}

/// The trusted root, held open for the whole operation.
pub struct Anchor {
    root: Dir,
    identity: FileIdentity,
}

impl Anchor {
    /// Open and validate `C:\rmt-agent` (and its parent's delete-child rights).
    pub fn open() -> io::Result<Self> {
        Self::open_at(Path::new(ROOT))
    }

    /// Test seam: the same protocol against another directory.
    pub fn open_at(path: &Path) -> io::Result<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_MODE, OPEN_EXISTING,
        };
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("anchor has no parent"))?;
        let open_dir = |p: &Path, share: u32| -> io::Result<OwnedHandle> {
            let wide: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
            let h = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_MODE(share),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(
                        FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0,
                    ),
                    None,
                )
                .map_err(win_err)?
            };
            Ok(unsafe { OwnedHandle::from_raw_handle(h.0) })
        };
        // The anchor itself: NO FILE_SHARE_DELETE, so it cannot be renamed or removed while held.
        let handle = open_dir(path, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        validate(handle.as_raw_handle(), true, OBJECT_MUTATE)?;
        // The parent: nobody else may remove entries from it (v6 A1). Share fully; it is only read.
        let parent_handle = open_dir(parent, FILE_SHARE_READ | FILE_SHARE_WRITE | 0x4)?;
        let attrs = attributes(parent_handle.as_raw_handle())?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("anchor parent is a reparse point"));
        }
        let (owner, aces) = handle_security(parent_handle.as_raw_handle())?;
        if !dacl_is_trusted(owner, aces.as_deref(), PARENT_REMOVE, true) {
            return Err(io::Error::other(
                "the anchor's parent lets a non-admin remove entries; refusing to update",
            ));
        }
        let identity = file_identity(handle.as_raw_handle())?;
        Ok(Self {
            root: Dir { handle },
            identity,
        })
    }

    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Fail unless this anchor is the one recorded in trusted state (v6 A1).
    pub fn expect_identity(&self, recorded: &FileIdentity) -> io::Result<()> {
        if &self.identity != recorded {
            return Err(io::Error::other("agent root identity changed"));
        }
        Ok(())
    }

    pub fn dir(&self) -> &Dir {
        &self.root
    }
}

impl Dir {
    pub fn raw(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }

    /// Open an existing child file for reading, validated. `share` controls what others may do
    /// meanwhile; pass `FILE_SHARE_READ` to forbid writers and renamers.
    pub fn open_file_read(&self, name: &str, share: u32) -> io::Result<std::fs::File> {
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = nt_open(
            Some(self.raw()),
            name,
            GENERIC_READ | READ_CONTROL,
            share,
            Disposition::Open,
            FILE_NON_DIRECTORY_FILE,
            None,
        )?;
        validate(h.as_raw_handle(), false, OBJECT_MUTATE)?;
        Ok(std::fs::File::from(h))
    }

    /// Bounded read of a child. `Ok(None)` when it does not exist.
    pub fn read(&self, name: &str, max: usize) -> io::Result<Option<Vec<u8>>> {
        use std::io::Read;
        let file = match self.open_file_read(name, FILE_SHARE_READ) {
            Ok(f) => f,
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut data = Vec::new();
        file.take(max as u64 + 1).read_to_end(&mut data)?;
        if data.len() > max {
            return Err(io::Error::other("file exceeds its size limit"));
        }
        Ok(Some(data))
    }

    /// Atomically replace (or create) a child with `bytes` (temp sibling with its final SD,
    /// write-through, flush, rename relative to this directory).
    pub fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let temp = format!("{name}.tmp-{}", uuid::Uuid::new_v4().simple());
        let sd = OwnedSd::protected_admin_only(false)?;
        let h = nt_open(
            Some(self.raw()),
            &temp,
            GENERIC_READ | 0x4000_0000 | DELETE | READ_CONTROL,
            0,
            Disposition::Create,
            FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
            Some(&sd),
        )?;
        let result = (|| {
            let mut file = std::fs::File::from(h.try_clone()?);
            file.write_all(bytes)?;
            file.sync_all()?;
            rename_relative(h.as_raw_handle(), self.raw(), name)
        })();
        if result.is_err() {
            let _ = delete_by_handle(h.as_raw_handle());
        }
        result
    }

    /// Delete a child file if present (validated first, so a planted junction is not followed).
    pub fn remove(&self, name: &str) -> io::Result<()> {
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = match nt_open(
            Some(self.raw()),
            name,
            DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            Disposition::Open,
            0,
            None,
        ) {
            Ok(h) => h,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        // A reparse point is deleted as itself (FILE_OPEN_REPARSE_POINT), never followed.
        delete_by_handle(h.as_raw_handle())
    }

    /// Create a NEW child file (fails if it exists) with the protected SD, opened read+write and
    /// shared for reading only, so nothing else can modify, rename or delete it while it is held.
    pub fn create_file(&self, name: &str) -> io::Result<std::fs::File> {
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let sd = OwnedSd::protected_admin_only(false)?;
        let h = nt_open(
            Some(self.raw()),
            name,
            GENERIC_READ | 0x4000_0000 | READ_CONTROL,
            FILE_SHARE_READ,
            Disposition::Create,
            FILE_NON_DIRECTORY_FILE,
            Some(&sd),
        )?;
        Ok(std::fs::File::from(h))
    }

    /// Open (creating with the protected SD if absent) a child with NO sharing at all: the
    /// updater's exclusive session lock. A sharing violation (OS error 32) means a session holds
    /// it.
    pub fn open_exclusive(&self, name: &str) -> io::Result<std::fs::File> {
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let sd = OwnedSd::protected_admin_only(false)?;
        let h = nt_open(
            Some(self.raw()),
            name,
            GENERIC_READ | READ_CONTROL,
            0,
            Disposition::OpenIf,
            FILE_NON_DIRECTORY_FILE,
            Some(&sd),
        )?;
        validate(h.as_raw_handle(), false, OBJECT_MUTATE)?;
        Ok(std::fs::File::from(h))
    }

    /// The 64-bit file id of a child, read from the directory listing WITHOUT opening the child
    /// (it may be held with no sharing).
    pub fn child_file_id(&self, name: &str) -> io::Result<u64> {
        use windows::Win32::Storage::FileSystem::{
            FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
            GetFileInformationByHandleEx, FILE_ID_BOTH_DIR_INFO,
        };
        let mut buf = vec![0u64; 8192];
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    HANDLE(self.raw()),
                    class,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                )
            };
            class = FileIdBothDirectoryInfo;
            if let Err(e) = ok {
                if e.code().0 as u32 == 0x8007_0012 {
                    return Err(io::Error::from_raw_os_error(2));
                }
                return Err(e.into());
            }
            let mut offset = 0usize;
            loop {
                let info = unsafe {
                    &*((buf.as_ptr() as *const u8).add(offset) as *const FILE_ID_BOTH_DIR_INFO)
                };
                let len = info.FileNameLength as usize / 2;
                let n = unsafe { std::slice::from_raw_parts(info.FileName.as_ptr(), len) };
                if String::from_utf16_lossy(n).eq_ignore_ascii_case(name) {
                    return Ok(info.FileId as u64);
                }
                if info.NextEntryOffset == 0 {
                    break;
                }
                offset += info.NextEntryOffset as usize;
            }
        }
    }

    /// Move child `name` into `dest` (another validated directory), keeping its name. Relative on
    /// both ends; a reparse point is moved as itself, never followed.
    pub fn move_to(&self, name: &str, dest: &Dir) -> io::Result<()> {
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = nt_open(
            Some(self.raw()),
            name,
            DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            Disposition::Open,
            0,
            None,
        )?;
        rename_relative(h.as_raw_handle(), dest.raw(), name)
    }

    /// Remove an EMPTY-able child directory: its direct file children first (one level), then the
    /// directory itself. Nested directories are refused rather than recursed into.
    pub fn remove_dir(&self, name: &str) -> io::Result<()> {
        let sub = match self.child_dir(name, false) {
            Ok(d) => d,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        for child in sub.list()? {
            sub.remove(&child)?;
        }
        drop(sub);
        let h = nt_open(
            Some(self.raw()),
            name,
            DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            Disposition::Open,
            FILE_DIRECTORY_FILE,
            None,
        )?;
        delete_by_handle(h.as_raw_handle())
    }

    /// Open (or create with the protected SD) a validated child directory.
    pub fn child_dir(&self, name: &str, create: bool) -> io::Result<Dir> {
        if !valid_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let sd = OwnedSd::protected_admin_only(true)?;
        let h = nt_open(
            Some(self.raw()),
            name,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | 0x2 | 0x4,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create {
                Disposition::OpenIf
            } else {
                Disposition::Open
            },
            FILE_DIRECTORY_FILE,
            Some(&sd),
        )?;
        validate(h.as_raw_handle(), true, OBJECT_MUTATE)?;
        Ok(Dir { handle: h })
    }

    /// Names of the direct children (files and directories), for cleanup sweeps.
    pub fn list(&self) -> io::Result<Vec<String>> {
        use windows::Win32::Storage::FileSystem::{
            FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
            GetFileInformationByHandleEx, FILE_ID_BOTH_DIR_INFO,
        };
        let mut out = Vec::new();
        let mut buf = vec![0u64; 8192];
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    HANDLE(self.raw()),
                    class,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                )
            };
            class = FileIdBothDirectoryInfo;
            if let Err(e) = ok {
                if e.code().0 as u32 == 0x8007_0012 {
                    break; // ERROR_NO_MORE_FILES
                }
                return Err(e.into());
            }
            let mut offset = 0usize;
            loop {
                let info = unsafe {
                    &*((buf.as_ptr() as *const u8).add(offset) as *const FILE_ID_BOTH_DIR_INFO)
                };
                let len = info.FileNameLength as usize / 2;
                let name = unsafe { std::slice::from_raw_parts(info.FileName.as_ptr(), len) };
                let name = String::from_utf16_lossy(name);
                if name != "." && name != ".." {
                    out.push(name);
                }
                if info.NextEntryOffset == 0 {
                    break;
                }
                offset += info.NextEntryOffset as usize;
            }
        }
        Ok(out)
    }

    /// The handle's final path (`\\?\C:\...` form stripped to `C:\...`). Used only to hand a path
    /// to a component that cannot take a handle (msiexec), AFTER the handle validated the object
    /// and while it is still held without delete sharing.
    pub fn final_path(&self) -> io::Result<String> {
        final_path(self.raw())
    }
}

pub fn final_path(handle: RawHandle) -> io::Result<String> {
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
    // A first try at 1024 units, then exactly the size the call asks for (it returns the required
    // length, including the terminator, when the buffer is too small): handle-relative opens have
    // no MAX_PATH, so a resolved path can be far longer, and an audit record must not truncate it.
    let mut buf = vec![0u16; 1024];
    let mut n = unsafe { GetFinalPathNameByHandleW(HANDLE(handle), &mut buf, FILE_NAME_NORMALIZED) };
    if n as usize >= buf.len() {
        buf = vec![0u16; n as usize + 1];
        n = unsafe { GetFinalPathNameByHandleW(HANDLE(handle), &mut buf, FILE_NAME_NORMALIZED) };
    }
    if n == 0 || n as usize >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    let s = String::from_utf16(&buf[..n as usize]).map_err(|_| io::Error::other("bad path"))?;
    Ok(s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned())
}

fn is_not_found(e: &io::Error) -> bool {
    // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND, also in their HRESULT form (in case an error was
    // converted without `win_err`).
    e.kind() == io::ErrorKind::NotFound
        || matches!(e.raw_os_error(), Some(2) | Some(3) | Some(-2147024894) | Some(-2147024893))
}

fn rename_relative(file: RawHandle, dir: RawHandle, name: &str) -> io::Result<()> {
    rename_into(file, dir, name, true)
}

/// Rename the object behind `file` to `name` inside the directory behind `dir`, both by handle.
/// `replace` false is the docs/58 rule: an existing `name` is an error (ERROR_ALREADY_EXISTS), never
/// overwritten.
pub(crate) fn rename_into(file: RawHandle, dir: RawHandle, name: &str, replace: bool) -> io::Result<()> {
    // NtSetInformationFile(FileRenameInformationEx) directly: kernel32's SetFileInformationByHandle
    // refused a RootDirectory-relative rename with ERROR_INVALID_PARAMETER (measured), and the
    // relative form is the point (the target is resolved inside the held anchor, not by path).
    // FILE_RENAME_INFORMATION: Flags u32 @0, RootDirectory @8, FileNameLength u32 @16, name @20.
    // Flags: REPLACE_IF_EXISTS (0x1) | POSIX_SEMANTICS (0x2).
    const FILE_RENAME_INFORMATION_EX: u32 = 65;
    let wide: Vec<u16> = name.encode_utf16().collect();
    // At least sizeof(FILE_RENAME_INFORMATION) (24 on x64): a one-character name gives 22, which the
    // kernel refuses with STATUS_INFO_LENGTH_MISMATCH ("command length is incorrect", measured).
    let total = (20 + wide.len() * 2).max(24);
    let mut buf = vec![0u64; total.div_ceil(8) + 1];
    unsafe {
        let base = buf.as_mut_ptr() as *mut u8;
        *(base as *mut u32) = if replace { 0x1 | 0x2 } else { 0x2 };
        *(base.add(8) as *mut RawHandle) = dir;
        *(base.add(16) as *mut u32) = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, base.add(20), wide.len() * 2);
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = NtSetInformationFile(
            file,
            &mut iosb,
            base.cast(),
            total as u32,
            FILE_RENAME_INFORMATION_EX,
        );
        if status < 0 {
            return Err(nt_err(status));
        }
    }
    Ok(())
}

pub(crate) fn delete_by_handle(handle: RawHandle) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::{FileDispositionInfoEx, SetFileInformationByHandle};
    // FILE_DISPOSITION_FLAG_DELETE (0x1) | POSIX_SEMANTICS (0x2)
    let flags: u32 = 0x1 | 0x2;
    unsafe {
        SetFileInformationByHandle(
            HANDLE(handle),
            FileDispositionInfoEx,
            (&flags as *const u32).cast(),
            4,
        )?;
    }
    Ok(())
}

// ─── Validated tree walk and removal (docs/65 D-C7) ────────────────────────────

/// Bounds on a tree walk: a planted deep or huge tree must end in an error, never an unbounded loop.
#[derive(Debug, Clone, Copy)]
pub struct TreeLimits {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for TreeLimits {
    fn default() -> Self {
        Self { max_entries: 100_000, max_depth: 16 }
    }
}

/// What a directory entry is, decided on the OPENED handle (never by name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    /// A reparse point (junction, symlink, mount point): never followed and never deleted by this walk.
    Reparse,
}

/// Looser than [`valid_component`] (which names OUR state files): a removal sweep meets whatever is in the directory,
/// but still refuses anything that could escape it or address a stream.
fn valid_tree_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.chars().any(|c| matches!(c, '\\' | '/' | ':' | '\0'))
}

impl Dir {
    /// Classify child `name` on its own handle (opened relative, reparse point not followed).
    pub fn entry_kind(&self, name: &str) -> io::Result<EntryKind> {
        if !valid_tree_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = nt_open(
            Some(self.raw()),
            name,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | 0x4,
            Disposition::Open,
            0,
            None,
        )?;
        let attrs = attributes(h.as_raw_handle())?;
        Ok(if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            EntryKind::Reparse
        } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            EntryKind::Dir
        } else {
            EntryKind::File
        })
    }

    /// Open a validated (plain, trusted owner/DACL) child directory for a removal walk. Unlike [`Dir::child_dir`] the name
    /// check is the looser tree one, and the handle carries DELETE so an emptied directory can be removed on it.
    fn tree_child(&self, name: &str) -> io::Result<Dir> {
        if !valid_tree_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = nt_open(
            Some(self.raw()),
            name,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | 0x2 | 0x4 | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Disposition::Open,
            FILE_DIRECTORY_FILE,
            None,
        )?;
        validate(h.as_raw_handle(), true, OBJECT_MUTATE)?;
        Ok(Dir { handle: h })
    }

    /// Read-only pre-flight: every entry below this directory is a plain file or directory (no reparse point anywhere) with a
    /// trusted owner and a DACL that grants no non-admin a mutating right. Returns the number of entries. Anything else, or
    /// exceeding `limits`, is an error: the caller must refuse the removal rather than delete around it.
    pub fn validate_tree(&self, limits: &TreeLimits) -> io::Result<usize> {
        fn walk(dir: &Dir, limits: &TreeLimits, depth: usize, seen: &mut usize) -> io::Result<()> {
            if depth > limits.max_depth {
                return Err(io::Error::other("directory tree is deeper than the removal limit"));
            }
            for name in dir.list()? {
                *seen += 1;
                if *seen > limits.max_entries {
                    return Err(io::Error::other("directory tree has more entries than the removal limit"));
                }
                match dir.entry_kind(&name)? {
                    EntryKind::Reparse => {
                        return Err(io::Error::other(format!("refusing a reparse point at {name:?}")))
                    }
                    EntryKind::File => {
                        let h = nt_open(
                            Some(dir.raw()),
                            &name,
                            READ_CONTROL | FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | 0x4,
                            Disposition::Open,
                            0,
                            None,
                        )?;
                        validate(h.as_raw_handle(), false, OBJECT_MUTATE)?;
                    }
                    EntryKind::Dir => walk(&dir.tree_child(&name)?, limits, depth + 1, seen)?,
                }
            }
            Ok(())
        }
        let mut seen = 0;
        walk(self, limits, 0, &mut seen)?;
        Ok(seen)
    }

    /// Delete child FILE `name`, validated (plain file, trusted owner/DACL) on the very handle that is deleted, so there is no
    /// check-then-delete gap: a swapped-in reparse point or an untrusted file is refused, never followed.
    pub fn remove_validated_file(&self, name: &str) -> io::Result<()> {
        if !valid_tree_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = match nt_open(
            Some(self.raw()),
            name,
            DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            Disposition::Open,
            0,
            None,
        ) {
            Ok(h) => h,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        validate(h.as_raw_handle(), false, OBJECT_MUTATE)?;
        delete_by_handle(h.as_raw_handle())
    }

    /// Delete child FILE `name` only if the object opened by that name IS the file recorded as `expected` (volume serial + file
    /// id). Validated (plain file, trusted owner/DACL) and compared on the very handle that is deleted: a different file that
    /// has taken the name since, a reparse point or an untrusted file is refused, never deleted. A missing file is success.
    pub fn remove_file_if_identity(&self, name: &str, expected: &FileIdentity) -> io::Result<()> {
        if !valid_tree_component(name) {
            return Err(io::Error::other("invalid child name"));
        }
        let h = match nt_open(
            Some(self.raw()),
            name,
            DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            Disposition::Open,
            0,
            None,
        ) {
            Ok(h) => h,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        validate(h.as_raw_handle(), false, OBJECT_MUTATE)?;
        if &file_identity(h.as_raw_handle())? != expected {
            return Err(io::Error::other("the file is not the one that was confirmed; refusing to delete it"));
        }
        delete_by_handle(h.as_raw_handle())
    }

    /// Delete everything below this directory (not the directory itself), depth first. Every directory is re-validated as it is
    /// entered and every file on its own delete handle (see [`Dir::remove_validated_file`]); a reparse point or untrusted entry
    /// stops the sweep with an error and deletes nothing further. Returns the number of entries removed.
    pub fn remove_tree_contents(&self, limits: &TreeLimits) -> io::Result<usize> {
        fn sweep(dir: &Dir, limits: &TreeLimits, depth: usize, removed: &mut usize) -> io::Result<()> {
            if depth > limits.max_depth {
                return Err(io::Error::other("directory tree is deeper than the removal limit"));
            }
            for name in dir.list()? {
                if *removed >= limits.max_entries {
                    return Err(io::Error::other("directory tree has more entries than the removal limit"));
                }
                match dir.entry_kind(&name)? {
                    EntryKind::Reparse => {
                        return Err(io::Error::other(format!("refusing a reparse point at {name:?}")))
                    }
                    EntryKind::File => dir.remove_validated_file(&name)?,
                    EntryKind::Dir => {
                        let sub = dir.tree_child(&name)?;
                        sweep(&sub, limits, depth + 1, removed)?;
                        // `sub` is empty and validated; delete it on the handle we hold.
                        delete_by_handle(sub.raw())?;
                    }
                }
                *removed += 1;
            }
            Ok(())
        }
        let mut removed = 0;
        sweep(self, limits, 0, &mut removed)?;
        Ok(removed)
    }
}

/// Create `name` under `parent` as a NEW directory whose DACL is SYSTEM + Administrators only (protected: nothing inherited),
/// returning it validated. `parent` is opened by path WITHOUT following a reparse point; the child is created relative to that
/// handle. Fails if the child exists (a pre-planted directory is never adopted).
pub fn create_private_dir(parent: &Path, name: &str) -> io::Result<Dir> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_MODE, OPEN_EXISTING,
    };
    if !valid_tree_component(name) {
        return Err(io::Error::other("invalid directory name"));
    }
    let wide: Vec<u16> = parent.as_os_str().encode_wide().chain(Some(0)).collect();
    let ph = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | 0x2 | 0x4 | SYNCHRONIZE,
            FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE | 0x4),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0),
            None,
        )
        .map_err(win_err)?
    };
    let parent_h = unsafe { OwnedHandle::from_raw_handle(ph.0) };
    if attributes(parent_h.as_raw_handle())? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("the parent is a reparse point"));
    }
    let sd = OwnedSd::protected_admin_only(true)?;
    let h = nt_open(
        Some(parent_h.as_raw_handle()),
        name,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | 0x2 | 0x4,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        Disposition::Create,
        FILE_DIRECTORY_FILE,
        Some(&sd),
    )?;
    validate(h.as_raw_handle(), true, OBJECT_MUTATE)?;
    Ok(Dir { handle: h })
}


// ─── Held, validated directory chains (docs/65 D-C7 / R4) ──────────────────────

/// A chain of directories from a floor down to a target, every one opened WITHOUT following a reparse point, validated (plain
/// directory, trusted owner, no non-admin right to remove or rewrite it) and HELD OPEN, so none can be renamed or replaced while
/// the guard lives. Every ancestor is held with no delete/rename sharing. The LEAF is held with delete sharing allowed, because the
/// operation the guard protects (an MSI removal) legitimately deletes it; swapping it needs a right the validation proved nobody
/// but an administrator has.
pub struct HeldChain {
    _handles: Vec<OwnedHandle>,
    leaf_path: String,
}

impl HeldChain {
    /// The leaf's final path as the OS resolved it from the held handle (`C:\...`, verbatim prefix stripped).
    pub fn leaf_path(&self) -> &str {
        &self.leaf_path
    }
}

/// Rights a non-admin must not hold on the FLOOR directory (the volume root in production): only the ones that would let it remove
/// or rewrite the floor itself. Creating files in a volume root is normal Windows and is not refused.
const FLOOR_FORBIDDEN: u32 = PARENT_REMOVE | DELETE;
/// Rights a non-admin must not hold on every directory BELOW the floor, the leaf included: write, append, delete, delete-child,
/// WRITE_DAC, WRITE_OWNER, GENERIC_ALL.
const BELOW_FLOOR_FORBIDDEN: u32 = OBJECT_MUTATE | PARENT_REMOVE | DELETE;

fn validate_held_dir(handle: RawHandle, forbidden: u32) -> io::Result<()> {
    let attrs = attributes(handle)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("refusing a reparse point"));
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(io::Error::other("expected a directory"));
    }
    let (owner, aces) = handle_security(handle)?;
    // TrustedInstaller owns Program Files and its children: accepted here (and only here).
    if !dacl_is_trusted(owner, aces.as_deref(), forbidden, true) {
        return Err(io::Error::other("untrusted owner or DACL (a non-admin could rewrite or remove it)"));
    }
    Ok(())
}

/// Open and hold `leaf` and every directory from `floor` down to it. `leaf` must lie under `floor` (or equal it). Nothing is
/// followed by name after the floor is opened: each child is opened relative to its parent's handle.
pub fn hold_chain(leaf: &Path, floor: &Path) -> io::Result<HeldChain> {
    use std::path::Component;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_MODE,
        OPEN_EXISTING,
    };
    let rel = leaf
        .strip_prefix(floor)
        .map_err(|_| io::Error::other("the directory is not under the floor"))?;
    let mut names = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => names.push(n.to_string_lossy().into_owned()),
            _ => return Err(io::Error::other("the path has a non-plain component")),
        }
    }
    let access = FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    let wide: Vec<u16> = floor.as_os_str().encode_wide().chain(Some(0)).collect();
    // The floor, by path, once; no delete sharing, so it cannot be renamed under us.
    let fh = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_MODE(FILE_SHARE_READ | FILE_SHARE_WRITE),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0),
            None,
        )
        .map_err(win_err)?
    };
    let floor_h = unsafe { OwnedHandle::from_raw_handle(fh.0) };
    validate_held_dir(floor_h.as_raw_handle(), FLOOR_FORBIDDEN)?;
    let mut handles = vec![floor_h];
    for (i, name) in names.iter().enumerate() {
        if !valid_tree_component(name) {
            return Err(io::Error::other("invalid path component"));
        }
        let is_leaf = i + 1 == names.len();
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | if is_leaf { 0x4 } else { 0 };
        let parent = handles.last().expect("at least the floor").as_raw_handle();
        let h = nt_open(Some(parent), name, access, share, Disposition::Open, FILE_DIRECTORY_FILE, None)?;
        validate_held_dir(h.as_raw_handle(), BELOW_FLOOR_FORBIDDEN)?;
        handles.push(h);
    }
    let leaf_path = strip_verbatim_prefix(&final_path(handles.last().expect("non-empty").as_raw_handle())?);
    Ok(HeldChain { _handles: handles, leaf_path })
}

fn strip_verbatim_prefix(s: &str) -> String {
    s.strip_prefix(r"\\?\").unwrap_or(s).to_owned()
}

impl Dir {
    /// Delete the direct child `name` (a file, or a directory with everything under it) through handles relative to this directory,
    /// validated as in [`Dir::remove_tree_contents`]. A reparse point is refused, never followed or deleted.
    pub fn remove_entry(&self, name: &str, limits: &TreeLimits) -> io::Result<()> {
        match self.entry_kind(name)? {
            EntryKind::Reparse => Err(io::Error::other(format!("refusing a reparse point at {name:?}"))),
            EntryKind::File => self.remove_validated_file(name),
            EntryKind::Dir => {
                let sub = self.tree_child(name)?;
                sub.remove_tree_contents(limits)?;
                delete_by_handle(sub.raw())
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn ace(who: Principal, mask: u32) -> AceView {
        AceView {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: 0,
            mask,
            who,
        }
    }

    #[test]
    fn hardened_root_shape_is_trusted() {
        let aces = [
            ace(Principal::System, 0x1F01FF),
            ace(Principal::Administrators, 0x1F01FF),
        ];
        assert!(dacl_is_trusted(Principal::Administrators, Some(&aces), OBJECT_MUTATE, false));
    }

    #[test]
    fn any_non_admin_mutating_right_is_refused() {
        for right in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_DELETE_CHILD,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
            GENERIC_WRITE,
        ] {
            let aces = [ace(Principal::System, 0x1F01FF), ace(Principal::Other, right)];
            assert!(
                !dacl_is_trusted(Principal::System, Some(&aces), OBJECT_MUTATE, false),
                "{right:#x}"
            );
        }
        // Read/execute for users is fine.
        let aces = [ace(Principal::Other, 0x1200A9)];
        assert!(dacl_is_trusted(Principal::System, Some(&aces), OBJECT_MUTATE, false));
    }

    // 1.3.19 VM run: a missing directory opened through the anchor came back as the HRESULT 0x80070002
    // (-2147024894), so `ErrorKind::NotFound` / `is_not_found` missed it and the uploader logged "the drain fence
    // cannot be read" forever on every machine without a recording queue.
    #[test]
    fn a_win32_hresult_is_unwrapped_to_its_plain_code_and_reads_as_not_found() {
        use windows::core::HRESULT;
        let e = win_err(windows::core::Error::from(HRESULT(0x8007_0002_u32 as i32)));
        assert_eq!(e.raw_os_error(), Some(2));
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(is_not_found(&e));
        let path = win_err(windows::core::Error::from(HRESULT(0x8007_0003_u32 as i32)));
        assert!(is_not_found(&path), "ERROR_PATH_NOT_FOUND too");
        // An error left in HRESULT form is still recognised by the fallback.
        assert!(is_not_found(&io::Error::from_raw_os_error(-2147024894)));
        // A non-Win32 HRESULT is not mistaken for "not found".
        let other = win_err(windows::core::Error::from(HRESULT(0x8000_4005_u32 as i32)));
        assert!(!is_not_found(&other));
    }

    #[test]
    fn opening_a_missing_directory_through_the_anchor_is_not_found() {
        let base = std::env::temp_dir().join(format!("anchor-missing-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&base).unwrap();
        let err = Anchor::open_at(&base.join("does-not-exist")).err().expect("a missing directory cannot be opened");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err:?}");
        assert!(is_not_found(&err));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn owner_null_dacl_unknown_ace_and_inherit_only() {
        assert!(!dacl_is_trusted(Principal::Other, Some(&[]), OBJECT_MUTATE, false), "owner");
        assert!(!dacl_is_trusted(Principal::System, None, OBJECT_MUTATE, false), "null DACL");
        let object_ace = AceView {
            ace_type: 5,
            flags: 0,
            mask: 0,
            who: Principal::System,
        };
        assert!(!dacl_is_trusted(Principal::System, Some(&[object_ace]), OBJECT_MUTATE, false));
        // CREATOR OWNER-style inherit-only grant does not apply to the object itself.
        let io = AceView {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: INHERIT_ONLY_ACE,
            mask: GENERIC_ALL,
            who: Principal::Other,
        };
        assert!(dacl_is_trusted(Principal::System, Some(&[io]), OBJECT_MUTATE, false));
        // A deny ACE never makes something trusted or untrusted by itself.
        let deny = AceView {
            ace_type: ACCESS_DENIED_ACE_TYPE,
            flags: 0,
            mask: GENERIC_ALL,
            who: Principal::Other,
        };
        assert!(dacl_is_trusted(Principal::System, Some(&[deny]), OBJECT_MUTATE, false));
    }

    #[test]
    fn default_c_drive_parent_passes_the_remove_check() {
        // C:\ default: Users RX, Authenticated Users AppendData on the object and Modify IO.
        let aces = [
            ace(Principal::Administrators, 0x1F01FF),
            ace(Principal::System, 0x1F01FF),
            ace(Principal::Other, 0x1200A9),
            ace(Principal::Other, FILE_APPEND_DATA),
            AceView {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: INHERIT_ONLY_ACE | 0x3,
                mask: 0x1301BF,
                who: Principal::Other,
            },
        ];
        assert!(dacl_is_trusted(Principal::TrustedInstaller, Some(&aces), PARENT_REMOVE, true));
        let mut bad = aces.to_vec();
        bad.push(ace(Principal::Other, FILE_DELETE_CHILD));
        assert!(!dacl_is_trusted(Principal::TrustedInstaller, Some(&bad), PARENT_REMOVE, true));
        // TrustedInstaller ownership is accepted only where the caller allows it.
        assert!(!dacl_is_trusted(Principal::TrustedInstaller, Some(&aces), OBJECT_MUTATE, false));
    }

    #[test]
    fn component_names_are_single_safe_segments() {
        for ok in ["update-state.json", "gate.0f1e.json", "a_b-c.d"] {
            assert!(valid_component(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a\\b", "a/b", "a:b", "x.", "c:", "name*", "a b"] {
            assert!(!valid_component(bad), "{bad}");
        }
    }

    /// A temp `<base>/rmt-agent` pair, both hardened like production (elevation required).
    fn hardened_pair() -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("rmt-anchor-{}", uuid::Uuid::new_v4()));
        let root = base.join("rmt-agent");
        std::fs::create_dir_all(&root).unwrap();
        for dir in [&base, &root] {
            icacls_ok(crate::agent_root::setowner_args(dir));
            icacls_ok(crate::agent_root::dacl_args(dir));
        }
        (base, root)
    }
    fn icacls_ok(args: Vec<std::ffi::OsString>) {
        let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe"))
            .args(args)
            .output()
            .expect("icacls runs");
        assert!(
            out.status.success(),
            "icacls failed (elevation required): {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn a_child_writable_by_users_is_refused() {
        let (base, root) = hardened_pair();
        std::fs::write(root.join("state.json"), b"{}").unwrap();
        let anchor = Anchor::open_at(&root).unwrap();
        assert!(anchor.dir().read("state.json", 64).unwrap().is_some(), "premise: trusted child reads");
        icacls_ok(vec![
            root.join("state.json").into_os_string(),
            "/grant".into(),
            "*S-1-5-32-545:(W)".into(),
        ]);
        let err = anchor.dir().read("state.json", 64).unwrap_err();
        assert!(err.to_string().contains("untrusted"), "{err}");
        drop(anchor);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_junction_child_is_never_followed() {
        let (base, root) = hardened_pair();
        let target = base.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = root.join("update-staging");
        let made = std::process::Command::new(crate::agent_root::system32_exe("cmd.exe"))
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(made.status.success(), "premise: junction created");
        let anchor = Anchor::open_at(&root).unwrap();
        assert!(anchor.dir().child_dir("update-staging", false).is_err());
        assert!(anchor.dir().child_dir("update-staging", true).is_err());
        drop(anchor);
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_parent_granting_delete_child_is_refused() {
        let (base, root) = hardened_pair();
        assert!(Anchor::open_at(&root).is_ok(), "premise: a hardened parent passes");
        icacls_ok(vec![base.clone().into_os_string(), "/grant".into(), "*S-1-5-32-545:(DC)".into()]);
        let err = Anchor::open_at(&root).err().expect("delete-child on the parent refused");
        assert!(err.to_string().contains("parent"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Real filesystem round trip under a private temp parent, both hardened exactly like the
    /// production root. Needs the elevated environment the gate provides (setting the owner to
    /// Administrators); a non-elevated runner FAILS here rather than skipping, because a skipped
    /// round trip would prove nothing about the native plumbing.
    #[test]
    fn write_read_replace_remove_round_trip_relative_to_the_anchor() {
        let base = std::env::temp_dir().join(format!("rmt-anchor-{}", uuid::Uuid::new_v4()));
        let root = base.join("rmt-agent");
        std::fs::create_dir_all(&root).unwrap();
        let icacls = |args: Vec<std::ffi::OsString>| {
            let out = std::process::Command::new(crate::agent_root::system32_exe("icacls.exe"))
                .args(args)
                .output()
                .expect("icacls runs");
            assert!(
                out.status.success(),
                "icacls failed (elevation required): {}",
                String::from_utf8_lossy(&out.stdout)
            );
        };
        for dir in [&base, &root] {
            icacls(crate::agent_root::setowner_args(dir));
            icacls(crate::agent_root::dacl_args(dir));
        }
        let result = std::panic::catch_unwind(|| {
            let anchor = match Anchor::open_at(&root) {
                Ok(a) => a,
                Err(e) => panic!("open_at: {e}"),
            };
            let d = anchor.dir();
            assert_eq!(d.read("state.json", 1024).unwrap(), None);
            d.write_atomic("state.json", b"one").unwrap();
            assert_eq!(d.read("state.json", 1024).unwrap().as_deref(), Some(&b"one"[..]));
            d.write_atomic("state.json", b"two").unwrap();
            assert_eq!(d.read("state.json", 1024).unwrap().as_deref(), Some(&b"two"[..]));
            assert!(d.read("state.json", 2).is_err(), "size limit enforced");
            // No temp leftovers.
            assert_eq!(d.list().unwrap(), ["state.json"]);
            // The anchor cannot be renamed while held.
            assert!(std::fs::rename(&root, base.join("moved")).is_err());
            let sub = d.child_dir("staging", true).unwrap();
            sub.write_atomic("x.bin", b"x").unwrap();
            assert!(sub.final_path().unwrap().ends_with("staging"));
            sub.remove("x.bin").unwrap();
            d.remove("state.json").unwrap();
            d.remove("state.json").unwrap();
            assert!(anchor.expect_identity(&anchor.identity()).is_ok());
        });
        let _ = std::fs::remove_dir_all(&base);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
    }
}
