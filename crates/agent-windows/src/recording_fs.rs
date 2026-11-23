//! Trusted-directory access for the recording uploader (docs/63 R2, review B1/B3).
//!
//! Everything the uploader touches on disk — its queue state, the recorder's segments and sidecars, its lock
//! files — goes through [`DirIo`], a handle-oriented view of ONE directory:
//!
//! * [`AnchoredFs`] (production) opens each directory through [`crate::anchor`]: the directory handle is held
//!   without `FILE_SHARE_DELETE`, children are opened RELATIVE to it with reparse points not followed, and the
//!   directory, its parent and every file used must be owned by SYSTEM/Administrators with no non-admin
//!   mutating right. A queue directory (or a recording) that fails that check is REFUSED, so a persisted
//!   `Complete` can only ever be trusted as delete authority if a non-admin could not have written it.
//! * [`StdFs`] implements the same trait over `std::fs` for tests: it keeps the reparse-point refusals and the
//!   file-identity checks but not the owner/DACL validation (a test directory under `%TEMP%` is user-owned).
//!
//! Files are opened once into a [`HeldFile`]: the handle, its volume serial + file id and its size. The uploader
//! hashes AND reads chunks from the held handle, and deletes only a file whose identity is the one that was
//! confirmed ([`DirIo::remove_file_if`]).

use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use crate::anchor::{self, Anchor, Dir, EntryKind, FileIdentity};

const FILE_SHARE_READ: u32 = 1;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const ERROR_SHARING_VIOLATION: i32 = 32;

/// An opened, validated regular file: the handle, its identity and its size at open.
pub struct HeldFile {
    pub file: File,
    pub id: FileIdentity,
    pub len: u64,
    pub mtime_ms: u128,
}

/// One directory, opened through a trusted route.
pub trait DirIo {
    /// Names of the direct children (files and directories).
    fn list(&self) -> io::Result<Vec<String>>;
    /// Names of the direct children that are plain directories (reparse points excluded).
    fn subdirs(&self) -> io::Result<Vec<String>>;
    /// Bounded read of a child file. `Ok(None)` when it does not exist.
    fn read(&self, name: &str, max: usize) -> io::Result<Option<Vec<u8>>>;
    /// Atomically replace (or create) a child file, durably (flushed before the rename).
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()>;
    /// Delete a child file; success when it is already gone.
    fn remove(&self, name: &str) -> io::Result<()>;
    /// Open a child regular file, refusing reparse points (and, in production, untrusted owners/DACLs).
    fn open_file(&self, name: &str) -> io::Result<HeldFile>;
    /// Delete a child file only if it is the file with this identity; success when it is gone.
    fn remove_file_if(&self, name: &str, id: &FileIdentity) -> io::Result<()>;
    /// This directory's own identity.
    fn identity(&self) -> io::Result<FileIdentity>;
    /// Open a child directory.
    fn child(&self, name: &str) -> io::Result<Box<dyn DirIo>>;
    /// Remove a child directory that is EMPTY; an error when it is not.
    fn remove_empty_subdir(&self, name: &str) -> io::Result<()>;
    /// Take the exclusive lock file `name` (created if absent). `Ok(None)` when someone else holds it.
    fn lock(&self, name: &str) -> io::Result<Option<File>>;
}

/// Opens directories by path.
pub trait FsProvider: Send + Sync {
    /// `create`: create the directory (with the protected descriptor in production) when absent.
    fn open(&self, path: &Path, create: bool) -> io::Result<Box<dyn DirIo>>;
}

fn bad_name() -> io::Error {
    io::Error::other("invalid child name")
}

fn mtime_ms(md: &std::fs::Metadata) -> u128 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

// ---- production: anchored ------------------------------------------------------------------------

pub struct AnchoredFs;

enum Holder {
    Root(Anchor),
    Child(Dir),
}

struct ADir {
    holder: Holder,
}

impl ADir {
    fn d(&self) -> &Dir {
        match &self.holder {
            Holder::Root(a) => a.dir(),
            Holder::Child(d) => d,
        }
    }
}

impl FsProvider for AnchoredFs {
    fn open(&self, path: &Path, create: bool) -> io::Result<Box<dyn DirIo>> {
        if create {
            if let (Some(parent), Some(leaf)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) {
                // The leaf is created with the protected (SYSTEM + Administrators) descriptor, below a validated parent.
                Anchor::open_at(parent)?.dir().child_dir(leaf, true)?;
            }
        }
        Ok(Box::new(ADir { holder: Holder::Root(Anchor::open_at(path)?) }))
    }
}

impl DirIo for ADir {
    fn list(&self) -> io::Result<Vec<String>> {
        self.d().list()
    }
    fn subdirs(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for name in self.d().list()? {
            if self.d().entry_kind(&name)? == EntryKind::Dir {
                out.push(name);
            }
        }
        Ok(out)
    }
    fn read(&self, name: &str, max: usize) -> io::Result<Option<Vec<u8>>> {
        self.d().read(name, max)
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.d().write_atomic(name, bytes)
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        self.d().remove(name)
    }
    fn open_file(&self, name: &str) -> io::Result<HeldFile> {
        // Shared for reading only: while it is held nobody can write to, rename or delete it.
        let file = self.d().open_file_read(name, FILE_SHARE_READ)?;
        let md = file.metadata()?;
        let id = anchor::file_identity(file.as_raw_handle())?;
        Ok(HeldFile { id, len: md.len(), mtime_ms: mtime_ms(&md), file })
    }
    fn remove_file_if(&self, name: &str, id: &FileIdentity) -> io::Result<()> {
        self.d().remove_file_if_identity(name, id)
    }
    fn identity(&self) -> io::Result<FileIdentity> {
        anchor::file_identity(self.d().raw())
    }
    fn child(&self, name: &str) -> io::Result<Box<dyn DirIo>> {
        Ok(Box::new(ADir { holder: Holder::Child(self.d().child_dir(name, false)?) }))
    }
    fn remove_empty_subdir(&self, name: &str) -> io::Result<()> {
        let sub = self.d().child_dir(name, false)?;
        if !sub.list()?.is_empty() {
            return Err(io::Error::other("directory is not empty"));
        }
        drop(sub);
        self.d().remove_dir(name)
    }
    fn lock(&self, name: &str) -> io::Result<Option<File>> {
        match self.d().open_exclusive(name) {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---- tests: std::fs -------------------------------------------------------------------------------

/// `std::fs` implementation (reparse refusal + identity checks, no owner/DACL validation).
pub struct StdFs;

struct StdDir {
    path: PathBuf,
}

impl FsProvider for StdFs {
    fn open(&self, path: &Path, create: bool) -> io::Result<Box<dyn DirIo>> {
        if create {
            std::fs::create_dir_all(path)?;
        }
        let md = std::fs::symlink_metadata(path)?;
        if !md.is_dir() || crate::agent_root::is_reparse_point(&md) {
            return Err(io::Error::other("not a plain directory"));
        }
        Ok(Box::new(StdDir { path: path.to_path_buf() }))
    }
}

impl StdDir {
    fn p(&self, name: &str) -> io::Result<PathBuf> {
        if !anchor::valid_component(name) {
            return Err(bad_name());
        }
        Ok(self.path.join(name))
    }
    fn open_nofollow(&self, name: &str) -> io::Result<HeldFile> {
        let p = self.p(name)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&p)?;
        let md = file.metadata()?;
        if !md.is_file() || crate::agent_root::is_reparse_point(&md) {
            return Err(io::Error::other("refusing a reparse point or non-regular file"));
        }
        let id = anchor::file_identity(file.as_raw_handle())?;
        Ok(HeldFile { id, len: md.len(), mtime_ms: mtime_ms(&md), file })
    }
}

impl DirIo for StdDir {
    fn list(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.path)? {
            if let Some(n) = e?.file_name().to_str() {
                out.push(n.to_string());
            }
        }
        Ok(out)
    }
    fn subdirs(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.path)? {
            let e = e?;
            let md = std::fs::symlink_metadata(e.path())?;
            if md.is_dir() && !crate::agent_root::is_reparse_point(&md) {
                if let Some(n) = e.file_name().to_str() {
                    out.push(n.to_string());
                }
            }
        }
        Ok(out)
    }
    fn read(&self, name: &str, max: usize) -> io::Result<Option<Vec<u8>>> {
        use std::io::Read;
        let held = match self.open_nofollow(name) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut data = Vec::new();
        held.file.take(max as u64 + 1).read_to_end(&mut data)?;
        if data.len() > max {
            return Err(io::Error::other("file exceeds its size limit"));
        }
        Ok(Some(data))
    }
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let target = self.p(name)?;
        let tmp = self.path.join(format!("{name}.tmp-{}", uuid::Uuid::new_v4().simple()));
        let r = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &target)
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        match std::fs::remove_file(self.p(name)?) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
    fn open_file(&self, name: &str) -> io::Result<HeldFile> {
        self.open_nofollow(name)
    }
    fn remove_file_if(&self, name: &str, id: &FileIdentity) -> io::Result<()> {
        let held = match self.open_nofollow(name) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if &held.id != id {
            return Err(io::Error::other("the file is not the one that was confirmed; refusing to delete it"));
        }
        drop(held);
        std::fs::remove_file(self.p(name)?)
    }
    fn identity(&self) -> io::Result<FileIdentity> {
        let f = std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(&self.path)?;
        anchor::file_identity(f.as_raw_handle())
    }
    fn child(&self, name: &str) -> io::Result<Box<dyn DirIo>> {
        StdFs.open(&self.p(name)?, false)
    }
    fn remove_empty_subdir(&self, name: &str) -> io::Result<()> {
        std::fs::remove_dir(self.p(name)?)
    }
    fn lock(&self, name: &str) -> io::Result<Option<File>> {
        match std::fs::OpenOptions::new().write(true).create(true).truncate(false).share_mode(0).open(self.p(name)?) {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
