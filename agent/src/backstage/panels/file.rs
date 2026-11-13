//! File browse panel — a read-only view of the remote filesystem, rendered natively in the
//! technician UI (a directory listing, not remoted pixels). This is the "File Manager" browse
//! half; download/upload/delete are separate capabilities.
//!
//! Requires [`crate::backstage::rbac::Capability::FileBrowse`]. Deliberately **not** chrooted:
//! a support technician's file manager is expected to reach the whole disk (ScreenConnect's
//! does). The controls that make this safe are the capability grant, the audit record of every
//! path browsed, and keeping mutation (`FileUpload`/`FileDelete`) behind separate Tier-2/3
//! capabilities — not a path jail that would make the tool useless.
//!
//! Portable: built on `std::fs`, so it lists real directories on any platform. An empty path
//! is treated as "the top level": the drive roots on Windows, `/` elsewhere.

use serde::{Deserialize, Serialize};

/// One entry in a directory listing. Shaped for direct JSON rendering; every field the UI
/// can't read is an `Option` so it renders "—" instead of a fabricated value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    /// File size in bytes; `None` for directories and for entries whose metadata can't be read.
    pub size_bytes: Option<u64>,
    /// Last-modified time as Unix milliseconds; `None` when unreadable or before the epoch.
    pub modified_unix_ms: Option<i64>,
}

/// A resolved directory listing. `path` is echoed back (normalized to what was actually read)
/// so the UI and the audit log agree on the target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirListing {
    pub path: String,
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum BrowseError {
    #[error("cannot read directory {path:?}: {source}")]
    Io { path: String, source: std::io::Error },
}

/// List a directory. An empty `path` yields the top level (drive roots on Windows, `/`
/// elsewhere). Entries are sorted directories-first, then case-insensitively by name — the
/// ordering a file manager is expected to show.
pub fn list(path: &str) -> Result<DirListing, BrowseError> {
    if path.is_empty() {
        return Ok(top_level());
    }

    // The sibling control-channel browser uses the same policy. Do not stat or open
    // the supplied path before these checks: that can already authenticate over SMB.
    super::local_path::validate_path_shape(path)
        .and_then(|_| super::local_path::refuse_remote_drive(path))
        .and_then(|_| super::local_path::refuse_reparse_indirection(path))
        .map_err(|e| BrowseError::Io {
            path: path.to_string(), source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
        })?;
    let read = std::fs::read_dir(path).map_err(|source| BrowseError::Io { path: path.to_string(), source })?;

    let mut scanned = 0usize;
    let mut entries: Vec<FileEntry> = read
        .take(4097)
        .inspect(|_| scanned += 1)
        .filter_map(|res| res.ok())
        .map(|dirent| {
            let name = dirent.file_name().to_string_lossy().into_owned();
            // `symlink_metadata` does not traverse links, so a dangling symlink still lists.
            let meta = dirent.path().symlink_metadata().ok();
            let is_symlink = meta.as_ref().map(|m| m.file_type().is_symlink()).unwrap_or(false);
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            FileEntry {
                name,
                is_dir,
                is_symlink,
                size_bytes: meta.as_ref().filter(|m| m.is_file()).map(|m| m.len()),
                modified_unix_ms: meta.as_ref().and_then(modified_ms),
            }
        })
        .collect();

    if scanned > 4096 {
        return Err(BrowseError::Io { path: path.to_string(), source: std::io::Error::other("directory exceeds the 4096-entry browse limit") });
    }
    sort_entries(&mut entries);
    Ok(DirListing { path: path.to_string(), entries })
}

/// Extract the modified time as Unix milliseconds, or `None` if unavailable / pre-epoch.
fn modified_ms(meta: &std::fs::Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(dur.as_millis() as i64)
}

/// Directories first, then case-insensitive by name.
fn sort_entries(entries: &mut [FileEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
    });
}

/// The top-level listing: available drive roots on Windows, `/` elsewhere.
fn top_level() -> DirListing {
    #[cfg(windows)]
    {
        // `GetLogicalDrives` returns a bitmask of present drive letters and touches no media —
        // unlike probing each `X:\` with `exists()`, which blocks for seconds on a disconnected
        // removable or network drive and would hang the technician's file manager.
        let mask = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
        let entries = (0u32..26)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| FileEntry {
                name: format!("{}:\\", (b'A' + i as u8) as char),
                is_dir: true,
                is_symlink: false,
                size_bytes: None,
                modified_unix_ms: None,
            })
            .collect();
        DirListing { path: String::new(), entries }
    }
    #[cfg(not(windows))]
    {
        // On Unix "the top level" is just the root directory.
        list("/").unwrap_or(DirListing { path: "/".into(), entries: Vec::new() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn security_browse_refuses_network_names_before_io() {
        for path in [r"\\attacker.invalid\share", r"\\?\UNC\attacker.invalid\share", r"\\.\PhysicalDrive0", r"C:relative"] {
            assert!(list(path).is_err(), "{path:?}");
        }
    }

    #[test]
    fn lists_a_real_temp_dir_with_known_contents() {
        // Build a scratch dir with a file and a subdirectory, then list it.
        let base = std::env::temp_dir().join(format!("rmt_browse_test_{}", std::process::id()));
        let sub = base.join("subdir");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(base.join("hello.txt"), b"hello world").unwrap();

        let listing = list(&base.to_string_lossy()).expect("temp dir should list");

        let file = listing.entries.iter().find(|e| e.name == "hello.txt").expect("file present");
        assert!(!file.is_dir);
        assert_eq!(file.size_bytes, Some(11));
        assert!(file.modified_unix_ms.is_some());

        let dir = listing.entries.iter().find(|e| e.name == "subdir").expect("subdir present");
        assert!(dir.is_dir);
        assert_eq!(dir.size_bytes, None, "directories report no size");

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn directories_sort_before_files() {
        let mut entries = vec![
            FileEntry { name: "zebra".into(), is_dir: false, is_symlink: false, size_bytes: Some(1), modified_unix_ms: None },
            FileEntry { name: "apple".into(), is_dir: true, is_symlink: false, size_bytes: None, modified_unix_ms: None },
            FileEntry { name: "Banana".into(), is_dir: false, is_symlink: false, size_bytes: Some(2), modified_unix_ms: None },
        ];
        sort_entries(&mut entries);
        assert_eq!(entries[0].name, "apple", "dir first");
        assert_eq!(entries[1].name, "Banana", "then case-insensitive: Banana before zebra");
        assert_eq!(entries[2].name, "zebra");
    }

    #[test]
    fn missing_directory_is_an_error_not_a_panic() {
        let err = list("this/path/does/not/exist/anywhere_12345");
        assert!(err.is_err());
    }

    #[test]
    fn empty_path_lists_the_top_level() {
        let listing = list("").expect("top level should list");
        assert!(!listing.entries.is_empty(), "there is always at least one drive/root");
        // Drive roots are all directories; Unix "/" also holds files and symlinks (e.g. /bin).
        #[cfg(windows)]
        assert!(listing.entries.iter().all(|e| e.is_dir), "roots are directories");
        #[cfg(not(windows))]
        assert_eq!(listing.path, "/", "the Unix top level is the root directory");
    }
}
