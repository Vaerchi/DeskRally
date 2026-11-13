//! Shared pre-I/O directory policy for both remote browse protocols.

use std::path::{Component, Path, Prefix};

/// Why a directory could not be listed.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// The path does not exist, is not a directory, or could not be opened (permission, I/O).
    /// Surfaced to the controller as a `ControlMessage::Error`.
    #[error("could not list directory: {0}")]
    Io(String),
    /// The path was REFUSED by this agent's own policy, before anything on the far side of it was
    /// touched (docs/25 F04). Surfaced as a `ControlMessage::DirectoryListingRefused`, and kept a
    /// separate variant from [`Io`](ListError::Io) precisely because the two are different events:
    /// `Io` is the filesystem declining, which happens constantly and means nothing, while this is
    /// the AGENT declining — somebody asked this machine to reach somewhere it will not reach, which
    /// is worth a line in the audit trail.
    #[error("{0}")]
    Refused(String),
}

/// Reject a `ListDirectory` path whose SHAPE names something other than an absolute path on a local
/// disk (docs/25 F04). Pure and total: no filesystem call, so it cannot itself perform the I/O it
/// exists to prevent.
///
/// The rule is an ALLOW-LIST of one prefix kind, not a deny-list of the spellings we happened to
/// think of — a deny-list on this surface is a list of the ways somebody else will find:
///
///   * `Prefix::Disk` (`C:\…`) is the only accepted prefix.
///   * `Prefix::UNC` / `Prefix::VerbatimUNC` are the network paths F04 is about.
///   * `Prefix::DeviceNS` (`\\.\PhysicalDrive0`) names a device, not a directory.
///   * `Prefix::Verbatim` / `Prefix::VerbatimDisk` (`\\?\…`) bypass Win32 path normalization and can
///     name a REDIRECTED DOS device, so `\\?\C:\` is not merely `C:\` spelled differently.
///
/// That last one is also why nothing canonicalizes before this runs: on Windows
/// `std::fs::canonicalize` RETURNS a `\\?\`-prefixed path, so a check placed after it would invert
/// its own rule and refuse everything it had just resolved.
///
/// Two shapes are refused for reasons that are not about the network at all:
///
///   * `C:folder` is DRIVE-RELATIVE — Windows resolves it against a per-drive current directory
///     belonging to this process, so the same request names different directories at different
///     times, and an audit line recording it would be a record of nothing in particular.
///   * a path containing `..` is refused even though there is no root to escape from, because the
///     path is what goes into the audit record: with `..` in it, two spellings name one directory
///     and one spelling can be made to look like somewhere else.
#[cfg(windows)]
pub fn validate_path_shape(path: &str) -> Result<(), ListError> {
    if path.is_empty() {
        // Not a path: the empty request is the drive-root listing, which reads no path at all (see
        // `drive_roots` — it asks the local device map for a bitmask). Refusing it would break the
        // browser's entry point to protect nothing.
        return Ok(());
    }
    let p = Path::new(path);
    let mut comps = p.components();
    match comps.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) => {}
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => {
                return Err(ListError::Refused(
                    "network (UNC) paths are not browsable: reaching one would make this machine \
                     authenticate to it"
                        .into(),
                ));
            }
            Prefix::DeviceNS(_) => {
                return Err(ListError::Refused(
                    r"device-namespace (\\.\) paths are not browsable: they name devices, not directories"
                        .into(),
                ));
            }
            Prefix::Verbatim(_) | Prefix::VerbatimDisk(_) => {
                return Err(ListError::Refused(
                    r"extended-length (\\?\) paths are not browsable: they bypass path normalization and can name a redirected device"
                        .into(),
                ));
            }
        },
        _ => {
            return Err(ListError::Refused(
                r"only an absolute local path such as C:\Users is browsable".into(),
            ));
        }
    }
    if comps.next() != Some(Component::RootDir) {
        return Err(ListError::Refused(
            r"a drive-relative path (C:folder) is not browsable; send C:\folder".into(),
        ));
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ListError::Refused(
            r#"a path containing ".." is not browsable; send the resolved path"#.into(),
        ));
    }
    Ok(())
}

/// Non-Windows stub, for the same reason `drive_roots` has one: off-Windows this crate is an empty
/// shell, and `Path::components` never yields a `Prefix` there — so the Windows rule would refuse
/// every path in existence, including the temp directories the unit tests build. The real agent is
/// Windows-only.
#[cfg(not(windows))]
pub fn validate_path_shape(_path: &str) -> Result<(), ListError> {
    Ok(())
}

/// The drive letter a validated path is on, if it has one.
#[cfg(windows)]
pub fn drive_letter_of(path: &str) -> Option<char> {
    match Path::new(path).components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(letter) => Some(letter as char),
            _ => None,
        },
        _ => None,
    }
}

/// Refuse a path on a MAPPED NETWORK DRIVE (docs/25 F04).
///
/// `Prefix::Disk` is not evidence that a path is local. `net use Z: \\server\share` makes `Z:\` a
/// drive letter whose device-map entry points at the SMB redirector, so `Z:\anything` satisfies
/// [`validate_path_shape`] and still authenticates this machine to `\\server`. Without this check the
/// string rule would be theatre: the attacker's path would simply be spelled with a letter.
///
/// `GetDriveTypeW` is the right instrument precisely because it answers from the local device map
/// rather than by probing the volume — it does not connect, which is the entire point. The obvious
/// alternative (stat the root and look at what came back) would have made the connection this exists
/// to prevent before it could report anything.
#[cfg(windows)]
pub fn refuse_remote_drive(path: &str) -> Result<(), ListError> {
    let Some(letter) = drive_letter_of(path) else {
        return Ok(());
    };
    if drive_is_remote(letter) {
        return Err(ListError::Refused(format!(
            r"{letter}:\ is a mapped network drive, which is not browsable: reaching it would make this machine authenticate to the share behind it"
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn refuse_remote_drive(_path: &str) -> Result<(), ListError> {
    Ok(())
}

/// Whether `letter:` is a mapped network drive, per this process's DOS device map. Local-only: no
/// packet is sent and no volume is touched.
#[cfg(windows)]
pub fn drive_is_remote(letter: char) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    use windows::Win32::System::WindowsProgramming::DRIVE_REMOTE;
    let root: Vec<u16> = format!(r"{letter}:\").encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `root` is a NUL-terminated UTF-16 buffer that outlives the call; GetDriveTypeW only
    // reads it and returns a DWORD.
    let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
    kind == DRIVE_REMOTE
}

/// Refuse a path that reaches its target THROUGH a reparse point whose target is off this machine
/// (docs/25 F04: "account for reparse points, not just string prefixes").
///
/// A string rule cannot see indirection. `mklink /D C:\x \\server\share` produces a path that passes
/// every check above and still resolves onto SMB, because Windows follows the reparse point in the
/// kernel when the handle is opened. Both obvious instruments LOSE here, and lose the same way:
/// `canonicalize` and `read_dir` have already opened the target — and therefore already
/// authenticated — by the time they hand back something to inspect. A check that runs after the
/// connection is a detection, not a defence.
///
/// So the walk goes the other way. Ancestors are examined SHORTEST FIRST (`C:\`, then `C:\x`, then
/// `C:\x\sub`) with `symlink_metadata`, which does not follow the FINAL component — so the first
/// reparse point is always found by a call that stopped AT it rather than one that went through it,
/// and the walk never issues the call that would traverse it. Its target is then read with
/// `read_link`, which asks the filesystem what the link RECORDS (`FSCTL_GET_REPARSE_POINT`) instead
/// of opening what it points at. Nothing on the far side is contacted before the decision.
///
/// A LOCAL target is allowed, deliberately: `C:\Users\All Users` and `C:\Documents and Settings` are
/// junctions Windows itself installs, and refusing every reparse point would break ordinary
/// navigation to protect against nothing. Only a target that leaves the local disk is refused, which
/// is the same line every other check here draws.
///
/// **Residual, stated rather than hidden.** A CHAIN of links (`C:\a` → `C:\b`, `C:\b` →
/// `\\server\share`) is not caught when the deep path is requested directly, because `C:\b` is not
/// textually an ancestor of `C:\a\sub` and this walk only sees ancestors. And any check of this
/// shape is a TOCTOU: the link could be repointed between the walk and `read_dir`, which costs an
/// attacker a write to the guest's own disk. F04's own recommendation — restrict outbound SMB/NTLM
/// at the host — is the containment for what a path check structurally cannot reach.
pub fn refuse_reparse_indirection(path: &str) -> Result<(), ListError> {
    let mut ancestors: Vec<&Path> = Path::new(path).ancestors().collect();
    ancestors.reverse(); // shortest first: the drive root before anything under it
    for ancestor in ancestors {
        let md = match std::fs::symlink_metadata(ancestor) {
            Ok(md) => md,
            // This ancestor does not exist or cannot be stat'ed, so nothing DEEPER does either.
            // Stop and let `read_dir` produce the real I/O error: this function only ever refuses,
            // and turning "not found" into a refusal would misreport a typo as an attack.
            Err(_) => break,
        };
        if !md.is_symlink() {
            continue;
        }
        let target = std::fs::read_link(ancestor).map_err(|e| {
            ListError::Refused(format!(
                "{} is a reparse point whose target could not be read ({e}), so where it leads \
                 cannot be established",
                ancestor.display()
            ))
        })?;
        if !target_is_local(&target) {
            return Err(ListError::Refused(format!(
                "{} is a link to {}, which is not on this machine's local disk",
                ancestor.display(),
                target.display()
            )));
        }
    }
    Ok(())
}

/// Whether a reparse point's target names a location on this machine's local disk.
///
/// `read_link` returns what the link actually RECORDS, and the three shapes differ: a junction's
/// target comes back verbatim (`\\?\C:\ProgramData`), a directory symlink's comes back as it was
/// created (`C:\Data`, `\\server\share`), and a symlink may be RELATIVE (`..\sibling`). All the
/// local shapes are accepted, relative ones included — a relative target carries no prefix and so
/// cannot name another machine at all.
pub fn target_is_local(target: &Path) -> bool {
    match target.components().next() {
        Some(Component::Prefix(p)) => matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)),
        // No prefix: rooted on, or relative to, the link's own volume.
        _ => true,
    }
}
