//! Remote directory listing for the file browser (docs/01 §3 "File Manager — browse remote
//! filesystem").
//!
//! [`list_directory`] enumerates a path (or the drive roots for an empty path) into the wire
//! [`DirEntry`] rows the controller renders. It is **read-only**: unlike the actuators
//! ([`crate::reboot`] / [`crate::launch`] / [`crate::command_run`]) it has no side effect, so there
//! is deliberately **no mock gate** — a gate/e2e that sends `ListDirectory` to the real CI agent
//! just gets a harmless listing of a real directory. For the same reason it is honored under
//! view-only (it grants nothing beyond what a viewer can already see on screen), exactly like
//! [`crate::screenshot`].
//!
//! The listing is bounded: at most [`MAX_ENTRIES`] rows come back, with a `truncated` flag when the
//! directory held more — never a silent under-report, and never an unbounded vector marshalled
//! through the control channel. `std::fs` does the reading (portable + unit-testable against a temp
//! directory); only the drive-root enumeration is Windows-specific.
//!
//! **WHICH MACHINE's disk, docs/25 F04.** The paragraph above was written about a *local* file
//! browser and stayed true only because nobody checked what a path could name. `read_dir` follows a
//! UNC path, a mapped network drive and a reparse point off the volume just as happily as it reads
//! `C:\Users`, and this agent runs as LocalSystem on domain-joined machines — so a peer that could
//! ask for `\\attacker\share` was asking this machine to authenticate to the attacker with its
//! MACHINE ACCOUNT, which is the first half of an NTLM relay. Three checks now run before any
//! directory is read, in cheapest-first order and each chosen so that refusing costs no contact with
//! the thing being refused: [`validate_path_shape`] (pure string), [`refuse_remote_drive`] (the local
//! device map), [`refuse_reparse_indirection`] (an ancestor walk that never follows a link).
//!
//! What is deliberately NOT here is a chroot. The operator's decision, and the policy
//! `agent/src/backstage/panels/file.rs` has stated since it was written, is that a support
//! technician's file manager reaches the whole local disk; what makes that safe is the capability
//! grant and the audit record that `host.rs` now applies to this message, not a path jail that would
//! make the tool useless. Every refusal below is about leaving the MACHINE, never about which folder
//! on it.

use std::cmp::Ordering;
#[cfg(test)]
use std::path::Path;


use rmt_agent_core::control::DirEntry;

/// Max entries returned for one directory. A pathological folder (a temp dir with 100k files) is
/// capped to this rather than marshalling an unbounded vector through the control channel and the
/// `select!` loop; any ordinary folder is far under it. 4096 is well beyond what a human browses at
/// once and keeps the `DirectoryListing` message small.
pub const MAX_ENTRIES: usize = 4096;

pub use rmt_agent::backstage::panels::local_path::*;

/// A listed directory: its (sorted, capped) entries and whether the cap truncated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirListing {
    /// The entries, sorted directories-first then case-insensitively by name.
    pub entries: Vec<DirEntry>,
    /// `true` ⇒ the directory held more than the cap; `entries` is a truncated prefix.
    pub truncated: bool,
}

/// List `path`: an empty `path` yields the drive roots; otherwise the directory's files and
/// subdirectories, sorted and capped at [`MAX_ENTRIES`]. An unreadable path (missing, not a
/// directory, denied) is a [`ListError::Io`].
///
/// A path this agent will not reach AT ALL — a UNC or device-namespace path, an extended-length
/// `\?\` path, a mapped network drive, or a link off this machine's disk — is a
/// [`ListError::Refused`] (docs/25 F04). The caller must keep the two apart: `Io` is the filesystem
/// declining and is not worth a record, while `Refused` is this agent declining and is.
pub fn list_directory(path: &str) -> Result<DirListing, ListError> {
    list_directory_capped(path, MAX_ENTRIES)
}

/// [`list_directory`] with an explicit cap, so a test can exercise truncation without creating
/// thousands of files.
fn list_directory_capped(path: &str, cap: usize) -> Result<DirListing, ListError> {
    if path.is_empty() {
        return Ok(DirListing { entries: drive_roots(), truncated: false });
    }
    // docs/25 F04. Everything that decides WHETHER to read runs before the read, cheapest first —
    // a pure string rule, then the local device map, then the reparse walk — and the order is not
    // cosmetic: each step is only safe to run once the ones before it have passed. The reparse walk
    // stats the drive root, which is exactly the call that would authenticate to a mapped network
    // drive, so `refuse_remote_drive` has to have cleared that letter first.
    validate_path_shape(path)?;
    refuse_remote_drive(path)?;
    refuse_reparse_indirection(path)?;
    let (mut entries, truncated) = read_entries(path, cap)?;
    sort_entries(&mut entries);
    Ok(DirListing { entries, truncated })
}

/// Read up to `cap` entries of `path` (in directory order), mapping each to a [`DirEntry`], and
/// report whether there were more (truncation). A single unreadable entry is skipped rather than
/// failing the whole listing; only failing to OPEN the directory is an error.
fn read_entries(path: &str, cap: usize) -> Result<(Vec<DirEntry>, bool), ListError> {
    let rd = std::fs::read_dir(path).map_err(|e| ListError::Io(e.to_string()))?;
    let mut entries = Vec::new();
    let mut truncated = false;
    for item in rd {
        let item = match item {
            Ok(it) => it,
            Err(_) => continue,
        };
        if entries.len() >= cap {
            truncated = true;
            break;
        }
        entries.push(to_dir_entry(&item));
    }
    Ok((entries, truncated))
}

/// Map one `std::fs::DirEntry` to the wire [`DirEntry`]. `file_type()` gives `is_dir` cheaply; size
/// and modified time come from `metadata()`, defaulting to `0` when unavailable (a symlink to a gone
/// target, a denied stat) rather than failing the whole listing.
///
/// **Neither call follows a reparse point, and that was checked rather than assumed** (docs/25 F04
/// asks for reparse points to be accounted for in the listing, not only in the path). `DirEntry`'s
/// `file_type()` and `metadata()` are both documented not to traverse a link — on Windows they are
/// answered from the directory-enumeration record, and Rust's `FileType::is_dir` is false for a
/// symlink or junction — so a junction lists as a non-directory row rather than as the directory it
/// points at. That is pinned by `a_junction_to_a_local_directory_is_still_browsable`, because it is
/// the property `refuse_reparse_indirection` is built on top of: if these ever started following,
/// the listing would silently reach through a link the path check refuses to walk.
fn to_dir_entry(item: &std::fs::DirEntry) -> DirEntry {
    let name = item.file_name().to_string_lossy().into_owned();
    let is_dir = item.file_type().map(|t| t.is_dir()).unwrap_or(false);
    let (size, modified_unix) = match item.metadata() {
        Ok(md) => (
            if md.is_dir() { 0 } else { md.len() },
            md.modified().ok().and_then(unix_seconds).unwrap_or(0),
        ),
        Err(_) => (0, 0),
    };
    DirEntry { name, is_dir, size, modified_unix }
}

/// Whole seconds since the Unix epoch (negative for the rare pre-1970 timestamp), or `None` on an
/// unrepresentable time.
fn unix_seconds(t: std::time::SystemTime) -> Option<i64> {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs() as i64),
        Err(e) => Some(-(e.duration().as_secs() as i64)),
    }
}

/// Sort directories first, then case-insensitively by name (exact name as a stable tie-break, so a
/// listing that differs only in case has a deterministic total order). Pure; unit-tested.
pub fn sort_entries(entries: &mut [DirEntry]) {
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => a
            .name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.name.cmp(&b.name)),
    });
}

/// The drive roots (`C:\`, `D:\`, …) as directory entries, from `GetLogicalDrives`. Each entry's
/// `name` is the full root path, so the controller navigates into it directly.
#[cfg(windows)]
fn drive_roots() -> Vec<DirEntry> {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;
    // SAFETY: no arguments, no memory touched; returns a bitmask DWORD.
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) != 0 {
            let letter = (b'A' + i as u8) as char;
            // docs/25 F04: a mapped network drive is not this machine's disk, and listing one makes
            // this machine authenticate to the share behind it. `list_directory` refuses such a path
            // anyway, so offering the root here would only be an invitation to a click that fails —
            // and an invitation is the wrong thing for the roots list to be making.
            if drive_is_remote(letter) {
                continue;
            }
            out.push(DirEntry {
                name: format!(r"{letter}:\"),
                is_dir: true,
                size: 0,
                modified_unix: 0,
            });
        }
    }
    out
}

/// Non-Windows stub so the crate type-checks off-Windows (it compiles to an empty shell — see the
/// crate docs). The real agent is Windows-only.
#[cfg(not(windows))]
fn drive_roots() -> Vec<DirEntry> {
    vec![DirEntry { name: "/".to_string(), is_dir: true, size: 0, modified_unix: 0 }]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/25 F04, the ALLOW-LIST. Both halves matter and the negative half is the point: a check
    /// that only proved `C:\Windows` passes would pass identically with the whole rule deleted.
    #[cfg(windows)]
    #[test]
    fn path_shape_accepts_only_absolute_local_disk_paths() {
        // Accepted: a drive root, a folder on it, and the empty path — which is not a path at all
        // but the drive-root listing, and must keep working or the browser has no entry point.
        // `C:` is a fixed disk on any box this runs on, so this also pins that the device-map probe
        // is wired and answering (a `drive_is_remote` that always said "remote" would refuse every
        // path, and a shape test alone would never notice).
        assert!(!drive_is_remote('C'), "C: is a local disk on the box running this");
        for ok in ["", r"C:\", r"C:\Windows"] {
            assert!(
                validate_path_shape(ok).is_ok(),
                "{ok:?} is an ordinary local path and must be browsable"
            );
        }

        // Refused, each with the reason it was refused FOR — asserting only "is_err" would let any
        // rejection stand in for the right one, and the UNC case is the finding.
        for (path, want) in [
            (r"\\server\share", "network (UNC)"),
            (r"\\?\UNC\server\share", "network (UNC)"),
            (r"\\?\C:\", "extended-length"),
            (r"\\.\PhysicalDrive0", "device-namespace"),
            (r"relative\path", "absolute local path"),
            (r"C:\Windows\..\Users", ".."),
            (r"C:Windows", "drive-relative"),
        ] {
            let err = match validate_path_shape(path) {
                Ok(()) => panic!("{path:?} must not be browsable"),
                Err(e) => e,
            };
            assert!(
                matches!(err, ListError::Refused(_)),
                "{path:?} must be a policy REFUSAL, not an I/O error: {err:?}"
            );
            assert!(
                err.to_string().contains(want),
                "{path:?} was refused for the wrong reason: {err}"
            );
        }
    }

    /// The reparse-point half of F04, at the only layer that can be tested without a domain: what
    /// `read_link` hands back is classified the same way a typed path is.
    #[cfg(windows)]
    #[test]
    fn link_targets_off_the_machine_are_not_local() {
        // A junction reports its target verbatim, which is why `\\?\C:\…` is LOCAL here while the
        // same spelling is refused as an incoming request: one is what Windows recorded, the other
        // is what a peer chose to send.
        for local in [r"\\?\C:\ProgramData", r"C:\Data", r"..\sibling", r"\rooted"] {
            assert!(target_is_local(Path::new(local)), "{local:?} is on this machine");
        }
        for remote in [r"\\server\share", r"\\?\UNC\server\share", r"\\.\PhysicalDrive0"] {
            assert!(!target_is_local(Path::new(remote)), "{remote:?} is NOT on this machine");
        }
    }

    /// THE F04 REGRESSION. A UNC path must be refused by the string rule — which also means refused
    /// *without contacting the host*, and the elapsed time is what proves that: the old code handed
    /// this straight to `read_dir`, which spends seconds in the SMB redirector resolving a name that
    /// does not exist and only then reports an I/O error. A refusal that arrives in microseconds
    /// cannot have made the connection this finding is about.
    #[cfg(windows)]
    #[test]
    fn a_unc_path_is_refused_without_a_network_round_trip() {
        let started = std::time::Instant::now();
        let err = list_directory(r"\\rmt-f04-no-such-host.invalid\share")
            .expect_err("a UNC path must be refused");
        let elapsed = started.elapsed();
        assert!(
            matches!(err, ListError::Refused(_)),
            "a UNC path must be a policy REFUSAL, not an I/O error: {err:?}"
        );
        assert!(
            err.to_string().contains("network (UNC)"),
            "the refusal must say what it refused: {err}"
        );
        // Generous by three orders of magnitude against a string compare, and still far under any
        // name-resolution attempt: this asserts "no I/O happened", not a performance budget.
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "a UNC refusal took {elapsed:?} — that is long enough to have gone to the network"
        );
    }

    /// THE REPARSE HALF OF F04, on the only construction that actually demonstrates it: a directory
    /// SYMLINK whose target is a UNC share. It passes every string rule — the path handed to the
    /// agent is an ordinary `C:\…` path under the temp directory — and Windows would resolve it onto
    /// SMB in the kernel, authenticating this machine to the far side, which is the escalation the
    /// finding is about.
    ///
    /// The elapsed-time assertion is doing the same work here as in the UNC test: `canonicalize` and
    /// `read_dir` would both have opened the target before they could report anything, so a refusal
    /// that arrives in microseconds is evidence that the walk stopped AT the link rather than
    /// through it. A detection that has already made the connection is not a defence.
    ///
    /// `mklink /D` needs `SeCreateSymbolicLink`, which unelevated accounts hold only with Developer
    /// Mode on. If it is not available this test FAILS rather than quietly passing — a check that
    /// silently declines to run is how an untested guard ships.
    #[cfg(windows)]
    #[test]
    fn a_link_to_a_unc_share_is_refused_without_a_network_round_trip() {
        let base = std::env::temp_dir().join(format!("rmt-dirlist-uncsym-{}", std::process::id()));
        let _ = remove_tree(&base);
        std::fs::create_dir_all(&base).unwrap();
        let link = base.join("share");

        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/D", &link.to_string_lossy(), r"\\rmt-f04-nohost.invalid\share"])
            .output()
            .expect("run mklink");
        assert!(
            out.status.success(),
            "mklink /D failed, so the reparse guard was never exercised — this needs \
             SeCreateSymbolicLink (Developer Mode) on the box running the gate: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        let started = std::time::Instant::now();
        let err = list_directory(&link.to_string_lossy()).expect_err("a link to a share is refused");
        let elapsed = started.elapsed();
        assert!(
            matches!(err, ListError::Refused(_)),
            "a link off the machine must be a policy REFUSAL, not an I/O error: {err:?}"
        );
        assert!(
            err.to_string().contains("not on this machine's local disk"),
            "the refusal must say what it refused: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the refusal took {elapsed:?} — long enough to have followed the link to the network"
        );

        // And a path UNDER the link is refused too: the walk checks ancestors shortest-first, so it
        // stops at `…\share` before ever issuing the call that would traverse it.
        let deep = link.join("subfolder");
        let err = list_directory(&deep.to_string_lossy()).expect_err("under the link too");
        assert!(matches!(err, ListError::Refused(_)), "{err:?}");

        let _ = remove_tree(&base);
    }

    /// Remove a tree that may contain reparse points. `remove_dir_all` follows a directory symlink on
    /// some Windows versions, and a test that deletes what a link POINTS AT rather than the link is a
    /// test that can damage the machine it runs on; `rmdir` on the link itself removes only the link.
    #[cfg(windows)]
    fn remove_tree(base: &std::path::Path) -> std::io::Result<()> {
        if let Ok(rd) = std::fs::read_dir(base) {
            for entry in rd.flatten() {
                let md = entry.path().symlink_metadata()?;
                if md.is_symlink() {
                    std::fs::remove_dir(entry.path()).or_else(|_| std::fs::remove_file(entry.path()))?;
                }
            }
        }
        std::fs::remove_dir_all(base)
    }

    /// The other side of the same rule, and the reason it is not simply "refuse every reparse
    /// point": Windows itself installs junctions inside the profile tree (`C:\Users\All Users`), so
    /// a blanket refusal would break ordinary navigation. A junction whose target is LOCAL is read
    /// through normally — which also proves the walk actually resolves the target rather than
    /// stopping at the reparse attribute.
    #[cfg(windows)]
    #[test]
    fn a_junction_to_a_local_directory_is_still_browsable() {
        let base = std::env::temp_dir().join(format!("rmt-dirlist-junction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("inside.txt"), b"hi").unwrap();
        let link = base.join("link");

        // `mklink /J` needs no privilege (a directory symlink would); it is the reparse point an
        // ordinary user can actually create, so this test runs unelevated on the gate box.
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J", &link.to_string_lossy(), &real.to_string_lossy()])
            .output()
            .expect("run mklink");
        assert!(
            out.status.success(),
            "mklink /J failed, so this test proved nothing: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        let listing = list_directory(&link.to_string_lossy()).expect("a local junction must list");
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["inside.txt"], "the junction's target's contents");

        // The junction row in the PARENT listing is not a directory: `DirEntry::file_type` reports a
        // reparse point as a link, not as the directory it happens to point at. Pinned here because
        // the whole F04 fix depends on this crate never quietly following one.
        let parent = list_directory(&base.to_string_lossy()).expect("list the parent");
        let row = parent.entries.iter().find(|e| e.name == "link").expect("junction row");
        assert!(!row.is_dir, "a junction must not be reported as a plain directory");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sorts_directories_first_then_case_insensitive() {
        let mut v = vec![
            DirEntry { name: "banana.txt".into(), is_dir: false, size: 1, modified_unix: 0 },
            DirEntry { name: "Zebra".into(), is_dir: true, size: 0, modified_unix: 0 },
            DirEntry { name: "apple".into(), is_dir: true, size: 0, modified_unix: 0 },
            DirEntry { name: "Ant.txt".into(), is_dir: false, size: 2, modified_unix: 0 },
        ];
        sort_entries(&mut v);
        let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
        // Directories first (apple, Zebra — case-insensitive), then files (Ant.txt, banana.txt).
        assert_eq!(names, vec!["apple", "Zebra", "Ant.txt", "banana.txt"]);
    }

    #[test]
    fn lists_a_real_directory_with_dir_and_file() {
        let base = std::env::temp_dir().join(format!("rmt-dirlist-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("subdir")).unwrap();
        std::fs::write(base.join("file.txt"), b"hello").unwrap();

        let listing = list_directory(base.to_str().unwrap()).expect("list");
        assert!(!listing.truncated);
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["subdir", "file.txt"], "directory sorts before file");

        let file = listing.entries.iter().find(|e| e.name == "file.txt").unwrap();
        assert!(!file.is_dir);
        assert_eq!(file.size, 5, "\"hello\" is 5 bytes");
        assert!(file.modified_unix > 0, "a real file has a modified time");

        let dir = listing.entries.iter().find(|e| e.name == "subdir").unwrap();
        assert!(dir.is_dir);
        assert_eq!(dir.size, 0, "a directory reports size 0");

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_missing_path_is_an_error_not_an_empty_listing() {
        // A path that does not exist must be an Err (the controller shows "cannot read"), NOT an
        // empty listing that would be indistinguishable from a real empty directory.
        let missing = std::env::temp_dir().join("rmt-dirlist-nope-xyzzy-does-not-exist");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(list_directory(missing.to_str().unwrap()).is_err());
    }

    #[test]
    fn truncates_and_flags_a_directory_over_the_cap() {
        // Five files, cap of 3: exactly 3 come back and `truncated` is set. Proves the cap keeps a
        // bounded prefix AND advertises the truncation (no silent under-report).
        let base = std::env::temp_dir().join(format!("rmt-dirlist-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        for i in 0..5 {
            std::fs::write(base.join(format!("f{i}.txt")), b"x").unwrap();
        }
        let listing = list_directory_capped(base.to_str().unwrap(), 3).expect("list");
        assert_eq!(listing.entries.len(), 3, "capped to 3");
        assert!(listing.truncated, "must flag truncation");

        // The exact-fit case does NOT truncate: cap == count.
        let exact = list_directory_capped(base.to_str().unwrap(), 5).expect("list");
        assert_eq!(exact.entries.len(), 5);
        assert!(!exact.truncated, "cap == count must not flag truncation");

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(windows)]
    #[test]
    fn empty_path_lists_drive_roots() {
        // An empty path lists the drive roots; the CI/box always has at least C:\. Each root is a
        // directory whose name is a full "X:\" path (so the controller navigates into it directly).
        let listing = list_directory("").expect("drive roots");
        assert!(!listing.truncated);
        assert!(!listing.entries.is_empty(), "at least one drive");
        assert!(
            listing.entries.iter().all(|e| e.is_dir && e.name.ends_with(":\\")),
            "every root is a directory named X:\\ : {:?}",
            listing.entries
        );
    }
}
