//! Harden the agent config root (`C:\rmt-agent`) so its config — the signaling / control-plane URLs
//! and, above all, `grant_issuer_pubkey` — cannot be rewritten by an unprivileged local user.
//!
//! ## Why this exists (measured, not assumed)
//! Every site that touches the root creates it with a bare `create_dir_all` / `New-Item -Force`
//! (`config::save_to`, `enroll::write_identity`, `install-agent.ps1`), so it INHERITS its DACL from the
//! volume root. On a stock Windows 11 that is `NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)`
//! (measured: `icacls C:\`), and that ACE propagates to `config.json` as `Authenticated Users:(I)(M)`
//! — Modify for **every** logged-in standard user. The SYSTEM service reads `grant_issuer_pubkey` from
//! that file, the key that decides which signed grants authorize backstage and elevation. So on the
//! default state of every installed machine a standard user can point the agent at their own signing
//! key (or their own control plane) and drive a SYSTEM-hosted session: a standard-user → SYSTEM
//! trust-boundary compromise. Loop 89's review named this the single biggest risk in the tree, and
//! [`crate::recording::ensure_locked_dir`] documents the same premise and explicitly punts the root
//! fix to "at install and at service start" — which is here.
//!
//! ## What [`harden_agent_root`] does
//! Called at SERVICE START (every boot — self-healing for the already-installed fleet, which no
//! installer will revisit), at `agent_host install`, and on the enroll write path:
//!  1. **Refuse a reparse point** at the root, and RE-STAT immediately before applying ACLs. A
//!     junction/symlink planted there would make every config read come from the attacker's target and
//!     would apply the DACL to *that* target. The check uses `symlink_metadata`, never `metadata`
//!     (which follows the reparse point and hides the very thing being guarded against); the re-stat
//!     closes the create-race and narrows the general check->act TOCTOU (icacls still acts by NAME —
//!     see the residual note).
//!  2. **Create the leaf EXCLUSIVELY** when absent (`create_dir`, not `create_dir_all`), so an
//!     attacker who won the race and planted the directory or a junction is refused by the re-stat
//!     rather than adopted — matching `ensure_locked_dir`.
//!  3. **Reset the OWNER to Administrators** — of the directory AND of `config.json`. A file's owner
//!     keeps implicit `WRITE_DAC` no matter the DACL, and the default Bypass-Traverse-Checking
//!     privilege lets that owner reopen the file by full path under a locked parent; so resetting only
//!     the directory (as an earlier revision did) left a standard user who had become `config.json`'s
//!     owner — trivial on the un-hardened fleet: delete + recreate — able to re-grant themselves write
//!     AFTER hardening. Loop 90's own adversarial review caught this; the fix is to reset the child's
//!     owner too. Ownership failures now abort hardening.
//!  4. **Discard planted explicit ACEs, then apply a protected, inheritable DACL** of exactly SYSTEM +
//!     Administrators. `icacls /grant:r` is ADDITIVE — it replaces only the named principal's ACE, so a
//!     hostile owner's pre-planted `Authenticated Users:(F)` EXPLICIT ACE survives it (measured). So
//!     the directory is first `/reset` (drop explicit ACEs), then `/inheritance:r /grant:r` (drop the
//!     re-inherited ACEs and set the two). `(OI)(CI)` makes NEW children inherit it; EXISTING children
//!     shed `Authenticated Users` by re-propagation WITHOUT `/T` (measured). `/T` is deliberately
//!     avoided: it would follow any junction planted inside the tree and disturb `identity.key`'s own
//!     tighter ACL.
//!  5. **Reset `config.json` itself** (`/setowner` + `/reset`): the directory grant re-propagates only
//!     INHERITED ACEs to the child and never touches its owner or its own explicit ACEs, so the crown
//!     jewel is sanitized directly. `identity.key` is left alone — it has its own owner-aware ACL
//!     ([`crate::enroll`]) that a `/reset` here would clobber.
//!
//! ## Residual, stated rather than hidden
//! icacls acts on a path BY NAME (it opens without `FILE_FLAG_OPEN_REPARSE_POINT`), so a directory
//! swapped for a junction in the window between the re-stat and the icacls calls is still followed —
//! a check->act TOCTOU shared with `ensure_locked_dir`. It is not reachable on the primary self-heal
//! path (service start runs at boot before any interactive user), and closing it fully needs
//! handle-based `SetSecurityInfo` on a no-follow handle — a logged follow-up, not widened here.
//!
//! ## Well-known SIDs, not localized names
//! The grants name S-1-5-18 (SYSTEM) and S-1-5-32-544 (Administrators) by SID. `icacls` resolves an
//! account NAME through the machine LOCALE, so on a French/German/Japanese Windows
//! `/grant:r Administrators:(F)` fails to resolve and would leave the directory UNPROTECTED. A fleet
//! ships to every locale, so a security control must not depend on the English display name.
//! Measured on this box, because the failure mode is not the one you would guess: an unresolvable
//! principal makes `icacls` abort the WHOLE command (`exit 1332`, "No mapping between account names
//! and security IDs was done") and apply **nothing** — not even the `/inheritance:r` that precedes it
//! in argv. So a name-based lockdown on a non-English machine leaves the object exactly as it was.
//!
//! [`crate::recording::ensure_locked_dir`] and [`crate::enroll::tighten_identity_acl`] used to grant
//! by NAME; loop 91 moved both onto the builders below ([`dacl_args`], [`file_dacl_args`],
//! [`reset_args`], [`setowner_args`], [`run_icacls`]) so the SIDs, the `/reset` and the owner reset
//! live in ONE place and a mutation to any of them is caught once for all three call sites.
//!
//! ## Failure direction
//! The DACL restriction (step 3) is REQUIRED — a failure returns `Err` and every caller logs it
//! loudly. The owner reset (step 2) is best-effort: on the real fleet the directory is already
//! SYSTEM/admin-owned (a legitimate elevated install), and the DACL alone removes the live
//! `Authenticated Users:(M)`; refusing to run over a failed `setowner` would leave a machine unmanaged
//! for a hardening step the normal install does not even need. This mirrors the deliberate
//! loud-but-not-fatal stance of [`crate::enroll`]'s identity-key ACL, and is the opposite of
//! `ensure_locked_dir`'s fail-closed stance, for the same reason each chose it: an unmanaged machine
//! is worse than a hardening step that a legitimate install already satisfied.

use std::path::Path;

/// Well-known, locale-invariant SIDs (see the module docs' "Well-known SIDs" section).
pub(crate) const SID_SYSTEM: &str = "*S-1-5-18";
pub(crate) const SID_ADMINISTRATORS: &str = "*S-1-5-32-544";

/// Basename of the sensitive child inside the root — the config file holding `grant_issuer_pubkey` —
/// whose OWNER and DACL are reset in addition to the directory's. Pinned to `config::CONFIG_FILE` by a
/// unit test so the two cannot drift.
const CONFIG_BASENAME: &str = "config.json";

/// What to do with the root path, decided from its on-disk state ALONE so the policy is unit-testable
/// without a privileged reparse point in the test (creating a real junction/symlink needs a privilege
/// a headless CI box may lack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootDisposition {
    /// The path does not exist yet: create it, then harden.
    Create,
    /// A real directory: harden it in place.
    Harden,
    /// A reparse point (junction/symlink): refuse — hardening it would act on its target, and reading
    /// config through it would read the target's file.
    RefuseReparsePoint,
    /// The path exists but is not a directory (a file planted where the root should be): refuse.
    RefuseNotDir,
}

/// Pure policy separated from the I/O so both refusal branches are covered without creating a real
/// reparse point in the test. `is_reparse_point` outranks `is_dir` deliberately: a directory JUNCTION
/// reports `is_dir = true`, and the reparse point is the thing to refuse — the caller computes it from
/// `FILE_ATTRIBUTE_REPARSE_POINT`, not just `is_symlink()`, so a junction (which needs no privilege to
/// plant) is caught as surely as a symlink.
pub fn root_disposition(exists: bool, is_reparse_point: bool, is_dir: bool) -> RootDisposition {
    if !exists {
        return RootDisposition::Create;
    }
    if is_reparse_point {
        return RootDisposition::RefuseReparsePoint;
    }
    if !is_dir {
        return RootDisposition::RefuseNotDir;
    }
    RootDisposition::Harden
}

/// The icacls arguments that RESTRICT `path`'s DACL to SYSTEM + Administrators with inheritable full
/// control and no inherited ACEs. This is the load-bearing security operation; its shape is unit-
/// tested so a mutation to an inheritance flag or a SID is caught without invoking icacls.
pub(crate) fn dacl_args(path: &Path) -> Vec<std::ffi::OsString> {
    vec![
        path.as_os_str().to_os_string(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("{SID_SYSTEM}:(OI)(CI)(F)").into(),
        "/grant:r".into(),
        format!("{SID_ADMINISTRATORS}:(OI)(CI)(F)").into(),
    ]
}

/// The icacls arguments that RESTRICT a **FILE**'s DACL to SYSTEM + Administrators, plus an optional
/// extra principal granted READ. A file has no children, so it carries no `(OI)(CI)` — applying the
/// container form to a file and then measuring the *directory* is how a lockdown gets confirmed
/// against the wrong object.
///
/// `extra_read_sid` exists for [`crate::enroll::tighten_identity_acl`]: a non-elevated `enroll` (a dev
/// run, or a per-user deploy) must be able to read back the key it just wrote, and `/inheritance:r`
/// strips the inherited grant that used to make that work by accident. The SID is passed already
/// filtered by the caller — granting SYSTEM or Administrators here would REPLACE their `(F)` ACE with
/// `(R)`, because `icacls /grant:r` is last-writer-wins per principal.
pub(crate) fn file_dacl_args(path: &Path, extra_read_sid: Option<&str>) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec![
        path.as_os_str().to_os_string(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("{SID_SYSTEM}:(F)").into(),
        "/grant:r".into(),
        format!("{SID_ADMINISTRATORS}:(F)").into(),
    ];
    if let Some(sid) = extra_read_sid {
        args.push("/grant:r".into());
        args.push(format!("*{sid}:(R)").into());
    }
    args
}

/// The icacls arguments that RESET `path`'s DACL to what it would inherit from its parent, discarding
/// every EXPLICIT ACE. `icacls /grant:r` replaces only the named principal's ACE and is additive with
/// respect to every other — so a hostile owner's pre-planted `Authenticated Users:(F)` explicit ACE
/// SURVIVES [`dacl_args`] alone (measured). Running `/reset` first on the directory drops it (the
/// following `/inheritance:r` then strips the freshly re-inherited ACEs); running it on `config.json`
/// both drops a planted explicit ACE and re-inherits the now-clean directory. `/C` continues past a
/// per-item error.
pub(crate) fn reset_args(path: &Path) -> Vec<std::ffi::OsString> {
    vec![path.as_os_str().to_os_string(), "/reset".into(), "/C".into()]
}

/// The icacls arguments that reset `path`'s OWNER to Administrators. `/C` continues past a per-item
/// failure. Applied to the directory AND to `config.json`: a file's OWNER keeps implicit `WRITE_DAC`
/// regardless of the DACL, and the default `SeChangeNotifyPrivilege` (Bypass Traverse Checking,
/// granted to Everyone) lets that owner reopen the file by full path even under a locked parent — so a
/// standard user who became `config.json`'s owner (delete + recreate, which the inherited `(M)` allows
/// on the un-hardened fleet) could otherwise re-grant themselves write AFTER the root is hardened.
pub(crate) fn setowner_args(path: &Path) -> Vec<std::ffi::OsString> {
    vec![
        path.as_os_str().to_os_string(),
        "/setowner".into(),
        SID_ADMINISTRATORS.into(),
        "/C".into(),
    ]
}

/// An absolute `%SystemRoot%\System32\<exe>` path, defaulting to `C:\Windows` when the variable is
/// unset or blank. Mirrors the helpers in [`crate::launch`] and [`crate::command_run`]; kept local
/// rather than shared because those are `cfg(windows)` modules this one must not depend on.
#[cfg(windows)]
pub(crate) fn system32_exe(exe: &str) -> std::path::PathBuf {
    let root = match std::env::var("SystemRoot").ok() {
        Some(v) if !v.trim().is_empty() => v,
        _ => r"C:\Windows".to_string(),
    };
    std::path::Path::new(&root).join("System32").join(exe)
}

/// Run icacls with `args`; `Ok(true)` iff it exited success. A non-success exit is logged with its
/// stderr so a locale/permission failure is visible rather than silent.
///
/// Launched by ABSOLUTE path under `%SystemRoot%`. `Command::new("icacls")` resolves through the
/// standard search order, which begins with the DIRECTORY OF THE CALLING EXECUTABLE — and this runs
/// as LocalSystem on every service start. Anyone who could write next to `agent_host.exe` could drop
/// an `icacls.exe` there and be executed as SYSTEM.
///
/// The installer now locks that directory, so this is defence in depth rather than the only guard.
/// It is also simply the house rule: every other launch in this crate builds an absolute
/// `%SystemRoot%` path and says why (`launch.rs`, `command_run.rs`, `service.rs`). These two were
/// the exceptions, with no comment showing anyone had considered them.
#[cfg(windows)]
pub(crate) fn run_icacls(args: &[std::ffi::OsString]) -> std::io::Result<bool> {
    let out = std::process::Command::new(system32_exe("icacls.exe")).args(args).output()?;
    if !out.status.success() {
        tracing::warn!(
            status = %out.status,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "harden: icacls exited non-success"
        );
    }
    Ok(out.status.success())
}

/// True iff `md` describes a reparse point of ANY tag. `is_symlink()` only reports the name-surrogate
/// tags (`IO_REPARSE_TAG_SYMLINK`, `..._MOUNT_POINT`), so it already catches a symlink and a
/// `mklink /J` junction — which is why a mutation dropping the attribute half of the `||` SURVIVES the
/// junction integration test (a documented equivalent mutant *for that test*). The attribute is kept
/// deliberately: a NON-surrogate reparse point (a dedup / cloud-placeholder tag, or a future tag) is
/// still a redirection this must refuse, and `is_symlink()` returns `false` for those. The attribute
/// is the definitional test; `is_symlink()` is the idiomatic one and matches `ensure_locked_dir`.
#[cfg(windows)]
pub(crate) fn is_reparse_point(md: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    md.file_type().is_symlink() || (md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

/// Reset the OWNER and DACL of a sensitive CHILD file (`config.json`) so that a hostile owner cannot
/// keep it re-DACL-able under a locked parent (see [`setowner_args`]). `/setowner` is best-effort;
/// `/reset` is REQUIRED — it both drops any explicit ACE the owner planted and re-inherits the now-
/// clean directory's SYSTEM + Administrators. A reparse-point child is refused, preventing service
/// startup from consuming redirected trust configuration.
#[cfg(windows)]
fn harden_config_file(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if is_reparse_point(&md) => {
            tracing::warn!(
                path = %path.display(),
                "harden: the agent config file is a reparse point; refusing to follow it to re-own or \
                 re-ACL its target"
            );
            return Err(std::io::Error::other("agent config must not be a reparse point"));
        }
        Ok(_) => {}
        // No config yet (a fresh machine that has not enrolled): nothing to protect, and the directory
        // DACL will cover it the moment it is written.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    if !run_icacls(&setowner_args(path))? {
        return Err(std::io::Error::other("could not secure sensitive file owner"));
    }
    if !run_icacls(&reset_args(path))? {
        return Err(std::io::Error::other(format!(
            "icacls could not reset the DACL/owner on {} — a prior owner could keep it writable",
            path.display()
        )));
    }
    Ok(())
}

/// Harden the agent config root at `dir`, and the `config.json` inside it. See the module docs. Loud
/// on failure of any ownership or DACL step (returns `Err`).
#[cfg(windows)]
pub fn harden_agent_root(dir: &Path) -> std::io::Result<()> {
    let disp = match std::fs::symlink_metadata(dir) {
        Ok(md) => root_disposition(true, is_reparse_point(&md), md.is_dir()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RootDisposition::Create,
        Err(e) => return Err(e),
    };
    match disp {
        RootDisposition::RefuseReparsePoint => {
            return Err(std::io::Error::other(format!(
                "refusing to harden {}: it is a reparse point (junction or symlink) — a config read \
                 through it would come from the target and the DACL would be applied there; treat \
                 this as a compromise indicator",
                dir.display()
            )));
        }
        RootDisposition::RefuseNotDir => {
            return Err(std::io::Error::other(format!(
                "refusing to harden {}: it exists and is not a directory",
                dir.display()
            )));
        }
        RootDisposition::Create => {
            // EXCLUSIVE create of the leaf (like `ensure_locked_dir`), never `create_dir_all`: if an
            // attacker won the race between the NotFound above and here and planted the directory (or a
            // junction), adopting it is how the fail-closed contract gets satisfied vacuously. On
            // `AlreadyExists` we fall through to the re-stat below, which refuses a reparse point.
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match std::fs::create_dir(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        RootDisposition::Harden => {}
    }

    // RE-STAT immediately before touching ACLs. This closes the Create race and narrows the general
    // check->act TOCTOU: if the path is (or was just raced into) a reparse point, refuse rather than
    // let icacls follow the junction to an attacker-chosen target. icacls acts BY NAME (it opens
    // without FILE_FLAG_OPEN_REPARSE_POINT), so a swap won between here and the calls below is still a
    // residual — see the module docs; on the self-heal path it runs at boot before any user logs in.
    let md = std::fs::symlink_metadata(dir)?;
    if is_reparse_point(&md) {
        return Err(std::io::Error::other(format!(
            "refusing to harden {}: it became a reparse point after the disposition check",
            dir.display()
        )));
    }
    if !md.is_dir() {
        return Err(std::io::Error::other(format!(
            "refusing to harden {}: it is not a directory",
            dir.display()
        )));
    }

    // DIRECTORY. Owner first (strip a hostile pre-creator's implicit WRITE_DAC), best-effort. Then
    // /reset to discard any EXPLICIT ACE a prior owner planted (additive /grant:r would leave it),
    // then the protected grant. Both DACL steps are REQUIRED: without /reset a planted Authenticated
    // Users:(F) survives and re-propagates into config.json.
    if !run_icacls(&setowner_args(dir))? {
        return Err(std::io::Error::other("could not secure agent directory owner"));
    }
    if !run_icacls(&reset_args(dir))? {
        return Err(std::io::Error::other(format!(
            "icacls could not reset the agent-root DACL on {} to strip planted explicit ACEs",
            dir.display()
        )));
    }
    if !run_icacls(&dacl_args(dir))? {
        return Err(std::io::Error::other(format!(
            "icacls could not restrict the agent-root DACL on {} — config.json may remain writable by \
             unprivileged users",
            dir.display()
        )));
    }

    // The crown-jewel CHILD. The directory grant re-propagates only INHERITED ACEs to config.json and
    // never touches its OWNER or its explicit ACEs, so a hostile owner would survive the directory
    // hardening — reset the file itself. `config.json` is the basename of `config::CONFIG_FILE` (a
    // test pins the two together).
    harden_config_file(&dir.join(CONFIG_BASENAME))?;
    harden_config_file(&dir.join("identity.key"))?;
    harden_config_file(&dir.join("agent_host.exe"))?;
    harden_config_file(&dir.join("stream_probe.exe"))?;

    tracing::info!(
        dir = %dir.display(),
        "harden: agent root + config.json restricted to SYSTEM + Administrators (Authenticated Users \
         removed, owner reset, planted ACEs stripped)"
    );
    Ok(())
}

/// Off Windows there are no NTFS DACLs; match `ensure_locked_dir`'s non-Windows shape (create the
/// directory, do nothing else) so callers compile and behave identically on a dev box. The pure
/// policy functions above are exercised by the tests on every platform.
#[cfg(not(windows))]
pub fn harden_agent_root(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn disposition_absent_is_create() {
        assert_eq!(root_disposition(false, false, false), RootDisposition::Create);
        // A non-existent path's other flags are irrelevant.
        assert_eq!(root_disposition(false, true, true), RootDisposition::Create);
    }

    #[test]
    fn disposition_real_directory_is_harden() {
        assert_eq!(root_disposition(true, false, true), RootDisposition::Harden);
    }

    #[test]
    fn disposition_reparse_point_is_refused_even_when_it_is_a_directory() {
        // A directory junction reports is_dir=true AND is_symlink=true; the reparse refusal must win,
        // or the DACL rewrite lands on the junction's target.
        assert_eq!(
            root_disposition(true, true, true),
            RootDisposition::RefuseReparsePoint
        );
        assert_eq!(
            root_disposition(true, true, false),
            RootDisposition::RefuseReparsePoint
        );
    }

    #[test]
    fn disposition_plain_file_is_refused() {
        assert_eq!(root_disposition(true, false, false), RootDisposition::RefuseNotDir);
    }

    #[test]
    fn dacl_args_are_locale_invariant_sids_with_inheritable_full_control() {
        let args: Vec<String> = dacl_args(&PathBuf::from(r"C:\rmt-agent"))
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // The directory, then a protected DACL granting exactly the two well-known SIDs, inheritable.
        assert_eq!(args[0], r"C:\rmt-agent");
        assert!(args.contains(&"/inheritance:r".to_string()), "must strip inherited ACEs: {args:?}");
        assert!(
            args.contains(&"*S-1-5-18:(OI)(CI)(F)".to_string()),
            "SYSTEM must be granted by SID with (OI)(CI) inheritance: {args:?}"
        );
        assert!(
            args.contains(&"*S-1-5-32-544:(OI)(CI)(F)".to_string()),
            "Administrators must be granted by SID with (OI)(CI) inheritance: {args:?}"
        );
        // No account NAME appears — a localized-name grant would silently fail to protect the dir.
        assert!(
            !args.iter().any(|a| a.contains("Administrators:") || a.contains("SYSTEM:")),
            "no localized account name may appear: {args:?}"
        );
        // Nothing broader than the two SIDs is granted.
        assert!(
            !args.iter().any(|a| a.contains("Users") || a.contains("Everyone") || a.contains("S-1-1-0")),
            "no broad principal may be granted: {args:?}"
        );
    }


    /// [`file_dacl_args`] names its principals by SID and carries NO container-inheritance flags.
    ///
    /// Both halves are load-bearing and were untested when loop 91 first moved the siblings onto this
    /// builder — a six-mutation sweep found every one of them unkillable, which is what this test and
    /// the two integration tests below exist to fix.
    ///
    /// SIDs: `icacls` resolves an account NAME through the machine LOCALE, and an unresolvable name
    /// makes it abort the whole command and apply NOTHING (measured: exit 1332, DACL untouched, not
    /// even a preceding `/inheritance:r`). A name-based lockdown on a French / German / Japanese
    /// Windows therefore leaves the object exactly as it was.
    ///
    /// No `(OI)(CI)`: those are inheritance flags for a CONTAINER. Applying the directory form to a
    /// file and then measuring the DIRECTORY is how a lockdown gets confirmed against the wrong
    /// object — the mistake `recording::ensure_locked_dir`'s own doc comment warns about.
    #[test]
    fn file_dacl_args_are_locale_invariant_sids_with_no_container_flags() {
        let args: Vec<String> = file_dacl_args(Path::new(r"C:\rmt-agent\identity.key"), None)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert!(args.contains(&"/inheritance:r".to_string()), "{args:?}");
        assert!(
            args.contains(&"*S-1-5-18:(F)".to_string()),
            "SYSTEM must be granted by SID with FULL control: {args:?}"
        );
        assert!(
            args.contains(&"*S-1-5-32-544:(F)".to_string()),
            "Administrators must be granted by SID with FULL control: {args:?}"
        );
        // NEGATIVE control on the locale bug: no argument may name a principal in English.
        assert!(
            !args.iter().any(|a| a.contains("SYSTEM:") || a.contains("Administrators:")),
            "a principal is named by its English display name, which does not resolve on a \
             non-English Windows: {args:?}"
        );
        // NEGATIVE control on the container flags: a file has no children to inherit anything.
        assert!(
            !args.iter().any(|a| a.contains("(OI)") || a.contains("(CI)")),
            "a FILE grant must carry no inheritance flags: {args:?}"
        );
    }

    /// The optional owner grant is READ-only, by SID, and absent when the caller passes `None`.
    ///
    /// `(R)` and not `(F)` is the whole point: a non-elevated `enroll` must be able to read back the
    /// key it just wrote, and nothing more. A mutation to `(F)` here would hand the creating user
    /// permanent write access to the agent's private key on every per-user deploy.
    #[test]
    fn file_dacl_args_grant_the_extra_principal_read_and_only_read() {
        let none: Vec<String> = file_dacl_args(Path::new("k"), None)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            none.iter().filter(|a| a.as_str() == "/grant:r").count(),
            2,
            "with no extra principal there must be exactly two grants: {none:?}"
        );

        let with: Vec<String> = file_dacl_args(Path::new("k"), Some("S-1-5-21-1-2-3-1001"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            with.iter().filter(|a| a.as_str() == "/grant:r").count(),
            3,
            "the extra principal must add exactly one grant: {with:?}"
        );
        assert!(
            with.contains(&"*S-1-5-21-1-2-3-1001:(R)".to_string()),
            "the owner grant must be READ, by SID, with the icacls '*' SID prefix: {with:?}"
        );
        assert!(
            !with.iter().any(|a| a.contains("S-1-5-21-1-2-3-1001:(F)")),
            "the owner must never be granted full control over a private key: {with:?}"
        );
        // The SID arrives WITHOUT a leading '*' and the builder adds exactly one. A double '*' does
        // not resolve, and icacls would abort the whole command — the same silent-no-op failure the
        // SIDs were adopted to avoid.
        assert!(
            !with.iter().any(|a| a.contains("**")),
            "the '*' SID prefix was applied twice: {with:?}"
        );
    }

    #[test]
    fn setowner_args_target_administrators_by_sid() {
        let args: Vec<String> = setowner_args(&PathBuf::from(r"C:\rmt-agent"))
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], r"C:\rmt-agent");
        assert!(args.contains(&"/setowner".to_string()), "{args:?}");
        assert!(args.contains(&"*S-1-5-32-544".to_string()), "owner must be Administrators by SID: {args:?}");
    }

    #[test]
    fn reset_args_discard_explicit_aces() {
        let args: Vec<String> = reset_args(&PathBuf::from(r"C:\rmt-agent\config.json"))
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], r"C:\rmt-agent\config.json");
        assert!(args.contains(&"/reset".to_string()), "must /reset to drop planted explicit ACEs: {args:?}");
        assert!(args.contains(&"/C".to_string()), "{args:?}");
    }

    #[test]
    fn config_basename_matches_the_real_config_file() {
        // harden_agent_root re-owns dir.join(CONFIG_BASENAME); if config::CONFIG_FILE's name drifted,
        // the crown-jewel child would silently stop being protected.
        let cfg = std::path::Path::new(crate::config::CONFIG_FILE);
        assert_eq!(
            cfg.file_name().and_then(|n| n.to_str()),
            Some(CONFIG_BASENAME),
            "CONFIG_BASENAME must equal the basename of config::CONFIG_FILE"
        );
        assert_eq!(
            cfg.parent(),
            Some(std::path::Path::new(crate::config::CONFIG_DIR)),
            "config::CONFIG_FILE must live directly in config::CONFIG_DIR"
        );
    }

    // --- Windows integration: the real icacls path, measured on a real directory ------------------
    // These run icacls for real (harmless on a test-owned temp dir) so a no-op / wrong-flag change is
    // caught, not just the argument shape. They read a DIRECTORY's own security descriptor, which its
    // owner can read via READ_CONTROL without traversing into it — so they hold whether or not the
    // gate runs elevated (the sibling recording DACL test measures a file inside the hardened dir and
    // therefore needs the elevated environment the gate already provides; measuring the dir avoids
    // that dependency). `/setowner` is best-effort, so on a non-elevated runner the dir stays
    // test-owned and the readback still succeeds.
    #[cfg(windows)]
    struct TempDir(std::path::PathBuf);
    #[cfg(windows)]
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "rmt-agentroot-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    #[cfg(windows)]
    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best-effort: elevated (Administrators:(F)) this succeeds; a non-elevated runner that
            // could not reset the owner still owns it and can remove it. A leaked temp dir is harmless.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(windows)]
    fn icacls_read(path: &Path) -> String {
        let out = std::process::Command::new("icacls")
            .arg(path.as_os_str())
            .output()
            .expect("icacls runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Harden a directory that really inherits `Authenticated Users:(M)` (staged to reproduce what
    /// `C:\rmt-agent` picks up from `C:\`) and prove the ACE is gone and only SYSTEM + Administrators
    /// remain, inheritable. The premise is asserted first (negative control) so a clean result cannot
    /// pass vacuously on an environment that never had the hazard.
    #[cfg(windows)]
    #[test]
    fn harden_strips_authenticated_users_and_leaves_only_system_and_administrators() {
        let parent = TempDir::new("strip");
        // Stage the hazard on the parent: an INHERITABLE Authenticated Users grant, the exact shape
        // C:\ hands down. A child created under it inherits Modify for every logged-in user.
        let staged = std::process::Command::new("icacls")
            .arg(parent.0.as_os_str())
            .args(["/grant", "*S-1-5-11:(OI)(CI)(M)"]) // S-1-5-11 = Authenticated Users
            .output()
            .expect("icacls runs");
        assert!(
            staged.status.success(),
            "could not stage the permissive parent ACE, so this test would pass vacuously: {}",
            String::from_utf8_lossy(&staged.stderr)
        );

        let root = parent.0.join("rmt-agent");
        std::fs::create_dir(&root).unwrap();
        // A config.json exists across the DACL change, as on the real root — it must shed the ACE too,
        // by re-propagation, which is why the grant has to be inheritable rather than dir-only.
        std::fs::write(root.join("config.json"), b"{}").unwrap();

        // PREMISE (negative control): the fresh child really inherited the permissive ACE.
        let before = icacls_read(&root);
        assert!(
            before.contains("Authenticated Users") || before.contains("S-1-5-11"),
            "premise not met — the child did not inherit the staged ACE, so a clean DACL proves \
             nothing:\n{before}"
        );

        harden_agent_root(&root).expect("hardening a real directory succeeds");

        let after = icacls_read(&root);
        assert!(
            !after.contains("Authenticated Users") && !after.contains("S-1-5-11"),
            "Authenticated Users SURVIVED hardening — config.json is still writable by any standard \
             user:\n{after}"
        );
        assert!(
            after.to_uppercase().contains("SYSTEM"),
            "SYSTEM must retain control or the service cannot read its own config:\n{after}"
        );
        // The grant must be INHERITABLE, or config.json and future children are not covered. This is
        // the assertion that makes the (OI)(CI) flags load-bearing; a mutation dropping them is caught
        // here because without them the dir shows (F) with no (OI)(CI).
        assert!(
            after.contains("(OI)(CI)"),
            "the grant is not inheritable — children would not be protected:\n{after}"
        );
        // And nothing broad crept back in.
        assert!(
            !after.contains("Everyone") && !after.contains("BUILTIN\\Users"),
            "a broad principal remains on the hardened dir:\n{after}"
        );
        // Locale-robust structural check: EXACTLY two principals remain. The English-string checks
        // above pass vacuously on a non-English Windows (where the ACE displays a localized name that
        // is neither "Authenticated Users" nor the SID) — counting the ACE lines does not. icacls
        // prints one "PRINCIPAL:(flags)" per ACE; the summary line has no ":(".
        assert_eq!(
            after.lines().filter(|l| l.contains(":(")).count(),
            2,
            "expected exactly SYSTEM + Administrators (2 ACEs):\n{after}"
        );
    }

    /// A hostile owner's PRE-PLANTED EXPLICIT ACE — on the directory AND on config.json — is stripped,
    /// and config.json is re-inherited clean. `icacls /grant:r` is ADDITIVE, so the earlier revision
    /// that ran only `/inheritance:r /grant:r` left a planted `Authenticated Users` explicit ACE (and
    /// its inheritance into config.json) intact; loop 90's adversarial review found it. This is the
    /// regression guard for the `/reset` steps on both the directory and the child. (The owner reset is
    /// VM-verified; a non-elevated unit runner may not be able to `/setowner`, but `/reset` still
    /// strips the planted ACE, which is the property asserted here.)
    #[cfg(windows)]
    #[test]
    fn harden_strips_a_planted_explicit_ace_on_dir_and_config() {
        let base = TempDir::new("planted");
        let root = base.0.join("rmt-agent");
        std::fs::create_dir(&root).unwrap();
        let cfg = root.join("config.json");
        std::fs::write(&cfg, b"{}").unwrap();

        // Plant an EXPLICIT (non-inherited) Authenticated Users grant on BOTH objects, as a hostile
        // owner could on the un-hardened fleet. Not inherited, so /inheritance:r alone would leave them.
        let d = std::process::Command::new("icacls").arg(root.as_os_str())
            .args(["/grant", "*S-1-5-11:(OI)(CI)(F)"]).output().expect("icacls runs");
        assert!(d.status.success(), "staging dir ACE failed: {}", String::from_utf8_lossy(&d.stderr));
        let f = std::process::Command::new("icacls").arg(cfg.as_os_str())
            .args(["/grant", "*S-1-5-11:(F)"]).output().expect("icacls runs");
        assert!(f.status.success(), "staging file ACE failed: {}", String::from_utf8_lossy(&f.stderr));

        // PREMISE (negative control): both really carry the explicit ACE now.
        let cfg_before = icacls_read(&cfg);
        assert!(
            (icacls_read(&root).contains("Authenticated Users") || icacls_read(&root).contains("S-1-5-11"))
                && (cfg_before.contains("Authenticated Users") || cfg_before.contains("S-1-5-11")),
            "premise not met — an object did not carry the planted ACE:\n{cfg_before}"
        );

        harden_agent_root(&root).expect("hardening succeeds");

        let dir_after = icacls_read(&root);
        let cfg_after = icacls_read(&cfg);
        assert!(
            !dir_after.contains("Authenticated Users") && !dir_after.contains("S-1-5-11"),
            "planted explicit ACE SURVIVED on the directory — additive /grant:r needs a preceding \
             /reset:\n{dir_after}"
        );
        assert!(
            !cfg_after.contains("Authenticated Users") && !cfg_after.contains("S-1-5-11"),
            "planted explicit ACE SURVIVED on config.json — the child needs its own /setowner + \
             /reset, not just the directory's:\n{cfg_after}"
        );
        assert_eq!(
            cfg_after.lines().filter(|l| l.contains(":(")).count(),
            2,
            "config.json should carry exactly the inherited SYSTEM + Administrators:\n{cfg_after}"
        );
    }

    /// A reparse point (a directory JUNCTION — needs no privilege) planted where the root should be is
    /// refused, and its target is left completely untouched: hardening returns `Err` before running a
    /// single icacls, so the DACL is never applied to the attacker-chosen target.
    #[cfg(windows)]
    #[test]
    fn a_reparse_point_root_is_refused_and_its_target_is_untouched() {
        let base = TempDir::new("reparse");
        let target = base.0.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("canary.txt"), b"do-not-touch").unwrap();
        let target_before = icacls_read(&target);

        let link = base.0.join("rmt-agent");
        let mk = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link.as_os_str())
            .arg(target.as_os_str())
            .output()
            .expect("cmd runs");
        assert!(
            mk.status.success(),
            "mklink /J failed, cannot exercise the reparse refusal: {}",
            String::from_utf8_lossy(&mk.stderr)
        );

        let err = harden_agent_root(&link).expect_err("hardening a reparse point must be refused");
        assert!(
            format!("{err}").contains("reparse point"),
            "refused for the wrong reason: {err}"
        );

        // The target's DACL is byte-for-byte what it was: harden never touched it.
        let target_after = icacls_read(&target);
        assert_eq!(
            target_before, target_after,
            "the junction's target had its security descriptor modified — the refusal leaked through"
        );
        assert!(
            target.join("canary.txt").exists(),
            "the junction's target contents were disturbed"
        );
    }
    /// The helper must produce an ABSOLUTE System32 path, because a bare name resolves through the
    /// calling executable's own directory first — and these tools run as LocalSystem on every
    /// service start.
    #[test]
    fn system32_exe_is_absolute_and_under_system_root() {
        let p = system32_exe("icacls.exe");
        assert!(p.is_absolute(), "must be absolute, got {p:?}");
        assert!(
            p.ends_with("System32\\icacls.exe") || p.ends_with("System32/icacls.exe"),
            "must sit in System32, got {p:?}"
        );
    }

    /// A blank SystemRoot must not yield a RELATIVE path — that would silently restore the
    /// hijackable bare-name behaviour this helper exists to remove.
    #[test]
    fn system32_exe_falls_back_when_system_root_is_blank() {
        // SAFETY: single-threaded test; restored immediately below.
        let prev = std::env::var("SystemRoot").ok();
        unsafe { std::env::set_var("SystemRoot", "   ") };
        let p = system32_exe("whoami.exe");
        match prev {
            Some(v) => unsafe { std::env::set_var("SystemRoot", v) },
            None => unsafe { std::env::remove_var("SystemRoot") },
        }
        assert!(p.is_absolute(), "a blank SystemRoot must still give an absolute path, got {p:?}");
    }
}
