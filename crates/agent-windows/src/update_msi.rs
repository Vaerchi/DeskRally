//! Windows Installer facts the updater needs (design v3 step 4, v4 version identity, v5 R2/R4):
//! the staged package's identity, the installed products of our UpgradeCode family, whether the
//! installer is executing, and the facts our custom actions leave in the verbose log.
//!
//! Read-only: nothing here changes installer state.

#![cfg(windows)]

use std::io;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    MsiCloseHandle, MsiDatabaseOpenViewW, MsiEnumRelatedProductsW, MsiGetProductInfoW,
    MsiOpenDatabaseW, MsiRecordGetStringW, MsiViewExecute, MsiViewFetch, MSIDBOPEN_READONLY,
    MSIHANDLE,
};

/// The DeskRally agent UpgradeCode (packaging/msi/RmtAgent.wxs). Pinned: a package claiming any
/// other family is not ours to install.
pub const UPGRADE_CODE: &str = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}";

/// Marker prefix our custom actions write into the verbose log (MsiProcessMessage).
pub const LOG_MARKER: &str = "DESKRALLY_GATE:";

struct Handle(MSIHANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                MsiCloseHandle(self.0);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn check(rc: u32, what: &str) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what}: Windows Installer error {rc}")))
    }
}

/// The identity a package claims in its Property table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentity {
    pub product_code: String,
    pub product_version: String,
    pub upgrade_code: String,
}

/// Read ProductCode / ProductVersion / UpgradeCode from a package, read-only.
pub fn package_identity(path: &Path) -> io::Result<PackageIdentity> {
    let p = wide(&path.to_string_lossy());
    let mut db = MSIHANDLE(0);
    check(
        unsafe { MsiOpenDatabaseW(PCWSTR(p.as_ptr()), MSIDBOPEN_READONLY, &mut db) },
        "open package",
    )?;
    let db = Handle(db);
    let prop = |name: &str| -> io::Result<String> {
        let q = wide(&format!(
            "SELECT `Value` FROM `Property` WHERE `Property`='{name}'"
        ));
        let mut view = MSIHANDLE(0);
        check(
            unsafe { MsiDatabaseOpenViewW(db.0, PCWSTR(q.as_ptr()), &mut view) },
            "open view",
        )?;
        let view = Handle(view);
        check(unsafe { MsiViewExecute(view.0, MSIHANDLE(0)) }, "execute view")?;
        let mut rec = MSIHANDLE(0);
        check(unsafe { MsiViewFetch(view.0, &mut rec) }, name)?;
        let rec = Handle(rec);
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        check(
            unsafe { MsiRecordGetStringW(rec.0, 1, PWSTR(buf.as_mut_ptr()), Some(&mut len)) },
            name,
        )?;
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    };
    Ok(PackageIdentity {
        product_code: prop("ProductCode")?,
        product_version: prop("ProductVersion")?,
        upgrade_code: prop("UpgradeCode")?,
    })
}

/// Installed products of the pinned family.
pub fn installed_family() -> io::Result<Vec<String>> {
    let code = wide(UPGRADE_CODE);
    let mut out = Vec::new();
    for i in 0.. {
        let mut buf = [0u16; 39];
        let rc = unsafe {
            MsiEnumRelatedProductsW(PCWSTR(code.as_ptr()), 0, i, PWSTR(buf.as_mut_ptr()))
        };
        match rc {
            0 => out.push(String::from_utf16_lossy(&buf[..38])),
            259 => break, // ERROR_NO_MORE_ITEMS
            rc => return Err(io::Error::other(format!("enumerate products: error {rc}"))),
        }
    }
    Ok(out)
}

/// The installed product's ProductVersion string.
pub fn installed_version(product_code: &str) -> io::Result<String> {
    let code = wide(product_code);
    let attr = wide("VersionString");
    let mut buf = vec![0u16; 64];
    let mut len = buf.len() as u32;
    check(
        unsafe {
            MsiGetProductInfoW(
                PCWSTR(code.as_ptr()),
                PCWSTR(attr.as_ptr()),
                PWSTR(buf.as_mut_ptr()),
                Some(&mut len),
            )
        },
        "product version",
    )?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Windows Installer is executing (or recovering) an installation (design v5 R2): the
/// `Global\_MSIExecute` mutex is held, or the `Installer\InProgress` key exists. Either means
/// "not provably finished", so callers keep the attempt unresolved.
pub fn installer_busy() -> io::Result<bool> {
    use windows::core::w;
    use windows::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
    use windows::Win32::System::Threading::{OpenMutexW, ReleaseMutex, WaitForSingleObject, SYNCHRONIZATION_SYNCHRONIZE};
    let mut key = HKEY::default();
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress"),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if rc.is_ok() {
        unsafe {
            let _ = RegCloseKey(key);
        }
        return Ok(true);
    }
    if rc.0 != 2 {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    // The mutex: absent = not executing. Present = probe with a zero wait; if we obtain it nobody
    // holds it, and we release it immediately.
    // MUTEX_MODIFY_STATE is required for ReleaseMutex: without it a successful probe would keep
    // ownership of the installer's mutex (Codex impl B).
    let access = SYNCHRONIZATION_SYNCHRONIZE | windows::Win32::System::Threading::MUTEX_MODIFY_STATE;
    match unsafe { OpenMutexW(access, false, w!(r"Global\_MSIExecute")) } {
        Err(e) if e.code().0 as u32 == 0x8007_0002 => Ok(false),
        Err(e) => Err(e.into()),
        Ok(m) => {
            let r = unsafe { WaitForSingleObject(m, 0) };
            let busy = if r == WAIT_OBJECT_0 || r == WAIT_ABANDONED {
                if let Err(e) = unsafe { ReleaseMutex(m) } {
                    unsafe {
                        let _ = CloseHandle(m);
                    }
                    return Err(io::Error::other(format!("could not release the installer mutex: {e}")));
                }
                false
            } else {
                // WAIT_TIMEOUT: someone holds it. WAIT_FAILED: unknown, so conservatively busy.
                let _ = r == WAIT_TIMEOUT;
                true
            };
            unsafe {
                let _ = CloseHandle(m);
            }
            Ok(busy)
        }
    }
}

/// What the verbose installer log says about one attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogFacts {
    /// Windows Installer could not restore the previous state (error 1712).
    pub incomplete_rollback: bool,
    /// Our gate custom action found the installed agent_host.exe is not the expected version
    /// (a deferred, in-use replacement).
    pub gate_in_use: bool,
    /// A custom action rejected the package or its parameters (Verification class).
    pub verification_failure: bool,
}

/// Parse a verbose log (UTF-16LE with BOM, or ANSI/UTF-8). Lines are matched only for our own
/// markers bound to `attempt_id` and Windows Installer's incomplete-rollback message.
pub fn log_facts(bytes: &[u8], attempt_id: &str) -> LogFacts {
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    let mut facts = LogFacts::default();
    let in_use = format!("{LOG_MARKER} in_use attempt={attempt_id}");
    let verification = format!("{LOG_MARKER} verification attempt={attempt_id}");
    for line in text.lines() {
        if line.contains("Error 1712.") {
            facts.incomplete_rollback = true;
        }
        if line.contains(&in_use) {
            facts.gate_in_use = true;
        }
        if line.contains(&verification) {
            facts.verification_failure = true;
        }
    }
    facts
}

/// Agent semver core `0.1.N` <-> ProductVersion `1.3.N` (design v4 version identity).
pub fn product_version_for(agent_version: &str) -> Option<String> {
    let core = agent_version.split('+').next()?;
    let mut parts = core.split('.');
    let (maj, min, pat) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || maj != "0" || min != "1" {
        return None;
    }
    let n: u16 = pat.parse().ok()?;
    if n.to_string() != pat {
        return None;
    }
    Some(format!("1.3.{n}"))
}

/// The version an offer must beat: the LOWER of the running agent's version and the version the
/// registered product maps to (1.3.N -> 0.1.N). They differ only after a broken transaction: a
/// power loss mid-install left the candidate binary on disk under the previous registration
/// (acceptance VM, 2026-10-15; Windows Installer does not roll back after power loss). Using the
/// lower one re-offers the same release, so it is reinstalled through the health gate and the
/// machine becomes consistent; a broken candidate cannot produce the fresh registration an
/// attempt requires, so it cannot loop.
pub fn effective_installed_version(running: &str, registered_product_version: &str) -> String {
    let mut f = registered_product_version.split('.');
    let mapped = match (f.next(), f.next(), f.next()) {
        (Some("1"), Some("3"), Some(n)) if n.parse::<u16>().is_ok() => format!("0.1.{n}"),
        _ => return running.to_owned(),
    };
    let core = running.split('+').next().unwrap_or(running);
    match rmt_agent::update::compare_versions(core, &mapped) {
        Ok(std::cmp::Ordering::Greater) => mapped,
        _ => running.to_owned(),
    }
}

/// Compare `a.b.c` ProductVersions numerically on the first three fields.
pub fn product_version_cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let parse = |s: &str| -> Option<[u32; 3]> {
        let mut it = s.split('.');
        let v = [
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
        ];
        Some(v)
    };
    Some(parse(a)?.cmp(&parse(b)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_mapping_is_exact() {
        assert_eq!(product_version_for("0.1.0").as_deref(), Some("1.3.0"));
        assert_eq!(product_version_for("0.1.7+abc123").as_deref(), Some("1.3.7"));
        for bad in ["0.2.0", "1.1.0", "0.1.07", "0.1", "0.1.0.0", "0.1.70000", " 0.1.0"] {
            assert_eq!(product_version_for(bad), None, "{bad}");
        }
        assert_eq!(
            product_version_cmp("1.3.10", "1.3.9"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(product_version_cmp("1.2.7", "1.3.0"), Some(std::cmp::Ordering::Less));
    }

    #[test]
    fn effective_version_is_the_lower_of_binary_and_registration() {
        assert_eq!(effective_installed_version("0.1.91+abc", "1.3.91"), "0.1.91+abc");
        assert_eq!(effective_installed_version("0.1.91+abc", "1.3.90"), "0.1.90", "power-loss mix");
        assert_eq!(effective_installed_version("0.1.90+abc", "1.3.91"), "0.1.90+abc", "binary older");
        assert_eq!(effective_installed_version("0.0.1+4bd1e5c", "1.2.7"), "0.0.1+4bd1e5c", "pre-bootstrap");
        assert_eq!(effective_installed_version("0.1.5", "garbage"), "0.1.5");
    }

    #[test]
    fn log_facts_match_only_this_attempt() {
        let id = "11111111-2222-3333-4444-555555555555";
        let log = format!(
            "MSI (s) x: {LOG_MARKER} in_use attempt={id}\n\
             MSI (s) x: {LOG_MARKER} verification attempt=00000000-0000-0000-0000-000000000000\n"
        );
        let f = log_facts(log.as_bytes(), id);
        assert!(f.gate_in_use && !f.verification_failure && !f.incomplete_rollback);
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                "Product: X -- Error 1712. One or more of the files required to restore"
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes()),
            )
            .collect();
        assert!(log_facts(&utf16, id).incomplete_rollback);
    }

    /// A successful idle probe must leave the mutex acquirable by ANOTHER thread (the installer).
    /// Uses a private mutex name through the same probe logic.
    #[test]
    fn an_idle_probe_releases_what_it_acquired() {
        use windows::core::w;
        use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
        // Create the real-named mutex only if Windows Installer is not using it right now.
        // Fail rather than skip (a skipped check proves nothing): rerun when no install is running.
        assert!(!installer_busy().unwrap(), "Windows Installer is busy; rerun this test when idle");
        let m = unsafe { CreateMutexW(None, false, w!(r"Global\_MSIExecute")) }.unwrap();
        assert!(!installer_busy().unwrap(), "unowned mutex reads idle");
        let raw = m.0 as usize;
        let acquired = std::thread::spawn(move || unsafe {
            let h = windows::Win32::Foundation::HANDLE(raw as *mut _);
            let ok = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
            if ok {
                let _ = ReleaseMutex(h);
            }
            ok
        })
        .join()
        .unwrap();
        unsafe {
            let _ = CloseHandle(m);
        }
        assert!(acquired, "after the probe another thread can take the mutex");
    }

    #[test]
    fn installer_busy_is_answerable() {
        // On a quiet box this is normally false; the point is that both probes work.
        installer_busy().expect("probe works");
    }

    #[test]
    fn family_enumeration_works() {
        let installed = installed_family().expect("enumerate");
        for code in &installed {
            assert!(code.starts_with('{') && code.ends_with('}'), "{code}");
            installed_version(code).expect("version of an installed product");
        }
    }
}
