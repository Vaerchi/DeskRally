//! Registry read/write. Reached only through the dispatcher, which has already applied the
//! `RegistryRead`/`RegistryWrite` capability and — for writes under sensitive persistence keys
//! (Services, Run, Winlogon, …) — the typed-confirmation guard rail.
//!
//! Scope for this scaffold: string (`REG_SZ`) values, the overwhelmingly common case for the
//! settings a technician edits. DWORD/binary/multi-string support is a follow-up that slots in
//! the same way. The write path reads and returns the prior value so the dispatcher can record
//! a before/after pair in the audit log.

use super::OpError;

/// Split `HKLM\Sub\Key` into the hive token and the subkey path. Accepts both short (`HKLM`)
/// and long (`HKEY_LOCAL_MACHINE`) hive names, case-insensitively.
pub fn split_path(full: &str) -> Option<(&'static str, String)> {
    if full.chars().any(char::is_control) { return None; }
    let (hive_raw, sub) = full.split_once('\\').unwrap_or((full, ""));
    let hive = match hive_raw.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM",
        "HKCU" | "HKEY_CURRENT_USER" => "HKCU",
        "HKCR" | "HKEY_CLASSES_ROOT" => "HKCR",
        "HKU" | "HKEY_USERS" => "HKU",
        "HKCC" | "HKEY_CURRENT_CONFIG" => "HKCC",
        _ => return None,
    };
    // Refuse ambiguous separator spellings instead of guessing Win32 normalization.
    if !sub.is_empty() && sub.split('\\').any(str::is_empty) { return None; }
    Some((hive, sub.to_string()))
}

/// Read a `REG_SZ` value. `Ok(None)` means the key/value doesn't exist (not an error — the
/// caller uses this to record "no prior value" in the audit before a write).
#[cfg(windows)]
pub fn read_string(path: &str, value_name: &str) -> Result<Option<String>, OpError> {
    use std::io::ErrorKind;

    let (_hive, sub) = split_path(path).ok_or_else(|| OpError::Other(format!("unknown hive in {path:?}")))?;
    let root = predef(path)?;
    match root.open_subkey(&sub) {
        Ok(key) => match key.get_value::<String, _>(value_name) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(map_io(e, path)),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(map_io(e, path)),
    }
}

/// Write a `REG_SZ` value, creating the subkey if needed. Returns the prior value (if any) so
/// the dispatcher can audit before→after.
#[cfg(windows)]
pub fn write_string(path: &str, value_name: &str, data: &str) -> Result<Option<String>, OpError> {
    let (_hive, sub) = split_path(path).ok_or_else(|| OpError::Other(format!("unknown hive in {path:?}")))?;
    let before = read_string(path, value_name)?;

    let root = predef(path)?;
    let (key, _disp) = root.create_subkey(&sub).map_err(|e| map_io(e, path))?;
    key.set_value(value_name, &data.to_string()).map_err(|e| map_io(e, path))?;
    Ok(before)
}

#[cfg(windows)]
fn predef(path: &str) -> Result<winreg::RegKey, OpError> {
    use winreg::enums::*;
    let (hive, _sub) = split_path(path).ok_or_else(|| OpError::Other(format!("unknown hive in {path:?}")))?;
    let h = match hive {
        "HKLM" => HKEY_LOCAL_MACHINE,
        "HKCU" => HKEY_CURRENT_USER,
        "HKCR" => HKEY_CLASSES_ROOT,
        "HKU" => HKEY_USERS,
        "HKCC" => HKEY_CURRENT_CONFIG,
        _ => return Err(OpError::Other(format!("unknown hive in {path:?}"))),
    };
    Ok(winreg::RegKey::predef(h))
}

#[cfg(windows)]
fn map_io(e: std::io::Error, path: &str) -> OpError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::PermissionDenied => OpError::AccessDenied(path.to_string()),
        ErrorKind::NotFound => OpError::NotFound(path.to_string()),
        _ => OpError::Other(format!("{path}: {e}")),
    }
}

#[cfg(not(windows))]
pub fn read_string(_path: &str, _value_name: &str) -> Result<Option<String>, OpError> {
    Err(OpError::Unsupported)
}

#[cfg(not(windows))]
pub fn write_string(_path: &str, _value_name: &str, _data: &str) -> Result<Option<String>, OpError> {
    Err(OpError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_short_and_long_hive_names() {
        assert_eq!(split_path(r"HKLM\SYSTEM\Foo"), Some(("HKLM", "SYSTEM\\Foo".to_string())));
        assert_eq!(
            split_path(r"HKEY_CURRENT_USER\Software\Acme"),
            Some(("HKCU", "Software\\Acme".to_string()))
        );
        assert_eq!(split_path(r"BOGUS\Path"), None);
    }

    // Round-trips through the real registry under a private HKCU test key, then cleans up.
    // HKCU is writable without elevation, so this runs in a normal test context.
    #[cfg(windows)]
    #[test]
    fn writes_reads_and_reports_prior_value_under_hkcu() {
        let key_path = format!(r"HKCU\Software\RmtAgentTest\{}", std::process::id());
        let name = "Marker";

        // First write: no prior value.
        let before = write_string(&key_path, name, "first").expect("write ok");
        assert_eq!(before, None, "no prior value on a fresh key");
        assert_eq!(read_string(&key_path, name).unwrap().as_deref(), Some("first"));

        // Second write: prior value reported for the before/after audit.
        let before2 = write_string(&key_path, name, "second").expect("overwrite ok");
        assert_eq!(before2.as_deref(), Some("first"));
        assert_eq!(read_string(&key_path, name).unwrap().as_deref(), Some("second"));

        // Reading an absent value is Ok(None), not an error.
        assert_eq!(read_string(&key_path, "DoesNotExist").unwrap(), None);

        // Clean up the whole test subtree.
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(format!(r"Software\RmtAgentTest\{}", std::process::id()));
    }
}
