//! Token acquisition and impersonation for launching backstage processes.
//!
//! The agent runs as a LocalSystem Windows service. Backstage processes (shells, tool
//! launches) run under a **selectable identity** — see `docs/04-backstage.md` §"Privilege
//! model". This module produces a primary token suitable for `CreateProcessAsUser`, plus the
//! environment block that must accompany it.
//!
//! Safety: this is `unsafe` FFI against the `windows` crate. Handles are wrapped in RAII
//! guards so they close on drop even on the error paths. Passwords are held in a `Zeroizing`
//! buffer and wiped after `LogonUser`.
//!
//! This is a Windows-only sketch; it is `cfg(windows)`-gated and compiled/tested on Windows.

#![cfg(windows)]

use zeroize::Zeroizing;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{
    WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};

/// Which identity a backstage process should run as. Mirrors [`crate::backstage::audit::RunAs`].
#[derive(Debug, Clone)]
pub enum Identity {
    /// Inherit the service's LocalSystem token. Deep maintenance; no profile/network identity.
    System,
    /// The user currently logged into the active console session.
    LoggedInUser,
    /// Explicit credentials. The password is zeroized immediately after logon.
    Credential {
        username: String,
        domain: String,
        password: Zeroizing<String>,
    },
}

/// An owned Windows `HANDLE` that is closed on drop. Prevents the classic long-running-service
/// handle leak when spawning shells per request.
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// A ready-to-use primary token plus its matching environment block. Pass both to
/// `CreateProcessAsUser` (the env block avoids the child inheriting SYSTEM's environment —
/// wrong TEMP/APPDATA/PATH otherwise).
pub struct LaunchToken {
    pub token: OwnedHandle,
    /// Pointer to the environment block from `CreateEnvironmentBlock`. Freed on drop.
    pub environment: EnvironmentBlock,
}

pub struct EnvironmentBlock(pub *mut core::ffi::c_void);

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("no user is logged into the active console session")]
    NoInteractiveUser,
    #[error("windows API {api} failed: {source}")]
    Api { api: &'static str, source: windows::core::Error },
}

/// Resolve the requested [`Identity`] to a primary token + environment block.
///
/// For `System` the caller can pass its own process token; here we obtain the interactive
/// user's token for the other cases. `Credential` is intentionally stubbed at the
/// `LogonUser` call site with a clear TODO — it's the most dangerous path and deserves its
/// own review before wiring (see `docs/04-backstage.md` security section).
pub fn acquire(identity: &Identity) -> Result<LaunchToken, TokenError> {
    match identity {
        Identity::System => {
            // The service already holds a LocalSystem token; duplicate the current process
            // token to a primary token the child can use.
            // Left as a focused follow-up: OpenProcessToken(GetCurrentProcess()) + DuplicateTokenEx.
            unimplemented!("duplicate current process (LocalSystem) token — see acquire() docs")
        }
        Identity::LoggedInUser => acquire_logged_in_user(),
        Identity::Credential { .. } => {
            // TODO(security-review): LogonUserW(LOGON32_LOGON_BATCH) -> DuplicateTokenEx.
            // Gate behind Capability::ShellAsCredential + typed confirmation + CredentialUse
            // audit event. Zeroize the password buffer immediately after LogonUserW returns.
            unimplemented!("supplied-credential logon — deliberately unimplemented pending review")
        }
    }
}

/// The `WTSQueryUserToken` + `DuplicateTokenEx` + `CreateEnvironmentBlock` sequence for the
/// logged-in console user. This is the well-trodden "run as the interactive user from a
/// service" path.
fn acquire_logged_in_user() -> Result<LaunchToken, TokenError> {
    unsafe {
        // 1. Which session owns the physical console? 0xFFFFFFFF means "none right now"
        //    (e.g. mid fast-user-switch) — caller should retry. For RDP targets, enumerate
        //    sessions with WTSEnumerateSessions and pick the WTSActive one instead.
        let session_id = WTSGetActiveConsoleSessionId();
        if session_id == 0xFFFF_FFFF {
            return Err(TokenError::NoInteractiveUser);
        }

        // 2. Primary token for the interactive user. Requires SeTcbPrivilege (LocalSystem has it).
        let mut user_token = HANDLE::default();
        WTSQueryUserToken(session_id, &mut user_token)
            .map_err(|e| TokenError::Api { api: "WTSQueryUserToken", source: e })?;
        let user_token = OwnedHandle(user_token);

        // 3. Duplicate to a clean primary token we own.
        let mut dup = HANDLE::default();
        DuplicateTokenEx(
            user_token.0,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        )
        .map_err(|e| TokenError::Api { api: "DuplicateTokenEx", source: e })?;
        let dup = OwnedHandle(dup);

        // 4. Build the environment block FROM THE TARGET TOKEN. Without this the child gets
        //    SYSTEM's environment. `false` = don't inherit the service's environment.
        let mut env: *mut core::ffi::c_void = core::ptr::null_mut();
        CreateEnvironmentBlock(&mut env, dup.0, false)
            .map_err(|e| TokenError::Api { api: "CreateEnvironmentBlock", source: e })?;

        // For an already-logged-on user the profile/HKCU is already loaded, so we skip
        // LoadUserProfile. Add it only for the logged-off / offline-hive cases.

        Ok(LaunchToken { token: dup, environment: EnvironmentBlock(env) })
    }
}

// Silence unused-import warnings in the stubbed paths without hiding them from a real build.
#[allow(unused_imports)]
use windows::Win32::Foundation as _foundation_used;
#[allow(dead_code)]
fn _keep_pwstr_hlocal(_p: PWSTR, _h: HLOCAL) {}
