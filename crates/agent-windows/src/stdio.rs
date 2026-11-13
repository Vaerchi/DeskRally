//! Working standard handles for a GUI-subsystem process (docs/27 step 8).
//!
//! `DeskRallySupport.exe` is compiled `#![windows_subsystem = "windows"]` so double-clicking it in
//! Explorer does not flash a console. The cost: a GUI-subsystem process launched from Explorer has
//! **no standard handles** — `GetStdHandle` returns an invalid handle for stdout and stderr. Rust's
//! `println!`/`eprintln!` write to those handles and **panic on a write error**, and the attended
//! code path this binary reuses (`host::run_attend_after_redeem`) is full of `println!`. Without
//! this the process would die at the first print — which happens right around redeem, so it would
//! look exactly like a redeem failure.
//!
//! [`ensure_stdio_sinks`] binds the `NUL` device to any invalid standard handle, so those writes
//! succeed and go nowhere. It is idempotent and leaves an already-valid handle (e.g. when run from a
//! console for debugging) untouched, so real output still appears there.

/// Bind `NUL` to any invalid standard handle. Call once, first thing in `main`, before any print.
#[cfg(windows)]
pub fn ensure_stdio_sinks() {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let nul = wide(r"\\.\NUL");
    // SAFETY: each call takes a well-known constant or a NUL-terminated wide string kept alive for
    // the call; the handle from CreateFileW is handed to SetStdHandle and thereafter owned by the
    // process's std-handle table. A failure on any handle is non-fatal — we simply leave it.
    unsafe {
        for (which, read) in [
            (STD_INPUT_HANDLE, true),
            (STD_OUTPUT_HANDLE, false),
            (STD_ERROR_HANDLE, false),
        ] {
            // Leave a usable handle alone: a console run keeps its real stdout/stderr.
            if let Ok(existing) = GetStdHandle(which) {
                if !existing.is_invalid() {
                    continue;
                }
            }
            let access = if read { GENERIC_READ.0 } else { GENERIC_WRITE.0 };
            if let Ok(h) = CreateFileW(
                PCWSTR(nul.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            ) {
                let _ = SetStdHandle(which, h);
            }
        }
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

    /// Under `cargo test` there IS a console, so all three standard handles are already valid and
    /// [`super::ensure_stdio_sinks`] must be a no-op: it must not swap a working stdout for NUL and
    /// swallow real output. Calling it twice must also leave the handles unchanged (idempotent).
    #[test]
    fn leaves_valid_handles_alone_and_is_idempotent() {
        // SAFETY: GetStdHandle is read-only.
        let before_out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let before_err = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        super::ensure_stdio_sinks();
        super::ensure_stdio_sinks();
        let after_out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let after_err = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        assert_eq!(
            before_out.ok().map(|h| h.0),
            after_out.ok().map(|h| h.0),
            "a valid stdout was replaced — real output would be swallowed to NUL"
        );
        assert_eq!(before_err.ok().map(|h| h.0), after_err.ok().map(|h| h.0));
    }
}
