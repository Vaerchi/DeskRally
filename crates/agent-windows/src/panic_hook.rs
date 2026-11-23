//! A panic hook that reaches the customer instead of vanishing (docs/27 step 8).
//!
//! On a GUI-subsystem process a panic is otherwise a silent death: no console to print the message
//! to, and a panic on a worker thread (the guest window pump, the capture loop) would just make that
//! thread disappear while `main` waited forever. This hook:
//!
//! * logs the payload and source location through `tracing::error!` into the support log;
//! * shows a "the support client stopped" dialog naming the per-run directory (which is KEPT, not
//!   swept, so a technician can inspect it) — the copy comes from the shared
//!   [`rmt_agent_core::support_ui`] table;
//! * exits with a distinct, non-zero code so a caller/script can tell a crash from a normal decline.
//!
//! Install it on `main` AND on every non-main entry point (guest window, capture thread), so a panic
//! anywhere is surfaced rather than swallowed.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Exit code after the panic hook fires. Distinct from the flow's own `0` (done / declined),
/// `1` (session failed), and `2` (bad argv), so a wrapper can tell a crash apart from those.
pub const PANIC_EXIT_CODE: i32 = 70;

/// The per-run directory named in the dialog and kept for inspection. Set once by
/// [`install`] before the hook can fire.
static RUN_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Install the process-wide panic hook, remembering `run_dir` to name in the dialog.
///
/// Idempotent-enough: a second call replaces the hook with an equivalent one and re-seeds nothing
/// (the `OnceLock` keeps the first directory), which is fine — support_main calls it exactly once.
pub fn install(run_dir: PathBuf) {
    let _ = RUN_DIR.set(run_dir);
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = payload_str(info.payload());
        tracing::error!(location = %loc, payload = %payload, "support client PANICKED — stopping");

        let (title, body) = stopped_message(RUN_DIR.get().map(PathBuf::as_path));
        #[cfg(windows)]
        show_stopped_dialog(&title, &body);
        #[cfg(not(windows))]
        {
            let _ = (title, body);
        }

        // The per-run directory is deliberately NOT deleted here: docs/27 keeps it so a technician
        // can review a crash. The exit code is distinct so that is observable to a caller.
        std::process::exit(PANIC_EXIT_CODE);
    }));
}

/// Extract a human string from a panic payload (`&str` or `String`, else a placeholder).
fn payload_str(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "(non-string panic payload)".to_string()
    }
}

/// Build the dialog (title, body) for an unexpected stop, naming the kept directory.
///
/// Pure so it is testable: the body must come from the shared failure table AND must name the
/// directory, because "tell your technician; send them the folder named below" is useless without
/// the folder.
fn stopped_message(run_dir: Option<&Path>) -> (String, String) {
    let m = rmt_agent_core::support_ui::message(&rmt_agent_core::support_ui::Failure::StoppedUnexpectedly);
    let mut body = m.body;
    if let Some(detail) = m.detail {
        body.push_str("\n\n");
        body.push_str(&detail);
    }
    if let Some(dir) = run_dir {
        body.push_str("\n\nFolder: ");
        body.push_str(&dir.display().to_string());
    }
    (m.title, body)
}

#[cfg(windows)]
fn show_stopped_dialog(title: &str, body: &str) {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let text = HSTRING::from(body);
    let caption = HSTRING::from(title);
    // SAFETY: owned HSTRING buffers; a NULL owner window is fine for a standalone process-exit
    // dialog. The return value is ignored — this is best-effort on the way out.
    unsafe {
        let _ = MessageBoxW(None, &text, &caption, MB_OK | MB_ICONERROR);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_extracts_str_and_string() {
        let s: &str = "boom";
        assert_eq!(payload_str(&s), "boom");
        let owned: String = "kaboom".to_string();
        assert_eq!(payload_str(&owned), "kaboom");
        let other: i32 = 5;
        assert_eq!(payload_str(&other), "(non-string panic payload)");
    }

    #[test]
    fn the_stopped_dialog_names_the_kept_directory() {
        let dir = PathBuf::from(r"C:\Users\me\AppData\Local\Temp\deskrally\session-abc");
        let (title, body) = stopped_message(Some(dir.as_path()));
        assert!(!title.trim().is_empty());
        assert!(
            body.contains(r"session-abc"),
            "the kept folder must be named so the customer can send it: {body:?}"
        );
        // The copy still comes from the shared table (so the "nothing is installed" wording holds).
        assert!(body.to_lowercase().contains("nothing is installed"), "{body:?}");
    }

    #[test]
    fn the_stopped_dialog_tolerates_a_missing_directory() {
        let (_t, body) = stopped_message(None);
        assert!(!body.trim().is_empty());
        assert!(!body.contains("Folder:"), "no folder line when there is no directory");
    }

    #[test]
    fn the_panic_exit_code_is_distinct_from_the_flows_own_codes() {
        for used in [0, 1, 2] {
            assert_ne!(PANIC_EXIT_CODE, used, "must not collide with the flow's exit codes");
        }
    }
}
