//! `DeskRallySupport.exe` — the public first-contact support client (docs/27, docs/28).
//!
//! A thin, cross-platform-safe shim; all logic is in `rmt_agent_windows::support::support_main`
//! (the crate compiles to nothing off Windows, so the Windows call is cfg-gated).
//!
//! `windows_subsystem = "windows"` makes it a GUI-subsystem binary: double-clicking it from
//! Explorer flashes no console. That is exactly why `support_main` binds NUL to the missing standard
//! handles first (`crate::stdio`) — otherwise the first `println!` would panic.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    {
        let tail: Vec<String> = std::env::args().skip(1).collect();
        std::process::exit(rmt_agent_windows::support::support_main(&tail));
    }
    #[cfg(not(windows))]
    {
        eprintln!("DeskRallySupport is a Windows-only binary");
        std::process::exit(1);
    }
}
