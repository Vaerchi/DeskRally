//! # rmt-agent-windows
//!
//! Windows platform layer for the remote-desktop agent. It provides the concrete Win32
//! implementations of the platform-abstraction traits declared in [`rmt_agent_core`]:
//!
//! * [`capture::DxgiCapturer`] — a [`ScreenCapturer`] backed by **DXGI Desktop Duplication**
//!   (the primary capture tier in ADR-005), and [`capture_gdi::GdiCapturer`] — the universal
//!   **GDI `BitBlt`** fallback tier that can read the Winlogon secure desktop and RDP sessions
//!   where DDA cannot. The WGC tier is documented inline in [`capture`] and lands next.
//! * [`input::SendInputSink`] — an [`InputSink`] backed by `SendInput`, converting normalized
//!   0..=65535 virtual-desktop coordinates into absolute mouse input.
//! * [`service`] — the LocalSystem service + per-session SYSTEM helper skeleton
//!   (`SERVICE_CONTROL_SESSIONCHANGE`, `WTSGetActiveConsoleSessionId`, desktop following).
//!
//! The whole crate is `#![cfg(windows)]`: on other targets it compiles to nothing so the
//! workspace remains buildable for cross-platform tooling.
//!
//! ## Relationship to `rmt-agent-core`
//!
//! `rmt-agent-core` owns the *portable* trait definitions and value types
//! (`ScreenCapturer`, `InputSink`, `InputEvent`, `MonitorInfo`, `CapturedFrame`). This crate
//! owns everything that touches Win32. The core crate is being authored in parallel; where an
//! exact field or method signature is still in flux it is called out with an
//! `// NOTE(agent-core):` marker so the integration seam is easy to find and reconcile.
#![cfg(windows)]
#![deny(rust_2018_idioms)]

pub mod agent_root;
pub mod anchor;
pub mod fs_manage;
pub(crate) mod backstage_worker;
pub(crate) mod upload_root;
pub(crate) mod upload_writer;
pub(crate) mod input_arbiter;
pub(crate) mod session_directory;
pub mod attend;
pub mod audio;
pub mod audio_report;
pub mod capture;
pub mod capture_gdi;
pub mod capture_loop;
pub mod capture_wgc;
pub(crate) mod dxgi_canvas;
pub(crate) mod dxgi_source;
pub mod canvas_bench;
pub mod clipboard;
pub mod code_prompt;
pub mod command_run;
pub mod config;
pub mod dir_list;
pub mod directive;
pub mod directive_hub;
pub mod directive_pin;
pub mod directive_reinstall;
pub mod directive_removal;
pub mod directive_win;
pub mod enroll;
pub mod following_capturer;
pub mod blank_monitor;
pub(crate) mod help_dialog;
pub mod help_diag;
pub mod help_request;
pub mod guest_window;
pub mod presence_pill;
pub(crate) mod text_typing;
pub mod helper_stop;
pub mod host;
pub mod msi;
pub mod input;
pub mod input_block;
pub mod topology_guard;
pub mod launch;
pub mod lock;
pub mod logging;
pub mod logoff;
pub mod monitor_report;
pub mod panic_hook;
pub mod reboot;
pub mod recording;
pub(crate) mod recording_broker;
pub mod recording_fs;
pub mod recording_upload;
pub mod recording_upload_http;
pub mod recording_upload_sig;
pub mod sas;
pub mod screenshot;
pub mod service;
pub mod session_live;
pub mod shared_capture;
pub mod signaling_mux;
pub mod stdio;
pub mod stub;
pub mod support;
#[cfg(feature = "secure-test")]
pub(crate) mod secure_test_harness;
pub mod tray;
pub(crate) mod tray_menu_provenance;
pub(crate) mod elevated_input;
pub(crate) mod elevated_link;
pub(crate) mod elevation_win;
pub(crate) mod admin_rights;
pub mod update_download;
pub mod update_files;
pub mod update_gate;
pub mod update_guard;
pub mod update_helper;
pub mod update_feed;
pub mod update_msi;
pub mod update_provision;
pub mod update_runner;
pub mod update_state;
pub mod uri;

pub use capture::{CaptureError, DxgiCapturer};
pub use clipboard::WinClipboard;
pub use capture_gdi::{GdiCapturer, GdiError};
pub use capture_wgc::{WgcCapturer, WgcError};
pub use config::HelperConfig;
pub use enroll::{EnrolledIdentity, IdentitySigner};
pub use following_capturer::FollowingCapturer;
pub use input::{InputError, SendInputSink};

/// Marks a process as **PerMonitorV2** DPI-aware.
///
/// This must run *before* any window, capture, or input context is created. Mixed-DPI
/// fractional scaling is the number-one cause of "the remote cursor lands in the wrong
/// place" (ADR-005): if the process is only system-DPI-aware, Windows silently virtualizes
/// coordinates and `MOUSEEVENTF_VIRTUALDESK` math no longer lines up with physical pixels.
///
/// Idempotent and safe to call from every helper process at startup.
pub fn set_process_dpi_awareness() -> Result<(), windows::core::Error> {
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    // SAFETY: no pointers involved; the context handle is a well-known constant. A failure
    // here is non-fatal on older OSes, so callers may choose to log-and-continue.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }
}

mod monitor_canvas;

/// Independent updater scheduler entry.
pub mod update_worker;

pub(crate) mod watched_freeze;
