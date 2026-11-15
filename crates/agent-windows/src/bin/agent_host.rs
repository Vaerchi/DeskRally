//! Entry point for the Windows agent host / per-session helper. All real logic lives in
//! `rmt_agent_windows::host`; this is a thin, cross-platform-safe shim (the crate compiles to
//! nothing off Windows, so the Windows call is cfg-gated).

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(rmt_agent_windows::host::host_main());
    }
    #[cfg(not(windows))]
    {
        eprintln!("rmt-agent-windows host is Windows-only");
        std::process::exit(1);
    }
}
