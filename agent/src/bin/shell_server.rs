//! Backstage shell server — bridges a live Windows PowerShell (over ConPTY) to a browser
//! terminal (xterm.js) over WebSocket. The first end-to-end demoable milestone.
//!
//!   cargo run --bin shell_server -- --insecure-dev
//!   # then open the URL it prints — it carries this run's token
//!
//! The bridge lives in `rmt_agent::transport::shell_server` so the end-to-end test shares it, and
//! the authorization decision in `rmt_agent::transport::shell_authz` so it is testable without a
//! ConPTY.
//!
//! DEMO-GRADE, AND IT NOW SAYS SO OUT LOUD (docs/25 F16). It binds loopback, issues itself a demo
//! grant, and runs the shell as the current user. It used to accept EVERY connection that reached
//! `/ws` — no token, no `Origin` check — which handed a PowerShell to any process on the machine,
//! and potentially to a web page, since loopback is not an authorization boundary. It now requires
//! a per-run token and checks `Host`/`Origin`, and it refuses to start without `--insecure-dev`
//! (or `RMT_SHELL_DEMO_INSECURE_DEV=1`) so nobody launches it believing it is a product feature.
//!
//! It is NOT shipped: `scripts/build-release.ps1` stages `agent_host.exe` and `stream_probe.exe`
//! only, and a packaging guard asserts this binary never appears in an artifact.

#[cfg(not(windows))]
fn main() {
    eprintln!("shell_server is Windows-only (ConPTY).");
}

#[cfg(windows)]
#[tokio::main]
async fn main() {
    use rmt_agent::transport::shell_authz::DemoAuthz;

    // Startup is EXPLICIT. This process hands out interactive shells, so running it must be a
    // decision somebody made on purpose rather than the result of typing a binary's name.
    let declared = std::env::args().any(|a| a == "--insecure-dev")
        || matches!(
            std::env::var("RMT_SHELL_DEMO_INSECURE_DEV").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
    if !declared {
        eprintln!(
            "refusing to start.\n\n\
             shell_server is an INSECURE DEVELOPMENT DEMO: it opens a real PowerShell in your own\n\
             user context for whoever connects with this run's token. It is not a product feature\n\
             and is never shipped in a release artifact.\n\n\
             If that is what you want, say so:\n\
             \n    cargo run --bin shell_server -- --insecure-dev\n\
             \nor set RMT_SHELL_DEMO_INSECURE_DEV=1."
        );
        std::process::exit(2);
    }

    let port: u16 = 8071;
    let authz = DemoAuthz::for_loopback(port);
    let token = authz.token().to_string();

    let app = rmt_agent::transport::shell_server::router(authz);
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");

    // The token is in the URL because a browser's WebSocket constructor cannot set headers, so the
    // page has no other way to present one. Fresh every run: a captured URL is dead once this
    // process exits.
    println!("backstage shell demo (INSECURE DEV) — open this exact URL, it carries the token:");
    println!("    http://{addr}/?t={token}");
    println!("this run's token dies with the process. Ctrl+C to stop.");
    axum::serve(listener, app).await.expect("serve");
}
