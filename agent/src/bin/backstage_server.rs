//! Demo backstage API server. Serves the request/response backstage channel over loopback HTTP
//! so the panels/ops can be driven from a browser or `curl`. Every request runs through the
//! real [`Dispatcher`] choke point; this binary just issues itself a demo grant and holds one
//! dispatcher (one audit chain) for the session.
//!
//!   cargo run --bin backstage_server -- --insecure-dev   # prints this run's token
//!   curl -s -H "Authorization: Bearer <token>" 127.0.0.1:8072/backstage/exec -d '{"type":"GetSystemInfo"}'
//!
//! Production replaces the demo grant with the relay-issued signed grant and carries these
//! frames over the backstage channel of the real transport instead of a loopback port.
//!
//! DEMO-GRADE, AND GATED (docs/25 F16). This is `shell_server`'s sibling and had the identical
//! hole: it served `FileBrowse` and `RegistryRead` to ANY caller that could reach the loopback
//! port, with no token and no `Origin` check. Loopback is not an authorization boundary. It now
//! requires a per-run token, checks `Host`/`Origin`, and refuses to start without
//! `--insecure-dev` (or `RMT_BACKSTAGE_DEMO_INSECURE_DEV=1`). It is never shipped: the packaging
//! guard asserts no binary from `agent/src/bin` reaches a release artifact.

use std::sync::{Arc, Mutex};

use rmt_agent::backstage::rbac::{Capability, Grant};
use rmt_agent::backstage::Dispatcher;
use rmt_agent::transport::backstage_api::http::{demo_router, BackstageState};
use rmt_agent::transport::shell_authz::DemoAuthz;

#[tokio::main]
async fn main() {
    // Startup is EXPLICIT: this process reads the filesystem and registry for whoever holds the
    // token, so running it must be a decision rather than the result of typing a binary's name.
    let declared = std::env::args().any(|a| a == "--insecure-dev")
        || matches!(
            std::env::var("RMT_BACKSTAGE_DEMO_INSECURE_DEV").as_deref(),
            Ok("1") | Ok("true") | Ok("yes") | Ok("on")
        );
    if !declared {
        eprintln!(
            "refusing to start.\n\n\
             backstage_server is an INSECURE DEVELOPMENT DEMO: it grants file-browse and\n\
             registry-read over a loopback port to whoever presents this run's token. It is\n\
             not a product feature and is never shipped in a release artifact.\n\n\
             If that is what you want, say so:\n\
             \n    cargo run --bin backstage_server -- --insecure-dev\n\
             \nor set RMT_BACKSTAGE_DEMO_INSECURE_DEV=1."
        );
        std::process::exit(2);
    }
    // A generous read-only demo grant plus registry read; the mutating capabilities are left
    // out of the default demo on purpose.
    let grant = Grant {
        technician_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::new_v4(),
        capabilities: vec![
            Capability::ProcessList,
            Capability::ServiceList,
            Capability::SystemInfoRead,
            Capability::EventLogRead,
            Capability::FileBrowse,
            Capability::RegistryRead,
        ],
    };
    let state = BackstageState { dispatcher: Arc::new(Mutex::new(Dispatcher::new(grant, "rmt-agent.exe"))) };

    let port: u16 = 8072;
    let authz = DemoAuthz::for_loopback(port);
    let token = authz.token().to_string();

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind backstage port");
    println!("backstage API (INSECURE DEV) on http://{addr}  — POST /backstage/exec");
    println!("this run's token (dies with the process):");
    println!("    curl -s -H \"Authorization: Bearer {token}\" {addr}/backstage/exec -d '{{\"type\":\"GetSystemInfo\"}}'");
    axum::serve(listener, demo_router(state, authz)).await.expect("serve");
}
