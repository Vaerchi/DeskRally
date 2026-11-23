//! Axum HTTP + WebSocket server that bridges a browser terminal to a live ConPTY shell.
//! Lives in the library so both the `shell_server` binary and the end-to-end test share it.
//!
//! Per connection: open one PowerShell, split into reader/writer/control halves, and run
//! blocking pipe I/O on std threads while the async side moves opaque frames. Wire format is
//! [`super::shell_ws`].
//!
//! Demo-grade: binds to loopback and issues itself a demo grant. It still routes the shell
//! through the real [`Dispatcher`] choke point (capability check → guard rail → confirmation →
//! spawn → audit); production swaps the demo grant for the relay-issued signed grant and
//! launches the child under a token from `crate::backstage::token`.

#![cfg(windows)]

use std::sync::mpsc as std_mpsc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc as tokio_mpsc;

use crate::backstage::rbac::{Capability, Grant};
use crate::backstage::{Confirmation, Dispatcher, RunAsRequest, ShellKind};
use crate::transport::shell_authz::DemoAuthz;
use crate::transport::shell_ws::{ClientMessage, ServerMessage};

/// Wall-clock milliseconds for audit timestamps. The library core takes an injected clock for
/// testability; this is the demo server's real-clock adapter at the edge.
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A stand-in for the relay-issued signed grant. Demo-only: grants exactly the capability the
/// demo terminal exercises (an interactive shell in the current user's context). Production
/// receives this from the relay after authenticating the technician.
fn demo_grant() -> Grant {
    Grant {
        technician_id: uuid::Uuid::nil(),
        session_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::nil(),
        capabilities: vec![Capability::ShellAsUser],
    }
}

/// Build the router: the terminal page, the vendored xterm assets, and the shell WebSocket.
///
/// Takes the run's [`DemoAuthz`] because `/ws` is no longer open (docs/25 F16): the policy is the
/// router's state, so there is no way to mount the socket without one.
pub fn router(authz: DemoAuthz) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/vendor/xterm.js", get(xterm_js))
        .route("/vendor/xterm.css", get(xterm_css))
        .route("/vendor/xterm-addon-fit.js", get(xterm_fit_js))
        .route("/ws", get(ws_upgrade))
        .with_state(authz)
}

async fn index() -> impl IntoResponse {
    Html(include_str!("../../assets/terminal.html"))
}
async fn xterm_js() -> impl IntoResponse {
    ([("content-type", "application/javascript")], include_str!("../../assets/vendor/xterm.js"))
}
async fn xterm_css() -> impl IntoResponse {
    ([("content-type", "text/css")], include_str!("../../assets/vendor/xterm.css"))
}
async fn xterm_fit_js() -> impl IntoResponse {
    ([("content-type", "application/javascript")], include_str!("../../assets/vendor/xterm-addon-fit.js"))
}

/// THE GATE. Every refusal here happens BEFORE `on_upgrade`, so an unauthorized caller never
/// reaches `handle_socket` and no ConPTY is ever opened for it (docs/25 F16).
///
/// The token travels as a query parameter rather than a header because a browser's `WebSocket`
/// constructor cannot set request headers — there is no way for the terminal page to send a bearer
/// token. It is therefore in the URL the operator opens, and the page forwards it. That does mean
/// the token can land in a shell history or a browser's autocomplete, which is why it is minted
/// fresh per run and dies with the process.
async fn ws_upgrade(
    State(authz): State<DemoAuthz>,
    Query(params): Query<WsParams>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let header = |name: HeaderName| -> Option<String> {
        headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
    };
    let host = header(header::HOST);
    let origin = header(header::ORIGIN);

    if let Err(refusal) = authz.authorize(params.t.as_deref(), host.as_deref(), origin.as_deref()) {
        // Logged without the presented token or origin: a refusal must not write a secret — or an
        // attacker-chosen string — into the operator's console.
        eprintln!("shell demo: REFUSED a /ws upgrade — {refusal}");
        return (StatusCode::FORBIDDEN, "forbidden\n").into_response();
    }
    ws.on_upgrade(handle_socket).into_response()
}

/// `/ws?t=<token>`. Absent `t` is `None`, which [`DemoAuthz::authorize`] refuses.
#[derive(serde::Deserialize)]
struct WsParams {
    t: Option<String>,
}

/// One browser terminal = one PowerShell session, gated by the dispatcher.
pub async fn handle_socket(socket: WebSocket) {
    // Route the shell through the enforced choke point instead of spawning it directly, then
    // split it into the three `unsafe impl Send` halves the async tasks can hold. This whole
    // step is confined to a block: the `Dispatcher`, the `Result`, and the `!Send`
    // `ShellSession` all drop at the block's end, so nothing non-`Send` survives across the
    // `await` points below (axum requires the connection future to be `Send`).
    let opened = {
        let mut dispatcher = Dispatcher::new(demo_grant(), "rmt-agent.exe");
        let (open_event, result) = dispatcher.open_shell(
            ShellKind::PowerShell,
            RunAsRequest::LoggedInUser,
            120,
            30,
            Confirmation::NotProvided,
            now_ms(),
        );
        // Production forwards this to the relay for per-tenant persistence; the demo logs it so
        // the enforced path is observable.
        eprintln!("audit: {}", serde_json::to_string(&open_event).unwrap_or_default());

        match result {
            Ok(a) => match a.session.split() {
                Ok(halves) => Some((a.shell_id, halves)),
                Err(e) => {
                    eprintln!("failed to split shell {}: {e}", a.shell_id);
                    None
                }
            },
            Err(e) => {
                eprintln!("shell open refused by dispatcher: {e}");
                None
            }
        }
    };
    let (shell_id, (mut reader, mut writer, mut control)) = match opened {
        Some(v) => v,
        None => return,
    };
    let _ = shell_id; // ties the transcript to the ShellOpen audit event; unused in the demo pumps

    let (out_tx, mut out_rx) = tokio_mpsc::unbounded_channel::<ServerMessage>();
    let (cmd_tx, cmd_rx) = std_mpsc::channel::<ClientMessage>();

    // Output pump: blocking reads until EOF (child exited / pty closed).
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.send(ServerMessage::Output(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = out_tx.send(ServerMessage::Exit { code: None });
    });

    // Input pump: owns writer + control; drains commands until the channel closes.
    std::thread::spawn(move || {
        while let Ok(msg) = cmd_rx.recv() {
            match msg {
                ClientMessage::Input(bytes) => {
                    let _ = writer.write(&bytes);
                }
                ClientMessage::Resize { cols, rows } => {
                    let _ = control.resize(cols, rows);
                }
                ClientMessage::Close => break,
            }
        }
        // Dropping `control` closes the pseudoconsole -> reader hits EOF -> output pump ends.
    });

    let (mut sink, mut stream) = socket.split();

    let to_browser = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if sink.send(Message::Binary(msg.encode())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    while let Some(Ok(frame)) = stream.next().await {
        match frame {
            Message::Binary(bytes) => {
                if let Ok(cmd) = ClientMessage::decode(&bytes) {
                    let close = matches!(cmd, ClientMessage::Close);
                    if cmd_tx.send(cmd).is_err() || close {
                        break;
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    drop(cmd_tx);
    let _ = to_browser.await;
}
