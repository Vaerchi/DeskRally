//! WebSocket client probe for the shell server. Connects to a RUNNING shell_server, sends a
//! PowerShell command, and reports whether the marker round-trips.
//!
//!   # terminal 1 (server gets its own console):
//!   cargo run --bin shell_server -- --insecure-dev
//!   # terminal 2 — the token is the `t=` value from the URL the server printed:
//!   cargo run --bin ws_probe -- "ws://127.0.0.1:8071/ws?t=<token>"
//!   #   ...or put it in RMT_SHELL_DEMO_TOKEN and pass no arguments at all.
//!
//! The token is required because `/ws` is no longer open to every caller (docs/25 F16).

#[tokio::main]
async fn main() {
    use futures_util::{SinkExt, StreamExt};
    use rmt_agent::transport::shell_ws::{ClientMessage, ServerMessage};
    use tokio_tungstenite::tungstenite::Message;

    let url = match std::env::args().nth(1) {
        // A URL that already carries a token is used as given.
        Some(u) if u.contains("t=") => u,
        // Otherwise fall back to the token in the environment, so the common case is argument-free.
        Some(u) => match std::env::var("RMT_SHELL_DEMO_TOKEN") {
            Ok(t) if !t.is_empty() => format!("{u}{}t={t}", if u.contains('?') { "&" } else { "?" }),
            _ => {
                eprintln!(
                    "no token. `{u}` carries no `t=` and RMT_SHELL_DEMO_TOKEN is unset, so the \
                     server will answer 403 and open no shell (docs/25 F16).\nTake the token from \
                     the URL shell_server printed at startup."
                );
                std::process::exit(2);
            }
        },
        None => match std::env::var("RMT_SHELL_DEMO_TOKEN") {
            Ok(t) if !t.is_empty() => format!("ws://127.0.0.1:8071/ws?t={t}"),
            _ => {
                eprintln!(
                    "no token. Pass the tokenised URL shell_server printed, or set \
                     RMT_SHELL_DEMO_TOKEN (docs/25 F16)."
                );
                std::process::exit(2);
            }
        },
    };
    let marker = "WS_PROBE_OK_31337";

    let (mut ws, _) = match tokio_tungstenite::connect_async(&url).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("connect failed: {e}");
            std::process::exit(2);
        }
    };
    println!("connected to {url}");

    // Send a command after a brief startup delay.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let cmd = format!("Write-Output {marker}\r\n");
    ws.send(Message::Binary(ClientMessage::Input(cmd.into_bytes()).encode()))
        .await
        .unwrap();

    let mut transcript = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut ok = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                if let Ok(ServerMessage::Output(chunk)) = ServerMessage::decode(&bytes) {
                    transcript.extend_from_slice(&chunk);
                    if String::from_utf8_lossy(&transcript).contains(marker) {
                        ok = true;
                        break;
                    }
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }

    println!("marker round-tripped: {ok}");
    println!("transcript ({} bytes): {:?}", transcript.len(), String::from_utf8_lossy(&transcript));
    std::process::exit(if ok { 0 } else { 1 });
}
