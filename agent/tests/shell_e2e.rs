//! End-to-end proof of the backstage shell: start the real axum+ConPTY server, connect a
//! WebSocket client (no browser), drive a live PowerShell, and assert the output round-trips
//! through ConPTY -> wire codec -> WebSocket.
//!
//! This is the whole pipeline the browser terminal uses, exercised headlessly.

#![cfg(windows)]

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use rmt_agent::transport::shell_ws::{ClientMessage, ServerMessage};

// `#[ignore]` by design: this starts the server IN-PROCESS under `cargo test`, which is
// console-less, so the ConPTY child can't attach (see the note in
// `backstage::shell::tests::conpty_interactive_roundtrip`). The same path IS verified
// out-of-band by running the `shell_server` binary as its own process and the `ws_probe`
// binary against it — see `docs/05-backstage-implementation.md`.
#[tokio::test]
#[ignore = "ConPTY child needs a real host console; verified via shell_server + ws_probe (see docs/05)"]
async fn powershell_command_round_trips_through_the_socket() {
    // 1. Start the real server on an ephemeral loopback port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // `/ws` requires this run's token and a loopback Host (docs/25 F16), so the test builds the
    // policy for the port it actually bound and presents the token it minted.
    let authz = rmt_agent::transport::shell_authz::DemoAuthz::with_token(addr.port(), "e2e-token");
    let token = authz.token().to_string();
    let app = rmt_agent::transport::shell_server::router(authz);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 2. Connect a WebSocket client to the shell endpoint.
    let url = format!("ws://{addr}/ws?t={token}");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect to shell ws");

    // 3. Drive PowerShell: print a unique marker, then exit so the stream reaches EOF.
    let marker = "e2e_marker_8675309";
    let cmd = format!("Write-Output {marker}; exit\r\n");
    ws.send(Message::Binary(ClientMessage::Input(cmd.into_bytes()).encode()))
        .await
        .unwrap();

    // 4. Collect output frames until we see the marker or the shell exits.
    let mut transcript = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut saw_marker = false;

    while tokio::time::Instant::now() < deadline {
        let next = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next()).await;
        let msg = match next {
            Ok(Some(Ok(m))) => m,
            _ => break,
        };
        if let Message::Binary(bytes) = msg {
            match ServerMessage::decode(&bytes) {
                Ok(ServerMessage::Output(chunk)) => {
                    transcript.extend_from_slice(&chunk);
                    if String::from_utf8_lossy(&transcript).contains(marker) {
                        saw_marker = true;
                        break;
                    }
                }
                Ok(ServerMessage::Exit { .. }) => break,
                Err(_) => {}
            }
        }
    }

    let text = String::from_utf8_lossy(&transcript);
    assert!(
        saw_marker,
        "expected PowerShell to echo {marker:?} back through the WebSocket.\nTranscript:\n{text}"
    );
}
