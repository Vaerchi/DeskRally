//! Runnable proof that the read-only file-browse panel produces real data end-to-end through
//! the dispatcher (capability check + audit of the browsed path included).
//!
//!   cargo run --example browse_dir              # lists the top level (drive roots / "/")
//!   cargo run --example browse_dir "C:\\Windows" # lists a specific directory

use rmt_agent::backstage::rbac::{Capability, Grant};
use rmt_agent::backstage::{Confirmation, Dispatcher, Request, Response};

fn main() {
    // Optional path argument; empty = top level (drive roots on Windows, "/" elsewhere).
    let path = std::env::args().nth(1).unwrap_or_default();

    let grant = Grant {
        technician_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::new_v4(),
        capabilities: vec![Capability::FileBrowse],
    };
    let mut dispatcher = Dispatcher::new(grant, "rmt-agent.exe");

    let (event, result) = dispatcher.handle(
        Request::BrowseDirectory { path: path.clone() },
        Confirmation::NotProvided,
        0,
    );

    match result {
        Ok(Response::DirectoryListing(listing)) => {
            let shown = if listing.path.is_empty() { "<top level>" } else { &listing.path };
            println!("{} ({} entries). First 20, directories first:\n", shown, listing.entries.len());
            println!("{:<5}  {:>12}  {}", "TYPE", "SIZE", "NAME");
            for e in listing.entries.iter().take(20) {
                let kind = if e.is_symlink { "LINK" } else if e.is_dir { "DIR" } else { "FILE" };
                let size = e.size_bytes.map(|b| b.to_string()).unwrap_or_else(|| "—".into());
                println!("{:<5}  {:>12}  {}", kind, size, e.name);
            }
        }
        other => eprintln!("unexpected result: {other:?}"),
    }

    if let Some(ev) = event {
        println!("\naudit: seq={} outcome={:?} hash={}", ev.seq, ev.outcome, &ev.hash[..8]);
    }
}
