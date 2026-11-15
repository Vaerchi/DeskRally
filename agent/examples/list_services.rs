//! Runnable proof that the read-only service panel produces real data end-to-end through the
//! dispatcher (capability check + audit included).
//!
//!   cargo run --example list_services

use rmt_agent::backstage::rbac::{Capability, Grant};
use rmt_agent::backstage::{Confirmation, Dispatcher, Request, Response};

fn main() {
    // A grant a technician might receive from the relay: read-only service access.
    let grant = Grant {
        technician_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::new_v4(),
        capabilities: vec![Capability::ServiceList],
    };
    let mut dispatcher = Dispatcher::new(grant, "rmt-agent.exe");

    // now_ms is injected; use a fixed value so the example needs no clock.
    let (event, result) = dispatcher.handle(Request::ListServices, Confirmation::NotProvided, 0);

    match result {
        Ok(Response::ServiceList(rows)) => {
            let running = rows.iter().filter(|r| r.pid.is_some()).count();
            println!("{} services ({} running). First 15 by state, then name:\n", rows.len(), running);
            println!("{:>8}  {:<16}  {}", "PID", "STATE", "DISPLAY NAME");
            for r in rows.iter().take(15) {
                println!(
                    "{:>8}  {:<16}  {}",
                    r.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
                    format!("{:?}", r.state),
                    r.display_name
                );
            }
        }
        other => eprintln!("unexpected result: {other:?}"),
    }

    if let Some(ev) = event {
        println!("\naudit: seq={} outcome={:?} hash={}", ev.seq, ev.outcome, &ev.hash[..8]);
    }
}
