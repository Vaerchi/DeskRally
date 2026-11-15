//! Runnable proof that the read-only process panel produces real data end-to-end through the
//! dispatcher (capability check + audit included).
//!
//!   cargo run --example list_processes

use rmt_agent::backstage::rbac::{Capability, Grant};
use rmt_agent::backstage::{Confirmation, Dispatcher, Request, Response};

fn main() {
    // A grant that a technician might receive from the relay: read-only process access.
    let grant = Grant {
        technician_id: uuid::Uuid::new_v4(),
        session_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::new_v4(),
        capabilities: vec![Capability::ProcessList],
    };
    let mut dispatcher = Dispatcher::new(grant, "rmt-agent.exe");

    // now_ms is injected; use a fixed value so the example needs no clock.
    let (event, result) = dispatcher.handle(Request::ListProcesses, Confirmation::NotProvided, 0);

    match result {
        Ok(Response::ProcessList(mut rows)) => {
            println!("Top 15 processes by CPU on this machine:\n");
            println!("{:>7}  {:>6}  {:>10}  {}", "PID", "CPU%", "MEM(MB)", "NAME");
            rows.truncate(15);
            for r in rows {
                println!(
                    "{:>7}  {:>6.1}  {:>10.1}  {}",
                    r.pid,
                    r.cpu_percent,
                    r.memory_bytes as f64 / (1024.0 * 1024.0),
                    r.name
                );
            }
        }
        other => eprintln!("unexpected result: {other:?}"),
    }

    // The action was audited (even read-only reads produce a record).
    if let Some(ev) = event {
        println!("\naudit: seq={} outcome={:?} hash={}", ev.seq, ev.outcome, &ev.hash[..8]);
    }
}
