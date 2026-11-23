//! Proves the SHIPPED `agent_host` binary actually installs a `tracing` subscriber that writes to
//! the helper log — the thing the agent lacked entirely until docs/07 loop 6 §2 was closed.
//!
//! **What carries which guarantee** (the loop rule about premises): `logging.rs`'s unit tests pin
//! the *subscriber* (writer wiring, level filter, unwritable-path survival) by installing it
//! scoped with `with_default`. They CANNOT prove `host_main` installs it — a build that dropped
//! the `logging::init()` call would leave them all green while every `tracing::*` in the shipped
//! agent went back to being a no-op, which is exactly the original defect. Only running the real
//! binary and reading the file it produced pins that, which is what this test does.
//!
//! It runs `agent_host <unknown-subcommand>`, which prints usage and exits 2 without touching the
//! network, a display, or the config — the cheapest path through `host_main`. `RMT_LOG_FILE`
//! redirects the log into a temp dir so the test never writes to the machine-wide `C:\rmt-agent`.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

/// A unique temp log path for this test process.
fn temp_log_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rmt-host-logging-{}-{:?}.log",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// A value shaped like an enrollment token, passed as an extra argv element. Enrollment tokens are
/// bearer secrets, so the assertion that this never reaches the log is a security property, not
/// tidiness.
const FAKE_SECRET: &str = "RMT-FAKE-BEARER-TOKEN-9d41c0aa";

#[test]
fn the_binary_installs_a_subscriber_that_writes_the_helper_log() {
    let log = temp_log_path();
    let _ = std::fs::remove_file(&log);

    // `CARGO_BIN_EXE_<name>` is set by cargo for integration tests and names the binary built from
    // THIS workspace — so the test always exercises the current source, not a stale install.
    //
    // RMT_LOG is set explicitly rather than inherited: a developer or CI with `RMT_LOG=off`
    // exported would otherwise see this fail with "the binary did not create the log", which reads
    // as a broken subscriber rather than as their own environment.
    let exe = env!("CARGO_BIN_EXE_agent_host");
    let out = Command::new(exe)
        .arg("definitely-not-a-subcommand")
        .arg(FAKE_SECRET)
        .env("RMT_LOG_FILE", &log)
        .env("RMT_LOG", "info")
        .output()
        .expect("run agent_host");

    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown subcommand exits 2 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&log).unwrap_or_else(|e| {
        panic!(
            "agent_host did not create the log at {}: {e}. \
             Is `crate::logging::init()` still the first statement of `host_main`?",
            log.display()
        )
    });
    assert!(
        text.contains("agent host start"),
        "the startup event reached the log file; got: {text}"
    );
    assert!(
        text.contains("INFO"),
        "events are formatted with their level; got: {text}"
    );
    // The subcommand is logged...
    assert!(
        text.contains("definitely-not-a-subcommand"),
        "the subcommand is recorded; got: {text}"
    );
    // ...and the REST of argv is not. `enroll --token <secret>` puts a bearer secret in argv, so
    // logging the whole command line would write it to a file that outlives the enrollment. This
    // is asserted rather than merely asserted-in-a-comment: `args` is right there in `host_main`,
    // and logging it is a one-word change away.
    assert!(
        !text.contains(FAKE_SECRET),
        "argv beyond the subcommand must never reach the log; got: {text}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(FAKE_SECRET),
        "argv beyond the subcommand must never reach stderr either"
    );

    let _ = std::fs::remove_file(&log);
}

/// Tracing goes to **stderr and the file, never stdout**, and the stderr mirror really happens.
///
/// Scope, stated precisely because an earlier version of this comment claimed more than the test
/// does: this drives one `host_main` path (an unknown subcommand) and inspects that process's two
/// captured streams. It does NOT exercise `host::log_line` — no subcommand reaches it without
/// entering the helper's 300-second loop — so the shared routing those two writers now have is
/// pinned by `logging::tests::the_shipped_cap_keeps_an_ordinary_log_intact` (the function they
/// share) and by the VM run recorded in docs/07, not here.
#[test]
fn tracing_output_does_not_pollute_stdout() {
    let log = temp_log_path();
    let _ = std::fs::remove_file(&log);

    let exe = env!("CARGO_BIN_EXE_agent_host");
    let out = Command::new(exe)
        .arg("definitely-not-a-subcommand")
        .env("RMT_LOG_FILE", &log)
        .env("RMT_LOG", "info")
        .output()
        .expect("run agent_host");

    // stdout is a machine-readable contract the e2e specs match on (`INJECTED …`,
    // `CLIPBOARD-SET …`, the streaming banners). Tracing must never interleave with it.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("agent host start"),
        "tracing must not reach stdout; got: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent host start"),
        "tracing is mirrored to stderr for an interactive operator; got: {stderr}"
    );

    let _ = std::fs::remove_file(&log);
}

/// An EMPTY `RMT_LOG` must not silence the agent. `tracing_core` parses `""` as `LevelFilter::ERROR`,
/// so the obvious `raw.parse()` implementation turns `RMT_LOG=` — a `-e RMT_LOG` with no value, a
/// blank service env entry, `RMT_LOG=$UNSET` in a wrapper — into an agent that logs nothing at INFO
/// or WARN and says nothing about why. That is indistinguishable from the defect this whole module
/// was written to fix, so it is pinned against the real binary rather than only in a unit test.
#[test]
fn an_empty_rmt_log_level_still_logs_at_info() {
    let log = temp_log_path();
    let _ = std::fs::remove_file(&log);

    let exe = env!("CARGO_BIN_EXE_agent_host");
    Command::new(exe)
        .arg("definitely-not-a-subcommand")
        .env("RMT_LOG_FILE", &log)
        .env("RMT_LOG", "")
        .output()
        .expect("run agent_host");

    let text = std::fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("an empty RMT_LOG silenced the agent ({e}) — does level_from_env still treat empty as absent?"));
    assert!(
        text.contains("agent host start"),
        "INFO still reaches the log with RMT_LOG empty; got: {text}"
    );

    let _ = std::fs::remove_file(&log);
}

/// A MALFORMED `RMT_LOG` must not silence the agent — it falls back to INFO and says so on stderr.
/// This pins the fallback in the REAL binary, where a wrong choice would mean an operator who
/// typo'd the variable gets an agent that logs nothing and no explanation.
#[test]
fn a_malformed_rmt_log_level_still_logs_at_info() {
    let log = temp_log_path();
    let _ = std::fs::remove_file(&log);

    let exe = env!("CARGO_BIN_EXE_agent_host");
    let out = Command::new(exe)
        .arg("definitely-not-a-subcommand")
        .env("RMT_LOG_FILE", &log)
        .env("RMT_LOG", "debgu")
        .output()
        .expect("run agent_host");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is not a level"),
        "the bad level is reported to the operator; stderr: {stderr}"
    );
    let text = std::fs::read_to_string(&log).expect("log file written despite the bad level");
    assert!(
        text.contains("agent host start"),
        "INFO still reaches the log; got: {text}"
    );

    let _ = std::fs::remove_file(&log);
}
