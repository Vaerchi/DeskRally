//! Proves the SHIPPED `stream_probe` binary installs a `tracing` subscriber — and that it writes
//! somewhere a controller-side tool may actually write.
//!
//! WHY THIS MATTERS MORE THAN IT LOOKS. `stream_probe` is the tool used to PROVE the agent streams
//! on the VM, and the failures worth diagnosing do not happen in the probe: they happen inside
//! `rmt_transport_webrtc`, which reports them with `tracing::warn!` — `set_remote(offer)`,
//! `create_answer`, `set_remote(answer)`, a malformed `agent_auth_challenge` nonce, and
//! "video encoder init failed; no video". With no subscriber installed, every one of those was a
//! silent no-op, so the probe would report "too few RTP packets" while the actual reason had
//! already been produced and discarded. The verdict was sound; the diagnosis was thrown away.
//!
//! WHAT CARRIES WHICH GUARANTEE (the loop rule about premises): `logging.rs`'s unit tests pin the
//! subscriber's own behaviour (writer wiring, level filter, path resolution) by installing it
//! scoped with `with_default`. They CANNOT prove `stream_probe` installs one — deleting the
//! `logging::init_at(...)` line leaves every one of them green while the shipped tool goes back to
//! discarding transport warnings. Only running the real binary and reading the file it produced
//! pins that, which is what these tests do (the same division `tests/host_logging.rs` draws for
//! `agent_host`).

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

/// A unique temp log path for this test process.
fn temp_log_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rmt-probe-logging-{tag}-{}-{:?}.log",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Run the shipped probe with an argument error, which exits 2 without touching the network.
/// Deliberately the cheapest path through `main`: the subscriber is installed BEFORE argument
/// validation precisely so a usage error is still observable, and a test that had to dial a
/// signaling server to see a log line would be an e2e test with a timeout, not a unit of evidence.
fn run_probe(log: &PathBuf, extra_env: &[(&str, &str)]) -> std::process::Output {
    let exe = env!("CARGO_BIN_EXE_stream_probe");
    let mut cmd = Command::new(exe);
    // No --device: PROBE FAIL, exit 2.
    cmd.env("RMT_LOG_FILE", log).env("RMT_LOG", "info");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("run stream_probe")
}

#[test]
fn the_probe_binary_installs_a_subscriber_that_writes_a_log() {
    let log = temp_log_path("basic");
    let _ = std::fs::remove_file(&log);

    let out = run_probe(&log, &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a missing --device exits 2 (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&log).unwrap_or_else(|e| {
        panic!(
            "stream_probe did not create the log at {}: {e}. \
             Is `logging::init_at(...)` still the first statement of its main?",
            log.display()
        )
    });
    assert!(
        text.contains("stream_probe start"),
        "the startup event reached the log file; got: {text}"
    );
    assert!(
        text.contains("INFO"),
        "events are formatted with their level; got: {text}"
    );

    let _ = std::fs::remove_file(&log);
}

/// Tracing must go to stderr and the file, NEVER stdout. `stdout` is a machine-readable contract:
/// the VM scripts and `docs/07`'s recorded runs match on `PROBE RESULT: <n> RTP packets …`, and the
/// e2e specs match on the agent's own stdout banners. A subscriber that wrote there would corrupt
/// the very output this tool exists to produce.
#[test]
fn probe_tracing_does_not_pollute_stdout() {
    let log = temp_log_path("stdout");
    let _ = std::fs::remove_file(&log);

    let out = run_probe(&log, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("stream_probe start"),
        "tracing must not reach stdout; got: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("stream_probe start"),
        "tracing is mirrored to stderr for an interactive operator; got: {stderr}"
    );

    let _ = std::fs::remove_file(&log);
}

/// THE PATH CHOICE, pinned. With no `RMT_LOG_FILE` the probe must default into the TEMP directory,
/// not the agent's `C:\rmt-agent`. Two reasons, both load-bearing: the probe is CONTROLLER-side and
/// commonly runs unelevated on a machine with no agent at all (the agent's directory is owned by
/// SYSTEM, so the subscriber would silently degrade to stderr-only and the file would never
/// appear); and mixing a controller's events into the log of the machine it is probing makes the
/// agent's own timeline harder to read.
///
/// This drives the real binary with `RMT_LOG_FILE` REMOVED — `env_remove`, not merely unset in this
/// process, because a developer or CI with it exported would otherwise silently redirect the very
/// default under test and the assertion would pass without exercising anything.
///
/// The child also gets its OWN `TMP`/`TEMP`. Two tests here exercise the shared default path, cargo
/// runs them on parallel threads, and one asserts the default was written while the other asserts it
/// was NOT — against the real `%TEMP%` those two race and fail each other intermittently. Giving the
/// child a private temp directory makes each hermetic while still pinning the real question: that
/// the default lands in the TEMP directory rather than the agent's.
#[test]
fn the_probe_defaults_into_temp_not_the_agent_directory() {
    let private_temp = temp_log_path("default-dir").with_extension("d");
    std::fs::create_dir_all(&private_temp).expect("private temp dir");
    let expected = private_temp.join("rmt-stream-probe.log");

    let exe = env!("CARGO_BIN_EXE_stream_probe");
    let out = Command::new(exe)
        .env_remove("RMT_LOG_FILE")
        .env("TMP", &private_temp)
        .env("TEMP", &private_temp)
        .env("RMT_LOG", "info")
        .output()
        .expect("run stream_probe");
    assert_eq!(out.status.code(), Some(2), "a missing --device exits 2");

    let text = std::fs::read_to_string(&expected).unwrap_or_else(|e| {
        panic!(
            "the probe's DEFAULT log is not {} ({e}). It must resolve to <temp>/rmt-stream-probe.log \
             and must NOT default into the agent's SYSTEM-owned C:\\rmt-agent — see \
             logging::tool_log_path.",
            expected.display()
        )
    });
    assert!(
        text.contains("stream_probe start"),
        "the default log carries the startup event; got: {text}"
    );
    // The intent — "the default is never inside the agent's directory" — asserted against the
    // SHIPPED function rather than against `expected`, which this test built itself and which
    // therefore could never have failed the check. (Several review lenses spotted that tautology
    // independently; it looked like a guard and was one line of decoration.)
    let shipped_default = rmt_agent_windows::logging::tool_log_path("stream-probe");
    assert!(
        !shipped_default.starts_with(r"C:\rmt-agent"),
        "tool_log_path must not resolve inside the agent's SYSTEM-owned directory: {}",
        shipped_default.display()
    );
    assert_eq!(
        shipped_default.file_name().and_then(|n| n.to_str()),
        Some("rmt-stream-probe.log"),
        "the probe's default file name is part of what an operator collects from a VM run"
    );

    let _ = std::fs::remove_dir_all(&private_temp);
}

/// `RMT_LOG_FILE` overrides the tool default. This is what makes the probe's log collectable from a
/// scripted VM run (the same variable already redirects the agent's), so it is pinned against the
/// real binary rather than only in `logging.rs`'s unit test.
#[test]
fn rmt_log_file_overrides_the_probe_default() {
    let log = temp_log_path("override");
    let _ = std::fs::remove_file(&log);
    // A PRIVATE temp for the child, so "the default was not written" is a statement about this run
    // and cannot be falsified by the sibling test writing the shared %TEMP% default concurrently.
    let private_temp = temp_log_path("override-dir").with_extension("d");
    std::fs::create_dir_all(&private_temp).expect("private temp dir");
    let default_path = private_temp.join("rmt-stream-probe.log");

    let out = run_probe(
        &log,
        &[
            ("TMP", private_temp.to_str().expect("utf-8 temp path")),
            ("TEMP", private_temp.to_str().expect("utf-8 temp path")),
        ],
    );
    assert_eq!(out.status.code(), Some(2));

    assert!(
        std::fs::read_to_string(&log)
            .expect("the override path was written")
            .contains("stream_probe start"),
        "RMT_LOG_FILE must win over the tool default"
    );
    // And the default was NOT also written — one destination, not two.
    assert!(
        !default_path.exists(),
        "the probe wrote BOTH the override and the default {}",
        default_path.display()
    );

    let _ = std::fs::remove_file(&log);
    let _ = std::fs::remove_dir_all(&private_temp);
}

/// A `--script` payload can carry a PASSWORD — the secure-desktop check in `docs/07` types the
/// guest credential through `text:` — so argv must never be logged wholesale. This is the same
/// rule `host_main` follows for enrollment tokens, asserted here because the probe is the binary
/// most likely to be handed a secret on its command line.
///
/// THE PREMISE HAS TO BE EARNED, and the first version of this test did not earn it: it passed
/// `--script` with NO `--device`, and `main` validates `--device` first, so the process exited
/// before the script was ever parsed or logged. It asserted "the secret is absent" about a run that
/// never handled the secret — green regardless of what the script path does with it.
///
/// So this run supplies a VALID `--device` (the script really is parsed, and `probe start` really
/// is logged with its step count) and points `--signaling` at a closed port, so `connect` fails
/// immediately and the process exits 1 without needing a server. The assertions below therefore
/// describe a run that got all the way through argument handling with the secret in hand.
#[test]
fn a_script_payload_never_reaches_the_log_or_stderr() {
    const FAKE_SECRET: &str = "RMT-FAKE-GUEST-PASSWORD-51ab77e2";
    let log = temp_log_path("secret");
    let _ = std::fs::remove_file(&log);

    let exe = env!("CARGO_BIN_EXE_stream_probe");
    let out = Command::new(exe)
        .arg("--device")
        .arg("f4bd0e20-d8e0-47e6-bc65-26056d62aae3")
        // Port 9 (discard) on the loopback: nothing listens, so the WS dial fails fast.
        .arg("--signaling")
        .arg("ws://127.0.0.1:9/ws")
        .arg("--script")
        .arg(format!("text:{FAKE_SECRET}"))
        .env("RMT_LOG_FILE", &log)
        .env("RMT_LOG", "trace") // the loudest setting: nothing may leak even at trace
        .output()
        .expect("run stream_probe");

    // Exit 1 = "connect failed", which is what proves we got PAST argument validation. A 2 here
    // would mean the arguments were rejected and the script was never parsed — the exact vacuous
    // shape this test was rewritten to escape.
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected a connect failure (exit 1), i.e. arguments accepted and the script parsed; \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&log).expect("the log was written");
    // The premise, asserted rather than assumed: the run really did reach script handling.
    assert!(
        text.contains("probe start"),
        "the run did not reach the post-argument-parsing startup event, so the secret assertions \
         below would prove nothing; got: {text}"
    );
    assert!(
        !text.contains(FAKE_SECRET),
        "a --script payload reached the log file; got: {text}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(FAKE_SECRET),
        "a --script payload reached stderr"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(FAKE_SECRET),
        "a --script payload reached stdout"
    );

    let _ = std::fs::remove_file(&log);
}
