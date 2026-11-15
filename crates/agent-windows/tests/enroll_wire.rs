//! Proves the agent actually PUTS `os` ON THE WIRE at `POST /enroll/redeem`.
//!
//! WHY THIS EXISTS. `machine.os` (migration 0017) was added, read by the console, and then sat blank
//! on every enrolled machine for weeks, because nothing populated it — the column, the console
//! column header and the server-side handling all existed and agreed with each other while the one
//! party that knows the answer never sent it. That defect was invisible to every test in the tree:
//! `enroll.rs`'s unit tests cover `compose_os_description` (a pure function over three strings) and
//! prove it formats correctly, but a formatter can be perfect while nothing calls it. Deleting
//! `"os": os_description()` from the request body leaves all of them green.
//!
//! So this test asserts the thing the unit tests structurally cannot: run the REAL `enroll_once`
//! against a real socket and read the JSON it sent. It is the same division of labour
//! `tests/host_logging.rs` draws — unit tests pin the piece, an integration test pins that the
//! shipped path uses it.
//!
//! The "mock" is a hand-rolled one-shot HTTP/1.1 responder on a loopback port rather than a mock
//! crate: enrollment is one blocking POST with a JSON body, the workspace has no HTTP-mock
//! dependency, and adding one to check a single request would be a heavier commitment than the 30
//! lines below.
//!
//! WHERE THIS RUNS. Locally, `verify-all.ps1`'s `cargo test --workspace` builds and runs every
//! integration target. In CI the broad Rust step is deliberately `--lib` (so a server-dependent
//! integration test cannot self-skip green there), which never even BUILDS this file — so
//! `.github/workflows/ci.yml` runs it, with `probe_logging` and `host_logging`, as named
//! deterministic targets. If you rename this file, rename it there too.

#![cfg(windows)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use rmt_agent_windows::config::HelperConfig;
use rmt_agent_windows::enroll;

/// A one-shot `/enroll/redeem` responder. Returns (base_url, join-handle yielding the request body).
///
/// It answers exactly one request and exits, which is all `enroll_once` makes. The response is the
/// minimum `parse_redeem_response` accepts: a `machine` object carrying `device_id`, `tenant_id`
/// and the pubkey ECHOED BACK — the agent refuses to enroll against a key it cannot sign with, so
/// the responder has to read the request to answer it, which is exactly what makes the body
/// available to assert on.
fn spawn_redeem_server() -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Read the request head, then exactly Content-Length bytes of body.
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).expect("read head") == 0 {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).expect("read body");
        let body = String::from_utf8(body).expect("utf-8 body");

        // Echo the pubkey the agent sent, so its pin check passes.
        let sent: serde_json::Value = serde_json::from_str(&body).expect("request is JSON");
        let pubkey = sent.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
        let payload = format!(
            r#"{{"machine":{{"device_id":"11111111-2222-3333-4444-555555555555","tenant_id":"66666666-7777-8888-9999-000000000000","pubkey":"{pubkey}"}}}}"#
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        stream.write_all(resp.as_bytes()).expect("write response");
        stream.flush().ok();
        body
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

/// A config pointed at the fake control plane, with its own temp identity + config paths so the
/// test never touches `C:\rmt-agent`.
fn temp_config(base: &str, tag: &str) -> (HelperConfig, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "rmt-enroll-wire-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let identity = dir.join("identity.key");
    let config = dir.join("config.json");
    let mut cfg = HelperConfig::default();
    cfg.control_plane_url = Some(base.to_string());
    cfg.enrollment_token = Some("test-enrollment-token".to_string());
    cfg.identity_path = Some(identity.to_string_lossy().to_string());
    (
        cfg,
        config.to_string_lossy().to_string(),
        dir.to_string_lossy().to_string(),
    )
}

/// THE HEADLINE: the request body carries a non-empty, plausible `os`.
#[test]
fn enrollment_sends_a_populated_os_field() {
    let (base, server) = spawn_redeem_server();
    let (mut cfg, config_path, dir) = temp_config(&base, "os");

    let enrolled = enroll::enroll_once(&mut cfg, &config_path, Some("TEST-MACHINE"))
        .unwrap_or_else(|e| panic!("enroll_once against the fake control plane failed: {e}"));
    assert_eq!(enrolled.device_id, "11111111-2222-3333-4444-555555555555");

    let body = server.join().expect("server thread");
    let sent: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");

    let os = sent
        .get("os")
        .unwrap_or_else(|| panic!("the enrollment body has NO `os` field at all: {body}"))
        .as_str()
        .unwrap_or_else(|| panic!("`os` is not a string: {body}"));

    // Non-empty is the whole original defect: the column was populated with "" on every machine.
    assert!(
        !os.is_empty(),
        "`os` is present but EMPTY — this is exactly the state migration 0017 shipped in: {body}"
    );
    // This test is `#![cfg(windows)]`, so the value comes from the real registry read on this box.
    // Asserting the product family (rather than an exact string) keeps it true on any Windows host
    // while still failing if the field is filled with a placeholder, a hostname, or a version alone.
    assert!(
        os.contains("Windows"),
        "`os` does not look like a Windows description: {os:?}"
    );
    // The server bounds this field at 255 characters (maxMachineNameLen in http.go). A value the
    // control plane would reject is not a working enrollment, so the agent must stay inside it.
    assert!(
        os.len() <= 255,
        "`os` is {} bytes, over the server's 255-byte bound: {os:?}",
        os.len()
    );

    // The neighbouring fields are asserted too, cheaply: if the body shape ever drifts, "os is
    // fine" alone would be a misleading green.
    assert_eq!(
        sent.get("token").and_then(|v| v.as_str()),
        Some("test-enrollment-token"),
        "the enrollment token is what authorizes the redemption"
    );
    assert_eq!(
        sent.get("name").and_then(|v| v.as_str()),
        Some("TEST-MACHINE"),
        "the caller-supplied machine name is forwarded"
    );
    assert!(
        sent.get("pubkey").and_then(|v| v.as_str()).is_some_and(|p| p.len() == 64),
        "a 32-byte Ed25519 pubkey is sent as 64 hex chars: {body}"
    );
    // `device_id` must NOT be sent: a redeemer that could choose it would be choosing which agent
    // the tenant's session tickets authorize (see the enroll_once comment and migration 0008).
    assert!(
        sent.get("device_id").is_none(),
        "device_id must never be in the redeem body: {body}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The `os` on the wire IS the shipped formatter's output. Pinned by re-deriving the expected
/// value from this machine's own registry through the same public entry point
/// (`enroll::os_description`) and requiring EXACT equality — an ad-hoc string assembled at the
/// call site (`format!("Windows (build {})", …)` and friends, which passed every assertion the
/// first version of this test had) fails this unless it reproduces `os_description()` byte for
/// byte ON THE HOST RUNNING THE TEST. That let-out is real: on a host where no compose branch
/// fires (windows-latest's Server 2025 image — honest ProductName, short values), an inline
/// `format!("{} {} (build {})", …)` over the same three registry reads matches byte for byte
/// while silently dropping the Win11 correction and the 255-byte clamp. It fails on any
/// lying-registry host — this dev box among them — so local verify-all catches what CI alone
/// would not.
///
/// What equality alone cannot see is any break INSIDE `os_description()` — it is symmetric here,
/// equal and wrong. The layers that carry that: the registry→parameter WIRING is pinned by
/// `enroll.rs`'s `os_description_wires_all_three_registry_values_through` (it re-derives the
/// expected value from the raw registry reads, so a dropped or misspelled value name fails it),
/// and the formatting RULES by the `compose_os_description` unit tests. What no layer pins is a
/// simultaneous matching break in a function and its own pinning test — the generic limit of
/// testing.
#[test]
fn the_os_on_the_wire_has_the_composed_shape() {
    let (base, server) = spawn_redeem_server();
    let (mut cfg, config_path, dir) = temp_config(&base, "shape");

    enroll::enroll_once(&mut cfg, &config_path, None).expect("enroll_once");
    let body = server.join().expect("server thread");
    let sent: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
    let os = sent.get("os").and_then(|v| v.as_str()).expect("os present");

    // THE claim: the wire value equals a fresh derivation through the shipped entry point. The
    // two reads are milliseconds apart and nothing legitimately rewrites these values mid-run —
    // though HKLM is live, admin-writable state (servicing and upgrades DO rewrite it between
    // boots), so an external writer landing in that window is possible in principle. If it ever
    // happens the failure is loud and prints both strings, which is diagnosable — unlike the
    // silent gaps this file exists to close.
    assert_eq!(
        os,
        enroll::os_description(),
        "the wire `os` is not this machine's own `os_description()` — the enrollment body is not \
         sending the shipped formatter's output: {body}"
    );

    // `compose_os_description` appends "(build NNNNN)" whenever the build number is readable, which
    // it is on any real Windows install. A bare ProductName — the obvious wrong value — has no
    // build suffix, so this distinguishes the composed value from the raw registry read.
    assert!(
        os.contains("(build "),
        "`os` has no build suffix, so it is not the composed description: {os:?}"
    );

    // The Win11-correction half: on a Win11-era host the wire value must not read "Windows 10".
    // Scope, from MEASURED registry values rather than inference (the first version of this
    // comment called this dev box an honest-registry host by trusting the COMPOSED output —
    // which cannot distinguish an honest "Windows 11" from a corrected "Windows 10"; WMI's
    // Caption tells the same lie-hiding story): ProductName reads "Windows 10 …" on essentially
    // every Windows 11 install, clean or upgraded — this dev box ("Windows 10 Enterprise",
    // build 26200) and the clean-installed lab VM ("Windows 10 Pro") both lie — so on local runs
    // this assertion proves the correction FIRED on the shipped path. On an honest-name host
    // (windows-latest's Server 2025 image) it holds without the correction firing, and the
    // correction mechanism is carried by `enroll.rs`'s unit tests. What can never happen is the
    // assertion silently not running: the previous version wrapped it in
    // `if build_num >= 22000 { … }`, which on any older host — or on any parse failure, via the
    // `unwrap_or(0)` below — evaporated while the test still reported PASS: a hidden skip, in a
    // tree whose harness treats a skip as a failure. So the premise is ASSERTED. A genuine
    // pre-22000 host (Windows 10 22H2, Server 2022) fails it loudly BY DESIGN — a recorded
    // tradeoff, not an accident: if such a host ever needs this suite, move the correction
    // coverage, do not re-hide it.
    let build_num: u32 = os
        .split("(build ")
        .nth(1)
        .and_then(|s| s.trim_end_matches(')').trim().parse().ok())
        .unwrap_or(0);
    assert!(
        build_num >= 22000,
        "premise not met: this host reports build {build_num} (< 22000), so the Win11 \
         ProductName correction cannot be observed here — failing loudly rather than silently \
         skipping the assertion below: {os:?}"
    );
    assert!(
        !os.contains("Windows 10"),
        "build {build_num} is Windows 11 but the wire value still says Windows 10 — the \
         ProductName correction is not being applied on the shipped path: {os:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Loop 86: the enrollment body carries `require_session_policy`, and carries the AGENT'S value
/// rather than a constant.
///
/// Same defect shape as the `os` one this file was built for, but with teeth: the column, the
/// migration, the mint condition and the console can all exist and agree while the one party that
/// knows the answer never sends it — and the symptom is not a blank inventory cell, it is an agent
/// that opens VIEW-ONLY FOREVER with no way to discharge the floor. Deleting the line from
/// `enroll_once`'s body leaves every unit test in the tree green.
///
/// Both values are asserted because only the pair rules out a hard-coded literal: `true` alone would
/// pass against `"require_session_policy": true`, and `false` alone against a dropped field that
/// defaults. Together they prove the wire value TRACKS the config.
#[test]
fn enrollment_sends_the_agents_own_require_session_policy_flag() {
    for want in [true, false] {
        let (base, server) = spawn_redeem_server();
        let (mut cfg, config_path, dir) =
            temp_config(&base, if want { "floor-on" } else { "floor-off" });
        cfg.require_session_policy = want;

        enroll::enroll_once(&mut cfg, &config_path, Some("TEST-MACHINE"))
            .unwrap_or_else(|e| panic!("enroll_once against the fake control plane failed: {e}"));

        let body = server.join().expect("server thread");
        let sent: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
        let got = sent.get("require_session_policy").unwrap_or_else(|| {
            panic!("the enrollment body has NO `require_session_policy` field at all: {body}")
        });
        assert_eq!(
            got.as_bool(),
            Some(want),
            "the wire flag does not track the agent's config (wanted {want}): {body}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
