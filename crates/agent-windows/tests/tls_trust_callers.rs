//! Binds `rmt_transport_webrtc::tls_trust` to every production HTTPS/WSS dial in the agent.
//!
//! The helper's own tests prove it trusts the right roots; they cannot prove anything USES it. A
//! client built with `reqwest::blocking::Client::builder()` and no preconfigured TLS silently falls back
//! to reqwest's feature roots (OS store only), which is exactly the fresh-machine failure this helper
//! fixes (MSI-Night, 2026-10-09). So this scans the production sources:
//!
//! * every `Client::builder()` must pass `tls_trust::client_config()` within the next few lines;
//! * every `connect_async_tls_with_config(` must be preceded closely by `tls_trust::client_config()`;
//! * `use_rustls_tls()` and a bare `connect_async(` are forbidden (both pick the feature's roots);
//! * the known callers must actually be found, so a moved directory cannot make the scan vacuous.
//!
//! Scope: agent-windows/src, transport-webrtc/src, agent/src — `src/bin/` probes excluded. Test code
//! under `tests/` is not scanned (fixtures dial plain loopback `ws://`).

use std::path::{Path, PathBuf};

const WINDOW: usize = 4;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "bin") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

#[derive(Debug, Default, PartialEq)]
struct Scan {
    bound_https: Vec<String>,
    bound_wss: Vec<String>,
    violations: Vec<String>,
}

fn scan_text(name: &str, text: &str, scan: &mut Scan) {
    let lines: Vec<&str> = text.lines().collect();
    // Code only: a comment that merely MENTIONS the helper must not bind a dial.
    let binds = |range: std::ops::Range<usize>| {
        lines[range].iter().any(|l| l.split("//").next().unwrap_or("").contains("tls_trust::client_config()"))
    };
    for (i, line) in lines.iter().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        let at = format!("{name}:{}", i + 1);
        if code.contains("Client::builder()") {
            if binds(i..(i + WINDOW + 1).min(lines.len())) {
                scan.bound_https.push(at.clone());
            } else {
                scan.violations.push(format!("{at}: HTTP client without tls_trust config"));
            }
        }
        if code.contains("connect_async_tls_with_config(") {
            if binds(i.saturating_sub(WINDOW)..i + 1) {
                scan.bound_wss.push(at.clone());
            } else {
                scan.violations.push(format!("{at}: WSS connect without tls_trust config"));
            }
        } else if code.contains("connect_async(") {
            scan.violations.push(format!("{at}: bare connect_async uses the feature's roots"));
        }
        if code.contains("use_rustls_tls()") {
            scan.violations.push(format!("{at}: use_rustls_tls() uses the feature's roots"));
        }
    }
}

fn scan_production() -> Scan {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for dir in ["agent-windows/src", "transport-webrtc/src", "../agent/src"] {
        rust_files(&crates.join(dir), &mut files);
    }
    let mut scan = Scan::default();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        scan_text(&name, &text, &mut scan);
    }
    scan
}

#[test]
fn every_production_https_and_wss_dial_uses_the_shared_trust_config() {
    let scan = scan_production();
    assert!(scan.violations.is_empty(), "unbound TLS dials:\n{}", scan.violations.join("\n"));
    // Non-vacuity: the callers this fix was written for must be among those found and bound.
    for (want, found) in [
        ("enroll.rs", &scan.bound_https),
        ("attend.rs", &scan.bound_https),
        ("signaling.rs", &scan.bound_wss),
    ] {
        assert!(
            found.iter().any(|at| at.starts_with(want)),
            "{want} not found among bound callers {found:?} — has the scan lost its files?"
        );
    }
}

/// Negative control: the scanner does flag each unbound form, so a passing scan means something.
#[test]
fn the_scanner_flags_unbound_dials() {
    let mut scan = Scan::default();
    scan_text(
        "fixture.rs",
        "let c = reqwest::blocking::Client::builder()\n    .timeout(T)\n    .build();\n\
         let (ws, _) = connect_async(url).await?;\n\
         let x = Client::builder().use_rustls_tls().build();\n\
         let (ws, _) = connect_async_tls_with_config(url, None, false, None).await?;\n",
        &mut scan,
    );
    assert_eq!(scan.violations.len(), 5, "{:#?}", scan.violations);
    assert!(scan.bound_https.is_empty() && scan.bound_wss.is_empty());

    let mut ok = Scan::default();
    scan_text(
        "fixture.rs",
        "let c = Client::builder()\n    .use_preconfigured_tls(tls_trust::client_config()?)\n    .build();\n\
         let tls = Connector::Rustls(Arc::new(crate::tls_trust::client_config()?));\n\
         let (ws, _) = connect_async_tls_with_config(url, None, false, Some(tls)).await?;\n",
        &mut ok,
    );
    assert!(ok.violations.is_empty(), "{:#?}", ok.violations);
    assert_eq!((ok.bound_https.len(), ok.bound_wss.len()), (1, 1));
}
