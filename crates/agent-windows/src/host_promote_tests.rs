//! Unit tests for the attend-promote path: ZIP extraction safety, token-tracking semantics.
//!
//! Physical acceptance gates (Setup launch, MSI install, UAC, network enrollment) are
//! VM-gated — the tests here cover the pure logic at the seams that sit above Windows effects.
//!
//! Key invariants exercised:
//!   • `extract_setup_zip` reads the **central directory**, not local headers, so it works
//!     correctly with Go's `archive/zip` streaming output (zero local-header sizes + data
//!     descriptors). The `build_streaming_zip` helper reproduces this exact wire format.
//!   • Exact filename allowlist: drive-qualified paths, ADS colons, traversal, and any name
//!     not on the allowlist all fail the extraction.
//!   • Duplicate entries: the `zip` crate deduplicates at read time (last-wins), so extraction
//!     succeeds if required files survive deduplication. Missing required entries fail closed.
//!   • Extraction writes under the canonical allowlisted name, not the raw ZIP entry name.

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a ZIP using the `zip` crate (seekable writer — local headers have correct sizes and
/// CRC). Suitable for testing the happy path and allowlist/duplicate checks.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = Vec::new();
    let cursor = std::io::Cursor::new(&mut buf);
    let mut zw = zip::ZipWriter::new(cursor);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    for &(name, data) in entries {
        zw.start_file(name, opts).unwrap();
        zw.write_all(data).unwrap();
    }
    zw.finish().unwrap();
    buf
}

/// CRC-32 (ISO 3309 / ZIP polynomial 0xEDB88320), computed inline so the streaming-ZIP
/// helper does not need an external crate at test time.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Build a **streaming-style** ZIP that replicates what Go's `archive/zip` emits when writing
/// to a non-seekable `http.ResponseWriter`:
///   • Local file headers have `crc=0`, `comp_size=0`, `uncomp_size=0`.
///   • General-purpose bit-flag bit 3 is set (data descriptor follows file data).
///   • A data descriptor (`PK\x07\x08` + crc32 + comp_size + uncomp_size) follows each entry.
///   • The **central directory** at the end carries the correct sizes and CRC.
///
/// This is the format that the old local-header parser failed on (producing empty files).
/// The `zip::ZipArchive` reader handles it correctly via the central directory.
fn build_streaming_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();

    for &(name, data) in entries {
        let name_bytes = name.as_bytes();
        let offset = out.len() as u32;
        offsets.push(offset);
        let sz = data.len() as u32;
        let crc = crc32(data);

        // Local file header — sizes and CRC are ZERO (bit 3 set, data descriptor follows).
        out.extend_from_slice(b"PK\x03\x04"); // local file signature
        out.extend_from_slice(&[20u8, 0]); // version needed: 2.0
        out.extend_from_slice(&[0x08, 0x00]); // flags: bit 3 = data descriptor present
        out.extend_from_slice(&[0, 0]); // compression: STORED (method 0)
        out.extend_from_slice(&[0, 0]); // last mod time (zeroed)
        out.extend_from_slice(&[0, 0]); // last mod date (zeroed)
        out.extend_from_slice(&[0, 0, 0, 0]); // crc-32: ZERO in local header
        out.extend_from_slice(&[0, 0, 0, 0]); // compressed size: ZERO
        out.extend_from_slice(&[0, 0, 0, 0]); // uncompressed size: ZERO
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]); // extra field length: 0
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        // Data descriptor (Go always writes the optional PK\x07\x08 signature).
        out.extend_from_slice(b"PK\x07\x08");
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&sz.to_le_bytes()); // compressed size
        out.extend_from_slice(&sz.to_le_bytes()); // uncompressed size (STORED — same)

        // Central directory entry — carries the CORRECT sizes and CRC.
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&[20, 0]); // version made by
        central.extend_from_slice(&[20, 0]); // version needed
        central.extend_from_slice(&[0x08, 0x00]); // flags: data descriptor
        central.extend_from_slice(&[0, 0]); // compression: STORED
        central.extend_from_slice(&[0, 0]); // mod time
        central.extend_from_slice(&[0, 0]); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&sz.to_le_bytes()); // compressed size
        central.extend_from_slice(&sz.to_le_bytes()); // uncompressed size
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0, 0]); // extra field length
        central.extend_from_slice(&[0, 0]); // file comment length
        central.extend_from_slice(&[0, 0]); // disk number start
        central.extend_from_slice(&[0, 0]); // internal attrs
        central.extend_from_slice(&[0, 0, 0, 0]); // external attrs
        central.extend_from_slice(&offset.to_le_bytes()); // local header offset
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory record.
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0]); // disk number
    out.extend_from_slice(&[0, 0]); // disk with CD start
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries on disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]); // comment length

    out
}

// ---------------------------------------------------------------------------
// Core extraction tests
// ---------------------------------------------------------------------------

#[test]
fn extract_setup_zip_works_with_standard_zip() {
    // Happy path: zip-crate-written file with correct local headers.
    let setup_content = b"fake Setup binary content";
    let token_content = b"fake-enrollment-token";
    let zip_bytes = build_zip(&[
        ("DeskRallySetup.exe", setup_content),
        ("DeskRallyAgent.msi", b"fake msi"),
        ("enrollment.token", token_content),
        ("README.txt", b"readme text"),
    ]);

    let setup_path = extract_setup_zip(&zip_bytes).expect("extraction must succeed");
    assert_eq!(
        setup_path.file_name().and_then(|s| s.to_str()),
        Some("DeskRallySetup.exe")
    );
    assert!(setup_path.exists());
    assert_eq!(std::fs::read(&setup_path).unwrap(), setup_content);
    let dir = setup_path.parent().unwrap();
    assert_eq!(std::fs::read(dir.join("enrollment.token")).unwrap(), token_content);
    let _ = std::fs::remove_dir_all(dir);
}

/// THE KEY REGRESSION TEST: Go's `archive/zip` writes streaming ZIPs (local headers have
/// zero sizes; sizes live in the central directory + data descriptors). The old local-header
/// parser produced empty files. `zip::ZipArchive` uses the central directory and must produce
/// the correct file contents.
#[test]
fn extract_setup_zip_works_with_go_style_streaming_zip() {
    let setup_content = b"DeskRallySetup-binary-data-goes-here";
    let msi_content = b"DeskRallyAgent-msi-data";
    let token_content = b"enrollment-token-value";

    let zip_bytes = build_streaming_zip(&[
        ("DeskRallySetup.exe", setup_content),
        ("DeskRallyAgent.msi", msi_content),
        ("enrollment.token", token_content),
        ("README.txt", b"readme"),
    ]);

    // Verify the fixture has zero local-header sizes (this is the bug-trigger).
    // Local header for entry 0 starts at offset 0; compressed_size is at bytes 18-21.
    let local_comp_size = u32::from_le_bytes([zip_bytes[18], zip_bytes[19], zip_bytes[20], zip_bytes[21]]);
    assert_eq!(
        local_comp_size, 0,
        "fixture must have zero local-header compressed size to reproduce the Go-format bug"
    );

    let setup_path = extract_setup_zip(&zip_bytes)
        .expect("extract_setup_zip must handle Go-style streaming ZIPs (central-directory sizes)");
    let dir = setup_path.parent().unwrap();

    assert_eq!(
        std::fs::read(&setup_path).unwrap(),
        setup_content,
        "DeskRallySetup.exe contents must be correct (not empty — old parser produced empty files here)"
    );
    assert_eq!(std::fs::read(dir.join("DeskRallyAgent.msi")).unwrap(), msi_content);
    assert_eq!(std::fs::read(dir.join("enrollment.token")).unwrap(), token_content);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn extract_setup_zip_fails_when_no_setup_exe_present() {
    let zip_bytes = build_zip(&[
        ("DeskRallyAgent.msi", b"msi data"),
        ("enrollment.token", b"tok"),
    ]);
    let err = extract_setup_zip(&zip_bytes)
        .expect_err("must fail when DeskRallySetup.exe is absent");
    assert!(
        err.contains("DeskRallySetup.exe"),
        "error must mention the missing file; got: {err}"
    );
}

#[test]
fn extract_setup_zip_fails_when_msi_missing() {
    // MSI is a required file — bundle without it is rejected.
    let zip_bytes = build_zip(&[
        ("DeskRallySetup.exe", b"setup"),
        ("enrollment.token", b"tok"),
        ("README.txt", b"read"),
    ]);
    let err = extract_setup_zip(&zip_bytes).expect_err("must fail when DeskRallyAgent.msi is absent");
    assert!(
        err.contains("DeskRallyAgent.msi"),
        "error must mention the missing MSI; got: {err}"
    );
}

#[test]
fn extract_setup_zip_fails_when_token_missing() {
    let zip_bytes = build_zip(&[
        ("DeskRallySetup.exe", b"setup"),
        ("DeskRallyAgent.msi", b"msi"),
        ("README.txt", b"read"),
    ]);
    let err = extract_setup_zip(&zip_bytes).expect_err("must fail when enrollment.token is absent");
    assert!(
        err.contains("enrollment.token"),
        "error must mention missing token; got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Allowlist enforcement — unexpected / dangerous names
// ---------------------------------------------------------------------------

#[test]
fn extract_setup_zip_rejects_path_traversal_dotdot() {
    // Any entry whose name contains ".." does not match the exact allowlist → rejected.
    let zip_bytes = build_zip(&[("../evil.txt", b"evil"), ("DeskRallySetup.exe", b"ok")]);
    let err = extract_setup_zip(&zip_bytes).expect_err("../evil.txt must be rejected");
    assert!(err.contains("unexpected entry"), "got: {err}");
}

#[test]
fn extract_setup_zip_rejects_absolute_path() {
    let zip_bytes = build_zip(&[("/etc/passwd", b"data"), ("DeskRallySetup.exe", b"ok")]);
    let err = extract_setup_zip(&zip_bytes).expect_err("/etc/passwd must be rejected");
    assert!(err.contains("unexpected entry"), "got: {err}");
}

#[test]
fn extract_setup_zip_rejects_drive_qualified_path() {
    // Windows drive-qualified paths are NOT on the allowlist → fail closed.
    let zip_bytes = build_zip(&[("C:\\evil.exe", b"data"), ("DeskRallySetup.exe", b"ok")]);
    let err = extract_setup_zip(&zip_bytes).expect_err("drive-qualified path must be rejected");
    assert!(err.contains("unexpected entry"), "got: {err}");
}

#[test]
fn extract_setup_zip_rejects_ads_colon() {
    // Alternate Data Stream names (file:stream) do not match any allowlisted name → rejected.
    let zip_bytes = build_zip(&[
        ("DeskRallySetup.exe:payload", b"ads"),
        ("DeskRallySetup.exe", b"ok"),
    ]);
    let err = extract_setup_zip(&zip_bytes).expect_err("ADS name must be rejected");
    assert!(err.contains("unexpected entry"), "got: {err}");
}

#[test]
fn extract_setup_zip_rejects_unexpected_filename() {
    // Any name not on the exact allowlist fails the entire extraction.
    let zip_bytes = build_zip(&[
        ("DeskRallySetup.exe", b"ok"),
        ("DeskRallyAgent.msi", b"msi"),
        ("enrollment.token", b"tok"),
        ("backdoor.dll", b"dll"),
    ]);
    let err = extract_setup_zip(&zip_bytes).expect_err("unexpected filename must be rejected");
    assert!(err.contains("unexpected entry"), "got: {err}");
}

#[test]
fn extract_setup_zip_handles_duplicate_entry_safely() {
    // The zip crate 2.x deduplicates entries at read time: a streaming ZIP with two entries
    // named "DeskRallySetup.exe" results in archive.len()=3 (unique names only), not 4. The
    // second occurrence's data wins. Extraction must be SAFE: no unsafe write outside the temp
    // dir, and required files that ARE present after deduplication are still extracted correctly.
    let zip_bytes = build_streaming_zip(&[
        ("DeskRallySetup.exe", b"first-version-overwritten"),
        ("DeskRallySetup.exe", b"second-wins"), // zip crate deduplicates — last wins
        ("DeskRallyAgent.msi", b"msi"),
        ("enrollment.token", b"tok"),
    ]);
    // The deduplication leaves only 3 unique entries; enrollment.token is present → Ok.
    match extract_setup_zip(&zip_bytes) {
        Ok(p) => {
            // Extraction succeeded: the surviving DeskRallySetup.exe content is determinate.
            let content = std::fs::read(&p).unwrap_or_default();
            // Must have SOME content (not empty — the old local-header parser produced empty files).
            assert!(!content.is_empty(), "DeskRallySetup.exe must not be empty after dedup");
            let _ = std::fs::remove_dir_all(p.parent().unwrap());
        }
        Err(_) => {
            // Also acceptable: any error is safe (fail-closed is always correct).
        }
    }
}

#[test]
fn extract_setup_zip_accepts_setup_exe_case_insensitively() {
    // The allowlist comparison is case-insensitive; the output file uses the canonical name.
    let zip_bytes = build_zip(&[
        ("deskrallysetup.exe", b"setup content"),
        ("deskrallyagent.msi", b"msi"),
        ("enrollment.token", b"tok"),
    ]);
    let setup_path = extract_setup_zip(&zip_bytes).expect("case-insensitive match must succeed");
    assert_eq!(
        setup_path.file_name().and_then(|s| s.to_str()),
        Some("DeskRallySetup.exe"),
        "output must use the canonical (uppercase) name"
    );
    let _ = std::fs::remove_dir_all(setup_path.parent().unwrap());
}

#[test]
fn extract_setup_zip_writes_under_canonical_name_not_raw_name() {
    // Even if the entry has a different case, the written file uses the allowlisted name.
    let zip_bytes = build_zip(&[
        ("DESKRALLYSETUP.EXE", b"setup"),
        ("DESKRALLYAGENT.MSI", b"msi"),
        ("ENROLLMENT.TOKEN", b"tok"),
    ]);
    let setup_path = extract_setup_zip(&zip_bytes).expect("must succeed");
    let dir = setup_path.parent().unwrap();
    // The canonical name must exist on disk.
    assert!(dir.join("DeskRallySetup.exe").exists());
    assert!(dir.join("DeskRallyAgent.msi").exists());
    assert!(dir.join("enrollment.token").exists());
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// installer_available + token-tracking (poller semantics, via AttendStatus)
// ---------------------------------------------------------------------------

#[test]
fn attend_status_installer_available_parses_from_json() {
    let body = r#"{"state":"active","promote":{"enrollment_token":"tok123","installer_available":true}}"#;
    let st = crate::attend::parse_attend_status(body).expect("parse must succeed");
    assert_eq!(st.promote_enrollment_token.as_deref(), Some("tok123"));
    assert!(st.installer_available, "installer_available must be true");
}

#[test]
fn attend_status_installer_available_defaults_false_when_absent() {
    let body = r#"{"state":"consented","promote":{"enrollment_token":"tok456"}}"#;
    let st = crate::attend::parse_attend_status(body).expect("parse must succeed");
    assert_eq!(st.promote_enrollment_token.as_deref(), Some("tok456"));
    assert!(!st.installer_available, "installer_available must default to false when absent");
}

#[test]
fn attend_status_no_promote_object_gives_empty_token_and_false() {
    let body = r#"{"state":"consented"}"#;
    let st = crate::attend::parse_attend_status(body).expect("parse must succeed");
    assert_eq!(st.promote_enrollment_token, None);
    assert!(!st.installer_available);
}

#[test]
fn extract_setup_zip_works_with_actual_go_handler_fixture() {
    // Read the fixture produced by TestWriteBundleProducesStreamingZIP (Go test in control-plane/).
    // This proves the real writeBundle streaming format (zip.NewWriter on a non-seekable writer →
    // data descriptors + central directory) is correctly handled by extract_setup_zip, not just
    // the hand-authored build_streaming_zip helper.
    //
    // Regenerate the fixture:
    //   go test -run TestWriteBundleProducesStreamingZIP ./control-plane/...
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/go_bundle_fixture.zip");
    let zip_bytes = std::fs::read(fixture_path)
        .expect("testdata/go_bundle_fixture.zip must exist — run the Go fixture test first");
    let setup_path = extract_setup_zip(&zip_bytes)
        .expect("extract_setup_zip must succeed on actual Go writeBundle output");
    let content = std::fs::read(&setup_path).unwrap_or_default();
    assert!(!content.is_empty(), "DeskRallySetup.exe must not be empty in Go fixture");
    let _ = std::fs::remove_dir_all(setup_path.parent().unwrap());
}

// ---------------------------------------------------------------------------
// Support-process exit path: installer observer lifetime contract
// ---------------------------------------------------------------------------

/// Verify the Arc-join pattern that prevents the Support process from exiting while a background
/// installer observer is still running. The JoinHandle returned by spawn_setup_waiter is pushed
/// into a shared Arc<Mutex<Vec<JoinHandle>>>, and run_attend_after_redeem drains and joins all
/// handles after serve_session returns but BEFORE returning to support_main (process::exit).
#[test]
fn pending_installer_waiter_is_joined_before_support_exits() {
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

    let completed = Arc::new(AtomicBool::new(false));
    let c = completed.clone();

    let handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        c.store(true, Ordering::SeqCst);
    });

    // Vec collects all observer handles; no single-Option overwrite risk.
    let pending: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(Mutex::new(vec![handle]));

    // Simulate run_attend_after_redeem's drain-and-join sequence.
    let waiters: Vec<_> = pending.lock().unwrap().drain(..).collect();
    for h in waiters {
        let _ = h.join();
    }

    assert!(
        completed.load(Ordering::SeqCst),
        "waiter must be joined (run to completion) before the support process exits"
    );
}

/// Verify that when no waiter was spawned the drain is a no-op — no blocking, no panic.
#[test]
fn pending_installer_waiter_no_op_when_empty() {
    use std::sync::{Arc, Mutex};

    let pending: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(Mutex::new(Vec::new()));

    let waiters: Vec<_> = pending.lock().unwrap().drain(..).collect();
    for h in waiters {
        let _ = h.join();
    }
    // Reaching here without panic confirms the empty-vec path is a safe no-op.
}

/// PollerGuard::drop signals stop, joins the real production poller, and drains installer
/// observers — covering the shutdown path taken by every early exit in run_attend_after_redeem
/// (runtime failure, missing transfer root, DXGI unavailability).
///
/// Uses `spawn_attend_status_poller` with stop pre-set so it exits without network calls.
/// A synthetic installer handle is pre-loaded into the pending Vec — simulating a promote
/// that completed just before the early return fires. The guard must drain and join it.
#[test]
fn early_return_guard_drop_drains_installer_observer() {
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

    let observer_ran = Arc::new(AtomicBool::new(false));
    let r = observer_ran.clone();

    // Pre-set stop: the real poller checks this at loop entry and exits without network I/O.
    let stop = Arc::new(AtomicBool::new(true));
    let pending: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(Mutex::new(Vec::new()));

    // Synthetic installer observer already in the Vec before the guard is created —
    // exactly as it would be if a promote completed before an early return fired.
    pending.lock().unwrap().push(std::thread::spawn(move || {
        r.store(true, Ordering::SeqCst);
    }));

    let handle = spawn_attend_status_poller(
        "http://localhost:1".to_string(),
        "tok".to_string(),
        stop.clone(),
        false,
        pending.clone(),
    );
    // Dropping the guard is the production early-return path: stop → join poller → drain Vec.
    drop(PollerGuard::new(stop, handle, pending));

    assert!(
        observer_ran.load(Ordering::SeqCst),
        "installer observer must be joined even when run_attend_after_redeem exits early"
    );
}

/// stop_during_status: should_dispatch_promote is the final admission gate before
/// run_attend_promote is entered. If stop has fired after the post-I/O check (a race between
/// status I/O returning and the session-end signal), no new install is started.
#[test]
fn stop_during_status_blocks_promote_dispatch() {
    use std::sync::atomic::AtomicBool;
    let stop = AtomicBool::new(true); // fired between I/O return and dispatch point
    assert!(
        !should_dispatch_promote(&stop, None, "tok1"),
        "stop fired — promote must not be dispatched even for a first-seen token"
    );
    assert!(
        !should_dispatch_promote(&stop, Some("tok0"), "tok1"),
        "stop fired — promote must not be dispatched even for a new token"
    );
}

/// Same-token deduplication: once a token has been accepted, re-seeing it must not re-prompt.
#[test]
fn same_token_blocks_promote_redispatch() {
    use std::sync::atomic::AtomicBool;
    let stop = AtomicBool::new(false);
    assert!(
        !should_dispatch_promote(&stop, Some("tok1"), "tok1"),
        "same token must not re-dispatch to avoid re-prompting the guest"
    );
}

/// New tokens are admitted when stop has not fired.
#[test]
fn new_token_admits_promote_when_not_stopped() {
    use std::sync::atomic::AtomicBool;
    let stop = AtomicBool::new(false);
    assert!(should_dispatch_promote(&stop, None, "tok1"));
    assert!(should_dispatch_promote(&stop, Some("tok1"), "tok2"));
}

/// Verify that successive promote requests each produce an observer that is joined — the Vec
/// collects all handles so no earlier one is silently overwritten by a later promote.
#[test]
fn multiple_pending_waiters_all_joined_before_process_exits() {
    use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

    let completed = Arc::new(AtomicUsize::new(0));
    let pending: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(Mutex::new(Vec::new()));

    for _ in 0..2 {
        let c = completed.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            c.fetch_add(1, Ordering::SeqCst);
        });
        pending.lock().unwrap().push(h);
    }

    let waiters: Vec<_> = pending.lock().unwrap().drain(..).collect();
    for w in waiters {
        let _ = w.join();
    }

    assert_eq!(
        completed.load(Ordering::SeqCst),
        2,
        "all pending installer observers must be joined — Vec must not overwrite earlier handles"
    );
}

// Security audit 2026-10-18: an unsigned DeskRallySetup.exe is refused before ShellExecuteExW — the
// promote flow never hands an unverified binary to UAC. The bytes are not an executable at all, so
// even a regression that skipped the check could not run anything; the assertion is on the refusal.
#[test]
fn launch_setup_exe_refuses_an_unsigned_setup() {
    let dir = std::env::temp_dir().join(format!("deskrally-promote-sig-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let setup = dir.join("DeskRallySetup.exe");
    std::fs::write(&setup, b"not a signed executable").unwrap();
    let result = super::launch_setup_exe(&setup);
    let _ = std::fs::remove_dir_all(&dir);
    match result {
        Err(super::SetupLaunchError::Failed(msg)) => {
            assert!(msg.contains("not signed by DeskRally's publisher"), "unexpected refusal: {msg}")
        }
        Err(super::SetupLaunchError::StillRunning(_)) => panic!("an unsigned Setup was launched"),
        Ok(code) => panic!("an unsigned Setup was launched (exit code {code})"),
    }
}

/// The POSITIVE control for the check above, on a real release: the production-signed
/// DeskRallySetup.exe a promote actually downloads must pass the SAME verifier `launch_setup_exe`
/// calls. Opt-in, because it needs that signed file: run before an agent release with
/// `RMT_TEST_SIGNED_SETUP=<path> cargo test -p rmt-agent-windows --lib -- --ignored a_production_signed_setup`.
/// It verifies only; it never launches Setup.
#[test]
#[ignore = "needs RMT_TEST_SIGNED_SETUP: the production-signed DeskRallySetup.exe"]
fn a_production_signed_setup_passes_the_promote_signature_check() {
    let path = std::env::var("RMT_TEST_SIGNED_SETUP").expect("set RMT_TEST_SIGNED_SETUP to the signed DeskRallySetup.exe");
    crate::update_download::verify_authenticode(std::path::Path::new(&path))
        .unwrap_or_else(|e| panic!("the production Setup failed the promote signature check: {e}"));
}
