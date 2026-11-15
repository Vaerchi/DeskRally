//! Build script for `rmt-agent-windows`.
//!
//! Give `DeskRallySupport.exe` VERSION and icon resources, linked into THAT binary only
//! (docs/27 step 9). `agent_host.exe` and `stream_probe.exe` receive the icon only — an unversioned
//! agent is fine, but a public download that shows a blank Description in the SmartScreen "More
//! info" panel and in file Properties is a trust signal working against us.
//!
//! It uses `embed-resource`, which compiles the generated `.rc` and links it through a `.lib` with a
//! forced-include symbol. That symbol is what makes `link.exe` MERGE the resource into the binary's
//! `.rsrc` directory: a bare `.res` on the link line (measured here) leaves the bytes in the file
//! but NOT in the resource directory, so `GetFileVersionInfo` reads nothing.
//!
//! The application MANIFEST (comctl32 v6 + PerMonitorV2, replacing rustc's minimal default) is a
//! second RT_MANIFEST that conflicts with the one rustc already embeds, which blanks the version
//! resource — so it is applied with `mt.exe` at packaging time (scripts/build-release.ps1), not
//! here. DPI awareness is set programmatically by `support_main` regardless.
//!
//! Best-effort: if the resource cannot be compiled, this warns and the build still succeeds.

fn main() {
    update_pin();
    dependent_load_flag();
    #[cfg(windows)]
    embed_support_resource();
}

/// docs/53 §3.1 step 4: resolve the shipped executables' static imports from System32 ONLY
/// (`LOAD_LIBRARY_SEARCH_SYSTEM32`). Both can run elevated from a folder the user can write (the
/// support client from Downloads, as the elevated input helper), and they import many DLLs that are
/// not KnownDLLs (bcrypt, dxgi, pdh, wtsapi32, …), which the default search would load from the
/// executable's own folder first. Verified in the built PE by scripts/build-release.ps1.
fn dependent_load_flag() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        for bin in ["agent_host", "deskrally_support"] {
            println!("cargo:rustc-link-arg-bin={bin}=/DEPENDENTLOADFLAG:0x800");
        }
    }
}

/// Update identity is opt-in: own feed, explicit official identity, or the lab feature.
fn update_pin() {
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    for v in ["DESKRALLY_UPDATE_OFFICIAL", "DESKRALLY_UPDATE_FEED", "DESKRALLY_UPDATE_PUBKEY_FILE", "DESKRALLY_UPDATE_PUBLISHER"] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    let official = match std::env::var("DESKRALLY_UPDATE_OFFICIAL") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(_) => panic!("DESKRALLY_UPDATE_OFFICIAL must be exactly 1 or empty"),
    };
    if !official.is_empty() && official != "1" {
        panic!("DESKRALLY_UPDATE_OFFICIAL must be exactly 1 or empty");
    }
    let test = std::env::var_os("CARGO_FEATURE_UPDATE_TEST_FEED").is_some();
    let mut feed = std::env::var("DESKRALLY_UPDATE_FEED").unwrap_or_default();
    let mut key_file = std::env::var("DESKRALLY_UPDATE_PUBKEY_FILE").unwrap_or_default();
    let mut publisher = std::env::var("DESKRALLY_UPDATE_PUBLISHER").unwrap_or_default();
    let set = [&feed, &key_file, &publisher].iter().filter(|v| !v.is_empty()).count();
    if official == "1" && (set != 0 || test) {
        panic!("DESKRALLY_UPDATE_OFFICIAL cannot be combined with own-feed variables or update-test-feed");
    }
    if set != 0 && (set != 3 || test) {
        panic!("DESKRALLY_UPDATE_FEED, DESKRALLY_UPDATE_PUBKEY_FILE and DESKRALLY_UPDATE_PUBLISHER must be set together, without update-test-feed");
    }
    let packaging = manifest_dir.join("../../packaging");
    let identity_path = packaging.join("official-update-identity.json");
    let official_key = packaging.join("update-signer-pubkey.hex");
    println!("cargo:rerun-if-changed={}", identity_path.display());
    println!("cargo:rerun-if-changed={}", official_key.display());
    if official == "1" {
        let text = std::fs::read_to_string(&identity_path)
            .unwrap_or_else(|e| panic!("{}: {e}", identity_path.display()));
        let identity: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", identity_path.display()));
        feed = identity["feed"].as_str().expect("official identity requires a feed string").to_owned();
        publisher = identity["publisher"].as_str().expect("official identity requires a publisher string").to_owned();
        key_file = official_key.to_string_lossy().into_owned();
    }
    if official == "1" || set == 3 {
        let host = feed.strip_prefix("https://").unwrap_or("");
        if host.is_empty() || host.contains('/') || host.contains('@') || host.contains('?') || host.contains('#') || host.contains('\\') || host.chars().any(char::is_whitespace) {
            panic!("update feed must be exactly https://<host[:port]> (got {feed:?})");
        }
        if publisher.is_empty() || publisher.contains(['\r', '\n']) {
            panic!("update publisher must be a non-empty single line");
        }
        println!("cargo:rerun-if-changed={key_file}");
        let pin = std::fs::read_to_string(&key_file)
            .unwrap_or_else(|e| panic!("{key_file}: {e}"))
            .trim().to_owned();
        validate_update_pin(&pin, &key_file);
        println!("cargo:rustc-env=DESKRALLY_UPDATE_PIN={pin}");
        println!("cargo:rustc-env=DESKRALLY_UPDATE_FEED_OVERRIDE={feed}");
        println!("cargo:rustc-env=DESKRALLY_UPDATE_PUBLISHER={publisher}");
    } else if test {
        // Preserve the lab feature's publisher and optional test pin exactly as before.
        let path = packaging.join("update-signer-pubkey.test.hex");
        println!("cargo:rerun-if-changed={}", path.display());
        let pin = match std::fs::read_to_string(&path) {
            Ok(text) => {
                let pin = text.trim().to_owned();
                validate_update_pin(&pin, &path.to_string_lossy());
                pin
            }
            Err(_) => String::new(),
        };
        println!("cargo:rustc-env=DESKRALLY_UPDATE_PIN={pin}");
        println!("cargo:rustc-env=DESKRALLY_UPDATE_FEED_OVERRIDE=");
        println!("cargo:rustc-env=DESKRALLY_UPDATE_PUBLISHER=CN=Edgar Nuckols, O=Edgar Nuckols, L=Orlando, S=fl, C=US");
    } else {
        println!("cargo:rustc-env=DESKRALLY_UPDATE_PIN=");
        println!("cargo:rustc-env=DESKRALLY_UPDATE_FEED_OVERRIDE=");
        println!("cargo:rustc-env=DESKRALLY_UPDATE_PUBLISHER=");
    }
}

fn validate_update_pin(pin: &str, path: &str) {
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        panic!("{path} must hold exactly 64 lowercase hex characters");
    }
}

#[cfg(windows)]
fn embed_support_resource() {
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resources/deskrally.ico");
    let icon = manifest_dir.join("resources/deskrally.ico").to_string_lossy().replace('\\', "/");

    // Installed helpers use the same session window. agent_host ALSO carries a VERSIONINFO whose
    // numeric FILEVERSION is the agent semver: Windows Installer compares file VERSIONS, so a normal
    // repair with an older MSI does not overwrite a newer auto-updated agent_host.exe (auto-update
    // bootstrap design, C6/R1). Packaging must assert it merged (see the MSVC 14.50 note above).
    let (amaj, amin, apat) = (
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap_or_else(|_| "0".into()),
        std::env::var("CARGO_PKG_VERSION_MINOR").unwrap_or_else(|_| "0".into()),
        std::env::var("CARGO_PKG_VERSION_PATCH").unwrap_or_else(|_| "0".into()),
    );
    let agent_rc = out_dir.join("deskrally_agent_icon.rc");
    let agent_rc_text = format!(
        r#"LANGUAGE 0x09, 0x01

101 ICON "{icon}"

1 VERSIONINFO
 FILEVERSION {amaj},{amin},{apat},0
 PRODUCTVERSION {amaj},{amin},{apat},0
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS 0x40004L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "Aeretek"
            VALUE "FileDescription", "DeskRally Remote Agent"
            VALUE "FileVersion", "{amaj}.{amin}.{apat}.0"
            VALUE "ProductName", "DeskRally Remote Agent"
            VALUE "ProductVersion", "{amaj}.{amin}.{apat}.0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );
    match std::fs::write(&agent_rc, agent_rc_text) {
        Ok(()) => {
            let result = embed_resource::compile_for(&agent_rc, ["agent_host", "stream_probe"], embed_resource::NONE);
            if let Err(e) = result.manifest_optional() {
                println!("cargo:warning=agent icon resource not embedded ({e})");
            }
        }
        Err(e) => println!("cargo:warning=could not write agent icon resource: {e}"),
    }

    let major = std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap_or_else(|_| "0".into());
    let minor = std::env::var("CARGO_PKG_VERSION_MINOR").unwrap_or_else(|_| "0".into());
    let patch = std::env::var("CARGO_PKG_VERSION_PATCH").unwrap_or_else(|_| "0".into());
    let ver_commas = format!("{major},{minor},{patch},0");
    let ver_str = format!("{major}.{minor}.{patch}.0");
    // VERSIONINFO uses numeric ID 1: without winver.h, VS_VERSION_INFO would be a string name
    // that Windows file properties cannot find. Icon ID 101 is loaded by the support windows.
    // LANGUAGE must match the StringFileInfo block key (040904b0 = US English) or .NET's
    // FileVersionInfo reads the wrong language block and returns empty strings.
    let rc = format!(
        r#"LANGUAGE 0x09, 0x01

101 ICON "{icon}"

1 VERSIONINFO
 FILEVERSION {ver_commas}
 PRODUCTVERSION {ver_commas}
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS 0x40004L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "Aeretek"
            VALUE "FileDescription", "DeskRally Support"
            VALUE "FileVersion", "{ver_str}"
            VALUE "InternalName", "DeskRallySupport"
            VALUE "OriginalFilename", "DeskRallySupport.exe"
            VALUE "ProductName", "DeskRally Support"
            VALUE "ProductVersion", "{ver_str}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );

    let rc_path = out_dir.join("deskrally_support.rc");
    if let Err(e) = std::fs::write(&rc_path, rc) {
        println!("cargo:warning=could not write the support version resource: {e}");
        return;
    }

    // Link into the support binary ONLY. A failure (no resource compiler) is a warning, not a break.
    let result = embed_resource::compile_for(&rc_path, ["deskrally_support"], embed_resource::NONE);
    if let Err(e) = result.manifest_optional() {
        println!("cargo:warning=support version resource not embedded ({e}); the exe will have a blank Description until built where a resource compiler is available");
    }
}
