//! First-run enrollment (M3): redeem an enrollment token for a **server-minted** identity.
//!
//! Before M3 the agent invented its own `device_id`. That is exactly the wrong shape: a device id
//! is what a session ticket authorizes the signaling server to broker to, and what
//! `register_agent` claims. So the control plane now mints it, at `POST /enroll/redeem`, and pins
//! the agent's Ed25519 public key against it (`control-plane/http.go handleRedeemEnrollment`,
//! migrations 0007/0008). This module is the agent half of that exchange.
//!
//! ## Order of operations
//!
//! The identity key is written **before** the config. A crash between the two leaves a key with no
//! device id (harmless — the next run enrolls again and pins the same key), never a device id whose
//! private key was lost (unrecoverable: the machine could never authenticate and would need
//! re-enrollment by hand).
//!
//! ## Blocking I/O
//!
//! [`enroll_once`] uses a blocking HTTP client and must NOT be called from inside a tokio runtime.
//! Both callers respect that: the `enroll` subcommand has no runtime, and the helper enrolls before
//! it builds one.

use std::io::Write as _;
use std::time::Duration;

use rmt_crypto::Identity;

use crate::config::HelperConfig;

/// Path appended to `control_plane_url` for redemption. Public + unauthenticated: the enrollment
/// token itself is the authorization.
pub const REDEEM_PATH: &str = "/enroll/redeem";

/// Whole-request budget for the redemption call. Generous — this runs once per machine, often over
/// a slow first-boot network — but bounded, so a black-holed control plane cannot wedge the helper
/// before it reaches its capture loop.
const REDEEM_TIMEOUT: Duration = Duration::from_secs(20);

/// What redemption hands back: the identity the control plane assigned to this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledIdentity {
    /// Server-minted, globally unique device id (migration 0008).
    pub device_id: String,
    /// Tenant the redeemed token belonged to. Bound into the `RMTAGENTAUTHv1` preimage.
    pub tenant_id: String,
    /// docs/65 D-C3: the control plane's directive public key from the redeem response (`directive_pubkey`, top level, present only
    /// when the control plane has directives enabled). Pinned into the config set-if-blank by [`apply_enrollment`]; `None` when absent.
    pub directive_pubkey: Option<String>,
}

/// True when this agent is control-plane managed, has an enrollment token, and has not yet been
/// assigned a device id. An agent that already holds a device id **never** re-enrolls: doing so
/// would burn a token use and orphan the previous machine row.
pub fn needs_enrollment(cfg: &HelperConfig) -> bool {
    cfg.is_control_plane_managed()
        && cfg.device_id.as_deref().is_none_or(|s| s.trim().is_empty())
        && cfg.enrollment_token.as_deref().is_some_and(|s| !s.trim().is_empty())
}

/// Validate a control-plane base URL for enrollment.
///
/// TLS is mandatory: the enrollment token is a bearer secret and the response carries the identity
/// this machine will be known by. The single exception is a loopback host, which is what the
/// local-development control plane runs on; it returns `Ok(true)` so the caller can log a warning.
/// Certificate validation is never disabled (there is no `danger_accept_invalid_certs` anywhere in
/// this crate, deliberately).
pub fn validate_control_plane_url(url: &str) -> Result<bool, String> {
    // Use the HTTP client's parser, and refuse inputs it would silently normalize.
    if url.chars().any(|c| c.is_control() || c == '\\') {
        return Err("control_plane_url contains a control character or backslash".into());
    }
    let url = url.trim();
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| "control_plane_url is not a valid absolute URL".to_string())?;
    if parsed.host_str().is_none() || !parsed.username().is_empty()
        || parsed.password().is_some() || parsed.query().is_some() || parsed.fragment().is_some()
    {
        return Err("control_plane_url requires a host and must not contain credentials, query or fragment".into());
    }
    match parsed.scheme() {
        "https" => Ok(false),
        "http" if matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) => Ok(true),
        _ => Err("control_plane_url requires HTTPS (HTTP is allowed only for loopback)".into()),
    }
}

/// Join a control-plane base URL with [`REDEEM_PATH`], tolerating a trailing slash.
pub fn redeem_url(base: &str) -> String {
    format!("{}{REDEEM_PATH}", base.trim().trim_end_matches('/'))
}

/// Parse a `201` redemption body and assert it describes *our* key.
///
/// `our_pubkey` is this agent's own hex public key. A control plane that answers with a different
/// pinned key has mis-provisioned us (or we are talking to the wrong one), and continuing would
/// leave the agent permanently unable to authenticate — so this is an abort, not a warning. The
/// comparison is case-insensitive because hex case is not semantic.
pub fn parse_redeem_response(body: &str, our_pubkey: &str) -> Result<EnrolledIdentity, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("redeem response is not JSON: {e}"))?;
    let m = v
        .get("machine")
        .ok_or_else(|| "redeem response has no \"machine\" object".to_string())?;

    let field = |name: &str| -> Result<String, String> {
        m.get(name)
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("redeem response machine.{name} is missing or empty"))
    };

    let device_id = field("device_id")?;
    let tenant_id = field("tenant_id")?;
    let pinned = field("pubkey")?;
    if !pinned.eq_ignore_ascii_case(our_pubkey) {
        return Err(format!(
            "control plane pinned pubkey {pinned} for this machine but our identity is {our_pubkey} \
             — refusing to enroll against a key we cannot sign with"
        ));
    }
    let directive_pubkey = v
        .get("directive_pubkey")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty());
    Ok(EnrolledIdentity { device_id, tenant_id, directive_pubkey })
}

/// Load the Ed25519 identity seed at `path`, or generate + persist a fresh one.
///
/// Returns `(identity, generated)`. A freshly generated key is written (and ACL-tightened) before
/// this returns, so the caller can rely on it being on disk.
pub fn load_or_generate_identity(path: &str) -> Result<(Identity, bool), String> {
    if let Some(id) = read_identity(path)? {
        return Ok((id, false));
    }
    let id = Identity::generate();
    write_identity(path, &id)?;
    Ok((id, true))
}

/// Read the identity seed at `path`. `Ok(None)` when the file does not exist; `Err` when it exists
/// but is unreadable or malformed — a corrupt key file must be loud, because silently replacing it
/// would orphan the enrolled `machine.pubkey` and make the agent unauthenticatable.
pub fn read_identity(path: &str) -> Result<Option<Identity>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read identity key {path}: {e}")),
    };
    let seed = decode_identity_seed(&raw)
        .ok_or_else(|| format!("identity key {path} is not 64 hex chars (32-byte Ed25519 seed)"))?;
    Ok(Some(Identity::from_seed(&seed)))
}

/// Decode the on-disk identity representation: 64 hex chars, tolerating surrounding whitespace and
/// a stray UTF-8 BOM (PowerShell's `Set-Content -Encoding utf8` writes one).
fn decode_identity_seed(raw: &str) -> Option<[u8; 32]> {
    let s = raw.strip_prefix('\u{feff}').unwrap_or(raw).trim();
    hex::decode(s).ok()?.try_into().ok()
}

/// Persist an identity as 64 lowercase hex chars (no BOM, no trailing newline) and tighten its ACL.
pub fn write_identity(path: &str, id: &Identity) -> Result<(), String> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let seed = id.seed();
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("could not create identity key {path}: {e}"))?;
    f.write_all(hex::encode(seed).as_bytes())
        .map_err(|e| format!("could not write identity key {path}: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("could not flush identity key {path}: {e}"))?;
    drop(f);
    tighten_identity_acl(path);
    Ok(())
}

/// Restrict the identity key to SYSTEM + Administrators, dropping inherited access.
///
/// Done here rather than in the installer on purpose: the installer is regenerated by
/// `scripts/build-release.ps1` and an image-based deployment may never run it, but every path that
/// writes a private key goes through [`write_identity`]. A failure is logged **loudly** — a
/// world-readable agent private key is a full compromise of this machine's identity — but is not
/// fatal, because refusing to run would leave the machine unmanaged as well as insecure.
fn tighten_identity_acl(path: &str) {
    // Three icacls steps, all built by `crate::agent_root` so the SIDs and flags live in ONE place.
    // Loop 91 moved this function onto them after MEASURING that the previous single-command version
    // left the agent's Ed25519 private key readable by every authenticated user in two ways:
    //
    //  1. **A planted explicit ACE survived.** `icacls /grant:r` replaces only the NAMED principal's
    //     ACE and is additive with respect to every other. Measured: a file carrying an explicit
    //     `Authenticated Users:(F)` came out of the old `/inheritance:r /grant:r SYSTEM /grant:r
    //     Administrators` argv reading `Administrators:(F) SYSTEM:(F) Authenticated Users:(F)` — the
    //     lockdown reported success and the key stayed world-readable. It is reachable because
    //     `write_identity` uses `File::create`, i.e. `CREATE_ALWAYS`, which TRUNCATES a pre-existing
    //     file rather than replacing it: the security descriptor a standard user put on a pre-created
    //     `identity.key` survives the key being written into it (measured). `/reset` first drops it.
    //  2. **The OWNER was never reset.** A file's owner keeps implicit `WRITE_DAC` whatever the DACL
    //     says, and Bypass Traverse Checking (granted to Everyone) lets that owner reopen the file by
    //     full path under a locked parent — so the same pre-creator could re-grant itself read AFTER
    //     this ran. The identical defect loop 90 fixed on `config.json`; this is its private-key
    //     instance, and the stake is higher: `config.json` decides which grants are honoured, the key
    //     IS the machine's identity.
    //
    // `/setowner` is BEST-EFFORT on purpose, and that is exactly what preserves the dev path below:
    // only an elevated caller can hand a file's ownership to `Administrators`, so on the SYSTEM /
    // elevated install — the one path where a hostile pre-creator's ownership is an escalation — it
    // succeeds, and on a non-elevated `enroll` it fails harmlessly, leaving the developer owning the
    // key they just wrote and reading it back through the owner grant further down.
    let p = std::path::Path::new(path);
    let _ = crate::agent_root::run_icacls(&crate::agent_root::setowner_args(p));
    if !matches!(crate::agent_root::run_icacls(&crate::agent_root::reset_args(p)), Ok(true)) {
        tracing::error!(
            path,
            "enroll: could not RESET the identity key ACL — an explicit ACE planted by a prior owner \
             may survive the lockdown below, leaving the agent private key readable"
        );
    }

    // SYSTEM + Administrators get full control, BY SID. `icacls` resolves an account NAME through the
    // machine LOCALE, and an unresolvable name makes it abort the WHOLE command and apply NOTHING —
    // measured: exit 1332, "No mapping between account names and security IDs was done", and the DACL
    // untouched, not even the `/inheritance:r` that preceded it in argv. So under the old name-based
    // argv this function did nothing at all on every French / German / Japanese Windows and merely
    // `tracing::error!`d about it, leaving the private key with its inherited `Authenticated
    // Users:(M)`. A fleet ships to every locale; a security control must not depend on a display name.
    //
    // We ALSO grant the current owner (the account that created the key) read access: an installer
    // enrolls as SYSTEM/elevated (already covered above), but a non-elevated `enroll` — a dev run, or
    // a per-user deploy — must still be able to read back the key it just wrote, and `/inheritance:r`
    // strips the inherited grant that used to make that work by accident. Granting only the *owner*
    // does not widen access to other unprivileged users, which is the entire point of the lockdown.
    // The filter matters: `/grant:r` is last-writer-wins per principal, so re-granting SYSTEM
    // (S-1-5-18) here as (R) would REPLACE its (F) ACE — harmless in effect (a LocalSystem token also
    // carries Administrators) but a confusing DACL to find on a private key.
    let owner_sid = current_user_sid().filter(|sid| !is_already_granted_full(sid));
    let args = crate::agent_root::file_dacl_args(p, owner_sid.as_deref());
    match crate::agent_root::run_icacls(&args) {
        Ok(true) => {
            tracing::info!(
                path,
                owner_granted = owner_sid.is_some(),
                "enroll: identity key ACL restricted to SYSTEM + Administrators (+ owner)"
            );
        }
        Ok(false) => tracing::error!(
            path,
            "enroll: FAILED to restrict the identity key ACL — the agent private key may be readable \
             by unprivileged users on this machine"
        ),
        Err(e) => tracing::error!(
            path,
            error = %e,
            "enroll: could not run icacls to restrict the identity key ACL — the agent private key \
             may be readable by unprivileged users on this machine"
        ),
    }
}

/// Best-effort current-user SID via `whoami /user`, so [`tighten_identity_acl`] can grant the key's
/// creating owner read access. Returns `None` on any failure — the ACL is then simply
/// SYSTEM + Administrators, never *less* strict than before.
fn current_user_sid() -> Option<String> {
    // Absolute, for the reason `agent_root::run_icacls` gives: a bare name resolves through the
    // calling executable's own directory first, and this can run from the service.
    let out = std::process::Command::new(crate::agent_root::system32_exe("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // One CSV row: "domain\user","S-1-5-21-…". Take the last quoted field and keep it only if it
    // looks like a SID, so an unexpected/localized format falls back to None rather than handing
    // garbage to icacls.
    let sid = text
        .lines()
        .find(|l| !l.trim().is_empty())?
        .rsplit(',')
        .next()?
        .trim()
        .trim_matches('"')
        .to_string();
    sid.starts_with("S-1-").then_some(sid)
}

/// Whether `sid` is a well-known principal already granted Full Control by [`tighten_identity_acl`]
/// (SYSTEM, or the BUILTIN\Administrators group). Re-granting one of these as the "owner" would only
/// add a redundant — and, under icacls last-writer-wins, downgraded — ACE to a private key's DACL.
fn is_already_granted_full(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544")
}

/// This machine's name, for the `machine.name` column. Best-effort: a blank name is accepted by the
/// control plane and is not worth failing enrollment over.
fn machine_name(override_name: Option<&str>) -> String {
    match override_name.map(str::trim).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => std::env::var("COMPUTERNAME").unwrap_or_default(),
    }
}

/// Compose the human-readable OS description stored as `machine.os`, from the three
/// `CurrentVersion` registry values. Split out from [`os_description`] so the (surprisingly fiddly)
/// formatting rules are unit-testable without a registry.
///
/// **`ProductName` lies on Windows 11**: Microsoft left it reading `Windows 10 …` on 11, so the
/// build number is the only reliable discriminator — 22000 is the first Windows 11 build. Reporting
/// a fleet of Windows 11 machines as "Windows 10" is exactly the kind of quietly-wrong inventory
/// data an operator would act on.
fn compose_os_description(product: &str, display_version: &str, build: &str) -> String {
    let product = product.trim();
    let display_version = display_version.trim();
    let build = build.trim();

    let corrected = match build.parse::<u32>() {
        Ok(n) if n >= 22000 && product.starts_with("Windows 10") => {
            product.replacen("Windows 10", "Windows 11", 1)
        }
        _ => product.to_string(),
    };

    let mut out = corrected;
    if !display_version.is_empty() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(display_version);
    }
    if !build.is_empty() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("(build {build})"));
    }

    // The control plane rejects an `os` longer than 255 BYTES with a 400, and enrollment treats any
    // non-2xx as fatal — so an oversized value here would not degrade the display field, it would
    // make the machine permanently unable to enroll. These strings come from the registry, which a
    // vendor image or a tampered key can make arbitrarily long, so clamp rather than trust it.
    // Truncation is on a CHAR boundary: `String::truncate` panics mid-codepoint, and a multi-byte
    // product name is entirely possible on a localized install.
    const MAX_OS_BYTES: usize = 255;
    if out.len() > MAX_OS_BYTES {
        let cut = (0..=MAX_OS_BYTES)
            .rev()
            .find(|&i| out.is_char_boundary(i))
            .unwrap_or(0);
        out.truncate(cut);
    }
    out
}

/// Read one REG_SZ value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
/// Best-effort: any failure yields an empty string, exactly like [`machine_name`] — a blank `os` is
/// accepted by the control plane and is never worth failing an enrollment over.
#[cfg(windows)]
fn current_version_value(name: &str) -> String {
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let value = HSTRING::from(name);
    let mut buf = [0u16; 256];
    let mut size = (buf.len() * std::mem::size_of::<u16>()) as u32;

    // SAFETY: `buf`/`size` describe one owned stack buffer; RegGetValueW writes at most `size`
    // bytes into it and updates `size`. Both key path and value name are NUL-terminated UTF-16.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return String::new();
    }
    // `size` is in BYTES and includes the terminating NUL.
    let chars = (size as usize / std::mem::size_of::<u16>()).saturating_sub(1);
    String::from_utf16_lossy(&buf[..chars.min(buf.len())])
}

#[cfg(not(windows))]
fn current_version_value(_name: &str) -> String {
    String::new()
}

/// This machine's OS description, for the `machine.os` column (e.g.
/// `"Windows 11 Pro 25H2 (build 26200)"`). Best-effort, like [`machine_name`].
///
/// Public so `tests/enroll_wire.rs` can re-derive the expected value through the SAME entry point
/// the enrollment body calls and require the wire `os` to equal it — the assertion that catches an
/// ad-hoc string assembled at the call site. It reads three registry values and composes a display
/// string; nothing about it needs hiding.
pub fn os_description() -> String {
    compose_os_description(
        &current_version_value("ProductName"),
        &current_version_value("DisplayVersion"),
        &current_version_value("CurrentBuildNumber"),
    )
}

/// Redeem `cfg.enrollment_token` against `cfg.control_plane_url` exactly once and persist the
/// result to `config_path`. `name` overrides the machine name reported to the control plane
/// (`None` ⇒ `%COMPUTERNAME%`).
///
/// On success the config has `device_id` + `tenant_id` set and `enrollment_token` **cleared** (it is
/// a single-use secret and must not linger on disk). Never falls back to a self-invented device id:
/// an agent that cannot enroll stays unenrolled and visible in the log.
pub fn enroll_once(
    cfg: &mut HelperConfig,
    config_path: &str,
    name: Option<&str>,
) -> Result<EnrolledIdentity, String> {
    let base = cfg
        .control_plane_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "enroll: no control_plane_url configured".to_string())?
        .to_string();
    let token = cfg
        .enrollment_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "enroll: no enrollment_token configured".to_string())?
        .to_string();

    if validate_control_plane_url(&base)? {
        tracing::warn!(
            url = %base,
            "enroll: using plaintext http:// to a loopback control plane — development only"
        );
    }

    // Key first (see the module docs on ordering).
    let identity_path = cfg.identity_path_or_default();
    let (identity, generated) = load_or_generate_identity(&identity_path)?;
    let pubkey = identity.public_hex();
    tracing::info!(path = %identity_path, generated, pubkey = %pubkey, "enroll: agent identity ready");

    let client = reqwest::blocking::Client::builder()
        // OS store UNION bundled public roots — native-only failed enrollment on a fresh machine.
        .use_preconfigured_tls(rmt_transport_webrtc::tls_trust::client_config()?)
        .timeout(REDEEM_TIMEOUT)
        .build()
        .map_err(|e| format!("enroll: could not build HTTP client: {e}"))?;
    // `device_id` is deliberately absent from the body: the field is deprecated and ignored
    // server-side precisely so a redeemer cannot choose which device a ticket authorizes.
    let body = serde_json::json!({
        "token": token,
        "pubkey": pubkey,
        "name": machine_name(name),
        // `machine.os` (migrations/0017). The column existed and was READ by the console from the
        // day it was added, but nothing ever populated it — the agent never sent an `os` and
        // neither enroll handler set one, so every enrolled machine displayed a blank OS.
        "os": os_description(),
        // The agent's local floor flag (machine.require_session_policy, migrations/0037). Sent so
        // the control plane knows, from the very first session, that this agent opens VIEW-ONLY
        // until a signed policy verifies — and therefore that it must mint one even when the
        // machine's group has no view-only mandate. Without it a freshly-installed enforcing agent
        // is stranded view-only forever, with nothing on screen explaining why.
        //
        // ALWAYS sent, including `false`, matching the register_agent refresh: the control plane
        // distinguishes "reported false" from "said nothing", and only the first may clear a stored
        // flag. Enrollment reads the config that is ALREADY on disk, so an operator who sets the
        // flag after enrolling is covered by that refresh, not by this line.
        "require_session_policy": cfg.require_session_policy,
    });
    let resp = client
        .post(redeem_url(&base))
        .json(&body)
        .send()
        .map_err(|e| format!("enroll: POST {}{REDEEM_PATH} failed: {e}", base))?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("enroll: control plane returned {status}: {}", text.trim()));
    }

    let enrolled = parse_redeem_response(&text, &pubkey)?;
    apply_enrollment(cfg, &enrolled);
    cfg.save_to(config_path)
        .map_err(|e| format!("enroll: could not persist config {config_path}: {e}"))?;
    // Harden the agent root so the config we just wrote is not left world-writable on the
    // MSI / manual-enroll path, where the service may not start until later. Scoped to the REAL
    // config dir: an e2e that enrolls into a temp dir (and may run non-elevated) must be left alone,
    // or hardening it to SYSTEM+Administrators would lock the test's own process out. On the real
    // path this only brings the DACL forward from the next service start. Loud, not fatal.
    if std::path::Path::new(config_path).parent()
        == Some(std::path::Path::new(crate::config::CONFIG_DIR))
    {
        if let Err(e) =
            crate::agent_root::harden_agent_root(std::path::Path::new(crate::config::CONFIG_DIR))
        {
            tracing::error!(error = %e, "enroll: could not harden the agent root after writing config");
        }
    }
    tracing::info!(
        device_id = %enrolled.device_id,
        tenant_id = %enrolled.tenant_id,
        "enroll: enrolled; enrollment token cleared from config"
    );
    Ok(enrolled)
}

/// Fold a redemption result into the config: record the identity, drop the spent token.
/// Split out from [`enroll_once`] so the state transition is testable without a control plane.
pub fn apply_enrollment(cfg: &mut HelperConfig, enrolled: &EnrolledIdentity) {
    cfg.device_id = Some(enrolled.device_id.clone());
    cfg.tenant_id = Some(enrolled.tenant_id.clone());
    cfg.enrollment_token = None;
    if let Some(key) = enrolled.directive_pubkey.as_deref() {
        // Set-if-blank, dedicated-key rule: a malformed or shared key leaves the agent without a pin (it then refuses every
        // directive), which is the safe failure; enrollment itself must not fail over it.
        match crate::directive_pin::pin_into_config(cfg, key) {
            Ok(outcome) => tracing::info!(?outcome, "enroll: directive public key"),
            Err(e) => tracing::warn!(error = %e, "enroll: the control plane's directive key was not pinned; directives will be refused"),
        }
    }
}

/// Adapts the agent's long-term [`Identity`] to the transport's signing seam, so
/// `rmt-transport-webrtc` needs no key material and no crypto dependency.
pub struct IdentitySigner {
    identity: Identity,
}

impl IdentitySigner {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }
}

impl rmt_transport_webrtc::ChallengeSigner for IdentitySigner {
    fn sign(&self, preimage: &[u8]) -> [u8; 64] {
        self.identity.sign(preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_transport_webrtc::ChallengeSigner as _;

    #[test]
    fn os_description_corrects_the_windows_11_product_name_lie() {
        // Windows 11 leaves ProductName reading "Windows 10 …"; build >= 22000 is the only reliable
        // discriminator. Getting this wrong reports an entire Win11 fleet as Windows 10.
        assert_eq!(
            compose_os_description("Windows 10 Pro", "25H2", "26200"),
            "Windows 11 Pro 25H2 (build 26200)"
        );
        // A genuine Windows 10 build is left alone.
        assert_eq!(
            compose_os_description("Windows 10 Pro", "22H2", "19045"),
            "Windows 10 Pro 22H2 (build 19045)"
        );
        // Exact boundary: 22000 IS Windows 11.
        assert_eq!(
            compose_os_description("Windows 10 Home", "21H2", "22000"),
            "Windows 11 Home 21H2 (build 22000)"
        );
        // Only the leading occurrence is rewritten, and a name that already says 11 is untouched.
        assert_eq!(
            compose_os_description("Windows 11 Enterprise", "25H2", "26200"),
            "Windows 11 Enterprise 25H2 (build 26200)"
        );
    }

    #[test]
    fn os_description_is_best_effort_with_missing_pieces() {
        // Every registry read is best-effort, so any subset can be empty. None of these may panic
        // or emit stray separators — the value is displayed verbatim in the console.
        assert_eq!(compose_os_description("", "", ""), "");
        assert_eq!(compose_os_description("Windows Server 2022", "", ""), "Windows Server 2022");
        assert_eq!(compose_os_description("", "", "26200"), "(build 26200)");
        assert_eq!(compose_os_description("  Windows 10 Pro  ", " 25H2 ", " 26200 "), "Windows 11 Pro 25H2 (build 26200)");
        // A non-numeric build cannot be compared, so the product name is passed through unchanged
        // rather than guessed at.
        assert_eq!(compose_os_description("Windows 10 Pro", "", "abc"), "Windows 10 Pro (build abc)");
    }

    #[test]
    fn os_description_is_clamped_to_the_servers_byte_bound() {
        // The control plane 400s an `os` over 255 bytes and enrollment treats a non-2xx as fatal, so
        // an over-long registry value must NOT be allowed to make the machine unenrollable.
        let huge = "X".repeat(400);
        let out = compose_os_description(&huge, "25H2", "26200");
        assert!(out.len() <= 255, "composed os is {} bytes, want <= 255", out.len());
    }

    #[test]
    fn os_description_truncation_never_splits_a_codepoint() {
        // A localized product name is multi-byte; truncating mid-codepoint would panic in
        // String::truncate and take enrollment down with it.
        let multi = "日本語版ウィンドウズ".repeat(40); // 3 bytes per char
        let out = compose_os_description(&multi, "", "");
        assert!(out.len() <= 255);
        // The result must still be valid UTF-8 that round-trips (it is a String, so the real
        // assertion is that we got here without panicking) and must not end mid-character.
        assert!(out.chars().count() * 3 >= out.len());
    }

    #[test]
    fn os_description_wires_all_three_registry_values_through() {
        // The one seam no other layer can see. The wire test's equality assert
        // (tests/enroll_wire.rs) derives its expected value from os_description() ITSELF, so any
        // break inside this function is symmetric there — equal and wrong; and the compose_*
        // tests above feed explicit literals, so they never exercise which registry value feeds
        // which parameter. Dropping or misspelling "DisplayVersion" below (current_version_value
        // returns "" for any unknown name, by design) was green under every other test in the
        // tree when the loop-8 review checked. This test re-derives the expected value from the
        // RAW reads, so a dropped value, a typo'd value name, or swapped arguments all fail it.
        //
        // Premise asserted first, not assumed: the equality is only evidence for a parameter if
        // this host actually provides a non-empty value for it. Every in-scope host does
        // (DisplayVersion exists from Win10 20H2 on; windows-latest's Server 2025 has all three).
        let product = current_version_value("ProductName");
        let display = current_version_value("DisplayVersion");
        let build = current_version_value("CurrentBuildNumber");
        assert!(
            !product.trim().is_empty() && !display.trim().is_empty() && !build.trim().is_empty(),
            "premise not met: this host does not provide all three CurrentVersion values \
             (ProductName={product:?}, DisplayVersion={display:?}, CurrentBuildNumber={build:?}) \
             — the wiring equality below would be vacuous for the missing one"
        );
        assert_eq!(
            os_description(),
            compose_os_description(&product, &display, &build),
            "os_description() does not feed the three registry values it documents into the \
             composer — a dropped value, a misspelled value name, or swapped arguments"
        );
    }

    fn temp_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("rmt_enroll_{tag}_{}.tmp", uuid::Uuid::new_v4()));
        p.to_string_lossy().into_owned()
    }

    // ---- enrollment state transitions -------------------------------------------------

    #[test]
    fn unmanaged_agents_never_enroll() {
        let cfg = HelperConfig { enrollment_token: Some("tok".into()), ..Default::default() };
        assert!(!needs_enrollment(&cfg), "no control_plane_url ⇒ no enrollment");
    }

    #[test]
    fn a_managed_agent_with_a_token_and_no_device_id_enrolls() {
        let cfg = HelperConfig {
            control_plane_url: Some("https://cp.example".into()),
            enrollment_token: Some("tok".into()),
            ..Default::default()
        };
        assert!(needs_enrollment(&cfg));
    }

    #[test]
    fn an_already_enrolled_agent_does_not_re_enroll() {
        // The single most important state transition: re-enrolling would burn a token use and
        // orphan the machine row the control plane already holds for us.
        let cfg = HelperConfig {
            control_plane_url: Some("https://cp.example".into()),
            enrollment_token: Some("tok".into()),
            device_id: Some("9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7".into()),
            ..Default::default()
        };
        assert!(!needs_enrollment(&cfg));
    }

    #[test]
    fn a_managed_agent_without_a_token_cannot_enroll() {
        let mut cfg = HelperConfig {
            control_plane_url: Some("https://cp.example".into()),
            ..Default::default()
        };
        assert!(!needs_enrollment(&cfg));
        cfg.enrollment_token = Some("   ".into());
        assert!(!needs_enrollment(&cfg), "a blank token is not a token");
    }

    #[test]
    fn applying_enrollment_records_the_identity_and_burns_the_token() {
        let mut cfg = HelperConfig {
            control_plane_url: Some("https://cp.example".into()),
            enrollment_token: Some("tok".into()),
            ..Default::default()
        };
        apply_enrollment(
            &mut cfg,
            &EnrolledIdentity {
                device_id: "dev-1".into(),
                tenant_id: "ten-1".into(),
                directive_pubkey: None,
            },
        );
        assert_eq!(cfg.device_id.as_deref(), Some("dev-1"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("ten-1"));
        assert_eq!(cfg.enrollment_token, None, "the spent token must not linger on disk");
        assert!(!needs_enrollment(&cfg), "enrollment is terminal");
    }

    #[test]
    fn a_persisted_enrollment_survives_a_reload() {
        let path = temp_path("cfg");
        let mut cfg = HelperConfig {
            signaling_url: Some("ws://x/ws".into()),
            control_plane_url: Some("https://cp.example".into()),
            enrollment_token: Some("tok".into()),
            ..Default::default()
        };
        apply_enrollment(
            &mut cfg,
            &EnrolledIdentity { device_id: "dev-1".into(), tenant_id: "ten-1".into(), directive_pubkey: None },
        );
        cfg.save_to(&path).unwrap();
        let mut back = HelperConfig::load_from(&path).expect("reload");
        assert_eq!(back.device_id.as_deref(), Some("dev-1"));
        assert_eq!(back.tenant_id.as_deref(), Some("ten-1"));
        assert!(back.enrollment_token.is_none());
        assert!(!needs_enrollment(&back));
        assert_eq!(back.device_id_or_dev_fallback().as_deref(), Some("dev-1"));
        let _ = std::fs::remove_file(&path);
    }

    // ---- URL policy --------------------------------------------------------------------

    #[test]
    fn https_urls_are_accepted_without_a_warning() {
        assert_eq!(validate_control_plane_url("https://cp.example:8443"), Ok(false));
        assert_eq!(validate_control_plane_url("  https://cp.example/  "), Ok(false));
    }

    #[test]
    fn loopback_http_is_allowed_but_flagged() {
        for u in [
            "http://localhost:8443",
            "http://127.0.0.1:8443",
            "http://[::1]:8443",
            "http://[::1]",
            "http://localhost",
            "http://127.0.0.1/enroll",
        ] {
            assert_eq!(validate_control_plane_url(u), Ok(true), "{u}");
        }
    }

    #[test]
    fn plaintext_http_to_a_remote_host_is_a_hard_error() {
        // The enrollment token is a bearer secret; shipping it in the clear would let anyone on
        // the path enroll a machine into the tenant.
        for u in [
            "http://cp.example:8443",
            "http://10.0.0.5",
            "http://evil.example/127.0.0.1",
        ] {
            assert!(validate_control_plane_url(u).is_err(), "{u} must be refused");
        }
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for u in ["ws://cp.example", "cp.example:8443", "", "file:///etc/passwd"] {
            assert!(validate_control_plane_url(u).is_err(), "{u:?} must be refused");
        }
    }

    #[test]
    fn redeem_url_tolerates_a_trailing_slash() {
        assert_eq!(redeem_url("https://cp.example:8443"), "https://cp.example:8443/enroll/redeem");
        assert_eq!(redeem_url("https://cp.example:8443/"), "https://cp.example:8443/enroll/redeem");
        assert_eq!(redeem_url("  https://cp/ "), "https://cp/enroll/redeem");
    }

    #[test]
    fn security_url_rejects_ambiguous_authorities() {
        for url in [
            "http://localhost:80@remote.example", "https://user@cp.example",
            r"https://evil.invalid\@trusted.example", r"https://cp.example/\x",
            "https://cp.example/\n", "https://cp.example?x=1", "https://cp.example#x",
            "https://", "http://localhost.evil.example",
        ] { assert!(validate_control_plane_url(url).is_err(), "{url:?}"); }
        assert_eq!(validate_control_plane_url("https://cp.example/cp"), Ok(false));
    }

    // ---- redemption response ------------------------------------------------------------

    const PUBKEY: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

    fn body(pubkey: &str) -> String {
        format!(
            r#"{{"machine":{{"id":"m-1","tenant_id":"11111111-2222-3333-4444-555555555555",
               "device_id":"9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7","group_id":"g-1","name":"HOST",
               "pubkey":"{pubkey}"}}}}"#
        )
    }

    #[test]
    fn a_valid_redemption_yields_the_server_minted_identity() {
        let got = parse_redeem_response(&body(PUBKEY), PUBKEY).unwrap();
        assert_eq!(got.device_id, "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7");
        assert_eq!(got.tenant_id, "11111111-2222-3333-4444-555555555555");
    }

    const DIRECTIVE_KEY: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

    #[test]
    fn the_redeem_response_directive_key_is_read_and_pinned_into_the_config() {
        // control-plane/http.go handleRedeemEnrollment: `directive_pubkey` is a TOP-LEVEL key beside `machine`.
        let with_key = body(PUBKEY).replacen('{', &format!(r#"{{"directive_pubkey":"{DIRECTIVE_KEY}","#), 1);
        let got = parse_redeem_response(&with_key, PUBKEY).unwrap();
        assert_eq!(got.directive_pubkey.as_deref(), Some(DIRECTIVE_KEY));
        assert_eq!(parse_redeem_response(&body(PUBKEY), PUBKEY).unwrap().directive_pubkey, None, "absent on a control plane without directives");
        let mut cfg = HelperConfig::default();
        apply_enrollment(&mut cfg, &got);
        assert_eq!(crate::directive_pin::pinned(&cfg).as_deref(), Some(DIRECTIVE_KEY));
    }

    #[test]
    fn a_directive_key_equal_to_the_grant_issuer_is_not_pinned_but_enrollment_still_succeeds() {
        let mut cfg = HelperConfig { grant_issuer_pubkey: Some(DIRECTIVE_KEY.into()), ..Default::default() };
        apply_enrollment(
            &mut cfg,
            &EnrolledIdentity { device_id: "d".into(), tenant_id: "t".into(), directive_pubkey: Some(DIRECTIVE_KEY.into()) },
        );
        assert_eq!(cfg.device_id.as_deref(), Some("d"));
        assert!(cfg.directive_pubkey.is_none(), "a shared key must leave the agent unpinned (refusing every directive)");
    }

    #[test]
    fn pubkey_hex_case_does_not_matter() {
        parse_redeem_response(&body(&PUBKEY.to_uppercase()), PUBKEY)
            .expect("hex case is not semantic");
    }

    #[test]
    fn a_response_pinning_a_different_key_is_refused() {
        // A control plane that pinned someone else's key has mis-provisioned us: we could never
        // sign a challenge it would accept, so enrolling would produce a permanently broken agent.
        let err = parse_redeem_response(&body(&"aa".repeat(32)), PUBKEY).unwrap_err();
        assert!(err.contains("refusing to enroll"), "{err}");
    }

    #[test]
    fn a_response_missing_required_fields_is_refused() {
        for missing in ["device_id", "tenant_id", "pubkey"] {
            let stripped = body(PUBKEY).replace(&format!("\"{missing}\""), "\"ignored\"");
            let err = parse_redeem_response(&stripped, PUBKEY).unwrap_err();
            assert!(err.contains(missing), "expected {missing} to be reported, got {err}");
        }
        assert!(parse_redeem_response("{}", PUBKEY).is_err());
        assert!(parse_redeem_response("not json", PUBKEY).is_err());
        // An empty device_id must not be accepted as "enrolled".
        let empty = body(PUBKEY).replace("9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7", "");
        assert!(parse_redeem_response(&empty, PUBKEY).is_err());
    }

    // ---- identity persistence -----------------------------------------------------------

    #[test]
    fn a_generated_identity_persists_as_64_lowercase_hex_chars() {
        let path = temp_path("key");
        let (id, generated) = load_or_generate_identity(&path).unwrap();
        assert!(generated);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.len(), 64, "seed is 64 hex chars, no BOM and no trailing newline");
        assert!(raw.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(hex::encode(id.seed()), raw);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_existing_identity_is_reused_not_regenerated() {
        // Re-running enrollment must keep the key the control plane already pinned.
        let path = temp_path("key");
        let (first, _) = load_or_generate_identity(&path).unwrap();
        let (second, generated) = load_or_generate_identity(&path).unwrap();
        assert!(!generated);
        assert_eq!(first.public_hex(), second.public_hex());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_bom_prefixed_or_padded_identity_still_loads() {
        // PowerShell's `Set-Content -Encoding utf8` prepends a BOM and appends a newline.
        let path = temp_path("key");
        let seed = [7u8; 32];
        std::fs::write(&path, format!("\u{feff}{}\r\n", hex::encode(seed))).unwrap();
        let id = read_identity(&path).unwrap().expect("must load");
        assert_eq!(id.seed(), seed);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_identity_is_an_error_not_a_silent_regeneration() {
        // Overwriting it would orphan the enrolled machine.pubkey and leave the agent
        // unauthenticatable with no signal that it happened.
        let path = temp_path("key");
        std::fs::write(&path, "not-a-key").unwrap();
        assert!(read_identity(&path).is_err());
        assert!(load_or_generate_identity(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not-a-key", "left untouched");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_identity_file_is_not_an_error() {
        assert_eq!(read_identity(&temp_path("absent")).unwrap().map(|i| i.public_hex()), None);
    }

    // ---- signer seam ---------------------------------------------------------------------

    #[test]
    fn the_signer_produces_the_golden_agent_auth_signature() {
        // Ties the agent's real key path to the cross-language golden vector in
        // crates/protocol/src/agent_auth.rs (and server/signaling/agentauth_test.go).
        let seed: [u8; 32] =
            hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap()
                .try_into()
                .unwrap();
        let signer = IdentitySigner::new(Identity::from_seed(&seed));
        let nonce = rmt_protocol::agent_auth::decode_nonce_hex(
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        )
        .unwrap();
        let preimage = rmt_protocol::agent_auth::agent_auth_signing_bytes(
            "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7",
            "11111111-2222-3333-4444-555555555555",
            &nonce,
        );
        assert_eq!(
            hex::encode(signer.sign(&preimage)),
            concat!(
                "b8ba719cba0e4301aba3d1d83b811eead5806461d7cd3633e3f27ae4cd15ecbb",
                "5480493e0eee099eb64234214f1fd874b5dafa95fc6d31ad2267788d2352f601",
            )
        );
    }
}

#[cfg(test)]
#[cfg(windows)]
mod identity_acl_tests {
    //! Real-`icacls` regression tests for [`super::tighten_identity_acl`] (loop 91).
    //!
    //! **These exist because a mutation sweep said they had to.** Loop 91 moved this function onto
    //! `crate::agent_root`'s builders — SIDs instead of English names, plus a `/reset` and an owner
    //! reset — and six mutations of that change were UNKILLABLE by any suite in the tree. A security
    //! fix with no test is a fix the next refactor removes silently.
    //!
    //! They run `icacls` for real against a test-owned temp file, which is harmless, and they read
    //! the FILE's own security descriptor — the object the lockdown is about. Measuring the parent
    //! directory instead is how a lockdown gets confirmed against the wrong object.

    use std::path::Path;

    /// A key file inside a directory that GRANTS INHERITABLE ACCESS.
    ///
    /// The own directory is not incidental. These tests are about STRIPPING inherited access, so
    /// they need something inherited to strip — and a file created directly under `%TEMP%` only
    /// carries inherited ACEs if the HOST's temp DACL happens to have inheritable entries. On a
    /// GitHub runner it does not: `%TEMP%`'s ACEs are not inheritable, so a new file gets the
    /// token's default DACL as EXPLICIT `SYSTEM:(F)` / `Administrators:(F)`, the premise assertion
    /// fires, and the test fails on every CI run while passing on every developer box.
    ///
    /// Failing loudly there was right — a vacuous pass would be worse. The fix is for the fixture
    /// to ESTABLISH the condition rather than borrow it from the host.
    struct TempFile(std::path::PathBuf, std::path::PathBuf);
    impl TempFile {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rmt-identity-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("fixture dir");

            // Granted by SID (`*S-1-5-32-545`, BUILTIN\\Users) for the same reason the production
            // code grants by SID: a name-based grant is wrong on a non-English Windows.
            let out = std::process::Command::new("icacls")
                .arg(dir.as_os_str())
                .args([
            "/grant",
            "*S-1-5-32-544:(OI)(CI)(F)",
            "/grant",
            "*S-1-5-18:(OI)(CI)(F)",
            "/grant",
            "*S-1-5-32-545:(OI)(CI)(RX)",
        ])
                .output()
                .expect("icacls runs");
            assert!(
                out.status.success(),
                "could not stage the inheritable ACE this fixture depends on: {} / {}",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            );

            let p = dir.join("identity.key");
            Self(p, dir)
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }

    fn icacls_read(path: &Path) -> String {
        let out = std::process::Command::new("icacls")
            .arg(path.as_os_str())
            .output()
            .expect("icacls runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// **THE MEASURED DEFECT, as a regression.** A pre-planted EXPLICIT `Authenticated Users:(F)`
    /// on the identity key is STRIPPED.
    ///
    /// Measured before the fix, on this box: `icacls /grant:r` replaces only the NAMED principal's
    /// ACE and is additive with respect to every other, so the old single-command argv left the key
    /// reading `Administrators:(F) SYSTEM:(F) Authenticated Users:(F)` — the lockdown reported
    /// success and the agent's Ed25519 private key stayed readable by every authenticated user on
    /// the machine.
    ///
    /// It is reachable, not theoretical: `write_identity` uses `File::create`, i.e. `CREATE_ALWAYS`,
    /// which TRUNCATES a pre-existing file rather than replacing it — so the security descriptor a
    /// standard user placed on a pre-created `C:\rmt-agent\identity.key` survives the key being
    /// written into it. Same shape as the `config.json` defect loop 90's review found, on a higher-
    /// value object: `config.json` decides which grants are honoured, the key IS the machine's
    /// identity.
    #[test]
    fn tighten_identity_acl_strips_a_planted_explicit_ace() {
        let f = TempFile::new("planted");
        std::fs::write(&f.0, b"00").expect("write key");

        // Plant the EXPLICIT (non-inherited) grant a hostile pre-creator could. S-1-5-11 is
        // Authenticated Users, named by SID so the staging step itself is locale-independent.
        let plant = std::process::Command::new("icacls")
            .arg(f.0.as_os_str())
            .args(["/grant", "*S-1-5-11:(F)"])
            .output()
            .expect("icacls runs");
        assert!(
            plant.status.success(),
            "staging the planted ACE failed: {}",
            String::from_utf8_lossy(&plant.stderr)
        );

        // PREMISE (negative control): it really is there. Without this leg a test against a file
        // that never carried the ACE would pass vacuously — which is exactly how the original
        // defect survived a green suite.
        let before = icacls_read(&f.0);
        assert!(
            before.contains("S-1-5-11") || before.contains("Authenticated Users"),
            "premise not met: the planted ACE is not on the file:\n{before}"
        );

        super::tighten_identity_acl(&f.0.to_string_lossy());

        let after = icacls_read(&f.0);
        assert!(
            !after.contains("Authenticated Users") && !after.contains("S-1-5-11"),
            "the planted Authenticated Users ACE SURVIVED the lockdown — the agent private key is \
             readable by every authenticated user:\n{after}"
        );
        // Locale-robust structural check, because the two string checks above pass vacuously on a
        // non-English Windows (where the ACE displays a localized name that is neither string).
        // icacls prints one `PRINCIPAL:(flags)` per ACE; the trailing summary line has no `:(`.
        // At most three remain: SYSTEM, Administrators, and the creating owner's read grant.
        let aces = after.lines().filter(|l| l.contains(":(")).count();
        assert!(
            (2..=3).contains(&aces),
            "expected SYSTEM + Administrators (+ optionally the owner), got {aces} ACEs:\n{after}"
        );
    }

    /// Inherited access is dropped and the two required principals are granted — by SID, so this
    /// holds on a non-English Windows where the old name-based argv applied NOTHING AT ALL.
    ///
    /// The negative control is the interesting half: the temp directory this file is created in
    /// grants broad inherited access, and after the lockdown none of it may remain.
    #[test]
    fn tighten_identity_acl_drops_inherited_access_and_grants_by_sid() {
        let f = TempFile::new("inherit");
        std::fs::write(&f.0, b"00").expect("write key");

        // PREMISE: a fresh file under %TEMP% really does carry INHERITED ACEs (icacls marks them
        // `(I)`). If it did not, the `/inheritance:r` this test is about would have nothing to do.
        let before = icacls_read(&f.0);
        assert!(
            before.contains("(I)"),
            "premise not met: the file carries no inherited ACEs to strip:\n{before}"
        );

        super::tighten_identity_acl(&f.0.to_string_lossy());

        let after = icacls_read(&f.0);
        assert!(
            !after.contains("(I)"),
            "inherited ACEs survived /inheritance:r:\n{after}"
        );
        // SYSTEM and Administrators are present. Asserted through the SIDs' resolved names OR the
        // raw SIDs, because icacls prints whichever it can resolve.
        assert!(
            after.contains("NT AUTHORITY\\SYSTEM") || after.contains("S-1-5-18"),
            "SYSTEM was not granted:\n{after}"
        );
        assert!(
            after.contains("BUILTIN\\Administrators") || after.contains("S-1-5-32-544"),
            "Administrators was not granted:\n{after}"
        );
    }
}
