//! Persistent helper configuration (M7).
//!
//! The installed service's per-session SYSTEM helper reads a small JSON config from
//! [`CONFIG_FILE`] to learn *where to connect* (the signaling server), *who it is* (a stable,
//! per-machine device id), and *how to traverse NAT* (optional STUN servers). Absent a usable
//! config the helper stays in its capture-proof mode (see [`crate::host::helper_worker`]).
//!
//! # File format (`C:\rmt-agent\config.json`)
//!
//! ```json
//! {
//!   "signaling_url": "ws://relay.example:8080/ws",
//!   "device_id": "550e8400-e29b-41d4-a716-446655440000",
//!   "stun": ["stun:stun.l.google.com:19302"]
//! }
//! ```
//!
//! * `signaling_url` — the WebSocket rendezvous endpoint. **Required** for streaming mode; without
//!   it the helper logs "no config" and falls back to the proof loop.
//! * `device_id` — a UUID identifying this agent to the relay. **Server-minted** at enrollment
//!   (M3); only the unmanaged dev/LAN path invents one locally (see
//!   [`HelperConfig::device_id_or_dev_fallback`]).
//! * `control_plane_url` / `enrollment_token` / `tenant_id` — the M3 enrollment triple (see
//!   [`crate::enroll`]). Present ⇒ this agent is control-plane managed and authenticates its
//!   `register_agent`.
//! * `stun` — zero or more STUN URLs for WAN NAT traversal. Empty = LAN/loopback (host candidates).
//! * `grant_issuer_pubkey` — the control plane's Ed25519 public key. Absent ⇒ backstage DENIED.
//! * `update_signer_pubkey` — the **release signer's** Ed25519 public key (docs/21 §3), a
//!   *different* key that never lives on the control plane. Absent ⇒ every update manifest is
//!   refused. See [`HelperConfig::update_signer_pubkey`], and note that the manifest itself is a
//!   separate file ([`UPDATE_MANIFEST_FILE`]) rather than a field here.

use serde::{Deserialize, Serialize};

/// Directory holding the helper's config + proof artifacts.
pub const CONFIG_DIR: &str = r"C:\rmt-agent";
/// Directory holding the agent's own EXECUTABLE, and the path the LocalSystem service is registered
/// against. Must match `install-agent.ps1`'s `-BinDir` default (scripts/build-release.ps1).
///
/// Separate from [`CONFIG_DIR`] because they are hardened for different reasons and one of them was
/// missed once already: loop 97 found this directory inheriting
/// `NT AUTHORITY\Authenticated Users:(I)(M)` from the root of C:, which made the service binary of a
/// LocalSystem auto-start service replaceable by any standard user. Anything that registers the
/// service must point it HERE, at a directory [`crate::agent_root::harden_agent_root`] owns — never
/// at wherever the running executable happens to sit.
pub const BIN_DIR: &str = r"C:\rmt-agent-bin";
/// Full path to the helper's JSON config.
pub const CONFIG_FILE: &str = r"C:\rmt-agent\config.json";
/// Full path to the signed agent-update manifest (docs/21 §3, step 2).
///
/// Deliberately **beside `config.json`, inside [`CONFIG_DIR`]**, and deliberately **not
/// configurable**. [`crate::agent_root::harden_agent_root`] restricts that directory to SYSTEM +
/// Administrators by SID and re-applies the DACL at every service start, so the manifest inherits
/// the protection that already exists rather than needing a fourth implementation of it. A config
/// knob for the location would be a way to point the agent at a directory nobody hardened — and
/// while the SIGNATURE is what makes a manifest trustworthy, the ACL is what stops a local user
/// swapping in a genuine but SUPERSEDED one, which is the attack a signature alone does not answer.
///
/// The file is **placed by an operator**. There is no fetch, by design: the unattended agent has no
/// authenticated HTTP channel to the control plane, and no scheduler exists to drive one. Both are
/// docs/21 step 3/4 work — see [`rmt_agent::update`], whose module docs draw that line.
///
/// The basename is pinned to [`rmt_agent::update::MANIFEST_FILENAME`] by
/// `tests::the_manifest_path_matches_the_portable_basename` so the two cannot drift.
pub const UPDATE_MANIFEST_FILE: &str = r"C:\rmt-agent\update-manifest.json";

/// Deserialized helper configuration. All fields tolerate absence so a partial hand-written config
/// still loads (a missing `device_id` is filled in and persisted on first run).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperConfig {
    /// Permit local interactive users to record through the SYSTEM writer. Off by default.
    /// Recordings stay in the service-owned folder; no caller paths are accepted.
    #[serde(default)]
    pub allow_cli_recording: bool,
    /// Signaling WebSocket URL. `None`/absent ⇒ streaming disabled (proof-loop fallback).
    #[serde(default)]
    pub signaling_url: Option<String>,
    /// Stable per-machine device UUID (string form). Generated + persisted if absent.
    #[serde(default)]
    pub device_id: Option<String>,
    /// Optional STUN server URLs for WAN NAT traversal. Empty ⇒ LAN/loopback.
    #[serde(default)]
    pub stun: Vec<String>,
    /// Optional root directory for M8 file transfers (uploads land here as `.part` then the final
    /// name; downloads are confined to this tree). `None`/absent ⇒ [`DEFAULT_TRANSFER_DIR`].
    #[serde(default)]
    pub transfer_dir: Option<String>,
    /// H1: the control-plane's long-term Ed25519 **public** identity, hex-encoded (64 chars). When
    /// set, the agent runs in **secure grant mode** — it will not grant any backstage access until a
    /// `Control::InstallGrant` carrying a grant signed by this key verifies.
    ///
    /// When `None`, blank or malformed the agent **fails closed**: backstage is DENIED
    /// (`BackstageAuth::Deny` in `crate::host`), streaming and input are unaffected. This comment
    /// used to say the agent fell back to an "insecure dev mode" with a self-issued demo grant and a
    /// loud warning — **that is no longer true of the installed service path**, and leaving the
    /// sentence here would describe a permissive fallback that the code removed precisely because
    /// the shipped installer defaulted `-GrantIssuerPubkey` to `""`, so the insecure path was the
    /// one an operator got by not passing a flag. Corrected in loop 98 while its sibling
    /// [`update_signer_pubkey`](Self::update_signer_pubkey) was added next to it.
    #[serde(default)]
    pub grant_issuer_pubkey: Option<String>,
    /// docs/21 §3: the **release signer's** long-term Ed25519 public identity, hex-encoded (64
    /// chars) — the key an update manifest must be signed by before this agent will believe a word
    /// of it.
    ///
    /// **This is NOT [`grant_issuer_pubkey`](Self::grant_issuer_pubkey), and it must never be set to
    /// the same value.** docs/21 §3 calls that "the most important sentence in this document". The
    /// control plane's key mints session-scoped, capability-bounded, audited artifacts and lives in
    /// a `.env` file on the internet-facing box; the update key authorizes arbitrary code as SYSTEM
    /// on every machine, permanently, and lives offline at release time (see
    /// `control-plane/cmd/rmt-update-sign`). Sharing one key would drag the update key's threat
    /// model down onto a value that is already sitting on the component most likely to be
    /// compromised. [`rmt_agent::update::UpdateTrust::from_config`] refuses to run at all when the
    /// two are equal, rather than pretending the resulting signature check means anything.
    ///
    /// `None`/absent/blank ⇒ this agent refuses every update manifest. That is the state of every
    /// machine installed before this feature existed and it is the correct default: there is no
    /// permissive third value, and "we could not verify a manifest" must mean "no update", never
    /// "install it anyway".
    ///
    /// Written by the INSTALLER (`install-agent.ps1 -UpdateSignerPubkey`), not by enrollment.
    /// docs/21 §3 originally claimed the agent "pins `update_signer_pubkey` at enrollment, alongside
    /// the grant issuer pubkey it already pins"; the code refutes that — `crate::enroll`'s
    /// `apply_enrollment` writes `device_id` and `tenant_id` and clears the token, and
    /// `grant_issuer_pubkey` appears nowhere in that file. The doc has been corrected.
    ///
    /// Rotation costs what `GRANT_ISSUER_SEED` rotation costs, and then some: a changed key means
    /// every enrolled agent refuses every update, silently, until someone edits `config.json` on
    /// each machine. There is no remote fix, because the mechanism you would use is the one that
    /// just stopped working.
    #[serde(default)]
    pub update_signer_pubkey: Option<String>,
    /// docs/65 D-C3: the control plane's DIRECTIVE public key, hex-encoded (64 chars): the only key whose
    /// signature makes a fleet directive (reinstall / uninstall) believable.
    ///
    /// **A DEDICATED key**: never [`grant_issuer_pubkey`](Self::grant_issuer_pubkey) and never
    /// [`update_signer_pubkey`](Self::update_signer_pubkey) (pinning refuses either), so a compromised grant
    /// signer cannot forge a fleet wipe. Pinned ONCE, set-if-blank, from the enroll response (`directive_pubkey`)
    /// or the MSI property `DIRECTIVE_PUBKEY` at install/upgrade ([`crate::directive_pin`]); no network message,
    /// grant or manifest can replace it. `None`/blank ⇒ this agent refuses every directive and does NOT advertise
    /// `directive_v1`.
    #[serde(default)]
    pub directive_pubkey: Option<String>,
    /// Loops 79/80: refuse the technician's input until a control-plane-signed SESSION ACCESS POLICY
    /// has been verified for this session.
    ///
    /// Why this exists at all: the policy reaches the agent because the VIEWER forwards it, and the
    /// viewer is the thing the policy is meant to bind. A technician who tampers with their own console
    /// can simply not send the frame — and without this flag the agent, having no idea a policy was
    /// ever minted, hands over full control. The whole per-group view-only mandate would be advisory.
    ///
    /// When true the session starts VIEW-ONLY and stays there until a policy verifies; the verified
    /// policy then sets the real level (which may be `control`). That initial state is a PROVISIONAL
    /// floor, deliberately distinct from a policy-imposed one — it is the only floor the ratchet is
    /// allowed to lift, and only once, by a signature.
    ///
    /// Defaults to FALSE so existing installs are unchanged: an agent with no
    /// [`grant_issuer_pubkey`](Self::grant_issuer_pubkey) cannot verify a policy at all, and flipping
    /// this on for them would strand every session in view-only. Set BOTH for an enforcing deployment.
    #[serde(default)]
    pub require_session_policy: bool,
    /// M3: control-plane base URL used for first-run enrollment (`POST <url>/enroll/redeem`).
    /// Present ⇒ this agent is **control-plane managed**: its device id is minted server-side and
    /// its `register_agent` is authenticated. Absent ⇒ the unmanaged dev/LAN path.
    #[serde(default)]
    pub control_plane_url: Option<String>,
    /// M3: one-shot enrollment bearer secret. **Cleared after a successful redemption** — it must
    /// not linger on disk, since anyone holding it can enroll a machine into the tenant.
    #[serde(default)]
    pub enrollment_token: Option<String>,
    /// M3: the tenant this machine was enrolled into, written by redemption. Required to build the
    /// `RMTAGENTAUTHv1` preimage the signaling server verifies.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// M3: override for the default identity-key path (`C:\rmt-agent\identity.key`). Exists so
    /// tests can point enrollment at a temp file; production leaves it absent.
    #[serde(default)]
    pub identity_path: Option<String>,
    /// Longest a single remote-control session may run, in seconds. `None`/absent ⇒ 4 hours.
    ///
    /// This was a hardcoded 5 minutes until it was discovered that it made the product unusable —
    /// every session ended mid-work. It is a RESOURCE bound (a session holds a capture thread and a
    /// libvpx context), not an authorization one, so it belongs in machine config rather than in a
    /// grant. Values below a minute are ignored as almost certainly a mistake.
    #[serde(default)]
    pub max_session_secs: Option<u64>,
    /// M11: the administrative ceiling on session quality for THIS machine. `None`/absent ⇒
    /// [`QualityPolicyConfig::default`], which allows requests up to 20 Mbps while sessions start at 3 Mbps.
    #[serde(default)]
    pub quality: Option<QualityPolicyConfig>,
    /// Which directions the clipboard may move on THIS machine. Absent ⇒
    /// [`ClipboardMode::Bidirectional`], which is what the agent did before this knob existed.
    ///
    /// This is the administrator's off switch, and until it existed there was no mitigation to
    /// recommend: the installed helper passed a live `WinClipboard` unconditionally, so an operator
    /// who decided the clipboard was too much exposure for a particular machine had nothing to turn
    /// off. A per-machine setting is the right altitude — whether a bank branch's teller PC should
    /// let its clipboard leave the building is a property of that machine, not of the technician
    /// who happens to connect.
    ///
    /// It composes with, and never overrides, the session's view-only state: view-only refuses both
    /// directions regardless of what is set here. This is the machine's ceiling; view-only is the
    /// session's floor, and the more restrictive of the two always wins.
    ///
    /// The default stays `Bidirectional` deliberately. Clipboard sync is a feature customers use and
    /// silently disabling it on upgrade would be a functional regression delivered as a security
    /// patch; the exfiltration this finding was really about — a *view-only* session siphoning the
    /// clipboard — is closed in the session loop, unconditionally, for every machine. See
    /// [`require_session_policy`](Self::require_session_policy), which defaults false for the same
    /// reason.
    #[serde(default)]
    pub clipboard: ClipboardMode,
    /// The composite stream's capture: absent (or anything but `"gdi"`) = the DXGI canvas (docs/52)
    /// with the GDI composite where DXGI cannot serve; `"gdi"` = the GDI composite only, the
    /// field escape hatch (docs/52 §4.6). Read at helper start; restart the RmtAgent service to apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canvas_capture: Option<String>,
}

/// Which directions clipboard text may move, as configured for a machine.
///
/// A named enum rather than a `bool` because the two directions carry genuinely different risk and
/// an administrator may reasonably want one without the other. Outbound is exfiltration: what the
/// guest copied — routinely a password manager's contents — leaves the machine. Inbound is the
/// agent WRITING to the guest's desktop as SYSTEM, so that the next thing the guest pastes may not
/// be what they believe they copied. A single on/off would force those two decisions together.
///
/// Serialized in `snake_case`, and an unrecognised value is a hard parse error rather than a silent
/// fallback: a typo'd `"disabled "` that quietly meant "bidirectional" would be the worst possible
/// failure for a switch whose entire purpose is turning something off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardMode {
    /// Both directions (the pre-existing behaviour, and the default).
    #[default]
    Bidirectional,
    /// The guest's clipboard may be sent to the technician; the technician may not write back.
    ToTechnician,
    /// The technician may write into the guest's clipboard; the guest's clipboard never leaves.
    /// The setting for a machine where the technician needs to hand over a command or a licence key
    /// but nothing on the machine should travel the other way.
    ToGuest,
    /// No clipboard sync at all. The session's clipboard channel carries nothing in either
    /// direction and no clipboard worker is started.
    Disabled,
}

impl ClipboardMode {
    /// May the guest's clipboard be sent OUT to the technician?
    pub fn allows_to_technician(self) -> bool {
        matches!(self, ClipboardMode::Bidirectional | ClipboardMode::ToTechnician)
    }

    /// May the technician write INTO the guest's clipboard?
    pub fn allows_to_guest(self) -> bool {
        matches!(self, ClipboardMode::Bidirectional | ClipboardMode::ToGuest)
    }

    /// Is any direction permitted at all? `false` ⇒ the host need not start a clipboard worker.
    pub fn any(self) -> bool {
        self != ClipboardMode::Disabled
    }
}

/// On-disk form of the M11 quality ceiling. Every field is optional so an existing `config.json`
/// keeps parsing untouched. The default request maximum is 20 Mbps.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct QualityPolicyConfig {
    /// Explicit hard limit on the effective bitrate after pixel scaling, bits/sec.
    /// Absent: requests may reach 20 Mbps; sessions still start at 3 Mbps.
    #[serde(default)]
    pub max_bitrate_bps: Option<u32>,
    /// Largest frame rate a technician may set. Absent ⇒ 60.
    #[serde(default)]
    pub max_fps: Option<u32>,
    /// `false` disables the adaptive rate controller for every session on this machine — the
    /// fleet-wide kill switch for a site where loss-based backoff misreads a lossy-but-uncongested
    /// link. Absent ⇒ `true`.
    #[serde(default)]
    pub adaptive: Option<bool>,
}

/// Default file-transfer root when [`HelperConfig::transfer_dir`] is unset.
pub const DEFAULT_TRANSFER_DIR: &str = r"C:\rmt-agent\transfers";

/// Where the installed agent writes **session recordings** (loop 89, docs/01 §5).
///
/// Deliberately NOT a `HelperConfig` field, unlike `transfer_dir`. Two reasons, and the second is
/// the one that matters: a per-machine override would be one more field to keep in step with the
/// installer's config template (build-release.ps1 guards that match), and — more importantly — the
/// recorder's whole disk-safety story is written against a directory it owns, with a DACL it sets
/// and a TTL sweep it runs. An operator-supplied path invites `C:\` or a network share, on which
/// `icacls /inheritance:r` is either a catastrophe or a no-op. When there is a reason to make it
/// configurable it should arrive with the validation that makes it safe, not before.
///
/// A sibling of [`DEFAULT_TRANSFER_DIR`] under the same agent root, and named for
/// `rmt_agent_windows::recording::DEFAULT_RECORDING_SUBDIR`; a unit test pins both relationships so
/// the two constants cannot drift into naming different places.
pub const DEFAULT_RECORDING_DIR: &str = r"C:\rmt-agent\recordings";

impl HelperConfig {
    /// The configured transfer root, or [`DEFAULT_TRANSFER_DIR`] if unset/empty.
    pub fn transfer_dir_or_default(&self) -> std::path::PathBuf {
        self.transfer_dir
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_TRANSFER_DIR))
    }
}

impl HelperConfig {
    /// Load and parse [`CONFIG_FILE`]. Returns `None` if the file is absent or unparseable (the
    /// caller treats either as "no config" and falls back to the proof loop, so a hand-editing typo
    /// never hard-crashes the helper).
    pub fn load() -> Option<Self> {
        Self::load_from(CONFIG_FILE)
    }

    /// Load + parse from an explicit path (testable form of [`load`](Self::load)).
    pub fn load_from(path: &str) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        // Tolerate a leading UTF-8 BOM: Windows editors and PowerShell's `Set-Content -Encoding
        // utf8` prepend one, and `serde_json` rejects a BOM as invalid JSON. Stripping it here means
        // a hand-authored config.json opened in Notepad still loads (this bit us on the VM).
        let data = data.strip_prefix('\u{feff}').unwrap_or(&data);
        match serde_json::from_str::<Self>(data) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!(error = %e, path, "helper: config.json parse failed; ignoring");
                None
            }
        }
    }

    /// Persist this config to [`CONFIG_FILE`] (pretty JSON), creating [`CONFIG_DIR`] if needed.
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(CONFIG_FILE)
    }

    /// Persist to an explicit path (testable form of [`save`](Self::save)).
    pub fn save_to(&self, path: &str) -> std::io::Result<()> {
        #[cfg(test)]
        assert_ne!(
            path, CONFIG_FILE,
            "a unit test tried to write the REAL agent config at {CONFIG_FILE}. On a developer \
             box that also runs the agent, this overwrites a live machine's enrolled identity \
             with an all-defaults config carrying a locally minted device_id -- the exact \
             state that took a machine down on 2026-09-04. Use device_id_or_dev_fallback_in() \
             or save_to() with a temp path.",
        );
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, data)
    }

    /// The enrolled device id, or a locally-invented one **only** when this agent is not
    /// control-plane managed.
    ///
    /// A device id is what a session ticket authorizes the signaling server to broker to, so an
    /// agent that talks to a control plane must never choose its own: it is minted server-side at
    /// `POST /enroll/redeem` (control-plane/http.go `handleRedeemEnrollment`, migration 0008).
    ///
    /// * `Some(id)` — already enrolled (or a dev id from a previous run); use it.
    /// * `None` — `control_plane_url` is configured but redemption has not happened yet. The caller
    ///   must enroll (see [`crate::enroll::enroll_once`]) or stay in the capture-proof loop.
    /// * `Some(fresh uuid)` — no `control_plane_url` at all (dev/LAN/e2e): generate + persist a
    ///   random UUID, exactly as the pre-M3 behaviour did.
    ///
    /// A persist failure is logged but non-fatal — the helper still runs this session with the
    /// just-generated id (it may simply regenerate next boot).
    pub fn device_id_or_dev_fallback(&mut self) -> Option<String> {
        self.device_id_or_dev_fallback_in(CONFIG_FILE)
    }

    /// [`device_id_or_dev_fallback`](Self::device_id_or_dev_fallback) against an explicit config
    /// path, so the guard and the mint can be tested without writing to `CONFIG_DIR`.
    pub fn device_id_or_dev_fallback_in(&mut self, path: &str) -> Option<String> {
        if let Some(id) = self.device_id.as_ref().filter(|s| !s.trim().is_empty()) {
            return Some(id.clone());
        }
        if self.managed_identity_evidence().is_some() {
            return None;
        }
        self.mint_dev_device_id(path)
    }

    /// Evidence that this machine's identity is **owned by a control plane**, and so must never be
    /// invented locally. `Some(reason)` forbids minting and names WHICH signal fired.
    ///
    /// **The guard used to be [`is_control_plane_managed`](Self::is_control_plane_managed) alone —
    /// `control_plane_url` being non-empty — and that is a guard reading a DIFFERENT field than the
    /// one it protects.** On 2026-09-04 it was defeated exactly that way, and on 2026-09-06 the
    /// same thing was reproduced live on the dev box: something rewrote `config.json` as an
    /// all-defaults document, `control_plane_url` went empty, this guard silently flipped off, and
    /// the agent minted a uuid the control plane had never issued while still holding its real,
    /// enrolled `identity.key`. Signaling rejects that forever as `device identity unknown` — the
    /// one thing unreadable from the agent's own logs, which say `agent identity loaded`.
    ///
    /// The rewriter turned out to be this crate's OWN unit suite persisting a mint to the hardcoded
    /// production path (now refused by `save_to` under `cfg(test)`), not the installer, whose
    /// `Mandatory` parameters do reject a prompted blank on both PowerShell 5.1 and 7. That matters
    /// here only as a warning: the thing that blanks the config is not necessarily the thing you
    /// suspect, so the guard must not depend on knowing what it was.
    ///
    /// So this reads every INDEPENDENT signal that enrollment has happened or is intended, and any
    /// one is enough. The decisive one is the last: an `identity.key` on disk is a long-term
    /// Ed25519 key the control plane has ALREADY pinned to a specific device row. Minting a fresh
    /// id while holding it cannot produce anything but a rejected agent — the key names a device,
    /// and the invented id names nothing. That signal alone would have stopped the operator's box, where
    /// every other field had been blanked.
    ///
    /// This also removes the recovery recipe's teeth. Blanking `device_id` to re-enroll used to
    /// ARM the mint, and only a successful `enroll` (needing a live token, which a
    /// long-broken machine rarely has) disarmed it. With the key on disk the blanked id now yields
    /// `None` — the agent says so and drops to the capture loop instead of inventing an identity.
    pub fn managed_identity_evidence(&self) -> Option<String> {
        if self.is_control_plane_managed() {
            return Some("control_plane_url is set".to_string());
        }
        if self.tenant_id.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return Some("tenant_id is set, so this agent has enrolled before".to_string());
        }
        if self.enrollment_token.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return Some("an enrollment_token is pending, so the control plane mints the id".to_string());
        }
        let key = self.identity_path_or_default();
        // Non-empty, not merely present: `enroll` creates the file before it has anything to put in
        // it on at least one path, and a zero-byte key is not an enrolled identity.
        if std::fs::metadata(&key).is_ok_and(|m| m.is_file() && m.len() > 0) {
            return Some(format!("an enrolled identity key exists at {key}"));
        }
        None
    }

    /// Mint a dev device id — **once per machine, even when several agent processes race.**
    ///
    /// The mint is a read-modify-write on a file more than one process opens. The installer stops
    /// the service, but a helper from the PREVIOUS install can still be alive (`verify-all.ps1`
    /// kills stale `agent_host` processes in its preflight — the same observation from the other
    /// side), and the TEST BINARY was a writer too. On 2026-09-04 two writes landed inside one
    /// 100 ms window and the machine ended up
    /// with THREE ids: one in the file, one the helper was registering with, one the control plane
    /// knew. Nothing reconciled them, and `save()` writes the WHOLE config, so the later writer
    /// silently replaced the earlier one's identity.
    ///
    /// Two things fix that, and the second matters even if the first fails: take a cross-process
    /// lock, then **re-read the config under it and ADOPT any id already on disk** rather than
    /// overwriting it. First writer wins; every later racer converges on the same id.
    fn mint_dev_device_id(&mut self, path: &str) -> Option<String> {
        let _lock = MintLock::acquire(path);
        // Re-read UNDER the lock: another process may have minted between our load and here.
        if let Some(disk) = Self::load_from(path) {
            if let Some(id) = disk.device_id.as_ref().filter(|s| !s.trim().is_empty()) {
                tracing::info!(device_id = %id, "helper: adopting a device_id another process minted");
                self.device_id = Some(id.clone());
                return Some(id.clone());
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.device_id = Some(id.clone());
        if let Err(e) = self.save_to(path) {
            tracing::warn!(error = %e, "helper: could not persist generated device_id");
        }
        Some(id)
    }

    /// True when a control-plane URL is configured, i.e. this machine's identity is owned by the
    /// control plane rather than invented locally.
    pub fn is_control_plane_managed(&self) -> bool {
        self.control_plane_url.as_deref().is_some_and(|s| !s.trim().is_empty())
    }

    /// The identity-key path this agent uses: [`identity_path`](Self::identity_path) when set,
    /// otherwise [`DEFAULT_IDENTITY_FILE`].
    pub fn identity_path_or_default(&self) -> String {
        self.identity_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_IDENTITY_FILE)
            .to_string()
    }
}

/// Default path of the agent's long-term Ed25519 identity seed (64 lowercase hex chars, no BOM).
/// ACL-tightened to SYSTEM + Administrators immediately after it is written.
pub const DEFAULT_IDENTITY_FILE: &str = r"C:\rmt-agent\identity.key";

/// A cross-process mutex held across the device-id mint's read-modify-write.
///
/// Windows has no advisory file lock in `std`, but it has something better here: opening a file
/// with `share_mode(0)` denies every other opener until the handle closes. The lock is a SIBLING of
/// the config (`config.json.lock`) rather than the config itself, so taking it never truncates or
/// competes with a reader of the real file.
///
/// **Fails OPEN, deliberately.** If the lock cannot be taken the mint still proceeds: an agent with
/// no device id does nothing at all, and a lock we could not acquire is not a reason to brick a dev
/// install. The re-read-and-adopt inside the lock is the half that survives this — it narrows the
/// race to the microseconds between read and write instead of the seconds an unlocked mint leaves
/// open, and it is what makes two racers AGREE rather than merely be quick.
struct MintLock(#[allow(dead_code)] Option<std::fs::File>);

impl MintLock {
    fn acquire(config_path: &str) -> Self {
        use std::os::windows::fs::OpenOptionsExt;
        let lock_path = format!("{config_path}.lock");
        if let Some(dir) = std::path::Path::new(&lock_path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .share_mode(0)
                .open(&lock_path)
            {
                Ok(f) => return Self(Some(f)),
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        tracing::warn!(
                            error = %e, lock_path,
                            "helper: could not take the device-id mint lock; minting unlocked",
                        );
                        return Self(None);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_documented_shape() {
        let json = r#"{
            "signaling_url": "ws://relay.example:8080/ws",
            "device_id": "550e8400-e29b-41d4-a716-446655440000",
            "stun": ["stun:stun.l.google.com:19302"]
        }"#;
        let cfg: HelperConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.signaling_url.as_deref(), Some("ws://relay.example:8080/ws"));
        assert_eq!(cfg.device_id.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(cfg.stun, vec!["stun:stun.l.google.com:19302".to_string()]);
    }

    #[test]
    fn tolerates_a_leading_utf8_bom() {
        // PowerShell's `Set-Content -Encoding utf8` (and Notepad) prepend a BOM; serde_json rejects
        // it. A BOM-prefixed config must still load (this exact case broke the VM helper).
        let mut path = std::env::temp_dir();
        path.push(format!("rmt_cfg_bom_{}.json", uuid::Uuid::new_v4()));
        let path = path.to_string_lossy().into_owned();
        let json = "\u{feff}{\"signaling_url\":\"ws://x/ws\",\"device_id\":\"11111111-1111-1111-1111-111111111111\"}";
        std::fs::write(&path, json).unwrap();
        let cfg = HelperConfig::load_from(&path).expect("BOM-prefixed config must load");
        assert_eq!(cfg.signaling_url.as_deref(), Some("ws://x/ws"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_fields_default_gracefully() {
        // A minimal config with only a signaling_url must still parse.
        let cfg: HelperConfig = serde_json::from_str(r#"{"signaling_url":"ws://x/ws"}"#).unwrap();
        assert_eq!(cfg.signaling_url.as_deref(), Some("ws://x/ws"));
        assert!(cfg.device_id.is_none());
        assert!(cfg.stun.is_empty());
    }

    #[test]
    fn device_id_returns_existing_without_change() {
        let mut cfg = HelperConfig {
            device_id: Some("abc-123".into()),
            ..Default::default()
        };
        // Present id is returned verbatim and no disk write is attempted.
        assert_eq!(cfg.device_id_or_dev_fallback().as_deref(), Some("abc-123"));
        assert_eq!(cfg.device_id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn an_enrolled_device_id_survives_a_configured_control_plane() {
        // Re-enrollment is not a thing: once a device id is persisted it is used as-is.
        let mut cfg = HelperConfig {
            device_id: Some("abc-123".into()),
            control_plane_url: Some("https://cp.example:8443".into()),
            ..Default::default()
        };
        assert_eq!(cfg.device_id_or_dev_fallback().as_deref(), Some("abc-123"));
    }

    #[test]
    fn a_control_plane_managed_agent_never_invents_a_device_id() {
        // The device id is what a session ticket authorizes brokering to. A managed agent that
        // invented one would be unenrollable AND unauthenticatable, so it must report None and let
        // the caller enroll instead.
        let mut cfg = HelperConfig {
            control_plane_url: Some("https://cp.example:8443".into()),
            ..Default::default()
        };
        assert_eq!(cfg.device_id_or_dev_fallback(), None);
        assert_eq!(cfg.device_id, None, "nothing is invented or persisted");
    }

    /// A scratch config path, unique per call. NEVER [`CONFIG_FILE`].
    fn temp_config_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("rmt_cfg_{tag}_{}.json", uuid::Uuid::new_v4()));
        p.to_string_lossy().into_owned()
    }

    /// A config for a genuinely UNENROLLED machine.
    ///
    /// `identity_path` is pinned at an absent temp file on purpose. Left at its default it resolves
    /// to [`DEFAULT_IDENTITY_FILE`], and on any box that has ever run the real agent that file
    /// EXISTS -- so these tests would read the developer's own enrolled identity and assert against
    /// a machine state they never set up. Declare the premise locally instead of inheriting it.
    fn unenrolled_cfg(tag: &str) -> HelperConfig {
        let mut p = std::env::temp_dir();
        p.push(format!("rmt_absent_{tag}_{}.key", uuid::Uuid::new_v4()));
        let key = p.to_string_lossy().into_owned();
        assert!(!std::path::Path::new(&key).exists(), "premise: no identity key at {key}");
        HelperConfig { identity_path: Some(key), ..Default::default() }
    }

    #[test]
    fn an_unmanaged_agent_still_generates_a_dev_device_id() {
        // The LAN/dev/e2e path (browser-agent.spec.ts, loopback tests) is unchanged: no control
        // plane ⇒ a random UUID is minted locally.
        //
        // THIS TEST USED TO WRITE C:\rmt-agent\config.json. It called the no-argument form, whose
        // mint persists to the fixed production path, so every `cargo test` on a box that also
        // RUNS the agent replaced that machine's enrolled identity with an all-defaults config
        // carrying a fresh uuid. Confirmed on this box 2026-09-06: the gate stopped the agent and
        // the suite left `device_id` = a value appearing ZERO times in helper.log -- the same
        // unexplained-third-id signature recorded for the machine that went down on 2026-09-04.
        let path = temp_config_path("unmanaged");
        let mut cfg = unenrolled_cfg("unmanaged");
        let id = cfg.device_id_or_dev_fallback_in(&path).expect("dev fallback mints an id");
        assert!(id.parse::<uuid::Uuid>().is_ok(), "dev fallback mints a UUID, got {id:?}");
        assert_eq!(cfg.device_id.as_deref(), Some(id.as_str()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn a_blank_control_plane_url_is_not_managed() {
        // A template-shipped `"control_plane_url": ""` must not strand the agent with no device id.
        // Uses the explicit-path form: the no-argument one persists to the real agent config.
        let path = temp_config_path("blank_cp");
        let mut cfg = HelperConfig {
            control_plane_url: Some("   ".into()),
            ..unenrolled_cfg("blank_cp")
        };
        assert!(!cfg.is_control_plane_managed());
        assert!(cfg.device_id_or_dev_fallback_in(&path).is_some());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    /// Write a plausible enrolled identity key and return its path.
    fn temp_identity_key(tag: &str, contents: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("rmt_id_{tag}_{}.key", uuid::Uuid::new_v4()));
        let p = p.to_string_lossy().into_owned();
        std::fs::write(&p, contents).unwrap();
        p
    }

    /// THE 2026-09-04 CASE, and the one the old guard could not see.
    ///
    /// Every field the old guard read had been blanked, so it flipped off and the agent minted a
    /// uuid the control plane had never issued -- while holding the real enrolled key. Signaling
    /// answered `device identity unknown` forever. The key on disk is the signal that survives a
    /// blanked config, because it is not IN the config.
    #[test]
    fn an_enrolled_identity_key_forbids_minting_even_when_every_other_field_is_blank() {
        let key = temp_identity_key("enrolled", &"a".repeat(64));
        let path = temp_config_path("enrolled");
        let mut cfg = HelperConfig {
            // Exactly the shape read off the broken machine: mandatory fields present but EMPTY.
            signaling_url: Some(String::new()),
            control_plane_url: Some(String::new()),
            tenant_id: Some(String::new()),
            device_id: Some(String::new()),
            identity_path: Some(key.clone()),
            ..Default::default()
        };
        let why = cfg.managed_identity_evidence().expect("an enrolled key must forbid minting");
        assert!(why.contains("identity key"), "the reason must name the key, got {why:?}");
        assert_eq!(cfg.device_id_or_dev_fallback_in(&path), None);
        assert!(
            !std::path::Path::new(&path).exists(),
            "refusing to mint must also refuse to WRITE; a persisted invention is the whole bug",
        );
        let _ = std::fs::remove_file(&key);
    }

    /// NEGATIVE CONTROL for the test above. Without it the guard could be "any file at that path"
    /// and still pass -- and `enroll` touches the key file before it has anything to put in it.
    #[test]
    fn an_empty_identity_key_file_is_not_an_enrolled_identity() {
        let key = temp_identity_key("empty", "");
        let path = temp_config_path("empty_key");
        let mut cfg = HelperConfig {
            identity_path: Some(key.clone()),
            ..Default::default()
        };
        assert_eq!(cfg.managed_identity_evidence(), None, "a zero-byte key is not an identity");
        assert!(
            cfg.device_id_or_dev_fallback_in(&path).is_some(),
            "a zero-byte key must not strand an unmanaged dev agent",
        );
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn an_enrolled_tenant_id_forbids_minting() {
        let path = temp_config_path("tenant");
        let mut cfg = HelperConfig {
            tenant_id: Some("87cbc6d3-2fc2-4d36-93f9-a36231582d29".into()),
            ..unenrolled_cfg("tenant")
        };
        assert!(cfg.managed_identity_evidence().is_some());
        assert_eq!(cfg.device_id_or_dev_fallback_in(&path), None);
    }

    #[test]
    fn a_pending_enrollment_token_forbids_minting() {
        // The control plane is about to mint this machine an id. Inventing one first is how a
        // machine ends up with an id nobody issued and an orphaned row server-side.
        let path = temp_config_path("token");
        let mut cfg = HelperConfig {
            enrollment_token: Some("tok-abc".into()),
            ..unenrolled_cfg("token")
        };
        assert!(cfg.managed_identity_evidence().is_some());
        assert_eq!(cfg.device_id_or_dev_fallback_in(&path), None);
    }

    /// Two processes minting at once must AGREE, not merely both be quick.
    ///
    /// The unlocked mint is a read-modify-write over a whole-file rewrite, so the later writer
    /// silently replaced the earlier one's identity -- which is how one machine carried three ids
    /// at once, none of which the control plane agreed with.
    #[test]
    fn racing_minters_converge_on_one_device_id() {
        let path = temp_config_path("race");
        let ids: Vec<String> = std::thread::scope(|sc| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    sc.spawn(move || {
                        let mut cfg = unenrolled_cfg("race");
                        cfg.device_id_or_dev_fallback_in(&path).expect("each racer gets an id")
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("racer")).collect()
        });
        let first = &ids[0];
        assert!(
            ids.iter().all(|id| id == first),
            "eight racing minters produced disagreeing ids: {ids:?}",
        );
        let on_disk = HelperConfig::load_from(&path).expect("config was persisted");
        assert_eq!(
            on_disk.device_id.as_deref(),
            Some(first.as_str()),
            "the id every process uses must be the one that is actually on disk",
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    /// The blast-radius guard. A unit test that persists to the production path rewrites a live
    /// machine's identity; this makes that impossible to do accidentally rather than merely
    /// discouraged, so the defect cannot come back the way it arrived.
    ///
    /// Deliberately NOT `#[should_panic]`. `verify-all.ps1` fails any Rust run whose output
    /// contains `panicked at`, because that is the only way a panic on a detached task ever
    /// surfaces -- cargo swallows those and still exits 0. A `should_panic` test prints exactly
    /// that line, so it would red the entire Rust suite while passing itself. (Measured: it did.)
    /// The hook is global and tests share a process, so it is silenced for the narrowest possible
    /// window; a concurrent panic in that window still FAILS its own test, only more quietly.
    #[test]
    fn a_unit_test_cannot_write_the_production_config() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(|| {
            let _ = HelperConfig::default().save_to(CONFIG_FILE);
        });
        std::panic::set_hook(prev);

        let payload = result.expect_err("writing CONFIG_FILE from a unit test must panic");
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("REAL agent config"),
            "the guard must name what it refused, got {msg:?}",
        );
    }

    #[test]
    fn identity_path_falls_back_to_the_default() {
        let mut cfg = HelperConfig::default();
        assert_eq!(cfg.identity_path_or_default(), DEFAULT_IDENTITY_FILE);
        cfg.identity_path = Some("  ".into());
        assert_eq!(cfg.identity_path_or_default(), DEFAULT_IDENTITY_FILE);
        cfg.identity_path = Some(r"D:\keys\id.key".into());
        assert_eq!(cfg.identity_path_or_default(), r"D:\keys\id.key");
    }

    #[test]
    fn parses_the_m3_enrollment_keys() {
        let json = r#"{
            "signaling_url": "ws://relay.example:8080/ws",
            "control_plane_url": "https://cp.example:8443",
            "enrollment_token": "tok-abc",
            "device_id": "",
            "tenant_id": ""
        }"#;
        let cfg: HelperConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.is_control_plane_managed());
        assert_eq!(cfg.enrollment_token.as_deref(), Some("tok-abc"));
        assert_eq!(cfg.tenant_id.as_deref(), Some(""));
    }

    /// A config written before M11 must keep loading, with the quality ceiling absent — which the
    /// session driver turns into exactly the pre-M11 behaviour. Every field of the new key is
    /// optional for the same reason, so a partially-specified policy is also legal.
    #[test]
    fn a_pre_m11_config_still_parses_and_a_partial_policy_is_legal() {
        let json = r#"{"signaling_url":"ws://x/ws","device_id":"abc","stun":[],"transfer_dir":"C:\\t"}"#;
        let cfg: HelperConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.quality.is_none(), "absent quality key must parse, not fail");

        let partial = r#"{"device_id":"abc","quality":{"max_bitrate_bps":800000}}"#;
        let cfg: HelperConfig = serde_json::from_str(partial).unwrap();
        let q = cfg.quality.expect("policy present");
        assert_eq!(q.max_bitrate_bps, Some(800_000));
        assert_eq!(q.max_fps, None, "an unspecified bound stays unspecified");
        assert_eq!(q.adaptive, None);

        // An empty object is legal too, and means "all defaults".
        let empty = r#"{"device_id":"abc","quality":{}}"#;
        let cfg: HelperConfig = serde_json::from_str(empty).unwrap();
        let q = cfg.quality.expect("policy present");
        assert_eq!((q.max_bitrate_bps, q.max_fps, q.adaptive), (None, None, None));
    }

    #[test]
    fn a_pre_m3_config_still_parses() {
        // Existing installs have none of the M3 keys; they must keep loading untouched.
        let json = r#"{"signaling_url":"ws://x/ws","device_id":"abc","stun":[],"transfer_dir":"C:\\t"}"#;
        let cfg: HelperConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.device_id.as_deref(), Some("abc"));
        assert!(cfg.control_plane_url.is_none());
        assert!(cfg.enrollment_token.is_none());
        assert!(cfg.tenant_id.is_none());
        assert!(cfg.identity_path.is_none());
    }

    #[test]
    fn the_recording_dir_is_a_sibling_of_the_transfer_root_and_named_for_its_subdir() {
        // Two constants in two modules describing one directory. Pinned here rather than trusted,
        // because the failure is silent in both directions: rename the subdir and the sweep tidies
        // a directory nothing writes to, while recordings pile up untouched somewhere else.
        let rec = std::path::Path::new(DEFAULT_RECORDING_DIR);
        let xfer = std::path::Path::new(DEFAULT_TRANSFER_DIR);
        assert_eq!(
            rec.file_name().and_then(|s| s.to_str()),
            Some(crate::recording::DEFAULT_RECORDING_SUBDIR),
            "the recording dir must be named for the subdir constant the recorder documents"
        );
        assert_eq!(rec.parent(), xfer.parent(), "both live under the one agent root");
        assert_ne!(rec, xfer, "and they are different directories");
    }

    #[test]
    fn an_absent_canvas_capture_leaves_the_dxgi_canvas_on() {
        let cfg: HelperConfig = serde_json::from_str(r#"{"signaling_url":"ws://x/ws"}"#).unwrap();
        assert_eq!(cfg.canvas_capture, None);
        let gdi: HelperConfig = serde_json::from_str(r#"{"canvas_capture":"gdi"}"#).unwrap();
        assert_eq!(gdi.canvas_capture.as_deref(), Some("gdi"));
    }

    #[test]
    fn round_trips_through_a_temp_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("rmt_cfg_test_{}.json", uuid::Uuid::new_v4()));
        let path = path.to_string_lossy().into_owned();

        let cfg = HelperConfig {
            allow_cli_recording: true,
            signaling_url: Some("ws://loopback/ws".into()),
            device_id: Some("11111111-1111-1111-1111-111111111111".into()),
            stun: vec!["stun:example:3478".into()],
            transfer_dir: Some(r"D:\transfers".into()),
            grant_issuer_pubkey: Some("a".repeat(64)),
            // Deliberately DIFFERENT from grant_issuer_pubkey above. A round trip that used the
            // same value for both would still pass if the two fields were swapped or aliased in
            directive_pubkey: Some("c".repeat(64)),
            // serde — and those two fields being the same value is precisely the misconfiguration
            // `UpdateTrust::from_config` exists to refuse (docs/21 §3).
            update_signer_pubkey: Some("b".repeat(64)),
            require_session_policy: true,
            control_plane_url: Some("https://cp.example:8443".into()),
            enrollment_token: None,
            tenant_id: Some("22222222-3333-4444-5555-666666666666".into()),
            identity_path: Some(r"D:\keys\id.key".into()),
            quality: Some(QualityPolicyConfig {
                max_bitrate_bps: Some(1_500_000),
                max_fps: Some(20),
                adaptive: Some(false),
            }),
            max_session_secs: Some(7200),
            // Deliberately NOT the default variant: a round trip that starts at the default proves
            // nothing about serialization, since a field that failed to persist would come back
            // looking correct.
            clipboard: ClipboardMode::ToGuest,
            canvas_capture: Some("gdi".into()),
        };
        cfg.save_to(&path).unwrap();
        let back = HelperConfig::load_from(&path).expect("reload");
        assert!(back.allow_cli_recording, "explicit broker opt-in must survive saving");
        let q = back.quality.expect("quality policy round-trips");
        assert_eq!(q.max_bitrate_bps, Some(1_500_000));
        assert_eq!(q.max_fps, Some(20));
        assert_eq!(q.adaptive, Some(false));
        assert_eq!(back.max_session_secs, Some(7200), "the session limit round-trips");
        assert_eq!(back.canvas_capture.as_deref(), Some("gdi"), "the canvas escape hatch round-trips");
        assert_eq!(back.signaling_url, cfg.signaling_url);
        assert_eq!(back.device_id, cfg.device_id);
        assert_eq!(back.stun, cfg.stun);
        assert_eq!(back.transfer_dir, cfg.transfer_dir);
        assert_eq!(back.grant_issuer_pubkey, cfg.grant_issuer_pubkey);
        assert_eq!(back.update_signer_pubkey, cfg.update_signer_pubkey);
        assert_eq!(back.directive_pubkey, cfg.directive_pubkey, "the directive pin round-trips (docs/65 D-C3)");
        assert_ne!(
            back.update_signer_pubkey, back.grant_issuer_pubkey,
            "the two keys must not be aliased by serde"
        );
        // A new config field must survive the JSON round trip like every other one; this is the guard
        // that catches a serde rename or a forgotten #[serde(default)].
        assert_eq!(back.require_session_policy, cfg.require_session_policy);
        assert_eq!(back.control_plane_url, cfg.control_plane_url);
        assert_eq!(back.enrollment_token, cfg.enrollment_token);
        assert_eq!(back.tenant_id, cfg.tenant_id);
        assert_eq!(back.identity_path, cfg.identity_path);
        assert_eq!(back.clipboard, ClipboardMode::ToGuest, "the clipboard mode round-trips");
        let _ = std::fs::remove_file(&path);
    }

    // --- the clipboard machine ceiling ----------------------------------------------------------

    #[test]
    fn an_absent_clipboard_setting_means_the_behaviour_the_agent_already_had() {
        // Every config written before this field existed omits it. Those installs must keep working
        // exactly as they did — this is a governance knob, not a feature removal delivered by
        // upgrade. Same reasoning as `require_session_policy` defaulting false.
        let cfg: HelperConfig = serde_json::from_str(r#"{"signaling_url":"ws://x/ws"}"#).unwrap();
        assert_eq!(cfg.clipboard, ClipboardMode::Bidirectional);
        assert!(cfg.clipboard.allows_to_technician());
        assert!(cfg.clipboard.allows_to_guest());
        assert!(cfg.clipboard.any());
    }

    #[test]
    fn each_clipboard_mode_permits_exactly_the_directions_it_names() {
        // A truth table, because the whole value of a four-variant enum over a bool is that the two
        // directions are independent, and an accessor that got one backwards would be a silent
        // hole in exactly the direction an administrator thought they had closed.
        let cases = [
            (ClipboardMode::Bidirectional, true, true, true),
            (ClipboardMode::ToTechnician, true, false, true),
            (ClipboardMode::ToGuest, false, true, true),
            (ClipboardMode::Disabled, false, false, false),
        ];
        for (mode, out, in_, any) in cases {
            assert_eq!(mode.allows_to_technician(), out, "{mode:?}.allows_to_technician()");
            assert_eq!(mode.allows_to_guest(), in_, "{mode:?}.allows_to_guest()");
            assert_eq!(mode.any(), any, "{mode:?}.any()");
        }
    }

    #[test]
    fn every_clipboard_mode_round_trips_under_its_documented_json_name() {
        // The names are an operator-facing contract: they appear in config.template.json, in the
        // installer, and in whatever an administrator types by hand.
        for (json, mode) in [
            ("\"bidirectional\"", ClipboardMode::Bidirectional),
            ("\"to_technician\"", ClipboardMode::ToTechnician),
            ("\"to_guest\"", ClipboardMode::ToGuest),
            ("\"disabled\"", ClipboardMode::Disabled),
        ] {
            assert_eq!(serde_json::from_str::<ClipboardMode>(json).unwrap(), mode);
            assert_eq!(serde_json::to_string(&mode).unwrap(), json);
        }
    }

    /// The Windows path and the portable basename must agree. They live in different crates —
    /// `rmt-agent` owns the manifest type and must build off Windows, `rmt-agent-windows` owns the
    /// `C:\` path — so nothing but this test stops one from being renamed without the other. The
    /// symptom of a drift is the worst kind for this feature: the agent looks for a file the
    /// operator did not write, finds nothing, reports "no manifest", and updates silently never
    /// happen.
    #[test]
    fn the_manifest_path_matches_the_portable_basename() {
        assert!(
            UPDATE_MANIFEST_FILE.ends_with(rmt_agent::update::MANIFEST_FILENAME),
            "{UPDATE_MANIFEST_FILE} does not end with {}",
            rmt_agent::update::MANIFEST_FILENAME
        );
        // …and it must sit in the directory `harden_agent_root` actually protects, beside
        // config.json. A manifest anywhere else has no ACL story at all.
        assert_eq!(
            UPDATE_MANIFEST_FILE,
            format!("{CONFIG_DIR}\\{}", rmt_agent::update::MANIFEST_FILENAME)
        );
        assert!(CONFIG_FILE.starts_with(CONFIG_DIR), "premise: config.json is in the hardened root");
    }

    #[test]
    fn an_unrecognised_clipboard_mode_is_refused_rather_than_silently_permissive() {
        // THE ONE THAT MATTERS for an off switch. A typo must not read as "bidirectional" — an
        // administrator who wrote "disable" or "off" and got a working clipboard would believe they
        // had turned it off. Loading the file fails, which is loud, instead of granting more than
        // was asked for, which is silent.
        for bad in ["\"off\"", "\"disable\"", "\"Disabled\"", "\"disabled \"", "false", "0"] {
            assert!(
                serde_json::from_str::<ClipboardMode>(bad).is_err(),
                "{bad} must not parse as a clipboard mode",
            );
        }
    }
}
