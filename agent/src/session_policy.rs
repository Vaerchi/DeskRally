//! Cryptographically-signed, expiring **session policies** — the control plane telling the AGENT
//! what a live support session is allowed to do (loop 79, docs/01 §3/§5).
//!
//! # Why this exists
//!
//! Loops 30–32 gave the product a view-only mode, but it is a *self-set toggle*: the controller
//! sends `ControlMessage::SetViewOnly` and the agent obeys, so the same controller can turn it
//! straight back off. Nothing the ORGANISATION decides can bind the session, because a plain
//! view/control session installs no signed material at all — the agent's only trusted channel (the
//! H1 backstage [`SignedGrant`](crate::backstage::grant::SignedGrant)) is scoped to backstage
//! tooling and is never installed for an ordinary screen-share.
//!
//! A [`SignedSessionPolicy`] is the missing piece: the control plane mints it for a specific
//! (technician, session, machine) at session start, signs it with the SAME long-term Ed25519
//! identity it already uses for grants, and the agent verifies it against its pinned issuer key
//! before applying it. An operator policy (today: "this machine group is view-only") therefore
//! arrives as an authenticated fact the agent enforces, not a request the viewer may decline.
//!
//! # Replay safety: the ratchet rule, and (since loop 86) session binding
//!
//! **The ratchet.** A verified policy may only ever *restrict* a session, never relax it. The agent
//! keeps the most restrictive [`AccessLevel`] it has ever verified for the live session and refuses
//! any later policy that claims MORE access (see `host.rs`). So an attacker who captures a `Control`
//! policy from an earlier session cannot install it to escape a `ViewOnly` policy in force now, and
//! replaying an OLD `ViewOnly` policy only ever restricts, which is harmless.
//!
//! **Why the ratchet alone stopped being enough.** It leaves one door open: a session that has seen
//! NO policy yet, and is holding the PROVISIONAL floor `require_session_policy` opens with. A
//! `Control` policy discharges that floor — it is supposed to, that is how a floored agent is
//! released. Until loop 86 every `Control` policy this system minted named an EPHEMERAL attended
//! device id that served one session and never existed again, so a captured one had nowhere to be
//! replayed. Migration 0037 mints `Control` for PERMANENT machines, which ends that containment.
//!
//! **Session binding replaces it.** [`SignedSessionPolicy::verify`] now takes a [`SessionBinding`]
//! and requires the policy's `session_id` to equal the live session's — the id the agent learns from
//! `brokered`, put there by a signaling server that verified the control plane's signature on the
//! controller's session ticket. A policy captured in one session is therefore rejected in every
//! other, and rejection is terminal for the session ([`SessionAccessState::reject_unverified`]), so
//! attempting the replay costs the attacker the session instead of winning them one. When the agent
//! cannot learn the id at all, [`SessionBinding::Unknown`] rejects rather than waves through.
//!
//! Elevation — the §3 "elevate client to admin mid-session" box — is deliberately NOT expressible
//! here, and never will be: a policy may only RESTRICT, and that one-way rule is what makes
//! replaying an old one harmless in the first place. Expressed as a policy, elevation would be a
//! ratchet running the wrong way. It has its own explicitly-designed, freshness-checked message
//! since loop 87 — [`crate::elevation`], domain tag `RMTELEVv1`, single-use and session-bound. If
//! you are reading this while adding a permission to [`AccessLevel`], that is the shape to copy for
//! anything that GRANTS.
//!
//! # Wire shape
//!
//! Mirrors [`crate::backstage::grant`] exactly, so the two verify paths read the same:
//!
//! ```json
//! {
//!   "claims": {
//!     "policy": { "technician_id": "…", "session_id": "…", "machine_id": "…",
//!                 "access": "view_only" },
//!     "issued_at_ms": 1730000000000,
//!     "expires_at_ms": 1730000900000
//!   },
//!   "sig": "<128 hex chars>"
//! }
//! ```
//!
//! # Canonical signing bytes (session-policy v1 — big-endian throughout)
//!
//! ```text
//! SESSION_POLICY_DOMAIN_TAG                   // 12 bytes: b"RMTSPOLv1\x00\x00\x00"
//! || technician_id                            // 16 raw bytes
//! || session_id                               // 16 raw bytes
//! || machine_id                               // 16 raw bytes
//! || u32be(len(access_utf8)) || access_utf8   // "view_only" | "control"
//! || i64be(issued_at_ms)
//! || i64be(expires_at_ms)
//! || u8(allow_recording)                      // 0x01 = allowed, 0x00 = banned (since loop 87/0043)
//! || u8(require_recording)                    // 0x01 = mandatory, 0x00 = optional (since loop 89/0044)
//! || u32be(max_session_duration_seconds)      // 0 = unlimited (since loop 90/0045)
//! || u32be(max_idle_seconds)                  // 0 = unlimited (since loop 91/0046)
//! ```
//!
//! The domain tag differs from the grant's and the audit chain's, so a signature over one preimage
//! can never be reinterpreted as another (see [`crate::backstage::canonical`]). Cross-language
//! agreement with the Go minter is proven by shared golden vectors: `tests::golden_vector_v1` here
//! and `TestSessionPolicyGoldenVectorV1` in `control-plane/session_policy_grant_test.go` assert the
//! SAME fixture produces the SAME canonical-bytes hex AND the SAME signature hex.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use rmt_crypto::{Identity, PublicIdentity};

use crate::backstage::canonical::CanonicalWriter;
use crate::backstage::grant::CLOCK_SKEW_MS;

/// What a session is permitted to do with the guest's input devices.
///
/// A NAMED enum rather than a `bool` or an `Option`, deliberately: this crate has been bitten once
/// by an absent-means-allow default (the `Option<Vec<Capability>>` whose `None` granted all 19
/// backstage capabilities). Here the restrictive variant is [`AccessLevel::ViewOnly`] AND it is the
/// [`Default`], so every "we could not work out what was meant" path lands on deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    /// Watch only: the agent DROPS the controller's injected input and refuses the write-actions
    /// (reboot / tool-launch / command-run / lock / log-off / shut-down), exactly as the loop-32
    /// read-only access level does. The default, so an unparseable or absent level denies.
    #[default]
    ViewOnly,
    /// Full remote control: input is injected and the write-actions are permitted.
    Control,
}

impl AccessLevel {
    /// The canonical snake_case name of this level — the exact string serde emits, used both in the
    /// claims JSON and (length-prefixed) in the canonical signing bytes, so it MUST match serde
    /// exactly (`tests::access_level_name_matches_serde` asserts that for every variant).
    ///
    /// Every variant is enumerated explicitly (no catch-all) so adding a level fails to compile
    /// until its canonical name is defined here — the same anti-drift discipline
    /// [`capability_name`](crate::backstage::canonical::capability_name) uses, mirrored in Go by
    /// `accessLevelName`.
    pub fn name(self) -> &'static str {
        match self {
            AccessLevel::ViewOnly => "view_only",
            AccessLevel::Control => "control",
        }
    }

    /// True when this level forbids injected input (i.e. it IS the view-only level). Written as a
    /// method rather than an `== ViewOnly` at each call site so a future third level has ONE place
    /// to declare which side of the input gate it falls on.
    pub fn is_view_only(self) -> bool {
        matches!(self, AccessLevel::ViewOnly)
    }

    /// The more restrictive of `self` and `other` — the ratchet used to fold a newly-verified
    /// policy into the one already in force. [`AccessLevel::ViewOnly`] dominates.
    pub fn most_restrictive(self, other: AccessLevel) -> AccessLevel {
        if self.is_view_only() || other.is_view_only() {
            AccessLevel::ViewOnly
        } else {
            AccessLevel::Control
        }
    }
}

fn default_allow_recording() -> bool { true }

/// What the control plane decided about one live session, bound to the machine it was minted for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPolicy {
    /// The technician the control plane authenticated when it minted this policy.
    pub technician_id: uuid::Uuid,
    /// The control-plane session record this policy governs, and (since loop 86) a CHECKED binding:
    /// [`SignedSessionPolicy::verify`] requires it to equal the live session id the agent learned
    /// from `brokered`. See the module docs — this is what stops a `Control` policy captured in one
    /// session from discharging a later session's provisional floor at the same permanent machine.
    pub session_id: uuid::Uuid,
    /// The device this policy is bound to. Verification REQUIRES this to equal the agent's own
    /// machine id, so a policy minted for machine A is not replayable to machine B.
    pub machine_id: uuid::Uuid,
    /// The access level the agent must enforce for this session.
    pub access: AccessLevel,
    /// Whether the control plane permits recording for this session. When `false` the agent must
    /// refuse `StartRecording` requests for the session's lifetime. Defaults to `true` on
    /// deserialization so a policy minted before this field existed is treated as permissive —
    /// the fail-OPEN default is deliberate: a ban is the restriction, not the baseline.
    #[serde(default = "default_allow_recording")]
    pub allow_recording: bool,
    /// Whether recording is mandatory for this session. When `true` the agent must auto-start
    /// recording and refuse `StopRecording` for the session's lifetime. Defaults to `false` on
    /// deserialization so a policy minted before this field existed is treated as optional —
    /// the fail-open default is correct: mandatory recording is the restriction, not the baseline.
    #[serde(default)]
    pub require_recording: bool,
    /// Per-group hard session time limit in seconds; 0 = unlimited. When non-zero the agent ends
    /// the session when `elapsed >= max_session_duration_seconds`. Defaults to `0` on
    /// deserialization so a policy minted before this field existed is treated as unlimited —
    /// the fail-open default is correct: a duration cap is the restriction, not the baseline.
    #[serde(default)]
    pub max_session_duration_seconds: u32,
    /// Per-group idle timeout in seconds; 0 = unlimited. When non-zero the agent ends the session
    /// when no controller keyboard/mouse input has arrived for this many consecutive seconds.
    /// Defaults to `0` on deserialization so a policy minted before this field existed is treated
    /// as unlimited — the fail-open default is correct: an idle cap is a restriction, not the
    /// baseline.
    #[serde(default)]
    pub max_idle_seconds: u32,
}

/// The signed payload: a [`SessionPolicy`] plus its validity window (Unix milliseconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicyClaims {
    /// The policy the agent will enforce once these claims verify.
    pub policy: SessionPolicy,
    /// When the control plane minted this policy (Unix ms).
    pub issued_at_ms: i64,
    /// When this policy stops being valid (Unix ms, exclusive).
    pub expires_at_ms: i64,
}

impl SessionPolicyClaims {
    /// The deployed-baseline (735d5a28b3601dc5b87971b912bc61d9dd8ffd35) 6-field signing bytes,
    /// ending at `expires_at_ms`. Old agents compute THIS and verify JSON `"sig"` against it.
    /// New agents use this only in `SignedSessionPolicy::verify` when falling back to `"sig"`.
    pub(crate) fn signing_bytes_v0(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.session_policy_tag()
            .raw16(self.policy.technician_id.as_bytes())
            .raw16(self.policy.session_id.as_bytes())
            .raw16(self.policy.machine_id.as_bytes())
            .lp_str(self.policy.access.name())
            .i64(self.issued_at_ms)
            .i64(self.expires_at_ms);
        w.into_bytes()
    }

    /// The canonical session-policy-v1 signing bytes (10 fields; see module docs).
    /// This is what the issuer signs into `"sig_v1"` and new agents verify against.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.session_policy_tag()
            .raw16(self.policy.technician_id.as_bytes())
            .raw16(self.policy.session_id.as_bytes())
            .raw16(self.policy.machine_id.as_bytes())
            .lp_str(self.policy.access.name())
            .i64(self.issued_at_ms)
            .i64(self.expires_at_ms)
            .u8(if self.policy.allow_recording { 1 } else { 0 })
            .u8(if self.policy.require_recording { 1 } else { 0 })
            .u32(self.policy.max_session_duration_seconds)
            .u32(self.policy.max_idle_seconds);
        w.into_bytes()
    }

    /// Sign these claims with the issuer's long-term identity (new-agent format: sig_v1 only).
    pub fn sign(&self, issuer: &Identity) -> SignedSessionPolicy {
        let sig = issuer.sign(&self.signing_bytes());
        SignedSessionPolicy { claims: self.clone(), sig_v1: hex::encode(sig), sig: String::new() }
    }
}

/// A [`SessionPolicyClaims`] plus the issuer's Ed25519 signature over its canonical signing bytes.
///
/// Two signature fields support mixed-version deployments:
///
/// * **`sig_v1`** (JSON `"sig_v1"`): the authoritative v1-preimage (10-field) signature — covers
///   ALL policy fields. New agents MUST verify this field when present.
/// * **`sig`** (JSON `"sig"`): a v0-preimage (6-field) signature, emitted only for
///   **non-restrictive** policies. Deployed agents at SHA 735d5a28 verify `"sig"` against the
///   6-field preimage (ending at `expires_at_ms`) they compute locally — so `"sig"` MUST carry a
///   v0 sig, NOT a copy of `"sig_v1"`. For restrictive policies this field is absent so deployed
///   agents fail closed.
///
/// `verify` prefers `sig_v1` (verified against `signing_bytes()`) and falls back to `sig`
/// (verified against `signing_bytes_v0()`). `"sig"` ≠ `"sig_v1"` in value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSessionPolicy {
    /// The signed claims.
    pub claims: SessionPolicyClaims,
    /// Authoritative v1 sig (JSON `"sig_v1"`). Preferred by new agents. Absent in old-CP wire.
    #[serde(rename = "sig_v1", default, skip_serializing_if = "String::is_empty")]
    pub sig_v1: String,
    /// Old-agent-compat v0-preimage sig (JSON `"sig"`). Absent for restrictive policies (fail
    /// old agents closed). When `sig_v1` is present this field is ignored by `verify`.
    #[serde(rename = "sig", default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

impl SignedSessionPolicy {
    /// Encode to the JSON wire string carried opaquely in the Control channel's
    /// `InstallSessionPolicy` message (so `rmt-agent-core` need not depend on `rmt-agent`).
    pub fn to_json(&self) -> Result<String, SessionPolicyError> {
        serde_json::to_string(self).map_err(|e| SessionPolicyError::Encoding(e.to_string()))
    }

    /// Decode from the JSON wire string. Does **not** verify — call [`verify`](Self::verify).
    pub fn from_json(s: &str) -> Result<Self, SessionPolicyError> {
        serde_json::from_str(s).map_err(|e| SessionPolicyError::Encoding(e.to_string()))
    }

    /// Verify the signature against the pinned `issuer`, check the validity window against
    /// `now_ms`, bind the policy to this DEVICE by requiring `machine_id == expected_machine_id`,
    /// and bind it to this SESSION per `binding`.
    ///
    /// Order mirrors [`SignedGrant::verify`](crate::backstage::grant::SignedGrant::verify)
    /// deliberately: signature FIRST (so a forged policy is rejected before any of its self-claimed
    /// fields are trusted), then not-yet-valid with [`CLOCK_SKEW_MS`] tolerance, then expiry
    /// (exact), then the device binding, then the session binding.
    ///
    /// The session binding comes LAST on purpose. It is the newest and narrowest check, and putting
    /// it after the device binding keeps the error a caller sees the most general true one: a policy
    /// meant for another machine reports `WrongMachine` rather than `WrongSession`, which is the more
    /// useful thing to see in a log. Both are rejections, so nothing rides on the order for safety —
    /// only on legibility. What DOES ride on order is the signature staying first.
    pub fn verify(
        &self,
        issuer: &PublicIdentity,
        now_ms: i64,
        expected_machine_id: uuid::Uuid,
        binding: SessionBinding,
    ) -> Result<SessionPolicy, SessionPolicyError> {
        // Prefer sig_v1 (new-CP: v1 preimage). Fall back to sig (old-CP: v0 preimage).
        // Deployed agents at 735d5a28 only emit "sig" and verify it against a 6-field v0 preimage.
        // New CP emits "sig" = v0 sig and "sig_v1" = v1 sig (different values, different preimages).
        //
        // When using the v0 fallback, the preimage ends at `expires_at_ms` — it does NOT cover the
        // 4 extension fields (allow_recording, require_recording, max_session_duration_seconds,
        // max_idle_seconds). An attacker who intercepts a non-restrictive v0-only envelope can inject
        // any value into those fields without invalidating the signature. Tracked as `v0_path` so
        // `verify` can sanitize those fields back to permissive defaults before returning.
        let v0_path = self.sig_v1.is_empty();
        let (sig_hex, bytes) = if !self.sig_v1.is_empty() {
            (&self.sig_v1, self.claims.signing_bytes())
        } else if !self.sig.is_empty() {
            (&self.sig, self.claims.signing_bytes_v0())
        } else {
            return Err(SessionPolicyError::Encoding(
                "no signature field present (sig_v1 or sig required)".into(),
            ));
        };
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|_| SessionPolicyError::Encoding("signature is not hex".into()))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SessionPolicyError::Encoding("signature is not 64 bytes".into()))?;

        issuer.verify(&bytes, &sig).map_err(|_| SessionPolicyError::BadSignature)?;

        if now_ms + CLOCK_SKEW_MS < self.claims.issued_at_ms {
            return Err(SessionPolicyError::NotYetValid);
        }
        if now_ms >= self.claims.expires_at_ms {
            return Err(SessionPolicyError::Expired);
        }
        if self.claims.policy.machine_id != expected_machine_id {
            return Err(SessionPolicyError::WrongMachine {
                expected: expected_machine_id,
                found: self.claims.policy.machine_id,
            });
        }
        match binding {
            SessionBinding::Session(expected) => {
                if self.claims.policy.session_id != expected {
                    return Err(SessionPolicyError::WrongSession {
                        expected,
                        found: self.claims.policy.session_id,
                    });
                }
            }
            // Not a pass-through. An agent that cannot name its own session cannot tell a policy
            // minted for it from one captured elsewhere, and accepting the second is the whole
            // attack. Refusing costs a dev deployment its policies; accepting would cost a real one
            // its floor.
            SessionBinding::Unknown => return Err(SessionPolicyError::UnboundSession),
        }

        // Extension fields not authenticated by the v0 preimage are sanitized to their permissive
        // defaults. This prevents an attacker from injecting restrictions (e.g. require_recording=true,
        // allow_recording=false, duration/idle caps) into a v0-only envelope: those bytes are never
        // included in the preimage so any value passes the v0 signature check. Old CPs never set these
        // fields at all, so permissive defaults faithfully represent their intent. New CPs only emit
        // "sig" (v0) for non-restrictive policies — restriction bytes are always permissive there too.
        if v0_path {
            let mut policy = self.claims.policy.clone();
            policy.allow_recording = true;
            policy.require_recording = false;
            policy.max_session_duration_seconds = 0;
            policy.max_idle_seconds = 0;
            Ok(policy)
        } else {
            Ok(self.claims.policy.clone())
        }
    }
}

/// The view-only state of ONE live session, and the only place the rules that produce it live.
///
/// Extracted from the session loop deliberately. The rules are small but they compose in ways that are
/// easy to get subtly wrong — a provisional floor, a policy floor, a technician toggle, and a ratchet
/// that must let exactly one of them be lifted exactly once — and inline in `host.rs` they were
/// unreachable by any test: `host.rs` needs a live transport, a capturer and a Windows desktop. As a
/// plain struct the whole security core is a truth table.
///
/// The four sources of view-only, and how they compose:
///
/// * **the observer floor** — present from construction and NEVER lifted. A separate field because
///   the technician may clear the toggle, and a control policy may leave the policy floor unset;
///   neither represents a restriction that must hold from the first frame with no way to lift it.
///
/// * **the provisional floor** — with `require_policy`, the session opens view-only and stays there
///   until a policy verifies. This is what stops a technician bypassing a mandate by simply not
///   forwarding the frame (the viewer is the party the mandate binds). It is the ONE floor a signature
///   may lift, and only the FIRST verified policy may lift it.
/// * **the policy floor** — set by a verified policy, and RATCHETED: once view-only, later policies can
///   never relax it. This is what makes replay harmless, since the agent cannot judge freshness.
/// * **the toggle** — the technician's own `SetViewOnly`. Composes on top; it can always add
///   restriction and can only remove its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAccessState {
    observer: bool,
    require_policy: bool,
    policy_seen: bool,
    policy_view_only: bool,
    toggle_view_only: bool,
}

impl SessionAccessState {
    /// A fresh regular session. `require_policy` mirrors the agent's `require_session_policy` config.
    pub fn new(require_policy: bool) -> Self {
        Self { observer: false, require_policy, policy_seen: false, policy_view_only: false, toggle_view_only: false }
    }

    /// A fresh observer session, permanently view-only from the first frame.
    ///
    /// Unlike the technician's toggle or a policy floor that a control policy leaves unset, this
    /// floor has NO way to be lifted, so it is stored separately from both.
    pub fn new_observer(require_policy: bool) -> Self {
        Self { observer: true, ..Self::new(require_policy) }
    }

    /// Is this session subject to the permanent observer floor?
    pub fn is_observer(&self) -> bool {
        self.observer
    }

    /// Is the agent dropping the technician's injected input right now? This is the value every
    /// view-only gate in the session loop reads — input, reboot, tool-launch, command-run, lock,
    /// log-off, shut-down — so a source of restriction added here is honoured by all of them at once.
    pub fn view_only(&self) -> bool {
        self.observer || self.toggle_view_only || self.policy_view_only || self.awaiting_required_policy()
    }

    /// True while a session that REQUIRES a policy has not yet seen one verify — the provisional floor.
    pub fn awaiting_required_policy(&self) -> bool {
        self.require_policy && !self.policy_seen
    }

    /// Has any policy verified for this session yet?
    pub fn policy_seen(&self) -> bool {
        self.policy_seen
    }

    /// Apply a VERIFIED policy.
    ///
    /// The ratchet: the policy floor only ever tightens (`most_restrictive`), so replaying a captured
    /// `Control` policy can never lift a `ViewOnly` floor already in force. The one thing a policy DOES
    /// lift is the provisional floor, and only because arriving at all is the proof that was being
    /// waited for.
    pub fn install_verified(&mut self, access: AccessLevel) {
        let current =
            if self.policy_view_only { AccessLevel::ViewOnly } else { AccessLevel::Control };
        self.policy_view_only = current.most_restrictive(access).is_view_only();
        self.policy_seen = true;
    }

    /// Apply a policy that FAILED to verify, or that arrived at an agent with no issuer key to check it
    /// against.
    ///
    /// Fails CLOSED: the controller asked for a policy to be installed and the agent cannot tell what
    /// this session is allowed to do, so it takes the most restrictive reading. Deliberately does NOT
    /// set `policy_seen` — an unverifiable blob is not the proof a required policy is waiting for, so a
    /// session under `require_policy` stays provisionally floored as well.
    ///
    /// This cannot be abused: it only ever restricts, so a hostile controller spamming garbage merely
    /// denies itself input.
    pub fn reject_unverified(&mut self) {
        self.policy_view_only = true;
    }

    /// The technician's own `SetViewOnly`. Returns the state now in force, which is NOT always what was
    /// asked for — a floor may hold it view-only regardless.
    pub fn set_toggle(&mut self, enabled: bool) -> bool {
        self.toggle_view_only = enabled;
        self.view_only()
    }
}

/// -------------------------------------------------------------------------------------------
// SESSION LEASES (docs/25 F03) — what makes a central "End session" reach an unattended host.
// -------------------------------------------------------------------------------------------

/// How long a session may run after it starts without ever presenting a lease — the window in which
/// the FIRST [`SignedSessionPolicy`] has to arrive.
///
/// It exists because the policy is delivered by the VIEWER over the Control channel, and that
/// channel does not exist at the instant the session loop starts: ICE and DTLS have to complete,
/// the agent has to announce that it wants a lease, and the console has to make one HTTPS round trip
/// to the control plane. Fifteen seconds covers all of that with room for several retries (the agent
/// re-announces on every [`LEASE_TICK`]), and is comfortably shorter than the control plane's own
/// lease TTL, so the grace can never be the widest hole in the scheme.
///
/// **It cannot be used to run indefinitely without a lease.** It is an ABSOLUTE deadline measured
/// from the start of the session loop, computed once and never extended by anything — not by a
/// rejected policy, not by a re-announcement, not by traffic. A peer that never produces a lease has
/// exactly this long, once.
pub const DEFAULT_LEASE_GRACE: Duration = Duration::from_secs(15);

/// How often the session loop re-evaluates the lease (and re-announces while it holds none).
///
/// This is the RESOLUTION of the revocation bound, not the bound itself: an administrator's "End
/// session" takes effect when the last lease expires, and the agent notices within one tick of that.
/// So the honest worst case is `control-plane lease TTL + LEASE_TICK`.
pub const LEASE_TICK: Duration = Duration::from_secs(2);

/// Whether THIS session's authority is a control-plane lease that has to be kept renewed.
///
/// A named enum rather than a `bool`, for the reason this file keeps rediscovering: "we could not
/// work out whether this session is leased" and "this session is deliberately not leased" are
/// different facts and must not share a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionLeaseMode {
    /// **The default, and the only one production uses.** Derive the answer from the session
    /// binding: a session the signaling server vouched for with a verified control-plane ticket IS
    /// leased; one it could not name ([`SessionBinding::Unknown`] — dev/LAN, or a signaling server
    /// run with `-insecure-no-ticket-verification`) is not, because there is no control plane in a
    /// position to revoke it and inventing one would only break local development.
    ///
    /// Deliberately NOT keyed on the agent's `require_session_policy` config flag. That flag is
    /// `#[serde(default)]` on a `bool` — false unless an operator set it, and false for a
    /// deliberate reason (an agent with no pinned issuer key cannot verify a policy, so defaulting
    /// it on would strand every session view-only). A lease keyed on it would bind on almost no
    /// deployment, which is worse than useless because it would look fixed.
    #[default]
    FromSessionBinding,
    /// Never enforce a lease. **The ATTENDED path**, and this is a decision rather than an omission:
    /// an attended guest already has a STRONGER revocation channel than a lease — `run_attend`
    /// polls `GET /attended-sessions/status` every three seconds and sets the agent's own `stop`
    /// when the control plane reports the session ended (see `spawn_attend_status_poller`).
    /// Attended and unattended sessions live in different tables and end through different routes,
    /// and the renewal endpoint only knows about `session_record`, so a leased attended session
    /// would be one whose renewals 404 — i.e. every attended session would die after the grace
    /// period for no security gain whatsoever.
    NotApplicable,
    /// Always enforce, whatever the binding says.
    ///
    /// The e2e harness uses this: it runs against a signaling server started **without** ticket
    /// verification, so `control_plane_session` is `None` there and `FromSessionBinding` would
    /// derive "not leased" — leaving the teardown path with no automated coverage at all, which is
    /// exactly the "a feature inert at its untested layer" shape this repo has shipped before.
    Required,
}

/// Why a leased session ran out of authority. Distinct variants because the two failures need
/// different operator responses: one means the viewer never started renewing, the other that it
/// stopped (or that the control plane refused to renew — which is what "End session" looks like
/// from here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseLapse {
    /// The grace window closed and no policy had ever verified for this session.
    NeverArrived,
    /// A lease was held and its expiry passed. `by_ms` is how far past it we are.
    Expired { by_ms: i64 },
}

/// The state of a session's lease at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseStatus {
    /// This session is not leased ([`SessionLeaseMode::NotApplicable`], an unbound session, or an
    /// agent with no pinned issuer key).
    NotEnforced,
    /// A lease is in force; `remaining_ms` is how long it has left.
    Held { remaining_ms: i64 },
    /// No lease yet, still inside the grace window. The session loop (re-)announces on this, so a
    /// viewer that missed the first announcement — or has only just finished connecting — gets
    /// another chance rather than losing the session to one dropped frame.
    AwaitingFirst { remaining_ms: i64 },
    /// Over. The session must end.
    Lapsed(LeaseLapse),
}

/// The lease held by ONE live session: whether one is required, when the current one expires, and
/// whether the grace window for the first one has closed.
///
/// # Why a lease and not a pushed revocation
///
/// `POST /sessions/{id}/end` used to update `session_record`, write a `session.end` audit row and
/// return success — and send nothing to signaling and nothing to the agent (docs/25 F03). An
/// unattended session ended only for a peer's *cooperative* `EndSession`, a local stop, transport
/// failure, or the session lifetime bound, so a hostile controller kept the desktop simply by not
/// cooperating. The administrator's primary incident-response control was cosmetic.
///
/// The fix is a LEASE rather than a pushed revocation because the control plane has no authenticated
/// channel to a running agent at all: the only agent to control-plane call in this product is
/// one-shot enrollment, so a push would mean designing, deploying and testing a second agent
/// authentication protocol. A lease needs none — it reuses the artifact the agent already verifies
/// ([`SignedSessionPolicy`]: Ed25519, pinned issuer, bound to technician + session + machine).
///
/// # The rule that makes it work, stated as sharply as possible
///
/// **The ABSENCE of a fresh lease ends the session. A bad lease ending it is not enough.**
///
/// The lease is delivered by the viewer — the very party the lease restrains — which sounds fatal
/// and is not. A hostile controller that stops renewing kills its own session; one that wants to
/// persist has to keep asking the control plane, which refuses the moment the session is ended, the
/// principal is disabled, the tenant is suspended or the machine is quarantined. There is nothing
/// for the controller to withhold that helps it.
///
/// # The bound, honestly
///
/// The worst case is a lease minted moments before the administrator clicks "End session": it
/// survives its own TTL. That IS the revocation window — the control plane's lease TTL plus one
/// [`LEASE_TICK`] of detection latency — and it is the number to quote, not a smaller one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLease {
    enforced: bool,
    grace: Duration,
    /// Wall-clock expiry (Unix ms) of the longest-lived policy that has VERIFIED for this session,
    /// or `None` while none has.
    ///
    /// The MAXIMUM rather than the most recent, and that is safe for a reason worth stating: every
    /// expiry here is an absolute instant chosen and signed by the control plane, so the maximum can
    /// never exceed the furthest instant the control plane ever agreed to, and the control plane
    /// stops agreeing the moment the session ends. Replaying a captured policy therefore buys a peer
    /// nothing beyond that artifact's own bounded life, while taking the maximum makes the scheme
    /// immune to renewals that arrive out of order — which they will, over HTTP.
    deadline_ms: Option<i64>,
}

impl SessionLease {
    /// Build the lease state for a session.
    ///
    /// `can_verify` is whether the agent has a pinned issuer key at all (`BackstageAuth::SignedBy`).
    /// It gates [`SessionLeaseMode::FromSessionBinding`] because an agent with no pinned key cannot
    /// tell a control-plane lease from an attacker's forgery, so "enforcement" there would be
    /// theatre: it could only ever end sessions, never authorize them. **This is a capability limit,
    /// not a compatibility fallback** — the agent says so loudly in its log at session start, and
    /// the control plane never mints a lease for such an agent because the agent never asks for one.
    pub fn new(
        mode: SessionLeaseMode,
        binding: SessionBinding,
        can_verify: bool,
        grace: Duration,
    ) -> Self {
        let enforced = match mode {
            SessionLeaseMode::Required => true,
            SessionLeaseMode::NotApplicable => false,
            SessionLeaseMode::FromSessionBinding => {
                can_verify && matches!(binding, SessionBinding::Session(_))
            }
        };
        Self { enforced, grace, deadline_ms: None }
    }

    /// Is this session leased?
    pub fn is_enforced(&self) -> bool {
        self.enforced
    }

    /// Fold a VERIFIED policy's expiry into the lease. Called only after
    /// [`SignedSessionPolicy::verify`] has succeeded, so `expires_at_ms` is authenticated.
    pub fn record_verified(&mut self, expires_at_ms: i64) {
        self.deadline_ms = Some(match self.deadline_ms {
            Some(d) => d.max(expires_at_ms),
            None => expires_at_ms,
        });
    }

    /// Whether any lease has ever been held. Used to log the difference between "the viewer never
    /// started renewing" and "the viewer stopped".
    pub fn ever_held(&self) -> bool {
        self.deadline_ms.is_some()
    }

    /// Evaluate the lease. `now_ms` is wall clock (the signed expiry is wall clock, so the
    /// comparison must be); `since_start` is monotonic elapsed session time, so a system clock jump
    /// cannot lengthen the grace window.
    pub fn status(&self, now_ms: i64, since_start: Duration) -> LeaseStatus {
        if !self.enforced {
            return LeaseStatus::NotEnforced;
        }
        match self.deadline_ms {
            Some(deadline) => {
                // Exclusive, exactly like `SignedSessionPolicy::verify`: at `expires_at_ms` the
                // policy is already too late. Keeping the two comparisons identical is what stops a
                // lease counting as live one millisecond after the artifact carrying it stopped
                // being installable.
                if now_ms >= deadline {
                    LeaseStatus::Lapsed(LeaseLapse::Expired { by_ms: now_ms - deadline })
                } else {
                    LeaseStatus::Held { remaining_ms: deadline - now_ms }
                }
            }
            None => {
                if since_start >= self.grace {
                    LeaseStatus::Lapsed(LeaseLapse::NeverArrived)
                } else {
                    // `saturating_sub`, not `-`. The branch above already guarantees
                    // `since_start < self.grace`, so the plain subtraction cannot underflow TODAY —
                    // but `Duration` subtraction PANICS on underflow, and a panic inside the session
                    // loop is indistinguishable from a clean teardown to anything watching the task
                    // handle. A mutation that broke the guard above proved exactly that: the e2e
                    // "the session ends" test still passed, because the session ended by panicking.
                    // A revocation control must not have a panic on any reachable path.
                    LeaseStatus::AwaitingFirst {
                        remaining_ms: self.grace.saturating_sub(since_start).as_millis() as i64,
                    }
                }
            }
        }
    }
}

// Which control-plane session a policy is being verified AGAINST.
///
/// Deliberately an enum rather than an `Option<Uuid>`: with an `Option`, "I could not find out" and
/// "do not check" are the same value, and the check would be silently skipped by anyone who forgot
/// to plumb it. Both readings are spelt out here, and BOTH of them are safe — `Unknown` rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBinding {
    /// The live control-plane session id, as vouched for by a signaling server that verified the
    /// controller's session ticket. A policy must name exactly this session.
    Session(uuid::Uuid),
    /// The agent was not told which control-plane session this is — the signaling server verifies no
    /// tickets (dev/LAN/e2e), predates the field, or sent something unparseable.
    ///
    /// FAIL-CLOSED: every policy is rejected, because an unbindable policy is exactly the artifact
    /// session binding exists to refuse. A session under `require_session_policy` therefore stays
    /// provisionally floored, which is safe; one that is not stays controllable, which is the
    /// pre-policy status quo.
    Unknown,
}

/// Why a [`SignedSessionPolicy`] was rejected. Distinct variants so the agent can log precisely and
/// a clock problem is never confused with a key problem.
#[derive(Debug, thiserror::Error)]
pub enum SessionPolicyError {
    #[error("session policy signature is invalid (wrong issuer key or tampered claims)")]
    BadSignature,
    #[error("session policy has expired")]
    Expired,
    #[error("session policy is not yet valid")]
    NotYetValid,
    #[error(
        "session policy is for a different machine (expected {expected}, policy carries {found})"
    )]
    WrongMachine { expected: uuid::Uuid, found: uuid::Uuid },
    #[error(
        "session policy is for a different session (expected {expected}, policy carries {found})"
    )]
    WrongSession { expected: uuid::Uuid, found: uuid::Uuid },
    #[error(
        "session policy cannot be bound: the signaling server did not report a control-plane \
         session id for this connection (is it running without ticket verification?)"
    )]
    UnboundSession,
    #[error("malformed signed session policy: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`AccessLevel`] variant, so a new one cannot be added without every table-driven test
    /// below covering it (the `name()` match is already exhaustive; this keeps the TESTS exhaustive
    /// too).
    const ALL_LEVELS: [AccessLevel; 2] = [AccessLevel::ViewOnly, AccessLevel::Control];

    /// The binding that MATCHES what [`claims`] mints (its `session_id` is the nil uuid). Tests
    /// that want a mismatch name a different uuid explicitly — which is the whole reason
    /// [`SessionBinding`] is an enum: there is no way to "just not check".
    fn bound() -> SessionBinding {
        SessionBinding::Session(uuid::Uuid::nil())
    }

    fn claims(now: i64, ttl: i64, access: AccessLevel) -> SessionPolicyClaims {
        SessionPolicyClaims {
            policy: SessionPolicy {
                technician_id: uuid::Uuid::nil(),
                session_id: uuid::Uuid::nil(),
                machine_id: uuid::Uuid::nil(),
                access,
                allow_recording: true,
                require_recording: false,
                max_session_duration_seconds: 0,
                max_idle_seconds: 0,
            },
            issued_at_ms: now,
            expires_at_ms: now + ttl,
        }
    }

    // ---------------------------------------------------------------------------------------
    // AccessLevel — the deny-by-default discipline
    // ---------------------------------------------------------------------------------------

    /// The canonical name MUST equal what serde emits, because the name goes into the signing
    /// bytes while serde produces the JSON: if they drift, a policy signs as one level and reads
    /// back as another. Compared against serde's own output rather than a hardcoded string, so this
    /// cannot pass by both sides being edited to the same wrong value.
    #[test]
    fn access_level_name_matches_serde() {
        for level in ALL_LEVELS {
            let serde_name = serde_json::to_string(&level).unwrap();
            let serde_name = serde_name.trim_matches('"');
            assert_eq!(level.name(), serde_name, "canonical name drifted from serde for {level:?}");
        }
    }

    /// The whole point of the named enum: the default is the RESTRICTIVE level. If someone ever
    /// moves `#[default]` to `Control`, every "could not determine the level" path silently starts
    /// granting control.
    #[test]
    fn the_default_access_level_denies_input() {
        assert_eq!(AccessLevel::default(), AccessLevel::ViewOnly);
        assert!(AccessLevel::default().is_view_only(), "the default must deny input");
    }

    /// The ratchet's full truth table. `ViewOnly` must dominate in BOTH argument positions — a
    /// one-sided implementation (`if self.is_view_only()`) would pass a test that only ever put the
    /// restrictive value on the left.
    #[test]
    fn most_restrictive_lets_view_only_dominate_in_either_position() {
        use AccessLevel::{Control, ViewOnly};
        assert_eq!(Control.most_restrictive(Control), Control, "control+control stays control");
        assert_eq!(ViewOnly.most_restrictive(Control), ViewOnly, "restrictive on the LEFT wins");
        assert_eq!(Control.most_restrictive(ViewOnly), ViewOnly, "restrictive on the RIGHT wins");
        assert_eq!(ViewOnly.most_restrictive(ViewOnly), ViewOnly);
    }

    /// An access level the agent does not understand must FAIL to decode, never fall back to a
    /// permissive value. Serde gives this for free for an unknown variant — pinned here because the
    /// safety of the whole design rests on it, and a future `#[serde(other)]` catch-all would
    /// quietly turn "unknown" into "allowed".
    #[test]
    fn an_unknown_access_level_fails_to_decode_rather_than_defaulting() {
        let json = r#"{"technician_id":"00000000-0000-0000-0000-000000000000",
                       "session_id":"00000000-0000-0000-0000-000000000000",
                       "machine_id":"00000000-0000-0000-0000-000000000000",
                       "access":"full_control_please"}"#;
        assert!(
            serde_json::from_str::<SessionPolicy>(json).is_err(),
            "an unrecognised access level must be a decode ERROR, not a silent default"
        );
    }

    /// Likewise an ABSENT level: `access` is a required field, so omitting it is a decode error.
    /// (`Default` is derived for the ENUM, not applied to the field — no `#[serde(default)]` — so
    /// a truncated policy cannot arrive as a level the agent then treats as authoritative.)
    #[test]
    fn a_missing_access_level_fails_to_decode() {
        let json = r#"{"technician_id":"00000000-0000-0000-0000-000000000000",
                       "session_id":"00000000-0000-0000-0000-000000000000",
                       "machine_id":"00000000-0000-0000-0000-000000000000"}"#;
        assert!(
            serde_json::from_str::<SessionPolicy>(json).is_err(),
            "a policy with no access level must not decode"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Signing / verification
    // ---------------------------------------------------------------------------------------

    #[test]
    fn sign_then_verify_round_trip_returns_the_policy() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        for access in ALL_LEVELS {
            let signed = claims(now, 60_000, access).sign(&issuer);
            // Survives a JSON round-trip, as it would crossing the Control channel.
            let json = signed.to_json().unwrap();
            let back = SignedSessionPolicy::from_json(&json).unwrap();
            let policy = back
                .verify(&issuer.public(), now + 5_000, uuid::Uuid::nil(), bound())
                .expect("a valid policy verifies");
            assert_eq!(policy.access, access, "the level survived the round trip");
        }
    }

    /// Flipping the level after signing must be caught. This is THE attack the signature exists to
    /// stop: a viewer that receives a `view_only` policy and rewrites it to `control`.
    #[test]
    fn tampering_view_only_up_to_control_is_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let mut signed = claims(now, 60_000, AccessLevel::ViewOnly).sign(&issuer);
        signed.claims.policy.access = AccessLevel::Control;
        assert!(matches!(
            signed.verify(&issuer.public(), now, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::BadSignature)
        ));
    }

    #[test]
    fn wrong_issuer_key_is_rejected() {
        let issuer = Identity::generate();
        let attacker = Identity::generate();
        let now = 1_000_000;
        let signed = claims(now, 60_000, AccessLevel::Control).sign(&issuer);
        assert!(matches!(
            signed.verify(&attacker.public(), now, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::BadSignature)
        ));
    }

    #[test]
    fn expired_policy_is_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let signed = claims(now, 10_000, AccessLevel::Control).sign(&issuer);
        assert!(matches!(
            signed.verify(&issuer.public(), now + 20_000, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::Expired)
        ));
        // Expiry is EXCLUSIVE: exactly at expires_at_ms is already too late.
        assert!(matches!(
            signed.verify(&issuer.public(), now + 10_000, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::Expired)
        ));
        // …and one millisecond earlier still verifies, so the boundary is pinned from both sides.
        assert!(signed.verify(&issuer.public(), now + 9_999, uuid::Uuid::nil(), bound()).is_ok());
    }

    #[test]
    fn not_yet_valid_policy_is_rejected_but_small_skew_is_tolerated() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let far_future = claims(now + 10 * CLOCK_SKEW_MS, 60_000, AccessLevel::Control).sign(&issuer);
        assert!(matches!(
            far_future.verify(&issuer.public(), now, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::NotYetValid)
        ));
        // Within the tolerated skew, a slightly-ahead issuer clock is accepted.
        let slightly_ahead = claims(now + 5_000, 60_000, AccessLevel::Control).sign(&issuer);
        assert!(slightly_ahead.verify(&issuer.public(), now, uuid::Uuid::nil(), bound()).is_ok());
    }

    /// H3 device binding: a policy minted for machine X is not replayable to machine Y.
    #[test]
    fn wrong_machine_is_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let machine_x = uuid::Uuid::from_u128(0x0A);
        let machine_y = uuid::Uuid::from_u128(0x0B);
        let mut c = claims(now, 60_000, AccessLevel::Control);
        c.policy.machine_id = machine_x;
        let signed = c.sign(&issuer);
        assert!(matches!(
            signed.verify(&issuer.public(), now + 5_000, machine_y, bound()),
            Err(SessionPolicyError::WrongMachine { expected, found })
                if expected == machine_y && found == machine_x
        ));
        assert!(signed.verify(&issuer.public(), now + 5_000, machine_x, bound()).is_ok());
    }

    /// SESSION BINDING (loop 86): a policy minted for session A is not replayable into session B,
    /// even at the SAME machine and well inside its TTL. This is what replaced the containment that
    /// migration 0037 spent — before it, every `control` policy named an ephemeral attended device
    /// that never existed twice, so there was no later session to replay one into.
    #[test]
    fn wrong_session_is_rejected_even_at_the_right_machine() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let machine = uuid::Uuid::from_u128(0x0A);
        let session_a = uuid::Uuid::from_u128(0xA1);
        let session_b = uuid::Uuid::from_u128(0xB2);
        let mut c = claims(now, 60_000, AccessLevel::Control);
        c.policy.machine_id = machine;
        c.policy.session_id = session_a;
        let signed = c.sign(&issuer);

        // The replay: same machine, unexpired, correctly signed — and refused.
        assert!(matches!(
            signed.verify(&issuer.public(), now + 5_000, machine, SessionBinding::Session(session_b)),
            Err(SessionPolicyError::WrongSession { expected, found })
                if expected == session_b && found == session_a
        ));
        // The genuine article still verifies, so the check is a binding and not a blanket refusal.
        assert!(signed
            .verify(&issuer.public(), now + 5_000, machine, SessionBinding::Session(session_a))
            .is_ok());
    }

    /// An agent that was never told which session it is serving must REFUSE every policy, including
    /// a perfectly valid one. `Unknown` is not "skip the check": an unbindable policy is exactly the
    /// artifact this binding exists to refuse, and the alternative — accepting it — is the replay.
    #[test]
    fn an_unbound_session_rejects_even_an_otherwise_valid_policy() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        for access in ALL_LEVELS {
            let signed = claims(now, 60_000, access).sign(&issuer);
            // Identical inputs to `sign_then_verify_round_trip_returns_the_policy`, which passes.
            assert!(
                signed.verify(&issuer.public(), now + 5_000, uuid::Uuid::nil(), bound()).is_ok(),
                "control: this policy is otherwise valid ({access:?})"
            );
            assert!(
                matches!(
                    signed.verify(
                        &issuer.public(),
                        now + 5_000,
                        uuid::Uuid::nil(),
                        SessionBinding::Unknown
                    ),
                    Err(SessionPolicyError::UnboundSession)
                ),
                "an unbindable policy must be refused, not waved through ({access:?})"
            );
        }
    }

    /// A garbage signature field is an ENCODING error, distinct from a well-formed-but-wrong
    /// signature — the agent logs the two differently (a key problem vs a corrupt message).
    #[test]
    fn a_malformed_signature_is_an_encoding_error_not_a_bad_signature() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let mut signed = claims(now, 60_000, AccessLevel::Control).sign(&issuer);
        // sign() puts the sig in sig_v1; mangle it to get an Encoding error.
        signed.sig_v1 = "not hex".into();
        assert!(matches!(
            signed.verify(&issuer.public(), now, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::Encoding(_))
        ));
        // Hex, but the wrong length.
        signed.sig_v1 = "abcd".into();
        assert!(matches!(
            signed.verify(&issuer.public(), now, uuid::Uuid::nil(), bound()),
            Err(SessionPolicyError::Encoding(_))
        ));
    }

    /// The signature is checked BEFORE the validity window, the device binding AND the session
    /// binding, so a forged policy reports `BadSignature` rather than leaking which of its
    /// self-claimed fields would have been rejected. (Ordering is a real property here: it is what
    /// stops an attacker probing the agent's clock, machine id or session id with unsigned garbage.)
    #[test]
    fn signature_is_checked_before_the_window_and_the_device_binding() {
        let issuer = Identity::generate();
        let attacker = Identity::generate();
        let now = 1_000_000;
        // Expired AND for the wrong machine AND signed by the wrong key: the signature wins.
        let mut c = claims(now - 100_000, 10_000, AccessLevel::Control);
        c.policy.machine_id = uuid::Uuid::from_u128(0x0A);
        let signed = c.sign(&attacker);
        assert!(matches!(
            signed.verify(&issuer.public(), now, uuid::Uuid::from_u128(0x0B), bound()),
            Err(SessionPolicyError::BadSignature)
        ));
    }

    /// A grant preimage and a policy preimage must never collide, so a signature minted over one
    /// can never be replayed as the other. Both open with the same three UUIDs; only the domain
    /// tag separates them, so this asserts the tags actually differ in the produced bytes.
    #[test]
    fn a_policy_preimage_is_domain_separated_from_a_grant_preimage() {
        use crate::backstage::canonical::{DOMAIN_TAG, SESSION_POLICY_DOMAIN_TAG};
        let bytes = claims(1_000_000, 60_000, AccessLevel::Control).signing_bytes();
        assert!(
            bytes.starts_with(&SESSION_POLICY_DOMAIN_TAG),
            "a policy preimage must open with the session-policy tag"
        );
        assert!(
            !bytes.starts_with(&DOMAIN_TAG),
            "a policy preimage must NOT open with the grant tag"
        );
    }

    // =====================================================================================
    // GOLDEN CROSS-LANGUAGE VECTOR (session-policy v1) — the proof Rust and Go agree
    // byte-for-byte. The SAME fixed fixture is hardcoded in
    // control-plane/session_policy_test.go's TestSessionPolicyGoldenVectorV1. If the two
    // languages' canonical encoders or Ed25519 signing ever diverge, one side's hex stops
    // matching. DO NOT change a value here without changing it identically in the Go test.
    //
    //   seed (32 bytes, hex): 0102…20  (the SAME seed the grant golden vector uses, deliberately:
    //     it means the two vectors share an issuer key, so the ONLY thing separating their
    //     signatures is the domain tag + payload — which is exactly the property under test)
    //   technician_id: 11111111-1111-1111-1111-111111111111
    //   session_id:    22222222-2222-2222-2222-222222222222
    //   machine_id:    33333333-3333-3333-3333-333333333333
    //   access:        view_only
    //   issued_at_ms:  1730000000000
    //   expires_at_ms: 1730000900000
    // =====================================================================================

    const GOLDEN_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const GOLDEN_PUBKEY_HEX: &str =
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    // V1 preimage (10 fields, 99 bytes for "view_only"). Cross-language: matches Go's
    // goldenPolicyPreimageHex in control-plane/session_policy_mint_test.go.
    const GOLDEN_PREIMAGE_HEX: &str = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000009766965775f6f6e6c7900000192cc09140000000192cc16cfa001000000000000000000";
    // V1 sig (JSON "sig_v1"). Cross-language: matches Go's goldenPolicySigHex.
    const GOLDEN_SIG_HEX: &str = "173461f73fc4f95521a90dfa2e07ebcfa9c977b34714f2aba0632887a50b8c0d99e87e4c4baebc4d4748705bfbe5990323f923e4e25969bae8dd7195b1d4590c";
    // V0 preimage (6 fields, 89 bytes for "view_only") — matches deployed agent 735d5a28.
    // Cross-language: matches Go's goldenPolicyV0PreimageHex.
    const GOLDEN_V0_PREIMAGE_HEX: &str = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000009766965775f6f6e6c7900000192cc09140000000192cc16cfa0";
    // V0 sig (JSON "sig") — signed by new CP for old-agent compat. Cross-language: matches
    // Go's goldenPolicyCompatSigHex.
    const GOLDEN_COMPAT_SIG_HEX: &str = "e61603c0cfad57952f37be8513e65121a9b1215fe9a1ee8141661054fdd040ae0391e8524fba935b4fd2a96b67e0bcb7fb4124de7bb5a2d5ec92d0847ef41903";

    fn golden_claims() -> SessionPolicyClaims {
        SessionPolicyClaims {
            policy: SessionPolicy {
                technician_id: "11111111-1111-1111-1111-111111111111".parse().unwrap(),
                session_id: "22222222-2222-2222-2222-222222222222".parse().unwrap(),
                machine_id: "33333333-3333-3333-3333-333333333333".parse().unwrap(),
                access: AccessLevel::ViewOnly,
                allow_recording: true,
                require_recording: false,
                max_session_duration_seconds: 0,
                max_idle_seconds: 0,
            },
            issued_at_ms: 1_730_000_000_000,
            expires_at_ms: 1_730_000_900_000,
        }
    }

    #[test]
    fn golden_vector_v1() {
        let issuer = Identity::from_seed(&GOLDEN_SEED);
        let claims = golden_claims();
        let preimage_hex = hex::encode(claims.signing_bytes());
        let signed = claims.sign(&issuer);

        // Printed so the constants can be captured on first run (cargo test -- --nocapture).
        eprintln!("GOLDEN_PUBKEY_HEX   = {}", issuer.public_hex());
        eprintln!("GOLDEN_PREIMAGE_HEX = {preimage_hex}");
        eprintln!("GOLDEN_SIG_HEX      = {}", signed.sig_v1);

        assert_eq!(issuer.public_hex(), GOLDEN_PUBKEY_HEX, "pubkey drift");
        assert_eq!(preimage_hex, GOLDEN_PREIMAGE_HEX, "canonical v1 preimage drift");
        // sign() places the sig in sig_v1 (new-agent format).
        assert_eq!(signed.sig_v1, GOLDEN_SIG_HEX, "sig_v1 drift");
        assert!(signed.sig.is_empty(), "sign() must leave sig empty (sig_v1 is authoritative)");
    }

    /// Pins the v0 (deployed-baseline, 735d5a28) preimage and its compat signature.
    /// Cross-language: Go's TestSessionPolicyGoldenVectorV0 asserts the same hex.
    /// If this drifts from Go, the deployed agent will reject every non-restrictive policy
    /// from the new CP (bad "sig" verification), silently breaking sessions.
    #[test]
    fn golden_vector_v0() {
        let issuer = Identity::from_seed(&GOLDEN_SEED);
        let claims = golden_claims();
        let v0_preimage_hex = hex::encode(claims.signing_bytes_v0());
        eprintln!("GOLDEN_V0_PREIMAGE_HEX  = {v0_preimage_hex}");
        assert_eq!(v0_preimage_hex, GOLDEN_V0_PREIMAGE_HEX, "v0 preimage drift");
        // Verify the compat sig against the v0 preimage.
        let sig_bytes = hex::decode(GOLDEN_COMPAT_SIG_HEX).unwrap();
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
        let pub_id = issuer.public();
        assert!(
            pub_id.verify(&claims.signing_bytes_v0(), &sig).is_ok(),
            "v0 compat sig must verify against v0 preimage"
        );
        // v0 and v1 preimages must differ.
        assert_ne!(
            claims.signing_bytes_v0(),
            claims.signing_bytes(),
            "v0 and v1 preimages must differ (restriction bytes missing from v0)"
        );
    }

    /// DEPLOYED-BASELINE format → new-agent compat: a `SignedSessionPolicy` JSON in the format
    /// emitted by the actual deployed agent at 735d5a28 — only `"sig"` (v0 sig), no `"sig_v1"`,
    /// no restriction fields in `claims.policy` — must verify after the new-agent upgrade.
    /// The new agent falls back to `"sig"` and verifies it against the v0 preimage.
    #[test]
    fn verifies_go_minted_session_policy() {
        // Deployed-baseline (735d5a28) format: only "sig" = v0 sig, no sig_v1, no restriction
        // fields in policy (old struct lacked them; serde fills defaults on deserialization).
        const GO_MINTED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only"},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"e61603c0cfad57952f37be8513e65121a9b1215fe9a1ee8141661054fdd040ae0391e8524fba935b4fd2a96b67e0bcb7fb4124de7bb5a2d5ec92d0847ef41903"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(GO_MINTED_JSON).expect("Go JSON decodes");
        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        // The fixture's OWN session id — the golden vector already carries one, so binding to it
        // costs no preimage change and proves the Go mint and the Rust check agree on the field.
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        // Inside the fixture's validity window.
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("a Go-minted policy verifies in Rust");

        assert_eq!(policy.access, AccessLevel::ViewOnly);
        assert!(policy.access.is_view_only());
        assert!(policy.allow_recording, "allow_recording must survive the Go→Rust round trip");
        assert!(!policy.require_recording, "require_recording must survive the Go→Rust round trip");
        assert_eq!(policy.max_session_duration_seconds, 0, "max_session_duration_seconds must survive the Go→Rust round trip");
        assert_eq!(policy.max_idle_seconds, 0, "max_idle_seconds must survive the Go→Rust round trip");
        assert_eq!(policy.machine_id, machine);
        assert_eq!(
            policy.technician_id,
            "11111111-1111-1111-1111-111111111111".parse::<uuid::Uuid>().unwrap()
        );
        assert_eq!(
            policy.session_id,
            "22222222-2222-2222-2222-222222222222".parse::<uuid::Uuid>().unwrap()
        );
    }

    /// The `control` half of the Go-mint → Rust-verify interop, and the END TO END of loop 83's fix:
    /// Go's ACTUAL wire bytes for `access=control` verify here AND discharge a provisional floor.
    ///
    /// This is the hop the sampling-window fix rests on, and it had no test because nothing in the
    /// tree had ever minted `control`. Note what would happen if it broke: the guest is already
    /// dropping the technician's input, the policy that would release it fails to verify, and the
    /// agent's fail-closed behaviour keeps it floored. So the failure mode of a `control` policy is
    /// SILENT — no error the technician sees, just a session that never becomes controllable —
    /// which is exactly the stranding this loop set out to remove.
    #[test]
    fn verifies_go_minted_control_session_policy() {
        // Deployed-baseline (735d5a28) format: only "sig" = v0 sig for control, no restriction
        // fields in policy claims. The new agent falls back to "sig" and verifies v0 preimage.
        const GO_MINTED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"control"},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"b9caa7f6010935eb261364ddf9ddd5c1215a7b330f075215ea777c5fd402dafe88aa3ccadf50325dc4e60522ce9c4967bab21fc7b49420dc4fac22d350693a0f"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(GO_MINTED_JSON).expect("Go JSON decodes");
        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        // The fixture's OWN session id — the golden vector already carries one, so binding to it
        // costs no preimage change and proves the Go mint and the Rust check agree on the field.
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("a Go-minted control policy verifies in Rust");

        assert_eq!(policy.access, AccessLevel::Control);
        assert!(!policy.access.is_view_only());

        // And it does the job it was minted for: a session that opened under the provisional floor
        // becomes controllable. Asserted here, on the DECODED-FROM-GO value, rather than only in the
        // truth table above — the truth table proves the rule, this proves the rule is reached by the
        // bytes the control plane actually sends.
        let mut st = SessionAccessState::new(true);
        assert!(st.view_only(), "premise: the session opens floored");
        st.install_verified(policy.access);
        assert!(
            !st.view_only(),
            "a Go-minted control policy did not release the provisional floor — the guest stays \
             view-only for the session's whole life with nothing explaining why"
        );
    }

    /// NEW-CP format → new-agent verification: a non-restrictive policy carries both `"sig"` (v0
    /// sig) and `"sig_v1"` (v1 sig) with DIFFERENT values. The new agent prefers `"sig_v1"`.
    /// Proves the NEW CP + NEW Agent cell.
    #[test]
    fn verifies_new_cp_format_session_policy() {
        // New-CP (R74+) format: "sig"=v0 sig, "sig_v1"=v1 sig (different values).
        // From Go's TestSessionPolicyGoldenVectorV1 log after the R74 fix.
        const GO_MINTED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":true,"require_recording":false,"max_session_duration_seconds":0,"max_idle_seconds":0},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"e61603c0cfad57952f37be8513e65121a9b1215fe9a1ee8141661054fdd040ae0391e8524fba935b4fd2a96b67e0bcb7fb4124de7bb5a2d5ec92d0847ef41903","sig_v1":"173461f73fc4f95521a90dfa2e07ebcfa9c977b34714f2aba0632887a50b8c0d99e87e4c4baebc4d4748705bfbe5990323f923e4e25969bae8dd7195b1d4590c"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(GO_MINTED_JSON).expect("new-CP JSON decodes");
        // sig_v1 is present — verify() must use it (not fall back to sig).
        assert!(!signed.sig_v1.is_empty(), "sig_v1 must be present in new-CP format");
        assert_ne!(signed.sig_v1, signed.sig, "sig_v1 (v1 preimage) and sig (v0 preimage) must differ");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("new-CP format policy verifies in Rust");
        assert_eq!(policy.access, AccessLevel::ViewOnly);
        assert!(policy.allow_recording);
    }

    /// The `allow_recording=false` half of the Go-mint → Rust-verify interop: pins that the ban
    /// byte encodes as 0x00 and that the Rust decoder reads it back as `false`. Uses new-CP format
    /// (`"sig_v1"` only — restrictive policies omit `"sig"` so old agents fail closed).
    #[test]
    fn verifies_go_minted_banned_session_policy() {
        // New-CP format for a restrictive policy: only "sig_v1" present, no "sig".
        // From Go's TestSessionPolicyGoldenVectorV1RecordingBanned log after the R72 fix.
        const GO_MINTED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":false,"require_recording":false,"max_session_duration_seconds":0,"max_idle_seconds":0},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig_v1":"9b59d058e332e732fbb9db4c032a2dc9cfb866dae352b3766242b58cd9a8e95537621b2fb927ec2e560f6323c8ae2f8fe9537ea178e23df19a894da869f4f10d"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(GO_MINTED_JSON).expect("Go JSON decodes");
        assert!(!signed.sig_v1.is_empty(), "sig_v1 must be present");
        assert!(signed.sig.is_empty(), "sig must be absent for restrictive policies");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("a Go-minted banned policy verifies in Rust");

        assert!(!policy.allow_recording, "allow_recording=false must survive the Go→Rust round trip");
        assert!(!policy.require_recording, "require_recording=false must survive the Go→Rust round trip");
        assert_eq!(policy.access, AccessLevel::ViewOnly);
    }

    /// The `require_recording=true` half of the Go-mint → Rust-verify interop: pins that the
    /// mandatory byte encodes as 0x01 and that the Rust decoder reads it back as `true`. Uses
    /// new-CP format (`"sig_v1"` only — restrictive policies omit `"sig"`).
    #[test]
    fn verifies_go_minted_required_session_policy() {
        // New-CP format for a restrictive policy: only "sig_v1" present, no "sig".
        // From Go's TestSessionPolicyGoldenVectorV1RecordingRequired log after the R72 fix.
        const GO_MINTED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":true,"require_recording":true,"max_session_duration_seconds":0,"max_idle_seconds":0},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig_v1":"8cac73f680179949d230aed6dd0195e604a6a6fbaba48d111d4e4be474e0d639ca389e33d0c9eda835ae4039c39665f690362847e90727850592c7672da45e0a"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(GO_MINTED_JSON).expect("Go JSON decodes");
        assert!(!signed.sig_v1.is_empty(), "sig_v1 must be present");
        assert!(signed.sig.is_empty(), "sig must be absent for restrictive policies");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("a Go-minted required-recording policy verifies in Rust");

        assert!(policy.require_recording, "require_recording=true must survive the Go→Rust round trip");
        assert!(policy.allow_recording, "allow_recording must also be true for this vector");
        assert_eq!(policy.access, AccessLevel::ViewOnly);
    }

    /// DOWNGRADE ATTACK (restrictive): attacker strips `"sig_v1"` from a new-CP restrictive policy.
    /// Result has no sig fields → Encoding error → fail closed. Mutation: if verify() accepted a
    /// policy with no sig at all, this test fails. The attack cannot succeed.
    #[test]
    fn sig_v1_stripping_on_restrictive_new_cp_is_encoding_error() {
        // Restrictive new-CP JSON with sig_v1 STRIPPED (no sig field at all — attacker removed it).
        // A real new CP never emits "sig" for restrictive policies, so stripping "sig_v1" leaves nothing.
        const STRIPPED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":false,"require_recording":false,"max_session_duration_seconds":0,"max_idle_seconds":0},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000}}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(STRIPPED_JSON).expect("claims-only JSON decodes");
        // Both sig fields must be absent.
        assert!(signed.sig_v1.is_empty() && signed.sig.is_empty(), "no sig fields in stripped JSON");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        assert!(
            matches!(
                signed.verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session)),
                Err(SessionPolicyError::Encoding(_))
            ),
            "a policy with no sig fields must be an Encoding error — stripping the sig is not an upgrade path"
        );
    }

    /// DOWNGRADE ATTACK (non-restrictive): attacker strips `"sig_v1"`, leaving only `"sig"` (v0 sig).
    /// The new agent falls back to `"sig"` and verifies against v0 preimage — correct, the policy
    /// has no new restrictions so accepting it is safe. The downgrade buys the attacker nothing.
    #[test]
    fn sig_v1_stripping_on_non_restrictive_falls_back_to_sig_safely() {
        // Non-restrictive policy with ONLY "sig" (v0 sig) present (new-CP "sig_v1" stripped).
        // The fallback path verifies "sig" against the v0 preimage, same as deployed-CP format.
        const STRIPPED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":true,"require_recording":false,"max_session_duration_seconds":0,"max_idle_seconds":0},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"e61603c0cfad57952f37be8513e65121a9b1215fe9a1ee8141661054fdd040ae0391e8524fba935b4fd2a96b67e0bcb7fb4124de7bb5a2d5ec92d0847ef41903"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(STRIPPED_JSON).expect("sig-only JSON decodes");
        assert!(signed.sig_v1.is_empty(), "sig_v1 absent after stripping");
        assert!(!signed.sig.is_empty(), "sig present");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("non-restrictive sig-only policy verifies — fallback is safe when no restrictions");
        assert_eq!(policy.access, AccessLevel::ViewOnly);
        // No restrictions were lost — the policy had none.
        assert!(policy.allow_recording);
        assert!(!policy.require_recording);
    }

    /// CODEX-15:13 — v0 fallback must not honour attacker-injected extension fields.
    ///
    /// The v0 preimage ends at `expires_at_ms` — it does NOT authenticate `allow_recording`,
    /// `require_recording`, `max_session_duration_seconds`, or `max_idle_seconds`. An attacker who
    /// intercepts a non-restrictive v0-only envelope can inject restrictive values into those fields
    /// without invalidating the v0 signature, because the preimage bytes covering those fields are
    /// never computed. `verify()` must return permissive defaults for unauthenticated extension fields.
    ///
    /// Mutation targets (one per extension field):
    /// - M1: remove `policy.allow_recording = true`   → injected `false` survives → FAILS
    /// - M2: remove `policy.require_recording = false` → injected `true` survives  → FAILS
    /// - M3: remove `policy.max_session_duration_seconds = 0` → injected `3600` survives → FAILS
    /// - M4: remove `policy.max_idle_seconds = 0`     → injected `300` survives   → FAILS
    #[test]
    fn v0_fallback_sanitizes_unsigned_extension_fields() {
        // A v0-only envelope (no sig_v1) with ALL extension fields set to restrictive values.
        // The v0 sig (GOLDEN_COMPAT_SIG_HEX) covers only the 6-field preimage ending at
        // expires_at_ms — it remains valid regardless of the extension field values.
        const INJECTED_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":false,"require_recording":true,"max_session_duration_seconds":3600,"max_idle_seconds":300},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"e61603c0cfad57952f37be8513e65121a9b1215fe9a1ee8141661054fdd040ae0391e8524fba935b4fd2a96b67e0bcb7fb4124de7bb5a2d5ec92d0847ef41903"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(INJECTED_JSON).expect("injected v0 JSON decodes");
        assert!(signed.sig_v1.is_empty(), "no sig_v1: forces v0 fallback path");
        assert!(!signed.sig.is_empty(), "v0 sig present");

        // Confirm the attacker's injected values ARE in the wire payload before verification.
        assert!(!signed.claims.policy.allow_recording, "injected: allow_recording=false");
        assert!(signed.claims.policy.require_recording, "injected: require_recording=true");
        assert_eq!(signed.claims.policy.max_session_duration_seconds, 3600, "injected: duration=3600");
        assert_eq!(signed.claims.policy.max_idle_seconds, 300, "injected: idle=300");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        // The v0 sig verifies: preimage covers only the 6 base fields, extension bytes absent.
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("v0 sig is valid — preimage covers only the 6 base fields");

        // The 4 extension fields must be sanitized to permissive defaults.
        // None of them are in the v0 preimage so their wire values are unauthenticated.
        assert!(
            policy.allow_recording,
            "M1: allow_recording must be sanitized to true (injected false is unauthenticated)"
        );
        assert!(
            !policy.require_recording,
            "M2: require_recording must be sanitized to false (injected true is unauthenticated)"
        );
        assert_eq!(
            policy.max_session_duration_seconds, 0,
            "M3: max_session_duration_seconds must be sanitized to 0 (injected 3600 is unauthenticated)"
        );
        assert_eq!(
            policy.max_idle_seconds, 0,
            "M4: max_idle_seconds must be sanitized to 0 (injected 300 is unauthenticated)"
        );
        // The 6 authenticated fields survive intact.
        assert_eq!(policy.access, AccessLevel::ViewOnly);
        assert_eq!(policy.machine_id, machine);
        assert_eq!(policy.session_id, session);
    }

    /// Prove the v1 path is NOT affected by the v0 sanitization. A new-CP policy with `sig_v1`
    /// that genuinely sets `allow_recording=false` must return that value. This ensures the fix
    /// does not regress legitimate restrictive policies arriving via the v1 path.
    ///
    /// (This path is also covered by `verifies_go_minted_banned_session_policy`; this test
    /// adds an explicit cross-check that the sanitization branch is conditioned on `v0_path`,
    /// not applied unconditionally.)
    #[test]
    fn v1_path_returns_genuine_restriction_fields_unchanged() {
        // New-CP restrictive JSON: sig_v1 only (no sig). allow_recording=false is authenticated.
        const RESTRICTIVE_JSON: &str = r#"{"claims":{"policy":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","access":"view_only","allow_recording":false,"require_recording":false,"max_session_duration_seconds":0,"max_idle_seconds":0},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig_v1":"9b59d058e332e732fbb9db4c032a2dc9cfb866dae352b3766242b58cd9a8e95537621b2fb927ec2e560f6323c8ae2f8fe9537ea178e23df19a894da869f4f10d"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedSessionPolicy::from_json(RESTRICTIVE_JSON).expect("restrictive v1 JSON decodes");
        assert!(!signed.sig_v1.is_empty(), "sig_v1 present: v1 path, no sanitization");
        assert!(signed.sig.is_empty(), "no v0 sig: this is a new-CP restrictive policy");

        let machine: uuid::Uuid = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let session: uuid::Uuid = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let policy = signed
            .verify(&issuer, 1_730_000_100_000, machine, SessionBinding::Session(session))
            .expect("restrictive v1 policy verifies");

        // allow_recording=false IS authenticated by sig_v1 and must survive.
        assert!(
            !policy.allow_recording,
            "allow_recording=false must survive the v1 path — sanitization must not apply"
        );
    }

    // =====================================================================================
    // SessionAccessState — the composition rules, as a truth table. Everything below was
    // unreachable by any test while it lived inline in host.rs.
    // =====================================================================================

    #[test]
    fn a_session_without_require_policy_starts_controllable() {
        let st = SessionAccessState::new(false);
        assert!(!st.view_only(), "the historical default: control until someone restricts it");
        assert!(!st.is_observer());
        assert!(!st.awaiting_required_policy());
    }

    #[test]
    fn an_observer_without_require_policy_starts_view_only() {
        let st = SessionAccessState::new_observer(false);
        assert!(st.is_observer());
        assert!(st.view_only(), "the observer floor applies from construction");
        assert!(!st.awaiting_required_policy());
    }

    #[test]
    fn the_toggle_cannot_lift_the_observer_floor() {
        let mut st = SessionAccessState::new_observer(false);
        assert!(st.set_toggle(false), "clearing an unset toggle must still report view-only");
        assert!(st.set_toggle(true));
        assert!(st.set_toggle(false), "the observer floor survives the toggle being cleared");
        assert!(st.view_only());
        assert!(st.is_observer());
    }

    #[test]
    fn a_verified_control_policy_cannot_lift_the_observer_floor() {
        for require_policy in [false, true] {
            let mut st = SessionAccessState::new_observer(require_policy);
            assert!(st.view_only());
            st.install_verified(AccessLevel::Control);
            assert!(st.policy_seen());
            assert!(!st.awaiting_required_policy());
            assert!(st.view_only(), "a signed control policy must not lift the observer floor");
            assert!(st.set_toggle(false));
            assert!(st.is_observer());
        }
    }

    #[test]
    fn require_policy_opens_the_session_view_only() {
        // THE FAIL-OPEN THIS CLOSES: the policy reaches the agent only because the VIEWER forwards it,
        // and the viewer is exactly what the policy binds. Without the provisional floor, "just do not
        // send the frame" is a complete bypass.
        let st = SessionAccessState::new(true);
        assert!(st.view_only(), "a session that requires a policy must not accept input before one");
        assert!(st.awaiting_required_policy());
    }

    #[test]
    fn the_first_verified_policy_discharges_the_provisional_floor() {
        let mut st = SessionAccessState::new(true);
        assert!(st.view_only());
        st.install_verified(AccessLevel::Control);
        assert!(!st.view_only(), "a signed `control` policy is what the agent was waiting for");
        assert!(st.policy_seen());
        assert!(!st.awaiting_required_policy());
    }

    #[test]
    fn a_verified_view_only_policy_floors_the_session() {
        let mut st = SessionAccessState::new(false);
        st.install_verified(AccessLevel::ViewOnly);
        assert!(st.view_only());
        // …and the technician's toggle cannot lift it. This is the whole product requirement.
        assert!(st.set_toggle(false), "SetViewOnly(false) must not defeat a policy floor");
        assert!(st.view_only());
    }

    #[test]
    fn the_ratchet_refuses_to_relax_a_floor_already_in_force() {
        // Replay: an attacker captures a `control` policy from an earlier session and installs it to
        // escape a `view_only` policy in force now. The agent cannot judge freshness — it does not know
        // its own control-plane session id — so the ratchet is the entire defence.
        let mut st = SessionAccessState::new(false);
        st.install_verified(AccessLevel::ViewOnly);
        assert!(st.view_only());
        st.install_verified(AccessLevel::Control);
        assert!(st.view_only(), "a later `control` policy must NEVER lift a view-only floor");
        // Any number of replays changes nothing.
        for _ in 0..5 {
            st.install_verified(AccessLevel::Control);
            assert!(st.view_only());
        }
    }

    #[test]
    fn a_replayed_view_only_policy_is_harmless() {
        // The other replay direction: only ever restricts, so it needs no defence.
        let mut st = SessionAccessState::new(false);
        st.install_verified(AccessLevel::Control);
        assert!(!st.view_only());
        st.install_verified(AccessLevel::ViewOnly);
        assert!(st.view_only(), "a restricting policy is always allowed to apply");
    }

    #[test]
    fn an_unverifiable_policy_fails_closed_and_does_not_satisfy_the_requirement() {
        let mut st = SessionAccessState::new(true);
        st.reject_unverified();
        assert!(st.view_only());
        // Crucially it does NOT count as the policy the session was waiting for — otherwise garbage
        // would discharge the provisional floor, and "send junk, then toggle" would be the bypass.
        assert!(!st.policy_seen());
        assert!(st.awaiting_required_policy());
        assert!(st.set_toggle(false), "the toggle must not lift the floor a rejection raised");
    }

    #[test]
    fn a_rejection_floors_even_a_session_that_did_not_require_a_policy() {
        // An agent that CAN verify (issuer pinned) but is handed a tampered/expired policy must not
        // carry on with full control: a forged policy would then buy MORE access than a valid one.
        let mut st = SessionAccessState::new(false);
        assert!(!st.view_only());
        st.reject_unverified();
        assert!(st.view_only());
    }

    #[test]
    fn the_toggle_can_always_add_restriction_and_only_remove_its_own() {
        let mut st = SessionAccessState::new(false);
        assert!(st.set_toggle(true));
        assert!(st.view_only());
        assert!(!st.set_toggle(false), "its own restriction is the technician's to remove");
        // With a policy floor underneath, the same call is refused.
        st.install_verified(AccessLevel::ViewOnly);
        assert!(st.set_toggle(true));
        assert!(st.set_toggle(false), "the policy floor survives the toggle being cleared");
    }

    #[test]
    fn a_control_policy_does_not_clear_a_technician_selected_view_only() {
        // `access` and the EFFECTIVE state are independent, which is why SessionPolicyInstalled carries
        // both. A technician who chose view-only keeps it even though the policy says control.
        let mut st = SessionAccessState::new(false);
        st.set_toggle(true);
        st.install_verified(AccessLevel::Control);
        assert!(st.view_only(), "a policy must not undo the technician's own choice");
        assert!(!st.set_toggle(false), "…and they can still undo it themselves");
    }

    // ---------------------------------------------------------------------------------------
    // SessionLease (docs/25 F03) — the truth table behind "End session actually ends it"
    // ---------------------------------------------------------------------------------------

    /// A bound session on an agent that CAN verify is leased. This is the production case and the
    /// one the whole finding is about.
    #[test]
    fn a_control_plane_bound_session_is_leased() {
        let l = SessionLease::new(
            SessionLeaseMode::FromSessionBinding,
            SessionBinding::Session(uuid::Uuid::nil()),
            true,
            DEFAULT_LEASE_GRACE,
        );
        assert!(l.is_enforced(), "a session the control plane vouched for must hold a lease");
    }

    /// An UNBOUND session is not leased. Not a loophole: an unbound session is one no control plane
    /// can revoke (dev/LAN, or signaling run without ticket verification), and every policy is
    /// rejected there anyway (`SessionBinding::Unknown` → `UnboundSession`), so "enforce" would mean
    /// "kill every local development session after the grace period".
    #[test]
    fn an_unbound_session_is_not_leased() {
        let l = SessionLease::new(
            SessionLeaseMode::FromSessionBinding,
            SessionBinding::Unknown,
            true,
            DEFAULT_LEASE_GRACE,
        );
        assert!(!l.is_enforced());
        assert_eq!(l.status(0, Duration::from_secs(3600)), LeaseStatus::NotEnforced);
    }

    /// An agent with NO pinned issuer key is not leased even when the session is bound. It cannot
    /// verify a lease, so enforcement could only ever end sessions and never authorize one.
    #[test]
    fn an_agent_that_cannot_verify_is_not_leased() {
        let l = SessionLease::new(
            SessionLeaseMode::FromSessionBinding,
            SessionBinding::Session(uuid::Uuid::nil()),
            false,
            DEFAULT_LEASE_GRACE,
        );
        assert!(!l.is_enforced(), "no pinned issuer key means no verifiable lease");
    }

    /// The ATTENDED opt-out. Attended revocation is the three-second status poll, and the renewal
    /// endpoint does not know attended sessions exist, so leasing one would kill it for nothing.
    #[test]
    fn the_attended_mode_is_never_leased() {
        let l = SessionLease::new(
            SessionLeaseMode::NotApplicable,
            SessionBinding::Session(uuid::Uuid::nil()),
            true,
            DEFAULT_LEASE_GRACE,
        );
        assert!(!l.is_enforced());
    }

    /// THE FINDING, as a table: a leased session with no lease yet survives exactly the grace window
    /// and not one tick longer. The boundary is asserted on both sides so a `>` / `>=` slip shows up.
    #[test]
    fn the_grace_window_is_absolute_and_closes() {
        let grace = Duration::from_secs(15);
        let l = SessionLease::new(
            SessionLeaseMode::Required,
            SessionBinding::Unknown,
            false,
            grace,
        );
        assert!(matches!(l.status(0, Duration::ZERO), LeaseStatus::AwaitingFirst { .. }));
        assert!(matches!(
            l.status(0, grace - Duration::from_millis(1)),
            LeaseStatus::AwaitingFirst { .. }
        ));
        assert_eq!(l.status(0, grace), LeaseStatus::Lapsed(LeaseLapse::NeverArrived));
        assert_eq!(
            l.status(0, grace + Duration::from_secs(600)),
            LeaseStatus::Lapsed(LeaseLapse::NeverArrived)
        );
    }

    /// The grace is measured on the MONOTONIC clock, so moving the wall clock cannot buy more of it.
    /// (`now_ms` swings wildly here while `since_start` does not.)
    #[test]
    fn a_wall_clock_jump_does_not_extend_the_grace() {
        let grace = Duration::from_secs(15);
        let l = SessionLease::new(SessionLeaseMode::Required, SessionBinding::Unknown, false, grace);
        for now in [i64::MIN / 2, -1, 0, 1, 1_700_000_000_000, i64::MAX / 2] {
            assert_eq!(
                l.status(now, grace),
                LeaseStatus::Lapsed(LeaseLapse::NeverArrived),
                "wall clock {now} must not extend an elapsed grace window"
            );
        }
    }

    /// A held lease expires EXCLUSIVELY at its instant, matching `SignedSessionPolicy::verify` —
    /// "exactly at expires_at_ms is already too late" on both sides or they disagree by a
    /// millisecond about whether an artifact is alive.
    #[test]
    fn a_held_lease_expires_exclusively() {
        let grace = Duration::from_secs(15);
        let mut l =
            SessionLease::new(SessionLeaseMode::Required, SessionBinding::Unknown, false, grace);
        l.record_verified(1_000);
        assert_eq!(l.status(999, Duration::from_secs(60)), LeaseStatus::Held { remaining_ms: 1 });
        assert_eq!(
            l.status(1_000, Duration::from_secs(60)),
            LeaseStatus::Lapsed(LeaseLapse::Expired { by_ms: 0 })
        );
        assert_eq!(
            l.status(1_500, Duration::from_secs(60)),
            LeaseStatus::Lapsed(LeaseLapse::Expired { by_ms: 500 })
        );
    }

    /// A lease OUTLIVES the grace window: once one has verified, the grace is irrelevant. Without
    /// this, a session would die at `grace` no matter how faithfully the viewer renewed — which is
    /// precisely the "fix that killed every session" a teardown-only test would have passed.
    #[test]
    fn a_held_lease_survives_the_grace_window() {
        let grace = Duration::from_secs(15);
        let mut l =
            SessionLease::new(SessionLeaseMode::Required, SessionBinding::Unknown, false, grace);
        l.record_verified(60_000);
        assert_eq!(
            l.status(1_000, Duration::from_secs(600)),
            LeaseStatus::Held { remaining_ms: 59_000 },
            "an elapsed grace window must not end a session that holds a live lease"
        );
    }

    /// **THE NEGATIVE CONTROL.** A session that keeps being renewed runs indefinitely. Drives forty
    /// renewals at a third of the TTL — twenty times the lease's own life — and requires the lease to
    /// be `Held` at every single instant in between, including immediately before each renewal.
    #[test]
    fn a_renewed_session_never_lapses() {
        let ttl_ms: i64 = 30_000;
        let renew_every_ms: i64 = 10_000;
        let mut l = SessionLease::new(
            SessionLeaseMode::Required,
            SessionBinding::Session(uuid::Uuid::nil()),
            true,
            Duration::from_secs(15),
        );
        let start_ms = 1_700_000_000_000_i64;
        l.record_verified(start_ms + ttl_ms);
        let mut now = start_ms;
        for i in 0..40 {
            // Sample just BEFORE the renewal lands, which is the tightest moment in the cycle.
            now += renew_every_ms;
            match l.status(now - 1, Duration::from_millis((now - 1 - start_ms) as u64)) {
                LeaseStatus::Held { .. } => {}
                other => panic!("renewal {i}: lease lapsed while being renewed: {other:?}"),
            }
            l.record_verified(now + ttl_ms);
            match l.status(now, Duration::from_millis((now - start_ms) as u64)) {
                LeaseStatus::Held { .. } => {}
                other => panic!("renewal {i}: lease lapsed at the renewal itself: {other:?}"),
            }
        }
        // …and it still dies once renewal stops. A negative control that could not also fail would
        // be pinning a constant.
        assert!(matches!(
            l.status(now + ttl_ms, Duration::from_secs(9_999)),
            LeaseStatus::Lapsed(LeaseLapse::Expired { .. })
        ));
    }

    /// `record_verified` takes the MAXIMUM, so renewals that arrive out of order (they will, over
    /// HTTP) cannot shorten a lease the control plane already granted. Safe because every expiry is
    /// an absolute instant the control plane signed, and it stops signing when the session ends.
    #[test]
    fn an_out_of_order_renewal_cannot_shorten_a_lease() {
        let mut l = SessionLease::new(
            SessionLeaseMode::Required,
            SessionBinding::Unknown,
            false,
            Duration::from_secs(15),
        );
        l.record_verified(90_000);
        l.record_verified(60_000); // the older renewal, delivered late
        assert_eq!(l.status(50_000, Duration::ZERO), LeaseStatus::Held { remaining_ms: 40_000 });
    }

    /// Replaying a captured policy buys nothing: its expiry is an absolute instant, so re-recording
    /// it after that instant leaves the lease lapsed.
    #[test]
    fn replaying_an_expired_policy_does_not_revive_a_lease() {
        let mut l = SessionLease::new(
            SessionLeaseMode::Required,
            SessionBinding::Unknown,
            false,
            Duration::from_secs(15),
        );
        l.record_verified(10_000);
        assert!(matches!(l.status(20_000, Duration::ZERO), LeaseStatus::Lapsed(_)));
        l.record_verified(10_000); // the same captured artifact, presented again
        assert!(
            matches!(l.status(20_000, Duration::ZERO), LeaseStatus::Lapsed(_)),
            "re-presenting an expired policy must not extend the lease"
        );
    }

    /// `ever_held` distinguishes "the viewer never started renewing" from "the viewer stopped",
    /// which is the difference between a stale console bundle and a revoked session in the log.
    #[test]
    fn ever_held_reports_whether_a_lease_was_ever_installed() {
        let mut l = SessionLease::new(
            SessionLeaseMode::Required,
            SessionBinding::Unknown,
            false,
            Duration::from_secs(15),
        );
        assert!(!l.ever_held());
        l.record_verified(1);
        assert!(l.ever_held());
    }

    /// An unleased session is never `Lapsed`, whatever the clock says. This is what keeps the fix
    /// from ending dev/LAN and attended sessions.
    #[test]
    fn an_unleased_session_is_never_lapsed() {
        for mode in [SessionLeaseMode::NotApplicable, SessionLeaseMode::FromSessionBinding] {
            let l = SessionLease::new(mode, SessionBinding::Unknown, true, Duration::from_secs(1));
            assert_eq!(
                l.status(i64::MAX / 2, Duration::from_secs(86_400)),
                LeaseStatus::NotEnforced,
                "{mode:?} must never end a session"
            );
        }
    }

    /// The default mode is the DERIVING one — so a future `SessionOptions` field that forgets to set
    /// it inherits "enforce exactly when the control plane is authoritative", not "never enforce".
    #[test]
    fn the_default_lease_mode_derives_from_the_binding() {
        assert_eq!(SessionLeaseMode::default(), SessionLeaseMode::FromSessionBinding);
    }
}
