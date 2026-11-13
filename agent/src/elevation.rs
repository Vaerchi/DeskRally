//! Cryptographically-signed, session-bound, **single-use** elevation grants — the control plane
//! authorizing ONE command to run with the guest's *linked elevated* token (loop 87, docs/01 §3
//! "Elevate client to admin mid-session").
//!
//! # Why this is not a session policy, and why that is not negotiable
//!
//! A [`SignedSessionPolicy`](crate::session_policy::SignedSessionPolicy) may only ever RESTRICT a
//! session, and that one-way ratchet is the entire reason replaying an old one is harmless: the
//! worst an attacker can do with a captured policy is take away access they already had. An
//! elevation grant is the opposite — it GRANTS — so none of that reasoning transfers. Expressed as
//! a policy it would be a ratchet running the wrong way, and every captured blob would be a
//! privilege escalation for the rest of its TTL. It therefore gets its own artifact, its own
//! domain tag ([`ELEVATION_DOMAIN_TAG`](crate::backstage::canonical::ELEVATION_DOMAIN_TAG)), its
//! own freshness rules, and its own fail-closed default.
//!
//! # What this gate IS — and, precisely, what it is not
//!
//! Loop 88 corrected this section, and the correction matters more than the feature: **on the
//! unattended host this is not a privilege boundary.** An earlier draft argued it was, and the
//! argument does not survive reading the code it sits next to.
//!
//! What the earlier draft got right: an elevated *user* token is not the same capability as SYSTEM.
//! SYSTEM authenticates on the network as the MACHINE account, cannot decrypt the user's
//! DPAPI-protected secrets, has a different profile, and sees none of their mapped drives. Those two
//! identities genuinely are not points on one lattice.
//!
//! What it got wrong is the conclusion. On the unattended host `RunCommand { as_user: false }` runs
//! arbitrary text as SYSTEM, ungated (the session is the authorization — see
//! `crates/agent-windows/src/command_run.rs`), and **SYSTEM holds `SeTcbPrivilege`, which is the
//! entire recipe for minting the guest's linked elevated token.** That recipe is not obscure: it is
//! two calls in this repository — `command_run::interactive_user_token` (`WTSQueryUserToken`) plus
//! `launch::linked_elevated_token` (`GetTokenInformation(TokenLinkedToken)`) — and a technician who
//! can run one SYSTEM command can reach the same end state without a grant. So a reviewer who
//! notices that `LaunchTool` and `RunCommand` reach comparable privilege ungated has noticed
//! something true, and no amount of restating the lattice argument answers them.
//!
//! **What the grant actually buys, which is worth having:**
//!
//! * **Attribution.** Every elevated command is separately authorized and recorded by the control
//!   plane, naming the technician, the session, the machine and the token kind. The SYSTEM path that
//!   could reach the same place records only "a command ran". An auditor asking "who took this
//!   user's identity, when, and under whose authority?" can answer it for the supported path and
//!   cannot for the improvised one.
//! * **Least privilege as POLICY.** `CapElevateSession` is Owner+Admin only and deliberately not
//!   API-token-grantable, so an organisation can hand out session and command rights without handing
//!   out "act as the guest at full admin". That is a revocable administrative control, not a
//!   cryptographic barrier — and stating it as the former is the honest claim.
//! * **A real boundary where SYSTEM is not on the table.** The ATTENDED host cannot elevate at all
//!   (medium integrity, no UAC consent a remote peer can supply — loop 84, measured), and any future
//!   posture that restricts the SYSTEM command path inherits this gate already built.
//!
//! Do not "strengthen" this section back into a privilege-boundary claim. If the boundary is ever
//! wanted for real, it has to be built where the hole is — the ungated SYSTEM command path — and
//! this artifact would then be the thing that re-opens it deliberately.
//!
//! # One grant, one command
//!
//! There is no "elevated mode" and no lease. Each elevated command carries its own grant, minted
//! by the control plane for that request and burned by the agent when it runs. Two consequences,
//! both wanted: the control plane's audit trail records EVERY elevated command rather than a
//! session-wide "elevation was granted at 10:05", and there is no window during which a session is
//! silently elevated.
//!
//! # Freshness: three checks, no nonce round trip
//!
//! Loop 83 sketched an agent-minted nonce for this, because "the agent does not independently know
//! its own control-plane session id". Since loop 86 it does, and the nonce is unnecessary:
//!
//! 1. **Session binding.** [`SignedElevationGrant::verify`] takes the same
//!    [`SessionBinding`](crate::session_policy::SessionBinding) the session policy uses and requires
//!    `session_id` to equal the live control-plane session. The agent learns that id from
//!    `Brokered`, and a signaling server only reports it for a ticket whose control-plane signature
//!    it checked, whose target device matched, and which it burned single-use against a 2-minute
//!    TTL (`server/signaling/broker.go` — `controlPlaneSessionOf` returns "" unless `ticketPub` is
//!    set, and `connect_request` consumes the ticket before brokering). So one control-plane
//!    session id is brokered to at most one peer connection, ever: there is no second party who
//!    could present a captured grant at it. **That single-use ticket burn is load-bearing for this
//!    module.**
//! 2. **Single use.** The agent burns the grant's own `elevation_id` (see
//!    `SpentGrants` in `crates/agent-windows/src/host.rs`), strictly AFTER verification, so a
//!    forgery naming a real id cannot burn it out from under the technician.
//! 3. **Fail closed when unbindable.** [`SessionBinding::Unknown`](crate::session_policy::SessionBinding::Unknown)
//!    — a signaling server that verifies no tickets, an older one, an unparseable value — rejects
//!    every grant. A deployment that cannot vouch for a session id does not get elevation.
//!
//! The agent does NOT check `technician_id`, and that is still the ENFORCEMENT rule: the binding
//! set is machine + session + single-use.
//!
//! It is no longer true that "it has no notion of who the technician is" — loop 91 gave it one, on
//! `brokered`, from the same verified ticket the session id comes from
//! ([`rmt_transport_webrtc::WebRtcTransport::session_technician`]), because the agent seals its own
//! audit events and `technician_id` is inside the hashed preimage. That value is deliberately NOT
//! folded into this check. An elevation grant is the one artifact in this system that GRANTS rather
//! than restricts, so widening its verification to compare two independently-sourced identities
//! would add a way for it to fail CLOSED-then-open on a mismatch the control plane never intended —
//! and it would buy nothing, because signaling and the grant issuer already read the same ticket.
//! Recorded here rather than left to be rediscovered: the ingredient exists now, and declining to
//! use it is a decision.
//!
//! # Wire shape
//!
//! Mirrors [`crate::session_policy`] and [`crate::backstage::grant`] exactly, so all three verify
//! paths read the same:
//!
//! ```json
//! {
//!   "claims": {
//!     "elevation": { "technician_id": "…", "session_id": "…", "machine_id": "…",
//!                    "elevation_id": "…", "token": "linked_elevated" },
//!     "issued_at_ms": 1730000000000,
//!     "expires_at_ms": 1730000120000
//!   },
//!   "sig": "<128 hex chars>"
//! }
//! ```
//!
//! # Canonical signing bytes (elevation v1 — big-endian throughout)
//!
//! ```text
//! ELEVATION_DOMAIN_TAG                        // 12 bytes: b"RMTELEVv1\x00\x00\x00"
//! || technician_id                            // 16 raw bytes
//! || session_id                               // 16 raw bytes
//! || machine_id                               // 16 raw bytes
//! || elevation_id                             // 16 raw bytes
//! || u32be(len(token_utf8)) || token_utf8     // "base" | "linked_elevated"
//! || i64be(issued_at_ms)
//! || i64be(expires_at_ms)
//! ```
//!
//! The command text is deliberately NOT in the preimage. Binding it would force the viewer to POST
//! the command line to the control plane — creating a path for text this system goes out of its way
//! never to log, because it can carry credentials — and would buy nothing: the party holding the
//! grant is the technician the control plane just authorized.
//!
//! Cross-language agreement with the Go minter is proven by shared golden vectors:
//! `tests::golden_vector_v1` here and `TestElevationGoldenVectorV1` in
//! `control-plane/elevation_mint_test.go` assert the SAME fixture produces the SAME canonical-bytes
//! hex AND the SAME signature hex, and `tests::verifies_go_minted_elevation` feeds Go's actual wire
//! bytes through the real decoder.

use serde::{Deserialize, Serialize};

use rmt_crypto::{Identity, PublicIdentity};

use crate::backstage::canonical::CanonicalWriter;
use crate::backstage::grant::CLOCK_SKEW_MS;
use crate::session_policy::SessionBinding;

/// Which token an authorized command runs with.
///
/// A NAMED enum whose RESTRICTIVE variant is also the [`Default`], for the reason this codebase
/// learned the hard way (`insecure-default-nobody-chose`): every "we could not work out what was
/// meant" path must land on *do not elevate*. [`ElevationToken::Base`] is the interactive user's
/// ordinary, UAC-filtered token — i.e. no elevation at all — so a grant that somehow arrived
/// without a readable token kind authorizes nothing.
///
/// `Base` is not dead weight. It is what makes the token kind a *choice* recorded in the signed
/// preimage rather than an implicit constant, so a future minter that stopped naming the kind
/// cannot silently keep producing elevated grants (`tests::the_token_kind_changes_the_preimage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ElevationToken {
    /// The interactive user's ordinary (UAC-filtered) token — no elevation. The default, so an
    /// absent or unparseable kind grants nothing.
    #[default]
    Base,
    /// The interactive user's **linked elevated** token: their own full administrator rights, as if
    /// they had clicked "Yes" on a UAC prompt. Never SYSTEM.
    LinkedElevated,
}

impl ElevationToken {
    /// The canonical snake_case name — the exact string serde emits, used both in the claims JSON
    /// and (length-prefixed) in the canonical signing bytes, so it MUST match serde exactly
    /// (`tests::token_name_matches_serde` asserts that for every variant).
    ///
    /// Exhaustive with no catch-all, so adding a variant fails to compile until its canonical name
    /// is defined here — the same anti-drift discipline
    /// [`capability_name`](crate::backstage::canonical::capability_name) and
    /// [`AccessLevel::name`](crate::session_policy::AccessLevel::name) use.
    ///
    /// Go does NOT mirror it with a function (an earlier version of this comment named an
    /// `elevationTokenName` that does not exist). There, `ElevationTokenKind` is a `string` newtype
    /// whose constants ARE the wire values — `ElevationTokenBase = "base"`,
    /// `ElevationTokenLinkedElevated = "linked_elevated"` in `control-plane/elevation_mint.go` — so
    /// the name cannot drift from the value on that side because they are the same thing. What
    /// keeps the two LANGUAGES together is not a shared function name but the golden vectors:
    /// `TestElevationGoldenVectorV1` (and its `base` sibling) pin the canonical preimage, which
    /// length-prefixes exactly this string.
    pub fn name(self) -> &'static str {
        match self {
            ElevationToken::Base => "base",
            ElevationToken::LinkedElevated => "linked_elevated",
        }
    }

    /// Does this kind actually authorize elevation? Only [`ElevationToken::LinkedElevated`] does.
    pub fn is_elevated(self) -> bool {
        matches!(self, ElevationToken::LinkedElevated)
    }
}

/// The authorization itself: who, which session, which machine, which single-use id, which token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Elevation {
    /// The technician the control plane authorized. Recorded for the audit trail; the agent does
    /// NOT check it (it has no notion of technician identity) — see the module docs.
    pub technician_id: uuid::Uuid,
    /// The CONTROL-PLANE session record id this grant is bound to. Checked against
    /// [`SessionBinding`].
    pub session_id: uuid::Uuid,
    /// The agent's DEVICE id. Checked against this agent's own, exactly as the H3 device binding
    /// on a backstage grant is.
    pub machine_id: uuid::Uuid,
    /// A fresh uuid per mint — the key the agent burns to make the grant single-use. Distinct from
    /// `session_id` on purpose: keying single-use on the session would make elevation a
    /// once-per-session capability instead of once-per-command.
    pub elevation_id: uuid::Uuid,
    /// Which token the command runs with.
    pub token: ElevationToken,
}

/// [`Elevation`] plus its validity window (Unix milliseconds). Keep the field set + order stable —
/// changing it changes the signing bytes and breaks the cross-language golden vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationClaims {
    /// The authorization the agent will enforce once these claims verify.
    pub elevation: Elevation,
    /// When the control plane minted this grant (Unix ms). `now_ms` must be at or after this, minus
    /// [`CLOCK_SKEW_MS`].
    pub issued_at_ms: i64,
    /// When this grant stops being valid (Unix ms, exclusive).
    pub expires_at_ms: i64,
}

impl ElevationClaims {
    /// The canonical elevation-v1 signing bytes (see the module docs for the exact layout). This —
    /// not the JSON — is what the issuer signs and the agent verifies, so Rust and Go produce
    /// identical signing input for the same claims.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.elevation_tag()
            .raw16(self.elevation.technician_id.as_bytes())
            .raw16(self.elevation.session_id.as_bytes())
            .raw16(self.elevation.machine_id.as_bytes())
            .raw16(self.elevation.elevation_id.as_bytes())
            .lp_str(self.elevation.token.name())
            .i64(self.issued_at_ms)
            .i64(self.expires_at_ms);
        w.into_bytes()
    }

    /// Sign these claims with the issuer's long-term identity.
    pub fn sign(&self, issuer: &Identity) -> SignedElevationGrant {
        let sig = issuer.sign(&self.signing_bytes());
        SignedElevationGrant { claims: self.clone(), sig: hex::encode(sig) }
    }
}

/// An [`ElevationClaims`] plus the issuer's Ed25519 signature over its canonical signing bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedElevationGrant {
    /// The signed claims.
    pub claims: ElevationClaims,
    /// Hex-encoded 64-byte Ed25519 signature over
    /// [`signing_bytes`](ElevationClaims::signing_bytes).
    pub sig: String,
}

impl SignedElevationGrant {
    /// Encode to the JSON wire string carried opaquely in the Control channel's `ElevatedRun`
    /// message (so `rmt-agent-core` need not depend on `rmt-agent`).
    pub fn to_json(&self) -> Result<String, ElevationError> {
        serde_json::to_string(self).map_err(|e| ElevationError::Encoding(e.to_string()))
    }

    /// Decode from the JSON wire string. Does **not** verify — call [`verify`](Self::verify).
    pub fn from_json(s: &str) -> Result<Self, ElevationError> {
        serde_json::from_str(s).map_err(|e| ElevationError::Encoding(e.to_string()))
    }

    /// Verify the signature against the pinned `issuer`, check the validity window against
    /// `now_ms`, bind to this DEVICE (`machine_id == expected_machine_id`), bind to this SESSION per
    /// `binding`, and require the grant to actually name an elevated token.
    ///
    /// Order mirrors [`SignedSessionPolicy::verify`](crate::session_policy::SignedSessionPolicy::verify)
    /// and [`SignedGrant::verify`](crate::backstage::grant::SignedGrant::verify) deliberately:
    /// signature FIRST (so a forged grant is rejected before any self-claimed field is trusted),
    /// then not-yet-valid with [`CLOCK_SKEW_MS`] tolerance, then expiry (exact), then the device
    /// binding, then the session binding, then the token kind.
    ///
    /// The token check is LAST because it is the only one that is not about *whether this grant is
    /// for us*: a `base` grant is a perfectly well-formed authorization that simply authorizes
    /// nothing, and reporting the most specific true reason keeps the log legible. What DOES ride on
    /// order is the signature staying first, and single-use (which lives in the caller) staying
    /// strictly after ALL of this.
    ///
    /// Single use is NOT enforced here, for the same reason the backstage grant's is not: this is a
    /// pure predicate pinned by byte-for-byte golden vectors shared with the Go issuer, and making
    /// it stateful would make those vectors meaningless. The agent owns the ledger.
    pub fn verify(
        &self,
        issuer: &PublicIdentity,
        now_ms: i64,
        expected_machine_id: uuid::Uuid,
        binding: SessionBinding,
    ) -> Result<Elevation, ElevationError> {
        let bytes = self.claims.signing_bytes();
        let sig_bytes = hex::decode(&self.sig)
            .map_err(|_| ElevationError::Encoding("signature is not hex".into()))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| ElevationError::Encoding("signature is not 64 bytes".into()))?;

        issuer.verify(&bytes, &sig).map_err(|_| ElevationError::BadSignature)?;

        if now_ms + CLOCK_SKEW_MS < self.claims.issued_at_ms {
            return Err(ElevationError::NotYetValid);
        }
        if now_ms >= self.claims.expires_at_ms {
            return Err(ElevationError::Expired);
        }
        if self.claims.elevation.machine_id != expected_machine_id {
            return Err(ElevationError::WrongMachine {
                expected: expected_machine_id,
                found: self.claims.elevation.machine_id,
            });
        }
        match binding {
            SessionBinding::Session(expected) => {
                if self.claims.elevation.session_id != expected {
                    return Err(ElevationError::WrongSession {
                        expected,
                        found: self.claims.elevation.session_id,
                    });
                }
            }
            // Not a pass-through. An agent that cannot name its own session cannot tell a grant
            // minted for it from one captured elsewhere, and accepting the second is the whole
            // attack — and unlike a session policy, accepting it hands over PRIVILEGE rather than
            // taking it away.
            SessionBinding::Unknown => return Err(ElevationError::UnboundSession),
        }
        if !self.claims.elevation.token.is_elevated() {
            return Err(ElevationError::NotElevating {
                token: self.claims.elevation.token.name(),
            });
        }
        Ok(self.claims.elevation.clone())
    }
}

/// Why a [`SignedElevationGrant`] was rejected. Distinct variants so the agent can log precisely and
/// a clock problem is never confused with a key problem — and so a test can assert WHICH check
/// refused, not merely that something did.
#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    #[error("elevation grant signature is invalid (wrong issuer key or tampered claims)")]
    BadSignature,
    #[error("elevation grant has expired")]
    Expired,
    #[error("elevation grant is not yet valid")]
    NotYetValid,
    #[error(
        "elevation grant is for a different machine (expected {expected}, grant carries {found})"
    )]
    WrongMachine { expected: uuid::Uuid, found: uuid::Uuid },
    #[error(
        "elevation grant is for a different session (expected {expected}, grant carries {found})"
    )]
    WrongSession { expected: uuid::Uuid, found: uuid::Uuid },
    #[error(
        "elevation grant cannot be bound: the signaling server did not report a control-plane \
         session id for this connection (is it running without ticket verification?)"
    )]
    UnboundSession,
    #[error("elevation grant authorizes no elevation (token kind {token:?})")]
    NotElevating { token: &'static str },
    #[error("malformed signed elevation grant: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`ElevationToken`] variant, so a new one cannot be added without the table-driven
    /// tests below covering it.
    const ALL_TOKENS: [ElevationToken; 2] = [ElevationToken::Base, ElevationToken::LinkedElevated];

    const MACHINE: &str = "33333333-3333-3333-3333-333333333333";
    const SESSION: &str = "22222222-2222-2222-2222-222222222222";

    fn machine() -> uuid::Uuid {
        MACHINE.parse().unwrap()
    }

    fn session() -> uuid::Uuid {
        SESSION.parse().unwrap()
    }

    /// The binding that MATCHES what [`claims`] mints. A mismatch is named explicitly by the tests
    /// that want one — which is why [`SessionBinding`] is an enum: there is no way to "just not
    /// check".
    fn bound() -> SessionBinding {
        SessionBinding::Session(session())
    }

    fn claims(now: i64, ttl: i64, token: ElevationToken) -> ElevationClaims {
        ElevationClaims {
            elevation: Elevation {
                technician_id: "11111111-1111-1111-1111-111111111111".parse().unwrap(),
                session_id: session(),
                machine_id: machine(),
                elevation_id: "44444444-4444-4444-4444-444444444444".parse().unwrap(),
                token,
            },
            issued_at_ms: now,
            expires_at_ms: now + ttl,
        }
    }

    // ---------------------------------------------------------------------------------------
    // ElevationToken — the deny-by-default discipline
    // ---------------------------------------------------------------------------------------

    /// The canonical name MUST equal what serde emits, because the name goes into the signing bytes
    /// while serde produces the JSON: if they drift, a grant signs as one kind and reads back as
    /// another. Compared against serde's own output rather than a hardcoded string, so this cannot
    /// pass by both sides being edited to the same wrong value.
    #[test]
    fn token_name_matches_serde() {
        for t in ALL_TOKENS {
            let json = serde_json::to_string(&t).expect("serialize");
            let serde_str = json.trim_matches('"');
            assert_eq!(t.name(), serde_str, "name() disagrees with serde for {t:?}");
        }
    }

    /// The DEFAULT must be the variant that authorizes nothing. Every unparseable/absent path lands
    /// here, so if this ever became `LinkedElevated` the failure mode would be silent elevation.
    #[test]
    fn the_default_token_grants_no_elevation() {
        assert_eq!(ElevationToken::default(), ElevationToken::Base);
        assert!(!ElevationToken::default().is_elevated());
        assert!(ElevationToken::LinkedElevated.is_elevated());
    }

    /// An unknown token kind must fail to DECODE rather than fall back to a default. serde's
    /// `rename_all` enum has no catch-all, so this is structural — but assert it, because a later
    /// `#[serde(other)]` would silently turn every unknown future kind into `Base`… or worse.
    #[test]
    fn an_unknown_token_kind_does_not_decode() {
        assert!(serde_json::from_str::<ElevationToken>(r#""system""#).is_err());
        assert!(serde_json::from_str::<ElevationToken>(r#""linked_elevated""#).is_ok());
    }

    // ---------------------------------------------------------------------------------------
    // verify() — the checks, one at a time
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_genuine_grant_verifies() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&issuer);
        let e = signed
            .verify(&issuer.public(), now + 1_000, machine(), bound())
            .expect("a genuine grant verifies");
        assert_eq!(e.token, ElevationToken::LinkedElevated);
        assert_eq!(e.machine_id, machine());
        assert_eq!(e.session_id, session());
    }

    #[test]
    fn a_tampered_claim_fails_the_signature() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let mut signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&issuer);
        // Move it to another machine, keeping the signature: the signature must catch it BEFORE
        // the device binding does, or a forger controls which error they see.
        signed.claims.elevation.machine_id = uuid::Uuid::nil();
        assert!(matches!(
            signed.verify(&issuer.public(), now + 1_000, uuid::Uuid::nil(), bound()),
            Err(ElevationError::BadSignature)
        ));
    }

    #[test]
    fn a_grant_from_another_issuer_is_refused() {
        let issuer = Identity::generate();
        let attacker = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&attacker);
        assert!(matches!(
            signed.verify(&issuer.public(), now + 1_000, machine(), bound()),
            Err(ElevationError::BadSignature)
        ));
    }

    #[test]
    fn the_validity_window_is_enforced_at_both_ends() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&issuer);

        // Expiry is EXACT: at expires_at_ms the grant is already dead.
        assert!(matches!(
            signed.verify(&issuer.public(), now + 120_000, machine(), bound()),
            Err(ElevationError::Expired)
        ));
        assert!(signed.verify(&issuer.public(), now + 119_999, machine(), bound()).is_ok());

        // Not-yet-valid tolerates CLOCK_SKEW_MS, one-sided.
        assert!(signed
            .verify(&issuer.public(), now - CLOCK_SKEW_MS, machine(), bound())
            .is_ok());
        assert!(matches!(
            signed.verify(&issuer.public(), now - CLOCK_SKEW_MS - 1, machine(), bound()),
            Err(ElevationError::NotYetValid)
        ));
    }

    #[test]
    fn a_grant_for_another_machine_is_refused() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&issuer);
        let other: uuid::Uuid = "99999999-9999-9999-9999-999999999999".parse().unwrap();
        assert!(matches!(
            signed.verify(&issuer.public(), now + 1_000, other, bound()),
            Err(ElevationError::WrongMachine { .. })
        ));
    }

    /// THE REPLAY. A perfectly signed, unexpired grant for THIS machine, captured from another
    /// session. Nothing about the blob is wrong; the only thing that refuses it is the binding.
    #[test]
    fn a_grant_from_another_session_is_refused() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&issuer);
        let other_session: uuid::Uuid = "77777777-7777-7777-7777-777777777777".parse().unwrap();
        match signed.verify(
            &issuer.public(),
            now + 1_000,
            machine(),
            SessionBinding::Session(other_session),
        ) {
            Err(ElevationError::WrongSession { expected, found }) => {
                assert_eq!(expected, other_session);
                assert_eq!(found, session());
            }
            other => panic!("a replayed grant must be refused as WrongSession, got {other:?}"),
        }
    }

    /// FAIL CLOSED. An agent that cannot learn its control-plane session id refuses every grant —
    /// it cannot tell a fresh one from a captured one, and here the cost of guessing wrong is
    /// handing over the guest's admin token.
    #[test]
    fn an_unbindable_session_refuses_even_a_genuine_grant() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::LinkedElevated).sign(&issuer);
        assert!(matches!(
            signed.verify(&issuer.public(), now + 1_000, machine(), SessionBinding::Unknown),
            Err(ElevationError::UnboundSession)
        ));
        // …and the message names the likely cause, because on a dev/LAN stack this looks exactly
        // like a broken feature (scripts/vmlab/start-stack.ps1 runs signaling that way).
        let msg = ElevationError::UnboundSession.to_string();
        assert!(msg.contains("ticket verification"), "unhelpful message: {msg}");
    }

    /// A well-formed grant that names the BASE token authorizes nothing. This is the deny-default
    /// reaching all the way to the end of verify: a minter that dropped the token kind produces
    /// `base` (serde's default is not used here — the field is required — but a minter that
    /// explicitly sent `base` must not elevate).
    #[test]
    fn a_base_token_grant_authorizes_no_elevation() {
        let issuer = Identity::generate();
        let now = 1_730_000_000_000;
        let signed = claims(now, 120_000, ElevationToken::Base).sign(&issuer);
        assert!(matches!(
            signed.verify(&issuer.public(), now + 1_000, machine(), bound()),
            Err(ElevationError::NotElevating { token: "base" })
        ));
    }

    /// A missing field must be an error, never a default. `elevation_id` is the single-use key: if
    /// it silently defaulted to the nil uuid, every grant would share one ledger slot and the
    /// SECOND elevated command of a session would be refused as a replay — a bug that looks like
    /// flakiness rather than like a missing check.
    #[test]
    fn a_missing_field_does_not_decode() {
        const FULL: &str = r#"{"claims":{"elevation":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","elevation_id":"44444444-4444-4444-4444-444444444444","token":"linked_elevated"},"issued_at_ms":1,"expires_at_ms":2},"sig":"ab"}"#;
        assert!(SignedElevationGrant::from_json(FULL).is_ok(), "the full fixture must decode");
        for field in [
            r#""elevation_id":"44444444-4444-4444-4444-444444444444","#,
            r#""token":"linked_elevated""#,
            r#""session_id":"22222222-2222-2222-2222-222222222222","#,
        ] {
            let without = FULL.replace(field, "").replace(",}", "}");
            assert!(
                SignedElevationGrant::from_json(&without).is_err(),
                "a grant without {field} must not decode"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // Domain separation
    // ---------------------------------------------------------------------------------------

    /// The preimage must open with the ELEVATION tag and no other. Both directions asserted: the
    /// same Ed25519 key signs grants, audit heads, session policies and these, and the tag is the
    /// only thing making a policy's signature unusable as an elevation.
    #[test]
    fn the_preimage_is_domain_separated() {
        use crate::backstage::canonical::{
            DOMAIN_TAG, ELEVATION_DOMAIN_TAG, SESSION_POLICY_DOMAIN_TAG,
        };
        let bytes = claims(1, 2, ElevationToken::LinkedElevated).signing_bytes();
        assert!(bytes.starts_with(&ELEVATION_DOMAIN_TAG));
        assert!(!bytes.starts_with(&SESSION_POLICY_DOMAIN_TAG));
        assert!(!bytes.starts_with(&DOMAIN_TAG));
    }

    /// The token kind is IN the signed bytes. A minter that dropped it from the preimage — while
    /// still putting it in the JSON — would let a `base` grant's signature be re-read as
    /// `linked_elevated` by editing one JSON field. This is the test that catches that.
    #[test]
    fn the_token_kind_changes_the_preimage() {
        let base = claims(1, 2, ElevationToken::Base).signing_bytes();
        let elevated = claims(1, 2, ElevationToken::LinkedElevated).signing_bytes();
        assert_ne!(base, elevated, "the token kind is not covered by the signature");
    }

    /// So is the single-use id. Without it in the preimage, one signature would cover every
    /// elevation_id and a captured grant could be re-keyed to dodge the ledger.
    #[test]
    fn the_elevation_id_changes_the_preimage() {
        let mut a = claims(1, 2, ElevationToken::LinkedElevated);
        let b = a.clone();
        a.elevation.elevation_id = uuid::Uuid::nil();
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    // =====================================================================================
    // GOLDEN CROSS-LANGUAGE VECTOR (elevation v1) — the proof Rust and Go agree byte-for-byte.
    // The SAME fixed fixture is hardcoded in control-plane/elevation_mint_test.go's
    // TestElevationGoldenVectorV1. If the two languages' canonical encoders or Ed25519 signing
    // ever diverge, one side's hex stops matching. DO NOT change a value here without changing it
    // identically in the Go test.
    //
    //   seed (32 bytes, hex): 0102…20  (the SAME seed the grant and session-policy vectors use,
    //     deliberately: the three then share an issuer key, so the ONLY thing separating their
    //     signatures is the domain tag + payload — which is exactly the property under test)
    //   technician_id: 11111111-1111-1111-1111-111111111111
    //   session_id:    22222222-2222-2222-2222-222222222222
    //   machine_id:    33333333-3333-3333-3333-333333333333
    //   elevation_id:  44444444-4444-4444-4444-444444444444
    //   token:         linked_elevated
    //   issued_at_ms:  1730000000000
    //   expires_at_ms: 1730000120000
    // =====================================================================================

    const GOLDEN_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const GOLDEN_PUBKEY_HEX: &str =
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const GOLDEN_PREIMAGE_HEX: &str = "524d54454c45567631000000111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333444444444444444444444444444444440000000f6c696e6b65645f656c65766174656400000192cc09140000000192cc0ae8c0";
    const GOLDEN_SIG_HEX: &str = "2553ca0a7026e5d3609f2827b4a862163dafe4cd98e9b25f68bb93825e5e242c1ef5227902e712e372852f6de58c7db628024369bf3444f32832c6c42a91930a";

    fn golden_claims() -> ElevationClaims {
        ElevationClaims {
            elevation: Elevation {
                technician_id: "11111111-1111-1111-1111-111111111111".parse().unwrap(),
                session_id: "22222222-2222-2222-2222-222222222222".parse().unwrap(),
                machine_id: "33333333-3333-3333-3333-333333333333".parse().unwrap(),
                elevation_id: "44444444-4444-4444-4444-444444444444".parse().unwrap(),
                token: ElevationToken::LinkedElevated,
            },
            issued_at_ms: 1_730_000_000_000,
            expires_at_ms: 1_730_000_120_000,
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
        eprintln!("GOLDEN_SIG_HEX      = {}", signed.sig);
        eprintln!("GOLDEN_JSON         = {}", signed.to_json().unwrap());

        assert_eq!(issuer.public_hex(), GOLDEN_PUBKEY_HEX, "pubkey drift");
        assert_eq!(preimage_hex, GOLDEN_PREIMAGE_HEX, "canonical preimage drift");
        assert_eq!(signed.sig, GOLDEN_SIG_HEX, "signature drift");
    }

    /// Direct Go-mint → Rust-verify interop: a `SignedElevationGrant` JSON produced by the Go
    /// `GrantIssuer.MintElevation` for the golden fixture (pasted verbatim from
    /// `control-plane/elevation_mint_test.go`'s logged output) verifies here.
    ///
    /// This proves more than `golden_vector_v1` does. That test shows both languages compute the
    /// same hex for the same fixture; this one feeds Go's wire bytes — field names, field order,
    /// number formatting and all — through the real decoder and the real verifier. A serde rename
    /// on THIS side passes the hex comparison and fails here.
    ///
    /// Read the direction carefully, because it was once written the other way round and was wrong:
    /// this constant is a frozen SNAPSHOT of Go's output, not Go's live output, so on its own it
    /// cannot catch a Go struct-tag rename — Go would happily emit the new spelling while this test
    /// kept verifying the old one. The Go half of the contract is `goldenElevationWireJSON` in
    /// `control-plane/elevation_mint_test.go`, which pins this exact string from the other side. The
    /// pair is the contract; either alone is half of it.
    #[test]
    fn verifies_go_minted_elevation() {
        const GO_MINTED_JSON: &str = r#"{"claims":{"elevation":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","elevation_id":"44444444-4444-4444-4444-444444444444","token":"linked_elevated"},"issued_at_ms":1730000000000,"expires_at_ms":1730000120000},"sig":"2553ca0a7026e5d3609f2827b4a862163dafe4cd98e9b25f68bb93825e5e242c1ef5227902e712e372852f6de58c7db628024369bf3444f32832c6c42a91930a"}"#;

        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedElevationGrant::from_json(GO_MINTED_JSON).expect("Go JSON decodes");
        let e = signed
            .verify(&issuer, 1_730_000_060_000, machine(), bound())
            .expect("a Go-minted elevation grant verifies in Rust");
        assert_eq!(e.token, ElevationToken::LinkedElevated);
        assert_eq!(e.elevation_id, "44444444-4444-4444-4444-444444444444".parse::<uuid::Uuid>().unwrap());
        assert_eq!(e.machine_id, machine());
        assert_eq!(e.session_id, session());
    }
}
