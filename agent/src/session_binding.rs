//! The agent's side of session binding (docs/69 §3.2, §3.5): a small state machine the session loop
//! drives. It verifies the control plane's grant, signs the agent's proof over the live DTLS
//! fingerprints, verifies the console's proof, and decides when media and input may flow.
//!
//! Platform-independent on purpose: the host feeds it fingerprints, a signer and the clock, so every
//! transition is unit-tested here rather than inside the session loop.

use std::time::{Duration, Instant};

use rmt_crypto::PublicIdentity;
use rmt_protocol::session_binding::{decode_field_hex, BindTranscript, ROLE_AGENT, ROLE_CONSOLE};

use crate::binding_grant::{SignedBindingGrant, VerifiedBindingGrant};

/// How long an enforcing agent waits for a complete binding before it ends the session (docs/69
/// §3.5: "An agent that receives no valid grant within 10 s ends the session").
pub const BINDING_DEADLINE: Duration = Duration::from_secs(10);

/// Most frames an enforcing agent holds while unbound; one more fails the binding.
pub const MAX_HELD_FRAMES: usize = 256;
/// Most bytes it holds while unbound.
pub const MAX_HELD_BYTES: usize = 4 * 1024 * 1024;

/// Whether this agent gates media and input on a completed binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// Answer binding requests (so a console can verify THIS agent) but do not gate anything.
    AnswerOnly,
    /// Hold every non-binding frame and send no media until the console's proof verifies.
    Enforce,
}

/// The two certificate fingerprints from the agent's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentFingerprints {
    /// SHA-256 of the agent's own DER certificate.
    pub agent: [u8; 32],
    /// SHA-256 of the DER certificate the console presented.
    pub console: [u8; 32],
}

/// Inputs the host supplies when a `BindStart` arrives.
pub struct BindStartContext<'a> {
    /// The pinned control-plane issuer key; `None` when the agent has none (cannot verify a grant).
    pub issuer: Option<&'a PublicIdentity>,
    /// This agent's device id.
    pub device: uuid::Uuid,
    /// The control-plane session id signaling reported for this connection, if any. A grant naming a
    /// different session is refused (docs/69: the grant is authoritative; a mismatch means someone lied).
    pub signaled_session: Option<uuid::Uuid>,
    /// The technician signaling reported, if any. The session acts and audits as this technician, so it must
    /// equal the grant's exactly; an absent one is refused too (the grant is authoritative, docs/69 §3.1).
    pub signaled_technician: Option<uuid::Uuid>,
    /// The live association's fingerprints, or `None` when they cannot be read unambiguously.
    pub fingerprints: Option<AgentFingerprints>,
    /// Signs with the device key; `None` when the agent has no enrolled identity.
    pub signer: Option<&'a dyn Fn(&[u8]) -> [u8; 64]>,
    /// Wall clock, Unix ms (grant validity).
    pub now_ms: i64,
    /// A fresh 32-byte nonce from a CSPRNG.
    pub agent_nonce: [u8; 32],
}

/// The reply the host sends to the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindReply {
    /// Send `BindAgentProof { agent_nonce, sig }` (hex).
    AgentProof { agent_nonce: String, sig: String },
    /// Send `BindResult { ok, reason }`.
    Result { ok: bool, reason: Option<String> },
}

#[derive(Debug)]
enum State {
    Unbound,
    AwaitingConsole { grant: VerifiedBindingGrant, transcript: BindTranscript },
    Bound { grant: VerifiedBindingGrant },
    Failed,
}

/// One connection's binding state.
pub struct AgentBinding {
    enforcement: Enforcement,
    state: State,
    deadline: Instant,
    held: Vec<rmt_protocol::Frame>,
    held_bytes: usize,
}

/// Why a binding failed (the reason string sent in `BindResult`).
pub mod reason {
    /// The grant did not verify (signature, expiry, device) or no issuer key is pinned.
    pub const GRANT: &str = "grant_refused";
    /// The grant names a different session than signaling reported.
    pub const SESSION_MISMATCH: &str = "session_mismatch";
    /// The grant names a different technician, or a stricter access level, than signaling reported.
    pub const IDENTITY_MISMATCH: &str = "identity_mismatch";
    /// The live DTLS fingerprints could not be read unambiguously.
    pub const NO_FINGERPRINTS: &str = "no_fingerprints";
    /// The agent has no enrolled device key to sign with.
    pub const NO_IDENTITY: &str = "no_identity";
    /// The console's proof did not verify.
    pub const CONSOLE_PROOF: &str = "console_proof_refused";
    /// A proof or a second start arrived out of order.
    pub const OUT_OF_ORDER: &str = "out_of_order";
}

impl AgentBinding {
    /// A fresh binding for a connection that started at `now`.
    pub fn new(enforcement: Enforcement, now: Instant) -> Self {
        Self { enforcement, state: State::Unbound, deadline: now + BINDING_DEADLINE, held: Vec::new(), held_bytes: 0 }
    }

    /// Handle `BindStart`. On success the reply is the agent's proof and the state awaits the console.
    pub fn on_bind_start(&mut self, grant_json: &str, console_nonce_hex: &str, cx: BindStartContext<'_>) -> BindReply {
        if !matches!(self.state, State::Unbound) {
            return self.fail(reason::OUT_OF_ORDER);
        }
        let Some(console_nonce) = decode_field_hex(console_nonce_hex) else {
            return self.fail(reason::OUT_OF_ORDER);
        };
        let Some(issuer) = cx.issuer else { return self.fail(reason::GRANT) };
        let grant = match SignedBindingGrant::from_json(grant_json).and_then(|g| g.verify(issuer, cx.now_ms, cx.device)) {
            Ok(g) => g,
            Err(_) => return self.fail(reason::GRANT),
        };
        if cx.signaled_session != Some(grant.session_id) {
            return self.fail(reason::SESSION_MISMATCH);
        }
        // The session acts and audits as signaling's technician, so it must be exactly the grant's (absent counts as
        // different). A STRICTER grant level (view-only for a control ticket, e.g. a view-only group) is not a
        // mismatch: the host applies it once bound (`bound_grant().access`).
        if cx.signaled_technician != Some(grant.technician_id) {
            return self.fail(reason::IDENTITY_MISMATCH);
        }
        let Some(fps) = cx.fingerprints else { return self.fail(reason::NO_FINGERPRINTS) };
        let Some(sign) = cx.signer else { return self.fail(reason::NO_IDENTITY) };
        let transcript = BindTranscript {
            session_id: *grant.session_id.as_bytes(),
            agent_cert_sha256: fps.agent,
            console_cert_sha256: fps.console,
            agent_nonce: cx.agent_nonce,
            console_nonce,
        };
        let sig = sign(&transcript.signing_bytes(ROLE_AGENT));
        self.state = State::AwaitingConsole { grant, transcript };
        BindReply::AgentProof { agent_nonce: hex::encode(cx.agent_nonce), sig: hex::encode(sig) }
    }

    /// Handle `BindConsoleProof`. `current` re-reads the live fingerprints: a verification is only good
    /// for the association it was made on (docs/69 §3.4), so a changed pair fails it.
    pub fn on_console_proof(&mut self, sig_hex: &str, current: Option<AgentFingerprints>) -> BindReply {
        let State::AwaitingConsole { grant, transcript } = std::mem::replace(&mut self.state, State::Failed) else {
            return self.fail(reason::OUT_OF_ORDER);
        };
        let same_association = current
            .is_some_and(|f| f.agent == transcript.agent_cert_sha256 && f.console == transcript.console_cert_sha256);
        if !same_association {
            return self.fail(reason::NO_FINGERPRINTS);
        }
        let sig: Option<[u8; 64]> = hex::decode(sig_hex).ok().and_then(|b| b.try_into().ok());
        let key = PublicIdentity::from_hex(&hex::encode(grant.console_pubkey));
        let ok = match (sig, key) {
            (Some(sig), Ok(key)) => key.verify(&transcript.signing_bytes(ROLE_CONSOLE), &sig).is_ok(),
            _ => false,
        };
        if !ok {
            return self.fail(reason::CONSOLE_PROOF);
        }
        self.state = State::Bound { grant };
        BindReply::Result { ok: true, reason: None }
    }

    fn fail(&mut self, why: &str) -> BindReply {
        self.state = State::Failed;
        BindReply::Result { ok: false, reason: Some(why.to_string()) }
    }

    /// Whether media may be sent and non-binding frames processed now.
    pub fn open(&self) -> bool {
        self.enforcement == Enforcement::AnswerOnly || matches!(self.state, State::Bound { .. })
    }

    /// Whether this connection must end now: an enforcing agent that failed, or whose deadline passed
    /// without a completed binding.
    pub fn must_end(&self, now: Instant) -> bool {
        self.enforcement == Enforcement::Enforce
            && match self.state {
                State::Failed => true,
                State::Bound { .. } => false,
                _ => now >= self.deadline,
            }
    }

    /// The verified grant once bound (its technician and access are authoritative, docs/69 §3.1).
    pub fn bound_grant(&self) -> Option<&VerifiedBindingGrant> {
        match &self.state {
            State::Bound { grant } => Some(grant),
            _ => None,
        }
    }

    /// Hold a frame that arrived while unbound. `false` when the hold limits are exceeded: the binding
    /// fails and the caller ends the session.
    pub fn hold(&mut self, frame: rmt_protocol::Frame) -> bool {
        self.held_bytes += frame.payload.len();
        self.held.push(frame);
        if self.held.len() > MAX_HELD_FRAMES || self.held_bytes > MAX_HELD_BYTES {
            self.held.clear();
            self.state = State::Failed;
            return false;
        }
        true
    }

    /// The held frames, in arrival order, once bound (empty otherwise).
    pub fn take_held(&mut self) -> Vec<rmt_protocol::Frame> {
        if !matches!(self.state, State::Bound { .. }) {
            return Vec::new();
        }
        self.held_bytes = 0;
        std::mem::take(&mut self.held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_policy::AccessLevel;
    use rmt_crypto::Identity;
    use rmt_protocol::{ChannelId, Frame};

    const SESSION: &str = "22222222-2222-2222-2222-222222222222";
    const DEVICE: &str = "33333333-3333-3333-3333-333333333333";

    struct Fixture {
        issuer: Identity,
        device_key: Identity,
        console_key: Identity,
        fps: AgentFingerprints,
    }

    fn fixture() -> Fixture {
        Fixture {
            issuer: Identity::from_seed(&[1; 32]),
            device_key: Identity::from_seed(&[2; 32]),
            console_key: Identity::from_seed(&[3; 32]),
            fps: AgentFingerprints { agent: [0xa1; 32], console: [0xb2; 32] },
        }
    }

    fn grant_json(f: &Fixture, session: &str, expires_at_ms: i64) -> String {
        let claims = crate::binding_grant::BindingGrantClaims {
            session_id: session.parse().unwrap(),
            device_id: DEVICE.parse().unwrap(),
            tenant_id: uuid::Uuid::nil(),
            technician_id: uuid::Uuid::nil(),
            access: AccessLevel::Control,
            console_pubkey: f.console_key.public_hex(),
            issued_at_ms: 1_000,
            expires_at_ms,
        };
        let sig = f.issuer.sign(&claims.signing_bytes().unwrap());
        serde_json::to_string(&SignedBindingGrant { claims, sig: hex::encode(sig) }).unwrap()
    }

    fn start(b: &mut AgentBinding, f: &Fixture, grant: &str, signaled: &str, fps: Option<AgentFingerprints>) -> BindReply {
        let signer = |m: &[u8]| f.device_key.sign(m);
        let issuer = f.issuer.public();
        b.on_bind_start(
            grant,
            &"d4".repeat(32),
            BindStartContext {
                issuer: Some(&issuer),
                device: DEVICE.parse().unwrap(),
                signaled_session: Some(signaled.parse().unwrap()),
                signaled_technician: Some(uuid::Uuid::nil()),
                fingerprints: fps,
                signer: Some(&signer),
                now_ms: 2_000,
                agent_nonce: [0xc3; 32],
            },
        )
    }

    /// The console's side, computed independently from ITS view (here the honest mirror).
    fn console_sig(f: &Fixture, console_view: AgentFingerprints) -> String {
        let t = BindTranscript {
            session_id: *SESSION.parse::<uuid::Uuid>().unwrap().as_bytes(),
            agent_cert_sha256: console_view.agent,
            console_cert_sha256: console_view.console,
            agent_nonce: [0xc3; 32],
            console_nonce: [0xd4; 32],
        };
        hex::encode(f.console_key.sign(&t.signing_bytes(ROLE_CONSOLE)))
    }

    #[test]
    fn honest_exchange_binds_and_releases_held_frames() {
        let f = fixture();
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        assert!(!b.open());
        assert!(b.hold(Frame::new(ChannelId::Control, b"setup".to_vec())));
        let BindReply::AgentProof { agent_nonce, sig } = start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, Some(f.fps)) else {
            panic!("no agent proof");
        };
        // The console can verify the agent's proof over the same transcript.
        let t = BindTranscript {
            session_id: *SESSION.parse::<uuid::Uuid>().unwrap().as_bytes(),
            agent_cert_sha256: f.fps.agent,
            console_cert_sha256: f.fps.console,
            agent_nonce: decode_field_hex(&agent_nonce).unwrap(),
            console_nonce: [0xd4; 32],
        };
        let sig: [u8; 64] = hex::decode(sig).unwrap().try_into().unwrap();
        f.device_key.public().verify(&t.signing_bytes(ROLE_AGENT), &sig).unwrap();
        assert!(b.take_held().is_empty(), "nothing is released before the console proves itself");
        assert_eq!(b.on_console_proof(&console_sig(&f, f.fps), Some(f.fps)), BindReply::Result { ok: true, reason: None });
        assert!(b.open());
        assert!(!b.must_end(Instant::now() + BINDING_DEADLINE * 2));
        assert_eq!(b.take_held().len(), 1);
        assert_eq!(b.bound_grant().unwrap().session_id.to_string(), SESSION);
    }

    #[test]
    fn a_man_in_the_middle_cannot_complete_the_binding() {
        let f = fixture();
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        // The agent's DTLS peer is the attacker: its "console" fingerprint is the attacker's certificate.
        let agent_view = AgentFingerprints { agent: f.fps.agent, console: [0xee; 32] };
        assert!(matches!(start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, Some(agent_view)), BindReply::AgentProof { .. }));
        // The real console signs ITS view (agent cert = the attacker's, as the console received it).
        let console_view = AgentFingerprints { agent: [0xff; 32], console: f.fps.console };
        assert_eq!(
            b.on_console_proof(&console_sig(&f, console_view), Some(agent_view)),
            BindReply::Result { ok: false, reason: Some(reason::CONSOLE_PROOF.into()) }
        );
        assert!(!b.open());
        assert!(b.must_end(Instant::now()));
    }

    #[test]
    fn refusals_fail_closed() {
        let f = fixture();
        let fail = |r: BindReply, why: &str| assert_eq!(r, BindReply::Result { ok: false, reason: Some(why.into()) });

        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        fail(start(&mut b, &f, &grant_json(&f, SESSION, 100_000), "99999999-9999-9999-9999-999999999999", Some(f.fps)), reason::SESSION_MISMATCH);
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        fail(start(&mut b, &f, &grant_json(&f, SESSION, 1_500), SESSION, Some(f.fps)), reason::GRANT); // expired
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        fail(start(&mut b, &f, "{}", SESSION, Some(f.fps)), reason::GRANT);
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        fail(start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, None), reason::NO_FINGERPRINTS);
        // A proof before any start, and a second start, are out of order.
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        fail(b.on_console_proof(&"00".repeat(64), Some(f.fps)), reason::OUT_OF_ORDER);
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        let _ = start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, Some(f.fps));
        fail(start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, Some(f.fps)), reason::OUT_OF_ORDER);
        // The association changed between the two proofs.
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        let _ = start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, Some(f.fps));
        let moved = AgentFingerprints { agent: f.fps.agent, console: [0x01; 32] };
        fail(b.on_console_proof(&console_sig(&f, f.fps), Some(moved)), reason::NO_FINGERPRINTS);
    }

    #[test]
    fn the_technician_must_match_exactly_and_a_stricter_level_still_binds() {
        let f = fixture();
        let signer = |m: &[u8]| f.device_key.sign(m);
        let issuer = f.issuer.public();
        let cx = |technician: Option<uuid::Uuid>, _unused: bool| BindStartContext {
            issuer: Some(&issuer),
            device: DEVICE.parse().unwrap(),
            signaled_session: Some(SESSION.parse().unwrap()),
            signaled_technician: technician,
            fingerprints: Some(f.fps),
            signer: Some(&signer),
            now_ms: 2_000,
            agent_nonce: [0xc3; 32],
        };
        let refused = BindReply::Result { ok: false, reason: Some(reason::IDENTITY_MISMATCH.into()) };
        // Signaling names a different technician than the grant (nil).
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        assert_eq!(b.on_bind_start(&grant_json(&f, SESSION, 100_000), &"d4".repeat(32), cx(Some(uuid::Uuid::from_u128(7)), false)), refused);
        // A view-only grant for a session signaling opened with control.
        let view_only_grant = {
            let mut g: SignedBindingGrant = serde_json::from_str(&grant_json(&f, SESSION, 100_000)).unwrap();
            g.claims.access = AccessLevel::ViewOnly;
            g.sig = hex::encode(f.issuer.sign(&g.claims.signing_bytes().unwrap()));
            serde_json::to_string(&g).unwrap()
        };
        // A STRICTER (view-only) grant for a control ticket binds: the host applies the restriction once bound.
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        assert!(matches!(b.on_bind_start(&view_only_grant, &"d4".repeat(32), cx(Some(uuid::Uuid::nil()), false)), BindReply::AgentProof { .. }));
        // Signaling saying NOTHING about the technician is a mismatch too (the audit chain would carry nil).
        let mut b = AgentBinding::new(Enforcement::Enforce, Instant::now());
        assert_eq!(b.on_bind_start(&grant_json(&f, SESSION, 100_000), &"d4".repeat(32), cx(None, false)), refused);
    }

    #[test]
    fn deadline_hold_limits_and_answer_only_mode() {
        let f = fixture();
        let t0 = Instant::now();
        let mut b = AgentBinding::new(Enforcement::Enforce, t0);
        assert!(!b.must_end(t0 + BINDING_DEADLINE - Duration::from_millis(1)));
        assert!(b.must_end(t0 + BINDING_DEADLINE));
        let mut b = AgentBinding::new(Enforcement::Enforce, t0);
        for _ in 0..MAX_HELD_FRAMES {
            assert!(b.hold(Frame::new(ChannelId::Input, vec![0])));
        }
        assert!(!b.hold(Frame::new(ChannelId::Input, vec![0])), "one frame over the limit fails the binding");
        assert!(b.must_end(t0));
        // Answer-only: everything flows, nothing ends, and the agent still proves itself.
        let mut b = AgentBinding::new(Enforcement::AnswerOnly, t0);
        assert!(b.open());
        assert!(!b.must_end(t0 + BINDING_DEADLINE * 10));
        assert!(matches!(start(&mut b, &f, &grant_json(&f, SESSION, 100_000), SESSION, Some(f.fps)), BindReply::AgentProof { .. }));
    }
}
