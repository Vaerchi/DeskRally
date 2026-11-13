//! Ticketed (BROKERED) controller path — a Rust controller against an ENFORCING signaling server.
//!
//! Everything else in the Rust suite dials a signaling server run with
//! `-insecure-no-ticket-verification`. This test starts its OWN signaling server with
//! `SIGNALING_TICKET_PUBKEY` set (ticket gate LIVE) and `-insecure-no-agent-auth` (agent gate off —
//! the two gates are deliberately uncoupled, and enrolling a real agent identity is out of scope
//! here), then proves the contract in both directions:
//!
//!   * a `connect_request` carrying a valid `RMTTICKETv1` ticket is brokered and the session runs;
//!   * the same request with NO ticket, a ticket for a DIFFERENT device, and a REPLAYED ticket are
//!     each refused with the server's single generic reason.
//!
//! The ticket is minted here with ed25519-dalek over the canonical preimage — the control plane's
//! job in production (`control-plane/ticket.go MintSessionTicket`). `canonical_ticket_preimage` is
//! pinned against the SAME cross-module golden fixture as `server/signaling/ticket_test.go` and
//! `control-plane/ticket_test.go`, so any byte drift fails as a unit assertion here rather than as
//! an unexplained "not authorized" hang.
//!
//! Self-skips (loudly) only when the signaling binary is genuinely unavailable.

use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rmt_protocol::signaling::{SessionTicketClaims, SignedSessionTicket};
use rmt_protocol::DeviceId;
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// The 12-byte domain tag: ASCII "RMTTICKETv1" + one NUL. Twin of `ticketDomainTag` in both Go
/// modules; distinct from the grant tag ("RMTGRANTv1\0\0") by construction.
const TICKET_DOMAIN_TAG: &[u8] = b"RMTTICKETv1\x00";

/// Rebuild the canonical v1 ticket preimage: tag || u8 v || u32be-length-prefixed
/// session/technician/tenant/device || i64be iat_ms || i64be exp_ms.
fn canonical_ticket_preimage(c: &SessionTicketClaims) -> Vec<u8> {
    let mut buf = TICKET_DOMAIN_TAG.to_vec();
    buf.push(c.v as u8);
    let mut lp = |s: &str| {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
    };
    lp(&c.session_id);
    lp(&c.technician_id);
    lp(&c.tenant_id);
    lp(&c.device_id);
    buf.extend_from_slice(&c.iat_ms.to_be_bytes());
    buf.extend_from_slice(&c.exp_ms.to_be_bytes());
    buf
}

fn sign_ticket(key: &SigningKey, claims: SessionTicketClaims) -> SignedSessionTicket {
    let sig = key.sign(&canonical_ticket_preimage(&claims));
    SignedSessionTicket { claims, sig: hex::encode(sig.to_bytes()) }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn fresh_claims(device: &DeviceId) -> SessionTicketClaims {
    let now = now_ms();
    SessionTicketClaims {
        v: 1,
        // Single-use is keyed on session_id, so every mint gets a fresh one.
        session_id: uuid_string(),
        technician_id: uuid_string(),
        tenant_id: "tenant-e2e".into(),
        device_id: device.to_string(),
        iat_ms: now,
        exp_ms: now + 120_000,
    }
}

fn uuid_string() -> String {
    DeviceId::new().to_string()
}

/// GOLDEN CROSS-MODULE VECTOR: the exact fixture pinned in server/signaling/ticket_test.go and
/// control-plane/ticket_test.go. If this Rust encoder drifts by a byte, the signaling server would
/// reject every ticket with only its generic reason — so pin the preimage AND the signature here.
#[test]
fn ticket_preimage_matches_the_go_golden_vector() {
    const SEED_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const PREIMAGE_HEX: &str = "524d545449434b4554763100010000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000002431313131313131312d313131312d313131312d313131312d3131313131313131313131310000000d74656e616e742d676f6c64656e0000002433333333333333332d333333332d333333332d333333332d33333333333333333333333300000192cc09140000000192cc0ae8c0";
    const SIG_HEX: &str = "b9a0410a9c14acba175a98d04a9a482bde5f08c682b17b708c08268e9eb17df25b691924e587403a69d180afcb2d90d4463e0097ed60c46e970c74d65aa78a06";
    const PUBKEY_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

    let claims = SessionTicketClaims {
        v: 1,
        session_id: "22222222-2222-2222-2222-222222222222".into(),
        technician_id: "11111111-1111-1111-1111-111111111111".into(),
        tenant_id: "tenant-golden".into(),
        device_id: "33333333-3333-3333-3333-333333333333".into(),
        iat_ms: 1_730_000_000_000,
        exp_ms: 1_730_000_120_000,
    };
    assert_eq!(
        hex::encode(canonical_ticket_preimage(&claims)),
        PREIMAGE_HEX,
        "canonical ticket preimage drifted from the Go modules' golden vector"
    );

    let key = signing_key_from_hex(SEED_HEX);
    assert_eq!(hex::encode(key.verifying_key().to_bytes()), PUBKEY_HEX);
    assert_eq!(sign_ticket(&key, claims).sig, SIG_HEX, "signature drift");
}

fn signing_key_from_hex(seed_hex: &str) -> SigningKey {
    let seed = hex::decode(seed_hex).expect("seed hex");
    SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"))
}

/// The signaling server this test drives, killed on drop so a failed assertion never leaks it.
struct Signaling {
    child: Child,
    url: String,
}

impl Drop for Signaling {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start an ENFORCING signaling server (ticket gate on, agent gate off) on its own port, or
/// return None when the binary genuinely cannot be produced.
fn start_enforcing_signaling(pubkey_hex: &str, port: u16) -> Option<Signaling> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    let dir = repo.join("server").join("signaling");
    let exe = dir.join(if cfg!(windows) { "signaling.exe" } else { "signaling" });
    if !exe.exists() {
        let built = Command::new("go")
            .args(["build", "-o", exe.to_str()?, "."])
            .current_dir(&dir)
            .status();
        match built {
            Ok(s) if s.success() => {}
            _ => return None,
        }
    }
    let child = Command::new(&exe)
        .args(["-addr", &format!(":{port}"), "-insecure-no-agent-auth"])
        .current_dir(&dir)
        .env("SIGNALING_TICKET_PUBKEY", pubkey_hex)
        .spawn()
        .ok()?;
    Some(Signaling { child, url: format!("ws://127.0.0.1:{port}/ws") })
}

/// `WebRtcTransport` has no `Debug`, so unwrap the refusal by hand rather than via `expect_err`.
fn expect_refused(res: Result<WebRtcTransport, String>, what: &str) -> String {
    match res {
        Ok(_) => panic!("{what}"),
        Err(e) => e,
    }
}

async fn wait_reachable(url: &str) -> bool {
    for _ in 0..40 {
        if tokio::time::timeout(Duration::from_millis(400), tokio_tungstenite::connect_async(url))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ticketed_controller_is_brokered_and_unticketed_is_refused() {
    // A per-run issuer key: the "control plane" whose public half the server pins.
    let issuer = signing_key_from_hex(
        "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
    );
    let pubkey_hex = hex::encode(issuer.verifying_key().to_bytes());

    // Its own port so it never fights the harness-spawned dev signaling on :18080.
    let Some(sig) = start_enforcing_signaling(&pubkey_hex, 18091) else {
        eprintln!("SKIP: could not build/start server/signaling (needs the Go toolchain)");
        return;
    };
    if !wait_reachable(&sig.url).await {
        eprintln!("SKIP: enforcing signaling did not come up at {}", sig.url);
        return;
    }

    let agent_device = DeviceId::new();
    let agent_url = sig.url.clone();
    // The agent just has to be registered and waiting; it is the CONTROLLER's request the ticket
    // gate judges. Its connect resolves once a controller is brokered to it.
    let agent = tokio::spawn(async move {
        WebRtcTransport::connect(&agent_url, Role::dev_agent(agent_device, "ed25519:test-agent"))
            .await
            .map(|_t| ())
    });
    tokio::time::sleep(Duration::from_millis(700)).await;

    // --- NEGATIVE 1: no ticket at all. ---
    let err = expect_refused(
        WebRtcTransport::connect(&sig.url, Role::dev_controller(agent_device)).await,
        "an unticketed connect_request must be refused by an enforcing server",
    );
    assert!(err.contains("not authorized"), "unexpected rejection: {err}");

    // --- NEGATIVE 2: a validly signed ticket for a DIFFERENT device. ---
    let wrong = sign_ticket(&issuer, fresh_claims(&DeviceId::new()));
    let err = expect_refused(
        WebRtcTransport::connect(&sig.url, Role::controller(agent_device, wrong)).await,
        "a ticket bound to another device must be refused",
    );
    assert!(err.contains("not authorized"), "unexpected rejection: {err}");

    // --- POSITIVE: a fresh, correctly bound ticket brokers the session. ---
    let good = sign_ticket(&issuer, fresh_claims(&agent_device));
    let replayed = good.clone();
    let controller = WebRtcTransport::connect(&sig.url, Role::controller(agent_device, good))
        .await
        .expect("a valid ticket must be brokered by the enforcing server");
    tokio::time::timeout(Duration::from_secs(15), agent)
        .await
        .expect("agent task timed out")
        .expect("agent task panicked")
        .expect("agent side of the ticketed session");
    drop(controller);
    eprintln!("TICKETED BROKERED PATH: enforcing signaling accepted a Rust controller's RMTTICKETv1");

    // --- NEGATIVE 3: REPLAY the same ticket. Single-use is keyed on claims.session_id, which the
    // server burned on the successful broker above. ---
    let err = expect_refused(
        WebRtcTransport::connect(&sig.url, Role::controller(agent_device, replayed)).await,
        "a replayed ticket must be refused",
    );
    assert!(err.contains("not authorized"), "unexpected rejection: {err}");
    eprintln!("TICKET REPLAY REFUSED: single-use enforced across connects");
}
