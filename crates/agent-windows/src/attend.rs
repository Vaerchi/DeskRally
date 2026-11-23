//! Attended (on-demand) guest client (docs/12-attended-sessions-contract.md).
//!
//! The guest is the SAME `agent_host` binary run in a new `attend` mode. Unlike enrollment
//! (enroll.rs), it never persists anything: it generates an EPHEMERAL Ed25519 key in memory,
//! redeems a one-time code for a server-minted ephemeral `device_id` (its pubkey pinned only for
//! the session's lifetime), shows a consent prompt, and then streams over the EXACT SAME
//! signaling/ticket/WebRTC path as unattended (host::serve_session). When the session ends it
//! simply exits — there is no key or config on disk to clean up.
//!
//! This module holds the pure + blocking-HTTP half (redeem / consent / status / promote parsing);
//! the streaming runtime wiring lives in host.rs `attend_command`, alongside `stream_command`,
//! exactly as `enroll_command` uses this crate's `enroll` module.
//!
//! Blocking I/O: like enroll.rs these use a blocking reqwest client and must NOT be called from
//! inside a tokio runtime (the caller redeems + consents BEFORE building the streaming runtime).

use std::time::Duration;

use crate::enroll::validate_control_plane_url;

/// Join a control-plane base URL with a guest path, tolerating a trailing slash (mirrors
/// enroll::redeem_url but for the attended paths).
fn attend_url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim().trim_end_matches('/'))
}

/// Does a `Content-Type` header value name JSON (`application/json`, `application/problem+json`)?
fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| {
        let essence = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        essence == "application/json" || essence.ends_with("+json")
    })
}

/// Did this answer come from something that is NOT the control plane's attended API?
///
/// A base URL missing its path prefix (e.g. `https://host` where Caddy routes the control plane at
/// `https://host/cp`) lands on a static handler or a SPA fallback: `405` for a POST, `404`, or a
/// `2xx`/`4xx` HTML page. To the guest that is "this build points at the wrong server path", not
/// "the service failed", so it must not share [`AttendRedeemError::Server`]'s wording.
///
/// Pure over (status, `Content-Type`, whether the endpoint's answers are JSON):
/// * `5xx` is never wrong-server: a real outage (or a proxy 502) is the service's problem.
/// * `405` is always wrong-server: no attended endpoint answers 405.
/// * `404` is wrong-server unless the body is JSON: the control plane answers an unknown attended
///   session with a JSON 404, a static handler or mux does not.
/// * `429` is never wrong-server: a CDN/WAF/edge rate limit is transient and its page is often HTML,
///   so telling the guest "wrong address, retrying will not help" would be false.
/// * Any other status is wrong-server only when JSON was required and the body is not JSON (the
///   control plane writes every attended answer, errors included, as `application/json`).
/// * The `404 => !json` arm only matters with `json_required == false`; every current call site
///   passes `true` (where the catch-all arm already covers it), so it is exercised by the pure test
///   only and is kept as the documented rule for a future non-JSON endpoint.
pub(crate) fn is_wrong_server_response(status: u16, content_type: Option<&str>, json_required: bool) -> bool {
    if status >= 500 || status == 429 {
        return false;
    }
    let json = is_json_content_type(content_type);
    match status {
        405 => true,
        404 => !json,
        _ => json_required && !json,
    }
}

/// Does a `Content-Type` header value name an HTML page?
fn is_html_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/html"))
}

fn content_type_of(resp: &reqwest::blocking::Response) -> Option<String> {
    resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// Operator-facing wording for the string-returning callbacks (the guest dialog for redeem is
/// [`rmt_agent_core::support_ui::Failure::WrongServer`]).
const WRONG_SERVER_TEXT: &str = "the configured address is not the control plane (wrong base URL path?)";

/// Whole-request budget for the attended callbacks. Generous but bounded, like enroll.rs.
const ATTEND_TIMEOUT: Duration = Duration::from_secs(20);

/// Control-plane paths (docs/12 §5). Guest-facing, unauthenticated-by-code or attend-token-bearer.
pub const ATTEND_REDEEM_PATH: &str = "/attended-sessions/redeem";
pub const ATTEND_CONSENT_PATH: &str = "/attended-sessions/consent";
pub const ATTEND_STATUS_PATH: &str = "/attended-sessions/status";
pub const ATTEND_PROMOTE_COMPLETE_PATH: &str = "/attended-sessions/promote-complete";
/// The installer bundle path: `GET` with the guest's attend bearer returns the managed Setup ZIP
/// when a promotion has been authorized for the session.
pub const ATTEND_INSTALLER_PATH: &str = "/attended-sessions/installer";

/// What redemption hands the guest: the server-minted ephemeral identity, where to signal, and the
/// attend token that authenticates its later callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttendRedeem {
    pub device_id: String,
    pub tenant_id: String,
    pub signaling_url: String,
    pub attend_token: String,
    /// The control plane's grant-issuer Ed25519 public key (bare hex), which the guest pins for the
    /// session so backstage requires a control-plane-SIGNED grant scoped to that technician.
    ///
    /// OPTIONAL on the wire, unlike every other field: a control plane with no grant issuer
    /// configured omits it, and older ones never sent it. Absent ⇒ the guest denies backstage
    /// outright (`attend_backstage_auth`) rather than falling back to a self-issued full grant.
    /// That is why parsing it must not be a hard error — the fail-closed default is safe, so an
    /// unknown/legacy server loses backstage instead of gaining unlimited backstage.
    pub grant_issuer_pubkey: Option<String>,
    /// Loop 82: open this session VIEW-ONLY and keep it there until a control-plane-signed session
    /// policy verifies — the attended equivalent of the installed agent's
    /// [`require_session_policy`](crate::config::HelperConfig::require_session_policy).
    ///
    /// The control plane sets it when the invite's group enforces view-only. It exists because an
    /// attended guest has no config.json and no argv flag, so that setting was UNREACHABLE on this
    /// path: the signed policy arrives only because the VIEWER forwards it, and the viewer is the
    /// party the policy binds, so a patched console could simply withhold the frame and the mandate
    /// became advisory.
    ///
    /// Defaults FALSE when absent, unlike `grant_issuer_pubkey`'s fail-closed default, and the
    /// asymmetry is deliberate: a control plane that never heard of this field would otherwise
    /// strand every attended session in view-only with no way out. The control plane only ever sends
    /// it TOGETHER with `grant_issuer_pubkey` — a guest that pinned no issuer cannot verify any
    /// policy, so requiring one would be a floor with no key.
    pub require_session_policy: bool,
    /// The technician-supplied reason for the session, as the control plane recorded it.
    ///
    /// On the typed-code support path the customer never sees a `rmt://` link, so the reason cannot
    /// ride the link the way it does for the URI handler — it has to come back from the control plane
    /// at redeem. Rendered in the consent dialog, attributed and quoted
    /// (`Someone identifying themselves as "…"`) by [`consent_prompt_text`], never as bare
    /// authoritative text, because it is attacker-chooseable: a scammer with a real tenant can write
    /// anything here.
    ///
    /// OPTIONAL, and parsed like [`grant_issuer_pubkey`](AttendRedeem::grant_issuer_pubkey): absent
    /// or blank means `None`, at which point the prompt falls back to "A support technician". A junk
    /// value must never fail the redeem — losing the reason costs a fact the guest could check;
    /// failing the redeem costs them support entirely.
    pub reason: Option<String>,
}

/// The guest's view of the session on a status poll: the state, plus an enrollment token to redeem
/// when the technician has requested promotion to a permanent unattended install.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttendStatus {
    pub state: String,
    /// The enrollment token to redeem + install as a permanent agent (docs/12 §8), when present.
    pub promote_enrollment_token: Option<String>,
    /// Whether the control plane has a managed installer bundle the guest can download via
    /// GET /attended-sessions/installer. False when absent from the response (older servers, or
    /// no managed installer published). Only meaningful when promote_enrollment_token is set.
    pub installer_available: bool,
    /// Per-attempt nonce minted by SetPromoteToken. The guest echoes it in POST /promote-complete
    /// so the server can reject a delayed old attempt's result from claiming a new attempt's slot.
    /// Absent on older servers (pre-pass6) — callers must treat None as "no binding" and still
    /// send whatever nonce was received (None → empty string in the request body).
    pub promote_attempt_nonce: Option<String>,
}

/// Parse a `201` redeem body into an [`AttendRedeem`]. Every field is required + non-empty.
pub fn parse_attend_redeem(body: &str) -> Result<AttendRedeem, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("attend redeem response is not JSON: {e}"))?;
    let field = |name: &str| -> Result<String, String> {
        v.get(name)
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("attend redeem response {name} is missing or empty"))
    };
    Ok(AttendRedeem {
        device_id: field("device_id")?,
        tenant_id: field("tenant_id")?,
        signaling_url: field("signaling_url")?,
        attend_token: field("attend_token")?,
        // Optional by design — see the field docs. Empty string is normalized to None so both
        // "absent" and "configured as blank" land on the same fail-closed branch.
        grant_issuer_pubkey: v
            .get("grant_issuer_pubkey")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        // Absent / non-boolean ⇒ false. See the field docs for why this one defaults OPEN while the
        // issuer key defaults closed: a legacy control plane omits it, and the safe reading of "this
        // server never mentioned a floor" is the behaviour that existed before floors did.
        require_session_policy: v
            .get("require_session_policy")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        // Optional, trimmed, blank-to-None — the grant_issuer_pubkey precedent. A non-string junk
        // value yields None rather than aborting the redeem (see the field docs).
        reason: v
            .get("reason")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    })
}

/// Parse a status body: `state` (required) + optional `promote` object.
pub fn parse_attend_status(body: &str) -> Result<AttendStatus, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("attend status response is not JSON: {e}"))?;
    let state = v
        .get("state")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| "attend status response has no state".to_string())?;
    let promote_obj = v.get("promote");
    let promote = promote_obj
        .and_then(|p| p.get("enrollment_token"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let installer_available = promote_obj
        .and_then(|p| p.get("installer_available"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let promote_attempt_nonce = promote_obj
        .and_then(|p| p.get("attempt_nonce"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(AttendStatus { state, promote_enrollment_token: promote, installer_available, promote_attempt_nonce })
}

/// Build a blocking HTTP client with the attend timeout (rustls, cert validation ON — never disabled).
fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(rmt_transport_webrtc::tls_trust::client_config()?)
        .timeout(ATTEND_TIMEOUT)
        .redirect(redirect_policy(rmt_agent_core::deployment::is_pass_mode()))
        .build()
        .map_err(|e| format!("attend: could not build HTTP client: {e}"))
}

/// A generic (pass-mode) Support follows a redirect only within the same origin (scheme, host,
/// port), at most 5 times: the pass pins the origin, and a cross-origin redirect would carry the
/// guest's requests to a server the pass does not name (docs/48). Baked and dev builds keep
/// reqwest's default policy, unchanged.
fn redirect_policy(pass_mode: bool) -> reqwest::redirect::Policy {
    if !pass_mode {
        return reqwest::redirect::Policy::default();
    }
    reqwest::redirect::Policy::custom(|attempt| {
        let allowed = attempt.previous().len() <= 5
            && attempt.previous().first().is_some_and(|first| same_origin(first, attempt.url()));
        if allowed {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// Same scheme, host and effective port.
fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

/// Why a redeem failed, in the few categories a customer can be told apart honestly.
///
/// The typed-code support client turns these into the [`rmt_agent_core::support_ui`] dialogs via
/// [`AttendRedeemError::to_failure`]; the legacy CLI/URI path flattens them to a string through
/// [`redeem`]. Deliberately coarse: the control plane collapses wrong / expired / already-used into
/// one `403` so the code space can't be probed for liveness, and this enum must not un-collapse it —
/// there is one [`AttendRedeemError::Invalid`], never three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttendRedeemError {
    /// `403`: the control plane rejected the code. Wrong, expired, and spent are ONE answer.
    Invalid,
    /// `429`: rate limited. `retry_after` is already clamped to a sane band (see
    /// [`clamp_retry_after`]).
    Throttled {
        /// Seconds to wait before retrying, in `1..=120`, or the fixed fallback.
        retry_after: u32,
    },
    /// The control plane could not be reached: DNS, TLS, connection refused, timeout.
    Network,
    /// The address answered like something other than the control plane (404/405 or non-JSON):
    /// the build's server path is wrong. See [`is_wrong_server_response`].
    WrongServer,
    /// `5xx` (and any other unexpected status): a problem on the service side, not the customer's.
    Server,
    /// A `2xx` whose body could not be parsed into an [`AttendRedeem`].
    Malformed,
}

impl std::fmt::Display for AttendRedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttendRedeemError::Invalid => write!(f, "the control plane did not accept that session code"),
            AttendRedeemError::Throttled { retry_after } => {
                write!(f, "rate limited by the control plane; retry in about {retry_after}s")
            }
            AttendRedeemError::Network => write!(f, "could not reach the control plane"),
            AttendRedeemError::WrongServer => {
                write!(f, "the configured address is not the control plane's attended API")
            }
            AttendRedeemError::Server => write!(f, "the control plane reported a server error"),
            AttendRedeemError::Malformed => write!(f, "the control plane's response could not be understood"),
        }
    }
}

impl AttendRedeemError {
    /// Bridge to the customer-facing [`rmt_agent_core::support_ui::Failure`] table.
    ///
    /// [`AttendRedeemError::Malformed`] maps to [`Server`](rmt_agent_core::support_ui::Failure::Server):
    /// a body the client cannot parse is, to the customer, a problem on the service side they can
    /// only retry or report — not something they can fix by retyping.
    #[must_use]
    pub fn to_failure(&self) -> rmt_agent_core::support_ui::Failure {
        use rmt_agent_core::support_ui::Failure;
        match self {
            AttendRedeemError::Invalid => Failure::InvalidCode,
            AttendRedeemError::Throttled { retry_after } => {
                Failure::Throttled { retry_after_secs: *retry_after }
            }
            AttendRedeemError::Network => Failure::Network,
            AttendRedeemError::WrongServer => Failure::WrongServer,
            AttendRedeemError::Server | AttendRedeemError::Malformed => Failure::Server,
        }
    }
}

/// The retry delay to honour, from a raw `Retry-After` header value.
///
/// Parsed as **delta-seconds only** and clamped to `1..=120`. Anything outside that — `0`, an
/// enormous `86400`, an HTTP-date, or garbage — falls back to [`RETRY_AFTER_FALLBACK`]. An
/// attacker who can influence the header must not be able to talk the client into either a tight
/// retry storm (`0`) or a day-long freeze (`86400`); a bounded, sane wait is the only safe reading.
fn clamp_retry_after(raw: &str) -> u32 {
    match raw.trim().parse::<u32>() {
        Ok(n) if (RETRY_AFTER_MIN..=RETRY_AFTER_MAX).contains(&n) => n,
        _ => RETRY_AFTER_FALLBACK,
    }
}

/// Lower bound for an honoured `Retry-After`, in seconds. `0` is treated as absent, not "retry now".
const RETRY_AFTER_MIN: u32 = 1;
/// Upper bound for an honoured `Retry-After`, in seconds. Beyond this the client uses the fallback
/// rather than freezing a customer for minutes at the control plane's (or an attacker's) word.
const RETRY_AFTER_MAX: u32 = 120;
/// The wait used whenever `Retry-After` is absent, unparseable, or out of band.
const RETRY_AFTER_FALLBACK: u32 = 30;

/// Map a non-success redeem status (plus the 429 `Retry-After`) to an [`AttendRedeemError`].
///
/// Pure, so the status→variant contract is unit-tested without a server. Only `403` and `429` are
/// expected on this endpoint; everything else — other `4xx` included — is anomalous and reads to the
/// customer as a service-side problem ([`AttendRedeemError::Server`]) they can retry or report,
/// which is more honest than blaming their code for a `404`.
fn redeem_error_for(status: u16, retry_after_header: Option<&str>) -> AttendRedeemError {
    match status {
        403 => AttendRedeemError::Invalid,
        429 => AttendRedeemError::Throttled {
            retry_after: clamp_retry_after(retry_after_header.unwrap_or("")),
        },
        _ => AttendRedeemError::Server,
    }
}

/// Redeem the attend `code` at `base`, presenting our ephemeral `pubkey_hex`, with TYPED errors.
///
/// The support client needs to tell a wrong code (retype) from a throttle (wait N seconds) from an
/// unreachable service (check the network) — a flat string cannot drive three different dialogs.
/// [`redeem`] is the thin string-returning wrapper the older CLI/URI callers keep using.
///
/// Enforces the same URL policy as enrollment (https except loopback). A policy failure here is a
/// build/config error, not a live one, and is treated as [`AttendRedeemError::Network`] — the
/// support path validates the baked origin BEFORE ever reaching this, so in practice this arm is
/// unreachable and exists only so a misconfigured caller fails closed rather than dialling nowhere.
pub fn redeem_detailed(
    base: &str,
    code: &str,
    pubkey_hex: &str,
    name: &str,
) -> Result<AttendRedeem, AttendRedeemError> {
    match validate_control_plane_url(base) {
        Ok(true) => {
            tracing::warn!(url = %base, "attend: plaintext http:// to a loopback control plane — dev only");
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!(url = %base, error = %e, "attend: control-plane URL failed policy");
            return Err(AttendRedeemError::Network);
        }
    }
    let url = attend_url(base, ATTEND_REDEEM_PATH);
    let body = serde_json::json!({ "code": code, "pubkey": pubkey_hex, "name": name });
    let client = client().map_err(|e| {
        tracing::error!(error = %e, "attend: could not build HTTP client");
        AttendRedeemError::Network
    })?;
    let resp = match client.post(&url).json(&body).send() {
        Ok(r) => r,
        Err(e) => {
            // DNS, TLS, connection refused, timeout — all surface here and all read as "unreachable".
            tracing::warn!(error = %e, "attend: redeem request failed to reach the control plane");
            return Err(AttendRedeemError::Network);
        }
    };
    let status = resp.status();
    if is_wrong_server_response(status.as_u16(), content_type_of(&resp).as_deref(), true) {
        tracing::error!(
            path = ATTEND_REDEEM_PATH,
            status = %status,
            "attend: the configured address does not serve the control plane API (wrong base URL path?)"
        );
        return Err(AttendRedeemError::WrongServer);
    }
    if status.is_success() {
        let text = resp.text().unwrap_or_default();
        return parse_attend_redeem(&text).map_err(|e| {
            tracing::warn!(error = %e, "attend: redeem body could not be parsed");
            AttendRedeemError::Malformed
        });
    }
    // Read Retry-After BEFORE the body is consumed. Never log the header value at info+ — it is
    // attacker-influenceable and this line runs on the customer's machine.
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let err = redeem_error_for(status.as_u16(), retry_after.as_deref());
    tracing::warn!(status = %status, "attend: redeem rejected by the control plane");
    Err(err)
}

/// Redeem the attend `code`, flattening the typed error to a string. Kept so the existing CLI/URI
/// callers and their tests are untouched; new code (the support client) uses [`redeem_detailed`].
pub fn redeem(base: &str, code: &str, pubkey_hex: &str, name: &str) -> Result<AttendRedeem, String> {
    redeem_detailed(base, code, pubkey_hex, name).map_err(|e| e.to_string())
}

/// Report the user's consent decision, authenticated by the attend token.
pub fn post_consent(base: &str, attend_token: &str, accept: bool, consent_user: &str) -> Result<(), String> {
    let url = attend_url(base, ATTEND_CONSENT_PATH);
    let decision = if accept { "accept" } else { "decline" };
    let resp = client()?
        .post(&url)
        .bearer_auth(attend_token)
        .json(&serde_json::json!({ "decision": decision, "consent_user": consent_user }))
        .send()
        .map_err(|e| format!("attend: POST {ATTEND_CONSENT_PATH} failed: {e}"))?;
    if is_wrong_server_response(resp.status().as_u16(), content_type_of(&resp).as_deref(), true) {
        tracing::error!(path = ATTEND_CONSENT_PATH, status = %resp.status(), "attend: wrong server path");
        return Err(format!("attend: consent: {WRONG_SERVER_TEXT} (HTTP {})", resp.status()));
    }
    if !resp.status().is_success() {
        return Err(format!("attend: consent returned {}", resp.status()));
    }
    Ok(())
}

/// Poll session status, authenticated by the attend token.
pub fn get_status(base: &str, attend_token: &str) -> Result<AttendStatus, String> {
    let url = attend_url(base, ATTEND_STATUS_PATH);
    let resp = client()?
        .get(&url)
        .bearer_auth(attend_token)
        .send()
        .map_err(|e| format!("attend: GET {ATTEND_STATUS_PATH} failed: {e}"))?;
    let status = resp.status();
    let wrong = is_wrong_server_response(status.as_u16(), content_type_of(&resp).as_deref(), true);
    let text = resp.text().unwrap_or_default();
    if wrong {
        tracing::error!(path = ATTEND_STATUS_PATH, status = %status, "attend: wrong server path");
        return Err(format!("attend: status: {WRONG_SERVER_TEXT} (HTTP {status})"));
    }
    if !status.is_success() {
        return Err(format!("attend: status returned {status}: {}", text.trim()));
    }
    parse_attend_status(&text)
}

/// Notify the control plane of the permanent-install outcome. Best-effort — the session may
/// have ended by the time the install completes; failures are logged but do not affect the live
/// session. The technician panel polls GET /attended-sessions/{id} and surfaces the result.
///
/// `attempt_nonce` must be the nonce received in the status response's `promote.attempt_nonce`.
/// Passing `None` (or an empty string) disables binding; the server accepts it only if the stored
/// nonce is also empty (legacy compatibility when the server omits the field).
pub fn post_promote_complete(
    base: &str,
    attend_token: &str,
    success: bool,
    error: Option<&str>,
    attempt_nonce: Option<&str>,
) -> Result<(), String> {
    let url = attend_url(base, ATTEND_PROMOTE_COMPLETE_PATH);
    let body = serde_json::json!({
        "success": success,
        "error": error.unwrap_or(""),
        "attempt_nonce": attempt_nonce.unwrap_or(""),
    });
    let resp = client()?
        .post(&url)
        .bearer_auth(attend_token)
        .json(&body)
        .send()
        .map_err(|e| format!("attend: POST {ATTEND_PROMOTE_COMPLETE_PATH} failed: {e}"))?;
    let status = resp.status();
    if is_wrong_server_response(status.as_u16(), content_type_of(&resp).as_deref(), true) {
        tracing::error!(path = ATTEND_PROMOTE_COMPLETE_PATH, status = %status, "attend: wrong server path");
        return Err(format!("attend: promote-complete: {WRONG_SERVER_TEXT} (HTTP {status})"));
    }
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("attend: promote-complete returned {status}"))
    }
}

/// Hard cap on installer bundle download size (256 MiB). A bundle larger than this is
/// rejected before extraction — it cannot be a legitimate DeskRallySetup.exe + MSI + token.
const MAX_INSTALLER_BYTES: u64 = 256 * 1024 * 1024;

/// Download the managed installer bundle (DeskRallySetup.exe + MSI + enrollment.token in a ZIP),
/// authenticated by the guest's attend token. Called when the technician has authorized promotion
/// and `installer_available` was true in the status response.
///
/// `attempt_nonce` is the nonce the guest received in the status response. It is sent as a query
/// parameter so the server can reject stale downloads atomically when the technician re-issued the
/// promotion while the guest's download was in progress — preventing a token-A download from
/// installing token-B and then posting nonce-A (which the server would reject as stale).
///
/// Returns the raw ZIP bytes. The caller is responsible for extracting them to a temp directory,
/// launching `DeskRallySetup.exe`, and cleaning up.
pub fn download_installer_bundle(base: &str, attend_token: &str, attempt_nonce: Option<&str>) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    // The nonce is a 32-char hex string (alphanumeric only) — no URL encoding needed.
    let url = match attempt_nonce {
        Some(n) => format!("{}{}?attempt_nonce={n}", base.trim_end_matches('/'), ATTEND_INSTALLER_PATH),
        None => attend_url(base, ATTEND_INSTALLER_PATH),
    };
    let resp = client()?
        .get(&url)
        .bearer_auth(attend_token)
        .send()
        .map_err(|e| format!("attend: GET {ATTEND_INSTALLER_PATH} failed: {e}"))?;
    let status = resp.status();
    // The bundle is a ZIP, so a 2xx is only wrong-server when it is an HTML page (a SPA fallback
    // answering 200); every other status goes through the shared classifier.
    let ct = content_type_of(&resp);
    let wrong = if status.is_success() {
        is_html_content_type(ct.as_deref())
    } else {
        is_wrong_server_response(status.as_u16(), ct.as_deref(), true)
    };
    if wrong {
        tracing::error!(path = ATTEND_INSTALLER_PATH, status = %status, "attend: wrong server path");
        return Err(format!("attend: installer: {WRONG_SERVER_TEXT} (HTTP {status})"));
    }
    if status.as_u16() == 409 {
        return Err(
            "the installation was not authorized for this session — the technician may need to re-issue the request"
                .to_string(),
        );
    }
    if status.as_u16() == 503 {
        return Err(
            "the managed installer is not published on this server — contact your technician for a manual installer link"
                .to_string(),
        );
    }
    if !status.is_success() {
        return Err(format!("attend: installer bundle returned {status}"));
    }
    // Read up to MAX_INSTALLER_BYTES + 1: if we hit the +1 byte the bundle is over the cap.
    let mut body = Vec::new();
    resp.take(MAX_INSTALLER_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("attend: could not read installer bundle: {e}"))?;
    if body.len() as u64 > MAX_INSTALLER_BYTES {
        return Err(format!(
            "attend: installer bundle exceeds size limit ({} MiB)",
            MAX_INSTALLER_BYTES / 1024 / 1024
        ));
    }
    Ok(body)
}

/// The OS username to report as the consenter. Best-effort (a blank value is accepted).
pub fn consent_user() -> String {
    std::env::var("USERNAME").unwrap_or_default()
}

/// Show the consent prompt and return the user's decision. `auto` (from `--auto-consent`, the
/// TEST-ONLY opt-out, mirroring signaling's `-insecure-*`) accepts without prompting and logs loudly.
///
/// `control_plane_host` is the host this session will actually connect to (see
/// [`consent_prompt_text`] for why it is not optional).
///
/// On a real desktop this is a system-modal Yes/No message box. If it cannot be shown (e.g. Session
/// 0 / no interactive desktop) it fails CLOSED — no prompt shown means no consent, so the session is
/// declined rather than silently proceeding.
pub fn obtain_consent(reason: &str, control_plane_host: &str, auto: bool) -> bool {
    matches!(
        obtain_consent_detailed(reason, control_plane_host, auto),
        ConsentOutcome::Granted
    )
}

/// The three distinguishable outcomes of asking for consent.
///
/// The old `obtain_consent -> bool` conflated the last two, so a customer on a desktop where the
/// prompt could not be shown was told they had "declined" a question they never saw. They are
/// different facts with different fixes — decline is final, could-not-display means "run this from
/// your own signed-in desktop" — and the support client shows different messages for each
/// ([`rmt_agent_core::support_ui::Failure::ConsentDeclined`] vs `ConsentUndisplayable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// The customer answered Yes.
    Granted,
    /// The customer answered No (or dismissed the dialog).
    Declined,
    /// The dialog could not be shown at all (no interactive desktop / session 0).
    CouldNotDisplay,
}

impl ConsentOutcome {
    /// The customer-facing failure for a non-grant, or `None` when consent was granted.
    #[must_use]
    pub fn to_failure(&self) -> Option<rmt_agent_core::support_ui::Failure> {
        use rmt_agent_core::support_ui::Failure;
        match self {
            ConsentOutcome::Granted => None,
            ConsentOutcome::Declined => Some(Failure::ConsentDeclined),
            ConsentOutcome::CouldNotDisplay => Some(Failure::ConsentUndisplayable),
        }
    }
}

/// Ask for consent, distinguishing decline from could-not-display. `auto` (from `--auto-consent`,
/// the TEST-ONLY opt-out) grants without prompting and logs loudly.
pub fn obtain_consent_detailed(reason: &str, control_plane_host: &str, auto: bool) -> ConsentOutcome {
    obtain_consent_with_issuer(reason, control_plane_host, None, auto)
}

/// [`obtain_consent_detailed`] for a generic (pass-mode) Support: the prompt also names whom the
/// deployment pass was issued to. `None` gives exactly today's prompt.
pub fn obtain_consent_with_issuer(reason: &str, control_plane_host: &str, issued_to: Option<&str>, auto: bool) -> ConsentOutcome {
    if auto {
        tracing::warn!(
            "attend: --auto-consent — the consent prompt is BYPASSED and access is auto-granted. \
             TEST/UNATTENDED-LAB USE ONLY; never ship a build that sets this by default."
        );
        return ConsentOutcome::Granted;
    }
    show_consent_dialog_detailed(&consent_prompt_text_issued(reason, control_plane_host, issued_to))
}

/// Build the body of the consent prompt: who is asking, **which control plane this machine will be
/// handed to**, and the question.
///
/// The host line is the load-bearing part, and it is why this is a separate pure function rather
/// than a `format!` buried in an untestable Win32 call.
///
/// A guest reaches this prompt from a code someone gave them — read over the phone, or (since the
/// `rmt://` handler exists) a *link on a web page the attacker controls*. `enroll::validate_control_plane_url`
/// proves the URL is `https` (or loopback `http`); it cannot prove WHOSE it is. Without the host on
/// screen, "Acme IT is requesting to view and control this computer" is equally true whether the
/// session lands at `cp.acme-it.example` or at `evil.test` — the guest is consenting to a support
/// session with *whoever sent them the code*. With it, a guest who was told "we're Acme IT" has one
/// concrete fact to disbelieve.
///
/// `reason` is re-sanitized here rather than trusted: this is the point of RENDERING, and the
/// copy-paste `--reason` path never passes through the URI parser.
/// [`crate::uri::sanitize_reason`] is idempotent, so the link path is unaffected by the second pass.
pub fn consent_prompt_text(reason: &str, control_plane_host: &str) -> String {
    consent_prompt_text_issued(reason, control_plane_host, None)
}

/// [`consent_prompt_text`] plus, for a generic (pass-mode) Support, an `Issued to:` line directly
/// under the host line (docs/48 "Generic Support"). The name comes only from the verified pass and
/// is charset-restricted ([A-Za-z0-9 .,&'()-], at most 64) at issuance and again at verification,
/// so it cannot carry line breaks or look-alike text. It is the accountable customer DeskRally
/// issued the pass to, and is stated as that, not as a vouched-for identity.
pub fn consent_prompt_text_issued(reason: &str, control_plane_host: &str, issued_to: Option<&str>) -> String {
    let clean = crate::uri::sanitize_reason(reason);
    // The reason is ATTRIBUTED, never stated as fact. A scammer with a real tenant can put anything
    // here ("Microsoft Windows Security"); quoting it and prefixing "Someone identifying themselves
    // as" makes plain that this is a claim the sender chose, not something the machine verified. An
    // empty reason falls back to the neutral phrasing rather than an empty pair of quotes.
    let requester = if clean.is_empty() {
        "A support technician is requesting to view and control this computer.".to_string()
    } else {
        format!(
            "Someone identifying themselves as \"{clean}\" is requesting to view and control this \
             computer."
        )
    };
    // An unknown host is stated as unknown, never omitted: a missing line reads as "no third party
    // involved", which is the opposite of the truth.
    let host = control_plane_host.trim();
    let host = if host.is_empty() { "(unknown)" } else { host };
    // Pass mode only: whom DeskRally issued this server's pass to, under the host line.
    let issuer = match issued_to.map(str::trim).filter(|s| !s.is_empty()) {
        Some(name) => format!("\nIssued to: {name}"),
        None => String::new(),
    };
    // The HOST line leads. It is the one fact a guest who was told "we're Acme IT" can disbelieve,
    // and burying it under an attacker-chosen reason line is exactly the failure this ordering
    // prevents — the sanitizer caps the reason, but the host must be first regardless.
    format!(
        "This will connect your computer to: {host}{issuer}\n\n\
         {requester}\n\n\
         Only allow this if you started this support session and you recognise that address.\n\n\
         Allow the remote support session?"
    )
}

/// The `MessageBoxW` style for the consent prompt, as a pure value.
///
/// Separated for the same reason [`consent_prompt_text`] is: the default button is a security
/// property, and a flag composed inline inside an `unsafe` Win32 call is a security property no
/// test can reach.
///
/// **`MB_DEFBUTTON2` makes "No" the default, and that is the load-bearing flag.** Without it button
/// one — *Yes* — is default, so a single Enter or Space grants a stranger view-and-control of the
/// machine. That was survivable while the only way here was a technician-guided command line, where
/// nothing upstream held keyboard focus. It stops being survivable the moment a guest reaches this
/// dialog by typing a code into a window and pressing Enter to submit it: the keystroke that
/// launches the connection and the keystroke that consents to it become the same one, separated
/// only by however long the redeem takes. A guest who double-taps Enter on a slow network would
/// consent to a session they never read the prompt for.
///
/// `MB_SYSTEMMODAL` keeps the prompt above the requester's own windows; `MB_ICONQUESTION` marks it
/// as a decision rather than a notification.
#[cfg(windows)]
fn consent_dialog_flags() -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE {
    use windows::Win32::UI::WindowsAndMessaging::{
        MB_DEFBUTTON2, MB_ICONQUESTION, MB_SYSTEMMODAL, MB_YESNO,
    };
    MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL | MB_DEFBUTTON2
}

#[cfg(windows)]
fn show_consent_dialog_detailed(prompt: &str) -> ConsentOutcome {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MESSAGEBOX_RESULT};
    let text = HSTRING::from(prompt);
    let title = HSTRING::from("Remote Support — Consent");
    // SAFETY: MessageBoxW with owned HSTRING buffers; a NULL owner window is fine for a standalone
    // prompt. `MessageBoxW` returns 0 when it could NOT be displayed (no interactive desktop),
    // which is a different fact from IDNO and is surfaced as such — never silently as "declined".
    let ret = unsafe { MessageBoxW(None, &text, &title, consent_dialog_flags()) };
    if ret == IDYES {
        ConsentOutcome::Granted
    } else if ret == MESSAGEBOX_RESULT(0) {
        ConsentOutcome::CouldNotDisplay
    } else {
        ConsentOutcome::Declined
    }
}

#[cfg(not(windows))]
fn show_consent_dialog_detailed(_prompt: &str) -> ConsentOutcome {
    // No interactive prompt off Windows — the box could not be shown, which fails closed.
    ConsentOutcome::CouldNotDisplay
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attend_client_accepts_the_shared_trust_config() {
        client().expect("attend HTTP client must build with shared TLS config");
    }

    #[test]
    fn a_valid_redeem_body_parses() {
        let body = r#"{"device_id":"dev-1","tenant_id":"ten-1",
            "signaling_url":"ws://127.0.0.1:8080/ws","attend_token":"tok-abc"}"#;
        let got = parse_attend_redeem(body).unwrap();
        assert_eq!(got.device_id, "dev-1");
        assert_eq!(got.tenant_id, "ten-1");
        assert_eq!(got.signaling_url, "ws://127.0.0.1:8080/ws");
        assert_eq!(got.attend_token, "tok-abc");
    }

    #[test]
    fn a_redeem_body_missing_a_field_is_refused() {
        for missing in ["device_id", "tenant_id", "signaling_url", "attend_token"] {
            let full = r#"{"device_id":"d","tenant_id":"t","signaling_url":"ws://x","attend_token":"k"}"#;
            let stripped = full.replace(&format!("\"{missing}\""), "\"ignored\"");
            assert!(parse_attend_redeem(&stripped).is_err(), "missing {missing} must error");
        }
        assert!(parse_attend_redeem("{}").is_err());
        assert!(parse_attend_redeem("not json").is_err());
    }

    // LOOP 82: the attended opt-in to the provisional view-only floor. The control plane sets this at
    // redeem when the invite's group enforces view-only, because an attended guest has no config.json
    // and no argv flag to set `require_session_policy` with.
    #[test]
    fn a_redeem_body_carries_the_session_policy_requirement() {
        let base = r#""device_id":"d","tenant_id":"t","signaling_url":"ws://x","attend_token":"k""#;
        let floored =
            parse_attend_redeem(&format!("{{{base},\"require_session_policy\":true}}")).unwrap();
        assert!(
            floored.require_session_policy,
            "the guest ignored the control plane's instruction to open FLOORED — the session starts              with full control and a viewer that withholds the policy frame keeps it"
        );

        // Explicit false and ABSENT must land on the same relaxed default, and for the same reason: a
        // control plane that never heard of the field (an older deployment) must not be read as
        // demanding a floor, or every attended session there is stranded in view-only.
        let open = parse_attend_redeem(&format!("{{{base},\"require_session_policy\":false}}")).unwrap();
        assert!(!open.require_session_policy);
        let absent = parse_attend_redeem(&format!("{{{base}}}")).unwrap();
        assert!(!absent.require_session_policy);
    }

    // A NON-BOOLEAN must degrade to the default rather than abort the redeem. Parsing is the guest's
    // only entry into the session: making a junk value fatal would turn a server-side typo into "no
    // attended support at all", and making a truthy-looking string floor the session would let a
    // stringly-typed server accidentally impose one.
    #[test]
    fn a_non_boolean_session_policy_requirement_degrades_to_the_default() {
        let base = r#""device_id":"d","tenant_id":"t","signaling_url":"ws://x","attend_token":"k""#;
        for junk in ["\"true\"", "1", "null", "[]", "{}"] {
            let got = parse_attend_redeem(&format!("{{{base},\"require_session_policy\":{junk}}}"))
                .unwrap_or_else(|e| panic!("require_session_policy={junk} must not fail the redeem: {e}"));
            assert!(
                !got.require_session_policy,
                "require_session_policy={junk} was read as a demand for a floor"
            );
        }
    }

    #[test]
    fn status_without_promote_parses() {
        let s = parse_attend_status(r#"{"state":"active","device_id":"d"}"#).unwrap();
        assert_eq!(s.state, "active");
        assert_eq!(s.promote_enrollment_token, None);
        assert!(!s.installer_available);
    }

    #[test]
    fn status_with_promote_extracts_the_enrollment_token() {
        let s = parse_attend_status(r#"{"state":"active","promote":{"enrollment_token":"ENR-123"}}"#).unwrap();
        assert_eq!(s.state, "active");
        assert_eq!(s.promote_enrollment_token.as_deref(), Some("ENR-123"));
        assert_eq!(s.promote_attempt_nonce, None); // absent → None (pre-nonce server compat)
    }

    #[test]
    fn status_with_promote_includes_attempt_nonce() {
        let s = parse_attend_status(
            r#"{"state":"active","promote":{"enrollment_token":"ENR-123","attempt_nonce":"aabbccddeeff00112233445566778899","installer_available":true}}"#,
        ).unwrap();
        assert_eq!(s.promote_enrollment_token.as_deref(), Some("ENR-123"));
        assert_eq!(s.promote_attempt_nonce.as_deref(), Some("aabbccddeeff00112233445566778899"));
        assert!(s.installer_available);
    }

    #[test]
    fn installer_offer_requires_explicit_boolean_capability() {
        for value in ["false", "null", "\"true\"", "1"] {
            let body = format!(r#"{{"state":"active","promote":{{"installer_available":{value}}}}}"#);
            assert!(!parse_attend_status(&body).unwrap().installer_available);
        }
        assert!(parse_attend_status(r#"{"state":"active","promote":{"installer_available":true}}"#).unwrap().installer_available);
    }

    #[test]
    fn status_without_state_is_refused() {
        assert!(parse_attend_status(r#"{"device_id":"d"}"#).is_err());
    }

    #[test]
    fn auto_consent_grants_without_prompting() {
        assert!(obtain_consent("Acme IT", "cp.example.com", true));
    }

    #[test]
    fn the_consent_prompt_names_the_control_plane_host() {
        // The whole point: the guest is told WHERE their machine is about to be connected. Without
        // this line the prompt is identical whether the code came from their IT department or from
        // a `rmt://` link on an attacker's page.
        let text = consent_prompt_text("Acme IT", "cp.acme.example");
        assert!(text.contains("cp.acme.example"), "the host must be shown: {text}");
        assert!(text.contains("Acme IT"), "the requester must be shown: {text}");
        assert!(text.contains("Allow the remote support session?"), "{text}");

        // A different host must produce different text — i.e. the host is really interpolated and
        // not a constant that happens to contain the expected substring.
        assert_ne!(text, consent_prompt_text("Acme IT", "evil.test"));
        assert!(consent_prompt_text("Acme IT", "evil.test").contains("evil.test"));
    }

    #[test]
    fn an_unknown_host_is_stated_not_omitted() {
        // Silence would read as "nothing external is involved". Say so instead.
        for blank in ["", "   "] {
            let text = consent_prompt_text("", blank);
            assert!(text.contains("(unknown)"), "blank host must be explicit: {text}");
            assert!(text.contains("A support technician"), "{text}");
        }
    }

    #[test]
    fn a_hostile_reason_cannot_push_the_question_off_screen() {
        // The copy-paste `--reason` path never goes through the URI parser, so the sanitizer has to
        // bite HERE too: newlines that scroll the box, and a reason long enough to bury the
        // question and the host under it.
        let text = consent_prompt_text("Acme\n\n\n\n\nIT", "cp.example.com");
        assert!(text.contains("AcmeIT"), "{text}");
        let flood = "A".repeat(5000);
        let text = consent_prompt_text(&flood, "cp.example.com");
        assert!(text.contains("cp.example.com"));
        assert!(text.contains("Allow the remote support session?"));
        assert!(
            text.chars().count() < 500,
            "a 5000-character reason must not survive into the dialog ({} chars)",
            text.chars().count()
        );
    }

    /// The consent dialog must default to **No**.
    ///
    /// A flag buried in an `unsafe` Win32 call is exactly the kind of security property that is
    /// asserted in a comment and never checked, so this reads the composed value back. It fails if
    /// anyone drops `MB_DEFBUTTON2` while "tidying" the flags — at which point a single Enter,
    /// arriving from whatever had focus a moment earlier, grants a stranger control of the machine.
    ///
    /// Both halves matter. The first assert pins the default button; the second pins that the
    /// dialog is still a Yes/No question, so a future edit cannot satisfy this test by turning it
    /// into a single-button box where "button 2" does not exist.
    #[cfg(windows)]
    #[test]
    fn the_consent_dialog_defaults_to_no() {
        use windows::Win32::UI::WindowsAndMessaging::{MB_DEFBUTTON2, MB_YESNO};
        let flags = super::consent_dialog_flags();
        assert_eq!(
            flags & MB_DEFBUTTON2,
            MB_DEFBUTTON2,
            "MB_DEFBUTTON2 is missing: the consent prompt defaults to YES, so one stray Enter \
             grants view-and-control of this machine to whoever sent the code"
        );
        assert_eq!(
            flags & MB_YESNO,
            MB_YESNO,
            "the consent prompt must remain a Yes/No question for MB_DEFBUTTON2 to mean 'No'"
        );
    }

    // ---- step 4: typed redeem errors, Retry-After clamp, attributed consent ----

    #[test]
    fn wrong_server_classification_is_pure_and_status_aware() {
        let json = Some("application/json");
        let html = Some("text/html; charset=utf-8");
        // The production incident: static handler 405 for the POST, no JSON.
        assert!(is_wrong_server_response(405, None, true));
        assert!(is_wrong_server_response(405, json, true));
        assert!(is_wrong_server_response(404, None, true));
        assert!(is_wrong_server_response(404, html, false));
        // A JSON 404 is the control plane's own "unknown attended session".
        assert!(!is_wrong_server_response(404, json, true));
        assert!(!is_wrong_server_response(404, Some("Application/JSON; charset=utf-8"), true));
        // HTML where JSON is required, whatever the status.
        assert!(is_wrong_server_response(200, html, true));
        assert!(is_wrong_server_response(403, html, true));
        assert!(is_wrong_server_response(200, None, true));
        // Real answers pass.
        assert!(!is_wrong_server_response(200, json, true));
        assert!(!is_wrong_server_response(403, json, true));
        assert!(!is_wrong_server_response(429, Some("application/problem+json"), true));
        // 5xx stays a service problem even with an HTML proxy page.
        assert!(!is_wrong_server_response(500, html, true));
        assert!(!is_wrong_server_response(502, None, true));
        assert!(!is_wrong_server_response(503, html, true));
        // An edge/WAF 429 page (HTML) is a transient refusal, not a wrong address.
        assert!(!is_wrong_server_response(429, html, true));
        assert!(!is_wrong_server_response(429, None, true));
        // JSON not required: only 404/405 count.
        assert!(!is_wrong_server_response(200, html, false));
        assert!(!is_wrong_server_response(409, html, false));
    }

    #[test]
    fn wrong_server_bridges_to_its_own_failure() {
        use rmt_agent_core::support_ui::Failure;
        assert_eq!(AttendRedeemError::WrongServer.to_failure(), Failure::WrongServer);
        assert_ne!(AttendRedeemError::WrongServer.to_failure(), Failure::Server);
    }

    /// The status→variant contract, tested without a server. `403` must be `Invalid` (and must be
    /// the ONLY thing that is — the collapse of wrong/expired/spent lives here). Unexpected statuses,
    /// other 4xx included, read as a service-side problem, not the customer's code.
    #[test]
    fn redeem_error_maps_each_status_to_its_variant() {
        assert_eq!(redeem_error_for(403, None), AttendRedeemError::Invalid);
        assert_eq!(
            redeem_error_for(429, Some("5")),
            AttendRedeemError::Throttled { retry_after: 5 }
        );
        assert_eq!(redeem_error_for(500, None), AttendRedeemError::Server);
        assert_eq!(redeem_error_for(503, None), AttendRedeemError::Server);
        // Anomalous statuses do NOT become Invalid — a 404 is a misdeployed endpoint, not a bad code.
        assert_eq!(redeem_error_for(404, None), AttendRedeemError::Server);
        assert_eq!(redeem_error_for(400, None), AttendRedeemError::Server);
        assert_eq!(redeem_error_for(401, None), AttendRedeemError::Server);
    }

    /// The clamp table from the plan, plus the band edges. `0` and `86400` must NOT survive — one is
    /// a retry storm, the other a day-long freeze, and both are header values an attacker can steer.
    #[test]
    fn retry_after_is_clamped_to_a_sane_band() {
        assert_eq!(clamp_retry_after("0"), 30, "0 is not 'retry now'; fall back");
        assert_eq!(clamp_retry_after("5"), 5);
        assert_eq!(clamp_retry_after("1"), 1, "lower band edge is honoured");
        assert_eq!(clamp_retry_after("120"), 120, "upper band edge is honoured");
        assert_eq!(clamp_retry_after("121"), 30, "just over the band falls back");
        assert_eq!(clamp_retry_after("86400"), 30, "a day is refused");
        assert_eq!(clamp_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), 30, "HTTP-date falls back");
        assert_eq!(clamp_retry_after(""), 30, "absent falls back");
        assert_eq!(clamp_retry_after("   "), 30);
        assert_eq!(clamp_retry_after("-5"), 30, "a negative parses as non-u32 and falls back");
        assert_eq!(clamp_retry_after("5.5"), 30);
        // Whitespace around a valid value is tolerated (a header may carry it).
        assert_eq!(clamp_retry_after("  7  "), 7);
    }

    /// A 2xx with an unparseable body is [`AttendRedeemError::Malformed`], not a panic. This pins the
    /// exact expression `redeem_detailed` uses on its success path.
    #[test]
    fn a_garbage_success_body_is_malformed() {
        let mapped: Result<AttendRedeem, AttendRedeemError> =
            parse_attend_redeem("not json at all").map_err(|_| AttendRedeemError::Malformed);
        assert_eq!(mapped, Err(AttendRedeemError::Malformed));
        // And a valid body still parses through the same expression.
        let ok = parse_attend_redeem(
            r#"{"device_id":"d","tenant_id":"t","signaling_url":"ws://x","attend_token":"k"}"#,
        )
        .map_err(|_| AttendRedeemError::Malformed);
        assert!(ok.is_ok());
    }

    // ---- real-TCP call-site tests: every attended call must run its answer through the
    // wrong-server classifier (the pure tests above cannot see a call site that forgot to) ----

    /// A one-shot loopback server. Derefs to its base URL. [`Served::finish`] joins the server thread and fails the test if the
    /// transport failed (no connection, a short request, a failed write), so a connection failure can never pass for an expected error.
    struct Served {
        base: String,
        handle: Option<std::thread::JoinHandle<Result<(), String>>>,
    }

    impl std::ops::Deref for Served {
        type Target = str;
        fn deref(&self) -> &str {
            &self.base
        }
    }

    impl Served {
        fn finish(mut self) {
            let r = self.handle.take().expect("joined once").join().expect("the loopback server thread panicked");
            r.unwrap_or_else(|e| panic!("loopback server transport failure: {e}"));
        }
    }

    /// One-shot loopback HTTP server: accepts a single connection, reads the request head and body,
    /// answers with the given status / `Content-Type` / body, and closes. Real sockets, no mocks.
    fn serve_once(status: u16, content_type: Option<&'static str>, body: &'static str) -> Served {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let base = format!("http://127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let handle = std::thread::spawn(move || -> Result<(), String> {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => return Err(format!("no client connected: {e}")),
                }
            };
            stream.set_nonblocking(false).map_err(|e| format!("blocking stream: {e}"))?;
            stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| format!("read timeout: {e}"))?;
            let mut reader = BufReader::new(stream.try_clone().map_err(|e| format!("clone: {e}"))?);
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => return Err("the client closed before the end of the request head".to_string()),
                    Ok(_) => {}
                    Err(e) => return Err(format!("reading the request head: {e}")),
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            let mut sink = vec![0u8; len];
            reader.read_exact(&mut sink).map_err(|e| format!("reading the request body: {e}"))?;
            let ct = content_type.map(|c| format!("Content-Type: {c}\r\n")).unwrap_or_default();
            let resp = format!(
                "HTTP/1.1 {status} X\r\n{ct}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(resp.as_bytes()).map_err(|e| format!("writing the response: {e}"))?;
            stream.flush().map_err(|e| format!("flushing the response: {e}"))?;
            Ok(())
        });
        Served { base, handle: Some(handle) }
    }

    /// The two shapes of the production incident: the static handler's 405 and a SPA/HTML 200.
    const WRONG_SERVERS: [(u16, &str, &str); 2] =
        [(405, "text/plain", "Method Not Allowed"), (200, "text/html", "<html><body>site</body></html>")];

    const GOOD_REDEEM: &str = r#"{"device_id":"d","tenant_id":"t","signaling_url":"ws://x","attend_token":"k"}"#;

    fn redeem_against(status: u16, ct: Option<&'static str>, body: &'static str) -> Result<AttendRedeem, AttendRedeemError> {
        let srv = serve_once(status, ct, body);
        let got = redeem_detailed(&srv, "CODE", "deadbeef", "test-host");
        srv.finish();
        got
    }

    fn assert_wrong_server_text(call: &str, got: Result<impl std::fmt::Debug, String>) {
        let err = got.expect_err(call);
        assert!(err.contains(WRONG_SERVER_TEXT), "{call}: expected the wrong-server wording, got {err:?}");
        assert!(err.contains("is not the control plane"), "{call}: wording drifted: {err:?}");
    }

    /// The call must fail with ITS OWN status-specific error (`expected`), not with the wrong-server wording and not with any other failure
    /// (a refused or reset connection also returns an `Err`, and must not satisfy a negative case).
    fn assert_not_wrong_server_text(call: &str, got: Result<impl std::fmt::Debug, String>, expected: &str) {
        let err = got.expect_err(call);
        assert!(!err.contains("is not the control plane"), "{call}: must NOT read as wrong-server: {err:?}");
        assert!(err.contains(expected), "{call}: expected the status-specific error {expected:?}, got {err:?}");
        assert!(!err.contains("failed:"), "{call}: a transport failure is not the expected error: {err:?}");
    }

    #[test]
    fn redeem_against_a_wrong_server_is_wrong_server() {
        for (status, ct, body) in WRONG_SERVERS {
            assert_eq!(
                redeem_against(status, Some(ct), body).map(|_| ()),
                Err(AttendRedeemError::WrongServer),
                "redeem against {status} {ct}"
            );
        }
        // No Content-Type at all on a 200 is also not the control plane.
        assert_eq!(redeem_against(200, None, "x").map(|_| ()), Err(AttendRedeemError::WrongServer));
    }

    #[test]
    fn redeem_keeps_real_control_plane_answers_distinct() {
        let json = Some("application/json");
        let err_body = r#"{"error":"nope"}"#;
        assert_eq!(redeem_against(403, json, err_body).map(|_| ()), Err(AttendRedeemError::Invalid));
        assert_eq!(redeem_against(500, json, err_body).map(|_| ()), Err(AttendRedeemError::Server));
        // A JSON 404 is the control plane's own answer, not a wrong address.
        assert_eq!(redeem_against(404, json, err_body).map(|_| ()), Err(AttendRedeemError::Server));
        // A 5xx proxy page in HTML is an outage, not a wrong address.
        assert_eq!(
            redeem_against(502, Some("text/html"), "<html>bad gateway</html>").map(|_| ()),
            Err(AttendRedeemError::Server)
        );
        // Positive control: the same wire path really can succeed.
        assert!(redeem_against(200, json, GOOD_REDEEM).is_ok(), "a JSON 200 must still redeem");
    }

    #[test]
    fn every_string_call_site_reports_a_wrong_server() {
        for (status, ct, body) in WRONG_SERVERS {
            let at = |s: &str| format!("{s} against {status} {ct}");
            assert_wrong_server_text(&at("post_consent"), post_consent(&serve_once(status, Some(ct), body), "tok", true, "u"));
            assert_wrong_server_text(&at("get_status"), get_status(&serve_once(status, Some(ct), body), "tok"));
            assert_wrong_server_text(
                &at("post_promote_complete"),
                post_promote_complete(&serve_once(status, Some(ct), body), "tok", true, None, Some("n")),
            );
            assert_wrong_server_text(
                &at("download_installer_bundle"),
                download_installer_bundle(&serve_once(status, Some(ct), body), "tok", Some("n")),
            );
        }
    }

    #[test]
    fn real_control_plane_errors_never_read_as_wrong_server_at_the_string_call_sites() {
        let json = Some("application/json");
        let err_body = r#"{"error":"nope"}"#;
        type Call<'a> = &'a dyn Fn(&str) -> Result<(), String>;
        let calls: [(&str, &str, Call<'_>); 4] = [
            ("post_consent", "attend: consent returned", &|b| post_consent(b, "tok", true, "u")),
            ("get_status", "attend: status returned", &|b| get_status(b, "tok").map(|_| ())),
            ("post_promote_complete", "attend: promote-complete returned", &|b| post_promote_complete(b, "tok", true, None, None)),
            ("download_installer_bundle", "attend: installer bundle returned", &|b| download_installer_bundle(b, "tok", None).map(|_| ())),
        ];
        for status in [403u16, 404, 409, 500] {
            for (name, prefix, call) in &calls {
                let at = format!("{name} against JSON {status}");
                // The installer answers a 409 with its own sentence (the promotion was not authorized); every other status is "<call> returned N".
                let expected =
                    if *name == "download_installer_bundle" && status == 409 { "the installation was not authorized".to_string() } else { format!("{prefix} {status}") };
                let srv = serve_once(status, json, err_body);
                assert_not_wrong_server_text(&at, call(&srv), &expected);
                srv.finish();
            }
        }
        // Positive controls: the same wire paths succeed on a real answer.
        assert!(get_status(&serve_once(200, json, r#"{"state":"active"}"#), "tok").is_ok());
        assert!(post_consent(&serve_once(200, json, "{}"), "tok", true, "u").is_ok());
        assert!(post_promote_complete(&serve_once(200, json, "{}"), "tok", true, None, None).is_ok());
        // A ZIP (non-JSON, non-HTML) 200 is a real installer bundle.
        let zip = download_installer_bundle(&serve_once(200, Some("application/zip"), "PK"), "tok", None);
        assert_eq!(zip.expect("a zip 200 is a bundle"), b"PK".to_vec());
    }

    /// A refused loopback connection is [`AttendRedeemError::Network`]. Real I/O, but to a port that
    /// is never listening, so it fails fast with connection-refused rather than the 20s timeout —
    /// this is the one arm the pure `redeem_error_for` cannot cover.
    #[test]
    fn a_refused_connection_is_network() {
        // Port 1 is not something this box listens on; connect() is refused immediately.
        let got = redeem_detailed("http://127.0.0.1:1", "CODE", "deadbeef", "test-host");
        assert_eq!(got, Err(AttendRedeemError::Network), "a refused connect must be Network");
    }

    /// The reason field is optional, trimmed, and blank-or-junk-tolerant — the grant_issuer_pubkey
    /// precedent. A server typo must never cost the customer the whole session.
    #[test]
    fn the_reason_field_is_parsed_optionally() {
        let base = r#""device_id":"d","tenant_id":"t","signaling_url":"ws://x","attend_token":"k""#;
        let with = parse_attend_redeem(&format!("{{{base},\"reason\":\"  Acme IT  \"}}")).unwrap();
        assert_eq!(with.reason.as_deref(), Some("Acme IT"), "trimmed and kept");
        for empty in ["\"\"", "\"   \"", "123", "null", "true", "[]"] {
            let got = parse_attend_redeem(&format!("{{{base},\"reason\":{empty}}}"))
                .unwrap_or_else(|e| panic!("reason={empty} must not fail the redeem: {e}"));
            assert_eq!(got.reason, None, "reason={empty} must degrade to None");
        }
        let absent = parse_attend_redeem(&format!("{{{base}}}")).unwrap();
        assert_eq!(absent.reason, None);
    }

    /// The consent prompt must LEAD with the host and ATTRIBUTE the reason. The host is the fact a
    /// guest can disbelieve; the reason is attacker-chosen text and must read as a claim.
    #[test]
    fn consent_prompt_leads_with_host_and_attributes_reason() {
        let text = consent_prompt_text("Acme IT", "cp.acme.example");
        let host_pos = text.find("cp.acme.example").expect("host must be present");
        let reason_pos = text
            .find("identifying themselves as")
            .expect("the reason must be attributed, not stated as fact");
        assert!(host_pos < reason_pos, "the host line must come before the reason line:\n{text}");
        assert!(
            text.contains("identifying themselves as \"Acme IT\""),
            "the reason must be quoted and attributed:\n{text}"
        );
        // A blank reason falls back to neutral phrasing, not an empty pair of quotes.
        let blank = consent_prompt_text("", "cp.acme.example");
        assert!(!blank.contains("\"\""), "no empty quotes for a missing reason:\n{blank}");
        assert!(blank.contains("A support technician"), "{blank}");
    }

    /// Decline and could-not-display are different outcomes that map to different customer messages.
    #[test]
    fn consent_outcomes_map_to_distinct_failures() {
        use rmt_agent_core::support_ui::Failure;
        assert_eq!(ConsentOutcome::Granted.to_failure(), None);
        assert_eq!(ConsentOutcome::Declined.to_failure(), Some(Failure::ConsentDeclined));
        assert_eq!(
            ConsentOutcome::CouldNotDisplay.to_failure(),
            Some(Failure::ConsentUndisplayable)
        );
        // auto-consent still grants (test-only path), through the tri-state entry point too.
        assert_eq!(
            obtain_consent_detailed("Acme IT", "cp.example.com", true),
            ConsentOutcome::Granted
        );
    }

    /// The typed error bridges to the customer-facing table, and Malformed is a service problem.
    #[test]
    fn redeem_error_bridges_to_the_support_failure_table() {
        use rmt_agent_core::support_ui::Failure;
        assert_eq!(AttendRedeemError::Invalid.to_failure(), Failure::InvalidCode);
        assert_eq!(
            AttendRedeemError::Throttled { retry_after: 12 }.to_failure(),
            Failure::Throttled { retry_after_secs: 12 }
        );
        assert_eq!(AttendRedeemError::Network.to_failure(), Failure::Network);
        assert_eq!(AttendRedeemError::Server.to_failure(), Failure::Server);
        assert_eq!(AttendRedeemError::Malformed.to_failure(), Failure::Server);
    }

    // ---- docs/48 C slice 4: generic (pass-mode) Support ----

    #[test]
    fn the_baked_consent_text_is_unchanged_and_the_pass_adds_one_line_under_the_host() {
        // Newlines are built, not typed: tooling once decoded typed escapes in this repo.
        let nl = char::from(10).to_string();
        let blank = nl.repeat(2);
        let baked = consent_prompt_text("Acme IT", "cp.acme.example");
        assert_eq!(baked, consent_prompt_text_issued("Acme IT", "cp.acme.example", None));
        assert!(baked.starts_with(&format!("This will connect your computer to: cp.acme.example{blank}")));
        assert!(!baked.contains("Issued to"));
        let pass = consent_prompt_text_issued("Acme IT", "remote.acme.example", Some("Acme Managed Services, LLC"));
        assert!(
            pass.starts_with(&format!(
                "This will connect your computer to: remote.acme.example{nl}Issued to: Acme Managed Services, LLC{blank}"
            )),
            "{pass}"
        );
        // Everything after the two header lines is the baked prompt's text.
        assert!(pass.ends_with(baked.split_once(blank.as_str()).unwrap().1));
        // A blank issuer adds nothing (never an empty "Issued to:" line).
        assert_eq!(consent_prompt_text_issued("Acme IT", "cp.acme.example", Some("  ")), baked);
    }

    #[test]
    fn pass_mode_redirects_stay_on_the_same_origin() {
        let u = |s: &str| reqwest::Url::parse(s).unwrap();
        assert!(same_origin(&u("https://remote.example.com/cp/a"), &u("https://remote.example.com/cp/b")));
        assert!(same_origin(&u("https://remote.example.com/x"), &u("https://remote.example.com:443/y")));
        for other in ["https://evil.example/cp", "http://remote.example.com/cp", "https://remote.example.com:8443/cp", "https://sub.remote.example.com/cp"] {
            assert!(!same_origin(&u("https://remote.example.com/cp"), &u(other)), "{other} counted as same origin");
        }
    }
}
