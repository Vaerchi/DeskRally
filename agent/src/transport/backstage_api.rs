//! The request/response backstage channel: the web console sends a JSON [`Request`], the agent
//! runs it through the enforced [`Dispatcher`] choke point, and returns a JSON envelope with the
//! typed [`Response`] and the audit event the action produced.
//!
//! This is the wire seam that connects the technician UI (which already renders the panel row
//! shapes) to the OS-facing tool code. It is transport-agnostic at heart — [`dispatch_json`] is
//! a pure `String -> String` step tested without any socket — with a thin axum HTTP adapter for
//! the demo and for driving from a browser.
//!
//! Demo-grade: the adapter issues itself a fixed grant. Production replaces that with the
//! relay-issued signed grant for the authenticated technician, and carries these frames over the
//! backstage channel of the real transport rather than a loopback HTTP port.

use crate::backstage::audit::AuditEvent;
use crate::backstage::{Confirmation, Dispatcher, HandleError, Request, Response};

/// The envelope returned for every backstage request. `audit` is always present (the dispatcher
/// records even denials), so the console can surface exactly what was authorized and run.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub ok: bool,
    /// The typed response on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    /// A human-readable error and its kind on failure (denied / needs-confirmation / refused / exec).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// The audit record this request produced. Present whenever the request reached the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditEvent>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ErrorInfo {
    pub kind: String,
    pub message: String,
    /// docs/58 §3: on `needs_confirmation`, what the confirmed retry must echo as `"confirm"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_token: Option<String>,
}

fn error_kind(e: &HandleError) -> &'static str {
    match e {
        HandleError::Denied(_) => "denied",
        HandleError::NeedsConfirmation { .. } => "needs_confirmation",
        HandleError::Refused { .. } => "refused",
        HandleError::Exec(_) => "exec_failed",
    }
}

/// Core step: decode a JSON [`Request`], run it through the dispatcher, encode the [`Envelope`].
/// Every request gets exactly one envelope (docs/58 §2): an authorization failure AND a malformed or
/// unknown request are well-formed `ok: false` envelopes, so a session channel that correlates
/// replies in order never loses one. `Err` is reserved for an envelope that cannot be encoded.
pub fn dispatch_json(
    dispatcher: &mut Dispatcher,
    request_json: &str,
    confirmation: Confirmation,
    now_ms: i64,
) -> Result<String, String> {
    dispatch_json_for(dispatcher, request_json, confirmation, now_ms, false)
}

/// [`dispatch_json`] for a session that may be a view-only OBSERVER (observer design v2). An
/// observer's non-read-only request is refused here, BEFORE the dispatcher sees it, with a
/// well-formed denial and no audit event (nothing was dispatched), exactly like
/// [`denied_no_grant_json`]. A grant can therefore only ever serve an observer's reads.
pub fn dispatch_json_for(
    dispatcher: &mut Dispatcher,
    request_json: &str,
    confirmation: Confirmation,
    now_ms: i64,
    observer: bool,
) -> Result<String, String> {
    dispatch_json_stamped(dispatcher, request_json, confirmation, now_ms, observer, None)
}

/// [`dispatch_json_for`] for a request stamped at ADMISSION (docs/58 §1): `stamp` is the mutation
/// gate's generation when the host queued it; `None` stamps it now.
///
/// The request JSON may carry a top-level `"confirm": "<token>"` beside `type`/`data` (docs/58 §3).
/// It is taken out before the request is decoded and becomes [`Confirmation::Token`]; without it,
/// the caller's `confirmation` applies.
pub fn dispatch_json_stamped(
    dispatcher: &mut Dispatcher,
    request_json: &str,
    confirmation: Confirmation,
    now_ms: i64,
    observer: bool,
    stamp: Option<u64>,
) -> Result<String, String> {
    let (request, confirmation) = match decode_request(request_json, confirmation) {
        Some(decoded) => decoded,
        None => return Ok(refused_json("this agent does not understand that request")),
    };
    if observer && !request.is_read_only() {
        return Ok(denied_json("this is a view-only observer session; it cannot change the machine"));
    }

    let (audit, result) = match stamp {
        Some(stamp) => dispatcher.handle_admitted(request, confirmation, now_ms, stamp),
        None => dispatcher.handle(request, confirmation, now_ms),
    };

    let envelope = match result {
        Ok(response) => Envelope { ok: true, response: Some(response), error: None, audit },
        Err(e) => Envelope {
            ok: false,
            response: None,
            error: Some(ErrorInfo {
                kind: error_kind(&e).to_string(),
                message: e.to_string(),
                confirm_token: match &e {
                    HandleError::NeedsConfirmation { token, .. } => Some(token.clone()),
                    _ => None,
                },
            }),
            audit,
        },
    };
    serde_json::to_string(&envelope).map_err(|e| format!("failed to encode envelope: {e}"))
}

/// Split a request body into the [`Request`] and its confirmation. `None` for anything that is not
/// a request this agent knows (malformed JSON, an unknown `type`, bad `data`).
fn decode_request(request_json: &str, confirmation: Confirmation) -> Option<(Request, Confirmation)> {
    let mut value: serde_json::Value = serde_json::from_str(request_json).ok()?;
    let confirmation = match value.as_object_mut().and_then(|o| o.remove("confirm")) {
        Some(serde_json::Value::String(token)) => Confirmation::Token(token),
        _ => confirmation,
    };
    let request: Request = serde_json::from_value(value).ok()?;
    Some((request, confirmation))
}

/// A well-formed `refused` [`Envelope`] with no audit event (nothing was dispatched).
/// A `refused` envelope with no audit (nothing was dispatched).
pub fn refused_json(message: &str) -> String {
    let envelope = Envelope {
        ok: false,
        response: None,
        error: Some(ErrorInfo { kind: "refused".to_string(), message: message.to_string(), confirm_token: None }),
        audit: None,
    };
    serde_json::to_string(&envelope)
        .unwrap_or_else(|_| r#"{"ok":false,"error":{"kind":"refused","message":"refused"}}"#.to_string())
}

/// Build a well-formed denial [`Envelope`] JSON for a backstage request received while **no valid
/// grant is installed** (H1 secure mode, before a `Control::InstallGrant` verifies). It mirrors an
/// authorization denial (`ok:false`, `error.kind = "denied"`) so the console renders it the same
/// way, but carries **no audit event** — nothing was dispatched, no [`Dispatcher`] (and hence no
/// audit chain) exists yet. Infallible: a fixed struct that always serializes.
/// A well-formed `denied` [`Envelope`] with no audit event (nothing was dispatched).
fn denied_json(message: &str) -> String {
    let envelope = Envelope {
        ok: false,
        response: None,
        error: Some(ErrorInfo { kind: "denied".to_string(), message: message.to_string(), confirm_token: None }),
        audit: None,
    };
    serde_json::to_string(&envelope)
        .unwrap_or_else(|_| r#"{"ok":false,"error":{"kind":"denied","message":"denied"}}"#.to_string())
}

pub fn denied_no_grant_json() -> String {
    let envelope = Envelope {
        ok: false,
        response: None,
        error: Some(ErrorInfo {
            kind: "denied".to_string(),
            message: "no valid grant installed for this session".to_string(),
            confirm_token: None,
        }),
        audit: None,
    };
    serde_json::to_string(&envelope)
        .unwrap_or_else(|_| r#"{"ok":false,"error":{"kind":"denied","message":"no valid grant installed for this session"}}"#.to_string())
}

/// HTTP adapter for the demo and browser-driven testing.
pub mod http {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;

    use crate::transport::shell_authz::DemoAuthz;

    /// Shared state: one dispatcher per console session (holds the running audit chain).
    #[derive(Clone)]
    pub struct BackstageState {
        pub dispatcher: Arc<Mutex<Dispatcher>>,
    }

    pub fn router(state: BackstageState) -> Router {
        Router::new().route("/backstage/exec", post(exec)).with_state(state)
    }

    /// [`router`] with the demo server's authorization in front of it (docs/25 F16).
    ///
    /// # Why this is separate from `router`
    ///
    /// `router` is the reusable one: in production these frames arrive over the real transport's
    /// backstage channel, already authenticated by a relay-issued signed grant, and a loopback
    /// token check there would be meaningless. This wrapper is for the DEMO binary, which listens
    /// on a loopback port and issues itself a grant.
    ///
    /// It exists because `backstage_server` is `shell_server`'s sibling and had the identical hole.
    /// F16 names only the shell demo, but this one served `FileBrowse` and `RegistryRead` to any
    /// caller that could reach 127.0.0.1:8072 — and fixing one sibling while leaving the other is
    /// the failure shape this project has already paid for more than once.
    pub fn demo_router(state: BackstageState, authz: DemoAuthz) -> Router {
        router(state).layer(axum::middleware::from_fn_with_state(authz, require_demo_authz))
    }

    /// Refuse anything the demo policy does not authorize, before it reaches a dispatcher.
    ///
    /// The token may arrive as `Authorization: Bearer <token>` or as `?t=<token>`. The header is
    /// the natural form for an HTTP API driven by curl; the query parameter exists because a
    /// browser page hitting this port cannot set headers on every kind of request, and the shell
    /// demo already established that shape.
    async fn require_demo_authz(
        State(authz): State<DemoAuthz>,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        use axum::http::{header, StatusCode};
        use axum::response::IntoResponse;

        let headers = request.headers();
        let str_header = |name: header::HeaderName| {
            headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
        };
        let bearer = str_header(header::AUTHORIZATION)
            .and_then(|v| v.strip_prefix("Bearer ").map(str::to_owned));
        let query_token = request.uri().query().and_then(|q| {
            q.split('&').find_map(|kv| kv.strip_prefix("t=").map(str::to_owned))
        });
        let token = bearer.or(query_token);
        let host = str_header(header::HOST);
        let origin = str_header(header::ORIGIN);

        if let Err(refusal) = authz.authorize(token.as_deref(), host.as_deref(), origin.as_deref())
        {
            // No presented value is echoed: a refusal must not put a secret, or an
            // attacker-chosen string, into the operator's console.
            eprintln!("backstage demo: REFUSED a request — {refusal}");
            return (StatusCode::FORBIDDEN, "forbidden\n").into_response();
        }
        next.run(request).await
    }

    /// POST a JSON `Request`; get an `Envelope` back. A `?confirm=1` query supplies the typed
    /// confirmation for actions that require it (the console sends it after the operator
    /// re-types the machine name).
    async fn exec(
        State(state): State<BackstageState>,
        axum::extract::RawQuery(query): axum::extract::RawQuery,
        body: String,
    ) -> (StatusCode, String) {
        let confirmation = if query.as_deref().is_some_and(|q| q.contains("confirm=1")) {
            Confirmation::Provided
        } else {
            Confirmation::NotProvided
        };
        let now = now_ms();
        let mut disp = state.dispatcher.lock().expect("dispatcher mutex");
        match dispatch_json(&mut disp, &body, confirmation, now) {
            Ok(json) => (StatusCode::OK, json),
            Err(e) => (StatusCode::BAD_REQUEST, e),
        }
    }

    fn now_ms() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backstage::rbac::{Capability, Grant};

    /// A dispatcher over an IDENTIFIED chain — the only state production ever reaches, since a
    /// grant's ids are minted server-side. With nil ids the chain is unidentified and
    /// `Dispatcher::record` seals nothing, so every `env["audit"]` assertion below would pass
    /// vacuously against a build that produced no audit at all.
    fn dispatcher_with(caps: Vec<Capability>) -> Dispatcher {
        let grant = Grant {
            technician_id: uuid::Uuid::from_u128(0x7ec4),
            session_id: uuid::Uuid::from_u128(0x5e55),
            machine_id: uuid::Uuid::from_u128(0x111),
            capabilities: caps,
        };
        Dispatcher::new(grant, "rmt-agent.exe")
    }

    #[test]
    fn request_json_shape_is_adjacently_tagged() {
        // The exact shape the web console emits.
        let json = r#"{"type":"BrowseDirectory","data":{"path":""}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::BrowseDirectory { .. }));

        // A unit variant needs no data field.
        let req: Request = serde_json::from_str(r#"{"type":"GetSystemInfo"}"#).unwrap();
        assert!(matches!(req, Request::GetSystemInfo));
    }

    #[test]
    fn granted_read_returns_ok_envelope_with_audit() {
        let mut d = dispatcher_with(vec![Capability::FileBrowse]);
        let out = dispatch_json(
            &mut d,
            r#"{"type":"BrowseDirectory","data":{"path":""}}"#,
            Confirmation::NotProvided,
            1,
        )
        .unwrap();

        let env: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(env["ok"], true);
        assert_eq!(env["response"]["type"], "DirectoryListing");
        assert!(env["response"]["data"]["entries"].is_array());
        // Audit is always present.
        assert!(env["audit"]["hash"].is_string());
    }

    #[test]
    fn ungranted_request_is_a_denied_envelope_not_an_error() {
        // No capabilities: the dispatcher denies, but the transport still returns a well-formed
        // envelope (ok:false) with the audit record — not a transport error.
        let mut d = dispatcher_with(vec![]);
        let out = dispatch_json(
            &mut d,
            r#"{"type":"ListProcesses"}"#,
            Confirmation::NotProvided,
            1,
        )
        .unwrap();

        let env: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"]["kind"], "denied");
        assert!(env["audit"]["hash"].is_string(), "the denial is audited");
    }

    #[test]
    fn observer_write_is_denied_before_dispatch() {
        // No kill capability: even a regression cannot execute a process kill. If the request
        // reaches the dispatcher, its denial consumes an audit sequence number.
        let mut d = dispatcher_with(vec![Capability::ProcessList]);
        let out = dispatch_json_for(
            &mut d,
            r#"{"type":"KillProcess","data":{"pid":0,"image":"x.exe","owner":"u"}}"#,
            Confirmation::Provided,
            1,
            true,
        ).unwrap();
        let env: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"]["kind"], "denied");
        assert!(env["error"]["message"].as_str().unwrap().contains("observer"));
        assert!(env.get("audit").is_none());
        assert!(env.get("response").is_none());

        // Compare against a fresh identified chain, rather than assuming its initial sequence.
        let mut fresh = dispatcher_with(vec![Capability::ProcessList]);
        let read = r#"{"type":"ListProcesses"}"#;
        let after = dispatch_json_for(&mut d, read, Confirmation::NotProvided, 2, true).unwrap();
        let baseline = dispatch_json_for(&mut fresh, read, Confirmation::NotProvided, 2, true).unwrap();
        let after: serde_json::Value = serde_json::from_str(&after).unwrap();
        let baseline: serde_json::Value = serde_json::from_str(&baseline).unwrap();
        assert_eq!(after["ok"], true);
        let first_seq = baseline["audit"]["seq"].as_u64().expect("baseline audit sequence");
        assert_eq!(after["audit"]["seq"].as_u64(), Some(first_seq),
            "observer write reached the dispatcher and advanced its audit chain");
    }

    #[test]
    fn observer_read_dispatches_normally() {
        let mut d = dispatcher_with(vec![Capability::ProcessList]);
        let out = dispatch_json_for(
            &mut d,
            r#"{"type":"ListProcesses"}"#,
            Confirmation::NotProvided,
            1,
            true,
        ).unwrap();
        let env: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(env["ok"], true);
        assert!(env["response"].is_object());
        assert!(env.get("error").is_none());
        assert!(env["audit"]["hash"].is_string(), "observer read must reach the dispatcher");
    }

    #[test]
    fn malformed_and_unknown_requests_get_a_refused_envelope() {
        // docs/58 §2: every frame gets exactly one reply. A dropped frame would leave the console's
        // in-order correlation pairing every later reply with the wrong request.
        let mut d = dispatcher_with(vec![Capability::ProcessList]);
        for body in [
            "not json",
            r#"{"type":"TeleportTheGuest","data":{}}"#,
            r#"{"type":"BrowseDirectory","data":{"wrong":1}}"#,
            r#"[1,2,3]"#,
        ] {
            let out = dispatch_json(&mut d, body, Confirmation::NotProvided, 1).unwrap();
            let env: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(env["ok"], false, "{body}");
            assert_eq!(env["error"]["kind"], "refused", "{body}");
            assert!(env.get("audit").is_none(), "nothing was dispatched for {body}");
        }
    }

    /// A dispatcher holding `file_delete` whose file manager is the scriptable fake.
    fn files_dispatcher(
        guard: crate::backstage::rbac::GuardRail,
        identity: &[u8],
    ) -> (Dispatcher, crate::backstage::fileops::fake::FakeFiles) {
        let mut d = dispatcher_with(vec![Capability::FileDelete]);
        let fake = crate::backstage::fileops::fake::FakeFiles::new(guard, identity);
        d.set_file_manager(Box::new(fake.clone()));
        (d, fake)
    }

    fn env(out: &str) -> serde_json::Value {
        serde_json::from_str(out).unwrap()
    }

    #[test]
    fn confirm_token_round_trip_binds_the_resolved_objects() {
        use crate::backstage::rbac::GuardRail;
        use std::sync::atomic::Ordering;
        let (mut d, fake) =
            files_dispatcher(GuardRail::RequireConfirmation { reason: "deleting is permanent" }, b"id-A");
        let body = r#"{"type":"DeletePath","data":{"path":"D:\\work\\old.txt"}}"#;

        // 1. Unconfirmed: needs_confirmation, carrying the token.
        let first = env(&dispatch_json(&mut d, body, Confirmation::NotProvided, 1).unwrap());
        assert_eq!(first["error"]["kind"], "needs_confirmation");
        let token = first["error"]["confirm_token"].as_str().expect("a token").to_string();
        assert_eq!(fake.commits.load(Ordering::SeqCst), 0);

        // 2. A wrong token does not confirm.
        let wrong = format!(r#"{{"type":"DeletePath","data":{{"path":"D:\\work\\old.txt"}},"confirm":"{}"}}"#, "0".repeat(64));
        let w = env(&dispatch_json(&mut d, &wrong, Confirmation::NotProvided, 2).unwrap());
        assert_eq!(w["error"]["kind"], "needs_confirmation");
        assert_eq!(fake.commits.load(Ordering::SeqCst), 0);

        // 3. The object changed between the dialog and the retry: the old token no longer confirms,
        //    and a NEW token is offered.
        *fake.identity.lock().unwrap() = b"id-B".to_vec();
        let retry = format!(r#"{{"type":"DeletePath","data":{{"path":"D:\\work\\old.txt"}},"confirm":"{token}"}}"#);
        let changed = env(&dispatch_json(&mut d, &retry, Confirmation::NotProvided, 3).unwrap());
        assert_eq!(changed["error"]["kind"], "needs_confirmation", "a swapped target must be re-confirmed");
        let token_b = changed["error"]["confirm_token"].as_str().unwrap().to_string();
        assert_ne!(token_b, token);
        assert_eq!(fake.commits.load(Ordering::SeqCst), 0);

        // 4. The matching token confirms, the commit runs once, and the RESOLVED path is audited.
        let good = format!(r#"{{"type":"DeletePath","data":{{"path":"D:\\work\\old.txt"}},"confirm":"{token_b}"}}"#);
        let ok = env(&dispatch_json(&mut d, &good, Confirmation::NotProvided, 4).unwrap());
        assert_eq!(ok["ok"], true, "{ok}");
        assert_eq!(fake.commits.load(Ordering::SeqCst), 1);
        assert_eq!(ok["audit"]["action"]["kind"], "file_delete");
        assert!(ok["audit"]["action"]["path"].as_str().unwrap().starts_with("RESOLVED:"));
    }

    #[test]
    fn a_token_does_not_confirm_a_different_request() {
        use crate::backstage::rbac::GuardRail;
        let (mut d, _fake) = files_dispatcher(GuardRail::RequireConfirmation { reason: "r" }, b"same");
        let a = r#"{"type":"DeletePath","data":{"path":"D:\\a"}}"#;
        let token = env(&dispatch_json(&mut d, a, Confirmation::NotProvided, 1).unwrap())["error"]["confirm_token"]
            .as_str()
            .unwrap()
            .to_string();
        let b = format!(r#"{{"type":"DeletePath","data":{{"path":"D:\\b"}},"confirm":"{token}"}}"#);
        let out = env(&dispatch_json(&mut d, &b, Confirmation::NotProvided, 2).unwrap());
        assert_eq!(out["error"]["kind"], "needs_confirmation", "a token is bound to its own request");
    }

    #[test]
    fn a_resolved_deny_is_refused_and_audited() {
        use crate::backstage::rbac::GuardRail;
        use std::sync::atomic::Ordering;
        let (mut d, fake) = files_dispatcher(GuardRail::Deny { reason: "the agent's own folder" }, b"x");
        let out = env(&dispatch_json(&mut d, r#"{"type":"DeletePath","data":{"path":"C:\\rmt-agent\\config.json"}}"#, Confirmation::Provided, 1).unwrap());
        assert_eq!(out["error"]["kind"], "refused");
        assert_eq!(out["audit"]["outcome"]["result"], "denied");
        assert_eq!(fake.commits.load(Ordering::SeqCst), 0, "even an unconditional confirmation cannot pass a Deny");
    }

    #[test]
    fn file_management_needs_file_delete_and_discard_needs_file_upload() {
        let mut d = dispatcher_with(vec![Capability::FileUpload, Capability::FileBrowse]);
        let fake = crate::backstage::fileops::fake::FakeFiles::new(crate::backstage::rbac::GuardRail::Allow, b"x");
        d.set_file_manager(Box::new(fake));
        for body in [
            r#"{"type":"CreateDirectory","data":{"path":"D:\\n"}}"#,
            r#"{"type":"RenamePath","data":{"from":"D:\\a","to":"D:\\b"}}"#,
            r#"{"type":"DeletePath","data":{"path":"D:\\a"}}"#,
            r#"{"type":"PlaceUpload","data":{"transfer_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","dest_dir":"D:\\d"}}"#,
        ] {
            let out = env(&dispatch_json(&mut d, body, Confirmation::Provided, 1).unwrap());
            assert_eq!(out["error"]["kind"], "denied", "an Operator grant must not manage files: {body}");
        }
        let discard = env(&dispatch_json(&mut d, r#"{"type":"DiscardUpload","data":{"transfer_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}"#, Confirmation::NotProvided, 2).unwrap());
        assert_eq!(discard["ok"], true, "discarding this session's own upload is Operator: {discard}");
    }

    #[test]
    fn revoked_admission_refuses_mutations_but_not_reads() {
        use crate::backstage::rbac::GuardRail;
        use std::sync::atomic::Ordering;
        let (mut d, fake) = files_dispatcher(GuardRail::Allow, b"x");
        let gate = std::sync::Arc::new(crate::backstage::gate::MutationGate::new());
        d.set_mutation_gate(std::sync::Arc::clone(&gate));
        let old = gate.stamp();
        gate.revoke();
        let body = r#"{"type":"CreateDirectory","data":{"path":"D:\\n"}}"#;
        let out = env(&dispatch_json_stamped(&mut d, body, Confirmation::NotProvided, 1, false, Some(old)).unwrap());
        assert_eq!(out["error"]["kind"], "refused");
        assert_eq!(out["audit"]["outcome"]["result"], "denied", "a refused mutation is still a record");
        // Reopening does not revive the request admitted before the loss.
        gate.reopen();
        let again = env(&dispatch_json_stamped(&mut d, body, Confirmation::NotProvided, 2, false, Some(old)).unwrap());
        assert_eq!(again["error"]["kind"], "refused");
        assert_eq!(fake.commits.load(Ordering::SeqCst), 0);
        // New work is admitted.
        let fresh = env(&dispatch_json_stamped(&mut d, body, Confirmation::NotProvided, 3, false, Some(gate.stamp())).unwrap());
        assert_eq!(fresh["ok"], true, "{fresh}");
        // A read is never gated.
        gate.revoke();
        let mut r = dispatcher_with(vec![Capability::ProcessList]);
        r.set_mutation_gate(std::sync::Arc::clone(&gate));
        let read = env(&dispatch_json_stamped(&mut r, r#"{"type":"ListProcesses"}"#, Confirmation::NotProvided, 4, false, Some(old)).unwrap());
        assert_eq!(read["ok"], true);
    }

    /// Non-file mutations (service, process, registry) have no commit step of their own, so the
    /// ENTRY admission check is their only gate. A nonexistent service keeps this harmless: without
    /// the gate it would reach the OS and fail as exec_failed; with it, it is refused first.
    #[test]
    fn revoked_admission_refuses_a_service_control_before_it_reaches_the_os() {
        let mut d = dispatcher_with(vec![Capability::ServiceControl]);
        let gate = std::sync::Arc::new(crate::backstage::gate::MutationGate::new());
        d.set_mutation_gate(std::sync::Arc::clone(&gate));
        let old = gate.stamp();
        gate.revoke();
        let body = r#"{"type":"ControlService","data":{"service":"rmt-no-such-service-58","verb":"start"}}"#;
        let out = env(&dispatch_json_stamped(&mut d, body, Confirmation::Provided, 1, false, Some(old)).unwrap());
        assert_eq!(out["error"]["kind"], "refused", "{out}");
        assert!(out["error"]["message"].as_str().unwrap().contains("indicator"));
        // Negative control: with the gate open the same request reaches the OS and fails there.
        let mut open = dispatcher_with(vec![Capability::ServiceControl]);
        let reached = env(&dispatch_json(&mut open, body, Confirmation::Provided, 2).unwrap());
        assert_eq!(reached["error"]["kind"], "exec_failed", "{reached}");
    }

    #[test]
    fn revocation_between_prepare_and_commit_is_caught_at_the_irreversible_step() {
        // The commit's own admission check is what stops it, not only the entry check.
        use crate::backstage::rbac::GuardRail;
        use std::sync::atomic::Ordering;
        struct RevokeOnPrepare {
            inner: crate::backstage::fileops::fake::FakeFiles,
            gate: std::sync::Arc<crate::backstage::gate::MutationGate>,
        }
        impl crate::backstage::fileops::FileManager for RevokeOnPrepare {
            fn prepare(
                &mut self,
                op: crate::backstage::fileops::FileOp<'_>,
            ) -> Result<crate::backstage::fileops::Prepared, crate::backstage::fileops::PrepareError> {
                let p = self.inner.prepare(op);
                self.gate.revoke(); // the indicator is lost while the operands are being resolved
                p
            }
        }
        let gate = std::sync::Arc::new(crate::backstage::gate::MutationGate::new());
        let fake = crate::backstage::fileops::fake::FakeFiles::new(GuardRail::Allow, b"x");
        let mut d = dispatcher_with(vec![Capability::FileDelete]);
        d.set_mutation_gate(std::sync::Arc::clone(&gate));
        d.set_file_manager(Box::new(RevokeOnPrepare { inner: fake.clone(), gate: std::sync::Arc::clone(&gate) }));
        let out = env(&dispatch_json(&mut d, r#"{"type":"CreateDirectory","data":{"path":"D:\\n"}}"#, Confirmation::NotProvided, 1).unwrap());
        assert_eq!(out["error"]["kind"], "refused");
        assert_eq!(*fake.admitted.lock().unwrap(), vec![false]);
        assert_eq!(fake.commits.load(Ordering::SeqCst), 0);
    }

    /// The SHIPPED (0.1.16) agent decodes requests with this enum shape: adjacently tagged, no
    /// `deny_unknown_fields`. It must keep ignoring the new `confirm` key on a request type it knows
    /// (docs/58 §3), or a confirmed retry sent to an old agent would be dropped as malformed.
    #[test]
    fn the_shipped_decoder_shape_ignores_the_confirm_key() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(tag = "type", content = "data")]
        #[allow(dead_code)]
        enum ShippedRequest {
            ListProcesses,
            BrowseDirectory { path: String },
            WriteRegistry { path: String, value_name: String, new_value: String },
        }
        let r: ShippedRequest =
            serde_json::from_str(r#"{"type":"BrowseDirectory","data":{"path":"C:"},"confirm":"abc"}"#).unwrap();
        assert!(matches!(r, ShippedRequest::BrowseDirectory { .. }));
        let r: ShippedRequest = serde_json::from_str(r#"{"type":"ListProcesses","confirm":"abc"}"#).unwrap();
        assert!(matches!(r, ShippedRequest::ListProcesses));
    }

    #[test]
    fn confirmation_gate_flows_through_the_envelope() {
        // A sensitive registry write is denied without confirmation, then passes with it.
        let mut d = dispatcher_with(vec![Capability::RegistryWrite]);
        let body = r#"{"type":"WriteRegistry","data":{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Foo","value_name":"ImagePath","new_value":"C:\\x.exe"}}"#;

        let out = dispatch_json(&mut d, body, Confirmation::NotProvided, 1).unwrap();
        let env: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"]["kind"], "needs_confirmation");
    }
}
