//! Backstage: headless background administration of a machine without disturbing the
//! logged-in user. This module is the enforced entry point — every request funnels through
//! [`Dispatcher::handle`], which applies the capability check, the guard rail, and the audit
//! record in that order. There is no other path to the tool implementations.
//!
//! The GUI hidden-desktop feature is intentionally out of scope here (deferred — see
//! `docs/04-backstage.md` Part 2). This module is the headless tool-panel surface.

pub mod audit;
pub mod canonical;
pub mod fileops;
pub mod gate;
pub mod grant;
pub mod ops;
pub mod panels;
pub mod rbac;

#[cfg(windows)]
pub mod shell;
#[cfg(windows)]
pub mod token;

use std::sync::Arc;

use audit::{AuditAction, AuditEvent, Direction, Outcome, SharedAuditChain};
use fileops::{CommitError, FileManager, FileOp, PrepareError};
use gate::MutationGate;
use rbac::{Capability, Denied, Grant, GuardRail};

/// A backstage request, tagged by the capability it needs. Kept separate from the tool
/// implementations so the dispatcher can authorize uniformly before any OS call happens.
///
/// Serialized adjacently-tagged (`{"type": "...", "data": {...}}`) so the web console can send
/// requests as JSON over the backstage channel and the agent decodes them straight into this
/// enum — the single typed entry point the dispatcher authorizes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    ListProcesses,
    ListServices,
    GetSystemInfo,
    ReadEventLog { channel: String, max: usize },
    BrowseDirectory { path: String },
    KillProcess { pid: u32, image: String, owner: String },
    ControlService { service: String, verb: ServiceVerb },
    ReadRegistry { path: String, value_name: String },
    WriteRegistry { path: String, value_name: String, new_value: String },
    OpenShell { program: ShellKind, cols: u16, rows: u16, run_as: RunAsRequest },
    // docs/58 file management (Admin tier, `file_delete`), and discarding this session's own upload
    // (`file_upload`). Sent only to an agent that advertised `file_manage`.
    CreateDirectory { path: String },
    RenamePath { from: String, to: String },
    DeletePath { path: String },
    PlaceUpload { transfer_id: uuid::Uuid, dest_dir: String },
    DiscardUpload { transfer_id: uuid::Uuid },
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceVerb { Start, Stop, Restart }

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind { PowerShell, Cmd }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunAsRequest { System, LoggedInUser, Credential }

impl Request {
    /// Whether this request only READS the machine. A view-only OBSERVER session (observer design
    /// v2) may send these and nothing else. Exhaustive with no wildcard, so a new request type does
    /// not compile until someone decides whether an observer may send it.
    pub fn is_read_only(&self) -> bool {
        match self {
            Request::ListProcesses
            | Request::ListServices
            | Request::GetSystemInfo
            | Request::ReadEventLog { .. }
            | Request::BrowseDirectory { .. }
            | Request::ReadRegistry { .. } => true,
            Request::KillProcess { .. }
            | Request::ControlService { .. }
            | Request::WriteRegistry { .. }
            | Request::OpenShell { .. }
            | Request::CreateDirectory { .. }
            | Request::RenamePath { .. }
            | Request::DeletePath { .. }
            | Request::PlaceUpload { .. }
            | Request::DiscardUpload { .. } => false,
        }
    }

    /// The single capability this request requires. Exhaustive by construction.
    pub fn required_capability(&self) -> Capability {
        match self {
            Request::ListProcesses => Capability::ProcessList,
            Request::ListServices => Capability::ServiceList,
            Request::GetSystemInfo => Capability::SystemInfoRead,
            Request::ReadEventLog { .. } => Capability::EventLogRead,
            Request::BrowseDirectory { .. } => Capability::FileBrowse,
            Request::KillProcess { .. } => Capability::ProcessKill,
            Request::ControlService { .. } => Capability::ServiceControl,
            Request::ReadRegistry { .. } => Capability::RegistryRead,
            Request::WriteRegistry { .. } => Capability::RegistryWrite,
            Request::OpenShell { run_as, .. } => match run_as {
                RunAsRequest::System => Capability::ShellAsSystem,
                RunAsRequest::LoggedInUser => Capability::ShellAsUser,
                RunAsRequest::Credential => Capability::ShellAsCredential,
            },
            // docs/58 §4: file management outside the transfer root is admin-equivalent (the agent
            // acts as SYSTEM), and `file_delete` is the admin-tier file capability every agent
            // already knows. A new capability would break old agents' grant decode.
            Request::CreateDirectory { .. }
            | Request::RenamePath { .. }
            | Request::DeletePath { .. }
            | Request::PlaceUpload { .. } => Capability::FileDelete,
            // Removes only what this session's own upload created, inside the transfer root.
            Request::DiscardUpload { .. } => Capability::FileUpload,
        }
    }

    /// The file operation this request names, if it is one.
    fn file_op(&self) -> Option<FileOp<'_>> {
        match self {
            Request::CreateDirectory { path } => Some(FileOp::CreateDirectory { path }),
            Request::RenamePath { from, to } => Some(FileOp::Rename { from, to }),
            Request::DeletePath { path } => Some(FileOp::Delete { path }),
            Request::PlaceUpload { transfer_id, dest_dir } => {
                Some(FileOp::Place { transfer_id: *transfer_id, dest_dir })
            }
            Request::DiscardUpload { transfer_id } => Some(FileOp::Discard { transfer_id: *transfer_id }),
            _ => None,
        }
    }

    /// Target-specific guard rail. Defaults to `Allow`; dangerous targets escalate.
    ///
    /// `resolved_image` is the image name the OS reports for the request's pid, looked up by the
    /// caller (see [`Dispatcher::authorize`]). The request's OWN `image` field is deliberately not
    /// consulted for the decision: it is attacker-supplied, and a guard that reads it protects
    /// nothing — name a harmless process, pass the pid of `lsass.exe`, and the kill proceeds.
    /// `None` (pid not resolvable) is a DENY, not a fallthrough.
    fn guard_rail(&self, own_service_image: &str, resolved_image: Option<&str>) -> GuardRail {
        match self {
            Request::KillProcess { .. } => match resolved_image {
                Some(actual) => GuardRail::for_process_kill(actual, own_service_image),
                None => GuardRail::Deny {
                    reason: "cannot determine which process this pid refers to",
                },
            },
            Request::WriteRegistry { path, .. } => GuardRail::for_registry_write(path),
            _ => GuardRail::Allow,
        }
    }
}

/// Whether the technician has already supplied the typed confirmation token this turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    NotProvided,
    /// Unconditional confirmation: the dev HTTP seam's `?confirm=1` and tests. Never produced from a
    /// session frame.
    Provided,
    /// docs/58 §3: the token from this request's `needs_confirmation` reply, echoed on the retry. It
    /// confirms only if it equals the token recomputed NOW, which binds it to the exact request and,
    /// for file operations, to the resolved objects. A client assertion, not proof that a human typed
    /// anything.
    Token(String),
}

pub struct Dispatcher {
    grant: Grant,
    /// The SESSION's chain, not this dispatcher's. Shared (loop 91) so that installing a second
    /// grant continues one trail instead of forking a new one at `seq 0`, and so that producers with
    /// no grant at all — session recording, and a REFUSED file transfer — still have somewhere to
    /// record. See [`audit::SharedAuditChain`].
    chain: SharedAuditChain,
    own_service_image: String,
    /// docs/58: the OS side of file management (Windows: handle-relative); [`fileops::Unsupported`]
    /// unless the host equips one.
    files: Box<dyn FileManager>,
    /// docs/58 §1: revoked on indicator loss and at teardown; shared with the host.
    gate: Arc<MutationGate>,
}

#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    #[error(transparent)]
    Denied(#[from] Denied),
    #[error("action requires confirmation: {reason}")]
    NeedsConfirmation {
        reason: &'static str,
        /// What the retry must echo (docs/58 §3).
        token: String,
    },
    #[error("action refused: {reason}")]
    Refused { reason: &'static str },
    #[error("execution failed: {0}")]
    Exec(String),
}

impl Dispatcher {
    /// Build a dispatcher that STARTS ITS OWN chain from the grant.
    ///
    /// This is the pre-loop-91 shape, kept for the dev/self-issued path and for tests that care
    /// about one dispatcher in isolation. A real session must use [`Dispatcher::with_chain`]: two
    /// dispatchers built this way in one session produce two chains that both start at `seq 0`, and
    /// the console's forwarder de-duplicates on `seq`, so the second one is discarded entirely.
    pub fn new(grant: Grant, own_service_image: impl Into<String>) -> Self {
        let chain =
            audit::new_shared_chain(grant.session_id, grant.technician_id, grant.machine_id);
        Self::with_chain(grant, own_service_image, chain)
    }

    /// Build a dispatcher that JOINS an existing session chain.
    ///
    /// The grant's own `session_id` / `technician_id` are deliberately ignored for chaining: the
    /// chain is the SESSION's, and its identity comes from what signaling vouched for. A grant that
    /// disagrees does not get to rename the trail — it only decides what this dispatcher may DO.
    pub fn with_chain(
        grant: Grant,
        own_service_image: impl Into<String>,
        chain: SharedAuditChain,
    ) -> Self {
        // If signaling could not identify the chain — a deployment that verifies no session tickets
        // vouches for neither id — adopt THIS grant's, once, before anything is sealed. The grant is
        // a control-plane-signed artifact minted as `Grants.Mint(p.UserID, …)`, i.e. it carries the
        // very technician id `/audit/ingest` will compare against, so this is the same claim from
        // the other channel rather than a weaker one. `adopt_identity` refuses if the chain is
        // already identified or has sealed an event, so a ticketed session's identity always wins
        // and a grant can never rename a trail that already exists.
        {
            let mut g = chain.lock().unwrap_or_else(|p| p.into_inner());
            if g.adopt_identity(grant.session_id, grant.technician_id) {
                tracing::info!(
                    session = %grant.session_id,
                    technician = %grant.technician_id,
                    "audit: chain identity adopted from the installed grant (signaling vouched for none)"
                );
            } else if !g.is_identified() {
                // Loud, because the consequence is silent everywhere else: nothing this dispatcher
                // does will be sealed, `/audit/ingest` would refuse it anyway, and the console
                // swallows flush failures by design. Without this line the session simply produces
                // no central audit and no one finds out.
                tracing::warn!(
                    grant_session = %grant.session_id,
                    grant_technician = %grant.technician_id,
                    chain_session = %g.session_id(),
                    "audit: chain is UNIDENTIFIED and the grant's identity was refused — \
                     backstage actions in this session will NOT be recorded centrally"
                );
            }
        }
        Self {
            grant,
            chain,
            own_service_image: own_service_image.into(),
            files: Box::new(fileops::Unsupported),
            gate: Arc::new(MutationGate::new()),
        }
    }

    /// A second dispatcher for the SAME session authority (docs/58 §12): the same grant, the same
    /// shared audit chain, the same mutation gate. The Backstage worker runs requests on the twin while
    /// the session loop keeps this one for file-transfer gating, so neither ever waits on a lock the
    /// other holds across a system call. The twin starts without file management; the host equips it.
    pub fn twin(&self) -> Dispatcher {
        Self {
            grant: self.grant.clone(),
            chain: std::sync::Arc::clone(&self.chain),
            own_service_image: self.own_service_image.clone(),
            files: Box::new(fileops::Unsupported),
            gate: Arc::clone(&self.gate),
        }
    }

    /// Equip the OS side of file management (docs/58). The host does this on Windows.
    pub fn set_file_manager(&mut self, files: Box<dyn FileManager>) {
        self.files = files;
    }

    /// Share the session's mutation gate (docs/58 §1).
    pub fn set_mutation_gate(&mut self, gate: Arc<MutationGate>) {
        self.gate = gate;
    }

    /// The confirmation token for `req` over the resolved `identity` bytes (empty for requests that
    /// resolve nothing). SHA-256 over a domain tag, the session, the request's JSON and the identity.
    fn confirm_token(&self, req: &Request, identity: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"rmt-confirm-v1\0");
        h.update(self.grant.session_id.as_bytes());
        h.update(serde_json::to_vec(req).unwrap_or_default());
        h.update((identity.len() as u64).to_be_bytes());
        h.update(identity);
        hex::encode(h.finalize())
    }

    fn confirmed(&self, confirmation: &Confirmation, token: &str) -> bool {
        match confirmation {
            Confirmation::NotProvided => false,
            Confirmation::Provided => true,
            Confirmation::Token(t) => t == token,
        }
    }

    /// Seal one event into the session chain. Takes `&self`: the chain has interior mutability, so
    /// recording never contends with a `&mut self` borrow at the call site.
    ///
    /// **Unconditional, and it must stay that way — this was tried the other way and reverted.**
    /// Loop 92 made it `try_record_shared`, so an unidentified chain sealed nothing. The reasoning
    /// looked sound (an event `/audit/ingest` will refuse is a wasted `seq`, and `seq` holes are
    /// permanent) and it is the rule `recording_audit` and the no-grant file-transfer denial in
    /// `host.rs` already follow. It broke three e2e tests, and they were right to break:
    ///
    /// **the sealed event has a SECOND consumer.** It goes back to the controller in the response
    /// envelope and in `FtMessage::Audit` — ADR-008's tamper-evident record, which the console
    /// renders as `backstage-audit-hash` and the file-transfer flow expects after every `Ack`. On an
    /// unticketed deployment the chain is legitimately unidentified, so guarding here silently
    /// removes a visible feature from every dev/LAN session rather than merely declining to forward.
    ///
    /// The real defect is that unidentified chains exist at all on a path that produces audit. Fix
    /// that end — give unticketed sessions an identity, or refuse to arm a dispatcher without one —
    /// not this one. See docs/19 §4.
    fn record(&self, action: AuditAction, outcome: Outcome, now_ms: i64) -> AuditEvent {
        audit::record_shared(&self.chain, action, outcome, now_ms)
    }

    /// THE choke point. Order is deliberate and must not be reordered:
    ///   1. capability check   (do they hold the right at all?)
    ///   2. guard rail          (is this target extra-dangerous / forbidden?)
    ///   3. confirmation gate   (typed machine name where required)
    ///   4. execute             (the actual OS work)
    ///   5. audit               (always, including on denial — a blocked attempt is a record)
    ///
    /// `now_ms` is injected so the caller controls the clock (testability; no ambient time).
    ///
    /// The interactive shell does not flow through here — a live shell session is neither
    /// `Clone` nor `Debug` and can't live in [`Response`], so it has its own dispatcher-gated
    /// entry point ([`Dispatcher::open_shell`]) that shares the exact same steps 1–3.
    pub fn handle(
        &mut self,
        req: Request,
        confirmation: Confirmation,
        now_ms: i64,
    ) -> (Option<AuditEvent>, Result<Response, HandleError>) {
        let stamp = self.gate.stamp();
        self.handle_admitted(req, confirmation, now_ms, stamp)
    }

    /// [`handle`](Self::handle) for work stamped when it was ADMITTED (docs/58 §1): the host stamps
    /// a request when it queues it, so a request queued before the indicator was lost is refused
    /// even if the gate has reopened since.
    pub fn handle_admitted(
        &mut self,
        req: Request,
        confirmation: Confirmation,
        now_ms: i64,
        stamp: u64,
    ) -> (Option<AuditEvent>, Result<Response, HandleError>) {
        if !req.is_read_only() && !self.gate.admits(stamp) {
            let reason = "the guest's on-screen indicator is not visible, so this machine is not accepting changes";
            let ev = self.record(describe(&req), Outcome::Denied { reason: reason.to_string() }, now_ms);
            return (Some(ev), Err(HandleError::Refused { reason }));
        }
        if req.file_op().is_some() {
            return self.handle_file_op(req, confirmation, now_ms, stamp);
        }
        // Steps 1–3. On failure the denial is already recorded into the chain.
        if let Err((ev, e)) = self.authorize(&req, confirmation, now_ms) {
            return (Some(ev), Err(e));
        }

        // 4. execute — dispatched to the tool implementations. An arm may return an audit-action
        //    override carrying detail only known after the OS call (e.g. a registry write's
        //    prior value); otherwise the request-derived `describe` shape is recorded.
        let (outcome, action, result) = match self.execute(&req) {
            Ok((resp, override_action)) => {
                (Outcome::Ok, override_action.unwrap_or_else(|| describe(&req)), Ok(resp))
            }
            Err(e) => (Outcome::Failed { error: e.to_string() }, describe(&req), Err(e)),
        };

        // 5. audit the outcome
        let ev = self.record(action, outcome, now_ms);
        (Some(ev), result)
    }

    /// The choke point for file management (docs/58), in the same order as [`handle`]: capability,
    /// then PREPARE (resolve to held handles, which yields the guard decision for the resolved
    /// objects), guard rail, confirmation bound to those objects, commit through the same handles,
    /// audit. Nothing is re-resolved by name between the check and the act.
    fn handle_file_op(
        &mut self,
        req: Request,
        confirmation: Confirmation,
        now_ms: i64,
        stamp: u64,
    ) -> (Option<AuditEvent>, Result<Response, HandleError>) {
        // 1. capability
        if let Err(denied) = self.grant.require(req.required_capability()) {
            let ev = self.record(describe(&req), Outcome::Denied { reason: denied.to_string() }, now_ms);
            return (Some(ev), Err(denied.into()));
        }
        let Some(op) = req.file_op() else {
            return (None, Err(HandleError::Exec("not a file operation".into())));
        };
        // Resolve. A path or protected-object rule refuses here (audited as denied, with the
        // requested operands: nothing was resolved).
        let prepared = match self.files.prepare(op) {
            Ok(p) => p,
            Err(PrepareError::Refused(reason)) => {
                let ev = self.record(describe(&req), Outcome::Denied { reason: reason.to_string() }, now_ms);
                return (Some(ev), Err(HandleError::Refused { reason }));
            }
            Err(PrepareError::Exec(error)) => {
                let ev = self.record(describe(&req), Outcome::Failed { error: error.clone() }, now_ms);
                return (Some(ev), Err(HandleError::Exec(error)));
            }
        };
        // 2. guard rail on the RESOLVED objects; 3. confirmation bound to them.
        let needs = match prepared.guard {
            GuardRail::Deny { reason } => {
                let ev = self.record(prepared.audit, Outcome::Denied { reason: reason.to_string() }, now_ms);
                return (Some(ev), Err(HandleError::Refused { reason }));
            }
            GuardRail::RequireConfirmation { reason } => Some(reason),
            GuardRail::Allow => None,
        };
        if let Some(reason) = needs {
            let token = self.confirm_token(&req, &prepared.identity);
            if !self.confirmed(&confirmation, &token) {
                let ev = self.record(
                    prepared.audit,
                    Outcome::Denied { reason: format!("confirmation required: {reason}") },
                    now_ms,
                );
                return (Some(ev), Err(HandleError::NeedsConfirmation { reason, token }));
            }
        }
        // 4. execute through the held handles, admitted at the irreversible step; 5. audit.
        let gate = Arc::clone(&self.gate);
        let admit = move || gate.admits(stamp);
        let fallback = prepared.audit.clone();
        match (prepared.commit)(&admit) {
            Ok(done) => (Some(self.record(done, Outcome::Ok, now_ms)), Ok(Response::Ack)),
            Err(CommitError::NotAdmitted) => {
                let reason = "the guest's on-screen indicator is not visible, so this machine is not accepting changes";
                let ev = self.record(fallback, Outcome::Denied { reason: reason.to_string() }, now_ms);
                (Some(ev), Err(HandleError::Refused { reason }))
            }
            Err(CommitError::Exec(error)) => {
                let ev = self.record(fallback, Outcome::Failed { error: error.clone() }, now_ms);
                (Some(ev), Err(HandleError::Exec(error)))
            }
        }
    }

    /// Steps 1–3 of the choke point (capability → guard rail → confirmation), factored out so
    /// both [`handle`](Self::handle) and [`open_shell`](Self::open_shell) enforce them
    /// identically. On failure the denial is recorded into the audit chain and returned as
    /// `(event, error)`; on success returns `Ok(())` and records nothing (the caller records
    /// the execution outcome).
    fn authorize(
        &mut self,
        req: &Request,
        confirmation: Confirmation,
        now_ms: i64,
    ) -> Result<(), (AuditEvent, HandleError)> {
        let cap = req.required_capability();

        // 1. capability
        if let Err(denied) = self.grant.require(cap) {
            let ev = self.record(
                describe(req),
                Outcome::Denied { reason: denied.to_string() },
                now_ms,
            );
            return Err((ev, denied.into()));
        }

        // 2. guard rail. For a kill, resolve the image from the PID first: the guard must judge the
        // process that will actually die, not the one the request says it will.
        let resolved_image = match req {
            Request::KillProcess { pid, .. } => super::backstage::ops::process::image_name_for_pid(*pid),
            _ => None,
        };
        match req.guard_rail(&self.own_service_image, resolved_image.as_deref()) {
            GuardRail::Deny { reason } => {
                let ev = self.record(
                    describe(req),
                    Outcome::Denied { reason: reason.to_string() },
                    now_ms,
                );
                return Err((ev, HandleError::Refused { reason }));
            }
            GuardRail::RequireConfirmation { reason } => {
                // 3. confirmation — also triggered by capabilities that always demand it.
                let token = self.confirm_token(req, &[]);
                if !self.confirmed(&confirmation, &token) {
                    let ev = self.record(
                        describe(req),
                        Outcome::Denied { reason: format!("confirmation required: {reason}") },
                        now_ms,
                    );
                    return Err((ev, HandleError::NeedsConfirmation { reason, token }));
                }
            }
            GuardRail::Allow => {
                let token = self.confirm_token(req, &[]);
                if cap.always_requires_confirmation() && !self.confirmed(&confirmation, &token) {
                    let reason = "this action always requires typed confirmation";
                    let ev = self.record(
                        describe(req),
                        Outcome::Denied { reason: reason.to_string() },
                        now_ms,
                    );
                    return Err((ev, HandleError::NeedsConfirmation { reason, token }));
                }
            }
        }

        Ok(())
    }

    /// Authorize, spawn, and audit an interactive shell — the dispatcher-gated entry point for
    /// the shell channel. Runs the same capability/guard-rail/confirmation gate as
    /// [`handle`](Self::handle), then, only if it passes, launches the ConPTY session and
    /// records a `ShellOpen` event carrying the **real** `shell_id` and the requested identity.
    /// Returns the live [`AuthorizedShell`] for the transport to pump; the session stays out of
    /// [`Response`] because it is neither `Clone` nor `Debug`.
    ///
    /// An audit event is ALWAYS returned — a denial, a spawn failure, and a success each
    /// produce a record. The transport should forward it to the relay regardless of outcome.
    #[cfg(windows)]
    pub fn open_shell(
        &mut self,
        program: ShellKind,
        run_as: RunAsRequest,
        cols: u16,
        rows: u16,
        confirmation: Confirmation,
        now_ms: i64,
    ) -> (AuditEvent, Result<AuthorizedShell, HandleError>) {
        let req = Request::OpenShell { program, cols, rows, run_as: run_as.clone() };

        // Steps 1–3, shared with `handle`. On failure the denial is already in the chain.
        if let Err((ev, e)) = self.authorize(&req, confirmation, now_ms) {
            return (ev, Err(e));
        }

        // 4. execute — spawn the pseudoconsole.
        //
        // The demo launches the shell under the agent's *current* identity. In the production
        // service the requested `run_as` selects a token from `token::acquire` (logged-in
        // user / SYSTEM / supplied credential) and the child is created with
        // `CreateProcessAsUser` + the pseudoconsole attribute. `conpty::Process::spawn` can't
        // take a custom token, so that swap lands with the service-hosted launcher (see
        // docs/05 next-steps) — not here. The requested identity is still recorded below.
        let shell_program = match program {
            ShellKind::PowerShell => shell::ShellProgram::PowerShell,
            ShellKind::Cmd => shell::ShellProgram::Cmd,
        };
        let shell_id = uuid::Uuid::new_v4();
        let identity = run_as_to_audit(&run_as);
        let program_name = format!("{program:?}").to_lowercase();

        match shell::ShellSession::open(shell_program, cols, rows) {
            Ok(session) => {
                // 5. audit success with the real shell id.
                let ev = self.record(
                    AuditAction::ShellOpen { shell_id, program: program_name, identity },
                    Outcome::Ok,
                    now_ms,
                );
                (ev, Ok(AuthorizedShell { shell_id, session }))
            }
            Err(e) => {
                // 5. audit the spawn failure.
                let ev = self.record(
                    AuditAction::ShellOpen { shell_id, program: program_name, identity },
                    Outcome::Failed { error: e.to_string() },
                    now_ms,
                );
                (ev, Err(HandleError::Exec(e.to_string())))
            }
        }
    }

    /// Whether this session's grant permits browsing directories ([`Capability::FileBrowse`]),
    /// WITHOUT recording anything (docs/25 F04).
    ///
    /// The read-only twin of [`allows_file_transfer`](Self::allows_file_transfer), and it exists for
    /// the same structural reason: a caller that is not a [`Request`] still has to ask the grant.
    /// `ControlMessage::ListDirectory` arrives on the CONTROL channel with its own wire shape and a
    /// bounded, truncation-flagged reply, so it cannot go through [`handle`](Self::handle) — which
    /// dispatches `Request::BrowseDirectory` into a different lister with no entry cap and a
    /// different row type. Until F04 that meant it asked nobody at all: the same directory listing
    /// was capability-gated and audited on one channel and completely open on the other.
    ///
    /// Narrow on purpose, rather than a general `allows(cap)`. A general accessor is an invitation
    /// to check a capability somewhere and forget the audit record that has to accompany it; one
    /// named method per gated non-`Request` entry point keeps each of them greppable.
    /// Whether this session's grant holds the file-management capability (docs/58 §4). The host
    /// advertises `file_manage` only when it does, so the console's controls rest on the grant the
    /// agent actually verified, not on what the console believes.
    pub fn allows_file_management(&self) -> bool {
        self.grant.allows(Capability::FileDelete)
    }

    pub fn allows_file_browse(&self) -> bool {
        self.grant.allows(Capability::FileBrowse)
    }

    /// The capability a file transfer in `direction` requires (ADR-008). [`Direction::Input`] is
    /// controller → machine (an upload, operator tier); [`Direction::Output`] is machine →
    /// controller (a download, read-only tier).
    pub fn file_transfer_capability(direction: Direction) -> Capability {
        match direction {
            Direction::Input => Capability::FileUpload,
            Direction::Output => Capability::FileDownload,
        }
    }

    /// Whether this session's grant permits a file transfer in `direction`, WITHOUT recording
    /// anything. Used to refuse an upload at its `Offer` — before a single byte touches the disk —
    /// while leaving the actual audit record for the point where the real digest and byte count are
    /// known ([`record_file_transfer`](Self::record_file_transfer)).
    pub fn allows_file_transfer(&self, direction: Direction) -> bool {
        self.grant.require(Self::file_transfer_capability(direction)).is_ok()
    }

    /// Authorize a file transfer and record it into this session's audit chain (ADR-008).
    ///
    /// File transfer runs its own state machine on [`ChannelId::FileTransfer`](rmt_protocol) rather
    /// than through [`handle`](Self::handle)'s request/response shape, so it gets its own gated
    /// entry point — exactly like [`open_shell`](Self::open_shell) does for the interactive shell.
    /// It enforces the SAME first step (the capability check) and always produces an audit event.
    ///
    /// The capability is chosen by direction, matching the tiers the RBAC model already defines:
    /// [`Direction::Input`] (controller → machine, an upload) requires
    /// [`Capability::FileUpload`] (operator); [`Direction::Output`] (machine → controller, a
    /// download) requires [`Capability::FileDownload`] (read-only).
    ///
    /// Returns `(event, allowed)`. `allowed == false` means the caller MUST NOT perform the
    /// transfer — the denial is already sealed into the chain, so a blocked attempt is still a
    /// record. `outcome` lets the caller report a transfer that was authorized but then failed
    /// (a hash mismatch, an I/O error), so the trail distinguishes "refused" from "broke".
    pub fn record_file_transfer(
        &mut self,
        direction: Direction,
        path: impl Into<String>,
        sha256: impl Into<String>,
        bytes: u64,
        outcome: Outcome,
        now_ms: i64,
    ) -> (AuditEvent, bool) {
        let cap = Self::file_transfer_capability(direction);
        let action = AuditAction::FileTransfer {
            direction,
            path: path.into(),
            sha256: sha256.into(),
            bytes,
        };
        if let Err(denied) = self.grant.require(cap) {
            let ev = self.record(action, Outcome::Denied { reason: denied.to_string() }, now_ms);
            return (ev, false);
        }
        (self.record(action, outcome, now_ms), true)
    }

    /// Run the OS work for an authorized request. Returns the typed [`Response`] and an optional
    /// [`AuditAction`] override for detail only known after the call (currently the registry
    /// write's before/after values); `None` means "record the request-derived shape".
    fn execute(&mut self, req: &Request) -> Result<(Response, Option<AuditAction>), HandleError> {
        match req {
            Request::ListProcesses => {
                Ok((Response::ProcessList(panels::process::snapshot_default()), None))
            }
            Request::ListServices => Ok((Response::ServiceList(panels::services::snapshot()), None)),
            Request::GetSystemInfo => Ok((Response::SystemInfo(panels::sysinfo::snapshot()), None)),
            Request::ReadEventLog { channel, max } => {
                Ok((Response::EventLog(panels::eventlog::query(channel, *max)), None))
            }
            Request::BrowseDirectory { path } => {
                let listing = panels::file::list(path).map_err(|e| HandleError::Exec(e.to_string()))?;
                Ok((Response::DirectoryListing(listing), None))
            }
            Request::KillProcess { pid, .. } => {
                // Guard rail already refused protected images and the agent itself.
                ops::process::kill(*pid, 1).map_err(op_err)?;
                Ok((Response::Ack, None))
            }
            Request::ControlService { service, verb } => {
                let v = match verb {
                    ServiceVerb::Start => ops::service::Verb::Start,
                    ServiceVerb::Stop => ops::service::Verb::Stop,
                    ServiceVerb::Restart => ops::service::Verb::Restart,
                };
                ops::service::control(service, v).map_err(op_err)?;
                Ok((Response::Ack, None))
            }
            Request::ReadRegistry { path, value_name } => {
                let value = ops::registry::read_string(path, value_name).map_err(op_err)?;
                Ok((Response::RegistryValue(value), None))
            }
            Request::WriteRegistry { path, value_name, new_value } => {
                // The op returns the prior value; fold it into the audit action so the tamper-
                // evident trail records the real before→after, not just the intended new value.
                let before = ops::registry::write_string(path, value_name, new_value).map_err(op_err)?;
                let action = AuditAction::RegistryWrite {
                    path: format!("{path}\\{value_name}"),
                    value: value_name.clone(),
                    before,
                    after: new_value.clone(),
                };
                Ok((Response::Ack, Some(action)))
            }
            // The interactive shell has its own gated entry point because a live session can't
            // live in `Response`. Reaching here means a caller routed a shell through `handle`
            // by mistake.
            Request::OpenShell { .. } => Err(HandleError::Exec(
                "open a shell via Dispatcher::open_shell, not handle".into(),
            )),
            // File operations are routed to `handle_file_op` before `execute` is reached.
            Request::CreateDirectory { .. }
            | Request::RenamePath { .. }
            | Request::DeletePath { .. }
            | Request::PlaceUpload { .. }
            | Request::DiscardUpload { .. } => {
                Err(HandleError::Exec("file operations go through handle_file_op".into()))
            }
        }
    }
}

/// Map a mutating-op error to a dispatcher execution error (audited as `Outcome::Failed`).
fn op_err(e: ops::OpError) -> HandleError {
    HandleError::Exec(e.to_string())
}

/// A shell that passed the dispatcher gate and is now live. Handed to the transport, which
/// splits it and pumps bytes; `shell_id` ties the transcript's `ShellData`/`ShellClose` audit
/// records back to the `ShellOpen` event.
#[cfg(windows)]
pub struct AuthorizedShell {
    pub shell_id: uuid::Uuid,
    pub session: shell::ShellSession,
}

/// Map a run-as request to its audit identity (no secrets; username left blank until the token
/// path resolves it).
fn run_as_to_audit(run_as: &RunAsRequest) -> audit::RunAs {
    match run_as {
        RunAsRequest::System => audit::RunAs::System,
        RunAsRequest::LoggedInUser => audit::RunAs::LoggedInUser { username: String::new() },
        RunAsRequest::Credential => {
            audit::RunAs::Credential { username: String::new(), domain: String::new() }
        }
    }
}

/// Per-tool typed response payloads, serialized to the technician UI. Adjacently tagged
/// (`{"type": "...", "data": ...}`) to match [`Request`], so the web console decodes each
/// response by its `type` and renders the matching panel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Response {
    Ack,
    ShellOpened { shell_id: uuid::Uuid },
    ProcessList(Vec<panels::process::ProcessRow>),
    ServiceList(Vec<panels::services::ServiceRow>),
    SystemInfo(panels::sysinfo::SystemInfo),
    EventLog(Vec<panels::eventlog::EventLogRow>),
    DirectoryListing(panels::file::DirListing),
    /// A single registry value read (`None` when the key/value doesn't exist).
    RegistryValue(Option<String>),
}

/// Map a request to its audit action shape (without secrets).
fn describe(req: &Request) -> AuditAction {
    match req {
        Request::ListProcesses => AuditAction::ConsentSignal { user_notified: false, policy: "read-only".into() },
        Request::ListServices => AuditAction::ConsentSignal { user_notified: false, policy: "read-only".into() },
        Request::GetSystemInfo => AuditAction::ConsentSignal { user_notified: false, policy: "read-only".into() },
        Request::ReadEventLog { .. } => AuditAction::ConsentSignal { user_notified: false, policy: "read-only".into() },
        Request::BrowseDirectory { path } => AuditAction::FileBrowse { path: path.clone() },
        Request::KillProcess { pid, image, owner } => {
            AuditAction::ProcessKill { pid: *pid, image: image.clone(), owner: owner.clone() }
        }
        Request::ControlService { service, verb } => AuditAction::ServiceControl {
            service: service.clone(),
            verb: format!("{verb:?}").to_lowercase(),
        },
        Request::ReadRegistry { path, value_name } => AuditAction::ConsentSignal {
            user_notified: false,
            policy: format!("read-only: {path}\\{value_name}"),
        },
        Request::WriteRegistry { path, value_name, new_value } => AuditAction::RegistryWrite {
            path: format!("{path}\\{value_name}"),
            value: value_name.clone(),
            before: None, // filled by the executor after reading the old value
            after: new_value.clone(),
        },
        Request::OpenShell { program, run_as, .. } => AuditAction::ShellOpen {
            shell_id: uuid::Uuid::nil(), // replaced with the real id on success (see open_shell)
            program: format!("{program:?}").to_lowercase(),
            identity: run_as_to_audit(run_as),
        },
        // docs/58: the REQUESTED operands, for records made before anything was resolved. A
        // resolved operation records the resolved paths instead (`fileops::Prepared::audit`).
        Request::CreateDirectory { path } => AuditAction::FileCreateDir { path: path.clone() },
        Request::RenamePath { from, to } => AuditAction::FileRename { from: from.clone(), to: to.clone() },
        Request::DeletePath { path } => AuditAction::FileDelete { path: path.clone() },
        Request::PlaceUpload { transfer_id, dest_dir } => AuditAction::FilePlace {
            transfer_id: *transfer_id,
            sha256: String::new(),
            to: dest_dir.clone(),
        },
        Request::DiscardUpload { transfer_id } => AuditAction::FileDelete { path: format!("upload {transfer_id}") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dispatcher over an IDENTIFIED chain, which is what production always has: a grant's
    /// `technician_id` is minted server-side as `Grants.Mint(p.UserID, …)` and its `session_id` is
    /// either the console's or a control-plane-substituted uuid, so neither is ever nil.
    ///
    /// These ids used to be `Uuid::nil()`. That was invisible while `Dispatcher::record` sealed
    /// unconditionally, and it made every test here exercise a chain that `/audit/ingest` would have
    /// answered 403 — i.e. the tests asserted on events production could never have delivered. Once
    /// `record` became guarded the fixture stopped sealing at all, which is how the drift surfaced.
    fn dispatcher_with(caps: Vec<Capability>) -> Dispatcher {
        let grant = Grant {
            technician_id: uuid::Uuid::from_u128(0x7ec4),
            session_id: uuid::Uuid::from_u128(0x5e55),
            machine_id: uuid::Uuid::from_u128(0x111),
            capabilities: caps,
        };
        Dispatcher::new(grant, "rmt-agent.exe")
    }

    /// The protected-process guard must judge the process the PID actually names, not the `image`
    /// string the request supplies.
    ///
    /// PREMISE, declared locally: `image` is caller-controlled. While the guard read it, the
    /// protected-process list was advisory — a caller wanting to kill `lsass.exe` sent lsass's pid
    /// with `image: "notepad.exe"` and the guard waved it through, then the audit event recorded the
    /// name that was claimed rather than the process that died.
    ///
    /// This test cannot use lsass (killing it bluescreens the machine, and the point is to prove the
    /// DENY happens before any of that). Instead it aims at THIS TEST PROCESS and declares the test
    /// process's own image as the agent's image, so the "cannot terminate the agent itself" rule is
    /// the one that must fire. That rule keys on the resolved name, so it fires only if the pid was
    /// resolved — which is exactly the property under test. Nothing is ever terminated: the request
    /// is refused at authorization, several steps before `ops::process::kill`.
    #[test]
    fn process_kill_guard_uses_the_resolved_image_not_the_claimed_one() {
        let me = std::process::id();
        let my_image = super::ops::process::image_name_for_pid(me)
            .expect("premise not met: this test process's own pid must resolve to an image name");

        // The dispatcher believes the AGENT is running as this test binary. Non-nil ids because a
        // real grant always carries server-minted ones, and a nil pair leaves the chain
        // unidentified — which now seals nothing, so the audit assertions below would be vacuous.
        let grant = Grant {
            technician_id: uuid::Uuid::from_u128(0x7ec4),
            session_id: uuid::Uuid::from_u128(0x5e55),
            machine_id: uuid::Uuid::from_u128(0x111),
            capabilities: vec![Capability::ProcessKill],
        };
        let mut disp = Dispatcher::new(grant, my_image.clone());

        // Negative control FIRST: an honest request for an unprotected pid is NOT refused by the
        // guard. Without this leg, a guard that denied every kill would satisfy the assertion below.
        // A pid that cannot exist resolves to None, so it must be denied for the *unresolvable*
        // reason and never for "this is the agent" — that distinction is what the assertion pins.
        let unresolvable = disp.authorize(
            &Request::KillProcess { pid: u32::MAX, image: my_image.clone(), owner: String::new() },
            Confirmation::Provided,
            1,
        );
        match unresolvable {
            Err((_, HandleError::Refused { reason })) => assert!(
                reason.contains("cannot determine"),
                "an unresolvable pid must be denied as unresolvable, got {reason:?}"
            ),
            other => panic!("an unresolvable pid must be refused, got {other:?}"),
        }

        // The measurement: the pid IS the agent, but the request claims a harmless image.
        let lied = disp.authorize(
            &Request::KillProcess { pid: me, image: "notepad.exe".into(), owner: String::new() },
            Confirmation::Provided,
            2,
        );
        match lied {
            Err((ev, HandleError::Refused { reason })) => {
                assert!(
                    reason.contains("agent itself"),
                    "SECURITY: the guard judged the CLAIMED image; refusal reason was {reason:?}"
                );
                assert!(
                    matches!(ev.outcome, Outcome::Denied { .. }),
                    "the refusal must be recorded as Denied, got {:?}",
                    ev.outcome
                );
            }
            other => panic!(
                "SECURITY: killing the agent's own pid was permitted because the request named a \
                 different image: {other:?}"
            ),
        }
    }

    // ---------------------------------------------------------------------------------------
    // ADR-008: file transfer is grant-scoped and audits into the SAME session chain.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn file_transfer_requires_the_direction_matching_capability() {
        // Upload needs FileUpload; download needs FileDownload. Holding one must not grant the
        // other — a read-only technician may pull a file but must not push one.
        let mut down_only = dispatcher_with(vec![Capability::FileDownload]);
        assert!(down_only.allows_file_transfer(Direction::Output));
        assert!(!down_only.allows_file_transfer(Direction::Input));

        let mut up_only = dispatcher_with(vec![Capability::FileUpload]);
        assert!(up_only.allows_file_transfer(Direction::Input));
        assert!(!up_only.allows_file_transfer(Direction::Output));

        let (ev, allowed) = down_only.record_file_transfer(
            Direction::Input, r"C:\t\x.bin", "abc", 10, Outcome::Ok, 1,
        );
        assert!(!allowed, "an upload without FileUpload must be refused");
        assert!(
            matches!(ev.outcome, Outcome::Denied { .. }),
            "the refusal must be recorded as Denied, got {:?}",
            ev.outcome
        );

        let (ev, allowed) = up_only.record_file_transfer(
            Direction::Output, r"C:\t\x.bin", "abc", 10, Outcome::Ok, 1,
        );
        assert!(!allowed, "a download without FileDownload must be refused");
        assert!(matches!(ev.outcome, Outcome::Denied { .. }));
    }

    #[test]
    fn granted_file_transfer_is_allowed_and_records_the_real_figures() {
        let mut d = dispatcher_with(vec![Capability::FileUpload, Capability::FileDownload]);
        let (ev, allowed) = d.record_file_transfer(
            Direction::Input,
            r"C:\transfers\report.pdf",
            "deadbeef",
            4096,
            Outcome::Ok,
            42,
        );
        assert!(allowed);
        assert!(matches!(ev.outcome, Outcome::Ok));
        match &ev.action {
            AuditAction::FileTransfer { direction, path, sha256, bytes } => {
                assert!(matches!(direction, Direction::Input));
                assert_eq!(path, r"C:\transfers\report.pdf");
                assert_eq!(sha256, "deadbeef");
                assert_eq!(*bytes, 4096);
            }
            other => panic!("expected a FileTransfer audit action, got {other:?}"),
        }
        assert_eq!(ev.occurred_at_unix_ms, 42);
    }

    #[test]
    fn a_transfer_that_failed_after_authorization_is_recorded_as_failed() {
        // The trail must distinguish "refused" from "broke": an authorized transfer whose digest
        // did not verify is Failed, not Denied.
        let mut d = dispatcher_with(vec![Capability::FileUpload]);
        let (ev, allowed) = d.record_file_transfer(
            Direction::Input,
            r"C:\t\x.bin",
            "actualdigest",
            7,
            Outcome::Failed { error: "sha256 mismatch".into() },
            1,
        );
        assert!(allowed, "the capability was held; the transfer was authorized");
        match &ev.outcome {
            Outcome::Failed { error } => assert!(error.contains("sha256 mismatch")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn file_transfer_events_join_the_session_chain_and_verify() {
        // The whole point of ADR-008: file-transfer events are sealed into the SAME chain as
        // backstage actions, interleaved in real order, and the chain still verifies.
        let mut d = dispatcher_with(vec![
            Capability::FileBrowse,
            Capability::FileUpload,
            Capability::FileDownload,
        ]);
        let (browse, _) = d.handle(
            Request::BrowseDirectory { path: r"C:\Windows".into() },
            Confirmation::NotProvided,
            1,
        );
        let (up, _) = d.record_file_transfer(Direction::Input, "a.bin", "aa", 1, Outcome::Ok, 2);
        let (down, _) = d.record_file_transfer(Direction::Output, "b.bin", "bb", 2, Outcome::Ok, 3);

        let events = vec![browse.expect("browse is audited"), up, down];
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[1].seq, 1);
        assert_eq!(events[2].seq, 2);
        assert_eq!(events[1].prev_hash, events[0].hash, "upload chains onto the browse");
        assert_eq!(events[2].prev_hash, events[1].hash, "download chains onto the upload");
        audit::verify_chain(&events).expect("the mixed chain must verify");
    }

    #[test]
    fn kill_without_capability_is_denied_and_audited() {
        let mut d = dispatcher_with(vec![Capability::ProcessList]);
        let (ev, res) = d.handle(
            Request::KillProcess { pid: 100, image: "notepad.exe".into(), owner: "u".into() },
            Confirmation::NotProvided,
            1,
        );
        assert!(matches!(res, Err(HandleError::Denied(_))));
        assert!(ev.is_some(), "denied attempts must still be audited");
    }

    // Windows only: the guard judges the process the pid really names, and pid 4 is the Windows
    // System process. On other systems pid 4 is an ordinary process, so the premise does not hold.
    #[cfg(windows)]
    #[test]
    fn killing_lsass_is_refused_even_with_capability() {
        let mut d = dispatcher_with(vec![Capability::ProcessKill]);
        let (_ev, res) = d.handle(
            Request::KillProcess { pid: 4, image: "lsass.exe".into(), owner: "SYSTEM".into() },
            Confirmation::Provided,
            1,
        );
        assert!(matches!(res, Err(HandleError::Refused { .. })));
    }

    #[test]
    fn granted_process_list_returns_real_data_and_audits_ok() {
        let mut d = dispatcher_with(vec![Capability::ProcessList]);
        let (ev, res) = d.handle(Request::ListProcesses, Confirmation::NotProvided, 1);
        match res {
            Ok(Response::ProcessList(rows)) => assert!(!rows.is_empty()),
            other => panic!("expected a process list, got {other:?}"),
        }
        let ev = ev.expect("every action is audited");
        assert!(matches!(ev.outcome, Outcome::Ok));
    }

    #[test]
    fn service_list_without_capability_is_denied_and_audited() {
        let mut d = dispatcher_with(vec![Capability::ProcessList]); // wrong capability
        let (ev, res) = d.handle(Request::ListServices, Confirmation::NotProvided, 1);
        assert!(matches!(res, Err(HandleError::Denied(_))));
        assert!(ev.is_some(), "denied reads must still be audited");
    }

    #[cfg(windows)]
    #[test]
    fn granted_service_list_returns_real_data_and_audits_ok() {
        let mut d = dispatcher_with(vec![Capability::ServiceList]);
        let (ev, res) = d.handle(Request::ListServices, Confirmation::NotProvided, 1);
        match res {
            Ok(Response::ServiceList(rows)) => assert!(!rows.is_empty()),
            other => panic!("expected a service list, got {other:?}"),
        }
        assert!(matches!(ev.unwrap().outcome, Outcome::Ok));
    }

    #[test]
    fn browse_without_capability_is_denied_and_audited() {
        let mut d = dispatcher_with(vec![Capability::ProcessList]); // wrong capability
        let (ev, res) = d.handle(
            Request::BrowseDirectory { path: String::new() },
            Confirmation::NotProvided,
            1,
        );
        assert!(matches!(res, Err(HandleError::Denied(_))));
        assert!(ev.is_some(), "denied reads must still be audited");
    }

    #[test]
    fn granted_browse_lists_top_level_and_audits_the_path() {
        let mut d = dispatcher_with(vec![Capability::FileBrowse]);
        // A directory of the test's own, not %TEMP% itself: a busy machine's temp folder can exceed
        // the browse entry limit and turn this into a test of somebody else's disk.
        let dir = std::env::temp_dir().join(format!("rmt-browse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let temp = dir.to_string_lossy().into_owned();
        let (ev, res) = d.handle(
            Request::BrowseDirectory { path: temp.clone() },
            Confirmation::NotProvided,
            1,
        );
        match res {
            Ok(Response::DirectoryListing(listing)) => assert_eq!(listing.path, temp),
            other => panic!("expected a directory listing, got {other:?}"),
        }
        // The audit event records exactly which path was browsed.
        let ev = ev.expect("browse must be audited");
        assert!(matches!(ev.outcome, Outcome::Ok));
        match ev.action {
            AuditAction::FileBrowse { path } => assert_eq!(path, temp),
            other => panic!("expected a FileBrowse audit action, got {other:?}"),
        }
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn browsing_a_missing_directory_is_audited_as_failed() {
        let mut d = dispatcher_with(vec![Capability::FileBrowse]);
        let (ev, res) = d.handle(
            Request::BrowseDirectory { path: "nope/does/not/exist_98765".into() },
            Confirmation::NotProvided,
            1,
        );
        assert!(matches!(res, Err(HandleError::Exec(_))));
        assert!(matches!(ev.unwrap().outcome, Outcome::Failed { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn granted_system_info_returns_data_and_audits_ok() {
        let mut d = dispatcher_with(vec![Capability::SystemInfoRead]);
        let (ev, res) = d.handle(Request::GetSystemInfo, Confirmation::NotProvided, 1);
        match res {
            Ok(Response::SystemInfo(info)) => assert!(info.total_memory_bytes > 0),
            other => panic!("expected system info, got {other:?}"),
        }
        assert!(matches!(ev.unwrap().outcome, Outcome::Ok));
    }

    #[cfg(windows)]
    #[test]
    fn granted_event_log_read_returns_data_and_audits_ok() {
        let mut d = dispatcher_with(vec![Capability::EventLogRead]);
        let (ev, res) = d.handle(
            Request::ReadEventLog { channel: "System".into(), max: 5 },
            Confirmation::NotProvided,
            1,
        );
        match res {
            Ok(Response::EventLog(rows)) => assert!(!rows.is_empty()),
            other => panic!("expected event log rows, got {other:?}"),
        }
        assert!(matches!(ev.unwrap().outcome, Outcome::Ok));
    }

    #[cfg(windows)]
    #[test]
    fn granted_process_kill_terminates_child_and_audits_ok() {
        // Spawn a child we own, then kill it end-to-end through the dispatcher.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 30 127.0.0.1 >NUL"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn child");
        let pid = child.id();

        let mut d = dispatcher_with(vec![Capability::ProcessKill]);
        let (ev, res) = d.handle(
            Request::KillProcess { pid, image: "cmd.exe".into(), owner: "me".into() },
            Confirmation::NotProvided,
            1,
        );
        assert!(matches!(res, Ok(Response::Ack)), "kill should succeed, got {res:?}");
        assert!(matches!(ev.unwrap().outcome, Outcome::Ok));

        let status = child.wait().expect("wait");
        assert!(!status.success(), "the process was terminated");
    }

    #[cfg(windows)]
    #[test]
    fn registry_write_audit_records_real_before_and_after() {
        let path = format!(r"HKCU\Software\RmtAgentTest\audit\{}", std::process::id());
        let mut d = dispatcher_with(vec![Capability::RegistryWrite]);

        // First write: audit before is None (no prior value), after is what we set.
        let (ev1, _) = d.handle(
            Request::WriteRegistry { path: path.clone(), value_name: "K".into(), new_value: "one".into() },
            Confirmation::NotProvided,
            1,
        );
        match ev1.unwrap().action {
            AuditAction::RegistryWrite { before, after, .. } => {
                assert_eq!(before, None);
                assert_eq!(after, "one");
            }
            other => panic!("expected RegistryWrite audit, got {other:?}"),
        }

        // Overwrite: audit before is the real prior value read from the registry.
        let (ev2, _) = d.handle(
            Request::WriteRegistry { path: path.clone(), value_name: "K".into(), new_value: "two".into() },
            Confirmation::NotProvided,
            2,
        );
        match ev2.unwrap().action {
            AuditAction::RegistryWrite { before, after, .. } => {
                assert_eq!(before.as_deref(), Some("one"), "audit captured the real prior value");
                assert_eq!(after, "two");
            }
            other => panic!("expected RegistryWrite audit, got {other:?}"),
        }

        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(format!(r"Software\RmtAgentTest\audit\{}", std::process::id()));
    }

    #[cfg(windows)]
    #[test]
    fn granted_registry_write_and_read_roundtrip_through_dispatcher() {
        // HKCU is non-sensitive (no confirmation gate) and writable without elevation.
        let path = format!(r"HKCU\Software\RmtAgentTest\dispatcher\{}", std::process::id());
        let mut d = dispatcher_with(vec![Capability::RegistryWrite, Capability::RegistryRead]);

        let (wev, wres) = d.handle(
            Request::WriteRegistry { path: path.clone(), value_name: "Marker".into(), new_value: "hi".into() },
            Confirmation::NotProvided,
            1,
        );
        assert!(matches!(wres, Ok(Response::Ack)), "write should succeed, got {wres:?}");
        assert!(matches!(wev.unwrap().outcome, Outcome::Ok));

        let (_rev, rres) = d.handle(
            Request::ReadRegistry { path: path.clone(), value_name: "Marker".into() },
            Confirmation::NotProvided,
            2,
        );
        match rres {
            Ok(Response::RegistryValue(Some(v))) => assert_eq!(v, "hi"),
            other => panic!("expected the value we wrote, got {other:?}"),
        }

        // Clean up the test subtree.
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(format!(r"Software\RmtAgentTest\dispatcher\{}", std::process::id()));
    }

    #[test]
    fn shell_without_capability_is_denied_and_audited() {
        // Holds ShellAsUser but asks for a SYSTEM shell -> denied on the missing capability.
        let mut d = dispatcher_with(vec![Capability::ShellAsUser]);
        let req = Request::OpenShell {
            program: ShellKind::PowerShell,
            cols: 80,
            rows: 25,
            run_as: RunAsRequest::System,
        };
        let (ev, res) = d.handle(req, Confirmation::NotProvided, 1);
        assert!(matches!(res, Err(HandleError::Denied(_))));
        let ev = ev.expect("denied shell opens must still be audited");
        assert!(matches!(ev.outcome, Outcome::Denied { .. }));
    }

    #[test]
    fn credential_shell_always_needs_confirmation() {
        // Even WITH the capability, a supplied-credential shell demands typed confirmation.
        let mut d = dispatcher_with(vec![Capability::ShellAsCredential]);
        let req = Request::OpenShell {
            program: ShellKind::PowerShell,
            cols: 80,
            rows: 25,
            run_as: RunAsRequest::Credential,
        };
        let (_ev, res) = d.handle(req, Confirmation::NotProvided, 1);
        assert!(matches!(res, Err(HandleError::NeedsConfirmation { .. })));
    }

    #[test]
    fn shell_routed_through_handle_is_rejected_toward_open_shell() {
        // A shell that passes the gate must not be spawned via `handle` (no session in Response).
        let mut d = dispatcher_with(vec![Capability::ShellAsUser]);
        let req = Request::OpenShell {
            program: ShellKind::PowerShell,
            cols: 80,
            rows: 25,
            run_as: RunAsRequest::LoggedInUser,
        };
        let (_ev, res) = d.handle(req, Confirmation::NotProvided, 1);
        match res {
            Err(HandleError::Exec(msg)) => assert!(msg.contains("open_shell")),
            other => panic!("expected an Exec error pointing at open_shell, got {other:?}"),
        }
    }

    #[test]
    fn sensitive_registry_write_needs_confirmation() {
        let mut d = dispatcher_with(vec![Capability::RegistryWrite]);
        let req = Request::WriteRegistry {
            path: r"HKLM\SYSTEM\CurrentControlSet\Services\Foo".into(),
            value_name: "ImagePath".into(),
            new_value: r"C:\evil.exe".into(),
        };
        // Without confirmation the dispatcher's confirm gate rejects a *sensitive* HKLM write
        // BEFORE it reaches execution — so this asserts the gate without performing any write.
        let (_ev, res) = d.handle(req, Confirmation::NotProvided, 1);
        assert!(matches!(res, Err(HandleError::NeedsConfirmation { .. })));
        // NOTE: we deliberately do NOT re-issue this with Confirmation::Provided. Doing so would
        // perform a REAL HKLM `Services\Foo` = `C:\evil.exe` write (this is not stubbed), which
        // persists a fake-service key when the suite runs elevated and is environment-dependent
        // (the write only fails on a non-elevated box). Execution-after-confirmation is covered
        // safely elsewhere (the HKCU round-trip in `ops::registry::tests`).
    }

}
