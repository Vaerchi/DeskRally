//! Under the Hood SYSTEM terminal, phase 3 (docs/76): the per-session relay between the console's `shell` data channel
//! and one [`SystemShell`].
//!
//! Who may type is decided HERE, on every input frame and once a second, not only at open (review finding 1):
//! [`ShellAuthority`] holds what the session loop knows (the mutation gate, the grant's generation and expiry,
//! view-only, session end) and [`ShellAuthority::check`] fails the moment any of it changes. A failed check kills the
//! shell's whole process tree and says why. Static refusals (an observer session; a host running as the guest's USER,
//! i.e. an attended session, where "SYSTEM" would not be SYSTEM and the guest never consented to a shell) are decided
//! before anything opens.
//!
//! Wire (text = JSON control, binary = terminal bytes):
//! - console -> agent: `{"t":"open","cols":N,"rows":N,"token":"..."?}`, `{"t":"resize","cols":N,"rows":N}`, `{"t":"close"}`
//! - agent -> console: `{"t":"needs_confirmation","reason":..,"token":..}`, `{"t":"refused","reason":..}`,
//!   `{"t":"opened","shell_id":..}`, `{"t":"closed","reason":..,"exit_code":N?}`. Audit events (ShellOpen, denials,
//!   ShellClose) travel on the SESSION channel as file-transfer `Audit` messages, never on this one.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_agent::backstage::gate::MutationGate;
use rmt_agent::backstage::{Confirmation, Dispatcher, HandleError};
use rmt_transport_webrtc::{ShellChannel, ShellMessage};
use serde::Deserialize;
use serde_json::json;

use crate::system_shell::SystemShell;

/// No keystroke AND no output for this long closes the shell.
pub(crate) const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
/// Stop reading shell output while more than this is queued on the data channel (review finding 5): the child then
/// blocks on a full pipe instead of output being dropped.
const OUTPUT_HIGH_WATER: usize = 512 * 1024;
const NO_EXPIRY: i64 = i64::MIN;
/// Most input chunks queued for the shell's writer thread (each at most 16 KiB): a shell that stops reading input
/// cannot make the agent buffer without limit (security review M3).
const INPUT_QUEUE: usize = 256;

/// What the session loop knows that decides whether the shell may keep running.
#[derive(Debug)]
pub(crate) struct ShellAuthority {
    gate: Arc<MutationGate>,
    grant_generation: AtomicU64,
    /// The grant's expiry as a MONOTONIC deadline (milliseconds since `base`), converted once when the grant is
    /// installed: a wall-clock change on the machine cannot extend it (security review M2).
    grant_deadline_ms: AtomicI64,
    view_only: AtomicBool,
    /// docs/69: the session is bound (or binding is not enforced). Same predicate that gates media (review L5).
    bound: AtomicBool,
    ended: AtomicBool,
    base: Instant,
}

/// What was true when the shell opened; every later check compares against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Admission {
    stamp: u64,
    generation: u64,
}

impl ShellAuthority {
    pub(crate) fn new(gate: Arc<MutationGate>) -> Self {
        Self {
            gate,
            grant_generation: AtomicU64::new(0),
            grant_deadline_ms: AtomicI64::new(NO_EXPIRY),
            view_only: AtomicBool::new(false),
            bound: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            base: Instant::now(),
        }
    }

    /// Now, on this authority's monotonic clock (what `admit` and `check` take).
    pub(crate) fn now(&self) -> i64 {
        i64::try_from(self.base.elapsed().as_millis()).unwrap_or(i64::MAX)
    }

    /// A grant was installed (or replaced): a shell opened under an earlier grant must stop. `expires_at_ms` is wall
    /// time (the grant's claim); `i64::MAX` means no expiry.
    pub(crate) fn set_grant(&self, expires_at_ms: i64) {
        self.set_grant_at(expires_at_ms, wall_now_ms(), self.now());
    }

    fn set_grant_at(&self, expires_at_ms: i64, wall_now_ms: i64, mono_now_ms: i64) {
        let deadline = if expires_at_ms == i64::MAX {
            i64::MAX
        } else {
            mono_now_ms.saturating_add(expires_at_ms.saturating_sub(wall_now_ms).max(0))
        };
        self.grant_deadline_ms.store(deadline, Ordering::SeqCst);
        self.grant_generation.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn set_bound(&self, bound: bool) {
        self.bound.store(bound, Ordering::SeqCst);
    }

    pub(crate) fn is_bound(&self) -> bool {
        self.bound.load(Ordering::SeqCst)
    }

    pub(crate) fn set_view_only(&self, view_only: bool) {
        self.view_only.store(view_only, Ordering::SeqCst);
    }

    /// The session is over (any path: end, lease lapse, transfer arriving as end). Final.
    pub(crate) fn end(&self) {
        self.ended.store(true, Ordering::SeqCst);
    }

    /// May a shell open now? Returns what to compare later checks against.
    pub(crate) fn admit(&self, now_ms: i64) -> Result<Admission, &'static str> {
        let a = Admission {
            stamp: self.gate.stamp(),
            generation: self.grant_generation.load(Ordering::SeqCst),
        };
        self.check(&a, now_ms).map(|()| a)
    }

    /// May a shell admitted as `a` keep running? The first reason it may not, if any.
    pub(crate) fn check(&self, a: &Admission, now_ms: i64) -> Result<(), &'static str> {
        if self.ended.load(Ordering::SeqCst) {
            return Err("the session ended");
        }
        if self.view_only.load(Ordering::SeqCst) {
            return Err("the session became view-only");
        }
        self.check_read(a, now_ms)?;
        // The shell (a SYSTEM process the technician types into) also ends with the grant that admitted it.
        if self.grant_generation.load(Ordering::SeqCst) != a.generation {
            return Err("access was replaced");
        }
        let deadline = self.grant_deadline_ms.load(Ordering::SeqCst);
        if deadline == NO_EXPIRY {
            return Err("no access has been granted");
        }
        if now_ms >= deadline {
            return Err("access expired");
        }
        Ok(())
    }

    /// docs/77 phase 3: may a READ (a streamed download) admitted as `a` continue? The session-level rules of
    /// [`Self::check`] (ended, bound, indicator) but NOT view-only (an observer may download today) and NOT the grant's
    /// expiry or generation: the session-channel download checks the grant once, at install, and the console mints a
    /// 5-minute grant once per session, so tying reads to it failed every streamed Get after five minutes (1.3.39
    /// release review H1). The streamed download re-checks the dispatcher's permission every second instead.
    pub(crate) fn admit_read(&self, now_ms: i64) -> Result<Admission, &'static str> {
        let a = Admission {
            stamp: self.gate.stamp(),
            generation: self.grant_generation.load(Ordering::SeqCst),
        };
        self.check_read(&a, now_ms).map(|()| a)
    }

    pub(crate) fn check_read(&self, a: &Admission, now_ms: i64) -> Result<(), &'static str> {
        if self.ended.load(Ordering::SeqCst) {
            return Err("the session ended");
        }
        if !self.bound.load(Ordering::SeqCst) {
            return Err("the session is not bound to this console");
        }
        if !self.gate.admits(a.stamp) {
            return Err("the on-screen indicator was lost");
        }
        let _ = now_ms; // reads are not bounded by the grant's deadline (see admit_read)
        Ok(())
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum ShellRequest {
    Open { cols: u16, rows: u16, #[serde(default)] token: Option<String> },
    Resize { cols: u16, rows: u16 },
    Close,
}

/// Everything the relay needs from the session.
pub(crate) struct ShellRelayContext {
    pub(crate) authority: Arc<ShellAuthority>,
    /// The session's current Backstage dispatcher (a twin), or `None` before any grant. The relay locks it only to
    /// authorize an open and to record audit events.
    pub(crate) dispatcher: Arc<Mutex<Option<Dispatcher>>>,
    /// Decided once for the session: an observer, or a host running as the guest's user.
    pub(crate) static_refusal: Option<&'static str>,
    /// Told when a shell opens or closes (the presence pill shows "terminal open").
    pub(crate) on_open_change: Box<dyn Fn(bool) + Send + Sync>,
    /// Every event this relay seals goes to the SESSION loop, which sends it on the session channel (as hand-off
    /// audit does). Never on the shell channel: the console may close that mid-session, and a sealed event that is
    /// never delivered is a permanent seq gap that refuses every later event of the chain.
    pub(crate) audit_out: tokio::sync::mpsc::UnboundedSender<rmt_agent::backstage::audit::AuditEvent>,
    /// The id of the shell this relay has open, if any. Teardown reads it after the relay task ended: a relay cut
    /// short (aborted) never recorded ShellClose, and teardown records it instead (re-review N2).
    pub(crate) open_shell: Arc<Mutex<Option<uuid::Uuid>>>,
}

/// Before the session is bound (docs/69) the shell channel says nothing specific (re-review N4).
const NOT_AVAILABLE: &str = "a shell is not available";

fn wall_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct OpenShell {
    shell: SystemShell,
    shell_id: uuid::Uuid,
    admission: Admission,
    input: std::sync::mpsc::SyncSender<Vec<u8>>,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    last_activity: Instant,
}

/// Serve one shell channel until it closes. One shell at a time; a new `open` after a close starts another. The
/// session's relay task calls this for each shell channel the console opens (one at a time), with the same context.
pub(crate) async fn run(mut chan: ShellChannel, ctx: &ShellRelayContext) {
    let mut open: Option<OpenShell> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // Backpressure (security review H2): while the channel holds more than the high-water mark we stop READING shell
    // output (the child blocks on its pipe), but the loop keeps serving input, closes and the authority checks.
    let mut paused = false;
    // A fixed 20 ms cadence while paused: a sleep re-created on every loop pass never fired while input kept
    // arriving faster than that, which kept output paused (re-review N5).
    let mut drain_tick = tokio::time::interval(Duration::from_millis(20));
    drain_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            msg = chan.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    ShellMessage::Binary(bytes) => {
                        let Some(o) = open.as_mut() else { continue };
                        if let Err(reason) = ctx.authority.check(&o.admission, ctx.authority.now()) {
                            close(&chan, ctx, &mut open, reason).await;
                            continue;
                        }
                        o.last_activity = Instant::now();
                        match o.input.try_send(bytes) {
                            Ok(()) => {}
                            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                close(&chan, ctx, &mut open, "the shell stopped reading input").await;
                            }
                            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                close(&chan, ctx, &mut open, "the shell stopped accepting input").await;
                            }
                        }
                    }
                    ShellMessage::Text(text) => match serde_json::from_str::<ShellRequest>(&text) {
                        Ok(ShellRequest::Open { cols, rows, token }) => {
                            if !ctx.authority.is_bound() {
                                send(&chan, json!({"t": "refused", "reason": NOT_AVAILABLE})).await;
                            } else if open.is_some() {
                                send(&chan, json!({"t": "refused", "reason": "a shell is already open"})).await;
                            } else {
                                open = try_open(&chan, ctx, cols, rows, token).await;
                            }
                        }
                        Ok(ShellRequest::Resize { cols, rows }) => {
                            if let Some(o) = open.as_ref() {
                                o.shell.resize(cols, rows);
                            }
                        }
                        Ok(ShellRequest::Close) => close(&chan, ctx, &mut open, "closed by the technician").await,
                        Err(_) if !ctx.authority.is_bound() => send(&chan, json!({"t": "refused", "reason": NOT_AVAILABLE})).await,
                        Err(_) => send(&chan, json!({"t": "refused", "reason": "malformed shell request"})).await,
                    },
                }
            }
            chunk = recv_output(&mut open), if !paused => {
                match chunk {
                    Some(bytes) => {
                        if let Some(o) = open.as_mut() {
                            o.last_activity = Instant::now();
                        }
                        if chan.send_binary(&bytes).await.is_err() {
                            break;
                        }
                        paused = chan.buffered_amount().await > OUTPUT_HIGH_WATER;
                    }
                    None => close(&chan, ctx, &mut open, "the shell exited").await,
                }
            }
            _ = drain_tick.tick(), if paused => {
                if !chan.is_open() {
                    break;
                }
                paused = chan.buffered_amount().await > OUTPUT_HIGH_WATER;
            }
            _ = tick.tick() => {
                if let Some(o) = open.as_ref() {
                    if let Err(reason) = ctx.authority.check(&o.admission, ctx.authority.now()) {
                        close(&chan, ctx, &mut open, reason).await;
                    } else if o.last_activity.elapsed() >= IDLE_LIMIT {
                        close(&chan, ctx, &mut open, "idle for 30 minutes").await;
                    }
                }
            }
        }
    }
    // The channel is gone (session over or console closed it): never leave a shell behind.
    if open.is_some() {
        close(&chan, ctx, &mut open, "the console disconnected").await;
    }
    let _ = chan.close().await;
}
async fn recv_output(open: &mut Option<OpenShell>) -> Option<Vec<u8>> {
    match open.as_mut() {
        Some(o) => o.output.recv().await,
        None => std::future::pending().await,
    }
}

async fn send(chan: &ShellChannel, v: serde_json::Value) {
    let _ = chan.send_text(&v.to_string()).await;
}

fn send_audit(ctx: &ShellRelayContext, ev: rmt_agent::backstage::audit::AuditEvent) {
    // If the session loop is gone the session is ending; a gap can then only be the chain's last event.
    let _ = ctx.audit_out.send(ev);
}

async fn try_open(chan: &ShellChannel, ctx: &ShellRelayContext, cols: u16, rows: u16, token: Option<String>) -> Option<OpenShell> {
    if let Some(reason) = ctx.static_refusal {
        send(chan, json!({"t": "refused", "reason": reason})).await;
        return None;
    }
    let admission = match ctx.authority.admit(ctx.authority.now()) {
        Ok(a) => a,
        Err(reason) => {
            send(chan, json!({"t": "refused", "reason": reason})).await;
            return None;
        }
    };
    let confirmation = match token {
        Some(t) => Confirmation::Token(t),
        None => Confirmation::NotProvided,
    };
    // The lock is released before any await (a std MutexGuard is not Send, and must never be held across one).
    let authorized = {
        let mut guard = ctx.dispatcher.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_mut().map(|d| d.authorize_system_shell(cols, rows, confirmation, wall_now_ms()))
    };
    let Some((ev, res)) = authorized else {
        send(chan, json!({"t": "refused", "reason": "Under the Hood access has not been granted"})).await;
        return None;
    };
    send_audit(ctx, ev);
    let shell_id = match res {
        Ok(id) => id,
        Err(HandleError::NeedsConfirmation { reason, token }) => {
            send(chan, json!({"t": "needs_confirmation", "reason": reason, "token": token})).await;
            return None;
        }
        Err(e) => {
            send(chan, json!({"t": "refused", "reason": e.to_string()})).await;
            return None;
        }
    };
    let mut shell = match SystemShell::spawn(cols, rows) {
        Ok(s) => s,
        Err(e) => {
            record_close(chan, ctx, shell_id, None).await;
            send(chan, json!({"t": "refused", "reason": format!("the shell could not start: {e}")})).await;
            return None;
        }
    };
    let reader = shell.take_reader().expect("a fresh shell has its reader");
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                // blocking_send: a full queue blocks this thread, so the shell blocks on its pipe (no output is lost).
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let (in_tx, in_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(INPUT_QUEUE);
    let writer = shell_writer(&shell);
    std::thread::spawn(move || {
        while let Ok(bytes) = in_rx.recv() {
            if writer(&bytes).is_err() {
                break;
            }
        }
    });
    *ctx.open_shell.lock().unwrap_or_else(|p| p.into_inner()) = Some(shell_id);
    (ctx.on_open_change)(true);
    send(chan, json!({"t": "opened", "shell_id": shell_id})).await;
    Some(OpenShell { shell, shell_id, admission, input: in_tx, output: out_rx, last_activity: Instant::now() })
}

/// A writer the input thread can own: WriteFile on the shell's input pipe can block, so it never runs on the async
/// runtime. The pipe handle is duplicated into the closure.
fn shell_writer(shell: &SystemShell) -> impl Fn(&[u8]) -> std::io::Result<()> + Send + 'static {
    let input = shell.input_handle();
    move |bytes: &[u8]| match &input {
        Some(h) => crate::system_shell::write_all(h, bytes),
        None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
    }
}

async fn record_close(chan: &ShellChannel, ctx: &ShellRelayContext, shell_id: uuid::Uuid, exit_code: Option<i32>) {
    let ev = {
        let guard = ctx.dispatcher.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref().map(|d| d.record_shell_close(shell_id, exit_code, wall_now_ms()))
    };
    if let Some(ev) = ev {
        send_audit(ctx, ev);
    }
    let _ = chan;
}

async fn close(chan: &ShellChannel, ctx: &ShellRelayContext, open: &mut Option<OpenShell>, reason: &str) {
    let Some(o) = open.take() else { return };
    let OpenShell { mut shell, shell_id, .. } = o;
    // Killing waits (up to 5 s) for the process to go: never on the async runtime (security review M3).
    let exited_on_its_own = tokio::task::spawn_blocking(move || {
        let code = shell.exit_code();
        shell.kill();
        code
    })
    .await
    .ok()
    .flatten();
    let exit_code = exited_on_its_own.map(|c| c as i32);
    let o_shell_id = shell_id;
    record_close(chan, ctx, o_shell_id, exit_code).await;
    *ctx.open_shell.lock().unwrap_or_else(|p| p.into_inner()) = None;
    (ctx.on_open_change)(false);
    send(chan, json!({"t": "closed", "reason": reason, "exit_code": exit_code})).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> (Arc<MutationGate>, ShellAuthority) {
        let gate = Arc::new(MutationGate::new());
        let a = ShellAuthority::new(gate.clone());
        a.set_bound(true);
        (gate, a)
    }

    #[test]
    fn nothing_opens_without_a_grant() {
        let (_g, a) = authority();
        assert_eq!(a.admit(1_000), Err("no access has been granted"));
    }

    #[test]
    fn nothing_opens_before_the_session_is_bound() {
        let (_g, a) = authority();
        a.set_bound(false);
        a.set_grant_at(10_000, 0, 0);
        assert_eq!(a.admit(1_000), Err("the session is not bound to this console"));
        a.set_bound(true);
        let adm = a.admit(1_000).expect("admitted once bound");
        a.set_bound(false);
        assert_eq!(a.check(&adm, 1_000), Err("the session is not bound to this console"));
    }

    #[test]
    fn expiry_is_a_monotonic_deadline_fixed_when_the_grant_is_installed() {
        let (_g, a) = authority();
        // Installed at wall 1_000_000 (mono 500) with 60 s left: the deadline is mono 60_500, whatever the wall
        // clock does afterwards.
        a.set_grant_at(1_060_000, 1_000_000, 500);
        let adm = a.admit(600).expect("admitted");
        assert_eq!(a.check(&adm, 60_499), Ok(()));
        assert_eq!(a.check(&adm, 60_500), Err("access expired"));
        // An already-expired grant (the fail-closed install) admits nothing.
        a.set_grant_at(5, 10, 700);
        assert_eq!(a.admit(700), Err("access expired"));
        // No expiry.
        a.set_grant_at(i64::MAX, 10, 0);
        assert_eq!(a.admit(i64::MAX - 1), Ok(a.admit(0).unwrap()));
    }

    /// 1.3.39 release review H1: a READ (streamed download) outlives the grant's 5-minute deadline and a re-minted grant,
    /// like the session-channel download; it stops on session end, the indicator, and binding. View-only does not stop
    /// it (an observer may download).
    #[test]
    fn a_read_ignores_grant_expiry_and_replacement_but_not_the_session_rules() {
        let (gate, a) = authority();
        a.set_bound(true);
        a.set_grant_at(10_000, 0, 0);
        let adm = a.admit_read(1_000).expect("admitted");
        assert_eq!(a.check_read(&adm, 50_000), Ok(()), "past the grant's deadline");
        a.set_grant_at(99_000, 0, 0);
        assert_eq!(a.check_read(&adm, 50_000), Ok(()), "a re-minted grant");
        a.set_view_only(true);
        assert_eq!(a.check_read(&adm, 50_000), Ok(()), "view-only (observers read)");
        a.set_bound(false);
        assert_eq!(a.check_read(&adm, 50_000), Err("the session is not bound to this console"));
        a.set_bound(true);
        gate.revoke();
        assert_eq!(a.check_read(&adm, 50_000), Err("the on-screen indicator was lost"));
        gate.reopen();
        let adm = a.admit_read(50_000).expect("new read after the indicator returned");
        a.end();
        assert_eq!(a.check_read(&adm, 50_000), Err("the session ended"));
    }
    #[test]
    fn an_admitted_shell_keeps_running_until_anything_changes() {
        let (gate, a) = authority();
        a.set_grant_at(10_000, 0, 0);
        let adm = a.admit(1_000).expect("admitted");
        assert_eq!(a.check(&adm, 2_000), Ok(()));

        // Expiry is checked on every check, not only at open.
        assert_eq!(a.check(&adm, 10_000), Err("access expired"));

        // A replaced grant (even one that lasts longer) stops a shell opened under the old one.
        a.set_grant_at(99_000, 0, 0);
        assert_eq!(a.check(&adm, 2_000), Err("access was replaced"));
        let adm = a.admit(2_000).expect("re-admitted under the new grant");

        // Indicator loss revokes the gate; its return does not revive the old stamp.
        gate.revoke();
        assert_eq!(a.check(&adm, 3_000), Err("the on-screen indicator was lost"));
        gate.reopen();
        assert_eq!(a.check(&adm, 3_000), Err("the on-screen indicator was lost"));
        let adm = a.admit(3_000).expect("new work after the indicator returned");

        a.set_view_only(true);
        assert_eq!(a.check(&adm, 4_000), Err("the session became view-only"));
        assert_eq!(a.admit(4_000), Err("the session became view-only"));
        a.set_view_only(false);
        assert_eq!(a.check(&adm, 4_000), Ok(()));

        a.end();
        assert_eq!(a.check(&adm, 5_000), Err("the session ended"));
        assert_eq!(a.admit(5_000), Err("the session ended"));
    }

    #[test]
    fn requests_parse_strictly() {
        assert_eq!(
            serde_json::from_str::<ShellRequest>(r#"{"t":"open","cols":80,"rows":25}"#).unwrap(),
            ShellRequest::Open { cols: 80, rows: 25, token: None }
        );
        assert_eq!(
            serde_json::from_str::<ShellRequest>(r#"{"t":"open","cols":80,"rows":25,"token":"abc"}"#).unwrap(),
            ShellRequest::Open { cols: 80, rows: 25, token: Some("abc".into()) }
        );
        assert_eq!(serde_json::from_str::<ShellRequest>(r#"{"t":"close"}"#).unwrap(), ShellRequest::Close);
        assert!(serde_json::from_str::<ShellRequest>(r#"{"t":"exec","cmd":"whoami"}"#).is_err());
        assert!(serde_json::from_str::<ShellRequest>(r#"{"t":"open","cols":-1,"rows":25}"#).is_err());
    }
}
