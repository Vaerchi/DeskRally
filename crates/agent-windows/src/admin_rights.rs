//! docs/53: an attended session's "Request admin rights", end to end on the agent.
//!
//! The technician's `RequestAdminRights` arrives in the session loop, which calls
//! [`AdminRights::request`]. That checks the preconditions (§3.1 step 1) and answers at once when
//! they fail; otherwise it reports `Pending` and, on its own thread, shows the guest our explanation
//! (the pre-dialog), then asks Windows (UAC) through [`crate::elevation_win::request`]. Results go
//! to the session loop over a channel, which sends them to the controller as `AdminRightsResult`.
//! A grant attaches the helper to the session's [`ElevatedSink`]; its end is reported as `Ended`.
//!
//! One request at a time; a decline blocks another for [`DECLINE_COOLDOWN`] so a technician cannot
//! keep raising prompts on the guest's screen. Session end retires an outstanding request (a late
//! answer then does nothing) and detaches a granted helper.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_agent_core::control::{AdminRightsState, ControlMessage};
use rmt_agent_core::InputSink;

use crate::elevated_link::{ElevatedSink, LinkEvent};

/// After the guest declines, how long before the technician may ask again.
pub(crate) const DECLINE_COOLDOWN: Duration = Duration::from_secs(60);

/// A result for the controller.
pub(crate) type AdminRightsUpdate = (AdminRightsState, Option<String>);

/// What a launch produced. `Granted` carries how to attach the helper to the session's sink.
pub(crate) enum Launch {
    Granted(Box<dyn FnOnce(&Arc<ElevatedSink>) + Send>),
    Declined,
    Unavailable(String),
}

type Dialog = Arc<dyn Fn() -> bool + Send + Sync>;
type Launcher = Arc<dyn Fn(Arc<AtomicBool>) -> Launch + Send + Sync>;

#[derive(Default)]
struct Status {
    /// The outstanding request's retire flag.
    outstanding: Option<Arc<AtomicBool>>,
    cooldown_until: Option<Instant>,
    ended: bool,
}

/// See the module docs.
pub(crate) struct AdminRights {
    sink: Arc<ElevatedSink>,
    /// `Err(reason)` when this session can never offer it (e.g. the guest is not an administrator).
    available: Result<(), String>,
    status: Mutex<Status>,
    granted: Arc<AtomicBool>,
    updates: tokio::sync::mpsc::UnboundedSender<AdminRightsUpdate>,
    dialog: Dialog,
    launcher: Launcher,
}

impl AdminRights {
    /// The production pair for an attended session: the session's input sink (an [`ElevatedSink`]
    /// over `local`), this, and the receiver the session loop polls for updates.
    pub(crate) fn for_attended_session(
        local: Arc<dyn InputSink>,
    ) -> (Arc<ElevatedSink>, Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<AdminRightsUpdate>) {
        let available = match crate::elevation_win::is_split_token_admin() {
            Ok(true) => Ok(()),
            Ok(false) => Err("the signed-in user is not an administrator".to_string()),
            Err(e) => Err(format!("could not read the guest's account ({e})")),
        };
        Self::with(local, available, Arc::new(guest_agrees), Arc::new(launch_with_uac))
    }

    pub(crate) fn with(
        local: Arc<dyn InputSink>,
        available: Result<(), String>,
        dialog: Dialog,
        launcher: Launcher,
    ) -> (Arc<ElevatedSink>, Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<AdminRightsUpdate>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let granted = Arc::new(AtomicBool::new(false));
        let (etx, eg) = (tx.clone(), Arc::clone(&granted));
        let sink = Arc::new(ElevatedSink::new(
            local,
            Arc::new(crate::elevation_win::tick_ms),
            Arc::new(move |e: LinkEvent| match e {
                LinkEvent::Ended => {
                    eg.store(false, Ordering::SeqCst);
                    let _ = etx.send((AdminRightsState::Ended, None));
                }
            }),
        ));
        let this = Arc::new(Self {
            sink: Arc::clone(&sink),
            available,
            status: Mutex::new(Status::default()),
            granted,
            updates: tx,
            dialog,
            launcher,
        });
        (sink, this, rx)
    }

    /// The session-start advertisement.
    pub(crate) fn advertisement(&self) -> ControlMessage {
        ControlMessage::AdminRightsAvailable {
            available: self.available.is_ok(),
            reason: self.available.as_ref().err().cloned(),
        }
    }

    fn send(&self, state: AdminRightsState, reason: Option<&str>) {
        let _ = self.updates.send((state, reason.map(str::to_string)));
    }

    /// Handle `RequestAdminRights`. `guest_window_shown`: the guest's session window is up (a
    /// prompt must not appear for a session the guest cannot see).
    pub(crate) fn request(self: &Arc<Self>, observer: bool, guest_window_shown: bool) {
        let refuse = |why: &str| self.send(AdminRightsState::Unavailable, Some(why));
        if observer {
            return refuse("an observer cannot request admin rights");
        }
        if let Err(why) = &self.available {
            return refuse(why);
        }
        if !guest_window_shown {
            return refuse("the guest's session window is not showing");
        }
        if self.granted.load(Ordering::SeqCst) {
            return refuse("admin rights are already granted");
        }
        let retire = {
            let mut st = self.status.lock().unwrap_or_else(|e| e.into_inner());
            if st.ended {
                return refuse("the session is ending");
            }
            if st.outstanding.is_some() {
                return refuse("a request is already waiting for the guest");
            }
            if st.cooldown_until.is_some_and(|t| Instant::now() < t) {
                return refuse("the guest declined a moment ago; try again in a minute");
            }
            let retire = Arc::new(AtomicBool::new(false));
            st.outstanding = Some(Arc::clone(&retire));
            retire
        };
        self.send(AdminRightsState::Pending, None);
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            // The guest's own answer first. The dialog can outlive a session that ends while it is
            // up; its answer is then ignored (the retire flag), and nothing is launched.
            let agreed = (this.dialog)();
            let result = if retire.load(Ordering::SeqCst) {
                Launch::Unavailable("the request was cancelled".into())
            } else if !agreed {
                Launch::Declined
            } else {
                (this.launcher)(Arc::clone(&retire))
            };
            let mut st = this.status.lock().unwrap_or_else(|e| e.into_inner());
            st.outstanding = None;
            match result {
                Launch::Granted(attach) if !retire.load(Ordering::SeqCst) && !st.ended => {
                    // Publish Granted while STILL holding the status lock, so end() (which takes the
                    // same lock) cannot interleave and detach/Ended between attach and the Granted
                    // notice — a cancelled request must never publish Granted after Ended (Codex impl-B).
                    attach(&this.sink);
                    this.granted.store(true, Ordering::SeqCst);
                    this.send(AdminRightsState::Granted, None);
                    drop(st);
                }
                Launch::Granted(attach) => {
                    // Granted just as the session ended: attach and detach at once, so the helper
                    // is told to end rather than left waiting on a pipe nobody reads.
                    attach(&this.sink);
                    drop(st);
                    this.sink.detach();
                }
                Launch::Declined => {
                    st.cooldown_until = Some(Instant::now() + DECLINE_COOLDOWN);
                    drop(st);
                    this.send(AdminRightsState::Declined, None);
                }
                Launch::Unavailable(why) => {
                    drop(st);
                    this.send(AdminRightsState::Unavailable, Some(&why));
                }
            }
        });
    }

    /// Session teardown: retire an outstanding request and end a grant.
    pub(crate) fn end(&self) {
        let mut st = self.status.lock().unwrap_or_else(|e| e.into_inner());
        st.ended = true;
        if let Some(r) = st.outstanding.take() {
            r.store(true, Ordering::SeqCst);
        }
        drop(st);
        self.sink.detach();
    }
}

/// The pre-dialog (docs/53 §3.1 step 2): our explanation, naming what Windows will show next.
fn guest_agrees() -> bool {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
    };
    let text = format!(
        "Your technician is asking for administrator rights so they can work in admin windows on this computer.\n\n\
         If you agree, Windows will ask you to confirm. {}\n\n\
         Your technician will be able to make administrator changes to this computer until this support session ends.\n\n\
         Allow administrator rights?",
        publisher_check()
    );
    // SAFETY: plain modal message box on this thread.
    let answer = unsafe {
        MessageBoxW(
            None,
            &HSTRING::from(text),
            &HSTRING::from("DeskRally: administrator rights"),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND,
        )
    };
    answer == IDYES
}

/// What to check in the UAC prompt: the pinned publisher's CN, or a neutral hint when this build pins none.
fn publisher_check() -> String {
    match publisher_name() {
        Some(name) => format!("Check that it shows the verified publisher \"{name}\"."),
        None => "Check that the publisher Windows shows is the one you expect.".to_owned(),
    }
}

/// The CN of the pinned publisher, which is what the UAC prompt displays; None without a pinned identity.
fn publisher_name() -> Option<&'static str> {
    let subject = env!("DESKRALLY_UPDATE_PUBLISHER");
    if subject.is_empty() {
        return None;
    }
    Some(subject
        .split(',')
        .find_map(|p| p.trim().strip_prefix("CN="))
        .unwrap_or(subject))
}

fn launch_with_uac(retire: Arc<AtomicBool>) -> Launch {
    match crate::elevation_win::request(retire) {
        crate::elevation_win::Outcome::Granted(g) => Launch::Granted(Box::new(move |sink| sink.attach(g.writer, g.acks, g.close))),
        crate::elevation_win::Outcome::Declined => Launch::Declined,
        crate::elevation_win::Outcome::Unavailable(why) => Launch::Unavailable(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elevated_input::{serve, HelperState};
    use rmt_agent_core::platform::PlatformResult;
    use rmt_agent_core::InputEvent;
    use std::sync::mpsc;

    struct Nothing;
    impl InputSink for Nothing {
        fn inject(&self, _: InputEvent) -> PlatformResult<()> {
            Ok(())
        }
    }

    fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<AdminRightsUpdate>) -> AdminRightsUpdate {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(u) = rx.try_recv() {
                return u;
            }
            assert!(Instant::now() < deadline, "no update arrived");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn fixed(answer: bool) -> Dialog {
        Arc::new(move || answer)
    }

    /// A launcher that connects a real `serve` over anonymous pipes, like a granted helper.
    fn granting() -> Launcher {
        Arc::new(|_retire| {
            let (to_r, to_w) = std::io::pipe().unwrap();
            let (ack_r, ack_w) = std::io::pipe().unwrap();
            let state = Arc::new(HelperState::new(Arc::new(crate::elevation_win::tick_ms)));
            std::thread::spawn(move || serve(to_r, ack_w, Arc::new(Nothing), state));
            Launch::Granted(Box::new(move |sink| sink.attach(to_w, ack_r, Box::new(|| {}))))
        })
    }

    #[test]
    fn it_advertises_why_not_and_refuses_without_asking() {
        let (_, ar, mut rx) = AdminRights::with(Arc::new(Nothing), Err("the signed-in user is not an administrator".into()), fixed(true), granting());
        assert_eq!(
            ar.advertisement(),
            ControlMessage::AdminRightsAvailable { available: false, reason: Some("the signed-in user is not an administrator".into()) }
        );
        ar.request(false, true);
        assert_eq!(next(&mut rx), (AdminRightsState::Unavailable, Some("the signed-in user is not an administrator".into())));
    }

    #[test]
    fn observers_and_hidden_sessions_are_refused_before_any_prompt() {
        let asked = Arc::new(AtomicBool::new(false));
        let a = asked.clone();
        let (_, ar, mut rx) = AdminRights::with(Arc::new(Nothing), Ok(()), Arc::new(move || { a.store(true, Ordering::SeqCst); true }), granting());
        ar.request(true, true);
        assert_eq!(next(&mut rx).0, AdminRightsState::Unavailable);
        ar.request(false, false);
        assert_eq!(next(&mut rx).0, AdminRightsState::Unavailable);
        assert!(!asked.load(Ordering::SeqCst), "the guest was never prompted");
    }

    #[test]
    fn a_grant_attaches_the_helper_and_its_end_is_reported() {
        let (sink, ar, mut rx) = AdminRights::with(Arc::new(Nothing), Ok(()), fixed(true), granting());
        ar.request(false, true);
        assert_eq!(next(&mut rx).0, AdminRightsState::Pending);
        assert_eq!(next(&mut rx).0, AdminRightsState::Granted);
        assert!(sink.is_attached());
        ar.request(false, true);
        assert_eq!(next(&mut rx), (AdminRightsState::Unavailable, Some("admin rights are already granted".into())));
        ar.end();
        assert_eq!(next(&mut rx).0, AdminRightsState::Ended);
        assert!(!sink.is_attached());
    }

    #[test]
    fn a_decline_starts_the_cooldown() {
        let (_, ar, mut rx) = AdminRights::with(Arc::new(Nothing), Ok(()), fixed(false), granting());
        ar.request(false, true);
        assert_eq!(next(&mut rx).0, AdminRightsState::Pending);
        assert_eq!(next(&mut rx).0, AdminRightsState::Declined);
        ar.request(false, true);
        let (state, why) = next(&mut rx);
        assert_eq!(state, AdminRightsState::Unavailable);
        assert!(why.unwrap().contains("declined a moment ago"));
    }

    #[test]
    fn one_request_at_a_time_and_session_end_retires_it() {
        let (go_tx, go_rx) = mpsc::channel::<bool>();
        let go_rx = Mutex::new(go_rx);
        let (sink, ar, mut rx) = AdminRights::with(Arc::new(Nothing), Ok(()), Arc::new(move || go_rx.lock().unwrap().recv().unwrap()), granting());
        ar.request(false, true);
        assert_eq!(next(&mut rx).0, AdminRightsState::Pending);
        ar.request(false, true);
        assert_eq!(next(&mut rx), (AdminRightsState::Unavailable, Some("a request is already waiting for the guest".into())));
        // The session ends while the guest is still looking at our dialog; then the guest says yes.
        ar.end();
        go_tx.send(true).unwrap();
        let (state, why) = next(&mut rx);
        assert_eq!(state, AdminRightsState::Unavailable, "a late yes launches nothing: {why:?}");
        assert!(!sink.is_attached());
    }

    #[test]
    fn the_publisher_name_is_the_certificate_cn() {
        match publisher_name() {
            Some(name) => {
                assert!(!name.is_empty() && !name.contains("CN=") && !name.contains(','), "{name}");
                assert!(publisher_check().contains(&format!("\"{name}\"")));
            }
            None => {
                assert!(env!("DESKRALLY_UPDATE_PUBLISHER").is_empty());
                assert!(!publisher_check().contains('"'));
            }
        }
    }
}
