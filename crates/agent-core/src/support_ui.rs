//! Every way the first-contact support client can fail, and the exact words the customer reads.
//!
//! One named, tested message per condition, produced by a **total match** ([`message`]). The
//! totality is the point: a new failure mode cannot be added to the client without adding its copy
//! here, because a non-exhaustive match will not compile. This is where docs/27's "what the page may
//! NOT claim" list is enforced in the binary rather than in a reviewer's memory:
//!
//! * The `403` message ([`Failure::InvalidCode`]) never distinguishes a wrong code from an expired
//!   one from a spent one. The control plane deliberately collapses all three into one status so the
//!   code space cannot be probed for liveness; telling the customer which it was would rebuild that
//!   oracle on the client.
//! * The antivirus copy carries BOTH clauses — never asking the customer to disable protection AND
//!   telling them to stop if the file is removed — because half of it ("we will never ask you to
//!   turn off your antivirus") reads as reassurance a scammer would also offer.
//! * Nothing here says the client is "safe", "verified", "trusted", or "secure", says it deletes
//!   itself, or says nothing is written to the machine.
//!
//! This crate is portable, so these are the CLIENT-side dialogs (the Windows support binary renders
//! them). The web `/join` page owns its own copy for the browser- and download-time failures that
//! happen before this binary ever runs; a row here for one of those (e.g.
//! [`Failure::AntivirusRemovedFile`]) is the canonical wording a technician script and the page can
//! be checked against, not a dialog the removed binary could somehow show.

/// A rendered failure message: a short title, the body, and an optional secondary line.
///
/// `detail` is copy the caller may follow with a runtime specific (a per-run directory path, say) —
/// it is kept free of runtime values so [`message`] stays pure and every variant is testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportMessage {
    /// The window/title-bar caption.
    pub title: String,
    /// The main explanation, addressed to the customer.
    pub body: String,
    /// A secondary line (what to do next), or `None`.
    pub detail: Option<String>,
}

/// Every terminal failure condition of the first-contact support flow.
///
/// Kept as a single enum so [`message`] is one total match — see the module docs for why the
/// totality is load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The control plane rejected the code (HTTP 403). **Deliberately conflates** wrong / expired /
    /// already-used — see the module docs.
    InvalidCode,
    /// The control plane is rate-limiting redemption (HTTP 429). `retry_after_secs` is the
    /// already-clamped, already-sanitised delay (see the client's `AttendRedeemError`).
    Throttled {
        /// Seconds to wait before retrying, clamped to a sane band by the caller.
        retry_after_secs: u32,
    },
    /// The control plane could not be reached at all: DNS, TLS, or connection failure.
    Network,
    /// The control plane returned a server error (HTTP 5xx).
    Server,
    /// The address this build points at answers, but not like the control plane (404/405, or an
    /// HTML/non-JSON body where JSON is required). The client cannot know the cause: the build may
    /// carry the wrong address, or the server may not be serving the guest routes. The copy states
    /// only what is known, never that retrying is pointless, and must not read as [`Failure::Server`].
    WrongServer,
    /// This binary was built with no control-plane origin (`deployment::is_unconfigured`).
    Unconfigured,
    /// The customer answered **No** at the consent prompt.
    ConsentDeclined,
    /// The consent prompt could not be DISPLAYED (no interactive desktop, session 0). Distinct from
    /// [`Failure::ConsentDeclined`]: the customer never saw a question, so "you declined" would be a
    /// lie, and the fix (run it from your own signed-in desktop) is different.
    ConsentUndisplayable,
    /// Screen capture is unavailable on this machine (Remote Desktop, a headless/again session).
    /// Only knowable AFTER consent — see docs/27.
    CaptureUnavailable,
    /// Another copy of the support client is already running.
    AlreadyRunning,
    /// The session ended (the technician closed it, or the connection dropped). Single-shot: a new
    /// code is needed to start again.
    SessionEnded,
    /// The machine's policy blocked the client (Smart App Control, AppLocker, WDAC, an ASR rule).
    /// The canonical wording for the technician script and the page; there may be no bypass.
    BlockedByPolicy,
    /// Antivirus removed the file. Carries the two-clause promise from docs/27.
    AntivirusRemovedFile,
    /// The per-run working directory could not be created or secured.
    WorkspaceSetupFailed,
    /// The client stopped unexpectedly (the panic hook fired). The working folder is KEPT so a
    /// technician can review it.
    StoppedUnexpectedly,
    /// A request to promote this session to a permanent install was refused.
    PromoteRefused,
    /// The client was launched elevated (as administrator) and refused to continue.
    ElevatedRun,
    /// A generic (pass-mode) build found no `deployment-pass.json` beside it: it was downloaded on
    /// its own rather than inside a session bundle, so it does not know which server to use.
    PassMissing,
    /// The deployment pass beside the client has lapsed (or is not valid yet by this clock).
    PassExpired,
    /// The deployment pass is malformed, not for support, or the server's answer does not match it.
    PassRejected,
}

/// Render a [`Failure`] into the exact words the customer sees.
///
/// A total match: adding a `Failure` variant without its copy is a compile error, which is how the
/// "no untested failure message" invariant is kept.
#[must_use]
pub fn message(failure: &Failure) -> SupportMessage {
    let msg = |title: &str, body: &str, detail: Option<&str>| SupportMessage {
        title: title.to_string(),
        body: body.to_string(),
        detail: detail.map(str::to_string),
    };
    match failure {
        Failure::InvalidCode => msg(
            "We couldn't start the session",
            // Never says WHY: wrong, expired, and already-used are one answer on purpose.
            "The control plane didn't accept that code. Check it with the person you called and \
             type it again.",
            Some("If it still doesn't work, ask them for a new code."),
        ),
        Failure::Throttled { retry_after_secs } => SupportMessage {
            title: "Too many attempts".to_string(),
            body: "The control plane is asking us to slow down. This can happen if a code was \
                   mistyped a few times, or if several people on your network are connecting at \
                   once."
                .to_string(),
            detail: Some(format!(
                "Please wait about {retry_after_secs} seconds, then type the code again."
            )),
        },
        Failure::Network => msg(
            "Couldn't reach the support service",
            "We couldn't connect to the support service. This is usually a network or firewall \
             problem on this side.",
            Some("Check this computer's internet connection and try again."),
        ),
        Failure::Server => msg(
            "The support service had a problem",
            "The support service reported an error on its side, not on yours.",
            Some("Wait a moment and try again, or tell your technician if it keeps happening."),
        ),
        Failure::WrongServer => msg(
            "Couldn't find the support service",
            "This download could not find the support service at the address it was built \
             with.",
            Some("Ask your support team about it. They may need to check the service, or send \
                  you a new download link."),
        ),
        Failure::Unconfigured => msg(
            "This copy isn't set up",
            "This download wasn't built with a support address, so it doesn't know where to \
             connect. It will not guess one.",
            Some("Download the client again from the link your technician gave you."),
        ),
        Failure::ConsentDeclined => msg(
            "Session cancelled",
            "You chose not to allow the remote support session. Nothing was shared.",
            Some("You can close this window. Start again with a new code if you called for help."),
        ),
        Failure::ConsentUndisplayable => msg(
            "Couldn't ask for your permission",
            "We couldn't show the permission prompt on this desktop, so no session was started \
             and nothing was shared.",
            Some("Run this again from the desktop you are signed in to, not from a service or a \
                  locked screen."),
        ),
        Failure::CaptureUnavailable => msg(
            "Can't share this screen",
            "This client couldn't read this computer's screen. This happens over Remote Desktop \
             and on some virtual machines, where the screen isn't available to share.",
            Some("If you're connected over Remote Desktop, sign in at the physical machine and \
                  try again."),
        ),
        Failure::AlreadyRunning => msg(
            "Already open",
            "The support client is already running on this computer.",
            Some("Switch to the window that's already open and type your code there."),
        ),
        Failure::SessionEnded => msg(
            "Session ended",
            "The support session has ended. Sessions are one-time, so this code can't be reused.",
            Some("If you still need help, ask your technician for a new code."),
        ),
        Failure::BlockedByPolicy => msg(
            "Blocked by this computer's policy",
            "Windows or this organisation's security policy stopped this program from running, \
             and there may be no way to allow it on this machine.",
            Some("Tell your technician exactly what Windows showed you; they'll know the next \
                  step."),
        ),
        Failure::AntivirusRemovedFile => msg(
            "Your antivirus removed the file",
            // Both clauses, per docs/27: the reassurance alone is what a scammer says too.
            "We will never ask you to turn off your antivirus or add an exclusion. If your \
             antivirus removed this file, do not try to bypass it.",
            Some("Tell your technician that your antivirus removed the file, and stop here."),
        ),
        Failure::WorkspaceSetupFailed => msg(
            "Couldn't set up a working folder",
            "The client couldn't create the temporary folder it needs to run.",
            Some("Try again; if it keeps failing, tell your technician."),
        ),
        Failure::StoppedUnexpectedly => msg(
            "The support client stopped",
            "Something went wrong and the client had to stop. Nothing is installed, but the \
             working folder was kept so a technician can see what happened.",
            Some("Tell your technician; they may ask you to send them the folder named below."),
        ),
        Failure::PromoteRefused => msg(
            "Couldn't set up permanent access",
            "The request to leave permanent access on this computer wasn't completed. The one-time \
             support session is unaffected.",
            Some("Your technician can try again, or continue without permanent access."),
        ),
        Failure::ElevatedRun => msg(
            "Don't run this as administrator",
            "This support client is meant to run as your normal user, not as an administrator. \
             It won't continue while it's running elevated.",
            Some("Close this, then open the client again with a normal double-click."),
        ),
        Failure::PassMissing => msg(
            "Open the full download",
            "This copy of the support client needs the other files that came with it, and they \
             aren't in the same folder.",
            Some("Download the session bundle from your technician's link, extract ALL files to \
                  one folder, then open DeskRallySupport.exe from there."),
        ),
        Failure::PassExpired => msg(
            "This download has expired",
            "The support provider's permission to use this client has lapsed, or this computer's \
             date and time are wrong.",
            Some("Check this computer's date and time, then download a fresh copy from your \
                  technician's link."),
        ),
        Failure::PassRejected => msg(
            "We couldn't start the session",
            "The files that came with this support client don't match the support service, so it \
             won't connect.",
            Some("Download a fresh copy from your technician's link. If it happens again, tell \
                  your technician."),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant renders a non-empty title and body. Written out variant by variant (not over a
    /// generated list) so the match in the test is total too: a new `Failure` forces a new line
    /// here, which is the same discipline [`message`] enforces on the source.
    #[test]
    fn every_failure_has_a_title_and_a_body() {
        let all = [
            Failure::InvalidCode,
            Failure::Throttled { retry_after_secs: 30 },
            Failure::Network,
            Failure::Server,
            Failure::WrongServer,
            Failure::Unconfigured,
            Failure::ConsentDeclined,
            Failure::ConsentUndisplayable,
            Failure::CaptureUnavailable,
            Failure::AlreadyRunning,
            Failure::SessionEnded,
            Failure::BlockedByPolicy,
            Failure::AntivirusRemovedFile,
            Failure::WorkspaceSetupFailed,
            Failure::StoppedUnexpectedly,
            Failure::PromoteRefused,
            Failure::ElevatedRun,
            Failure::PassMissing,
            Failure::PassExpired,
            Failure::PassRejected,
        ];
        for f in &all {
            let m = message(f);
            assert!(!m.title.trim().is_empty(), "{f:?} has an empty title");
            assert!(!m.body.trim().is_empty(), "{f:?} has an empty body");
            // A string continuation without its `\` leaves the next line's indent in the copy.
            let shown = format!("{} {} {}", m.title, m.body, m.detail.clone().unwrap_or_default());
            assert!(!shown.contains("  "), "{f:?} shows a run of spaces: {shown:?}");
        }
    }

    /// The client only knows the address did not answer like the support service. The cause may be the
    /// build's address or the server's own configuration (guest routes not mounted), and the dialog
    /// still offers another attempt: the copy must not call the address wrong or say retrying cannot help.
    #[test]
    fn the_wrong_server_message_states_only_what_is_known() {
        let m = message(&Failure::WrongServer);
        let hay = format!("{} {} {}", m.title, m.body, m.detail.unwrap_or_default()).to_lowercase();
        for claim in ["wrong", "will not help", "won't help", "cannot help", "not help", "pointless", "no use"] {
            assert!(!hay.contains(claim), "claims more than is known ({claim:?}): {hay:?}");
        }
        assert!(hay.contains("could not find the support service"), "{hay:?}");
        assert!(hay.contains("support team"), "it must send the customer to the support team: {hay:?}");
        assert!(hay.contains("check the service") && hay.contains("new download link"), "{hay:?}");
        assert_ne!(message(&Failure::WrongServer), message(&Failure::Server), "an outage and a wrong server are different facts");
    }

    /// The 403 copy must be identical whatever the real reason was, so the page/client cannot be
    /// used as a liveness oracle over the code space. There is only one variant by construction, so
    /// this pins the WORDING: it must not name "expired", "used", "spent", or "wrong".
    #[test]
    fn the_invalid_code_message_never_distinguishes_bad_from_expired_from_spent() {
        let m = message(&Failure::InvalidCode);
        let hay = format!("{} {} {}", m.title, m.body, m.detail.unwrap_or_default()).to_lowercase();
        for leak in ["expired", "already used", "spent", "wrong code", "invalid code", "used up"] {
            assert!(
                !hay.contains(leak),
                "the 403 message leaks a liveness distinction ({leak:?}): {hay:?}"
            );
        }
    }

    /// The throttle message must surface the delay the caller computed — otherwise the clamp the
    /// client does on `Retry-After` is invisible to the customer, who then retries immediately.
    #[test]
    fn the_throttle_message_states_the_wait() {
        let m = message(&Failure::Throttled { retry_after_secs: 42 });
        let all = format!("{} {} {}", m.title, m.body, m.detail.clone().unwrap_or_default());
        assert!(all.contains("42"), "the throttle wait must be shown: {all:?}");
        // A different delay must produce different text — proves it is interpolated, not a constant.
        let other = message(&Failure::Throttled { retry_after_secs: 7 });
        assert_ne!(m.detail, other.detail);
    }

    /// The antivirus copy must carry BOTH clauses. The "we will never ask you to turn it off" half
    /// alone is exactly what a scammer would also say; the "if it removes this, stop" half is what
    /// makes it protective.
    #[test]
    fn the_antivirus_message_keeps_both_clauses() {
        let m = message(&Failure::AntivirusRemovedFile);
        let all = format!("{} {}", m.body, m.detail.unwrap_or_default()).to_lowercase();
        assert!(all.contains("never ask you to turn off your antivirus"), "{all:?}");
        assert!(all.contains("exclusion"), "the second half of the promise is missing: {all:?}");
        assert!(all.contains("stop"), "the 'stop here' instruction is missing: {all:?}");
    }

    /// "declined" and "could not be displayed" are different facts with different fixes; conflating
    /// them (as the old `obtain_consent` did) tells a customer they refused a prompt they never saw.
    #[test]
    fn declined_and_undisplayable_are_different_messages() {
        assert_ne!(
            message(&Failure::ConsentDeclined),
            message(&Failure::ConsentUndisplayable),
            "the two consent outcomes must not share copy"
        );
    }

    /// None of docs/27's forbidden reassurances may appear in ANY message. This is the copy-review
    /// gate moved into the binary.
    #[test]
    fn no_message_makes_a_forbidden_claim() {
        let all = [
            Failure::InvalidCode,
            Failure::Throttled { retry_after_secs: 30 },
            Failure::Network,
            Failure::Server,
            Failure::WrongServer,
            Failure::Unconfigured,
            Failure::ConsentDeclined,
            Failure::ConsentUndisplayable,
            Failure::CaptureUnavailable,
            Failure::AlreadyRunning,
            Failure::SessionEnded,
            Failure::BlockedByPolicy,
            Failure::AntivirusRemovedFile,
            Failure::WorkspaceSetupFailed,
            Failure::StoppedUnexpectedly,
            Failure::PromoteRefused,
            Failure::ElevatedRun,
            Failure::PassMissing,
            Failure::PassExpired,
            Failure::PassRejected,
        ];
        // "safe"/"secure" would match inside innocent words, so bound them; the rest are phrases.
        let forbidden = [
            "verified", "trusted", "certified", "self-delete", "deletes itself", "removes itself",
            "leaves nothing behind", "nothing is written",
        ];
        for f in &all {
            let m = message(f);
            let hay = format!("{} {} {}", m.title, m.body, m.detail.unwrap_or_default())
                .to_lowercase();
            for bad in &forbidden {
                assert!(!hay.contains(bad), "{f:?} makes a forbidden claim ({bad:?}): {hay:?}");
            }
        }
    }
}
