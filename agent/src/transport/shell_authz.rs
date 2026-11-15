//! Who may open the backstage shell demo's WebSocket (docs/25 F16).
//!
//! # Why this exists, and why it is a separate module
//!
//! `shell_server` bridges a live PowerShell to a browser terminal on `127.0.0.1:8071`. Its
//! `ws_upgrade` handler took nothing but the upgrade itself: **every** connection that reached
//! `/ws` was handed a demo grant and got a shell in the current user's context, with no token and
//! no `Origin` check. Loopback is not an authorization boundary — it does not distinguish the
//! browser tab the operator opened from any other process on the machine, and depending on the
//! browser's local-network controls a hostile web page can reach a loopback port too.
//!
//! The decision lives here, apart from the server, for two reasons:
//!
//!  1. `shell_server` is `#![cfg(windows)]` because ConPTY is. There is nothing Windows-specific
//!     about deciding whether a request is authorized, and a security guard that only compiles on
//!     one platform is only *tested* on one platform.
//!  2. F16's regression asks to prove that missing and foreign tokens and foreign origins cannot
//!     spawn a shell **without starting a shell in ordinary CI**. Because this is a pure function
//!     over the request's token and headers, the refusal cases are provable with no ConPTY, no
//!     child process and no console — which is also why they can run on every platform.

use std::fmt;

/// Why an upgrade was refused. Rendered for a log line; never carries the token or the presented
/// value, so a refusal cannot write a secret (or an attacker's chosen string) into a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No `t=` query parameter at all.
    MissingToken,
    /// A token was presented and did not match.
    BadToken,
    /// No `Host` header. HTTP/1.1 requires one, so this is not an ordinary browser.
    MissingHost,
    /// The `Host` header names something other than the loopback address we are serving.
    ///
    /// This is the DNS-rebinding case: a page on `evil.example` whose name resolves to 127.0.0.1
    /// reaches this port with `Host: evil.example`.
    ForeignHost,
    /// An `Origin` was presented and is not one of ours — a web page trying to reach the port.
    ForeignOrigin,
}

impl Refusal {
    /// A short, non-echoing reason for the operator's console.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::MissingToken => "no token (the URL printed at startup carries one)",
            Refusal::BadToken => "token did not match this run's token",
            Refusal::MissingHost => "no Host header",
            Refusal::ForeignHost => "Host is not the loopback address this server is serving",
            Refusal::ForeignOrigin => "Origin is not this server",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// The demo server's authorization policy for one run.
#[derive(Debug, Clone)]
pub struct DemoAuthz {
    token: String,
    allowed_origins: Vec<String>,
    allowed_hosts: Vec<String>,
}

impl DemoAuthz {
    /// Build the policy for a loopback server on `port`, minting a fresh token for this run.
    ///
    /// The token is new every start, so a stale bookmark or a script that captured one cannot open
    /// a shell in a later run. Two v4 UUIDs of hex — 244 bits of randomness from the same CSPRNG
    /// the rest of the agent's identifiers come from, and no new dependency for a demo tool.
    pub fn for_loopback(port: u16) -> Self {
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        Self::with_token(port, token)
    }

    /// The same policy with a caller-supplied token, so a test can assert against a known value.
    pub fn with_token(port: u16, token: impl Into<String>) -> Self {
        // Both spellings of loopback, and both are legitimate: a browser sent to
        // `http://127.0.0.1:PORT` reports that Origin exactly, and one sent to `localhost` reports
        // `http://localhost:PORT`. Nothing else is accepted — in particular no scheme-less or
        // wildcard form, because a substring or prefix match is how these checks are usually
        // defeated (`http://127.0.0.1:8071.evil.example` prefixes nothing if you compare wholes).
        let allowed_origins = vec![
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
        ];
        let allowed_hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        Self { token: token.into(), allowed_origins, allowed_hosts }
    }

    /// This run's token, for printing the URL the operator should open.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Decide one upgrade. `Ok(())` means a shell may be opened; nothing else may open one.
    ///
    /// Checked in a deliberate order: the token first, because it is the actual authorization and
    /// the header checks are containment around it.
    pub fn authorize(
        &self,
        token: Option<&str>,
        host: Option<&str>,
        origin: Option<&str>,
    ) -> Result<(), Refusal> {
        match token {
            None => return Err(Refusal::MissingToken),
            Some(t) if !constant_time_eq(t.as_bytes(), self.token.as_bytes()) => {
                return Err(Refusal::BadToken)
            }
            Some(_) => {}
        }

        match host {
            None => return Err(Refusal::MissingHost),
            Some(h) if !self.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h)) => {
                return Err(Refusal::ForeignHost)
            }
            Some(_) => {}
        }

        // AN ABSENT ORIGIN IS ALLOWED, AND THAT IS A DECISION, not an oversight.
        //
        // The threat this check answers is a web page reaching a loopback port, and a browser
        // ALWAYS sends `Origin` on a WebSocket handshake — it cannot be suppressed from script. So
        // a foreign page is caught by the mismatch branch below. A request with no `Origin` is a
        // non-browser client (our own `ws_probe`, curl, a test), which the token already gates, and
        // refusing it would break the probe this tool exists to be verified with while adding
        // nothing against the browser threat.
        if let Some(o) = origin {
            if !self.allowed_origins.iter().any(|a| a.eq_ignore_ascii_case(o)) {
                return Err(Refusal::ForeignOrigin);
            }
        }

        Ok(())
    }
}

/// Compare two byte strings without an early return on the first difference.
///
/// A loopback demo tool is a marginal place for a timing oracle, but the correct comparison costs
/// six lines and means nobody has to make that judgement again if this moves. Lengths are compared
/// first and unequal lengths short-circuit, which leaks only the length — not the contents.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    //! These are the F16 regressions, and they run on every platform and start no shell: the
    //! decision is a pure function, so "a foreign origin cannot spawn a shell" is provable without
    //! a ConPTY, a child process or a host console.

    use super::*;

    const PORT: u16 = 8071;
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn authz() -> DemoAuthz {
        DemoAuthz::with_token(PORT, TOKEN)
    }

    /// The positive control. Without this the rest could pass against a guard that refuses
    /// everything, which would "fix" the finding by breaking the tool.
    #[test]
    fn the_operators_own_tab_is_authorized() {
        for (host, origin) in [
            ("127.0.0.1:8071", "http://127.0.0.1:8071"),
            ("localhost:8071", "http://localhost:8071"),
        ] {
            assert_eq!(
                authz().authorize(Some(TOKEN), Some(host), Some(origin)),
                Ok(()),
                "host={host} origin={origin} is the ordinary case and must be allowed"
            );
        }
    }

    /// THE FINDING ITSELF: before this existed, every one of these opened a PowerShell.
    #[test]
    fn no_token_is_refused() {
        assert_eq!(
            authz().authorize(None, Some("127.0.0.1:8071"), Some("http://127.0.0.1:8071")),
            Err(Refusal::MissingToken)
        );
    }

    #[test]
    fn a_foreign_token_is_refused() {
        for wrong in [
            "",
            "not-the-token",
            // A prefix and an extension of the real token: a comparison written with
            // starts_with/contains would admit one of these.
            &TOKEN[..TOKEN.len() - 1],
            &format!("{TOKEN}x"),
        ] {
            assert_eq!(
                authz().authorize(Some(wrong), Some("127.0.0.1:8071"), Some("http://127.0.0.1:8071")),
                Err(Refusal::BadToken),
                "token {wrong:?} must be refused"
            );
        }
    }

    /// The hostile-web-page case. A page on another origin always sends its own `Origin`.
    #[test]
    fn a_foreign_origin_is_refused_even_with_a_valid_token() {
        for origin in [
            "http://evil.example",
            "https://evil.example",
            // Suffix and prefix games against a naive match.
            "http://127.0.0.1:8071.evil.example",
            "http://evil.example/127.0.0.1:8071",
            "http://127.0.0.1:8072",
            "null",
        ] {
            assert_eq!(
                authz().authorize(Some(TOKEN), Some("127.0.0.1:8071"), Some(origin)),
                Err(Refusal::ForeignOrigin),
                "origin {origin:?} must be refused"
            );
        }
    }

    /// The DNS-rebinding case: a name that resolves to 127.0.0.1 still announces itself in `Host`.
    #[test]
    fn a_foreign_host_is_refused() {
        for host in ["evil.example", "evil.example:8071", "127.0.0.1:8072", "0.0.0.0:8071"] {
            assert_eq!(
                authz().authorize(Some(TOKEN), Some(host), None),
                Err(Refusal::ForeignHost),
                "host {host:?} must be refused"
            );
        }
        assert_eq!(authz().authorize(Some(TOKEN), None, None), Err(Refusal::MissingHost));
    }

    /// The documented decision, asserted so that changing it is deliberate: a non-browser client
    /// with the right token and Host is allowed, because a browser cannot suppress `Origin` and
    /// refusing this would only break our own probe.
    #[test]
    fn an_absent_origin_is_allowed_because_browsers_always_send_one() {
        assert_eq!(authz().authorize(Some(TOKEN), Some("127.0.0.1:8071"), None), Ok(()));
    }

    /// The token is checked BEFORE the headers, so an unauthorized caller learns nothing about
    /// which origins are acceptable by probing.
    #[test]
    fn the_token_is_judged_before_the_headers() {
        assert_eq!(
            authz().authorize(None, Some("evil.example"), Some("http://evil.example")),
            Err(Refusal::MissingToken),
            "a caller with no token must be told about the token, not about the origin policy"
        );
    }

    /// A fresh token every run: a captured URL cannot open a shell in a later run.
    #[test]
    fn each_run_mints_a_different_token() {
        let a = DemoAuthz::for_loopback(PORT);
        let b = DemoAuthz::for_loopback(PORT);
        assert_ne!(a.token(), b.token(), "the per-run token must not be reused across runs");
        assert_eq!(a.token().len(), 64, "expected 64 hex chars (244 bits)");
        assert!(a.token().chars().all(|c| c.is_ascii_hexdigit()));
        // And one run's token must not open the other run's server.
        assert_eq!(
            b.authorize(Some(a.token()), Some("127.0.0.1:8071"), None),
            Err(Refusal::BadToken)
        );
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    /// Header comparison is case-insensitive, because `Host` and the host part of `Origin` are.
    #[test]
    fn host_and_origin_matching_ignores_ascii_case() {
        assert_eq!(authz().authorize(Some(TOKEN), Some("LOCALHOST:8071"), None), Ok(()));
        assert_eq!(
            authz().authorize(Some(TOKEN), Some("127.0.0.1:8071"), Some("HTTP://LOCALHOST:8071")),
            Ok(())
        );
    }
}
