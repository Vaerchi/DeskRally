//! The `rmt://` custom URI scheme — the browser → installed-client launch handoff.
//!
//! # What this is, and what it is NOT
//!
//! The `/join` page can only hand a guest a copy-paste command line
//! (`agent_host attend --code … --control-plane-url …`). On a machine where the client is
//! **already installed**, a registered URI scheme turns that into one click: the page links to
//! `rmt://attend?code=…&cp=…`, Windows launches our exe with the URI as `%1`, and this module
//! turns it back into an attended session.
//!
//! **A URI scheme cannot solve first contact.** A machine that has never run the client has no
//! handler registered, so the link does nothing (or the browser offers to search the Store). This
//! is the *second-visit accelerator*; the download/copy-paste path remains the entry point for a
//! machine that has never seen this product, and closing the docs/01 §12 item needs both halves.
//!
//! Windows only, deliberately. There is no macOS or Linux agent in this repo and no host to test
//! one on, so there is no `CFBundleURLSchemes` plist and no `x-scheme-handler/rmt` desktop entry
//! here: shipping an untestable handler for a platform whose agent does not exist would be a
//! defence that has never once been executed.
//!
//! # The grammar
//!
//! ```text
//! rmt://attend?code=<CODE>&cp=<control-plane-url>[&reason=<text>]
//! ```
//!
//! * ASCII only, no raw spaces/control characters, and none of the URI-excluded characters
//!   (`" < > \ ^ ` { } |`) or a raw `#`. Everything else goes in percent-encoded, as RFC 3986
//!   requires; `+` is **literal**, not a space (a link generator must emit `%20`).
//! * Parameters may appear in any order. A repeated parameter is an error rather than a
//!   last-one-wins guess — `…&cp=good&cp=evil` must not have a "winner".
//! * Unknown parameters are ignored (an older client must still honour a link a newer console
//!   emits); unknown *duplicates* are still refused.
//!
//! # Why the validation here is paranoid
//!
//! A `rmt://` link is **attacker-supplied input that arrives with a user's click**. Two distinct
//! risks, handled in two distinct places:
//!
//! 1. *Argument injection through `%1`.* Registering a URL protocol handler for a remote-access
//!    binary means an arbitrary web page can choose part of our command line. The structural
//!    defence is in [`crate::host`]: the URI is taken as ONE argv entry and re-parsed in-process,
//!    never re-assembled into a command string and never handed to a shell. The defence here is
//!    the character allow-lists below, which keep anything quote-, flag- or path-shaped out of the
//!    fields entirely.
//! 2. *Pointing the guest at the attacker's control plane.* [`crate::enroll::validate_control_plane_url`]
//!    enforces the *scheme* (https, or http only to loopback); it does not and cannot enforce
//!    *identity*. That is why the consent dialog names the host — see
//!    [`crate::attend::consent_prompt_text`]. Parsing is not authorization; the human is.

use std::collections::BTreeMap;
use std::path::Path;

use crate::enroll::validate_control_plane_url;

/// The scheme we register, and the only action verb the handler understands.
pub const SCHEME: &str = "rmt";
/// The single supported action (the URI's authority component): `rmt://attend?…`.
pub const ACTION_ATTEND: &str = "attend";

/// Hard bound on a `rmt://` URI. Comfortably longer than any link the console emits and short
/// enough that no crafted link can make the parser (or a log line) do meaningful work.
pub const MAX_URI_BYTES: usize = 2048;

/// Longest attend code we will pass onward.
///
/// **This is a syntactic safety net, not the code format.** The control plane owns that (it mints
/// Crockford base32 and normalizes case + `-` grouping at redemption), and re-deriving its alphabet
/// here would create a second, divergent copy of a rule that is not ours — the exact bug class this
/// repo keeps re-finding. All this cap and the [`code_char_is_safe`] allow-list do is guarantee that
/// whatever we forward is short and contains nothing dangerous; the control plane still decides
/// whether it is a *real* code, and answers `ErrAttendedInvalid` when it is not.
pub const MAX_CODE_CHARS: usize = 64;

/// Longest `reason` text rendered in the consent dialog (plus one ellipsis when truncated).
///
/// The reason is attacker-controllable and is drawn in a **system-modal dialog on the guest's
/// screen**. Without a cap, a crafted reason of a few thousand characters pushes the actual
/// question ("Allow the remote support session?") and the control-plane host off the bottom of the
/// box, leaving a guest clicking Yes on a prompt whose text they never saw.
pub const MAX_REASON_CHARS: usize = 120;

/// A parsed, validated `rmt://attend` link. Every field has already passed its check, so a holder
/// of this struct can use it without re-validating (and must not need to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttendUri {
    /// The one-time attend code, as typed into the link (never normalized here — the control plane
    /// owns normalization).
    pub code: String,
    /// Control-plane base URL, already through [`validate_control_plane_url`].
    pub control_plane_url: String,
    /// Sanitized technician/reason text for the consent prompt. May be empty.
    pub reason: String,
}

/// Errors from the registry half of this module. The parsing half returns plain `String`s (they are
/// printed to the user as-is, exactly like the other CLI paths in this crate).
#[derive(Debug, thiserror::Error)]
pub enum UriError {
    /// A Win32 registry call failed while writing or removing the handler keys.
    #[error("rmt:// scheme registry access failed: {0}")]
    Registry(#[source] windows::core::Error),
}

// ---------------------------------------------------------------------------
// Parsing (pure — no Win32, no I/O)
// ---------------------------------------------------------------------------

/// Characters that may appear **raw** in a `rmt://` URI.
///
/// Everything outside this set has to arrive percent-encoded. The excluded characters are exactly
/// the ones that make a URI ambiguous or a command line dangerous: ASCII control and space, the
/// RFC 3986 "excluded" set (`" < > \ ^ ` { } |`), a raw `#` (we take no fragment — refusing beats
/// silently discarding whatever follows it), and everything non-ASCII (a URI is ASCII by
/// definition; an IDN host or a Unicode reason is percent-encoded UTF-8).
fn raw_uri_char_is_safe(c: char) -> bool {
    if !c.is_ascii() || c.is_ascii_control() || c == ' ' {
        return false;
    }
    !matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '}' | '|' | '#')
}

/// The conservative attend-code allow-list: ASCII alphanumerics and `-` (the display grouping the
/// console renders, which the control plane strips). See [`MAX_CODE_CHARS`] — this is a safety net,
/// not the code format.
///
/// **This is also the code-prompt's keystroke filter, and that is deliberate.** The typed-code
/// prompt validates each character against THIS allow-list rather than against the control plane's
/// Crockford alphabet, for the reason [`MAX_CODE_CHARS`] already gives: the alphabet is not ours to
/// know, and a second copy of it here would drift. It also removes a whole bug rather than fixing
/// it. A filter built from the *uppercase* Crockford set has to run on the raw `WM_CHAR`, which
/// arrives BEFORE an `ES_UPPERCASE` edit control folds the case — so every lowercase keystroke
/// would be swallowed in silence, while PASTE kept working, because the paste path normalizes
/// first. A customer would watch nothing appear as they typed and have no idea why. Accepting ASCII
/// alphanumerics leaves no case to get wrong.
pub fn code_char_is_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Parse and validate a `rmt://attend?…` URI. Fails closed: every error path refuses rather than
/// forwarding a value we are unsure about.
pub fn parse_attend_uri(raw: &str) -> Result<AttendUri, String> {
    if raw.len() > MAX_URI_BYTES {
        return Err(format!(
            "rmt:// URI is {} bytes, over the {MAX_URI_BYTES}-byte limit",
            raw.len()
        ));
    }
    if let Some(bad) = raw.chars().find(|c| !raw_uri_char_is_safe(*c)) {
        return Err(format!(
            "rmt:// URI contains the character {bad:?}, which must be percent-encoded (or is not \
             allowed at all)"
        ));
    }

    // Accept the legacy bare `rmt://` AND a namespaced `rmt-<fingerprint>://` (see
    // [`deployment_scheme`]). The OS routed this link here by its registered scheme and the
    // authoritative control-plane URL rides in `cp`, so the fingerprint is not re-derived here —
    // matching it would couple this pure parser to on-disk config for no security gain.
    let (scheme, rest) = raw
        .split_once("://")
        .filter(|(scheme, _)| scheme_is_ours(scheme))
        .ok_or_else(|| {
            // Do NOT echo the raw URI here. A `rmt://attend` link's query carries the one-time
            // attend `code`, a BEARER SECRET, and every caller of this parser (`uri_command`,
            // `stub_command`, `make_stub_command`) prints this error while promising not to log the
            // code. `{raw:?}` broke that promise; the scheme being unrecognized is the whole
            // diagnostic and never contains the secret.
            format!("not an {SCHEME}:// (or {SCHEME}-<fingerprint>://) URI — unrecognized scheme")
        })?;
    let _ = scheme; // routing already used it; the parser does not.

    // Split the authority (the action verb) from the query. A launcher may normalize
    // `rmt://attend?x` to `rmt://attend/?x` (empty path), so one trailing slash is tolerated.
    let (action, query) = match rest.split_once('?') {
        Some((a, q)) => (a, q),
        None => (rest, ""),
    };
    let action = action.strip_suffix('/').unwrap_or(action);
    if !action.eq_ignore_ascii_case(ACTION_ATTEND) {
        return Err(format!(
            "unsupported rmt:// action {action:?} (the only supported action is {ACTION_ATTEND:?})"
        ));
    }

    let params = parse_query(query)?;

    let code = validate_code(
        params
            .get("code")
            .ok_or("rmt:// URI has no code parameter")?,
    )
    // `validate_code` now speaks in "session code …" because the typed-code prompt shares it; on the
    // URI path re-scope its diagnostic so the message still reads as an rmt:// problem, as before.
    .map_err(|e| format!("rmt:// URI {e}"))?;
    let cp = params
        .get("cp")
        .ok_or("rmt:// URI has no cp (control-plane URL) parameter")?
        .trim()
        .to_string();
    // Reuse the ENROLLMENT url policy verbatim — https, or http only to loopback. A second copy of
    // that check here would be a second thing to keep correct, and this repo has been bitten by
    // exactly that. The `Ok(true)` (plaintext loopback) case is warned about downstream by
    // `attend::redeem`, which validates again on the wire path.
    validate_control_plane_url(&cp).map_err(|e| format!("rmt:// URI cp parameter: {e}"))?;
    let reason = sanitize_reason(params.get("reason").map(String::as_str).unwrap_or(""));

    Ok(AttendUri { code, control_plane_url: cp, reason })
}

/// Whether a URI scheme is one this handler owns: the legacy bare `rmt`, or a namespaced
/// `rmt-<fingerprint>` (see [`deployment_scheme`]). Case-insensitive — a browser lower-cases a
/// scheme, a hand-typed link may not.
///
/// The fingerprint is NOT re-derived or matched here (see the note at the call site). A namespaced
/// scheme is `rmt` + `-` + a non-empty run of ASCII alphanumerics; our fingerprints are hex, so a
/// stray `rmt-a-b` is refused rather than waved through.
fn scheme_is_ours(scheme: &str) -> bool {
    if scheme.eq_ignore_ascii_case(SCHEME) {
        return true;
    }
    match scheme.split_once('-') {
        Some((head, fingerprint)) => {
            head.eq_ignore_ascii_case(SCHEME)
                && !fingerprint.is_empty()
                && fingerprint.bytes().all(|b| b.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// FNV-1a (64-bit) over `s`'s UTF-8 bytes, as 16 lowercase hex digits.
///
/// A **namespacing** fingerprint, deliberately not a cryptographic one: its only job is that two
/// different control-plane origins almost never collide and the same origin always maps to the same
/// value. FNV-1a is chosen because it reimplements byte-for-byte identically in the browser console
/// (`web/viewer/src/lib/attend_link.ts`), which must derive the SAME scheme to emit a link this
/// agent answers. The golden vectors in both test suites pin that agreement.
fn fnv1a64_hex(s: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    format!("{hash:016x}")
}

/// Canonicalize a control-plane URL to its ORIGIN — `scheme://host[:port]` — exactly as a browser's
/// `window.location.origin` would: lower-case scheme and host, drop userinfo, and drop a port that
/// equals the scheme's default (443 for https, 80 for http).
///
/// Path, query and fragment are DISCARDED. The console's fingerprint input is
/// `window.location.origin`, which has none, while the agent's `control_plane_url` may carry a `/cp`
/// base path — using the origin is precisely what lets the two sides agree. The stated assumption is
/// one control-plane deployment per origin.
fn canonical_origin(url: &str) -> String {
    let s = url.trim();
    let (scheme, rest) = match s.split_once("://") {
        Some((sc, r)) => (sc.to_ascii_lowercase(), r),
        None => (String::new(), s), // no scheme: treat the whole string as the authority
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Userinfo is everything before the LAST '@' (RFC 3986).
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, hp)) => hp,
        None => authority,
    };
    // Split host from port, keeping an IPv6 literal's brackets intact.
    let (host, port) = if let Some(close) = host_port.rfind(']') {
        (&host_port[..=close], host_port[close + 1..].strip_prefix(':'))
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        (h, Some(p))
    } else {
        (host_port, None)
    };
    let host = host.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => Some("443"),
        "http" => Some("80"),
        _ => None,
    };
    let port = match port {
        Some(p) if !p.is_empty() && Some(p) != default_port => format!(":{p}"),
        _ => String::new(),
    };
    if scheme.is_empty() {
        format!("{host}{port}")
    } else {
        format!("{scheme}://{host}{port}")
    }
}

/// The per-deployment URI scheme, `rmt-<fingerprint>`, derived from the control plane's ORIGIN.
///
/// This is the fix for the collision documented in docs/07 (loop 18). Registering the bare `rmt`
/// scheme machine-wide means two deployments' clients fight over one `HKLM\Software\Classes\rmt`
/// key — the last installer silently retargets the first's links, and either uninstall deletes the
/// other's handler. Namespacing by the control-plane origin gives each deployment its own key, the
/// same thing ScreenConnect does with `sc-<fingerprint>`.
///
/// The console derives the identical scheme from `window.location.origin`
/// (`web/viewer/src/lib/attend_link.ts`); the golden vectors pin the agreement.
pub fn deployment_scheme(control_plane_url: &str) -> String {
    format!("{SCHEME}-{}", fnv1a64_hex(&canonical_origin(control_plane_url)))
}

/// Split a query string into decoded key→value pairs.
///
/// A repeated key is an **error**: `…&cp=good&cp=evil` has no defensible winner, and picking one
/// silently is how a smuggled parameter gets honoured. Empty segments (`a=1&&b=2`) are skipped; a
/// segment with no `=` is an error rather than a valueless key.
fn parse_query(query: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("rmt:// URI query segment {pair:?} is not key=value"))?;
        let key = percent_decode(k)?;
        let value = percent_decode(v)?;
        if out.insert(key.clone(), value).is_some() {
            return Err(format!(
                "rmt:// URI repeats the parameter {key:?} — refusing rather than guessing which \
                 one is authoritative"
            ));
        }
    }
    Ok(out)
}

/// Percent-decode one URI component, **rejecting** a malformed escape instead of passing it
/// through.
///
/// Passing `%zz` through as the literal three characters is the permissive behaviour most
/// hand-rolled decoders have, and it is how one layer's "harmless literal" becomes the next
/// layer's escape. A truncated (`…%4`) or non-hex escape, and a decode that does not yield UTF-8,
/// are all refusals. `+` decodes to `+`: this is a URI query, not an HTML form body, and silently
/// turning `+` into a space would mean the string we validate is not the string the link said.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes
                .get(i + 1)
                .and_then(|b| hex_nibble(*b))
                .ok_or_else(|| format!("malformed percent-escape in {s:?}"))?;
            let lo = bytes
                .get(i + 2)
                .and_then(|b| hex_nibble(*b))
                .ok_or_else(|| format!("malformed percent-escape in {s:?}"))?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("percent-escapes in {s:?} do not decode to UTF-8"))
}

/// One hex digit → its value, or `None` if it is not a hex digit.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Validate the attend code against the conservative allow-list (see [`MAX_CODE_CHARS`]).
///
/// The leading-`-` refusal is not cosmetic. Anything that later reaches an argv-style parser can be
/// read as a **flag** rather than a value: a code of `--auto-consent` would, in a naive
/// "rebuild the command line and re-parse it" handoff, turn into the test-only consent bypass. The
/// structural fix is that [`crate::host`] never rebuilds a command line from these fields — this is
/// the belt to that braces, and it costs nothing, because no code the control plane mints starts
/// with `-`.
pub fn validate_code(raw: &str) -> Result<String, String> {
    // Messages say "session code", not "rmt:// URI …", because this is now shared with the typed-code
    // support prompt (docs/28 §3.1), where "rmt:// URI" would be meaningless — a customer typed a
    // code, there is no URI. The URI path re-scopes these back to a URI diagnostic by wrapping the
    // error (see `parse_attend_uri`), so its output still reads as an rmt:// problem.
    if raw.is_empty() {
        return Err("session code is empty".to_string());
    }
    let n = raw.chars().count();
    if n > MAX_CODE_CHARS {
        return Err(format!(
            "session code is {n} characters, over the {MAX_CODE_CHARS}-character limit"
        ));
    }
    if let Some(bad) = raw.chars().find(|c| !code_char_is_safe(*c)) {
        return Err(format!(
            "session code contains {bad:?}; only letters, digits and '-' are accepted"
        ));
    }
    if raw.starts_with('-') {
        return Err("session code may not start with '-'".to_string());
    }
    Ok(raw.to_string())
}

/// Make an arbitrary `reason` string safe to render in the consent dialog: drop the
/// display-hostile characters, trim, and cap the length (see [`MAX_REASON_CHARS`]).
///
/// **Idempotent by construction** — sanitizing an already-sanitized string returns it unchanged.
/// That matters because this is the SINGLE implementation and it is applied at both ends: the URI
/// parser calls it (so a bad link is rejected/cleaned at the boundary) and
/// [`crate::attend::consent_prompt_text`] calls it again at the point of rendering (so the
/// copy-paste `--reason` path, which never goes through the parser, gets the same protection). One
/// function, several call sites — not two implementations that can drift apart.
///
/// **Moved down to `agent-core` (2026-08-13).** The rule now also governs the guest window, which
/// draws the technician's live chat text on the guest's screen — a bigger surface for the same
/// `U+202E` attack this has always defended the consent dialog against. `agent-windows` depends on
/// `agent-core` and never the reverse, so the shared rule had to live there; this stays as the named
/// `reason`-shaped entry point, carrying the cap that is a URI concern. See
/// [`rmt_agent_core::text`].
pub fn sanitize_reason(raw: &str) -> String {
    rmt_agent_core::text::sanitize_display(raw, MAX_REASON_CHARS)
}

/// The host (with port, if any) a control-plane URL will actually be dialled at — for **display in
/// the consent prompt**, never for a security decision.
///
/// Uses the same URL parser as reqwest, including its handling of special-scheme backslashes.
/// Invalid URLs have no display host; callers must validate the base URL before connecting.
pub fn control_plane_host(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url.trim()) else { return String::new() };
    let Some(host) = parsed.host_str() else { return String::new() };
    match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Pick the single URI operand out of argv for the `uri` subcommand.
///
/// Requires **exactly one** operand. More than one means the launcher split the URI (whitespace
/// that should have been percent-encoded, a mis-quoted `%1` in the registered command); continuing
/// with only the first fragment would silently act on a truncated URL, so this refuses instead.
pub fn uri_arg(args: &[String]) -> Result<&str, String> {
    match args.len() {
        3 => Ok(args[2].as_str()),
        n if n < 3 => Err("uri: expected one argument, the rmt:// URI".to_string()),
        n => Err(format!(
            "uri: expected exactly ONE argument, got {}; the URI was split into separate arguments \
             (it must be passed as a single quoted value)",
            n - 2
        )),
    }
}

// ---------------------------------------------------------------------------
// Registration (HKLM\Software\Classes\rmt)
// ---------------------------------------------------------------------------

/// The `Software\Classes` base under which a URL protocol handler is registered. Machine-wide when
/// rooted at `HKEY_LOCAL_MACHINE` (what `install` writes, from an already-elevated process).
const CLASSES_SUBKEY: &str = r"Software\Classes";

/// The `(Default)` value of the scheme key. The `URL:` prefix is the convention that marks a
/// ProgID as a protocol handler; the text after it is what the shell shows.
const SCHEME_DESCRIPTION: &str = "URL:RMT Remote Support";

/// Build the `shell\open\command` string Windows will run for a `rmt://` link.
///
/// `"<exe>" uri "%1"` — the exe path quoted (it lives under `C:\Program Files\…`, which has a
/// space), then our subcommand, then the URI as a **single quoted parameter**. `%1` must stay
/// quoted: unquoted, a URI containing a space would arrive as several argv entries and
/// [`uri_arg`] would (correctly) refuse the launch.
pub fn open_command_line(exe: &str) -> String {
    format!("\"{exe}\" uri \"%1\"")
}

/// Register the machine-wide handler for `scheme` (a [`deployment_scheme`] value), pointing at
/// `exe_path`.
///
/// Writes, under `HKLM\Software\Classes\<scheme>`:
/// * `(Default)` = [`SCHEME_DESCRIPTION`]
/// * `URL Protocol` = `""` (the empty value is the flag; its presence is what makes the shell treat
///   this ProgID as a protocol)
/// * `shell\open\command\(Default)` = [`open_command_line`]
///
/// `scheme` is namespaced per deployment so two clients on one machine do not share (and clobber)
/// one key — see [`deployment_scheme`]. Requires write access to `HKLM\Software\Classes`, i.e. an
/// elevated caller — which is why the only production caller is [`crate::service::install_service`].
pub fn register_scheme(exe_path: &Path, scheme: &str) -> Result<(), UriError> {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    register_scheme_at(
        HKEY_LOCAL_MACHINE,
        CLASSES_SUBKEY,
        scheme,
        &exe_path.display().to_string(),
    )
}

/// Remove the machine-wide handler for `scheme`. A handler that is not there is not an error.
pub fn unregister_scheme(scheme: &str) -> Result<(), UriError> {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    unregister_scheme_at(HKEY_LOCAL_MACHINE, CLASSES_SUBKEY, scheme)
}

/// Root/base-parameterized registration. Split out from [`register_scheme`] so the unit test can
/// exercise **this exact code** against a scratch key under `HKEY_CURRENT_USER` — writing the real
/// `HKLM` keys needs elevation, and a test must not mutate a developer's machine-wide registry.
fn register_scheme_at(
    root: windows::Win32::System::Registry::HKEY,
    base: &str,
    scheme: &str,
    exe: &str,
) -> Result<(), UriError> {
    let scheme_key = format!(r"{base}\{scheme}");
    set_sz(root, &scheme_key, "", SCHEME_DESCRIPTION)?;
    // The VALUE is empty; its mere presence is the "this ProgID is a URL protocol" flag.
    set_sz(root, &scheme_key, "URL Protocol", "")?;
    set_sz(
        root,
        &format!(r"{scheme_key}\shell\open\command"),
        "",
        &open_command_line(exe),
    )
}

/// Root/base-parameterized removal (see [`register_scheme_at`] for why this is split out).
fn unregister_scheme_at(
    root: windows::Win32::System::Registry::HKEY,
    base: &str,
    scheme: &str,
) -> Result<(), UriError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Registry::RegDeleteTreeW;

    let subkey = wide(&format!(r"{base}\{scheme}"));
    // SAFETY: `subkey` is a NUL-terminated UTF-16 buffer that outlives the call; `root` is a
    // predefined key handle. RegDeleteTreeW removes the named subkey and everything under it.
    let status = unsafe { RegDeleteTreeW(root, PCWSTR(subkey.as_ptr())) };
    if status.is_ok() || status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    Err(UriError::Registry(windows::core::Error::from(WIN32_ERROR(
        status.0,
    ))))
}

/// After registering the current scheme, reclaim any OTHER handler THIS SAME executable previously
/// registered: a stale `rmt-<old fingerprint>` left behind when the agent was re-pointed at a
/// different control-plane origin (e.g. an attended-session promote — [`crate::host`]'s
/// `run_attend_promote` rewrites `control_plane_url` and re-runs install, docs/12 §8), or a legacy
/// bare `rmt` from a pre-namespacing install.
///
/// Only keys whose `shell\open\command` launches `exe_path` are removed, so another deployment's
/// handler — which points at a DIFFERENT exe — is never touched. Returns how many were reclaimed.
/// This is what keeps "one executable owns exactly one rmt handler" true across re-enrollment, so a
/// later config-derived uninstall leaves nothing orphaned.
pub fn reclaim_other_schemes_for_exe(exe_path: &Path, keep_scheme: &str) -> Result<usize, UriError> {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    reclaim_other_schemes_at(
        HKEY_LOCAL_MACHINE,
        CLASSES_SUBKEY,
        &exe_path.display().to_string(),
        keep_scheme,
    )
}

/// Root/base-parameterized reclaim (split out for the HKCU-scratch unit test, like the others).
fn reclaim_other_schemes_at(
    root: windows::Win32::System::Registry::HKEY,
    base: &str,
    exe: &str,
    keep_scheme: &str,
) -> Result<usize, UriError> {
    let mut removed = 0usize;
    for name in our_scheme_subkeys(root, base, exe) {
        if name.eq_ignore_ascii_case(keep_scheme) {
            continue;
        }
        unregister_scheme_at(root, base, &name)?;
        removed += 1;
    }
    Ok(removed)
}

/// Names of the `rmt*` subkeys directly under `root\base` whose `shell\open\command` launches `exe`.
///
/// Enumeration is best-effort: an unreadable base or a subkey with no command value simply yields
/// nothing for that entry rather than erroring, so a hostile or partial registry cannot make the
/// reclaim fail an install.
fn our_scheme_subkeys(
    root: windows::Win32::System::Registry::HKEY,
    base: &str,
    exe: &str,
) -> Vec<String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, KEY_READ,
    };

    let base_w = wide(base);
    let mut hkey = HKEY::default();
    // SAFETY: `base_w` is NUL-terminated UTF-16 outliving the call; `hkey` receives an owned handle
    // closed below. A failure to open (base absent) means there is nothing to reclaim.
    let open = unsafe { RegOpenKeyExW(root, PCWSTR(base_w.as_ptr()), 0, KEY_READ, &mut hkey) };
    if open.is_err() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        // SAFETY: `name_buf`/`name_len` describe a buffer of `name_len` UTF-16 units; the other
        // out-params are unused. RegEnumKeyExW returns ERROR_NO_MORE_ITEMS (an error) at the end.
        let status = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        };
        if status.is_err() {
            break;
        }
        index += 1;
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if !scheme_is_ours(&name) {
            continue;
        }
        let cmd_key = format!(r"{base}\{name}\shell\open\command");
        if let Some(cmd) = read_sz_at(root, &cmd_key, "") {
            if command_targets_exe(&cmd, exe) {
                out.push(name);
            }
        }
    }
    // SAFETY: `hkey` was opened above and is closed exactly once here.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    out
}

/// Whether a registered `shell\open\command` string launches `exe` — a case-insensitive substring
/// match, because the command embeds the exe path in quotes (`"<exe>" uri "%1"`) and Windows paths
/// are case-insensitive. This is the discriminator between a handler THIS install wrote and another
/// deployment's (which names a different exe).
fn command_targets_exe(command: &str, exe: &str) -> bool {
    !exe.is_empty() && command.to_ascii_lowercase().contains(&exe.to_ascii_lowercase())
}

/// Read a `REG_SZ` (or the key's `(Default)` when `value_name` is empty) from `root\subkey`, or
/// `None` if the key/value is absent or not a string. The production counterpart to the test-only
/// `read_sz`; only the default command value is ever read in production.
fn read_sz_at(
    root: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    value_name: &str,
) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegGetValueW, RRF_RT_REG_SZ};

    let subkey_w = wide(subkey);
    let name_w = wide(value_name);
    let mut size: u32 = 0;
    // SAFETY: a null data pointer with a valid size-out asks for the required byte count only; both
    // name buffers are NUL-terminated UTF-16 outliving the call.
    let status = unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if status.is_err() {
        return None;
    }
    let mut buf: Vec<u16> = vec![0u16; (size as usize + 1) / 2 + 1];
    let mut size2 = (buf.len() * 2) as u32;
    // SAFETY: `buf` is at least `size2` bytes and RegGetValueW writes at most that many.
    let status = unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size2),
        )
    };
    if status.is_err() {
        return None;
    }
    let chars = (size2 as usize / 2).saturating_sub(1); // drop the NUL RegGetValueW counts
    Some(String::from_utf16_lossy(&buf[..chars]))
}

/// Create `subkey` (and any missing parents) under `root` and set one `REG_SZ` value. An empty
/// `value_name` sets the key's `(Default)` value.
///
/// Mirrors `sas::write_policy`'s idiom: `RegCreateKeyExW` (which opens an existing key) →
/// `RegSetValueExW` → `RegCloseKey`, with each Win32 status mapped into [`UriError::Registry`].
fn set_sz(
    root: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    value_name: &str,
    value: &str,
) -> Result<(), UriError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE,
        REG_SZ,
    };

    let subkey_w = wide(subkey);
    let name_w = wide(value_name);
    let mut hkey = HKEY::default();
    // SAFETY: `subkey_w` is NUL-terminated UTF-16 outliving the call; we pass no class/security and
    // receive an owned key handle that is closed below. RegCreateKeyExW creates every missing level
    // of the path and opens the key if it already exists.
    let create = unsafe {
        RegCreateKeyExW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if create.is_err() {
        return Err(UriError::Registry(windows::core::Error::from(WIN32_ERROR(
            create.0,
        ))));
    }

    let data = sz_bytes(value);
    // SAFETY: `hkey` is a valid open key with KEY_SET_VALUE; `name_w` is NUL-terminated UTF-16 (an
    // empty string names the key's default value); `data` is the UTF-16 string INCLUDING its NUL
    // terminator, which is what REG_SZ requires.
    let set = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            0,
            REG_SZ,
            Some(&data),
        )
    };
    // SAFETY: `hkey` was opened by the RegCreateKeyExW above and is closed exactly once here.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if set.is_err() {
        return Err(UriError::Registry(windows::core::Error::from(WIN32_ERROR(
            set.0,
        ))));
    }
    Ok(())
}

/// A `REG_SZ` payload: native-endian UTF-16 **including** the terminating NUL.
fn sz_bytes(s: &str) -> Vec<u8> {
    wide(s).iter().flat_map(|u| u.to_ne_bytes()).collect()
}

/// UTF-16, NUL-terminated (mirrors [`crate::sas::wide`] / `service::wide`, kept local for the same
/// reason they are: no cross-module visibility change for a three-line helper).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CP: &str = "https://cp.example.com";

    fn attend_uri(query: &str) -> Result<AttendUri, String> {
        parse_attend_uri(&format!("rmt://attend?{query}"))
    }

    #[test]
    fn a_well_formed_link_parses() {
        let got = parse_attend_uri(
            "rmt://attend?code=ABCD1234WXYZ9&cp=https://cp.example.com&reason=Acme%20IT",
        )
        .expect("well-formed link");
        assert_eq!(got.code, "ABCD1234WXYZ9");
        assert_eq!(got.control_plane_url, "https://cp.example.com");
        assert_eq!(got.reason, "Acme IT");

        // Parameter order is free, the grouping '-' the console displays is accepted, `reason` is
        // optional, and a launcher-normalized empty path (`attend/`) still parses.
        let got = parse_attend_uri("RMT://Attend/?cp=https://cp.example.com/cp&code=ABCD-1234-WXYZ9")
            .expect("reordered, grouped, uppercase-scheme link");
        assert_eq!(got.code, "ABCD-1234-WXYZ9");
        assert_eq!(got.control_plane_url, "https://cp.example.com/cp");
        assert_eq!(got.reason, "");
    }

    #[test]
    fn a_rejected_link_never_echoes_the_one_time_code() {
        // The scheme-mismatch error is printed to stderr/logs by every caller of this parser
        // (`uri_command`, and the guest-stub `stub_command`/`make_stub_command`), each of which
        // promises NOT to log the one-time attend `code` — a bearer secret. An error that dumped the
        // raw URI broke that promise. The code must never appear in the message.
        let secret = "SUPERSECRETCODE9";
        let err = parse_attend_uri(&format!("evil://attend?code={secret}&cp=https://cp.example.com"))
            .expect_err("a foreign scheme is refused");
        assert!(!err.contains(secret), "the one-time code must not leak into the error: {err}");
        // Unparseable garbage that happens to embed the code likewise.
        let err = parse_attend_uri(&format!("{secret}-is-not-a-uri")).expect_err("garbage refused");
        assert!(!err.contains(secret), "no raw echo of the input: {err}");
    }

    #[test]
    fn only_the_rmt_attend_action_is_accepted() {
        for bad in [
            "https://attend?code=A&cp=https://cp.example.com",
            "rmt:attend?code=A&cp=https://cp.example.com",
            "rmt://enroll?code=A&cp=https://cp.example.com",
            "rmt://attend.evil?code=A&cp=https://cp.example.com",
            "rmt://attend/extra?code=A&cp=https://cp.example.com",
            "rmt://",
        ] {
            assert!(parse_attend_uri(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn malformed_percent_escapes_are_refused_not_passed_through() {
        // Truncated, non-hex, and a decode that is not UTF-8. A permissive decoder would hand the
        // literal "%zz" onward; every one of these must be an error instead.
        for bad in ["code=A%", "code=A%4", "code=A%zz", "code=%FF%FE", "code=%2"] {
            let err = attend_uri(&format!("{bad}&cp={CP}"))
                .expect_err(&format!("{bad:?} must be refused"));
            assert!(
                err.contains("percent-escape") || err.contains("UTF-8"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn percent_escapes_are_decoded_in_values() {
        let got = attend_uri("code=ABCD1234&cp=https%3A%2F%2Fcp.example.com%2Fcp&reason=a%2Bb")
            .expect("encoded values");
        assert_eq!(got.control_plane_url, "https://cp.example.com/cp");
        // '+' is LITERAL in a URI query — not a space. A form-style decoder would say "a b".
        assert_eq!(got.reason, "a+b");
    }

    #[test]
    fn raw_characters_that_must_be_percent_encoded_are_refused() {
        // Asserted through `reason`, which has no allow-list of its own — so ONLY the whole-URI raw
        // character guard can reject these. (Through `code` the field allow-list would catch them
        // too, and the test would pass with the guard deleted.)
        for bad in [
            "a b",       // raw space: splits the URI into two argv entries at the shell
            "a\"b",      // the `"%1"` breakout character
            "a<b",       // RFC 3986 "excluded"
            "a#b",       // a fragment we would otherwise silently discard
            "Ünicode",   // non-ASCII: a URI is ASCII, Unicode arrives percent-encoded
        ] {
            assert!(
                attend_uri(&format!("code=ABCD1234&cp={CP}&reason={bad}")).is_err(),
                "reason={bad:?} must be refused as a RAW value"
            );
        }
        // …and each of them is accepted percent-encoded, which is the point of refusing them raw.
        let got = attend_uri(&format!("code=ABCD1234&cp={CP}&reason=a%20b%23c%20%C3%9C")).unwrap();
        assert_eq!(got.reason, "a b#c Ü");
    }

    #[test]
    fn a_dangerous_code_is_refused() {
        for bad in [
            "",                       // empty
            "A B",                    // raw space (caught by the raw-URI guard)
            "A%20B",                  // decoded space
            "A%0ABBB",                // embedded newline
            "A;calc",                 // shell metacharacter
            "A&code=B",               // parameter smuggling (becomes a duplicate `code`)
            "..%2F..%2Fwindows",      // path traversal
            "A%22B",                  // a double quote — the `"%1"` breakout character
            "--auto-consent",         // a FLAG, not a value: the consent-bypass smuggle
            "-A",                     // anything starting with '-' is flag-shaped
        ] {
            assert!(
                attend_uri(&format!("code={bad}&cp={CP}")).is_err(),
                "code={bad:?} must be refused"
            );
        }
        // Over the length cap.
        let long = "A".repeat(MAX_CODE_CHARS + 1);
        assert!(attend_uri(&format!("code={long}&cp={CP}")).is_err(), "over-long code");
        // …and exactly at it is fine, so the cap is a cap and not an off-by-one refusal.
        let at_cap = "A".repeat(MAX_CODE_CHARS);
        assert!(attend_uri(&format!("code={at_cap}&cp={CP}")).is_ok(), "code at the cap");
    }

    /// The typed-code prompt shares [`validate_code`], so this is ALSO the pin on its keystroke
    /// filter: a lowercase code must be ACCEPTED.
    ///
    /// It guards a specific regression that a design review proposed and this crate already
    /// forbids. Deriving the filter from the control plane's uppercase Crockford alphabet would
    /// reject every lowercase keystroke — and only *typing*, never pasting, because the paste path
    /// normalizes case before validating. The result is a prompt where nothing appears as the
    /// customer types and no error is ever shown. If this test fails, someone has taught the agent
    /// the code FORMAT; the module header explains why that is not ours to know.
    #[test]
    fn a_lowercase_code_is_accepted_because_the_format_is_not_ours() {
        for good in [
            "abcdefghjkmnp",  // all lowercase, as a customer would type it
            "ABCDEFGHJKMNP",  // all uppercase, as the console displays it
            "aBcD-eFgH-jKmN", // mixed case with the display grouping
            "0123456789",     // digits alone
            "uUlLiIoO",       // letters Crockford EXCLUDES — still not ours to reject
        ] {
            assert!(
                validate_code(good).is_ok(),
                "{good:?} must be accepted: the control plane decides whether a code is real"
            );
        }
    }

    /// The shared validator is what stands between a typed-code prompt and an argv-flag injection,
    /// and it now speaks in "session code" wording (docs/28 §3). A code that begins with `-` — the
    /// `--auto-consent` test-bypass being the worst case — must be refused, and the message must be
    /// the customer-facing one, not the old "rmt:// URI …" phrasing that makes no sense at a prompt.
    #[test]
    fn a_leading_dash_code_is_refused_with_the_session_code_wording() {
        let err = validate_code("--auto-consent").expect_err("a leading '-' must be refused");
        assert!(err.contains("session code"), "customer-facing wording expected: {err:?}");
        assert!(!err.contains("rmt://"), "the standalone validator must not mention a URI: {err:?}");

        // On the URI path the SAME rejection is re-scoped to an rmt:// diagnostic by the wrapper, so
        // link errors still read as link errors.
        let uri_err = attend_uri("code=--auto-consent&cp=https://cp.example.com")
            .expect_err("a leading '-' code in a link must be refused");
        assert!(uri_err.contains("rmt:// URI"), "URI diagnostic scoping lost: {uri_err:?}");
        assert!(uri_err.contains("session code"), "{uri_err:?}");
    }

    #[test]
    fn the_cp_parameter_must_pass_the_enrollment_url_policy() {
        // Accepted: https anywhere, http to loopback (the dev control plane).
        for good in ["https://cp.example.com", "http://127.0.0.1:8081", "http://localhost:8081/cp"] {
            assert!(
                attend_uri(&format!("code=ABCD1234&cp={good}")).is_ok(),
                "{good:?} must be accepted"
            );
        }
        // Refused. The last two are the cases only the SHARED validator gets right — a naive
        // "contains 127.0.0.1" or "starts with http" check would wave them through.
        for bad in [
            "ftp://cp.example.com",
            "cp.example.com",
            "http://cp.example.com",
            "http://evil.example/127.0.0.1",
            "http://127.0.0.1.evil.example",
            "https://",
        ] {
            assert!(
                attend_uri(&format!("code=ABCD1234&cp={}", bad)).is_err(),
                "cp={bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_repeated_parameter_is_refused() {
        // No last-one-wins: an appended `&cp=` must not be able to redirect the guest.
        let err = attend_uri("code=ABCD1234&cp=https://good.example&cp=https://evil.example")
            .expect_err("duplicate cp");
        assert!(err.contains("repeats"), "{err}");
        assert!(attend_uri("code=A1&code=B2&cp=https://cp.example.com").is_err());
        // An unknown parameter is IGNORED (an older client must still honour a newer link)…
        assert!(attend_uri(&format!("code=ABCD1234&cp={CP}&future=1")).is_ok());
        // …but a repeated unknown one is still refused.
        assert!(attend_uri(&format!("code=ABCD1234&cp={CP}&future=1&future=2")).is_err());
    }

    #[test]
    fn a_missing_or_malformed_parameter_is_refused() {
        assert!(attend_uri(&format!("cp={CP}")).is_err(), "no code");
        assert!(attend_uri("code=ABCD1234").is_err(), "no cp");
        assert!(parse_attend_uri("rmt://attend").is_err(), "no query at all");
        assert!(attend_uri(&format!("code=ABCD1234&cp={CP}&flag")).is_err(), "valueless segment");
        // Over the whole-URI byte cap.
        let huge = format!("rmt://attend?code=A&cp={CP}&reason={}", "x".repeat(MAX_URI_BYTES));
        assert!(parse_attend_uri(&huge).is_err(), "over-long URI");
    }

    #[test]
    fn the_reason_is_stripped_and_capped_before_it_reaches_a_dialog() {
        // Control characters (a newline would scroll the real question out of the box) and the
        // bidi override that reverses everything drawn after it are removed.
        assert_eq!(sanitize_reason("Acme\r\n\tIT"), "AcmeIT");
        assert_eq!(sanitize_reason("Acme\u{202E}IT"), "AcmeIT");
        assert_eq!(sanitize_reason("Acme\u{200B}\u{FEFF}IT"), "AcmeIT");
        assert_eq!(sanitize_reason("  Acme IT  "), "Acme IT");

        // Capped, marked as truncated, and EXACTLY at the cap so a second pass is a no-op.
        let long = "A".repeat(MAX_REASON_CHARS * 3);
        let once = sanitize_reason(&long);
        assert_eq!(once.chars().count(), MAX_REASON_CHARS);
        assert!(once.ends_with('…'), "truncation must be visible: {once}");
        assert_eq!(sanitize_reason(&once), once, "sanitize_reason must be idempotent");

        // …and the parser applies it, so a crafted link cannot smuggle a control character through.
        let got = attend_uri(&format!("code=ABCD1234&cp={CP}&reason=Acme%0A%0AIT")).unwrap();
        assert_eq!(got.reason, "AcmeIT");
    }

    #[test]
    fn control_plane_host_names_the_host_the_session_will_dial() {
        assert_eq!(control_plane_host("https://cp.example.com/cp"), "cp.example.com");
        assert_eq!(control_plane_host("http://127.0.0.1:8081"), "127.0.0.1:8081");
        assert_eq!(control_plane_host("https://CP.Example.COM"), "cp.example.com");
        assert_eq!(control_plane_host("https://cp.example.com?x=1"), "cp.example.com");
        // Userinfo: the guest must be shown evil.test, not the reassuring name in front of the '@'.
        assert_eq!(
            control_plane_host("https://support.example.com@evil.test/cp"),
            "evil.test"
        );
        assert_eq!(control_plane_host("https://a@b@evil.test/"), "evil.test");
        // Already a bare host, or empty.
        assert_eq!(control_plane_host("cp.example.com"), "");
        assert_eq!(control_plane_host(""), "");
    }

    #[test]
    fn security_url_consent_uses_http_parser() {
        assert_eq!(control_plane_host(r"https://evil.invalid\@trusted.example"), "evil.invalid");
        assert_eq!(control_plane_host("http://localhost:80@remote.example"), "remote.example");
    }

    #[test]
    fn the_uri_subcommand_takes_exactly_one_argument() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let one = argv(&["agent_host.exe", "uri", "rmt://attend?code=A&cp=https://x"]);
        assert_eq!(uri_arg(&one).unwrap(), "rmt://attend?code=A&cp=https://x");
        assert!(uri_arg(&argv(&["agent_host.exe", "uri"])).is_err(), "no URI");
        // A split URI (an unquoted %1, or whitespace that should have been encoded) must refuse
        // rather than act on the first fragment.
        assert!(
            uri_arg(&argv(&["agent_host.exe", "uri", "rmt://attend?code=A", "&cp=https://evil"]))
                .is_err(),
            "a split URI must be refused"
        );
    }

    // -----------------------------------------------------------------------
    // Per-deployment scheme namespacing (docs/07 loop 18 fix).
    // -----------------------------------------------------------------------

    /// **The cross-language golden vectors.** These exact `(control-plane URL → scheme)` pairs are
    /// asserted BYTE-FOR-BYTE in `web/viewer/src/lib/attend_link.test.ts` too. If either side's
    /// canonicalization or FNV-1a drifts, one of the two suites goes red — which is the whole point:
    /// the agent registers the scheme and the console must emit a link for the SAME one.
    #[test]
    fn deployment_scheme_golden_vectors_match_the_console() {
        for (url, want) in [
            ("https://cp.example.com", "rmt-ef00d58d898ca752"),
            ("https://cp.example.com:8443", "rmt-7e8af514034ea1b1"),
            ("https://support.example.com", "rmt-caf7983af7c5a89a"),
            ("http://127.0.0.1:5173", "rmt-a099e98b44c17566"),
            ("http://localhost", "rmt-06dafc8df10020c4"),
        ] {
            assert_eq!(deployment_scheme(url), want, "scheme for {url}");
        }
    }

    /// The agent's `control_plane_url` and the console's `window.location.origin` describe the same
    /// deployment through different strings; canonicalization to the ORIGIN is what makes them agree.
    /// Every variation below must yield the SAME scheme as the bare origin.
    #[test]
    fn the_same_deployment_maps_to_one_scheme_through_all_its_spellings() {
        let base = deployment_scheme("https://cp.example.com");
        for equivalent in [
            "https://cp.example.com/",          // trailing slash
            "https://cp.example.com/cp",        // the agent's /cp base path
            "https://cp.example.com:443",       // the default https port, explicit
            "HTTPS://CP.EXAMPLE.COM",           // case
            "https://tech@cp.example.com/cp",   // userinfo
            "https://cp.example.com/cp?x=1#f",  // query + fragment
        ] {
            assert_eq!(deployment_scheme(equivalent), base, "{equivalent} must share the origin's scheme");
        }
        // And genuinely different origins must NOT collide.
        assert_ne!(deployment_scheme("https://cp.example.com"), deployment_scheme("http://cp.example.com"), "scheme differs");
        assert_ne!(deployment_scheme("https://cp.example.com"), deployment_scheme("https://cp.example.com:8443"), "port differs");
        assert_ne!(deployment_scheme("https://a.example.com"), deployment_scheme("https://b.example.com"), "host differs");
    }

    /// A namespaced scheme is a valid RFC 3986 scheme (starts with a letter, then letters/digits/`-`)
    /// and a valid registry key name (no backslash) — so both the shell and `RegCreateKeyExW` accept
    /// it.
    #[test]
    fn a_namespaced_scheme_is_a_valid_scheme_and_key_name() {
        let scheme = deployment_scheme("https://cp.example.com:8443");
        assert!(scheme.starts_with("rmt-"));
        let mut chars = scheme.chars();
        assert!(chars.next().unwrap().is_ascii_alphabetic(), "a scheme must start with a letter");
        assert!(scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "scheme charset");
        assert!(!scheme.contains('\\'), "a registry key name must not contain a backslash");
    }

    /// The parser accepts a link on the NAMESPACED scheme, not only the legacy bare `rmt`.
    #[test]
    fn the_parser_accepts_a_namespaced_scheme() {
        let scheme = deployment_scheme("https://cp.example.com");
        let uri = format!("{scheme}://attend?code=ABCD1234&cp=https://cp.example.com");
        let got = parse_attend_uri(&uri).expect("a namespaced link parses");
        assert_eq!(got.code, "ABCD1234");
        // The bare legacy scheme still parses (an older cached /join page may emit it)...
        assert!(parse_attend_uri("rmt://attend?code=ABCD1234&cp=https://cp.example.com").is_ok());
        // ...but a foreign scheme, or a malformed namespace, does not.
        for bad in [
            "https://attend?code=A&cp=https://cp.example.com",
            "rmtx://attend?code=A&cp=https://cp.example.com",
            "rmt-://attend?code=A&cp=https://cp.example.com",   // empty fingerprint
            "rmt-ab_cd://attend?code=A&cp=https://cp.example.com", // non-alphanumeric fingerprint
        ] {
            assert!(parse_attend_uri(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn scheme_is_ours_accepts_bare_and_namespaced_only() {
        assert!(scheme_is_ours("rmt"));
        assert!(scheme_is_ours("RMT"));
        assert!(scheme_is_ours("rmt-ef00d58d898ca752"));
        assert!(scheme_is_ours("RMT-EF00D58D898CA752"));
        assert!(!scheme_is_ours("rmtx"));
        assert!(!scheme_is_ours("rmt-"));
        assert!(!scheme_is_ours("rmt-a-b"));
        assert!(!scheme_is_ours("http"));
        assert!(!scheme_is_ours("xrmt"));
    }

    #[test]
    fn the_registered_command_quotes_both_the_exe_and_the_uri() {
        let cmd = open_command_line(r"C:\Program Files\RMT Agent\agent_host.exe");
        assert_eq!(cmd, r#""C:\Program Files\RMT Agent\agent_host.exe" uri "%1""#);
        // The exe path is quoted (it contains a space) and `%1` is quoted, so a URI is delivered as
        // ONE argv entry — which is what `uri_arg` insists on.
        assert!(cmd.starts_with('"') && cmd.ends_with(r#""%1""#));
        assert!(cmd.contains(" uri "), "the handler must invoke the `uri` subcommand");
    }

    // -----------------------------------------------------------------------
    // Registry round-trip.
    //
    // Runs against a SCRATCH key under HKEY_CURRENT_USER, not HKLM: writing the real machine-wide
    // handler needs elevation, and a unit test must not mutate the developer's machine (or clobber
    // a real per-user `rmt` registration — hence a private base, not `Software\Classes`). The code
    // under test is the same `register_scheme_at` / `unregister_scheme_at` the elevated installer
    // reaches; only the root and base differ.
    // -----------------------------------------------------------------------

    const TEST_BASE: &str = r"Software\RmtAgentUriTest\Classes";

    /// Read a `REG_SZ` back from the HKCU scratch, or `None`. Delegates to the production
    /// [`read_sz_at`] so the round-trip test also exercises that helper (the reclaim path relies on
    /// it to read each candidate's command value).
    fn read_sz(subkey: &str, value_name: &str) -> Option<String> {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;
        read_sz_at(HKEY_CURRENT_USER, subkey, value_name)
    }

    #[test]
    fn registering_writes_the_protocol_keys_and_unregistering_removes_them() {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;

        let exe = r"C:\Program Files\RMT Agent\agent_host.exe";
        // Register the NAMESPACED scheme a real install writes, not the bare `rmt` — this is the
        // whole point of the loop-18 fix, and the round-trip must exercise it.
        let scheme = deployment_scheme("https://cp.example.com");
        assert!(scheme.starts_with("rmt-"), "a namespaced scheme, not bare rmt: {scheme}");
        let scheme_key = format!(r"{TEST_BASE}\{scheme}");
        let command_key = format!(r"{scheme_key}\shell\open\command");

        // Clean slate even if a previous run died mid-test.
        let _ = unregister_scheme_at(HKEY_CURRENT_USER, TEST_BASE, &scheme);

        register_scheme_at(HKEY_CURRENT_USER, TEST_BASE, &scheme, exe)
            .expect("register into HKCU scratch");
        assert_eq!(read_sz(&scheme_key, "").as_deref(), Some(SCHEME_DESCRIPTION));
        // Present and EMPTY: the presence of `URL Protocol` is the flag.
        assert_eq!(read_sz(&scheme_key, "URL Protocol").as_deref(), Some(""));
        assert_eq!(
            read_sz(&command_key, "").as_deref(),
            Some(open_command_line(exe).as_str())
        );

        // Re-registering is idempotent (an installer re-run must not fail).
        register_scheme_at(HKEY_CURRENT_USER, TEST_BASE, &scheme, exe).expect("re-register");
        assert_eq!(read_sz(&command_key, "").as_deref(), Some(open_command_line(exe).as_str()));

        unregister_scheme_at(HKEY_CURRENT_USER, TEST_BASE, &scheme).expect("unregister");
        assert_eq!(read_sz(&scheme_key, ""), None, "the scheme key must be gone");
        assert_eq!(read_sz(&command_key, ""), None, "the command subkey must be gone");
        // Removing an absent handler is not an error (uninstall must be re-runnable).
        unregister_scheme_at(HKEY_CURRENT_USER, TEST_BASE, &scheme).expect("unregister when absent");

        // Drop the scratch parent so the test leaves nothing behind. NOT via
        // `unregister_scheme_at`, which appends `\rmt` to its base — that call would target
        // `HKCU\Software\rmt`, i.e. somebody else's key.
        delete_tree(r"Software\RmtAgentUriTest");
        assert_eq!(read_sz(&scheme_key, ""), None);
    }

    /// **The re-enrollment orphan fix (review finding, docs/07 loop 18).** When an agent is
    /// re-pointed at a new control-plane origin and re-installed, install must reclaim the scheme it
    /// registered under the OLD origin — but never another deployment's handler, which points at a
    /// different exe.
    #[test]
    fn reclaim_removes_this_exes_stale_schemes_and_never_another_deployments() {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;

        const BASE: &str = r"Software\RmtAgentReclaimTest\Classes";
        let our_exe = r"C:\rmt-agent-bin\agent_host.exe";
        let other_exe = r"C:\other-deployment\agent_host.exe";

        let old = deployment_scheme("https://cp.example.com"); // our first origin
        let new = deployment_scheme("https://support.example.com"); // after a re-point/promote
        let foreign = deployment_scheme("https://third.example.com"); // ANOTHER deployment

        let _ = delete_tree(r"Software\RmtAgentReclaimTest");

        // State after a re-point that has not cleaned up: OUR old + OUR new both point at our exe,
        // plus a foreign deployment's handler pointing at a different exe.
        register_scheme_at(HKEY_CURRENT_USER, BASE, &old, our_exe).expect("old");
        register_scheme_at(HKEY_CURRENT_USER, BASE, &new, our_exe).expect("new");
        register_scheme_at(HKEY_CURRENT_USER, BASE, &foreign, other_exe).expect("foreign");
        // Also a legacy bare `rmt` this exe once registered — must be reclaimed too.
        register_scheme_at(HKEY_CURRENT_USER, BASE, SCHEME, our_exe).expect("legacy bare rmt");

        let removed = reclaim_other_schemes_at(HKEY_CURRENT_USER, BASE, our_exe, &new)
            .expect("reclaim");
        assert_eq!(removed, 2, "the old namespaced key AND the legacy bare rmt, both ours");

        // The current scheme survives; the foreign one (different exe) is untouched; ours are gone.
        assert!(read_sz(&format!(r"{BASE}\{new}"), "").is_some(), "the current scheme must remain");
        assert!(read_sz(&format!(r"{BASE}\{foreign}"), "").is_some(), "another deployment's key must survive");
        assert!(read_sz(&format!(r"{BASE}\{old}"), "").is_none(), "our stale origin key must be reclaimed");
        assert!(read_sz(&format!(r"{BASE}\{SCHEME}"), "").is_none(), "our legacy bare rmt must be reclaimed");

        // Idempotent: a second reclaim now finds nothing of ours but the keep.
        let again = reclaim_other_schemes_at(HKEY_CURRENT_USER, BASE, our_exe, &new).expect("reclaim 2");
        assert_eq!(again, 0, "nothing left of ours to reclaim");

        delete_tree(r"Software\RmtAgentReclaimTest");
    }

    #[test]
    fn command_targets_exe_matches_case_insensitively_and_only_the_named_exe() {
        let cmd = open_command_line(r"C:\rmt-agent-bin\agent_host.exe");
        assert!(command_targets_exe(&cmd, r"c:\RMT-agent-bin\Agent_Host.exe"), "case-insensitive");
        assert!(!command_targets_exe(&cmd, r"C:\other\agent_host.exe"), "a different path must not match");
        assert!(!command_targets_exe(&cmd, ""), "an empty exe never matches (would match everything)");
    }

    /// Delete a whole scratch subtree under `HKEY_CURRENT_USER` (test cleanup only).
    fn delete_tree(subkey: &str) {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER};
        let w = wide(subkey);
        // SAFETY: `w` is NUL-terminated UTF-16 outliving the call; a missing key is a status we
        // ignore.
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(w.as_ptr()));
        }
    }
}
