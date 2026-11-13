//! The downloadable guest stub — a per-download-configured copy of `agent_host.exe` that
//! self-configures from a placeholder patched into its own binary.
//!
//! # The gap this closes
//!
//! [`crate::uri`] is the *second-visit* accelerator: on a machine where the client is already
//! installed, a `rmt://` link turns a support code into one click. It cannot solve **first contact**
//! — a machine that has never run the client has no handler registered, so the link does nothing.
//! The remaining entry point is the one every commercial tool ships: the user downloads a small
//! one-time client and runs it. That client must know *which* deployment and *which* session it is
//! for **without a command line and without a config file** — the guest just double-clicks it.
//!
//! # Mechanism (measured from a real `ScreenConnect.ClientSetup.exe`, see the memory note
//! `screenconnect-stub-mechanism`)
//!
//! The configuration is **patched into a fixed placeholder inside the binary** — never the filename
//! (browsers rewrite those) and never a sidecar file (there is nothing to carry it). At download
//! time the server takes the pristine template binary, writes the session's parameters into the
//! placeholder, and re-signs the result with the operator's own code-signing certificate
//! (`scripts/sign-release.ps1`, which timestamps). The signature is valid on the per-download-unique
//! binary because SmartScreen reputation is **publisher-based, not per-file-hash** — a unique binary
//! per download does not reset reputation.
//!
//! What we embed is exactly a [`crate::uri`] attend link:
//!
//! ```text
//! rmt-<fingerprint>://attend?code=<CODE>&cp=<https-url>[&reason=<text>]
//! ```
//!
//! so the stub reuses [`crate::uri::parse_attend_uri`] **verbatim** — the same hardened, fail-closed
//! parser the browser handoff uses, with the same character allow-lists, the same URL policy, and
//! the same `auto_consent = false`. A configured stub is therefore identical in security posture to
//! a clicked link; it just does not need a handler registered first.
//!
//! ## Why no embedded server public key (the ScreenConnect `k`)
//!
//! ScreenConnect embeds the server's public key so the client can pin it on first contact — that is
//! MITM protection for a transport that is not necessarily TLS-with-a-CA. RMT's redeem is **HTTPS
//! with certificate validation on** (rustls native roots — see the memory note
//! `tls-client-trust-native-roots`), so first-contact trust is the TLS certificate of the `cp` URL
//! the operator baked in, and the grant-issuer key the guest pins for backstage is returned in the
//! redeem response and pinned per session ([`crate::attend::AttendRedeem::grant_issuer_pubkey`]).
//! An embedded key would duplicate trust the transport already establishes. The one honest
//! consequence versus ScreenConnect: a *private-CA* RMT deployment needs the guest's machine to
//! trust the operator's CA for the HTTPS redeem to succeed — the same requirement RMT's attended
//! flow already had before this stub existed. Pinning an embedded key is a possible future
//! enhancement, recorded, not shipped.
//!
//! # The placeholder, and why it survives compilation (this is the fiddly part — it was measured)
//!
//! [`RMT_STUB_SLOT`] is a `#[used] #[no_mangle] static [u8; SLOT_LEN]`. Three properties, each
//! verified empirically before this shipped (a standalone spike, then the release binary):
//!
//! 1. **It lands in the file, once.** A `static` with any non-zero byte in its initializer is
//!    *initialized data* → the linker writes it into `.rdata` in full (an all-zero static would go
//!    to `.bss` and carry no bytes in the file). The slot begins with a 32-byte [`MAGIC`] and is
//!    padded with a non-zero [`FILLER`], so every byte is present on disk.
//! 2. **`#[used]` + `#[no_mangle]` keep it through the rlib→bin link** even though nothing at
//!    runtime reads the static (the config is read back from the *file*, below). [`anchor`] adds a
//!    black-boxed reference from an always-called path as belt-and-suspenders against a future
//!    codegen-unit split.
//! 3. **The plaintext magic appears in the binary exactly once — in the slot.** The magic is stored
//!    in source only in its XOR-obfuscated form ([`MAGIC_OBF`]); both the slot builder (at
//!    const-eval time) and the runtime [`needle`] deobfuscate it. The runtime deobfuscation is fed
//!    through [`std::hint::black_box`] so the optimizer cannot const-fold it back into a *second*
//!    plaintext copy in `.rdata` — measured: without the black_box the plaintext appeared twice and
//!    the scan was ambiguous.
//!
//! At run time a configured stub reads its own executable file, scans for the single magic, and
//! recovers the payload. Reading the *file* (rather than the in-memory static) sidesteps a subtle
//! trap: the compiler treats an immutable static's value as a known constant and may fold a direct
//! read to the *template* value, ignoring the bytes the patcher wrote — file bytes are unambiguous
//! runtime data.

/// Byte length of the magic marker at the head of the slot.
const MAGIC_LEN: usize = 32;
/// Header = magic + a little-endian `u32` payload length.
const HEADER_LEN: usize = MAGIC_LEN + 4;
/// Capacity of the payload region. Matches [`crate::uri::MAX_URI_BYTES`] — the embedded value is an
/// attend URI and the URI parser refuses anything longer, so a larger slot would be dead space.
pub const PAYLOAD_CAP: usize = crate::uri::MAX_URI_BYTES;
/// Total slot size written into the binary.
const SLOT_LEN: usize = HEADER_LEN + PAYLOAD_CAP;

/// The slot must be able to hold any URI the shared parser accepts — the URI's grammar bound
/// ([`crate::uri::MAX_URI_BYTES`]) is the SINGLE length constraint, and the slot is sized to it. This
/// compile-time check makes "a valid attend link always fits" a guarantee rather than a runtime
/// branch that (because the two constants are equal) could never fire and so could never be tested.
const _SLOT_FITS_ANY_VALID_URI: () = assert!(PAYLOAD_CAP >= crate::uri::MAX_URI_BYTES);
/// Non-zero pad byte. MUST be non-zero so the whole static is initialized data and is written to the
/// file (an all-zero static lands in `.bss` and carries no on-disk bytes to patch).
const FILLER: u8 = 0xEE;

/// The marker, stored ONLY XOR-obfuscated so the plaintext 32-byte sequence is never a code literal
/// (it would otherwise appear a second time in `.rdata` and make the slot scan ambiguous). The
/// plaintext begins with the ASCII tag `RMT-STUB-CFGv1::` purely to make a hex dump legible.
const MAGIC_OBF: [u8; MAGIC_LEN] = [
    0xf5, 0xea, 0xf3, 0x8a, 0xf4, 0xf3, 0xf2, 0xe5, 0x8a, 0xe4, 0xe1, 0xe0, 0xd1, 0x96, 0x9d, 0x9d,
    0x28, 0x83, 0x16, 0xc9, 0x74, 0xad, 0xf0, 0x0b, 0xbe, 0x55, 0xea, 0x21, 0x67, 0x9c, 0x32, 0xd9,
];
/// XOR key that turns [`MAGIC_OBF`] back into the plaintext magic.
const XOR_KEY: u8 = 0xA7;

/// The plaintext magic, computed at compile time from [`MAGIC_OBF`]. Used only inside the const-eval
/// of [`build_slot`], so its bytes are materialized exactly once — as the slot's leading bytes.
const MAGIC: [u8; MAGIC_LEN] = {
    let mut m = [0u8; MAGIC_LEN];
    let mut i = 0;
    while i < MAGIC_LEN {
        m[i] = MAGIC_OBF[i] ^ XOR_KEY;
        i += 1;
    }
    m
};

/// Construct the pristine (unpatched) slot: magic, a zero length, then filler. A zero length is how
/// a normally-built `agent_host.exe` is recognised as *not a configured stub*.
const fn build_slot() -> [u8; SLOT_LEN] {
    let mut a = [FILLER; SLOT_LEN];
    let mut i = 0;
    while i < MAGIC_LEN {
        a[i] = MAGIC[i];
        i += 1;
    }
    // Little-endian u32 length = 0 (template). Bytes are FILLER otherwise, so overwrite the four.
    a[MAGIC_LEN] = 0;
    a[MAGIC_LEN + 1] = 0;
    a[MAGIC_LEN + 2] = 0;
    a[MAGIC_LEN + 3] = 0;
    a
}

/// The embedded configuration placeholder. See the module docs for why the attributes and the
/// non-zero filler are load-bearing.
#[used]
#[no_mangle]
pub static RMT_STUB_SLOT: [u8; SLOT_LEN] = build_slot();

/// Force a reference to [`RMT_STUB_SLOT`] from an always-linked path so the linker cannot drop the
/// static regardless of codegen-unit layout. The black_box keeps the reference from being elided and
/// prevents the optimizer from reasoning about the static's contents. Returns the address purely so
/// the call cannot be optimized to a no-op.
#[inline(never)]
pub fn anchor() -> usize {
    std::hint::black_box(RMT_STUB_SLOT.as_ptr()) as usize
}

/// The 32-byte search needle: [`MAGIC_OBF`] deobfuscated at runtime. Fed through `black_box` so the
/// optimizer cannot const-fold it into a stored plaintext constant (which would be a second magic in
/// the binary). Do not "simplify" this to a plain XOR of the const array — that reintroduces the
/// duplicate the whole obfuscation exists to prevent.
fn needle() -> [u8; MAGIC_LEN] {
    let obf = std::hint::black_box(MAGIC_OBF);
    let mut n = [0u8; MAGIC_LEN];
    let mut i = 0;
    while i < MAGIC_LEN {
        n[i] = obf[i] ^ XOR_KEY;
        i += 1;
    }
    n
}

/// Locate the single slot magic in `bytes`. Requires **exactly one** occurrence: zero means the
/// binary was not built with a slot (should be impossible for `agent_host`); more than one means
/// something is wrong and picking one would be a guess, so both are refused.
pub fn locate_slot(bytes: &[u8]) -> Result<usize, String> {
    let n = needle();
    let mut found: Option<usize> = None;
    let mut count = 0usize;
    if bytes.len() >= MAGIC_LEN {
        for i in 0..=bytes.len() - MAGIC_LEN {
            if bytes[i..i + MAGIC_LEN] == n[..] {
                count += 1;
                if found.is_none() {
                    found = Some(i);
                }
            }
        }
    }
    match (found, count) {
        (Some(off), 1) => Ok(off),
        (None, _) => Err("stub slot magic not found in binary".to_string()),
        (_, n) => Err(format!("stub slot magic found {n} times — ambiguous, refusing")),
    }
}

/// Read the embedded payload out of a full binary image. `Ok(None)` means a pristine template
/// (length 0); `Ok(Some(uri))` is a configured stub. A corrupt header (length past the slot,
/// non-UTF-8 payload) is an `Err`, not a silent empty.
pub fn read_embedded(bytes: &[u8]) -> Result<Option<String>, String> {
    let off = locate_slot(bytes)?;
    // `locate_slot` only guarantees the 32 magic bytes fit; a truncated or crafted image could put
    // the length/payload past EOF. Bounds-check before every read so this fails closed instead of
    // panicking.
    if off + HEADER_LEN > bytes.len() {
        return Err("stub slot header runs past the end of the binary — truncated".to_string());
    }
    let len_at = off + MAGIC_LEN;
    let len = u32::from_le_bytes([
        bytes[len_at],
        bytes[len_at + 1],
        bytes[len_at + 2],
        bytes[len_at + 3],
    ]) as usize;
    if len == 0 {
        return Ok(None);
    }
    if len > PAYLOAD_CAP {
        return Err(format!(
            "stub payload length {len} exceeds the {PAYLOAD_CAP}-byte slot capacity — corrupt"
        ));
    }
    let start = off + HEADER_LEN;
    if start + len > bytes.len() {
        return Err("stub payload runs past the end of the binary — truncated".to_string());
    }
    let payload = &bytes[start..start + len];
    let s = std::str::from_utf8(payload)
        .map_err(|_| "stub payload is not valid UTF-8 — corrupt".to_string())?;
    Ok(Some(s.to_string()))
}

/// Read the embedded attend URI from THIS process's own executable, or `None` if this is an
/// unconfigured build (or the exe cannot be read). Fails closed: any error is logged at debug and
/// treated as "no embedded config", so a normally-built `agent_host` run with no arguments falls
/// through to its usage message rather than misbehaving.
///
/// Reading the file (not the in-memory [`RMT_STUB_SLOT`]) is deliberate — see the module docs.
pub fn embedded_config() -> Option<String> {
    // Anchor the static (belt-and-suspenders retention) — see `anchor`.
    let _ = anchor();
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "stub: current_exe() failed; no embedded config");
            return None;
        }
    };
    let bytes = match std::fs::read(&exe) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "stub: could not read own exe; no embedded config");
            return None;
        }
    };
    match read_embedded(&bytes) {
        Ok(cfg) => cfg,
        Err(e) => {
            // A corrupt slot must never be acted on. Fail closed.
            tracing::warn!(error = %e, "stub: embedded slot is corrupt; ignoring");
            None
        }
    }
}

/// Produce a per-download binary: a copy of `template` with `attend_uri` written into the slot.
///
/// Pure and side-effect free (the caller owns file I/O and re-signing). Validates that:
/// * `template` has exactly one pristine-or-not slot ([`locate_slot`]);
/// * `attend_uri` is a **valid attend link** — parsed by the very same
///   [`crate::uri::parse_attend_uri`] the running stub will use, so a stub that patches can never
///   produce a payload the reader would reject; and
/// * the payload fits the slot.
///
/// The whole payload region is rewritten (payload then [`FILLER`]) so no bytes from a previously
/// patched template can survive past the new length.
pub fn patch(template: &[u8], attend_uri: &str) -> Result<Vec<u8>, String> {
    // Validate the URI up front with the reader's own parser — one validation path, not two. This
    // also bounds the length: `parse_attend_uri` refuses anything over `MAX_URI_BYTES`, and the slot
    // is compile-time guaranteed to fit that (`_SLOT_FITS_ANY_VALID_URI`), so a parse-accepted URI
    // always fits the payload region below.
    crate::uri::parse_attend_uri(attend_uri)
        .map_err(|e| format!("refusing to embed an invalid attend URI: {e}"))?;
    let payload = attend_uri.as_bytes();

    let off = locate_slot(template)?;
    // The full slot must be present to patch it (a truncated template would otherwise overrun).
    if off + SLOT_LEN > template.len() {
        return Err("template slot runs past the end of the binary — truncated".to_string());
    }
    let mut out = template.to_vec();

    // Length (LE u32).
    let len_at = off + MAGIC_LEN;
    let len_bytes = (payload.len() as u32).to_le_bytes();
    out[len_at..len_at + 4].copy_from_slice(&len_bytes);

    // Payload region: the URI, then FILLER for the remainder (no stale bytes).
    let start = off + HEADER_LEN;
    out[start..start + payload.len()].copy_from_slice(payload);
    for b in &mut out[start + payload.len()..start + PAYLOAD_CAP] {
        *b = FILLER;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pristine slot assembled at RUNTIME from [`needle`] (not [`build_slot`]).
    ///
    /// This matters: calling `build_slot()` at runtime reads the `MAGIC` const, which makes the
    /// optimizer materialize `MAGIC`'s plaintext bytes in `.rdata` — a SECOND magic that would make
    /// the real binary carry two and break the exactly-one invariant. In the shipped `agent_host`,
    /// `build_slot()` runs only in the const initializer, so `MAGIC` is never materialized at
    /// runtime. The tests must not reintroduce it, so they synthesize the slot the black-box-safe
    /// way, exactly as the runtime reader derives its needle.
    fn synthetic_slot() -> Vec<u8> {
        let mut s = vec![FILLER; SLOT_LEN];
        s[..MAGIC_LEN].copy_from_slice(&needle());
        s[MAGIC_LEN..MAGIC_LEN + 4].copy_from_slice(&0u32.to_le_bytes()); // length 0 = template
        s
    }

    /// A synthetic binary image: junk, a pristine slot, more junk. Lets the pure functions be tested
    /// without building/patching a real exe (and independent of the build profile).
    fn synthetic_image() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xAB; 137]); // leading junk
        v.extend_from_slice(&synthetic_slot()); // a slot byte-identical to the linker's
        v.extend_from_slice(&[0xCD; 91]); // trailing junk
        v
    }

    #[test]
    fn a_pristine_template_reads_as_no_config() {
        let img = synthetic_image();
        assert_eq!(read_embedded(&img).unwrap(), None, "len 0 ⇒ no embedded config");
    }

    #[test]
    fn patch_then_read_round_trips() {
        let img = synthetic_image();
        let uri = "rmt-ef00d58d898ca752://attend?code=ABCD1234WXYZ9&cp=https://cp.example.com&reason=Acme%20IT";
        let patched = patch(&img, uri).expect("patch a valid URI");
        // Same length — patching never resizes the image (it must not shift any other bytes).
        assert_eq!(patched.len(), img.len(), "patching must not resize the binary");
        assert_eq!(read_embedded(&patched).unwrap().as_deref(), Some(uri));
        // And the recovered URI parses back to the same attend fields.
        let parsed = crate::uri::parse_attend_uri(&read_embedded(&patched).unwrap().unwrap()).unwrap();
        assert_eq!(parsed.code, "ABCD1234WXYZ9");
        assert_eq!(parsed.control_plane_url, "https://cp.example.com");
        assert_eq!(parsed.reason, "Acme IT");
    }

    #[test]
    fn re_patching_physically_clears_the_stale_tail() {
        // A long URI then a short one. The length-bounded read returns the new URI either way, so
        // that assertion alone does NOT test the clear — the tail must be inspected DIRECTLY. Why it
        // matters: the previous payload is a one-time attend code (a bearer secret), and it must not
        // linger in the binary's dead space after a shorter re-patch.
        let img = synthetic_image();
        let long = format!(
            "rmt://attend?code=ABCD1234&cp=https://cp.example.com&reason={}",
            "a".repeat(200)
        );
        let once = patch(&img, &long).unwrap();
        let short = "rmt://attend?code=Z9&cp=https://cp.example.com";
        let twice = patch(&once, short).unwrap();
        assert_eq!(read_embedded(&twice).unwrap().as_deref(), Some(short));

        // The whole payload region past the new URI is physically FILLER — no stale bytes.
        let off = locate_slot(&twice).unwrap();
        let tail = &twice[off + HEADER_LEN + short.len()..off + SLOT_LEN];
        assert!(tail.iter().all(|&b| b == FILLER), "the stale tail must be overwritten with FILLER");
        // Concretely: the long URI's distinctive 'aaaa…' run must be gone from the whole image.
        assert!(
            !twice.windows(50).any(|w| w == [b'a'; 50]),
            "no stale run from the long URI may survive the shorter re-patch"
        );
    }

    #[test]
    fn patch_refuses_an_invalid_attend_uri() {
        let img = synthetic_image();
        // The "not-a-uri" case is the one that pins the parse validation: with it deleted from
        // `patch`, this garbage would be embedded and `patch` would return Ok — so is_err() fails.
        let over_long = format!(
            "rmt://attend?code=A&cp=https://cp.example.com&reason={}",
            "x".repeat(crate::uri::MAX_URI_BYTES)
        );
        for bad in [
            "not-a-uri",
            "https://attend?code=A&cp=https://cp.example.com", // wrong scheme
            "rmt://attend?cp=https://cp.example.com",           // no code
            "rmt://attend?code=--auto-consent&cp=https://cp.example.com", // flag-shaped code
            "rmt://attend?code=A&cp=http://evil.example",       // http to non-loopback
            over_long.as_str(),                                 // over the URI grammar's length bound
        ] {
            assert!(patch(&img, bad).is_err(), "{bad:?} must be refused before embedding");
        }
    }

    #[test]
    fn read_and_patch_fail_closed_on_a_truncated_slot() {
        // A magic at the very end with no room for the header/payload must NOT panic — both paths
        // bounds-check and return Err. (locate_slot only guarantees the 32 magic bytes fit.)
        let mut trunc = vec![0u8; 10];
        trunc.extend_from_slice(&needle()); // magic, then EOF: header runs past the end
        assert!(read_embedded(&trunc).is_err(), "truncated header must be refused, not panic");
        assert!(
            patch(&trunc, "rmt://attend?code=A1&cp=https://cp.example.com").is_err(),
            "patching a truncated template must be refused, not panic"
        );
    }

    #[test]
    fn locate_requires_exactly_one_slot() {
        // Zero slots.
        assert!(locate_slot(&[0u8; 500]).is_err(), "no magic ⇒ error");
        // Exactly one.
        let img = synthetic_image();
        assert!(locate_slot(&img).is_ok(), "one magic ⇒ Ok");
        // Two slots ⇒ ambiguous.
        let mut two = synthetic_image();
        two.extend_from_slice(&synthetic_slot());
        let err = locate_slot(&two).expect_err("two magics ⇒ error");
        assert!(err.contains("ambiguous") || err.contains("2 times"), "{err}");
    }

    #[test]
    fn an_over_capacity_length_is_refused_before_reading_past_the_slot() {
        // The payload region here is VALID ASCII, so the ONLY thing that can refuse an over-capacity
        // length is the explicit cap check — with a FILLER payload the read would fail UTF-8
        // regardless and hide a deleted cap check (a second mechanism satisfying the assertion).
        let mut v = Vec::new();
        v.extend_from_slice(&[b'A'; 50]); // leading junk (ASCII)
        v.extend_from_slice(&needle()); // magic
        v.extend_from_slice(&(PAYLOAD_CAP as u32 + 16).to_le_bytes()); // length just over the cap
        v.extend_from_slice(&vec![b'B'; PAYLOAD_CAP + 32]); // ASCII payload + slack, so the read is in-bounds
        let off = locate_slot(&v).unwrap();
        // Without the cap check the over-length read would be IN-BOUNDS and valid UTF-8 — i.e. only
        // the cap check stands between it and a wrong Ok(Some(..)).
        assert!(off + HEADER_LEN + PAYLOAD_CAP + 16 <= v.len(), "the over-length read would be in-bounds");
        assert!(read_embedded(&v).is_err(), "a length over the slot capacity must be refused");
    }

    #[test]
    fn a_truncated_payload_is_refused() {
        // A length WITHIN the cap but pointing past EOF must be refused by the payload-bounds check
        // (removing it makes the slice read panic — still lethal to this test).
        let mut v = Vec::new();
        v.extend_from_slice(&[b'A'; 50]);
        v.extend_from_slice(&needle());
        v.extend_from_slice(&100u32.to_le_bytes()); // claim 100 bytes…
        v.extend_from_slice(&[b'B'; 20]); // …but only 20 are present before EOF
        assert!(read_embedded(&v).is_err(), "a payload running past EOF must be refused, not read");
    }

    #[test]
    fn a_non_utf8_payload_is_refused() {
        let mut img = synthetic_image();
        let off = locate_slot(&img).unwrap();
        // len = 2, payload = invalid UTF-8 (a lone 0xFF 0xFE).
        img[off + MAGIC_LEN..off + MAGIC_LEN + 4].copy_from_slice(&2u32.to_le_bytes());
        img[off + HEADER_LEN] = 0xFF;
        img[off + HEADER_LEN + 1] = 0xFE;
        assert!(read_embedded(&img).is_err(), "non-UTF-8 payload must be refused");
    }

    /// **The load-bearing "it survives compilation" test.** The `#[used]` static must be present in
    /// this very test process's own binary, exactly once, with a zero length (the test binary is
    /// never patched). If a refactor or a compiler change drops the static or duplicates the magic,
    /// this goes red — which is the whole early-warning point.
    #[test]
    fn the_running_binary_carries_exactly_one_pristine_slot() {
        let exe = std::env::current_exe().expect("current_exe");
        let bytes = std::fs::read(&exe).expect("read own exe");
        let off = locate_slot(&bytes).expect("exactly one slot in the test binary");
        let len_at = off + MAGIC_LEN;
        let len = u32::from_le_bytes([
            bytes[len_at],
            bytes[len_at + 1],
            bytes[len_at + 2],
            bytes[len_at + 3],
        ]);
        assert_eq!(len, 0, "the test binary is a pristine template (length 0)");
        assert_eq!(read_embedded(&bytes).unwrap(), None);
        // Deliberately NO `anchor()` call here. Referencing the static from the test would itself
        // keep the linker from dropping it, so the test would pass even if `#[used]`/`#[no_mangle]`
        // stopped working — masking the very retention failure this guard exists to catch. Nothing
        // in the test path references RMT_STUB_SLOT, so its presence in THIS binary is owed to
        // `#[used]` alone (same-crate, so archive-member selection cannot drop it). The RELEASE
        // artifact is additionally scanned by build-release.ps1's Assert-StubSlot, which is where the
        // optimizer-dependent claims (const-fold, LTO) are actually validated.
    }
}
