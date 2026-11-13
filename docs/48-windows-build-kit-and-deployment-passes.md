# Windows build kit (B) and deployment passes (C) — design v3

This reference describes deployment-specific builds and the generic deployment-pass design.
Self-hosters can build and sign their own binaries.

- **B, the build kit.** A self-hoster builds DeskRally's Windows binaries with their own server
  address baked in, and signs them with **their own** certificate. DeskRally's signature is never
  involved.
- **C, deployment passes.** DeskRally ships one generic, DeskRally-signed installer
  (`DeskRallySetup.exe`) and one generic support tool (`DeskRallySupport.exe`). Neither has a server
  address built in. Each runs only for a server that holds a short-lived **deployment pass**: a file
  signed with DeskRally's key that names that server.

A generic signed installer must authenticate the server configuration it accepts. A deployment
pass binds that configuration to an authorized origin and limits its validity.

## What exists today (facts)

**DeskRallySetup.exe** (`packaging/setup/setup.cpp`).
- `scripts/build-setup.ps1` generates `setup_config.h` with `SETUP_CONTROL_PLANE_URL`,
  `SETUP_SIGNALING_URL`, `SETUP_GRANT_ISSUER_PUBKEY` and `SETUP_MSI_SHA256`.
- At run time it reads only `DeskRallyAgent.msi` and `enrollment.token` from its own folder. That
  folder must be on a local fixed drive with no reparse points, and its parent folders are held open.
- It verifies the MSI against the baked SHA-256, using BCrypt. It verifies no signature.
- It stages the MSI into a SYSTEM-and-Administrators-only folder and hashes it again there.
- The consent dialog shows the baked control-plane URL.

**DeskRallySupport.exe** (`crates/agent-windows/src/support.rs`).
- It has one baked value, `RMT_CONTROL_PLANE_URL`, which the `agent-core` build reads from the
  environment.
- The signaling URL and the grant key come from the control plane's redeem response.
- It reads `session.code` from beside itself.

**Control plane** (`managed_install.go`).
- At startup it validates `installer-manifest.json` against its own configuration; a mismatch is
  fatal.
- It serves `DeskRally-Install.zip` (Setup, MSI, a fresh 15-minute single-use `enrollment.token`)
  and `DeskRally-Support.zip` (support exe and `session.code`).

**The agent MSI is generic already**: it gets its settings from a provisioning file. Its update feed,
update key and publisher pin are fixed at compile time.

## B — the build kit

1. **`scripts/build-windows-kit.ps1`**
   - Takes `-ServerUrl https://remote.example.com` (the control-plane URL and `wss://…/ws` are derived
     from it), `-GrantIssuerPubkey`, a signing choice (`LocalCertificate -CertThumbprint …`,
     `AzureArtifact …`, or `-Unsigned`) and `-OutDir`.
   - Builds, in one run: the agent MSI (unchanged), a BAKED-mode Setup, and a BAKED-mode Support.
   - **Signs every final artifact before hashing anything.** It then writes:
     - `installer-manifest.json`, now including `support_sha256` (no script writes it today);
     - `SHA256SUMS`;
     - a README saying which file goes into `MANAGED_INSTALL_HOST_DIR` and which into `ARTIFACT_DIR`.
   - Builds into a clean output directory every time.
   - Wraps the existing `build-msi.ps1`, `build-setup.ps1` and `build-release.ps1`.
2. **`scripts/install-windows-build-prereqs.ps1`** (optional). Uses winget, check-then-install, for:
   - VS Build Tools (C++ workload + Windows SDK);
   - rustup (MSVC toolchain);
   - vcpkg `libvpx`/`opus` `x64-windows-static`;
   - the WiX CLI;
   - Node 20.
3. **Agent update trust for kit-built agents.** This is a real trust-policy choice, so it is specified
   in full.
   - **None (default).** Source and kit builds have no update feed, signer pin, or publisher.
     Auto-update is off. The kit packages this mode with `-AllowNoPin -ExpectedFeed none`.
   - **Official (opt-in).** Set `DESKRALLY_UPDATE_OFFICIAL=1`, or pass `-OfficialUpdates` to the kit,
     to trust `packaging/official-update-identity.json` and `packaging/update-signer-pubkey.hex`.
     Official updates keep the operator's provisioning (server URL, enrollment).
     This selector cannot be combined with own-feed inputs or `update-test-feed`.
   - **Own feed (advanced).** `DESKRALLY_UPDATE_FEED`, `DESKRALLY_UPDATE_PUBKEY_FILE`, and the
     operator's publisher subject (`DESKRALLY_UPDATE_PUBLISHER`) are build-time inputs.
     - All three must be set together, or the build fails.
     - `msi-capabilities` prints all three.
     - Official DeskRally updates then never reach that fleet.
     - **The operator's update-signing key is what actually authenticates an update.** Its signed
       manifest binds the MSI's SHA-256, version and product identity, and the agent verifies the
       staged MSI against it. The publisher check only matches the subject name on an otherwise
       valid Authenticode signature, so it is a secondary check, not a key identity: another
       certificate can carry the same subject. DeskRally's own pin works the same way today, and
       this is accepted deliberately. Pinning a certificate or key fingerprint instead would break at
       every certificate renewal, and Azure Trusted Signing certificates are valid for only days.
   - The kit accepts own-feed inputs through `-UpdateFeed`, `-UpdatePubkeyFile`, and `-UpdatePublisher`.
     Its summary states the selected mode. Only the exact non-empty official selector `1` is accepted.
4. **Docs**: a "Build your own Windows binaries" section in `docs/guides/server-deployment.md`.

## C — deployment passes

### Principles

1. **Explicit build modes.** Every Setup and Support is built in one of two modes.
   - `MODE=BAKED` is today's behaviour. Every baked field and the MSI hash are required, and a partial
     configuration fails the build.
   - `MODE=PASS` is generic. It requires the compiled-in pass root key, and any baked server value
     fails the build.
   - The mode is a compile-time constant. It is shown by Support's `--deployment` and by Setup's
     version resource, and the signing pipeline asserts it.
   - **A broken baked build can never fall through to pass mode.**
2. **Short-lived passes; revoking means not renewing.**
   - A pass is valid for **at most 31 days**. Refusing to renew it revokes it within that window for
     correctly clocked clients, and at once for new installs from a cooperating server, which checks
     against its own clock. A guest who rolls the clock back can bypass this indefinitely; see the
     clock limitation below. It fails closed and needs no network access to DeskRally from guests or
     servers.
   - There is no online revocation list in v1. Failing open is bypassable,
     and failing closed makes every guest depend on DeskRally.
   - Phase 1: renewal is manual (`rmt-pass-sign issue`, few customers).
   - Future design: automated renewal through an online, root-certified,
     short-lived issuing key.
3. **Release attestations keep Setup's exact-hash guarantee.**
   - A generic Setup has no baked MSI hash. Instead, DeskRally signs one **agent release attestation**
     per published MSI. It uses the same root key with a separate purpose and domain.
   - Setup verifies the **staged** MSI's SHA-256 and size **exactly** against the attestation. There
     is no Authenticode or "any DeskRally package" trust.
   - Old, vulnerable releases are refused by the pass's `min_agent_version` and by the attestation's
     own expiry (at most 13 months).
   - Downgrading an installed agent stays refused by the MSI's Upgrade table, which is existing and
     tested behaviour.
4. **Issuing a pass is a security boundary, not a utility.** See "Issuance policy".

### Formats (one specification, three implementations)

**The envelope.** Every signed object uses `{ "format": 1, "body": "<base64>", "sig": "<128 hex>" }`,
at most 4 KiB.
- **Signature:** ECDSA P-256 over **SHA-256(domain ‖ body bytes)**, hashed exactly once.
  - `sig` is the fixed-width 64-byte big-endian `r ‖ s`, with r and s in [1, n−1]. No low-S rule.
  - Domains are NUL-terminated ASCII:
    - `DRPASS1\0`: deployment pass;
    - `DRREL1\0`: agent release attestation;
    - `DRISSUER1\0`: phase 2 only.
  - Domain separation means a signature made for one purpose never verifies as another.
- **Public keys:** SEC1 uncompressed, 65 bytes, hex. Off-curve points are rejected; CNG import, Go and
  Rust's `p256` all validate them.
- **Why P-256 and not Ed25519:**
  - Setup is C++ with only Windows CNG. CNG verifies P-256 on every supported Windows, but not Ed25519
    on Windows 10, so Ed25519 would mean vendoring crypto into a binary that runs elevated.
  - Go and Rust both handle P-256 natively.
- **Why the signed bytes are embedded:** three languages never have to agree on JSON
  canonicalisation.
- **Body rules:**
  - Strict UTF-8 JSON object, at most 2 KiB.
  - Duplicate keys are rejected, unknown keys are rejected, and every field is required with an exact
    type.
  - No NUL or control characters anywhere.
  - Parsed **once** into an immutable value. Those values are the only ones used for display,
    provisioning and network calls.

**Deployment pass body:**
- `purpose: "deskrally-deployment-pass"`, `v: 1`
- `pass_id` (UUID)
- `issued_to`: 1–64 characters from `[A-Za-z0-9 .,&'()-]`
- `origin`: exactly `https://<host>[:<port>]`
  - lowercase ASCII host, with internationalised names in punycode;
  - default port omitted;
  - no path, userinfo, query or fragment.
- `grant_issuer_pubkey`: 64 lowercase hex characters
- `uses`: a non-empty subset of `["setup","support"]`
- `min_agent_version`: `X.Y.Z`
- `issued_at`, `expires_at`: UTC timestamps spelled exactly `YYYY-MM-DDTHH:MM:SSZ` (an RFC 3339
  subset: whole seconds, no offset, chosen so three implementations parse one spelling), with
  `expires_at − issued_at` ≤ 31 days

The control-plane URL is **derived** as `origin + "/cp"` and signaling as `wss://<host[:port]>/ws`,
the layout every DeskRally server uses. So there is one canonical form and no URL-equality policy to
get wrong.

**Release attestation body:**
- `purpose: "deskrally-agent-release"`, `v: 1`
- `msi_sha256`, `msi_size`
- `product_version`, `product_code`, `upgrade_code`
- `arch: "x64"`
- `issued_at`, `expires_at` (at most 13 months apart, fixed at **396 days** so no implementation
  needs calendar arithmetic)

**Pinned by slice 2** (`control-plane/deployment_pass.go`, the reference implementation):
- Timestamps are spelled exactly `YYYY-MM-DDTHH:MM:SSZ` (no fraction, no offset).
- `body` must be the **canonical** padded standard base64 of the body bytes: re-encoding the
  decoded bytes must reproduce it exactly. This refuses embedded CR/LF (Go's decoder skips them
  even in strict mode), extra padding and nonzero padding bits.
- The Go verifier returns **opaque verified values**: `DeploymentPass` and `AgentRelease` have
  only accessors, and `Claims()` returns a copy. The signer's input types, `*Claims`, are separate,
  and slices 3 to 5 must consume only the verified types.
- `pass_id` is a lowercase canonical UUID.
- `msi_size` is 1 to 2³¹−1.
- The envelope may contain JSON whitespace. The body may contain spaces but no other control bytes
  (so no tab or newline).
- **Check order**, so every implementation reports the same kind for the same input:
  `key` → `envelope` → `signature` → `body` → `validity`.
- Low-S is not enforced: the negated-s twin of a valid signature verifies.
- **The shared contract** is `control-plane/testdata/deployment-pass-vectors.json`: 138 vectors,
  generated by `go test -run TestGenerateDeploymentPassVectors -update-pass-vectors`. Each gives the
  exact file bytes, a clock, the expected kind and, for valid objects, the parsed fields. The Rust
  and C++ verifiers must pass the same file.

**Validity:** `issued_at − 5 min ≤ now < expires_at`, with no grace after expiry.

**Clock limitation, stated honestly.** Every time check made by a client uses the guest's own clock.
A guest who rolls their clock back, or an attacker who controls the victim's clock, can bypass pass
expiry, attestation expiry and the client lifetime **indefinitely**. Client-side expiry is a
best-effort bound, not a guarantee.

**The checks that do hold run on the server's clock:**
- the control plane serves an install bundle only while its pass is valid by its own clock;
- the 15-minute, single-use enrollment token inside that bundle is minted and enforced by the server.

So once a pass lapses, a legitimate server stops new permanent enrolments, whatever any guest's clock
says. Clock rollback only helps someone who already controls the victim's machine, or an attacker
server presenting a stale pass, and that pass still names only the customer origin it was issued for.

### Client lifetime (mitigation for a key compromise, not a recovery guarantee)

- Generic binaries embed their build date and refuse every pass once the build is older than 18
  months, judged by the guest's clock. On victims whose clocks are correct, this retires old generic
  tools after a root-key compromise. Clock rollback defeats it (see above).
- To rotate: ship new generic builds with a new root key.
- No stronger recovery exists without trusted time, which this design does not add. Keeping the key
  off servers is the main defence.

### Pass issuer policy

- **Who gets a pass:** only an accountable, recorded customer (legal name, contact, server origin).
- **Domain control is verified before the first issue and at every renewal.** The customer's server
  serves `https://<origin>/.well-known/deskrally-pass-challenge` with a DeskRally-chosen nonce.
  `rmt-pass-sign issue` performs the check itself and refuses on a mismatch.
- **Abuse:** on a credible report the pass is not renewed, so it lapses within 31 days for correctly
  clocked clients. In an emergency, the next generic build can ship a denylist of `pass_id`s.
- **Residual risk, stated plainly:** an approved customer who turns malicious, a compromised customer
  server, a stolen technician account, or a transferred customer domain can still use DeskRally's
  signed tools against victims for the rest of the pass's life. Against a victim whose clock was
  rolled back, that can be indefinite. Passes make abuse **accountable**, and time-bounded for
  correctly clocked victims; they do not make it impossible.
- **Operator key management:**
  - If you operate your own pass signer, keep your root key off servers and CI runners.
  - `rmt-pass-sign` protects its key with an owner-only Windows ACL and DPAPI (CurrentUser).
    `rmt-update-sign` uses a separate plain hex seed file; restrict access to that file.
  - A DPAPI-bound key cannot be restored on another account or machine, so there is a deliberate
    backup path:
    - `rmt-pass-sign export-key -key FILE -out BACKUP` asks twice for a passphrase of at least 16
      characters (console, echo off; never a flag or the environment).
    - It seals the scalar with AES-256-GCM under argon2id (t=4, 256 MiB, 4 lanes). The public key
      and every KDF parameter are authenticated data.
    - It proves the backup restores before writing it, and never overwrites.
    - `import-key -backup BACKUP -key FILE` decrypts it, checks the scalar reproduces the recorded
      public key, and writes a fresh DPAPI key file.
    - Parameters read from a file are bounded, so a crafted backup cannot demand unbounded work.
    - Store the backup OFFLINE in two places, with the passphrase kept apart from the file.
  - `gen-key` uses exclusive creation.
  - The issuing tool requires network access, because `rmt-pass-sign issue` performs the domain challenge
    over HTTPS itself. Use manual, attended issuance; do not expose signing as a service.
  - Phase 2's automated renewal would add a separate online issuing key, certified by the root key
    with a short lifetime. This is future work.

### The signing tool

`control-plane/cmd/rmt-pass-sign`. The key is read only from its file:
- `gen-key -key FILE`: exclusive create. The file gets a protected, owner-only DACL **before** it
  is written, then holds the P-256 scalar under DPAPI (CurrentUser) with purpose entropy. The command
  reads the file back to prove it.
- `pubkey -key FILE`
- `challenge -key FILE -origin URL`: mints a fresh 64-hex nonce and records it, synced, in
  `pass-challenges.jsonl` beside the key, **bound to that origin** with a 72-hour expiry.
- `issue -key -to -origin -grant-issuer-pubkey -min-agent-version -challenge NONCE [-days ≤31]
  [-uses]`:
  - It accepts only a nonce that the issuing tool recorded for the same origin, unexpired and
    never used. An arbitrary, foreign, cross-origin, expired or replayed nonce is refused.
  - It fetches `https://<origin>/.well-known/deskrally-pass-challenge` with normal TLS checks and
    **no redirects**, and refuses unless the response is the nonce. Only then does it record the
    nonce as consumed, before signing.
  - `-lab-skip-domain-check` exists for the VM lab only. It is refused unless the host is
    `localhost`, `*.localhost` or `*.test` (RFC 6761 names no customer can own).
  - Every issue is appended to `pass-issuance-log.jsonl` beside the key, and synced, **before** the
    pass is written. The record carries the SHA-256 of the exact file bytes.
- `attest -key -msi -product-version -product-code -upgrade-code [-days ≤396]`: hashes and sizes
  the MSI locally.
- `verify -kind pass|release -in -pubkey [-at]`

Every command verifies its own output before writing it, and output files are never overwritten.
The package linked into the control plane holds only the verifier;
`TestDeploymentPassPackageCannotSign` fails if a non-test file in it touches an ECDSA private key.

### The customer's server

- **New settings:** `CP_DEPLOYMENT_PASS_FILE` and `CP_AGENT_RELEASE_ATTESTATION_FILE`, in the installer
  overlay.
- **At startup the control plane verifies both signatures** with the root public key. That key is
  compiled into the control plane and can be overridden only by an explicit test flag. It also checks:
  - purposes and validity;
  - `origin` equals its own public origin;
  - the grant key equals its own;
  - the attestation hash equals the MSI it serves;
  - `product_version ≥ min_agent_version`.

  Any mismatch is fatal at startup, like the installer manifest.

  **Startup rules** (`managed_install_pass.go`):
  - **No new setting describes the server's own origin.** The pass must derive exactly the
    existing `CP_MANAGED_INSTALL_CONTROL_PLANE_URL` and `CP_SIGNALING_URL`.
  - **An EXPIRED or not-yet-valid pass or attestation at startup is NOT fatal.** Lapsing is how a
    pass is revoked, and it gates only new installs and support launches. A fatal check would
    take every enrolled agent and live session down at the next restart.
    - The server starts, logs a warning and shows it to admins.
    - It refuses every bundle with a 503, before any token is minted.
  - **Pass-mode refusals name the failing check** (`PassModeError`). The baked-mode failure stays
    opaque, as before.
  - **Also fatal:**
    - a pass that does not cover setup;
    - a directory serving Support under a pass without `support`;
    - a `"mode":"pass"` manifest carrying URLs;
    - pass files configured with a baked manifest;
    - a pass manifest without pass files;
    - pass files without `CP_MANAGED_INSTALL_DIR`.
  - `CP_DEPLOYMENT_PASS_TEST_ROOT_KEY` may authorize only test origins
    (`localhost`, `*.localhost`, `*.test`). The signer uses the same `IsLabOrigin` rule.
  - **The admin warning** is on `GET /managed-installer`, as `deployment_pass.warnings`, and the
    console's installer panel shows it.
- **After startup:** `/healthz` stays `ok`, but an admin-visible warning starts 7 days before either
  the pass or the release attestation expires.
- **Expiry is re-checked when a bundle is issued, not just at startup:**
  - an install bundle is refused with a clear 503 ("deployment pass expired" / "agent release
    attestation expired") if either has expired;
  - a support bundle checks the pass only.
- **Bundles** add `deployment-pass.json` (both bundles) and `agent-release.json` (the install bundle).
- **`installer-manifest.json` gains `"mode":"pass"`.**
  - In pass mode the URL fields are absent, and the control plane takes them from the pass.
  - Baked-mode manifests are unchanged and validated exactly as today.
  - The manifest is never an authentication source for clients.

### Generic Setup (MODE=PASS)

- **Reading:** it reads `deployment-pass.json`, `agent-release.json`, `enrollment.token` and
  `DeskRallyAgent.msi` from its own folder, with the existing locked, local-fixed-drive, no-reparse
  handling.
- **Verifying:** it checks the pass and the attestation, then stages the MSI. It hashes the
  **staged** copy against the attestation (exact SHA-256 and size), and keeps the stage handles open
  until msiexec exits, as it does today.
- **The MSI:** it must be self-contained, with an embedded cabinet; `test-msi-contents.ps1` asserts
  this at packaging.
- **msiexec** runs from the absolute System32 path, with no TRANSFORMS and every property quoted.
- **The consent dialog** keeps today's wording, plus `Server: <host[:port]>` and
  `Issued to: <issued_to>`. Both are charset-restricted at issuance and re-validated at verification.
- **`provisioning.json`** values come only from the parsed pass.

### Generic Support (MODE=PASS)

- **Reading:** a bounded, regular-file-only, at most 4 KiB read of `deployment-pass.json` beside the
  exe, then verification, then the derived control-plane URL.
- **Binding the redeem response to the pass:**
  - `signaling_url` must equal the derived one, and `grant_issuer_pubkey` must equal the pass's;
    otherwise it refuses.
  - Control-plane HTTP calls disallow cross-origin redirects.
- **The consent dialog** shows `Server:` and `Issued to:`, as Setup does.
- **Only the session bundle works:** a generic Support runs only from the session bundle, which carries
  the pass. The join page hides the plain exe link in pass mode.
- **DLL search order:** `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at start; Setup
  already does this.

### Residual threats (accepted, listed)

- DNS or domain takeover of a customer origin: the pass follows the name.
- A compromised customer control plane returning hostile data within the pinned origin.
- Enrollment-token theft within its existing 15-minute single-use window.
- Guest clock rollback, which can bypass client-side expiry indefinitely (see "Clock limitation"); the server-side checks still hold.
- Already-enrolled agents are unaffected by pass expiry. Passes gate installs and support launches
  only; cutting off a customer's existing fleet is a separate operation, out of scope here.
- Revocation privacy: there is no online list, so nothing is sent anywhere.

### Compatibility tests (every slice)

- **Baked builds:** run them with no pass beside them, a valid pass, a malformed pass and an expired
  pass. All four must behave exactly as today (the pass is ignored).
- **Legacy control-plane configuration** (no pass environment variables): unchanged startup and
  bundles.
- **Cross-language vectors**, covering:
  - a valid object;
  - the wrong domain;
  - a bit-flipped body;
  - r or s equal to 0 or ≥ n;
  - the wrong key, and an off-curve key;
  - duplicate and unknown keys;
  - oversize objects;
  - expired, future-dated, and validity longer than 31 days;
  - malformed origins (path, userinfo, port 443 written out, uppercase, Unicode host).
- **Build pipeline:** sign every final artifact **before** hashing and writing manifests; clean
  per-build output directories.

### Build and acceptance rules

- Support's `DESKRALLY_BUILD_MODE` is unset for development, `baked` for a deployment-specific
  `RMT_CONTROL_PLANE_URL`, or `pass` with a 130-hex public `DESKRALLY_PASS_ROOT_KEY`.
  Mixed configurations fail the build.
- Setup uses `build-setup.ps1 -Mode Baked|Pass`; Pass requires `-PassRootKey` and refuses baked URLs.
  Verify the mode in the executable's version resource before signing.
- The join page withholds the plain Support executable link while pass-mode detection is pending;
  pass mode offers the session bundle only.
- Verify generic Setup installation while the staged MSI is held open, enrollment with pass-derived
  configuration, consent's server and issued-to fields, tampered-pass refusal, and Support's
  missing-pass refusal. Also test baked Setup and Support as regressions.
- Test the actual UAC flow and a live viewer session separately from isolated verifier tests.

Desktop client update trust is also opt-in: `clients/windows/build-client.ps1 -OfficialUpdates`
selects the official identity. Without update options it disables self-update; use `-UpdateHost`
and `-UpdatePublisher` for your own identity.
