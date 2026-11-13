# Automatic update release operations

Build and feed preparation do not prove that an installed machine updated. Before rollout,
validate bootstrap installation, a real SYSTEM canary upgrade and rollback, and feed acceptance.
Record privileged checks separately from isolated tests.

Source builds default to auto-update off. An agent trusts the official update identity only
when built with `DESKRALLY_UPDATE_OFFICIAL=1`; the desktop client requires `-OfficialUpdates`.
For your own agent feed, set `DESKRALLY_UPDATE_FEED`, `DESKRALLY_UPDATE_PUBKEY_FILE` and
`DESKRALLY_UPDATE_PUBLISHER` together. See the [build kit](48-windows-build-kit-and-deployment-passes.md).

## Release feed

The feed is public, contains no enrollment information, and is mounted read-only
into Caddy with the existing support download artifacts. Keep deployment profiles and
machine enrollment separate from public release artifacts.

The legacy executable feed uses these paths (for current MSI/v2 paths, see the
[server deployment guide](guides/server-deployment.md#5-publish-installers-and-updates-under-download)):

- `/download/client/manifest.json`
- `/download/client/releases/<major.minor.patch>/DeskRallyClient.exe`
- `/download/agent/{canary,early,general}/manifest.json`
- `/download/agent/releases/<major.minor.patch>/agent_host.exe`

Manifests have `Cache-Control: no-store`. Versioned payloads are immutable:
never replace the bytes of an already published version. Publish the payload
first, read it back and verify its SHA-256, then atomically publish its manifest.
Do not copy an entire development, private-key, or enrollment directory into
the public artifact mount.

## Preparing artifacts

`scripts/prepare_update_feed.py` prepares a **new local output directory**. It
does not upload, restart a service, or enable a rollout. It verifies the staged
binary's Authenticode signature, timestamp, publisher, and actual version before
making its manifest available. A failed preparation must not be published.

The official desktop client build is a manual release step. Before signing and
packaging, build it with `clients/windows/build-client.ps1 -OfficialUpdates`
(add `-SmokeTestBuild` when needed). The support publisher script handles
`DeskRallySupport.exe`, not this desktop client. A build without update options
has self-update disabled. For an own identity, supply both `-UpdateHost` and
`-UpdatePublisher` instead.

Feed preparation also requires explicit identity selection: `--official` reads
`packaging/official-update-identity.json`; alternatively supply both
`--origin https://host[:port]` and `--publisher "CN=Your Publisher, O=Your Organization"`.
These alternatives cannot be combined. The origin has no trailing slash or path.

Official desktop example:

```powershell
python scripts/prepare_update_feed.py client --official --binary <signed-client.exe> --version 0.5.0 --output <new-output-directory>
```

Agent example:

```powershell
python scripts/prepare_update_feed.py agent --official --binary <signed-agent_host.exe> --version <actual-version-plus-commit> --output <new-output-directory> --signer <rmt-update-sign.exe> --seed <offline-private-key-file> --public-key <pinned-public-hex> --minimum 0.0.1 --ring canary
```

The agent seed stays off the server, outside distribution folders, and
outside the prepared public tree. The existing `rmt-update-sign` tool signs and
then verifies the manifest. The control-plane grant issuer key must never be
used for updates. Back up the release key privately before enabling a fleet;
losing it strands the update channel.

Azure Artifact Signing rotates leaf certificates frequently. Verify the trusted
publisher and timestamped chain; do not pin a short-lived leaf certificate's
thumbprint. The agent's separate Ed25519 manifest key is the stable release
authorization key.

## Versions and rollout

The previous agent releases used `0.0.1+<commit>`. Build metadata does not affect
version precedence. Starting with the updater bootstrap, increment the numeric
release version for every published agent update. Never try to order commit
hashes or enable downgrades to compensate for a missing version bump.

Start with a canary machine that can be reached locally. Prove an update from
the installed previous build, preservation of identity/configuration, deferred
application during a remote session, and recovery from a deliberately failed
candidate in an isolated test environment. Confirm an authenticated return to
signaling; the Windows service merely reaching `Running` is insufficient.

Only promote a release to `early` and then `general` after recording successful
canary health and the operator's chosen soak interval. There is no automatic
ring promotion in the release preparation tool. Removing a ring's manifest
halts future offers. Removing all three halts the agent feed. Preserve previous
payloads and local backups for diagnosis and controlled recovery.

Existing installations require one bootstrap update before they can run an
updater. Do not describe a copied release package or a server deployment as
proof that an installed remote machine updated itself.

## Release validation

Validate signature and timestamp refusal, publisher/version/product binding, byte limits,
path injection, key separation, signer failure and refusal to overwrite prepared releases.
Check allowed download routes, manifest cache policy and rejection of private directories.
Run native updater recovery and bootstrap installation acceptance separately from feed preparation.

## Agent bootstrap and maintenance

The updater requires an installed, enrolled agent at numeric version 0.0.2 or
later. Existing 0.0.1 installations need the signed manual agent update first,
during a maintenance window. Keep the existing configuration and identity files.

After installing the bootstrap agent, run `enable-agent-auto-update.ps1` as an
administrator from the complete release package. `-PrepareOnly` checks the
package and installed state without enabling the task. Use `-Ring canary` on the
first locally accessible test machine; general rollout remains a separate step.
The release package must include its public update-signing key. The installer
refuses to replace a different existing pin or reuse the grant issuer key.

The bootstrap installs a separate signed worker at
`C:\rmt-agent-bin\DeskRallyUpdater.exe` and the SYSTEM scheduled task
`DeskRally Agent Auto Update`. Startup/hourly task runs handle pending recovery;
normal offers are checked at most once daily. This worker survives stopping the
RmtAgent service. It accepts no caller-supplied path, URL, or command. Its own
maintenance remains part of the signed bootstrap installer.

The agent holds a shared file lock for each installed remote session. Applying
an update requires the exclusive lock, so active sessions defer installation.
The worker verifies the offline-signed manifest, expiry, exact download URL,
SHA-256, timestamped Windows publisher signature, and actual executable version.
It rechecks the live offer immediately before stopping the service.

An update succeeds only after the restarted agent writes the fresh watchdog
nonce with its actual compiled version following authenticated registration.
A failed start or missing acknowledgment within 120 seconds restores the old
executable and restarts the service. The previous executable remains available.
A disk journal permits the independent worker to restore an interrupted
transaction on a later task run or reboot. A failed release digest is quarantined
until a different release is offered. Recovery errors keep the backup and report
failure; do not delete the transaction directory to silence them.

Local policy is `C:\rmt-agent\auto-update.json` with only `enabled` and `ring`.
Set `enabled` to false to stop new offers while keeping recovery available.
Do not disable the scheduled task while an update transaction is unresolved.
The status file is `C:\rmt-agent\update-state.json`; current recovery files are
in `C:\rmt-agent\update-transaction`, with completed history under
`C:\rmt-agent\update-history`. These paths stay restricted to SYSTEM and
administrators. Neither enrollment tokens nor the private signing key belong in
public downloads or distribution packages.

This implementation has local download, lock, service-adapter, and injected
rollback tests. A real SYSTEM canary upgrade and rollback exercise are still
required before enabling automatic installation on other machines.

The current agent implementation uses per-machine ring policy and manual release
promotion. Withdrawing the ring manifests is the implemented offer kill switch;
there is no control-plane ring-management or update-now button in this release.
The original design document's group controls remain future work.
