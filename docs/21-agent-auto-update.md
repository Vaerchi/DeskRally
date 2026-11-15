# Agent auto-update — design and trust requirements

For operational setup, bootstrap installation and release acceptance, see
[automatic update release operations](automatic-update-release.md). The current implementation
uses an independent scheduled worker, an idle barrier and a rollback journal. Per-machine ring
policy and manual release promotion are supported; control-plane group controls and an update-now
button remain future work.

## Update identity

Source and kit builds default to auto-update off. An agent trusts the official DeskRally update
identity only when built with `DESKRALLY_UPDATE_OFFICIAL=1` (or the kit's `-OfficialUpdates`).
A self-hoster can instead set `DESKRALLY_UPDATE_FEED`, `DESKRALLY_UPDATE_PUBKEY_FILE` and
`DESKRALLY_UPDATE_PUBLISHER` together. See the [build kit reference](48-windows-build-kit-and-deployment-passes.md).
For the desktop client, `clients/windows/build-client.ps1 -OfficialUpdates` selects official
updates; without update options self-update is disabled.

An update channel executes code as SYSTEM. Keep your update signing key separate from the grant
issuer key and off the control plane. The server serves already-signed manifests and must not
hold the key needed to mint them. Protect and securely back up your own signing key before
pinning a fleet; losing it can strand the update channel. Never distribute the private key.
The public official pin may be referenced at `packaging/update-signer-pubkey.hex`.

The release signer is `control-plane/cmd/rmt-update-sign`. Server packages contain verification,
not update signing. Ed25519 manifest authorization and timestamped Authenticode verification are
separate checks: perform both. Sign and timestamp final binaries before hashing them or writing
manifests. A certificate store or signing service does not substitute for requesting and checking
an RFC 3161 timestamp.

## Identity and version reporting

`AGENT_VERSION` comes from the crate version plus the build's short commit SHA. Agents report
it during registration; signaling carries it through the presence feed to the control plane.
The console can then show version skew. Authenticated registration after restart, rather than a
service merely reaching `Running`, is the update health signal.

Increment the numeric release version for every published update. Build metadata such as a
commit hash does not affect version precedence. Keep older configuration readable by new agents;
configuration migration is a separate compatibility responsibility.

## Verification and installation

A signed manifest binds the payload URL, hash, version and upgrade constraints. Verify the
signature before trusting manifest claims, then validate time bounds and field shapes. Use the
release tooling and shared verification formats rather than constructing signature preimages by
hand. The historical v1 domain tag is `RMTUPDATEv1\x00`; current MSI feeds and paths are documented
in the [server deployment guide](guides/server-deployment.md#5-publish-installers-and-updates-under-download).

Absent or invalid trust configuration must refuse updates. Never reuse the grant issuer public
key as the update signer pin. Rotation requires a planned way to distribute a new trusted pin;
changing the server's key alone does not update existing agents' trust.

Stage payloads under SYSTEM-and-Administrators-only permissions. Verify the staged bytes and
prevent modification between verification and execution. Defer installation during active remote
sessions. An independent recovery worker must survive stopping the agent service and retain a
journal and backup for interrupted or failed transactions.

## Rollout and recovery

1. Start with a locally accessible canary and prove upgrade, identity/configuration preservation,
   session deferral, authenticated return to signaling and recovery from a deliberately failed build.
2. Promote manually through `canary`, `early` and `general` after a chosen soak interval.
3. Publish immutable payloads first; read them back and verify the hash before publishing manifests.
4. Withdraw ring manifests to stop future offers. Keep previous payloads and recovery backups.
5. Keep recovery enabled while an update transaction is unresolved, even when new offers are disabled.

An outbound update check must not create an inbound agent endpoint. A future console trigger
needs explicit authorization: existing technician commands use an in-session WebRTC channel,
which is unavailable on idle agents. Daily checks should be jittered to avoid synchronized load.

Server upgrades use their own deployment and database migration procedures; they are separate
from Windows agent updates. A prepared feed, copied package or website deployment does not prove
that any installed machine updated itself.
