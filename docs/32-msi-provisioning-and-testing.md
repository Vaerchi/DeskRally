# Configuration-aware MSI — unsigned testing round

The MSI implementation is designed to provision and enroll a fresh managed agent, register an
automatic LocalSystem service and start it. Repair and upgrade are designed to preserve enrolled
configuration and identity without spending another token. These lifecycle behaviors still need
the isolated VM acceptance run described below. The package remains unsigned; no publisher or SmartScreen
reputation claim is made.

## First install

Run from an elevated PowerShell prompt on the target machine. Create a fresh, single-use token
through your authorized console workflow, then enter it at the prompt below. The token does not
appear in the MSI command line or a child process's arguments.

```powershell
$provisioning = .\scripts\new-msi-provisioning.ps1 `
  -ControlPlaneUrl 'https://console.example.com/cp' `
  -SignalingUrl 'wss://console.example.com/ws' `
  -GrantIssuerPubkey '<64-hex issuer key>'

msiexec.exe /i .\dist\RmtAgent-1.1.0-test.msi /qn /norestart `
  PROVISIONINGFILE="$provisioning" /l*v "$env:TEMP\DeskRally-install.log"
```

The provisioning helper prompts for the token as a SecureString and writes JSON under
`C:\ProgramData\DeskRally-Provisioning`, protected for SYSTEM and Administrators. Keep it local,
not in OneDrive or source control. After confirming installation, delete that specific file.
The enrolled runtime config clears its token automatically. A failed enrollment may leave the
input token unspent; do not distribute the provisioning file.

The script now REQUIRES `-GrantIssuerPubkey` (the independently verified 64-hex control-plane grant
issuer key) and turns `require_session_policy` on by default; without a pin the group view-only
mandate, session lease and signed grants are advisory. `-InsecureNoGrantKey` provisions an
unenforced lab agent (and forces the policy flag off); the console flags such machines "policy not
enforced". An update-signing pin, if configured, must be a different offline release key. Do not
invent or copy an issuer key from an untrusted installer location. Existing-machine upgrades do not change any of these settings.

This round is a silent installation workflow, not an interactive MSI wizard. Hand-authored
provisioning JSON must use the helper's schema and equivalent owner/DACL protection. Unknown
fields and supplied device/tenant IDs are refused. HTTPS/WSS are required except for loopback
test endpoints. Input/config files are bounded to 64 KiB, local and non-reparse.

## Repair and upgrade

With an existing enrolled `C:\rmt-agent\config.json` and protected `identity.key`, omit
`PROVISIONINGFILE`. Even if provided, it cannot override an enrolled installation's settings.
The config is not serialized again: unknown future settings and the original bytes survive.

```powershell
msiexec.exe /i .\dist\RmtAgent-1.1.1-test.msi /qn /norestart /l*v "$env:TEMP\DeskRally-upgrade.log"
```

Use monotonically increasing MSI ProductVersions for upgrades. Rebuilding a different package
under the same ProductVersion is not an upgrade strategy. ProductVersion is independent of the
agent's git build stamp. The test MSI packages the working-tree provisioning implementation;
the base git stamp alone does not identify an uncommitted build. Use the recorded artifact hash.

Malformed, half-enrolled, unprotected or redirected existing configurations are refused rather
than silently replaced. Custom identity locations are not migrated by this installer. Back up
and repair such a configuration explicitly; never use `agent_host uninstall` as an upgrade step.

## Failure, rollback and removal

Windows Installer owns the binary and service transaction. The deferred SYSTEM provisioning
action runs after InstallFiles and before InstallServices/StartServices; failure aborts the
installation. Enrollment uses the existing agent protocol and bounded request timeout. The
native bridge also bounds the child process runtime and never invokes a shell.

Identity/config retention is intentional, including after uninstall or installation rollback.
An enrollment-token redemption on the server cannot be undone by MSI rollback. Deleting a key
after successful redemption would strand that device, so retry/reinstallation reuses protected
enrolled state. Failed enrollment does not write a runnable, unenrolled config. Directory ACL
hardening is not rolled back to weaker permissions.

Uninstall removes the MSI-owned binary/service; it does **not** erase agent identity, settings,
recordings, transfers or old PowerShell-layout files. Complete device retirement and data cleanup
are explicit management tasks, outside MSI removal. MSI does not yet register the deployment-specific
guest URI handler; first-contact support downloads remain a separate product path.

| Provisioning exit code in MSI log | Meaning |
|---|---|
| 20 | Missing/invalid provisioning, settings or arguments |
| 21 | Untrusted ACL, remote/reparse path or hardening refusal |
| 22 | Existing config/identity is invalid or incomplete |
| 23 | Enrollment failed; no service should start from a fresh installation |
| 24 | Local file I/O failed |

Only generic codes reach the MSI log; parser errors, JSON contents and server response bodies
are not printed because they can contain secrets. Inspect the protected input locally if needed.

## Build and verification

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --release -p rmt-agent-windows --bin agent_host
pwsh -File scripts/build-msi.ps1 -AgentExe target/release/agent_host.exe `
  -Version 1.1.0 -Out dist/RmtAgent-1.1.0-test.msi
```

The build requires MSVC x64 tools and WiX. A static-CRT native custom-action bridge is compiled
from `packaging/msi/actions.cpp`; Rust owns provisioning, not the bridge. A read-only
`msi-capabilities` probe rejects an older agent lacking this installer ABI. The MSI table guard
checks actual deferred-action flags, sequence, hidden/secure data and service lifecycle rows.

Implementation follows Microsoft's [deferred-action context rules](https://learn.microsoft.com/en-us/windows/win32/msi/obtaining-context-information-for-deferred-execution-custom-actions)
and FireGiant's [custom-action schema](https://docs.firegiant.com/wix/schema/wxs/customaction/).

Targeted provisioning tests run with `cargo test -p rmt-agent-windows --lib msi_`.
`scripts/test-msi-vm.ps1` is destructive only inside the named disconnected disposable clone,
never the source VM or the host. It uses a synthetic loopback enrollment server and tokens, checks
failure/rollback, fresh install, repair, major upgrade, downgrade, uninstall/reinstall and migration
from a PowerShell-style service, and scans verbose MSI logs for the synthetic secret.

## Validation summary

Unsigned packages passed all nine compiled-table checks, four targeted Rust provisioning
unit tests, PowerShell parser checks, and static-CRT import checks for the agent and
native custom-action DLL. Read-only MSI extraction confirmed the embedded files matched
the build inputs by SHA-256. These are build/static checks, not installation acceptance.

The disposable-VM harness covers fresh enrollment, repair, upgrade and rollback,
downgrade rejection, removal, reinstall and legacy-service migration. The earlier
blocked installation run is superseded; the static checks above alone do not establish
installation acceptance for a new package.
