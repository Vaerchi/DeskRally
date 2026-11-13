# Agent auto-update (MSI 1.3.x)

Status: implemented for MSI 1.3.x. This page states what an operator can rely on.

## How it works
- **Bootstrap.** The first 1.3.x MSI is installed manually (ZIP or console download), like any earlier release. From then on the agent updates itself.
- **The worker.** A SYSTEM scheduled task, `\DeskRally\AutoUpdate`, runs `agent_host.exe auto-update-worker` at boot and hourly. It checks the feed at most once a day:
  `https://console.example.com/download/agent/v2/<ring>/manifest.json`
  The ring comes from `C:\rmt-agent\auto-update.json` and is `general` by default.
- **The manifest.** It is format 2, signed by the offline update key. Agents pin the public half (`update_signer_pubkey`, written at install if it is blank).
- **The package.** The MSI must:
  - match the signed digest;
  - carry a valid Authenticode signature from the expected publisher;
  - declare the ProductCode and version the manifest names.
- **The install.** It happens only when no remote session is open (the idle barrier). It runs in-process through `MsiInstallProductW`. Inside the MSI transaction, after the new service starts, HealthGate waits up to 180 s for the new agent to register with signaling. If it doesn't, Windows Installer rolls the whole transaction back to the previous version.

## Outcomes
Recorded in `C:\rmt-agent\update-state.json`, with evidence kept under `update-history\`.

| Outcome | Meaning | Effect |
|---|---|---|
| Done | New version committed and acknowledged | Counters reset |
| Unknown / Busy / NotStarted | Rolled back, or never started, with no proof the release is bad (for example a gate timeout) | Backoff of 1 h, then 4 h, then 24 h. After 3 failures, paused to 1 attempt per day. Never quarantined. |
| Health | The new agent itself reported a fault | Release quarantined (never retried) |
| Verification | Signed bytes are not what they claim | Release quarantined |
| RolledBackReboot / DonePendingReboot | Replacement deferred, or not provable | Waits for a reboot, then retries or verifies |
| Unresolved | The installer process died with no result and no transaction record | Updates blocked until the next reboot, then classified |
| Anomaly | Installed state not understood | Updates blocked until an admin clears the state |

## Contracts and limits (verified on a Windows 11 VM, 2026-10-15)
- **Repair.** Settings › Apps › Repair (`msiexec /fa`) on an auto-updated machine fails with error 1706. The updater's download folder is cleaned after success, and Windows caches the MSI without its embedded files. To repair, run the matching MSI with `REINSTALL=ALL REINSTALLMODE=amus`, or just re-run it. Verified: config, identity and policy are preserved. This is the same as a manual install whose MSI was deleted.
- **Power loss during an update.** Windows Installer does not roll back a transaction interrupted by power loss. It keeps its rollback files in `C:\Config.Msi` but never applies them. The new agent binary can therefore be left on disk under the previous product registration.
  - The updater classifies the attempt Unknown and re-offers the same release, comparing against the lower of the running and registered versions. That reinstalls it through the health gate.
  - Measured: the first retry resumes Windows Installer's suspended install with the old attempt's saved properties, so the gate refuses it and it rolls back, which clears the suspended state. The second retry installs cleanly (gate passed, Done, registration consistent). With the normal 1 h + 4 h backoff, the machine heals within about 5 hours, unattended.
  - If the left-over binary cannot start at all, there is no automatic recovery. Reinstall the current MSI by hand.
- **Rollback disabled by policy** (`DisableRollback`): install and update are refused with an explicit message.
- **Downgrade:** refused. Uninstall first.
- **Uninstall:** removes the task, the policy and the update state. Keeps `config.json` and `identity.key` for reinstallation.
- **The idle barrier:** an open remote session defers the update to a later run.

## Publishing a release (operator)
1. Build with `RUSTFLAGS=+crt-static`, then package with `scripts/build-msi.ps1 -Version 1.3.N`. Packaging refuses to build if any of these fail:
   - lab-feed builds;
   - a missing signer pin;
   - a version mismatch (agent `0.1.N` ↔ MSI `1.3.N` ↔ FileVersion `0.1.N.0`);
   - dynamic CRT linkage;
   - a script action placed before RemoveExistingProducts.
2. Azure-sign `agent_host.exe` before packaging, and the MSI after.
3. Sign the manifest with the offline update key using the deployment's release tooling. The version must equal `agent_host.exe version` exactly.
4. Publish the MSI at `/download/agent/releases/<0.1.N>/DeskRallyAgent.msi`, then the manifest at `/download/agent/v2/<ring>/manifest.json`. Publish to `canary` first.
5. To withdraw a release, remove the manifest. Agents treat 404 as "no update".
