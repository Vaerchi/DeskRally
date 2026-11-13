# Updating an installed Windows agent

Use the complete extracted release package. `Update-DeskRally.cmd` opens the updater with an Administrator prompt. It runs `update-agent.ps1`, which requires the package's `release-manifest.json` and signed `agent_host.exe`.

The updater supports the standard `C:\rmt-agent-bin` installation and the standard MSI executable path under `C:\Program Files\RMT Agent`. It refuses unexpected service paths, redirected installed files, untrusted owners or writable permissions, incomplete enrollment, invalid release hashes, an invalid publisher signature, and version mismatches before stopping the service.

The existing configuration and identity are preserved byte-for-byte. A verified backup remains in the installed executable directory. If replacement or restart fails, the updater attempts to restore that executable and the previous running state. Active sessions can disconnect during replacement. `-PrepareOnly` performs verification and stages a protected backup without stopping the service.

For a new machine, use the package's `install-agent.ps1` with a fresh enrollment token and the deployment URLs/public keys documented in its README. Do not use fresh enrollment to update an already enrolled machine. Keep tokens and identity files out of shared distribution folders.

The source updater is a package component, not a self-contained download: the release process supplies the signed executable and its measured hash/version manifest. On 2026-10-01, local checks exercised successful preflight, rejection of bad hash/signature/version with the installed service unchanged, and successful replacement of an existing manually installed agent with configuration and identity unchanged. A fresh-machine install and the MSI-path variant require separate physical acceptance.
