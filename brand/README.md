# DeskRally identity

Use **DeskRally** in product copy and **Remote support. Keep it simple.** as the primary tagline.
The road and checkered finish mark is the default product icon. Its lime plate (`#c8ff48`) and navy road (`#13283e`) stay the same on the project website, console, browser app, Android launcher, Windows client and support agent. Paper (`#f4f1e8`) is the project website background. Console chrome retains its accessible dark/light themes.

`identity.json` defines the mark geometry and colors. On Windows, run `powershell -NoProfile -File scripts/update-brand-assets.ps1` from the repository root to regenerate SVG, PNG and ICO resources. This is a small asset conversion, not an application build. Copy `brand/rally-mark.svg` to `website/assets/rally-mark.svg` in the separate release repository when syncing that website. Verify generated resources before signing new binaries; existing installed binaries do not update until a release.

Use these terms consistently:

- **One-time support client**: the program run by the person receiving help; it requires consent and does not install permanent access.
- **Desktop app**: the Windows technician client.
- **Browser console**: the technician's web interface.
- **Unattended access agent**: the installed service for managed computers.
- **Project website**: overview and visitor guides; **server documentation**: deployment-specific instructions.
- **Source release**: the status page until the reviewed public repository is available. Do not label a status link “GitHub”.

Tenant-configured names, logos and contact information are separate from the default product identity. Do not replace them in bulk. Preserve security explanations, exact signer/publisher checks, wire keys, service names, registry paths and upgrade identities. Historical audit records keep the names in use at their recorded date. Publisher attribution and required third-party notices belong in legal/release metadata; they are not a secondary product name.
