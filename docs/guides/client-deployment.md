# Deploying DeskRally on client computers

This guide is for administrators putting DeskRally software on Windows computers. There are three
pieces:

| Piece | Who runs it | What it is for |
|---|---|---|
| **Agent** (`DeskRallyAgent.msi`, service `RmtAgent`) | Machines you manage | Permanent, unattended access. The machine appears in **Machines**. |
| **Support tool** (`DeskRallySupport.exe`) | A guest you are helping once | Attended support. Nothing is installed, and it runs only while the guest allows it. |
| **Desktop app** (`DeskRallyClient.exe`) | Technicians | Optional. The console in its own window, with `deskrally-client://` links and Microsoft sign-in. |

The server side (the installer bundle and `/download`) is covered in
[server-deployment.md](server-deployment.md).

For the underlying identity, codec and transport details, see the
[full build and deployment reference](../10-deployment.md#4a-enrollment-and-agent-identity-m3).
For blank video or relay-limit failures, see [connection troubleshooting](../connection-troubleshooting.md).

> **On your own server domain:** the prebuilt support tool and installer bundle connect to the
> hosted service (main.deskrally.com). A self-hosted server needs its own Windows builds of them.
> The MSI with a provisioning file (section 2) works with any server.

---

## 1. Install the agent on one computer (installer bundle)

This is the easiest way, and it needs nothing prepared in advance. It needs the server's managed
installer to be enabled; if it is not, the console says *"The preconfigured installer is not
available on this server yet."*

1. In the console, open the DeskRally menu → **Deploy**. The section is **Install a computer**.
2. Choose the **Machine group** the computer will join. Groups are created under
   **Machine groups**.
3. Click **Download Windows installer**. You get `DeskRally-Install.zip`.
   - The bundle enrolls **one** computer and **expires 15 minutes** after you download it.
   - Do not share it, and delete it afterwards.
4. Copy it to the target PC, **extract all files** to a local folder (not a network share or a
   redirected folder), and double-click **DeskRallySetup.exe**.
5. Read the confirmation, *"DeskRally Setup — Permanent Unattended Access"*, and approve the
   Windows administrator (UAC) prompt.
6. Setup checks the installer's hash, installs the service and enrolls the computer under its
   Windows computer name. It ends with *"DeskRally Remote Agent installed successfully."*
7. Delete the ZIP and the extracted files.

The computer appears in **Machines** within a minute or so, showing as online.

## 2. Silent or mass deployment (MSI)

Use this for scripted installs, RMM tools, or many computers. The enrollment token is passed in a
**protected provisioning file**, never on a command line where other processes could read it.

### 2a. Get an enrollment token

1. **Deploy** → **Advanced: enrollment tokens**.
2. Choose the **Machine group**, and optionally **Expires in days** and **Max uses**, then click
   **Mint token**.
3. Copy the token. It is shown only once. Tokens can be revoked from the same table.

Each agent lands in the group the token was minted for. Prefer a fresh token per batch, and revoke
it when you are done.

### 2b. Get the files

Neither file needs a build machine:

- **`DeskRallyAgent.msi`.** It is inside the installer bundle: **Deploy** → **Download Windows
  installer**, then extract the ZIP. You can reuse the MSI on any number of computers. The
  bundle's own enrollment token is single-use and is not needed here. On the hosted service the
  current MSI is also at `https://main.deskrally.com/download/agent/releases/<version>/DeskRallyAgent.msi`
  (the version an agent reports, without the `+commit` suffix).
- **`new-msi-provisioning.ps1`.** Download it from
  `https://remote.example.com/download/agent/new-msi-provisioning.ps1`. Check it against
  `.../new-msi-provisioning.ps1.sha256.txt` with `Get-FileHash`.

### 2c. Create the provisioning file and install

Run this in an **elevated** PowerShell on the target computer. Windows refuses to run a downloaded
script under its default execution policy, so allow it for this window only (the first line), not
machine-wide.

The grant issuer key is the server's `SIGNALING_TICKET_PUBKEY`. The console does not show it. On the
server, run `grep '^SIGNALING_TICKET_PUBKEY=' deploy/.env` (or, with an API token,
`GET https://remote.example.com/cp/grant/pubkey`). It is 64 hex characters, and it is the same for
every computer.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$provisioning = .\new-msi-provisioning.ps1 `
  -ControlPlaneUrl 'https://remote.example.com/cp' `
  -SignalingUrl 'wss://remote.example.com/ws' `
  -GrantIssuerPubkey '<64-hex SIGNALING_TICKET_PUBKEY from the server>'
# Prompts for the enrollment token (or pass -EnrollmentToken as a SecureString).

msiexec.exe /i .\DeskRallyAgent.msi /qn /norestart `
  PROVISIONINGFILE="$provisioning" /l*v "$env:TEMP\DeskRally-install.log"

Remove-Item $provisioning      # the file holds the token: delete it after install
```

**What the provisioning script does.**
- It writes `C:\ProgramData\DeskRally-Provisioning\<guid>.json`, readable only by SYSTEM and
  Administrators, and prints its path.
- Optional parameters:
  - `-GrantIssuerPubkey` is **required** (the control plane's grant issuer key); `-RequireSessionPolicy`
    is on by default. `-InsecureNoGrantKey` knowingly provisions an unenforced agent (lab only; the
    console shows "policy not enforced" for it);
  - `-UpdateSignerPubkey`;
  - `-Clipboard bidirectional|to_technician|to_guest|disabled`;
  - `-Stun`.

**MSI properties.**

| Property | Meaning |
|---|---|
| `PROVISIONINGFILE` | Path to the provisioning file (first install only). |
| `RING` | Update ring: `canary`, `early` or `general` (the default). Applies only when no update policy exists yet. |

Do not set the `DESKRALLY_AUTOUPDATE*` properties; they belong to the updater.

**What gets installed.**
- The product is "DeskRally Remote Agent", installed per machine to
  `C:\Program Files\RMT Agent\agent_host.exe`.
- The service is `RmtAgent`, set to start automatically, running as LocalSystem.

**GPO, Intune and RMM tools.** There is no packaged procedure yet. Wrap the two commands above in
your tool's script step. A plain "assign this MSI" policy cannot supply the per-machine
provisioning file.

### Provisioning error codes (in the `/l*v` log)

| Code | Meaning |
|---|---|
| 20 | Missing or invalid provisioning file or settings |
| 21 | The file's location or permissions are not trusted (network path, link, wrong ACL) |
| 22 | An existing configuration or identity is invalid or incomplete |
| 23 | Enrollment failed (bad, expired or used-up token; server unreachable). The service is not started. |
| 24 | Local file error |

## 3. Attended support for a guest (nothing installed)

**Technician side:**
1. DeskRally menu → **Attended**.
2. Choose the **Machine group**, type a **Reason** (the guest sees it), and click
   **Start support session**.
3. Read the one-time code to the guest, or send them the **Join link**. The code is shown once
   and expires in 10 minutes.
4. When the guest has approved, click **Connect**. **End** closes the session.

**Guest side:**
1. Open the join link (or `https://remote.example.com/join`). The page is **Get remote support**.
2. Click **Download support client** (or **Download session bundle**, which already contains the
   code) and run `DeskRallySupport.exe`. Rules:
   - Do **not** run it as administrator.
   - It does not work inside a Remote Desktop session.
   - Smart App Control, AppLocker or WDAC can block it.
3. Enter the code if asked, then approve the prompt *"Allow the remote support session?"*, which
   shows the technician's reason.
4. When the session ends, nothing remains installed. The working folder
   (`%TEMP%\DeskRally\session-…`) can be deleted.

**Making it permanent.** During an attended session, click **Enable unattended access**.
1. The guest is asked *"Your technician has requested to install permanent remote access…"*.
2. If they agree, the same installer as in section 1 runs, with its confirmation and UAC prompt.
3. If they decline or cancel, you can ask again.

## 4. The technician desktop app

**Requirements:** Windows 10 1903 or later, and the Microsoft WebView2 Runtime (already present on
current Windows).

**Install:**
1. Go to `https://remote.example.com/downloads` → **Download Windows desktop app**.
2. Extract the package and run `Install-DeskRally-Client.cmd`. No administrator rights are needed.

The app installs to `%LOCALAPPDATA%\Programs\DeskRally Client\` with a Start menu shortcut. It also
registers `deskrally-client://` links for your Windows user.

**Use:**
- The first launch asks for your **organization** (the part before `.deskrally.com`).
  **Organization → Open another organization...** switches between organizations.
- **Sign in with Microsoft** works inside the app (from 0.8.0) for Entra members and
  Microsoft-account guests.
  - Duo, federated and seamless sign-in are not supported in the app; it tells you to use a web
    browser instead.
  - The sign-in window title is *"Microsoft sign-in – <host> – DeskRally"*.
- The console's **Connect in** selector (Desktop app or Browser) opens sessions in the app when you
  choose it.

**Updates:**
- The app checks when it opens and once a day; **Updates → Check for updates** checks now.
- An update installs once all DeskRally windows are closed. The previous version is kept and
  restored if the update fails.
- **Help → About DeskRally** shows the version, the signature status and the last update result.

**Remove:**
1. Delete the Start menu shortcut and `%LOCALAPPDATA%\Programs\DeskRally Client`.
2. Optionally delete the profile, `%LOCALAPPDATA%\DeskRally Client`, and the registry key
   `HKCU\Software\DeskRally\Client`.

## 5. Checking an installed agent

```powershell
Get-Service RmtAgent                                           # Running
& 'C:\Program Files\RMT Agent\agent_host.exe' version            # e.g. 0.1.4+02dc43c
Get-Content C:\rmt-agent\helper.log -Tail 50                     # connection log (rotates at 8 MB)
```

- "Running" alone does not prove the agent is connected. The console's **Machines** list is the
  real check: the presence dot, and the reported version, which carries a "⚠ mismatch" badge when
  it differs from the published one.
- Files live in `C:\rmt-agent\` and are readable only by SYSTEM and Administrators:
  - `config.json`
  - `identity.key` (never share it)
  - `transfers\`
  - `recordings\`
  - `update-state.json`
  - `helper.log`

## 6. Updates and removal

**Automatic updates (agent 1.3.0 and later):**
- The scheduled task `\DeskRally\AutoUpdate` runs as SYSTEM at boot and hourly, and checks the
  server's signed feed at most once a day.
- It installs only when **no remote session is open**.
- If the new version does not come up healthy within 180 seconds, Windows Installer rolls back to
  the previous one.

**Rings:** `canary`, then `early`, then `general` (the default). Set the ring at install with
`RING=...`, or later in `C:\rmt-agent\auto-update.json`.

**Updating by hand:** run a newer MSI. The configuration and enrollment are kept:
```powershell
msiexec.exe /i .\DeskRallyAgent.msi /qn /norestart /l*v "$env:TEMP\DeskRally-upgrade.log"
```

**Repairing a machine that updated itself:** the Settings app's *Repair* fails with error 1706.
Instead, run the matching MSI with `REINSTALL=ALL REINSTALLMODE=amus`. Downgrades are refused;
uninstall first.

**Uninstalling:**
- Use **Settings → Apps → DeskRally Remote Agent → Uninstall**, or `msiexec /x DeskRallyAgent.msi`.
- This removes the program, the service and the update task.
- It **keeps** `C:\rmt-agent\` (identity, configuration, recordings), so a reinstall needs no new
  token.
- To retire the computer completely, delete that folder too and remove the machine in the
  console.

## 7. Troubleshooting

| Problem | What to do |
|---|---|
| *"enrollment.token is invalid…"* or the bundle has expired | Download a fresh bundle; each one lasts 15 minutes and works once. |
| Setup refuses the folder | Extract to a local folder on a fixed drive, not a network share or redirected Desktop/Documents. |
| *"Installation failed (msiexec exit code …)"* | Check the Windows Application event log, or rerun the MSI with `/l*v` and look for exit codes 20–24 (section 2). |
| The machine never appears in **Machines** | Check `C:\rmt-agent\helper.log` for connection errors. The computer must reach `https://<server>` and `wss://<server>/ws` on port 443. |
| A guest cannot run the support tool | Run it as a normal user, outside Remote Desktop. Application-control policies may block it. Logs are in `%TEMP%\DeskRally\`. |
| **Enable unattended access** says the installer is unavailable | The server's managed installer is not enabled (see the server guide). |
| Video is black or the session will not start | In the session, open **Connection details** and note two readings about 10 seconds apart. Reconnect once, then send that report to your administrator. Never send tokens or `identity.key`. |
