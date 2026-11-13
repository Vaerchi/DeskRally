# DeskRally Windows Client 0.8.4

A minimal native Windows shell for the DeskRally web console, built with Win32 and Microsoft WebView2.
Each window is pinned to one organization, `https://<organization>.deskrally.com`. The app contains
no list of organizations.

## 0.8.4 changes

- **Full screen fills the whole screen.** The viewer's Full screen button (and the pop-out window's)
  now hides the title bar, window frame, menu and tabs and covers the monitor, instead of filling only
  the app window. Esc or the button restores the window as it was.

## 0.8.3 changes

- **Automatic clipboard sharing.** The clipboard question is asked once per app start (Yes or No is
  remembered until the app restarts) instead of on every read, and the app tells the console it can
  share the clipboard automatically: what you copy goes to the remote when you click into its screen.
  The console's "Share clipboard automatically" switch turns it off.
- **Closing the app no longer leaves a hidden DeskRally process running** when a dialog was open at
  the moment the window closed.
- **The updater records why an update was not installed** (Help > About shows it), and discards a
  downloaded update that is no longer newer than the installed app.

## 0.8.2 changes

- **Windows Hello face and fingerprint unlock at startup.** The app asked Windows Hello to verify
  before its window was visible; face and fingerprint sign-in only engage for a prompt in front of a
  visible window, so they failed while PIN entry worked. The window now appears first.
- **A failed unlock offers Try again** instead of closing the app.

## 0.8.1 changes

- **Retrying Microsoft sign-in after a timeout works.** A reload of the same console address did not
  count as returning to the organization, so after one timed-out sign-in every retry was refused
  until the app restarted.
- **A blocked page no longer receives a request.** WebView2 still sent the request of a navigation the
  app had cancelled; that exact request is now answered inside the app.

## 0.8.0 changes

**Microsoft sign-in inside the app.** Supports Entra members and Microsoft-account (MSA) guests
with Microsoft-hosted MFA. Duo, federation and seamless SSO are not supported; an unsupported
sign-in step shows a native message directing you to use the console in a web browser.
Sign-in is bounded to 10 minutes; returning to a committed organization page permits a fresh flow.
While Microsoft content is committed, the native window title shows
"Microsoft sign-in – <host> – DeskRally", and its tab label is "Microsoft sign-in".
Timeout or unsupported-step messages return the tab to the organization's console when dismissed.

## 0.7.0 changes

**Tabs.** Each window is still one organization, and now holds tabs: the console and your sessions
side by side, so you can open the Toolbox (or Machines) while a session is running.
- New tab: Ctrl+T, the "+" tab, or Tabs > New tab. It opens that organization's console, already
  signed in (all tabs share the organization's sign-in).
- Close tab: Ctrl+W, middle-click the tab, or Tabs > Close tab. Closing the last tab closes the window.
- Switch: Ctrl+Tab / Ctrl+Shift+Tab, Ctrl+1 to Ctrl+8 for a tab, Ctrl+9 for the last one.
- Up to 12 tabs per window. Pop-out windows still open as separate windows.
- If a tab stops responding, DeskRally offers to reload or close just that tab.

**About.** Help > About DeskRally shows the version, the build, whether the publisher signature is
verified, the organization of this window and the last update result.

## 0.6.1 changes

0.6.0 asked for the organization on every launch against the production service: it remembered
an organization only after seeing the service's sign-in cookie, and it looked for the cookie under
the name a non-HTTPS development server uses (`cp_session`), while the production service names it
`__Host-cp_session`. 0.6.1 recognises both names, with the same checks as before (set by the server
for exactly that organization's address, HTTPS-only, not readable by page script). After one
sign-in, the Start menu opens that organization directly again.

## 0.6.0 changes

Up to 0.5.0 the app built in exactly two organizations, Main and Loam, and showed both
in every user's Organization menu. Each customer could see the other's name, and any
further organization could not use the app. 0.6.0 removes the list:

- **Any organization.** A link `deskrally-client://tenant/<organization>/...` opens that
  organization, where `<organization>` is one DNS label (1-63 of `a-z`, `0-9`, `-`, not
  starting or ending with `-`; matched case-insensitively). Infrastructure names in the
  same zone (`www`, `turn`, `api`, `download`, ... see `is_reserved_slug`) are refused;
  the control plane refuses the same names as tenant slugs. Legacy links without
  `tenant/` still open Main.
- **Start menu launch** opens the organization this Windows user last signed in to from the
  app (`HKCU\Software\DeskRally\Client\LastOrganization`). Otherwise, including the first
  launch after upgrading from 0.5, the app asks once for the organization name; Cancel exits
  without creating a profile. Existing profile folders are not used to guess: 0.5 opened Main
  on every Start-menu launch, so a folder says nothing about which organization a user is in.
- **Organization menu** lists the current window's organization and the others this Windows
  user has signed in to through the app on this PC (most recent first, 20 entries including the
  current one), plus **Open another organization...**. An organization is recorded
  (`...\Client\<organization>\LastUsed`) only when its own origin holds a server-issued
  `cp_session` cookie (host-only, `Path=/`, Secure, HttpOnly, so page script cannot forge it),
  checked every 3 seconds until found. This shows a sign-in completed through that origin; it
  does not prove the session is still valid. A page that merely loads, such as an error page for
  a mistyped name, is never recorded.
- **Unchanged storage:** Main keeps `Profile`, every other organization uses
  `Profile.<organization>` (so Loam's `Profile.loam` is unchanged), and Windows Hello stays
  at `...\Client\<organization>\HelloEnabled`. Signed-in sessions and Hello settings survive
  the upgrade.
- **Origin pinning is unchanged:** each process trusts exactly one host, and a page can hand
  off only to a link for its own organization.

## 0.5.0 changes

The installed app checks for updates when opened and daily while it remains open.
Use **Updates > Check for updates** to check immediately. Downloads run in the
background; installation waits for **all** DeskRally app windows to close, so
remote sessions are not terminated. The worker waits for up to seven days; after
a reboot or an expired wait, opening the app permits a new check when due.

Only the installed copy updates itself. Development and standalone test copies
do not download updates. Existing 0.4 and older installations need the complete
signed 0.5 package once to bootstrap this feature. Profiles and Windows Hello
settings are preserved.

## 0.4.0 changes

The native **Security** menu enables or disables Windows Hello for the selected
organization. Both changes require Windows verification. Close and reopen the
window after enabling; the app verifies Hello before initializing WebView2 or
opening the saved profile. Cancellation, unavailable verification, and unreadable
settings leave the protected profile unopened. Existing open windows are unchanged.

After unlocking, sign out and sign in again with **Remember this app for 30 days**
selected. This requires the matching server/viewer update. It retains the server
session, not your password, for at most 30 days and expires after seven unused
days. Normal server sign-out, credential changes, and disabled accounts still
invalidate it. The checkbox is opt-in and does not extend an existing session.

Settings are separate DWORD `HelloEnabled` values (0/1) beneath
`HKCU\Software\DeskRally\Client\main` and `...\loam`. No PIN is stored. Main/Loam
profiles remain unchanged. New processes, including protocol launches, each
verify; pop-outs in an unlocked process share its unlock. This is a startup
privacy lock, not a passkey, server attestation, automatic idle lock, or protection
against software acting as the same Windows user. Lock Windows when away.
Disabling Hello does not revoke a remembered server session; use **Sign out**.

The desktop API requires a supported Windows Hello configuration (Microsoft
documents Windows build 22000 or later for this interop API). If unavailable,
leave Hello disabled and use ordinary sign-in, or use the website. Details and
acceptance status: [Remembered sign-in](../../docs/desktop-remembered-sign-in.md).

Pure policy tests cover startup admission and stale/closing callbacks. The
synthetic smoke binary neither reads/writes real Hello settings nor prompts the
user. A real Hello enable/reopen/approve check remains separate from those tests.

## 0.3.0 changes

- **Multi-tenant support**: processes are pinned at startup to a single tenant (Main or Loam) selected from the launch URI. The tenant is locked before the WebView2 environment is created and never changed in-place.
- **Strict protocol**: new URI format `deskrally-client://tenant/{main|loam}/{connect|attended}/<UUID>[/]` and `deskrally-client://tenant/{main|loam}/console[/]`. Tenant name, action, and UUID are validated; unknown tenants, unknown actions, extra segments, query, fragment, percent-encoding, backslash, control characters (0x00–0x1F), and DEL (0x7F) are all rejected.
- **Legacy protocol preserved**: `deskrally-client://connect/<UUID>[/]` and `deskrally-client://attended/<UUID>[/]` continue to work and always resolve to the Main tenant.
- **Origin pinning**: every navigation check, source-frame trust check, popup origin check, and clipboard permission check uses only the selected process tenant's host. No window trusts both hosts simultaneously.
- **Source-initiated spawn gating**: when a trusted page navigates to a `deskrally-client://` URI, the parsed tenant must match the selected process tenant. Legacy URIs (Main) are rejected in a Loam process.
- **Tenant-qualified titles**: window title includes ` – Main` or ` – Loam` after every `DocumentTitleChanged` update and at initial window creation. Popups inherit the process tenant.
- **Separate profiles**: Main uses `%LOCALAPPDATA%\DeskRally Client\Profile` (unchanged); Loam uses `%LOCALAPPDATA%\DeskRally Client\Profile.loam`.
- **Organization menu**: a native `Organization` menu on the main window offers `Main` and `Loam` items. Each opens the selected console in an independent new process via `CreateProcessW` and the validated strict protocol (`deskrally-client://tenant/{main|loam}/console`). Active sessions in other windows are not affected.
- **`build_initial_url` helper**: a single pure policy function converts a validated `ClientUriResult` to the correct HTTPS URL. All startup URL construction goes through this helper.
- **User-Agent marker**: updated to `DeskRallyDesktop/0.3.0`.

## 0.2.0 changes

- **Maximized by default**: main window and popouts open with `SW_SHOWMAXIMIZED`.
- **Console URL**: default navigation is `https://main.deskrally.com/console` (not the root).
- **`deskrally-client://` protocol**: installer registers `HKCU\Software\Classes\deskrally-client` per-user (no admin). Legacy actions `connect` and `attended` map to `?device=` and `?attended=` respectively.
- **User-Agent marker**: `DeskRallyDesktop/0.2.0` appended (now updated to 0.3.0).
- **In-app connection hand-off**: trusted console pages can navigate to a `deskrally-client://` URI via user gesture; the native layer cancels the WebView navigation, validates the URI, and spawns a new client process.

## 0.1.1 note

0.1.1 explicitly shows the embedded browser surface. That fix is preserved.

## Scope

This desktop release uses the deployed DeskRally web console inside a dedicated Windows application. It provides:

- A native resizable window titled **DeskRally – <Organization>**, opened maximized by default.
- Process-pinned HTTPS console URL built from the parsed launch URI via `build_initial_url`.
- **Per-organization** persistent WebView2 profiles (Main: `%LOCALAPPDATA%\DeskRally Client\Profile`; any other organization: `%LOCALAPPDATA%\DeskRally Client\Profile.<organization>`). Profiles are never shared between organizations.
- `window.open` popup support: `about:blank` popups with a user gesture open in a native child window; popups inherit the parent process's tenant and are bound to the same host.
- Navigation restricted to the exact trusted origin of the selected process tenant – lookalike hosts, the other tenant's host, credentials, wrong port, non-HTTPS, DEL/control characters in URLs, and local files are all rejected.
- Clipboard read permission shown to the user as a Yes/No consent dialog; not silently granted or persistently stored.
- All other permission requests (microphone, camera, geolocation, notifications) denied without prompting.
- Native **Organization** menu: the organizations used on this PC, and **Open another organization...**; each opens an independent console process. Existing sessions are not disturbed.

**Not in this release:** automatic updates, MSI packaging, crash reporting. The release package contains a signed executable, installer and measured hash manifest. Authenticated remote-session acceptance remains separate from the local synthetic checks.

## Trusted Hosts

| Organization | Host | Origin |
|--------|------|--------|
| `<organization>` | `<organization>.deskrally.com` | `https://<organization>.deskrally.com` |

Each process trusts exactly one origin: its own organization's. Subdomains, superdomains, lookalike hosts, other organizations' hosts, non-HTTPS schemes, non-default ports, and userinfo are all denied.

## Protocol Reference

| URI | Tenant | Kind | Behavior |
|-----|--------|------|----------|
| `deskrally-client://connect/<UUID>` | Main | Connect | Opens `main.deskrally.com/console?device=<UUID>` |
| `deskrally-client://attended/<UUID>` | Main | Attended | Opens `main.deskrally.com/console?attended=<UUID>` |
| `deskrally-client://tenant/<org>/console[/]` | `<org>` | Console | Opens `<org>.deskrally.com/console` |
| `deskrally-client://tenant/<org>/connect/<UUID>[/]` | `<org>` | Connect | Opens `<org>.deskrally.com/console?device=<UUID>` |
| `deskrally-client://tenant/<org>/attended/<UUID>[/]` | `<org>` | Attended | Opens `<org>.deskrally.com/console?attended=<UUID>` |

UUID must be exactly 36 characters in 8-4-4-4-12 hexadecimal form. Invalid or reserved organization names, unknown actions, extra path segments, query strings, fragments, percent-encoding, backslash, control characters (0x00–0x1F), and DEL (0x7F) are rejected. The scheme and all structural tokens are case-insensitive; the UUID is normalized to lowercase.

## Prerequisites

- Windows 10 (version 1903+) or later.
- Microsoft Edge WebView2 Runtime installed (evergreen or fixed version).
  Install from: https://developer.microsoft.com/microsoft-edge/webview2/
- MSVC BuildTools 2022 or later (for building from source).

## Build from Source

Run from a PowerShell session:

```powershell
cd clients\windows
.\build-client.ps1
```

For a self-hosted server, use `.\build-client.ps1 -TenantZone example.test`. This pins organizations to `<organization>.example.test`,
including the Main organization at `main.example.test`. Omit `-TenantZone` to use
`deskrally.com`, the hosted service default. The suffix must use lowercase letters,
digits, hyphens and dots, contain at least one dot, have no empty labels or leading/
trailing label hyphens, and be at most 253 characters. The option applies to policy
tests and the smoke variant as well as the client; update identity is configured separately.

This will:
1. Locate MSVC BuildTools via `vswhere`.
2. Download `Microsoft.Web.WebView2 1.0.4191.47` from NuGet, verify SHA-256.
3. Compile `client_policy_test.exe` (pure URL/permission/protocol policy tests, no WebView2).
4. Run policy tests – build fails if any test fails.
5. Compile `DeskRallyClient.exe` with `/MT` and static `WebView2Loader`.

Default output: the repository's `target\desktop-client` directory. Use `-OutDir` to select another build directory; keep this workstation's artifacts on F:.

### Full screen

The viewer's **Full screen** button (and the pop-out window's) takes the whole app window full screen: no title bar, frame, menu or tab strip, covering the monitor the window is on. **Esc** or the button leaves it and restores the window as it was (maximized stays maximized). The window follows the tab it shows: switching to another tab leaves full screen, and switching back resumes it.

### Optional smoke-test variant

```powershell
.\build-client.ps1 -SmokeTestBuild
```

Produces `DeskRallyClient-smoke.exe` (compiled with `/DSMOKE_TEST`). When launched,
it uses local test fixtures through an isolated virtual host and a separate profile beside the executable. It checks popup creation, opener DOM access, clipboard permission routing, popup close and parent close while a child initializes, then a tab sequence (create/close races, consent settlement, failure recovery) and full screen (a page's `requestFullscreen()` makes the maximized window borderless and monitor-sized with no menu or tab strip; exiting restores it maximized with its menu; showing another tab leaves full screen and returning resumes it; Esc leaves it). It writes `smoke-test.log` beside the executable and exits with failure unless all 28 checks pass within 30 seconds. Run it in an interactive desktop session (the lab VM's console session via an interactive scheduled task), never over a Session-0 remote shell. The clipboard test denies access after checking permission routing; it does not read the real clipboard. The build script does **not** launch it. These synthetic checks do not establish authenticated remote-session acceptance.

## Install or update the signed release

Extract the complete package and run `Install-DeskRally-Client.cmd`, then open **DeskRally** from the Start menu. No administrator prompt is needed. The same launcher updates an existing installation after you close the app.

For PowerShell:

```powershell
.\install-client.ps1 -SourceDir "path\to\complete-signed-package"
```

The complete package must contain `DeskRallyClient.exe` and `release-manifest.json` with its measured `sha256`. The manual installer retains its own fixed publisher policy; the build options below configure the desktop self-updater only.

The installer:
- Validates the timestamped Authenticode signature, exact publisher, and file hash.
- Refuses to install if the client is running.
- Rejects reparse points on the destination path.
- Installs to `%LOCALAPPDATA%\Programs\DeskRally Client\`.
- Creates a Start Menu shortcut.
- Preserves the existing WebView2 profiles for both tenants.
- Restores the previous executable and shortcut if replacement or shortcut creation fails; retains backup files for recovery.
- Requires no administrator privileges.
- Creates no autorun entry or Windows service.

## Security Boundaries

| Threat | Mitigation |
|---|---|
| Navigation to non-trusted origin | `NavigationStarting` blocks anything outside the selected process tenant's exact host |
| Cross-tenant host spoofing | Process tenant is pinned before WebView2 env creation; each window checks only its own tenant's host |
| Credential theft via URL | Userinfo in URI rejected by policy |
| Lookalike host | Exact host match only; any deviation denied |
| DEL / control chars in URI | `parse_url` and `parse_client_uri` reject 0x00–0x1F and 0x7F |
| Unrequested popup | Only `about:blank` with user gesture allowed via `NewWindowRequested` |
| Cross-tenant popup | Child popups inherit parent process tenant; NavigationStarting enforces it |
| Silent clipboard access | User sees a Yes/No dialog per request; no persistent grant |
| Privilege escalation | Manifest declares `asInvoker`; installer requires no admin |
| Symlink attack on install | Reparse-point check before and after directory creation |
| Source-initiated cross-tenant spawn | Parsed URI tenant checked against selected process tenant before spawning |

## Updater

The self-updater has three build modes:

- No update options: self-update is OFF, the host and publisher pins are empty, and About reports "updates are not configured in this build" and "Publisher: not pinned in this build".
- `build-client.ps1 -OfficialUpdates`: explicitly reads the host and exact publisher from `packaging/official-update-identity.json`.
- `build-client.ps1 -UpdateHost updates.example.test:8443 -UpdatePublisher "CN=Your Publisher, O=Your Organization"`: pins your own identity. Both values are required and cannot be combined with `-OfficialUpdates`.

Configured builds fetch `https://<configured-host[:port]>/download/client/manifest.json`.
About shows the CN from the configured subject when its signature verifies.
The same configuration applies to all policy/runtime tests and the smoke build.
The client accepts only the
corresponding versioned binary on that origin, with no redirects or automatic
HTTP authentication. Downloads are bounded to 32 MiB. Before installation, the
app verifies the hash, timestamped Authenticode chain and publisher, product
identity, and signed file version. Versions must increase; metadata cannot
relabel an older signed executable as a new release.

Each app process holds a shared lifetime file handle. The independent update
worker waits for exclusive access before replacing the executable; new app
launches are deferred during replacement. The manual installer uses the same
barrier. The worker rechecks the live manifest before applying a downloaded
release, so withdrawing the manifest stops pending installations too.

A verified copy of the previous executable is retained. Failed post-install
verification or a failed WebView2-runtime startup self-test restores that copy.
A release that fails this check is not automatically retried. This self-test
checks local startup prerequisites; it does not authenticate to a tenant or
prove a remote connection works. A power loss or forced termination during the
worker transaction still requires inspection of the retained files; the manual
signed installer remains the recovery path.

No app windows are forcibly closed. No SYSTEM service, scheduled task, saved
password, or new profile is added. The updater runs with the current user's
permissions. The user's own account already has write access to its per-user
installation; this is not a boundary against malware running as that account.

Manual recovery: close the app and rerun `Install-DeskRally-Client.cmd` from the
complete signed package. Do not delete the profile folders to fix an update.
Release preparation and ring operations are documented in
`docs/automatic-update-release.md`.

## Validation

`build-client.ps1` compiles and runs URI/permission policy checks (organization-name grammar and reserved names, typed organization input, navigation cases for several organizations, cross-tenant denial, origin pinning, DEL/control-char rejection, popup, permission, legacy URI parser cases, new strict URI parser cases including console routes, invalid tenants, cross-tenant field verification, and `build_initial_url` URL value assertions). `test-installer.ps1` exercises fifteen filesystem/registry transaction cases with mocked signature, process, shortcut, and registry APIs; this verifies rollback paths but does not replace real Authenticode/COM installation checks. The packaged installer is separately checked under Windows PowerShell 5.1 using real signed bytes and shortcuts. The isolated WebView2 smoke fixture checks 28 surface/popup/permission/lifecycle/tab/full-screen behaviors; it does not log in or read the operator's clipboard.

## Remove the app

Close DeskRally, remove its Start-menu shortcut and the `%LOCALAPPDATA%\Programs\DeskRally Client` folder. Login profiles are at `%LOCALAPPDATA%\DeskRally Client\Profile` (Main) and `%LOCALAPPDATA%\DeskRally Client\Profile.<organization>`; remove them only if you also want to discard saved login state. The remembered organizations are under `HKCU\Software\DeskRally\Client`.
